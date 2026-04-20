// Copyright 2026 Oleksandr Vovkotrub. Apache-2.0.
//
// P7sSignature — sig-side gadget for the p7s dual-circuit bring-up.
//
// Task 25a introduced this class as a thin MAC-binding scaffold that
// linked the hash circuit (GF(2^128)) and the sig circuit (Fp256Base)
// via a cross-field MAC on a compile-time sentinel. Task 29 (25b)
// replaced the sentinel with `e = SHA-256(cert_tbs)` and wired one
// `ECDSA VerifyCircuit` around the MAC, proving "`(r1, s1)` is a valid
// P-256 signature of `e` under the DIIA QTSP 2311 root public key AND
// `e` equals the cross-circuit value the hash side committed to".
//
// Task 26 (invariant 2a, merged with former #30 SPKI binding) adds
// the CMS content signature leg. The key that signed the content is
// NOT the JSON-embedded wallet pubkey (invariant 4's pk, which is
// secp256k1 for the Ethereum wallet being authorized) — it's the
// holder's DIIA-issued P-256 signing key, embedded as the
// SubjectPublicKeyInfo inside cert_tbs. Promoting that cert SPKI to
// the public blob would leak holder identity (a privacy regression),
// so instead we extract it from cert_tbs on the hash side (via a
// byte-range route at a host-witnessed offset, anchored by a 26-byte
// DIIA SPKI prefix assertion) and MAC-bind its X and Y coordinates
// across the hash/sig field split as two additional messages. The
// sig circuit consumes `holder_pk_x` and `holder_pk_y` as PRIVATE
// EltW inputs, unpacked from the MAC witnesses — the same pattern
// mdoc uses for `dpkx_` / `dpky_`.
//
// The sig circuit now proves:
//
//   (A) (r1, s1) is valid ECDSA on `e`  under DIIA root_pk  (invariant 1)
//   (B) (r2, s2) is valid ECDSA on `e2` under holder_pk     (invariant 2a)
//   (C) `e`         cross-binds to SHA-256(cert_tbs)        (hash side)
//   (D) `e2`        cross-binds to SHA-256(signedAttrs)     (hash side)
//   (E) holder_pk_x cross-binds to cert_tbs SPKI X bytes    (hash side)
//   (F) holder_pk_y cross-binds to cert_tbs SPKI Y bytes    (hash side)
//
// `root_pk` is a compile-time constant baked into the strings below
// (DIIA QTSP 2311, not a public input). `holder_pk_x` / `holder_pk_y`
// are PRIVATE Fp256Base EltW inputs in the sig circuit, bound to the
// hash circuit's cert_tbs SPKI bytes via MAC. Total bound messages =
// 4 (e, e2, SPKI_X, SPKI_Y); total MAC values = 8 (2 per message).
//
// Rationale for the MAC step remains the same as 25a: the ECDSA
// VerifyCircuit operates over Fp256Base, but the SHA-256 computations
// and cert-SPKI extraction happen on the hash side over GF(2^128).
// The MAC gives us a negligible-probability cross-field binding per
// message.

#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_P7S_SUB_P7S_SIGNATURE_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_P7S_SUB_P7S_SIGNATURE_H_

#include <cstddef>

#include "circuits/ecdsa/verify_circuit.h"
#include "circuits/logic/bit_plucker.h"
#include "circuits/mac/mac_circuit.h"

namespace proofs {
namespace p7s {

// BitPlucker packing depth used by the sig-side MAC witness. Matches
// the value hard-coded by the MAC primitive (`kMACPluckerBits = 2`);
// re-exported here so callers can access it via this header without
// reaching into the primitive's internals.
constexpr size_t kMacPluckerBits = 2;

// Number of distinct 256-bit messages the p7s circuits bind across
// the hash/sig field split. Task 25a bound 1 sentinel; Task 29 bound
// `e = SHA-256(cert_tbs)`; Task 26 (invariant 2a + SPKI binding)
// bumps to 4:
//   message 0 = `e  = SHA-256(cert_tbs)`
//   message 1 = `e2 = SHA-256(signedAttrs_rewritten)`
//   message 2 = cert_tbs SPKI X coordinate (LE-ordered 32 bytes)
//   message 3 = cert_tbs SPKI Y coordinate (LE-ordered 32 bytes)
constexpr size_t kMacMessagesCount = 4;

// Message indices — keeps layout-dependent code (MAC index slicing,
// dense-array fillers, etc.) readable.
constexpr size_t kMacMsgIdxE       = 0;
constexpr size_t kMacMsgIdxE2      = 1;
constexpr size_t kMacMsgIdxSpkiX   = 2;
constexpr size_t kMacMsgIdxSpkiY   = 3;

// MAC produces 2 GF(2^128) values per bound message (low + high
// halves of the 256-bit value). Part of the primitive, not per-task.
constexpr size_t kMacValuesPerMessage = 2;

// Total MAC values that appear as public inputs in each circuit.
// For mdoc this is 6 (3 messages × 2); for us, 2 (1 message × 2).
constexpr size_t kTotalMacValues =
    kMacMessagesCount * kMacValuesPerMessage;

// Length of a MAC-bound message in bytes. The primitive assumes 256-bit
// messages; the value is exported for callers that pack/unpack the
// 32-byte digest without having to recompute 32.
constexpr size_t kMacMessageBytes = 32;

// DIIA QTSP 2311 root public key — the trust anchor the signer cert's
// ECDSA signature is verified against. Extracted from the official
// `diia-qtsp-2311.der` certificate (Ukrainian Trust List, Nov 2023).
// SEC1 uncompressed point hex:
//   0x04
//   0x8500048265e919c1738e873572c1f6443895a0c03985fc71bd96a6f62a53bcc8  (X)
//   0x69d23ca6e6a2a7dc443bbb2a0b914ee35f1c74e282ecd8e6c5287c7a3d4aee10  (Y)
// Decimal forms are baked in as compile-time string literals so
// `p256_base.of_string(...)` returns a Montgomery-form `Elt` without
// any runtime parsing ambiguity.
constexpr char kDiiaRootPkX_decimal[] =
    "60157639984085317032243857144591567409916300241404119731688357596981577891"
    "016";
constexpr char kDiiaRootPkY_decimal[] =
    "47864305589267125428873492369100630325836418204952516382052455720647888924"
    "176";

// Sig-circuit gadget — the Fp256Base half of the cross-field MAC,
// plus the ECDSA verifications. Mirrors the shape of `MdocSignature`:
// mdoc binds 3 messages and verifies 2 signatures; p7s binds 2
// messages (`e`, `e2`) and verifies 2 signatures (cert sig against
// the DIIA root, content sig against the user's holder_pk).
template <class LogicCircuit, class Field, class EC>
class P7sSignature {
  using EltW = typename LogicCircuit::EltW;
  using Nat = typename Field::N;
  using v128 = typename LogicCircuit::v128;
  using MacBitPlucker = BitPlucker<LogicCircuit, kMacPluckerBits>;
  using mac = MAC<LogicCircuit, MacBitPlucker>;
  using Ecdsa = VerifyCircuit<LogicCircuit, Field, EC>;

  const LogicCircuit& lc_;
  const EC& ec_;
  const Nat& order_;

 public:
  using MACWitness = typename mac::Witness;
  using EcdsaWitness = typename Ecdsa::Witness;

  // Private witness bundle for the sig-circuit checks. One MAC entry
  // per bound message (`e`, `e2`) plus one ECDSA advice table per
  // verified signature (cert sig, content sig). See verify_circuit.h
  // for the advice-table shape.
  class Witness {
   public:
    MACWitness macs_[kMacMessagesCount];
    EcdsaWitness ecdsa_cert_;     // invariant 1   — cert sig
    EcdsaWitness ecdsa_content_;  // invariant 2a  — CMS content sig

    void input(const LogicCircuit& lc) {
      for (size_t i = 0; i < kMacMessagesCount; ++i) {
        macs_[i].input(lc);
      }
      ecdsa_cert_.input(lc);
      ecdsa_content_.input(lc);
    }
  };

  explicit P7sSignature(const LogicCircuit& lc, const EC& ec, const Nat& order)
      : lc_(lc), ec_(ec), order_(order) {}

  // Task 26 (invariants 1 + 2a + SPKI binding combined): verify:
  //   (A) cert sig (r1, s1) on `msg_e  = SHA-256(cert_tbs)` under
  //       the hardcoded DIIA root pk;
  //   (B) content sig (r2, s2) on `msg_e2 = SHA-256(signedAttrs)`
  //       under holder_pk (= cert_tbs SPKI, bound via MAC);
  //   (C) `msg_e`  cross-binds to the hash circuit's SHA(cert_tbs);
  //   (D) `msg_e2` cross-binds to the hash circuit's SHA(signedAttrs);
  //   (E) `holder_pk_x` cross-binds to cert_tbs SPKI X bytes;
  //   (F) `holder_pk_y` cross-binds to cert_tbs SPKI Y bytes.
  //
  // Soundness argument (per-message): ECDSA VerifyCircuit binds
  // (r, s) on `msg` under the given public key (forging requires the
  // private key). MAC::verify_mac asserts msg equals the bit-expansion
  // of `vw.macs_[i].xx_`; the SAME MAC values and `av` appear as
  // public inputs in the hash circuit, which binds the same 256-bit
  // value to its in-circuit source (SHA output, or routed SPKI bytes).
  // Almost-universality of MAC over the verifier-sampled `av` gives
  // agreement with overwhelming probability.
  //
  // `order` should be the curve order (`n256_order` for P-256). The
  // MAC primitive range-checks each message bit-decomposition against
  // this bound; the ECDSA circuit separately range-checks `r` and
  // `-s` against the same bound. A MAC::verify_mac call would fail
  // liveness if the bound message's nat value exceeds the curve order
  // (probability ~2^{-32} per SHA-256 output; for a P-256 SPKI X or
  // Y coordinate it is by construction below the prime p_256, which
  // is slightly larger than the order n_256 — collision with the gap
  // is possible but honest certs won't hit it, so again a liveness
  // concern not a soundness one).
  //
  // `holder_pk_x` / `holder_pk_y` are PRIVATE Fp256Base EltW inputs
  // the caller declared via `eltw_input()` in the sig circuit's
  // private-witness section. Their binding to the actual cert_tbs
  // SPKI bytes is enforced by the MAC unpack_msg on `vw.macs_[2]` /
  // `vw.macs_[3]` below.
  void assert_signature(EltW root_pk_x, EltW root_pk_y, EltW holder_pk_x,
                        EltW holder_pk_y, EltW msg_e, EltW msg_e2,
                        const v128 mac_e[kMacValuesPerMessage],
                        const v128 mac_e2[kMacValuesPerMessage],
                        const v128 mac_spki_x[kMacValuesPerMessage],
                        const v128 mac_spki_y[kMacValuesPerMessage],
                        const v128& av, const Witness& vw) const {
    Ecdsa ecc(lc_, ec_, order_);

    // Invariant 1 — cert sig over e under the DIIA root.
    ecc.verify_signature3(root_pk_x, root_pk_y, msg_e, vw.ecdsa_cert_);

    // Invariant 2a — CMS content sig over e2 under the holder pk.
    ecc.verify_signature3(holder_pk_x, holder_pk_y, msg_e2,
                          vw.ecdsa_content_);

    // MAC gadget — per-message cross-field binding. Same `av` across
    // all four (sampled once from the shared transcript post-commit);
    // per-message `ap` committed pre-commit in the mac witnesses.
    mac macc(lc_);
    macc.verify_mac(msg_e,       mac_e,       av, vw.macs_[kMacMsgIdxE],     order_);
    macc.verify_mac(msg_e2,      mac_e2,      av, vw.macs_[kMacMsgIdxE2],    order_);
    macc.verify_mac(holder_pk_x, mac_spki_x,  av, vw.macs_[kMacMsgIdxSpkiX], order_);
    macc.verify_mac(holder_pk_y, mac_spki_y,  av, vw.macs_[kMacMsgIdxSpkiY], order_);
  }
};

}  // namespace p7s
}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_P7S_SUB_P7S_SIGNATURE_H_
