// Copyright 2026 Oleksandr Vovkotrub. Apache-2.0.
//
// P7sSignature — sig-side gadget for the p7s dual-circuit bring-up.
//
// Task 25a introduced this class as a thin MAC-binding scaffold that
// linked the hash circuit (GF(2^128)) and the sig circuit (Fp256Base)
// via a cross-field MAC on a compile-time sentinel. Task 29 (25b)
// replaces the sentinel with `e = SHA-256(cert_tbs)` and wires an
// `ECDSA VerifyCircuit` around the same MAC, so the sig circuit now
// proves "`(r, s)` is a valid P-256 signature of `e` under the DIIA
// QTSP 2311 root public key, AND `e` equals the cross-circuit value
// the hash side committed to".
//
// root_pk is a compile-time constant — the DIIA QTSP 2311 uncompressed
// SEC1 point baked into `kDiiaRootPkX_decimal` / `kDiiaRootPkY_decimal`
// strings below. It does not appear as a circuit public input; the
// caller wires it via `lc.konst(p256_base.of_string(...))`.
//
// Rationale for the MAC step remains the same as 25a: the ECDSA
// VerifyCircuit operates over Fp256Base, but the SHA-256 computation
// happens on the hash side over GF(2^128). The MAC gives us a
// negligible-probability cross-field binding that `e` in the sig
// circuit equals `SHA-256(cert_tbs)` in the hash circuit.

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
// the hash/sig field split. Task 25a bound a sentinel; Task 29 binds
// `e = SHA-256(cert_tbs)`. Task 26 (invariant 2a) will bump this to 2
// when the content-signature MAC (over the signedAttrs hash) lands.
constexpr size_t kMacMessagesCount = 1;

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
// plus (in Task 29) the ECDSA verification against the hardcoded
// DIIA root. Mirrors the shape of `MdocSignature` but carries only
// ONE bound message and ONE ECDSA witness (mdoc binds 3 messages
// and verifies 2 signatures; p7s invariant 1 verifies exactly 1).
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
  // per bound message (we have one; Task 26 will add a second) plus
  // the full ECDSA advice table (see verify_circuit.h for the shape).
  class Witness {
   public:
    MACWitness macs_[kMacMessagesCount];
    EcdsaWitness ecdsa_;

    void input(const LogicCircuit& lc) {
      for (size_t i = 0; i < kMacMessagesCount; ++i) {
        macs_[i].input(lc);
      }
      ecdsa_.input(lc);
    }
  };

  explicit P7sSignature(const LogicCircuit& lc, const EC& ec, const Nat& order)
      : lc_(lc), ec_(ec), order_(order) {}

  // Task 29 (25b): verify that `(r, s)` — implicit in `vw.ecdsa_` —
  // is a valid ECDSA-P256 signature of `msg_e` under the hardcoded
  // DIIA root public key `(root_pk_x, root_pk_y)`, AND that the same
  // `msg_e` equals the cross-circuit value committed in the hash
  // circuit (via the MAC on `mac_values[2]` / `av`).
  //
  // Soundness argument:
  //   * ECDSA VerifyCircuit binds `(r, s)` to produce a valid signature
  //     on `msg_e` under the given public key. Forging requires
  //     root_pk's private key.
  //   * The MAC gadget binds `msg_e` to `x_` in `vw.macs_[0]` (see
  //     `MAC::unpack_msg`). The same MAC values and `av` appear as
  //     public inputs in the hash circuit, which binds the same 256-bit
  //     value to `SHA-256(cert_tbs)` computed in-circuit. Because the
  //     MAC is almost-universal over the verifier-sampled `av`, a
  //     successful verification means the two circuits agree on `msg_e`
  //     with overwhelming probability.
  //
  // `order` should be the curve order (`n256_order` for P-256). The
  // MAC primitive range-checks the message bit-decomposition against
  // this bound; the ECDSA circuit separately range-checks `r` and
  // `-s` against the same bound. For `msg_e = SHA-256(cert_tbs)` the
  // probability that the SHA output happens to exceed the curve order
  // is ~2^{-32} — in that case the honest prover fails at witness
  // generation time (a benign liveness issue, not a soundness issue).
  void assert_signature(EltW root_pk_x, EltW root_pk_y, EltW msg_e,
                        const v128 mac_values[kMacValuesPerMessage],
                        const v128& av, const Witness& vw) const {
    // 1. ECDSA: the witness contains r = rx (mod n), s, and the scalar-
    //    mult advice table. verify_signature3 asserts the curve equation
    //    `id == g·e + pk·r + (rx,ry)·(-s)` and that `(pk_x, pk_y)` and
    //    `(rx, ry)` are on-curve, `rx != 0`, `s != 0`.
    Ecdsa ecc(lc_, ec_, order_);
    ecc.verify_signature3(root_pk_x, root_pk_y, msg_e, vw.ecdsa_);

    // 2. MAC: bind msg_e to the cross-circuit value (same `av` sampled
    //    from the shared transcript post-commit, same ap committed
    //    pre-commit, same 256-bit bit-decomposition of msg_e on both
    //    sides).
    mac macc(lc_);
    macc.verify_mac(msg_e, mac_values, av, vw.macs_[0], order_);
  }
};

}  // namespace p7s
}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_P7S_SUB_P7S_SIGNATURE_H_
