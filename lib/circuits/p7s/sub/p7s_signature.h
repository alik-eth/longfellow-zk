// Copyright 2026 Oleksandr Vovkotrub. Apache-2.0.
//
// P7sSignature — sig-side gadget for the p7s dual-circuit bring-up.
//
// Task 25a introduced this class as a thin MAC-binding scaffold that
// linked the hash circuit (GF(2^128)) and the sig circuit (Fp256Base)
// via a cross-field MAC on a compile-time sentinel. Task 29 (25b)
// replaced the sentinel with `e = SHA-256(cert_tbs)` and wired one
// `ECDSA VerifyCircuit` around the MAC, proving "`(r1, s1)` is a valid
// P-256 signature of `e` under the compile-time trust-anchor root pubkey
// (DIIA QTSP 2311 at the time of Task 29; TestAnchorA post-#43a) AND
// `e` equals the cross-circuit value the hash side committed to".
//
// Task 26 (invariant 2a, merged with former #30 SPKI binding) adds
// the CMS content signature leg. The key that signed the content is
// NOT the JSON-embedded wallet pubkey (invariant 4's pk, which is
// secp256k1 for the Ethereum wallet being authorized) — it's the
// holder's QTSP-issued P-256 signing key, embedded as the
// SubjectPublicKeyInfo inside cert_tbs. Promoting that cert SPKI to
// the public blob would leak holder identity (a privacy regression),
// so instead we extract it from cert_tbs on the hash side (via a
// byte-range route at a host-witnessed offset, anchored by a 26-byte
// P-256 SPKI prefix assertion) and MAC-bind its X and Y coordinates
// across the hash/sig field split as two additional messages. The
// sig circuit consumes `holder_pk_x` and `holder_pk_y` as PRIVATE
// EltW inputs, unpacked from the MAC witnesses — the same pattern
// mdoc uses for `dpkx_` / `dpky_`.
//
// The sig circuit now proves:
//
//   (A) (r1, s1) is valid ECDSA on `e`  under anchor root_pk (invariant 1)
//   (B) (r2, s2) is valid ECDSA on `e2` under holder_pk     (invariant 2a)
//   (C) `e`         cross-binds to SHA-256(cert_tbs)        (hash side)
//   (D) `e2`        cross-binds to SHA-256(signedAttrs)     (hash side)
//   (E) holder_pk_x cross-binds to cert_tbs SPKI X bytes    (hash side)
//   (F) holder_pk_y cross-binds to cert_tbs SPKI Y bytes    (hash side)
//
// `root_pk` is selected from a compile-time TrustAnchor[] table (see
// `kTrustAnchors` below) by the witness-driven `trust_anchor_index`
// public input. Phase 2b ships with N=2 (TestAnchorA + TestAnchorB,
// both synthetic; see Task #44). The sig circuit implements a one-hot
// multiplexer over the table indexed by `trust_anchor_index`, and the
// hash circuit asserts the witnessed index is in range
// (`< kTrustAnchorCount`). Real production anchors arrive with Task
// #37. `holder_pk_x` / `holder_pk_y` are PRIVATE Fp256Base EltW inputs
// in the sig circuit, bound to the hash circuit's cert_tbs SPKI bytes
// via MAC. Total bound messages = 4 (e, e2, SPKI_X, SPKI_Y); total MAC
// values = 8 (2 per message).
//
// Rationale for the MAC step remains the same as 25a: the ECDSA
// VerifyCircuit operates over Fp256Base, but the SHA-256 computations
// and cert-SPKI extraction happen on the hash side over GF(2^128).
// The MAC gives us a negligible-probability cross-field binding per
// message.

#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_P7S_SUB_P7S_SIGNATURE_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_P7S_SUB_P7S_SIGNATURE_H_

#include <cstddef>

#include "algebra/static_string.h"
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
// bumped to 4; the OPRF-fusion (feat/p7s-v13) bumps to 5:
//   message 0 = `e  = SHA-256(cert_tbs)`
//   message 1 = `e2 = SHA-256(signedAttrs_rewritten)`
//   message 2 = cert_tbs SPKI X coordinate (LE-ordered 32 bytes)
//   message 3 = cert_tbs SPKI Y coordinate (LE-ordered 32 bytes)
//   message 4 = `stable_id` — the cert-verified X.520 serialNumber
//               value (DIIA RNOKPP `TINUA-<10 digits>`, 16 bytes),
//               packed (LE-ordered, zero-padded) into ONE 256-bit
//               MAC message. This is the SOUNDNESS GATE for the OPRF:
//               the OPRF's `rnokpp` input on the sig side MUST equal
//               this cert-verified value, NOT a free witness. Without
//               this binding one valid cert could mint unlimited OPRF
//               identities (Sybil). See the doc on `kStableIdMacBytes`
//               in p7s_circuit.h for the UA-fixed-length constraint.
constexpr size_t kMacMessagesCount = 5;

// Message indices — keeps layout-dependent code (MAC index slicing,
// dense-array fillers, etc.) readable.
constexpr size_t kMacMsgIdxE        = 0;
constexpr size_t kMacMsgIdxE2       = 1;
constexpr size_t kMacMsgIdxSpkiX    = 2;
constexpr size_t kMacMsgIdxSpkiY    = 3;
constexpr size_t kMacMsgIdxStableId = 4;

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

// TestAnchorA synthetic root public key (Task #43a). Replaces the DIIA
// QTSP 2311 root that was baked into earlier Phase-2b commits; the
// synthetic fixtures produced by
// `crates/zk-eidas-p7s/src/bin/gen_synthetic_fixtures.rs` (seed
// "zk-eidas-test-anchor-A-root-v1") carry a signer cert whose sig
// verifies under this root.
//
// SEC1 uncompressed point hex:
//   0x04
//   0xe62c46fd4aeeef700e933114a1b85af927a007019f157e89f3ec8a36d4dc08a3  (X)
//   0xc327059b5cb8ef635db4fc15e3da7ef174332efd07b7ef3a35c4b69492a64c28  (Y)
// Decimal forms are baked in as compile-time string literals so
// `p256_base.of_string(...)` returns a Montgomery-form `Elt` without
// any runtime parsing ambiguity.
constexpr char kTestAnchorARootPkX_decimal[] =
    "10411018639600370223116240342174465648759973561081352565806674112222641861"
    "6483";
constexpr char kTestAnchorARootPkY_decimal[] =
    "88269951206551578807887439798916112555166422509420054001162626778754936359"
    "976";

// TestAnchorB synthetic root public key (Task #44). Second synthetic
// anchor so the N=2 multiplexer in `build_sig_circuit` is exercised
// by a real fixture. Produced by `gen_synthetic_fixtures.rs` with
// seed "zk-eidas-p7s-testanchor-b-root-v1"; the fixture pair
// `testanchor-b-binding.qkb.p7s` / `testanchor-b-admin-binding.qkb.p7s`
// carries a signer cert whose sig verifies under this root.
//
// SEC1 uncompressed point hex:
//   0x04
//   0x3a48db8f884948fb58ce44bc21a3deeb6e62ceb23c7a1384cf27d126c8ea0b9b  (X)
//   0xbaed0eeec7f234ced5e8b233cec71ed2346d1dbb3559acb2f5ccc1faa4778043  (Y)
constexpr char kTestAnchorBRootPkX_decimal[] =
    "26362873558568434135757859508946912507274750529511868229520166364868409691"
    "035";
constexpr char kTestAnchorBRootPkY_decimal[] =
    "84549035652812971100161935258006361651891028412283608100255874746995940229"
    "187";

// Real Diia QTSP CA P-256 root public keys (Phase 2b.3, §8.1). These
// are PUBLIC keys of Ukraine's "Diia" Qualified Trust Services Provider
// CA — the issuer of citizen QES leaf certs (subject
// `serialNumber=TINUA-<RNOKPP>`). Source:
//   http://ca.diia.gov.ua/uploads/certificates/diia_ecdsa.p7b
// (also Ukraine's national Trusted List). Two are pinned because the
// issuer rotates CA keys; both are valid leaf issuers in the Diia.Підпис
// ECDSA hierarchy (avoid the DSTU 4145 / RSA branches). A real citizen
// leaf (ECDSA-P256) verifies under the -2311 CA. SEC1 uncompressed.
//
// ROTATION GOVERNANCE (future): as Diia rotates CA keys the allowed set
// changes. A later enhancement makes the pinned set an admin-settable
// on-chain commitment (Merkle root of allowed CA keys) the circuit
// reads, rather than this compile-time table. A compile-time set is
// fine for now — rotation is rare and recompile-to-rotate is acceptable
// at this stage.
//
// UA-43395033-2311:
//   X 0x8500048265e919c1738e873572c1f6443895a0c03985fc71bd96a6f62a53bcc8
//   Y 0x69d23ca6e6a2a7dc443bbb2a0b914ee35f1c74e282ecd8e6c5287c7a3d4aee10
constexpr char kDiiaUA2311RootPkX_decimal[] =
    "60157639984085317032243857144591567409916300241404119731688357596981577891"
    "016";
constexpr char kDiiaUA2311RootPkY_decimal[] =
    "47864305589267125428873492369100630325836418204952516382052455720647888924"
    "176";
// UA-43395033-2503:
//   X 0xc8b3546f4a34c021a31b3578057d1de304cbf1743a391b2032cd5b7d37184148
//   Y 0xc2440ea2fba10872b0bc90a92371ad50f59d0e9c0216ed52fd259b8a8cc9ee54
constexpr char kDiiaUA2503RootPkX_decimal[] =
    "90779418088310628816706020968158030531241837634267785377256434346519973871"
    "944";
constexpr char kDiiaUA2503RootPkY_decimal[] =
    "87868939244018454967800774829639315729556263329937970677956700290484567404"
    "116";

// ===========================================================================
// Trust-anchor table (Task 36; N=2 by Task #44; N=4 by Phase 2b.3).
// Compile-time array of ETSI-compliant QTSP root pubkeys. The witness-
// driven `trust_anchor_index` (a v32 public-input wire on the hash
// side) selects which row the sig circuit's cert-sig ECDSA verifies
// under, via a general one-hot / Lagrange selector in build_sig_circuit
// (sound for any N — see there).
//
// Index order (Phase 3's Rust `TRUST_ANCHOR_PROBES` MUST mirror this):
//   0  TestAnchorA  (synthetic) — the synthetic fixture cert is signed
//                                 by this key; KEEP for tests.
//   1  TestAnchorB  (synthetic)
//   2  Diia UA-43395033-2311 (REAL Diia QTSP CA P-256 root)
//   3  Diia UA-43395033-2503 (REAL Diia QTSP CA P-256 root)
// Real citizen proofs select index 2 or 3; synthetic test fixtures
// select 0 (or 1). The real-vs-synthetic split is fine: invariant 1's
// ECDSA verifies the leaf TBS under whichever key the index selects, so
// a fixture signed by TestAnchorA only verifies at index 0.
//
// All current anchors share:
//   * P-256 (prime256v1) curve — prime256v1 OID baked into the 26-byte
//     P-256 SPKI DER prefix the hash circuit asserts on cert_tbs.
//   * SEC1 uncompressed SubjectPublicKeyInfo layout.
//   * ETSI EN 319 411 QCP-n-qscd issuance policy (implied by SPKI
//     shape; not directly asserted in-circuit).
//
// If a future anchor uses a different curve / algorithm identifier,
// the 26-byte SPKI prefix anchor at `kSpkiP256Prefix` has to become
// per-entry (flagged as Task #36.0 follow-up). For the current table
// every entry is P-256, so the anchor stays universal.
struct TrustAnchor {
  // Compile-time decimal representations of the root public key.
  // Wrapped in `StaticString` so `FpGeneric::of_string` can consume
  // them via its non-templated overload (the templated
  // `of_string(const char (&)[N])` needs an array type and wouldn't
  // deduce N from a field access path).
  StaticString root_pk_x_decimal;
  StaticString root_pk_y_decimal;

  // Human-readable metadata for diagnostics / logging. Never consumed
  // by the circuit.
  const char* name;
};

// `const` (not `constexpr`) because `StaticString`'s constructor isn't
// constexpr in the upstream header — runtime-initialized at process
// start, indexed by value like a const lookup table. `kTrustAnchorCount`
// stays `constexpr` because `sizeof` is compile-time.
inline const TrustAnchor kTrustAnchors[] = {
    // Index 0 — TestAnchorA (synthetic, Task #43a). Replaces the
    // DIIA QTSP 2311 anchor that was present before the PII scrub;
    // the decimal constants above were regenerated by
    // `gen_synthetic_fixtures`. A real production anchor returns when
    // #37 lands non-PII multi-QTSP fixtures.
    {
        StaticString(kTestAnchorARootPkX_decimal),
        StaticString(kTestAnchorARootPkY_decimal),
        "TestAnchorA (synthetic, P-256)",
    },
    // Index 1 — TestAnchorB (synthetic, Task #44). Second synthetic
    // anchor so the N=2 multiplexer in `build_sig_circuit` is a real
    // 2-way mux rather than a degenerate "pick entry 0" shortcut.
    // Fixtures: `testanchor-b-binding.qkb.p7s` /
    // `testanchor-b-admin-binding.qkb.p7s`.
    {
        StaticString(kTestAnchorBRootPkX_decimal),
        StaticString(kTestAnchorBRootPkY_decimal),
        "TestAnchorB (synthetic, P-256)",
    },
    // Index 2 — REAL Diia QTSP CA root UA-43395033-2311 (Phase 2b.3).
    {
        StaticString(kDiiaUA2311RootPkX_decimal),
        StaticString(kDiiaUA2311RootPkY_decimal),
        "Diia UA-43395033-2311 (real QTSP CA, P-256)",
    },
    // Index 3 — REAL Diia QTSP CA root UA-43395033-2503 (Phase 2b.3).
    {
        StaticString(kDiiaUA2503RootPkX_decimal),
        StaticString(kDiiaUA2503RootPkY_decimal),
        "Diia UA-43395033-2503 (real QTSP CA, P-256)",
    },
    // Future QTSP entries appended here (rotation → on-chain Merkle set).
};

constexpr size_t kTrustAnchorCount =
    sizeof(kTrustAnchors) / sizeof(TrustAnchor);

// Sanity: the table must be non-empty, or the circuit has no anchor
// to verify against. Any refactor that zeroed the table would fail
// this at compile time.
static_assert(kTrustAnchorCount >= 1,
              "kTrustAnchors must contain at least one entry");

// General N-entry selector (Phase 2b.3): the sig circuit's cert-sig
// ECDSA verifies under a `(root_pk_x, root_pk_y)` pair selected from
// `kTrustAnchors[]` by a Lagrange / one-hot selector over the public
// `trust_anchor_index` wire (see build_sig_circuit). The hash circuit
// still asserts `vlt(trust_anchor_index, kTrustAnchorCount)`; the sig
// circuit independently asserts `prod_{i<N}(idx - i) == 0` (idx is one
// of {0..N-1}) and selects `Σ_i L_i(idx)·k_i`, so out-of-range / forged
// indices fail closed and exactly the selected anchor's key is used.
// Appending an anchor is purely additive: extend the table here, extend
// `TRUST_ANCHOR_PROBES` in `parser.rs` in the same order; the selector
// picks up the new row automatically (no N hard-coded in the circuit).

// Bit-width of the `trust_anchor_index` wire the hash circuit reads
// from the public blob. 32 is overkill for small N but matches the
// `u32 trust_anchor_index` in the v11 public blob layout and gives
// room for the foreseeable future. Any change requires bumping the
// host-side `kHashPubTrustAnchorIdx` and re-checking the blob layout.
constexpr size_t kTrustAnchorIndexBits = 32;

// Sig-circuit gadget — the Fp256Base half of the cross-field MAC,
// plus the ECDSA verifications. Mirrors the shape of `MdocSignature`:
// mdoc binds 3 messages and verifies 2 signatures; p7s binds 2
// messages (`e`, `e2`) and verifies 2 signatures (cert sig against
// the selected trust-anchor root, content sig against the user's
// holder_pk).
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
  //       the selected trust-anchor root pk;
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
  //   (G) `stable_id` cross-binds to the cert_tbs serialNumber bytes
  //       (hash side). `stable_id` is a PRIVATE Fp256Base EltW the
  //       caller declared via `eltw_input()`; its binding to the
  //       cert-verified X.520 serialNumber value is enforced by the
  //       MAC unpack_msg on `vw.macs_[4]`. The OPRF block (fused in a
  //       later step) recomposes the SAME field element from its
  //       `rnokpp` byte wires and asserts equality, so the OPRF input
  //       is provably the cert identity — the Sybil gate.
  void assert_signature(EltW root_pk_x, EltW root_pk_y, EltW holder_pk_x,
                        EltW holder_pk_y, EltW msg_e, EltW msg_e2,
                        EltW stable_id,
                        const v128 mac_e[kMacValuesPerMessage],
                        const v128 mac_e2[kMacValuesPerMessage],
                        const v128 mac_spki_x[kMacValuesPerMessage],
                        const v128 mac_spki_y[kMacValuesPerMessage],
                        const v128 mac_stable_id[kMacValuesPerMessage],
                        const v128& av, const Witness& vw) const {
    Ecdsa ecc(lc_, ec_, order_);

    // Invariant 1 — cert sig over e under the selected trust-anchor root.
    ecc.verify_signature3(root_pk_x, root_pk_y, msg_e, vw.ecdsa_cert_);

    // Invariant 2a — CMS content sig over e2 under the holder pk.
    ecc.verify_signature3(holder_pk_x, holder_pk_y, msg_e2,
                          vw.ecdsa_content_);

    // MAC gadget — per-message cross-field binding. Same `av` across
    // all five (sampled once from the shared transcript post-commit);
    // per-message `ap` committed pre-commit in the mac witnesses.
    mac macc(lc_);
    macc.verify_mac(msg_e,       mac_e,         av, vw.macs_[kMacMsgIdxE],        order_);
    macc.verify_mac(msg_e2,      mac_e2,        av, vw.macs_[kMacMsgIdxE2],       order_);
    macc.verify_mac(holder_pk_x, mac_spki_x,    av, vw.macs_[kMacMsgIdxSpkiX],    order_);
    macc.verify_mac(holder_pk_y, mac_spki_y,    av, vw.macs_[kMacMsgIdxSpkiY],    order_);
    macc.verify_mac(stable_id,   mac_stable_id, av, vw.macs_[kMacMsgIdxStableId], order_);
  }
};

}  // namespace p7s
}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_P7S_SUB_P7S_SIGNATURE_H_
