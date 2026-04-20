// Copyright 2026 Oleksandr Vovkotrub. Apache-2.0.
//
// P7sSignature — Task 25a dual-circuit MAC binding gadget.
//
// Wires the sig-circuit (over Fp256Base) half of the cross-field MAC
// primitive defined in `circuits/mac/mac_circuit.h`. The hash-circuit
// half uses `MACGF2` directly over the native GF(2^128) backend; this
// class is the Fp256Base counterpart that the sig-circuit needs to
// bind the same 256-bit shared value.
//
// In Task 25a the shared value is a **compile-time non-zero sentinel**
// (see `kMacBindingSentinel` below). Task 29 (25b) swaps the sentinel
// for `e = SHA-256(cert_tbs)` and adds the ECDSA verification around
// this same plumbing — so this class is an intentionally thin
// scaffold that will grow (not get refactored out) when 25b lands.
//
// Rationale for the non-zero sentinel: the MAC primitive is only
// unforgeable when `x != 0` (see `mac_circuit.h:48-55`). A
// zero-message sentinel would degenerate the MAC arithmetic and the
// cross-circuit binding would silent-pass in tests without actually
// exercising the MAC.

#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_P7S_SUB_P7S_SIGNATURE_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_P7S_SUB_P7S_SIGNATURE_H_

#include <cstddef>

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
// the hash/sig field split. Task 25a (and 25b) binds just one — the
// cross-circuit hash `e`. Task 26 (invariant 2a) will bump this to 2
// when the content-signature MAC lands.
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
// sentinel (or, in 25b, `e`) without having to recompute 32.
constexpr size_t kMacMessageBytes = 32;

// Compile-time non-zero sentinel bound across both circuits in 25a.
// Defined in `p7s_signature.cc` so the constant survives across
// translation units. See header comment for the "why non-zero".
extern const unsigned char kMacBindingSentinel[kMacMessageBytes];

// Sig-circuit MAC binding gadget — the Fp256Base half of the cross-
// field MAC. Mirrors the shape of `MdocSignature` but carries only
// the MAC witness in 25a; the ECDSA witness lands in Task 29.
template <class LogicCircuit, class Field>
class P7sSignature {
  using EltW = typename LogicCircuit::EltW;
  using Nat = typename Field::N;
  using v128 = typename LogicCircuit::v128;
  using MacBitPlucker = BitPlucker<LogicCircuit, kMacPluckerBits>;
  using mac = MAC<LogicCircuit, MacBitPlucker>;

  const LogicCircuit& lc_;

 public:
  using MACWitness = typename mac::Witness;

  // Private witness bundle for the sig-circuit MAC check. One entry
  // per bound message (we have one; Task 26 will add a second).
  class Witness {
   public:
    MACWitness macs_[kMacMessagesCount];

    void input(const LogicCircuit& lc) {
      for (size_t i = 0; i < kMacMessagesCount; ++i) {
        macs_[i].input(lc);
      }
    }
  };

  explicit P7sSignature(const LogicCircuit& lc) : lc_(lc) {}

  // Assert `mac_values[2]` is a valid MAC of `msg_e` under key
  // `(ap + av)`, where `ap` is the prover's committed half of the
  // MAC key (inside `vw.macs_[0]`) and `av` is the verifier's
  // contribution sampled from the transcript after commit.
  //
  // `order` is the bound against which the bit-decomposition of
  // `msg_e` is range-checked inside the MAC primitive; pass
  // `Field::kModulus` (or equivalent) so the bitvec can represent
  // the full field but can't overflow into an ambiguous value.
  void assert_mac_binding(EltW msg_e, const v128 mac_values[kMacValuesPerMessage],
                          const v128& av, const Witness& vw, Nat order) const {
    mac macc(lc_);
    macc.verify_mac(msg_e, mac_values, av, vw.macs_[0], order);
  }
};

}  // namespace p7s
}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_P7S_SUB_P7S_SIGNATURE_H_
