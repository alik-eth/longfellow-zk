// Copyright 2026 Oleksandr Vovkotrub. Apache-2.0.
//
// P7sHash — composes FlatSHA256Circuit to assert the Phase 2a invariant:
//
//   9. context_hash == SHA-256(context_bytes)
//
// Analogous to MdocHash (circuits/mdoc/mdoc_hash.h) but with just the
// single SHA-256 constraint. As further invariants land in Phase 2a,
// additional assert_* methods can be added here without disturbing the
// existing call sites.

#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_P7S_P7S_HASH_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_P7S_P7S_HASH_H_

#include <cstddef>

#include "circuits/logic/bit_plucker.h"
#include "circuits/sha/flatsha256_circuit.h"

namespace proofs {
namespace p7s {

// Plucker packing used for FlatSHA256 intermediate wires. Matches the size
// used by the mdoc circuit (2) for consistency.
constexpr size_t kP7sPluckerBits = 2;

// v1 bound: CONTEXT_MAX_BYTES = 32 (a 256-bit symmetric ceiling). 32 + 9
// bytes of SHA-256 Merkle-Damgård overhead fit in one 64-byte block, so
// MAX_BLOCKS = 1. Bumping to 64 bytes is a recompile + new transcript tag.
constexpr size_t kContextMaxBytes = 32;
constexpr size_t kContextMaxBlocks = 1;

template <class LC>
class P7sHash {
 public:
  using Logic = LC;
  using v8 = typename Logic::v8;
  using v256 = typename Logic::v256;
  using FlatSha = FlatSHA256Circuit<Logic, BitPlucker<Logic, kP7sPluckerBits>>;
  using ShaBlockWitness = typename FlatSha::BlockWitness;

  explicit P7sHash(const Logic& l) : l_(l), sha_(l) {}

  // Assert invariant 9:
  //   `target` (the public context_hash) equals SHA-256 of the implicit
  //   message represented by `(nb, in[64 * kContextMaxBlocks], bw[])`.
  //
  // `in` holds the pre-padded SHA input (caller pads per Merkle-Damgård
  // before filling the witness). `bw` holds the per-block intermediate
  // witness values produced by FlatSHA256Witness::transform_and_witness_message.
  void assert_context_hash(const v8& nb,
                           const v8 in[64 * kContextMaxBlocks],
                           const v256& target,
                           const ShaBlockWitness bw[kContextMaxBlocks]) const {
    sha_.assert_message_hash(kContextMaxBlocks, nb, in, target, bw);
  }

 private:
  const Logic& l_;
  FlatSha sha_;
};

}  // namespace p7s
}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_P7S_P7S_HASH_H_
