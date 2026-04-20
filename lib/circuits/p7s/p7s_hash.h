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

// v1 bound: context length fits in 6 bits (<= 32 bytes, one SHA block).
// The derived context byte-length wire is a bitvec<6>.
constexpr size_t kContextLenBits = 6;

template <class LC>
class P7sHash {
 public:
  using Logic = LC;
  using BitW = typename Logic::BitW;
  using v8 = typename Logic::v8;
  using v64 = typename Logic::v64;
  using v256 = typename Logic::v256;
  using FlatSha = FlatSHA256Circuit<Logic, BitPlucker<Logic, kP7sPluckerBits>>;
  using ShaBlockWitness = typename FlatSha::BlockWitness;
  using ContextLenBV = typename Logic::template bitvec<kContextLenBits>;

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

  // Derive the context byte length from the SHA-256 padding's 64-bit
  // trailing length field and return it as a kContextLenBits-wide
  // bitvec. Asserts that:
  //   * the bottom 3 bits of the bit-length are zero (byte-aligned), and
  //   * bits above kContextLenBits + 3 are zero (len ≤ kContextMaxBytes).
  //
  // Binding the byte-length to the SHA padding guarantees the byte-range
  // check in `assert_context_equals` sees the same length the SHA-256
  // invariant uses — closes off the "prover claims one length, pads with
  // another" attack without introducing an independent context_len wire.
  ContextLenBV derive_context_byte_len(const v8 in[64 * kContextMaxBlocks],
                                       const v8& nb) const {
    v64 len_bits = sha_.find_len(kContextMaxBlocks, in, nb);

    // Byte alignment: bit-length must be a multiple of 8.
    l_.assert0(len_bits[0]);
    l_.assert0(len_bits[1]);
    l_.assert0(len_bits[2]);

    // Cap: bit-length <= kContextMaxBytes * 8 = 2^(kContextLenBits + 3).
    for (size_t i = kContextLenBits + 3; i < 64; ++i) {
      l_.assert0(len_bits[i]);
    }

    ContextLenBV out;
    for (size_t i = 0; i < kContextLenBits; ++i) {
      out[i] = len_bits[i + 3];
    }
    return out;
  }

  // Assert invariant 6:
  //   For each i in [0, kContextMaxBytes), if i < context_len then
  //   `in[i] == window[i]`. Here `window` is an `shift`-extracted view
  //   of `signed_content` starting at `json_context_offset`.
  //
  // Padding bytes (i >= context_len) are unconstrained: they are SHA
  // padding bytes (0x80, 0x00..., big-endian length) which need not
  // match the signed_content layout.
  void assert_context_equals(const v8 in[64 * kContextMaxBlocks],
                             const v8 window[kContextMaxBytes],
                             const ContextLenBV& context_len) const {
    for (size_t i = 0; i < kContextMaxBytes; ++i) {
      BitW in_range = l_.vlt(i, context_len);
      BitW bytes_eq = l_.veq(in[i], window[i]);
      l_.assert_implies(in_range, bytes_eq);
    }
  }

 private:
  const Logic& l_;
  FlatSha sha_;
};

}  // namespace p7s
}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_P7S_P7S_HASH_H_
