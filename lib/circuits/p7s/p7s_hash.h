// Copyright 2026 Oleksandr Vovkotrub. Apache-2.0.
//
// P7sHash — composes FlatSHA256Circuit to assert SHA-256(message) == target
// over messages bounded by `kMaxBlocks` SHA blocks.
//
// Instantiated twice in the current circuit:
//   * kMaxBlocks = 1  for invariant 9  (context_hash over ≤ 32 bytes, 1 block)
//   * kMaxBlocks = 16 for invariant 2b (messageDigest over ≤ 1024 bytes,
//                                       the `signed_content` byte array)
//
// The two instantiations share the same internal `FlatSha` wiring but
// carry independent witness/block arrays — enforced via the template
// parameter so type confusion between contexts and signed_content is a
// compile-time error.

#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_P7S_P7S_HASH_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_P7S_P7S_HASH_H_

#include <cstddef>
#include <cstdint>

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

// Context byte-length bitvec width (bitvec<6> spans 0..63, covers the
// 0..32 range for kContextMaxBytes).
constexpr size_t kContextLenBits = 6;

// v1 bound for signed_content SHA: 16 blocks × 64 bytes = 1024 bytes. The
// minimum SHA padding overhead is 9 bytes (0x80 + 64-bit length), so the
// longest representable signed_content is 1024 - 9 = 1015 bytes. The
// current QKB-format signed JSON is ~849 bytes — fits comfortably.
constexpr size_t kSignedContentMaxBlocks = 16;
constexpr size_t kSignedContentMaxBytes =
    kSignedContentMaxBlocks * 64;  // 1024

template <class LC, size_t kMaxBlocks>
class P7sHash {
 public:
  using Logic = LC;
  using BitW = typename Logic::BitW;
  using v8 = typename Logic::v8;
  using v64 = typename Logic::v64;
  using v256 = typename Logic::v256;
  using FlatSha = FlatSHA256Circuit<Logic, BitPlucker<Logic, kP7sPluckerBits>>;
  using ShaBlockWitness = typename FlatSha::BlockWitness;

  static constexpr size_t kBufferBytes = 64 * kMaxBlocks;

  explicit P7sHash(const Logic& l) : l_(l), sha_(l) {}

  // Assert `target` equals SHA-256 of the implicit message represented by
  // `(nb, in[kBufferBytes], bw[kMaxBlocks])`.
  //
  // `in` holds the pre-padded SHA input (caller pads per Merkle-Damgård
  // before filling the witness). `bw` holds the per-block intermediate
  // witness values produced by
  //   FlatSHA256Witness::transform_and_witness_message.
  void assert_message_hash(const v8& nb,
                           const v8 in[kBufferBytes],
                           const v256& target,
                           const ShaBlockWitness bw[kMaxBlocks]) const {
    sha_.assert_message_hash(kMaxBlocks, nb, in, target, bw);
  }

  // Derive the message byte length from the SHA-256 padding's 64-bit
  // trailing length field and return it as a `kLenBits`-wide bitvec.
  // Asserts that:
  //   * the bottom 3 bits of the bit-length are zero (byte-aligned), and
  //   * bits above `kLenBits + 3` are zero (len ≤ 2^kLenBits bytes).
  //
  // Binding the byte-length to the SHA padding guarantees downstream
  // byte-range checks see the same length the SHA-256 invariant uses —
  // closes off the "prover claims one length, pads with another" attack
  // without introducing an independent length wire.
  template <size_t kLenBits>
  typename Logic::template bitvec<kLenBits> derive_byte_len(
      const v8 in[kBufferBytes], const v8& nb) const {
    v64 len_bits = sha_.find_len(kMaxBlocks, in, nb);

    // Byte alignment: bit-length must be a multiple of 8.
    l_.assert0(len_bits[0]);
    l_.assert0(len_bits[1]);
    l_.assert0(len_bits[2]);

    // Cap: bit-length ≤ 2^(kLenBits + 3).
    for (size_t i = kLenBits + 3; i < 64; ++i) {
      l_.assert0(len_bits[i]);
    }

    typename Logic::template bitvec<kLenBits> out;
    for (size_t i = 0; i < kLenBits; ++i) {
      out[i] = len_bits[i + 3];
    }
    return out;
  }

 private:
  const Logic& l_;
  FlatSha sha_;
};

// Byte-length mask check for invariant 6: for each i in [0, N), if
// i < len then `a[i] == b[i]`. Free function so callers can pass any
// buffer shapes (context's SHA `in[]` vs signed_content's `in[]`, vs
// a shift-extracted window).
template <class LC, size_t N, size_t kLenBits>
void assert_range_equals_masked(
    const LC& l, const typename LC::v8 a[N],
    const typename LC::v8 b[N],
    const typename LC::template bitvec<kLenBits>& len) {
  for (size_t i = 0; i < N; ++i) {
    typename LC::BitW in_range = l.vlt(i, len);
    typename LC::BitW bytes_eq = l.veq(a[i], b[i]);
    l.assert_implies(in_range, bytes_eq);
  }
}

// ---- v12 (Plan 1, 2026-04-27) — issuer-pseudonym privacy ---------
//
// The v12 hard fork introduces a 32-byte holder-side secret
// `holder_seed` (private witness) and three new public outputs:
//   * nullifier        = SHA-256(0x01 || holder_seed || context_hash)
//                        (rewritten invariant 7; was stable_id-bound in v11)
//   * enroll_commit    = SHA-256(0x03 || holder_seed)
//                        (invariant 14; bound to JSON `holder_seed_commit`
//                         hex via invariant 13; same `holder_seed` wires
//                         re-used = invariant 15 wire equality)
//   * enroll_nullifier = SHA-256(0x02 || stable_id || ENROLL_DOMAIN_SEP)
//                        (invariant 12; issuer-computable handle for
//                         sybil 1-write enforcement)
//
// `context_hash` is a 32-byte fixed-length value (the verifier-chosen
// scope, pre-hashed by the host) — replaces the variable-length
// `context_raw` window v11 used for the nullifier preimage.
//
// All constants must stay byte-for-byte in sync with the Rust mirror
// at `crates/zk-eidas-p7s-circuit/src/witness.rs` (HOLDER_SEED_LEN,
// ENROLL_*_LEN, DS_TAG_*, ENROLL_DOMAIN_SEP).

constexpr size_t kHolderSeedLen      = 32;  // private holder secret
constexpr size_t kContextHashLen     = 32;  // app context, pre-hashed
constexpr size_t kEnrollCommitLen    = 32;  // SHA-256(0x03 || holder_seed)
constexpr size_t kEnrollNullifierLen = 32;  // SHA-256(0x02 || stable_id || ENROLL_DOMAIN_SEP)

constexpr uint8_t kDsTagPerAppNullifier = 0x01;
constexpr uint8_t kDsTagEnrollNullifier = 0x02;
constexpr uint8_t kDsTagEnrollCommit    = 0x03;

// "zk-eidas-enroll!" — 16 bytes, ASCII, no NUL padding.
constexpr uint8_t kEnrollDomainSep[16] = {
    0x7a, 0x6b, 0x2d, 0x65, 0x69, 0x64, 0x61, 0x73,
    0x2d, 0x65, 0x6e, 0x72, 0x6f, 0x6c, 0x6c, 0x21,
};
constexpr size_t kEnrollDomainSepLen = 16;

}  // namespace p7s
}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_P7S_P7S_HASH_H_
