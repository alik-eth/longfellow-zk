// Copyright 2026 Oleksandr Vovkotrub. Apache-2.0.
//
// HexDecode — assert that a run of ASCII lowercase hex characters
// (`'0'..'9' | 'a'..'f'`) decodes to a given byte sequence.
//
// Soundness shape (bit-level decomposition, tight in GF(2^128)):
//   For each output byte `b` and its two source hex chars `h_hi, h_lo`:
//     1. The prover witnesses nibble values `hi, lo : v8` with their upper
//        four bits asserted zero (`vassert0`). This makes `hi, lo ∈ [0, 15]`.
//     2. The byte's low four bits match `lo.bit[0..4]` and the byte's high
//        four bits match `hi.bit[0..4]`, via per-bit `vassert_eq`. Bit
//        positions have fixed integer meaning, so this rules out the
//        nibble-overflow path (there is no "hi = 16+k, lo = -k" trick in
//        bit-level constraints).
//     3. Each source hex char is bound to its witnessed nibble via a
//        16-way multiplicative disjunction (Fermat-style product of
//        differences, mirroring mdoc_signature.h:132-138) over the packed
//        12-bit pair `(char, nibble_lo4)`:
//           probe    = as_scalar<12>({char.bits[0..8], nibble.bits[0..4]})
//           good     = prod_{k=0..15} (probe - valid_pair_k)
//           assert0(good)
//        The 12-bit pack is injective over GF(2^128) (basis elements
//        beta(0)..beta(11) are linearly independent), so `good == 0` is
//        satisfied iff (char, nibble) equals one of the 16 legal pairs.
//
// Result: three soundness layers — nibble range (step 1), byte packing
// (step 2), char/nibble lookup (step 3). Any tampering at any layer
// fails at constraint check, not at witness-fill time.
//
// Reuse target: invariants 5 (nonce), and — via its exported HEX_PAIRS
// table — any future JSON hex field.

#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_P7S_SUB_HEX_DECODE_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_P7S_SUB_HEX_DECODE_H_

#include <array>
#include <cstddef>
#include <cstdint>

namespace proofs {
namespace p7s {

// The 16 valid (char, nibble) pairs. `char` is ASCII, `nibble` is 0..15.
// Lowercase-only to match the JSON emitter in zk-eidas-p7s.
constexpr std::array<std::pair<uint8_t, uint8_t>, 16> kHexPairs = {{
    {'0', 0},  {'1', 1},  {'2', 2},  {'3', 3},
    {'4', 4},  {'5', 5},  {'6', 6},  {'7', 7},
    {'8', 8},  {'9', 9},  {'a', 10}, {'b', 11},
    {'c', 12}, {'d', 13}, {'e', 14}, {'f', 15},
}};

template <class LC>
class HexDecode {
 public:
  using Logic = LC;
  using BitW = typename LC::BitW;
  using EltW = typename LC::EltW;
  using Elt = typename LC::Elt;
  using v8 = typename LC::v8;

  explicit HexDecode(const LC& l) : l_(l) {}

  // Assert that `chars[0..2n]` is a hex encoding of `bytes[0..n]`, using
  // the prover-supplied nibble witness `hi_lo_nibbles[0..2n]`:
  //   chars[2i]   + hi_lo_nibbles[2i]   encode high nibble of bytes[i]
  //   chars[2i+1] + hi_lo_nibbles[2i+1] encode low  nibble of bytes[i]
  //
  // Each nibble is a v8 (8 bits); the upper 4 bits MUST be zero.
  void assert_decodes(const v8 chars[], const v8 bytes[],
                      const v8 hi_lo_nibbles[], size_t n) const {
    for (size_t i = 0; i < n; ++i) {
      const v8& h_hi = chars[2 * i];
      const v8& h_lo = chars[2 * i + 1];
      const v8& nib_hi = hi_lo_nibbles[2 * i];
      const v8& nib_lo = hi_lo_nibbles[2 * i + 1];
      const v8& byte = bytes[i];

      // (1) Nibbles fit in 4 bits.
      assert_nibble_bounded(nib_hi);
      assert_nibble_bounded(nib_lo);

      // (2) Byte packing: byte.bit[0..4] == nib_lo.bit[0..4],
      //                   byte.bit[4..8] == nib_hi.bit[0..4].
      for (size_t j = 0; j < 4; ++j) {
        l_.assert_eq(byte[j], nib_lo[j]);
        l_.assert_eq(byte[j + 4], nib_hi[j]);
      }

      // (3) Char ↔ nibble lookup.
      assert_char_nibble(h_hi, nib_hi);
      assert_char_nibble(h_lo, nib_lo);
    }
  }

 private:
  const LC& l_;

  // Assert n.bit[4..8] == 0 (so n ∈ [0, 15]).
  void assert_nibble_bounded(const v8& n) const {
    for (size_t j = 4; j < 8; ++j) {
      (void)l_.assert0(n[j]);
    }
  }

  // Assert (char, nibble) ∈ kHexPairs via 16-way multiplicative
  // disjunction. Packing: 12-bit probe = char.bits[0..8] concatenated
  // with nibble.bits[0..4] (low nibble bits; upper bits of `nibble`
  // are already asserted zero by assert_nibble_bounded).
  //
  // Injectivity: as_scalar<12> maps distinct 12-bit patterns to distinct
  // field elements because the basis {beta(0), ..., beta(11)} is linearly
  // independent in any field Longfellow supports (prime or GF(2^k) with
  // k ≥ 12). The 16 valid probes are thus distinct, and the product
  // `prod_k (probe - valid_k)` is zero iff `probe` matches one of them.
  void assert_char_nibble(const v8& ch, const v8& nib) const {
    typename LC::template bitvec<12> packed;
    for (size_t j = 0; j < 8; ++j) packed[j] = ch[j];
    for (size_t j = 0; j < 4; ++j) packed[8 + j] = nib[j];

    EltW probe = l_.template as_scalar<12>(packed);

    EltW good = l_.mul(0, kHexPairs.size(), [&](size_t k) {
      return l_.sub(probe, l_.konst(valid_pair_elt(k)));
    });
    (void)l_.assert0(good);
  }

  // Compile-time computation of the k-th valid packed field element:
  //   valid_k = as_scalar<12>({bits_of_char[0..8], bits_of_nibble[0..4]})
  //
  // `as_scalar<N>` in Longfellow computes sum_i beta(i) * bit_i via
  // `of_scalar` on the bit pattern as a uint64_t. For that reason we can
  // precompute the integer pack directly.
  Elt valid_pair_elt(size_t k) const {
    const uint8_t ch = kHexPairs[k].first;
    const uint8_t nib = kHexPairs[k].second;
    // Bits 0..7: char, bits 8..11: low 4 bits of nibble.
    uint64_t pack = static_cast<uint64_t>(ch) |
                    (static_cast<uint64_t>(nib & 0x0f) << 8);
    return l_.elt(pack);
  }
};

}  // namespace p7s
}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_P7S_SUB_HEX_DECODE_H_
