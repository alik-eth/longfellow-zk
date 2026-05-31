// Copyright 2026 Google LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_HASH2CURVE_EXPAND_XMD_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_HASH2CURVE_EXPAND_XMD_H_

#include <cstddef>
#include <cstdint>
#include <vector>

#include "arrays/dense.h"
#include "circuits/hash2curve/expand_xmd_witness.h"
#include "circuits/logic/bit_plucker.h"
#include "circuits/logic/bit_plucker_encoder.h"
#include "circuits/sha/flatsha256_circuit.h"

/*
In-circuit RFC 9380 section 5.3.1 expand_message_xmd(SHA-256) for the suite
P256_XMD:SHA-256_SSWU_RO_ (len_in_bytes = 96, ell = 3).  Mirrors P7sHash: the
SHA-256 invariant is asserted via FlatSHA256Circuit with a caller-pre-padded
input buffer + per-block BlockWitness.

The four SHA-256 calls (b0, b1, b2, b3) are each asserted against the message
preimage that is itself constructed in-circuit from the public/fixed DST and
the (private) msg bytes plus the previous block outputs.  This binds the SHA
witnesses to the actual expand_message_xmd preimages.

Exposes uniform_bytes = b1 || b2 || b3 as 96 v8 bytes.
*/
namespace proofs {

constexpr size_t kXmdPluckerBits = 2;

template <class LC, size_t kMsgBytes, size_t kDstBytes>
class ExpandMessageXmd {
 public:
  using Logic = LC;
  using BitW = typename Logic::BitW;
  using v8 = typename Logic::v8;
  using v256 = typename Logic::v256;
  using FlatSha = FlatSHA256Circuit<Logic, BitPlucker<Logic, kXmdPluckerBits>>;
  using ShaBlockWitness = typename FlatSha::BlockWitness;

  static constexpr size_t kB0Payload =
      expand_xmd_b0_payload(kMsgBytes, kDstBytes);
  static constexpr size_t kBiPayload = expand_xmd_bi_payload(kDstBytes);
  static constexpr size_t kB0Blocks = expand_xmd_blocks(kB0Payload);
  static constexpr size_t kBiBlocks = expand_xmd_blocks(kBiPayload);
  static constexpr size_t kB0Buf = 64 * kB0Blocks;
  static constexpr size_t kBiBuf = 64 * kBiBlocks;

  // Witness wiring for one expand evaluation.
  struct Witness {
    // SHA-256 outputs as bytes (b0..b3), used to assemble preimages.  These
    // are re-derived/bound below; carrying them as v8 keeps the byte algebra
    // simple while the SHA invariant pins them to the true hash.
    v8 b0[32];
    v8 b1[32];
    v8 b2[32];
    v8 b3[32];

    // Pre-padded SHA input buffers + block counts + block witnesses.
    v8 nb0;
    v8 in0[kB0Buf];
    ShaBlockWitness bw0[kB0Blocks];

    v8 nb1, nb2, nb3;
    v8 in1[kBiBuf];
    v8 in2[kBiBuf];
    v8 in3[kBiBuf];
    ShaBlockWitness bw1[kBiBlocks];
    ShaBlockWitness bw2[kBiBlocks];
    ShaBlockWitness bw3[kBiBlocks];

    // CompilerBackend input wiring.
    void input(const Logic& lc) {
      for (size_t i = 0; i < 32; ++i) b0[i] = lc.template vinput<8>();
      for (size_t i = 0; i < 32; ++i) b1[i] = lc.template vinput<8>();
      for (size_t i = 0; i < 32; ++i) b2[i] = lc.template vinput<8>();
      for (size_t i = 0; i < 32; ++i) b3[i] = lc.template vinput<8>();
      nb0 = lc.template vinput<8>();
      for (size_t i = 0; i < kB0Buf; ++i) in0[i] = lc.template vinput<8>();
      for (size_t b = 0; b < kB0Blocks; ++b) bw0[b].input(lc);
      nb1 = lc.template vinput<8>();
      nb2 = lc.template vinput<8>();
      nb3 = lc.template vinput<8>();
      for (size_t i = 0; i < kBiBuf; ++i) in1[i] = lc.template vinput<8>();
      for (size_t i = 0; i < kBiBuf; ++i) in2[i] = lc.template vinput<8>();
      for (size_t i = 0; i < kBiBuf; ++i) in3[i] = lc.template vinput<8>();
      for (size_t b = 0; b < kBiBlocks; ++b) bw1[b].input(lc);
      for (size_t b = 0; b < kBiBlocks; ++b) bw2[b].input(lc);
      for (size_t b = 0; b < kBiBlocks; ++b) bw3[b].input(lc);
    }

    // EvaluationBackend: set from host hints.
    void set(const Logic& lc,
             const ExpandXmdWitness<kMsgBytes, kDstBytes>& h) {
      BitPluckerEncoder<typename Logic::Field, kXmdPluckerBits> enc(lc.f_);
      for (size_t i = 0; i < 32; ++i) b0[i] = lc.vbit8(h.b0[i]);
      for (size_t i = 0; i < 32; ++i) b1[i] = lc.vbit8(h.b1[i]);
      for (size_t i = 0; i < 32; ++i) b2[i] = lc.vbit8(h.b2[i]);
      for (size_t i = 0; i < 32; ++i) b3[i] = lc.vbit8(h.b3[i]);
      nb0 = lc.vbit8(h.numb0);
      for (size_t i = 0; i < kB0Buf; ++i) in0[i] = lc.vbit8(h.in0[i]);
      set_bw(lc, enc, bw0, h.bw0, kB0Blocks);
      nb1 = lc.vbit8(h.numb_i);
      nb2 = lc.vbit8(h.numb_i);
      nb3 = lc.vbit8(h.numb_i);
      for (size_t i = 0; i < kBiBuf; ++i) in1[i] = lc.vbit8(h.in1[i]);
      for (size_t i = 0; i < kBiBuf; ++i) in2[i] = lc.vbit8(h.in2[i]);
      for (size_t i = 0; i < kBiBuf; ++i) in3[i] = lc.vbit8(h.in3[i]);
      set_bw(lc, enc, bw1, h.bw1, kBiBlocks);
      set_bw(lc, enc, bw2, h.bw2, kBiBlocks);
      set_bw(lc, enc, bw3, h.bw3, kBiBlocks);
    }

    // CompilerBackend witness fill (round-trip).
    static void fill(DenseFiller<typename Logic::Field>& filler,
                     const typename Logic::Field& F,
                     const ExpandXmdWitness<kMsgBytes, kDstBytes>& h) {
      BitPluckerEncoder<typename Logic::Field, kXmdPluckerBits> enc(F);
      for (size_t i = 0; i < 32; ++i) push_byte(filler, F, h.b0[i]);
      for (size_t i = 0; i < 32; ++i) push_byte(filler, F, h.b1[i]);
      for (size_t i = 0; i < 32; ++i) push_byte(filler, F, h.b2[i]);
      for (size_t i = 0; i < 32; ++i) push_byte(filler, F, h.b3[i]);
      push_byte(filler, F, h.numb0);
      for (size_t i = 0; i < kB0Buf; ++i) push_byte(filler, F, h.in0[i]);
      fill_bw(filler, enc, h.bw0, kB0Blocks);
      push_byte(filler, F, h.numb_i);
      push_byte(filler, F, h.numb_i);
      push_byte(filler, F, h.numb_i);
      for (size_t i = 0; i < kBiBuf; ++i) push_byte(filler, F, h.in1[i]);
      for (size_t i = 0; i < kBiBuf; ++i) push_byte(filler, F, h.in2[i]);
      for (size_t i = 0; i < kBiBuf; ++i) push_byte(filler, F, h.in3[i]);
      fill_bw(filler, enc, h.bw1, kBiBlocks);
      fill_bw(filler, enc, h.bw2, kBiBlocks);
      fill_bw(filler, enc, h.bw3, kBiBlocks);
    }

   private:
    static void push_byte(DenseFiller<typename Logic::Field>& filler,
                          const typename Logic::Field& F, uint8_t v) {
      for (size_t i = 0; i < 8; ++i)
        filler.push_back((v >> i) & 1 ? F.one() : F.zero());
    }
    static void set_bw(const Logic& lc,
                       BitPluckerEncoder<typename Logic::Field,
                                         kXmdPluckerBits>& enc,
                       ShaBlockWitness* dst,
                       const FlatSHA256Witness::BlockWitness* src,
                       size_t nblk) {
      for (size_t b = 0; b < nblk; ++b) {
        for (size_t k = 0; k < 48; ++k)
          dst[b].outw[k] = lc.konst(enc.mkpacked_v32(src[b].outw[k]));
        for (size_t k = 0; k < 64; ++k) {
          dst[b].oute[k] = lc.konst(enc.mkpacked_v32(src[b].oute[k]));
          dst[b].outa[k] = lc.konst(enc.mkpacked_v32(src[b].outa[k]));
        }
        for (size_t k = 0; k < 8; ++k)
          dst[b].h1[k] = lc.konst(enc.mkpacked_v32(src[b].h1[k]));
      }
    }
    static void fill_bw(DenseFiller<typename Logic::Field>& filler,
                        BitPluckerEncoder<typename Logic::Field,
                                          kXmdPluckerBits>& enc,
                        const FlatSHA256Witness::BlockWitness* src,
                        size_t nblk) {
      for (size_t b = 0; b < nblk; ++b) {
        for (size_t k = 0; k < 48; ++k)
          for (auto& e : enc.mkpacked_v32(src[b].outw[k])) filler.push_back(e);
        for (size_t k = 0; k < 64; ++k) {
          for (auto& e : enc.mkpacked_v32(src[b].oute[k])) filler.push_back(e);
          for (auto& e : enc.mkpacked_v32(src[b].outa[k])) filler.push_back(e);
        }
        for (size_t k = 0; k < 8; ++k)
          for (auto& e : enc.mkpacked_v32(src[b].h1[k])) filler.push_back(e);
      }
    }
  };

  explicit ExpandMessageXmd(const Logic& l) : l_(l), sha_(l) {}

  // Build the (fixed-length) byte DST_prime = DST || len(DST) as v8 constants.
  void dst_prime(v8 out[kDstBytes + 1], const uint8_t dst[kDstBytes]) const {
    for (size_t i = 0; i < kDstBytes; ++i) out[i] = l_.vbit8(dst[i]);
    out[kDstBytes] = l_.vbit8(static_cast<uint8_t>(kDstBytes));
  }

  // Assert the expand and bind the b0..b3 byte wires to the true SHA outputs.
  // `msg` are the (private) message v8 bytes; `dst` is the fixed DST.
  // After this call, w.b1/b2/b3 (uniform_bytes) are pinned to the hashes.
  void assert_expand(const v8 msg[kMsgBytes], const uint8_t dst[kDstBytes],
                     const Witness& w) const {
    v8 dstp[kDstBytes + 1];
    dst_prime(dstp, dst);

    // ---- bind b0 preimage: Z_pad(64) || msg || 00 60 || 00 || DST_prime ----
    assert_preimage_b0(msg, dstp, w);
    assert_sha(w.nb0, w.in0, w.b0, w.bw0, kB0Blocks);

    // ---- bind bi preimage (i>=1): first32 || idx || DST_prime ----
    // b1: first32 = b0
    assert_preimage_bi(w.in1, w.nb1, w.b0, 0x01, dstp);
    assert_sha(w.nb1, w.in1, w.b1, w.bw1, kBiBlocks);
    // b2: first32 = b0 XOR b1
    v8 xb1[32];
    for (size_t i = 0; i < 32; ++i) xb1[i] = l_.vxor(w.b0[i], w.b1[i]);
    assert_preimage_bi(w.in2, w.nb2, xb1, 0x02, dstp);
    assert_sha(w.nb2, w.in2, w.b2, w.bw2, kBiBlocks);
    // b3: first32 = b0 XOR b2
    v8 xb2[32];
    for (size_t i = 0; i < 32; ++i) xb2[i] = l_.vxor(w.b0[i], w.b2[i]);
    assert_preimage_bi(w.in3, w.nb3, xb2, 0x03, dstp);
    assert_sha(w.nb3, w.in3, w.b3, w.bw3, kBiBlocks);
  }

  // uniform_bytes = b1 || b2 || b3 (96 bytes), exposed as v8[96].
  void uniform_bytes(const Witness& w, v8 out[96]) const {
    for (size_t i = 0; i < 32; ++i) out[i] = w.b1[i];
    for (size_t i = 0; i < 32; ++i) out[32 + i] = w.b2[i];
    for (size_t i = 0; i < 32; ++i) out[64 + i] = w.b3[i];
  }

 private:
  // target v256 from 32 big-endian output bytes (bit layout per assert_hash).
  v256 target_of(const v8 b32[32]) const {
    // assert_hash unpacks the hash into a v256 in REVERSE byte order: byte j of
    // the hash sits at v256 indices [(7-? )...].  The flatsha256 test builds
    // target as: target[k] = bit (hash[(255-k)/8] >> (k%8)).  For a 32-byte
    // big-endian hash, that means v256 index k corresponds to byte (255-k)/8,
    // bit (k%8).
    v256 t;
    for (size_t k = 0; k < 256; ++k) {
      size_t byte = (255 - k) / 8;  // big-endian byte index 0..31
      size_t bit = k % 8;
      t[k] = b32[byte][bit];
    }
    return t;
  }

  void assert_sha(const v8& nb, const v8 in[], const v8 bout[32],
                  const ShaBlockWitness bw[], size_t nblk) const {
    v256 target = target_of(bout);
    sha_.assert_message_hash(nblk, nb, in, target, bw);
  }

  // Assert the b0 preimage bytes in w.in0 match Z_pad||msg||lib||00||DST_prime
  // for the active (= first kB0Payload) bytes.  SHA padding bytes after the
  // payload are checked by the SHA gadget's assert_zero_padding / find_len.
  void assert_preimage_b0(const v8 msg[kMsgBytes], const v8 dstp[kDstBytes + 1],
                          const Witness& w) const {
    size_t p = 0;
    for (size_t i = 0; i < 64; ++i) l_.vassert_eq(w.in0[p++], 0u);  // Z_pad
    for (size_t i = 0; i < kMsgBytes; ++i)
      l_.vassert_eq(w.in0[p++], msg[i]);
    l_.vassert_eq(w.in0[p++], 0x00u);  // l_i_b high
    l_.vassert_eq(w.in0[p++], 0x60u);  // l_i_b low = 96
    l_.vassert_eq(w.in0[p++], 0x00u);  // I2OSP(0,1)
    for (size_t i = 0; i < kDstBytes + 1; ++i)
      l_.vassert_eq(w.in0[p++], dstp[i]);
    assert_sha_len(w.in0, w.nb0, kB0Blocks, kB0Payload);
  }

  void assert_preimage_bi(const v8 in[], const v8& nb, const v8 first32[32],
                          uint8_t idx, const v8 dstp[kDstBytes + 1]) const {
    size_t p = 0;
    for (size_t i = 0; i < 32; ++i) l_.vassert_eq(in[p++], first32[i]);
    l_.vassert_eq(in[p++], static_cast<uint64_t>(idx));
    for (size_t i = 0; i < kDstBytes + 1; ++i)
      l_.vassert_eq(in[p++], dstp[i]);
    assert_sha_len(in, nb, kBiBlocks, kBiPayload);
  }

  // Pin the SHA message byte length (from the padding's trailing length field)
  // to the known payload length, so the prover cannot shift the payload.
  void assert_sha_len(const v8 in[], const v8& nb, size_t nblk,
                      size_t payload) const {
    typename Logic::v64 len = sha_.find_len(nblk, in, nb);
    typename Logic::v64 want = l_.template vbit<64>(payload * 8);
    l_.vassert_eq(len, want);
  }

  const Logic& l_;
  FlatSha sha_;
};

}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_HASH2CURVE_EXPAND_XMD_H_
