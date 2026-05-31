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

#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_HASH2CURVE_EXPAND_XMD_WITNESS_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_HASH2CURVE_EXPAND_XMD_WITNESS_H_

#include <stddef.h>
#include <stdint.h>

#include <vector>

#include "circuits/sha/flatsha256_witness.h"
#include "util/panic.h"

/*
Host reference implementation of RFC 9380 section 5.3.1 expand_message_xmd
specialised to SHA-256 and len_in_bytes = 96 (count = 2, L = 48 for the suite
P256_XMD:SHA-256_SSWU_RO_, ell = ceil(96/32) = 3):

  DST_prime = DST || I2OSP(len(DST), 1)
  Z_pad     = I2OSP(0, 64)              (one full SHA-256 block of zeros)
  l_i_b     = I2OSP(96, 2) = 0x00 0x60
  b0 = SHA256( Z_pad || msg || l_i_b || 0x00 || DST_prime )
  b1 = SHA256( b0 || 0x01 || DST_prime )
  b2 = SHA256( (b0 XOR b1) || 0x02 || DST_prime )
  b3 = SHA256( (b0 XOR b2) || 0x03 || DST_prime )
  uniform_bytes = b1 || b2 || b3              (96 bytes)

This header also produces the pre-padded SHA input buffers and per-block
FlatSHA256Witness::BlockWitness arrays needed by the in-circuit gadget
(expand_xmd.h), mirroring the p7s_zk SHA-witness helpers.

The block bounds are fixed at compile time from the maximum message length so
the in-circuit gadget has a static wire count.  The gadget verifies the actual
block count via the SHA padding's trailing length field (the same
mechanism FlatSHA256Circuit::assert_zero_padding / find_len use), so sizing
for the maximum is sound.
*/
namespace proofs {

// len_in_bytes for the SSWU suite (count=2, L=48 -> 2*48 = 96).
inline constexpr size_t kXmdLenInBytes = 96;

// b0 SHA input payload length, before SHA padding:
//   Z_pad(64) || msg(kMsg) || l_i_b(2) || 0x00(1) || DST_prime(kDst+1)
inline constexpr size_t expand_xmd_b0_payload(size_t kMsg, size_t kDst) {
  return 64 + kMsg + 2 + 1 + (kDst + 1);
}
// bi (i>=1) SHA input payload length, before SHA padding:
//   b_im1(32) || I2OSP(i,1)(1) || DST_prime(kDst+1)
inline constexpr size_t expand_xmd_bi_payload(size_t kDst) {
  return 32 + 1 + (kDst + 1);
}
// Block count = ceil((payload + 9) / 64).
inline constexpr size_t expand_xmd_blocks(size_t payload) {
  return (payload + 9 + 63) / 64;
}

// Host output + circuit hints for a single expand_message_xmd evaluation.
template <size_t kMsgBytes, size_t kDstBytes>
struct ExpandXmdWitness {
  static constexpr size_t kB0Payload =
      expand_xmd_b0_payload(kMsgBytes, kDstBytes);
  static constexpr size_t kBiPayload = expand_xmd_bi_payload(kDstBytes);
  static constexpr size_t kB0Blocks = expand_xmd_blocks(kB0Payload);
  static constexpr size_t kBiBlocks = expand_xmd_blocks(kBiPayload);

  // SHA-256 outputs.
  uint8_t b0[32];
  uint8_t b1[32];
  uint8_t b2[32];
  uint8_t b3[32];
  uint8_t uniform_bytes[kXmdLenInBytes];  // b1 || b2 || b3

  // Pre-padded SHA input buffers (caller-padded per Merkle-Damgard).
  uint8_t in0[64 * kB0Blocks];
  uint8_t in1[64 * kBiBlocks];
  uint8_t in2[64 * kBiBlocks];
  uint8_t in3[64 * kBiBlocks];
  uint8_t numb0;  // actual block count used for b0 (<= kB0Blocks)
  uint8_t numb_i;  // actual block count used for b1/b2/b3 (<= kBiBlocks)

  // Per-block SHA witnesses.
  FlatSHA256Witness::BlockWitness bw0[kB0Blocks];
  FlatSHA256Witness::BlockWitness bw1[kBiBlocks];
  FlatSHA256Witness::BlockWitness bw2[kBiBlocks];
  FlatSHA256Witness::BlockWitness bw3[kBiBlocks];
};

// Pure byte-level reference (no SHA witnesses), generic over len_in_bytes,
// using a plain reference SHA-256 driven through FlatSHA256Witness.  This is
// the exact RFC 9380 5.3.1 algorithm and is used for the Appendix K.1 KATs
// (which publish vectors for len_in_bytes 0x20 and 0x80, not the suite's
// 0x60).  Returns uniform_bytes (len_in_bytes long).
inline std::vector<uint8_t> sha256_host(const uint8_t* msg, size_t n) {
  // Drive the existing FlatSHA256Witness reference; max blocks = ceil((n+9)/64).
  size_t max = (n + 9 + 63) / 64;
  std::vector<uint8_t> in(64 * max);
  std::vector<FlatSHA256Witness::BlockWitness> bw(max);
  uint8_t numb = 0;
  FlatSHA256Witness::transform_and_witness_message(n, msg, max, numb, in.data(),
                                                    bw.data());
  std::vector<uint8_t> out(32);
  for (size_t j = 0; j < 8; ++j) {
    uint32_t hj = bw[numb - 1].h1[j];
    out[4 * j + 0] = (hj >> 24) & 0xff;
    out[4 * j + 1] = (hj >> 16) & 0xff;
    out[4 * j + 2] = (hj >> 8) & 0xff;
    out[4 * j + 3] = (hj >> 0) & 0xff;
  }
  return out;
}

inline std::vector<uint8_t> expand_message_xmd_bytes(const uint8_t* msg,
                                                     size_t msg_len,
                                                     const uint8_t* dst,
                                                     size_t dst_len,
                                                     size_t len_in_bytes) {
  check(dst_len <= 255, "DST too long for the short-DST path");
  size_t ell = (len_in_bytes + 31) / 32;
  check(ell <= 255, "ell too large");

  std::vector<uint8_t> dst_prime(dst, dst + dst_len);
  dst_prime.push_back(static_cast<uint8_t>(dst_len));

  // b0 = SHA256( Z_pad || msg || I2OSP(len,2) || 0x00 || DST_prime ).
  std::vector<uint8_t> m0;
  m0.insert(m0.end(), 64, 0x00);  // Z_pad
  m0.insert(m0.end(), msg, msg + msg_len);
  m0.push_back((len_in_bytes >> 8) & 0xff);
  m0.push_back(len_in_bytes & 0xff);
  m0.push_back(0x00);
  m0.insert(m0.end(), dst_prime.begin(), dst_prime.end());
  std::vector<uint8_t> b0 = sha256_host(m0.data(), m0.size());

  std::vector<std::vector<uint8_t>> b(ell + 1);
  b[0] = b0;
  for (size_t i = 1; i <= ell; ++i) {
    std::vector<uint8_t> mi(32);
    if (i == 1) {
      mi = b0;
    } else {
      for (size_t k = 0; k < 32; ++k) mi[k] = b0[k] ^ b[i - 1][k];
    }
    mi.push_back(static_cast<uint8_t>(i));
    mi.insert(mi.end(), dst_prime.begin(), dst_prime.end());
    b[i] = sha256_host(mi.data(), mi.size());
  }

  std::vector<uint8_t> out;
  for (size_t i = 1; i <= ell && out.size() < len_in_bytes; ++i) {
    out.insert(out.end(), b[i].begin(), b[i].end());
  }
  out.resize(len_in_bytes);
  return out;
}

// Compute expand_message_xmd(msg, DST, 96) and all SHA witnesses.
//   msg is exactly kMsgBytes long; dst is exactly kDstBytes long.
template <size_t kMsgBytes, size_t kDstBytes>
void expand_message_xmd(const uint8_t msg[kMsgBytes],
                        const uint8_t dst[kDstBytes],
                        ExpandXmdWitness<kMsgBytes, kDstBytes>& out) {
  check(kDstBytes <= 255, "DST too long for the short-DST path");

  // DST_prime = DST || len(DST).
  std::vector<uint8_t> dst_prime(kDstBytes + 1);
  for (size_t i = 0; i < kDstBytes; ++i) dst_prime[i] = dst[i];
  dst_prime[kDstBytes] = static_cast<uint8_t>(kDstBytes);

  // ---- b0 = SHA256( Z_pad || msg || l_i_b || 0x00 || DST_prime ) ----
  std::vector<uint8_t> msg0(out.kB0Payload);
  size_t p = 0;
  for (size_t i = 0; i < 64; ++i) msg0[p++] = 0x00;        // Z_pad
  for (size_t i = 0; i < kMsgBytes; ++i) msg0[p++] = msg[i];
  msg0[p++] = 0x00;                                        // l_i_b high
  msg0[p++] = 0x60;                                        // l_i_b low (96)
  msg0[p++] = 0x00;                                        // I2OSP(0,1)
  for (size_t i = 0; i < dst_prime.size(); ++i) msg0[p++] = dst_prime[i];
  check(p == out.kB0Payload, "b0 payload length mismatch");

  FlatSHA256Witness::transform_and_witness_message(
      out.kB0Payload, msg0.data(), out.kB0Blocks, out.numb0, out.in0, out.bw0);
  // The final-block running hash (H1 of block numb0-1) is b0, big-endian.
  for (size_t j = 0; j < 8; ++j) {
    uint32_t hj = out.bw0[out.numb0 - 1].h1[j];
    out.b0[4 * j + 0] = (hj >> 24) & 0xff;
    out.b0[4 * j + 1] = (hj >> 16) & 0xff;
    out.b0[4 * j + 2] = (hj >> 8) & 0xff;
    out.b0[4 * j + 3] = (hj >> 0) & 0xff;
  }

  // Helper to compute bi = SHA256( first32 || idx || DST_prime ).
  auto compute_bi = [&](const uint8_t first32[32], uint8_t idx,
                        uint8_t in[/*64*kBiBlocks*/],
                        FlatSHA256Witness::BlockWitness* bw, uint8_t bout[32]) {
    std::vector<uint8_t> mi(out.kBiPayload);
    size_t q = 0;
    for (size_t i = 0; i < 32; ++i) mi[q++] = first32[i];
    mi[q++] = idx;
    for (size_t i = 0; i < dst_prime.size(); ++i) mi[q++] = dst_prime[i];
    check(q == out.kBiPayload, "bi payload length mismatch");
    uint8_t numb;
    FlatSHA256Witness::transform_and_witness_message(
        out.kBiPayload, mi.data(), out.kBiBlocks, numb, in, bw);
    out.numb_i = numb;
    for (size_t j = 0; j < 8; ++j) {
      uint32_t hj = bw[numb - 1].h1[j];
      bout[4 * j + 0] = (hj >> 24) & 0xff;
      bout[4 * j + 1] = (hj >> 16) & 0xff;
      bout[4 * j + 2] = (hj >> 8) & 0xff;
      bout[4 * j + 3] = (hj >> 0) & 0xff;
    }
  };

  // b1 = SHA256( b0 || 0x01 || DST_prime ).
  compute_bi(out.b0, 0x01, out.in1, out.bw1, out.b1);

  // b2 = SHA256( (b0 XOR b1) || 0x02 || DST_prime ).
  uint8_t xb1[32];
  for (size_t i = 0; i < 32; ++i) xb1[i] = out.b0[i] ^ out.b1[i];
  compute_bi(xb1, 0x02, out.in2, out.bw2, out.b2);

  // b3 = SHA256( (b0 XOR b2) || 0x03 || DST_prime ).
  uint8_t xb2[32];
  for (size_t i = 0; i < 32; ++i) xb2[i] = out.b0[i] ^ out.b2[i];
  compute_bi(xb2, 0x03, out.in3, out.bw3, out.b3);

  // uniform_bytes = b1 || b2 || b3.
  for (size_t i = 0; i < 32; ++i) out.uniform_bytes[i] = out.b1[i];
  for (size_t i = 0; i < 32; ++i) out.uniform_bytes[32 + i] = out.b2[i];
  for (size_t i = 0; i < 32; ++i) out.uniform_bytes[64 + i] = out.b3[i];
}

}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_HASH2CURVE_EXPAND_XMD_WITNESS_H_
