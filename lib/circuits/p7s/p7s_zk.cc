// Copyright 2026 Oleksandr Vovkotrub. Apache-2.0.
//
// Phase 2a p7s circuit — blob protocol (schema v3).
//
// Invariants enforced by the current circuit:
//   (9)  context_hash == SHA-256(context_bytes)                 — Task 1b
//   (4)  signed_content[pk_offset..+130] == pk_hex              — Task 20
//        AND pk_hex decodes to public.pk (65 bytes)             — Task 20
//   (5)  signed_content[nonce_offset..+64] == nonce_hex         — Task 21
//        AND nonce_hex decodes to public.nonce (32 bytes)       — Task 21
//
// -----------------------------------------------------------------------------
// Blob protocol — schema history
// -----------------------------------------------------------------------------
//   v1 (Task 1a, 1b): typed C args for context_hash + context_bytes.
//                     Removed in Task 20 in favor of byte-blobs so additional
//                     witness fields can land without per-task ABI churn.
//
//   v2 (Task 20):
//     Witness blob (little-endian):
//       u32  version                = 2
//       u32  context_len            in [0, 32]
//       u8   context[32]            padded with zeros
//       u32  signed_content_len     in [0, 1024]
//       u8   signed_content[1024]   padded with zeros
//       u32  json_pk_offset         relative to signed_content; + 130 <= 1024
//       u8   pk_hex[130]            ASCII lowercase hex
//
//     Public blob (little-endian):
//       u32  version                = 2
//       u8   context_hash[32]
//       u8   pk[65]
//
//   v3 (Task 21): adds nonce field appended to both blobs.
//     Witness blob extends v2 with:
//       u32  json_nonce_offset      relative to signed_content; + 64 <= 1024
//       u8   nonce_hex[64]          ASCII lowercase hex
//
//     Public blob extends v2 with:
//       u8   nonce[32]              decoded freshness nonce
// -----------------------------------------------------------------------------

#include "p7s_zk.h"

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <mutex>
#include <vector>

#include "arrays/dense.h"
#include "circuits/compiler/compiler.h"
#include "circuits/logic/bit_plucker_encoder.h"
#include "circuits/logic/compiler_backend.h"
#include "circuits/logic/logic.h"
#include "circuits/logic/routing.h"
#include "circuits/p7s/p7s_circuit.h"
#include "circuits/p7s/p7s_hash.h"
#include "circuits/p7s/sub/byte_range_eq.h"
#include "circuits/p7s/sub/hex_decode.h"
#include "circuits/sha/flatsha256_witness.h"
#include "gf2k/gf2_128.h"
#include "gf2k/lch14_reed_solomon.h"
#include "proto/circuit.h"
#include "random/secure_random_engine.h"
#include "random/transcript.h"
#include "sumcheck/circuit.h"
#include "util/readbuffer.h"
#include "zk/zk_proof.h"
#include "zk/zk_prover.h"
#include "zk/zk_verifier.h"

namespace proofs {
namespace p7s {
namespace {

using F = GF2_128<>;
using RSFactory = LCH14ReedSolomonFactory<F>;
using CB = CompilerBackend<F>;
using LC = Logic<F, CB>;
using P7sHashC = P7sHash<LC>;
using ByteRangeEqC = ByteRangeEq<LC>;
using HexDecodeC = HexDecode<LC>;
using RoutingC = Routing<LC>;
using ShaBlockWitness = P7sHashC::ShaBlockWitness;

// Ligero parameters — match zk_testing.h's kLigeroRate / kLigeroNreq so
// Task-20 proofs have the same statistical-soundness margin as the
// reference regression tests.
constexpr size_t kRate = 4;
constexpr size_t kNreq = 189;

// Transcript seed. Bumped from "p7s-20" so proofs minted under the
// Task-20 circuit cannot be misinterpreted as Task-21 proofs.
constexpr char kTranscriptSeed[] = "p7s-21";
constexpr size_t kTranscriptSeedLen = sizeof(kTranscriptSeed) - 1;

constexpr size_t kShaBlockBytes = 64;
constexpr size_t kContextPaddedBytes = kShaBlockBytes * kContextMaxBlocks;

// log2(1024) = 10. `json_pk_offset` fits in 10 bits.
constexpr size_t kSignedContentLogN = 10;
static_assert((size_t{1} << kSignedContentLogN) == kMaxSignedContent,
              "kSignedContentLogN must equal log2(kMaxSignedContent)");

// Blob schema version.
constexpr uint32_t kBlobSchemaVersion = 3;

// Build the Task-20 circuit.
std::unique_ptr<Circuit<F>> build_circuit() {
  const F Fs;

  QuadCircuit<F> Q(Fs);
  const CB cbk(&Q);
  const LC lc(&cbk, Fs);
  P7sHashC ph(lc);
  ByteRangeEqC breq(lc);
  HexDecodeC hex_decode(lc);
  RoutingC routing(lc);

  // ---- Public inputs ----
  // Invariant 9 target (context_hash, bit-decomposed, 256 bits).
  auto context_hash = lc.template vinput<256>();

  // Invariant 4 target (decoded pk, 65 bytes → 65 v8 values).
  std::vector<typename LC::v8> pk_bytes(kPkBytes);
  for (size_t i = 0; i < kPkBytes; ++i) {
    pk_bytes[i] = lc.template vinput<8>();
  }

  // Invariant 5 target (decoded nonce, 32 bytes → 32 v8 values).
  std::vector<typename LC::v8> nonce_bytes(kNonceBytes);
  for (size_t i = 0; i < kNonceBytes; ++i) {
    nonce_bytes[i] = lc.template vinput<8>();
  }

  // ---- Private witness ----
  Q.private_input();

  // Invariant 9 SHA witness.
  auto numb = lc.template vinput<8>();
  std::vector<typename LC::v8> context_in(kContextPaddedBytes);
  for (size_t i = 0; i < kContextPaddedBytes; ++i) {
    context_in[i] = lc.template vinput<8>();
  }
  std::vector<ShaBlockWitness> bw(kContextMaxBlocks);
  for (size_t b = 0; b < kContextMaxBlocks; ++b) {
    bw[b].input(lc);
  }

  // Invariant 4: full signed_content, json_pk_offset, pk_hex, nibble witnesses.
  std::vector<typename LC::v8> signed_content(kMaxSignedContent);
  for (size_t i = 0; i < kMaxSignedContent; ++i) {
    signed_content[i] = lc.template vinput<8>();
  }
  auto json_pk_offset = lc.template vinput<kSignedContentLogN>();

  std::vector<typename LC::v8> pk_hex(kPkHexLen);
  for (size_t i = 0; i < kPkHexLen; ++i) {
    pk_hex[i] = lc.template vinput<8>();
  }

  // Prover-supplied nibble witnesses — one v8 per hex char (upper 4 bits
  // get zero-asserted inside HexDecode::assert_decodes).
  std::vector<typename LC::v8> hi_lo_nibbles(kPkHexLen);
  for (size_t i = 0; i < kPkHexLen; ++i) {
    hi_lo_nibbles[i] = lc.template vinput<8>();
  }

  // Invariant 5: json_nonce_offset, nonce_hex, nonce_nibbles.
  auto json_nonce_offset = lc.template vinput<kSignedContentLogN>();
  std::vector<typename LC::v8> nonce_hex(kNonceHexLen);
  for (size_t i = 0; i < kNonceHexLen; ++i) {
    nonce_hex[i] = lc.template vinput<8>();
  }
  std::vector<typename LC::v8> nonce_nibbles(kNonceHexLen);
  for (size_t i = 0; i < kNonceHexLen; ++i) {
    nonce_nibbles[i] = lc.template vinput<8>();
  }

  // ---- Constraints ----

  // Invariant 9.
  ph.assert_context_hash(numb, context_in.data(), context_hash, bw.data());

  // Invariant 4a: signed_content[pk_offset..+130] == pk_hex.
  // Use the Routing shifter to extract the 130-byte window.
  std::vector<typename LC::v8> pk_window(kPkHexLen);
  const typename LC::v8 zz = lc.template vbit<8>(0);
  routing.template shift<typename LC::v8, kSignedContentLogN>(
      json_pk_offset, kPkHexLen, pk_window.data(), kMaxSignedContent,
      signed_content.data(), zz, /*unroll=*/3);
  breq.assert_eq(pk_window.data(), pk_hex.data(), kPkHexLen);

  // Invariant 4b: pk_hex decodes to public.pk.
  hex_decode.assert_decodes(pk_hex.data(), pk_bytes.data(),
                            hi_lo_nibbles.data(), kPkBytes);

  // Invariant 5a: signed_content[nonce_offset..+64] == nonce_hex.
  std::vector<typename LC::v8> nonce_window(kNonceHexLen);
  routing.template shift<typename LC::v8, kSignedContentLogN>(
      json_nonce_offset, kNonceHexLen, nonce_window.data(), kMaxSignedContent,
      signed_content.data(), zz, /*unroll=*/3);
  breq.assert_eq(nonce_window.data(), nonce_hex.data(), kNonceHexLen);

  // Invariant 5b: nonce_hex decodes to public.nonce.
  hex_decode.assert_decodes(nonce_hex.data(), nonce_bytes.data(),
                            nonce_nibbles.data(), kNonceBytes);

  return Q.mkcircuit(/*nc=*/1);
}

const Circuit<F>& get_circuit() {
  static std::mutex m;
  static std::unique_ptr<Circuit<F>> c;
  std::lock_guard<std::mutex> lock(m);
  if (!c) {
    c = build_circuit();
  }
  return *c;
}

// Push an 8-bit value as 8 wires, LSB-first.
void push_v8(DenseFiller<F>& filler, uint8_t x, const F& Fs) {
  filler.push_back(static_cast<uint64_t>(x), 8, Fs);
}

// Push a k-bit integer as k wires, LSB-first.
void push_uint(DenseFiller<F>& filler, uint64_t x, size_t k, const F& Fs) {
  filler.push_back(x, k, Fs);
}

// Push the context_hash as 256 target bits. Matches FlatSHA256Circuit's
// assert_hash layout: bit j of target corresponds to bit (j % 8) of byte
// ((255 - j) / 8).
void push_target(DenseFiller<F>& filler, const uint8_t context_hash[32],
                 const F& Fs) {
  for (size_t j = 0; j < 256; ++j) {
    size_t byte_idx = (255 - j) / 8;
    size_t bit_idx = j % 8;
    uint8_t bit = (context_hash[byte_idx] >> bit_idx) & 1;
    filler.push_back(bit ? Fs.one() : Fs.zero());
  }
}

// Push the decoded pk as 65 v8 values (LSB-first bits within each byte),
// matching the `lc.vinput<8>()` layout.
void push_pk_public(DenseFiller<F>& filler, const uint8_t pk[kPkBytes],
                    const F& Fs) {
  for (size_t i = 0; i < kPkBytes; ++i) {
    push_v8(filler, pk[i], Fs);
  }
}

// Push the decoded nonce as 32 v8 values.
void push_nonce_public(DenseFiller<F>& filler,
                       const uint8_t nonce[kNonceBytes], const F& Fs) {
  for (size_t i = 0; i < kNonceBytes; ++i) {
    push_v8(filler, nonce[i], Fs);
  }
}

// Push SHA private witness: numb + padded context bytes + per-block
// intermediates. Layout matches `build_circuit`'s private-input order.
void push_sha_witness(DenseFiller<F>& filler,
                      const uint8_t* context_bytes, size_t context_len,
                      const F& Fs) {
  uint8_t numb = 0;
  uint8_t padded_in[kContextPaddedBytes] = {};
  FlatSHA256Witness::BlockWitness bw[kContextMaxBlocks]{};
  FlatSHA256Witness::transform_and_witness_message(
      context_len, context_bytes, kContextMaxBlocks, numb, padded_in, bw);

  push_v8(filler, numb, Fs);
  for (size_t i = 0; i < kContextPaddedBytes; ++i) {
    push_v8(filler, padded_in[i], Fs);
  }

  BitPluckerEncoder<F, kP7sPluckerBits> bpenc(Fs);
  for (size_t b = 0; b < kContextMaxBlocks; ++b) {
    for (size_t k = 0; k < 48; ++k) {
      auto packed = bpenc.mkpacked_v32(bw[b].outw[k]);
      for (auto& e : packed) filler.push_back(e);
    }
    for (size_t k = 0; k < 64; ++k) {
      auto p_e = bpenc.mkpacked_v32(bw[b].oute[k]);
      auto p_a = bpenc.mkpacked_v32(bw[b].outa[k]);
      for (auto& e : p_e) filler.push_back(e);
      for (auto& e : p_a) filler.push_back(e);
    }
    for (size_t k = 0; k < 8; ++k) {
      auto packed = bpenc.mkpacked_v32(bw[b].h1[k]);
      for (auto& e : packed) filler.push_back(e);
    }
  }
}

// Decode a single lowercase-or-digit hex char to its nibble value. Any
// non-hex char is mapped to 0 so the HexDecode circuit can reject at
// constraint time rather than at witness-fill time.
uint8_t nibble_of(uint8_t c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return 0;
}

// Push invariant-4 private witness: signed_content (padded to 1024),
// json_pk_offset (10 bits), pk_hex (130 bytes), pk nibble witnesses.
void push_invariant4_witness(DenseFiller<F>& filler,
                             const uint8_t signed_content[kMaxSignedContent],
                             uint32_t json_pk_offset,
                             const uint8_t pk_hex[kPkHexLen],
                             const F& Fs) {
  for (size_t i = 0; i < kMaxSignedContent; ++i) {
    push_v8(filler, signed_content[i], Fs);
  }
  push_uint(filler, json_pk_offset, kSignedContentLogN, Fs);
  for (size_t i = 0; i < kPkHexLen; ++i) {
    push_v8(filler, pk_hex[i], Fs);
  }
  // Nibble witnesses derived from pk_hex: one v8 per hex char carrying the
  // decoded nibble in the low 4 bits and zero in the upper 4.
  for (size_t i = 0; i < kPkHexLen; ++i) {
    push_v8(filler, nibble_of(pk_hex[i]), Fs);
  }
}

// Push invariant-5 private witness: json_nonce_offset (10 bits),
// nonce_hex (64 bytes), nonce nibble witnesses.
void push_invariant5_witness(DenseFiller<F>& filler,
                             uint32_t json_nonce_offset,
                             const uint8_t nonce_hex[kNonceHexLen],
                             const F& Fs) {
  push_uint(filler, json_nonce_offset, kSignedContentLogN, Fs);
  for (size_t i = 0; i < kNonceHexLen; ++i) {
    push_v8(filler, nonce_hex[i], Fs);
  }
  for (size_t i = 0; i < kNonceHexLen; ++i) {
    push_v8(filler, nibble_of(nonce_hex[i]), Fs);
  }
}

// Read helpers for the little-endian blob format.
bool read_u32(const uint8_t*& p, const uint8_t* end, uint32_t& out) {
  if (end - p < 4) return false;
  out = static_cast<uint32_t>(p[0]) |
        (static_cast<uint32_t>(p[1]) << 8) |
        (static_cast<uint32_t>(p[2]) << 16) |
        (static_cast<uint32_t>(p[3]) << 24);
  p += 4;
  return true;
}

// Parsed witness blob (zero-padded to fixed array sizes).
struct ParsedWitness {
  uint32_t context_len;
  uint8_t context[kContextMaxBytes];
  uint32_t signed_content_len;
  uint8_t signed_content[kMaxSignedContent];
  uint32_t json_pk_offset;
  uint8_t pk_hex[kPkHexLen];
  uint32_t json_nonce_offset;
  uint8_t nonce_hex[kNonceHexLen];
};

// Parsed public blob.
struct ParsedPublic {
  uint8_t context_hash[32];
  uint8_t pk[kPkBytes];
  uint8_t nonce[kNonceBytes];
};

bool parse_witness_blob(const uint8_t* blob, size_t blob_len,
                        ParsedWitness& out) {
  if (blob == nullptr || blob_len == 0) return false;
  const uint8_t* p = blob;
  const uint8_t* end = blob + blob_len;

  uint32_t version = 0;
  if (!read_u32(p, end, version) || version != kBlobSchemaVersion) return false;

  if (!read_u32(p, end, out.context_len)) return false;
  if (out.context_len > kContextMaxBytes) return false;
  if (end - p < static_cast<ptrdiff_t>(kContextMaxBytes)) return false;
  std::memcpy(out.context, p, kContextMaxBytes);
  p += kContextMaxBytes;

  if (!read_u32(p, end, out.signed_content_len)) return false;
  if (out.signed_content_len > kMaxSignedContent) return false;
  if (end - p < static_cast<ptrdiff_t>(kMaxSignedContent)) return false;
  std::memcpy(out.signed_content, p, kMaxSignedContent);
  p += kMaxSignedContent;

  if (!read_u32(p, end, out.json_pk_offset)) return false;
  // `json_pk_offset + kPkHexLen <= kMaxSignedContent` ensures the shifted
  // window stays within the buffer. (The Routing shifter would zero-default
  // out-of-range reads, but we refuse obviously nonsensical offsets up
  // front so the pk_hex witness can't mask them.)
  if (out.json_pk_offset > kMaxSignedContent - kPkHexLen) return false;

  if (end - p < static_cast<ptrdiff_t>(kPkHexLen)) return false;
  std::memcpy(out.pk_hex, p, kPkHexLen);
  p += kPkHexLen;

  if (!read_u32(p, end, out.json_nonce_offset)) return false;
  if (out.json_nonce_offset > kMaxSignedContent - kNonceHexLen) return false;

  if (end - p < static_cast<ptrdiff_t>(kNonceHexLen)) return false;
  std::memcpy(out.nonce_hex, p, kNonceHexLen);
  p += kNonceHexLen;

  if (p != end) return false;
  return true;
}

bool parse_public_blob(const uint8_t* blob, size_t blob_len,
                       ParsedPublic& out) {
  if (blob == nullptr || blob_len == 0) return false;
  const uint8_t* p = blob;
  const uint8_t* end = blob + blob_len;

  uint32_t version = 0;
  if (!read_u32(p, end, version) || version != kBlobSchemaVersion) return false;

  if (end - p < 32) return false;
  std::memcpy(out.context_hash, p, 32);
  p += 32;

  if (end - p < static_cast<ptrdiff_t>(kPkBytes)) return false;
  std::memcpy(out.pk, p, kPkBytes);
  p += kPkBytes;

  if (end - p < static_cast<ptrdiff_t>(kNonceBytes)) return false;
  std::memcpy(out.nonce, p, kNonceBytes);
  p += kNonceBytes;

  if (p != end) return false;
  return true;
}

}  // namespace
}  // namespace p7s
}  // namespace proofs

extern "C" {

P7sErrorCode p7s_prove(const uint8_t* witness_blob, size_t witness_blob_len,
                       const uint8_t* public_blob, size_t public_blob_len,
                       uint8_t** proof_out, size_t* proof_len_out) {
  using namespace proofs;
  using namespace proofs::p7s;

  if (proof_out == nullptr || proof_len_out == nullptr) return P7S_NULL_INPUT;

  ParsedWitness wit{};
  if (!parse_witness_blob(witness_blob, witness_blob_len, wit)) {
    return P7S_INVALID_INPUT;
  }
  ParsedPublic pub{};
  if (!parse_public_blob(public_blob, public_blob_len, pub)) {
    return P7S_INVALID_INPUT;
  }

  const F Fs;
  const RSFactory rsf(Fs);
  const Circuit<F>& circuit = get_circuit();

  Dense<F> W(1, circuit.ninputs);
  DenseFiller<F> filler(W);
  filler.push_back(Fs.one());
  push_target(filler, pub.context_hash, Fs);
  push_pk_public(filler, pub.pk, Fs);
  push_nonce_public(filler, pub.nonce, Fs);
  push_sha_witness(filler, wit.context, wit.context_len, Fs);
  push_invariant4_witness(filler, wit.signed_content, wit.json_pk_offset,
                          wit.pk_hex, Fs);
  push_invariant5_witness(filler, wit.json_nonce_offset, wit.nonce_hex, Fs);

  if (filler.size() != circuit.ninputs) {
    return P7S_INVALID_INPUT;
  }

  ZkProof<F> zkp(circuit, kRate, kNreq);
  Transcript tp(reinterpret_cast<const uint8_t*>(kTranscriptSeed),
                kTranscriptSeedLen);
  SecureRandomEngine rng;
  ZkProver<F, RSFactory> prover(circuit, Fs, rsf);
  prover.commit(zkp, W, tp, rng);
  if (!prover.prove(zkp, W, tp)) {
    return P7S_PROVER_FAILURE;
  }

  std::vector<uint8_t> buf;
  zkp.write(buf, Fs);

  uint8_t* out = static_cast<uint8_t*>(malloc(buf.size()));
  if (!out) {
    return P7S_MEMORY_FAILURE;
  }
  memcpy(out, buf.data(), buf.size());
  *proof_out = out;
  *proof_len_out = buf.size();
  return P7S_SUCCESS;
}

P7sErrorCode p7s_verify(const uint8_t* public_blob, size_t public_blob_len,
                        const uint8_t* proof, size_t proof_len) {
  using namespace proofs;
  using namespace proofs::p7s;

  if (proof == nullptr) return P7S_NULL_INPUT;
  if (proof_len == 0) return P7S_INVALID_INPUT;

  ParsedPublic pub{};
  if (!parse_public_blob(public_blob, public_blob_len, pub)) {
    return P7S_INVALID_INPUT;
  }

  const F Fs;
  const RSFactory rsf(Fs);
  const Circuit<F>& circuit = get_circuit();

  ZkProof<F> zkp(circuit, kRate, kNreq);
  const std::vector<uint8_t> zbuf(proof, proof + proof_len);
  ReadBuffer rb(zbuf);
  if (!zkp.read(rb, Fs)) {
    return P7S_VERIFIER_FAILURE;
  }
  if (rb.remaining() != 0) {
    return P7S_VERIFIER_FAILURE;
  }

  Dense<F> pub_w(1, circuit.npub_in);
  DenseFiller<F> filler(pub_w);
  filler.push_back(Fs.one());
  push_target(filler, pub.context_hash, Fs);
  push_pk_public(filler, pub.pk, Fs);
  push_nonce_public(filler, pub.nonce, Fs);
  if (filler.size() != circuit.npub_in) {
    return P7S_INVALID_INPUT;
  }

  ZkVerifier<F, RSFactory> verifier(circuit, rsf, kRate, kNreq, Fs);
  Transcript tv(reinterpret_cast<const uint8_t*>(kTranscriptSeed),
                kTranscriptSeedLen);
  verifier.recv_commitment(zkp, tv);
  return verifier.verify(zkp, pub_w, tv) ? P7S_SUCCESS : P7S_VERIFIER_FAILURE;
}

void p7s_free_proof(uint8_t* proof) { free(proof); }

}  // extern "C"
