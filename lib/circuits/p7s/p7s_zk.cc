// Copyright 2026 Oleksandr Vovkotrub. Apache-2.0.
//
// Phase 2a Task 1b — invariant 9: context_hash == SHA-256(context_bytes).
//
// Adds a real SHA-256 constraint on top of the Task-1a hello-world. The
// circuit over f_128 (GF(2^128)) declares:
//
//   Public input:
//     target[256]                               — context_hash
//
//   Private witness:
//     numb[8]                                   — number of real SHA blocks
//     in[64 * kContextMaxBlocks] bytes          — Merkle-Damgård-padded input
//     BlockWitness × kContextMaxBlocks          — per-block SHA intermediates
//
//   Constraint:
//     FlatSHA256Circuit::assert_message_hash(numb, in, target, bw)
//     (implicitly enforces zero padding beyond `numb` blocks).
//
// Witness filling is done off-circuit via FlatSHA256Witness::
// transform_and_witness_message, which produces both the padded `in`
// buffer and all intermediate round witnesses.

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
#include "circuits/p7s/p7s_hash.h"
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
using ShaBlockWitness = P7sHashC::ShaBlockWitness;

// Ligero parameters — match zk_testing.h's kLigeroRate / kLigeroNreq so
// Task-1b proofs have the same statistical-soundness margin as the
// reference regression tests.
constexpr size_t kRate = 4;
constexpr size_t kNreq = 189;

// Transcript seed. Bumped from "p7s-1a" so proofs minted under the
// trivially-satisfiable circuit cannot be misinterpreted as Task-1b proofs.
constexpr char kTranscriptSeed[] = "p7s-1b";
constexpr size_t kTranscriptSeedLen = sizeof(kTranscriptSeed) - 1;

constexpr size_t kShaBlockBytes = 64;
constexpr size_t kContextPaddedBytes = kShaBlockBytes * kContextMaxBlocks;

// Build the Task-1b circuit.
std::unique_ptr<Circuit<F>> build_circuit() {
  const F Fs;

  QuadCircuit<F> Q(Fs);
  const CB cbk(&Q);
  const LC lc(&cbk, Fs);
  P7sHashC ph(lc);

  // Public input: the claimed context_hash.
  auto target = lc.template vinput<256>();

  // Private inputs.
  Q.private_input();
  auto numb = lc.template vinput<8>();

  std::vector<typename LC::v8> in_bytes(kContextPaddedBytes);
  for (size_t i = 0; i < kContextPaddedBytes; ++i) {
    in_bytes[i] = lc.template vinput<8>();
  }

  std::vector<ShaBlockWitness> bw(kContextMaxBlocks);
  for (size_t b = 0; b < kContextMaxBlocks; ++b) {
    bw[b].input(lc);
  }

  ph.assert_context_hash(numb, in_bytes.data(), target, bw.data());

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

// Push the context_hash as the 256-bit `target` public input wires.
// Matches FlatSHA256Circuit's `assert_hash` layout, which treats the
// 32 target bytes as big-endian byte order with LSB-first within each byte:
//   bit j of target corresponds to bit (j % 8) of byte ((255 - j) / 8).
void push_target(DenseFiller<F>& filler, const uint8_t context_hash[32],
                 const F& Fs) {
  for (size_t j = 0; j < 256; ++j) {
    size_t byte_idx = (255 - j) / 8;
    size_t bit_idx = j % 8;
    uint8_t bit = (context_hash[byte_idx] >> bit_idx) & 1;
    filler.push_back(bit ? Fs.one() : Fs.zero());
  }
}

// Push the SHA private witness (numb + padded bytes + per-block
// intermediates) into `filler`, matching the circuit's input declaration
// order inside the private-input section.
void push_sha_witness(DenseFiller<F>& filler,
                      const uint8_t* context_bytes, size_t context_len,
                      const F& Fs) {
  // Compute padded input and per-block witnesses off-circuit.
  uint8_t numb = 0;
  uint8_t padded_in[kContextPaddedBytes] = {};
  FlatSHA256Witness::BlockWitness bw[kContextMaxBlocks]{};
  FlatSHA256Witness::transform_and_witness_message(
      context_len, context_bytes, kContextMaxBlocks, numb, padded_in, bw);

  // numb as v8.
  push_v8(filler, numb, Fs);

  // Padded input bytes, each as 8 bits LSB-first.
  for (size_t i = 0; i < kContextPaddedBytes; ++i) {
    push_v8(filler, padded_in[i], Fs);
  }

  // Per-block FlatSHA intermediates. FlatSHA256Circuit uses packed_v32
  // wires with BitPlucker<LC, kP7sPluckerBits>; match the packing used
  // in flatsha256_circuit_test.cc::fill_input.
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

}  // namespace
}  // namespace p7s
}  // namespace proofs

extern "C" {

P7sErrorCode p7s_prove(const uint8_t context_hash[32], uint8_t** proof_out,
                       size_t* proof_len_out,
                       const uint8_t* context_bytes, size_t context_len) {
  using namespace proofs;
  using namespace proofs::p7s;

  if (context_hash == nullptr || proof_out == nullptr ||
      proof_len_out == nullptr) {
    return P7S_NULL_INPUT;
  }
  if (context_bytes == nullptr && context_len != 0) {
    return P7S_NULL_INPUT;
  }
  if (context_len > kContextMaxBytes) {
    return P7S_INVALID_INPUT;
  }

  const F Fs;
  const RSFactory rsf(Fs);

  const Circuit<F>& circuit = get_circuit();

  Dense<F> W(1, circuit.ninputs);
  DenseFiller<F> filler(W);
  filler.push_back(Fs.one());
  push_target(filler, context_hash, Fs);
  push_sha_witness(filler, context_bytes, context_len, Fs);

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

P7sErrorCode p7s_verify(const uint8_t context_hash[32], const uint8_t* proof,
                        size_t proof_len) {
  using namespace proofs;
  using namespace proofs::p7s;

  if (context_hash == nullptr || proof == nullptr) {
    return P7S_NULL_INPUT;
  }
  if (proof_len == 0) {
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

  // Public-input portion only: constant-1 wire + target.
  Dense<F> pub(1, circuit.npub_in);
  DenseFiller<F> filler(pub);
  filler.push_back(Fs.one());
  push_target(filler, context_hash, Fs);
  if (filler.size() != circuit.npub_in) {
    return P7S_INVALID_INPUT;
  }

  ZkVerifier<F, RSFactory> verifier(circuit, rsf, kRate, kNreq, Fs);
  Transcript tv(reinterpret_cast<const uint8_t*>(kTranscriptSeed),
                kTranscriptSeedLen);
  verifier.recv_commitment(zkp, tv);
  return verifier.verify(zkp, pub, tv) ? P7S_SUCCESS : P7S_VERIFIER_FAILURE;
}

void p7s_free_proof(uint8_t* proof) { free(proof); }

}  // extern "C"
