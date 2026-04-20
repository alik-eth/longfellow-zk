// Copyright 2026 Oleksandr Vovkotrub. Apache-2.0.
//
// Phase 2a Task 1a — trivially-satisfiable hello-world circuit.
//
// The circuit declares context_hash[32] (256 bits) as a public input and
// imposes a single identity constraint. Used to validate the full
// Longfellow prove/verify loop end-to-end before the SHA-256 constraint
// lands in Task 1b.
//
// Field choice: f_128 (GF(2^128)). SHA-256 in Longfellow lives naturally
// over GF(2^128) via the Ligero framework; starting on the hash-field
// directly means Task 1b can reuse the same circuit/Dense layout.
//
// Caching: the compiled Circuit<f_128> is built once on first call and
// kept in a mutex-guarded static unique_ptr. Building is cheap (no
// constraints), but caching matches the pattern used by mdoc's cached
// circuits in the larger application.

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
#include "circuits/logic/compiler_backend.h"
#include "circuits/logic/logic.h"
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

// Ligero parameters. Match the defaults used by zk_testing.h's
// run_test_zk (rate 4, 128 queries).
constexpr size_t kRate = 4;
constexpr size_t kNreq = 128;

// A Longfellow Transcript is seeded from a short domain-separated byte
// string. Prover and verifier must use the same seed; the constant below
// acts as a protocol version tag for Task 1a's trivial circuit.
constexpr char kTranscriptSeed[] = "p7s-1a";
constexpr size_t kTranscriptSeedLen = sizeof(kTranscriptSeed) - 1;

// Build the Task-1a circuit: one public input (context_hash as v256),
// asserted equal to itself. Always satisfiable.
std::unique_ptr<Circuit<F>> build_circuit() {
  const F Fs;
  using CB = CompilerBackend<F>;
  using LC = Logic<F, CB>;

  QuadCircuit<F> Q(Fs);
  const CB cbk(&Q);
  const LC lc(&cbk, Fs);

  auto ch = lc.template vinput<256>();
  Q.private_input();  // No private witnesses in 1a.

  // Trivial identity constraint — ensures at least one gate so the
  // circuit is well-formed; semantically always true.
  lc.vassert_eq(ch, ch);

  return Q.mkcircuit(/*nc=*/1);
}

// Cached circuit. First call builds; subsequent calls reuse.
const Circuit<F>& get_circuit() {
  static std::mutex m;
  static std::unique_ptr<Circuit<F>> c;
  std::lock_guard<std::mutex> lock(m);
  if (!c) {
    c = build_circuit();
  }
  return *c;
}

// Push `context_hash[32]` as 256 bit wires, matching vinput<256>'s layout
// (each byte spread LSB-first across 8 wires).
void fill_context_hash(DenseFiller<F>& filler, const uint8_t context_hash[32],
                       const F& Fs) {
  for (size_t i = 0; i < 32; ++i) {
    filler.push_back(static_cast<uint64_t>(context_hash[i]), 8, Fs);
  }
}

}  // namespace
}  // namespace p7s
}  // namespace proofs

extern "C" {

P7sErrorCode p7s_prove(const uint8_t context_hash[32], uint8_t** proof_out,
                       size_t* proof_len_out) {
  using namespace proofs;
  using namespace proofs::p7s;

  if (context_hash == nullptr || proof_out == nullptr ||
      proof_len_out == nullptr) {
    return P7S_NULL_INPUT;
  }

  const F Fs;
  const RSFactory rsf(Fs);

  const Circuit<F>& circuit = get_circuit();

  // Build the witness: constant-1 wire, then the 256 context_hash bits.
  Dense<F> W(1, circuit.ninputs);
  DenseFiller<F> filler(W);
  filler.push_back(Fs.one());
  fill_context_hash(filler, context_hash, Fs);

  if (filler.size() != circuit.ninputs) {
    return P7S_INVALID_INPUT;
  }

  // Commit + prove.
  ZkProof<F> zkp(circuit, kRate, kNreq);
  Transcript tp(reinterpret_cast<const uint8_t*>(kTranscriptSeed),
                kTranscriptSeedLen);
  SecureRandomEngine rng;
  ZkProver<F, RSFactory> prover(circuit, Fs, rsf);
  prover.commit(zkp, W, tp, rng);
  if (!prover.prove(zkp, W, tp)) {
    return P7S_PROVER_FAILURE;
  }

  // Serialize proof to bytes.
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

  // Parse proof bytes.
  ZkProof<F> zkp(circuit, kRate, kNreq);
  const std::vector<uint8_t> zbuf(proof, proof + proof_len);
  ReadBuffer rb(zbuf);
  if (!zkp.read(rb, Fs)) {
    return P7S_VERIFIER_FAILURE;
  }
  if (rb.remaining() != 0) {
    return P7S_VERIFIER_FAILURE;
  }

  // Fill the PUBLIC-input portion of the witness. For 1a, public inputs
  // are the constant-1 wire plus the 256 context_hash bits.
  Dense<F> pub(1, circuit.npub_in);
  DenseFiller<F> filler(pub);
  filler.push_back(Fs.one());
  fill_context_hash(filler, context_hash, Fs);
  if (filler.size() != circuit.npub_in) {
    return P7S_INVALID_INPUT;
  }

  // Verify.
  ZkVerifier<F, RSFactory> verifier(circuit, rsf, kRate, kNreq, Fs);
  Transcript tv(reinterpret_cast<const uint8_t*>(kTranscriptSeed),
                kTranscriptSeedLen);
  verifier.recv_commitment(zkp, tv);
  return verifier.verify(zkp, pub, tv) ? P7S_SUCCESS : P7S_VERIFIER_FAILURE;
}

void p7s_free_proof(uint8_t* proof) { free(proof); }

}  // extern "C"
