// Smoke test function callable from Rust FFI.
// Proves and verifies a single age_over_18 attribute using built-in test data.

#include <cstdlib>
#include <cstring>
#include "circuits/mdoc/mdoc_zk.h"
#include "circuits/mdoc/mdoc_examples.h"
#include "circuits/mdoc/mdoc_test_attributes.h"

extern "C" int longfellow_smoke_test() {
  using namespace proofs;
  using namespace proofs::test;

  // Generate circuit for 1 attribute
  uint8_t* circuit = nullptr;
  size_t circuit_len = 0;
  auto gen_ret = generate_circuit(&kZkSpecs[0], &circuit, &circuit_len);
  if (gen_ret != CIRCUIT_GENERATION_SUCCESS) return -1;

  // Prove age_over_18 on first test mdoc
  const auto& test = mdoc_tests[0];
  RequestedAttribute attrs[1] = {age_over_18};

  uint8_t contract_hash[8] = {0};  // zero contract hash for smoke test
  uint8_t nullifier_hash[32] = {0};

  uint8_t* proof = nullptr;
  size_t proof_len = 0;
  auto prove_ret = run_mdoc_prover(
      circuit, circuit_len,
      test.mdoc, test.mdoc_size,
      test.pkx.as_pointer, test.pky.as_pointer,
      test.transcript, test.transcript_size,
      attrs, 1,
      (const char*)test.now,
      contract_hash,
      &proof, &proof_len,
      nullifier_hash,
      &kZkSpecs[0]);

  if (prove_ret != MDOC_PROVER_SUCCESS) {
    free(circuit);
    return -2;
  }

  // Verify the proof
  auto verify_ret = run_mdoc_verifier(
      circuit, circuit_len,
      test.pkx.as_pointer, test.pky.as_pointer,
      test.transcript, test.transcript_size,
      attrs, 1,
      (const char*)test.now,
      contract_hash,
      nullifier_hash,
      proof, proof_len,
      test.doc_type,
      &kZkSpecs[0]);

  free(proof);
  free(circuit);

  return (verify_ret == MDOC_VERIFIER_SUCCESS) ? 0 : -3;
}

// Prove+verify with pre-generated circuit bytes (avoids circuit regeneration).
// Returns: 0=success, -2=prove failed, -3=verify failed.
// proof_out/proof_len_out: if non-null, receives the proof bytes (caller must free).
extern "C" int longfellow_prove_verify_cached(
    const uint8_t* circuit, size_t circuit_len,
    uint8_t** proof_out, size_t* proof_len_out) {
  using namespace proofs;
  using namespace proofs::test;

  const auto& test = mdoc_tests[0];
  RequestedAttribute attrs[1] = {age_over_18};

  uint8_t contract_hash[8] = {0};
  uint8_t nullifier_hash[32] = {0};

  uint8_t* proof = nullptr;
  size_t proof_len = 0;
  auto prove_ret = run_mdoc_prover(
      circuit, circuit_len,
      test.mdoc, test.mdoc_size,
      test.pkx.as_pointer, test.pky.as_pointer,
      test.transcript, test.transcript_size,
      attrs, 1,
      (const char*)test.now,
      contract_hash,
      &proof, &proof_len,
      nullifier_hash,
      &kZkSpecs[0]);

  if (prove_ret != MDOC_PROVER_SUCCESS) return -2;

  auto verify_ret = run_mdoc_verifier(
      circuit, circuit_len,
      test.pkx.as_pointer, test.pky.as_pointer,
      test.transcript, test.transcript_size,
      attrs, 1,
      (const char*)test.now,
      contract_hash,
      nullifier_hash,
      proof, proof_len,
      test.doc_type,
      &kZkSpecs[0]);

  if (proof_out && proof_len_out) {
    *proof_out = proof;
    *proof_len_out = proof_len;
  } else {
    free(proof);
  }

  return (verify_ret == MDOC_VERIFIER_SUCCESS) ? 0 : -3;
}
