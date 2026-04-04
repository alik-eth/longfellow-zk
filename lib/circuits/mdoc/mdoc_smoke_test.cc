// Smoke test function callable from Rust FFI.
// Proves and verifies a single age_over_18 attribute using built-in test data.

#include <cstdlib>
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

  uint8_t* proof = nullptr;
  size_t proof_len = 0;
  auto prove_ret = run_mdoc_prover(
      circuit, circuit_len,
      test.mdoc, test.mdoc_size,
      test.pkx.as_pointer, test.pky.as_pointer,
      test.transcript, test.transcript_size,
      attrs, 1,
      (const char*)test.now,
      &proof, &proof_len,
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
      proof, proof_len,
      test.doc_type,
      &kZkSpecs[0]);

  free(proof);
  free(circuit);

  return (verify_ret == MDOC_VERIFIER_SUCCESS) ? 0 : -3;
}
