// Copyright 2026 Oleksandr Vovkotrub. Apache-2.0.
//
// p7s v12 vendor-side smoke test (Task #41). Loads the canonical v12
// witness + public blobs (deterministic, generated from the
// TestAnchorA v12 fixture by `dump_v12_blobs.rs`) and runs the full
// p7s_prove pipeline. Asserts P7S_SUCCESS on the honest blob; asserts
// non-success on a corrupted blob.
//
// Why this exists despite the Rust slow-tests canary covering the
// same path:
//   * Lives in vendor's own test tree, so vendor CI catches v12
//     regressions without crossing the FFI boundary.
//   * Self-contained: no Rust toolchain required to run, no FFI hop.
//   * The corrupted-blob negative test is a regression-test for the
//     positive test — proves the smoke test would actually catch
//     drift, not just silently pass.
//
// Wall-clock cost: ~19s for the positive test (full sumcheck +
// Ligero), ~1s for the negative test (fails fast at parse_witness_blob
// or at the c_hash.ninputs guard or at eval_circuit). Acceptable for a
// vendor-side regression canary that runs only when explicitly invoked
// (`ctest -R p7s_v12_smoke_test`).

#include <cstddef>
#include <cstdint>
#include <vector>

#include "circuits/p7s/p7s_v12_test_blobs.h"
#include "circuits/p7s/p7s_zk.h"
#include "gtest/gtest.h"

namespace proofs {
namespace {

TEST(p7s, v12_honest_witness_proves) {
  uint8_t* proof = nullptr;
  size_t proof_len = 0;
  const P7sErrorCode rc = p7s_prove(kP7sV12Witness, sizeof(kP7sV12Witness),
                                    kP7sV12Public, sizeof(kP7sV12Public),
                                    &proof, &proof_len);
  EXPECT_EQ(rc, P7S_SUCCESS) << "p7s_prove returned " << rc
                             << " on honest v12 witness blob";
  EXPECT_NE(proof, nullptr);
  EXPECT_GT(proof_len, 1000U) << "proof bytes len suspiciously small: "
                              << proof_len;

  if (proof != nullptr) {
    // Round-trip: verify must accept the proof we just produced.
    const P7sErrorCode vrc =
        p7s_verify(kP7sV12Public, sizeof(kP7sV12Public), proof, proof_len);
    EXPECT_EQ(vrc, P7S_SUCCESS) << "p7s_verify returned " << vrc
                                << " on honest proof";
    p7s_free_proof(proof);
  }
}

TEST(p7s, v12_corrupted_witness_does_not_prove) {
  // Single-byte flip inside `signed_content[]` (offset 0x40 lands well
  // inside the binding JSON body — past the version/context-len header
  // but before the cert_tbs region). The exact wire that surfaces the
  // failure depends on which v12 invariant the byte participates in,
  // but ANY bit-flip inside signed_content must trip at least one of
  // invariants 4/5/6/9/10/13/2b — so prove() MUST NOT return SUCCESS.
  std::vector<uint8_t> bad_witness(kP7sV12Witness,
                                   kP7sV12Witness + sizeof(kP7sV12Witness));
  // Find a non-zero byte in the signed_content range to flip; the
  // first 64 bytes of the v12 blob are version + context_len/bytes,
  // so the JSON proper starts ~0x40 in.
  ASSERT_GE(bad_witness.size(), 0x100U);
  bad_witness[0x80] ^= 0x01;  // single-bit flip; cheap, reliable

  uint8_t* proof = nullptr;
  size_t proof_len = 0;
  const P7sErrorCode rc = p7s_prove(bad_witness.data(), bad_witness.size(),
                                    kP7sV12Public, sizeof(kP7sV12Public),
                                    &proof, &proof_len);
  EXPECT_NE(rc, P7S_SUCCESS) << "p7s_prove unexpectedly succeeded on corrupted "
                                "witness blob — the smoke test would not "
                                "catch v12 drift";
  if (proof != nullptr) {
    p7s_free_proof(proof);
  }
}

}  // namespace
}  // namespace proofs
