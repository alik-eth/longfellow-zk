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

// NOTE (Phase 2b.2): the OPRF fusion bumped kBlobSchemaVersion 13 → 14
// and appended the OPRF Y/M/s tail to the public blob. The canonical
// fixture (`p7s_v12_test_blobs.h`) is still the v13 byte layout, so
// these tests now rebuild v14 blobs from it at runtime: bump the
// witness schema-version u32, and build a v14 public blob = v13 public
// (version bumped) + the 160-byte OPRF tail computed from the witness's
// cert stable_id via `p7s_oprf_public_for_witness`. The OPRF block is
// now part of the proved sig circuit, so the positive case is slower
// than the pre-fusion v12 cost.

#include <cstddef>
#include <cstdint>
#include <vector>

#include "circuits/p7s/p7s_v12_test_blobs.h"
#include "circuits/p7s/p7s_zk.h"
#include "gtest/gtest.h"

namespace proofs {
namespace {

constexpr uint32_t kV14 = 14;
constexpr size_t kOprfTail = 160;

static void put_u32_le(std::vector<uint8_t>& b, size_t off, uint32_t v) {
  b[off + 0] = static_cast<uint8_t>(v & 0xFF);
  b[off + 1] = static_cast<uint8_t>((v >> 8) & 0xFF);
  b[off + 2] = static_cast<uint8_t>((v >> 16) & 0xFF);
  b[off + 3] = static_cast<uint8_t>((v >> 24) & 0xFF);
}

static std::vector<uint8_t> make_v14_witness() {
  std::vector<uint8_t> w(kP7sV12Witness, kP7sV12Witness + sizeof(kP7sV12Witness));
  put_u32_le(w, 0, kV14);
  return w;
}

static bool make_v14_public(const std::vector<uint8_t>& wit,
                            std::vector<uint8_t>& out) {
  uint8_t oprf[kOprfTail];
  if (p7s_oprf_public_for_witness(wit.data(), wit.size(), oprf) != P7S_SUCCESS) {
    return false;
  }
  out.assign(kP7sV12Public, kP7sV12Public + sizeof(kP7sV12Public));
  put_u32_le(out, 0, kV14);
  out.insert(out.end(), oprf, oprf + kOprfTail);
  return true;
}

TEST(p7s, v12_honest_witness_proves) {
  std::vector<uint8_t> wit = make_v14_witness();
  std::vector<uint8_t> pub;
  ASSERT_TRUE(make_v14_public(wit, pub));

  uint8_t* proof = nullptr;
  size_t proof_len = 0;
  const P7sErrorCode rc = p7s_prove(wit.data(), wit.size(), pub.data(),
                                    pub.size(), &proof, &proof_len);
  EXPECT_EQ(rc, P7S_SUCCESS) << "p7s_prove returned " << rc
                             << " on honest v14 witness blob";
  EXPECT_NE(proof, nullptr);
  EXPECT_GT(proof_len, 1000U) << "proof bytes len suspiciously small: "
                              << proof_len;

  if (proof != nullptr) {
    const P7sErrorCode vrc =
        p7s_verify(pub.data(), pub.size(), proof, proof_len);
    EXPECT_EQ(vrc, P7S_SUCCESS) << "p7s_verify returned " << vrc
                                << " on honest proof";
    p7s_free_proof(proof);
  }
}

TEST(p7s, v12_corrupted_witness_does_not_prove) {
  // Single-byte flip inside `signed_content[]` (offset 0x80 lands well
  // inside the binding JSON body). ANY bit-flip there must trip at
  // least one of invariants 4/5/6/9/10/13/2b — so prove() MUST NOT
  // return SUCCESS.
  std::vector<uint8_t> bad_witness = make_v14_witness();
  std::vector<uint8_t> pub;
  ASSERT_TRUE(make_v14_public(bad_witness, pub));
  ASSERT_GE(bad_witness.size(), 0x100U);
  bad_witness[0x80] ^= 0x01;  // single-bit flip; cheap, reliable

  uint8_t* proof = nullptr;
  size_t proof_len = 0;
  const P7sErrorCode rc = p7s_prove(bad_witness.data(), bad_witness.size(),
                                    pub.data(), pub.size(), &proof, &proof_len);
  EXPECT_NE(rc, P7S_SUCCESS) << "p7s_prove unexpectedly succeeded on corrupted "
                                "witness blob — the smoke test would not "
                                "catch v14 drift";
  if (proof != nullptr) {
    p7s_free_proof(proof);
  }
}

}  // namespace
}  // namespace proofs
