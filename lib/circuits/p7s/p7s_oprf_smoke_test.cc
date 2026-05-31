// Copyright 2026 Oleksandr Vovkotrub. Apache-2.0.
//
// p7s + OPRF fused smoke test (Phase 2b.2). Builds a v14 witness/public
// blob pair from the canonical v13 fixture (only the schema-version u32
// changes in the witness; the public blob gains the OPRF Y/M/s tail) and
// runs the full fused p7s_prove → p7s_verify pipeline.
//
// What the fused sig circuit now proves, on top of the v13 invariants:
//   * M = r · H2C(stable_id)            (stable_id = MAC-bound cert id)
//   * r · N == Y                        (Y public input)
//   * s = SHA-256(N.x || N.y)
// with M, s exposed as public outputs (modeled as asserted public
// inputs — see the kSigPubTotal note in p7s_zk.cc). The OPRF `rnokpp`
// is the MAC #4-bound stable_id, NOT a free witness (the Sybil gate).
//
// Tests:
//   * honest v14 proves + verifies; M, s, Y match the host OPRF;
//   * a corrupted OPRF output (M.x byte flipped in the public blob)
//     does NOT verify (the in-circuit assert_eq trips / prover
//     self-check rejects) — fail-closed;
//   * a corrupted witness still fails (regression for the positive).

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>

#include "circuits/p7s/p7s_v12_test_blobs.h"
#include "circuits/p7s/p7s_zk.h"
#include "gtest/gtest.h"

namespace proofs {
namespace {

constexpr uint32_t kV14 = 14;
constexpr size_t kOprfTail = 160;  // Y.x|Y.y|M.x|M.y|s, 5 × 32 BE bytes

static void put_u32_le(std::vector<uint8_t>& b, size_t off, uint32_t v) {
  b[off + 0] = static_cast<uint8_t>(v & 0xFF);
  b[off + 1] = static_cast<uint8_t>((v >> 8) & 0xFF);
  b[off + 2] = static_cast<uint8_t>((v >> 16) & 0xFF);
  b[off + 3] = static_cast<uint8_t>((v >> 24) & 0xFF);
}

// v14 witness = v13 witness with the leading schema-version bumped.
static std::vector<uint8_t> make_v14_witness() {
  std::vector<uint8_t> w(kP7sV12Witness, kP7sV12Witness + sizeof(kP7sV12Witness));
  put_u32_le(w, 0, kV14);
  return w;
}

// v14 public = v13 public (version bumped) + the 160-byte OPRF tail,
// computed from the witness's cert stable_id with the same synthetic
// (k, r) the prover uses.
static bool make_v14_public(const std::vector<uint8_t>& v14_witness,
                            std::vector<uint8_t>& out) {
  uint8_t oprf[kOprfTail];
  P7sErrorCode rc = p7s_oprf_public_for_witness(
      v14_witness.data(), v14_witness.size(), oprf);
  if (rc != P7S_SUCCESS) return false;
  out.assign(kP7sV12Public, kP7sV12Public + sizeof(kP7sV12Public));
  put_u32_le(out, 0, kV14);
  out.insert(out.end(), oprf, oprf + kOprfTail);
  return true;
}

TEST(p7sOprf, fused_honest_proves_and_verifies) {
  std::vector<uint8_t> wit = make_v14_witness();
  std::vector<uint8_t> pub;
  ASSERT_TRUE(make_v14_public(wit, pub)) << "OPRF public-tail build failed";
  EXPECT_EQ(pub.size(), sizeof(kP7sV12Public) + kOprfTail);

  uint8_t* proof = nullptr;
  size_t proof_len = 0;
  const P7sErrorCode rc = p7s_prove(wit.data(), wit.size(), pub.data(),
                                    pub.size(), &proof, &proof_len);
  EXPECT_EQ(rc, P7S_SUCCESS) << "fused p7s+OPRF prove returned " << rc;
  ASSERT_NE(proof, nullptr);
  EXPECT_GT(proof_len, 1000U);

  const P7sErrorCode vrc =
      p7s_verify(pub.data(), pub.size(), proof, proof_len);
  EXPECT_EQ(vrc, P7S_SUCCESS) << "fused p7s+OPRF verify returned " << vrc;
  p7s_free_proof(proof);
}

// Prover self-check: a public blob whose OPRF output (M.x) disagrees
// with the prover's host-computed value is rejected at prove time
// (clean early error before the expensive prove).
TEST(p7sOprf, corrupted_oprf_output_rejected_at_prove) {
  std::vector<uint8_t> wit = make_v14_witness();
  std::vector<uint8_t> pub;
  ASSERT_TRUE(make_v14_public(wit, pub));
  const size_t mx_off = sizeof(kP7sV12Public) + 64;  // 3rd 32-byte field
  pub[mx_off] ^= 0x01;

  uint8_t* proof = nullptr;
  size_t proof_len = 0;
  const P7sErrorCode rc = p7s_prove(wit.data(), wit.size(), pub.data(),
                                    pub.size(), &proof, &proof_len);
  EXPECT_NE(rc, P7S_SUCCESS) << "prover accepted a blob M.x != host M.x";
  if (proof != nullptr) p7s_free_proof(proof);
}

// SOUNDNESS (the real binding): an HONEST proof must NOT verify against
// a public blob whose OPRF output M.x was tampered after proving. This
// exercises the in-circuit assert_eq(oprf_Mx, oprf_mx) at VERIFY time
// (the verifier rebuilds the public Dense from the corrupted blob), NOT
// the prover's host self-check. A pass here proves M is genuinely bound
// to the in-circuit OPRF result, not just to a host equality check.
TEST(p7sOprf, tampered_M_at_verify_fails_closed) {
  std::vector<uint8_t> wit = make_v14_witness();
  std::vector<uint8_t> pub;
  ASSERT_TRUE(make_v14_public(wit, pub));

  uint8_t* proof = nullptr;
  size_t proof_len = 0;
  ASSERT_EQ(p7s_prove(wit.data(), wit.size(), pub.data(), pub.size(), &proof,
                      &proof_len),
            P7S_SUCCESS);
  ASSERT_NE(proof, nullptr);

  // Flip a byte of M.x in the public blob the VERIFIER sees.
  std::vector<uint8_t> tampered = pub;
  tampered[sizeof(kP7sV12Public) + 64] ^= 0x01;
  const P7sErrorCode vrc =
      p7s_verify(tampered.data(), tampered.size(), proof, proof_len);
  EXPECT_NE(vrc, P7S_SUCCESS)
      << "honest proof verified against a tampered M.x — OPRF output not "
         "bound in-circuit (fail-open soundness bug)!";
  p7s_free_proof(proof);
}

// Corrupting the witness signed_content still trips a v13 invariant —
// regression guard that the fused positive test would actually catch
// drift.
TEST(p7sOprf, corrupted_witness_does_not_prove) {
  std::vector<uint8_t> wit = make_v14_witness();
  std::vector<uint8_t> pub;
  ASSERT_TRUE(make_v14_public(wit, pub));
  ASSERT_GE(wit.size(), 0x100U);
  wit[0x80] ^= 0x01;

  uint8_t* proof = nullptr;
  size_t proof_len = 0;
  const P7sErrorCode rc = p7s_prove(wit.data(), wit.size(), pub.data(),
                                    pub.size(), &proof, &proof_len);
  EXPECT_NE(rc, P7S_SUCCESS) << "corrupted witness unexpectedly proved";
  if (proof != nullptr) p7s_free_proof(proof);
}

// Trust-anchor index in the v14 public blob sits at the u32 right after
// enroll_nullifier: version(4)+ctx_hash(32)+pk(65)+nonce(32)+
// nullifier(32)+enroll_commit(32)+enroll_nullifier(32) = 229.
constexpr size_t kPubTrustAnchorIdxOff = 229;

// Phase 2b.3 selector — out-of-range trust_anchor_index fails closed.
// The parse layer rejects index >= kTrustAnchorCount (4) in BOTH blobs;
// the in-circuit `prod(idx - i) == 0` range constraint is the deeper
// backstop. Set a wildly out-of-range index in both blobs.
TEST(p7sOprf, out_of_range_anchor_index_fails_closed) {
  std::vector<uint8_t> wit = make_v14_witness();
  std::vector<uint8_t> pub;
  ASSERT_TRUE(make_v14_public(wit, pub));
  // Witness trust_anchor_index offset: trailing u32 fields. Find it by
  // setting the public one and observing the prover reject; but to also
  // exercise the witness parser, set the public index out of range.
  put_u32_le(pub, kPubTrustAnchorIdxOff, 99u);

  uint8_t* proof = nullptr;
  size_t proof_len = 0;
  const P7sErrorCode rc = p7s_prove(wit.data(), wit.size(), pub.data(),
                                    pub.size(), &proof, &proof_len);
  EXPECT_NE(rc, P7S_SUCCESS)
      << "out-of-range trust_anchor_index accepted — selector fail-open!";
  if (proof != nullptr) p7s_free_proof(proof);
}

// Wrong (but in-range) anchor index: the public blob selects index 1
// (TestAnchorB) while the fixture cert is signed by index 0
// (TestAnchorA). The in-circuit selector picks TestAnchorB's key, so
// invariant-1 ECDSA over the cert TBS fails — fail-closed. This proves
// the selector binds the SPECIFIC anchor, not just "some valid index".
TEST(p7sOprf, wrong_inrange_anchor_index_fails_closed) {
  std::vector<uint8_t> wit = make_v14_witness();
  std::vector<uint8_t> pub;
  ASSERT_TRUE(make_v14_public(wit, pub));
  put_u32_le(pub, kPubTrustAnchorIdxOff, 1u);  // TestAnchorB, fixture is A

  uint8_t* proof = nullptr;
  size_t proof_len = 0;
  const P7sErrorCode rc = p7s_prove(wit.data(), wit.size(), pub.data(),
                                    pub.size(), &proof, &proof_len);
  if (rc == P7S_SUCCESS) {
    ASSERT_NE(proof, nullptr);
    const P7sErrorCode vrc =
        p7s_verify(pub.data(), pub.size(), proof, proof_len);
    EXPECT_NE(vrc, P7S_SUCCESS)
        << "fixture-A cert verified under anchor index 1 — selector "
           "fail-open!";
    p7s_free_proof(proof);
  } else {
    EXPECT_NE(rc, P7S_SUCCESS);
    if (proof != nullptr) p7s_free_proof(proof);
  }
}

}  // namespace
}  // namespace proofs
