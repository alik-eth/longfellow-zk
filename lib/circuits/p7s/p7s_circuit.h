// Copyright 2026 Oleksandr Vovkotrub. Apache-2.0.
#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_P7S_P7S_CIRCUIT_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_P7S_P7S_CIRCUIT_H_

// Phase 2a scaffold. Populated incrementally across Phase 2a steps.
//
// Size bounds for the blob-protocol witness. All paddings are filled
// with zero bytes on the host side; the host deserializer enforces
// `signed_content_len <= kMaxSignedContent` before filling.
//
// As further invariants land the constants grow (nonce, context, etc.);
// keep these literals in sync with the blob schema version bumped in
// p7s_zk.cc's deserializer-history comment.

#include <cstddef>

namespace proofs {
namespace p7s {

// v1 bound on the signed_content slice copied into the witness. 1024
// bytes covers current DIIA QKB payloads (~600 bytes) with headroom.
constexpr size_t kMaxSignedContent = 1024;

// Length of an uncompressed SEC1 secp256k1 public key as lowercase hex:
// `04 || X[32] || Y[32]` = 65 bytes, each byte emitted as 2 hex chars.
constexpr size_t kPkHexLen = 130;

// Decoded pk length in bytes.
constexpr size_t kPkBytes = 65;

// Freshness nonce emitted as lowercase hex (2 chars per byte).
constexpr size_t kNonceBytes = 32;
constexpr size_t kNonceHexLen = 64;

// messageDigest attribute inside CAdES signedAttrs — 32 bytes holding
// SHA-256(signed_content). Bound by invariant 2b (Task 24).
constexpr size_t kMessageDigestLen = 32;

// ---- Invariant 1 (Task 29) — cert TBS + cert signature bounds ----
//
// The signer cert's TBSCertificate (the portion the DIIA root signs
// over) is bounded by kCertTbsMaxBlocks SHA-256 blocks. 32 blocks ×
// 64 bytes/block = 2048 bytes; minus the 9-byte MD padding floor that
// leaves 2039 bytes of raw TBS headroom. Current DIIA QTSP certs are
// ~1203 bytes TBS, so 32 blocks is comfortable (the fixture test
// verifies the exact offset).
constexpr size_t kCertTbsMaxBlocks = 32;
constexpr size_t kCertTbsMaxBytes = kCertTbsMaxBlocks * 64;  // 2048
constexpr size_t kCertTbsLenBits = 11;  // log2(2048)

// SHA-256 digest length — same as kMessageDigestLen but aliased for
// invariant 1's cert_tbs digest to keep call sites self-documenting.
constexpr size_t kCertTbsDigestLen = 32;

}  // namespace p7s
}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_P7S_P7S_CIRCUIT_H_
