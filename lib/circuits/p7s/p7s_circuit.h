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

}  // namespace p7s
}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_P7S_P7S_CIRCUIT_H_
