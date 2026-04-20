// Copyright 2026 Oleksandr Vovkotrub. Apache-2.0.
#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_P7S_P7S_ZK_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_P7S_P7S_ZK_H_

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
  P7S_SUCCESS = 0,
  P7S_NULL_INPUT = 1,
  P7S_INVALID_INPUT = 2,
  P7S_PROVER_FAILURE = 3,
  P7S_VERIFIER_FAILURE = 4,
  P7S_MEMORY_FAILURE = 5,
} P7sErrorCode;

// ============================================================================
// Phase 2a p7s circuit — blob protocol (schema v2).
//
// Prove/verify take two byte buffers that the caller serializes:
//   * `witness_blob`: private witness — circuit-dependent; schema below.
//   * `public_blob`:  public inputs — circuit-dependent; schema below.
//
// Both blobs start with a little-endian u32 schema version, bumped when
// the layout changes. See the "schema history" block in p7s_zk.cc's
// deserializer for the authoritative list.
//
// Current invariants (additive, each task extends both schemas):
//   (1b) invariant 9  — context_hash == SHA-256(context_bytes)
//   (20) invariant 4  — signed_content[pk_offset..+130] == pk_hex
//                       AND pk_hex decodes to public.pk (65 bytes)
//
// Witness blob v2 layout (all little-endian):
//   u32  version                                    = 2
//   u32  context_len                                in [0, 32]
//   u8   context[32]                                (padded with zeros)
//   u32  signed_content_len                         in [0, 1024]
//   u8   signed_content[1024]                       (padded with zeros)
//   u32  json_pk_offset                             relative to signed_content
//   u8   pk_hex[130]                                ASCII lowercase hex
//
// Public blob v2 layout:
//   u32  version                                    = 2
//   u8   context_hash[32]
//   u8   pk[65]                                     decoded SEC1 uncompressed
//
// Proof bytes are opaque; the caller must free the buffer via
// p7s_free_proof.
// ============================================================================

extern P7sErrorCode p7s_prove(
    const uint8_t* witness_blob, size_t witness_blob_len,
    const uint8_t* public_blob, size_t public_blob_len,
    uint8_t** proof_out, size_t* proof_len_out);

extern P7sErrorCode p7s_verify(
    const uint8_t* public_blob, size_t public_blob_len,
    const uint8_t* proof, size_t proof_len);

// Free a proof buffer returned by p7s_prove.
extern void p7s_free_proof(uint8_t* proof);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_P7S_P7S_ZK_H_
