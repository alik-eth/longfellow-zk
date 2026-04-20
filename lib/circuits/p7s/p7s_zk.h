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
// Phase 2a p7s circuit — blob protocol (schema v6).
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
//   (21) invariant 5  — signed_content[nonce_offset..+64] == nonce_hex
//                       AND nonce_hex decodes to public.nonce (32 bytes)
//   (22) invariant 6  — signed_content[ctx_offset..+ctx_len] == context_bytes
//                       (byte-length derived from SHA padding, no new public input)
//   (23) invariant 10 — signed_content[decl_offset..+510] == kDeclarationPhrase
//                       (N=1 compile-time whitelist, no new public input)
//   (24) invariant 2b — message_digest == SHA-256(signed_content)
//                       (signed_content length derived from SHA padding;
//                        binding to signedAttrs byte range arrives in Task 26)
//
// Witness blob v6 layout (all little-endian):
//   u32  version                                    = 6
//   u32  context_len                                in [0, 32]
//   u8   context[32]                                raw bytes + zero pad;
//                                                   filler SHA-pads
//   u32  signed_content_len                         in [0, 1015]
//   u8   signed_content[1024]                       raw bytes + zero pad;
//                                                   filler SHA-pads
//   u32  json_pk_offset                             relative to signed_content
//   u8   pk_hex[130]                                ASCII lowercase hex
//   u32  json_nonce_offset                          relative to signed_content
//   u8   nonce_hex[64]                              ASCII lowercase hex
//   u32  json_context_offset                        relative to signed_content
//   u32  json_declaration_offset                    relative to signed_content
//   u8   message_digest[32]                         prover-claimed
//                                                   SHA-256(signed_content)
//
// Note: `context_len` and `signed_content_len` are host-side filler
// parameters — the C++ witness filler uses them to build SHA-256
// Merkle-Damgård padded buffers that go into the circuit's `context_in`
// and `signed_content` wires. The CIRCUIT itself does NOT see either
// length as a wire; both lengths are derivable from the SHA padding
// in-circuit (Task 22's discipline, applied to both fields).
//
// Public blob v6 layout (unchanged from v3):
//   u32  version                                    = 6
//   u8   context_hash[32]
//   u8   pk[65]                                     decoded SEC1 uncompressed
//   u8   nonce[32]                                  decoded freshness nonce
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
