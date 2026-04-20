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
// Phase 2a Task 1b — invariant 9: context_hash == SHA-256(context_bytes).
//
// Public input:
//   context_hash[32] : the SHA-256 digest the prover claims.
//
// Private witness (v1 constraint: context_len + 9 <= 64, i.e. ≤ 55 bytes):
//   context_bytes[context_len] : the preimage.
//
// The circuit asserts context_hash == SHA-256(context_bytes). Proof bytes
// are opaque; the caller must free the buffer via p7s_free_proof.
// ============================================================================

// Prove: produce a proof that SHA-256(context_bytes[0..context_len]) equals
// the declared context_hash.
extern P7sErrorCode p7s_prove(
    const uint8_t context_hash[32],
    uint8_t** proof_out, size_t* proof_len_out,
    const uint8_t* context_bytes, size_t context_len);

// Verify: return P7S_SUCCESS iff `proof` is valid for `context_hash`.
extern P7sErrorCode p7s_verify(
    const uint8_t context_hash[32],
    const uint8_t* proof, size_t proof_len);

// Free a proof buffer returned by p7s_prove.
extern void p7s_free_proof(uint8_t* proof);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_P7S_P7S_ZK_H_
