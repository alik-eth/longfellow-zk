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
// Phase 2a Task 1a — trivially-satisfiable hello-world circuit.
//
// Public input:
//   context_hash[32] : the 32-byte value the circuit makes public.
//
// The circuit declares context_hash as a 256-bit public input and imposes
// one identity constraint (context_hash == context_hash). This proves the
// FFI + CMake + prove/verify loop end-to-end without relying on the more
// delicate SHA-256 gadget, which lands in Task 1b.
//
// Proof bytes are opaque; the caller must free the buffer via p7s_free_proof.
// ============================================================================

// Prove: produce a proof for the public context_hash input.
extern P7sErrorCode p7s_prove(
    const uint8_t context_hash[32],
    uint8_t** proof_out, size_t* proof_len_out);

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
