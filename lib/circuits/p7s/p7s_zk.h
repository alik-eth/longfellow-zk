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
// Phase 2a p7s circuit — blob protocol (schema v9).
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
//   (25a) dual-circuit MAC plumbing — a sig-circuit over Fp256Base is
//                       introduced alongside the existing hash-circuit
//                       over GF(2^128), linked via a MAC gadget bound
//                       to a non-zero sentinel.
//   (29)  invariant 1 — signer-cert ECDSA signature verifies over
//                       `cert_tbs` under the compile-time trust-anchor
//                       root public key (TestAnchorA post-#43a;
//                       selected out of `kTrustAnchors[]`). Sentinel
//                       is gone; the MAC now binds
//                       `e = SHA-256(cert_tbs)` across the two fields.
//   (26) invariant 2a — CMS content signature verifies over the CAdES-
//                       canonical signedAttrs (SET form, [0] IMPLICIT
//                       0xA0 rewritten to 0x31) under the user's
//                       `holder_pk` (= invariant-4-constrained pk). The
//                       MAC additionally binds
//                       `e2 = SHA-256(signedAttrs_rewritten)`.
//
// Witness blob v9 layout (extends v8 with signedAttrs + content sig):
//   u32  version                                    = 9
//   u32  context_len                                in [0, 32]
//   u8   context[32]                                raw bytes + zero pad
//   u32  signed_content_len                         in [0, 1015]
//   u8   signed_content[1024]                       raw bytes + zero pad
//   u32  json_pk_offset                             relative to signed_content
//   u8   pk_hex[130]                                ASCII lowercase hex
//   u32  json_nonce_offset                          relative to signed_content
//   u8   nonce_hex[64]                              ASCII lowercase hex
//   u32  json_context_offset                        relative to signed_content
//   u32  json_declaration_offset                    relative to signed_content
//   u8   message_digest[32]                         SHA-256(signed_content)
//   u32  cert_tbs_len                               in [0, 2039]
//   u8   cert_tbs[2048]                             raw bytes + zero pad;
//                                                   filler SHA-pads
//   u8   cert_sig_r[32]                             big-endian scalar
//   u8   cert_sig_s[32]                             big-endian scalar
//   u32  signed_attrs_len                           in [0, 1527]; tag = 0xA0
//   u8   signed_attrs[1536]                         raw bytes + zero pad;
//                                                   filler rewrites
//                                                   signed_attrs[0] 0xA0→0x31
//                                                   then SHA-pads
//   u8   content_sig_r[32]                          big-endian scalar
//   u8   content_sig_s[32]                          big-endian scalar
//
// Public blob v9 layout (unchanged from v3..v8):
//   u32  version                                    = 9
//   u8   context_hash[32]
//   u8   pk[65]                                     decoded SEC1 uncompressed
//   u8   nonce[32]                                  decoded freshness nonce
//
// Note: the trust-anchor root public key (TestAnchorA post-#43a) is a
// COMPILE-TIME CONSTANT baked into sub/p7s_signature.h's
// `kTrustAnchors[]` — it is NOT part of the public blob.
// The USER holder public key (invariant-2a signer) IS part of the
// public blob: it's the same `pub.pk[65]` that invariant 4 constrains
// on the hash side, re-parsed on the host as Fp256Base (X, Y) and
// pushed as sig-circuit public inputs.
//
// Extended proof-output format (v9):
//   u32  schema_version                             = 9 (LE)
//   u8   macs_b[64]                                 4 × GF(2^128) MAC values
//                                                   (2 per message × 2
//                                                    messages = e, e2)
//   u8   hash_zk[...]                               ZkProof<GF2_128>,
//                                                   self-delimited by
//                                                   ZkProof::read
//   u8   sig_zk[...]                                ZkProof<Fp256Base>,
//                                                   self-delimited by
//                                                   ZkProof::read
//
// Known caveats (deferred, not in this task's scope):
//   * DER re-encode on cert_sig / content_sig: the Rust host DER-parses
//     both signatures and supplies raw (r, s) scalars. The circuit proves
//     "some (r, s) verifies"; it does NOT bind the raw DER bytes to
//     (r, s). Downstream callers that commit to the raw p7s bytes via
//     another channel are not affected (PublicInputs does not expose
//     those bytes). Accepted as a permanent deferral.
//   * SPKI binding between the cert_tbs embedded pubkey and the JSON
//     holder_pk (invariant 4) is NOT enforced by invariant 2a alone —
//     invariant 2a verifies the content sig under holder_pk, and
//     invariant 1 verifies the cert sig under root_pk over cert_tbs,
//     but nothing in this task ties the SubjectPublicKeyInfo inside
//     cert_tbs to holder_pk. That linkage arrives in Task 30.
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
