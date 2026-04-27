// Copyright 2026 Oleksandr Vovkotrub. Apache-2.0.
//
// Phase 2b p7s circuit — blob protocol (schema v11).
//
// Invariants enforced by the current circuit:
//   (9)  context_hash == SHA-256(context_bytes)                 — Task 1b
//   (4)  signed_content[pk_offset..+130] == pk_hex              — Task 20
//        AND pk_hex decodes to public.pk (65 bytes)             — Task 20
//   (5)  signed_content[nonce_offset..+64] == nonce_hex         — Task 21
//        AND nonce_hex decodes to public.nonce (32 bytes)       — Task 21
//   (6)  signed_content[ctx_offset..+ctx_len] == context_bytes  — Task 22
//   (10) signed_content[decl_offset..+510] == kDeclarationPhrase — Task 23
//   (2b) message_digest == SHA-256(signed_content)              — Task 24
//  (25a) cross-field MAC plumbing (sentinel)                     — Task 25
//   (1)  signer-cert ECDSA signature verifies over cert_tbs — Task 29
//        under the compile-time trust-anchor root pubkey (TestAnchorA
//        post-#43a; kTrustAnchors[0] in the submodule table),
//        with `e = SHA-256(cert_tbs)` MAC-bound across hash/sig
//        circuits (replaces the 25a sentinel).
//   (2a) CMS content signature verifies over signedAttrs         — Task 26
//        (CAdES-canonical form, [0] IMPLICIT 0xA0 rewritten to
//        0x31 SET OF) under the user's holder public key (=
//        invariant 4's pk_bytes). Digest `e2 = SHA-256(
//        signedAttrs_rewritten)` is MAC-bound as a 2nd message.
//   (2c) blob.message_digest byte-equals the 32-byte OCTET STRING — Task 31
//        value embedded in signed_attrs at the messageDigest
//        attribute. Together with invariant 2b, this binds the
//        in-circuit hashed `signed_content` to the bytes the
//        content signature actually attests to. Host-witnessed
//        offset `signed_attrs_md_offset` + 17-byte CMS
//        messageDigest DER anchor on-wire.
//   (7)  nullifier == SHA-256(stable_id[16] || context_raw[..])  — Task 34
//        where stable_id is the 16-byte X.520 serialNumber value
//        (OID 2.5.4.5) embedded in cert_tbs's Subject DN. 9-byte
//        DER anchor on cert_tbs[subject_sn_offset..+9] + range
//        check `subject_sn_offset > subject_dn_start_offset`
//        (guards against the Issuer DN's serialNumber which has
//        an identical 9-byte anchor — same X.520 ATV shape). New
//        256-bit public output `nullifier`.
//
// -----------------------------------------------------------------------------
// Blob protocol — schema history
// -----------------------------------------------------------------------------
//   v1 (Task 1a, 1b): typed C args for context_hash + context_bytes.
//                     Removed in Task 20 in favor of byte-blobs so additional
//                     witness fields can land without per-task ABI churn.
//
//   v2 (Task 20):
//     Witness blob (little-endian):
//       u32  version                = 2
//       u32  context_len            in [0, 32]
//       u8   context[32]            padded with zeros
//       u32  signed_content_len     in [0, 1024]
//       u8   signed_content[1024]   padded with zeros
//       u32  json_pk_offset         relative to signed_content; + 130 <= 1024
//       u8   pk_hex[130]            ASCII lowercase hex
//
//     Public blob (little-endian):
//       u32  version                = 2
//       u8   context_hash[32]
//       u8   pk[65]
//
//   v3 (Task 21): adds nonce field appended to both blobs.
//     Witness blob extends v2 with:
//       u32  json_nonce_offset      relative to signed_content; + 64 <= 1024
//       u8   nonce_hex[64]          ASCII lowercase hex
//
//     Public blob extends v2 with:
//       u8   nonce[32]              decoded freshness nonce
//
//   v4 (Task 22): adds json_context_offset to the witness; public blob
//                 unchanged. Context byte-length is derived in-circuit
//                 from the SHA padding via FlatSHA256Circuit::find_len —
//                 no independent context_len wire, which forecloses any
//                 length-inconsistency attack between SHA and byte-eq.
//     Witness blob extends v3 with:
//       u32  json_context_offset    relative to signed_content;
//                                   + context_len <= 1024 (enforced with
//                                   the conservative bound ≤ 1024 - 32 here,
//                                   since the context can be at most 32 bytes).
//
//   v5 (Task 23): adds json_declaration_offset to the witness; public
//                 blob unchanged. The declaration length is a compile-
//                 time constant (`kDeclarationLen = 510`) and the
//                 phrase itself (`kDeclarationPhrase`) is a circuit-side
//                 literal — so there is no length or content wire, just
//                 the locator offset into signed_content.
//     Witness blob extends v4 with:
//       u32  json_declaration_offset  relative to signed_content;
//                                     + kDeclarationLen <= 1024.
//
//   v6 (Task 24): adds a SHA-256 hash of signed_content against a
//                 prover-claimed message_digest. signed_content stays
//                 as raw bytes + zero padding in the blob — the host
//                 filler computes the SHA Merkle-Damgård padding
//                 off-circuit and pushes the padded buffer into the
//                 signed_content[] circuit wires. The circuit treats
//                 `signed_content_len` as a host-side filler parameter
//                 only (same discipline Task 22 applied to context_len:
//                 circuit-side length derivable from SHA padding).
//     Witness blob extends v5 with:
//       u8   message_digest[32]       prover-claimed SHA-256(signed_content)
//
//   v7 (Task 25a): no blob schema change — witness and public blobs
//                  stay identical to v6. The split that happens here
//                  is proof-format only: the single GF(2^128) circuit
//                  gains a MAC-binding public input (2 mac values + 1
//                  av, all GF(2^128) native), and a second circuit over
//                  Fp256Base is introduced that carries the same MAC
//                  primitive in the Fp256 field. The two circuits share
//                  a transcript, and a non-zero sentinel is bound by
//                  both MACs.
//
//   v8 (Task 29): real ECDSA verification + SHA-256(cert_tbs) MAC
//                 binding. The sentinel is gone; the sig circuit now
//                 instantiates `VerifyCircuit<LC, Fp256Base, P256>`
//                 against the hardcoded DIIA QTSP 2311 root pubkey,
//                 and the MAC-bound value is the cert_tbs digest
//                 computed in the hash circuit.
//     Witness blob extends v7 with:
//       u32  cert_tbs_len           in [0, 2039]
//       u8   cert_tbs[2048]         raw bytes + zero pad; filler SHA-pads
//       u8   cert_sig_r[32]         big-endian scalar (DER-parsed in Rust)
//       u8   cert_sig_s[32]         big-endian scalar
//     Public blob unchanged from v7 (root_pk is a compile-time
//       constant at the circuit-build site, not a public input).
//     Extended proof-output format:
//       u32  schema_version(= 8)
//       u8   macs_b[32]             2 × GF(2^128) values = MAC of
//                                   `e = SHA-256(cert_tbs)` (low+high)
//       u8   hash_zk[...]           ZkProof<GF2_128>, self-delimited
//       u8   sig_zk[...]            ZkProof<Fp256Base>, self-delimited
//
//   v11 (Task 34): nullifier from stable-ID — invariant 7. The 256-bit
//                  public output `nullifier` is derived in-circuit as
//                  `SHA-256(stable_id[16] || context_raw[..ctx_len])`,
//                  where `stable_id` is the 16-byte value of the X.520
//                  serialNumber attribute (OID 2.5.4.5) embedded in
//                  cert_tbs's Subject DN (DIIA RNOKPP format: `TINUA-`
//                  + 10 digits). Three new host-witnessed fields extend
//                  the witness blob:
//                    `subject_sn_offset_in_tbs`        offset of 9-byte
//                                                     DER anchor in
//                                                     cert_tbs (370 for
//                                                     current fixtures).
//                    `subject_dn_start_offset_in_tbs`  offset of outer
//                                                     Subject DN
//                                                     SEQUENCE in
//                                                     cert_tbs (294 for
//                                                     current fixtures
//                                                     — feeds the
//                                                     dual-match range
//                                                     check).
//                    `trust_anchor_index`              selects which
//                                                     kTrustAnchors[]
//                                                     entry the sig
//                                                     circuit's cert-
//                                                     sig ECDSA runs
//                                                     under. #34 left
//                                                     this as a
//                                                     placeholder;
//                                                     #36 activated
//                                                     it with an
//                                                     in-circuit
//                                                     `vlt(index,
//                                                      kTrustAnchorCount)`
//                                                     bound check +
//                                                     host-side
//                                                     mirror.
//                  The public blob gains `nullifier[32]` +
//                  `trust_anchor_index u32`. Hash-circuit public inputs
//                  grow by 32×v8 (nullifier) + v32 (trust_anchor_index)
//                  between `nonce_bytes` and the MAC region — MAC
//                  indexing shifts by 288 bits.
//                  Dual-match protection: the 9-byte DER anchor appears
//                  at BOTH the subject DN serialNumber AND the issuer
//                  DN serialNumber (both attributes share the same
//                  X.520 ATV shape). The
//                  in-circuit range check
//                  `subject_sn_offset_in_tbs >
//                   subject_dn_start_offset_in_tbs`
//                  rejects any offset pointing before the subject DN,
//                  which includes the entire issuer DN block. Without
//                  this check a prover could bind `nullifier` to the
//                  issuer's stable ID — defeating the anti-replay
//                  guarantee.
//                  v1 constraint: stable-ID length is fixed at 16
//                  bytes (DIIA RNOKPP). Non-DIIA QTSPs with different
//                  lengths deferred to Task #37.
//     Witness blob extends v10 with:
//       u32 subject_sn_offset_in_tbs
//       u32 subject_dn_start_offset_in_tbs
//       u32 trust_anchor_index       (bound-checked against
//                                     kTrustAnchorCount by Task #36)
//     Public blob extends v10 with:
//       u8  nullifier[32]
//       u32 trust_anchor_index
//     Transcript seed "p7s-7-hash".
//
//   v10 (Task 31): messageDigest binding — invariant 2c. The 32-byte
//                  OCTET STRING value of the CMS messageDigest
//                  attribute (embedded inside signed_attrs) is asserted
//                  to byte-equal blob.message_digest[32] (already bound
//                  to SHA-256(signed_content) by invariant 2b). A new
//                  host-witnessed u32 wire `signed_attrs_md_offset`
//                  locates the messageDigest Attribute SEQUENCE tag
//                  (0x30) within signed_attrs; the circuit asserts a
//                  17-byte DER anchor at window[0..17] and the 32-byte
//                  digest equality at window[17..49]. Anchor is NOT
//                  unique within signed_attrs (the nested
//                  contentTimestamp TSA token contains its own
//                  messageDigest with the same 17-byte prefix), but
//                  SHA-256 preimage resistance makes a dual-offset
//                  attack infeasible — see §6.2 of
//                  docs/superpowers/specs/handoff-31-messagedigest-binding.md.
//     Witness blob extends v9 with:
//       u32  signed_attrs_md_offset   offset of messageDigest Attribute
//                                     SEQUENCE tag (0x30) WITHIN
//                                     signed_attrs (= md_value_offset - 17).
//                                     Host-witnessed — current
//                                     fixtures measure 60 but the
//                                     underlying BER ordering is an
//                                     implementation choice of the
//                                     signer, not a canonical form,
//                                     so a re-issuance could shift it.
//     Public blob unchanged from v9. Transcript seed "p7s-31-hash".
//
//   v9 (Task 26): CMS content signature over signedAttrs — invariant 2a.
//                 The hash circuit computes a SECOND SHA-256, this time
//                 over the CAdES-canonical signedAttrs (witnessed form
//                 is `[0xA0, body[1..]]`; circuit rewrites the first
//                 byte to `0x31` and hashes the result — an in-circuit
//                 IMPLICIT→SET rewrite that only costs one const vbit
//                 plus a byte-equality assertion on the witness's
//                 first byte). The sig circuit instantiates a SECOND
//                 `VerifyCircuit` against the user's `holder_pk` (the
//                 same bytes invariant 4 constrains on the hash side;
//                 parsed host-side from `pub.pk` and supplied as
//                 Fp256Base X + Y public inputs on the sig circuit).
//                 `e2 = SHA-256(signedAttrs_rewritten)` joins `e` as a
//                 MAC-bound message.
//     Witness blob extends v8 with:
//       u32  signed_attrs_len       in [0, 1527]
//       u8   signed_attrs[1536]     raw bytes + zero pad; first byte MUST
//                                   be 0xA0 ([0] IMPLICIT tag as in p7s);
//                                   filler SHA-pads after rewriting [0]
//                                   to 0x31.
//       u8   content_sig_r[32]      big-endian scalar (DER-parsed in Rust)
//       u8   content_sig_s[32]      big-endian scalar
//     Public blob unchanged from v8. Sig-circuit holder_pk X/Y are
//       derived host-side from `pub.pk[1..33]` / `pub.pk[33..65]` (SEC1
//       big-endian), converted to Fp256Base Montgomery form, and
//       pushed as sig-circuit public-input EltWs. Host-side the
//       verifier enforces pk[0] == 0x04; the hash circuit additionally
//       asserts `pk_bytes[0] == 0x04` on the wire level.
//     Extended proof-output format:
//       u32  schema_version(= 9)
//       u8   macs_b[64]             4 × GF(2^128) values = MAC of
//                                   `e` (low+high) + `e2` (low+high)
//       u8   hash_zk[...]           ZkProof<GF2_128>, self-delimited
//       u8   sig_zk[...]            ZkProof<Fp256Base>, self-delimited
// -----------------------------------------------------------------------------

#include "p7s_zk.h"

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <mutex>
#include <vector>

#include "algebra/convolution.h"
#include "algebra/fp2.h"
#include "algebra/reed_solomon.h"
#include "arrays/dense.h"
#include "circuits/compiler/compiler.h"
#include "circuits/ecdsa/verify_witness.h"
#include "circuits/logic/bit_plucker_encoder.h"
#include "circuits/logic/compiler_backend.h"
#include "circuits/logic/logic.h"
#include "circuits/logic/routing.h"
#include "circuits/mac/mac_reference.h"
#include "circuits/mac/mac_witness.h"
#include "circuits/p7s/p7s_circuit.h"
#include "circuits/p7s/p7s_hash.h"
#include "circuits/p7s/sub/byte_range_eq.h"
#include "circuits/p7s/sub/declaration_whitelist.h"
#include "circuits/p7s/sub/hex_decode.h"
#include "circuits/p7s/sub/p7s_signature.h"
#include "circuits/sha/flatsha256_witness.h"
#include "ec/p256.h"
#include "gf2k/gf2_128.h"
#include "gf2k/lch14_reed_solomon.h"
#include "proto/circuit.h"
#include "random/secure_random_engine.h"
#include "random/transcript.h"
#include "sumcheck/circuit.h"
#include "util/crypto.h"
#include "util/readbuffer.h"
#include "zk/zk_proof.h"
#include "zk/zk_prover.h"
#include "zk/zk_verifier.h"

namespace proofs {
namespace p7s {
namespace {

// ========================= Hash circuit (GF(2^128)) =========================
using F = GF2_128<>;
using gf2k = F::Elt;
using RSFactory = LCH14ReedSolomonFactory<F>;
using CB = CompilerBackend<F>;
using LC = Logic<F, CB>;
using ContextHash = P7sHash<LC, kContextMaxBlocks>;
using SignedContentHash = P7sHash<LC, kSignedContentMaxBlocks>;
using CertTbsHash = P7sHash<LC, kCertTbsMaxBlocks>;
using SignedAttrsHash = P7sHash<LC, kSignedAttrsMaxBlocks>;
using NullifierHash = P7sHash<LC, kNullifierShaBlocks>;  // v11 (Task 34)
using ByteRangeEqC = ByteRangeEq<LC>;
using HexDecodeC = HexDecode<LC>;
using RoutingC = Routing<LC>;
using ContextShaBw = ContextHash::ShaBlockWitness;
using SignedContentShaBw = SignedContentHash::ShaBlockWitness;
using CertTbsShaBw = CertTbsHash::ShaBlockWitness;
using SignedAttrsShaBw = SignedAttrsHash::ShaBlockWitness;
using NullifierShaBw = NullifierHash::ShaBlockWitness;  // v11 (Task 34)

// 26-byte P-256 SPKI DER prefix — kept in both the host parser
// (`crates/zk-eidas-p7s/src/parser.rs`) and the hash circuit's
// anchor assertion. Any change requires updating both sites.
constexpr uint8_t kSpkiP256Prefix[kSpkiPrefixLen] = {
    0x30, 0x59,                                    // SPKI SEQUENCE hdr (l=89)
    0x30, 0x13,                                    // AlgId SEQUENCE hdr (l=19)
    0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d,      // OID id-ecPublicKey
    0x02, 0x01,
    0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d,      // OID prime256v1 (P-256)
    0x03, 0x01, 0x07,
    0x03, 0x42, 0x00,                              // BIT STRING hdr (l=66,
                                                   //                unused=0)
};

// 9-byte X.520 serialNumber attribute DER prefix for a 16-byte
// stable-ID (DIIA RNOKPP format: `TINUA-` + 10 digits, which the v1
// lengths are dimensioned for). Attribute SEQUENCE hdr (l=23) + OID
// 2.5.4.5 + PrintableString hdr (l=16). Asserted on-wire at
// `cert_tbs[subject_sn_offset..+9]`. Mirrored in
// `crates/zk-eidas-p7s/src/parser.rs`'s `X520_SUBJECT_SN_ANCHOR`.
// Any change requires updating both sites. v1 fixes lengths at 23/16;
// non-DIIA QTSPs with variable lengths are Task #37.
constexpr uint8_t kSubjectSnAnchor[kSubjectSnAnchorLen] = {
    0x30, 0x17,                                    // ATV SEQUENCE (l=23)
    0x06, 0x03, 0x55, 0x04, 0x05,                  // OID 2.5.4.5 (serialNumber)
    0x13, 0x10,                                    // PrintableString (l=16)
};

// 17-byte CMS messageDigest attribute DER prefix (RFC 5652). Fixed for
// all CMS SignedData whose messageDigest is SHA-256 (all modern CAdES
// p7s): Attribute SEQUENCE hdr + OID messageDigest + SET OF hdr +
// OCTET STRING hdr. The 32-byte SHA-256 value follows at window[17].
// Mirrored in `crates/zk-eidas-p7s/src/parser.rs`'s
// `CMS_MESSAGE_DIGEST_ATTR_PREFIX` and in parse_witness_blob below.
constexpr uint8_t kSignedAttrsMdPrefix[kSignedAttrsMdPrefixLen] = {
    0x30, 0x2f,                                    // Attribute SEQUENCE (l=47)
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7,      // OID messageDigest
    0x0d, 0x01, 0x09, 0x04,                        // (1.2.840.113549.1.9.4)
    0x31, 0x22,                                    // SET OF AttributeValue (l=34)
    0x04, 0x20,                                    // OCTET STRING hdr (l=32)
};

// Hash-side MAC primitive. Uses the native `MACGF2` variant whose v128
// IS an EltW (GF(2^128) is 128 bits wide natively).
using MacBitPluckerH = BitPlucker<LC, kMacPluckerBits>;
using MACH = MACGF2<CB, MacBitPluckerH>;
using MACHWitness = typename MACH::Witness;

// ========================= Sig circuit (Fp256Base) ==========================
// Typedefs copied verbatim from mdoc_zk.cc:71-90 so the two circuits
// can share an omega / FFT / Reed-Solomon stack. Do not invent
// alternatives — the root-of-unity constants below are matched to
// these typedefs and to the mdoc-side FFT setup.
using Elt256 = Fp256Base::Elt;
using f2_p256 = Fp2<Fp256Base>;
using Elt256_2 = f2_p256::Elt;
using FftExtConvolutionFactory_b = FFTExtConvolutionFactory<Fp256Base, f2_p256>;
using RSFactory_b = ReedSolomonFactory<Fp256Base, FftExtConvolutionFactory_b>;
using CB256 = CompilerBackend<Fp256Base>;
using LC256 = Logic<Fp256Base, CB256>;
using P7sSigCircuit = P7sSignature<LC256, Fp256Base, P256>;
using P7sSigWitness = typename P7sSigCircuit::Witness;

// Root of unity for the f_p256^2 extension field (same as mdoc_zk.cc).
static constexpr char kRootX[] =
    "112649224146410281873500457609690258373018840430489408729223714171582664"
    "680802";
static constexpr char kRootY[] =
    "84087994358540907695740461427818660560182168997182378749313018254450460212"
    "908";

// Ligero parameters — match zk_testing.h's kLigeroRate / kLigeroNreq so
// Task-25 proofs have the same statistical-soundness margin as the
// reference regression tests.
constexpr size_t kRate = 4;
constexpr size_t kNreq = 189;

// Transcript seed — bumped from "p7s-31-hash" to "p7s-7-hash" so proofs
// minted under v10 (no in-circuit nullifier) cannot be misinterpreted
// as v11 proofs. A SINGLE Transcript instance is used for hash commit,
// av sampling, and sig commit/prove; both circuits share the same seed
// (mirrors mdoc, which uses one transcript with circuit-specific
// processing keyed by the distinct circuit structures themselves). The
// per-circuit seed below names the hash-side convention; the sig side
// consumes the same Transcript instance directly (no second seed — if
// that changes, bump both).
constexpr char kHashTranscriptSeed[] = "p7s-7-hash";
constexpr size_t kHashTranscriptSeedLen = sizeof(kHashTranscriptSeed) - 1;

constexpr size_t kShaBlockBytes = 64;
constexpr size_t kContextPaddedBytes = kShaBlockBytes * kContextMaxBlocks;
constexpr size_t kSignedContentPaddedBytes =
    kShaBlockBytes * kSignedContentMaxBlocks;
static_assert(kSignedContentPaddedBytes == kMaxSignedContent,
              "signed_content buffer must match padded SHA buffer size");

// log2(1024) = 10. `json_pk_offset` fits in 10 bits.
constexpr size_t kSignedContentLogN = 10;
static_assert((size_t{1} << kSignedContentLogN) == kMaxSignedContent,
              "kSignedContentLogN must equal log2(kMaxSignedContent)");

// Blob schema version.
constexpr uint32_t kBlobSchemaVersion = 11;

// ===========================================================================
// Hash-circuit public-input layout (v11). v11 (Task 34) adds two new
// public inputs between nonce_bytes and the MAC region: a 256-bit
// `nullifier` output (32 × v8) and a 32-bit `trust_anchor_index`
// (v32). Task 36 activated the trust_anchor_index with an in-circuit
// `vlt(index, kTrustAnchorCount)` bound check against the compile-
// time `kTrustAnchors[]` table defined in sub/p7s_signature.h.
// MAC-region position shifts by their combined width; kHashMacIndex
// is still derived from kHashPubPreMac so every downstream index is
// correct.
//
//   [0]                              = const 1
//   [1 .. 1 + 256)                   = context_hash v256
//   [257 .. 257 + 520)               = pk_bytes (65 × v8)
//   [777 .. 777 + 256)               = nonce_bytes (32 × v8)
//   [1033 .. 1033 + 256)             = nullifier_bytes (32 × v8)    ← v11
//   [1289 .. 1289 + 32)              = trust_anchor_index v32       ← v11
//   [1321 .. 1321 + kTotalMacValues) = mac values (EltW each).
//   [1321 + kTotalMacValues]         = av (EltW)
//   npub_in_hash = 1321 + kTotalMacValues + 1 = 1330
constexpr size_t kHashPubConst = 1;
constexpr size_t kHashPubContextHash = 256;
constexpr size_t kHashPubPk = kPkBytes * 8;              // 520
constexpr size_t kHashPubNonce = kNonceBytes * 8;        // 256
constexpr size_t kHashPubNullifier = kNullifierLen * 8;  // 256
constexpr size_t kHashPubTrustAnchorIdx = 32;            // v32 placeholder
constexpr size_t kHashPubPreMac =
    kHashPubConst + kHashPubContextHash + kHashPubPk + kHashPubNonce +
    kHashPubNullifier + kHashPubTrustAnchorIdx;
// Each hash-side MAC public input is 1 native EltW (GF2_128 is 128b
// wide, and a v128 IS an EltW here). kTotalMacValues mac values +
// 1 av = (kTotalMacValues + 1) EltW.
constexpr size_t kHashMacInputWires = kTotalMacValues + 1;
constexpr size_t kHashPubTotal = kHashPubPreMac + kHashMacInputWires;
static_assert(kHashPubPreMac == 1321,
              "layout drift — update kHashPubPreMac comment & index");
static_assert(kHashPubTotal == 1330,
              "layout drift — update npub_in_hash comment");

// Index (in the DENSE Wit array) where the hash MAC region begins.
// update_mac_in_dense writes (kTotalMacValues + 1) native EltW at this
// position. Must match the circuit's declared public-input order —
// anything else would let a malicious prover slot forged MACs into
// positions the verifier doesn't bind.
constexpr size_t kHashMacIndex = kHashPubPreMac;

// ===========================================================================
// Sig-circuit public-input layout (Task #44 — v10 bump). Holder pk is
// NOT in the public blob (privacy: leaking cert SPKI would deanonymize
// the holder). It enters as a PRIVATE EltW pair in the sig witness,
// bound to the hash-side cert_tbs SPKI bytes via the MAC gadget.
//
// Task #44 added a SINGLE public EltW input for `trust_anchor_index`
// (the same u32 value the hash circuit reads, reinterpreted as a
// field element). The sig circuit constrains it to `{0, 1}` for N=2
// and uses it to multiplex over `kTrustAnchors[0..N]`. Soundness: the
// verifier parses one public blob and pushes the SAME
// `trust_anchor_index` into both circuits, so they agree by
// construction — no MAC binding needed for this specific value.
//
//   [0]                              = const 1 (auto-allocated wire 0)
//   [1]                              = trust_anchor_index (EltW)      ← new
//   [2 .. 2 + 128)                   = mac values[0] as v128 (mac_e[0])
//   [130 .. 130 + 128)               = mac values[1] (mac_e[1])
//   [258 .. 258 + 128)               = mac values[2] (mac_e2[0])
//   [386 .. 386 + 128)               = mac values[3] (mac_e2[1])
//   [514 .. 514 + 128)               = mac values[4] (mac_spki_x[0])
//   [642 .. 642 + 128)               = mac values[5] (mac_spki_x[1])
//   [770 .. 770 + 128)               = mac values[6] (mac_spki_y[0])
//   [898 .. 898 + 128)               = mac values[7] (mac_spki_y[1])
//   [1026 .. 1026 + 128)             = av (v128)
//   npub_in_sig = 1 + 1 + 9 × 128    = 1154
constexpr size_t kSigPubConst = 1;
// Single Fp256Base EltW carrying the trust_anchor_index (small u32
// value, range-constrained by the in-circuit `idx * (idx - 1) == 0`
// assertion for N=2 — tighten if N grows).
constexpr size_t kSigPubTrustAnchorIdx = 1;
// Each sig-side MAC public input is a v128 = 128 bit wires (Fp256Base
// isn't wide enough to hold a 128-bit GF(2^128) element as a single
// field element, so it's bit-decomposed).
constexpr size_t kSigMacBitsPerWire = 128;
constexpr size_t kSigMacInputWires =
    (kTotalMacValues + 1) * kSigMacBitsPerWire;  // 9 × 128 = 1152
constexpr size_t kSigPubTotal =
    kSigPubConst + kSigPubTrustAnchorIdx + kSigMacInputWires;
static_assert(kSigPubTotal == 1154,
              "layout drift — update npub_in_sig comment");

// Index (in the DENSE W_sig array) where the sig MAC region begins.
// update_mac_in_dense writes 128 wires per MAC value (one field
// element per bit).
constexpr size_t kSigMacIndex = kSigPubConst + kSigPubTrustAnchorIdx;  // 2

// ===========================================================================
// Hash circuit builder — keeps every pre-v7 constraint intact and adds
// the cross-field MAC binding at the end of the public-input section.
//
// v9 (Task 26) additions vs v8:
//   * Private witness: cert_tbs_spki_offset (11-bit offset of the
//     SPKI SEQUENCE tag inside cert_tbs — host-witnessed because
//     the subject DN length varies); signed_attrs_numb, signed_attrs
//     [1536] (first byte MUST be 0xA0 — [0] IMPLICIT tag), 24 SHA
//     block witnesses, e2_digest_bytes[32]; two additional MAC
//     witnesses (mac_witness_spki_x, mac_witness_spki_y).
//   * Constraint (2a): assert `signed_attrs[0] == 0xA0`. Construct a
//     1536-byte buffer whose first byte is the compile-time-const
//     0x31 (SET OF tag) and whose bytes [1..] route from
//     `signed_attrs[1..]`; assert SHA-256(that buffer) equals
//     `e2_digest_bytes`.
//   * Constraint (SPKI extraction): `Routing::shift` a 91-byte window
//     over cert_tbs at `cert_tbs_spki_offset`; assert the first 26
//     bytes match the fixed P-256 SPKI DER prefix; assert byte
//     26 is `0x04` (SEC1 uncompressed). The X coordinate is bytes
//     [27..59] (BE), Y is [59..91] (BE).
//   * MAC-bound messages grow to FOUR: `e`, `e2`, cert SPKI X, cert
//     SPKI Y (all in the LE-byte convention that matches the sig
//     side's MAC::unpack_msg). kMacMessagesCount = 4,
//     kTotalMacValues = 8.
std::unique_ptr<Circuit<F>> build_hash_circuit() {
  const F Fs;

  QuadCircuit<F> Q(Fs);
  const CB cbk(&Q);
  const LC lc(&cbk, Fs);
  ContextHash context_hasher(lc);
  SignedContentHash signed_content_hasher(lc);
  CertTbsHash cert_tbs_hasher(lc);
  SignedAttrsHash signed_attrs_hasher(lc);
  ByteRangeEqC breq(lc);
  HexDecodeC hex_decode(lc);
  RoutingC routing(lc);

  // ---- Public inputs (layout above) ----
  // Invariant 9 target (context_hash, bit-decomposed, 256 bits).
  auto context_hash = lc.template vinput<256>();

  // Invariant 4 target (decoded pk, 65 bytes → 65 v8 values).
  std::vector<typename LC::v8> pk_bytes(kPkBytes);
  for (size_t i = 0; i < kPkBytes; ++i) {
    pk_bytes[i] = lc.template vinput<8>();
  }

  // Invariant 5 target (decoded nonce, 32 bytes → 32 v8 values).
  std::vector<typename LC::v8> nonce_bytes(kNonceBytes);
  for (size_t i = 0; i < kNonceBytes; ++i) {
    nonce_bytes[i] = lc.template vinput<8>();
  }

  // v11 / Task 34: invariant 7 public output — nullifier SHA target.
  // Declared as a bit-decomposed v256 bitvec (same layout as
  // `context_hash` at the invariant 9 target), which matches FlatSHA's
  // big-endian-per-byte convention and avoids the byte-aligned wire
  // shuffling `pk_bytes` needs. The Rust public-blob side stores the
  // 32 bytes big-endian; `push_target` flips them into bit-per-wire
  // order consistent with the circuit's `assert_message_hash`.
  auto nullifier = lc.template vinput<256>();

  // v11 / Task 34; activated in Task 36; real bound check in Task #44.
  // trust_anchor_index (v32). The public blob carries a u32 selecting
  // which entry of the compile-time `kTrustAnchors[]` table the sig
  // circuit's cert-sig ECDSA verifies under. Phase 2b now ships with
  // kTrustAnchorCount = 2 (TestAnchorA + TestAnchorB), so the
  // in-circuit `vlt(index, 2)` is a genuine 1-bit bound check: any
  // prover claiming an index >= 2 fails here.
  auto trust_anchor_index = lc.template vinput<kHashPubTrustAnchorIdx>();
  // In-circuit bound check: trust_anchor_index < kTrustAnchorCount.
  // The sig circuit independently range-constrains the same index
  // value via `idx * (idx - 1) == 0` (see build_sig_circuit); verifier
  // parses one public blob and pushes the same u32 into both circuits,
  // so the two checks bracket the same value from both sides.
  lc.assert1(lc.vlt(trust_anchor_index,
                    static_cast<uint64_t>(kTrustAnchorCount)));

  // Task 25a MAC inputs (native GF(2^128) EltW for each value).
  // In GF(2^128) a v128 is natively an EltW, so each MAC public input
  // is a single wire (compare with the sig circuit, where the same
  // 128-bit value fills 128 Fp256Base wires). Keep these in lockstep
  // with kHashMacIndex / kHashMacInputWires above.
  typename LC::EltW mac_pub[kHashMacInputWires];
  for (size_t i = 0; i < kHashMacInputWires; ++i) {
    mac_pub[i] = lc.eltw_input();
  }

  // ---- Private witness ----
  Q.private_input();

  // v12 (Plan 1, 2026-04-27) — holder_seed is a 32-byte private witness
  // re-used across invariants 7 (per-app nullifier preimage) and 14
  // (enroll_commit preimage). Same wires, no copies — invariant 15
  // (wire equality between the two preimages' holder_seed bytes) is
  // enforced trivially because both invariants reference these same
  // `holder_seed[i]` values via `vassert_eq`. Path A derives this from
  // an EIP-712 deterministic ECDSA signature; Path B from TEE-ECDH;
  // both are opaque to the circuit.
  std::vector<typename LC::v8> holder_seed(kHolderSeedLen);
  for (size_t i = 0; i < kHolderSeedLen; ++i) {
    holder_seed[i] = lc.template vinput<8>();
  }

  // Invariant 9 SHA witness (context hash).
  auto context_numb = lc.template vinput<8>();
  std::vector<typename LC::v8> context_in(kContextPaddedBytes);
  for (size_t i = 0; i < kContextPaddedBytes; ++i) {
    context_in[i] = lc.template vinput<8>();
  }
  std::vector<ContextShaBw> context_bw(kContextMaxBlocks);
  for (size_t b = 0; b < kContextMaxBlocks; ++b) {
    context_bw[b].input(lc);
  }

  // Invariant 4: full signed_content (SHA-256 padded preimage),
  // json_pk_offset, pk_hex, nibble witnesses.
  std::vector<typename LC::v8> signed_content(kMaxSignedContent);
  for (size_t i = 0; i < kMaxSignedContent; ++i) {
    signed_content[i] = lc.template vinput<8>();
  }
  auto json_pk_offset = lc.template vinput<kSignedContentLogN>();

  std::vector<typename LC::v8> pk_hex(kPkHexLen);
  for (size_t i = 0; i < kPkHexLen; ++i) {
    pk_hex[i] = lc.template vinput<8>();
  }
  std::vector<typename LC::v8> hi_lo_nibbles(kPkHexLen);
  for (size_t i = 0; i < kPkHexLen; ++i) {
    hi_lo_nibbles[i] = lc.template vinput<8>();
  }

  // Invariant 5: json_nonce_offset, nonce_hex, nonce_nibbles.
  auto json_nonce_offset = lc.template vinput<kSignedContentLogN>();
  std::vector<typename LC::v8> nonce_hex(kNonceHexLen);
  for (size_t i = 0; i < kNonceHexLen; ++i) {
    nonce_hex[i] = lc.template vinput<8>();
  }
  std::vector<typename LC::v8> nonce_nibbles(kNonceHexLen);
  for (size_t i = 0; i < kNonceHexLen; ++i) {
    nonce_nibbles[i] = lc.template vinput<8>();
  }

  // Invariant 6 / 10 locators.
  auto json_context_offset = lc.template vinput<kSignedContentLogN>();
  auto json_declaration_offset = lc.template vinput<kSignedContentLogN>();

  // Invariant 2b: signed_content_numb, block witnesses, message_digest.
  auto signed_content_numb = lc.template vinput<8>();
  std::vector<SignedContentShaBw> signed_content_bw(kSignedContentMaxBlocks);
  for (size_t b = 0; b < kSignedContentMaxBlocks; ++b) {
    signed_content_bw[b].input(lc);
  }
  std::vector<typename LC::v8> message_digest(kMessageDigestLen);
  for (size_t i = 0; i < kMessageDigestLen; ++i) {
    message_digest[i] = lc.template vinput<8>();
  }

  // Task 29 / invariant 1 — cert_tbs SHA witness + claimed digest.
  // cert_tbs_numb holds the block index of the last SHA block that
  // carries real data (same convention as FlatSHA for context / sc).
  // cert_tbs[kCertTbsMaxBytes] is the pre-padded SHA input buffer
  // (host-side filler applies Merkle-Damgård padding). cert_tbs_bw
  // carries per-block intermediate SHA witness values.
  auto cert_tbs_numb = lc.template vinput<8>();
  // Task 26 — offset of the SPKI SEQUENCE (0x30) within cert_tbs.
  // Host-witnessed (not compile-time stable across holders — see
  // handoff-30 §3.2). Bit-width matches kCertTbsMaxBytes so
  // the offset covers [0, 2047]. Kept adjacent to cert_tbs_numb so
  // "all cert_tbs metadata" lives in one place.
  auto cert_tbs_spki_offset = lc.template vinput<kCertTbsLenBits>();
  std::vector<typename LC::v8> cert_tbs(kCertTbsMaxBytes);
  for (size_t i = 0; i < kCertTbsMaxBytes; ++i) {
    cert_tbs[i] = lc.template vinput<8>();
  }
  std::vector<CertTbsShaBw> cert_tbs_bw(kCertTbsMaxBlocks);
  for (size_t b = 0; b < kCertTbsMaxBlocks; ++b) {
    cert_tbs_bw[b].input(lc);
  }
  // e_digest_bytes: prover-claimed SHA-256(cert_tbs) output, 32 bytes
  // in big-endian order (byte 0 = most-significant). The circuit
  // builds two v256 views from these 32 wires:
  //   * e_digest_v256_flatsha — FlatSHA convention (byte_idx = (255-j)/8,
  //     bit_idx = j%8) — asserted against cert_tbs_hasher.
  //   * e_digest_v256_mac     — LE convention (byte_idx = j/8,
  //     bit_idx = j%8) — passed to the MAC gadget. Same underlying
  //     wires, different view, so MAC and SHA bind consistent bytes
  //     without any extra equality constraints.
  std::vector<typename LC::v8> e_digest_bytes(kCertTbsDigestLen);
  for (size_t i = 0; i < kCertTbsDigestLen; ++i) {
    e_digest_bytes[i] = lc.template vinput<8>();
  }

  // Task 26 / invariant 2a — signedAttrs SHA witness + claimed digest.
  // signed_attrs_numb holds the SHA block count of the CAdES-canonical
  // buffer ([0x31, body[1..]] + Merkle-Damgård pad). signed_attrs holds
  // the CAdES-CANONICAL SHA-padded bytes (first byte = 0x31, the SET
  // OF tag; bytes [1..len] = witnessed signedAttrs body; bytes
  // [len..] = SHA-256 Merkle-Damgård pad). The raw p7s carries a
  // [0] IMPLICIT tag (0xA0); the host filler rewrites byte 0 to 0x31
  // before SHA-padding, same transformation the OpenSSL CMS signer
  // applies when computing the content-sig digest. Soundness of the
  // rewrite: the content-sig ECDSA in the sig circuit binds the
  // holder-produced digest, so a malicious prover swapping bytes
  // here would need a holder-signed digest of their forged bytes —
  // unavailable without the private key.
  auto signed_attrs_numb = lc.template vinput<8>();
  // Task 31 — offset of the messageDigest Attribute SEQUENCE (0x30)
  // within signed_attrs. Host-witnessed (BER attribute ordering inside
  // signedAttrs is an implementation choice of the signer, not a
  // canonical form; both current fixtures happen to report 60 but a
  // signer-side change could shift this — see handoff-31 §4.2).
  // Bit-width matches kSignedAttrsMaxBytes so the offset covers
  // [0, 2047]. Adjacent to signed_attrs_numb so "all signed_attrs
  // metadata" lives in one place.
  auto signed_attrs_md_offset = lc.template vinput<kSignedAttrsLenBits>();
  std::vector<typename LC::v8> signed_attrs(kSignedAttrsMaxBytes);
  for (size_t i = 0; i < kSignedAttrsMaxBytes; ++i) {
    signed_attrs[i] = lc.template vinput<8>();
  }
  std::vector<SignedAttrsShaBw> signed_attrs_bw(kSignedAttrsMaxBlocks);
  for (size_t b = 0; b < kSignedAttrsMaxBlocks; ++b) {
    signed_attrs_bw[b].input(lc);
  }
  // e2_digest_bytes — SHA-256(signed_attrs_rewritten), 32 big-endian
  // bytes. Same dual-view trick as e_digest_bytes.
  std::vector<typename LC::v8> e2_digest_bytes(kSignedAttrsDigestLen);
  for (size_t i = 0; i < kSignedAttrsDigestLen; ++i) {
    e2_digest_bytes[i] = lc.template vinput<8>();
  }

  // v11 / Task 34: invariant 7 private witnesses.
  //   subject_sn_offset     host-witnessed offset of the 9-byte X.520
  //                         serialNumber DER anchor within cert_tbs.
  //                         370 for current fixtures.
  //   subject_dn_start      host-witnessed offset of the outer Subject
  //                         DN SEQUENCE within cert_tbs. 294 for
  //                         current fixtures. Feeds the dual-match
  //                         range check.
  //   nullifier_input_numb  SHA block count (= 1 since stable_id + ctx
  //                         always fits in one 64-byte block).
  //   nullifier_input[64]   host-padded SHA preimage
  //                         `stable_id[16] || context_raw[..] || SHA_pad`.
  //                         The circuit constrains bytes [0..16] to
  //                         equal the routed stable_id window, bytes
  //                         [16..16 + ctx_len] to equal context_in, and
  //                         byte-length to equal 16 + ctx_len; SHA
  //                         padding is trusted via FlatSHA's standard
  //                         length-binding.
  //   nullifier_input_bw[1] FlatSHA per-block intermediate witnesses.
  auto subject_sn_offset = lc.template vinput<kCertTbsLenBits>();
  auto subject_dn_start_offset = lc.template vinput<kCertTbsLenBits>();
  auto nullifier_input_numb = lc.template vinput<8>();
  std::vector<typename LC::v8> nullifier_input(kNullifierShaMaxBytes);
  for (size_t i = 0; i < kNullifierShaMaxBytes; ++i) {
    nullifier_input[i] = lc.template vinput<8>();
  }
  std::vector<NullifierShaBw> nullifier_input_bw(kNullifierShaBlocks);
  for (size_t b = 0; b < kNullifierShaBlocks; ++b) {
    nullifier_input_bw[b].input(lc);
  }

  // MAC witness (prover's `ap` halves). Four bound messages:
  //   0: e            = SHA-256(cert_tbs)
  //   1: e2           = SHA-256(signedAttrs_rewritten)
  //   2: holder_pk_x  = cert_tbs SPKI X coordinate (LE-byte convention)
  //   3: holder_pk_y  = cert_tbs SPKI Y coordinate (LE-byte convention)
  // Each witness is a MACGF2::Witness carrying 2 EltW ap halves.
  MACHWitness mac_witness_e;
  mac_witness_e.input(lc);
  MACHWitness mac_witness_e2;
  mac_witness_e2.input(lc);
  MACHWitness mac_witness_spki_x;
  mac_witness_spki_x.input(lc);
  MACHWitness mac_witness_spki_y;
  mac_witness_spki_y.input(lc);

  // ---- Constraints (unchanged from v6) ----
  // Invariant 9 — context hash.
  context_hasher.assert_message_hash(context_numb, context_in.data(),
                                     context_hash, context_bw.data());

  // Invariant 4a.
  std::vector<typename LC::v8> pk_window(kPkHexLen);
  const typename LC::v8 zz = lc.template vbit<8>(0);
  routing.template shift<typename LC::v8, kSignedContentLogN>(
      json_pk_offset, kPkHexLen, pk_window.data(), kMaxSignedContent,
      signed_content.data(), zz, /*unroll=*/3);
  breq.assert_eq(pk_window.data(), pk_hex.data(), kPkHexLen);

  // Invariant 4b.
  hex_decode.assert_decodes(pk_hex.data(), pk_bytes.data(),
                            hi_lo_nibbles.data(), kPkBytes);

  // Invariant 5a.
  std::vector<typename LC::v8> nonce_window(kNonceHexLen);
  routing.template shift<typename LC::v8, kSignedContentLogN>(
      json_nonce_offset, kNonceHexLen, nonce_window.data(), kMaxSignedContent,
      signed_content.data(), zz, /*unroll=*/3);
  breq.assert_eq(nonce_window.data(), nonce_hex.data(), kNonceHexLen);

  // Invariant 5b.
  hex_decode.assert_decodes(nonce_hex.data(), nonce_bytes.data(),
                            nonce_nibbles.data(), kNonceBytes);

  // Invariant 6.
  auto ctx_len = context_hasher.template derive_byte_len<kContextLenBits>(
      context_in.data(), context_numb);
  std::vector<typename LC::v8> ctx_window(kContextMaxBytes);
  routing.template shift<typename LC::v8, kSignedContentLogN>(
      json_context_offset, kContextMaxBytes, ctx_window.data(),
      kMaxSignedContent, signed_content.data(), zz, /*unroll=*/3);
  assert_range_equals_masked<LC, kContextMaxBytes, kContextLenBits>(
      lc, context_in.data(), ctx_window.data(), ctx_len);

  // Invariant 10.
  std::vector<typename LC::v8> decl_window(kDeclarationLen);
  routing.template shift<typename LC::v8, kSignedContentLogN>(
      json_declaration_offset, kDeclarationLen, decl_window.data(),
      kMaxSignedContent, signed_content.data(), zz, /*unroll=*/3);
  std::vector<typename LC::v8> decl_expected(kDeclarationLen);
  for (size_t i = 0; i < kDeclarationLen; ++i) {
    decl_expected[i] = lc.template vbit<8>(kDeclarationPhrase[i]);
  }
  breq.assert_eq(decl_window.data(), decl_expected.data(), kDeclarationLen);

  // Invariant 2b — message_digest == SHA-256(signed_content).
  typename LC::v256 message_digest_v256;
  for (size_t j = 0; j < 256; ++j) {
    size_t byte_idx = (255 - j) / 8;
    size_t bit_idx = j % 8;
    message_digest_v256[j] = message_digest[byte_idx][bit_idx];
  }
  signed_content_hasher.assert_message_hash(
      signed_content_numb, signed_content.data(), message_digest_v256,
      signed_content_bw.data());

  // Task 29 / invariant 1 — SHA-256(cert_tbs) == e_digest_bytes.
  // FlatSHA layout: target[j].bit = e_digest_bytes[(255-j)/8][j%8].
  typename LC::v256 e_digest_v256_flatsha;
  for (size_t j = 0; j < 256; ++j) {
    size_t byte_idx = (255 - j) / 8;
    size_t bit_idx = j % 8;
    e_digest_v256_flatsha[j] = e_digest_bytes[byte_idx][bit_idx];
  }
  cert_tbs_hasher.assert_message_hash(cert_tbs_numb, cert_tbs.data(),
                                      e_digest_v256_flatsha,
                                      cert_tbs_bw.data());

  // Task 26 / invariant 2a — SHA-256(signedAttrs_canonical) == e2_digest_bytes.
  // `signed_attrs[]` wires carry the SHA-padded CAdES-canonical buffer
  // directly (first byte = 0x31 from the host-side IMPLICIT→SET OF
  // rewrite). Pattern matches cert_tbs: padded-bytes-as-wires + SHA
  // gadget. No in-circuit rewrite needed; no raw 0xA0 assertion
  // needed — the content-sig ECDSA in the sig circuit binds the
  // signed digest, so any prover-supplied bytes that hash differently
  // would need a holder-signed ECDSA over that forged digest.
  typename LC::v256 e2_digest_v256_flatsha;
  for (size_t j = 0; j < 256; ++j) {
    size_t byte_idx = (255 - j) / 8;
    size_t bit_idx = j % 8;
    e2_digest_v256_flatsha[j] = e2_digest_bytes[byte_idx][bit_idx];
  }
  signed_attrs_hasher.assert_message_hash(
      signed_attrs_numb, signed_attrs.data(),
      e2_digest_v256_flatsha, signed_attrs_bw.data());

  // Task 31 / invariant 2c — the 32-byte OCTET STRING value of the CMS
  // messageDigest attribute embedded in signed_attrs byte-equals
  // `message_digest[32]` (already bound to SHA-256(signed_content) by
  // invariant 2b). Closes the soundness gap where an attacker with
  // honest (cert, signed_attrs, sigs) could substitute a fake
  // signed_content and pre-image `message_digest = SHA-256(fake)`; such
  // a prover passes invariants 1 + 2a + 2b independently but fails
  // here because `signed_attrs[md_offset+17..md_offset+49]` is
  // `SHA-256(real)` ≠ `SHA-256(fake)`.
  //
  // Anchor soundness (dual-match caveat): the 17-byte DER prefix is
  // NOT unique within signed_attrs — the nested
  // id-smime-aa-ets-contentTimestamp attribute wraps a TSA token
  // that contains its own messageDigest with the SAME 17-byte prefix
  // (current fixtures: offsets 60 AND 930). A prover could lie by
  // witnessing the inner offset; the window[17..49] bytes there equal
  // the TSA's digest = SHA-256(real_content) in an honest p7s (TSA
  // timestamps the same content). So witnessing the inner offset
  // succeeds iff the two 32-byte blobs coincidentally equal — which
  // happens exactly when the p7s is honest. To attack, a malicious
  // prover needs SHA-256(fake) to equal one of those two specific
  // 32-byte blobs — a SHA-256 preimage attack on a chosen target, 2^256
  // work. Do NOT "strengthen" the anchor to include bytes outside the
  // 17-byte fixed prefix: any longer anchor would encode a particular
  // signer's attribute ordering and break on any signer-side BER layout
  // change (see handoff-31 §6.3). SHA-256 preimage resistance is the
  // correct foundation here.
  std::vector<typename LC::v8> sa_md_window(kSignedAttrsMdWindowLen);
  routing.template shift<typename LC::v8, kSignedAttrsLenBits>(
      signed_attrs_md_offset, kSignedAttrsMdWindowLen, sa_md_window.data(),
      kSignedAttrsMaxBytes, signed_attrs.data(), zz, /*unroll=*/3);

  // 17-byte CMS messageDigest DER prefix anchor. Window[0..17] MUST
  // match kSignedAttrsMdPrefix (SEQUENCE hdr + OID + SET OF hdr +
  // OCTET STRING hdr). The prefix anchor pins the window to a REAL
  // CMS messageDigest attribute value — without it, a prover could
  // point the shifter at any 49-byte region whose bytes 17..49 happen
  // to equal message_digest. The dual-match (TSA-inner) scenario is
  // addressed by the SHA-256 preimage argument above.
  std::vector<typename LC::v8> sa_md_prefix_expected(kSignedAttrsMdPrefixLen);
  for (size_t i = 0; i < kSignedAttrsMdPrefixLen; ++i) {
    sa_md_prefix_expected[i] = lc.template vbit<8>(kSignedAttrsMdPrefix[i]);
  }
  breq.assert_eq(sa_md_window.data(), sa_md_prefix_expected.data(),
                 kSignedAttrsMdPrefixLen);

  // Load-bearing: the 32 bytes after the prefix equal blob.message_digest.
  // This is the constraint that closes the soundness gap.
  breq.assert_eq(&sa_md_window[kSignedAttrsMdPrefixLen],
                 message_digest.data(), kMessageDigestLen);

  // Task 26 (merged with #30) — SPKI extraction from cert_tbs.
  // Route a 91-byte window starting at `cert_tbs_spki_offset`. The
  // window must contain the 26-byte P-256 SPKI prefix followed by
  // `0x04` (SEC1 uncompressed tag) at index 26, then 32 bytes of
  // X and 32 bytes of Y.
  std::vector<typename LC::v8> spki_window(kSpkiWindowLen);
  routing.template shift<typename LC::v8, kCertTbsLenBits>(
      cert_tbs_spki_offset, kSpkiWindowLen, spki_window.data(),
      kCertTbsMaxBytes, cert_tbs.data(), zz, /*unroll=*/3);

  // Anchor: first 26 bytes MUST be the P-256 SPKI DER prefix.
  // Without this the prover could point the shifter at an arbitrary
  // byte-match elsewhere in cert_tbs. The 0x04 SEC1 tag is pinned
  // implicitly because the prefix ends with `0x03 0x42 0x00` (BIT
  // STRING header + unused-bits) and the ECDSA verify downstream
  // requires X/Y to be on the curve.
  std::vector<typename LC::v8> spki_prefix_expected(kSpkiPrefixLen);
  for (size_t i = 0; i < kSpkiPrefixLen; ++i) {
    spki_prefix_expected[i] = lc.template vbit<8>(kSpkiP256Prefix[i]);
  }
  breq.assert_eq(spki_window.data(), spki_prefix_expected.data(),
                 kSpkiPrefixLen);
  // Explicit SEC1 lead-byte check. Redundant with the prefix anchor
  // (since the prefix DOES NOT include 0x04), but kept as an extra
  // invariant so a future tightening/relaxation of kSpkiPrefixLen
  // doesn't silently change this property.
  typename LC::v8 expected_sec1_04 = lc.template vbit<8>(0x04);
  breq.assert_eq(&spki_window[kSpkiPrefixLen], &expected_sec1_04, 1);

  // SPKI X and Y bytes: big-endian per SEC1. The MAC LE convention
  // means bit j of the MAC message = bit (j % 8) of byte (j/8) in
  // the LITTLE-endian interpretation of the 32-byte integer. So
  // `spki_x_mac[j] = spki_x_be[31 - j/8][j%8]` — mirror of the
  // same trick used for e_digest / e2_digest (`(255-j)/8 == 31 -
  // j/8` for j < 256).
  const size_t kSpkiXStart = kSpkiPrefixLen + 1;            // 27
  const size_t kSpkiYStart = kSpkiXStart + kSpkiXYLen;      // 59
  typename LC::v256 spki_x_v256_mac;
  typename LC::v256 spki_y_v256_mac;
  for (size_t j = 0; j < 256; ++j) {
    size_t le_byte_idx = j / 8;
    size_t be_byte_idx = kSpkiXYLen - 1 - le_byte_idx;
    size_t bit_idx = j % 8;
    spki_x_v256_mac[j] = spki_window[kSpkiXStart + be_byte_idx][bit_idx];
    spki_y_v256_mac[j] = spki_window[kSpkiYStart + be_byte_idx][bit_idx];
  }

  // Task 34 / invariant 7 — nullifier from stable-ID.
  //
  // Step 1: route a 25-byte (9 + 16) stable-ID window from cert_tbs at
  // `subject_sn_offset`. The 9-byte DER anchor + 16-byte
  // PrintableString value occupy a contiguous range; the shifter
  // extracts it verbatim.
  std::vector<typename LC::v8> sn_window(kSubjectSnWindowLen);
  routing.template shift<typename LC::v8, kCertTbsLenBits>(
      subject_sn_offset, kSubjectSnWindowLen, sn_window.data(),
      kCertTbsMaxBytes, cert_tbs.data(), zz, /*unroll=*/3);

  // Step 2: 9-byte DER anchor assertion. Without this the prover could
  // aim the shifter at arbitrary 25 bytes of cert_tbs — e.g. a
  // PrintableString inside an unrelated extension whose first 9 bytes
  // coincidentally spell `30 17 06 03 55 04 05 13 10`.
  std::vector<typename LC::v8> sn_anchor_expected(kSubjectSnAnchorLen);
  for (size_t i = 0; i < kSubjectSnAnchorLen; ++i) {
    sn_anchor_expected[i] = lc.template vbit<8>(kSubjectSnAnchor[i]);
  }
  breq.assert_eq(sn_window.data(), sn_anchor_expected.data(),
                 kSubjectSnAnchorLen);

  // Step 3: dual-match range check. The identical 9-byte anchor also
  // appears at the ISSUER DN's serialNumber attribute (the issuer's
  // registration code fits the same X.520 ATV shape). Without this
  // check the prover could bind `nullifier` to the issuer's ID,
  // trivially sharing a nullifier with every holder under this
  // trust anchor. Enforce
  // `subject_sn_offset > subject_dn_start_offset` on-wire: the issuer
  // DN ends BEFORE the subject DN starts (they're serialized in
  // Issuer → Validity → Subject order), so any offset ≤
  // subject_dn_start_offset points either at the issuer DN or earlier
  // TBS fields — never at the holder's stable-ID.
  lc.assert1(lc.vlt(subject_dn_start_offset, subject_sn_offset));

  // v12 (Plan 1, 2026-04-27) — invariant 7 rewritten:
  //   nullifier == SHA-256(0x01 || holder_seed[32] || context_hash[32])
  //
  // The preimage is FIXED-LENGTH (65 bytes raw, 128 bytes SHA-padded
  // across 2 blocks). All bytes outside the holder_seed and
  // context_hash regions are compile-time constants — no host-side
  // variable-length routing, no mask, no length-binding bitvec dance.
  // Soundness rests on three byte-equality assertions:
  //   (a) nullifier_input[0]      == 0x01 (kDsTagPerAppNullifier)
  //   (b) nullifier_input[1..33]  == holder_seed[0..32]    (private)
  //   (c) nullifier_input[33..65] == context_hash[0..32]   (public)
  // plus
  //   (d) nullifier_input[65..128] == SHA-256 padding constants
  //                                   (0x80 || zeros || 0x0208 BE)
  // and finally
  //   (e) SHA-256(nullifier_input[0..128]) == public `nullifier`.
  //
  // The stable_id window routing + anchor + dual-match range check
  // above are KEPT — they're now consumed by invariant 12
  // (enroll_nullifier) instead of invariant 7. The block count is
  // fixed at 2 since the preimage length is fixed.

  // (a) Domain-separation tag at byte 0.
  {
    typename LC::v8 ds_tag = lc.template vbit<8>(kDsTagPerAppNullifier);
    breq.assert_eq(&nullifier_input[0], &ds_tag, 1);
  }

  // (b) holder_seed[32] at bytes 1..33. Same wires `holder_seed[i]`
  // are re-used by invariant 14 (enroll_commit); that satisfies the
  // invariant 15 cross-invariant wire equality automatically.
  for (size_t i = 0; i < kHolderSeedLen; ++i) {
    for (size_t b = 0; b < 8; ++b) {
      lc.assert_eq(nullifier_input[1 + i][b], holder_seed[i][b]);
    }
  }

  // (c) context_hash[32] at bytes 33..65. The public input
  // `context_hash` is a v256 in FlatSHA bit-decomposition convention
  // (bit j corresponds to bit (j%8) of output byte ((255 - j)/8)).
  // For each preimage byte i (0..32), pull the 8 bits of v256 from
  // positions [(31 - i)*8 .. (31 - i)*8 + 8). Inverse of the v8→v256
  // construction used for `e_digest_v256_mac` (~line 1100).
  for (size_t i = 0; i < kContextHashLen; ++i) {
    for (size_t b = 0; b < 8; ++b) {
      lc.assert_eq(nullifier_input[1 + kHolderSeedLen + i][b],
                   context_hash[(31 - i) * 8 + b]);
    }
  }

  // (d) SHA-256 Merkle–Damgård padding for a 65-byte message in 2
  // blocks (128 bytes total). Pad layout:
  //   byte 65       = 0x80
  //   bytes 66..120 = 0x00
  //   bytes 120..126 = 0x00 (high 6 bytes of the 64-bit BE length)
  //   bytes 126..128 = 0x02 0x08 (520 = 65 * 8 bits, BE u16 in tail)
  {
    typename LC::v8 pad80 = lc.template vbit<8>(0x80);
    typename LC::v8 pad00 = lc.template vbit<8>(0x00);
    typename LC::v8 len_hi = lc.template vbit<8>(0x02);
    typename LC::v8 len_lo = lc.template vbit<8>(0x08);
    breq.assert_eq(&nullifier_input[65], &pad80, 1);
    for (size_t i = 66; i < 126; ++i) {
      breq.assert_eq(&nullifier_input[i], &pad00, 1);
    }
    breq.assert_eq(&nullifier_input[126], &len_hi, 1);
    breq.assert_eq(&nullifier_input[127], &len_lo, 1);
  }

  // Bind the SHA block count to the constant 2. nullifier_input_numb
  // is host-witnessed to avoid changing the FlatSHA call shape; the
  // assertion forecloses the prover supplying numb=1 to elide the
  // second block's contribution.
  {
    typename LC::v8 numb_const = lc.template vbit<8>(kNullifierShaBlocks);
    breq.assert_eq(&nullifier_input_numb, &numb_const, 1);
  }

  // (e) SHA-256 over the fixed-layout 2-block preimage equals the
  // public `nullifier` v256 output. Same FlatSHA convention as v11.
  NullifierHash(lc).assert_message_hash(
      nullifier_input_numb, nullifier_input.data(),
      nullifier, nullifier_input_bw.data());

  // Task 29 / 26 — cross-field MAC binding to (e, e2, SPKI_X, SPKI_Y).
  // Digest views — byte-identical to the flatsha views (same wires,
  // same bits per j; `(255 - j) / 8 == 31 - j/8`). See Nit D comment
  // for the soundness story.
  typename LC::v256 e_digest_v256_mac;
  typename LC::v256 e2_digest_v256_mac;
  for (size_t j = 0; j < 256; ++j) {
    size_t le_byte_idx = j / 8;
    size_t be_byte_idx = kCertTbsDigestLen - 1 - le_byte_idx;
    size_t bit_idx = j % 8;
    e_digest_v256_mac[j]  = e_digest_bytes [be_byte_idx][bit_idx];
    e2_digest_v256_mac[j] = e2_digest_bytes[be_byte_idx][bit_idx];
  }

  MACH mac_check(lc);
  // mac_pub layout (matches kMacMsgIdx*):
  //   [0..2)   = mac_e[0..2]
  //   [2..4)   = mac_e2[0..2]
  //   [4..6)   = mac_spki_x[0..2]
  //   [6..8)   = mac_spki_y[0..2]
  //   [8]      = av
  typename LC::EltW mac_e_vals     [kMacValuesPerMessage];
  typename LC::EltW mac_e2_vals    [kMacValuesPerMessage];
  typename LC::EltW mac_spki_x_vals[kMacValuesPerMessage];
  typename LC::EltW mac_spki_y_vals[kMacValuesPerMessage];
  for (size_t i = 0; i < kMacValuesPerMessage; ++i) {
    mac_e_vals     [i] = mac_pub[kMacMsgIdxE     * kMacValuesPerMessage + i];
    mac_e2_vals    [i] = mac_pub[kMacMsgIdxE2    * kMacValuesPerMessage + i];
    mac_spki_x_vals[i] = mac_pub[kMacMsgIdxSpkiX * kMacValuesPerMessage + i];
    mac_spki_y_vals[i] = mac_pub[kMacMsgIdxSpkiY * kMacValuesPerMessage + i];
  }
  typename LC::EltW av_h = mac_pub[kTotalMacValues];
  mac_check.verify_mac(mac_e_vals,      av_h, e_digest_v256_mac,  mac_witness_e);
  mac_check.verify_mac(mac_e2_vals,     av_h, e2_digest_v256_mac, mac_witness_e2);
  mac_check.verify_mac(mac_spki_x_vals, av_h, spki_x_v256_mac,    mac_witness_spki_x);
  mac_check.verify_mac(mac_spki_y_vals, av_h, spki_y_v256_mac,    mac_witness_spki_y);

  return Q.mkcircuit(/*nc=*/1);
}

// Sig-circuit builder — invariants 1 + 2a (Task 26), with the Task #44
// multi-anchor multiplexer. Verifies:
//   (A) the signer cert's ECDSA signature against the selected
//       `kTrustAnchors[trust_anchor_index]` root public key over
//       `e = SHA-256(cert_tbs)`;
//   (B) the CMS content ECDSA signature against the user's
//       holder_pk (private input) over `e2 = SHA-256(signedAttrs)`.
// Both digests are MAC-bound to the hash circuit's SHA computations
// (cross-field MAC with shared `av` / per-message `ap` halves). The
// `trust_anchor_index` itself is a public Fp256Base EltW shared by
// value between the hash + sig circuits — the verifier parses one
// public blob and pushes the same u32 into both.
std::unique_ptr<Circuit<Fp256Base>> build_sig_circuit() {
  QuadCircuit<Fp256Base> Q(p256_base);
  const CB256 cbk(&Q);
  const LC256 lc(&cbk, p256_base);

  // ---- Public inputs ----
  // trust_anchor_index (single EltW) + mac values + av. mac values
  // are bit-decomposed v128 each: 4 bound messages × 2 mac values
  // each + 1 av = 9 × 128 = 1152 bit-wires, plus 1 EltW.
  typename LC256::EltW trust_anchor_idx = lc.eltw_input();
  typename LC256::v128 mac_pub[kTotalMacValues + 1];
  for (size_t i = 0; i < kTotalMacValues + 1; ++i) {
    mac_pub[i] = lc.template vinput<128>();
  }

  // ---- Private witness ----
  Q.private_input();

  // holder_pk_x / holder_pk_y — the cert SPKI coordinates, treated
  // as private Fp256Base EltWs. Binding to cert_tbs SPKI bytes on
  // the hash side is enforced by the per-message MAC gadget below
  // (messages 2 and 3). Making them private avoids leaking the
  // holder's QTSP-issued signing key (privacy: a fixed cert would
  // otherwise make holders individually identifiable across proofs).
  typename LC256::EltW holder_pk_x = lc.eltw_input();
  typename LC256::EltW holder_pk_y = lc.eltw_input();

  // Cert_tbs digest `e` and signedAttrs digest `e2` as scalar
  // Fp256Base elements. Same privacy rationale as holder_pk: binding
  // is via MAC (messages 0 and 1), not via exposing them.
  typename LC256::EltW e_wit  = lc.eltw_input();
  typename LC256::EltW e2_wit = lc.eltw_input();

  P7sSigWitness sig_witness;
  sig_witness.input(lc);

  // ---- Constraints ----
  // Trust-anchor root public key: one-hot multiplexer over
  // `kTrustAnchors[]` indexed by the public `trust_anchor_idx`.
  //
  // Soundness sketch: `trust_anchor_idx` is a PUBLIC Fp256Base input
  // that the verifier also sees in the hash circuit's public blob —
  // both circuits receive the same u32, reinterpreted into their
  // respective field representations. The hash circuit asserts
  // `vlt(trust_anchor_index, kTrustAnchorCount)` (v32 bits) so the
  // value is in `[0, N)`; this circuit independently constrains
  // `idx * (idx - 1) == 0` which for N=2 also forces `idx ∈ {0, 1}`.
  // The two constraints agree on the valid-index set by construction.
  //
  // For N=2, the one-hot mux `k0 + idx*(k1 - k0)` collapses to `k0`
  // when idx == 0 and `k1` when idx == 1. The product-of-differences
  // zero check below is the canonical `idx ∈ {0, 1}` constraint.
  //
  // `of_string` returns Elts already in Montgomery form (fp_generic.h
  // 329-336), so `lc.konst(...)` binds the right internal
  // representation directly.
  static_assert(kTrustAnchorCount == 2,
                "N=2 sig-side mux expects exactly 2 entries. To extend "
                "to N>2, replace the 2-way `k0 + idx*(k1-k0)` expression "
                "with a generic Σ_i Lagrange_i(idx) * k_i construction "
                "and update the `idx * (idx - 1) == 0` bound check.");
  typename LC256::EltW k0_x =
      lc.konst(p256_base.of_string(kTrustAnchors[0].root_pk_x_decimal));
  typename LC256::EltW k0_y =
      lc.konst(p256_base.of_string(kTrustAnchors[0].root_pk_y_decimal));
  typename LC256::EltW k1_x =
      lc.konst(p256_base.of_string(kTrustAnchors[1].root_pk_x_decimal));
  typename LC256::EltW k1_y =
      lc.konst(p256_base.of_string(kTrustAnchors[1].root_pk_y_decimal));
  typename LC256::EltW one_elt = lc.konst(p256_base.one());

  // idx ∈ {0, 1}: (idx) * (idx - 1) == 0.
  typename LC256::EltW idx_minus_one = lc.sub(trust_anchor_idx, one_elt);
  typename LC256::EltW idx_product = lc.mul(trust_anchor_idx, idx_minus_one);
  lc.assert_eq(idx_product, lc.konst(p256_base.zero()));

  // root_pk = k0 + idx * (k1 - k0).
  typename LC256::EltW root_pk_x =
      lc.add(k0_x, lc.mul(trust_anchor_idx, lc.sub(k1_x, k0_x)));
  typename LC256::EltW root_pk_y =
      lc.add(k0_y, lc.mul(trust_anchor_idx, lc.sub(k1_y, k0_y)));

  P7sSigCircuit sig_gadget(lc, p256, n256_order);
  // mac_pub layout (matches kMacMsgIdx*):
  //   [0..2) = mac_e, [2..4) = mac_e2, [4..6) = mac_spki_x,
  //   [6..8) = mac_spki_y, [8] = av.
  typename LC256::v128 mac_e_vals     [kMacValuesPerMessage]{};
  typename LC256::v128 mac_e2_vals    [kMacValuesPerMessage]{};
  typename LC256::v128 mac_spki_x_vals[kMacValuesPerMessage]{};
  typename LC256::v128 mac_spki_y_vals[kMacValuesPerMessage]{};
  for (size_t i = 0; i < kMacValuesPerMessage; ++i) {
    mac_e_vals     [i] = mac_pub[kMacMsgIdxE     * kMacValuesPerMessage + i];
    mac_e2_vals    [i] = mac_pub[kMacMsgIdxE2    * kMacValuesPerMessage + i];
    mac_spki_x_vals[i] = mac_pub[kMacMsgIdxSpkiX * kMacValuesPerMessage + i];
    mac_spki_y_vals[i] = mac_pub[kMacMsgIdxSpkiY * kMacValuesPerMessage + i];
  }
  typename LC256::v128 av_s{};
  av_s = mac_pub[kTotalMacValues];

  // Both ECDSA verifications + four MAC bindings in one call. Soundness
  // argument lives in P7sSignature::assert_signature's doc comment.
  sig_gadget.assert_signature(root_pk_x, root_pk_y, holder_pk_x, holder_pk_y,
                              e_wit, e2_wit,
                              mac_e_vals, mac_e2_vals,
                              mac_spki_x_vals, mac_spki_y_vals,
                              av_s, sig_witness);

  return Q.mkcircuit(/*nc=*/1);
}

const Circuit<F>& get_hash_circuit() {
  static std::mutex m;
  static std::unique_ptr<Circuit<F>> c;
  std::lock_guard<std::mutex> lock(m);
  if (!c) {
    c = build_hash_circuit();
  }
  return *c;
}

const Circuit<Fp256Base>& get_sig_circuit() {
  static std::mutex m;
  static std::unique_ptr<Circuit<Fp256Base>> c;
  std::lock_guard<std::mutex> lock(m);
  if (!c) {
    c = build_sig_circuit();
  }
  return *c;
}

// ========================== Witness-fill helpers ===========================

// Push an 8-bit value as 8 wires, LSB-first.
void push_v8(DenseFiller<F>& filler, uint8_t x, const F& Fs) {
  filler.push_back(static_cast<uint64_t>(x), 8, Fs);
}

// Push a k-bit integer as k wires, LSB-first.
void push_uint(DenseFiller<F>& filler, uint64_t x, size_t k, const F& Fs) {
  filler.push_back(x, k, Fs);
}

// Push the context_hash as 256 target bits. Matches FlatSHA256Circuit's
// assert_hash layout: bit j of target corresponds to bit (j % 8) of byte
// ((255 - j) / 8).
void push_target(DenseFiller<F>& filler, const uint8_t context_hash[32],
                 const F& Fs) {
  for (size_t j = 0; j < 256; ++j) {
    size_t byte_idx = (255 - j) / 8;
    size_t bit_idx = j % 8;
    uint8_t bit = (context_hash[byte_idx] >> bit_idx) & 1;
    filler.push_back(bit ? Fs.one() : Fs.zero());
  }
}

void push_pk_public(DenseFiller<F>& filler, const uint8_t pk[kPkBytes],
                    const F& Fs) {
  for (size_t i = 0; i < kPkBytes; ++i) {
    push_v8(filler, pk[i], Fs);
  }
}

void push_nonce_public(DenseFiller<F>& filler,
                       const uint8_t nonce[kNonceBytes], const F& Fs) {
  for (size_t i = 0; i < kNonceBytes; ++i) {
    push_v8(filler, nonce[i], Fs);
  }
}

// Push the MAC public-input region in the HASH circuit as native
// EltW wires (GF(2^128) is 128 bits wide → 1 EltW per v128).
// The values we push here are placeholders (Fs.zero()) that
// update_hash_macs overwrites in the DENSE array after commit.
void push_hash_mac_placeholders(DenseFiller<F>& filler, const F& Fs) {
  for (size_t i = 0; i < kHashMacInputWires; ++i) {
    filler.push_back(Fs.zero());
  }
}

// Push the MAC public-input region in the SIG circuit as v128
// bit-wires. Each v128 = 128 Fp256Base wires (one per bit, LSB-first
// in the EltW interpretation). Placeholder zeros here; overwritten by
// update_sig_macs after commit.
void push_sig_mac_placeholders(DenseFiller<Fp256Base>& filler) {
  for (size_t i = 0; i < kSigMacInputWires; ++i) {
    filler.push_back(p256_base.zero());
  }
}

// SHA witness helpers.
template <size_t kMaxBlocks>
struct ShaWitness {
  uint8_t numb = 0;
  uint8_t padded_in[64 * kMaxBlocks] = {};
  FlatSHA256Witness::BlockWitness bw[kMaxBlocks]{};
};

template <size_t kMaxBlocks>
void compute_sha_witness(const uint8_t* raw_bytes, size_t raw_len,
                         ShaWitness<kMaxBlocks>& out) {
  FlatSHA256Witness::transform_and_witness_message(
      raw_len, raw_bytes, kMaxBlocks, out.numb, out.padded_in, out.bw);
}

template <size_t kMaxBlocks>
void push_sha_padded_bytes(DenseFiller<F>& filler,
                           const ShaWitness<kMaxBlocks>& sw, const F& Fs) {
  for (size_t i = 0; i < 64 * kMaxBlocks; ++i) {
    push_v8(filler, sw.padded_in[i], Fs);
  }
}

template <size_t kMaxBlocks>
void push_sha_block_witnesses(DenseFiller<F>& filler,
                              const ShaWitness<kMaxBlocks>& sw, const F& Fs) {
  BitPluckerEncoder<F, kP7sPluckerBits> bpenc(Fs);
  for (size_t b = 0; b < kMaxBlocks; ++b) {
    for (size_t k = 0; k < 48; ++k) {
      auto packed = bpenc.mkpacked_v32(sw.bw[b].outw[k]);
      for (auto& e : packed) filler.push_back(e);
    }
    for (size_t k = 0; k < 64; ++k) {
      auto p_e = bpenc.mkpacked_v32(sw.bw[b].oute[k]);
      auto p_a = bpenc.mkpacked_v32(sw.bw[b].outa[k]);
      for (auto& e : p_e) filler.push_back(e);
      for (auto& e : p_a) filler.push_back(e);
    }
    for (size_t k = 0; k < 8; ++k) {
      auto packed = bpenc.mkpacked_v32(sw.bw[b].h1[k]);
      for (auto& e : packed) filler.push_back(e);
    }
  }
}

uint8_t nibble_of(uint8_t c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return 0;
}

void push_invariant4_witness(DenseFiller<F>& filler, uint32_t json_pk_offset,
                             const uint8_t pk_hex[kPkHexLen], const F& Fs) {
  push_uint(filler, json_pk_offset, kSignedContentLogN, Fs);
  for (size_t i = 0; i < kPkHexLen; ++i) {
    push_v8(filler, pk_hex[i], Fs);
  }
  for (size_t i = 0; i < kPkHexLen; ++i) {
    push_v8(filler, nibble_of(pk_hex[i]), Fs);
  }
}

void push_invariant5_witness(DenseFiller<F>& filler,
                             uint32_t json_nonce_offset,
                             const uint8_t nonce_hex[kNonceHexLen],
                             const F& Fs) {
  push_uint(filler, json_nonce_offset, kSignedContentLogN, Fs);
  for (size_t i = 0; i < kNonceHexLen; ++i) {
    push_v8(filler, nonce_hex[i], Fs);
  }
  for (size_t i = 0; i < kNonceHexLen; ++i) {
    push_v8(filler, nibble_of(nonce_hex[i]), Fs);
  }
}

void push_invariant6_witness(DenseFiller<F>& filler,
                             uint32_t json_context_offset, const F& Fs) {
  push_uint(filler, json_context_offset, kSignedContentLogN, Fs);
}

void push_invariant10_witness(DenseFiller<F>& filler,
                              uint32_t json_declaration_offset, const F& Fs) {
  push_uint(filler, json_declaration_offset, kSignedContentLogN, Fs);
}

// ========================== MAC plumbing ===================================

// Sample av from the (shared) transcript. Called exactly once, AFTER
// both circuits have committed and BEFORE either circuit proves.
gf2k generate_mac_key(Transcript& t) {
  F gf;
  uint8_t buf[F::kBytes];
  t.bytes(buf, F::kBytes);
  return gf.of_bytes_field(buf).value();
}

// Write a single gf2k value into a specific position of both dense
// arrays. On the sig side, each gf2k fills 128 field-element wires
// (one per bit, as one() / zero()). On the hash side, each gf2k fills
// exactly 1 native EltW wire.
void update_mac_in_dense(Dense<Fp256Base>& W_sig, Dense<F>& W_hash,
                         size_t& si, size_t& hi, const gf2k mac) {
  for (size_t j = 0; j < F::kBits; ++j) {
    W_sig.v_[si++] = mac[j] ? p256_base.one() : p256_base.zero();
  }
  W_hash.v_[hi++] = mac;
}

// Write all MAC values + av into both dense arrays at the known
// index positions. The caller MUST have:
//   1. committed both circuits BEFORE calling this
//   2. sampled av AFTER commit and BEFORE calling this
//   3. computed the macs using the sampled av BEFORE calling this
// Any other ordering produces a silent-pass soundness bug (see the
// "Interleaving order" section of docs/superpowers/specs/
// handoff-25a-dual-circuit.md section 5).
void update_macs(Dense<Fp256Base>& W_sig, Dense<F>& W_hash,
                 const gf2k macs[kTotalMacValues], gf2k av) {
  size_t si = kSigMacIndex;
  size_t hi = kHashMacIndex;
  for (size_t mi = 0; mi < kTotalMacValues; ++mi) {
    update_mac_in_dense(W_sig, W_hash, si, hi, macs[mi]);
  }
  update_mac_in_dense(W_sig, W_hash, si, hi, av);
  // Runtime guard: the write window must end EXACTLY at the end of
  // the public-input section in each circuit. A mismatch means the
  // circuit layout drifted away from kHashMacIndex / kSigMacIndex —
  // catch it here rather than producing a silently-wrong proof.
  check(si == kSigMacIndex + kSigMacInputWires,
        "sig MAC write went past expected boundary");
  check(hi == kHashMacIndex + kHashMacInputWires,
        "hash MAC write went past expected boundary");
}

// ========================== Blob parsing ==================================

bool read_u32(const uint8_t*& p, const uint8_t* end, uint32_t& out) {
  if (end - p < 4) return false;
  out = static_cast<uint32_t>(p[0]) |
        (static_cast<uint32_t>(p[1]) << 8) |
        (static_cast<uint32_t>(p[2]) << 16) |
        (static_cast<uint32_t>(p[3]) << 24);
  p += 4;
  return true;
}

struct ParsedWitness {
  uint32_t context_len;
  uint8_t context[kContextMaxBytes];
  uint32_t signed_content_len;
  uint8_t signed_content[kMaxSignedContent];
  uint32_t json_pk_offset;
  uint8_t pk_hex[kPkHexLen];
  uint32_t json_nonce_offset;
  uint8_t nonce_hex[kNonceHexLen];
  uint32_t json_context_offset;
  uint32_t json_declaration_offset;
  uint8_t message_digest[kMessageDigestLen];
  uint32_t cert_tbs_len;
  // v9: offset (absolute within cert_tbs, NOT relative to signed_content)
  // of the SPKI SEQUENCE's 0x30 tag. Host-witnessed — see handoff-30 §3.2
  // (varies with subject DN length).
  uint32_t cert_tbs_spki_offset;
  uint8_t cert_tbs[kCertTbsMaxBytes];
  // v8: raw (r, s) scalars from the cert_sig DER, each 32 big-endian
  // bytes. The Rust side DER-parses the cert signature and supplies
  // the raw scalars so the C++ side doesn't need an ASN.1 parser.
  uint8_t cert_sig_r[32];
  uint8_t cert_sig_s[32];
  // v9: signedAttrs (RAW witnessed bytes — first byte 0xA0) + the
  // CMS content signature's raw (r, s) scalars (DER-parsed in Rust).
  uint32_t signed_attrs_len;
  // v10 (Task 31): offset of the messageDigest Attribute SEQUENCE tag
  // (0x30) WITHIN signed_attrs. The 32-byte digest VALUE sits at
  // `signed_attrs[signed_attrs_md_offset + 17 ..
  //              signed_attrs_md_offset + 49]`. Host-witnessed
  // (signedAttrs BER attribute ordering is not canonical; both
  // current fixtures measure 60 but any signer-side re-issuance
  // could shift it).
  uint32_t signed_attrs_md_offset;
  uint8_t signed_attrs[kSignedAttrsMaxBytes];
  uint8_t content_sig_r[32];
  uint8_t content_sig_s[32];
  // v11 (Task 34) — invariant 7 stable-ID extraction.
  //   subject_sn_offset_in_tbs       offset of 9-byte DER anchor within
  //                                  cert_tbs. 370 for current fixtures.
  //   subject_dn_start_offset_in_tbs offset of outer Subject DN SEQUENCE
  //                                  within cert_tbs. 294 for current
  //                                  fixtures.
  //   trust_anchor_index             selects which `kTrustAnchors[]`
  //                                  entry the cert-sig ECDSA verifies
  //                                  under. Activated by Task #36;
  //                                  bound-checked against
  //                                  kTrustAnchorCount both at parse
  //                                  time and via an in-circuit
  //                                  `vlt` assertion in
  //                                  `build_hash_circuit`.
  uint32_t subject_sn_offset_in_tbs;
  uint32_t subject_dn_start_offset_in_tbs;
  uint32_t trust_anchor_index;
};

struct ParsedPublic {
  uint8_t context_hash[32];
  uint8_t pk[kPkBytes];
  uint8_t nonce[kNonceBytes];
  // v11 (Task 34) — invariant 7 public output + trust-anchor placeholder.
  uint8_t nullifier[kNullifierLen];
  uint32_t trust_anchor_index;
};

// If `skip_host_anchors` is true, the host-side DER-prefix assertions
// (SPKI and messageDigest) are NOT enforced — a malformed witness can
// still reach the circuit, where the in-circuit anchor constraints
// are the last line of defense. Only the test-only FFI path
// `p7s_prove_test_bypass_host_anchors` passes `true`; the production
// `p7s_prove` entry always passes `false`. See crates/
// zk-eidas-p7s/Cargo.toml's `test-bypass-host-anchors` feature.
bool parse_witness_blob(const uint8_t* blob, size_t blob_len,
                        ParsedWitness& out,
                        bool skip_host_anchors = false) {
  if (blob == nullptr || blob_len == 0) return false;
  const uint8_t* p = blob;
  const uint8_t* end = blob + blob_len;

  uint32_t version = 0;
  if (!read_u32(p, end, version) || version != kBlobSchemaVersion) return false;

  if (!read_u32(p, end, out.context_len)) return false;
  if (out.context_len > kContextMaxBytes) return false;
  if (end - p < static_cast<ptrdiff_t>(kContextMaxBytes)) return false;
  std::memcpy(out.context, p, kContextMaxBytes);
  p += kContextMaxBytes;

  if (!read_u32(p, end, out.signed_content_len)) return false;
  if (out.signed_content_len > kMaxSignedContent) return false;
  if (end - p < static_cast<ptrdiff_t>(kMaxSignedContent)) return false;
  std::memcpy(out.signed_content, p, kMaxSignedContent);
  p += kMaxSignedContent;

  if (!read_u32(p, end, out.json_pk_offset)) return false;
  if (out.json_pk_offset > kMaxSignedContent - kPkHexLen) return false;

  if (end - p < static_cast<ptrdiff_t>(kPkHexLen)) return false;
  std::memcpy(out.pk_hex, p, kPkHexLen);
  p += kPkHexLen;

  if (!read_u32(p, end, out.json_nonce_offset)) return false;
  if (out.json_nonce_offset > kMaxSignedContent - kNonceHexLen) return false;

  if (end - p < static_cast<ptrdiff_t>(kNonceHexLen)) return false;
  std::memcpy(out.nonce_hex, p, kNonceHexLen);
  p += kNonceHexLen;

  if (!read_u32(p, end, out.json_context_offset)) return false;
  if (out.json_context_offset > kMaxSignedContent - kContextMaxBytes) {
    return false;
  }

  if (!read_u32(p, end, out.json_declaration_offset)) return false;
  if (out.json_declaration_offset > kMaxSignedContent - kDeclarationLen) {
    return false;
  }

  if (end - p < static_cast<ptrdiff_t>(kMessageDigestLen)) return false;
  std::memcpy(out.message_digest, p, kMessageDigestLen);
  p += kMessageDigestLen;

  // v8: cert_tbs fields.
  if (!read_u32(p, end, out.cert_tbs_len)) return false;
  if (out.cert_tbs_len > kCertTbsMaxBytes) return false;
  // Minimum SHA padding is 9 bytes (0x80 + 8-byte bit-length), so the
  // raw cert_tbs can be at most kCertTbsMaxBytes - 9 = 2039 bytes.
  if (out.cert_tbs_len > kCertTbsMaxBytes - 9) return false;
  // v9: cert_tbs SPKI offset. The 91-byte SPKI window must fit
  // inside cert_tbs — the routing.shift zero-fills past the tail,
  // which would fail the prefix anchor in-circuit, but catching it
  // at parse time gives a cleaner P7S_INVALID_INPUT. Also require
  // the offset to sit inside the REAL cert_tbs content (not the
  // zero-pad region) since the prefix bytes we assert are non-zero.
  if (!read_u32(p, end, out.cert_tbs_spki_offset)) return false;
  if (out.cert_tbs_spki_offset + kSpkiWindowLen > out.cert_tbs_len) {
    return false;
  }
  if (end - p < static_cast<ptrdiff_t>(kCertTbsMaxBytes)) return false;
  std::memcpy(out.cert_tbs, p, kCertTbsMaxBytes);
  p += kCertTbsMaxBytes;
  // Belt-and-suspenders: check the prefix host-side too, so a
  // malformed witness never reaches the circuit. Matches the parser
  // layer's own pre-check (see crates/zk-eidas-p7s/src/parser.rs).
  //
  // Gated by `skip_host_anchors` so the test-only bypass FFI entry
  // can exercise the in-circuit anchor as the sole enforcement layer
  // — without this, the host pre-check always trips first and the
  // circuit-side 26-byte assertion becomes an untested comment.
  if (!skip_host_anchors) {
    if (std::memcmp(&out.cert_tbs[out.cert_tbs_spki_offset],
                    kSpkiP256Prefix, kSpkiPrefixLen) != 0) {
      return false;
    }
    if (out.cert_tbs[out.cert_tbs_spki_offset + kSpkiPrefixLen] != 0x04) {
      return false;
    }
  }

  // v8: raw (r, s) scalars from the cert signature — 32 big-endian
  // bytes each. Rust host-side DER-parses the p7s cert_sig and
  // supplies these directly.
  if (end - p < 32) return false;
  std::memcpy(out.cert_sig_r, p, 32);
  p += 32;
  if (end - p < 32) return false;
  std::memcpy(out.cert_sig_s, p, 32);
  p += 32;

  // v9: signedAttrs fields + content signature (r, s).
  if (!read_u32(p, end, out.signed_attrs_len)) return false;
  if (out.signed_attrs_len > kSignedAttrsMaxBytes) return false;
  // Minimum SHA padding is 9 bytes.
  if (out.signed_attrs_len > kSignedAttrsMaxBytes - 9) return false;
  // v10 (Task 31): messageDigest offset within signed_attrs. The
  // 49-byte anchor+digest window must fit inside the real (non-padded)
  // signed_attrs content — past the boundary, routing.shift zero-fills
  // and the in-circuit prefix anchor would fail, but rejecting here
  // yields a cleaner P7S_INVALID_INPUT.
  if (!read_u32(p, end, out.signed_attrs_md_offset)) return false;
  if (out.signed_attrs_md_offset + kSignedAttrsMdWindowLen >
      out.signed_attrs_len) {
    return false;
  }
  if (end - p < static_cast<ptrdiff_t>(kSignedAttrsMaxBytes)) return false;
  std::memcpy(out.signed_attrs, p, kSignedAttrsMaxBytes);
  p += kSignedAttrsMaxBytes;
  // Reject early if the witness's first byte isn't the CAdES [0]
  // IMPLICIT tag 0xA0 — the circuit would reject at prove time, but
  // catching it at parse time yields P7S_INVALID_INPUT rather than
  // P7S_PROVER_FAILURE, which is more useful for callers.
  if (out.signed_attrs_len == 0 || out.signed_attrs[0] != 0xA0) {
    return false;
  }
  // Belt-and-suspenders: check the 17-byte CMS messageDigest DER
  // prefix at the witnessed offset. Matches the parser layer's own
  // pre-check (see crates/zk-eidas-p7s/src/parser.rs) and the
  // in-circuit assertion. The in-circuit anchor is the soundness
  // bound; this host-side check is the debuggability bound (rejects
  // malformed witnesses at parse time before they reach the prover).
  //
  // Gated by `skip_host_anchors`; see the SPKI anchor comment above.
  if (!skip_host_anchors) {
    if (std::memcmp(&out.signed_attrs[out.signed_attrs_md_offset],
                    kSignedAttrsMdPrefix, kSignedAttrsMdPrefixLen) != 0) {
      return false;
    }
  }

  if (end - p < 32) return false;
  std::memcpy(out.content_sig_r, p, 32);
  p += 32;
  if (end - p < 32) return false;
  std::memcpy(out.content_sig_s, p, 32);
  p += 32;

  // v11 (Task 34) — invariant 7 host-witnessed offsets + trust-anchor
  // index placeholder. Order must match Rust
  // `crates/zk-eidas-p7s-circuit/src/witness.rs`'s `to_ffi_bytes()` tail.
  if (!read_u32(p, end, out.subject_sn_offset_in_tbs)) return false;
  // The 9+16-byte stable-ID window must fit inside real cert_tbs
  // content (not the zero-pad region) — the anchor bytes we assert are
  // non-zero.
  if (out.subject_sn_offset_in_tbs + kSubjectSnWindowLen > out.cert_tbs_len) {
    return false;
  }
  if (!read_u32(p, end, out.subject_dn_start_offset_in_tbs)) return false;
  // Range sanity: subject_dn_start must precede subject_sn (the
  // in-circuit check enforces strict inequality, but reject negatives
  // and obvious offset scrambles at parse time too).
  //
  // Gated by `skip_host_anchors` so the test-only bypass FFI entry
  // (`p7s_prove_test_bypass_host_anchors`) can exercise the in-circuit
  // `lc.assert1(lc.vlt(subject_dn_start_offset, subject_sn_offset))`
  // as the sole enforcement layer — without this gate the host check
  // always trips first and the circuit-side assertion goes untested.
  // (Task #41 bypass-gated companion for invariant_7 test N1.)
  if (!skip_host_anchors) {
    if (out.subject_dn_start_offset_in_tbs >= out.subject_sn_offset_in_tbs) {
      return false;
    }
    if (out.subject_dn_start_offset_in_tbs >= out.cert_tbs_len) return false;
  }
  if (!read_u32(p, end, out.trust_anchor_index)) return false;
  // Task #36: bound check against the compile-time trust-anchor table
  // size. Matches the in-circuit `vlt(trust_anchor_index,
  // kTrustAnchorCount)` constraint one-to-one; catching out-of-range
  // at parse time surfaces P7S_INVALID_INPUT instead of an opaque
  // P7S_PROVER_FAILURE. With N=2 (Task #44) this rejects any index
  // >= 2; stays correct as the table grows.
  //
  // Gated by `skip_host_anchors` so the bypass FFI entry can exercise
  // the in-circuit `lc.assert1(lc.vlt(trust_anchor_index,
  // kTrustAnchorCount))` as the sole enforcement layer.
  // (Task #42 N3 bypass-gated trust_anchor test.)
  if (!skip_host_anchors) {
    if (out.trust_anchor_index >= kTrustAnchorCount) return false;
  }

  // Belt-and-suspenders: 9-byte X.520 serialNumber DER anchor at the
  // witnessed offset. Gated by `skip_host_anchors` for parity with the
  // SPKI / messageDigest anchors; `p7s_prove_test_bypass_host_anchors`
  // skips this so invariant_7 tests can exercise the in-circuit anchor
  // as the sole enforcement layer.
  if (!skip_host_anchors) {
    if (std::memcmp(&out.cert_tbs[out.subject_sn_offset_in_tbs],
                    kSubjectSnAnchor, kSubjectSnAnchorLen) != 0) {
      return false;
    }
  }

  if (p != end) return false;
  return true;
}

bool parse_public_blob(const uint8_t* blob, size_t blob_len,
                       ParsedPublic& out) {
  if (blob == nullptr || blob_len == 0) return false;
  const uint8_t* p = blob;
  const uint8_t* end = blob + blob_len;

  uint32_t version = 0;
  if (!read_u32(p, end, version) || version != kBlobSchemaVersion) return false;

  if (end - p < 32) return false;
  std::memcpy(out.context_hash, p, 32);
  p += 32;

  if (end - p < static_cast<ptrdiff_t>(kPkBytes)) return false;
  std::memcpy(out.pk, p, kPkBytes);
  p += kPkBytes;

  if (end - p < static_cast<ptrdiff_t>(kNonceBytes)) return false;
  std::memcpy(out.nonce, p, kNonceBytes);
  p += kNonceBytes;

  // v11 (Task 34) — public nullifier output + trust_anchor_index
  // (activated by Task #36; bound-checked to match the in-circuit
  // `vlt(index, kTrustAnchorCount)` so verify-time rejects out-of-
  // range values before re-deriving the hash public inputs).
  if (end - p < static_cast<ptrdiff_t>(kNullifierLen)) return false;
  std::memcpy(out.nullifier, p, kNullifierLen);
  p += kNullifierLen;
  if (!read_u32(p, end, out.trust_anchor_index)) return false;
  if (out.trust_anchor_index >= kTrustAnchorCount) return false;

  if (p != end) return false;
  return true;
}

// ========================== Public-input fillers ===========================

// Fill the pre-MAC public-input section of the HASH circuit. Callers
// must subsequently invoke either push_hash_mac_placeholders (prove
// path — zero-fills the MAC slots; update_macs overwrites them after
// commit) or push_hash_mac_values (verify path — seeds the MAC region
// directly from the parsed proof bytes).
void fill_hash_public_inputs(DenseFiller<F>& filler, const ParsedPublic& pub,
                             const F& Fs) {
  filler.push_back(Fs.one());
  push_target(filler, pub.context_hash, Fs);
  push_pk_public(filler, pub.pk, Fs);
  push_nonce_public(filler, pub.nonce, Fs);
  // v11 (Task 34) — invariant 7 public output.
  // `push_target` uses the same big-endian bit layout the circuit's
  // `nullifier_v256_flatsha` view extracts from `nullifier_bytes[]`
  // via `(255 - j) / 8` / `j % 8`. Safe to reuse.
  push_target(filler, pub.nullifier, Fs);
  // v11 (Task 34, activated by Task 36) — trust-anchor index
  // (v32 LSB-first). Bound-checked in-circuit against
  // `kTrustAnchorCount` via `vlt`; `push_uint` streams the u32 LSB-
  // first into the 32 wires declared as `vinput<kHashPubTrustAnchorIdx>`.
  push_uint(filler, pub.trust_anchor_index, kHashPubTrustAnchorIdx, Fs);
}

void push_hash_mac_values(DenseFiller<F>& filler,
                          const gf2k macs[kTotalMacValues], gf2k av) {
  for (size_t i = 0; i < kTotalMacValues; ++i) {
    filler.push_back(macs[i]);
  }
  filler.push_back(av);
}

void push_sig_mac_values(DenseFiller<Fp256Base>& filler,
                         const gf2k macs[kTotalMacValues], gf2k av) {
  // One Fp256Base wire per bit, LSB-first — matches the circuit's
  // v128 bit ordering and update_mac_in_dense's write pattern.
  for (size_t i = 0; i < kTotalMacValues; ++i) {
    for (size_t j = 0; j < F::kBits; ++j) {
      filler.push_back(macs[i][j] ? p256_base.one() : p256_base.zero());
    }
  }
  for (size_t j = 0; j < F::kBits; ++j) {
    filler.push_back(av[j] ? p256_base.one() : p256_base.zero());
  }
}

// Transform from u8 be (i.e., be[kBytes-1] is the most significant
// byte) into Nat form by first reversing into LE order then calling
// `Nat::of_bytes` (which is LE-oriented). Inlined rather than pulled
// from `mdoc_witness.h` to avoid dragging in CBOR/mdoc-specific
// dependencies.
template <class Nat>
Nat nat_from_be(const uint8_t be[/* Nat::kBytes */]) {
  uint8_t tmp[Nat::kBytes];
  for (size_t i = 0; i < Nat::kBytes; ++i) {
    tmp[i] = be[Nat::kBytes - 1 - i];
  }
  return Nat::of_bytes(tmp);
}

// =========================== Proof serialization ===========================

// Little-endian u32 write into a byte vector.
void write_u32(std::vector<uint8_t>& buf, uint32_t x) {
  buf.push_back(static_cast<uint8_t>(x & 0xFF));
  buf.push_back(static_cast<uint8_t>((x >> 8) & 0xFF));
  buf.push_back(static_cast<uint8_t>((x >> 16) & 0xFF));
  buf.push_back(static_cast<uint8_t>((x >> 24) & 0xFF));
}

}  // namespace
}  // namespace p7s
}  // namespace proofs

extern "C" {

// Shared core — `skip_host_anchors` controls whether
// parse_witness_blob's belt-and-suspenders DER anchor assertions fire.
// Production callers use `false` (via `p7s_prove`); the test-only
// `p7s_prove_test_bypass_host_anchors` entry uses `true` to exercise
// the in-circuit anchors as the sole line of defense.
static P7sErrorCode p7s_prove_impl(
    const uint8_t* witness_blob, size_t witness_blob_len,
    const uint8_t* public_blob, size_t public_blob_len,
    uint8_t** proof_out, size_t* proof_len_out,
    bool skip_host_anchors);

P7sErrorCode p7s_prove(const uint8_t* witness_blob, size_t witness_blob_len,
                       const uint8_t* public_blob, size_t public_blob_len,
                       uint8_t** proof_out, size_t* proof_len_out) {
  return p7s_prove_impl(witness_blob, witness_blob_len, public_blob,
                        public_blob_len, proof_out, proof_len_out,
                        /*skip_host_anchors=*/false);
}

// Test-only FFI entry — skips host-side DER anchor assertions so the
// in-circuit anchors can be exercised directly. Must NOT be called
// from production; the Rust FFI wrapper only exposes this under the
// `test-bypass-host-anchors` Cargo feature.
P7sErrorCode p7s_prove_test_bypass_host_anchors(
    const uint8_t* witness_blob, size_t witness_blob_len,
    const uint8_t* public_blob, size_t public_blob_len,
    uint8_t** proof_out, size_t* proof_len_out) {
  return p7s_prove_impl(witness_blob, witness_blob_len, public_blob,
                        public_blob_len, proof_out, proof_len_out,
                        /*skip_host_anchors=*/true);
}

static P7sErrorCode p7s_prove_impl(
    const uint8_t* witness_blob, size_t witness_blob_len,
    const uint8_t* public_blob, size_t public_blob_len,
    uint8_t** proof_out, size_t* proof_len_out,
    bool skip_host_anchors) {
  using namespace proofs;
  using namespace proofs::p7s;

  if (proof_out == nullptr || proof_len_out == nullptr) return P7S_NULL_INPUT;

  ParsedWitness wit{};
  if (!parse_witness_blob(witness_blob, witness_blob_len, wit,
                          skip_host_anchors)) {
    return P7S_INVALID_INPUT;
  }
  // Safety guard: even in bypass mode, an out-of-range trust_anchor_index
  // must not reach the `kTrustAnchors[wit.trust_anchor_index]` array
  // access below (line ~1923) — that would be undefined behaviour. Return
  // P7S_PROVER_FAILURE (not P7S_INVALID_INPUT) to match the observable
  // signal of the in-circuit `lc.assert1(lc.vlt(trust_anchor_index,
  // kTrustAnchorCount))` for bypass-gated tests. In production,
  // `parse_witness_blob` already rejects out-of-range before this.
  if (wit.trust_anchor_index >= kTrustAnchorCount) return P7S_PROVER_FAILURE;
  ParsedPublic pub{};
  if (!parse_public_blob(public_blob, public_blob_len, pub)) {
    return P7S_INVALID_INPUT;
  }

  const F Fs;
  const RSFactory rsf_h(Fs);
  const Circuit<F>& c_hash = get_hash_circuit();
  const Circuit<Fp256Base>& c_sig = get_sig_circuit();

  // Sanity-check that the circuits we built actually match the
  // layout constants — if the circuit grew/shrank without someone
  // bumping kHashPubTotal / kSigPubTotal, we'd write MACs at the
  // wrong offset. Runtime check here is cheap and catches the
  // class of bugs that are otherwise only detectable at verify
  // time (silent pass if the layout coincidentally cancels out).
  if (c_hash.npub_in != kHashPubTotal) return P7S_INVALID_INPUT;
  if (c_sig.npub_in != kSigPubTotal) return P7S_INVALID_INPUT;

  // Compute SHA witnesses off-circuit. For signedAttrs, the input to
  // FlatSHA is the CAdES-canonical form `[0x31, body[1..]]` — we
  // materialize that buffer here so the witness-derived digest
  // matches what `build_hash_circuit` asserts in-circuit.
  ShaWitness<kContextMaxBlocks> ctx_sw;
  compute_sha_witness<kContextMaxBlocks>(wit.context, wit.context_len, ctx_sw);
  ShaWitness<kSignedContentMaxBlocks> sc_sw;
  compute_sha_witness<kSignedContentMaxBlocks>(wit.signed_content,
                                               wit.signed_content_len, sc_sw);
  ShaWitness<kCertTbsMaxBlocks> cert_sw;
  compute_sha_witness<kCertTbsMaxBlocks>(wit.cert_tbs, wit.cert_tbs_len,
                                         cert_sw);

  // signedAttrs in CAdES-canonical form. The raw witness carries the
  // [0] IMPLICIT tag 0xA0 (already validated in parse_witness_blob);
  // rewrite byte 0 to 0x31 (SET OF) before SHA.
  uint8_t signed_attrs_canonical[kSignedAttrsMaxBytes];
  std::memcpy(signed_attrs_canonical, wit.signed_attrs, kSignedAttrsMaxBytes);
  signed_attrs_canonical[0] = 0x31;
  ShaWitness<kSignedAttrsMaxBlocks> sa_sw;
  compute_sha_witness<kSignedAttrsMaxBlocks>(signed_attrs_canonical,
                                             wit.signed_attrs_len, sa_sw);

  // Compute e = SHA-256(cert_tbs) and e2 = SHA-256(signedAttrs_canonical)
  // outside the circuit. Matches the in-circuit FlatSHA output bit for
  // bit; both views use openssl SHA256.
  uint8_t e_digest_be[kCertTbsDigestLen];
  {
    proofs::SHA256 sha;
    sha.Update(wit.cert_tbs, wit.cert_tbs_len);
    sha.DigestData(e_digest_be);
  }
  uint8_t e2_digest_be[kSignedAttrsDigestLen];
  {
    proofs::SHA256 sha;
    sha.Update(signed_attrs_canonical, wit.signed_attrs_len);
    sha.DigestData(e2_digest_be);
  }

  // Parse (r, s) from the DER-encoded cert signature and the CMS
  // content signature. v9 blob carries 32 raw big-endian bytes each.
  Fp256Nat ne  = nat_from_be<Fp256Nat>(e_digest_be);
  Fp256Nat ne2 = nat_from_be<Fp256Nat>(e2_digest_be);
  Fp256Nat nr  = nat_from_be<Fp256Nat>(wit.cert_sig_r);
  Fp256Nat ns  = nat_from_be<Fp256Nat>(wit.cert_sig_s);
  Fp256Nat nr2 = nat_from_be<Fp256Nat>(wit.content_sig_r);
  Fp256Nat ns2 = nat_from_be<Fp256Nat>(wit.content_sig_s);

  // Trust-anchor root — selected from the compile-time
  // `kTrustAnchors[]` table by the witness-driven
  // `wit.trust_anchor_index`. Parsed value is already bounds-checked
  // in parse_witness_blob (`index < kTrustAnchorCount`), so the array
  // indexing below is safe. Matches the sig circuit's in-circuit mux
  // over `kTrustAnchors[0..kTrustAnchorCount)` (Task #44): the prover
  // feeds this same root_pk into `ecdsa_cert_wit.compute_witness`
  // here (witness-side) and the circuit selects it from its
  // compile-time table indexed by the public `trust_anchor_index`
  // (verifier side). If they disagree, the ECDSA verify fails.
  const TrustAnchor& selected_anchor = kTrustAnchors[wit.trust_anchor_index];
  Fp256Base::Elt root_pkX =
      p256_base.of_string(selected_anchor.root_pk_x_decimal);
  Fp256Base::Elt root_pkY =
      p256_base.of_string(selected_anchor.root_pk_y_decimal);

  // Holder pk from the cert_tbs SPKI, NOT the JSON public blob.
  // The parser and parse_witness_blob already anchor-checked the
  // 26-byte P-256 SPKI prefix at `cert_tbs_spki_offset`, and the
  // in-circuit SPKI extraction does the same on-wire; these offsets
  // are therefore trusted here.
  const size_t kSpkiXAbs =
      wit.cert_tbs_spki_offset + kSpkiPrefixLen + 1;  // skip prefix + 0x04
  const size_t kSpkiYAbs = kSpkiXAbs + kSpkiXYLen;
  uint8_t spki_x_be[kSpkiXYLen];
  uint8_t spki_y_be[kSpkiXYLen];
  std::memcpy(spki_x_be, &wit.cert_tbs[kSpkiXAbs], kSpkiXYLen);
  std::memcpy(spki_y_be, &wit.cert_tbs[kSpkiYAbs], kSpkiXYLen);
  Fp256Nat nhxnat = nat_from_be<Fp256Nat>(spki_x_be);
  Fp256Nat nhynat = nat_from_be<Fp256Nat>(spki_y_be);
  Fp256Base::Elt holder_pkX = p256_base.to_montgomery(nhxnat);
  Fp256Base::Elt holder_pkY = p256_base.to_montgomery(nhynat);

  // Build BOTH sig-side ECDSA witnesses. Failures here mean the
  // prover supplied (r, s) that don't verify under the respective
  // public key — malicious prover or fixture mismatch.
  VerifyWitness3<P256, Fp256Scalar> ecdsa_cert_wit(p256_scalar, p256);
  if (!ecdsa_cert_wit.compute_witness(root_pkX, root_pkY, ne, nr, ns)) {
    return P7S_INVALID_INPUT;
  }
  VerifyWitness3<P256, Fp256Scalar> ecdsa_content_wit(p256_scalar, p256);
  if (!ecdsa_content_wit.compute_witness(holder_pkX, holder_pkY, ne2, nr2,
                                         ns2)) {
    return P7S_INVALID_INPUT;
  }

  // Fp256Base::Elt of e, e2 in Montgomery form — the MAC-bound
  // EltWs on the sig side (after `.eltw_input()` wire declarations).
  Fp256Base::Elt e_elt  = p256_base.to_montgomery(ne);
  Fp256Base::Elt e2_elt = p256_base.to_montgomery(ne2);

  // Sample the prover's halves of the MAC key BEFORE commit so they
  // become part of the committed witness. kTotalMacValues = 4 = 2
  // messages × 2 halves/message.
  SecureRandomEngine rng;
  MACReference<F> mac_ref;
  gf2k ap[kTotalMacValues];
  mac_ref.sample(ap, kTotalMacValues, &rng);

  // ===== Fill HASH witness (W_hash over GF(2^128)) =====
  Dense<F> W_hash(1, c_hash.ninputs);
  DenseFiller<F> hash_filler(W_hash);

  // Public section.
  fill_hash_public_inputs(hash_filler, pub, Fs);
  push_hash_mac_placeholders(hash_filler, Fs);

  // Private section.
  push_v8(hash_filler, ctx_sw.numb, Fs);
  push_sha_padded_bytes<kContextMaxBlocks>(hash_filler, ctx_sw, Fs);
  push_sha_block_witnesses<kContextMaxBlocks>(hash_filler, ctx_sw, Fs);
  push_sha_padded_bytes<kSignedContentMaxBlocks>(hash_filler, sc_sw, Fs);
  push_invariant4_witness(hash_filler, wit.json_pk_offset, wit.pk_hex, Fs);
  push_invariant5_witness(hash_filler, wit.json_nonce_offset, wit.nonce_hex, Fs);
  push_invariant6_witness(hash_filler, wit.json_context_offset, Fs);
  push_invariant10_witness(hash_filler, wit.json_declaration_offset, Fs);
  push_v8(hash_filler, sc_sw.numb, Fs);
  push_sha_block_witnesses<kSignedContentMaxBlocks>(hash_filler, sc_sw, Fs);
  for (size_t i = 0; i < kMessageDigestLen; ++i) {
    push_v8(hash_filler, wit.message_digest[i], Fs);
  }

  // Task 29: cert_tbs SHA-256 witness + prover-claimed digest.
  // Fill order must match the circuit's wire-declaration order:
  //   cert_tbs_numb (v8)
  //   cert_tbs_spki_offset (v<kCertTbsLenBits> = v11)  ← v9/#26
  //   cert_tbs[kCertTbsMaxBytes] (padded bytes)
  //   cert_tbs_bw[kCertTbsMaxBlocks] (per-block SHA witnesses)
  //   e_digest_bytes[32]
  push_v8(hash_filler, cert_sw.numb, Fs);
  push_uint(hash_filler, wit.cert_tbs_spki_offset, kCertTbsLenBits, Fs);
  push_sha_padded_bytes<kCertTbsMaxBlocks>(hash_filler, cert_sw, Fs);
  push_sha_block_witnesses<kCertTbsMaxBlocks>(hash_filler, cert_sw, Fs);
  for (size_t i = 0; i < kCertTbsDigestLen; ++i) {
    push_v8(hash_filler, e_digest_be[i], Fs);
  }

  // Task 26: signedAttrs SHA witness + prover-claimed digest. The
  // wire-level signed_attrs[i] holds SHA-padded CAdES-CANONICAL bytes
  // (first byte 0x31 — same IMPLICIT→SET OF rewrite OpenSSL CMS
  // applies when computing the content-sig digest). Pattern matches
  // cert_tbs above: push padded bytes, let the SHA gadget consume
  // them directly. No separate raw-byte witness; soundness comes
  // from the content-sig ECDSA.
  //
  // Fill order must match the circuit's wire-declaration order:
  //   signed_attrs_numb (v8)
  //   signed_attrs_md_offset (v<kSignedAttrsLenBits> = v11)  ← v10/#31
  //   signed_attrs[kSignedAttrsMaxBytes] (padded bytes)
  //   signed_attrs_bw[kSignedAttrsMaxBlocks] (per-block SHA witnesses)
  //   e2_digest_bytes[32]
  push_v8(hash_filler, sa_sw.numb, Fs);
  push_uint(hash_filler, wit.signed_attrs_md_offset, kSignedAttrsLenBits, Fs);
  push_sha_padded_bytes<kSignedAttrsMaxBlocks>(hash_filler, sa_sw, Fs);
  push_sha_block_witnesses<kSignedAttrsMaxBlocks>(hash_filler, sa_sw, Fs);
  for (size_t i = 0; i < kSignedAttrsDigestLen; ++i) {
    push_v8(hash_filler, e2_digest_be[i], Fs);
  }

  // v11 / Task 34: invariant 7 private witness fill.
  //   subject_sn_offset_in_tbs (v11 offset)
  //   subject_dn_start_offset_in_tbs (v11 offset)
  //   nullifier_input_numb (v8 SHA block count)
  //   nullifier_input[64] (SHA-padded stable_id || context)
  //   nullifier_input_bw[1] (per-block SHA witnesses)
  //
  // Build the nullifier preimage buffer off-circuit:
  //   raw = stable_id[16] || context_raw[ctx_len]
  // then SHA-pad. The stable_id bytes come from
  // cert_tbs[subject_sn_offset + 9 .. subject_sn_offset + 25].
  const size_t kStableIdAbs = wit.subject_sn_offset_in_tbs + kSubjectSnAnchorLen;
  uint8_t nullifier_raw[kStableIdLen + kContextMaxBytes] = {};
  std::memcpy(nullifier_raw, &wit.cert_tbs[kStableIdAbs], kStableIdLen);
  std::memcpy(&nullifier_raw[kStableIdLen], wit.context, wit.context_len);
  const size_t nullifier_raw_len = kStableIdLen + wit.context_len;
  ShaWitness<kNullifierShaBlocks> null_sw;
  compute_sha_witness<kNullifierShaBlocks>(nullifier_raw, nullifier_raw_len,
                                           null_sw);

  push_uint(hash_filler, wit.subject_sn_offset_in_tbs, kCertTbsLenBits, Fs);
  push_uint(hash_filler, wit.subject_dn_start_offset_in_tbs, kCertTbsLenBits, Fs);
  push_v8(hash_filler, null_sw.numb, Fs);
  push_sha_padded_bytes<kNullifierShaBlocks>(hash_filler, null_sw, Fs);
  push_sha_block_witnesses<kNullifierShaBlocks>(hash_filler, null_sw, Fs);

  // Task 25a/26: prover's committed `ap` halves. kTotalMacValues
  // EltWs = 4 MAC witnesses × 2 halves/witness. Order must match
  // the circuit's declaration: mac_witness_e, mac_witness_e2,
  // mac_witness_spki_x, mac_witness_spki_y.
  for (size_t i = 0; i < kTotalMacValues; ++i) {
    hash_filler.push_back(ap[i]);
  }
  if (hash_filler.size() != c_hash.ninputs) return P7S_INVALID_INPUT;

  // ===== Fill SIG witness (W_sig over Fp256Base) =====
  Dense<Fp256Base> W_sig(1, c_sig.ninputs);
  DenseFiller<Fp256Base> sig_filler(W_sig);

  // Public section: const 1 + trust_anchor_index (Task #44) + MAC
  // region placeholders. Holder pk is NOT a public input (privacy:
  // cert SPKI would deanonymize the holder). The trust_anchor_index
  // is the same u32 value the hash circuit reads from the public
  // blob, reinterpreted as an Fp256Base field element.
  sig_filler.push_back(p256_base.one());
  sig_filler.push_back(
      p256_base.of_scalar(static_cast<uint64_t>(pub.trust_anchor_index)));
  push_sig_mac_placeholders(sig_filler);

  // Private section — order MUST match build_sig_circuit's declaration:
  //   holder_pk_x, holder_pk_y, e_wit, e2_wit, then
  //   P7sSigWitness (macs_[0..4], ecdsa_cert_, ecdsa_content_).
  sig_filler.push_back(holder_pkX);
  sig_filler.push_back(holder_pkY);
  sig_filler.push_back(e_elt);
  sig_filler.push_back(e2_elt);

  // MAC witnesses — LE-ordered 32 bytes of each bound message.
  // `spki_x_be` / `spki_y_be` and `kSpkiXAbs` / `kSpkiYAbs` were
  // computed earlier in this function (during holder_pkX/Y derivation).
  // `MacWitness::compute_witness(ap_pair, le_bytes)` packs (a) the
  // two ap halves via BitPluckerEncoder and (b) the 256 bit-wires of
  // the LE-byte message. Order here MUST match MACReference::compute
  // slicing below and the circuit's mac_witness_* declaration order.
  uint8_t e_digest_le [kCertTbsDigestLen];
  uint8_t e2_digest_le[kSignedAttrsDigestLen];
  uint8_t spki_x_le   [kSpkiXYLen];
  uint8_t spki_y_le   [kSpkiXYLen];
  for (size_t i = 0; i < kCertTbsDigestLen; ++i) {
    e_digest_le [i] = e_digest_be [kCertTbsDigestLen     - 1 - i];
    e2_digest_le[i] = e2_digest_be[kSignedAttrsDigestLen - 1 - i];
  }
  for (size_t i = 0; i < kSpkiXYLen; ++i) {
    spki_x_le[i] = spki_x_be[kSpkiXYLen - 1 - i];
    spki_y_le[i] = spki_y_be[kSpkiXYLen - 1 - i];
  }
  // Note: ap halves are sliced per-message; ap[0..2] pair with e,
  // ap[2..4] with e2, ap[4..6] with SPKI_X, ap[6..8] with SPKI_Y.
  {
    MacWitness<Fp256Base> mw(p256_base, Fs);
    mw.compute_witness(&ap[kMacMsgIdxE     * kMacValuesPerMessage], e_digest_le);
    mw.fill_witness(sig_filler);
  }
  {
    MacWitness<Fp256Base> mw(p256_base, Fs);
    mw.compute_witness(&ap[kMacMsgIdxE2    * kMacValuesPerMessage], e2_digest_le);
    mw.fill_witness(sig_filler);
  }
  {
    MacWitness<Fp256Base> mw(p256_base, Fs);
    mw.compute_witness(&ap[kMacMsgIdxSpkiX * kMacValuesPerMessage], spki_x_le);
    mw.fill_witness(sig_filler);
  }
  {
    MacWitness<Fp256Base> mw(p256_base, Fs);
    mw.compute_witness(&ap[kMacMsgIdxSpkiY * kMacValuesPerMessage], spki_y_le);
    mw.fill_witness(sig_filler);
  }

  // ECDSA witnesses — match P7sSignature::Witness::input() order:
  // ecdsa_cert_ first, then ecdsa_content_.
  ecdsa_cert_wit.fill_witness(sig_filler);
  ecdsa_content_wit.fill_witness(sig_filler);

  if (sig_filler.size() != c_sig.ninputs) return P7S_INVALID_INPUT;

  // ===== Shared transcript + commit phase =====
  // One Transcript instance threads both circuits; the per-circuit
  // seeds are distinct compile-time constants. Construction order:
  //   Transcript tp(kHashSeed, ...) — keeps the hash commit first
  //   (mirrors mdoc), then sig commit on the same tp, then av
  //   sampling, then both proves.
  Transcript tp(reinterpret_cast<const uint8_t*>(kHashTranscriptSeed),
                kHashTranscriptSeedLen);

  // Sig-circuit FFT / Reed-Solomon stack (copied from mdoc_zk.cc).
  const f2_p256 p256_2(p256_base);
  const Elt256_2 omega = p256_2.of_string(kRootX, kRootY);
  const FftExtConvolutionFactory_b fft_b(p256_base, p256_2, omega, 1ull << 31);
  const RSFactory_b rsf_s(fft_b, p256_base);

  ZkProof<F> h_zk(c_hash, kRate, kNreq);
  ZkProof<Fp256Base> sig_zk(c_sig, kRate, kNreq);
  ZkProver<F, RSFactory> hash_p(c_hash, Fs, rsf_h);
  ZkProver<Fp256Base, RSFactory_b> sig_p(c_sig, p256_base, rsf_s);

  // Commit both circuits BEFORE sampling av. The Dense arrays still
  // have zero placeholders in their MAC slots — that's the whole
  // point of the av-sampled-after-commit protocol.
  hash_p.commit(h_zk, W_hash, tp, rng);
  sig_p.commit(sig_zk, W_sig, tp, rng);

  // Sample av from the post-commit transcript state and compute the
  // MAC values over all 4 messages (LE-ordered — matches the
  // in-circuit LE v256 views + Fp256Base::of_bytes_field on the sig
  // side + gf_.of_bytes_field on the MAC reference side). macs
  // layout must match the circuit's mac_pub vector + kMacMsgIdx*.
  gf2k av = generate_mac_key(tp);
  gf2k macs[kTotalMacValues];
  // Reuse the _le buffers already computed above for the MAC witness
  // fill — they're in scope. Pair macs[i * 2 .. (i+1) * 2] with
  // ap[i * 2 .. (i+1) * 2] for message i.
  mac_ref.compute(&macs[kMacMsgIdxE     * kMacValuesPerMessage], av,
                  &ap  [kMacMsgIdxE     * kMacValuesPerMessage], e_digest_le);
  mac_ref.compute(&macs[kMacMsgIdxE2    * kMacValuesPerMessage], av,
                  &ap  [kMacMsgIdxE2    * kMacValuesPerMessage], e2_digest_le);
  mac_ref.compute(&macs[kMacMsgIdxSpkiX * kMacValuesPerMessage], av,
                  &ap  [kMacMsgIdxSpkiX * kMacValuesPerMessage], spki_x_le);
  mac_ref.compute(&macs[kMacMsgIdxSpkiY * kMacValuesPerMessage], av,
                  &ap  [kMacMsgIdxSpkiY * kMacValuesPerMessage], spki_y_le);

  // Write the MAC values + av into both dense arrays' MAC slots.
  // DOES NOT touch the committed snapshot — commit() captured the
  // Dense as-is; these writes only affect the subsequent prove().
  update_macs(W_sig, W_hash, macs, av);

  if (!hash_p.prove(h_zk, W_hash, tp)) return P7S_PROVER_FAILURE;
  if (!sig_p.prove(sig_zk, W_sig, tp)) return P7S_PROVER_FAILURE;

  // ===== Serialize [schema(4)][macs_b(32)][hash_zk][sig_zk] =====
  std::vector<uint8_t> buf;
  buf.reserve(4 + kTotalMacValues * F::kBytes + h_zk.size() + sig_zk.size());
  write_u32(buf, kBlobSchemaVersion);
  for (size_t i = 0; i < kTotalMacValues; ++i) {
    size_t pos = buf.size();
    buf.resize(pos + F::kBytes);
    Fs.to_bytes_field(buf.data() + pos, macs[i]);
  }
  h_zk.write(buf, Fs);
  sig_zk.write(buf, p256_base);

  uint8_t* out = static_cast<uint8_t*>(malloc(buf.size()));
  if (!out) return P7S_MEMORY_FAILURE;
  memcpy(out, buf.data(), buf.size());
  *proof_out = out;
  *proof_len_out = buf.size();
  return P7S_SUCCESS;
}

P7sErrorCode p7s_verify(const uint8_t* public_blob, size_t public_blob_len,
                        const uint8_t* proof, size_t proof_len) {
  using namespace proofs;
  using namespace proofs::p7s;

  if (proof == nullptr) return P7S_NULL_INPUT;
  if (proof_len == 0) return P7S_INVALID_INPUT;

  ParsedPublic pub{};
  if (!parse_public_blob(public_blob, public_blob_len, pub)) {
    return P7S_INVALID_INPUT;
  }

  const F Fs;
  const RSFactory rsf_h(Fs);
  const Circuit<F>& c_hash = get_hash_circuit();
  const Circuit<Fp256Base>& c_sig = get_sig_circuit();

  if (c_hash.npub_in != kHashPubTotal) return P7S_VERIFIER_FAILURE;
  if (c_sig.npub_in != kSigPubTotal) return P7S_VERIFIER_FAILURE;

  // Parse proof bytes in order: schema(4) | macs_b(32) | hash_zk | sig_zk
  const std::vector<uint8_t> zbuf(proof, proof + proof_len);
  ReadBuffer rb(zbuf);
  if (rb.remaining() < 4) return P7S_VERIFIER_FAILURE;
  const uint8_t* sver = rb.next(4);
  uint32_t schema = static_cast<uint32_t>(sver[0]) |
                    (static_cast<uint32_t>(sver[1]) << 8) |
                    (static_cast<uint32_t>(sver[2]) << 16) |
                    (static_cast<uint32_t>(sver[3]) << 24);
  if (schema != kBlobSchemaVersion) return P7S_VERIFIER_FAILURE;

  if (rb.remaining() < kTotalMacValues * F::kBytes) return P7S_VERIFIER_FAILURE;
  gf2k macs[kTotalMacValues];
  for (size_t i = 0; i < kTotalMacValues; ++i) {
    const uint8_t* mb = rb.next(F::kBytes);
    auto m = Fs.of_bytes_field(mb);
    if (!m.has_value()) return P7S_VERIFIER_FAILURE;
    macs[i] = m.value();
  }

  ZkProof<F> pr_hash(c_hash, kRate, kNreq);
  ZkProof<Fp256Base> pr_sig(c_sig, kRate, kNreq);
  if (!pr_hash.read(rb, Fs)) return P7S_VERIFIER_FAILURE;
  if (!pr_sig.read(rb, p256_base)) return P7S_VERIFIER_FAILURE;
  if (rb.remaining() != 0) return P7S_VERIFIER_FAILURE;

  // Shared transcript — same seed as the prover.
  const f2_p256 p256_2(p256_base);
  const Elt256_2 omega = p256_2.of_string(kRootX, kRootY);
  const FftExtConvolutionFactory_b fft_b(p256_base, p256_2, omega, 1ull << 31);
  const RSFactory_b rsf_s(fft_b, p256_base);

  Transcript tv(reinterpret_cast<const uint8_t*>(kHashTranscriptSeed),
                kHashTranscriptSeedLen);
  ZkVerifier<F, RSFactory> hash_v(c_hash, rsf_h, kRate, kNreq, Fs);
  ZkVerifier<Fp256Base, RSFactory_b> sig_v(c_sig, rsf_s, kRate, kNreq,
                                           p256_base);

  // Same commit → av → verify interleaving as the prover.
  hash_v.recv_commitment(pr_hash, tv);
  sig_v.recv_commitment(pr_sig, tv);
  gf2k av = generate_mac_key(tv);

  // Build public-input Dense arrays with the parsed MAC values.
  Dense<F> pub_hash(1, c_hash.npub_in);
  DenseFiller<F> hash_filler(pub_hash);
  fill_hash_public_inputs(hash_filler, pub, Fs);
  push_hash_mac_values(hash_filler, macs, av);
  if (hash_filler.size() != c_hash.npub_in) return P7S_VERIFIER_FAILURE;

  Dense<Fp256Base> pub_sig(1, c_sig.npub_in);
  DenseFiller<Fp256Base> sig_filler(pub_sig);
  sig_filler.push_back(p256_base.one());
  // Task #44: trust_anchor_index public input (single EltW). The sig
  // circuit's `idx * (idx - 1) == 0` constraint + 2-way mux select
  // the root_pk used for cert-sig ECDSA verification.
  sig_filler.push_back(
      p256_base.of_scalar(static_cast<uint64_t>(pub.trust_anchor_index)));
  // holder_pk_{x,y} are PRIVATE on the sig side (see build_sig_circuit
  // layout). The remaining public-input wires are the MAC region —
  // filled below.
  push_sig_mac_values(sig_filler, macs, av);
  if (sig_filler.size() != c_sig.npub_in) return P7S_VERIFIER_FAILURE;

  bool ok_h = hash_v.verify(pr_hash, pub_hash, tv);
  bool ok_s = sig_v.verify(pr_sig, pub_sig, tv);
  return (ok_h && ok_s) ? P7S_SUCCESS : P7S_VERIFIER_FAILURE;
}

void p7s_free_proof(uint8_t* proof) { free(proof); }

}  // extern "C"
