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
// bytes covers current QKB-format payloads (~600 bytes) with headroom.
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
// The signer cert's TBSCertificate (the portion the trust-anchor root
// signs over) is bounded by kCertTbsMaxBlocks SHA-256 blocks. 32
// blocks × 64 bytes/block = 2048 bytes; minus the 9-byte MD padding
// floor that leaves 2039 bytes of raw TBS headroom. Current QTSP certs
// are ~1203 bytes TBS, so 32 blocks is comfortable (the fixture test
// verifies the exact offset).
constexpr size_t kCertTbsMaxBlocks = 32;
constexpr size_t kCertTbsMaxBytes = kCertTbsMaxBlocks * 64;  // 2048
constexpr size_t kCertTbsLenBits = 11;  // log2(2048)

// SHA-256 digest length — same as kMessageDigestLen but aliased for
// invariant 1's cert_tbs digest to keep call sites self-documenting.
constexpr size_t kCertTbsDigestLen = 32;

// ---- Invariant 2a (Task 26) — signedAttrs + content signature bounds ----
//
// The CAdES-BES signedAttrs SET (with [0] IMPLICIT tag 0xA0 rewritten
// to 0x31 before SHA-256) is bounded by kSignedAttrsMaxBlocks SHA-256
// blocks. 24 blocks × 64 = 1536 bytes; minus the 9-byte MD padding
// floor that leaves 1527 bytes of raw signedAttrs headroom. The
// current fixture's signedAttrs is ~1387 bytes (dominated by the
// embedded signingCertificateV2 ESSCertIDv2 + signed timestamp). 24
// blocks gives ~140 bytes of headroom over that fixture; any real-world
// signedAttrs that exceeds kSignedAttrsMaxRaw means the prover layer
// (Rust host) must fail cleanly rather than truncate, and this
// constant needs a bump.
constexpr size_t kSignedAttrsMaxBlocks = 24;
constexpr size_t kSignedAttrsMaxBytes = kSignedAttrsMaxBlocks * 64;  // 1536
constexpr size_t kSignedAttrsLenBits = 11;  // log2(2048) — conservative;
                                            // actual bound is 1536 < 2048.

// SHA-256 digest of signedAttrs — the message the content ECDSA
// signature signs over. Aliased for call-site readability.
constexpr size_t kSignedAttrsDigestLen = 32;

// ---- SPKI binding (Task 26, merged with #30) ----
//
// cert_tbs embeds a P-256 SubjectPublicKeyInfo: 26 bytes of fixed
// DER prefix + a 65-byte SEC1 uncompressed point (0x04 || X[32] ||
// Y[32]). The 65-byte point IS the holder's signing pubkey — the same
// key that produced the CMS content signature. We extract it from
// cert_tbs via a `Routing::shift` over a host-witnessed offset;
// soundness comes from (a) asserting the 26-byte DER prefix at
// offset [0..26] of the extracted window (foreclosing offset-redirect
// attacks), and (b) MAC-binding the SPKI's X and Y coordinates
// across the hash/sig field split so the sig circuit's ECDSA can
// treat them as private Fp256Base inputs. The public blob is
// UNCHANGED — cert SPKI never leaks outside the proof (holder
// identity privacy).
//
// Prefix literal (constant for any P-256 `id-ecPublicKey` SPKI):
//   30 59           SPKI SEQUENCE hdr (l=89)
//   30 13           AlgId SEQUENCE hdr (l=19)
//   06 07 2a 86 48 ce 3d 02 01          OID id-ecPublicKey
//   06 08 2a 86 48 ce 3d 03 01 07       OID prime256v1 (P-256)
//   03 42 00        BIT STRING hdr (l=66, unused-bits=0)
// 26 bytes total. The SEC1 0x04 tag sits at window index 26; X at
// [27..59]; Y at [59..91].
constexpr size_t kSpkiPrefixLen = 26;
constexpr size_t kSpkiXYLen = 32;        // per coordinate
constexpr size_t kSpkiWindowLen =
    kSpkiPrefixLen + 1 + 2 * kSpkiXYLen;  // 26 + 1 + 64 = 91

// ---- Invariant 2c (Task 31) — messageDigest binding bounds ----
//
// The CMS messageDigest attribute embedded in signed_attrs has a fixed
// 17-byte DER prefix (Attribute SEQUENCE hdr + OID TLV + SET OF hdr +
// OCTET STRING hdr) immediately preceding the 32-byte SHA-256 digest
// value. The 32 bytes MUST byte-match `blob.message_digest[32]` (bound
// by invariant 2b to SHA-256(signed_content)). This closes the
// soundness gap where an attacker with honest (cert, signed_attrs,
// sigs) could substitute a fake signed_content + fake message_digest
// and still pass invariants 1 + 2a + 2b independently.
//
// Prefix literal (constant per RFC 5652 messageDigest attribute):
//   30 2f              Attribute SEQUENCE hdr (l=47)
//   06 09 2a 86 48 86 f7 0d 01 09 04   OID messageDigest (1.2.840.113549.1.9.4)
//   31 22              SET OF AttributeValue hdr (l=34)
//   04 20              OCTET STRING hdr (l=32)
// 17 bytes total; the 32-byte digest value follows at window index 17.
constexpr size_t kSignedAttrsMdPrefixLen = 17;
constexpr size_t kSignedAttrsMdWindowLen =
    kSignedAttrsMdPrefixLen + kMessageDigestLen;  // 17 + 32 = 49

// ---- Invariant 7 (Task 34) — nullifier from stable-ID ----
//
// The X.520 serialNumber attribute in cert_tbs's Subject DN carries
// the holder's stable identifier (DIIA: `TINUA-` + 10-digit RNOKPP =
// 16 bytes PrintableString). Invariant 7 routes a 9-byte DER anchor +
// 16-byte value window from cert_tbs at `subject_sn_offset_in_tbs`,
// asserts the anchor on-wire, range-checks
// `subject_sn_offset_in_tbs > subject_dn_start_offset_in_tbs` (the
// ISSUER DN's serialNumber attribute has the SAME 9-byte prefix —
// the range check is the sole disambiguator, without it a prover
// could bind the nullifier to the issuer's ID), and computes
// `SHA-256(stable_id[16] || context_raw[..ctx_len])` as a new 256-bit
// public output `nullifier`.
//
// Anchor literal:
//   30 17                  Attribute SEQUENCE hdr (l=23)
//   06 03 55 04 05         OID 2.5.4.5 (id-at-serialNumber)
//   13 10                  PrintableString hdr (l=16)
// 9 bytes total; stable-ID value follows at window[9..25].
//
// v1 limitation: stable-ID length is fixed at 16 bytes (DIIA RNOKPP).
// Non-DIIA QTSPs with different lengths are deferred to Task #37.
constexpr size_t kStableIdLen = 16;
constexpr size_t kSubjectSnAnchorLen = 9;
constexpr size_t kSubjectSnWindowLen =
    kSubjectSnAnchorLen + kStableIdLen;  // 25

// Nullifier SHA input is `stable_id[16] || context_raw[..ctx_len]`.
// With kContextMaxBytes = 32 and the 9-byte SHA padding floor,
// 16 + 32 + 9 = 57 < 64, so a SINGLE SHA-256 block holds the padded
// preimage. The raw input length fits in 6 bits (max 48 bytes).
constexpr size_t kNullifierShaBlocks = 1;
constexpr size_t kNullifierShaMaxBytes = 64 * kNullifierShaBlocks;  // 64
// log2 of the max raw-preimage byte length, rounded up. max raw =
// kStableIdLen + kContextMaxBytes = 16 + 32 = 48; log2(48) → 6.
constexpr size_t kNullifierShaLenBits = 6;
constexpr size_t kNullifierLen = 32;                                // SHA-256

}  // namespace p7s
}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_P7S_P7S_CIRCUIT_H_
