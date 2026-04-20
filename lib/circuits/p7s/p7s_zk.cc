// Copyright 2026 Oleksandr Vovkotrub. Apache-2.0.
//
// Phase 2a p7s circuit — blob protocol (schema v8).
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
//   (1)  DIIA signer-cert ECDSA signature verifies over cert_tbs — Task 29
//        under the hardcoded DIIA QTSP 2311 root pubkey,
//        with `e = SHA-256(cert_tbs)` MAC-bound across hash/sig
//        circuits (replaces the 25a sentinel).
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
//     Public blob unchanged from v7 (root_pk is a compile-time
//       constant at the circuit-build site, not a public input).
//     Extended proof-output format:
//       u32  schema_version(= 8)
//       u8   macs_b[32]             2 × GF(2^128) values = MAC of
//                                   `e = SHA-256(cert_tbs)` (low+high)
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
using ByteRangeEqC = ByteRangeEq<LC>;
using HexDecodeC = HexDecode<LC>;
using RoutingC = Routing<LC>;
using ContextShaBw = ContextHash::ShaBlockWitness;
using SignedContentShaBw = SignedContentHash::ShaBlockWitness;
using CertTbsShaBw = CertTbsHash::ShaBlockWitness;

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

// Transcript seed — bumped from "p7s-25-hash" to "p7s-29-hash" so proofs
// minted under the v7 sentinel-only circuit cannot be misinterpreted as
// v8 real-ECDSA proofs. A SINGLE Transcript instance is used for hash
// commit, av sampling, and sig commit/prove; both circuits share the
// same seed (mirrors mdoc, which uses one transcript with
// circuit-specific processing keyed by the distinct circuit structures
// themselves).
constexpr char kHashTranscriptSeed[] = "p7s-29-hash";
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
constexpr uint32_t kBlobSchemaVersion = 8;

// ===========================================================================
// Hash-circuit public-input layout (v7). MAC positions are derived from
// this layout so if any of these counts change, the MAC index updates
// automatically (and the static_assert below keeps us honest).
//
//   [0]                              = const 1
//   [1 .. 1 + 256)                   = context_hash v256
//   [257 .. 257 + 520)               = pk_bytes (65 × v8)
//   [777 .. 777 + 256)               = nonce_bytes (32 × v8)
//   [1033]                           = mac[0] (EltW, GF(2^128) native)
//   [1034]                           = mac[1] (EltW)
//   [1035]                           = av     (EltW)
//   npub_in_hash                     = 1036
//
// All of the above are `public`; the private witness starts at
// npub_in_hash and is opaque to the MAC plumbing.
constexpr size_t kHashPubConst = 1;
constexpr size_t kHashPubContextHash = 256;
constexpr size_t kHashPubPk = kPkBytes * 8;         // 520
constexpr size_t kHashPubNonce = kNonceBytes * 8;   // 256
constexpr size_t kHashPubPreMac =
    kHashPubConst + kHashPubContextHash + kHashPubPk + kHashPubNonce;
// Each hash-side MAC public input is 1 native EltW (GF2_128 is 128b
// wide, and a v128 IS an EltW here). kTotalMacValues mac values +
// 1 av = (kTotalMacValues + 1) EltW.
constexpr size_t kHashMacInputWires = kTotalMacValues + 1;
constexpr size_t kHashPubTotal = kHashPubPreMac + kHashMacInputWires;
static_assert(kHashPubPreMac == 1033,
              "layout drift — update kHashPubPreMac comment & index");
static_assert(kHashPubTotal == 1036,
              "layout drift — update npub_in_hash comment");

// Index (in the DENSE Wit array) where the hash MAC region begins.
// update_mac_in_dense writes (kTotalMacValues + 1) native EltW at this
// position. Must match the circuit's declared public-input order —
// anything else would let a malicious prover slot forged MACs into
// positions the verifier doesn't bind.
constexpr size_t kHashMacIndex = kHashPubPreMac;

// ===========================================================================
// Sig-circuit public-input layout (v8). The public input section is
// IDENTICAL to v7 — only the MAC/av wires live here. The ECDSA public
// key (DIIA QTSP 2311 root) is a compile-time `lc.konst(...)` rather
// than a public input (trust anchor is hardcoded at circuit-build time),
// and `e` (= SHA-256(cert_tbs)) is a PRIVATE witness bound to the hash
// circuit via the MAC.
//
//   [0]                              = const 1 (auto-allocated wire 0)
//   [1 .. 1 + 128)                   = mac[0] as v128 (128 bit wires)
//   [129 .. 129 + 128)               = mac[1] as v128
//   [257 .. 257 + 128)               = av as v128
//   npub_in_sig                      = 385
constexpr size_t kSigPubConst = 1;
// Each sig-side MAC public input is a v128 = 128 bit wires (Fp256Base
// isn't wide enough to hold a 128-bit GF(2^128) element as a single
// field element, so it's bit-decomposed).
constexpr size_t kSigMacBitsPerWire = 128;
constexpr size_t kSigMacInputWires =
    (kTotalMacValues + 1) * kSigMacBitsPerWire;  // 3 × 128 = 384
constexpr size_t kSigPubTotal = kSigPubConst + kSigMacInputWires;
static_assert(kSigPubTotal == 385,
              "layout drift — update npub_in_sig comment");

// Index (in the DENSE W_sig array) where the sig MAC region begins.
// update_mac_in_dense writes 128 wires per MAC value (one field
// element per bit).
constexpr size_t kSigMacIndex = kSigPubConst;  // 1

// ===========================================================================
// Hash circuit builder — keeps every pre-v7 constraint intact and adds
// the cross-field MAC binding at the end of the public-input section.
//
// v8 (Task 29) additions vs v7:
//   * Private witness: cert_tbs_numb (v8), cert_tbs[2048] (v8),
//     cert_tbs_bw[32] (SHA block witnesses), e_digest_bytes[32] (v8 —
//     prover-claimed SHA-256(cert_tbs) in big-endian byte order).
//   * Constraint: `e_digest_v256_flatsha == SHA-256(cert_tbs)` via
//     CertTbsHash::assert_message_hash (where e_digest_v256_flatsha is
//     built from e_digest_bytes using the FlatSHA big-endian-byte
//     LSB-first-bit mapping).
//   * MAC-bound value changes from the v7 sentinel to e_digest_v256_mac
//     built from the SAME e_digest_bytes but using the little-endian-
//     byte LSB-first-bit mapping (matches MAC::of_bytes_field and the
//     sig-side Fp256Base::of_bytes_field). The two v256 views point at
//     identical underlying v8 wires — no extra equality constraint
//     needed; wire identity gives byte equality for free.
std::unique_ptr<Circuit<F>> build_hash_circuit() {
  const F Fs;

  QuadCircuit<F> Q(Fs);
  const CB cbk(&Q);
  const LC lc(&cbk, Fs);
  ContextHash context_hasher(lc);
  SignedContentHash signed_content_hasher(lc);
  CertTbsHash cert_tbs_hasher(lc);
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

  // MAC witness (prover's `ap` halves). Still 2 EltW total — one
  // bound message for invariant 1 (Task 26 will add another for 2a).
  MACHWitness mac_witness;
  mac_witness.input(lc);

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

  // Task 29 — cross-field MAC binding to `e = SHA-256(cert_tbs)`.
  // LE-byte view over the SAME 32 BE-ordered wires (different mapping).
  // `e_digest_bytes[i]` is BE byte i (i=0 is MSByte); the MAC treats
  // the digest as a little-endian 256-bit integer — byte 0 of LE ==
  // byte 31 of BE. Matches `Fp256Base::of_bytes_field` (LE Nat) and
  // `MACReference::compute` (splits the 32 bytes into two 16-byte
  // LE halves).
  typename LC::v256 e_digest_v256_mac;
  for (size_t j = 0; j < 256; ++j) {
    size_t le_byte_idx = j / 8;
    size_t be_byte_idx = kCertTbsDigestLen - 1 - le_byte_idx;
    size_t bit_idx = j % 8;
    e_digest_v256_mac[j] = e_digest_bytes[be_byte_idx][bit_idx];
  }

  MACH mac_check(lc);
  typename LC::EltW mac_vals[kTotalMacValues];
  for (size_t i = 0; i < kTotalMacValues; ++i) {
    mac_vals[i] = mac_pub[i];
  }
  typename LC::EltW av_h = mac_pub[kTotalMacValues];
  mac_check.verify_mac(mac_vals, av_h, e_digest_v256_mac, mac_witness);

  return Q.mkcircuit(/*nc=*/1);
}

// Sig-circuit builder — invariant 1 (Task 29). Verifies the DIIA
// signer cert's ECDSA signature against the hardcoded DIIA QTSP 2311
// root public key, AND MAC-binds the cert_tbs digest to the hash
// circuit (so the SHA-256 computation is done ONCE in the hash
// circuit and trusted on the sig side via the cross-field MAC).
std::unique_ptr<Circuit<Fp256Base>> build_sig_circuit() {
  QuadCircuit<Fp256Base> Q(p256_base);
  const CB256 cbk(&Q);
  const LC256 lc(&cbk, p256_base);

  // ---- Public inputs (layout below — see kSigMacInputWires) ----
  // mac values + av as bit-decomposed v128 each.
  typename LC256::v128 mac_pub[kTotalMacValues + 1];
  for (size_t i = 0; i < kTotalMacValues + 1; ++i) {
    mac_pub[i] = lc.template vinput<128>();
  }

  // ---- Private witness ----
  Q.private_input();

  // Cert_tbs digest as a scalar Fp256Base element. Soundness binding
  // of this wire to the hash-circuit's cert_tbs SHA comes from the MAC
  // primitive below. Treated as a private input here because
  // propagating it through the public-input section would expose the
  // digest (a privacy regression for credentials with distinguishable
  // certs) and is unnecessary — the MAC gadget checks its
  // bit-decomposition anyway.
  typename LC256::EltW e_wit = lc.eltw_input();

  P7sSigWitness sig_witness;
  sig_witness.input(lc);

  // ---- Constraints ----
  // Hardcoded DIIA QTSP 2311 root public key as base-field constants.
  // `of_string` returns Elts already in Montgomery form (fp_generic.h:
  // 329-336), so `lc.konst(...)` binds the right internal
  // representation directly.
  typename LC256::EltW root_pk_x =
      lc.konst(p256_base.of_string(kDiiaRootPkX_decimal));
  typename LC256::EltW root_pk_y =
      lc.konst(p256_base.of_string(kDiiaRootPkY_decimal));

  P7sSigCircuit sig_gadget(lc, p256, n256_order);
  typename LC256::v128 mac_vals[kTotalMacValues]{};
  for (size_t i = 0; i < kTotalMacValues; ++i) {
    mac_vals[i] = mac_pub[i];
  }
  typename LC256::v128 av_s{};
  av_s = mac_pub[kTotalMacValues];

  // Real ECDSA verification + MAC binding in one call. Soundness
  // argument lives in P7sSignature::assert_signature's doc comment.
  sig_gadget.assert_signature(root_pk_x, root_pk_y, e_wit, mac_vals, av_s,
                              sig_witness);

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
  uint8_t cert_tbs[kCertTbsMaxBytes];
  // v8: raw (r, s) scalars from the cert_sig DER, each 32 big-endian
  // bytes. The Rust side DER-parses the cert signature and supplies
  // the raw scalars so the C++ side doesn't need an ASN.1 parser.
  uint8_t cert_sig_r[32];
  uint8_t cert_sig_s[32];
};

struct ParsedPublic {
  uint8_t context_hash[32];
  uint8_t pk[kPkBytes];
  uint8_t nonce[kNonceBytes];
};

bool parse_witness_blob(const uint8_t* blob, size_t blob_len,
                        ParsedWitness& out) {
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
  if (end - p < static_cast<ptrdiff_t>(kCertTbsMaxBytes)) return false;
  std::memcpy(out.cert_tbs, p, kCertTbsMaxBytes);
  p += kCertTbsMaxBytes;

  // v8: raw (r, s) scalars from the cert signature — 32 big-endian
  // bytes each. Rust host-side DER-parses the p7s cert_sig and
  // supplies these directly.
  if (end - p < 32) return false;
  std::memcpy(out.cert_sig_r, p, 32);
  p += 32;
  if (end - p < 32) return false;
  std::memcpy(out.cert_sig_s, p, 32);
  p += 32;

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

P7sErrorCode p7s_prove(const uint8_t* witness_blob, size_t witness_blob_len,
                       const uint8_t* public_blob, size_t public_blob_len,
                       uint8_t** proof_out, size_t* proof_len_out) {
  using namespace proofs;
  using namespace proofs::p7s;

  if (proof_out == nullptr || proof_len_out == nullptr) return P7S_NULL_INPUT;

  ParsedWitness wit{};
  if (!parse_witness_blob(witness_blob, witness_blob_len, wit)) {
    return P7S_INVALID_INPUT;
  }
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

  // Compute SHA witnesses off-circuit.
  ShaWitness<kContextMaxBlocks> ctx_sw;
  compute_sha_witness<kContextMaxBlocks>(wit.context, wit.context_len, ctx_sw);
  ShaWitness<kSignedContentMaxBlocks> sc_sw;
  compute_sha_witness<kSignedContentMaxBlocks>(wit.signed_content,
                                               wit.signed_content_len, sc_sw);
  ShaWitness<kCertTbsMaxBlocks> cert_sw;
  compute_sha_witness<kCertTbsMaxBlocks>(wit.cert_tbs, wit.cert_tbs_len,
                                         cert_sw);

  // Compute e = SHA-256(cert_tbs) outside the circuit so the Rust-side
  // helper matches the in-circuit result bit for bit. Uses openssl's
  // SHA256 (same implementation FlatSHA256Witness internally uses to
  // derive its reference digest), so the two views trivially agree.
  //
  // e_digest_be is the standard big-endian SHA output (byte 0 is the
  // most-significant byte of the 256-bit integer).
  uint8_t e_digest_be[kCertTbsDigestLen];
  {
    // Fully-qualify to disambiguate against openssl's C-linkage SHA256
    // function introduced via the openssl/sha.h transitive include.
    proofs::SHA256 sha;
    sha.Update(wit.cert_tbs, wit.cert_tbs_len);
    sha.DigestData(e_digest_be);
  }

  // Parse (r, s) from the DER-encoded cert signature. v8 blob carries
  // 32 raw big-endian bytes each.
  Fp256Nat ne = nat_from_be<Fp256Nat>(e_digest_be);
  Fp256Nat nr = nat_from_be<Fp256Nat>(wit.cert_sig_r);
  Fp256Nat ns = nat_from_be<Fp256Nat>(wit.cert_sig_s);

  // Build the sig-side ECDSA witness. A failure here means the
  // prover supplied (r, s) that don't verify under the hardcoded DIIA
  // root — either a malicious prover or a fixture mismatch.
  Fp256Base::Elt root_pkX = p256_base.of_string(kDiiaRootPkX_decimal);
  Fp256Base::Elt root_pkY = p256_base.of_string(kDiiaRootPkY_decimal);
  VerifyWitness3<P256, Fp256Scalar> ecdsa_wit(p256_scalar, p256);
  if (!ecdsa_wit.compute_witness(root_pkX, root_pkY, ne, nr, ns)) {
    return P7S_INVALID_INPUT;
  }
  // Fp256Base::Elt of e in Montgomery form, used as the MAC-bound
  // EltW on the sig side (after `.eltw_input()` wire declaration).
  Fp256Base::Elt e_elt = p256_base.to_montgomery(ne);

  // Sample the prover's half of the MAC key BEFORE commit so it
  // becomes part of the committed witness. `ap` is 2 gf2k values
  // (low + high halves of `e = SHA-256(cert_tbs)`).
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
  // Same pattern as context / signed_content: numb, padded bytes,
  // per-block witnesses, then the 32-byte target (big-endian).
  push_v8(hash_filler, cert_sw.numb, Fs);
  push_sha_padded_bytes<kCertTbsMaxBlocks>(hash_filler, cert_sw, Fs);
  push_sha_block_witnesses<kCertTbsMaxBlocks>(hash_filler, cert_sw, Fs);
  for (size_t i = 0; i < kCertTbsDigestLen; ++i) {
    push_v8(hash_filler, e_digest_be[i], Fs);
  }

  // Task 25a/29: prover's committed `ap` halves (2 native EltW).
  for (size_t i = 0; i < kTotalMacValues; ++i) {
    hash_filler.push_back(ap[i]);
  }
  if (hash_filler.size() != c_hash.ninputs) return P7S_INVALID_INPUT;

  // ===== Fill SIG witness (W_sig over Fp256Base) =====
  Dense<Fp256Base> W_sig(1, c_sig.ninputs);
  DenseFiller<Fp256Base> sig_filler(W_sig);

  // Public section.
  sig_filler.push_back(p256_base.one());
  push_sig_mac_placeholders(sig_filler);

  // Private section:
  //   1. e_wit — the 32-byte digest as an Fp256Base::Elt in Montgomery
  //      form, bound to the hash circuit via the MAC below.
  //   2. MAC witness — prover's ap halves (packed via BitPluckerEncoder)
  //      plus the message bit-decomposition (of the same 32 bytes that
  //      yielded e_elt above, LE-ordered to match of_bytes_field).
  //   3. ECDSA witness — the 1038-element (rx, ry, pre[], bi[], int_*)
  //      advice table produced by VerifyWitness3::compute_witness.
  sig_filler.push_back(e_elt);

  // MAC witness — uses the LE-ordered 32 bytes of `e` (MacWitness
  // calls gf_.of_bytes_field on each 16-byte half).
  uint8_t e_digest_le[kCertTbsDigestLen];
  for (size_t i = 0; i < kCertTbsDigestLen; ++i) {
    e_digest_le[i] = e_digest_be[kCertTbsDigestLen - 1 - i];
  }
  {
    MacWitness<Fp256Base> mw(p256_base, Fs);
    mw.compute_witness(ap, e_digest_le);
    mw.fill_witness(sig_filler);
  }

  // ECDSA witness — fills 1033 Fp256Base wires per the shape declared
  // in VerifyCircuit::Witness::input. compute_witness was called on
  // the sig-circuit prep above; just drain it into the filler.
  ecdsa_wit.fill_witness(sig_filler);

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
  // MAC values over the cert_tbs digest (LE-ordered — matches the
  // in-circuit LE v256 view + Fp256Base::of_bytes_field on the sig
  // side + gf_.of_bytes_field on the MAC reference side).
  gf2k av = generate_mac_key(tp);
  gf2k macs[kTotalMacValues];
  {
    uint8_t e_le[kCertTbsDigestLen];
    for (size_t i = 0; i < kCertTbsDigestLen; ++i) {
      e_le[i] = e_digest_be[kCertTbsDigestLen - 1 - i];
    }
    mac_ref.compute(macs, av, ap, e_le);
  }

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
  push_sig_mac_values(sig_filler, macs, av);
  if (sig_filler.size() != c_sig.npub_in) return P7S_VERIFIER_FAILURE;

  bool ok_h = hash_v.verify(pr_hash, pub_hash, tv);
  bool ok_s = sig_v.verify(pr_sig, pub_sig, tv);
  return (ok_h && ok_s) ? P7S_SUCCESS : P7S_VERIFIER_FAILURE;
}

void p7s_free_proof(uint8_t* proof) { free(proof); }

}  // extern "C"
