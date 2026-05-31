// Copyright 2026 Oleksandr Vovkotrub. Apache-2.0.
//
// p7s MAC message #4 (stable_id) — the OPRF Sybil gate.
//
// The OPRF-fusion (feat/p7s-v13) adds `stable_id` as a 5th cross-field
// MAC message: the cert-verified X.520 serialNumber value is bound on
// the hash circuit (GF(2^128)) and consumed as a PRIVATE Fp256Base
// field element on the sig circuit, where the OPRF block (a later
// step) recomposes the SAME element from its `rnokpp` byte wires. This
// test exercises the soundness-critical property of that binding
// directly, at the level of the MAC primitive `assert_signature` uses
// for message #4:
//
//   HONEST: the sig-side `stable_id` field element equals the
//           cert-extracted value the hash side MAC'd  → MAC verifies.
//   GATE:   a sig-side `stable_id` that differs from the hash-side
//           cert-extracted value  → MAC mismatch trips (fail-closed).
//
// Without this gate a single valid cert could mint unlimited OPRF
// identities (Sybil). The test uses the EvaluationBackend with
// panic=false so the negative case is observable via
// `assertion_failed()` instead of aborting (same discipline as
// oprf_blind_test's negative cases).

#include <cstddef>
#include <cstdint>
#include <cstring>

#include "circuits/logic/bit_plucker.h"
#include "circuits/logic/bit_plucker_encoder.h"
#include "circuits/logic/evaluation_backend.h"
#include "circuits/logic/logic.h"
#include "circuits/mac/mac_circuit.h"
#include "circuits/mac/mac_reference.h"
#include "circuits/p7s/p7s_circuit.h"
#include "circuits/p7s/sub/p7s_signature.h"
#include "ec/p256.h"
#include "gf2k/gf2_128.h"
#include "random/secure_random_engine.h"
#include "gtest/gtest.h"

namespace proofs {
namespace {

using p7s::kStableIdMacBytes;
using Field = Fp256Base;
using gf2k = GF2_128<>::Elt;
using EvalBackend = EvaluationBackend<Field>;
using EvalLC = Logic<Field, EvalBackend>;
using MacBitPlucker = BitPlucker<EvalLC, p7s::kMacPluckerBits>;
using MacCircuit = MAC<EvalLC, MacBitPlucker>;
using Enc = BitPluckerEncoder<Field, p7s::kMacPluckerBits>;

// Build the 32-byte little-endian MAC message the HASH side commits for
// `stable_id`: the kStableIdMacBytes value bytes packed big-endian into
// the low bytes (LE byte i = value byte kStableIdMacBytes-1-i), zero
// above. Mirrors `stable_id_v256_mac` in p7s_zk.cc and `stable_id_le`.
static void make_stable_id_le(const char* s16, uint8_t out[32]) {
  std::memset(out, 0, 32);
  for (size_t i = 0; i < kStableIdMacBytes; ++i) {
    out[i] = static_cast<uint8_t>(s16[kStableIdMacBytes - 1 - i]);
  }
}

// Field element the sig side binds: big-endian value of the 16
// serialNumber bytes, mod p. Mirrors p7s_zk.cc's `stable_id_elt`.
static Field::Elt stable_id_field_elt(const char* s16) {
  uint8_t be32[Fp256Nat::kBytes] = {0};
  for (size_t i = 0; i < kStableIdMacBytes; ++i) {
    be32[Fp256Nat::kBytes - kStableIdMacBytes + i] =
        static_cast<uint8_t>(s16[i]);
  }
  uint8_t le32[Fp256Nat::kBytes];
  for (size_t i = 0; i < Fp256Nat::kBytes; ++i) {
    le32[i] = be32[Fp256Nat::kBytes - 1 - i];
  }
  Fp256Nat n = Fp256Nat::of_bytes(le32);
  return p256_base.to_montgomery(n);
}

// MAC::Witness with constant (konst) wires, reproducing what
// MacWitness::compute_witness + fill_witness feed the sig circuit.
static MacCircuit::Witness konst_mac_witness(const EvalLC& lc,
                                             const gf2k ap[2],
                                             const uint8_t msg_le[32]) {
  Enc enc(lc.f_);
  MacCircuit::Witness vw;
  uint8_t bits[GF2_128<>::kBits];
  for (size_t i = 0; i < 2; ++i) {
    for (size_t j = 0; j < GF2_128<>::kBits; ++j) bits[j] = ap[i][j];
    auto packed = enc.pack<Enc::packed_v128>(bits, GF2_128<>::kBits);
    for (size_t k = 0; k < packed.size(); ++k)
      vw.aa_[i][k] = lc.konst(packed[k]);
  }
  uint8_t mbits[256];
  for (size_t j = 0; j < 256; ++j) mbits[j] = (msg_le[j / 8] >> (j % 8)) & 1;
  auto packed_msg = enc.pack<Enc::packed_v256>(mbits, 256);
  for (size_t k = 0; k < packed_msg.size(); ++k)
    vw.xx_[k] = lc.konst(packed_msg[k]);
  return vw;
}

// Run the message-#4 MAC verify with sig-side field element `msg_elt`
// against a MAC computed over `mac_msg_le` (the hash-side bound value).
// Returns whether any assertion tripped.
static bool run_stable_id_mac(const Field::Elt& msg_elt,
                              const uint8_t mac_msg_le[32]) {
  const Field& F = p256_base;
  const EvalBackend ebk(F, /*panic=*/false);
  const EvalLC lc(&ebk, F);

  SecureRandomEngine rng;
  MACReference<GF2_128<>> mac_ref;
  gf2k av, ap[2], mac[2];
  mac_ref.sample(&av, 1, &rng);
  mac_ref.sample(ap, 2, &rng);
  uint8_t mac_msg_copy[32];
  std::memcpy(mac_msg_copy, mac_msg_le, 32);
  mac_ref.compute(mac, av, ap, mac_msg_copy);

  // The sig-side v128 MAC public inputs are bitvecs (one BitW per bit,
  // LSB-first), matching the circuit's `vinput<128>()` declaration.
  EvalLC::v128 mac_v[2], av_v;
  for (size_t j = 0; j < GF2_128<>::kBits; ++j) {
    av_v[j] = lc.bit(av[j] ? 1 : 0);
    mac_v[0][j] = lc.bit(mac[0][j] ? 1 : 0);
    mac_v[1][j] = lc.bit(mac[1][j] ? 1 : 0);
  }

  MacCircuit macc(lc);
  MacCircuit::Witness vw = konst_mac_witness(lc, ap, mac_msg_le);
  macc.verify_mac(lc.konst(msg_elt), mac_v, av_v, vw, n256_order);
  return ebk.assertion_failed();
}

// HONEST: sig-side stable_id == the cert-extracted value the hash side
// MAC'd → the MAC verifies, no assertion trips.
TEST(P7sStableIdMac, HonestBindingPasses) {
  const char* id = "TINUA-1234567890";
  uint8_t mac_le[32];
  make_stable_id_le(id, mac_le);
  Field::Elt elt = stable_id_field_elt(id);
  EXPECT_FALSE(run_stable_id_mac(elt, mac_le))
      << "honest stable_id MAC binding must verify";
}

// GATE (the whole point): a sig-side stable_id that DIFFERS from the
// hash-side cert-extracted value MUST trip the MAC. This is the Sybil
// gate: the OPRF input cannot be a free witness divorced from the cert.
TEST(P7sStableIdMac, MismatchedStableIdFailsClosed) {
  const char* cert_id = "TINUA-1234567890";  // what the cert says (hash side)
  const char* forged = "TINUA-9999999999";   // what the prover wants (sig side)
  uint8_t mac_le[32];
  make_stable_id_le(cert_id, mac_le);  // hash side MAC's the CERT value
  Field::Elt forged_elt = stable_id_field_elt(forged);  // sig side feeds forged
  EXPECT_TRUE(run_stable_id_mac(forged_elt, mac_le))
      << "sig-side stable_id != hash-side cert value must trip the MAC "
         "(Sybil gate failed open!)";
}

// A single-bit difference in the sig-side field element must also trip
// (almost-universality of the MAC over the verifier-sampled av).
TEST(P7sStableIdMac, OneBitDifferenceFailsClosed) {
  const char* id = "TINUA-1234567890";
  uint8_t mac_le[32];
  make_stable_id_le(id, mac_le);
  Field::Elt elt = stable_id_field_elt(id);
  Field::Elt off_by_one = p256_base.addf(elt, p256_base.one());
  EXPECT_TRUE(run_stable_id_mac(off_by_one, mac_le))
      << "off-by-one sig-side stable_id must trip the MAC";
}

}  // namespace
}  // namespace proofs
