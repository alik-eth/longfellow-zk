// Copyright 2026 Google LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <functional>
#include <memory>
#include <string>
#include <vector>

#include "algebra/static_string.h"
#include "arrays/dense.h"
#include "circuits/compiler/circuit_dump.h"
#include "circuits/compiler/compiler.h"
#include "circuits/hash2curve/expand_xmd_witness.h"
#include "circuits/hash2curve/hash_to_curve.h"
#include "circuits/hash2curve/hash_to_curve_witness.h"
#include "circuits/hash2curve/p256_sswu_witness.h"
#include "circuits/logic/compiler_backend.h"
#include "circuits/logic/evaluation_backend.h"
#include "circuits/logic/logic.h"
#include "ec/p256.h"
#include "sumcheck/circuit.h"
#include "sumcheck/testing.h"
#include "util/log.h"
#include "zk/zk_prover.h"
#include "zk/zk_verifier.h"
#include "gtest/gtest.h"

namespace proofs {
namespace {

using Field = Fp256Base;
using Elt = Field::Elt;

// Parse a hex string into bytes.
static std::vector<uint8_t> unhex(const std::string& s) {
  std::vector<uint8_t> out;
  for (size_t i = 0; i + 1 < s.size(); i += 2) {
    auto nib = [](char c) -> uint8_t {
      if (c >= '0' && c <= '9') return c - '0';
      if (c >= 'a' && c <= 'f') return c - 'a' + 10;
      if (c >= 'A' && c <= 'F') return c - 'A' + 10;
      return 0;
    };
    out.push_back((nib(s[i]) << 4) | nib(s[i + 1]));
  }
  return out;
}

static std::string tohex(const std::vector<uint8_t>& b) {
  static const char* k = "0123456789abcdef";
  std::string s;
  for (uint8_t x : b) {
    s.push_back(k[x >> 4]);
    s.push_back(k[x & 0xf]);
  }
  return s;
}

// RFC 9380 Appendix K.1 expand_message_xmd(SHA-256).
// DST = "QUUX-V01-CS02-with-expander-SHA256-128".
static const char kK1Dst[] = "QUUX-V01-CS02-with-expander-SHA256-128";

struct K1Vec {
  const char* msg;
  size_t len_in_bytes;
  const char* uniform_bytes;
};

static const K1Vec kK1[] = {
    // len_in_bytes = 0x20
    {"", 0x20, "68a985b87eb6b46952128911f2a4412bbc302a9d759667f87f7a21d803f07235"},
    {"abc", 0x20,
     "d8ccab23b5985ccea865c6c97b6e5b8350e794e603b4b97902f53a8a0d605615"},
    {"abcdef0123456789", 0x20,
     "eff31487c770a893cfb36f912fbfcbff40d5661771ca4b2cb4eafe524333f5c1"},
    // len_in_bytes = 0x80
    {"", 0x80,
     "af84c27ccfd45d41914fdff5df25293e221afc53d8ad2ac06d5e3e29485dadbee0d1"
     "21587713a3e0dd4d5e69e93eb7cd4f5df4cd103e188cf60cb02edc3edf18eda8576c4"
     "12b18ffb658e3dd6ec849469b979d444cf7b26911a08e63cf31f9dcc541708d349118"
     "4472c2c29bb749d4286b004ceb5ee6b9a7fa5b646c993f0ced"},
    {"abc", 0x80,
     "abba86a6129e366fc877aab32fc4ffc70120d8996c88aee2fe4b32d6c7b6437a647e6"
     "c3163d40b76a73cf6a5674ef1d890f95b664ee0afa5359a5c4e07985635bbecbac65d"
     "747d3d2da7ec2b8221b17b0ca9dc8a1ac1c07ea6a1e60583e2cb00058e77b7b72a298"
     "425cd1b941ad4ec65e8afc50303a22c0f99b0509b4c895f40"},
    {"abcdef0123456789", 0x80,
     "ef904a29bffc4cf9ee82832451c946ac3c8f8058ae97d8d629831a74c6572bd9ebd0d"
     "f635cd1f208e2038e760c4994984ce73f0d55ea9f22af83ba4734569d4bc95e18350f"
     "740c07eef653cbb9f87910d833751825f0ebefa1abe5420bb52be14cf489b37fe1a72"
     "f7de2d10be453b2c9d9eb20c7e3f6edc5a60629178d9478df"},
};

// RFC 9380 Appendix J.1.1 P256_XMD:SHA-256_SSWU_RO_.
// dst = "QUUX-V01-CS02-with-P256_XMD:SHA-256_SSWU_RO_".
struct J11Vec {
  const char* msg;
  StaticString u0, u1, px, py;
};

static const J11Vec kJ11[] = {
    {"",
     StaticString(
         "0xad5342c66a6dd0ff080df1da0ea1c04b96e0330dd89406465eeba11582515009"),
     StaticString(
         "0x8c0f1d43204bd6f6ea70ae8013070a1518b43873bcd850aafa0a9e220e2eea5a"),
     StaticString(
         "0x2c15230b26dbc6fc9a37051158c95b79656e17a1a920b11394ca91c44247d3e4"),
     StaticString(
         "0x8a7a74985cc5c776cdfe4b1f19884970453912e9d31528c060be9ab5c43e8415")},
    {"abc",
     StaticString(
         "0xafe47f2ea2b10465cc26ac403194dfb68b7f5ee865cda61e9f3e07a537220af1"),
     StaticString(
         "0x379a27833b0bfe6f7bdca08e1e83c760bf9a338ab335542704edcd69ce9e46e0"),
     StaticString(
         "0x0bb8b87485551aa43ed54f009230450b492fead5f1cc91658775dac4a3388a0f"),
     StaticString(
         "0x5c41b3d0731a27a7b14bc0bf0ccded2d8751f83493404c84a88e71ffd424212e")},
    {"abcdef0123456789",
     StaticString(
         "0x0fad9d125a9477d55cf9357105b0eb3a5c4259809bf87180aa01d651f53d312c"),
     StaticString(
         "0xb68597377392cd3419d8fcc7d7660948c8403b19ea78bbca4b133c9d2196c0fb"),
     StaticString(
         "0x65038ac8f2b1def042a5df0b33b1f4eca6bff7cb0f9c6c1526811864e544ed80"),
     StaticString(
         "0xcad44d40a656e7aff4002a8de287abc8ae0482b5ae825822bb870d6df9b56ca3")},
};

// Production DST for the J.1.1 KATs (44 bytes).
static const char kRfcDst[] = "QUUX-V01-CS02-with-P256_XMD:SHA-256_SSWU_RO_";
static constexpr size_t kRfcDstLen = 44;  // strlen(kRfcDst)

// ---------------------------------------------------------------------------
// 1) Host expand_message_xmd vs RFC 9380 Appendix K.1.
// ---------------------------------------------------------------------------
TEST(ExpandXmd, HostMatchesRfc9380K1) {
  std::vector<uint8_t> dst(kK1Dst, kK1Dst + std::strlen(kK1Dst));
  for (const auto& v : kK1) {
    std::vector<uint8_t> msg(v.msg, v.msg + std::strlen(v.msg));
    auto got = expand_message_xmd_bytes(msg.data(), msg.size(), dst.data(),
                                        dst.size(), v.len_in_bytes);
    EXPECT_EQ(tohex(got), std::string(v.uniform_bytes))
        << "K.1 mismatch msg='" << v.msg << "' len=" << v.len_in_bytes;
  }
}

// Max message length across the J.1.1 KATs ("abcdef0123456789" = 16).
constexpr size_t kMaxMsg = 16;

// Build a fixed-length msg buffer (zero-padded) and run host hash_to_curve.
// The circuit/host both treat msg as a fixed-length kMaxMsg buffer; the SHA
// length-pin uses the FIXED kMaxMsg payload, so KATs must use msgs of exactly
// kMaxMsg bytes OR we instantiate per length.  We instantiate per length via a
// templated helper.
template <size_t kM>
static HashToCurveWitness<Field, kM, kRfcDstLen> host_h2c(const char* msg) {
  const Field& F = p256_base;
  uint8_t m[kM == 0 ? 1 : kM];
  for (size_t i = 0; i < kM; ++i) m[i] = static_cast<uint8_t>(msg[i]);
  uint8_t dst[kRfcDstLen];
  for (size_t i = 0; i < kRfcDstLen; ++i) dst[i] = kRfcDst[i];
  HashToCurveWitness<Field, kM, kRfcDstLen> h;
  hash_to_curve<Field, kM, kRfcDstLen>(F, m, dst, h);
  return h;
}

// ---------------------------------------------------------------------------
// 2) Host hash_to_field (u0, u1) + full hash_to_curve (P) vs RFC 9380 J.1.1.
// ---------------------------------------------------------------------------
TEST(HashToCurve, HostMatchesRfc9380J11) {
  const Field& F = p256_base;
  auto check_vec = [&](size_t idx, auto h) {
    Elt u0 = F.of_string(kJ11[idx].u0);
    Elt u1 = F.of_string(kJ11[idx].u1);
    Elt px = F.of_string(kJ11[idx].px);
    Elt py = F.of_string(kJ11[idx].py);
    EXPECT_TRUE(h.u0 == u0) << "u0 mismatch at " << idx;
    EXPECT_TRUE(h.u1 == u1) << "u1 mismatch at " << idx;
    EXPECT_TRUE(h.px == px) << "P.x mismatch at " << idx;
    EXPECT_TRUE(h.py == py) << "P.y mismatch at " << idx;
    EXPECT_TRUE(p256.is_on_curve(h.px, h.py)) << "off-curve at " << idx;
  };
  check_vec(0, host_h2c<0>(kJ11[0].msg));
  check_vec(1, host_h2c<3>(kJ11[1].msg));
  check_vec(2, host_h2c<16>(kJ11[2].msg));
}

// ---------------------------------------------------------------------------
// 3) In-circuit ExpandMessageXmd (EvaluationBackend): uniform_bytes match host.
// ---------------------------------------------------------------------------
TEST(ExpandXmd, EvaluationBackendMatchesHost) {
  using EvalBackend = EvaluationBackend<Field>;
  using LC = Logic<Field, EvalBackend>;
  const Field& F = p256_base;
  const EvalBackend ebk(F);
  const LC lc(&ebk, F);

  constexpr size_t kM = 16;
  using Xmd = ExpandMessageXmd<LC, kM, kRfcDstLen>;
  Xmd xmd(lc);

  const char* msg = "abcdef0123456789";
  uint8_t m[kM];
  for (size_t i = 0; i < kM; ++i) m[i] = msg[i];
  uint8_t dst[kRfcDstLen];
  for (size_t i = 0; i < kRfcDstLen; ++i) dst[i] = kRfcDst[i];

  ExpandXmdWitness<kM, kRfcDstLen> h;
  expand_message_xmd<kM, kRfcDstLen>(m, dst, h);

  typename Xmd::Witness w;
  std::vector<uint8_t> mv(m, m + kM);
  typename LC::v8 msgw[kM];
  for (size_t i = 0; i < kM; ++i) msgw[i] = lc.vbit8(m[i]);
  w.set(lc, h);

  xmd.assert_expand(msgw, dst, w);
  EXPECT_FALSE(ebk.assertion_failed()) << "expand assert failed";

  // uniform_bytes must equal the host's: assert in-circuit; any mismatch
  // trips assertion_failed().
  typename LC::v8 ub[96];
  xmd.uniform_bytes(w, ub);
  for (size_t i = 0; i < 96; ++i) {
    lc.vassert_eq(ub[i], static_cast<uint64_t>(h.uniform_bytes[i]));
  }
  EXPECT_FALSE(ebk.assertion_failed()) << "uniform_bytes mismatch vs host";
}

// ---------------------------------------------------------------------------
// 3b) In-circuit ExpandMessageXmd negative: corrupt a SHA block witness.
// ---------------------------------------------------------------------------
TEST(ExpandXmd, EvaluationBackendNegative) {
  using EvalBackend = EvaluationBackend<Field>;
  using LC = Logic<Field, EvalBackend>;
  const Field& F = p256_base;
  const EvalBackend ebk(F, false);  // don't panic
  const LC lc(&ebk, F);

  constexpr size_t kM = 3;
  using Xmd = ExpandMessageXmd<LC, kM, kRfcDstLen>;
  Xmd xmd(lc);

  const char* msg = "abc";
  uint8_t m[kM];
  for (size_t i = 0; i < kM; ++i) m[i] = msg[i];
  uint8_t dst[kRfcDstLen];
  for (size_t i = 0; i < kRfcDstLen; ++i) dst[i] = kRfcDst[i];

  ExpandXmdWitness<kM, kRfcDstLen> h;
  expand_message_xmd<kM, kRfcDstLen>(m, dst, h);
  // Corrupt one byte of b1 (claimed hash output): SHA invariant must trip.
  h.b1[5] ^= 0x01;

  typename Xmd::Witness w;
  w.set(lc, h);
  typename LC::v8 msgw[kM];
  for (size_t i = 0; i < kM; ++i) msgw[i] = lc.vbit8(m[i]);
  xmd.assert_expand(msgw, dst, w);
  EXPECT_TRUE(ebk.assertion_failed()) << "corrupted b1 not caught";
}

// ---------------------------------------------------------------------------
// 4) Full in-circuit hash_to_curve (EvaluationBackend) vs RFC 9380 J.1.1.
// ---------------------------------------------------------------------------
template <size_t kM>
static void eval_full_h2c(size_t idx, const char* msg) {
  using EvalBackend = EvaluationBackend<Field>;
  using LC = Logic<Field, EvalBackend>;
  using H2C = P256HashToCurve<LC, Field, kM, kRfcDstLen>;
  const Field& F = p256_base;
  const EvalBackend ebk(F);
  const LC lc(&ebk, F);
  H2C h2c(lc);

  auto h = host_h2c<kM>(msg);
  uint8_t dst[kRfcDstLen];
  for (size_t i = 0; i < kRfcDstLen; ++i) dst[i] = kRfcDst[i];

  typename H2C::Witness w;
  w.set(lc, h);

  typename LC::v8 msgw[kM == 0 ? 1 : kM];
  for (size_t i = 0; i < kM; ++i) msgw[i] = lc.vbit8(msg[i]);

  typename LC::EltW px, py;
  h2c.hash_to_curve(msgw, dst, w, px, py);

  EXPECT_FALSE(ebk.assertion_failed()) << "h2c assert failed at " << idx;
  Elt epx = F.of_string(kJ11[idx].px);
  Elt epy = F.of_string(kJ11[idx].py);
  EXPECT_TRUE(px == lc.konst(epx)) << "circuit P.x mismatch at " << idx;
  EXPECT_TRUE(py == lc.konst(epy)) << "circuit P.y mismatch at " << idx;
}

TEST(HashToCurve, EvaluationBackendMatchesRfc9380J11) {
  eval_full_h2c<0>(0, kJ11[0].msg);
  eval_full_h2c<3>(1, kJ11[1].msg);
  eval_full_h2c<16>(2, kJ11[2].msg);
}

// ---------------------------------------------------------------------------
// 4b) Full hash_to_curve negatives (EvaluationBackend).
// ---------------------------------------------------------------------------
TEST(HashToCurve, EvaluationBackendNegatives) {
  using EvalBackend = EvaluationBackend<Field>;
  using LC = Logic<Field, EvalBackend>;
  constexpr size_t kM = 3;
  using H2C = P256HashToCurve<LC, Field, kM, kRfcDstLen>;
  const Field& F = p256_base;
  const char* msg = "abc";
  uint8_t dst[kRfcDstLen];
  for (size_t i = 0; i < kRfcDstLen; ++i) dst[i] = kRfcDst[i];

  auto run = [&](const std::function<void(HashToCurveWitness<Field, kM,
                                          kRfcDstLen>&)>& mutate) -> bool {
    const EvalBackend ebk(F, false);
    const LC lc(&ebk, F);
    H2C h2c(lc);
    auto h = host_h2c<kM>(msg);
    mutate(h);
    typename H2C::Witness w;
    w.set(lc, h);
    typename LC::v8 msgw[kM];
    for (size_t i = 0; i < kM; ++i) msgw[i] = lc.vbit8(msg[i]);
    typename LC::EltW px, py;
    h2c.hash_to_curve(msgw, dst, w, px, py);
    return ebk.assertion_failed();
  };

  // sanity: good witness passes.
  EXPECT_FALSE(run([](auto&) {}));
  // bad zinv: affine normalisation / on-curve must trip.
  EXPECT_TRUE(run([&](auto& h) { h.zinv = F.addf(h.zinv, F.one()); }))
      << "bad zinv not caught";
  // corrupted map0 hint (y_candidate): SSWU sqrt assertion must trip.
  EXPECT_TRUE(run([&](auto& h) {
    h.q0.y_candidate = F.addf(h.q0.y_candidate, F.one());
  })) << "corrupted map0 hint not caught";
  // corrupted SHA b3 output: expand SHA invariant must trip.
  EXPECT_TRUE(run([&](auto& h) { h.exp.b3[0] ^= 0x01; }))
      << "corrupted b3 not caught";
}

// ---------------------------------------------------------------------------
// 5) One full compiled prove -> verify round-trip, public (Px, Py).
// ---------------------------------------------------------------------------
constexpr size_t kRtMsg = 16;
using RtH2C =
    P256HashToCurve<Logic<Field, CompilerBackend<Field>>, Field, kRtMsg,
                    kRfcDstLen>;

std::unique_ptr<Circuit<Field>> make_h2c_circuit() {
  using CB = CompilerBackend<Field>;
  using LC = Logic<Field, CB>;
  using H2C = P256HashToCurve<LC, Field, kRtMsg, kRfcDstLen>;
  QuadCircuit<Field> Q(p256_base);
  const CB cbk(&Q);
  const LC lc(&cbk, p256_base);
  H2C h2c(lc);

  uint8_t dst[kRfcDstLen];
  for (size_t i = 0; i < kRfcDstLen; ++i) dst[i] = kRfcDst[i];

  // Public outputs: Px, Py.
  typename LC::EltW px_in = lc.eltw_input();
  typename LC::EltW py_in = lc.eltw_input();
  Q.private_input();

  typename LC::v8 msgw[kRtMsg];
  for (size_t i = 0; i < kRtMsg; ++i) msgw[i] = lc.template vinput<8>();
  typename H2C::Witness w;
  w.input(lc);

  typename LC::EltW px, py;
  h2c.hash_to_curve(msgw, dst, w, px, py);
  lc.assert_eq(px, px_in);
  lc.assert_eq(py, py_in);

  auto CIRCUIT = Q.mkcircuit(1);
  dump_info("p256 hash_to_curve", Q);
  return CIRCUIT;
}

void fill_h2c_input(Dense<Field>& W, bool prover) {
  const Field& F = p256_base;
  auto h = host_h2c<kRtMsg>(kJ11[2].msg);  // "abcdef0123456789"
  DenseFiller<Field> filler(W);
  filler.push_back(F.one());  // constant-1 wire
  filler.push_back(h.px);
  filler.push_back(h.py);
  if (prover) {
    for (size_t i = 0; i < kRtMsg; ++i) {
      uint8_t b = static_cast<uint8_t>(kJ11[2].msg[i]);
      for (size_t k = 0; k < 8; ++k)
        filler.push_back((b >> k) & 1 ? F.one() : F.zero());
    }
    RtH2C::Witness::fill(filler, F, h);
  }
}

TEST(HashToCurve, ProverVerifierRoundTrip) {
  set_log_level(INFO);
  std::unique_ptr<Circuit<Field>> CIRCUIT = make_h2c_circuit();
  auto W = std::make_unique<Dense<Field>>(1, CIRCUIT->ninputs);
  fill_h2c_input(*W, /*prover=*/true);

  Proof<Field> pr(CIRCUIT->nl);
  run_prover<Field>(CIRCUIT.get(), W->clone(), &pr, p256_base);
  log(INFO, "Prover done");
  run_verifier<Field>(CIRCUIT.get(), std::move(W), pr, p256_base);
  log(INFO, "Verify done");
}

}  // namespace
}  // namespace proofs
