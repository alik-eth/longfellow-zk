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
#include <functional>
#include <memory>
#include <utility>

#include "algebra/static_string.h"
#include "arrays/dense.h"
#include "circuits/compiler/circuit_dump.h"
#include "circuits/compiler/compiler.h"
#include "circuits/hash2curve/p256_sswu.h"
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

// RFC 9380 Appendix J.1.1, suite P256_XMD:SHA-256_SSWU_RO_
// (dst = QUUX-V01-CS02-with-P256_XMD:SHA-256_SSWU_RO_).
// We test map_to_curve_simple_swu(u[i]) == Qi for messages "", "abc",
// "abcdef0123456789".  These are the intermediate map outputs Q0/Q1, which
// is exactly what this gadget computes (hash_to_field and the point add are
// out of scope for this primitive).
struct sswu_vec {
  StaticString u;
  StaticString qx, qy;
};

static const sswu_vec RFC9380_J11[] = {
    // msg = ""
    {StaticString("0xad5342c66a6dd0ff080df1da0ea1c04b96e0330dd89406465eeba1158251"
                  "5009"),
     StaticString("0xab640a12220d3ff283510ff3f4b1953d09fad35795140b1c5d64f313967"
                  "934d5"),
     StaticString("0xdccb558863804a881d4fff3455716c836cef230e5209594ddd33d85c565"
                  "b19b1")},
    {StaticString("0x8c0f1d43204bd6f6ea70ae8013070a1518b43873bcd850aafa0a9e220e2"
                  "eea5a"),
     StaticString("0x51cce63c50d972a6e51c61334f0f4875c9ac1cd2d3238412f84e31da7d9"
                  "80ef5"),
     StaticString("0xb45d1a36d00ad90e5ec7840a60a4de411917fbe7c82c3949a6e699e5a1b"
                  "66aac")},
    // msg = "abc"
    {StaticString("0xafe47f2ea2b10465cc26ac403194dfb68b7f5ee865cda61e9f3e07a5372"
                  "20af1"),
     StaticString("0x5219ad0ddef3cc49b714145e91b2f7de6ce0a7a7dc7406c7726c7e373c5"
                  "8cb48"),
     StaticString("0x7950144e52d30acbec7b624c203b1996c99617d0b61c2442354301b191d"
                  "93ecf")},
    {StaticString("0x379a27833b0bfe6f7bdca08e1e83c760bf9a338ab335542704edcd69ce9"
                  "e46e0"),
     StaticString("0x019b7cb4efcfeaf39f738fe638e31d375ad6837f58a852d032ff60c69ee"
                  "3875f"),
     StaticString("0x589a62d2b22357fed5449bc38065b760095ebe6aeac84b01156ee425271"
                  "5446e")},
    // msg = "abcdef0123456789"
    {StaticString("0x0fad9d125a9477d55cf9357105b0eb3a5c4259809bf87180aa01d651f53"
                  "d312c"),
     StaticString("0xa17bdf2965eb88074bc01157e644ed409dac97cfcf0c61c998ed0fa45e7"
                  "9e4a2"),
     StaticString("0x4f1bc80c70d411a3cc1d67aeae6e726f0f311639fee560c7f5a664554e3"
                  "c9c2e")},
    {StaticString("0xb68597377392cd3419d8fcc7d7660948c8403b19ea78bbca4b133c9d219"
                  "6c0fb"),
     StaticString("0x7da48bb67225c1a17d452c983798113f47e438e4202219dd0715f8419b2"
                  "74d66"),
     StaticString("0xb765696b2913e36db3016c47edb99e24b1da30e761a8a3215dc0ec4d8f9"
                  "6e6f9")},
};

constexpr size_t kNumVec = sizeof(RFC9380_J11) / sizeof(RFC9380_J11[0]);

// ---------------------------------------------------------------------------
// 1) Host reference KATs vs RFC vectors.
// ---------------------------------------------------------------------------
TEST(P256Sswu, HostReferenceMatchesRfc9380) {
  const Field& F = p256_base;
  P256SswuReference<Field> ref(F);

  for (size_t i = 0; i < kNumVec; ++i) {
    Elt u = F.of_string(RFC9380_J11[i].u);
    Elt qx = F.of_string(RFC9380_J11[i].qx);
    Elt qy = F.of_string(RFC9380_J11[i].qy);

    auto h = ref.map(u);
    EXPECT_TRUE(h.x == qx) << "x mismatch at vector " << i;
    EXPECT_TRUE(h.y == qy) << "y mismatch at vector " << i;
    EXPECT_TRUE(p256.is_on_curve(h.x, h.y)) << "off-curve at vector " << i;
  }
}

// ---------------------------------------------------------------------------
// 2) In-circuit gadget KATs vs RFC vectors (EvaluationBackend).
// ---------------------------------------------------------------------------
TEST(P256Sswu, EvaluationBackendMatchesRfc9380) {
  using EvalBackend = EvaluationBackend<Field>;
  using LogicCircuit = Logic<Field, EvalBackend>;
  using Gadget = P256SswuCircuit<LogicCircuit, Field>;

  const Field& F = p256_base;
  const EvalBackend ebk(F);
  const LogicCircuit lc(&ebk, F);
  P256SswuReference<Field> ref(F);
  Gadget g(lc);

  for (size_t i = 0; i < kNumVec; ++i) {
    Elt u = F.of_string(RFC9380_J11[i].u);
    Elt qx = F.of_string(RFC9380_J11[i].qx);
    Elt qy = F.of_string(RFC9380_J11[i].qy);

    auto h = ref.map(u);
    typename Gadget::Witness w;
    w.set(lc, h);

    typename LogicCircuit::EltW x, y;
    g.map_to_curve(lc.konst(u), x, y, w);

    EXPECT_FALSE(ebk.assertion_failed()) << "assertion failed at vector " << i;
    EXPECT_TRUE(x == lc.konst(qx)) << "circuit x mismatch at vector " << i;
    EXPECT_TRUE(y == lc.konst(qy)) << "circuit y mismatch at vector " << i;
  }
}

// ---------------------------------------------------------------------------
// 3) Negative tests: corrupting any hint must trip assertion_failed().
// ---------------------------------------------------------------------------
TEST(P256Sswu, NegativeTestsTripAssertion) {
  using EvalBackend = EvaluationBackend<Field>;
  using LogicCircuit = Logic<Field, EvalBackend>;
  using Gadget = P256SswuCircuit<LogicCircuit, Field>;

  const Field& F = p256_base;
  // panic_on_assertion_failure_ = false so we can read assertion_failed().
  const EvalBackend ebk(F, false);
  const LogicCircuit lc(&ebk, F);
  P256SswuReference<Field> ref(F);
  Gadget g(lc);

  Elt u = F.of_string(RFC9380_J11[0].u);
  auto good = ref.map(u);

  auto run = [&](const typename P256SswuReference<Field>::Hints& h) -> bool {
    typename Gadget::Witness w;
    w.set(lc, h);
    typename LogicCircuit::EltW x, y;
    g.map_to_curve(lc.konst(u), x, y, w);
    return ebk.assertion_failed();
  };

  // Run with a witness mutated after set() (to corrupt bit decompositions).
  auto run_mut =
      [&](const std::function<void(typename Gadget::Witness&)>& mutate)
      -> bool {
    typename Gadget::Witness w;
    w.set(lc, good);
    mutate(w);
    typename LogicCircuit::EltW x, y;
    g.map_to_curve(lc.konst(u), x, y, w);
    return ebk.assertion_failed();
  };

  // (sanity) the good witness must NOT trip.
  EXPECT_FALSE(run(good));

  // wrong sqrt (y_candidate)
  {
    auto h = good;
    h.y_candidate = F.addf(h.y_candidate, F.one());
    EXPECT_TRUE(run(h)) << "wrong sqrt not caught";
  }
  // wrong branch bit e1
  {
    auto h = good;
    h.e1 = !h.e1;
    EXPECT_TRUE(run(h)) << "wrong branch bit not caught";
  }
  // wrong inv0 (den_inv)
  {
    auto h = good;
    h.den_inv = F.addf(h.den_inv, F.one());
    EXPECT_TRUE(run(h)) << "wrong inv0 not caught";
  }
  // corrupt the is_square sqrt witness w1
  {
    auto h = good;
    h.w1 = F.addf(h.w1, F.one());
    EXPECT_TRUE(run(h)) << "wrong is_square witness not caught";
  }
  // Flip the sgn0 bit (u_bits[0]): lying about the parity must trip an
  // assertion (the bit-decomposition reconstruction no longer equals u, or
  // the resulting y is the wrong sign and fails the on-curve sign check).
  {
    EXPECT_TRUE(run_mut([&](typename Gadget::Witness& w) {
      w.u_bits[0] = lc.lnot(w.u_bits[0]);
    })) << "flipped sgn0(u) bit not caught";
  }
  // Corrupt a high bit of the y decomposition: must break the reconstruction
  // pin assertion (recon != y_candidate).
  {
    EXPECT_TRUE(run_mut([&](typename Gadget::Witness& w) {
      w.y_bits[40] = lc.lnot(w.y_bits[40]);
    })) << "corrupted y bit decomposition not caught";
  }
}

// ---------------------------------------------------------------------------
// 3b) Adversarial canonical-range test: a non-canonical alias (value + p) of
//     a sgn0-feeding decomposition has the SAME field element but a flipped
//     bit[0] (since p is odd).  The < p range check must reject it.
// ---------------------------------------------------------------------------
TEST(P256Sswu, NonCanonicalSgn0AliasRejected) {
  using Nat = Field::N;
  using EvalBackend = EvaluationBackend<Field>;
  using LogicCircuit = Logic<Field, EvalBackend>;
  using Gadget = P256SswuCircuit<LogicCircuit, Field>;
  using BitW = LogicCircuit::BitW;

  const Field& F = p256_base;
  const EvalBackend ebk(F, false);  // do not panic; read assertion_failed()
  const LogicCircuit lc(&ebk, F);
  Gadget g(lc);

  const Nat p(
      "0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff");

  // For an element with a small canonical integer `value`, the only other
  // 256-bit integer congruent to it mod p is value + p (value + 2p overflows
  // 256 bits).  This alias is >= p and, since p is odd, has the opposite
  // bit[0] -- exactly the sgn0-forgery the range check must block.
  //
  // Drive decompose_and_pin() directly: the checked element `v` is fixed to
  // the canonical small value, and we feed it the alias bits.  recon == v
  // still holds in-field (alias reduces to value), so ONLY the < p check can
  // reject it.
  auto run_bits = [&](uint64_t value, bool use_alias) -> bool {
    Nat n(value);
    if (use_alias) n.add(p);  // value + p (>= p, fits in 256 bits)
    Elt v = F.of_scalar(value);
    BitW bits[256];
    for (size_t k = 0; k < 256; ++k) bits[k] = lc.bit(n.bit(k) & 1);
    (void)g.decompose_and_pin(lc.konst(v), bits);
    return ebk.assertion_failed();
  };

  // Honest canonical decompositions must pass (both parities).
  EXPECT_FALSE(run_bits(4u, /*use_alias=*/false)) << "honest even value tripped";
  EXPECT_FALSE(run_bits(7u, /*use_alias=*/false)) << "honest odd value tripped";

  // Sanity: value + p flips bit[0] for both parities.
  {
    Nat a(4u);
    a.add(p);
    EXPECT_NE(a.bit(0) & 1, Nat(4u).bit(0) & 1);
  }

  // The non-canonical aliases (same field element, flipped sgn0) must be
  // rejected by the < p range check.
  EXPECT_TRUE(run_bits(4u, /*use_alias=*/true))
      << "non-canonical alias of even value not rejected";
  EXPECT_TRUE(run_bits(7u, /*use_alias=*/true))
      << "non-canonical alias of odd value not rejected";
}

// ---------------------------------------------------------------------------
// 4) One full compiled prove -> verify round-trip, public (x, y).
// ---------------------------------------------------------------------------
std::unique_ptr<Circuit<Field>> make_circuit() {
  using CompilerBackend = CompilerBackend<Field>;
  using LogicCircuit = Logic<Field, CompilerBackend>;
  using Gadget = P256SswuCircuit<LogicCircuit, Field>;
  using EltW = LogicCircuit::EltW;

  QuadCircuit<Field> Q(p256_base);
  const CompilerBackend cbk(&Q);
  const LogicCircuit lc(&cbk, p256_base);
  Gadget g(lc);

  EltW u = lc.eltw_input();   // public input: u
  EltW x = lc.eltw_input();   // public input: expected x
  EltW y = lc.eltw_input();   // public input: expected y
  Q.private_input();

  typename Gadget::Witness w;
  w.input(lc);

  EltW cx, cy;
  g.map_to_curve(u, cx, cy, w);
  lc.assert_eq(cx, x);
  lc.assert_eq(cy, y);

  auto CIRCUIT = Q.mkcircuit(1);
  dump_info("p256 sswu map_to_curve", Q);
  return CIRCUIT;
}

void fill_input(Dense<Field>& W, bool prover) {
  const Field& F = p256_base;
  P256SswuReference<Field> ref(F);

  Elt u = F.of_string(RFC9380_J11[0].u);
  auto h = ref.map(u);

  DenseFiller<Field> filler(W);
  filler.push_back(F.one());  // constant-1 wire
  filler.push_back(u);
  filler.push_back(h.x);
  filler.push_back(h.y);
  if (prover) {
    P256SswuCircuit<Logic<Field, CompilerBackend<Field>>, Field>::Witness::fill(
        filler, F, h);
  }
}

TEST(P256Sswu, ProverVerifierRoundTrip) {
  set_log_level(INFO);
  std::unique_ptr<Circuit<Field>> CIRCUIT = make_circuit();

  auto W = std::make_unique<Dense<Field>>(1, CIRCUIT->ninputs);
  fill_input(*W, /*prover=*/true);

  Proof<Field> pr(CIRCUIT->nl);
  run_prover<Field>(CIRCUIT.get(), W->clone(), &pr, p256_base);
  log(INFO, "Prover done");
  run_verifier<Field>(CIRCUIT.get(), std::move(W), pr, p256_base);
  log(INFO, "Verify done");
}

}  // namespace
}  // namespace proofs
