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

#include "circuits/ec2/scalar_mul.h"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>

#include "arrays/dense.h"
#include "circuits/compiler/circuit_dump.h"
#include "circuits/compiler/compiler.h"
#include "circuits/ec2/scalar_mul_witness.h"
#include "circuits/logic/compiler_backend.h"
#include "circuits/logic/evaluation_backend.h"
#include "circuits/logic/logic.h"
#include "ec/p256.h"
#include "sumcheck/circuit.h"
#include "sumcheck/testing.h"
#include "util/log.h"
#include "gtest/gtest.h"

namespace proofs {
namespace {

using Field = Fp256Base;
using Elt = Field::Elt;
using Nat = Fp256Nat;
using ECPoint = P256::ECPoint;

// ---- helpers --------------------------------------------------------------

// Affine point P (z = 1) from coordinates known to be on the curve.
static ECPoint affine(const Elt& x, const Elt& y) {
  return ECPoint(x, y, p256_base.one());
}

// Normalise a projective point to affine (z = 1).
static ECPoint to_affine(ECPoint p) {
  p256.normalize(p);
  return p;
}

// n - 1.
static Nat order_minus_1() {
  Nat r(n256_order);
  r.sub(Nat(1));
  return r;
}

// A fixed "random" scalar < n (just a representative non-trivial value).
static Nat random_scalar() {
  return Nat(
      "0x39a3e7b6f1c2d4e5a6b7c8d9e0f10213243546576879a0b1c2d3e4f506172839");
}

// A second fixed "random" scalar < n.
static Nat random_scalar2() {
  return Nat(
      "0x0123456789abcdeffedcba98765432100f1e2d3c4b5a69788796a5b4c3d2e1f0");
}

// ---------------------------------------------------------------------------
// Step 1 - host reference KAT: host trace [k]P == EC::scalar_multf(P, k).
// ---------------------------------------------------------------------------
static void host_kat(const ECPoint& P, const Nat& k) {
  const Field& F = p256_base;
  ScalarMulWitness<Field, P256> w;
  scalar_mul_witness<Field, P256>(F, p256, P, k, w);

  ECPoint expect = to_affine(p256.scalar_multf(P, k));

  if (expect.z == F.zero()) {
    // Reference says [k]P is the identity; host must agree (is_infinity).
    EXPECT_TRUE(w.is_infinity);
  } else {
    EXPECT_FALSE(w.is_infinity);
    EXPECT_TRUE(w.rx == expect.x);
    EXPECT_TRUE(w.ry == expect.y);
    EXPECT_TRUE(p256.is_on_curve(w.rx, w.ry));
  }
}

TEST(ScalarMulHost, MatchesScalarMultf) {
  ECPoint G = p256.generator();
  host_kat(G, Nat(1));               // [1]G == G
  host_kat(G, Nat(2));               // [2]G
  host_kat(G, order_minus_1());      // [n-1]G == -G
  host_kat(G, random_scalar());      // random k, P = G

  // Random on-curve P = [s]G, then [k]P.
  ECPoint P = to_affine(p256.scalar_multf(G, random_scalar2()));
  host_kat(P, random_scalar());
}

TEST(ScalarMulHost, NMinus1IsNegG) {
  const Field& F = p256_base;
  ECPoint G = p256.generator();
  ScalarMulWitness<Field, P256> w;
  scalar_mul_witness<Field, P256>(F, p256, G, order_minus_1(), w);
  // -G = (Gx, p - Gy).
  EXPECT_TRUE(w.rx == G.x);
  EXPECT_TRUE(w.ry == F.negf(G.y));
}

// ---------------------------------------------------------------------------
// Step 2 - EvaluationBackend KAT: gadget output == host, no assertion failure.
// ---------------------------------------------------------------------------
using EvalBackend = EvaluationBackend<Field>;
using EvalLC = Logic<Field, EvalBackend>;
using EvalGadget = VarBaseScalarMul<EvalLC, Field, P256>;

// Run the gadget on the EvaluationBackend; return (assertion_failed, Rx, Ry).
struct EvalResult {
  bool failed;
  Elt rx, ry;
};

static EvalResult run_eval(
    const ECPoint& P, const Nat& k,
    const std::function<void(ScalarMulWitness<Field, P256>&)>& mutate,
    bool panic_on_fail) {
  const Field& F = p256_base;
  const EvalBackend ebk(F, panic_on_fail);
  const EvalLC lc(&ebk, F);
  EvalGadget gadget(lc, p256, n256_order);

  ScalarMulWitness<Field, P256> h;
  scalar_mul_witness<Field, P256>(F, p256, P, k, h);
  mutate(h);

  typename EvalGadget::Witness w;
  w.set(lc, h);

  EvalLC::EltW Rx, Ry;
  gadget.mul(lc.konst(P.x), lc.konst(P.y), w, Rx, Ry);

  EvalResult r;
  // Decode the result wires back to field elements BEFORE reading (and
  // resetting) the assertion flag.
  r.rx = Rx.elt();
  r.ry = Ry.elt();
  r.failed = ebk.assertion_failed();
  return r;
}

static void eval_kat(const ECPoint& P, const Nat& k) {
  const Field& F = p256_base;
  ECPoint expect = to_affine(p256.scalar_multf(P, k));
  auto r = run_eval(P, k, [](auto&) {}, /*panic=*/true);
  EXPECT_FALSE(r.failed);
  EXPECT_TRUE(r.rx == expect.x);
  EXPECT_TRUE(r.ry == expect.y);
  (void)F;
}

TEST(ScalarMulEval, MatchesHostKAT) {
  ECPoint G = p256.generator();
  eval_kat(G, Nat(1));
  eval_kat(G, Nat(2));
  eval_kat(G, order_minus_1());
  eval_kat(G, random_scalar());

  ECPoint P = to_affine(p256.scalar_multf(G, random_scalar2()));
  eval_kat(P, random_scalar());
}

// ---------------------------------------------------------------------------
// Step 3 - adversarial / boundary tests (correct-or-fail-closed).
// ---------------------------------------------------------------------------

// k = 1: accumulator passes through identity at the first add -> correct P.
TEST(ScalarMulEval, KEqualsOne) {
  ECPoint G = p256.generator();
  auto r = run_eval(G, Nat(1), [](auto&) {}, true);
  EXPECT_FALSE(r.failed);
  EXPECT_TRUE(r.rx == G.x);
  EXPECT_TRUE(r.ry == G.y);
}

// k = n-1: correct -G == (Gx, p - Gy).
TEST(ScalarMulEval, KEqualsNMinus1) {
  const Field& F = p256_base;
  ECPoint G = p256.generator();
  auto r = run_eval(G, order_minus_1(), [](auto&) {}, true);
  EXPECT_FALSE(r.failed);
  EXPECT_TRUE(r.rx == G.x);
  EXPECT_TRUE(r.ry == F.negf(G.y));
}

// Identity result: [n]P over a small-order base. P256 is prime order, so we use
// a base of order 2 in the affine sense is impossible; instead we exercise the
// identity-RESULT path by forcing the gadget to compute [n]G is not allowed
// (k < n).  We instead test [k]P landing on identity via P + (-P) structure:
// choose k = n-1 on P, then separately verify the identity FAIL-CLOSED behavior
// by feeding a scalar/point pair whose product is the identity using k that is
// still < n is impossible for a prime-order curve except k = 0.  k = 0 -> [0]P
// is the identity; the gadget must FAIL CLOSED at affine-normalise (Z == 0).
TEST(ScalarMulEval, IdentityResultFailsClosed) {
  ECPoint G = p256.generator();
  // k = 0: [0]G is the point at infinity.  Host marks is_infinity; the gadget's
  // Z*zinv == 1 constraint is unsatisfiable -> fail closed (never wrong).
  const Field& F = p256_base;
  ScalarMulWitness<Field, P256> h;
  scalar_mul_witness<Field, P256>(F, p256, G, Nat(0), h);
  EXPECT_TRUE(h.is_infinity) << "host: [0]G should be identity";

  auto r = run_eval(G, Nat(0), [](auto&) {}, /*panic=*/false);
  EXPECT_TRUE(r.failed) << "identity result must fail closed at affine-norm";
}

// Non-canonical scalar: bits of (k + n) >= n must trip the < n range check.
// We build a "scalar" whose 256-bit pattern is >= n by setting it to n itself.
TEST(ScalarMulEval, NonCanonicalScalarRejected) {
  const Field& F = p256_base;
  ECPoint G = p256.generator();
  // Use k = n (== order).  Its 256-bit pattern is not < n, so the canonical
  // check must fail.  (The double-and-add still runs over the bit pattern.)
  Nat n(n256_order);
  auto r = run_eval(G, n, [](auto&) {}, /*panic=*/false);
  EXPECT_TRUE(r.failed) << "k == n must trip the canonical < n check";
  (void)F;
}

// Corrupt a scalar bit WIRE to a non-{0,1} value -> assert_is_bit must trip.
TEST(ScalarMulEval, BitWireNotBoolRejected) {
  const Field& F = p256_base;
  const EvalBackend ebk(F, /*panic=*/false);
  const EvalLC lc(&ebk, F);
  EvalGadget gadget(lc, p256, n256_order);
  ECPoint G = p256.generator();

  ScalarMulWitness<Field, P256> h;
  scalar_mul_witness<Field, P256>(F, p256, G, random_scalar(), h);
  typename EvalGadget::Witness w;
  w.set(lc, h);
  // Overwrite one bit wire with the field element 2 (not a bit).
  w.bits[100] = lc.konst(F.of_scalar(2));

  EvalLC::EltW Rx, Ry;
  gadget.mul(lc.konst(G.x), lc.konst(G.y), w, Rx, Ry);
  EXPECT_TRUE(ebk.assertion_failed()) << "non-bit scalar wire must trip";
}

// Wrong final zinv must trip the affine-normalisation / on-curve check.
TEST(ScalarMulEval, WrongZinvRejected) {
  ECPoint G = p256.generator();
  auto r = run_eval(
      G, random_scalar(),
      [](ScalarMulWitness<Field, P256>& h) {
        h.zinv = p256_base.addf(h.zinv, p256_base.one());
      },
      /*panic=*/false);
  EXPECT_TRUE(r.failed) << "wrong zinv must trip";
}

// Off-curve result: corrupt zinv such that (Rx,Ry) lands off curve is already
// covered by WrongZinvRejected (the on-curve check is the last guard).  Here we
// additionally confirm that an honest witness with a DIFFERENT base point still
// passes (sanity: gadget is genuinely variable-base).
TEST(ScalarMulEval, VariableBaseSanity) {
  ECPoint G = p256.generator();
  ECPoint P = to_affine(p256.scalar_multf(G, random_scalar2()));
  ECPoint expect = to_affine(p256.scalar_multf(P, random_scalar()));
  auto r = run_eval(P, random_scalar(), [](auto&) {}, true);
  EXPECT_FALSE(r.failed);
  EXPECT_TRUE(r.rx == expect.x);
  EXPECT_TRUE(r.ry == expect.y);
}

// ---------------------------------------------------------------------------
// Step 4 - compiled prove -> verify round-trip + cost (depth, wires).
// ---------------------------------------------------------------------------
using RtLC = Logic<Field, CompilerBackend<Field>>;
using RtGadget = VarBaseScalarMul<RtLC, Field, P256>;

static const Nat& rt_scalar() {
  static const Nat k = random_scalar();
  return k;
}
static ECPoint rt_base() { return p256.generator(); }

std::unique_ptr<Circuit<Field>> make_scalar_mul_circuit() {
  using CB = CompilerBackend<Field>;
  using LC = Logic<Field, CB>;
  using Gadget = VarBaseScalarMul<LC, Field, P256>;
  QuadCircuit<Field> Q(p256_base);
  const CB cbk(&Q);
  const LC lc(&cbk, p256_base);
  Gadget gadget(lc, p256, n256_order);

  // Public inputs: base point (Px, Py) and result (Rx, Ry).
  typename LC::EltW px_in = lc.eltw_input();
  typename LC::EltW py_in = lc.eltw_input();
  typename LC::EltW rx_in = lc.eltw_input();
  typename LC::EltW ry_in = lc.eltw_input();
  Q.private_input();

  typename Gadget::Witness w;
  w.input(lc);

  typename LC::EltW Rx, Ry;
  gadget.mul(px_in, py_in, w, Rx, Ry);
  lc.assert_eq(Rx, rx_in);
  lc.assert_eq(Ry, ry_in);

  auto CIRCUIT = Q.mkcircuit(1);
  dump_info("p256 var-base [k]P", Q);
  return CIRCUIT;
}

void fill_scalar_mul_input(Dense<Field>& W, bool prover) {
  const Field& F = p256_base;
  ECPoint P = rt_base();
  ScalarMulWitness<Field, P256> h;
  scalar_mul_witness<Field, P256>(F, p256, P, rt_scalar(), h);

  DenseFiller<Field> filler(W);
  filler.push_back(F.one());  // constant-1 wire
  filler.push_back(P.x);
  filler.push_back(P.y);
  filler.push_back(h.rx);
  filler.push_back(h.ry);
  if (prover) {
    RtGadget::Witness::fill(filler, F, h);
  }
}

TEST(ScalarMul, ProverVerifierRoundTrip) {
  set_log_level(INFO);
  std::unique_ptr<Circuit<Field>> CIRCUIT = make_scalar_mul_circuit();
  auto W = std::make_unique<Dense<Field>>(1, CIRCUIT->ninputs);
  fill_scalar_mul_input(*W, /*prover=*/true);

  Proof<Field> pr(CIRCUIT->nl);
  run_prover<Field>(CIRCUIT.get(), W->clone(), &pr, p256_base);
  log(INFO, "Prover done");
  run_verifier<Field>(CIRCUIT.get(), std::move(W), pr, p256_base);
  log(INFO, "Verify done");
}

}  // namespace
}  // namespace proofs
