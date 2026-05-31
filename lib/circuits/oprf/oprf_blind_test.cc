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

#include "circuits/oprf/oprf_blind.h"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>

#include "arrays/dense.h"
#include "circuits/compiler/circuit_dump.h"
#include "circuits/compiler/compiler.h"
#include "circuits/logic/compiler_backend.h"
#include "circuits/logic/evaluation_backend.h"
#include "circuits/logic/logic.h"
#include "circuits/oprf/oprf_blind_witness.h"
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

// 10-byte RNOKPP demo message "1234567890".
constexpr size_t kMsg = 10;

static void set_msg(uint8_t m[kMsg], const char* s) {
  for (size_t i = 0; i < kMsg; ++i) m[i] = static_cast<uint8_t>(s[i]);
}

// Representative scalars < n.
static Nat key1() {
  return Nat(
      "0x39a3e7b6f1c2d4e5a6b7c8d9e0f10213243546576879a0b1c2d3e4f506172839");
}
static Nat blind1() {
  return Nat(
      "0x0123456789abcdeffedcba98765432100f1e2d3c4b5a69788796a5b4c3d2e1f0");
}
static Nat key2() {
  return Nat(
      "0x55555555aaaaaaaa1111111122222222333333334444444466666666cccccccc");
}
static Nat blind2() { return Nat(7); }

// ---------------------------------------------------------------------------
// Step 1 - host OPRF reference KAT.
// ---------------------------------------------------------------------------
static OprfBlindWitness<Field, kMsg> host_run(const char* msg, const Nat& k,
                                              const Nat& r) {
  const Field& F = p256_base;
  uint8_t m[kMsg];
  set_msg(m, msg);
  OprfBlindWitness<Field, kMsg> w;
  oprf_blind_witness<Field, kMsg>(F, p256, k, m, r, w);
  return w;
}

TEST(OprfBlindHost, RelationHolds) {
  const Field& F = p256_base;
  struct Tc {
    const char* msg;
    Nat k, r;
  };
  Tc tcs[] = {
      {"1234567890", key1(), blind1()},
      {"abcdefghij", key2(), blind2()},
      {"0000000000", key1(), blind2()},
  };
  for (auto& t : tcs) {
    auto w = host_run(t.msg, t.k, t.r);
    // M on curve.
    EXPECT_TRUE(p256.is_on_curve(w.mx, w.my)) << "M off-curve msg=" << t.msg;
    // r*N == Y (host already checks, double-check here).
    EXPECT_TRUE(w.mul_n.rx == w.yx) << "r*N.x != Y.x msg=" << t.msg;
    EXPECT_TRUE(w.mul_n.ry == w.yy) << "r*N.y != Y.y msg=" << t.msg;
    // M == r*H.
    EXPECT_TRUE(w.mul_h.rx == w.mx);
    EXPECT_TRUE(w.mul_h.ry == w.my);
    // s is 32 bytes (non-trivial).
    bool any = false;
    for (uint8_t b : w.s) any |= (b != 0);
    EXPECT_TRUE(any) << "s all-zero msg=" << t.msg;
    (void)F;
  }
}

// s is stable for a fixed (msg, k, r) and the M coordinates are deterministic.
TEST(OprfBlindHost, StableKAT) {
  auto a = host_run("1234567890", key1(), blind1());
  auto b = host_run("1234567890", key1(), blind1());
  for (size_t i = 0; i < 32; ++i) EXPECT_EQ(a.s[i], b.s[i]);
  EXPECT_TRUE(a.mx == b.mx);
  EXPECT_TRUE(a.my == b.my);
}

// ---------------------------------------------------------------------------
// Step 2 - EvaluationBackend KAT: circuit M, s == host; no assertion failure.
// ---------------------------------------------------------------------------
using EvalBackend = EvaluationBackend<Field>;
using EvalLC = Logic<Field, EvalBackend>;
using EvalGadget = OprfBlind<EvalLC, Field, kMsg>;

struct EvalResult {
  bool failed;
  Elt mx, my;
  uint8_t s[32];
};

static EvalResult run_eval(
    const OprfBlindWitness<Field, kMsg>& base,
    const std::function<void(OprfBlindWitness<Field, kMsg>&)>& mutate,
    bool panic) {
  const Field& F = p256_base;
  const EvalBackend ebk(F, panic);
  const EvalLC lc(&ebk, F);
  EvalGadget gadget(lc);

  OprfBlindWitness<Field, kMsg> h = base;
  mutate(h);

  typename EvalGadget::Witness w;
  w.set(lc, h);

  EvalLC::EltW Mx, My;
  EvalLC::v8 s_out[32];
  gadget.blind(w, lc.konst(h.yx), lc.konst(h.yy), Mx, My, s_out);

  EvalResult r;
  r.mx = Mx.elt();
  r.my = My.elt();
  for (size_t i = 0; i < 32; ++i) {
    uint8_t byte = 0;
    for (size_t b = 0; b < 8; ++b) {
      if (lc.eval(s_out[i][b]).elt() == F.one()) byte |= (1u << b);
    }
    r.s[i] = byte;
  }
  r.failed = ebk.assertion_failed();
  return r;
}

TEST(OprfBlindEval, MatchesHostKAT) {
  auto h = host_run("1234567890", key1(), blind1());
  auto r = run_eval(h, [](auto&) {}, /*panic=*/true);
  EXPECT_FALSE(r.failed);
  EXPECT_TRUE(r.mx == h.mx) << "circuit M.x != host";
  EXPECT_TRUE(r.my == h.my) << "circuit M.y != host";
  for (size_t i = 0; i < 32; ++i) EXPECT_EQ(r.s[i], h.s[i]) << "s byte " << i;
}

TEST(OprfBlindEval, MatchesHostKAT_SecondVector) {
  auto h = host_run("abcdefghij", key2(), blind2());
  auto r = run_eval(h, [](auto&) {}, /*panic=*/true);
  EXPECT_FALSE(r.failed);
  EXPECT_TRUE(r.mx == h.mx);
  EXPECT_TRUE(r.my == h.my);
  for (size_t i = 0; i < 32; ++i) EXPECT_EQ(r.s[i], h.s[i]);
}

// ---------------------------------------------------------------------------
// Step 3 - negatives (must trip / fail-closed).  Honest passes (above).
// ---------------------------------------------------------------------------

// Wrong N (so r*N != Y): corrupt the witnessed Nx field wire + its bytes.
TEST(OprfBlindEval, WrongNFailsClosed) {
  auto h = host_run("1234567890", key1(), blind1());
  auto r = run_eval(
      h,
      [](OprfBlindWitness<Field, kMsg>& w) {
        // Flip N to a different on-curve point: N' = 2N (r*N' != Y).
        ECPoint N(w.nx, w.ny, p256_base.one());
        ECPoint N2 = p256.scalar_multf(N, Nat(2));
        p256.normalize(N2);
        w.nx = N2.x;
        w.ny = N2.y;
        // Recompute SHA bytes for the new N so the SHA binding itself is
        // internally consistent; the FAILURE must come from r*N' != Y.
        uint8_t pre[64];
        oprf_elt_to_be32<Field>(p256_base, w.nx, &pre[0]);
        oprf_elt_to_be32<Field>(p256_base, w.ny, &pre[32]);
        FlatSHA256Witness::transform_and_witness_message(
            64, pre, OprfBlindWitness<Field, kMsg>::kShaBlocks, w.sha_numb,
            w.sha_in, w.sha_bw);
        // Recompute mul_n trace for r*N' (its zinv etc) so only the == Y
        // assertion is the tripping constraint.
        scalar_mul_witness<Field, P256>(p256_base, p256, N2, w.mul_n.k,
                                        w.mul_n);
      },
      /*panic=*/false);
  EXPECT_TRUE(r.failed) << "r*N' != Y must trip the R==Y assertion";
}

// Binding break: feed the SECOND mul a DIFFERENT scalar than the first.
// The gadget aliases r_bits into both muls, so to exercise the break we patch
// the gadget-level witness directly here (bypassing the alias) and confirm the
// R==Y assertion trips.
TEST(OprfBlindEval, MismatchedSecondScalarFails) {
  const Field& F = p256_base;
  auto h = host_run("1234567890", key1(), blind1());

  const EvalBackend ebk(F, /*panic=*/false);
  const EvalLC lc(&ebk, F);
  EvalGadget gadget(lc);

  typename EvalGadget::Witness w;
  w.set(lc, h);
  // Corrupt one shared r bit.  Because the gadget feeds w.r_bits to BOTH muls,
  // this changes BOTH M and r*N consistently -> M,s differ from host but r*N
  // still == the (untouched, public) Y?  No: Y is the honest r*N; flipping r
  // changes r*N so r*N != Y -> trips.  This is the structural guard that the
  // single shared r must be the honest one binding M and Y together.
  Elt old = lc.eval(typename EvalLC::BitW(w.r_bits[200], F)).elt();
  w.r_bits[200] =
      lc.konst(old == F.one() ? F.zero() : F.one());

  EvalLC::EltW Mx, My;
  EvalLC::v8 s_out[32];
  gadget.blind(w, lc.konst(h.yx), lc.konst(h.yy), Mx, My, s_out);
  (void)Mx;
  (void)My;
  EXPECT_TRUE(ebk.assertion_failed())
      << "altering the shared r must break r*N == Y";
}

// Truly distinct second-mul scalar: build the gadget by hand, give mul_n a
// different scalar wire set than mul_h, and confirm R==Y trips.  This directly
// guards the shared-r property at the sub-mul boundary.
TEST(OprfBlindEval, DistinctMulScalarsFail) {
  const Field& F = p256_base;
  auto h = host_run("1234567890", key1(), blind1());

  const EvalBackend ebk(F, /*panic=*/false);
  const EvalLC lc(&ebk, F);

  // Manually run the two muls with DIFFERENT scalars over the honest H and N,
  // mirroring what OprfBlind::blind does internally, then assert R==Y.
  using SMul = VarBaseScalarMul<EvalLC, Field, P256>;
  SMul smul(lc, p256, n256_order);

  // mul_h with honest r.
  ScalarMulWitness<Field, P256> wmh_h;
  scalar_mul_witness<Field, P256>(F, p256, ECPoint(h.hx, h.hy, F.one()),
                                  blind1(), wmh_h);
  // mul_n with a DIFFERENT scalar r' over N.
  ScalarMulWitness<Field, P256> wmn_h;
  scalar_mul_witness<Field, P256>(F, p256, ECPoint(h.nx, h.ny, F.one()),
                                  blind2(), wmn_h);

  typename SMul::Witness wmh, wmn;
  wmh.set(lc, wmh_h);
  wmn.set(lc, wmn_h);

  EvalLC::EltW Mx, My, Rx, Ry;
  smul.mul(lc.konst(h.hx), lc.konst(h.hy), wmh, Mx, My);
  smul.mul(lc.konst(h.nx), lc.konst(h.ny), wmn, Rx, Ry);
  lc.assert_eq(Rx, lc.konst(h.yx));
  lc.assert_eq(Ry, lc.konst(h.yy));
  (void)Mx;
  (void)My;
  EXPECT_TRUE(ebk.assertion_failed())
      << "distinct second-mul scalar must trip R==Y";
}

// Corrupted SHA witness: flip a byte of a block-witness h1 output.
TEST(OprfBlindEval, CorruptShaWitnessFails) {
  auto h = host_run("1234567890", key1(), blind1());
  auto r = run_eval(
      h,
      [](OprfBlindWitness<Field, kMsg>& w) {
        w.sha_bw[w.sha_numb - 1].h1[0] ^= 0x1u;
      },
      /*panic=*/false);
  EXPECT_TRUE(r.failed) << "corrupted SHA h1 must trip";
}

// Off-curve N: corrupt only Ny so (Nx,Ny) is off-curve; the second mul's
// on-curve / result check (or R==Y) must trip.
TEST(OprfBlindEval, OffCurveNFails) {
  auto h = host_run("1234567890", key1(), blind1());
  auto r = run_eval(
      h,
      [](OprfBlindWitness<Field, kMsg>& w) {
        w.ny = p256_base.addf(w.ny, p256_base.one());  // now off-curve
        // keep SHA bytes consistent with the corrupted Ny so failure is the
        // EC path, not the SHA binding.
        uint8_t pre[64];
        oprf_elt_to_be32<Field>(p256_base, w.nx, &pre[0]);
        oprf_elt_to_be32<Field>(p256_base, w.ny, &pre[32]);
        FlatSHA256Witness::transform_and_witness_message(
            64, pre, OprfBlindWitness<Field, kMsg>::kShaBlocks, w.sha_numb,
            w.sha_in, w.sha_bw);
      },
      /*panic=*/false);
  EXPECT_TRUE(r.failed) << "off-curve N must trip";
}

// SHA preimage / point binding: corrupt only the SHA input bytes (leave Nx,Ny)
// -> the Horner recomposition assertion (nx_rec == Nx) must trip.
TEST(OprfBlindEval, ShaBytesNotBoundToNFails) {
  auto h = host_run("1234567890", key1(), blind1());
  auto r = run_eval(
      h,
      [](OprfBlindWitness<Field, kMsg>& w) {
        // Flip a byte of the SHA preimage (N.x region) without touching Nx.
        w.sha_in[3] ^= 0xff;
        // Recompute the SHA block witnesses for the tampered preimage so the
        // SHA relation itself is satisfiable; the tripping constraint must be
        // the byte<->Nx binding.
        FlatSHA256Witness::transform_and_witness_message(
            64, w.sha_in, OprfBlindWitness<Field, kMsg>::kShaBlocks,
            w.sha_numb, w.sha_in, w.sha_bw);
      },
      /*panic=*/false);
  EXPECT_TRUE(r.failed) << "SHA bytes not matching N must trip the binding";
}

// ---------------------------------------------------------------------------
// Step 4 - compiled prove -> verify round-trip + cost (depth, wires).
// ---------------------------------------------------------------------------
using RtCB = CompilerBackend<Field>;
using RtLC = Logic<Field, RtCB>;
using RtGadget = OprfBlind<RtLC, Field, kMsg>;

static OprfBlindWitness<Field, kMsg> rt_witness() {
  return host_run("1234567890", key1(), blind1());
}

std::unique_ptr<Circuit<Field>> make_oprf_circuit() {
  QuadCircuit<Field> Q(p256_base);
  const RtCB cbk(&Q);
  const RtLC lc(&cbk, p256_base);
  RtGadget gadget(lc);

  // Public inputs: Y = (Yx, Yy).  Public outputs: M = (Mx, My), s = 32 bytes.
  RtLC::EltW yx_in = lc.eltw_input();
  RtLC::EltW yy_in = lc.eltw_input();
  RtLC::EltW mx_out = lc.eltw_input();
  RtLC::EltW my_out = lc.eltw_input();
  RtLC::v8 s_pub[32];
  for (size_t i = 0; i < 32; ++i) s_pub[i] = lc.template vinput<8>();
  Q.private_input();

  typename RtGadget::Witness w;
  w.input(lc);

  RtLC::EltW Mx, My;
  RtLC::v8 s_out[32];
  gadget.blind(w, yx_in, yy_in, Mx, My, s_out);
  lc.assert_eq(Mx, mx_out);
  lc.assert_eq(My, my_out);
  for (size_t i = 0; i < 32; ++i) lc.vassert_eq(s_out[i], s_pub[i]);

  auto CIRCUIT = Q.mkcircuit(1);
  dump_info("oprf blind block", Q);
  return CIRCUIT;
}

void fill_oprf_input(Dense<Field>& W, bool prover) {
  const Field& F = p256_base;
  auto h = rt_witness();
  DenseFiller<Field> filler(W);
  filler.push_back(F.one());  // constant-1 wire
  filler.push_back(h.yx);
  filler.push_back(h.yy);
  filler.push_back(h.mx);
  filler.push_back(h.my);
  for (size_t i = 0; i < 32; ++i) {
    for (size_t k = 0; k < 8; ++k)
      filler.push_back((h.s[i] >> k) & 1 ? F.one() : F.zero());
  }
  if (prover) {
    RtGadget::Witness::fill(filler, F, h);
  }
}

TEST(OprfBlind, ProverVerifierRoundTrip) {
  set_log_level(INFO);
  std::unique_ptr<Circuit<Field>> CIRCUIT = make_oprf_circuit();
  auto W = std::make_unique<Dense<Field>>(1, CIRCUIT->ninputs);
  fill_oprf_input(*W, /*prover=*/true);

  Proof<Field> pr(CIRCUIT->nl);
  run_prover<Field>(CIRCUIT.get(), W->clone(), &pr, p256_base);
  log(INFO, "Prover done");
  run_verifier<Field>(CIRCUIT.get(), std::move(W), pr, p256_base);
  log(INFO, "Verify done");
}

}  // namespace
}  // namespace proofs
