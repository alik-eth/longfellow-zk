// Copyright 2026 zk-eidas contributors
// Licensed under the Apache License, Version 2.0

#include "circuits/mdoc/predicate_gadgets.h"

#include <stddef.h>
#include <stdint.h>

#include "algebra/fp.h"
#include "circuits/compiler/circuit_dump.h"
#include "circuits/compiler/compiler.h"
#include "circuits/logic/compiler_backend.h"
#include "circuits/logic/evaluation_backend.h"
#include "circuits/logic/logic.h"
#include "gtest/gtest.h"

namespace proofs {
namespace {

using Field = Fp<4, true>;
const Field F("18446744073709551557");

// ---------------------------------------------------------------------------
// Evaluation tests (actually run the circuit logic with concrete values)
// ---------------------------------------------------------------------------

using EvalBackend = EvaluationBackend<Field>;
using EvalLogic = Logic<Field, EvalBackend>;

// Helper: make a 4-byte big-endian v8 array from a uint32_t
void fill_v8_be(const EvalLogic& L, EvalLogic::v8 out[], size_t n,
                uint64_t val) {
  for (size_t i = 0; i < n; i++) {
    out[i] = L.vbit<8>((val >> (8 * (n - 1 - i))) & 0xFF);
  }
}

TEST(PredicateGadgets, GtePass) {
  const EvalBackend ebk(F);
  const EvalLogic L(&ebk, F);
  const PredicateGadgets<EvalLogic> P(L);

  constexpr size_t n = 4;
  EvalLogic::v8 claim[n], threshold[n];

  // 100 >= 50 — should not throw
  fill_v8_be(L, claim, n, 100);
  fill_v8_be(L, threshold, n, 50);
  EXPECT_NO_FATAL_FAILURE(P.assert_gte(n, claim, threshold));

  // 50 >= 50 — equality, should pass
  fill_v8_be(L, claim, n, 50);
  fill_v8_be(L, threshold, n, 50);
  EXPECT_NO_FATAL_FAILURE(P.assert_gte(n, claim, threshold));
}

TEST(PredicateGadgets, LtePass) {
  const EvalBackend ebk(F);
  const EvalLogic L(&ebk, F);
  const PredicateGadgets<EvalLogic> P(L);

  constexpr size_t n = 4;
  EvalLogic::v8 claim[n], threshold[n];

  // 30 <= 50
  fill_v8_be(L, claim, n, 30);
  fill_v8_be(L, threshold, n, 50);
  EXPECT_NO_FATAL_FAILURE(P.assert_lte(n, claim, threshold));
}

TEST(PredicateGadgets, EqPass) {
  const EvalBackend ebk(F);
  const EvalLogic L(&ebk, F);
  const PredicateGadgets<EvalLogic> P(L);

  constexpr size_t n = 4;
  EvalLogic::v8 claim[n], expected[n];

  fill_v8_be(L, claim, n, 42);
  fill_v8_be(L, expected, n, 42);
  EXPECT_NO_FATAL_FAILURE(P.assert_eq(n, claim, expected));
}

TEST(PredicateGadgets, NeqPass) {
  const EvalBackend ebk(F);
  const EvalLogic L(&ebk, F);
  const PredicateGadgets<EvalLogic> P(L);

  constexpr size_t n = 4;
  EvalLogic::v8 claim[n], expected[n];

  // 42 != 99
  fill_v8_be(L, claim, n, 42);
  fill_v8_be(L, expected, n, 99);
  EXPECT_NO_FATAL_FAILURE(P.assert_neq(n, claim, expected));
}

TEST(PredicateGadgets, RangePass) {
  const EvalBackend ebk(F);
  const EvalLogic L(&ebk, F);
  const PredicateGadgets<EvalLogic> P(L);

  constexpr size_t n = 4;
  EvalLogic::v8 claim[n], low[n], high[n];

  // 25 in [18, 65]
  fill_v8_be(L, claim, n, 25);
  fill_v8_be(L, low, n, 18);
  fill_v8_be(L, high, n, 65);
  EXPECT_NO_FATAL_FAILURE(P.assert_range(n, claim, low, high));
}

// ---------------------------------------------------------------------------
// Compiler test (verify circuit structure compiles)
// ---------------------------------------------------------------------------

TEST(PredicateGadgets, CircuitCompiles) {
  using CBackend = CompilerBackend<Field>;
  using CLogic = Logic<Field, CBackend>;

  QuadCircuit<Field> Q(F);
  const CBackend cbk(&Q);
  const CLogic LC(&cbk, F);
  const PredicateGadgets<CLogic> P(LC);

  constexpr size_t n = 8;  // 8 bytes = 64 bits

  // Public inputs: threshold
  CLogic::v8 threshold[n];
  for (size_t i = 0; i < n; i++) threshold[i] = LC.vinput<8>();

  Q.private_input();

  // Private input: claim
  CLogic::v8 claim[n];
  for (size_t i = 0; i < n; i++) claim[i] = LC.vinput<8>();

  P.assert_gte(n, claim, threshold);

  auto CIRCUIT = Q.mkcircuit(1);
  EXPECT_NE(CIRCUIT, nullptr);
  dump_info<Field>("predicate_gte_8byte", Q);
}

}  // namespace
}  // namespace proofs
