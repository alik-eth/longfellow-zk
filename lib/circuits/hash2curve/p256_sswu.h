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

#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_HASH2CURVE_P256_SSWU_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_HASH2CURVE_P256_SSWU_H_

#include <cstddef>

#include "arrays/dense.h"
#include "circuits/hash2curve/p256_sswu_witness.h"

/*
In-circuit gadget for the RFC 9380 simplified SWU map for suite
P256_XMD:SHA-256_SSWU_RO_ (RFC 9380 sections 6.6.2 and 8.2):

  map_to_curve_simple_swu(u) -> (x, y) on y^2 = x^3 + A*x + B,
  A = -3, B = 0x5ac6..604b, Z = -10, cofactor 1.

Strategy (no inversion / sqrt in-circuit; witnessed hints + assertions),
mirroring the proven Noir SvdW gadget in
packages/oprf/v3-grumpkin/circuits/oprf_commitment/src/main.nr:

  inv0:   witness den_inv and a selector den_is_zero in {0,1}.
          den = Z^2 u^4 + Z u^2.
          Assert  den * den_inv = 1 - den_is_zero  and  den_is_zero * den = 0
          and     den_is_zero * den_inv = 0.
          This pins den_inv = inverse(den) when den != 0 and den_inv = 0 when
          den = 0 (inv0 semantics).
  branch: witness e1 in {0,1} and w1.  With Z a fixed non-residue:
          assert  e1*(w1^2 - gx1) + (1-e1)*(w1^2 - gx1*Z) = 0.
          (same shape as Noir assert_is_square)
          Select x = mux(e1, x1, x2), gx = mux(e1, gx1, gx2).
  sqrt:   witness y_candidate; assert y_candidate^2 = gx_selected.
  sgn0:   witness little-endian bit decompositions of u and y_candidate;
          assert each is a bit and reconstructs the element; sgn0 = bit[0].
          Fix the sign: y = mux(sgn0(u) == sgn0(y_candidate), y_candidate,
          -y_candidate).
  final:  is_on_curve(x, y) via y^2 == x^3 + A*x + B.
*/
namespace proofs {

template <class LogicCircuit, class Field>
class P256SswuCircuit {
  using EltW = typename LogicCircuit::EltW;
  using BitW = typename LogicCircuit::BitW;
  using Elt = typename LogicCircuit::Elt;
  using Nat = typename Field::N;
  using Ref = P256SswuReference<Field>;
  static constexpr size_t kBits = 256;

 public:
  struct Witness {
    EltW den_inv;
    BitW den_is_zero;
    BitW e1;
    EltW w1;
    EltW y_candidate;
    BitW u_bits[kBits];
    BitW y_bits[kBits];

    // Wire the witness from circuit inputs (CompilerBackend path).
    void input(const LogicCircuit& lc) {
      den_inv = lc.eltw_input();
      den_is_zero = lc.input();
      e1 = lc.input();
      w1 = lc.eltw_input();
      y_candidate = lc.eltw_input();
      for (size_t i = 0; i < kBits; ++i) u_bits[i] = lc.input();
      for (size_t i = 0; i < kBits; ++i) y_bits[i] = lc.input();
    }

    // Set the witness from host hints (EvaluationBackend path).
    void set(const LogicCircuit& lc, const typename Ref::Hints& h) {
      const Field& F = lc.f_;
      den_inv = lc.konst(h.den_inv);
      den_is_zero = bit_of(lc, h.den_is_zero);
      e1 = bit_of(lc, h.e1);
      w1 = lc.konst(h.w1);
      y_candidate = lc.konst(h.y_candidate);
      Nat un = F.from_montgomery(h.u_elt);
      Nat yn = F.from_montgomery(h.y_candidate);
      for (size_t i = 0; i < kBits; ++i) {
        u_bits[i] = lc.bit(un.bit(i) & 1);
        y_bits[i] = lc.bit(yn.bit(i) & 1);
      }
    }

    // Push witness values (CompilerBackend round-trip).
    static void fill(DenseFiller<Field>& filler, const Field& F,
                     const typename Ref::Hints& h) {
      filler.push_back(h.den_inv);
      filler.push_back(h.den_is_zero ? F.one() : F.zero());
      filler.push_back(h.e1 ? F.one() : F.zero());
      filler.push_back(h.w1);
      filler.push_back(h.y_candidate);
      Nat un = F.from_montgomery(h.u_elt);
      Nat yn = F.from_montgomery(h.y_candidate);
      for (size_t i = 0; i < kBits; ++i) {
        filler.push_back(((un.bit(i) & 1) ? F.one() : F.zero()));
      }
      for (size_t i = 0; i < kBits; ++i) {
        filler.push_back(((yn.bit(i) & 1) ? F.one() : F.zero()));
      }
    }

   private:
    static BitW bit_of(const LogicCircuit& lc, bool b) {
      return lc.bit(b ? 1 : 0);
    }
  };

  explicit P256SswuCircuit(const LogicCircuit& lc)
      : lc_(lc),
        ref_(lc.f_),
        a_(ref_.A()),
        b_(ref_.B()),
        z_(ref_.Z()),
        znr_(ref_.Znr()) {
    const Field& F = lc.f_;
    minusB_over_A_ = F.mulf(F.negf(b_), F.invertf(a_));  // -B/A
    B_over_ZA_ = F.mulf(b_, F.invertf(F.mulf(z_, a_)));  // B/(Z*A)
    // Precompute 2^i as field elements (F.beta() only supports i < 64).
    Elt p = F.one();
    for (size_t i = 0; i < kBits; ++i) {
      pow2_[i] = p;
      p = F.addf(p, p);
    }
    // Little-endian bits of the field modulus, for the canonical-range
    // (value < p) check on the sgn0 bit decompositions.  p =
    // 2^256 - 2^224 + 2^192 + 2^96 - 1 (Fp256Base).
    Nat modulus(
        "0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff");
    for (size_t i = 0; i < kBits; ++i) {
      mod_bits_[i] = lc.bit(modulus.bit(i) & 1);
    }
  }

  // g(x) = x^3 + A*x + B in-circuit.
  EltW g(const EltW& x) const {
    EltW x2 = lc_.mul(x, x);
    EltW x3 = lc_.mul(x2, x);
    EltW ax = lc_.mul(a_, x);
    return lc_.add(lc_.add(x3, ax), lc_.konst(b_));
  }

  void map_to_curve(const EltW& u, EltW& x_out, EltW& y_out,
                    const Witness& w) const {
    const Field& F = lc_.f_;
    EltW one = lc_.konst(F.one());

    // den = Z^2 u^4 + Z u^2 = (Z u^2) + (Z u^2)^2
    EltW u2 = lc_.mul(u, u);
    EltW zu2 = lc_.mul(z_, u2);
    EltW z2u4 = lc_.mul(zu2, zu2);
    EltW den = lc_.add(z2u4, zu2);

    // inv0 constraints: pin den_inv = inverse(den) when den != 0, else 0.
    EltW is_zero = lc_.eval(w.den_is_zero);  // in {0,1}
    lc_.assert_is_bit(w.den_is_zero);
    // den * den_inv == 1 - is_zero
    lc_.assert_eq(lc_.mul(den, w.den_inv), lc_.sub(one, is_zero));
    // is_zero * den == 0  (if selector says zero, den must be zero)
    lc_.assert0(lc_.mul(is_zero, den));
    // is_zero * den_inv == 0  (inv0(0) = 0)
    lc_.assert0(lc_.mul(is_zero, w.den_inv));

    // tv1 = den_inv (= inv0(den))
    EltW tv1 = w.den_inv;

    // x1 = (-B/A) * (1 + tv1), corrected to B/(Z*A) when tv1 == 0.
    EltW x1_generic = lc_.mul(minusB_over_A_, lc_.add(one, tv1));
    // mux on den_is_zero: when den==0, tv1==0 and x1 = B/(Z*A).
    EltW x1 = lc_.mux(w.den_is_zero, lc_.konst(B_over_ZA_), x1_generic);

    EltW gx1 = g(x1);

    // x2 = Z u^2 x1
    EltW x2 = lc_.mul(zu2, x1);
    EltW gx2 = g(x2);

    // is_square branch: assert e1*(w1^2 - gx1) + (1-e1)*(w1^2 - gx1*Znr) == 0
    lc_.assert_is_bit(w.e1);
    EltW w1sq = lc_.mul(w.w1, w.w1);
    EltW e1f = lc_.eval(w.e1);
    EltW term_sq = lc_.sub(w1sq, gx1);                       // w1^2 - gx1
    EltW term_nr = lc_.sub(w1sq, lc_.mul(znr_, gx1));        // w1^2 - gx1*Znr
    EltW branch = lc_.add(lc_.mul(e1f, term_sq),
                          lc_.mul(lc_.sub(one, e1f), term_nr));
    lc_.assert0(branch);

    // select x and gx according to e1 (e1 == 1 -> use x1)
    EltW x = lc_.mux(w.e1, x1, x2);
    EltW gx = lc_.mux(w.e1, gx1, gx2);

    // sqrt: y_candidate^2 == gx
    lc_.assert_eq(lc_.mul(w.y_candidate, w.y_candidate), gx);

    // sgn0 via witnessed bit decomposition; reconstruct & pin to element.
    BitW sgn0_u = decompose_and_pin(u, w.u_bits);
    BitW sgn0_y = decompose_and_pin(w.y_candidate, w.y_bits);

    // sign fix: y = (sgn0(u) == sgn0(y)) ? y_candidate : -y_candidate
    BitW same = lc_.lnot(lc_.lxor(sgn0_u, sgn0_y));
    EltW neg_y = lc_.sub(lc_.konst(F.zero()), w.y_candidate);
    EltW y = lc_.mux(same, w.y_candidate, neg_y);

    // final on-curve check: y^2 == x^3 + A x + B
    lc_.assert_eq(lc_.mul(y, y), g(x));

    x_out = x;
    y_out = y;
  }

  // Assert each bit is a bit, reconstruct sum b[i] 2^i, assert it equals v,
  // assert the 256-bit value is < p (canonical), and return bit[0] (sgn0).
  // Public so the canonical-range defense can be exercised in isolation.
  BitW decompose_and_pin(const EltW& v, const BitW bits[kBits]) const {
    // recon = sum_i bit[i] * 2^i, using precomputed power-of-two constants
    // (Logic::as_scalar relies on F.beta(), which only supports i < 64).
    typename LogicCircuit::template bitvec<kBits> bv;
    EltW recon = lc_.konst(lc_.f_.zero());
    for (size_t i = 0; i < kBits; ++i) {
      lc_.assert_is_bit(bits[i]);
      bv[i] = bits[i];
      // bit[i] as a field wire times 2^i, accumulated.
      recon = lc_.axpy(recon, pow2_[i], lc_.eval(bits[i]));
    }
    lc_.assert_eq(recon, v);

    // Canonical-range check: the 256-bit value must be < p.  Without this,
    // since 2^256 > p, a prover could supply the non-canonical alias
    // (value + p) -- same field element, but a flipped bit[0] -- and thereby
    // flip sgn0 to forge -y.  RFC 9380 sgn0 is defined on the canonical
    // integer in [0, p).  Reuses the same bitwise less-than the ecdsa gadget
    // uses to bound scalars by the curve order.
    lc_.assert1(lc_.vlt(bv, mod_bits_));

    return bits[0];
  }

 private:
  const LogicCircuit& lc_;
  Ref ref_;
  Elt a_, b_, z_, znr_;
  Elt minusB_over_A_, B_over_ZA_;
  Elt pow2_[kBits];
  typename LogicCircuit::template bitvec<kBits> mod_bits_;
};

}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_HASH2CURVE_P256_SSWU_H_
