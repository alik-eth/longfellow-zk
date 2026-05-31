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

#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_HASH2CURVE_P256_SSWU_WITNESS_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_HASH2CURVE_P256_SSWU_WITNESS_H_

#include <cstddef>

#include "ec/p256.h"

/*
Host reference implementation of the RFC 9380 simplified SWU map for the
suite P256_XMD:SHA-256_SSWU_RO_ (RFC 9380 sections 6.6.2 and 8.2), restricted
to map_to_curve_simple_swu(u) -> (x, y).

Curve: y^2 = x^3 + A*x + B over Fp256Base (p256_base), with
  A = -3
  B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
  Z = -10
Cofactor h_eff = 1, so there is no clear_cofactor step.

This header also produces all the "hints" needed by the in-circuit gadget
(see p256_sswu.h), which deliberately performs no inversion/sqrt in-circuit
and instead checks witnessed values with field multiplications.  The hint
shape mirrors the proven Noir SvdW gadget in
packages/oprf/v3-grumpkin/circuits/oprf_commitment/src/main.nr
(inv0 -> witnessed inverse + is-zero selector, is_square -> {e, w},
sqrt -> y_candidate, sgn0 -> LSB bits).
*/
namespace proofs {

template <class Field>
class P256SswuReference {
 public:
  using Elt = typename Field::Elt;
  using Nat = typename Field::N;

  struct Hints {
    // the input field element u (kept so the circuit witness can recover its
    // bit decomposition for sgn0).
    Elt u_elt;

    // map output point (affine, always on curve, cofactor 1)
    Elt x, y;

    // inv0 hint for tv1 = inv0(Z^2 u^4 + Z u^2):
    //   den = Z^2 u^4 + Z u^2 ; den_is_zero in {0,1} ; den_inv = inverse(den)
    //   (den_inv is the field inverse when den != 0, else 0)
    Elt den;
    Elt den_inv;
    bool den_is_zero;

    // candidate-selection hints (gx1 = g(x1)):
    //   e1 in {0,1}: 1 iff gx1 is a square
    //   w1: if e1==1, sqrt(gx1); else sqrt(gx1 * Z_nonresidue)
    bool e1;
    Elt w1;

    // sqrt hint for the selected gx:
    //   y_candidate^2 == gx_selected
    Elt y_candidate;

    // sgn0 hints: low bit of the integer (non-Montgomery) representation
    bool sgn0_u;
    bool sgn0_y_candidate;  // sgn0 of y_candidate (before the sign fix)
  };

  explicit P256SswuReference(const Field& f) : f_(f) {
    a_ = f_.negf(f_.of_scalar(3));  // A = -3
    b_ = f_.of_string(
        "0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b");
    z_ = f_.negf(f_.of_scalar(10));  // Z = -10

    // Z_nonresidue: a fixed quadratic non-residue used by the is_square
    // assertion.  Z = -10 is a non-residue mod p (the SSWU suite requires
    // this), so we reuse it.
    z_nonresidue_ = z_;
  }

  const Elt& A() const { return a_; }
  const Elt& B() const { return b_; }
  const Elt& Z() const { return z_; }
  const Elt& Znr() const { return z_nonresidue_; }

  // g(x) = x^3 + A*x + B
  Elt g(const Elt& x) const {
    Elt x2 = f_.mulf(x, x);
    Elt x3 = f_.mulf(x2, x);
    return f_.addf(f_.addf(x3, f_.mulf(a_, x)), b_);
  }

  // sgn0(x) per RFC 9380 (m=1): low bit of the integer representation.
  bool sgn0(const Elt& x) const { return f_.from_montgomery(x).bit(0) & 1; }

  // a^e via square-and-multiply over the Nat exponent.
  Elt powf(const Elt& a, const Nat& e) const {
    Elt r = f_.one();
    Elt base = a;
    for (size_t i = 0; i < Nat::kBits; ++i) {
      if (e.bit(i) & 1) {
        r = f_.mulf(r, base);
      }
      base = f_.mulf(base, base);
    }
    return r;
  }

  // Euler's criterion: a is a (nonzero) square iff a^((p-1)/2) == 1.
  // 0 is treated as a square (sqrt 0 = 0), matching RFC is_square(0)=True.
  bool is_square(const Elt& a) const {
    if (a == f_.zero()) return true;
    return powf(a, p_minus_1_over_2()) == f_.one();
  }

  // sqrt for p == 3 (mod 4): sqrt(a) = a^((p+1)/4).  Returns *a* square root;
  // the caller fixes the sign via sgn0.  Precondition: a is a square.
  Elt sqrt(const Elt& a) const { return powf(a, p_plus_1_over_4()); }

  // Compute the map output and all witness hints.
  Hints map(const Elt& u) const {
    Hints h;
    h.u_elt = u;

    Elt u2 = f_.mulf(u, u);
    Elt zu2 = f_.mulf(z_, u2);              // Z u^2
    Elt z2u4 = f_.mulf(zu2, zu2);           // Z^2 u^4
    Elt den = f_.addf(z2u4, zu2);           // Z^2 u^4 + Z u^2
    h.den = den;
    h.den_is_zero = (den == f_.zero());
    h.den_inv = h.den_is_zero ? f_.zero() : f_.invertf(den);

    // tv1 = inv0(den)
    Elt tv1 = h.den_inv;

    // x1 = (-B/A) * (1 + tv1); if tv1 == 0 then x1 = B/(Z*A)
    Elt minusB_over_A = f_.mulf(f_.negf(b_), f_.invertf(a_));
    Elt x1;
    if (h.den_is_zero) {
      x1 = f_.mulf(b_, f_.invertf(f_.mulf(z_, a_)));  // B/(Z*A)
    } else {
      x1 = f_.mulf(minusB_over_A, f_.addf(f_.one(), tv1));
    }

    Elt gx1 = g(x1);

    // x2 = Z u^2 x1
    Elt x2 = f_.mulf(zu2, x1);
    Elt gx2 = g(x2);

    h.e1 = is_square(gx1);

    Elt x_sel, gx_sel;
    if (h.e1) {
      x_sel = x1;
      gx_sel = gx1;
      h.w1 = sqrt(gx1);
    } else {
      x_sel = x2;
      gx_sel = gx2;
      // w1 is the sqrt of gx1 * Z_nonresidue (always a square when gx1 is a
      // non-residue), used by the in-circuit non-residue assertion.
      h.w1 = sqrt(f_.mulf(gx1, z_nonresidue_));
    }

    Elt y = sqrt(gx_sel);
    h.y_candidate = y;
    h.sgn0_u = sgn0(u);
    h.sgn0_y_candidate = sgn0(y);

    // if sgn0(u) != sgn0(y): y = -y
    if (h.sgn0_u != h.sgn0_y_candidate) {
      y = f_.negf(y);
    }

    h.x = x_sel;
    h.y = y;
    return h;
  }

 private:
  // (p-1)/2 and (p+1)/4 as Nats, computed once.
  const Nat& p_minus_1_over_2() const {
    static const Nat v = compute_p_minus_1_over_2();
    return v;
  }
  const Nat& p_plus_1_over_4() const {
    static const Nat v = compute_p_plus_1_over_4();
    return v;
  }

  static Nat modulus() {
    // p = 2^256 - 2^224 + 2^192 + 2^96 - 1
    return Nat(
        "0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff");
  }
  static Nat compute_p_minus_1_over_2() {
    Nat p = modulus();
    p.sub(Nat(1u));
    p.shiftr(1);
    return p;
  }
  static Nat compute_p_plus_1_over_4() {
    Nat p = modulus();
    p.add(Nat(1u));
    p.shiftr(1);
    p.shiftr(1);
    return p;
  }

  const Field& f_;
  Elt a_, b_, z_, z_nonresidue_;
};

}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_HASH2CURVE_P256_SSWU_WITNESS_H_
