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

#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_EC2_EC_OPS_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_EC2_EC_OPS_H_

namespace proofs {

// Shared in-circuit elliptic-curve primitive operations: complete projective
// point addition, exception-free point doubling, and the affine curve-equation
// check.  The formulas are the Renes-Costello-Batina (2016) complete formulas
// for short Weierstrass curves and are EXCEPTION-FREE / COMPLETE: identity,
// equal-point (doubling) and mutual-inverse inputs are all handled with no
// special casing, so a plain double-and-add built on top of these has no
// exceptional cases.  The point at infinity in these projective coordinates is
// (0, 1, 0); addE((0,1,0), P) == P.
//
// These formulas are byte-for-byte identical to the private members previously
// living in ecdsa/verify_circuit.h and the private copy in
// hash2curve/hash_to_curve.h.  This header is the single canonical copy used by
// the variable-base scalar-mul gadget (circuits/ec2/scalar_mul.h) and by
// hash_to_curve.h.
//
// Template parameters:
//   LogicCircuit  the in-circuit logic backend (Logic<...>).
//   EC            an EllipticCurve<...> instance, providing a_ (curve "a"),
//                 k3b (= 3*b) and b_ (curve "b").
template <class LogicCircuit, class EC>
struct ECOps {
  using EltW = typename LogicCircuit::EltW;

  const LogicCircuit& lc_;
  const EC& ec_;

  ECOps(const LogicCircuit& lc, const EC& ec) : lc_(lc), ec_(ec) {}

  // Check that y^2 = x^3 + a*x + b for the affine point (x, y).
  void is_on_curve(EltW x, EltW y) const {
    auto yy = lc_.mul(y, y);
    auto xx = lc_.mul(x, x);
    auto xxx = lc_.mul(x, xx);
    auto ax = lc_.mul(ec_.a_, x);
    auto b = lc_.konst(ec_.b_);
    auto axb = lc_.add(ax, b);
    auto rhs = lc_.add(axb, xxx);
    lc_.assert_eq(yy, rhs);
  }

  // Algorithm 1: Complete, projective point addition for arbitrary prime
  // order short Weierstrass curves E/Fq : y^2 = x^3 + ax + b.
  // The compiler seems to optimize the cases when Z1,Z2=1.
  void addE(EltW& X3, EltW& Y3, EltW& Z3, EltW X1, EltW Y1, EltW Z1, EltW X2,
            EltW Y2, EltW Z2) const {
    EltW t0 = lc_.mul(X1, X2);
    EltW t1 = lc_.mul(Y1, Y2);
    EltW t2 = lc_.mul(Z1, Z2);
    EltW t3 = lc_.add(X1, Y1);
    EltW t4 = lc_.add(X2, Y2);
    t3 = lc_.mul(t3, t4);
    t4 = lc_.add(t0, t1);
    t3 = lc_.sub(t3, t4);
    t4 = lc_.add(X1, Z1);
    EltW t5 = lc_.add(X2, Z2);
    t4 = lc_.mul(t4, t5);
    t5 = lc_.add(t0, t2);
    t4 = lc_.sub(t4, t5);
    t5 = lc_.add(Y1, Z1);
    EltW X3t = lc_.add(Y2, Z2);
    t5 = lc_.mul(t5, X3t);
    X3t = lc_.add(t1, t2);
    t5 = lc_.sub(t5, X3t);
    auto a = lc_.konst(ec_.a_);
    EltW Z3t = lc_.mul(a, t4);
    auto k3b = lc_.konst(ec_.k3b);
    X3t = lc_.mul(k3b, t2);
    Z3t = lc_.add(X3t, Z3t);
    X3t = lc_.sub(t1, Z3t);
    Z3t = lc_.add(t1, Z3t);
    EltW Y3t = lc_.mul(X3t, Z3t);
    t1 = lc_.add(t0, t0);
    t1 = lc_.add(t1, t0);
    t2 = lc_.mul(a, t2);
    t4 = lc_.mul(k3b, t4);
    t1 = lc_.add(t1, t2);
    t2 = lc_.sub(t0, t2);
    t2 = lc_.mul(a, t2);
    t4 = lc_.add(t4, t2);
    t0 = lc_.mul(t1, t4);
    Y3t = lc_.add(Y3t, t0);
    t0 = lc_.mul(t5, t4);
    X3t = lc_.mul(t3, X3t);
    X3t = lc_.sub(X3t, t0);
    t0 = lc_.mul(t3, t1);
    Z3t = lc_.mul(t5, Z3t);
    Z3t = lc_.add(Z3t, t0);

    X3 = X3t;
    Y3 = Y3t;
    Z3 = Z3t;
  }

  // Algorithm 3: Exception-free point doubling for arbitrary prime order
  // short Weierstrass curves E/Fq : y^2 = x^3 + ax + b.
  // The compiler will presumably optimize away 0 mults when a=0 and 1
  // mults when Z = 1.
  void doubleE(EltW& X3, EltW& Y3, EltW& Z3, EltW X, EltW Y, EltW Z) const {
    EltW t0 = lc_.mul(X, X);
    EltW t1 = lc_.mul(Y, Y);
    EltW t2 = lc_.mul(Z, Z);
    EltW t3 = lc_.mul(X, Y);
    t3 = lc_.add(t3, t3);
    EltW Z3t = lc_.mul(X, Z);
    Z3t = lc_.add(Z3t, Z3t);
    auto a = lc_.konst(ec_.a_);
    auto k3b = lc_.konst(ec_.k3b);
    EltW X3t = lc_.mul(a, Z3t);
    EltW Y3t = lc_.mul(k3b, t2);
    Y3t = lc_.add(X3t, Y3t);
    X3t = lc_.sub(t1, Y3t);
    Y3t = lc_.add(t1, Y3t);
    Y3t = lc_.mul(X3t, Y3t);
    X3t = lc_.mul(t3, X3t);
    Z3t = lc_.mul(k3b, Z3t);
    t2 = lc_.mul(a, t2);
    t3 = lc_.sub(t0, t2);
    t3 = lc_.mul(a, t3);
    t3 = lc_.add(t3, Z3t);
    Z3t = lc_.add(t0, t0);
    t0 = lc_.add(Z3t, t0);
    t0 = lc_.add(t0, t2);
    t0 = lc_.mul(t0, t3);
    Y3t = lc_.add(Y3t, t0);
    t2 = lc_.mul(Y, Z);
    t2 = lc_.add(t2, t2);
    t0 = lc_.mul(t2, t3);
    X3t = lc_.sub(X3t, t0);
    Z3t = lc_.mul(t2, t1);
    Z3t = lc_.add(Z3t, Z3t);
    Z3t = lc_.add(Z3t, Z3t);

    X3 = X3t;
    Y3 = Y3t;
    Z3 = Z3t;
  }
};

}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_EC2_EC_OPS_H_
