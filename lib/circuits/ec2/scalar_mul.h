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

#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_EC2_SCALAR_MUL_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_EC2_SCALAR_MUL_H_

#include <cstddef>

#include "arrays/dense.h"
#include "circuits/ec2/ec_ops.h"
#include "circuits/ec2/scalar_mul_witness.h"

namespace proofs {

// In-circuit variable-base scalar multiplication R = [k]P on a short Weierstrass
// curve, for a variable (witnessed) base point P and a variable scalar k.
//
// This is the shared EC primitive behind the OPRF (M = r*H2C), DLEQ, and unblind
// steps.  It uses the exception-free / complete RCB-2016 EC formulas (ECOps), so
// a plain double-and-add has NO exceptional cases: identity, doubling and
// mutual-inverse intermediates are all handled.
//
//   acc = (0, 1, 0)                          (point at infinity)
//   for each scalar bit b, MSB -> LSB:
//     acc = doubleE(acc)
//     acc = addE(acc, b ? {Px,Py,1} : (0,1,0))
//   assert k = sum_i b_i 2^i  is canonical (k < n, the curve order)
//   affine-normalise acc with a witnessed inverse zinv (PROJECTIVE: single
//   inverse, R = (X*zinv, Y*zinv)); assert on-curve.
//
// Each scalar bit is constrained to {0,1}.  If the result is the point at
// infinity (acc.Z == 0), the `Z*zinv == 1` constraint is unsatisfiable and the
// gadget fails closed (it never produces a wrong affine point).
//
// Template parameters:
//   LogicCircuit  in-circuit logic backend.
//   Field         the EC base field.
//   EC            an EllipticCurve<...> instance (provides a_, b_, k3b, kBits,
//                 and the curve order via the constructor `order` argument).
template <class LogicCircuit, class Field, class EC>
class VarBaseScalarMul {
  using EltW = typename LogicCircuit::EltW;
  using BitW = typename LogicCircuit::BitW;
  using Elt = typename LogicCircuit::Elt;
  using Nat = typename Field::N;
  using Bitvec = typename LogicCircuit::v256;
  static constexpr size_t kBits = EC::kBits;

 public:
  struct Witness {
    EltW bits[kBits];  // scalar bits, MSB (bits[0]) -> LSB (bits[kBits-1])
    EltW zinv;         // inverse of the final projective Z

    void input(const LogicCircuit& lc) {
      for (size_t i = 0; i < kBits; ++i) {
        bits[i] = lc.eltw_input();
      }
      zinv = lc.eltw_input();
    }

    // Build the witness wires from a host trace (EvaluationBackend path).
    template <class F2, class EC2>
    void set(const LogicCircuit& lc, const ScalarMulWitness<F2, EC2>& h) {
      for (size_t i = 0; i < kBits; ++i) {
        bits[i] = lc.konst(h.bits[i] ? lc.f_.one() : lc.f_.zero());
      }
      zinv = lc.konst(h.zinv);
    }

    // Push the witness values into a dense filler (CompilerBackend path).
    template <class F2, class EC2>
    static void fill(DenseFiller<Field>& filler, const Field& F,
                     const ScalarMulWitness<F2, EC2>& h) {
      for (size_t i = 0; i < kBits; ++i) {
        filler.push_back(h.bits[i] ? F.one() : F.zero());
      }
      filler.push_back(h.zinv);
    }
  };

  VarBaseScalarMul(const LogicCircuit& lc, const EC& ec, const Nat& order)
      : lc_(lc), ec_(ec), ec_ops_(lc, ec) {
    // Bit representation of the curve order n, LSB at index 0.
    for (size_t i = 0; i < kBits; ++i) {
      bits_n_[i] = lc_.bit(order.bit(i));
    }
  }

  // Compute R = [k]P.  (Px, Py) is the affine base point (z = 1); the scalar
  // bits and zinv come from the witness.  Outputs the affine result (Rx, Ry).
  void mul(EltW Px, EltW Py, const Witness& w, EltW& Rx, EltW& Ry) const {
    EltW zero = lc_.konst(lc_.zero());
    EltW one = lc_.konst(lc_.one());

    // Accumulator starts at the neutral element (0, 1, 0).
    EltW ax = zero, ay = one, az = zero;

    // bits used for the canonical (< n) range check, LSB at index 0.
    Bitvec k_bits;

    for (size_t i = 0; i < kBits; ++i) {
      EltW bit_w = w.bits[i];
      BitW bit(bit_w, lc_.f_);

      // Constrain bit in {0,1}.
      lc_.assert_is_bit(bit);

      // Record this bit for the range check.  bits[0] is the MSB, so it lands
      // at index kBits-1; bits[kBits-1] (LSB) lands at index 0.
      k_bits[kBits - 1 - i] = bit;

      // Exception-free double-and-add step.
      ec_ops_.doubleE(ax, ay, az, ax, ay, az);

      // Select the point to add: P (z=1) if bit set, else neutral (0,1,0).
      EltW tx = lc_.mux(bit, Px, zero);
      EltW ty = lc_.mux(bit, Py, one);
      EltW tz = lc_.mux(bit, one, zero);
      ec_ops_.addE(ax, ay, az, ax, ay, az, tx, ty, tz);
    }

    // Canonical-scalar check: assert reconstructed k < n.
    auto k_range = lc_.vlt(k_bits, bits_n_);
    lc_.assert1(k_range);

    // Affine-normalise (PROJECTIVE): assert Z*zinv == 1, R = (X*zinv, Y*zinv).
    // If the result is the point at infinity (Z == 0), this is unsatisfiable
    // and the gadget fails closed.
    lc_.assert_eq(lc_.mul(az, w.zinv), one);
    Rx = lc_.mul(ax, w.zinv);
    Ry = lc_.mul(ay, w.zinv);

    // The affine result must satisfy the curve equation.
    ec_ops_.is_on_curve(Rx, Ry);
  }

 private:
  const LogicCircuit& lc_;
  const EC& ec_;
  ECOps<LogicCircuit, EC> ec_ops_;
  Bitvec bits_n_;
};

}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_EC2_SCALAR_MUL_H_
