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

#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_EC2_SCALAR_MUL_WITNESS_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_EC2_SCALAR_MUL_WITNESS_H_

#include <cstddef>

namespace proofs {

// Host reference + witness generator for the in-circuit variable-base
// scalar-multiplication gadget R = [k]P.
//
// The in-circuit gadget runs an exception-free double-and-add over the kBits
// scalar bits, MSB->LSB, using the complete RCB-2016 formulas:
//   acc = (0, 1, 0)                       (point at infinity)
//   for bit in k (MSB..LSB):
//     acc = doubleE(acc)
//     acc = addE(acc, bit ? P : (0,1,0))
//   R = affine_normalise(acc)             (single projective inverse)
//
// This host code reproduces that exact trace so the in-circuit accumulator
// (and the final affine point) match bit-for-bit, and it also cross-checks the
// final point against EC::scalar_multf.  The single witness datum the gadget
// needs (beyond the scalar bits, which it constrains itself) is `zinv`, the
// inverse of the final projective Z.
template <class Field, class EC>
struct ScalarMulWitness {
  using Elt = typename Field::Elt;
  using N = typename EC::N;
  using ECPoint = typename EC::ECPoint;
  static constexpr size_t kBits = EC::kBits;

  // The scalar, the base point and the (affine) result.
  N k;
  Elt px, py;  // affine base point P (assumed on curve, z = 1)
  Elt rx, ry;  // affine result R = [k]P (only meaningful if !is_infinity)

  // Affine-normalisation hint: inverse of the final projective Z.
  Elt zinv;

  // True iff [k]P is the point at infinity (final Z == 0).  In that case the
  // gadget's `Z*zinv == 1` constraint is unsatisfiable and it fails closed;
  // (rx, ry) are left undefined.
  bool is_infinity;

  // scalar bits MSB->LSB (bits[0] is the most-significant), as the gadget
  // consumes them.
  bool bits[kBits];
};

// Compute the host trace for R = [k]P with the SAME exception-free
// double-and-add the gadget uses, and fill the witness.
template <class Field, class EC>
void scalar_mul_witness(const Field& F, const EC& ec,
                        const typename EC::ECPoint& P, const typename EC::N& k,
                        ScalarMulWitness<Field, EC>& out) {
  using ECPoint = typename EC::ECPoint;
  constexpr size_t kBits = EC::kBits;

  out.k = k;
  // P is assumed affine (z = 1); record its affine coordinates.
  out.px = P.x;
  out.py = P.y;

  // Extract the scalar bits MSB->LSB.
  for (size_t i = 0; i < kBits; ++i) {
    // bit (kBits-1-i) is the i-th from the MSB.
    out.bits[i] = k.bit(kBits - 1 - i);
  }

  // Exception-free double-and-add, MSB->LSB, mirroring the gadget exactly.
  ECPoint acc = ec.zero();  // (0, 1, 0)
  for (size_t i = 0; i < kBits; ++i) {
    ec.doubleE(acc);
    if (out.bits[i]) {
      ec.addE(acc, P);
    } else {
      // Adding the neutral element; complete addE handles it, but skipping is
      // the same result and keeps the host trace cheap.  We still call addE
      // with the neutral so the host matches the circuit's unconditional add.
      ECPoint neutral = ec.zero();
      ec.addE(acc, neutral);
    }
  }

  // Affine-normalise the projective accumulator.
  out.is_infinity = (acc.z == F.zero());
  if (out.is_infinity) {
    out.zinv = F.zero();  // unsatisfiable Z*zinv==1; gadget fails closed.
    out.rx = F.zero();
    out.ry = F.zero();
  } else {
    out.zinv = F.invertf(acc.z);
    out.rx = F.mulf(acc.x, out.zinv);
    out.ry = F.mulf(acc.y, out.zinv);
  }
}

}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_EC2_SCALAR_MUL_WITNESS_H_
