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

#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_HASH2CURVE_HASH_TO_CURVE_WITNESS_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_HASH2CURVE_HASH_TO_CURVE_WITNESS_H_

#include <cstddef>
#include <cstdint>

#include "circuits/hash2curve/expand_xmd_witness.h"
#include "circuits/hash2curve/p256_sswu_witness.h"
#include "ec/p256.h"

/*
Host reference implementation of the full RFC 9380 hash_to_curve for the suite
P256_XMD:SHA-256_SSWU_RO_:

  uniform_bytes = expand_message_xmd(msg, DST, 96)
  u0 = OS2IP(uniform_bytes[0:48]) mod p
  u1 = OS2IP(uniform_bytes[48:96]) mod p
  Q0 = map_to_curve(u0) ; Q1 = map_to_curve(u1)
  P  = Q0 + Q1            (cofactor 1, no clear_cofactor)

Produces all witness hints needed by the in-circuit gadget (hash_to_curve.h):
the full ExpandXmdWitness (SHA block witnesses), the two SSWU map hint sets,
and the affine-normalisation inverse `zinv` for the point addition.
*/
namespace proofs {

// OS2IP over a big-endian byte range, reduced mod p by field Horner.
template <class Field>
typename Field::Elt os2ip_mod_p(const Field& F, const uint8_t* bytes,
                                size_t n) {
  using Elt = typename Field::Elt;
  Elt acc = F.zero();
  Elt c256 = F.of_scalar(256);
  for (size_t i = 0; i < n; ++i) {
    acc = F.addf(F.mulf(acc, c256), F.of_scalar(bytes[i]));
  }
  return acc;
}

template <class Field, size_t kMsgBytes, size_t kDstBytes>
struct HashToCurveWitness {
  using Elt = typename Field::Elt;
  using SswuHints = typename P256SswuReference<Field>::Hints;

  ExpandXmdWitness<kMsgBytes, kDstBytes> exp;
  Elt u0, u1;
  SswuHints q0, q1;          // map hints
  Elt q0x, q0y, q1x, q1y;    // map outputs (affine)

  // Point-add result in projective coords + the affine-normalisation inverse.
  Elt px, py;                // final affine output P
  Elt zinv;                  // inverse of the projective Z of Q0 + Q1
};

// Compute the full hash_to_curve and all hints.
template <class Field, size_t kMsgBytes, size_t kDstBytes>
void hash_to_curve(const Field& F, const uint8_t msg[kMsgBytes],
                   const uint8_t dst[kDstBytes],
                   HashToCurveWitness<Field, kMsgBytes, kDstBytes>& out) {
  using Elt = typename Field::Elt;

  expand_message_xmd<kMsgBytes, kDstBytes>(msg, dst, out.exp);

  out.u0 = os2ip_mod_p(F, &out.exp.uniform_bytes[0], 48);
  out.u1 = os2ip_mod_p(F, &out.exp.uniform_bytes[48], 48);

  P256SswuReference<Field> ref(F);
  out.q0 = ref.map(out.u0);
  out.q1 = ref.map(out.u1);
  out.q0x = out.q0.x;
  out.q0y = out.q0.y;
  out.q1x = out.q1.x;
  out.q1y = out.q1.y;

  // P = Q0 + Q1 via the host curve's complete addition (affine inputs z=1).
  typename P256::ECPoint p0(out.q0x, out.q0y, F.one());
  typename P256::ECPoint p1(out.q1x, out.q1y, F.one());
  typename P256::ECPoint sum = p256.addEf(p0, p1);

  // Affine normalise: zinv = 1/Z, x = X*zinv^2, y = Y*zinv^3 (Jacobian-style)?
  // The complete-addition formula here is PROJECTIVE: x = X/Z, y = Y/Z.
  out.zinv = F.invertf(sum.z);
  out.px = F.mulf(sum.x, out.zinv);
  out.py = F.mulf(sum.y, out.zinv);
}

}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_HASH2CURVE_HASH_TO_CURVE_WITNESS_H_
