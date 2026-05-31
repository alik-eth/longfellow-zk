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

#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_OPRF_OPRF_BLIND_WITNESS_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_OPRF_OPRF_BLIND_WITNESS_H_

#include <cstddef>
#include <cstdint>

#include "circuits/ec2/scalar_mul_witness.h"
#include "circuits/hash2curve/hash_to_curve.h"
#include "circuits/hash2curve/hash_to_curve_witness.h"
#include "circuits/sha/flatsha256_witness.h"
#include "ec/p256.h"
#include "util/panic.h"

/*
Host reference for the in-circuit OPRF blinding block (oprf_blind.h).

Relation proved by the gadget (NO in-circuit DLEQ):

  H = H2C_P256(rnokpp)             RFC 9380 P256_XMD:SHA-256_SSWU_RO_ (prod DST)
  M = r * H                        PUBLIC output (Mx, My)
  r * N == Y                       Y (Yx, Yy) PUBLIC, asserted == r*N
  s = SHA256(N.x || N.y)           PUBLIC output, raw 32 bytes

Honest host construction (the OPRF service picks the key k, evaluates Y=k*M in
plain at registration; that step is out of scope for this gadget):

  pick k; H = H2C(rnokpp); M = r*H; Y = k*M; N = k*H
  =>  r*N = r*k*H = k*(r*H) = k*M = Y          (the relation the gadget checks)

This host code reproduces the exact sub-witnesses the gadget consumes:
  * the full HashToCurveWitness for H = H2C(rnokpp),
  * two ScalarMulWitness traces: scalar `r` over base H (-> M) and over base N
    (-> Y).  Both muls use the SAME scalar r; the gadget pins r's bits ONCE and
    feeds both muls, so the host stores the SAME `r` in both.
  * the SHA-256 block witnesses for s = SHA256(N.x || N.y).

N.x and N.y are each serialised BIG-ENDIAN into 32 bytes (MSB first), so the
64-byte SHA preimage is  N.x[0..31] || N.y[0..31].  The in-circuit gadget
recomposes these bytes MSB-first (Horner * 256) and asserts the result equals
the witnessed field coordinates, binding the SHA preimage to the EC point.
*/
namespace proofs {

// Big-endian 32-byte serialisation of a P256 base-field element.
// to_bytes_field() emits the canonical integer little-endian; reverse it.
template <class Field>
void oprf_elt_to_be32(const Field& F, const typename Field::Elt& x,
                      uint8_t out[32]) {
  uint8_t le[Field::kBytes];
  F.to_bytes_field(le, x);
  for (size_t i = 0; i < 32; ++i) {
    out[i] = le[31 - i];
  }
}

template <class Field, size_t kRnokppBytes>
struct OprfBlindWitness {
  using Elt = typename Field::Elt;
  using Nat = typename P256::N;
  using ECPoint = typename P256::ECPoint;
  static constexpr size_t kDstBytes = sizeof(kHashToCurveProdDst) - 1;  // 38
  // SHA-256 of 64-byte preimage (N.x||N.y): 64+9=73 bytes -> ceil(73/64)=2.
  static constexpr size_t kShaBlocks = 2;

  // Public outputs / inputs (affine).
  Elt mx, my;  // M = r*H        (public output)
  Elt yx, yy;  // Y = k*M = r*N  (public input, asserted == r*N)
  uint8_t s[32];  // raw SHA256(N.x || N.y) (public output)

  // The (private) hashed point H and the (private) point N.
  Elt hx, hy;
  Elt nx, ny;

  // The raw rnokpp message bytes (private input to H2C), stored for the gadget
  // witness fillers.
  uint8_t rnokpp[kRnokppBytes];

  // Sub-witnesses.
  HashToCurveWitness<Field, kRnokppBytes, kDstBytes> h2c;
  ScalarMulWitness<Field, P256> mul_h;  // r * H -> M
  ScalarMulWitness<Field, P256> mul_n;  // r * N -> Y

  // SHA-256 preimage + block witnesses for s = SHA256(N.x || N.y).
  uint8_t sha_in[64 * kShaBlocks];
  uint8_t sha_numb;
  FlatSHA256Witness::BlockWitness sha_bw[kShaBlocks];
};

// Compute the full honest OPRF blinding trace for inputs (k, rnokpp, r).
//   - k    : the OPRF service key (private to this host helper; used to build
//            the honest N and Y, never enters the circuit witness).
//   - rnokpp : the kRnokppBytes message hashed to the curve.
//   - r    : the client blinding scalar (< n), SHARED by both scalar-muls.
template <class Field, size_t kRnokppBytes>
void oprf_blind_witness(const Field& F, const P256& ec,
                        const typename P256::N& k,
                        const uint8_t rnokpp[kRnokppBytes],
                        const typename P256::N& r,
                        OprfBlindWitness<Field, kRnokppBytes>& out) {
  using ECPoint = typename P256::ECPoint;
  constexpr size_t kDstBytes = OprfBlindWitness<Field, kRnokppBytes>::kDstBytes;

  // 1) H = H2C(rnokpp) with the production DST.
  uint8_t dst[kDstBytes];
  for (size_t i = 0; i < kDstBytes; ++i) {
    dst[i] = static_cast<uint8_t>(kHashToCurveProdDst[i]);
  }
  for (size_t i = 0; i < kRnokppBytes; ++i) out.rnokpp[i] = rnokpp[i];
  hash_to_curve<Field, kRnokppBytes, kDstBytes>(F, rnokpp, dst, out.h2c);
  out.hx = out.h2c.px;
  out.hy = out.h2c.py;
  ECPoint H(out.hx, out.hy, F.one());

  // 2) M = r * H.
  scalar_mul_witness<Field, P256>(F, ec, H, r, out.mul_h);
  check(!out.mul_h.is_infinity, "OPRF host: r*H is identity");
  out.mx = out.mul_h.rx;
  out.my = out.mul_h.ry;

  // 3) Honest N = k * H and Y = k * M.
  ECPoint N = ec.scalar_multf(H, k);
  ec.normalize(N);
  check(N.z != F.zero(), "OPRF host: k*H is identity");
  out.nx = N.x;
  out.ny = N.y;

  ECPoint M(out.mx, out.my, F.one());
  ECPoint Y = ec.scalar_multf(M, k);
  ec.normalize(Y);
  check(Y.z != F.zero(), "OPRF host: k*M is identity");
  out.yx = Y.x;
  out.yy = Y.y;

  // 4) r * N -> must equal Y (the relation the gadget asserts).
  ECPoint Naff(out.nx, out.ny, F.one());
  scalar_mul_witness<Field, P256>(F, ec, Naff, r, out.mul_n);
  check(!out.mul_n.is_infinity, "OPRF host: r*N is identity");
  check(out.mul_n.rx == out.yx && out.mul_n.ry == out.yy,
        "OPRF host relation broken: r*N != Y");

  // 5) s = SHA256(N.x || N.y), each coordinate big-endian 32 bytes.
  uint8_t preimage[64];
  oprf_elt_to_be32<Field>(F, out.nx, &preimage[0]);
  oprf_elt_to_be32<Field>(F, out.ny, &preimage[32]);
  FlatSHA256Witness::transform_and_witness_message(
      64, preimage, OprfBlindWitness<Field, kRnokppBytes>::kShaBlocks,
      out.sha_numb, out.sha_in, out.sha_bw);

  // Final hash s = bw[numb-1].h1 serialised big-endian.
  for (size_t j = 0; j < 8; ++j) {
    uint32_t w = out.sha_bw[out.sha_numb - 1].h1[j];
    out.s[j * 4 + 0] = static_cast<uint8_t>(w >> 24);
    out.s[j * 4 + 1] = static_cast<uint8_t>(w >> 16);
    out.s[j * 4 + 2] = static_cast<uint8_t>(w >> 8);
    out.s[j * 4 + 3] = static_cast<uint8_t>(w);
  }
}

}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_OPRF_OPRF_BLIND_WITNESS_H_
