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

#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_HASH2CURVE_HASH_TO_CURVE_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_HASH2CURVE_HASH_TO_CURVE_H_

#include <cstddef>
#include <cstdint>

#include "arrays/dense.h"
#include "circuits/ec2/ec_ops.h"
#include "circuits/hash2curve/expand_xmd.h"
#include "circuits/hash2curve/hash_to_curve_witness.h"
#include "circuits/hash2curve/p256_sswu.h"
#include "circuits/hash2curve/p256_sswu_witness.h"
#include "ec/p256.h"

/*
In-circuit RFC 9380 hash_to_curve for the suite P256_XMD:SHA-256_SSWU_RO_.

  uniform_bytes = expand_message_xmd(msg, DST, 96)          (expand_xmd.h)
  u0 = OS2IP(uniform_bytes[0:48]) mod p
  u1 = OS2IP(uniform_bytes[48:96]) mod p                    (Horner, here)
  Q0 = map_to_curve(u0) ; Q1 = map_to_curve(u1)             (p256_sswu.h)
  P  = Q0 + Q1                                              (addE, here)

The point addition uses the complete projective formula (Renes-Costello-Batina,
a = -3) identical to the one in ecdsa/verify_circuit.h.  The projective result
(X, Y, Z) is normalised to affine with a witnessed inverse zinv:
  assert Z * zinv == 1 ; Px = X * zinv ; Py = Y * zinv ; assert is_on_curve.

The reduction OS2IP(.) mod p is a field Horner over the 48 SHA output bytes,
MSB-first: acc = acc*256 + byte.  Field arithmetic auto-reduces mod p, which is
exactly OS2IP(.) mod p (no witnessed quotient needed).
*/
namespace proofs {

// RFC 9380 J.1.1 test DST (so published KATs match).
inline constexpr char kHashToCurveTestDst[] =
    "QUUX-V01-CS02-with-P256_XMD:SHA-256_SSWU_RO_";  // 44 bytes

// PRODUCTION DST for CRISP-QES v4.  NOT exercised by the RFC KATs; switching to
// it changes every hashed point and is a hard fork / new transcript tag.
inline constexpr char kHashToCurveProdDst[] =
    "CRISP-QES-V4-P256_XMD:SHA-256_SSWU_RO_";  // 38 bytes

template <class LogicCircuit, class Field, size_t kMsgBytes, size_t kDstBytes>
class P256HashToCurve {
  using EltW = typename LogicCircuit::EltW;
  using BitW = typename LogicCircuit::BitW;
  using Elt = typename LogicCircuit::Elt;
  using v8 = typename LogicCircuit::v8;
  using Sswu = P256SswuCircuit<LogicCircuit, Field>;
  using Xmd = ExpandMessageXmd<LogicCircuit, kMsgBytes, kDstBytes>;

 public:
  struct Witness {
    typename Xmd::Witness exp;
    typename Sswu::Witness map0;
    typename Sswu::Witness map1;
    EltW zinv;  // inverse of the projective Z of Q0 + Q1

    void input(const LogicCircuit& lc) {
      exp.input(lc);
      map0.input(lc);
      map1.input(lc);
      zinv = lc.eltw_input();
    }

    template <size_t kM, size_t kD>
    void set(const LogicCircuit& lc,
             const HashToCurveWitness<Field, kM, kD>& h) {
      exp.set(lc, h.exp);
      map0.set(lc, h.q0);
      map1.set(lc, h.q1);
      zinv = lc.konst(h.zinv);
    }

    template <size_t kM, size_t kD>
    static void fill(DenseFiller<Field>& filler, const Field& F,
                     const HashToCurveWitness<Field, kM, kD>& h) {
      Xmd::Witness::fill(filler, F, h.exp);
      Sswu::Witness::fill(filler, F, h.q0);
      Sswu::Witness::fill(filler, F, h.q1);
      filler.push_back(h.zinv);
    }
  };

  explicit P256HashToCurve(const LogicCircuit& lc)
      : lc_(lc), sswu_(lc), xmd_(lc), ref_(lc.f_), ec_ops_(lc, p256) {
    const Field& F = lc.f_;
    c256_ = F.of_scalar(256);
  }

  // Full hash_to_curve.  `msg` are the (private) message v8 bytes; `dst` is the
  // fixed DST.  Outputs the affine point (px, py).
  void hash_to_curve(const v8 msg[kMsgBytes], const uint8_t dst[kDstBytes],
                     const Witness& w, EltW& px, EltW& py) const {
    // 1) expand_message_xmd -> 96 uniform bytes.
    xmd_.assert_expand(msg, dst, w.exp);
    v8 ub[96];
    xmd_.uniform_bytes(w.exp, ub);

    // 2) hash_to_field: Horner over each 48-byte half, MSB-first.
    EltW u0 = bytes_to_field(&ub[0], 48);
    EltW u1 = bytes_to_field(&ub[48], 48);

    // 3) map_to_curve x2.
    EltW q0x, q0y, q1x, q1y;
    sswu_.map_to_curve(u0, q0x, q0y, w.map0);
    sswu_.map_to_curve(u1, q1x, q1y, w.map1);

    // 4) P = Q0 + Q1 (complete projective addition, affine inputs z=1).
    EltW X3, Y3, Z3;
    ec_ops_.addE(X3, Y3, Z3, q0x, q0y, lc_.konst(lc_.f_.one()), q1x, q1y,
                 lc_.konst(lc_.f_.one()));

    // 5) affine normalise with witnessed inverse, then on-curve check.
    EltW one = lc_.konst(lc_.f_.one());
    lc_.assert_eq(lc_.mul(Z3, w.zinv), one);  // Z * zinv == 1
    px = lc_.mul(X3, w.zinv);
    py = lc_.mul(Y3, w.zinv);
    ec_ops_.is_on_curve(px, py);
  }

  // Horner: acc = acc*256 + byte, MSB-first.  byte = sum_i bit_i 2^i.
  EltW bytes_to_field(const v8 bytes[], size_t n) const {
    EltW acc = lc_.konst(lc_.f_.zero());
    for (size_t i = 0; i < n; ++i) {
      acc = lc_.add(lc_.mul(c256_, acc), byte_to_elt(bytes[i]));
    }
    return acc;
  }

 private:
  EltW byte_to_elt(const v8& b) const {
    // sum_i bit_i * 2^i, i in 0..7.
    EltW acc = lc_.konst(lc_.f_.zero());
    Elt p = lc_.f_.one();
    for (size_t i = 0; i < 8; ++i) {
      acc = lc_.axpy(acc, p, lc_.eval(b[i]));
      p = lc_.f_.addf(p, p);
    }
    return acc;
  }

  const LogicCircuit& lc_;
  Sswu sswu_;
  Xmd xmd_;
  P256SswuReference<Field> ref_;
  ECOps<LogicCircuit, P256> ec_ops_;
  Elt c256_;
};

}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_HASH2CURVE_HASH_TO_CURVE_H_
