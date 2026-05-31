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

#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_OPRF_OPRF_BLIND_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_OPRF_OPRF_BLIND_H_

#include <cstddef>
#include <cstdint>

#include "arrays/dense.h"
#include "circuits/ec2/scalar_mul.h"
#include "circuits/ec2/scalar_mul_witness.h"
#include "circuits/hash2curve/hash_to_curve.h"
#include "circuits/logic/bit_plucker.h"
#include "circuits/logic/bit_plucker_encoder.h"
#include "circuits/oprf/oprf_blind_witness.h"
#include "circuits/sha/flatsha256_circuit.h"
#include "circuits/sha/flatsha256_io.h"
#include "circuits/sha/flatsha256_witness.h"
#include "ec/p256.h"

namespace proofs {

/*
In-circuit OPRF blinding block.  Composes three already-validated gadgets:

  H = P256HashToCurve(rnokpp)                       (hash2curve/hash_to_curve.h)
  M = VarBaseScalarMul(r, H)        PUBLIC (Mx,My)  (ec2/scalar_mul.h)
  R = VarBaseScalarMul(r, N) ; assert R == Y        (ec2/scalar_mul.h)
  s = FlatSHA256(N.x || N.y)        PUBLIC 32 bytes  (sha/flatsha256_circuit.h)

There is NO in-circuit DLEQ.  The OPRF service recomputes Y = k*M in plain at
registration (out of scope here); the gadget only checks r*N == Y and exposes
M and s.

SHARED SCALAR r.  The two scalar-muls use ONE scalar r.  The gadget stores a
single array of r bit wires in the Witness and feeds the SAME wires to BOTH
sub-mul witnesses (Witness::set / Witness::input wire them once, then alias).
Because both muls read the identical bit wires, a prover cannot use a different
scalar in the second mul: there is only one set of r bits in the circuit.  (The
negative test confirms that forcing distinct r values makes r*N != Y and trips
the R == Y assertion.)

The point N is private, witnessed both as field coordinates (Nx, Ny) -- the
base point for the second mul -- and as 64 SHA input byte wires.  The gadget
binds the two: it recomposes N.x and N.y from their 32 big-endian byte wires
(Horner * 256, MSB first) and asserts the result equals Nx / Ny.  This pins the
SHA preimage to the exact EC point fed to the scalar-mul.
*/
template <class LogicCircuit, class Field, size_t kRnokppBytes>
class OprfBlind {
  using EltW = typename LogicCircuit::EltW;
  using BitW = typename LogicCircuit::BitW;
  using Elt = typename LogicCircuit::Elt;
  using v8 = typename LogicCircuit::v8;
  using v256 = typename LogicCircuit::v256;
  using H2C = P256HashToCurve<LogicCircuit, Field, kRnokppBytes,
                              sizeof(kHashToCurveProdDst) - 1>;
  using SMul = VarBaseScalarMul<LogicCircuit, Field, P256>;
  using FlatSha =
      FlatSHA256Circuit<LogicCircuit,
                        BitPlucker<LogicCircuit, kShaPluckerSize>>;
  using ShaBlockWitness = typename FlatSha::BlockWitness;
  static constexpr size_t kBits = P256::kBits;

 public:
  static constexpr size_t kDstBytes = sizeof(kHashToCurveProdDst) - 1;  // 38
  static constexpr size_t kShaBlocks =
      OprfBlindWitness<Field, kRnokppBytes>::kShaBlocks;  // 2

  struct Witness {
    // rnokpp message bytes (private).
    v8 rnokpp[kRnokppBytes];

    // The ONE blinding scalar r, as kBits EltW bit wires, MSB->LSB.  Shared by
    // both scalar-muls.
    EltW r_bits[kBits];

    // Private point N: field coordinates (base for r*N) ...
    EltW nx, ny;
    // ... and the full SHA-preimage byte wires.  The first 64 bytes are
    // N.x||N.y (each big-endian, the actual message); the remaining bytes are
    // the SHA-256 padding for the 64-byte message across kShaBlocks blocks.
    v8 n_bytes[64 * kShaBlocks];

    // Sub-witnesses (NB: their .bits[] are overwritten with the shared r_bits
    // inside blind(); the per-mul .bits stored here are ignored).
    typename H2C::Witness h2c;
    typename SMul::Witness mul_h;
    typename SMul::Witness mul_n;

    // SHA-256 block witnesses + block count.
    v8 sha_numb;
    ShaBlockWitness sha_bw[kShaBlocks];

    void input(const LogicCircuit& lc) {
      for (size_t i = 0; i < kRnokppBytes; ++i) {
        rnokpp[i] = lc.template vinput<8>();
      }
      for (size_t i = 0; i < kBits; ++i) {
        r_bits[i] = lc.eltw_input();
      }
      nx = lc.eltw_input();
      ny = lc.eltw_input();
      for (size_t i = 0; i < 64 * kShaBlocks; ++i) {
        n_bytes[i] = lc.template vinput<8>();
      }
      h2c.input(lc);
      // mul_h / mul_n bits are aliased to r_bits in blind(); we still consume
      // their zinv wires (their own bit wires are not used).
      mul_h.zinv = lc.eltw_input();
      mul_n.zinv = lc.eltw_input();
      sha_numb = lc.template vinput<8>();
      for (size_t b = 0; b < kShaBlocks; ++b) {
        sha_bw[b].input(lc);
      }
    }

    void set(const LogicCircuit& lc,
             const OprfBlindWitness<Field, kRnokppBytes>& h) {
      for (size_t i = 0; i < kRnokppBytes; ++i) {
        rnokpp[i] = lc.vbit8(h.rnokpp[i]);
      }
      for (size_t i = 0; i < kBits; ++i) {
        // r is the SAME scalar in both muls; take it from mul_h.
        r_bits[i] = lc.konst(h.mul_h.bits[i] ? lc.f_.one() : lc.f_.zero());
      }
      nx = lc.konst(h.nx);
      ny = lc.konst(h.ny);
      for (size_t i = 0; i < 64 * kShaBlocks; ++i) {
        n_bytes[i] = lc.vbit8(h.sha_in[i]);
      }
      h2c.set(lc, h.h2c);
      mul_h.zinv = lc.konst(h.mul_h.zinv);
      mul_n.zinv = lc.konst(h.mul_n.zinv);
      sha_numb = lc.vbit8(h.sha_numb);
      BitPluckerEncoder<Field, kShaPluckerSize> enc(lc.f_);
      for (size_t b = 0; b < kShaBlocks; ++b) {
        for (size_t k = 0; k < 48; ++k)
          sha_bw[b].outw[k] = lc.konst(enc.mkpacked_v32(h.sha_bw[b].outw[k]));
        for (size_t k = 0; k < 64; ++k) {
          sha_bw[b].oute[k] = lc.konst(enc.mkpacked_v32(h.sha_bw[b].oute[k]));
          sha_bw[b].outa[k] = lc.konst(enc.mkpacked_v32(h.sha_bw[b].outa[k]));
        }
        for (size_t k = 0; k < 8; ++k)
          sha_bw[b].h1[k] = lc.konst(enc.mkpacked_v32(h.sha_bw[b].h1[k]));
      }
    }

    static void fill(DenseFiller<Field>& filler, const Field& F,
                     const OprfBlindWitness<Field, kRnokppBytes>& h) {
      // rnokpp bytes.
      for (size_t i = 0; i < kRnokppBytes; ++i) {
        uint8_t b = h.rnokpp[i];
        for (size_t k = 0; k < 8; ++k)
          filler.push_back((b >> k) & 1 ? F.one() : F.zero());
      }
      // shared r bits (MSB->LSB) -- from mul_h (== mul_n).
      for (size_t i = 0; i < kBits; ++i) {
        filler.push_back(h.mul_h.bits[i] ? F.one() : F.zero());
      }
      filler.push_back(h.nx);
      filler.push_back(h.ny);
      for (size_t i = 0; i < 64 * kShaBlocks; ++i) {
        uint8_t b = h.sha_in[i];
        for (size_t k = 0; k < 8; ++k)
          filler.push_back((b >> k) & 1 ? F.one() : F.zero());
      }
      H2C::Witness::fill(filler, F, h.h2c);
      filler.push_back(h.mul_h.zinv);
      filler.push_back(h.mul_n.zinv);
      // sha_numb byte.
      for (size_t k = 0; k < 8; ++k)
        filler.push_back((h.sha_numb >> k) & 1 ? F.one() : F.zero());
      BitPluckerEncoder<Field, kShaPluckerSize> enc(F);
      for (size_t b = 0; b < kShaBlocks; ++b) {
        for (size_t k = 0; k < 48; ++k)
          filler.push_back(enc.mkpacked_v32(h.sha_bw[b].outw[k]));
        for (size_t k = 0; k < 64; ++k) {
          filler.push_back(enc.mkpacked_v32(h.sha_bw[b].oute[k]));
          filler.push_back(enc.mkpacked_v32(h.sha_bw[b].outa[k]));
        }
        for (size_t k = 0; k < 8; ++k)
          filler.push_back(enc.mkpacked_v32(h.sha_bw[b].h1[k]));
      }
    }
  };

  explicit OprfBlind(const LogicCircuit& lc)
      : lc_(lc),
        h2c_(lc),
        smul_(lc, p256, n256_order),
        sha_(lc) {
    c256_ = lc.f_.of_scalar(256);
  }

  // Prove the OPRF block.  Public inputs: Y = (Yx, Yy).  Public outputs:
  // M = (Mx, My) and s = 32 SHA bytes.
  void blind(const Witness& w, EltW Yx, EltW Yy, EltW& Mx, EltW& My,
             v8 s_out[32]) const {
    uint8_t dst[kDstBytes];
    for (size_t i = 0; i < kDstBytes; ++i)
      dst[i] = static_cast<uint8_t>(kHashToCurveProdDst[i]);

    // 1) H = H2C(rnokpp).
    EltW Hx, Hy;
    h2c_.hash_to_curve(w.rnokpp, dst, w.h2c, Hx, Hy);

    // 2) Build the two sub-mul witnesses, SHARING the one r bit array.
    typename SMul::Witness wmh, wmn;
    for (size_t i = 0; i < kBits; ++i) {
      wmh.bits[i] = w.r_bits[i];  // shared r
      wmn.bits[i] = w.r_bits[i];  // SAME wires -> binding
    }
    wmh.zinv = w.mul_h.zinv;
    wmn.zinv = w.mul_n.zinv;

    // 3) M = r * H  (public output).
    smul_.mul(Hx, Hy, wmh, Mx, My);

    // 4) R = r * N ; assert R == Y.
    EltW Rx, Ry;
    smul_.mul(w.nx, w.ny, wmn, Rx, Ry);
    lc_.assert_eq(Rx, Yx);
    lc_.assert_eq(Ry, Yy);

    // 5) Bind N's SHA byte wires to (Nx, Ny): big-endian Horner recomposition.
    EltW nx_rec = bytes_be_to_field(&w.n_bytes[0]);
    EltW ny_rec = bytes_be_to_field(&w.n_bytes[32]);
    lc_.assert_eq(nx_rec, w.nx);
    lc_.assert_eq(ny_rec, w.ny);

    // 6) s = SHA256(N.x || N.y).  Build the public-output target wires from the
    //    witnessed final-block hash, assert the SHA relation against them, then
    //    expose them as s_out.
    v256 target;
    // sha_bw[numb-1].h1 holds the digest words; with a fixed 64-byte preimage
    // numb is constant (kShaBlocks).  Pack big-endian into the v256 the way
    // assert_hash expects: hash byte i lands at indices (31-i)*8 + bit.
    BitPlucker<LogicCircuit, kShaPluckerSize> bp(lc_);
    typename FlatSha::v32 digest[8];
    for (size_t j = 0; j < 8; ++j) {
      digest[j] = bp.unpack_v32(w.sha_bw[kShaBlocks - 1].h1[j]);
    }
    for (size_t j = 0; j < 8; ++j) {
      for (size_t k = 0; k < 32; ++k) {
        target[(7 - j) * 32 + k] = digest[j][k];
      }
    }
    sha_.assert_message_hash(kShaBlocks, w.sha_numb, w.n_bytes, target,
                             w.sha_bw);

    // Expose s as 32 big-endian bytes: hash word j (big-endian) -> bytes
    // 4j..4j+3, MSB first.  digest[j] is a little-endian bit v32 (bit b = 2^b).
    for (size_t j = 0; j < 8; ++j) {
      for (size_t byte = 0; byte < 4; ++byte) {
        // big-endian byte `byte` of word j = bits [ (3-byte)*8 .. +7 ].
        for (size_t bit = 0; bit < 8; ++bit) {
          s_out[j * 4 + byte][bit] = digest[j][(3 - byte) * 8 + bit];
        }
      }
    }
  }

 private:
  // Horner over 32 big-endian byte wires: acc = acc*256 + byte, MSB first.
  EltW bytes_be_to_field(const v8 bytes[/*32*/]) const {
    EltW acc = lc_.konst(lc_.f_.zero());
    for (size_t i = 0; i < 32; ++i) {
      acc = lc_.add(lc_.mul(c256_, acc), byte_to_elt(bytes[i]));
    }
    return acc;
  }

  EltW byte_to_elt(const v8& b) const {
    EltW acc = lc_.konst(lc_.f_.zero());
    Elt p = lc_.f_.one();
    for (size_t i = 0; i < 8; ++i) {
      acc = lc_.axpy(acc, p, lc_.eval(b[i]));
      p = lc_.f_.addf(p, p);
    }
    return acc;
  }

  const LogicCircuit& lc_;
  H2C h2c_;
  SMul smul_;
  FlatSha sha_;
  Elt c256_;
};

}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_OPRF_OPRF_BLIND_H_
