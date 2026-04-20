// Copyright 2026 Oleksandr Vovkotrub. Apache-2.0.
//
// ByteRangeEq — assert bytewise equality of two v8 ranges of equal length.
//
// Composed from Logic::vassert_eq on each byte. Reused across Phase 2a
// invariants whose JSON fields are byte-slices of signed_content:
//   4.  pk              — 130 hex chars
//   5.  nonce           — 64 hex chars
//   6.  context         — variable
//   10. declaration     — variable (vs a whitelisted phrase)
//   2b. messageDigest   — 32 bytes of SHA-256(signed_content) inside signedAttrs
//
// The sub/ templated-class pattern follows MdocHash in
// lib/circuits/mdoc/mdoc_hash.h — all constraint gadgets live in headers
// so the generator (run at circuit-build time) can instantiate them over
// `LogicCircuit` (compiler backend) and the witness filler (off-circuit)
// can instantiate them over the evaluator backend in tests, if needed.

#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_P7S_SUB_BYTE_RANGE_EQ_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_P7S_SUB_BYTE_RANGE_EQ_H_

#include <cstddef>

namespace proofs {
namespace p7s {

template <class LC>
class ByteRangeEq {
 public:
  using v8 = typename LC::v8;

  explicit ByteRangeEq(const LC& l) : l_(l) {}

  // Assert a[0..n] == b[0..n] bytewise.
  void assert_eq(const v8 a[], const v8 b[], size_t n) const {
    for (size_t i = 0; i < n; ++i) {
      l_.vassert_eq(a[i], b[i]);
    }
  }

 private:
  const LC& l_;
};

}  // namespace p7s
}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_P7S_SUB_BYTE_RANGE_EQ_H_
