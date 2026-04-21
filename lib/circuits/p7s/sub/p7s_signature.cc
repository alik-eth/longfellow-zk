// Copyright 2026 Oleksandr Vovkotrub. Apache-2.0.
//
// Task 29 (25b): the 25a compile-time sentinel is GONE — the MAC-bound
// value is now `e = SHA-256(cert_tbs)`, computed in the hash circuit
// and derived on the sig side from the same 32 digest bytes. There is
// nothing left to define in this translation unit; the class
// `P7sSignature` lives entirely in the header, and the trust-anchor
// root pubkey (TestAnchorA post-#43a; symbol names kept as
// `kDiiaRootPk{X,Y}_decimal` to minimize cross-file churn) is a
// compile-time string constant wired directly via
// `p256_base.of_string(kDiiaRootPkX_decimal)` at circuit-build time.
//
// The file is kept (rather than deleted) so the CMakeLists.txt entry
// added in 25a continues to resolve, and so future invariant-2a work
// has a place to put sig-side witness helpers alongside the header
// without re-touching build files.

#include "circuits/p7s/sub/p7s_signature.h"

namespace proofs {
namespace p7s {
// (intentionally empty — see comment above)
}  // namespace p7s
}  // namespace proofs
