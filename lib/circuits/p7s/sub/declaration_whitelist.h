// Copyright 2026 Oleksandr Vovkotrub. Apache-2.0.
//
// DeclarationWhitelist — invariant 10: the JSON "declaration" field inside
// signed_content is one of a compile-time-fixed set of accepted phrases.
//
// v1 scope (N = 1): a single entry — the verbatim Ukrainian DIIA QKB
// declaration text in English translation. The length is known at circuit
// compile time (510 ASCII bytes, byte-counted with `wc -c` on the
// `"declaration"` JSON value after stripping the trailing newline).
//
// v2+ extension (documented, not implemented):
//   To support N > 1, replace the single `assert_eq` call with an OR
//   reduction over N byte_range_eq assertions, following the pattern in
//   mdoc/predicate_gadgets.h::assert_set_member (lor over all-match
//   bitmasks). For v1 with N = 1, a plain byte_range_eq against the
//   single whitelist entry is tighter and simpler.

#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_P7S_SUB_DECLARATION_WHITELIST_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_P7S_SUB_DECLARATION_WHITELIST_H_

#include <cstddef>
#include <cstdint>

namespace proofs {
namespace p7s {

// Fixed byte length of the sole v1 whitelist entry. Matches the output of
//   python3 -c 'print(len(open(...).read().split(b"\"declaration\":\"")[1]
//                       .split(b"\",\"")[0]))'
// on both `binding.qkb.p7s` and `admin-binding.qkb.p7s` fixtures.
constexpr size_t kDeclarationLen = 510;

// The whitelist (N = 1 for v1). Defined in declaration_whitelist.cc so
// it's a single shared symbol (avoids duplication across translation units
// that include this header).
extern const uint8_t kDeclarationPhrase[kDeclarationLen];

}  // namespace p7s
}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_P7S_SUB_DECLARATION_WHITELIST_H_
