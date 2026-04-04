// Copyright 2026 zk-eidas contributors
// Licensed under the Apache License, Version 2.0

#ifndef CIRCUITS_MDOC_PREDICATE_GADGETS_H_
#define CIRCUITS_MDOC_PREDICATE_GADGETS_H_

#include "circuits/logic/memcmp.h"

namespace proofs {

// Predicate gadgets for zk-eidas selective disclosure.
// Operate on claim values represented as v8 byte arrays (big-endian),
// matching Longfellow's Memcmp convention.
template <class Logic>
class PredicateGadgets {
 public:
  using BitW = typename Logic::BitW;
  using v8 = typename Logic::v8;

  explicit PredicateGadgets(const Logic& l) : l_(l), cmp_(l) {}

  // Assert claim >= threshold (big-endian byte arrays, n bytes each)
  void assert_gte(size_t n, const v8 claim[], const v8 threshold[]) const {
    // claim >= threshold  <=>  threshold <= claim
    BitW ok = cmp_.leq(n, threshold, claim);
    l_.assert1(ok);
  }

  // Assert claim <= threshold
  void assert_lte(size_t n, const v8 claim[], const v8 threshold[]) const {
    BitW ok = cmp_.leq(n, claim, threshold);
    l_.assert1(ok);
  }

  // Assert claim == expected (byte-wise equality)
  void assert_eq(size_t n, const v8 claim[], const v8 expected[]) const {
    for (size_t i = 0; i < n; i++) {
      l_.vassert_eq(claim[i], expected[i]);
    }
  }

  // Assert claim != expected
  void assert_neq(size_t n, const v8 claim[], const v8 expected[]) const {
    // XOR all bytes, OR-reduce to single bit. Must be nonzero.
    BitW any_diff = l_.lnot(l_.lnot(claim[0][0]));  // dummy init
    bool first = true;
    for (size_t i = 0; i < n; i++) {
      auto diff = l_.vxor(claim[i], expected[i]);
      for (size_t j = 0; j < 8; j++) {
        if (first) {
          any_diff = diff[j];
          first = false;
        } else {
          any_diff = l_.lor(any_diff, diff[j]);
        }
      }
    }
    l_.assert1(any_diff);
  }

  // Assert low <= claim <= high
  void assert_range(size_t n, const v8 claim[], const v8 low[],
                    const v8 high[]) const {
    assert_gte(n, claim, low);
    assert_lte(n, claim, high);
  }

  // Assert claim matches at least one element in set.
  // set is a flat array of max_set * n v8 values (each element is n bytes).
  void assert_set_member(size_t n, const v8 claim[],
                         const v8 set[], size_t max_set) const {
    // For each set element: check if all n bytes match claim
    // OR the results together: at least one must match
    BitW found = l_.konst(0);
    for (size_t s = 0; s < max_set; s++) {
      BitW all_match = l_.konst(1);
      for (size_t i = 0; i < n; i++) {
        auto diff = l_.vxor(claim[i], set[s * n + i]);
        for (size_t j = 0; j < 8; j++) {
          all_match = l_.land(all_match, l_.lnot(diff[j]));
        }
      }
      found = l_.lor(found, all_match);
    }
    l_.assert1(found);
  }

 private:
  const Logic& l_;
  Memcmp<Logic> cmp_;
};

}  // namespace proofs

#endif  // CIRCUITS_MDOC_PREDICATE_GADGETS_H_
