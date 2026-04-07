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

#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_MDOC_MDOC_HASH_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_MDOC_MDOC_HASH_H_

#include <cstddef>
#include <cstdint>
#include <vector>

#include "circuits/cbor_parser/cbor_byte_decoder.h"
#include "circuits/logic/bit_plucker.h"
#include "circuits/logic/memcmp.h"
#include "circuits/logic/routing.h"
#include "circuits/mdoc/mdoc_constants.h"
#include "circuits/sha/flatsha256_circuit.h"

namespace proofs {

static constexpr size_t kSHAPluckerBits = 4u;

// This class (only) verifies the hashing and pseudo-parsing of an mdoc.
// Specifically, it checks
//   (a) the hash of the mdoc matches its mac.
//   (b) the values dpk_{x,y} appear in approximate cbor form, and their macs
//       match the expected values
//   (c) validFrom, validUntil appear in approximate cbor form, and that
//         validFrom <= now <= validUntil
//   (d) For each expected attribute, there exists a preimage to a sha hash
//       that appears in the mso, the preimage is approximately cbor formatted,
//       and the preimage includes the expected attribute id and value.
template <class LogicCircuit, class Field>
class MdocHash {
  using BitW = typename LogicCircuit::BitW;
  using v8 = typename LogicCircuit::v8;
  using v32 = typename LogicCircuit::v32;
  using v64 = typename LogicCircuit::v64;
  using v256 = typename LogicCircuit::v256;

  using vind = typename LogicCircuit::template bitvec<kCborIndexBits>;

  using Flatsha = FlatSHA256Circuit<LogicCircuit,
                                    BitPlucker<LogicCircuit, kSHAPluckerBits>>;
  using ShaBlockWitness = typename Flatsha::BlockWitness;
  using sha_packed_v32 = typename Flatsha::packed_v32;

 public:
  // These structures mimic the similarly named structures in Witness, but
  // their members are circuit wire objects instead of size_t.
  struct OpenedAttribute {
    v8 attr[32]; /* 32b representing attribute name in be. */
    v8 v1[64];   /* 64b of attribute value */
    // NOTE: although these arrays are sized {32,64}, other aspects of the
    // system constrain the sum of the elementIdentifier and elementValue to be
    // at most 56 bytes for a proof to succeed.  We will maintain this API, but
    // publish the constraint about the sum in the documentation.
    v8 len;      /* public length of the encoded attribute id */
    v8 vlen;     /* public length of the encoded attribute value */
    void input(const LogicCircuit& lc) {
      for (size_t j = 0; j < 32; ++j) {
        attr[j] = lc.template vinput<8>();
      }
      for (size_t j = 0; j < 64; ++j) {
        v1[j] = lc.template vinput<8>();
      }
      len = lc.template vinput<8>();
      vlen = lc.template vinput<8>();
    }
  };
  struct CborIndex {
    vind k;
    void input(const LogicCircuit& lc) {
      k = lc.template vinput<kCborIndexBits>();
    }
  };

  struct AttrShift {
    vind offset;
    vind len;
    void input(const LogicCircuit& lc) {
      offset = lc.template vinput<kCborIndexBits>();
      len = lc.template vinput<kCborIndexBits>();
    }
  };

  struct SaltedHash {
    vind i1, i2, i3;
    vind l[4];
    v8 perm;
    void input(const LogicCircuit& lc) {
      i1 = lc.template vinput<kCborIndexBits>();
      i2 = lc.template vinput<kCborIndexBits>();
      i3 = lc.template vinput<kCborIndexBits>();
      for (size_t j = 0; j < 4; ++j) {
        l[j] = lc.template vinput<kCborIndexBits>();
      }
      perm = lc.template vinput<8>();
    }
  };

  class Witness {
   public:
    v8 in_[64 * kMaxSHABlocks]; /* input bytes, 64 * MAX */

    v8 nb_; /* index of sha block that contains the real hash  */
    ShaBlockWitness sig_sha_[kMaxSHABlocks];

    std::vector<std::vector<ShaBlockWitness>> attr_sha_;
    std::vector<std::vector<v8>> attrb_;

    CborIndex valid_from_, valid_until_;
    CborIndex dev_key_info_;
    CborIndex value_digests_;
    std::vector<CborIndex> attr_mso_;
    std::vector<AttrShift> attr_ei_;
    std::vector<AttrShift> attr_ev_;
    std::vector<SaltedHash> salted_hashes_;
    size_t num_attr_;

    // Nullifier witness: 1-block SHA-256 input (64 bytes) + block witness
    v8 nullifier_in_[64];
    ShaBlockWitness nullifier_bw_;

    // Holder binding witness: SHA-256(first_attr_v1[0..31]), 1 block
    v8 binding_in_[64];
    ShaBlockWitness binding_bw_;

    // Identity escrow: SHA-256(escrow_fields[0..255]), 5 blocks (256 data + padding)
    v8 escrow_in_[256];  // 8 × 32-byte fields concatenated
    ShaBlockWitness escrow_bw_[5];  // 5 SHA-256 blocks

    explicit Witness(size_t num_attr) {
      num_attr_ = num_attr;
      attr_mso_.resize(num_attr);
      attr_ei_.resize(num_attr);
      attr_ev_.resize(num_attr);
      attr_sha_.resize(num_attr);
      salted_hashes_.resize(num_attr);
      for (size_t i = 0; i < num_attr; ++i) {
        attr_sha_[i].resize(2);
      }

      attrb_.resize(num_attr);
    }

    void input(const LogicCircuit& lc) {
      nb_ = lc.template vinput<8>();

      // sha input init =========================
      for (size_t i = 0; i + kCose1PrefixLen < 64 * kMaxSHABlocks; ++i) {
        in_[i] = lc.template vinput<8>();
      }
      for (size_t j = 0; j < kMaxSHABlocks; j++) {
        sig_sha_[j].input(lc);
      }

      valid_from_.input(lc);
      valid_until_.input(lc);
      dev_key_info_.input(lc);
      value_digests_.input(lc);

      // Attribute opening witnesses
      for (size_t ai = 0; ai < num_attr_; ++ai) {
        for (size_t i = 0; i < 64 * 2; ++i) {
          attrb_[ai].push_back(lc.template vinput<8>());
        }
        for (size_t j = 0; j < 2; j++) {
          attr_sha_[ai][j].input(lc);
        }
        attr_mso_[ai].input(lc);
        attr_ei_[ai].input(lc);
        attr_ev_[ai].input(lc);
        salted_hashes_[ai].input(lc);
      }

      // Nullifier witness
      for (size_t i = 0; i < 64; ++i) {
        nullifier_in_[i] = lc.template vinput<8>();
      }
      nullifier_bw_.input(lc);

      // Holder binding witness
      for (size_t i = 0; i < 64; ++i) {
        binding_in_[i] = lc.template vinput<8>();
      }
      binding_bw_.input(lc);

      // Escrow witness: 256 bytes (8 × 32-byte fields) + 5 block witnesses
      for (size_t i = 0; i < 256; ++i) {
        escrow_in_[i] = lc.template vinput<8>();
      }
      for (size_t j = 0; j < 5; ++j) {
        escrow_bw_[j].input(lc);
      }
    }
  };

  explicit MdocHash(const LogicCircuit& lc)
      : lc_(lc), sha_(lc), r_(lc), cb_(lc) {}

  void assert_valid_hash_mdoc(OpenedAttribute oa[/* NUM_ATTR */],
                              const v8 now[/*20*/],
                              const v8 contract_hash[/*8*/],
                              const v256& nullifier_target,
                              const v256& binding_target,
                              const v256& escrow_target,
                              const v256& e,
                              const v256& dpkx, const v256& dpky,
                              const Witness& vw) const {
    auto preimage = construct_signature_preimage(vw);
    lc_.vassert_is_bit(vw.nb_);
    lc_.vleq(vw.nb_, kMaxSHABlocks);
    sha_.assert_message_hash(kMaxSHABlocks, vw.nb_, preimage.data(), e,
                             vw.sig_sha_);

    // Find the length of the MSO in bytes. Use this to range check each index.
    v64 len = sha_.find_len(kMaxSHABlocks, preimage.data(), vw.nb_);

    // Shift a portion of the MSO into buf and check it.
    const v8 zz = lc_.template vbit<8>(0);  // cannot appear in strings
    std::vector<v8> cmp_buf(kMaxMsoLen);
    const Memcmp<LogicCircuit> CMP(lc_);

    // In the shifting below, the +5 corresponds to the prefix
    // D8 18 <len2> prefix of the mso that we want to skip parsing.
    // The +2 corresponds to the length.

    // validFrom <= now
    check_index(vw.valid_from_.k, len);
    r_.shift(vw.valid_from_.k, kValidFromLen + kDateLen, &cmp_buf[0],
             kMaxMsoLen, vw.in_ + 5 + 2, zz, /*unroll=*/3);
    assert_bytes_at(kValidFromLen, &cmp_buf[0], kValidFromCheck);
    auto cmp = CMP.leq(kDateLen, &cmp_buf[kValidFromLen], &now[0]);
    lc_.assert1(cmp);

    // now <= validUntil
    check_index(vw.valid_until_.k, len);
    r_.shift(vw.valid_until_.k, kValidUntilLen + kDateLen, &cmp_buf[0],
             kMaxMsoLen, vw.in_ + 5 + 2, zz, /*unroll=*/3);
    assert_bytes_at(kValidUntilLen, &cmp_buf[0], kValidUntilCheck);
    cmp = CMP.leq(kDateLen, &now[0], &cmp_buf[kValidUntilLen]);
    lc_.assert1(cmp);

    // DPK_{x,y}
    check_index(vw.dev_key_info_.k, len);
    r_.shift(vw.dev_key_info_.k, kDeviceKeyInfoLen + 3 + 32 + 32, &cmp_buf[0],
             kMaxMsoLen, vw.in_ + 5 + 2, zz, /*unroll=*/3);
    assert_bytes_at(kDeviceKeyInfoLen, &cmp_buf[0], kDeviceKeyInfoCheck);
    uint8_t dpkyCheck[] = {0x22, 0x58, 0x20};
    assert_bytes_at(sizeof(dpkyCheck), &cmp_buf[65], dpkyCheck);

    assert_key(dpkx, &cmp_buf[kPkxInd]);
    assert_key(dpky, &cmp_buf[kPkyInd]);

    // Nullifier: SHA-256(e || contract_hash) == nullifier_target
    assert_nullifier(e, contract_hash, nullifier_target, vw);

    // Holder binding: SHA-256(oa[0].v1[0..31]) == binding_target
    assert_binding(oa[0], binding_target, vw);

    // Identity escrow: SHA-256(escrow_fields[0..255]) == escrow_target
    assert_escrow_digest(escrow_target, vw);

    // Attributes parsing
    // valueDigests, ignore byte 13 \in {A1,A2} representing map size.
    check_index(vw.value_digests_.k, len);
    r_.shift(vw.value_digests_.k, kValueDigestsLen, cmp_buf.data(), kMaxMsoLen,
             vw.in_ + 5 + 2, zz, /*unroll=*/3);
    assert_bytes_at(13, &cmp_buf[0], kValueDigestsCheck);

    // Attributes: Equality of hash with MSO value.

    for (size_t ai = 0; ai < vw.num_attr_; ++ai) {
      // Recall that the MSO contains a hash value e2 where
      //   e2 = hash( cbor.bstr( IssuerSignedItem ))
      // and IssuerSignedItem is a CBOR structure defined as:
      // IssuerSignedItem = {
      //     "digestID" : uint,
      //     "random" : bstr,
      //     "elementIdentifier" : DataElementIdentifier,
      //     "elementValue" : DataElementValue };
      // The order of the elements in the IssuerSignedItem is not specified.
      //
      // The constraints below verify the following:
      //     1. the index attr_mso_[ai].k < len(mso)
      //     2. a 32-byte cbor array e2 occurs at index attr_mso_[ai].k in mso
      //     -- attrb_[ai] is a SHA-256 length-padded 128-byte witness array
      //     3. e2 = hash(attrb_[ai].data())
      //     4. sl is the length of attrb_[ai] as per the SHA-256 padding rule
      //     5. The attrb_[ai] array is well-formed cbor that includes the
      //        expected elementIdentifier, and elementValue fields as per the
      //        public oa[ai] argument.
      check_index(vw.attr_mso_[ai].k, len);
      r_.shift(vw.attr_mso_[ai].k, 2 + 32, &cmp_buf[0], kMaxMsoLen,
               vw.in_ + 5 + 2, zz, /*unroll=*/3);

      // 2. Basic CBOR check of the Tag
      assert_bytes_at(2, &cmp_buf[0], kTag32);

      v256 mm;
      // The loop below accounts for endian and v256 vs v8 types.
      for (size_t j = 0; j < 256; ++j) {
        mm[j] = cmp_buf[2 + (255 - j) / 8][(j % 8)];
      }
      lc_.vassert_is_bit(mm);

      // 3. Check the hash matches the value in the witness.
      auto two = lc_.template vbit<8>(2);
      sha_.assert_message_hash(2, two, vw.attrb_[ai].data(), mm,
                               vw.attr_sha_[ai].data());

      // 4. Check the length of the witness.
      v64 salted_len = sha_.find_len(2, vw.attrb_[ai].data(), two);

      // 5. Check the attribute is well-formed and matches the public argument.
      assert_attribute(128, vw.attrb_[ai].data(), vw.salted_hashes_[ai], oa[ai],
                       salted_len);
    }
  }

 private:
  std::vector<v8> construct_signature_preimage(const Witness& vw) const {
    std::vector<v8> bbuf(64 * kMaxSHABlocks);
    for (size_t i = 0; i < 64 * kMaxSHABlocks; ++i) {
      if (i < kCose1PrefixLen) {
        lc_.bits(8, bbuf[i].data(), kCose1Prefix[i]);
      } else {
        bbuf[i] = vw.in_[i - kCose1PrefixLen];
      }
    }
    return bbuf;
  }

  vind extract_vind(const v64& len) const {
    auto low = lc_.template slice<0, 3>(len);
    auto mid = lc_.template slice<3, 3 + kCborIndexBits>(len);
    auto hi = lc_.template slice<3 + kCborIndexBits, 64>(len);
    // Because check_index is called on several indices, the following two
    // checks will be called several times. However, the compiler removes
    // redundant checks, and it is convenient to verify the ranges in one
    // function. An alternative would be to verify the low 3 bits of len
    // and upper 40+ bits of len are 0, and then rely on that invariant in
    // this method, but that separates the logic, and this is easier to audit.
    lc_.vassert0(low);
    lc_.vassert0(hi);
    return mid;
  }

  // Checks that the index is less than the length. The len is given as bits
  // in a v64 in big endian order, and the index is given as a byte index.
  void check_index(const vind& index, const v64& len) const {
    lc_.vassert_is_bit(index);
    auto mid = extract_vind(len);
    lc_.assert1(lc_.vlt(index, mid));
  }

  void assert_bytes_at(size_t len, const v8 buf[/*>=len*/],
                       const uint8_t want[/*len*/]) const {
    for (size_t i = 0; i < len; ++i) {
      auto want_i = lc_.template vbit<8>(want[i]);
      lc_.vassert_eq(buf[i], want_i);
    }
  }

  void format_element(v8 buf[/*max*/], size_t max,
                      const uint8_t prefix[/*prefix_len*/], size_t prefix_len,
                      const v8 str[/*str_len*/], size_t str_len) const {
    for (size_t i = 0; i < max; ++i) {
      buf[i] = lc_.template vbit<8>(0);
    }
    for (size_t i = 0; i < prefix_len; ++i) {
      buf[i] = lc_.template vbit<8>(prefix[i]);
    }
    for (size_t i = 0; i < str_len && prefix_len + i < max; ++i) {
      buf[prefix_len + i] = str[i];
    }
  }

  // This function verifies that the length of a cbor key-value pair in an array
  // matches the claimed length.
  //    key_len: the length of the key with its header byte included.
  //    val_hdr_index: the index of the value's cbor header
  //                   byte in the buffer.
  //    atom:  true if the value is an atom, e.g., the digestID.
  //           false it is a string or array.
  void check_cbor_length(const v8 buf[/*max*/], size_t max,
                         const vind& expected_len, size_t val_hdr_index,
                         bool atom = false) const {
    // The length of a key-value field for a known key will be:
    // len(encoding of key) + len(key) + len(header of value) + len(value)

    auto cbor = cb_.decode_one_v8(buf[val_hdr_index]);
    lc_.assert0(cbor.invalid);

    vind l1 = lc_.template vbit<kCborIndexBits>(0),  // len of value
        l2 = lc_.template vbit<kCborIndexBits>(0);   // len of header of value
    vind one = lc_.template vbit<kCborIndexBits>(1),
         two = lc_.template vbit<kCborIndexBits>(2);
    if (!atom) {
      // Mux the length of the value into l1.
      // In this case, the value is either encoded in the last 5 bits of the
      // header byte, or in the next byte.  The array length is < 256 by
      // external constraints, and thus its length is in 1 or 2 bytes.
      for (size_t j = 0; j < 8; ++j) {
        l1[j] = lc_.mux(cbor.length_plus_next_v8, buf[val_hdr_index + 1][j],
                        j < 5 ? buf[val_hdr_index][j] : lc_.bit(0));
      }
      lc_.vmux(cbor.length_plus_next_v8, l2, two, one);
    } else {
      // For atoms, the value length is zero. The header length is 1,2,3, or 5
      // because the digestID is constrained to be < 2^31 [18013-5, 9.1.2.4].
      lc_.assert0(cbor.count27);
      l2[2] = cbor.count26;
      l2[1] = lc_.lor(cbor.count24, cbor.count25);
      l2[0] = lc_.lnot(cbor.count24);
    }

    // Compute the read length.
    vind k_len = lc_.template vbit<kCborIndexBits>(val_hdr_index);
    vind v_len = lc_.template vadd<kCborIndexBits>(l1, l2);
    lc_.assert_sum(kCborIndexBits, expected_len.data(), k_len.data(),
                   v_len.data());
  }

  // assert_attribute checks that the bytes in buf correspond to a valid
  // cbor structure that encodes the OpenedAttribute oa.
  void assert_attribute(size_t max, const v8 buf[/*max*/], const SaltedHash& sh,
                        const OpenedAttribute& oa,
                        const v64& salted_len) const {
    // Perform a cbor parsing of the buffer, which is expected to be
    // a 4-element key-value array consisting of keys digestId, random,
    // elementIdentifier, and elementValue. Then perform a check on the
    // last two.  The complexity of check stems from the fact that the 4 pairs
    // can occur in any order.
    // The prover provides the following witnesses in SaltedHash:
    // -- (5, l0), (i1, l1), (i2, l2), (i3, l3)
    //    where li is the length of the i-th element in bytes.
    // -- j7j6 j5j4 j3j2 j1j0 where ji \in {0,1}, and
    //    j1j0: specifies the index in the previous array of digestId
    //    j3j2: specifies the index in the previous array of random
    //    j5j4: specifies the index in the previous array of elementIdentifier
    //    j7j6: specifies the index in the previous array of elementValue

    // Verify the cbor prefix for IssuerSignedItem.
    static const uint8_t cbor_tag[] = {0xD8, 0x18, 0x58};
    static const uint8_t cbor_array[] = {0xA4};
    assert_bytes_at(3, buf, cbor_tag);
    assert_bytes_at(1, &buf[4], cbor_array);

    // Verify all of the indices and lengths are contiguous and consistent.
    vind five = lc_.template vbit<kCborIndexBits>(5);
    vind tot = extract_vind(salted_len);
    lc_.assert_sum(kCborIndexBits, sh.i1.data(), five.data(), sh.l[0].data());
    lc_.assert_sum(kCborIndexBits, sh.i2.data(), sh.i1.data(), sh.l[1].data());
    lc_.assert_sum(kCborIndexBits, sh.i3.data(), sh.i2.data(), sh.l[2].data());
    lc_.assert_sum(kCborIndexBits, tot.data(), sh.i3.data(), sh.l[3].data());

    // Verify expected structure of the salted hash cbor array.
    vind shift, len;
    const size_t MAX_BUF = 119;
    v8 got[MAX_BUF];  // Max buffer length for a 2-block SHA hash.
    const v8 zz = lc_.template vbit<8>(0);  // cannot appear in strings

    // Shift each of the 4 fields into place, and perform consistency checks.
    // "digestID" checks the cbor key and consistency with the total length.
    mux_offset(0, shift, len, sh);
    r_.shift(shift, MAX_BUF, got, max, buf, zz, 3);
    assert_bytes_at(kDigestLen, &got[0], kDigestID);
    check_cbor_length(got, MAX_BUF, len, 9, true);

    // "random" checks the cbor key and consistency with the total length.
    mux_offset(1, shift, len, sh);
    r_.shift(shift, MAX_BUF, got, max, buf, zz, 3);
    assert_bytes_at(kRandomLen, &got[0], kRandomID);
    check_cbor_length(got, MAX_BUF, len, 7);

    const size_t MAX_EI =
        1 + 17 + 32;  // The 32/64 includes len of any headers.
    const size_t MAX_EV = 1 + 12 + 64;
    v8 want_ei[MAX_EI], want_ev[MAX_EV];
    uint8_t ei_bytes[] = {0x60 + 17, 'e', 'l', 'e', 'm', 'e', 'n', 't', 'I',
                          'd',       'e', 'n', 't', 'i', 'f', 'i', 'e', 'r'};
    uint8_t ev_bytes[] = {0x60 + 12, 'e', 'l', 'e', 'm', 'e', 'n',
                          't',       'V', 'a', 'l', 'u', 'e'};
    format_element(want_ei, MAX_EI, ei_bytes, sizeof(ei_bytes), oa.attr, 32);
    format_element(want_ev, MAX_EV, ev_bytes, sizeof(ev_bytes), oa.v1, 64);

    // "elementIdentifier" checks the full cbor key-value, because it is public.
    mux_offset(2, shift, len, sh);
    r_.shift(shift, MAX_BUF, got, max, buf, zz, 3);
    for (size_t j = 0; j < MAX_EI; ++j) {
      auto ll = lc_.vlt(j, oa.len);
      for (size_t i = 0; i < 8; ++i) {
        auto same = lc_.eq(1, &got[j][i], &want_ei[j][i]);
        lc_.assert_implies(ll, same);
      }
    }
    v8 tmp;
    std::copy(len.begin(), len.begin() + 8, tmp.begin());  // cast vind into v8.
    lc_.vassert_eq(tmp, oa.len);

    // "elementValue" — verification type is packed in vlen bits 6-7.
    // Bits 0-5: actual value length (max 63, sufficient for 56-byte limit)
    // Bits 6-7: verification type (0=EQ, 1=LEQ, 2=GEQ, 3=NEQ)
    //
    // When type=0 (EQ): byte-for-byte equality (original behavior)
    // When type=1 (LEQ): got_value <= want_value (lexicographic)
    // When type=2 (GEQ): got_value >= want_value (lexicographic)
    // When type=3 (NEQ): got_value != want_value

    // Extract verification type (bits 6-7) and actual length (bits 0-5)
    auto vtype_bit0 = oa.vlen[6];
    auto vtype_bit1 = oa.vlen[7];
    auto has_predicate = lc_.lor(vtype_bit0, vtype_bit1);

    // Mask vlen to 6 bits: zero out bits 6-7 for length comparisons
    v8 masked_vlen;
    for (size_t i = 0; i < 6; ++i) masked_vlen[i] = oa.vlen[i];
    masked_vlen[6] = lc_.bit(0);
    masked_vlen[7] = lc_.bit(0);

    mux_offset(3, shift, len, sh);
    r_.shift(shift, MAX_BUF, got, max, buf, zz, 3);

    // Byte-for-byte equality check on elementValue (same as original for EQ)
    for (size_t j = 0; j < MAX_EV; ++j) {
      auto ll = lc_.vlt(j, masked_vlen);
      for (size_t i = 0; i < 8; ++i) {
        auto same = lc_.eq(1, &got[j][i], &want_ev[j][i]);
        // In EQ mode: require equality for all bytes
        // In predicate mode: only require equality for CBOR prefix (first 13 bytes)
        // The value bytes (j >= 13) are checked via Memcmp below
        if (j < 13) {
          lc_.assert_implies(ll, same);
        } else {
          // For value bytes: assert equality only when NOT in predicate mode
          auto eq_required = lc_.lnot(has_predicate);
          auto check = lc_.lor(lc_.lnot(ll), lc_.lor(eq_required, same));
          // When ll=1 and eq_required=1: same must be 1
          // When ll=1 and eq_required=0: always passes (predicate handles it)
          // When ll=0: always passes
          lc_.assert1(lc_.lor(lc_.lnot(ll),
                              lc_.lor(lc_.lnot(eq_required), same)));
        }
      }
    }

    // For predicate modes, compare value bytes (after 13-byte CBOR prefix)
    // using lexicographic Memcmp
    constexpr size_t EV_PREFIX = 13;
    constexpr size_t VAL_LEN = MAX_EV - EV_PREFIX;
    v8 val_got[VAL_LEN], val_want[VAL_LEN];
    for (size_t j = 0; j < VAL_LEN; ++j) {
      val_got[j] = got[EV_PREFIX + j];
      val_want[j] = want_ev[EV_PREFIX + j];
    }

    const Memcmp<LogicCircuit> VCMP(lc_);
    auto is_leq = VCMP.leq(VAL_LEN, val_got, val_want);
    auto is_geq = VCMP.leq(VAL_LEN, val_want, val_got);
    auto val_eq = lc_.land(is_leq, is_geq);

    // Type selection:
    // type 1 (bit0=1, bit1=0): LEQ — assert is_leq
    // type 2 (bit0=0, bit1=1): GEQ — assert is_geq
    // type 3 (bit0=1, bit1=1): NEQ — assert NOT val_eq
    auto is_type_leq = lc_.land(vtype_bit0, lc_.lnot(vtype_bit1));
    auto is_type_geq = lc_.land(lc_.lnot(vtype_bit0), vtype_bit1);
    auto is_type_neq = lc_.land(vtype_bit0, vtype_bit1);

    // Each type implies its condition: type_X → condition_X
    lc_.assert1(lc_.lor(lc_.lnot(is_type_leq), is_leq));
    lc_.assert1(lc_.lor(lc_.lnot(is_type_geq), is_geq));
    lc_.assert1(lc_.lor(lc_.lnot(is_type_neq), lc_.lnot(val_eq)));

    // Assert extracted length matches (using masked vlen without type bits)
    std::copy(len.begin(), len.begin() + 8, tmp.begin());  // cast vind into v8.
    lc_.vassert_eq(tmp, masked_vlen);
  }

  void mux_offset(size_t slot, vind& shift, vind& len,
                  const SaltedHash& sh) const {
    vind t[2];
    vind five = lc_.template vbit<kCborIndexBits>(5);
    lc_.vmux(sh.perm[2 * slot + 1], t[0], sh.i2, five);
    lc_.vmux(sh.perm[2 * slot + 1], t[1], sh.i3, sh.i1);
    lc_.vmux(sh.perm[2 * slot], shift, t[1], t[0]);

    lc_.vmux(sh.perm[2 * slot + 1], t[0], sh.l[2], sh.l[0]);
    lc_.vmux(sh.perm[2 * slot + 1], t[1], sh.l[3], sh.l[1]);
    lc_.vmux(sh.perm[2 * slot], len, t[1], t[0]);
  }

  // Asserts nullifier = SHA-256(e || contract_hash) where e is the 32-byte
  // big-endian MSO hash and contract_hash is 8 bytes.  The full 64-byte
  // SHA-256 block is constrained: 32 bytes e + 8 bytes contract_hash +
  // 24 bytes deterministic padding (0x80 + zeros + 0x0140 length).
  void assert_nullifier(const v256& e, const v8 contract_hash[/*8*/],
                        const v256& nullifier_target,
                        const Witness& vw) const {
    // Assert witness bytes 0..31 match e (little-endian, matching to_bytes_field).
    // e[j] = bit j%8 of e_bytes[j/8], where e_bytes is to_bytes_field output.
    for (size_t j = 0; j < 256; ++j) {
      lc_.assert_eq(vw.nullifier_in_[j / 8][j % 8], e[j]);
    }
    // Assert witness bytes 32..39 match contract_hash
    for (size_t i = 0; i < 8; ++i) {
      lc_.vassert_eq(vw.nullifier_in_[32 + i], contract_hash[i]);
    }
    // Assert deterministic SHA-256 padding for 40-byte message
    // byte 40: 0x80, bytes 41..55: 0x00, bytes 56..61: 0x00,
    // byte 62: 0x01, byte 63: 0x40  (320 bits = 0x0140)
    lc_.vassert_eq(vw.nullifier_in_[40], lc_.template vbit<8>(0x80));
    for (size_t i = 41; i < 62; ++i) {
      lc_.vassert_eq(vw.nullifier_in_[i], lc_.template vbit<8>(0x00));
    }
    lc_.vassert_eq(vw.nullifier_in_[62], lc_.template vbit<8>(0x01));
    lc_.vassert_eq(vw.nullifier_in_[63], lc_.template vbit<8>(0x40));

    // Verify SHA-256 hash of the block matches nullifier_target
    auto one = lc_.template vbit<8>(1);
    sha_.assert_message_hash(1, one, vw.nullifier_in_, nullifier_target,
                             &vw.nullifier_bw_);
  }

  // Asserts binding_hash = SHA-256(oa.v1[0..31]) where the first 32 bytes
  // of the attribute value are hashed.  The full 64-byte SHA-256 block is
  // constrained: 32 bytes value + 32 bytes deterministic padding.
  void assert_binding(const OpenedAttribute& oa, const v256& binding_target,
                      const Witness& vw) const {
    // Assert witness bytes 0..31 match first attribute's value bytes.
    // oa.v1[i] and binding_in_[i] use the same per-byte bit encoding.
    for (size_t i = 0; i < 32; ++i) {
      lc_.vassert_eq(vw.binding_in_[i], oa.v1[i]);
    }
    // Assert deterministic SHA-256 padding for 32-byte message
    // byte 32: 0x80, bytes 33..55: 0x00, bytes 56..61: 0x00,
    // byte 62: 0x01, byte 63: 0x00  (256 bits = 0x0100)
    lc_.vassert_eq(vw.binding_in_[32], lc_.template vbit<8>(0x80));
    for (size_t i = 33; i < 62; ++i) {
      lc_.vassert_eq(vw.binding_in_[i], lc_.template vbit<8>(0x00));
    }
    lc_.vassert_eq(vw.binding_in_[62], lc_.template vbit<8>(0x01));
    lc_.vassert_eq(vw.binding_in_[63], lc_.template vbit<8>(0x00));

    // Verify SHA-256 hash of the block matches binding_target
    auto one = lc_.template vbit<8>(1);
    sha_.assert_message_hash(1, one, vw.binding_in_, binding_target,
                             &vw.binding_bw_);
  }

  // Asserts escrow_digest = SHA-256(escrow_fields[0..255]) where 256 bytes
  // of credential field values (8 × 32 bytes, zero-padded) are hashed.
  // The 256-byte message requires 5 SHA-256 blocks:
  // blocks 0-3: 256 data bytes, block 4: SHA-256 padding.
  // Padding: byte 256 = 0x80, bytes 257..317 = 0x00,
  // bytes 318..319 = big-endian length 0x0800 (2048 bits).
  void assert_escrow_digest(const v256& escrow_target,
                            const Witness& vw) const {
    // Build 5-block padded message (320 bytes) for SHA-256
    v8 padded[320];

    // First 256 bytes: escrow field data from witness
    for (size_t i = 0; i < 256; ++i) {
      padded[i] = vw.escrow_in_[i];
    }

    // SHA-256 padding for 256-byte (2048-bit) message
    padded[256] = lc_.template vbit<8>(0x80);
    for (size_t i = 257; i < 318; ++i) {
      padded[i] = lc_.template vbit<8>(0x00);
    }
    // Big-endian length: 2048 = 0x0800
    padded[318] = lc_.template vbit<8>(0x08);
    padded[319] = lc_.template vbit<8>(0x00);

    // Verify SHA-256(padded) == escrow_target using 5 blocks
    auto five = lc_.template vbit<8>(5);
    sha_.assert_message_hash(5, five, padded, escrow_target,
                             vw.escrow_bw_);
  }

  // Asserts that the key is equal to the value in big-endian order in buf_be.
  void assert_key(const v256& key, const v8 buf_be[/*32*/]) const {
    v256 m;
    for (size_t i = 0; i < 256; ++i) {
      m[i] = buf_be[31 - (i / 8)][i % 8];
    }
    lc_.vassert_eq(m, key);
  }

  // The constants below define the prefix of each field that is verified
  // in the MDOC. This string matching approach is substantially faster than
  // parsing the MDOC into cbor, and its soundness analysis provides at least 96
  // bits of static security.  These constants differ from similarly named ones
  // in mdoc_constants because they include header bytes; the mdoc_constants
  // values are used for cbor parsing of the raw mdoc, whereas these are used by
  // the circuit.

  // 69 [text(9)] 76616C696446726F6D [validFrom] C0 [tag(0)] 74 [len 20]
  static constexpr uint8_t kValidFromCheck[] = {
      0x69, 0x76, 0x61, 0x6C, 0x69, 0x64, 0x46, 0x72, 0x6F, 0x6D, 0xC0, 0x74};
  static constexpr size_t kValidFromLen = sizeof(kValidFromCheck);

  // 6A [text(10)] 76616C6964556E74696C [validUntil] C0 [tag(0)] 74
  static constexpr uint8_t kValidUntilCheck[] = {0x6A, 0x76, 0x61, 0x6C, 0x69,
                                                 0x64, 0x55, 0x6E, 0x74, 0x69,
                                                 0x6C, 0xC0, 0x74};
  static constexpr size_t kValidUntilLen = sizeof(kValidUntilCheck);

  // 6D text(13) 6465766963654B6579496E666F "deviceKeyInfo"
  //   A1 map(1) 69 text(9) 6465766963654B6579 "deviceKey"
  //      A4 map(4) 01 02 20 01
  //      21 negative(1) 58 20 bytes(32)
  //      <dpkx>
  //      22 negative(2) 58 20 bytes(32)
  //      <dpky>
  static constexpr uint8_t kDeviceKeyInfoCheck[] = {
      0x6D, 0x64, 0x65, 0x76, 0x69, 0x63, 0x65, 0x4B, 0x65, 0x79, 0x49,
      0x6E, 0x66, 0x6F, 0xA1, 0x69, 0x64, 0x65, 0x76, 0x69, 0x63, 0x65,
      0x4B, 0x65, 0x79, 0xA4, 0x01, 0x02, 0x20, 0x01, 0x21, 0x58, 0x20};
  static constexpr size_t kDeviceKeyInfoLen = sizeof(kDeviceKeyInfoCheck);
  static constexpr size_t kPkxInd = kDeviceKeyInfoLen;
  static constexpr size_t kPkyInd = 68; /* 64 + 3 byte tag + 1*/

  // 6C text(12) 76616C756544696765737473  "valueDigests" A{1,2} # map(1,2)
  //     71 text(17) 6F72672E69736F2E31383031332E352E31 "org.iso.18013.5.1"
  static constexpr uint8_t kValueDigestsCheck[] = {
      0x6C, 0x76, 0x61, 0x6C, 0x75, 0x65, 0x44,
      0x69, 0x67, 0x65, 0x73, 0x74, 0x73,
  };
  static constexpr size_t kValueDigestsLen = sizeof(kValueDigestsCheck);

  static constexpr size_t kDateLen = 20;

  const LogicCircuit& lc_;
  Flatsha sha_;
  Routing<LogicCircuit> r_;
  CborByteDecoder<LogicCircuit> cb_;
};
}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_MDOC_MDOC_HASH_H_
