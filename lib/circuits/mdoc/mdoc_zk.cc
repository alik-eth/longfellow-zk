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

#include "circuits/mdoc/mdoc_zk.h"

#include <stdint.h>
#include <sys/types.h>

#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <vector>

#include "algebra/convolution.h"
#include "algebra/fp2.h"
#include "algebra/reed_solomon.h"
#include "arrays/dense.h"
#include "cbor/host_decoder.h"
#include "circuits/mac/mac_reference.h"
#include "circuits/mac/mac_witness.h"
#include "circuits/mdoc/mdoc_decompress.h"
#include "circuits/mdoc/mdoc_witness.h"
#include "ec/p256.h"
#include "gf2k/gf2_128.h"
#include "gf2k/lch14_reed_solomon.h"
#include "proto/circuit.h"
#include "random/secure_random_engine.h"
#include "random/transcript.h"
#include "sumcheck/circuit.h"
#include "util/log.h"
#include "util/panic.h"
#include "util/readbuffer.h"
#include "zk/zk_proof.h"
#include "zk/zk_prover.h"
#include "zk/zk_verifier.h"
#include "zstd.h"

// The result of getHashMacIndex is derived from the circuit layout.
// It represents the location of the hash MAC wire in the hash verification
// circuit and must be updated if the public interface of the hash circuit is
// changed.
// This index is part of the public input, but it is needed so that the prover
// can commit the rest of the witness (including its portion of the MAC key),
// the verifier can then select its a_v half of the mac key, the prover can
// then compute the MAC and finally place it into the correct part of the
// dense witness array.
// ex: numAttrs = 1, this function returns (1*768 + 8) + 161
size_t getHashMacIndex(size_t numAttrs, size_t version) {
  // The length of the attribute field that is added in version 4.
  // Nullifier: 320 wires (8*8 contract_hash + 256 nullifier_target).
  // Binding: 256 wires (256 binding_target).
  return numAttrs * 8 * (96 + (version < 7 ? 1 : 2)) + 160 + 320 + 256 + 256 + 1;
}

namespace proofs {

// ======= Global typedefs for convenience ==========
// P256-related types
using N = Fp256Base::N;
using Scalar = Fp256Base::Elt;
using Elt = Fp256Base::Elt;
using f2_p256 = Fp2<Fp256Base>;
using Elt2 = f2_p256::Elt;
using FftExtConvolutionFactory = FFTExtConvolutionFactory<Fp256Base, f2_p256>;
using RSFactory_b = ReedSolomonFactory<Fp256Base, FftExtConvolutionFactory>;
using f_128 = GF2_128<>;
using gf2k = f_128::Elt;

using RSFactory = LCH14ReedSolomonFactory<f_128>;

// Root of unity for the f_p256^2 extension field.
static constexpr char kRootX[] =
    "112649224146410281873500457609690258373018840430489408729223714171582664"
    "680802";
static constexpr char kRootY[] =
    "84087994358540907695740461427818660560182168997182378749313018254450460212"
    "908";

// Magic constant 4 is derived from the circuit layout.
// It represents the location of the signature MAC wire in the signature
// verification circuit and must be updated if the public interface of the sig
// circuit is changed. This index is part of the public input, but it is needed
// so that the prover can commit the rest of the witness (including its portion
// of the MAC key), the verifier can then select its a_v half of the mac key,
// the prover can then compute the MAC and finally place it into the correct
// part of the dense witness array.
static constexpr size_t kSigMacIndex = 4;

// Flags that indicate whether the prover and/or verifier ought
// to check the circuit id stored in the circuit itself.
//
// In this particular application the ID's of the individual circuits
// are trusted, and we don't want to incur the performance cost
// of verifying the ID for every proof or verification.
//
// The larger application is expected to contain a hardcoded
// list of supported circuit IDs.  After downloading the circuit
// (or compiling it locally) the application is expected to
// check the ID once, and then store the checked circuit in
// trusted local storage.
static constexpr bool enforce_circuit_id_in_prover = false;
static constexpr bool enforce_circuit_id_in_verifier = false;

// =========== Helper methods for the main exported C functions.

// Specialization for filling the mac when using f_128.
template <>
void fill_gf2k<f_128, f_128>(const typename f_128::Elt& m,
                             DenseFiller<f_128>& df, const f_128& f) {
  df.push_back(m);
}

void compute_macs(size_t len, const Elt x[], gf2k gmacs[/* 6 */],
                  uint8_t macs[/* 2.len.gf2k_size */],
                  const gf2k ap[/* 2.len */], gf2k av) {
  // This code relies on the assumption that an Elt can be mac'ed in 2
  // gf2k elements.
  check(f_128::kBits * 2 >= Fp256Base::kBits, "Mac is not large enough");
  f_128 gf;
  MACReference<f_128> mac_ref;
  uint8_t buf[Fp256Base::kBytes];

  for (size_t i = 0; i < len; ++i) {
    p256_base.to_bytes_field(buf, x[i]);
    mac_ref.compute(&gmacs[2 * i], av, &ap[i * 2], buf);
    gf.to_bytes_field(&macs[2 * i * f_128::kBytes], gmacs[2 * i]);
    gf.to_bytes_field(&macs[(2 * i + 1) * f_128::kBytes], gmacs[2 * i + 1]);
  }
}

struct ProverState {
  Elt common[3];  //  e2, dpkx, dpky
  gf2k ap[6];     //  mac keys for the above
  using mac_witness = MacGF2Witness;
  mac_witness macs[3];
};

// Pushes a 32-byte hash digest as a v256 with the SHA-output convention
// (bit (255-j)/8 byte, j%8 LSB-first within byte).
static void push_v256_hash(DenseFiller<f_128>& hash_filler,
                           const uint8_t hash32[32], const f_128& Fs) {
  std::vector<typename f_128::Elt> v(256, Fs.zero());
  for (size_t j = 0; j < 256; ++j) {
    size_t byte_idx = (255 - j) / 8;
    size_t bit_idx = j % 8;
    v[j] = (hash32[byte_idx] >> bit_idx) & 1 ? Fs.one() : Fs.zero();
  }
  hash_filler.push_back(v);
}

// Fills the hash witness with the attributes, time, nullifier, binding,
// escrow, and v12 enroll-commit/enroll-nullifier inputs. v11 callers pass
// zero buffers for the enroll values (the resulting proof will be malformed
// because the v12 circuit asserts byte-equality with the in-circuit holder
// seed commit witness, but the build will succeed -- v11 callers exist
// solely for transitional purposes during the Plan 2 rollout).
MdocProverErrorCode fill_attributes(DenseFiller<f_128>& hash_filler,
                                    const RequestedAttribute* attrs,
                                    size_t attrs_len, const uint8_t* now,
                                    const uint8_t* contract_hash,
                                    const uint8_t* nullifier_hash,
                                    const uint8_t* binding_hash,
                                    const uint8_t* escrow_digest,
                                    const uint8_t* enroll_commit,
                                    const uint8_t* enroll_nullifier,
                                    const f_128& Fs, size_t version) {
  hash_filler.push_back(Fs.one());
  for (size_t ai = 0; ai < attrs_len; ++ai) {
    MdocProverErrorCode err =
        fill_attribute(hash_filler, attrs[ai], Fs, version);
    if (err != MDOC_PROVER_SUCCESS) {
      return err;
    }
  }
  fill_bit_string(hash_filler, now, 20, 20, Fs);

  // Nullifier public inputs: contract_hash (8 bytes) + nullifier_target (32 bytes as v256)
  fill_bit_string(hash_filler, contract_hash, 8, 8, Fs);
  push_v256_hash(hash_filler, nullifier_hash, Fs);
  // Binding target
  push_v256_hash(hash_filler, binding_hash, Fs);
  // Escrow digest target
  push_v256_hash(hash_filler, escrow_digest, Fs);
  // v12 enroll-commit public output
  push_v256_hash(hash_filler, enroll_commit, Fs);
  // v12 enroll-nullifier public output
  push_v256_hash(hash_filler, enroll_nullifier, Fs);
  return MDOC_PROVER_SUCCESS;
}

// Fills the signature witness with the public inputs pkX, pkY, and e.
void fill_signature_inputs(DenseFiller<Fp256Base>& sig_filler, const Elt& pkX,
                           const Elt& pkY, const Elt& e) {
  sig_filler.push_back(p256_base.one());
  sig_filler.push_back(pkX);
  sig_filler.push_back(pkY);
  sig_filler.push_back(e);
}

// Fills the public inputs for the hash and signature circuits.
// Empty values for the MAC inputs and AV are used.
bool fill_public_inputs(DenseFiller<Fp256Base>& sig_filler,
                        DenseFiller<f_128>& hash_filler, const Elt& pkX,
                        const Elt& pkY, const uint8_t* tr, size_t tr_len,
                        const RequestedAttribute* attrs, size_t attrs_len,
                        const uint8_t* now,
                        const uint8_t* contract_hash,
                        const uint8_t* nullifier_hash,
                        const uint8_t* binding_hash,
                        const uint8_t* escrow_digest,
                        const uint8_t* enroll_commit,
                        const uint8_t* enroll_nullifier,
                        const uint8_t* docType,
                        size_t dt_len, const gf2k macs[], gf2k av,
                        const f_128& Fs, size_t version) {
  if (fill_attributes(hash_filler, attrs, attrs_len, now, contract_hash,
                      nullifier_hash, binding_hash, escrow_digest,
                      enroll_commit, enroll_nullifier, Fs, version) !=
      MDOC_PROVER_SUCCESS) {
    return false;
  }

  for (size_t i = 0; i < 6; ++i) { /* 6 mac + 1 av */
    fill_gf2k<f_128, f_128>(macs[i], hash_filler, Fs);
  }
  fill_gf2k<f_128, f_128>(av, hash_filler, Fs);

  std::vector<uint8_t> docTypeBytes(docType, docType + dt_len);

  // The verify_ecdsa circuit requires that e2 != 0. We consider the pr that the
  // adversary produces a SHA-256 preimage of 0 to be negligible. Thus, we
  // satisfy the pre-condition here by directly computing the transcript hash
  // and assume it is not 0.
  Elt e2 = p256_base.to_montgomery(
      compute_transcript_hash<N>(tr, tr_len, &docTypeBytes));
  fill_signature_inputs(sig_filler, pkX, pkY, e2);

  for (size_t i = 0; i < 6; ++i) {
    fill_gf2k<f_128, Fp256Base>(macs[i], sig_filler, p256_base);
  }
  fill_gf2k<f_128, Fp256Base>(av, sig_filler, p256_base);
  return true;
}

// Fills the hash and signature public inputs and private witnesses.
//
// v12: holder_seed (32 bytes, MAY be null for legacy v11 callers), and
// the matching enroll_commit_out + enroll_nullifier_out (32 bytes each)
// receive the SHA-256 outputs of the new asserts. When holder_seed is
// null, the host populates the holder_seed_ scratchpad with zeros and
// fills enroll_*_out with zeros -- the resulting proof is malformed
// against the v12 circuit (byte-equality between holder_seed_commit_
// and enroll_commit_target won't hold for arbitrary public-input
// values), but the build path stays compatible during the transition.
MdocProverErrorCode fill_witness(
    DenseFiller<Fp256Base>& fill_b, DenseFiller<f_128>& fill_s,
    const uint8_t* mdoc, size_t mdoc_len, const Elt& pkX, const Elt& pkY,
    const uint8_t* tr, size_t tr_len, const RequestedAttribute* attrs,
    size_t attrs_len, const uint8_t* now,
    const uint8_t* contract_hash, uint8_t* nullifier_hash_out,
    uint8_t* binding_hash_out,
    const uint8_t escrow_fields[8][32], uint8_t* escrow_digest_out,
    const uint8_t* holder_seed,            /* nullable; 32 bytes if non-null */
    uint8_t* enroll_commit_out,            /* 32 bytes */
    uint8_t* enroll_nullifier_out,         /* 32 bytes */
    ProverState& state,
    SecureRandomEngine& rng, const f_128& Fs, size_t version) {
  using MdocHW = MdocHashWitness<P256, f_128>;
  using MdocSW = MdocSignatureWitness<P256, Fp256Scalar>;

  // Allocate these objects on the heap because Android has a small stack.
  auto hw = std::make_unique<MdocHW>(attrs_len, p256, Fs);
  auto sw = std::make_unique<MdocSW>(p256, p256_scalar, Fs);

  // Seed the host-side holder_seed scratch BEFORE compute_witness because
  // compute_witness assembles the COSE1 SHA preimage with bytes [18..50)
  // routed from holder_seed_commit_ (which compute_enroll_commit derives
  // from holder_seed_). Order: compute_enroll_commit -> compute_witness.
  if (holder_seed != nullptr) {
    memcpy(hw->holder_seed_, holder_seed, 32);
    hw->compute_enroll_commit();
  }
  // (else: holder_seed_ stays zeroed from the ctor; enroll_commit_*
  // remain zeros too -- v11 transitional path.)

  // hash public inputs — nullifier/binding filled as zeros, updated in dense later
  uint8_t zero_hash[32] = {};
  MdocProverErrorCode err =
      fill_attributes(fill_s, attrs, attrs_len, now, contract_hash,
                      zero_hash, zero_hash, zero_hash, zero_hash, zero_hash,
                      Fs, version);
  if (err != MDOC_PROVER_SUCCESS) {
    return err;
  }

  // init mac+av to 0
  for (size_t i = 0; i < 6 + 1; ++i) { /* 6 mac + 1 av */
    fill_gf2k<f_128, f_128>(Fs.zero(), fill_s, Fs);
  }

  MdocProverErrorCode ok_h = hw->compute_witness(mdoc, mdoc_len, tr, tr_len,
                                                 attrs, attrs_len, version);
  if (ok_h != MDOC_PROVER_SUCCESS) return ok_h;

  // Compute nullifier and binding after witness is ready.
  // v12 nullifier consumes holder_seed_ (set above for the v12 path,
  // zeroed for the v11 transitional path).
  hw->compute_nullifier(contract_hash);
  memcpy(nullifier_hash_out, hw->nullifier_hash_, 32);
  hw->compute_binding(attrs[0]);
  memcpy(binding_hash_out, hw->binding_hash_, 32);
  hw->compute_escrow_digest(escrow_fields);
  memcpy(escrow_digest_out, hw->escrow_digest_, 32);

  // v12 enroll-nullifier depends on e_, which compute_witness sets.
  if (holder_seed != nullptr) {
    hw->compute_enroll_nullifier();
  }
  memcpy(enroll_commit_out, hw->enroll_commit_hash_, 32);
  memcpy(enroll_nullifier_out, hw->enroll_nullifier_hash_, 32);

  MdocProverErrorCode ok_s =
      sw->compute_witness(pkX, pkY, mdoc, mdoc_len, tr, tr_len);
  if (ok_s != MDOC_PROVER_SUCCESS) return ok_s;

  // signature public inputs
  fill_signature_inputs(fill_b, pkX, pkY, sw->e2_);
  for (size_t i = 0; i < 7; ++i) {
    fill_gf2k<f_128, Fp256Base>(Fs.zero(), fill_b, p256_base);
  }

  // compute macs
  state = {.common = {hw->e_, hw->dpkx_, hw->dpky_}};
  MACReference<f_128> mac_ref;
  mac_ref.sample(state.ap, 6, &rng);

  uint8_t buf[Fp256Base::kBytes];

  Fp256Base::Elt tt[3] = {hw->e_, hw->dpkx_, hw->dpky_};
  for (size_t i = 0; i < 3; ++i) {
    p256_base.to_bytes_field(buf, tt[i]);
    sw->macs_[i].compute_witness(&state.ap[2 * i], buf);
    state.macs[i].compute_witness(&state.ap[2 * i]);
    fill_bit_string(fill_s, buf, 32, 32, Fs);
  }

  // private witnesses
  hw->fill_witness(fill_s, version);
  for (auto& mac : state.macs) {
    mac.fill_witness(fill_s);
  }

  sw->fill_witness(fill_b);

  return MDOC_PROVER_SUCCESS;
}

gf2k generate_mac_key(Transcript& t) {
  f_128 gf;
  uint8_t buf[f_128::kBytes];
  t.bytes(buf, f_128::kBytes);
  return gf.of_bytes_field(buf).value();
}

// Updates the dense input array with a mac.The location
// of the start of the macs+av inputs must be passed in as (si, hi).
void update_mac_in_dense(Dense<Fp256Base>& W_sig, Dense<f_128>& W_hash,
                         size_t& si, size_t& hi, const gf2k mac,
                         const f_128& Fs) {
  for (size_t j = 0; j < f_128::kBits; ++j) {
    W_sig.v_[si++] = mac[j] ? p256_base.one() : p256_base.zero();
  }
  W_hash.v_[hi++] = mac;
}

// Updates all macs in both dense arrays. The (si,hi) should be the index
// of the first mac in the respective dense arrays.
void update_macs(Dense<Fp256Base>& W_sig, Dense<f_128>& W_hash, size_t si,
                 size_t hi, const gf2k macs[], gf2k av, const f_128& Fs) {
  for (size_t mi = 0; mi < 6; ++mi) {
    update_mac_in_dense(W_sig, W_hash, si, hi, macs[mi], Fs);
  }
  update_mac_in_dense(W_sig, W_hash, si, hi, av, Fs);
}

// Returns the index of the nullifier public inputs (contract_hash + target)
// in the hash circuit's public input array.  Located after constant(1) +
// attributes + now(160).
size_t getNullifierIndex(size_t numAttrs, size_t version) {
  return numAttrs * 8 * (96 + (version < 7 ? 1 : 2)) + 160 + 1;
}

// Updates the nullifier public inputs in the hash dense array.
// Writes contract_hash (64 wires) + nullifier_hash as v256 (256 wires).
void update_nullifier_in_dense(Dense<f_128>& W_hash, size_t start,
                               const uint8_t contract_hash[8],
                               const uint8_t nullifier_hash[32],
                               const f_128& Fs) {
  size_t idx = start;
  // contract_hash: 8 bytes × 8 bits, LSB-first per byte
  for (size_t i = 0; i < 8; ++i) {
    for (size_t j = 0; j < 8; ++j) {
      W_hash.v_[idx++] =
          (contract_hash[i] >> j) & 1 ? Fs.one() : Fs.zero();
    }
  }
  // nullifier_hash as v256 — same encoding as fill_attributes
  for (size_t j = 0; j < 256; ++j) {
    size_t byte_idx = (255 - j) / 8;
    size_t bit_idx = j % 8;
    W_hash.v_[idx++] =
        (nullifier_hash[byte_idx] >> bit_idx) & 1 ? Fs.one() : Fs.zero();
  }
}

// Returns the index of the binding public input (after nullifier).
size_t getBindingIndex(size_t numAttrs, size_t version) {
  return getNullifierIndex(numAttrs, version) + 320;  // +320 = nullifier wires
}

// Updates the binding public input (v256) in the hash dense array.
void update_binding_in_dense(Dense<f_128>& W_hash, size_t start,
                             const uint8_t binding_hash[32],
                             const f_128& Fs) {
  size_t idx = start;
  for (size_t j = 0; j < 256; ++j) {
    size_t byte_idx = (255 - j) / 8;
    size_t bit_idx = j % 8;
    W_hash.v_[idx++] =
        (binding_hash[byte_idx] >> bit_idx) & 1 ? Fs.one() : Fs.zero();
  }
}

// Returns the index of the escrow digest public input (after binding).
size_t getEscrowDigestIndex(size_t numAttrs, size_t version) {
  return getBindingIndex(numAttrs, version) + 256;
}

// Updates the escrow digest public input (v256) in the hash dense array.
void update_escrow_digest_in_dense(Dense<f_128>& W_hash, size_t start,
                                   const uint8_t escrow_digest[32],
                                   const f_128& Fs) {
  size_t idx = start;
  for (size_t j = 0; j < 256; ++j) {
    size_t byte_idx = (255 - j) / 8;
    size_t bit_idx = j % 8;
    W_hash.v_[idx++] =
        (escrow_digest[byte_idx] >> bit_idx) & 1 ? Fs.one() : Fs.zero();
  }
}

// v12 enroll-commit public-input index (after escrow_digest).
size_t getEnrollCommitIndex(size_t numAttrs, size_t version) {
  return getEscrowDigestIndex(numAttrs, version) + 256;
}

// v12 enroll-nullifier public-input index (after enroll_commit).
size_t getEnrollNullifierIndex(size_t numAttrs, size_t version) {
  return getEnrollCommitIndex(numAttrs, version) + 256;
}

// Generic helper: writes a 32-byte hash digest as a v256 into the dense
// array starting at `start`. Same encoding as push_v256_hash.
static void update_v256_hash_in_dense(Dense<f_128>& W_hash, size_t start,
                                      const uint8_t hash32[32],
                                      const f_128& Fs) {
  size_t idx = start;
  for (size_t j = 0; j < 256; ++j) {
    size_t byte_idx = (255 - j) / 8;
    size_t bit_idx = j % 8;
    W_hash.v_[idx++] =
        (hash32[byte_idx] >> bit_idx) & 1 ? Fs.one() : Fs.zero();
  }
}

bool parsePk(const char* pkx, const char* pky, Elt& pkX, Elt& pkY) {
  auto maybe_x = p256_base.of_untrusted_string(pkx);
  auto maybe_y = p256_base.of_untrusted_string(pky);
  if (!maybe_x.has_value() || !maybe_y.has_value()) {
    return false;
  }
  pkX = maybe_x.value();
  pkY = maybe_y.value();
  return true;
}

bool sameNamespace(const RequestedAttribute attrs[/*n*/], size_t n) {
  for (size_t i = 1; i < n; ++i) {
    if (attrs[i].namespace_len != attrs[0].namespace_len ||
        memcmp(attrs[i].namespace_id, attrs[0].namespace_id,
               attrs[0].namespace_len) != 0) {
      return false;
    }
  }
  return true;
}

// Validates that the input is a valid CBOR encoding of one of the following:
// - String (TEXT)
// - Boolean (PRIMITIVE TRUE/FALSE)
// - Integer (UNSIGNED/NEGATIVE)
// - Binary String (BYTES)
// - Fulldate (TAG 1004) -> must be 14 bytes total
// - Tdate (TAG 0) -> must be 22 bytes total
bool cbor_validate(const uint8_t* in, size_t len) {
  uint8_t dummy[1];  // For 0-length checks if needed, though len > 0 usually
  const uint8_t* buf = in ? in : dummy;
  size_t pos = 0;
  CborDoc doc;

  if (!doc.decode(buf, len, pos, 0)) {
    return false;
  }

  // Ensure we consumed the entire buffer
  if (pos != len) {
    return false;
  }

  switch (doc.t_) {
    case TEXT:
    case BYTES:
    case UNSIGNED:
    case NEGATIVE:
      return true;

    case PRIMITIVE:
      return (doc.u_.p == CTRUE || doc.u_.p == CFALSE);

    case TAG: {
      // items.n is the tag value
      size_t tag = doc.u_.items.n;
      if (tag == 1004) {  // Fulldate
        if (len != 14) return false;
        // Check inner type is TEXT? CborDoc handles valid children decode.
        // host_decoder.h: case 6 (TAG) ... decode_items ...
        // We know it has 1 child.
        if (doc.children_.empty() || doc.children_[0].t_ != TEXT) return false;
        return true;
      }
      if (tag == 0) {  // Tdate
        if (len != 22) return false;
        if (doc.children_.empty() || doc.children_[0].t_ != TEXT) return false;
        return true;
      }
      return false;
    }

    default:
      return false;
  }
}

// =========== End of helper functions =====================
extern "C" {
/*
API version that uses 2 circuits over different fields.
*/
using MdocSWw = MdocSignatureWitness<P256, Fp256Scalar>;

// Main endpoint for producing a ZK proof for mdoc properties.
// This implementation uses 2 separate circuits over 2 fields to verify
// the signature and the hash components of the mdoc.
// It is the caller's job to free the memory pointed to by prf.
MdocProverErrorCode run_mdoc_prover(
    const uint8_t* bcp, size_t bcsz, /* circuit data */
    const uint8_t* mdoc, size_t mdoc_len, const char* pkx,
    const char* pky,                          /* string rep of public key */
    const uint8_t* transcript, size_t tr_len, /* session transcript */
    const RequestedAttribute* attrs, size_t attrs_len,
    const char* now, /* time formatted as "2023-11-02T09:00:00Z" */
    const uint8_t* contract_hash, /* 8 bytes */
    const uint8_t* escrow_fields, /* 8×32=256 bytes */
    uint8_t** prf, size_t* proof_len,
    uint8_t nullifier_hash_out[32],
    uint8_t binding_hash_out[32],
    uint8_t escrow_digest_out[32],
    const ZkSpecStruct* zk_spec) {
  if (bcp == nullptr || mdoc == nullptr || pkx == nullptr || pky == nullptr ||
      transcript == nullptr || attrs == nullptr || now == nullptr ||
      contract_hash == nullptr || escrow_fields == nullptr ||
      prf == nullptr || proof_len == nullptr ||
      nullifier_hash_out == nullptr || binding_hash_out == nullptr ||
      escrow_digest_out == nullptr || zk_spec == nullptr) {
    return MDOC_PROVER_NULL_INPUT;
  }

  Elt pkX, pkY;
  if (!parsePk(pkx, pky, pkX, pkY)) {
    log(ERROR, "invalid pkx, pky");
    return MDOC_PROVER_INVALID_INPUT;
  }

  if (!sameNamespace(attrs, attrs_len)) {
    log(ERROR, "attributes must all be in the same namespace");
    return MDOC_PROVER_INVALID_INPUT;
  }

  // Parse circuits from cached byte representation.
  const f2_p256 p256_2(p256_base);
  const f_128 Fs;

  std::unique_ptr<Circuit<Fp256Base>> c_sig = nullptr;
  std::unique_ptr<Circuit<f_128>> c_hash = nullptr;
  /* scope for the bytes array */ {
    size_t len = kCircuitSizeMax;
    std::vector<uint8_t> bytes(len);
    size_t full_size = decompress(bytes, bcp, bcsz);

    if (full_size == 0) {
      return MDOC_PROVER_CIRCUIT_PARSING_FAILURE;
    }

    log(INFO, "bytes len: %zu", full_size);
    ReadBuffer rb_circuit(bytes.data(), full_size);

    CircuitRep<Fp256Base> cr_s(p256_base, P256_ID);
    c_sig = cr_s.from_bytes(rb_circuit, enforce_circuit_id_in_prover);
    if (c_sig == nullptr) {
      log(ERROR, "signature circuit could not be parsed");
      return MDOC_PROVER_CIRCUIT_PARSING_FAILURE;
    }
    CircuitRep<f_128> cr_h(Fs, GF2_128_ID);
    c_hash = cr_h.from_bytes(rb_circuit, enforce_circuit_id_in_prover);

    if (c_hash == nullptr) {
      log(ERROR, "hash circuit could not be parsed");
      return MDOC_PROVER_HASH_PARSING_FAILURE;
    }
    log(INFO, "circuit created. h[in:%zu q:%zu], s[in:%zu q:%zu]",
        c_hash->ninputs, c_hash->nl, c_sig->ninputs, c_sig->nl);
  }

  //  ============ Produce zk witness ==============
  auto W_sig = Dense<Fp256Base>(1, c_sig->ninputs);
  auto W_hash = Dense<f_128>(1, c_hash->ninputs);
  DenseFiller<Fp256Base> sig_filler(W_sig);
  DenseFiller<f_128> hash_filler(W_hash);

  SecureRandomEngine rng;
  ProverState state;
  uint8_t enroll_commit_local[32] = {};
  uint8_t enroll_nullifier_local[32] = {};
  MdocProverErrorCode ok = fill_witness(
      sig_filler, hash_filler, mdoc, mdoc_len, pkX, pkY, transcript, tr_len,
      attrs, attrs_len, (const uint8_t*)now, contract_hash, nullifier_hash_out,
      binding_hash_out, (const uint8_t (*)[32])escrow_fields, escrow_digest_out,
      /*holder_seed=*/nullptr,
      enroll_commit_local, enroll_nullifier_local,
      state, rng, Fs, zk_spec->version);
  if (ok != MDOC_PROVER_SUCCESS) {
    log(ERROR, "fill_witness failed");
    return ok;
  }

  // Update nullifier + binding + escrow + enroll public inputs in dense array
  // (initially zeros from fill_attributes).
  update_nullifier_in_dense(W_hash,
                            getNullifierIndex(attrs_len, zk_spec->version),
                            contract_hash, nullifier_hash_out, Fs);
  update_binding_in_dense(W_hash,
                          getBindingIndex(attrs_len, zk_spec->version),
                          binding_hash_out, Fs);
  update_escrow_digest_in_dense(W_hash,
                                getEscrowDigestIndex(attrs_len, zk_spec->version),
                                escrow_digest_out, Fs);
  update_v256_hash_in_dense(W_hash,
                            getEnrollCommitIndex(attrs_len, zk_spec->version),
                            enroll_commit_local, Fs);
  update_v256_hash_in_dense(W_hash,
                            getEnrollNullifierIndex(attrs_len, zk_spec->version),
                            enroll_nullifier_local, Fs);

  // ========= Run prover ==============
  // Use the transcript from the session to select the random oracle.
  Transcript tp(transcript, tr_len, zk_spec->version);

  const Elt2 omega = p256_2.of_string(kRootX, kRootY);
  const FftExtConvolutionFactory fft_b(p256_base, p256_2, omega, 1ull << 31);
  const RSFactory_b rsf_b(fft_b, p256_base);
  const RSFactory the_reed_solomon_factory(Fs);

  size_t r = zk_spec->version < 7 ? kLigeroRate : kLigeroRatev7;
  size_t req = zk_spec->version < 7 ? kLigeroNreq : kLigeroNreqv7;
  ZkProof<f_128> h_zk(*c_hash, r, req, zk_spec->block_enc_hash);
  ZkProof<Fp256Base> sig_zk(*c_sig, r, req, zk_spec->block_enc_sig);

  ZkProver<f_128, RSFactory> hash_p(*c_hash, Fs, the_reed_solomon_factory);
  ZkProver<Fp256Base, RSFactory_b> sig_p(*c_sig, p256_base, rsf_b);

  hash_p.commit(h_zk, W_hash, tp, rng);
  sig_p.commit(sig_zk, W_sig, tp, rng);

  log(INFO,
      "commit created. h[nl:%zu, ni:%zu], s[nl:%zu, ni:%zu] hc[b:%zu r:%zu] "
      "sc[b:%zu r:%zu]",
      c_hash->nl, c_hash->ninputs, c_sig->nl, c_sig->ninputs, h_zk.param.block,
      h_zk.param.nrow, sig_zk.param.block, sig_zk.param.nrow);

  // After prover has committed to the public inputs, compute
  // verifier challenge av, and then compute MACs of the common public
  // inputs.

  gf2k av = generate_mac_key(tp), macs[6];
  uint8_t macs_b[6 * f_128::kBytes];
  compute_macs(3, state.common, macs, macs_b, state.ap, av);
  update_macs(W_sig, W_hash, kSigMacIndex,
              getHashMacIndex(attrs_len, zk_spec->version), macs, av, Fs);

  if (!hash_p.prove(h_zk, W_hash, tp)) {
    return MDOC_PROVER_GENERAL_FAILURE;
  };
  log(INFO, "ZK hash proof done");

  if (!sig_p.prove(sig_zk, W_sig, tp)) {
    return MDOC_PROVER_GENERAL_FAILURE;
  };
  log(INFO, "ZK signature proof done");

  // Serialize proof to bytes.
  // [6 mac values] [docType] [hash proof] [sig proof]
  std::vector<uint8_t> buf;
  // This sum will not overflow based on constraints of circuit & proof size.
  size_t tt = 6 * f_128::kBytes + h_zk.size() + sig_zk.size();
  buf.reserve(tt);
  buf.insert(buf.begin(), macs_b, macs_b + 6 * f_128::kBytes);
  h_zk.write(buf, Fs);
  sig_zk.write(buf, p256_base);
  *proof_len = buf.size();
  log(INFO, "proof_len: %zu ", *proof_len);

  // Allocate memory and copy proof bytes.
  *prf = (uint8_t*)malloc(*proof_len);
  if (!*prf) {
    log(ERROR, "malloc failed");
    return MDOC_PROVER_MEMORY_ALLOCATION_FAILURE;
  }
  memcpy(*prf, buf.data(), buf.size());
  return MDOC_PROVER_SUCCESS;
}

MdocVerifierErrorCode run_mdoc_verifier(
    const uint8_t* bcp, size_t bcsz,          /* circuit data */
    const char* pkx, const char* pky,         /* string rep of public key */
    const uint8_t* transcript, size_t tr_len, /* session Transcript */
    const RequestedAttribute* attrs, size_t attrs_len,
    const char* now, /* time formatted as "2023-11-02T09:00:00Z" */
    const uint8_t* contract_hash, /* 8 bytes */
    const uint8_t nullifier_hash[32],
    const uint8_t binding_hash[32],
    const uint8_t escrow_digest[32],
    const uint8_t* zkproof, size_t proof_len, const char* docType,
    const ZkSpecStruct* zk_spec) {
  if (bcp == nullptr || pkx == nullptr || pky == nullptr ||
      transcript == nullptr || now == nullptr || attrs == nullptr ||
      contract_hash == nullptr || nullifier_hash == nullptr ||
      binding_hash == nullptr || escrow_digest == nullptr ||
      zkproof == nullptr || docType == nullptr || zk_spec == nullptr) {
    return MDOC_VERIFIER_NULL_INPUT;
  }

  Elt pkX, pkY;
  if (!parsePk(pkx, pky, pkX, pkY)) {
    log(ERROR, "invalid pkx, pky");
    return MDOC_VERIFIER_INVALID_INPUT;
  }

  if (!sameNamespace(attrs, attrs_len)) {
    log(ERROR, "attributes must all be in the same namespace");
    return MDOC_VERIFIER_INVALID_INPUT;
  }

  // Verify that the values in the RequestedAttribute structure are valid cbor.
  for (size_t i = 0; i < attrs_len; ++i) {
    if (!cbor_validate(attrs[i].cbor_value, attrs[i].cbor_value_len)) {
      log(ERROR, "invalid cbor value");
      return MDOC_VERIFIER_INVALID_CBOR;
    }
  }

  const f_128 Fs;

  // Sanity check input sizes.
  if (bcsz < 50000 || tr_len < 1 || attrs_len < 1 || proof_len < 20000) {
    return MDOC_VERIFIER_ARGUMENTS_TOO_SMALL;
  }

  const f2_p256 p256_2(p256_base);

  // Parse circuits from cached byte representation.
  size_t len = kCircuitSizeMax;
  std::vector<uint8_t> bytes(len);
  size_t full_size = decompress(bytes, bcp, bcsz);

  // For now, we are not using the ZKSpec version anywhere and assuming no
  // backwards compatibility. As soon as we have a use case for it, we have to
  // pass the ZkSpecStruct to all required downstream functions.
  log(INFO, "bytes len: %zu", full_size);

  ReadBuffer rb_circuit(bytes.data(), full_size);
  CircuitRep<Fp256Base> cr_s(p256_base, P256_ID);
  auto c_sig = cr_s.from_bytes(rb_circuit, enforce_circuit_id_in_verifier);
  if (c_sig == nullptr) {
    log(ERROR, "signature circuit could not be parsed");
    return MDOC_VERIFIER_CIRCUIT_PARSING_FAILURE;
  }

  CircuitRep<f_128> cr_h(Fs, GF2_128_ID);
  auto c_hash = cr_h.from_bytes(rb_circuit, enforce_circuit_id_in_verifier);

  if (c_hash == nullptr) {
    log(ERROR, "circuit could not be parsed");
    return MDOC_VERIFIER_CIRCUIT_PARSING_FAILURE;
  }
  log(INFO, "circuit created. h[in:%zu], s[in:%zu]", c_hash->ninputs,
      c_sig->ninputs);

  // Parse proofs
  size_t r = zk_spec->version < 7 ? kLigeroRate : kLigeroRatev7;
  size_t req = zk_spec->version < 7 ? kLigeroNreq : kLigeroNreqv7;
  ZkProof<f_128> pr_hash(*c_hash, r, req, zk_spec->block_enc_hash);
  ZkProof<Fp256Base> pr_sig(*c_sig, r, req, zk_spec->block_enc_sig);

  log(INFO,
      "proof params: h[nl:%zu, ni:%zu], s[nl:%zu, ni:%zu] hc[b:%zu r:%zu] "
      "sc[b:%zu r:%zu]",
      c_hash->nl, c_hash->ninputs, c_sig->nl, c_sig->ninputs,
      pr_hash.param.block, pr_hash.param.nrow, pr_sig.param.block,
      pr_sig.param.nrow);

  const std::vector<uint8_t> zbuf(zkproof, zkproof + proof_len);
  ReadBuffer rb(zbuf);

  // Read macs from proof string.
  // The sanity check above ensures that the proof is big enough for the MACs.
  gf2k macs[6];

  for (size_t i = 0; i < 6; ++i) {
    macs[i] = Fs.of_bytes_field(rb.next(f_128::kBytes)).value();
  }

  // The proof read methods check proof length internally.
  if (!pr_hash.read(rb, Fs)) {
    log(ERROR, "hash proof could not be parsed");
    return MDOC_VERIFIER_HASH_PARSING_FAILURE;
  };
  if (!pr_sig.read(rb, p256_base)) {
    log(ERROR, "sig proof could not be parsed");
    return MDOC_VERIFIER_SIGNATURE_PARSING_FAILURE;
  }
  if (rb.remaining() != 0) {
    log(ERROR, "proof bytes contains extra data: %zu bytes", rb.remaining());
    return MDOC_VERIFIER_SIGNATURE_PARSING_FAILURE;
  }

  log(INFO, "proofs read");

  // =============== Verify

  const Elt2 omega = p256_2.of_string(kRootX, kRootY);
  const FftExtConvolutionFactory fft_b(p256_base, p256_2, omega, 1ull << 31);
  const RSFactory_b rsf_b(fft_b, p256_base);
  const RSFactory the_reed_solomon_factory(Fs);

  ZkVerifier<f_128, RSFactory> hash_v(*c_hash, the_reed_solomon_factory, r, req,
                                      zk_spec->block_enc_hash, Fs);
  ZkVerifier<Fp256Base, RSFactory_b> sig_v(*c_sig, rsf_b, r, req,
                                           zk_spec->block_enc_sig, p256_base);

  // Use the transcript from the session to select the random oracle.
  class Transcript tv(transcript, tr_len, zk_spec->version);

  hash_v.recv_commitment(pr_hash, tv);
  sig_v.recv_commitment(pr_sig, tv);

  gf2k av = generate_mac_key(tv);

  // =============== Create public inputs
  auto pub_hash = Dense<f_128>(1, c_hash->npub_in);
  auto pub_sig = Dense<Fp256Base>(1, c_sig->npub_in);
  DenseFiller<f_128> hash_filler(pub_hash);
  DenseFiller<Fp256Base> sig_filler(pub_sig);

  // v11 verifier path: enroll-commit + enroll-nullifier expected as zeros.
  // v12 verifier (run_mdoc_verifier_v12 below) supplies real values.
  uint8_t zero_enroll[32] = {};
  size_t dlen = strlen(docType);
  if (!fill_public_inputs(sig_filler, hash_filler, pkX, pkY, transcript, tr_len,
                          attrs, attrs_len, (const uint8_t*)now,
                          contract_hash, nullifier_hash, binding_hash,
                          escrow_digest, zero_enroll, zero_enroll,
                          (const uint8_t*)docType, dlen,
                          macs, av, Fs, zk_spec->version)) {
    return MDOC_VERIFIER_GENERAL_FAILURE;
  }

  if (hash_filler.size() != c_hash->npub_in ||
      sig_filler.size() != c_sig->npub_in) {
    return MDOC_VERIFIER_ATTRIBUTE_NUMBER_MISMATCH;
  }

  bool ok = hash_v.verify(pr_hash, pub_hash, tv);
  bool ok2 = sig_v.verify(pr_sig, pub_sig, tv);

  return ok && ok2 ? MDOC_VERIFIER_SUCCESS : MDOC_VERIFIER_GENERAL_FAILURE;
}

// =========================== v12 entry points ===========================

MdocProverErrorCode run_mdoc_prover_v12(
    const uint8_t* bcp, size_t bcsz,
    const uint8_t* mdoc, size_t mdoc_len,
    const char* pkx, const char* pky,
    const uint8_t* transcript, size_t tr_len,
    const RequestedAttribute* attrs, size_t attrs_len,
    const char* now,
    const uint8_t* contract_hash,
    const uint8_t* escrow_fields,
    const uint8_t* holder_seed,
    const uint8_t* holder_seed_commit,
    uint8_t** prf, size_t* proof_len,
    uint8_t nullifier_hash_out[32],
    uint8_t binding_hash_out[32],
    uint8_t escrow_digest_out[32],
    uint8_t enroll_commit_out[32],
    uint8_t enroll_nullifier_out[32],
    const ZkSpecStruct* zk_spec) {
  if (bcp == nullptr || mdoc == nullptr || pkx == nullptr || pky == nullptr ||
      transcript == nullptr || attrs == nullptr || now == nullptr ||
      contract_hash == nullptr || escrow_fields == nullptr ||
      holder_seed == nullptr ||
      prf == nullptr || proof_len == nullptr ||
      nullifier_hash_out == nullptr || binding_hash_out == nullptr ||
      escrow_digest_out == nullptr || enroll_commit_out == nullptr ||
      enroll_nullifier_out == nullptr || zk_spec == nullptr) {
    return MDOC_PROVER_NULL_INPUT;
  }
  // Note: holder_seed_commit is currently ignored -- compute_enroll_commit
  // re-derives it from holder_seed and the circuit's invariant 13 binds
  // them in-circuit. Caller-provided holder_seed_commit is documented
  // for future cross-validation but redundant for now.
  (void)holder_seed_commit;

  Elt pkX, pkY;
  if (!parsePk(pkx, pky, pkX, pkY)) {
    log(ERROR, "invalid pkx, pky");
    return MDOC_PROVER_INVALID_INPUT;
  }

  if (!sameNamespace(attrs, attrs_len)) {
    log(ERROR, "attributes must all be in the same namespace");
    return MDOC_PROVER_INVALID_INPUT;
  }

  const f2_p256 p256_2(p256_base);
  const f_128 Fs;

  std::unique_ptr<Circuit<Fp256Base>> c_sig = nullptr;
  std::unique_ptr<Circuit<f_128>> c_hash = nullptr;
  {
    size_t len = kCircuitSizeMax;
    std::vector<uint8_t> bytes(len);
    size_t full_size = decompress(bytes, bcp, bcsz);
    if (full_size == 0) return MDOC_PROVER_CIRCUIT_PARSING_FAILURE;
    log(INFO, "bytes len: %zu", full_size);
    ReadBuffer rb_circuit(bytes.data(), full_size);
    CircuitRep<Fp256Base> cr_s(p256_base, P256_ID);
    c_sig = cr_s.from_bytes(rb_circuit, enforce_circuit_id_in_prover);
    if (c_sig == nullptr) return MDOC_PROVER_CIRCUIT_PARSING_FAILURE;
    CircuitRep<f_128> cr_h(Fs, GF2_128_ID);
    c_hash = cr_h.from_bytes(rb_circuit, enforce_circuit_id_in_prover);
    if (c_hash == nullptr) return MDOC_PROVER_HASH_PARSING_FAILURE;
    log(INFO, "v12 circuit created. h[in:%zu q:%zu], s[in:%zu q:%zu]",
        c_hash->ninputs, c_hash->nl, c_sig->ninputs, c_sig->nl);
  }

  auto W_sig = Dense<Fp256Base>(1, c_sig->ninputs);
  auto W_hash = Dense<f_128>(1, c_hash->ninputs);
  DenseFiller<Fp256Base> sig_filler(W_sig);
  DenseFiller<f_128> hash_filler(W_hash);

  SecureRandomEngine rng;
  ProverState state;
  MdocProverErrorCode ok = fill_witness(
      sig_filler, hash_filler, mdoc, mdoc_len, pkX, pkY, transcript, tr_len,
      attrs, attrs_len, (const uint8_t*)now, contract_hash, nullifier_hash_out,
      binding_hash_out, (const uint8_t (*)[32])escrow_fields, escrow_digest_out,
      holder_seed, enroll_commit_out, enroll_nullifier_out,
      state, rng, Fs, zk_spec->version);
  if (ok != MDOC_PROVER_SUCCESS) {
    log(ERROR, "v12 fill_witness failed");
    return ok;
  }

  update_nullifier_in_dense(W_hash,
                            getNullifierIndex(attrs_len, zk_spec->version),
                            contract_hash, nullifier_hash_out, Fs);
  update_binding_in_dense(W_hash,
                          getBindingIndex(attrs_len, zk_spec->version),
                          binding_hash_out, Fs);
  update_escrow_digest_in_dense(W_hash,
                                getEscrowDigestIndex(attrs_len, zk_spec->version),
                                escrow_digest_out, Fs);
  update_v256_hash_in_dense(W_hash,
                            getEnrollCommitIndex(attrs_len, zk_spec->version),
                            enroll_commit_out, Fs);
  update_v256_hash_in_dense(W_hash,
                            getEnrollNullifierIndex(attrs_len, zk_spec->version),
                            enroll_nullifier_out, Fs);

  Transcript tp(transcript, tr_len, zk_spec->version);
  const Elt2 omega = p256_2.of_string(kRootX, kRootY);
  const FftExtConvolutionFactory fft_b(p256_base, p256_2, omega, 1ull << 31);
  const RSFactory_b rsf_b(fft_b, p256_base);
  const RSFactory the_reed_solomon_factory(Fs);

  size_t r = zk_spec->version < 7 ? kLigeroRate : kLigeroRatev7;
  size_t req = zk_spec->version < 7 ? kLigeroNreq : kLigeroNreqv7;
  ZkProof<f_128> h_zk(*c_hash, r, req, zk_spec->block_enc_hash);
  ZkProof<Fp256Base> sig_zk(*c_sig, r, req, zk_spec->block_enc_sig);
  ZkProver<f_128, RSFactory> hash_p(*c_hash, Fs, the_reed_solomon_factory);
  ZkProver<Fp256Base, RSFactory_b> sig_p(*c_sig, p256_base, rsf_b);

  hash_p.commit(h_zk, W_hash, tp, rng);
  sig_p.commit(sig_zk, W_sig, tp, rng);

  gf2k av = generate_mac_key(tp), macs[6];
  uint8_t macs_b[6 * f_128::kBytes];
  compute_macs(3, state.common, macs, macs_b, state.ap, av);
  update_macs(W_sig, W_hash, kSigMacIndex,
              getHashMacIndex(attrs_len, zk_spec->version), macs, av, Fs);

  if (!hash_p.prove(h_zk, W_hash, tp)) return MDOC_PROVER_GENERAL_FAILURE;
  if (!sig_p.prove(sig_zk, W_sig, tp)) return MDOC_PROVER_GENERAL_FAILURE;

  std::vector<uint8_t> buf;
  size_t tt = 6 * f_128::kBytes + h_zk.size() + sig_zk.size();
  buf.reserve(tt);
  buf.insert(buf.begin(), macs_b, macs_b + 6 * f_128::kBytes);
  h_zk.write(buf, Fs);
  sig_zk.write(buf, p256_base);
  *proof_len = buf.size();

  *prf = (uint8_t*)malloc(*proof_len);
  if (!*prf) return MDOC_PROVER_MEMORY_ALLOCATION_FAILURE;
  memcpy(*prf, buf.data(), buf.size());
  return MDOC_PROVER_SUCCESS;
}

MdocVerifierErrorCode run_mdoc_verifier_v12(
    const uint8_t* bcp, size_t bcsz,
    const char* pkx, const char* pky,
    const uint8_t* transcript, size_t tr_len,
    const RequestedAttribute* attrs, size_t attrs_len,
    const char* now,
    const uint8_t* contract_hash,
    const uint8_t nullifier_hash[32],
    const uint8_t binding_hash[32],
    const uint8_t escrow_digest[32],
    const uint8_t enroll_commit[32],
    const uint8_t enroll_nullifier[32],
    const uint8_t* zkproof, size_t proof_len, const char* docType,
    const ZkSpecStruct* zk_spec) {
  if (bcp == nullptr || pkx == nullptr || pky == nullptr ||
      transcript == nullptr || now == nullptr || attrs == nullptr ||
      contract_hash == nullptr || nullifier_hash == nullptr ||
      binding_hash == nullptr || escrow_digest == nullptr ||
      enroll_commit == nullptr || enroll_nullifier == nullptr ||
      zkproof == nullptr || docType == nullptr || zk_spec == nullptr) {
    return MDOC_VERIFIER_NULL_INPUT;
  }

  Elt pkX, pkY;
  if (!parsePk(pkx, pky, pkX, pkY)) return MDOC_VERIFIER_INVALID_INPUT;
  if (!sameNamespace(attrs, attrs_len)) return MDOC_VERIFIER_INVALID_INPUT;

  for (size_t i = 0; i < attrs_len; ++i) {
    if (!cbor_validate(attrs[i].cbor_value, attrs[i].cbor_value_len)) {
      return MDOC_VERIFIER_INVALID_CBOR;
    }
  }

  const f_128 Fs;
  if (bcsz < 50000 || tr_len < 1 || attrs_len < 1 || proof_len < 20000) {
    return MDOC_VERIFIER_ARGUMENTS_TOO_SMALL;
  }

  const f2_p256 p256_2(p256_base);

  size_t len = kCircuitSizeMax;
  std::vector<uint8_t> bytes(len);
  size_t full_size = decompress(bytes, bcp, bcsz);
  ReadBuffer rb_circuit(bytes.data(), full_size);
  CircuitRep<Fp256Base> cr_s(p256_base, P256_ID);
  auto c_sig = cr_s.from_bytes(rb_circuit, enforce_circuit_id_in_verifier);
  if (c_sig == nullptr) return MDOC_VERIFIER_CIRCUIT_PARSING_FAILURE;
  CircuitRep<f_128> cr_h(Fs, GF2_128_ID);
  auto c_hash = cr_h.from_bytes(rb_circuit, enforce_circuit_id_in_verifier);
  if (c_hash == nullptr) return MDOC_VERIFIER_CIRCUIT_PARSING_FAILURE;

  size_t r = zk_spec->version < 7 ? kLigeroRate : kLigeroRatev7;
  size_t req = zk_spec->version < 7 ? kLigeroNreq : kLigeroNreqv7;
  ZkProof<f_128> pr_hash(*c_hash, r, req, zk_spec->block_enc_hash);
  ZkProof<Fp256Base> pr_sig(*c_sig, r, req, zk_spec->block_enc_sig);

  const std::vector<uint8_t> zbuf(zkproof, zkproof + proof_len);
  ReadBuffer rb(zbuf);

  gf2k macs[6];
  for (size_t i = 0; i < 6; ++i) {
    macs[i] = Fs.of_bytes_field(rb.next(f_128::kBytes)).value();
  }
  if (!pr_hash.read(rb, Fs)) return MDOC_VERIFIER_HASH_PARSING_FAILURE;
  if (!pr_sig.read(rb, p256_base)) return MDOC_VERIFIER_SIGNATURE_PARSING_FAILURE;
  if (rb.remaining() != 0) return MDOC_VERIFIER_SIGNATURE_PARSING_FAILURE;

  const Elt2 omega = p256_2.of_string(kRootX, kRootY);
  const FftExtConvolutionFactory fft_b(p256_base, p256_2, omega, 1ull << 31);
  const RSFactory_b rsf_b(fft_b, p256_base);
  const RSFactory the_reed_solomon_factory(Fs);
  ZkVerifier<f_128, RSFactory> hash_v(*c_hash, the_reed_solomon_factory, r, req,
                                      zk_spec->block_enc_hash, Fs);
  ZkVerifier<Fp256Base, RSFactory_b> sig_v(*c_sig, rsf_b, r, req,
                                           zk_spec->block_enc_sig, p256_base);

  class Transcript tv(transcript, tr_len, zk_spec->version);
  hash_v.recv_commitment(pr_hash, tv);
  sig_v.recv_commitment(pr_sig, tv);
  gf2k av = generate_mac_key(tv);

  auto pub_hash = Dense<f_128>(1, c_hash->npub_in);
  auto pub_sig = Dense<Fp256Base>(1, c_sig->npub_in);
  DenseFiller<f_128> hash_filler(pub_hash);
  DenseFiller<Fp256Base> sig_filler(pub_sig);

  size_t dlen = strlen(docType);
  if (!fill_public_inputs(sig_filler, hash_filler, pkX, pkY, transcript, tr_len,
                          attrs, attrs_len, (const uint8_t*)now,
                          contract_hash, nullifier_hash, binding_hash,
                          escrow_digest, enroll_commit, enroll_nullifier,
                          (const uint8_t*)docType, dlen,
                          macs, av, Fs, zk_spec->version)) {
    return MDOC_VERIFIER_GENERAL_FAILURE;
  }

  if (hash_filler.size() != c_hash->npub_in ||
      sig_filler.size() != c_sig->npub_in) {
    return MDOC_VERIFIER_ATTRIBUTE_NUMBER_MISMATCH;
  }

  bool ok = hash_v.verify(pr_hash, pub_hash, tv);
  bool ok2 = sig_v.verify(pr_sig, pub_sig, tv);
  return ok && ok2 ? MDOC_VERIFIER_SUCCESS : MDOC_VERIFIER_GENERAL_FAILURE;
}

} /* extern "C" */
}  // namespace proofs
