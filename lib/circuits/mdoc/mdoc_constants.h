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

#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_MDOC_MDOC_CONSTANTS_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_MDOC_MDOC_CONSTANTS_H_

#include <stddef.h>
#include <stdint.h>

namespace proofs {

/* Max number of SHA blocks to process. */
// v7 circuits use 40, earlier ones use 35.
constexpr static const size_t kMaxSHABlocks = 40;

/* Number of bits in CBOR index. Must be large enough to index into MDOC.*/
constexpr static const size_t kCborIndexBits = 12;

// This is the prefix added to the D8... mdoc encoding to produce
// a COSE1 encoding that is ready to be hashed.
static constexpr uint8_t kCose1Prefix[18] = {
    0x84, 0x6A, 0x53, 0x69, 0x67, 0x6E, 0x61, 0x74, 0x75,
    0x72, 0x65, 0x31, 0x43, 0xA1, 0x01, 0x26, 0x40, 0x59,
};
static constexpr size_t kCose1PrefixLen = 18;

/* Max size of an MSO that hashes using < MAX SHA blocks. */
constexpr static const size_t kMaxMsoLen =
    kMaxSHABlocks * 64 - 9 - kCose1PrefixLen;

// v12 (issuer-pseudonym privacy via holder-bound nullifier).
// Layout: same COSE1 Sig_structure as v11, but external_aad carries
// holder_seed_commit (32 bytes) instead of being empty.
//
//   84             - array(4)
//   6A 53..31      - "Signature1" (10 bytes text)
//   43 A1 01 26    - protected = bstr(3) {1: -7} = ES256
//   58 20 <32B>    - external_aad = bstr(32) holder_seed_commit  <- NEW slot
//   59 <2-byte len>- payload bstr length-prefix
//
// The 32 bytes between bytes 18 and 50 are NOT a constant -- they are
// witness inputs supplied at proof time. The constant array contains
// zeros at those positions; the circuit overwrites them with witness
// wires (see mdoc_hash.h::construct_signature_preimage).
static constexpr uint8_t kCose1PrefixV12[51] = {
    0x84, 0x6A, 0x53, 0x69, 0x67, 0x6E, 0x61, 0x74, 0x75, 0x72, 0x65, 0x31,
    0x43, 0xA1, 0x01, 0x26,
    0x58, 0x20,                        // bstr(32) length-prefix for external_aad
    /* bytes 18..50: holder_seed_commit witness slot -- zero in constant table */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x59,                              // payload bstr length-prefix
};
static constexpr size_t kCose1PrefixV12Len            = 51;
static constexpr size_t kHolderSeedCommitPrefixOffset = 18;
static constexpr size_t kHolderSeedCommitWitnessLen   = 32;

// Witness-side payload length cap for v12. The longer prefix steals
// from the payload budget; same kMaxSHABlocks as v11.
constexpr static const size_t kMaxMsoLenV12 =
    kMaxSHABlocks * 64 - 9 - kCose1PrefixV12Len;

// 16-byte ASCII domain-separation tag for enroll-nullifier hashing.
// Mirrors crates/zk-eidas-p7s/src/outputs.rs::ENROLL_DOMAIN_SEP. Defined
// here for the mdoc circuit's assert_enroll_nullifier; the p7s circuit
// has its own copy in p7s_hash.h (vendor C++ has no clean cross-circuit
// shared-header pattern, duplicating the 16-byte constant is fine).
static constexpr uint8_t kEnrollDomainSep[16] = {
    'z', 'k', '-', 'e', 'i', 'd', 'a', 's',
    '-', 'e', 'n', 'r', 'o', 'l', 'l', '!',
};
static constexpr size_t kEnrollDomainSepLen = 16;

static constexpr size_t kValidityInfoLen = 12;
static constexpr size_t kValidFromLen = 9;
static constexpr size_t kDeviceKeyLen = 9;
static constexpr size_t kDeviceKeyInfoLen = 13;
static constexpr size_t kValidUntilLen = 10;
static constexpr size_t kValueDigestsLen = 12;
static constexpr size_t kOrgLen = 17;

static constexpr uint8_t kTag32[] = {0x58, 0x20};
static constexpr size_t kIdLen = 32;
static constexpr size_t kValueLen = 64;
static constexpr size_t kDigestLen = 8 + 1;
static constexpr size_t kRandomLen = 6 + 1;

static constexpr uint8_t kValidityInfoID[kValidityInfoLen] = {
    'v', 'a', 'l', 'i', 'd', 'i', 't', 'y', 'I', 'n', 'f', 'o'};

static constexpr uint8_t kValidFromID[kValidFromLen] = {'v', 'a', 'l', 'i', 'd',
                                                        'F', 'r', 'o', 'm'};

static constexpr uint8_t kValidUntilID[kValidUntilLen] = {
    'v', 'a', 'l', 'i', 'd', 'U', 'n', 't', 'i', 'l'};

static constexpr uint8_t kDeviceKeyID[kDeviceKeyLen] = {'d', 'e', 'v', 'i', 'c',
                                                        'e', 'K', 'e', 'y'};

static constexpr uint8_t kDeviceKeyInfoID[kDeviceKeyInfoLen] = {
    'd', 'e', 'v', 'i', 'c', 'e', 'K', 'e', 'y', 'I', 'n', 'f', 'o'};

static constexpr uint8_t kValueDigestsID[kValueDigestsLen] = {
    'v', 'a', 'l', 'u', 'e', 'D', 'i', 'g', 'e', 's', 't', 's'};

static constexpr uint8_t kOrgID[kOrgLen] = {'o', 'r', 'g', '.', 'i', 's',
                                            'o', '.', '1', '8', '0', '1',
                                            '3', '.', '5', '.', '1'};

static constexpr uint8_t kDigestID[kDigestLen] = {0x68, 'd', 'i', 'g', 'e',
                                                  's',  't', 'I', 'D'};

static constexpr uint8_t kRandomID[kRandomLen] = {0x66, 'r', 'a', 'n',
                                                  'd',  'o', 'm'};
}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_MDOC_MDOC_CONSTANTS_H_
