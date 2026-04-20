// Copyright 2026 Oleksandr Vovkotrub. Apache-2.0.

#include "circuits/p7s/sub/p7s_signature.h"

namespace proofs {
namespace p7s {

// 29 ASCII bytes "p7s-25a-mac-plumbing-sentinel" + 3 NUL padding = 32 bytes.
// Leading byte 'p' (0x70) guarantees the MSB interpretation is non-zero,
// which is required by the MAC primitive's unforgeability argument
// (see `circuits/mac/mac_circuit.h:48-55`). The tag is chosen to be
// recognizable in hex dumps and distinct from any real payload.
const unsigned char kMacBindingSentinel[kMacMessageBytes] = {
    'p', '7', 's', '-', '2', '5', 'a', '-',
    'm', 'a', 'c', '-', 'p', 'l', 'u', 'm',
    'b', 'i', 'n', 'g', '-', 's', 'e', 'n',
    't', 'i', 'n', 'e', 'l', 0, 0, 0,
};

}  // namespace p7s
}  // namespace proofs
