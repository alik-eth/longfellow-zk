# Copyright 2026 Oleksandr Vovkotrub. Apache-2.0.

add_library(p7s_static STATIC
  p7s_circuit.cc
  p7s_zk.cc
  sub/byte_range_eq.cc
  sub/declaration_whitelist.cc
  sub/p7s_signature.cc
  sub/signedattrs_rewrite.cc
  $<TARGET_OBJECTS:flatsha>
  $<TARGET_OBJECTS:ec>
  $<TARGET_OBJECTS:algebra>
  $<TARGET_OBJECTS:util>
)
target_include_directories(p7s_static PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_SOURCE_DIR}
)

set(installable_libs p7s_static)
install(TARGETS ${installable_libs} DESTINATION lib)
install(FILES p7s_zk.h DESTINATION include)

# Task #41 — vendor-side smoke test against the canonical v12
# witness/public blobs. ~19s on the positive case (full prove + verify
# cycle); ~1s on the negative case. Blobs are pre-generated from the
# canonical TestAnchorA v12 fixture via
# `crates/zk-eidas-p7s-circuit/examples/dump_v12_blobs.rs` and
# embedded in p7s_v12_test_blobs.h.
add_executable(p7s_v12_smoke_test p7s_v12_smoke_test.cc)
target_link_libraries(p7s_v12_smoke_test p7s_static crypto)
proofs_add_testing_libraries(p7s_v12_smoke_test)
