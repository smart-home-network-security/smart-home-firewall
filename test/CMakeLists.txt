# Minimum required CMake version
cmake_minimum_required(VERSION 3.20)

# Set test output directory
set(TEST_BIN_DIR ${BIN_DIR}/test)
set(EXECUTABLE_OUTPUT_PATH ${TEST_BIN_DIR})

# Packet utils test
add_executable(packet_utils-test packet_utils.c)
target_include_directories(packet_utils-test PRIVATE ${INCLUDE_DIR})
target_link_libraries(packet_utils-test cunit)
target_link_libraries(packet_utils-test packet_utils)
install(TARGETS packet_utils-test DESTINATION ${TEST_BIN_DIR})

# Domain - IP mapping test
add_executable(dns_map-test dns_map.c)
target_include_directories(dns_map-test PRIVATE ${INCLUDE_DIR})
target_link_libraries(dns_map-test cunit)
target_link_libraries(dns_map-test hashmap)
target_link_libraries(dns_map-test packet_utils)
target_link_libraries(dns_map-test dns_map)
install(TARGETS dns_map-test DESTINATION ${TEST_BIN_DIR})

# Rule utilitairies test
add_executable(rule_utils-test rule_utils.c)
target_include_directories(rule_utils-test PRIVATE ${INCLUDE_DIR})
target_link_libraries(rule_utils-test cunit)
target_link_libraries(rule_utils-test rule_utils)
install(TARGETS rule_utils-test DESTINATION ${TEST_BIN_DIR})

# Test subdirectories
add_subdirectory(parsers)
