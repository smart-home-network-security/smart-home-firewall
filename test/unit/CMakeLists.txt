# Minimum required CMake version
cmake_minimum_required(VERSION 3.20)

# Set test output directory
set(TEST_BIN_DIR ${BIN_DIR}/test)
set(EXECUTABLE_OUTPUT_PATH ${TEST_BIN_DIR})

## Build unit tests

# Rule utilitairies test
add_executable(rule_utils-test rule_utils.c)
target_include_directories(rule_utils-test PRIVATE ${INCLUDE_DIR})
target_link_libraries(rule_utils-test cunit)
target_link_libraries(rule_utils-test rule_utils)
install(TARGETS rule_utils-test DESTINATION ${TEST_BIN_DIR})
