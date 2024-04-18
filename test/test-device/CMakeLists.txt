# Minimum required CMake version
cmake_minimum_required(VERSION 3.20)

set(TEST_BIN_DIR ${BIN_DIR}/devices/test)
set(EXECUTABLE_OUTPUT_PATH ${TEST_BIN_DIR})

# Queue get-ip-address
add_executable(test-get-ip-address nfqueues/get-ip-address.c)
target_link_libraries(test-get-ip-address pthread)
target_link_libraries(test-get-ip-address nfqueue packet_utils rule_utils)
target_link_libraries(test-get-ip-address ${PARSERS})
target_include_directories(test-get-ip-address PRIVATE ${INCLUDE_DIR})
install(TARGETS test-get-ip-address DESTINATION ${EXECUTABLE_OUTPUT_PATH})

