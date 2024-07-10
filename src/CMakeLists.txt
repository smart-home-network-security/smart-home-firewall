# Minimum required CMake version
cmake_minimum_required(VERSION 3.20)

## Build instructions

# Protocol parsers libs
add_subdirectory(parsers)

# rule_utils lib
add_library(rule_utils STATIC ${INCLUDE_DIR}/rule_utils.h rule_utils.c)
target_link_libraries(rule_utils nftables nftnl nfnetlink mnl jansson)
target_include_directories(rule_utils PRIVATE ${INCLUDE_DIR})
install(TARGETS rule_utils DESTINATION ${LIB_DIR})

# nfqueue lib
add_library(nfqueue STATIC ${INCLUDE_DIR}/nfqueue.h nfqueue.c)
target_link_libraries(nfqueue netfilter_queue)
target_link_libraries(nfqueue packet_utils)
target_include_directories(nfqueue PRIVATE ${INCLUDE_DIR} ${INCLUDE_PARSERS_DIR})
install(TARGETS nfqueue DESTINATION ${LIB_DIR})

# nflog executable
add_executable(nflog nflog.c)
target_link_libraries(nflog nfnetlink mnl netfilter_log pthread)
target_link_libraries(nflog packet_utils)
target_include_directories(nflog PRIVATE ${INCLUDE_DIR} ${INCLUDE_PARSERS_DIR})
install(TARGETS nflog DESTINATION ${BIN_DIR})
