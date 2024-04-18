# Minimum required CMake version
cmake_minimum_required(VERSION 3.20)

# Build libraries

# hashmap
add_library(hashmap STATIC ${INCLUDE_DIR}/hashmap.h hashmap.c)
target_include_directories(hashmap PRIVATE ${INCLUDE_DIR})
install(TARGETS hashmap DESTINATION ${LIB_DIR})

# SHA256
add_library(sha256 STATIC ${INCLUDE_DIR}/sha256.h sha256.c)
target_include_directories(sha256 PRIVATE ${INCLUDE_DIR})
install(TARGETS sha256 DESTINATION ${LIB_DIR})

# packet_utils
add_library(packet_utils STATIC ${INCLUDE_DIR}/packet_utils.h packet_utils.c)
target_link_libraries(packet_utils sha256)
target_include_directories(packet_utils PRIVATE ${INCLUDE_DIR})
install(TARGETS packet_utils DESTINATION ${LIB_DIR})

# dns_map
add_library(dns_map STATIC ${INCLUDE_DIR}/dns_map.h dns_map.c)
target_link_libraries(dns_map hashmap)
target_include_directories(dns_map PRIVATE ${INCLUDE_DIR})
install(TARGETS dns_map DESTINATION ${LIB_DIR})

# rule_utils
add_library(rule_utils STATIC ${INCLUDE_DIR}/rule_utils.h rule_utils.c)
target_link_libraries(rule_utils nftables nftnl nfnetlink mnl jansson)
target_include_directories(rule_utils PRIVATE ${INCLUDE_DIR})
install(TARGETS rule_utils DESTINATION ${LIB_DIR})

# nfqueue
add_library(nfqueue STATIC ${INCLUDE_DIR}/nfqueue.h nfqueue.c)
target_link_libraries(nfqueue netfilter_queue)
target_link_libraries(nfqueue packet_utils)
target_include_directories(nfqueue PRIVATE ${INCLUDE_DIR})
install(TARGETS nfqueue DESTINATION ${LIB_DIR})

# nflog executable
add_executable(nflog nflog.c)
target_link_libraries(nflog nfnetlink mnl netfilter_log pthread)
target_link_libraries(nflog packet_utils)
target_include_directories(nflog PRIVATE ${INCLUDE_DIR})
install(TARGETS nflog DESTINATION ${BIN_DIR})

# Build parsers
add_subdirectory(parsers)
