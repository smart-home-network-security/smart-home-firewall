# Minimum required CMake version
cmake_minimum_required(VERSION 3.20)

set(INCLUDE_PARSERS_DIR ${INCLUDE_DIR}/parsers)

# Header parser
add_library(header STATIC ${INCLUDE_PARSERS_DIR}/header.h header.c)
target_include_directories(header PRIVATE ${INCLUDE_DIR} ${INCLUDE_PARSERS_DIR})
target_link_libraries(header packet_utils)
# DNS parser
add_library(dns STATIC ${INCLUDE_PARSERS_DIR}/dns.h dns.c)
target_include_directories(dns PRIVATE ${INCLUDE_DIR} ${INCLUDE_PARSERS_DIR})
target_link_libraries(dns packet_utils dns_map)
# DHCP parser
add_library(dhcp STATIC ${INCLUDE_PARSERS_DIR}/dhcp.h dhcp.c)
target_include_directories(dhcp PRIVATE ${INCLUDE_DIR} ${INCLUDE_PARSERS_DIR})
# HTTP parser
add_library(http STATIC ${INCLUDE_PARSERS_DIR}/http.h http.c)
target_include_directories(http PRIVATE ${INCLUDE_DIR} ${INCLUDE_PARSERS_DIR})
# IGMP parser
add_library(igmp STATIC ${INCLUDE_PARSERS_DIR}/igmp.h igmp.c)
target_include_directories(igmp PRIVATE ${INCLUDE_DIR} ${INCLUDE_PARSERS_DIR})
# SSDP parser
add_library(ssdp STATIC ${INCLUDE_PARSERS_DIR}/ssdp.h ssdp.c)
target_include_directories(ssdp PRIVATE ${INCLUDE_DIR} ${INCLUDE_PARSERS_DIR})
# CoAP parser
add_library(coap STATIC ${INCLUDE_PARSERS_DIR}/coap.h coap.c)
target_include_directories(coap PRIVATE ${INCLUDE_DIR} ${INCLUDE_PARSERS_DIR})
target_link_libraries(coap http)
# Installation
install(TARGETS ${PARSERS} DESTINATION ${LIB_DIR})
