/**
 * @file test/parsers/header.c
 * @brief Unit test for the header parser (OSI layers 3 and 4)
 * @date 2022-12-01
 * 
 * @copyright Copyright (c) 2022
 * 
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
// Custom libraries
#include "packet_utils.h"
#include "parsers/header.h"
// CUnit
#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>


/**
 * @brief Unit test using a TCP SYN packet.
 */
void test_tcp_syn() {

    char *hexstring = "4500003cbcd2400040066e0fc0a801966c8ae111c67f005004f77abb00000000a002ffff2b380000020405b40402080a0003c6690000000001030306";

    uint8_t *payload;
    size_t length = hexstr_to_payload(hexstring, &payload);
    CU_ASSERT_EQUAL(length, strlen(hexstring) / 2);  // Verify packet length

    // Layer-3 header length
    uint16_t l3_header_length = get_l3_header_length(payload);
    CU_ASSERT_EQUAL(l3_header_length, 20);

    // IPv4 destination address
    uint32_t ipv4_src_addr = get_ipv4_src_addr(payload);
    CU_ASSERT_STRING_EQUAL(ipv4_net_to_str(ipv4_src_addr), "192.168.1.150");

    // IPv4 destination address
    uint32_t ipv4_dst_addr = get_ipv4_dst_addr(payload);
    CU_ASSERT_STRING_EQUAL(ipv4_net_to_str(ipv4_dst_addr), "108.138.225.17");

    // TCP header length
    uint16_t tcp_header_length = get_tcp_header_length(payload + l3_header_length);
    CU_ASSERT_EQUAL(tcp_header_length, 40);

    // Layers 3 and 4 headers length
    uint16_t headers_length = get_headers_length(payload);
    CU_ASSERT_EQUAL(headers_length, 20 + 40);

    // Destination port
    uint16_t dst_port = get_dst_port(payload + l3_header_length);
    CU_ASSERT_EQUAL(dst_port, 80);

    // Contains payload ?
    CU_ASSERT_FALSE(length - headers_length > 0);

    free(payload);
}

/**
 * @brief Unit test using an HTTPS data packet.
 */
void test_https_data() {

    char *hexstring = "450001613b64400040067977c0a801dec0a8018d8da801bbec035d653f25b250501808065ff2000017030301340000000000000087884ca5c237291279d20249e09c2848a56615a0fda66e788fdc5a04cb96d7be52b00302e4956118ec87e74ad1e3e20192689876cc821e6c95087fbc160163edd6a48b5f1f06752e3b0b0ee4c9c1f208508ba36fd57499c3a1d95805f33a5e5b89edb06e8b70615eb3f531a375537674e298b7692d78bd5e407738597097285a1205a2d3f4ba183bbd7f609ec1a9464934dd9999b8955c6a537a28a03118ac8a3391fdc378413bfcacba2a3995f54b45ea05126f1d906bbad2629a8d16e88b531f2d047a7f8b5199c5db819f76eac6d83e1e428b97b71721f3280e4eab6fb1c10dd58dfad004d11061aff1ee559c4704930a4dac9e33f32707f80823438990457dafdd5d325dda22f2fab0863cbbb45cafc11c5209370e23d5bc779506f5621d75afa003932c8bdb72ff5f9a2f";

    uint8_t *payload;
    size_t length = hexstr_to_payload(hexstring, &payload);
    CU_ASSERT_EQUAL(length, strlen(hexstring) / 2); // Verify packet length

    // Layer-3 header length
    uint16_t l3_header_length = get_l3_header_length(payload);
    CU_ASSERT_EQUAL(l3_header_length, 20);

    // IPv4 destination address
    uint32_t ipv4_src_addr = get_ipv4_src_addr(payload);
    CU_ASSERT_STRING_EQUAL(ipv4_net_to_str(ipv4_src_addr), "192.168.1.222");

    // IPv4 destination address
    uint32_t ipv4_dst_addr = get_ipv4_dst_addr(payload);
    CU_ASSERT_STRING_EQUAL(ipv4_net_to_str(ipv4_dst_addr), "192.168.1.141");

    // TCP header length
    uint16_t tcp_header_length = get_tcp_header_length(payload + l3_header_length);
    CU_ASSERT_EQUAL(tcp_header_length, 20);

    // Layers 3 and 4 headers length
    uint16_t headers_length = get_headers_length(payload);
    CU_ASSERT_EQUAL(headers_length, 20 + 20);

    // Destination port
    uint16_t dst_port = get_dst_port(payload + l3_header_length);
    CU_ASSERT_EQUAL(dst_port, 443);

    // Contains payload ?
    CU_ASSERT_TRUE(length - headers_length > 0);

    free(payload);
}

/**
 * @brief Unit test using a DNS message over IPv6.
 */
void test_dns_ipv6() {

    char *hexstring = "6002ec1b002d1140fddded18f05b0000d8a3adc0f68fe5cffddded18f05b00000000000000000001b0f20035002d5388ac4a01000001000000000000036170690b736d6172747468696e677303636f6d00001c0001";

    uint8_t *payload;
    size_t length = hexstr_to_payload(hexstring, &payload);
    CU_ASSERT_EQUAL(length, strlen(hexstring) / 2); // Verify packet length

    // Layer-3 header length
    uint16_t l3_header_length = get_l3_header_length(payload);
    CU_ASSERT_EQUAL(l3_header_length, IPV6_HEADER_LENGTH);

    // IPv6 source address
    uint8_t *ipv6_src_addr = get_ipv6_src_addr(payload);
    uint8_t expected_src[IPV6_ADDR_LENGTH] = {0xfd, 0xdd, 0xed, 0x18, 0xf0, 0x5b, 0x00, 0x00, 0xd8, 0xa3, 0xad, 0xc0, 0xf6, 0x8f, 0xe5, 0xcf};
    CU_ASSERT_TRUE(compare_ipv6(ipv6_src_addr, expected_src));
    free(ipv6_src_addr);

    // IPv6 destination address
    uint8_t *ipv6_dst_addr = get_ipv6_dst_addr(payload);
    uint8_t expected_dst[IPV6_ADDR_LENGTH] = {0xfd, 0xdd, 0xed, 0x18, 0xf0, 0x5b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
    CU_ASSERT_TRUE(compare_ipv6(ipv6_dst_addr, expected_dst));
    free(ipv6_dst_addr);

    // UDP header length
    uint16_t udp_header_length = get_udp_header_length(payload + l3_header_length);
    CU_ASSERT_EQUAL(udp_header_length, UDP_HEADER_LENGTH);

    // Layers 3 and 4 headers length
    uint16_t headers_length = get_headers_length(payload);
    CU_ASSERT_EQUAL(headers_length, IPV6_HEADER_LENGTH + UDP_HEADER_LENGTH);

    // Destination port
    uint16_t dst_port = get_dst_port(payload + l3_header_length);
    CU_ASSERT_EQUAL(dst_port, 53);

    // UDP payload length
    uint16_t udp_payload_length = get_udp_payload_length(payload + l3_header_length);
    CU_ASSERT_EQUAL(udp_payload_length, 45 - UDP_HEADER_LENGTH);

    free(payload);
}

/**
 * Driver function for the unit tests.
 */
int main(int argc, char const *argv[])
{
    // Initialize registry and suite
    if (CU_initialize_registry() != CUE_SUCCESS)
        return CU_get_error();
    CU_pSuite suite = CU_add_suite("header", NULL, NULL);
    // Run tests
    CU_add_test(suite, "tcp-syn", test_tcp_syn);
    CU_add_test(suite, "https-data", test_https_data);
    CU_add_test(suite, "dns-ipv6", test_dns_ipv6);
    CU_basic_run_tests();
    CU_cleanup_registry();
    return 0;
}
