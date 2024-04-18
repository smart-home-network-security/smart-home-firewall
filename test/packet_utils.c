/**
 * @file test/packet_utils.c
 * @brief Unit tests for the packet utilities
 * @date 2022-09-13
 * 
 * @copyright Copyright (c) 2022
 * 
 */

// Standard libraries
#include <stdlib.h>
#include <string.h>
// Custom libraries
#include "packet_utils.h"
// CUnit
#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>


/**
 * @brief Unit test for the function hexstr_to_payload.
 */
void test_hexstr_to_payload() {
    char *hexstr = "48656c6c6f20576f726c6421";
    uint8_t expected[] = {0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64, 0x21};
    uint8_t *actual;
    size_t length = hexstr_to_payload(hexstr, &actual);
    CU_ASSERT_EQUAL(length, strlen(hexstr) / 2);  // Verify payload length
    // Verify payload byte by byte
    for (uint8_t i = 0; i < length; i++) {
        CU_ASSERT_EQUAL(*(actual + i), expected[i]);
    }
    free(actual);
}

/**
 * @brief Unit test for the function mac_hex_to_str.
 */
void test_mac_hex_to_str()
{
    uint8_t mac_hex[] = {0x00, 0x0c, 0x29, 0x6b, 0x9f, 0x5a};
    char *expected = "00:0c:29:6b:9f:5a";
    char *actual = mac_hex_to_str(mac_hex);
    CU_ASSERT_STRING_EQUAL(actual, expected);
    free(actual);
}

/**
 * @brief Unit test for the function mac_str_to_hex.
 */
void test_mac_str_to_hex()
{
    char *mac_str = "00:0c:29:6b:9f:5a";
    uint8_t *expected = (uint8_t *) malloc(sizeof(uint8_t) * 6);
    memcpy(expected, "\x00\x0c\x29\x6b\x9f\x5a", 6);
    uint8_t *actual = mac_str_to_hex(mac_str);
    for (uint8_t i = 0; i < 6; i++)
    {
        CU_ASSERT_EQUAL(*(actual + i), *(expected + i))
    }
    free(actual);
    free(expected);
}

/**
 * @brief Unit test for the function ipv4_net_to_str.
 */
void test_ipv4_net_to_str() {
    uint32_t ipv4_net = 0xa101a8c0;
    char *expected = "192.168.1.161";
    char *actual = ipv4_net_to_str(ipv4_net);
    CU_ASSERT_STRING_EQUAL(actual, expected);
}

/**
 * @brief Unit test for the function ipv4_str_to_net.
 */
void test_ipv4_str_to_net() {
    char *ipv4_str = "192.168.1.161";
    uint32_t expected = 0xa101a8c0;
    uint32_t actual = ipv4_str_to_net(ipv4_str);
    CU_ASSERT_EQUAL(actual, expected);
}

/**
 * @brief Unit test for the function ipv4_hex_to_str.
 */
void test_ipv4_hex_to_str() {
    char *ipv4_hex = "\xc0\xa8\x01\xa1";
    char *expected = "192.168.1.161";
    char *actual = ipv4_hex_to_str(ipv4_hex);
    CU_ASSERT_STRING_EQUAL(actual, expected);
    free(actual);
}

/**
 * @brief Unit test for the function ipv4_str_to_hex.
 */
void test_ipv4_str_to_hex() {
    char *ipv4_str = "192.168.1.161";
    char *expected = "\xc0\xa8\x01\xa1";
    char *actual = ipv4_str_to_hex(ipv4_str);
    for (uint8_t i = 0; i < 4; i++) {
        CU_ASSERT_EQUAL(*(actual + i), *(expected + i))
    }
    free(actual);
}

/**
 * @brief Unit test for the function ipv6_net_to_str.
 */
void test_ipv6_net_to_str() {
    // Full textual representation
    uint8_t ipv6_1[] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11};
    char *actual = ipv6_net_to_str(ipv6_1);
    char *expected = "1122:3344:5566:7788:99aa:bbcc:ddee:ff11";
    CU_ASSERT_STRING_EQUAL(actual, expected);
    free(actual);

    // Compressed textual representation
    uint8_t ipv6_2[] = {0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
    actual = ipv6_net_to_str(ipv6_2);
    expected = "1::1";
    CU_ASSERT_STRING_EQUAL(actual, expected);
    free(actual);
}

/**
 * @brief Unit test for the function ipv6_str_to_net.
 * 
 */
void test_ipv6_str_to_net() {
    // Full textual representation
    char *ipv6_1 = "1122:3344:5566:7788:99aa:bbcc:ddee:ff11";
    uint8_t *expected = (uint8_t *) malloc(IPV6_ADDR_LENGTH * sizeof(uint8_t));
    memcpy(expected, "\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff\x11", IPV6_ADDR_LENGTH);
    uint8_t *actual = ipv6_str_to_net(ipv6_1);
    for (uint8_t i = 0; i < IPV6_ADDR_LENGTH; i++) {
        CU_ASSERT_EQUAL(*(actual + i), *(expected + i))
    }
    free(actual);

    // Compressed textual representation
    char *ipv6_2 = "1::1";
    memcpy(expected, "\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01", IPV6_ADDR_LENGTH);
    actual = ipv6_str_to_net(ipv6_2);
    for (uint8_t i = 0; i < IPV6_ADDR_LENGTH; i++) {
        CU_ASSERT_EQUAL(*(actual + i), *(expected + i))
    }
    free(actual);
    free(expected);
}

/**
 * @brief Unit test for the function ip_net_to_str.
 */
void test_ip_net_to_str() {
    // IPv4
    ip_addr_t ipv4 = {.version = 4, .value.ipv4 = 0x0101a8c0};
    char *actual = ip_net_to_str(ipv4);
    char *expected = "192.168.1.1";
    CU_ASSERT_STRING_EQUAL(actual, expected);

    // IPv6
    ip_addr_t ipv6 = {.version = 6, .value.ipv6 = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11}};
    actual = ip_net_to_str(ipv6);
    expected = "1122:3344:5566:7788:99aa:bbcc:ddee:ff11";
    CU_ASSERT_STRING_EQUAL(actual, expected);
    free(actual);
}

/**
 * @brief Unit test for the function ip_str_to_net.
 *
 */
void test_ip_str_to_net()
{
    // IPv4
    char *ipv4_str = "192.168.1.161";
    ip_addr_t actual = ip_str_to_net(ipv4_str, 4);
    ip_addr_t expected = (ip_addr_t) {.version = 4, .value.ipv4 = 0xa101a8c0};
    CU_ASSERT_EQUAL(actual.version, expected.version);
    CU_ASSERT_EQUAL(actual.value.ipv4, expected.value.ipv4);

    // IPv6
    char *ipv6_str = "1122:3344:5566:7788:99aa:bbcc:ddee:ff11";
    actual = ip_str_to_net(ipv6_str, 6);
    expected.version = 6;
    memcpy(expected.value.ipv6, "\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff\x11", IPV6_ADDR_LENGTH);
    CU_ASSERT_EQUAL(actual.version, expected.version);
    for (uint8_t i = 0; i < IPV6_ADDR_LENGTH; i++) {
        CU_ASSERT_EQUAL(actual.value.ipv6[i], expected.value.ipv6[i]);
    }
}

/**
 * @brief Unit test for the function compare_ipv6.
 */
void test_compare_ipv6() {
    uint8_t ipv6_1[] = {0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
    uint8_t ipv6_2[] = {0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
    uint8_t ipv6_3[] = {0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02};
    CU_ASSERT_TRUE(compare_ipv6(ipv6_1, ipv6_2));
    CU_ASSERT_TRUE(compare_ipv6(ipv6_2, ipv6_1));
    CU_ASSERT_FALSE(compare_ipv6(ipv6_1, ipv6_3));
    CU_ASSERT_FALSE(compare_ipv6(ipv6_3, ipv6_1));
}

/**
 * @brief Unit test for the function compare_ip.
 */
void test_compare_ip() {
    // Compare IPv4
    ip_addr_t ipv4_1 = { .version = 4, .value.ipv4 = 0xa101a8c0 };
    ip_addr_t ipv4_2 = {.version = 4, .value.ipv4 = 0xa101a8c0};
    ip_addr_t ipv4_3 = {.version = 4, .value.ipv4 = 0xa201a8c0};
    CU_ASSERT_TRUE(compare_ip(ipv4_1, ipv4_2));
    CU_ASSERT_TRUE(compare_ip(ipv4_2, ipv4_1));
    CU_ASSERT_FALSE(compare_ip(ipv4_1, ipv4_3));
    CU_ASSERT_FALSE(compare_ip(ipv4_3, ipv4_1));

    // Compare IPv6
    ip_addr_t ipv6_1 = {.version = 6, .value.ipv6 = {0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}};
    ip_addr_t ipv6_2 = {.version = 6, .value.ipv6 = {0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}};
    ip_addr_t ipv6_3 = {.version = 6, .value.ipv6 = {0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02}};
    CU_ASSERT_TRUE(compare_ip(ipv6_1, ipv6_2));
    CU_ASSERT_TRUE(compare_ip(ipv6_2, ipv6_1));
    CU_ASSERT_FALSE(compare_ip(ipv6_1, ipv6_3));
    CU_ASSERT_FALSE(compare_ip(ipv6_3, ipv6_1));

    // Compare IPv4 and IPv6
    CU_ASSERT_FALSE(compare_ip(ipv4_1, ipv6_1));
    CU_ASSERT_FALSE(compare_ip(ipv6_1, ipv4_1));
}

/**
 * Test suite entry point.
 */
int main(int argc, char const *argv[])
{
    // Initialize the CUnit test registry and suite
    printf("Test suite: packet_utils\n");
    if (CU_initialize_registry() != CUE_SUCCESS)
        return CU_get_error();
    CU_pSuite suite = CU_add_suite("packet_utils", NULL, NULL);
    // Add and run tests
    CU_add_test(suite, "hexstr_to_payload", test_hexstr_to_payload);
    CU_add_test(suite, "mac_hex_to_str", test_mac_hex_to_str);
    CU_add_test(suite, "mac_str_to_hex", test_mac_str_to_hex);
    CU_add_test(suite, "ipv4_net_to_str", test_ipv4_net_to_str);
    CU_add_test(suite, "ipv4_str_to_net", test_ipv4_str_to_net);
    CU_add_test(suite, "ipv4_hex_to_str", test_ipv4_hex_to_str);
    CU_add_test(suite, "ipv4_str_to_hex", test_ipv4_str_to_hex);
    CU_add_test(suite, "ipv6_net_to_str", test_ipv6_net_to_str);
    CU_add_test(suite, "ipv6_str_to_net", test_ipv6_str_to_net);
    CU_add_test(suite, "ip_net_to_str", test_ip_net_to_str);
    CU_add_test(suite, "ip_str_to_net", test_ip_str_to_net);
    CU_add_test(suite, "compare_ipv6", test_compare_ipv6);
    CU_add_test(suite, "compare_ip", test_compare_ip);
    CU_basic_run_tests();
    CU_cleanup_registry();
    return 0;
}
