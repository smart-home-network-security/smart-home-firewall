/**
 * @file test/parsers/dhcp.c
 * @brief Unit tests for the DHCP parser
 * @date 2022-09-12
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
#include "parsers/dhcp.h"
// CUnit
#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>


/**
 * @brief Compare the headers of two DHCP messages.
 * 
 * @param actual actual DHCP message
 * @param expected expected DHCP message
 */
void compare_headers(dhcp_message_t actual, dhcp_message_t expected) {
    CU_ASSERT_EQUAL(actual.op, expected.op);
    CU_ASSERT_EQUAL(actual.htype, expected.htype);
    CU_ASSERT_EQUAL(actual.hlen, expected.hlen);
    CU_ASSERT_EQUAL(actual.hops, expected.hops);
    CU_ASSERT_EQUAL(actual.xid, expected.xid);
    CU_ASSERT_EQUAL(actual.secs, expected.secs);
    CU_ASSERT_EQUAL(actual.flags, expected.flags);
    CU_ASSERT_EQUAL(actual.ciaddr, expected.ciaddr);
    CU_ASSERT_EQUAL(actual.yiaddr, expected.yiaddr);
    CU_ASSERT_EQUAL(actual.siaddr, expected.siaddr);
    CU_ASSERT_EQUAL(actual.giaddr, expected.giaddr);
    for (uint8_t i = 0; i < MAX_HW_LEN; i++) {
        CU_ASSERT_EQUAL(actual.chaddr[i], expected.chaddr[i]);
    }
}

/**
 * @brief Compare two DHCP options lists.
 * 
 * @param actual actual DHCP options list
 * @param expected expected DHCP options list
 */
void compare_options(dhcp_options_t actual, dhcp_options_t expected) {
    for (uint8_t i = 0; i < expected.count; i++) {
        CU_ASSERT_EQUAL((actual.options + i)->code, (expected.options + i)->code);
        CU_ASSERT_EQUAL((actual.options + i)->length, (expected.options + i)->length);
        for (uint8_t j = 0; j < (actual.options + i)->length; j++) {
            CU_ASSERT_EQUAL(*(((actual.options + i)->value) + j), *(((expected.options + i)->value) + j));
        }
    }
}

/**
 * DHCP Unit test, with a DHCP Discover message.
 */
void test_dhcp_discover() {
    char *hexstring = "4500014c00000000401179a200000000ffffffff004400430138dc40010106006617ca540000000000000000000000000000000000000000788b2ab220ea00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000638253633501013d0701788b2ab220ea3902024037070103060c0f1c2a3c0c756468637020312e32382e310c16636875616e676d695f63616d6572615f697063303139ff";

    uint8_t *payload;
    size_t length = hexstr_to_payload(hexstring, &payload);
    CU_ASSERT_EQUAL(length, strlen(hexstring) / 2);  // Verify message length

    size_t skipped = get_headers_length(payload);
    dhcp_message_t message = dhcp_parse_message(payload + skipped);
    free(payload);
    //dhcp_print_message(message);

    // Test different sections of the DHCP message

    // Header
    dhcp_message_t expected;
    expected.op = DHCP_BOOTREQUEST;
    expected.htype = 1;
    expected.hlen = 6;
    expected.hops = 0;
    expected.xid = 0x6617ca54;
    expected.secs = 0;
    expected.flags = 0x0000;
    expected.ciaddr = ipv4_str_to_net("0.0.0.0");
    expected.yiaddr = ipv4_str_to_net("0.0.0.0");
    expected.siaddr = ipv4_str_to_net("0.0.0.0");
    expected.giaddr = ipv4_str_to_net("0.0.0.0");
    memcpy(expected.chaddr, "\x78\x8b\x2a\xb2\x20\xea\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", MAX_HW_LEN);
    compare_headers(message, expected);

    // Options
    expected.options.count = 7;
    expected.options.options = (dhcp_option_t *) malloc(sizeof(dhcp_option_t) * expected.options.count);
    // Option 53: DHCP Message Type
    expected.options.options->code = 53;
    expected.options.options->length = 1;
    expected.options.options->value = (uint8_t *) malloc(sizeof(uint8_t) * expected.options.options->length);
    *(expected.options.options->value) = DHCP_DISCOVER;
    CU_ASSERT_EQUAL(message.options.message_type, DHCP_DISCOVER);
    // Option 61: Client Identifier
    (expected.options.options + 1)->code = 61;
    (expected.options.options + 1)->length = 7;
    (expected.options.options + 1)->value = (uint8_t *) malloc(sizeof(uint8_t) * (expected.options.options + 1)->length);
    memcpy((expected.options.options + 1)->value, "\x01\x78\x8b\x2a\xb2\x20\xea", (expected.options.options + 1)->length);
    // Option 57: Maximum DHCP Message Size
    (expected.options.options + 2)->code = 57;
    (expected.options.options + 2)->length = 2;
    (expected.options.options + 2)->value = (uint8_t *) malloc(sizeof(uint8_t) * (expected.options.options + 2)->length);
    memcpy((expected.options.options + 2)->value, "\x02\x40", (expected.options.options + 2)->length);
    // Option 55: Parameter Request List
    (expected.options.options + 3)->code = 55;
    (expected.options.options + 3)->length = 7;
    (expected.options.options + 3)->value = (uint8_t *) malloc(sizeof(uint8_t) * (expected.options.options + 3)->length);
    memcpy((expected.options.options + 3)->value, "\x01\x03\x06\x0c\x0f\x1c\x2a", (expected.options.options + 3)->length);
    // Option 60: Vendor Class Identifier
    (expected.options.options + 4)->code = 60;
    (expected.options.options + 4)->length = 12;
    (expected.options.options + 4)->value = (uint8_t *) malloc(sizeof(uint8_t) * (expected.options.options + 4)->length);
    memcpy((expected.options.options + 4)->value, "\x75\x64\x68\x63\x70\x20\x31\x2e\x32\x38\x2e\x31", (expected.options.options + 4)->length);
    // Option 12: Host Name
    (expected.options.options + 5)->code = 12;
    (expected.options.options + 5)->length = 22;
    (expected.options.options + 5)->value = (uint8_t *) malloc(sizeof(uint8_t) * (expected.options.options + 5)->length);
    memcpy((expected.options.options + 5)->value, "\x63\x68\x75\x61\x6e\x67\x6d\x69\x5f\x63\x61\x6d\x65\x72\x61\x5f\x69\x70\x63\x30\x31\x39", (expected.options.options + 5)->length);
    // Option 255: End
    (expected.options.options + 6)->code = 255;
    (expected.options.options + 6)->length = 0;
    (expected.options.options + 6)->value = NULL;
    // Compare and free options
    compare_options(message.options, expected.options);

    // Free messages
    dhcp_free_message(message);
    dhcp_free_message(expected);
}

/**
 * DHCP Unit test, with a DHCP Offer message.
 */
void test_dhcp_offer() {
    char *hexstring = "45c0014820a000004011d452c0a80101c0a801a10043004401341617020106006617ca540000000000000000c0a801a1c0a8010100000000788b2ab220ea00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000638253633501023604c0a8010133040000a8c03a04000054603b04000093a80104ffffff001c04c0a801ff0304c0a801010604c0a801010f036c616eff000000";

    uint8_t *payload;
    size_t length = hexstr_to_payload(hexstring, &payload);
    CU_ASSERT_EQUAL(length, strlen(hexstring) / 2);  // Verify message length

    size_t skipped = get_headers_length(payload);
    dhcp_message_t message = dhcp_parse_message(payload + skipped);
    free(payload);
    //dhcp_print_message(message);

    // Test different sections of the DHCP message

    // Header
    dhcp_message_t expected;
    expected.op = DHCP_BOOTREPLY;
    expected.htype = 1;
    expected.hlen = 6;
    expected.hops = 0;
    expected.xid = 0x6617ca54;
    expected.secs = 0;
    expected.flags = 0x0000;
    expected.ciaddr = ipv4_str_to_net("0.0.0.0");
    expected.yiaddr = ipv4_str_to_net("192.168.1.161");
    expected.siaddr = ipv4_str_to_net("192.168.1.1");
    expected.giaddr = ipv4_str_to_net("0.0.0.0");
    memcpy(expected.chaddr, "\x78\x8b\x2a\xb2\x20\xea\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", MAX_HW_LEN);
    compare_headers(message, expected);

    // Options
    expected.options.count = 11;
    expected.options.options = (dhcp_option_t *) malloc(sizeof(dhcp_option_t) * expected.options.count);
    // Option 53: DHCP Message Type
    expected.options.options->code = 53;
    expected.options.options->length = 1;
    expected.options.options->value = (uint8_t *) malloc(sizeof(uint8_t) * expected.options.options->length);
    *(expected.options.options->value) = DHCP_OFFER;
    CU_ASSERT_EQUAL(message.options.message_type, DHCP_OFFER);
    // Option 54: Server Identifier
    (expected.options.options + 1)->code = 54;
    (expected.options.options + 1)->length = 4;
    (expected.options.options + 1)->value = (uint8_t *) malloc(sizeof(uint8_t) * (expected.options.options + 1)->length);
    memcpy((expected.options.options + 1)->value, "\xc0\xa8\x01\x01", (expected.options.options + 1)->length);
    // Option 51: IP Address Lease Time
    (expected.options.options + 2)->code = 51;
    (expected.options.options + 2)->length = 4;
    (expected.options.options + 2)->value = (uint8_t *) malloc(sizeof(uint8_t) * (expected.options.options + 2)->length);
    memcpy((expected.options.options + 2)->value, "\x00\x00\xa8\xc0", (expected.options.options + 2)->length);
    // Option 58: Renewal Time Value
    (expected.options.options + 3)->code = 58;
    (expected.options.options + 3)->length = 4;
    (expected.options.options + 3)->value = (uint8_t *) malloc(sizeof(uint8_t) * (expected.options.options + 3)->length);
    memcpy((expected.options.options + 3)->value, "\x00\x00\x54\x60", (expected.options.options + 3)->length);
    // Option 59: Rebinding Time Value
    (expected.options.options + 4)->code = 59;
    (expected.options.options + 4)->length = 4;
    (expected.options.options + 4)->value = (uint8_t *) malloc(sizeof(uint8_t) * (expected.options.options + 4)->length);
    memcpy((expected.options.options + 4)->value, "\x00\x00\x93\xa8", (expected.options.options + 4)->length);
    // Option 1: Subnet Mask
    (expected.options.options + 5)->code = 1;
    (expected.options.options + 5)->length = 4;
    (expected.options.options + 5)->value = (uint8_t *) malloc(sizeof(uint8_t) * (expected.options.options + 5)->length);
    memcpy((expected.options.options + 5)->value, "\xff\xff\xff\x00", (expected.options.options + 5)->length);
    // Option 28: Broadcast Address
    (expected.options.options + 6)->code = 28;
    (expected.options.options + 6)->length = 4;
    (expected.options.options + 6)->value = (uint8_t *) malloc(sizeof(uint8_t) * (expected.options.options + 6)->length);
    memcpy((expected.options.options + 6)->value, "\xc0\xa8\x01\xff", (expected.options.options + 6)->length);
    // Option 3: Router
    (expected.options.options + 7)->code = 3;
    (expected.options.options + 7)->length = 4;
    (expected.options.options + 7)->value = (uint8_t *) malloc(sizeof(uint8_t) * (expected.options.options + 7)->length);
    memcpy((expected.options.options + 7)->value, "\xc0\xa8\x01\x01", (expected.options.options + 7)->length);
    // Option 6: Domain Name Server
    (expected.options.options + 8)->code = 6;
    (expected.options.options + 8)->length = 4;
    (expected.options.options + 8)->value = (uint8_t *) malloc(sizeof(uint8_t) * (expected.options.options + 8)->length);
    memcpy((expected.options.options + 8)->value, "\xc0\xa8\x01\x01", (expected.options.options + 8)->length);
    // Option 15: Domain Name
    (expected.options.options + 9)->code = 15;
    (expected.options.options + 9)->length = 3;
    (expected.options.options + 9)->value = (uint8_t *) malloc(sizeof(uint8_t) * (expected.options.options + 9)->length);
    memcpy((expected.options.options + 9)->value, "\x6c\x61\x6e", (expected.options.options + 9)->length);
    // Option 255: End
    (expected.options.options + 10)->code = 255;
    (expected.options.options + 10)->length = 0;
    (expected.options.options + 10)->value = NULL;
    // Compare and free options
    compare_options(message.options, expected.options);

    // Free messages
    dhcp_free_message(message);
    dhcp_free_message(expected);
}

/**
 * Main function for the unit tests.
 */
int main(int argc, char const *argv[])
{
    // Initialize registry and suite
    if (CU_initialize_registry() != CUE_SUCCESS)
        return CU_get_error();
    CU_pSuite suite = CU_add_suite("dhcp", NULL, NULL);
    // Run tests
    CU_add_test(suite, "dhcp-discover", test_dhcp_discover);
    CU_add_test(suite, "dhcp-offer", test_dhcp_offer);
    CU_basic_run_tests();
    CU_cleanup_registry();
    return 0;
}
