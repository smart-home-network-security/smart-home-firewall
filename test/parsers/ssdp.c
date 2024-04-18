/**
 * @file test/parsers/ssdp.c
 * @brief Unit tests for the SSDP parser
 * @date 2022-11-24
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
#include "parsers/ssdp.h"
// CUnit
#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>


/**
 * @brief Unit test for an SSDP M-SEARCH message.
 */
void test_ssdp_msearch() {

    char *hexstring = "45000095dba640000111eb7bc0a80193effffffad741076c008163124d2d534541524348202a20485454502f312e310d0a4d583a20340d0a4d414e3a2022737364703a646973636f766572220d0a484f53543a203233392e3235352e3235352e3235303a313930300d0a53543a2075726e3a736368656d61732d75706e702d6f72673a6465766963653a62617369633a310d0a0d0a";

    uint8_t *payload;
    size_t length = hexstr_to_payload(hexstring, &payload);
    CU_ASSERT_EQUAL(length, strlen(hexstring) / 2);  // Verify message length

    uint32_t dst_addr = get_ipv4_dst_addr(payload); // IPv4 destination address, in network byte order
    size_t skipped = get_ipv4_header_length(payload);
    skipped += get_udp_header_length(payload + skipped);
    ssdp_message_t actual = ssdp_parse_message(payload + skipped, dst_addr);
    free(payload);
    //ssdp_print_message(actual);

    // Test if SSDP message has been correctly parsed
    ssdp_message_t expected;
    expected.is_request = true;
    expected.method = SSDP_M_SEARCH;
    CU_ASSERT_EQUAL(actual.is_request, expected.is_request);
    CU_ASSERT_EQUAL(actual.method, expected.method);

}

/**
 * @brief Unit test for an SSDP NOTIFY message.
 */
void test_ssdp_notify() {

    char *hexstring = "4500014db3ea4000ff111485c0a8018deffffffa076c076c01399a564e4f54494659202a20485454502f312e310d0a484f53543a203233392e3235352e3235352e3235303a313930300d0a43414348452d434f4e54524f4c3a206d61782d6167653d3130300d0a4c4f434154494f4e3a20687474703a2f2f3139322e3136382e312e3134313a38302f6465736372697074696f6e2e786d6c0d0a5345525645523a204875652f312e302055506e502f312e3020332e31342e302f49704272696467650d0a4e54533a20737364703a616c6976650d0a6875652d62726964676569643a20303031373838464646453734433244430d0a4e543a2075706e703a726f6f746465766963650d0a55534e3a20757569643a32663430326638302d646135302d313165312d396232332d3030313738383734633264633a3a75706e703a726f6f746465766963650d0a0d0a";

    uint8_t *payload;
    size_t length = hexstr_to_payload(hexstring, &payload);
    CU_ASSERT_EQUAL(length, strlen(hexstring) / 2);  // Verify message length

    uint32_t dst_addr = get_ipv4_dst_addr(payload);  // IPv4 destination address, in network byte order
    size_t skipped = get_ipv4_header_length(payload);
    skipped += get_udp_header_length(payload + skipped);
    ssdp_message_t actual = ssdp_parse_message(payload + skipped, dst_addr);
    free(payload);
    //ssdp_print_message(actual);

    // Test if SSDP message has been correctly parsed
    ssdp_message_t expected;
    expected.is_request = true;
    expected.method = SSDP_NOTIFY;
    CU_ASSERT_EQUAL(actual.is_request, expected.is_request);
    CU_ASSERT_EQUAL(actual.method, expected.method);
}

/**
 * @brief Unit test for an SSDP response.
 */
void test_ssdp_response() {

    char *hexstring = "45000140456c400040116f85c0a8018dc0a801de076c0f66012cdcc8485454502f312e3120323030204f4b0d0a484f53543a203233392e3235352e3235352e3235303a313930300d0a4558543a0d0a43414348452d434f4e54524f4c3a206d61782d6167653d3130300d0a4c4f434154494f4e3a20687474703a2f2f3139322e3136382e312e3134313a38302f6465736372697074696f6e2e786d6c0d0a5345525645523a204875652f312e302055506e502f312e302049704272696467652f312e34382e300d0a6875652d62726964676569643a20303031373838464646453734433244430d0a53543a2075706e703a726f6f746465766963650d0a55534e3a20757569643a32663430326638302d646135302d313165312d396232332d3030313738383734633264633a3a75706e703a726f6f746465766963650d0a0d0a";

    uint8_t *payload;
    size_t length = hexstr_to_payload(hexstring, &payload);
    CU_ASSERT_EQUAL(length, strlen(hexstring) / 2);  // Verify message length

    uint32_t dst_addr = get_ipv4_dst_addr(payload);  // IPv4 destination address, in network byte order
    size_t skipped = get_ipv4_header_length(payload);
    skipped += get_udp_header_length(payload + skipped);
    ssdp_message_t actual = ssdp_parse_message(payload + skipped, dst_addr);
    free(payload);
    //ssdp_print_message(actual);

    // Test if SSDP message has been correctly parsed
    ssdp_message_t expected;
    expected.is_request = false;
    expected.method = SSDP_UNKNOWN;
    CU_ASSERT_EQUAL(actual.is_request, expected.is_request);
    CU_ASSERT_EQUAL(actual.method, expected.method);

}

/**
 * Main function for the unit tests.
 */
int main(int argc, char const *argv[]) {
    // Initialize registry and suite
    if (CU_initialize_registry() != CUE_SUCCESS)
        return CU_get_error();
    CU_pSuite suite = CU_add_suite("ssdp", NULL, NULL);
    // Run tests
    CU_add_test(suite, "ssdp-msearch", test_ssdp_msearch);
    CU_add_test(suite, "ssdp-notify", test_ssdp_notify);
    CU_add_test(suite, "ssdp-response", test_ssdp_response);
    CU_basic_run_tests();
    CU_cleanup_registry();
    return 0;
}
