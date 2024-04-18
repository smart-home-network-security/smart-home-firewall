/**
 * @file test/parsers/coap.c
 * @brief Unit tests for the CoAP parser
 * @date 2022-11-30
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
#include "parsers/coap.h"
// CUnit
#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>


/**
 * @brief Unit test for the CoAP parser, using a Non-Confirmable GET message.
 */
void test_coap_non_get() {

    char *hexstring = "60017a1800451102fe80000000000000db22fbeca6b444feff0200000000000000000000000001588b5316330045c374580175f2d55892c87b38f0fbb36f6963037265734d1472743d782e636f6d2e73616d73756e672e70726f766973696f6e696e67696e666f213ce1fed6c0";

    uint8_t *payload;
    size_t length = hexstr_to_payload(hexstring, &payload);
    CU_ASSERT_EQUAL(length, strlen(hexstring) / 2);  // Verify message length

    // Actual message
    size_t skipped = get_ipv6_header_length(payload);
    uint16_t coap_length = get_udp_payload_length(payload + skipped);
    skipped += get_udp_header_length(payload + skipped);
    coap_message_t actual = coap_parse_message(payload + skipped, coap_length);
    free(payload);
    //coap_print_message(actual);

    // Expected message
    coap_message_t expected;
    expected.type = COAP_NON;
    expected.method = HTTP_GET;
    expected.uri = "/oic/res?rt=x.com.samsung.provisioninginfo";

    // Compare messages
    CU_ASSERT_EQUAL(actual.type, expected.type);
    CU_ASSERT_EQUAL(actual.method, expected.method);
    CU_ASSERT_STRING_EQUAL(actual.uri, expected.uri);

    coap_free_message(actual);

}


/**
 * Main function for the unit tests.
 */
int main(int argc, char const *argv[])
{
    // Initialize registry and suite
    if (CU_initialize_registry() != CUE_SUCCESS)
        return CU_get_error();
    CU_pSuite suite = CU_add_suite("coap", NULL, NULL);
    // Run tests
    CU_add_test(suite, "coap-non-get", test_coap_non_get);
    CU_basic_run_tests();
    CU_cleanup_registry();
    return 0;
}
