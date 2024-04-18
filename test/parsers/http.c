/**
 * @file test/parsers/http.c
 * @brief Unit tests for the HTTP parser
 * @date 2022-20-09
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
#include "parsers/http.h"
// CUnit
#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>


/**
 * @brief Unit test for the HTTP parser.
 */
void test_http_request() {

    char *hexstring = "450000ccb11f400040065845c0a801a16e2b005387b8005023882026a6ab695450180e4278860000474554202f67736c623f747665723d322669643d33363932313536313726646d3d6f74732e696f2e6d692e636f6d2674696d657374616d703d38267369676e3d6a327a743325324270624177637872786f765155467443795a3644556d47706c584e4b723169386a746552623425334420485454502f312e310d0a486f73743a20646e732e696f2e6d692e636f6d0d0a557365722d4167656e743a204d496f540d0a0d0a";

    uint8_t *payload;
    size_t length = hexstr_to_payload(hexstring, &payload);
    CU_ASSERT_EQUAL(length, strlen(hexstring) / 2);  // Verify message length

    size_t l3_header_length = get_l3_header_length(payload);
    uint16_t dst_port = get_dst_port(payload + l3_header_length);
    size_t skipped = get_headers_length(payload);
    http_message_t actual = http_parse_message(payload + skipped, dst_port);
    free(payload);
    //http_print_message(actual);

    // Test if HTTP message has been correctly parsed
    http_message_t expected;
    expected.is_request = true;
    expected.method = HTTP_GET;
    expected.uri = "/gslb?tver=2&id=369215617&dm=ots.io.mi.com&timestamp=8&sign=j2zt3%2BpbAwcxrxovQUFtCyZ6DUmGplXNKr1i8jteRb4%3D";
    CU_ASSERT_EQUAL(actual.is_request, expected.is_request);
    CU_ASSERT_EQUAL(actual.method, expected.method);
    CU_ASSERT_STRING_EQUAL(actual.uri, expected.uri);

    http_free_message(actual);

}

void test_http_response() {

    char *hexstring = "450001a42fc540002f06e9c76e2b0053c0a801a1005087b8a6ab6954238820ca501803b8e92e0000485454502f312e3120323030204f4b0d0a5365727665723a2054656e67696e650d0a446174653a205765642c203330204d617220323032322031323a30353a323420474d540d0a436f6e74656e742d547970653a206170706c69636174696f6e2f6a736f6e3b20636861727365743d7574662d380d0a436f6e74656e742d4c656e6774683a203231350d0a436f6e6e656374696f6e3a206b6565702d616c6976650d0a0d0a7b22696e666f223a7b22656e61626c65223a312c22686f73745f6c697374223a5b7b226970223a223132302e39322e39362e313535222c22706f7274223a3434337d2c7b226970223a223132302e39322e3134352e313430222c22706f7274223a3434337d2c7b226970223a223132302e39322e36352e323431222c22706f7274223a3434337d5d7d2c227369676e223a225a757856496a2b337858303362654a4b5936684e385668454f7a65485630446a6753654471656d2b7032413d222c2274696d657374616d70223a313634383634313932347d";

    uint8_t *payload;
    size_t length = hexstr_to_payload(hexstring, &payload);
    CU_ASSERT_EQUAL(length, strlen(hexstring) / 2); // Verify message length

    size_t skipped = get_ipv4_header_length(payload);
    uint16_t dst_port = get_dst_port(payload + skipped);
    skipped += get_tcp_header_length(payload + skipped);
    http_message_t actual = http_parse_message(payload + skipped, dst_port);
    free(payload);
    //http_print_message(actual);

    // Test if HTTP message has been correctly parsed
    http_message_t expected;
    expected.is_request = false;
    CU_ASSERT_EQUAL(actual.is_request, expected.is_request);

    http_free_message(actual);

}

/**
 * Driver function for the unit tests.
 */
int main(int argc, char const *argv[])
{
    // Initialize registry and suite
    if (CU_initialize_registry() != CUE_SUCCESS)
        return CU_get_error();
    CU_pSuite suite = CU_add_suite("http", NULL, NULL);
    // Run tests
    CU_add_test(suite, "http-request", test_http_request);
    CU_add_test(suite, "http-response", test_http_response);
    CU_basic_run_tests();
    CU_cleanup_registry();
    return 0;
}
