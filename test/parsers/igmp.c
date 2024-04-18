/**
 * @file test/parsers/igmp.c
 * @brief Unit tests for the IGMP parser
 * @date 2022-10-05
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
#include "parsers/igmp.h"
// CUnit
#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>


/**
 * @brief Compare two IGMPv2 messages.
 * 
 * @param actual actual IGMPv2 message
 * @param expected expected IGMPv2 message
 */
void compare_igmp_v2_messages(igmp_v2_message_t actual, igmp_v2_message_t expected) {
    CU_ASSERT_EQUAL(actual.max_resp_time, expected.max_resp_time);
    CU_ASSERT_EQUAL(actual.checksum, expected.checksum);
    CU_ASSERT_EQUAL(actual.group_address, expected.group_address);
}

/**
 * @brief Compare two IGMPv3 Membership Report messages.
 *
 * @param actual actual IGMPv3 Membership Report message
 * @param expected expected IGMPv3 Membership Report message
 */
void compare_igmp_v3_messages(igmp_v3_membership_report_t actual, igmp_v3_membership_report_t expected) {
    CU_ASSERT_EQUAL(actual.checksum, expected.checksum);
    CU_ASSERT_EQUAL(actual.num_groups, expected.num_groups);
    for (uint16_t i = 0; i < actual.num_groups; i++) {
        igmp_v3_group_record_t actual_group = *(actual.groups + i);
        igmp_v3_group_record_t expected_group = *(expected.groups + i);
        CU_ASSERT_EQUAL(actual_group.type, expected_group.type);
        CU_ASSERT_EQUAL(actual_group.aux_data_len, expected_group.aux_data_len);
        CU_ASSERT_EQUAL(actual_group.num_sources, expected_group.num_sources);
        CU_ASSERT_EQUAL(actual_group.group_address, expected_group.group_address);
        for (uint16_t j = 0; j < actual_group.num_sources; j++) {
            CU_ASSERT_EQUAL(*(actual_group.sources + j), *(expected_group.sources + j));
        }
    }
}

/**
 * @brief Compare two IGMP messages.
 *
 * @param actual actual IGMP message
 * @param expected expected IGMP message
 */
void compare_igmp_messages(igmp_message_t actual, igmp_message_t expected)
{
    CU_ASSERT_EQUAL(actual.version, expected.version);
    if (actual.version != expected.version)
        return;
    
    CU_ASSERT_EQUAL(actual.type, expected.type);
    if (actual.type != expected.type)
        return;

    switch (actual.version)
    {
    case 2:
        compare_igmp_v2_messages(actual.body.v2_message, expected.body.v2_message);
        break;
    case 3:
        compare_igmp_v3_messages(actual.body.v3_membership_report, expected.body.v3_membership_report);
        break;
    default:
        CU_FAIL("Unknown IGMP version");
    }
}

/**
 * @brief Unit test with an IGMPv2 Membership Report message.
 */
void test_igmp_v2_membership_report() {

    char *hexstring = "46c000200000400001024096c0a801dee00000fb9404000016000904e00000fb";

    uint8_t *payload;
    size_t length = hexstr_to_payload(hexstring, &payload);
    CU_ASSERT_EQUAL(length, strlen(hexstring) / 2);  // Verify message length

    size_t skipped = get_headers_length(payload);
    igmp_message_t actual = igmp_parse_message(payload + skipped);
    free(payload);
    //igmp_print_message(actual);

    // Expected message
    igmp_message_t expected;
    expected.version = 2;
    expected.type = V2_MEMBERSHIP_REPORT;
    expected.body.v2_message.max_resp_time = 0;
    expected.body.v2_message.checksum = 0x0904;
    expected.body.v2_message.group_address = ipv4_str_to_net("224.0.0.251");

    // Compare messages
    compare_igmp_messages(actual, expected);

}

/**
 * @brief Unit test with an IGMPv2 Leave Group message.
 */
void test_igmp_v2_leave_group() {

    char *hexstring = "46c00020000040000102418fc0a801dee00000029404000017000804e00000fb";

    uint8_t *payload;
    size_t length = hexstr_to_payload(hexstring, &payload);
    CU_ASSERT_EQUAL(length, strlen(hexstring) / 2);  // Verify message length

    size_t skipped = get_headers_length(payload);
    igmp_message_t actual = igmp_parse_message(payload + skipped);
    free(payload);
    //igmp_print_message(actual);

    // Expected message
    igmp_message_t expected;
    expected.version = 2;
    expected.type = LEAVE_GROUP;
    expected.body.v2_message.max_resp_time = 0;
    expected.body.v2_message.checksum = 0x0804;
    expected.body.v2_message.group_address = ipv4_str_to_net("224.0.0.251");

    // Compare messages
    compare_igmp_messages(actual, expected);

}

/**
 * @brief Unit test with an IGMPv3 Membership Report message.
 */
void test_igmp_v3_membership_report() {

    char *hexstring = "46c0002800004000010241dec0a80173e0000016940400002200f9020000000104000000e00000fb";

    uint8_t *payload;
    size_t length = hexstr_to_payload(hexstring, &payload);
    CU_ASSERT_EQUAL(length, strlen(hexstring) / 2);  // Verify message length

    size_t skipped = get_headers_length(payload);
    igmp_message_t actual = igmp_parse_message(payload + skipped);
    free(payload);
    //igmp_print_message(actual);

    // Expected message
    igmp_message_t expected;
    expected.version = 3;
    expected.type = V3_MEMBERSHIP_REPORT;
    expected.body.v3_membership_report.checksum = 0xf902;
    expected.body.v3_membership_report.num_groups = 1;
    expected.body.v3_membership_report.groups = malloc(sizeof(igmp_v3_group_record_t));
    expected.body.v3_membership_report.groups->type = 4;
    expected.body.v3_membership_report.groups->aux_data_len = 0;
    expected.body.v3_membership_report.groups->num_sources = 0;
    expected.body.v3_membership_report.groups->group_address = ipv4_str_to_net("224.0.0.251");

    // Compare messages
    compare_igmp_messages(actual, expected);
    
    // Free messages
    igmp_free_message(actual);
    igmp_free_message(expected);
}

/**
 * Main function for the unit tests.
 */
int main(int argc, char const *argv[])
{
    // Initialize registry and suite
    if (CU_initialize_registry() != CUE_SUCCESS)
        return CU_get_error();
    CU_pSuite suite = CU_add_suite("igmp", NULL, NULL);
    // Run tests
    CU_add_test(suite, "igmp-v2-membership-report", test_igmp_v2_membership_report);
    CU_add_test(suite, "igmp-leave-group", test_igmp_v2_leave_group);
    CU_add_test(suite, "igmp-v3-membership-report", test_igmp_v3_membership_report);
    CU_basic_run_tests();
    CU_cleanup_registry();
    return 0;
}
