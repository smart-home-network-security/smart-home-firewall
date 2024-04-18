/**
 * @file test/rule_utils.c
 * @brief Unit tests for the rule utilitaries
 * @date 2022-11-02
 * 
 * @copyright Copyright (c) 2022
 * 
 */

#include <stdio.h>
#include <stdint.h>
#include <sys/time.h>
// Custom libraries
#include "rule_utils.h"
// CUnit
#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>


// Store one handle to be used by a later test
int16_t rule_handle;


/**
 * @brief Test the reading of the current time in microseconds.
 */
void test_counter_read_microseconds() {
    // Retrieve time before calling function under test
    struct timeval tv;
    int ret = gettimeofday(&tv, NULL);
    if (ret != 0) {
        CU_FAIL("test_counter_read_microseconds: Error with gettimeofday");
        return;
    }
    uint64_t timestamp_base = ((uint64_t) tv.tv_sec) * 1000000 + ((uint64_t) tv.tv_usec);
    // Call function under test
    CU_ASSERT_TRUE(counter_read_microseconds() >= timestamp_base);
}

/**
 * @brief Test the duration counter initialization.
 */
void test_counter_duration_init() {
    // Retrieve time before calling function under test
    struct timeval tv;
    int ret = gettimeofday(&tv, NULL);
    if (ret != 0)
    {
        CU_FAIL("test_counter_duration_init: Error with gettimeofday");
        return;
    }
    uint64_t timestamp = ((uint64_t)tv.tv_sec) * 1000000 + ((uint64_t)tv.tv_usec);

    // Initialize duration counter
    duration_init_t duration = counter_duration_init();
    CU_ASSERT(duration.is_initialized);
    CU_ASSERT(duration.microseconds >= timestamp);
}

/**
 * @brief Test the execution of an nftables command.
 */
void test_exec_nft_cmd() {
    // Build rule string
    char *rule = "ip saddr 192.168.1.1";
    uint16_t length = 32 + strlen(rule);
    char add_rule_cmd[length];
    int ret = snprintf(add_rule_cmd, length, "add rule test-table test-chain %s", rule);
    if (ret != length - 1)
    {
        CU_FAIL("test_exec_nft_cmd: could not build the command to add the rule.");
        return;
    }

    // Execute command to add rule
    bool success = exec_nft_cmd(add_rule_cmd);
    CU_ASSERT_TRUE(success);
}

/**
 * @brief Test the verbose execution of an nftables command.
 */
void test_exec_nft_cmd_verbose()
{
    // Build rule string
    char *rule = "ip daddr 192.168.1.2";
    uint16_t length = 32 + strlen(rule);
    char add_rule_cmd[length];
    int ret = snprintf(add_rule_cmd, length, "add rule test-table test-chain %s", rule);
    if (ret != length - 1)
    {
        CU_FAIL("test_exec_nft_cmd_verbose: could not build the command to add the rule.");
        return;
    }

    // Execute command to add rule
    char *output = exec_nft_cmd_verbose(add_rule_cmd);
    CU_ASSERT_PTR_NOT_NULL(output);
    CU_ASSERT(strlen(output) > strlen(add_rule_cmd));
    free(output);
}

/**
 * @brief Test the retrieval of an nftables handle.
 */
void test_get_nft_handle()
{
    // Build rule string
    char *rule = "ip daddr 192.168.1.3";
    uint16_t length = 32 + strlen(rule);
    char add_rule_cmd[length];
    int ret = snprintf(add_rule_cmd, length, "add rule test-table test-chain %s", rule);
    if (ret != length - 1)
    {
        CU_FAIL("test_exec_nft_cmd_verbose: could not build the command to add the rule.");
        return;
    }

    // Execute command and get handle
    char *output = exec_nft_cmd_verbose(add_rule_cmd);
    int16_t handle = get_nft_handle(output);
    free(output);
    rule_handle = handle;
    CU_ASSERT(handle >= 0);
}

/**
 * @brief Test the deletion of an nftables rule by its handle value.
 */
void test_delete_nft_rule_by_handle()
{
    // Delete an existing rule
    bool result = delete_nft_rule_by_handle("test-table", "test-chain", rule_handle);
    CU_ASSERT_TRUE(result);
}

/**
 * @brief Test the deletion of an nftables rule by its string.
 */
void test_delete_nft_rule() {
    // Delete an existing rule
    char *rule = "ip saddr 192.168.1.1";
    bool result = delete_nft_rule("test-table", "test-chain", rule);
    CU_ASSERT_TRUE(result);
}

/**
 * @brief Test the reading of the packets value of an nftables counter.
 */
void test_counter_read_packets()
{
    CU_ASSERT_EQUAL(counter_read_packets("test-table", "counter1"), 0);
}

/**
 * @brief Test the reading of the bytes value of an nftables counter.
 */
void test_counter_read_bytes()
{
    CU_ASSERT_EQUAL(counter_read_bytes("test-table", "counter1"), 0);
}

/**
 * Test suite entry point.
 */
int main(int argc, char const *argv[]) {
    // Initialize the CUnit test registry and suite
    printf("Test suite: rule_utils\n");
    if (CU_initialize_registry() != CUE_SUCCESS)
        return CU_get_error();
    CU_pSuite suite = CU_add_suite("rule_utils", NULL, NULL);

    // Initialize the nftables table and counter
    int err;
    err = system("sudo nft flush ruleset");
    if (err == -1) {
        CU_FAIL("Error when executing command `sudo nft flush ruleset`");
    }
    err = system("sudo nft add table test-table");
    if (err == -1) {
        CU_FAIL("Error when executing command `sudo nft add table test-table`");
    }
    err = system("sudo nft add chain test-table test-chain { type filter hook prerouting priority 0 \\; }");
    if (err == -1) {
        CU_FAIL("Error when executing command `sudo nft add chain test-table test-chain { type filter hook prerouting priority 0 \\; }`");
    }
    err = system("sudo nft add counter test-table counter1");
    if (err == -1) {
        CU_FAIL("Error when executing command `sudo nft add counter test-table counter1`");
    }

    // Add and run tests
    CU_add_test(suite, "counter_read_microseconds", test_counter_read_microseconds);
    CU_add_test(suite, "counter_duration_init", test_counter_duration_init);
    CU_add_test(suite, "exec_nft_cmd", test_exec_nft_cmd);
    CU_add_test(suite, "exec_nft_cmd_verbose", test_exec_nft_cmd_verbose);
    CU_add_test(suite, "get_nft_handle", test_get_nft_handle);
    CU_add_test(suite, "delete_nft_rule_by_handle", test_delete_nft_rule_by_handle);
    CU_add_test(suite, "delete_nft_rule", test_delete_nft_rule);
    CU_add_test(suite, "counter_read_packets", test_counter_read_packets);
    CU_add_test(suite, "counter_read_bytes", test_counter_read_bytes);
    CU_basic_run_tests();
    CU_cleanup_registry();
    return 0;
}
