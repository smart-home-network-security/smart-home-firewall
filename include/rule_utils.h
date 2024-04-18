/**
 * @file include/rule_utils.h
 * @brief Interface to nftables counters
 * @date 2022-11-02
 * 
 * @copyright Copyright (c) 2022
 * 
 */

#ifndef _IOTFIREWALL_RULE_UTILS_
#define _IOTFIREWALL_RULE_UTILS_

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <sys/time.h>
#include <errno.h>
#include <nftables/libnftables.h>

#define INET_MIN_ADDRSTRLEN  1
#define INET6_MIN_ADDRSTRLEN 2

// Counter type
typedef enum {
    PACKETS = 1,
    BYTES = 2
} counter_type_t;

// Packet count value
typedef struct {
    bool is_initialized;
    uint16_t value;
} packet_count_t;

// Initial value for duration counter
typedef struct {
    bool is_initialized;
    uint64_t microseconds;
} duration_init_t;

// Initial counters values
typedef struct {
    packet_count_t packet_count;
    duration_init_t duration;
} counters_t;

// Periodic policy data
typedef struct {
    bool is_initialized;
    char *cmd;
    int16_t handle;
} periodic_policy_t;

// Aliases for libnftables
typedef struct nft_ctx nft_ctx_t;


/**
 * @brief Read the current microseconds value.
 * 
 * @return current microseconds value
 */
uint64_t counter_read_microseconds();

/**
 * @brief Initialize the values of a duration_t structure.
 * 
 * @return duration_init_t struct containing the initial duration value
 */
duration_init_t counter_duration_init();

/**
 * @brief Execute an nftables command.
 *
 * @param cmd nftables command to be executed
 * @return true if the command was correctly executed, false otherwise
 */
bool exec_nft_cmd(char *cmd);

/**
 * @brief Execute an nftables command and return its output.
 *
 * Uses libnftables to execute the command.
 *
 * @param cmd nftables command to be executed
 * @return buffer containing the command output, or NULL in case of error
 */
char *exec_nft_cmd_verbose(char *cmd);

/**
 * @brief Get an nftables handle from a command output.
 *
 * @param buf nftables command output to search for the handle
 * @return nftables handle, or -1 in case of error
 */
int16_t get_nft_handle(char *buf);

/**
 * @brief Delete an nftables rule, by specifying its handle
 *
 * @param nft_table nftables table containing the rule
 * @param nft_chain nftables chain containing the rule
 * @param handle handle of the nftables rule to delete
 * @return true if the rule was correctly deleted, false otherwise
 */
bool delete_nft_rule_by_handle(char *nft_table, char *nft_chain, int16_t handle);

/**
 * @brief Delete an nftables rule.
 *
 * @param nft_table nftables table containing the rule
 * @param nft_chain nftables chain containing the rule
 * @param nft_rule nftables rule to delete
 * @return true if the rule was correctly deleted, false otherwise
 */
bool delete_nft_rule(char *nft_table, char *nft_chain, char *nft_rule);

/**
 * @brief Read the packet count value of an nftables counter.
 *
 * @param table_name name of the nftables table containing the counter
 * @param counter_name name of the nftables counter to read
 * @return packet count value of the counter
 */
int32_t counter_read_packets(char *table_name, char *counter_name);

/**
 * @brief Read the bytes value of an nftables counter.
 *
 * @param table_name name of the nftables table containing the counter
 * @param counter_name name of the nftables counter to read
 * @return bytes value of the counter
 */
int32_t counter_read_bytes(char *table_name, char *counter_name);


#endif
