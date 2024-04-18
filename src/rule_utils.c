/**
 * @file src/rule_utils.c
 * @brief Rule utilitaries
 * @date 2022-11-02
 *
 * @copyright Copyright (c) 2022
 *
 */

#include "rule_utils.h"


/**
 * @brief Read the current microseconds value.
 *
 * @return current microseconds value
 */
uint64_t counter_read_microseconds() {
    struct timeval tv;
    int ret = gettimeofday(&tv, NULL);
    if (ret != 0) {
        perror("counters_read_microseconds - gettimeofday");
        exit(EXIT_FAILURE);
    }
    return ((uint64_t) tv.tv_sec) * 1000000 + ((uint64_t) tv.tv_usec);
}

/**
 * @brief Initialize the values of a duration_init_t structure.
 *
 * @param nft_table_name name of the nftables table containing the associated nftables counter
 * @param nft_counter_name name of the associated nftables counter
 * @return duration_init_t struct containing the initial duration value
 */
duration_init_t counter_duration_init() {
    duration_init_t duration;
    duration.is_initialized = true;
    duration.microseconds = counter_read_microseconds();
    return duration;
}

/**
 * @brief Execute an nftables command.
 *
 * @param cmd nftables command to be executed
 * @return true if the command was correctly executed, false otherwise
 */
bool exec_nft_cmd(char *cmd) {
    // Create nftables context
    nft_ctx_t *ctx = nft_ctx_new(NFT_CTX_DEFAULT);
    if (ctx == NULL)
    {
        fprintf(stderr, "Failed to create nftables context for command \"%s\"\n", cmd);
        return false;
    }

    // Execute command
    int err = nft_run_cmd_from_buffer(ctx, cmd);
    if (err != 0)
    {
        fprintf(stderr, "Failed to run nftables command \"%s\"\n", cmd);
        return false;
    }

    nft_ctx_free(ctx);
    return true;
}

/**
 * @brief Execute an nftables command and return its output.
 * 
 * Uses libnftables to execute the command.
 * 
 * @param cmd nftables command to be executed
 * @return buffer containing the command output, or NULL in case of error
 */
char* exec_nft_cmd_verbose(char *cmd) {
    // Create nftables context
    nft_ctx_t *ctx = nft_ctx_new(NFT_CTX_DEFAULT);
    if (ctx == NULL)
    {
        fprintf(stderr, "Failed to create nftables context for command \"%s\"\n", cmd);
        return NULL;
    }

    // Set output buffer
    unsigned int flags = NFT_CTX_OUTPUT_HANDLE | NFT_CTX_OUTPUT_ECHO;
    nft_ctx_output_set_flags(ctx, flags);
    int err = nft_ctx_buffer_output(ctx);
    if (err != 0)
    {
        fprintf(stderr, "Failed to set output buffer for nft command \"%s\"\n", cmd);
        return NULL;
    }

    // Execute command
    err = nft_run_cmd_from_buffer(ctx, cmd);
    if (err != 0)
    {
        fprintf(stderr, "Failed to run nftables command \"%s\"\n", cmd);
        return NULL;
    }

    // Retrieve output buffer and free resources
    const char *tmp = nft_ctx_get_output_buffer(ctx);
    size_t length = strlen(tmp) + 1;
    char *output = (char *) malloc(sizeof(char) * length);
    if (output == NULL)
    {
        fprintf(stderr, "Failed to allocate memory for output buffer of nft command \"%s\"\n", cmd);
        return NULL;
    }
    memcpy(output, tmp, length);
    nft_ctx_free(ctx);
    return output;
}

/**
 * @brief Get an nftables handle from a command output.
 * 
 * @param buf nftables command output to search for the handle
 * @return nftables handle, or -1 in case of error
 */
int16_t get_nft_handle(char *buf) {
    // Find handle value
    char *handle_str = strstr(buf, "handle");
    if (handle_str == NULL)
    {
        fprintf(stderr, "No handle found in buffer \"%s\"\n", buf);
        return -1;
    }

    // Parse handle value
    int16_t handle;
    int err = sscanf(handle_str, "handle %hd", &handle);
    if (err != 1)
    {
        fprintf(stderr, "Error while reading handle in string %s\n", handle_str);
        return -1;
    }

    // No error (who would've thought ?), return handle
    return handle;
}

/**
 * @brief Delete an nftables rule, by specifying its handle
 *
 * @param nft_table nftables table containing the rule
 * @param nft_chain nftables chain containing the rule
 * @param handle handle of the nftables rule to delete
 * @return true if the rule was correctly deleted, false otherwise
 */
bool delete_nft_rule_by_handle(char *nft_table, char *nft_chain, int16_t handle) {
    // Build command to delete the correspondig nftables rule
    uint16_t length = 27 + strlen(nft_table) + strlen(nft_chain);
    char delete_handle_cmd[length];
    int err = snprintf(delete_handle_cmd, length, "delete rule %s %s handle %hu", nft_table, nft_chain, handle);
    if (err < length - 5 || err > length - 1)
    {
        fprintf(stderr, "Error while building command to delete rule with handle %hu\n", handle);
        return false;
    }

    // Execute command to delete the corresponding nftables rule
    char *buf = exec_nft_cmd_verbose(delete_handle_cmd);
    if (buf == NULL)
    {
        fprintf(stderr, "Failed to run nft command \"%s\"\n", delete_handle_cmd);
        return false;
    }
    else
    {
        printf("Successfully deleted rule with handle %hu\n", handle);
        free(buf);
        return true;
    }
}

/**
 * @brief Delete an nftables rule.
 *
 * Retrieve the rule handle,
 * then delete the rule.
 *
 * @param nft_table nftables table containing the rule
 * @param nft_chain nftables chain containing the rule
 * @param nft_rule nftables rule to delete
 * @return true if the rule was correctly deleted, false otherwise
 */
bool delete_nft_rule(char *nft_table, char *nft_chain, char *nft_rule) {
    // Build command to read rule handle value
    uint16_t length = 13 + strlen(nft_table) + strlen(nft_chain);
    char read_handle_cmd[length];
    int err = snprintf(read_handle_cmd, length, "list chain %s %s", nft_table, nft_chain);
    if (err != length - 1) {
        fprintf(stderr, "Error while building command to read handle value for rule \"%s\"\n", nft_rule);
        return false;
    }

    // Execute nft command
    char *buf = exec_nft_cmd_verbose(read_handle_cmd);
    if (buf == NULL) {
        return false;
    }

    // Retrive the line containing the rule to delete
    char *rule_line = strstr(buf, nft_rule);

    // Retrieve handle
    int16_t handle = get_nft_handle(rule_line);
    free(buf);
    if (handle == -1)
    {
        fprintf(stderr, "Failed to retrieve handle for rule \"%s\"\n", nft_rule);
        return false;
    }

    // Delete rule with corresponding handle
    return delete_nft_rule_by_handle(nft_table, nft_chain, handle);
}

/**
 * @brief Generic function to read an nftables counter value.
 *
 * @param table_name name of the nftables table containing the counter
 * @param counter_name name of the nftables counter to read
 * @param counter_type type of the counter to read
 * @return value read from the counter, or -1 in case of error
 */
static int32_t counter_read_nft(char *table_name, char *counter_name, counter_type_t counter_type)
{
    // Build command
    uint16_t length = 15 + strlen(table_name) + strlen(counter_name);
    char cmd[length];
    int err = snprintf(cmd, length, "list counter %s %s", table_name, counter_name);
    if (err != length - 1)
    {
        fprintf(stderr, "Error while building command to read counter %s in table %s\n", counter_name, table_name);
        return -1;
    }

    // Execute command
    char *output = exec_nft_cmd_verbose(cmd);
    if (output == NULL)
    {
        fprintf(stderr, "Failed to run command \"%s\"\n", cmd);
        return -1;
    }

    // Find the substring containing the counter value
    char *pattern;
    char *format;
    switch (counter_type)
    {
    case PACKETS:
        pattern = "packets";
        format = "packets %d";
        break;
    case BYTES:
        pattern = "bytes";
        format = "bytes %d";
        break;
    default:
        return -1;
    }
    char *substring = strstr(output, pattern);
    if (substring == NULL)
    {
        fprintf(stderr, "Error while reading output of command \"%s\"\n", cmd);
        return -1;
    }

    // Parse the counters value
    int32_t count;
    err = sscanf(substring, format, &count);
    free(output);
    if (err != 1)
    {
        fprintf(stderr, "Error while parsing output of command \"%s\"\n", cmd);
        return -1;
    }

    return count;
}

/**
 * @brief Read the packet count value of an nftables counter.
 *
 * @param table_name name of the nftables table containing the counter
 * @param counter_name name of the nftables counter to read
 * @return packet count value of the counter
 */
int32_t counter_read_packets(char *table_name, char *counter_name)
{
    return counter_read_nft(table_name, counter_name, PACKETS);
}

/**
 * @brief Read the bytes value of an nftables counter.
 *
 * @param table_name name of the nftables table containing the counter
 * @param counter_name name of the nftables counter to read
 * @return bytes value of the counter
 */
int32_t counter_read_bytes(char *table_name, char *counter_name)
{
    return counter_read_nft(table_name, counter_name, BYTES);
}
