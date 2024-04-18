/**
 * @file src/parsers/dhcp.c
 * @brief DHCP message parser
 * @date 2022-09-12
 * 
 * @copyright Copyright (c) 2022
 * 
 */

#include "parsers/dhcp.h"


///// PARSING /////

/**
 * @brief Parse the header of a DHCP message (not including options).
 * 
 * @param data a pointer to the start of the DHCP message
 * @return the parsed DHCP message with the header fields filled in
 */
dhcp_message_t dhcp_parse_header(uint8_t *data) {
    dhcp_message_t message;
    // Opcode: 1 byte
    message.op = *data;
    // htype: 1 byte
    message.htype = *(data + 1);
    // hlen: 1 byte
    message.hlen = *(data + 2);
    // hops: 1 byte
    message.hops = *(data + 3);
    // xid: 4 bytes
    message.xid = ntohl(*((uint32_t *) (data + 4)));
    // secs: 2 bytes
    message.secs = ntohs(*((uint16_t *) (data + 8)));
    // flags: 2 bytes
    message.flags = ntohs(*((uint16_t *) (data + 10)));
    // The IP addresses are left in network byte order
    // ciaddr: 4 bytes
    message.ciaddr = *((uint32_t *) (data + 12));
    // yiaddr: 4 bytes
    message.yiaddr = *((uint32_t *) (data + 16));
    // siaddr: 4 bytes
    message.siaddr = *((uint32_t *) (data + 20));
    // giaddr: 4 bytes
    message.giaddr = *((uint32_t *) (data + 24));
    // chaddr: 16 bytes
    memcpy(message.chaddr, data + 28, sizeof(uint8_t) * 16);
    // sname: 64 bytes
    memcpy(message.sname, data + 44, sizeof(uint8_t) * 64);
    // file: 128 bytes
    memcpy(message.file, data + 108, sizeof(uint8_t) * 128);
    return message;
}

/**
 * @brief Parse a DHCP option.
 * 
 * @param data a pointer to the start of the DHCP option
 * @param offset a pointer to the current offset inside the DHCP message
 *               Its value will be updated to point to the next option
 * @return the parsed DHCP option
 */
dhcp_option_t dhcp_parse_option(uint8_t *data, uint16_t *offset) {
    dhcp_option_t option;
    option.code = *(data + *offset);
    if (option.code == DHCP_PAD || option.code == DHCP_END)
    {
        option.length = 0;
        option.value = NULL;
        *offset += 1;
    }
    else
    {
        option.length = *(data + *offset + 1);
        option.value = (uint8_t *) malloc(sizeof(uint8_t) * option.length);
        memcpy(option.value, data + *offset + 2, option.length * sizeof(uint8_t));
        *offset += 2 + option.length;
    }
    return option;
}

/**
 * @brief Parse DHCP options.
 * 
 * @param data a pointer to the start of the DHCP options list
 * @return a pointer to the start of the parsed DHCP options
 */
dhcp_options_t dhcp_parse_options(uint8_t *data) {
    // Init
    uint8_t max_option_count = DHCP_MAX_OPTION_COUNT;
    dhcp_options_t options;
    options.count = 0;
    // Check magic cookie is equal to 0x63825363
    uint32_t magic_cookie = ntohl(*((uint32_t *) data));
    if (magic_cookie != DHCP_MAGIC_COOKIE) {
        fprintf(stderr, "Error: DHCP magic cookie is %#x, which is not equal to %#x\n", magic_cookie, DHCP_MAGIC_COOKIE);
        return options;
    }
    // Parse options
    options.options = (dhcp_option_t *) malloc(sizeof(dhcp_option_t) * max_option_count);
    uint16_t offset = 4;
    uint8_t code;
    do {
        if (options.count == max_option_count) {
            // Realloc memory if too many options
            max_option_count *= 2;
            options.options = (dhcp_option_t *) realloc(options.options, sizeof(dhcp_option_t) * max_option_count);
        }
        dhcp_option_t option = dhcp_parse_option(data, &offset);
        code = option.code;
        if (code == DHCP_MESSAGE_TYPE) {
            // Store DHCP message type
            options.message_type = *option.value;
        }
        *(options.options + (options.count++)) = option;
    } while (code != DHCP_END);
    // Shrink allocated memory to the actual number of options, if needed
    if (options.count < max_option_count) {
        options.options = (dhcp_option_t *) realloc(options.options, sizeof(dhcp_option_t) * options.count);
    }
    return options;
}

/**
 * @brief Parse a DHCP message.
 * 
 * @param data a pointer to the start of the DHCP message
 * @return the parsed DHCP message
 */
dhcp_message_t dhcp_parse_message(uint8_t *data) {
    // Parse constant fields
    dhcp_message_t message = dhcp_parse_header(data);
    // Parse DHCP options
    message.options = dhcp_parse_options(data + DHCP_HEADER_LEN);
    // Return
    return message;
}


///// DESTROY //////

/**
 * @brief Free the memory allocated for a DHCP message.
 *
 * @param message the DHCP message to free
 */
void dhcp_free_message(dhcp_message_t message) {
    if (message.options.count > 0) {
        for (uint8_t i = 0; i < message.options.count; i++) {
            dhcp_option_t option = *(message.options.options + i);
            if (option.length > 0) {
                free(option.value);
            }
        }
        free(message.options.options);
    }
}


///// PRINTING /////

/**
 * @brief Print a hardware address.
 * 
 * @param htype hardware type
 * @param chaddr the hardware address to print
 */
static void dhcp_print_chaddr(uint8_t htype, uint8_t chaddr[]) {
    printf("  Client hardware address: ");
    uint8_t length = (htype == 1) ? 6 : 16;
    printf("%02hhx", chaddr[0]);
    for (uint8_t i = 1; i < length; i++) {
        printf(":%02hhx", chaddr[i]);
    }
    printf("\n");
}

/**
 * @brief Print the header of a DHCP message.
 * 
 * @param message the DHCP message to print the header of
 */
void dhcp_print_header(dhcp_message_t message) {
    // Opcode
    printf("  Opcode: %hhu\n", message.op);
    // htype
    printf("  Hardware type: %hhu\n", message.htype);
    // hlen
    printf("  Hardware address length: %hhu\n", message.hlen);
    // hops
    printf("  Hops: %hhu\n", message.hops);
    // xid
    printf("  Transaction ID: %#x\n", message.xid);
    // secs
    printf("  Seconds elapsed: %hu\n", message.secs);
    // flags
    printf("  Flags: 0x%04x\n", message.flags);
    // ciaddr
    printf("  Client IP address: %s\n", inet_ntoa((struct in_addr) {message.ciaddr}));
    // yiaddr
    printf("  Your IP address: %s\n", inet_ntoa((struct in_addr) {message.yiaddr}));
    // siaddr
    printf("  Server IP address: %s\n", inet_ntoa((struct in_addr) {message.siaddr}));
    // giaddr
    printf("  Gateway IP address: %s\n", inet_ntoa((struct in_addr) {message.giaddr}));
    // chaddr
    dhcp_print_chaddr(message.htype, message.chaddr);
    // sname
    if (strlen((char *) message.sname) > 0) {
        printf("  Server name: %s\n", message.sname);
    }
    // file
    if (strlen((char *) message.file) > 0) {
        printf("  Boot file name: %s\n", message.file);
    }
}

/**
 * @brief Print a DHCP option.
 * 
 * @param option the DHCP option to print
 */
void dhcp_print_option(dhcp_option_t option) {
    printf("    Code: %hhu;  Length: %hhu;  Value: ", option.code, option.length);
    for (uint8_t i = 0; i < option.length; i++) {
        printf("%02hhx ", *(option.value + i));
    }
    printf("\n");
}

/**
 * @brief Print a DHCP message.
 * 
 * @param message the DHCP message to print
 */
void dhcp_print_message(dhcp_message_t message) {
    printf("DHCP message\n");
    // Print header fields
    dhcp_print_header(message);
    // Print DHCP options
    printf("  DHCP options:\n");
    for (uint8_t i = 0; i < message.options.count; i++) {
        dhcp_print_option(*(message.options.options + i));
    }
}
