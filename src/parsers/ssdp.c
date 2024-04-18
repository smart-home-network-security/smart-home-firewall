/**
 * @file src/parsers/ssdp.c
 * @brief SSDP message parser
 * @date 2022-11-24
 *
 * @copyright Copyright (c) 2022
 *
 */

#include "ssdp.h"


///// PARSING /////

/**
 * @brief Parse the method of an SSDP message.
 *
 * Parse a SSDP message to retrieve its method,
 * and convert it to a ssdp_message_t.
 * Only the two first characters need to be parsed.
 * Advances the offset value after parsing.
 *
 * @param data pointer to the start of the SSDP message
 * @param offset current offset in the message
 * @return parsed SSDP method
 */
static ssdp_method_t ssdp_parse_method(uint8_t *data, uint16_t *offset) {
    switch (*(data + *offset)) {
    case 'M':
        // Method is M-SEARCH
        *offset += 9;
        return SSDP_M_SEARCH;
        break;
    case 'N':
        // Method is NOTIFY
        *offset += 7;
        return SSDP_NOTIFY;
        break;
    default:
        // Unknown method
        return SSDP_UNKNOWN;
    }
}

/**
 * @brief Parse the method and URI of SSDP message.
 *
 * @param data pointer to the start of the SSDP message
 * @param dst_addr IPv4 destination address, in network byte order
 * @return the parsed SSDP message
 */
ssdp_message_t ssdp_parse_message(uint8_t *data, uint32_t dst_addr) {
    ssdp_message_t message;
    message.is_request = dst_addr == ipv4_str_to_net(SSDP_MULTICAST_ADDR);
    uint16_t offset = 0;
    message.method = ssdp_parse_method(data, &offset);
    return message;
}


///// PRINTING /////

/**
 * @brief Converts a SSDP method from enum value to character string.
 *
 * @param method the SSDP method in enum value
 * @return the same SSDP method as a character string
 */
char *ssdp_method_to_str(ssdp_method_t method) {
    switch (method) {
    case SSDP_M_SEARCH:
        return "M-SEARCH";
        break;
    case SSDP_NOTIFY:
        return "NOTIFY";
        break;
    default:
        return "UNKNOWN";
    }
}

/**
 * @brief Print the method and URI of a SSDP message.
 *
 * @param message the message to print
 */
void ssdp_print_message(ssdp_message_t message) {
    printf("SSDP message:\n");
    printf("  is request ?: %d\n", message.is_request);
    printf("  Method: %s\n", ssdp_method_to_str(message.method));
}
