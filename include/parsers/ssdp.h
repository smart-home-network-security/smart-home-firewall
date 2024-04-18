/**
 * @file include/parsers/ssdp.h
 * @brief SSDP message parser
 * @date 2022-11-24
 *
 * @copyright Copyright (c) 2022
 *
 */

#ifndef _IOTFIREWALL_SSDP_
#define _IOTFIREWALL_SSDP_

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include "packet_utils.h"

#define SSDP_METHOD_MAX_LEN 8                  // Maximum length of a SSDP method
#define SSDP_MULTICAST_ADDR "239.255.255.250"  // SSDP multicast group address

/**
 * SSDP methods
 */
typedef enum {
    SSDP_M_SEARCH,
    SSDP_NOTIFY,
    SSDP_UNKNOWN
} ssdp_method_t;

/**
 * Abstraction of an SSDP message
 */
typedef struct ssdp_message {
    bool is_request;       // True if the message is a request, false if it is a response
    ssdp_method_t method;  // SSDP method (M-SEARCH or NOTIFY)
} ssdp_message_t;


////////// FUNCTIONS //////////

///// PARSING /////

/**
 * @brief Parse the method and URI of SSDP message.
 *
 * @param data pointer to the start of the SSDP message
 * @param dst_addr IPv4 destination address, in network byte order
 * @return the parsed SSDP message
 */
ssdp_message_t ssdp_parse_message(uint8_t *data, uint32_t dst_addr);


///// PRINTING /////

/**
 * @brief Converts a SSDP method from enum value to character string.
 *
 * @param method the SSDP method in enum value
 * @return the same SSDP method as a character string
 */
char *ssdp_method_to_str(ssdp_method_t method);

/**
 * @brief Print the method and URI of a SSDP message.
 *
 * @param message the message to print
 */
void ssdp_print_message(ssdp_message_t message);


#endif /* _IOTFIREWALL_SSDP_ */
