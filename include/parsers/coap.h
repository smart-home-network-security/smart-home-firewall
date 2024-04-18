/**
 * @file include/parsers/coap.h
 * @brief CoAP message parser
 * @date 2022-11-30
 * 
 * @copyright Copyright (c) 2022
 * 
 */

#ifndef _IOTFIREWALL_COAP_
#define _IOTFIREWALL_COAP_

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>
#include "parsers/http.h"


/**
 * @brief CoAP message type
 */
typedef enum
{
    COAP_CON = 0,
    COAP_NON = 1,
    COAP_ACK = 2,
    COAP_RST = 3
} coap_type_t;

/**
 * @brief CoAP Option number
 */
typedef enum
{
    COAP_URI_PATH = 11,
    COAP_URI_QUERY = 15
} coap_option_t;

/**
 * @brief Abstraction of a CoAP message
 */
typedef struct coap_message
{
    coap_type_t type;      // CoAP message type
    http_method_t method;  // CoAP method, analogous to HTTP
    char *uri;             // Message URI
    uint16_t uri_len;      // URI length
} coap_message_t;


////////// FUNCTIONS //////////

///// PARSING /////

/**
 * @brief Parse a CoAP message.
 *
 * @param data pointer to the start of the CoAP message
 * @param length length of the CoAP message, in bytes
 * @return the parsed CoAP message
 */
coap_message_t coap_parse_message(uint8_t *data, uint16_t length);


///// DESTROY /////

/**
 * @brief Free the memory allocated for a CoAP message.
 *
 * @param message the CoAP message to free
 */
void coap_free_message(coap_message_t message);


///// PRINTING /////

/**
 * @brief Print a CoAP message.
 *
 * @param message the CoAP message to print
 */
void coap_print_message(coap_message_t message);


#endif /* _IOTFIREWALL_COAP_ */
