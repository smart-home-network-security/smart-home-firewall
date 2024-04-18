/**
 * @file src/parsers/coap.c
 * @brief CoAP message parser
 * @date 2022-11-30
 * 
 * @copyright Copyright (c) 2022
 * 
 */

#include "coap.h"


///// PARSING /////

/**
 * @brief Parse the method of a CoAP message.
 * 
 * @param code byte which encodes the CoAP method
 * @return CoAP method
 */
static http_method_t coap_parse_method(uint8_t code) {
    switch (code) {
    case 1:
        return HTTP_GET;
        break;
    case 2:
        return HTTP_POST;
        break;
    case 3:
        return HTTP_PUT;
        break;
    case 4:
        return HTTP_DELETE;
        break;
    default:
        // CoAP responses and all other codes are not supported
        return HTTP_UNKNOWN;
    }
}

/**
 * @brief Parse an URI option (Uri-Path or Uri-Query) of a CoAP message.
 * 
 * @param message pointer to the CoAP message, which will be updated
 * @param option CoAP option number (11 for Uri-Path, 15 for Uri-Query)
 * @param length CoAP option length
 * @param data pointer to the start of the URI option
 */
static void coap_parse_uri_option(coap_message_t *message, coap_option_t option_num, uint16_t length, uint8_t *data) {
    char prefix = (option_num == COAP_URI_PATH) ? '/' : '?';
    if (message->uri == NULL) {
        message->uri = malloc(length + 2);
    } else {
        message->uri = realloc(message->uri, message->uri_len + length + 2);
    }
    *(message->uri + message->uri_len) = prefix;
    memcpy(message->uri + message->uri_len + 1, data, length);
    message->uri_len += length + 1;
    *(message->uri + message->uri_len) = '\0';
}

/**
 * @brief Parse CoAP options.
 * 
 * @param message pointer to the currently parsed CoAP message, which will be updated
 * @param data pointer to the start of the options section of a CoAP message
 * @param msg_length length of the rest of the CoAP message (after the header)
 */
static void coap_parse_options(coap_message_t *message, uint8_t *data, uint16_t msg_length) {
    uint16_t option_num = 0;
    uint16_t bytes_read = 0;
    while (bytes_read < msg_length && *data != 0b11111111)
    {
        // Parse option delta
        uint16_t delta = (*data) >> 4;
        uint8_t delta_len = 0;  // Length of the extended delta field
        switch (delta) {
        case 13:
            delta = (*(data + 1)) + 13;
            delta_len = 1;
            break;
        case 14:
            delta = ntohs(*((uint16_t*) (data + 1))) + 269;
            delta_len = 2;
            break;
        case 15:
            continue;
            break;
        default:
            break;
        }
        // Compute option number
        option_num += delta;

        // Parse option length
        uint16_t option_length = (*data) & 0b00001111;
        uint8_t length_len = 0;  // Length of the extended length field
        switch (option_length)
        {
        case 13:
            option_length = (*(data + 1 + delta_len)) + 13;
            length_len = 1;
            break;
        case 14:
            option_length = ntohs(*((uint16_t *)(data + 1 + delta_len))) + 269;
            length_len = 2;
            break;
        case 15:
            continue;
            break;
        default:
            break;
        }

        // Parse option value
        data += 1 + delta_len + length_len;
        if (option_num == COAP_URI_PATH || option_num == COAP_URI_QUERY)
        {
            // Option Uri-Path or Uri-Query
            coap_parse_uri_option(message, option_num, option_length, data);
        }
        data += option_length;
        bytes_read += 1 + delta_len + length_len + option_length;
        // Other options are not supported (yet)
    }
}

/**
 * @brief Parse a CoAP message.
 *
 * @param data pointer to the start of the CoAP message
 * @param length length of the CoAP message, in bytes
 * @return the parsed CoAP message
 */
coap_message_t coap_parse_message(uint8_t *data, uint16_t length)
{
    coap_message_t message;
    message.type = (coap_type_t) (((*data) & 0b00110000) >> 4);  // CoAP type is encoded in bits 2-3
    message.method = coap_parse_method(*(data + 1));             // CoAP method is encoded in byte 1
    uint8_t token_length = (*data) & 0b00001111;                 // CoAP token length is encoded in bits 4-7
    uint8_t header_length = 4 + token_length;                    // Length of the CoAP header
    data += header_length;                                       // Skip the header
    message.uri = NULL;                                          // Initialize the URI to NULL
    message.uri_len = 0;
    coap_parse_options(&message, data, length - header_length);  // Parse CoAP options
    return message;
}


///// DESTROY /////

/**
 * @brief Free the memory allocated for a CoAP message.
 *
 * @param message the CoAP message to free
 */
void coap_free_message(coap_message_t message) {
    if (message.uri != NULL)
        free(message.uri);
}


///// PRINTING /////

/**
 * @brief Converts a CoAP message type to its string representation.
 * 
 * @param type CoAP message type
 * @return string representation of the CoAP message type
 */
static char* coap_type_to_str(coap_type_t type) {
    switch (type) {
    case COAP_CON:
        return "Confirmable";
        break;
    case COAP_NON:
        return "Non-Confirmable";
        break;
    case COAP_ACK:
        return "Acknowledgement";
        break;
    case COAP_RST:
        return "Reset";
        break;
    default:
        return "Unknown";
    }
}

/**
 * @brief Print a CoAP message.
 *
 * @param message the CoAP message to print
 */
void coap_print_message(coap_message_t message)
{
    printf("CoAP message:\n");
    printf("  Type: %s\n", coap_type_to_str(message.type));
    printf("  Method: %s\n", http_method_to_str(message.method));
    printf("  URI: %s\n", message.uri);
}
