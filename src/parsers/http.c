/**
 * @file src/parsers/http.c
 * @brief HTTP message parser
 * @date 2022-09-19
 * 
 * @copyright Copyright (c) 2022
 * 
 */

#include "http.h"


///// PARSING /////

/**
 * @brief Parse the method of an HTTP message.
 * 
 * Parse a HTTP message to retrieve its method,
 * and convert it to a http_message_t.
 * Only the two first characters need to be parsed.
 * Advances the offset value after parsing.
 * 
 * @param data pointer to the start of the HTTP message
 * @param offset current offset in the message
 * @return parsed HTTP method
 */
static http_method_t http_parse_method(uint8_t *data, uint16_t *offset) {
    switch (*(data + *offset)) {
    case 'G':
        // Method is GET
        *offset += 4;
        return HTTP_GET;
        break;
    case 'H':
        // Method is HEAD
        *offset += 5;
        return HTTP_HEAD;
        break;
    case 'P':
        // Method is POST or PUT
        switch (*(data + *offset + 1)) {
        case 'O':
            // Method is POST
            *offset += 5;
            return HTTP_POST;
            break;
        case 'U':
            // Method is PUT
            *offset += 4;
            return HTTP_PUT;
            break;
        default:
            // Unknown method
            return HTTP_UNKNOWN;
        }
    case 'D':
        // Method is DELETE
        *offset += 7;
        return HTTP_DELETE;
        break;
    case 'C':
        // Method is CONNECT
        *offset += 8;
        return HTTP_CONNECT;
        break;
    case 'O':
        // Method is OPTIONS
        *offset += 8;
        return HTTP_OPTIONS;
        break;
    case 'T':
        // Method is TRACE
        *offset += 6;
        return HTTP_TRACE;
        break;
    default:
        // Unknown method
        return HTTP_UNKNOWN;
    }
}

/**
 * @brief Check if a TCP message is a HTTP message.
 *
 * @param data pointer to the start of the TCP payload
 * @param dst_port TCP destination port
 * @return true if the message is a HTTP message
 * @return false if the message is not a HTTP message
 */
bool is_http(uint8_t *data)
{
    uint16_t offset = 0;
    return http_parse_method(data, &offset) != HTTP_UNKNOWN;
}

/**
 * @brief Parse an URI in an HTTP message.
 * 
 * Parse a HTTP message to retrieve its URI,
 * and convert it to a character string.
 * Advances the offset value after parsing.
 * 
 * @param data pointer to the start of the HTTP message
 * @param offset current offset in the message
 * @return parsed URI
 */
static char* http_parse_uri(uint8_t *data, uint16_t *offset) {
    uint16_t length = 1;
    uint16_t max_length = HTTP_METHOD_MAX_LEN;
    char *uri = (char *) malloc(sizeof(char) * max_length);
    while (*(data + *offset) != ' ') {
        if (length == max_length) {
            // URI is too long, increase buffer size
            max_length *= 2;
            void* realloc_ptr = realloc(uri, sizeof(char) * max_length);
            if (realloc_ptr == NULL) {
                // Handle realloc error
                fprintf(stderr, "Error reallocating memory for URI %s\n", uri);
                free(uri);
                return NULL;
            } else {
                uri = (char*) realloc_ptr;
            }
        }
        *(uri + (length - 1)) = *(data + (*offset)++);
        length++;
    }
    if (length < max_length) {
        // URI is shorter than allocated buffer, shrink buffer
        void *realloc_ptr = realloc(uri, sizeof(char) * length);
        if (realloc_ptr == NULL) {
            fprintf(stderr, "Error shrinking memory for URI %s\n", uri);
        } else {
            uri = (char*) realloc_ptr;
        }
    }
    // Add NULL terminating character
    *(uri + length - 1) = '\0';
    return uri;
}

/**
 * @brief Parse the method and URI of HTTP message.
 * 
 * @param data pointer to the start of the HTTP message
 * @param dst_port TCP destination port
 * @return the parsed HTTP message
 */
http_message_t http_parse_message(uint8_t *data, uint16_t dst_port) {
    http_message_t message;
    uint16_t offset = 0;
    http_method_t http_method = http_parse_method(data, &offset);
    message.is_request = dst_port == 80 && http_method != HTTP_UNKNOWN;
    if (message.is_request) {
        message.method = http_method;
        message.uri = http_parse_uri(data, &offset);
    } else {
        message.method = HTTP_UNKNOWN;
        message.uri = NULL;
    }
    return message;
}


///// DESTROY /////

/**
 * @brief Free the memory allocated for a HTTP message.
 *
 * @param message the HTTP message to free
 */
void http_free_message(http_message_t message) {
    if (message.uri != NULL)
        free(message.uri);
}


///// PRINTING /////

/**
 * @brief Converts a HTTP method from enum value to character string.
 * 
 * @param method the HTTP method in enum value
 * @return the same HTTP method as a character string
 */
char* http_method_to_str(http_method_t method) {
    switch (method) {
    case HTTP_GET:
        return "GET";
        break;
    case HTTP_HEAD:
        return "HEAD";
        break;
    case HTTP_POST:
        return "POST";
        break;
    case HTTP_PUT:
        return "PUT";
        break;
    case HTTP_DELETE:
        return "DELETE";
        break;
    case HTTP_CONNECT:
        return "CONNECT";
        break;
    case HTTP_OPTIONS:
        return "OPTIONS";
        break;
    case HTTP_TRACE:
        return "TRACE";
        break;
    default:
        return "UNKNOWN";
    }
}

/**
 * @brief Print the method and URI of a HTTP message.
 * 
 * @param message the message to print
 */
void http_print_message(http_message_t message) {
    printf("HTTP message:\n");
    printf("  is request ?: %d\n", message.is_request);
    if (message.is_request) {
        printf("  Method: %s\n", http_method_to_str(message.method));
        printf("  URI: %s\n", message.uri);
    }
}
