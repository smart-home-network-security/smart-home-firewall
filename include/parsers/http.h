/**
 * @file include/parsers/http.h
 * @brief HTTP message parser
 * @date 2022-09-09
 * 
 * @copyright Copyright (c) 2022
 * 
 */

#ifndef _IOTFIREWALL_HTTP_
#define _IOTFIREWALL_HTTP_

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

#define HTTP_MESSAGE_MIN_LEN 16   // Minimum length of a HTTP message
#define HTTP_METHOD_MAX_LEN  7    // Maximum length of a HTTP method
#define HTTP_URI_DEFAULT_LEN 100  // Default length of a HTTP URI


/**
 * HTTP methods
 */
typedef enum
{
    HTTP_GET,
    HTTP_HEAD,
    HTTP_POST,
    HTTP_PUT,
    HTTP_DELETE,
    HTTP_CONNECT,
    HTTP_OPTIONS,
    HTTP_TRACE,
    HTTP_UNKNOWN
} http_method_t;

/**
 * Abstraction of a HTTP message
 */
typedef struct http_message {
    bool is_request;       // True if the message is a request, false if it is a response
    http_method_t method;  // HTTP method (GET, POST, etc.)
    char *uri;             // Message URI
} http_message_t;


////////// FUNCTIONS //////////

///// PARSING /////

/**
 * @brief Check if a TCP message is a HTTP message.
 * 
 * @param data pointer to the start of the TCP payload
 * @param dst_port TCP destination port
 * @return true if the message is a HTTP message
 * @return false if the message is not a HTTP message
 */
bool is_http(uint8_t *data);

/**
 * @brief Parse the method and URI of HTTP message.
 * 
 * @param data pointer to the start of the HTTP message
 * @param src_port TCP destination port
 * @return the parsed HTTP message
 */
http_message_t http_parse_message(uint8_t *data, uint16_t dst_port);


///// DESTROY /////

/**
 * @brief Free the memory allocated for a HTTP message.
 * 
 * @param message the HTTP message to free
 */
void http_free_message(http_message_t message);


///// PRINTING /////

/**
 * @brief Converts a HTTP method from enum value to character string.
 * 
 * @param method the HTTP method in enum value
 * @return the same HTTP method as a character string
 */
char* http_method_to_str(http_method_t method);

/**
 * @brief Print an HTTP message.
 * 
 * @param message the HTTP message to print
 */
void http_print_message(http_message_t message);


#endif /* _IOTFIREWALL_HTTP_ */
