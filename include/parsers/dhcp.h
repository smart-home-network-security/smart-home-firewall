/**
 * @file include/parsers/dhcp.h
 * @brief DHCP message parser
 * @date 2022-09-12
 * 
 * @copyright Copyright (c) 2022
 * 
 */

#ifndef _IOTFIREWALL_DHCP_
#define _IOTFIREWALL_DHCP_

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>

#define MAX_HW_LEN            16
#define DHCP_HEADER_LEN       236
#define DHCP_MAX_OPTION_COUNT 20
#define DHCP_MAGIC_COOKIE     0x63825363


////////// TYPE DEFINITIONS //////////

/**
 * DHCP opcode
 */
typedef enum
{
    DHCP_BOOTREQUEST = 1,
    DHCP_BOOTREPLY = 2
} dhcp_opcode_t;

/**
 * Useful DHCP option codes
 */
typedef enum
{
    DHCP_PAD = 0,
    DHCP_MESSAGE_TYPE = 53,
    DHCP_END = 255
} dhcp_option_code_t;

/**
 * DHCP message type
 */
typedef enum
{
    DHCP_DISCOVER = 1,
    DHCP_OFFER = 2,
    DHCP_REQUEST = 3,
    DHCP_DECLINE = 4,
    DHCP_ACK = 5,
    DHCP_NAK = 6,
    DHCP_RELEASE = 7,
    DHCP_INFORM = 8
} dhcp_message_type_t;

/**
 * DHCP Option
 */
typedef struct dhcp_option {
    dhcp_option_code_t code;
    uint8_t length;
    uint8_t *value;
} dhcp_option_t;

/**
 * DHCP Options
 */
typedef struct dhcp_options {
    uint8_t count;                     // Number of options
    dhcp_message_type_t message_type;  // DHCP Message type (stored for convenience)
    dhcp_option_t *options;            // List of options
} dhcp_options_t;

/**
 * DHCP Message
 */
typedef struct dhcp_message {
    dhcp_opcode_t op;            // DHCP opcode
    uint8_t htype;         // Hardware address type
    uint8_t hlen;          // Hardware address length
    uint8_t hops;          // Number of hops
    uint32_t xid;          // Transaction ID
    uint16_t secs;         // Seconds elapsed since client began address acquisition or renewal process
    uint16_t flags;        // DHCP flags
    uint32_t ciaddr;       // Client IP address
    uint32_t yiaddr;       // Your (client) IP address
    uint32_t siaddr;       // Next server IP address
    uint32_t giaddr;       // Relay agent IP address
    uint8_t chaddr[16];    // Client hardware address
    uint8_t sname[64];     // Optional server host name
    uint8_t file[128];     // Boot file name
    dhcp_options_t options;  // DHCP options
} dhcp_message_t;


////////// FUNCTIONS //////////

///// PARSING /////

/**
 * @brief Parse the header of a DHCP message (not including options)
 * 
 * @param data a pointer to the start of the DHCP message
 * @return the parsed DHCP message with the header fields filled in
 */
dhcp_message_t dhcp_parse_header(uint8_t *data);

/**
 * @brief Parse a DHCP option
 * 
 * @param data a pointer to the start of the DHCP option
 * @param offset a pointer to the current offset inside the DHCP message
 *               Its value will be updated to point to the next option
 * @return the parsed DHCP option
 */
dhcp_option_t dhcp_parse_option(uint8_t *data, uint16_t *offset);

/**
 * @brief Parse DHCP options
 * 
 * @param data a pointer to the start of the DHCP options list
 * @return a pointer to the start of the parsed DHCP options
 */
dhcp_options_t dhcp_parse_options(uint8_t *data);

/**
 * @brief Parse a DHCP message
 * 
 * @param data a pointer to the start of the DHCP message
 * @return the parsed DHCP message
 */
dhcp_message_t dhcp_parse_message(uint8_t *data);


///// DESTROY //////

/**
 * @brief Free the memory allocated for a DHCP message.
 * 
 * @param message the DHCP message to free
 */
void dhcp_free_message(dhcp_message_t message);


///// PRINTING /////

/**
 * @brief Print the header of a DHCP message
 * 
 * @param message the DHCP message to print the header of
 */
void dhcp_print_header(dhcp_message_t message);

/**
 * @brief Print a DHCP option
 * 
 * @param option the DHCP option to print
 */
void dhcp_print_option(dhcp_option_t option);

/**
 * @brief Print a DHCP message
 * 
 * @param message the DHCP message to print
 */
void dhcp_print_message(dhcp_message_t message);


#endif /* _IOTFIREWALL_DHCP_ */
