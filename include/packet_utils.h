/**
 * @file include/packet_utils.h
 * @brief Utilitaries for payload manipulation and display
 * @date 2022-09-09
 * 
 * @copyright Copyright (c) 2022
 * 
 */

#ifndef _IOTFIREWALL_PACKET_UTILS_
#define _IOTFIREWALL_PACKET_UTILS_

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <arpa/inet.h>
#include "sha256.h"

#define MAC_ADDR_LENGTH  6
#define MAC_ADDR_STRLEN  18
#define IPV4_ADDR_LENGTH 4
#define IPV6_ADDR_LENGTH 16

/**
 * @brief IP (v4 or v6) address value
 */
typedef union {
    uint32_t ipv4;  // IPv4 address, as a 32-bit unsigned integer in network byte order
    uint8_t ipv6[IPV6_ADDR_LENGTH];  // IPv6 address, as a 16-byte array
} ip_val_t;

/**
 * @brief IP (v4 or v6) address
 */
typedef struct {
    uint8_t version;  // IP version (4 or 6, 0 if not set)
    ip_val_t value;   // IP address value (0 if not set)
} ip_addr_t;

/**
 * Print a packet payload.
 * 
 * @param length length of the payload in bytes
 * @param data pointer to the start of the payload
 */
void print_payload(int length, uint8_t *data);

/**
 * Converts a hexstring payload to a data buffer.
 * 
 * @param hexstring the hexstring to convert
 * @param payload a double pointer to the payload, which will be set to the start of the payload
 * @return the length of the payload in bytes
 */
size_t hexstr_to_payload(char *hexstring, uint8_t **payload);

/**
 * Converts a MAC address from its hexadecimal representation
 * to its string representation.
 *
 * @param mac_hex MAC address in hexadecimal representation
 * @return the same MAC address in string representation
 */
char *mac_hex_to_str(uint8_t mac_hex[]);

/**
 * Converts a MAC address from its string representation
 * to its hexadecimal representation.
 *
 * @param mac_str MAC address in string representation
 * @return the same MAC address in hexadecimal representation
 */
uint8_t *mac_str_to_hex(char *mac_str);

/**
 * Converts an IPv4 address from its network order numerical representation
 * to its string representation.
 * (Wrapper arount inet_ntoa)
 * 
 * @param ipv4_net IPv4 address in hexadecimal representation
 * @return the same IPv4 address in string representation
 */
char* ipv4_net_to_str(uint32_t ipv4_net);

/**
 * Converts an IPv4 address from its string representation
 * to its network order numerical representation.
 * (Wrapper arount inet_aton)
 * 
 * @param ipv4_str IPv4 address in string representation
 * @return the same IPv4 address in network order numerical representation
 */
uint32_t ipv4_str_to_net(char *ipv4_str);

/**
 * Converts an IPv4 addres from its hexadecimal representation
 * to its string representation.
 * 
 * @param ipv4_hex IPv4 address in hexadecimal representation
 * @return the same IPv4 address in string representation
 */
char* ipv4_hex_to_str(char *ipv4_hex);

/**
 * Converts an IPv4 address from its string representation
 * to its hexadecimal representation.
 * 
 * @param ipv4_str IPv4 address in string representation
 * @return the same IPv4 address in hexadecimal representation
 */
char* ipv4_str_to_hex(char *ipv4_str);

/**
 * @brief Converts an IPv6 address to its string representation.
 * 
 * @param ipv6 the IPv6 address
 * @return the same IPv6 address in string representation
 */
char* ipv6_net_to_str(uint8_t ipv6[]);

/**
 * Converts an IPv6 address from its string representation
 * to its network representation (a 16-byte array).
 *
 * @param ipv6_str IPv6 address in string representation
 * @return the same IPv6 address as a 16-byte array
 */
uint8_t* ipv6_str_to_net(char *ipv6_str);

/**
 * @brief Converts an IP (v4 or v6) address to its string representation.
 * 
 * @param ip_addr the IP address, as an ip_addr_t struct
 * @return the same IP address in string representation
 */
char* ip_net_to_str(ip_addr_t ip_addr);

/**
 * Converts an IP (v4 or v6) address from its string representation
 * to an ip_addr_t struct.
 *
 * @param ip_str IP (v4 or v6) address in string representation
 * @return the same IP address as a ip_addr_t struct
 */
ip_addr_t ip_str_to_net(char *ip_str, uint8_t version);

/**
 * @brief Compare two IPv6 addresses.
 *
 * @param ipv6_1 first IPv6 address
 * @param ipv6_2 second IPv6 address
 * @return true if the two addresses are equal, false otherwise
 */
bool compare_ipv6(uint8_t *ipv6_1, uint8_t *ipv6_2);

/**
 * @brief Compare two IP (v4 or v6) addresses.
 *
 * @param ip_1 first IP address
 * @param ip_2 second IP address
 * @return true if the two addresses are equal, false otherwise
 */
bool compare_ip(ip_addr_t ip_1, ip_addr_t ip_2);

/**
 * @brief Compute SHA256 hash of a given payload.
 *
 * @param payload Payload to hash
 * @param payload_len Payload length, including padding (in bytes)
 * @return uint8_t* SHA256 hash of the payload
 */
uint8_t* compute_hash(uint8_t *payload, int payload_len);

/**
 * @brief Print a SHA256 hash.
 *
 * @param hash SHA256 hash to print
 */
void print_hash(uint8_t *hash);


#endif /* _IOTFIREWALL_PACKET_UTILS_ */
