/**
 * @file src/parsers/header.c
 * @brief Parser for layer 3 and 4 headers (currently only IPv4, IPv6, UDP and TCP)
 * 
 * Parser for layer 3 and 4 headers.
 * Currently supported protocols:
 *   - Layer 3:
 *     - IPv4
 *     - IPv6
 *   - Layer 4:
 *     - UDP
 *     - TCP
 * 
 * @date 2022-09-09
 * 
 * @copyright Copyright (c) 2022
 * 
 */

#include "header.h"


/**
 * Retrieve the length of a packet's IPv4 header.
 * 
 * @param data a pointer to the start of the packet's IPv4 header
 * @return the size, in bytes, of the IPv4 header
 */
size_t get_ipv4_header_length(uint8_t *data) {
    // 4-bit IPv4 header length is encoded in the last 4 bits of byte 0.
    // It indicates the number of 32-bit words.
    // It must be multiplied by 4 to obtain the header size in bytes.
    uint8_t length = (*data & 0x0f) * 4;
    return length;
}

/**
 * Retrieve the length of a packet's IPv6 header.
 * 
 * @param data a pointer to the start of the packet's IPv6 header
 * @return the size, in bytes, of the IPv6 header
 */
size_t get_ipv6_header_length(uint8_t *data) {
    // An IPv6 header has a fixed length of 40 bytes
    return IPV6_HEADER_LENGTH;
}

/**
 * Retrieve the length of a packet's UDP header.
 * 
 * @param data a pointer to the start of the packet's UDP (layer 4) header
 * @return the size, in bytes, of the UDP header
 */
size_t get_udp_header_length(uint8_t *data) {
    // A UDP header has a fixed length of 8 bytes
    return UDP_HEADER_LENGTH;
}

/**
 * Retrieve the length of a packet's TCP header.
 * 
 * @param data a pointer to the start of the packet's TCP (layer 4) header
 * @return the size, in bytes, of the UDP header
 */
size_t get_tcp_header_length(uint8_t *data) {
    // 4-bit TCP header data offset is encoded in the first 4 bits of byte 12.
    // It indicates the number of 32-bit words.
    // It must be multiplied by 4 to obtain the header size in bytes.
    uint8_t length = (*((data) + 12) >> 4) * 4;
    return length;
}

/**
 * Retrieve the length of a packet's layer 3 header (IPv4 or IPv6).
 *
 * @param data a pointer to the start of the packet's layer 3 header
 * @return the size, in bytes, of the layer 3 header
 */
size_t get_l3_header_length(uint8_t *data) {
    uint8_t ip_version = (*data) >> 4;
    switch (ip_version) {
    case 4:
        return get_ipv4_header_length(data);
        break;
    case 6:
        return get_ipv6_header_length(data);
        break;
    default:
        return 0;
        break;
    }
}

/**
 * Retrieve the length of a packet's layer-3 and layer-4 headers.
 * 
 * @param data a pointer to the start of the packet's layer-3 header
 * @return the size, in bytes, of the UDP header
 */
size_t get_headers_length(uint8_t* data) {
    size_t length = 0;

    // Layer 3: Network
    // Retrieve the IP version, which is encoded in the first 4 bits of byte 0
    uint8_t ip_version = (*data) >> 4;
    ip_protocol_t protocol = 0;
    switch (ip_version) {
    case 4:
        length += get_ipv4_header_length(data);
        protocol = *((data) + 9);  // In IPv4, the protocol number is encoded in byte 9
        break;
    case 6:
        length += get_ipv6_header_length(data);
        protocol = *((data) + 6);  // In IPv6, the protocol number is encoded in byte 6
        break;
    default:
        break;
    }

    // Layer 4: Transport
    switch (protocol) {
    case TCP:
        length += get_tcp_header_length(data + length);
        break;
    case UDP:
        length += get_udp_header_length(data + length);
        break;
    default:
        break;
    }
    return length;
}

/**
 * @brief Retrieve the length of a UDP payload.
 *
 * @param data pointer to the start of the UDP header
 * @return length of the UDP payload, in bytes
 */
uint16_t get_udp_payload_length(uint8_t *data)
{
    // The 16-bit length of the complete UDP datagram is encoded in bytes 4 and 5 of the UDP header.
    // The length of the UDP header (8 bytes) must then be subtracted to obtain the length of the UDP payload.
    return ntohs(*((uint16_t *) (data + 4))) - UDP_HEADER_LENGTH;
}

/**
 * @brief Retrieve the source port from a layer 4 header.
 *
 * @param data pointer to the start of the layer 4 header
 * @return destination port
 */
uint16_t get_dst_port(uint8_t *data) {
    // Source port is encoded in bytes 2 and 3
    return ntohs(*((uint16_t*) (data + 2)));
}

/**
 * @brief Retrieve the source address from an IPv4 header.
 *
 * @param data pointer to the start of the IPv4 header
 * @return source IPv4 address, in network byte order
 */
uint32_t get_ipv4_src_addr(uint8_t *data) {
    // Source address is encoded in bytes 12 to 15
    return *((uint32_t*) (data + 12));
}

/**
 * @brief Retrieve the destination address from an IPv4 header.
 * 
 * @param data pointer to the start of the IPv4 header
 * @return destination IPv4 address, in network byte order
 */
uint32_t get_ipv4_dst_addr(uint8_t* data) {
    // Destination address is encoded in bytes 16 to 19
    return *((uint32_t*) (data + 16));
}

/**
 * @brief Retrieve the source address from an IPv6 header.
 *
 * @param data pointer to the start of the IPv6 header
 * @return source IPv6 address, as a 16-byte array
 */
uint8_t* get_ipv6_src_addr(uint8_t *data) {
    // Source address is encoded in bytes 8 to 23
    uint8_t *addr = (uint8_t *) malloc(IPV6_ADDR_LENGTH);
    memcpy(addr, data + 8, IPV6_ADDR_LENGTH);
    return addr;
}

/**
 * @brief Retrieve the destination address from an IPv6 header.
 *
 * @param data pointer to the start of the IPv6 header
 * @return destination IPv6 address, as a 16-byte array
 */
uint8_t* get_ipv6_dst_addr(uint8_t *data) {
    // Source address is encoded in bytes 24 to 39
    uint8_t *addr = (uint8_t *) malloc(IPV6_ADDR_LENGTH);
    memcpy(addr, data + 24, IPV6_ADDR_LENGTH);
    return addr;
}
