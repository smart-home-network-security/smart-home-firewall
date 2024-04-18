/**
 * @file src/packet_utils.c
 * @brief Utilitaries for payload manipulation and display
 * @date 2022-09-09
 * 
 * @copyright Copyright (c) 2022
 * 
 */

#include "packet_utils.h"


/**
 * Print a packet payload.
 * 
 * @param length length of the payload in bytes
 * @param data pointer to the start of the payload
 */
void print_payload(int length, uint8_t *data) {
    char trailing = ' ';
	// Iterate on the whole payload
	for (int i = 0; i < length; i++) {
        if (i == length - 1) {
            // Insert newline after last byte
            trailing = '\n';
        }

		uint8_t c = *(data + i);
		if (c == 0) {
			printf("0x00%c", trailing);
		} else {
			printf("%#.2x%c", c, trailing);
		}
	}
}

/**
 * Converts a hexstring payload to a data buffer.
 * 
 * @param hexstring the hexstring to convert
 * @param payload a double pointer to the payload, which will be set to the start of the payload
 * @return the length of the payload in bytes
 */
size_t hexstr_to_payload(char *hexstring, uint8_t **payload) {
    size_t length = strlen(hexstring) / 2;  // Size of the payload in bytes, one byte is two characters
    *payload = (uint8_t *) malloc(length * sizeof(uint8_t));  // Allocate memory for the payload

    // WARNING: no sanitization or error-checking whatsoever
    for (size_t count = 0; count < length; count++) {
        sscanf(hexstring + 2*count, "%2hhx", (*payload) + count);  // Convert two characters to one byte
    }

    return length;
}

/**
 * Converts a MAC address from its hexadecimal representation
 * to its string representation.
 *
 * @param mac_hex MAC address in hexadecimal representation
 * @return the same MAC address in string representation
 */
char *mac_hex_to_str(uint8_t mac_hex[])
{
    char *mac_str = (char *) malloc(MAC_ADDR_STRLEN * sizeof(char));  // A string representation of a MAC address is 17 characters long + null terminator
    int ret = snprintf(mac_str, MAC_ADDR_STRLEN, "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx", mac_hex[0], mac_hex[1], mac_hex[2], mac_hex[3], mac_hex[4], mac_hex[5]);
    // Error handling
    if (ret != MAC_ADDR_STRLEN - 1)
    {
        free(mac_str);
        fprintf(stderr, "Error converting MAC address \\x%2x\\x%2x\\x%2x\\x%2x\\x%2x\\x%2x to string representation.\n", mac_hex[0], mac_hex[1], mac_hex[2], mac_hex[3], mac_hex[4], mac_hex[5]);
        return NULL;
    }
    return mac_str;
}

/**
 * Converts a MAC address from its string representation
 * to its hexadecimal representation.
 *
 * @param mac_str MAC address in string representation
 * @return the same MAC address in hexadecimal representation
 */
uint8_t *mac_str_to_hex(char *mac_str)
{
    uint8_t *mac_hex = (uint8_t *) malloc(MAC_ADDR_LENGTH * sizeof(uint8_t));  // A MAC address is 6 bytes long
    int ret = sscanf(mac_str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", mac_hex, mac_hex + 1, mac_hex + 2, mac_hex + 3, mac_hex + 4, mac_hex + 5);
    // Error handling
    if (ret != MAC_ADDR_LENGTH)
    {
        free(mac_hex);
        fprintf(stderr, "Error converting MAC address %s to hexadecimal representation.\n", mac_str);
        return NULL;
    }
    return mac_hex;
}

/**
 * Converts an IPv4 address from its network order numerical representation
 * to its string representation.
 * (Wrapper arount inet_ntoa)
 * 
 * @param ipv4_net IPv4 address in hexadecimal representation
 * @return the same IPv4 address in string representation
 */
char* ipv4_net_to_str(uint32_t ipv4_net) {
    return inet_ntoa((struct in_addr) {ipv4_net});
}

/**
 * Converts an IPv4 address from its string representation
 * to its network order numerical representation.
 * (Wrapper arount inet_aton)
 * 
 * @param ipv4_str IPv4 address in string representation
 * @return the same IPv4 address in network order numerical representation
 */
uint32_t ipv4_str_to_net(char *ipv4_str) {
    struct in_addr ipv4_addr;
    inet_aton(ipv4_str, &ipv4_addr);
    return ipv4_addr.s_addr;
}

/**
 * Converts an IPv4 addres from its hexadecimal representation
 * to its string representation.
 * 
 * @param ipv4_hex IPv4 address in hexadecimal representation
 * @return the same IPv4 address in string representation
 */
char* ipv4_hex_to_str(char *ipv4_hex) {
    char* ipv4_str = (char *) malloc(INET_ADDRSTRLEN * sizeof(char));  // A string representation of an IPv4 address is at most 15 characters long + null terminator
    int ret = snprintf(ipv4_str, INET_ADDRSTRLEN, "%hhu.%hhu.%hhu.%hhu", *ipv4_hex, *(ipv4_hex + 1), *(ipv4_hex + 2), *(ipv4_hex + 3));
    // Error handling
    if (ret < 0) {
        free(ipv4_str);
        fprintf(stderr, "Error converting IPv4 address \\x%2x\\x%2x\\x%2x\\x%2x to string representation.\n", *ipv4_hex, *(ipv4_hex + 1), *(ipv4_hex + 2), *(ipv4_hex + 3));
        return NULL;
    }
    return ipv4_str;
}

/**
 * Converts an IPv4 address from its string representation
 * to its hexadecimal representation.
 * 
 * @param ipv4_str IPv4 address in string representation
 * @return the same IPv4 address in hexadecimal representation
 */
char* ipv4_str_to_hex(char *ipv4_str) {
    char* ipv4_hex = (char *) malloc(4 * sizeof(char));  // An IPv4 address is 4 bytes long 
    int ret = sscanf(ipv4_str, "%hhu.%hhu.%hhu.%hhu", ipv4_hex, ipv4_hex + 1, ipv4_hex + 2, ipv4_hex + 3);
    // Error handling
    if (ret != 4) {
        free(ipv4_hex);
        fprintf(stderr, "Error converting IPv4 address %s to hexadecimal representation.\n", ipv4_str);
        return NULL;
    }
    return ipv4_hex;
}

/**
 * @brief Converts an IPv6 to its string representation.
 *
 * @param ipv6 the IPv6 address
 * @return the same IPv6 address in string representation
 */
char* ipv6_net_to_str(uint8_t ipv6[]) {
    char *ipv6_str = (char *) malloc(INET6_ADDRSTRLEN * sizeof(char));
    const char *ret = inet_ntop(AF_INET6, ipv6, ipv6_str, INET6_ADDRSTRLEN);
    // Error handling
    if (ret == NULL) {
        fprintf(stderr, "Error converting IPv6 address \\x%2x\\x%2x\\x%2x\\x%2x\\x%2x\\x%2x\\x%2x\\x%2x\\x%2x\\x%2x\\x%2x\\x%2x\\x%2x\\x%2x\\x%2x\\x%2x to its string representation.\n", ipv6[0], ipv6[1], ipv6[2], ipv6[3], ipv6[4], ipv6[5], ipv6[6], ipv6[7], ipv6[8], ipv6[9], ipv6[10], ipv6[11], ipv6[12], ipv6[13], ipv6[14], ipv6[15]);
    }
    return ipv6_str;
}

/**
 * Converts an IPv6 address from its string representation
 * to its network representation (a 16-byte array).
 *
 * @param ipv6_str IPv6 address in string representation
 * @return the same IPv6 address as a 16-byte array
 */
uint8_t *ipv6_str_to_net(char *ipv6_str) {
    uint8_t *ipv6 = (uint8_t *) malloc(IPV6_ADDR_LENGTH * sizeof(uint8_t));  // An IPv6 address is 16 bytes long
    int err = inet_pton(AF_INET6, ipv6_str, ipv6);
    // Error handling
    if (err != 1) {
        fprintf(stderr, "Error converting IPv6 address %s to its network representation.\n", ipv6_str);
        return NULL;
    }
    return ipv6;
}

/**
 * @brief Converts an IP (v4 or v6) address to its string representation.
 *
 * Converts an IP (v4 or v6) address to its string representation.
 * If it is an IPv6 address, it must be freed after use.
 *
 * @param ip_addr the IP address, as an ip_addr_t struct
 * @return the same IP address in string representation
 */
char* ip_net_to_str(ip_addr_t ip_addr) {
    switch (ip_addr.version) {
    case 4:
        return ipv4_net_to_str(ip_addr.value.ipv4);
        break;
    case 6:
        return ipv6_net_to_str(ip_addr.value.ipv6);
        break;
    default:
        fprintf(stderr, "Unknown IP version: %hhu.\n", ip_addr.version);
        return "";
    }
}

/**
 * Converts an IP (v4 or v6) address from its string representation
 * to an ip_addr_t struct.
 *
 * @param ip_str IP (v4 or v6) address in string representation
 * @return the same IP address as a ip_addr_t struct
 */
ip_addr_t ip_str_to_net(char *ip_str, uint8_t version) {
    ip_addr_t ip_addr;
    ip_addr.version = version;
    if (version == 4) {
        ip_addr.value.ipv4 = ipv4_str_to_net(ip_str);
    } else if (version == 6) {
        uint8_t *ipv6_net = ipv6_str_to_net(ip_str);
        memcpy(ip_addr.value.ipv6, ipv6_net, IPV6_ADDR_LENGTH);
        free(ipv6_net);
    } else {
        fprintf(stderr, "Error converting address %s to ip_addr_t.\n", ip_str);
    }
    return ip_addr;
}

/**
 * @brief Compare two IPv6 addresses.
 *
 * @param ipv6_1 first IPv6 address
 * @param ipv6_2 second IPv6 address
 * @return true if the two addresses are equal, false otherwise
 */
bool compare_ipv6(uint8_t *ipv6_1, uint8_t *ipv6_2) {
    return memcmp(ipv6_1, ipv6_2, 16) == 0;
}

/**
 * @brief Compare two IP (v4 or v6) addresses.
 *
 * @param ip_1 first IP address
 * @param ip_2 second IP address
 * @return true if the two addresses are equal, false otherwise
 */
bool compare_ip(ip_addr_t ip_1, ip_addr_t ip_2) {
    if (ip_1.version == 4 && ip_2.version == 4) {
        return ip_1.value.ipv4 == ip_2.value.ipv4;
    } else if (ip_1.version == 6 && ip_2.version == 6) {
        return compare_ipv6(ip_1.value.ipv6, ip_2.value.ipv6);
    } else {
        return false;
    }
}

/**
 * @brief Compute SHA256 hash of a given payload.
 * 
 * @param payload Payload to hash
 * @param payload_len Payload length, including padding (in bytes)
 * @return uint8_t* SHA256 hash of the payload
 */
uint8_t* compute_hash(uint8_t *payload, int payload_len) {
    uint8_t *hash = (uint8_t *) malloc(SHA256_BLOCK_SIZE * sizeof(uint8_t));
    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, payload, payload_len);
    sha256_final(&ctx, hash);
    return hash;
}

/**
 * @brief Print a SHA256 hash.
 *
 * @param hash SHA256 hash to print
 */
void print_hash(uint8_t *hash) {
    for (uint16_t i = 0; i < SHA256_BLOCK_SIZE; i++) {
        printf("%02x", *(hash + i));
    }
}
