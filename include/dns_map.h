/**
 * @file include/dns_map.h
 * @brief Implementation of a DNS domain name to IP addresses mapping, using Joshua J Baker's hashmap.c (https://github.com/tidwall/hashmap.c)
 * @date 2022-09-06
 * 
 * @copyright Copyright (c) 2022
 * 
 */

#ifndef _IOTFIREWALL_DNS_MAP_
#define _IOTFIREWALL_DNS_MAP_

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "hashmap.h"
#include "packet_utils.h"

// Initial size of the DNS table
// If set to 0, the default size will be 16
#define DNS_MAP_INIT_SIZE 0


////////// TYPE DEFINITIONS //////////

/**
 * List of IP addresses
 */
typedef struct ip_list {
    uint8_t ip_count;         // Number of IP addresses
    ip_addr_t *ip_addresses;  // List of IP addresses
} ip_list_t;

/**
 * DNS table entry:
 * mapping between domain name and a list of IP addresses.
 */
typedef struct dns_entry {
    char *domain_name;  // Domain name
    ip_list_t ip_list;  // List of IP addresses
} dns_entry_t;

/**
 * Alias for the hashmap structure.
 */
typedef struct hashmap dns_map_t;


////////// FUNCTIONS //////////

/**
 * @brief Initialize an ip_list_t structure.
 *
 * Creates an empty list of IP addresses.
 * The `ip_count` field is set to 0,
 * and the `ip_addresses` field is set to NULL.
 *
 * @return ip_list_t newly initialized structure
 */
ip_list_t ip_list_init();

/**
 * @brief Checks if a dns_entry_t structure contains a given IP address.
 *
 * @param dns_entry pointer to the DNS entry to process
 * @param ip_address IP address to check the presence of
 * @return true if the IP address is present in the DNS entry, false otherwise
 */
bool dns_entry_contains(dns_entry_t *dns_entry, ip_addr_t ip_address);

/**
 * Create a new DNS table.
 * 
 * @return the newly created DNS table 
 */
dns_map_t* dns_map_create();

/**
 * Destroy (free) a DNS table.
 * 
 * @param table the DNS table to free
 */
void dns_map_free(dns_map_t *table);

/**
 * Add IP addresses corresponding to a given domain name in the DNS table.
 * If the domain name was already present, its IP addresses will be replaced by the new ones.
 * 
 * @param table the DNS table to add the entry to
 * @param domain_name the domain name of the entry
 * @param ip_list an ip_list_t structure containing the list of IP addresses
 */
void dns_map_add(dns_map_t *table, char *domain_name, ip_list_t ip_list);

/**
 * Remove a domain name (and its corresponding IP addresses) from the DNS table.
 * 
 * @param table the DNS table to remove the entry from
 * @param domain_name the domain name of the entry to remove
 */
void dns_map_remove(dns_map_t *table, char *domain_name);

/**
 * Retrieve the IP addresses corresponding to a given domain name in the DNS table.
 * 
 * @param table the DNS table to retrieve the entry from
 * @param domain_name the domain name of the entry to retrieve
 * @return a pointer to a dns_entry structure containing the IP addresses corresponding to the domain name,
 *         or NULL if the domain name was not found in the DNS table
 */
dns_entry_t* dns_map_get(dns_map_t *table, char *domain_name);

/**
 * Retrieve the IP addresses corresponding to a given domain name,
 * and remove the domain name from the DNS table.
 * 
 * @param table the DNS table to retrieve the entry from
 * @param domain_name the domain name of the entry to retrieve
 * @return a pointer to a dns_entry structure containing the IP addresses corresponding to the domain name,
 *         or NULL if the domain name was not found in the DNS table
 */
dns_entry_t* dns_map_pop(dns_map_t *table, char *domain_name);

/**
 * @brief Print a DNS table entry.
 *
 * @param dns_entry the DNS table entry to print
 */
void dns_entry_print(dns_entry_t *dns_entry);

#endif /* _IOTFIREWALL_DNS_MAP_ */
