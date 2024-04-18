/**
 * @file include/parsers/dns.h
 * @brief DNS message parser
 * @date 2022-09-09
 * 
 * @copyright Copyright (c) 2022
 * 
 */

#ifndef _IOTFIREWALL_DNS_
#define _IOTFIREWALL_DNS_

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <arpa/inet.h>
#include "packet_utils.h"
#include "dns_map.h"

#define DNS_HEADER_SIZE 12
#define DNS_MAX_DOMAIN_NAME_LENGTH 100
#define DNS_QR_FLAG_MASK 0x8000
#define DNS_CLASS_MASK 0x7fff
#define DNS_COMPRESSION_MASK 0x3fff


////////// TYPE DEFINITIONS //////////

/**
 * DNS types
 */
typedef enum {
    A     =  1,
    NS    =  2,
    MD    =  3,
    MF    =  4,
    CNAME =  5,
    SOA   =  6,
    MB    =  7,
    MG    =  8,
    MR    =  9,
    NULL_ = 10,
    WKS   = 11,
    PTR   = 12,
    HINFO = 13,
    MINFO = 14,
    MX    = 15,
    TXT   = 16,
    AAAA  = 28,
    OPT   = 41,  // Used to specify extensions
    ANY   = 255  // Used to query any type
} dns_rr_type_t;

/**
 * DNS Header
 */
typedef struct dns_header {
    uint16_t id;
    uint16_t flags;
    bool qr;           // 0 if the message is a query, 1 if it is a response
    uint16_t qdcount;  // Number of entries in Question section
    uint16_t ancount;  // Number of Resource Records in Answer section
    uint16_t nscount;  // Number of Resource Records in Authority section
    uint16_t arcount;  // Number of Resource Records in Additional section
} dns_header_t;

/**
 * DNS Question
 */
typedef struct dns_question {
    char *qname;
    dns_rr_type_t qtype;
    uint16_t qclass;
} dns_question_t;

/**
 * RDATA field of a DNS Resource Record
 */
typedef union {
    char *domain_name;  // Domain name, character string
    ip_addr_t ip;       // IP (v4 or v6) address
    uint8_t *data;      // Generic data, series of bytes
} rdata_t;

/**
 * DNS Resource Record
 */
typedef struct dns_resource_record {
    char *name;
    dns_rr_type_t rtype;
    uint16_t rclass;
    uint32_t ttl;
    uint16_t rdlength;
    rdata_t rdata;
} dns_resource_record_t;

/**
 * DNS Message
 */
typedef struct dns_message {
    dns_header_t header;
    dns_question_t *questions;
    dns_resource_record_t *answers;
    dns_resource_record_t *authorities;
    dns_resource_record_t *additionals;
} dns_message_t;


////////// FUNCTIONS //////////

///// PARSING /////

/**
 * Parse a DNS header.
 * A DNS header is always 12 bytes.
 * 
 * @param data a pointer pointing to the start of the DNS message
 * @param offset a pointer to the current parsing offset
 * @return the parsed header
 */
dns_header_t dns_parse_header(uint8_t *data, uint16_t *offset);

/**
 * Parse a DNS question section.
 * 
 * @param qdcount the number of questions present in the question section
 * @param data a pointer pointing to the start of the DNS message
 * @param offset a pointer to the current parsing offset
 * @return the parsed question section
 */
dns_question_t* dns_parse_questions(uint16_t qdcount, uint8_t *data, uint16_t *offset);

/**
 * Parse a DNS resource record list.
 * 
 * @param count the number of resource records present in the section
 * @param data a pointer pointing to the start of the DNS message
 * @param offset a pointer to the current parsing offset
 * @return the parsed resource records list
 */
dns_resource_record_t* dns_parse_rrs(uint16_t count, uint8_t *data, uint16_t *offset);

/**
 * Parse a DNS message.
 * 
 * @param data a pointer to the start of the DNS message
 * @return the parsed DNS message
 */
dns_message_t dns_parse_message(uint8_t *data);


///// LOOKUP /////

/**
 * @brief Check if a given DNS Questions list contains a domain name which has a given suffix.
 *
 * @param questions DNS Questions list
 * @param qdcount number of Questions in the list
 * @param suffix the domain name suffix to search for
 * @param suffix_length the length of the domain name suffix
 * @return true if a domain name with the given suffix is found is found in the Questions list,
 *         false otherwise
 */
bool dns_contains_suffix_domain_name(dns_question_t *questions, uint16_t qdcount, char *suffix, uint16_t suffix_length);

/**
 * @brief Check if a given domain name is fully contained in a DNS Questions list.
 * 
 * @param questions DNS Questions list
 * @param qdcount number of Questions in the list
 * @param domain_name the domain name to search for
 * @return true if the full domain name is found in the Questions list, false otherwise
 */
bool dns_contains_full_domain_name(dns_question_t *questions, uint16_t qdcount, char *domain_name);

/**
 * @brief Search for a specific domain name in a DNS Questions list.
 * 
 * @param questions DNS Questions list
 * @param qdcount number of Suestions in the list
 * @param domain_name the domain name to search for
 * @return the DNS Question related to the given domain name, or NULL if not found
 */
dns_question_t* dns_get_question(dns_question_t *questions, uint16_t qdcount, char *domain_name);

/**
 * @brief Retrieve the IP addresses corresponding to a given domain name in a DNS Answers list.
 * 
 * Searches a DNS Answer list for a specific domain name and returns the corresponding IP address.
 * Processes each Answer recursively if the Answer Type is a CNAME.
 * 
 * @param answers DNS Answers list to search in
 * @param ancount number of Answers in the list
 * @param domain_name domain name to search for
 * @return struct ip_list representing the list of corresponding IP addresses
 */
ip_list_t dns_get_ip_from_name(dns_resource_record_t *answers, uint16_t ancount, char *domain_name);


///// DESTROY /////

/**
 * Free the memory allocated for a DNS message.
 * 
 * @param question the DNS message to free
 */
void dns_free_message(dns_message_t message);


///// PRINTING /////

/**
 * Print a DNS header.
 * 
 * @param message the DNS header
 */
void dns_print_header(dns_header_t header);

/**
 * Print a DNS Question
 * 
 * @param question the DNS Question
 */
void dns_print_question(dns_question_t question);

/**
 * Print a DNS Question section.
 * 
 * @param qdcount the number of Questions in the Question section
 * @param questions the list of DNS Questions
 */
void dns_print_questions(uint16_t qdcount, dns_question_t *questions);

/**
 * Return a string representation of the given RDATA value.
 * 
 * @param rtype the type corresponding to the RDATA value
 * @param rdlength the length, in bytes, of the RDATA value
 * @param rdata the RDATA value, stored as a union type
 * @return a string representation of the RDATA value
 */
char* dns_rdata_to_str(dns_rr_type_t rtype, uint16_t rdlength, rdata_t rdata);

/**
 * Print a DNS Resource Record.
 * 
 * @param section_name the name of the Resource Record section
 * @param rr the DNS Resource Record
 */
void dns_print_rr(char* section_name, dns_resource_record_t rr);

/**
 * Print a DNS Resource Records section.
 * 
 * @param section_name the name of the Resource Record section
 * @param count the number of Resource Records in the section
 * @param rrs the list of DNS Resource Records
 */
void dns_print_rrs(char* section_name, uint16_t count, dns_resource_record_t *rrs);

/**
 * Print a DNS message.
 * 
 * @param message the DNS message
 */
void dns_print_message(dns_message_t message);


#endif /* _IOTFIREWALL_DNS_ */
