/**
 * @file src/parsers/dns.c
 * @brief DNS message parser
 * @date 2022-09-09
 * 
 * @copyright Copyright (c) 2022
 * 
 */

#include "dns.h"


///// PARSING /////

/**
 * Parse a DNS header.
 * A DNS header is always 12 bytes.
 * 
 * @param data a pointer pointing to the start of the DNS message
 * @param offset a pointer to the current parsing offset
 * @return the parsed header
 */
dns_header_t dns_parse_header(uint8_t *data, uint16_t *offset) {
    // Init
    dns_header_t header;
    // Parse fields
    header.id = ntohs(*((uint16_t *) (data + *offset)));
    header.flags = ntohs(*((uint16_t *) (data + *offset + 2)));
    header.qr = (header.flags & DNS_QR_FLAG_MASK);
    header.qdcount = ntohs(*((uint16_t *) (data + *offset + 4)));
    header.ancount = ntohs(*((uint16_t *) (data + *offset + 6)));
    header.nscount = ntohs(*((uint16_t *) (data + *offset + 8)));
    header.arcount = ntohs(*((uint16_t *) (data + *offset + 10)));
    // Update offset to point after header
    *offset += DNS_HEADER_SIZE;

    return header;
}

/**
 * Parse a DNS Domain Name.
 * 
 * @param data a pointer pointing to the start of the DNS message
 * @param offset a pointer to the current parsing offset
 * @return the parsed domain name
 */
static char* dns_parse_domain_name(uint8_t *data, uint16_t *offset) {
    if (*(data + *offset) == '\0') {
        // Domain name is ROOT
        (*offset)++;
        return "";
    }
    uint16_t current_length = 0;
    uint16_t max_length = DNS_MAX_DOMAIN_NAME_LENGTH;
    char* domain_name = (char *) malloc(sizeof(char) * max_length);
    bool compression = false;
    uint16_t domain_name_offset = *offset;  // Other offset, might be useful for domain name compression
    while (*(data + domain_name_offset) != '\0') {
        uint8_t length_byte = *((uint8_t *) (data + domain_name_offset));
        if (length_byte >> 6 == 3) {  // Length byte starts with 0b11
            // Domain name compression
            // Advance offset by 2 bytes, and do not update it again
            if(!compression) {
                *offset += 2;
            }
            compression = true;
            // Retrieve new offset to parse domain name from
            domain_name_offset = ntohs(*((uint16_t *) (data + domain_name_offset))) & DNS_COMPRESSION_MASK;
        } else {
            // Fully written label, parse it
            for (int i = 1; i <= length_byte; i++) {
                if (current_length == max_length) {
                    // Realloc buffer
                    max_length *= 2;
                    void *realloc_ptr = realloc(domain_name, sizeof(char) * max_length);
                    if (realloc_ptr == NULL) {
                        // Handle realloc error
                        fprintf(stderr, "Error reallocating memory for domain name %s\n", domain_name);
                        free(domain_name);
                        return NULL;
                    } else {
                        domain_name = (char*) realloc_ptr;
                    }
                }
                char c = *(data + domain_name_offset + i);
                *(domain_name + (current_length++)) = c;
            }
            *(domain_name + (current_length++)) = '.';
            domain_name_offset += length_byte + 1;
            if (!compression) {
                *offset = domain_name_offset;
            }
        }
    }
    // Domain name was fully parsed
    // Overwrite last '.' written with NULL byte
    *(domain_name + (--current_length)) = '\0';
    // Shrink allocated memory to fit domain name, if needed
    if (current_length + 1 < max_length) {
        void* realloc_ptr = realloc(domain_name, sizeof(char) * (current_length + 1));
        if (realloc_ptr == NULL) {
            fprintf(stderr, "Error shrinking memory for domain name %s\n", domain_name);
        } else {
            domain_name = (char*) realloc_ptr;
        } 
    }
    // Advance offset after NULL terminator, if domain name compression was not used
    if (!compression) {
        (*offset)++;
    }
    return domain_name;
}

/**
 * Parse a DNS Question section.
 * 
 * @param qdcount the number of questions present in the question section
 * @param data a pointer pointing to the start of the DNS message
 * @param offset a pointer to the current parsing offset
 * @return the parsed question section
 */
dns_question_t* dns_parse_questions(uint16_t qdcount, uint8_t *data, uint16_t *offset) {
    // Init
    dns_question_t *questions = (dns_question_t *) malloc(qdcount * sizeof(dns_question_t));
    // Iterate over all questions
    for (uint16_t i = 0; i < qdcount; i++) {
        // Parse domain name
        (questions + i)->qname = dns_parse_domain_name(data, offset);
        // Parse rtype and rclass
        (questions + i)->qtype = ntohs(*((uint16_t *) (data + *offset)));
        (questions + i)->qclass = ntohs(*((uint16_t *) (data + *offset + 2))) & DNS_CLASS_MASK;
        *offset += 4;
    }
    return questions;
}

/**
 * Parse a DNS Resource Record RDATA field.
 * 
 * @param rdlength the length, in bytes, of the RDATA field
 * @param data a pointer pointing to the start of the DNS message
 * @param offset a pointer to the current parsing offset
 * @return the parsed RDATA field
 */
static rdata_t dns_parse_rdata(dns_rr_type_t rtype, uint16_t rdlength, uint8_t *data, uint16_t *offset) {
    rdata_t rdata;
    if (rdlength == 0) {
        // RDATA field is empty
        rdata.data = NULL;
    } else {
        // RDATA field is not empty
        switch (rtype) {
        case A:
            // RDATA contains an IPv4 address
            rdata.ip.version = 4;
            rdata.ip.value.ipv4 = *((uint32_t *) (data + *offset));  // Stored in network byte order
            *offset += rdlength;
            break;
        case AAAA:
            // RDATA contains an IPv6 address
            rdata.ip.version = 6;
            memcpy(rdata.ip.value.ipv6, data + *offset, rdlength);
            *offset += rdlength;
            break;
        case NS:
        case CNAME:
        case PTR:
            // RDATA contains is a domain name
            rdata.domain_name = dns_parse_domain_name(data, offset);
            break;
        default:
            // RDATA contains is generic data
            rdata.data = (uint8_t *) malloc(sizeof(char) * rdlength);
            memcpy(rdata.data, data + *offset, rdlength);
            *offset += rdlength;
        }
    }
    return rdata;
}

/**
 * Parse a DNS Resource Record list.
 * @param count the number of resource records present in the section
 * @param data a pointer pointing to the start of the DNS message
 * @param offset a pointer to the current parsing offset
 * @return the parsed resource records list
 */
dns_resource_record_t* dns_parse_rrs(uint16_t count, uint8_t *data, uint16_t *offset) {
    dns_resource_record_t *rrs = (dns_resource_record_t *) malloc(count * sizeof(dns_resource_record_t));
    for (uint16_t i = 0; i < count; i++) {
        // Parse domain name
        (rrs + i)->name = dns_parse_domain_name(data, offset);
        // Parse rtype, rclass and TTL
        dns_rr_type_t rtype = ntohs(*((uint16_t *) (data + *offset)));
        (rrs + i)->rtype = rtype;
        (rrs + i)->rclass = ntohs(*((uint16_t *) (data + *offset + 2))) & DNS_CLASS_MASK;
        (rrs + i)->ttl = ntohl(*((uint32_t *) (data + *offset + 4)));
        // Parse rdata
        uint16_t rdlength = ntohs(*((uint16_t *) (data + *offset + 8)));
        (rrs + i)->rdlength = rdlength;
        *offset += 10;
        (rrs + i)->rdata = dns_parse_rdata(rtype, rdlength, data, offset);
    }
    return rrs;
}

/**
 * Parse a DNS message.
 * 
 * @param data a pointer to the start of the DNS message
 * @return the parsed DNS message
 */
dns_message_t dns_parse_message(uint8_t *data) {
    // Init
    dns_message_t message;
    uint16_t offset = 0;
    message.questions = NULL;
    message.answers = NULL;
    message.authorities = NULL;
    message.additionals = NULL;

    // Parse DNS header
    message.header = dns_parse_header(data, &offset);
    // If present, parse DNS Question section
    if (message.header.qdcount > 0)
    {
        message.questions = dns_parse_questions(message.header.qdcount, data, &offset);
    }
    // If message is a response and section is present, parse DNS Answer section
    if (message.header.qr == 1 && message.header.ancount > 0)
    {
        message.answers = dns_parse_rrs(message.header.ancount, data, &offset);
    }

    /* Parsing other sections is not necessary for this project

    // If message is a response and section is present, parse DNS Authority section
    if (message.header.qr == 1 && message.header.nscount > 0)
    {
        message.authorities = dns_parse_rrs(message.header.nscount, data, &offset);
    }
    // If message is a response and section is present, parse DNS Additional section
    if (message.header.qr == 1 && message.header.arcount > 0)
    {
        message.additionals = dns_parse_rrs(message.header.arcount, data, &offset);
    }

    */

    return message;
}


///// LOOKUP /////

/**
 * @brief Check if a given string ends with a given suffix.
 * 
 * @param str the string to check
 * @param suffix the suffix to search for
 * @param suffix_length the length of the suffix
 * @return true if the string ends with the suffix
 * @return false if the string does not end with the suffix
 */
static bool ends_with(char* str, char* suffix, uint16_t suffix_length) {
    uint16_t str_length = strlen(str);
    if (str_length < suffix_length) {
        return false;
    }
    return strncmp(str + str_length - suffix_length, suffix, suffix_length) == 0;
}

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
bool dns_contains_suffix_domain_name(dns_question_t *questions, uint16_t qdcount, char *suffix, uint16_t suffix_length) {
    for (uint16_t i = 0; i < qdcount; i++) {
        if (ends_with((questions + i)-> qname, suffix, suffix_length)) {
            return true;
        }
    }
    return false;
}

/**
 * @brief Check if a given domain name is fully contained in a DNS Questions list.
 *
 * @param questions DNS Questions list
 * @param qdcount number of Questions in the list
 * @param domain_name the domain name to search for
 * @return true if the full domain name is found in the Questions list, false otherwise
 */
bool dns_contains_full_domain_name(dns_question_t *questions, uint16_t qdcount, char *domain_name)
{
    for (uint16_t i = 0; i < qdcount; i++) {
        if (strcmp((questions + i)->qname, domain_name) == 0) {
            return true;
        }
    }
    return false;
}

/**
 * @brief Search for a specific domain name in a DNS Questions list.
 * 
 * @param questions DNS Questions list
 * @param qdcount number of Suestions in the list
 * @param domain_name the domain name to search for
 * @return the DNS Question related to the given domain name, or NULL if not found
 */
dns_question_t* dns_get_question(dns_question_t *questions, uint16_t qdcount, char *domain_name) {
    for (uint16_t i = 0; i < qdcount; i++) {
        if (strcmp((questions + i)->qname, domain_name) == 0) {
            return questions + i;
        }
    }
    return NULL;
}

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
ip_list_t dns_get_ip_from_name(dns_resource_record_t *answers, uint16_t ancount, char *domain_name) {
    ip_list_t ip_list;
    ip_list.ip_count = 0;
    ip_list.ip_addresses = NULL;
    char *cname = domain_name;
    for (uint16_t i = 0; i < ancount; i++) {
        if (strcmp((answers + i)->name, cname) == 0) {
            dns_rr_type_t rtype = (answers + i)->rtype;
            if (rtype == A || rtype == AAAA)
            {
                // Handle IP list length
                if (ip_list.ip_addresses == NULL) {
                    ip_list.ip_addresses = (ip_addr_t *) malloc(sizeof(ip_addr_t));
                } else {
                    void *realloc_ptr = realloc(ip_list.ip_addresses, (ip_list.ip_count + 1) * sizeof(ip_addr_t));
                    if (realloc_ptr == NULL) {
                        // Handle realloc error
                        free(ip_list.ip_addresses);
                        fprintf(stderr, "Error reallocating memory for IP list.\n");
                        ip_list.ip_count = 0;
                        ip_list.ip_addresses = NULL;
                        return ip_list;
                    } else {
                        ip_list.ip_addresses = (ip_addr_t*) realloc_ptr;
                    }
                }
                // Handle IP version and value
                *(ip_list.ip_addresses + ip_list.ip_count) = (answers + i)->rdata.ip;
                ip_list.ip_count++;
            }
            else if ((answers + i)->rtype == CNAME)
            {
                cname = (answers + i)->rdata.domain_name;
            }
        }
    }
    return ip_list;
}


///// DESTROY /////

/**
 * @brief Free the memory allocated for a DNS RDATA field.
 * 
 * @param rdata the DNS RDATA field to free
 * @param rtype the DNS Resource Record Type of the RDATA field
 */
static void dns_free_rdata(rdata_t rdata, dns_rr_type_t rtype) {
    switch (rtype) {
    case A:
    case AAAA:
        break;  // Nothing to free for IP addresses
    case NS:
    case CNAME:
    case PTR:
        free(rdata.domain_name);
        break;
    default:
        free(rdata.data);
    }
}

/**
 * @brief Free the memory allocated for a list of DNS Resource Records.
 * 
 * @param rr the list of DNS Resource Records to free
 * @param count the number of Resource Records in the list
 */
static void dns_free_rrs(dns_resource_record_t *rrs, uint16_t count) {
    if (rrs != NULL && count > 0) {
        for (uint16_t i = 0; i < count; i++) {
            dns_resource_record_t rr = *(rrs + i);
            if (rr.rdlength > 0) {
                free(rr.name);
                dns_free_rdata(rr.rdata, rr.rtype);
            }
        }
        free(rrs);
    }
}

/**
 * Free the memory allocated for a DNS message.
 *
 * @param question the DNS message to free
 */
void dns_free_message(dns_message_t message) {
    // Free DNS Questions
    if (message.header.qdcount > 0) {
        for (uint16_t i = 0; i < message.header.qdcount; i++) {
            free((message.questions + i)->qname);
        }
        free(message.questions);
    }

    // Free DNS Answers
    dns_free_rrs(message.answers, message.header.ancount);

    /* Other sections are not used in this project

    // Free DNS Authorities
    dns_free_rrs(message.authorities, message.header.nscount);
    // Free DNS Additionals
    dns_free_rrs(message.additionals, message.header.arcount);

    */
}


///// PRINTING /////

/**
 * Print a DNS header.
 * 
 * @param message the DNS header
 */
void dns_print_header(dns_header_t header) {
    printf("DNS Header:\n");
    printf("  ID: %#hx\n", header.id);
    printf("  Flags: %#hx\n", header.flags);
    printf("  QR: %d\n", header.qr);
    printf("  Questions count: %hd\n", header.qdcount);
    printf("  Answers count: %hd\n", header.ancount);
    printf("  Authority name servers count: %hd\n", header.nscount);
    printf("  Additional records count: %hd\n", header.arcount);
}

/**
 * Print a DNS Question
 * 
 * @param question the DNS Question
 */
void dns_print_question(dns_question_t question) {
    printf("  Question:\n");
    printf("    Domain name: %s\n", question.qname);
    printf("    Type: %hd\n", question.qtype);
    printf("    Class: %hd\n", question.qclass);
}

/**
 * Print a DNS Question section.
 * 
 * @param qdcount the number of Questions in the Question section
 * @param questions the list of DNS Questions
 */
void dns_print_questions(uint16_t qdcount, dns_question_t *questions) {
    printf("DNS Question section:\n");
    for (uint16_t i = 0; i < qdcount; i++) {
        dns_question_t *question = questions + i;
        if (question != NULL) {
            dns_print_question(*question);
        }
    }
}

/**
 * Return a string representation of the given RDATA value.
 * 
 * @param rtype the type corresponding to the RDATA value
 * @param rdlength the length, in bytes, of the RDATA value
 * @param rdata the RDATA value, stored as a union type
 * @return a string representation of the RDATA value
 */
char* dns_rdata_to_str(dns_rr_type_t rtype, uint16_t rdlength, rdata_t rdata) {
    if (rdlength == 0) {
        // RDATA is empty
        return "";
    }
    switch (rtype) {
        case A:
        case AAAA:
            // RDATA is an IP (v4 or v6) address
            return ip_net_to_str(rdata.ip);
            break;
        case NS:
        case CNAME:
        case PTR:
            // RDATA is a domain name
            return rdata.domain_name;
            break;
        default: ;
            // Generic RDATA
            char *buffer = (char *) malloc(rdlength * 4 + 1);  // Allocate memory for each byte (4 characters) + the NULL terminator
            for (uint8_t i = 0; i < rdlength; i++) {
                snprintf(buffer + (i * 4), 5, "\\x%02x", *(rdata.data + i));
            }
            return buffer;
    }
}

/**
 * Print a DNS Resource Record.
 * 
 * @param section_name the name of the Resource Record section
 * @param rr the DNS Resource Record
 */
void dns_print_rr(char* section_name, dns_resource_record_t rr) {
    printf("  %s RR:\n", section_name);
    printf("    Name: %s\n", rr.name);
    printf("    Type: %hd\n", rr.rtype);
    printf("    Class: %hd\n", rr.rclass);
    printf("    TTL [s]: %d\n", rr.ttl);
    printf("    Data length: %hd\n", rr.rdlength);
    printf("    RDATA: %s\n", dns_rdata_to_str(rr.rtype, rr.rdlength, rr.rdata));
}

/**
 * Print a DNS Resource Records section.
 * 
 * @param section_name the name of the Resource Record section
 * @param count the number of Resource Records in the section
 * @param rrs the list of DNS Resource Records
 */
void dns_print_rrs(char* section_name, uint16_t count, dns_resource_record_t *rrs) {
    printf("%s RRs:\n", section_name);
    for (uint16_t i = 0; i < count; i++) {
        dns_resource_record_t *rr = rrs + i;
        if (rr != NULL)
            dns_print_rr(section_name, *rr);
    }
}

/**
 * Print a DNS message.
 * 
 * @param message the DNS message
 */
void dns_print_message(dns_message_t message) {
    // Print DNS Header
    dns_print_header(message.header);

    // Print DNS Questions, if any
    if (message.header.qdcount > 0)
        dns_print_questions(message.header.qdcount, message.questions);

    // Print DNS Answers, if message is a response and has answers
    if (message.header.qr == 1 && message.header.ancount > 0)
        dns_print_rrs("Answer", message.header.ancount, message.answers);

    /* Other sections are not used in this project

    dns_print_rrs("Authority", message.header.nscount, message.authorities);
    dns_print_rrs("Additional", message.header.arcount, message.additionals);

    */
}
