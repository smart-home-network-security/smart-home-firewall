/**
 * @file include/parsers/igmp.h
 * @brief IGMP message parser
 * @date 2022-10-05
 *
 * IGMP message parser.
 * Supports v1 and v2, and v3 Membership Report messages.
 * TODO: support v3 Membership Query messages.
 *
 * @copyright Copyright (c) 2022
 *
 */

#ifndef _IOTFIREWALL_IGMP_
#define _IOTFIREWALL_IGMP_

#include <stdio.h>
#include <stdint.h>
#include "packet_utils.h"


/**
 * @brief IGMP message types
 */
typedef enum {
    MEMBERSHIP_QUERY     = 0x11,
    V1_MEMBERSHIP_REPORT = 0x12,
    V2_MEMBERSHIP_REPORT = 0x16,
    LEAVE_GROUP          = 0x17,
    V3_MEMBERSHIP_REPORT = 0x22
} igmp_message_type_t;

/**
 * @brief IGMPv2 message
 */
typedef struct {
    uint8_t max_resp_time;
    uint16_t checksum;
    uint32_t group_address;  // IPv4 group address, in network byte order
} igmp_v2_message_t;

/**
 * @brief IGMPv3 membership query
 */
typedef struct {
    uint8_t max_resp_code;
    uint16_t checksum;
    uint32_t group_address;  // IPv4 group address, in network byte order
    uint8_t flags;  // Resv, S, QRV
    uint8_t qqic;
    uint16_t num_sources;
    uint32_t *sources;  // Array of IPv4 addresses, in network byte order
} igmp_v3_membership_query_t;

/**
 * @brief IGMPv3 Group Record
 */
typedef struct {
    uint8_t type;
    uint8_t aux_data_len;
    uint16_t num_sources;
    uint32_t group_address;  // IPv4 group address, in network byte order
    uint32_t *sources;  // Array of IPv4 addresses, in network byte order
} igmp_v3_group_record_t;

/**
 * @brief IGMPv3 membership report
 */
typedef struct {
    uint16_t checksum;
    uint16_t num_groups;
    igmp_v3_group_record_t *groups;  // Array of group records
} igmp_v3_membership_report_t;

/**
 * @brief IGMP message body.
 */
typedef union
{
    igmp_v2_message_t v2_message;
    igmp_v3_membership_query_t v3_membership_query;
    igmp_v3_membership_report_t v3_membership_report;
} igmp_message_body_t;

/**
 * @brief Generic IGMP message
 */
typedef struct
{
    uint8_t version;
    igmp_message_type_t type;
    igmp_message_body_t body;
} igmp_message_t;


////////// FUNCTIONS //////////

/**
 * @brief Parse an IGMP message.
 * 
 * @param data pointer to the start of the IGMP message
 * @return the parsed IGMP message
 */
igmp_message_t igmp_parse_message(uint8_t *data);

/**
 * @brief Free the memory allocated for an IGMP message.
 * 
 * @param message the IGMP message to free
 */
void igmp_free_message(igmp_message_t message);

/**
 * @brief Print an IGMP message.
 * 
 * @param message the IGMP message to print
 */
void igmp_print_message(igmp_message_t message);


#endif /* _IOTFIREWALL_IGMP_ */
