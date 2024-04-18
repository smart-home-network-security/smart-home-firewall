/**
 * @file src/parsers/igmp.c
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

#include "igmp.h"


///// PARSING /////

/**
 * @brief Parse an IGMPv2 message.
 *
 * @param data pointer to the start of the IGMPv2 message
 * @return the parsed IGMPv2 message
 */
static igmp_v2_message_t igmp_v2_parse_message(uint8_t *data) {
    igmp_v2_message_t message;
    message.max_resp_time = *(data + 1);
    message.checksum = ntohs(*((uint16_t *)(data + 2)));
    message.group_address = *((uint32_t *)(data + 4));  // Stored in network byte order
    return message;
}

/**
 * @brief Parse an array of IGMPv3 group records.
 * 
 * @param num_groups number of group records
 * @param data pointer to the start of the group records
 * @return pointer to the array of parsed group records
 */
static igmp_v3_group_record_t* igmp_v3_parse_groups(uint16_t num_groups, uint8_t *data) {
    // If num_groups is 0, group list is NULL
    if (num_groups == 0)
        return NULL;

    // num_groups is greater than 0
    igmp_v3_group_record_t *groups = malloc(num_groups * sizeof(igmp_v3_group_record_t));
    for (uint16_t i = 0; i < num_groups; i++) {
        igmp_v3_group_record_t *group = groups + i;
        group->type = *data;
        group->aux_data_len = *(data + 1);
        group->num_sources = ntohs(*((uint16_t *)(data + 2)));
        group->group_address = *((uint32_t *)(data + 4));  // Stored in network byte order
        if (group->num_sources > 0) {
            group->sources = malloc(group->num_sources * sizeof(uint32_t));
            for (uint16_t j = 0; j < group->num_sources; j++) {
                *((group->sources) + j) = *((uint32_t *)(data + 8 + j * 4));  // Stored in network byte order
            }
        } else {
            group->sources = NULL;
        }
        data += 8 + group->num_sources * 4;
    }
    return groups;
}

/**
 * @brief Parse an IGMPv3 Membership Report message.
 *
 * @param data pointer to the start of the IGMPv3 Membership Report message
 * @return the parsed IGMPv3 Membership Report message
 */
static igmp_v3_membership_report_t igmp_v3_parse_membership_report(uint8_t *data) {
    igmp_v3_membership_report_t message;
    message.checksum = ntohs(*((uint16_t *)(data + 2)));
    message.num_groups = ntohs(*((uint16_t *)(data + 6)));
    message.groups = igmp_v3_parse_groups(message.num_groups, data + 8);
    return message;
}

/**
 * @brief Parse an IGMP message.
 * 
 * @param data pointer to the start of the IGMP message
 * @return the parsed IGMP message
 */
igmp_message_t igmp_parse_message(uint8_t *data) {
    igmp_message_t message;
    message.type = (igmp_message_type_t) *data;
    // Dispatch on IGMP message type
    switch (message.type) {
    case MEMBERSHIP_QUERY:
    case V1_MEMBERSHIP_REPORT:
    case V2_MEMBERSHIP_REPORT:
    case LEAVE_GROUP:
        message.version = 2;
        message.body.v2_message = igmp_v2_parse_message(data);
        break;
    case V3_MEMBERSHIP_REPORT:
        message.version = 3;
        message.body.v3_membership_report = igmp_v3_parse_membership_report(data);
        break;
    default:
        break;
    }
    return message;
}

/**
 * @brief Free the memory allocated for an IGMP message.
 *
 * @param message the IGMP message to free
 */
void igmp_free_message(igmp_message_t message) {
    if (message.version == 3 && message.body.v3_membership_report.num_groups > 0) {
        for (uint16_t i = 0; i < message.body.v3_membership_report.num_groups; i++)
        {
            igmp_v3_group_record_t group = *(message.body.v3_membership_report.groups + i);
            if (group.num_sources > 0)
                free(group.sources);
        }
        free(message.body.v3_membership_report.groups);
    }
}


///// PRINTING /////

/**
 * @brief Print an IGMPv2 message.
 *
 * @param v2_message the IGMPv2 message to print
 */
static void igmp_v2_print_message(igmp_v2_message_t v2_message) {
    printf("  Max resp time: %hhu\n", v2_message.max_resp_time);
    printf("  Checksum: %#hx\n", v2_message.checksum);
    printf("  Group address: %s\n", ipv4_net_to_str(v2_message.group_address));
}

/**
 * @brief Print an IGMPv3 Membership Report message.
 * 
 * @param group the IGMPv3 Membership Report message to print
 */
static void igmp_v3_print_membership_report(igmp_v3_membership_report_t v3_message) {
    printf("  Checksum: %#hx\n", v3_message.checksum);
    printf("  Number of groups: %hu\n", v3_message.num_groups);
    for (uint16_t i = 0; i < v3_message.num_groups; i++) {
        igmp_v3_group_record_t group = *(v3_message.groups + i);
        printf("  Group %d:\n", i);
        printf("    Type: %#hhx\n", group.type);
        printf("    Aux data len: %hhu\n", group.aux_data_len);
        printf("    Number of sources: %hu\n", group.num_sources);
        printf("    Group address: %s\n", ipv4_net_to_str(group.group_address));
        for (uint16_t j = 0; j < group.num_sources; j++) {
            printf("    Source %d: %s\n", j, ipv4_net_to_str(*(group.sources + j)));
        }
    }
}

/**
 * @brief Print an IGMP message.
 * 
 * @param message the IGMP message to print
 */
void igmp_print_message(igmp_message_t message) {
    printf("IGMP message:\n");
    printf("  Version: %hhu\n", message.version);
    printf("  Type: %#hhx\n", message.type);
    switch (message.version) {
    case 2:
        igmp_v2_print_message(message.body.v2_message);
        break;
    case 3:
        igmp_v3_print_membership_report(message.body.v3_membership_report);
        break;
    }
}
