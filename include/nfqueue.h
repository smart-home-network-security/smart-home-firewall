/**
 * @file include/nfqueue.h
 * @brief Wrapper for the netfilter_queue library
 * @date 2022-09-09
 * 
 * @copyright Copyright (c) 2022
 * 
 */

#ifndef _IOTFIREWALL_NFQUEUE_
#define _IOTFIREWALL_NFQUEUE_

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <errno.h>
#include <pthread.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include "rule_utils.h"
#include "packet_utils.h"

#define DEFAULT_TIMEOUT 3600 // Default timeout is one sec

/**
 * @brief Structure defining the period of activity of a policy.
 */
typedef struct {
    char start[20];
    char duration[20];
} ActivityPeriod;

/**
 * @brief Structure which stores the data relative to one policy interaction.
 */
typedef struct {
    uint16_t nfq_id_base;   // Base nfqueue ID
    uint8_t num_policies;   // Total number of policies
    uint8_t num_states;     // Number of different states
    pthread_mutex_t mutex;  // State mutex
    uint8_t current_state;  // Current state
    counters_t *counters;   // Array of counters
    ip_addr_t cached_ip;    // Cached IP address
    double timeout;         // Timeout of the request (in sec). 0 = DEFAULT_TIMEOUT ; -1 = no timeout
    time_t time_request;    // Time since last request ; set to 0 if no request has been made before
    time_t current_time;   // Current time
    ActivityPeriod *activity_period; // Activity period of the policy
    bool in_loop;           // Whether currently in a loop
} interaction_data_t;

/**
 * @brief Packet and duration counters ids.
 * 
 * Identifiers for the packet and duration counters.
 * Used as argument for the nfqueue threads.
 */
typedef struct {
    uint8_t packet_counter_id;
    uint8_t duration_counter_id;
} counters_id_t;

/**
 * @brief Alias for a basic callback function.
 *
 * @param pkt_id packet ID for netfilter queue
 * @param hash packet payload SHA256 hash (only present if LOG is defined)
 * @param timestamp packet timestamp (only present if LOG is defined)
 * @param pkt_len packet length, in bytes
 * @param payload pointer to the packet payload
 * @param arg pointer to the argument passed to the callback function
 * @return the verdict for the packet
 */
#ifdef LOG
typedef uint32_t basic_callback(int pkt_id, uint8_t *hash, struct timeval timestamp, int pkt_len, uint8_t *payload, void *arg);
#else
typedef uint32_t basic_callback(int pkt_id, int pkt_len, uint8_t *payload, void *arg);
#endif /* LOG */

/**
 * Structure that stores a basic callback function and its arguments.
 */
typedef struct callback_struct {
    basic_callback *func;  // Basic callback function
    void *arg;             // Arguments to pass to the callback function
} callback_struct_t;

/**
 * @brief Contains the necessary arguments for an nfqueue thread.
 * The arguments are:
 * - the thread ID
 * - the queue number to bind to
 * - the basic callback function
 * - the arguments to pass to the callback function
 */
typedef struct {
    uint16_t queue_id;     // Queue number to bind to
    basic_callback *func;  // Basic callback function
    void *arg;             // Arguments to pass to the callback function
} thread_arg_t;

/**
 * Retrieve the packet id from a nfq_data struct,
 * or -1 in case of error.
 * 
 * @param nfa the given nfq_data struct
 * @return the packet id, or -1 in case of error
 */
int get_pkt_id(struct nfq_data *nfad);

/**
 * Bind queue to callback function,
 * and wait for packets.
 * 
 * @param queue_num the number of the queue to bind to
 * @param callback the callback funtion, called upon packet reception
 * The callback function must have the following signature:
 *     int callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data)
 * @param arg the argument to pass to the callback function
 */
void bind_queue(uint16_t queue_num, basic_callback *callback, void *arg);

/**
 * @brief pthread wrapper for bind_queue.
 * 
 * @param arg typeless pointer to the thread argument, which is a thread_arg_t struct containing the necessary arguments for bind_queue.
 * @return NULL
 */
void* nfqueue_thread(void *arg);

/**
 * @brief Check if the last request is too old to be accepted
 * 
 * @param threshold time in sec before dropping the request
 * @param last_request time of the last request 
 * @return true the request is too old and must be refused
 * @return false the request is recent enought and might be accepted
 */
bool is_timedout(double threshold, time_t last_request);


/**
 * @brief Parse the period string and fill in the corresponding values
 * 
 * @param cron_str 
 * @param minutes 
 * @param hours 
 * @param days 
 * @param dayOfWeek 
 * @param is_duration 
 */
void parse_period(const char *period_str, int *minutes, int *hours, int *days, int *dayOfWeek, int is_duration);

/**
 * @brief Get the Day Of Week from a time_t. 0 = Sunday, 1 = Monday, ..., 6 = Saturday
 * 
 * @param time 
 * @return int 
 */
int getDayOfWeek(time_t time);

/**
 * @brief Find the previous trigger time before the current time
 * 
 * @param activity_period 
 * @param current_time 
 * @return time_t 
 */
time_t previous_trigger(const ActivityPeriod *activity_period, time_t current_time);

/**
 * @brief Check if the current time is in the activity period of the policy
 * 
 * @param activity_period the activity period of the policy
 * @param current_time the current time
 * @return true the current time is in the activity period
 * @return false the current time is not in the activity period
 */
bool is_in_activity_period(ActivityPeriod *activity_period, time_t current_time);

#endif /* _IOTFIREWALL_NFQUEUE_ */
