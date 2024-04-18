/**
 * @file src/nflog.h
 * @brief Wrapper for the netfilter_log library
 * @date 2023-05-04
 *
 * @copyright Copyright (c) 2023
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <pthread.h>
#include <libnetfilter_log/libnetfilter_log.h>
#include "packet_utils.h"

#define STDOUT "-"


// GLOBAL VARIABLES
// Global packet counter
pthread_mutex_t pkt_cnt_mutex;
volatile uint16_t pkt_cnt;
// Log file
bool is_log_file_stdout;
FILE *log_file;


/**
 * @brief SIGINT handler, flush and close log file.
 *
 * @param arg unused
 */
void sigint_handler(int arg)
{
    int err;

    err = fflush(log_file);
    if (err != 0)
    {
        perror("fflush log_file");
    }

    if (!is_log_file_stdout) {
        err = fclose(log_file);
        if (err != 0)
        {
            perror("fclose log_file");
        }
    }
    exit(0);
}


/**
 * @brief Log callback function.
 * 
 * Print packet data in the following format:
 *   id,timestamp,policy,state,verdict
 * 
 * @return int: 0 if successful
 */
static int callback(struct nflog_g_handle *gh, struct nfgenmsg *nfmsg,
              struct nflog_data *nfa, void *data)
{
    pthread_mutex_lock(&pkt_cnt_mutex);
    struct timeval timestamp;
    int payload_len;
    char *payload;
    char *prefix;
    int err;

    // Field 1: Packet count
    err = fprintf(log_file, "%hu,", pkt_cnt++);
    if (err < 0)
    {
        fprintf(stderr, "Error writing packet count %hu to log file\n", pkt_cnt);
    }

    pthread_mutex_unlock(&pkt_cnt_mutex);

    // Get packet payload
    payload_len = nflog_get_payload(nfa, &payload);
    if (payload_len == -1) {
        fprintf(stderr, "Error getting payload\n");
    }

    // Field 2: Payload SHA256 hash
    uint8_t *hash = compute_hash((uint8_t *) payload, payload_len);
    for (uint16_t i = 0; i < SHA256_BLOCK_SIZE; i++) {
        err = fprintf(log_file, "%02x", *(hash + i));
        if (err < 0) {
            fprintf(stderr, "Error writing hash byte %02x to log file\n", *(hash + i));
        }
    }
    free(hash);

    // Field 3: Timestamp
    if (nflog_get_timestamp(nfa, &timestamp) == 0) {
        err = fprintf(log_file, ",%ld.%06ld", (long int)timestamp.tv_sec, (long int)timestamp.tv_usec);
        if (err < 0) {
            fprintf(stderr, "Error writing timestamp %ld.%06ld to log file\n", (long int)timestamp.tv_sec, (long int)timestamp.tv_usec);
        }
    }

    // Remaining fields, put in log prefix
    prefix = nflog_get_prefix(nfa);
    if (prefix != NULL) {
        err = fprintf(log_file, ",%s\n", prefix);
        if (err < 0) {
            fprintf(stderr, "Error writing \"%s\" to log file\n", prefix);
        }
    }

    // Flush log file
    err = fflush(log_file);
    if (err != 0) {
        perror("fflush log_file");
    }

    return 0;
}

// nflog program entry point
int main(int argc, char* argv[])
{
    uint8_t log_group;
    char *log_file_name = NULL;
    struct nflog_handle *h;
    struct nflog_g_handle *gh;
    int rv, fd;
    char buf[4096];


    /* COMMAND LINE ARGUMENTS */

    // Check number of arguments
    if (argc != 2 && argc != 3) {
        // Second argument is optional
        fprintf(stderr, "Usage: %s log_group [log_file]\n", argv[0]);
        exit(1);
    }
    // Parse log group
    log_group = atoi(argv[1]);
    // Parse log file
    if (argc == 3) {
        // CSV log file name provided
        log_file_name = argv[2];
        if (strcmp(log_file_name, STDOUT) != 0) {
            is_log_file_stdout = false;
        } else {
            is_log_file_stdout = true;
            log_file = stdout;
        }
    } else if (argc == 2) {
        // Default CSV log file: stdout
        is_log_file_stdout = true;
        log_file = stdout;
    }

    // Initialize packet counter
    pkt_cnt = 1;
    pthread_mutex_init(&pkt_cnt_mutex, NULL);

    h = nflog_open();
    if (!h)
    {
        perror("nflog_open");
        exit(1);
    }

    #ifdef DEBUG
    printf("unbinding existing nf_log handler for AF_INET (if any)\n");
    #endif
    if (nflog_unbind_pf(h, AF_INET) < 0)
    {
        perror("nflog_unbind_pf");
        exit(1);
    }

    #ifdef DEBUG
    printf("binding nfnetlink_log to AF_INET\n");
    #endif
    if (nflog_bind_pf(h, AF_INET) < 0)
    {
        perror("nflog_bind_pf");
        exit(1);
    }

    #ifdef DEBUG
    printf("binding this socket to group %hhu\n", log_group);
    #endif
    gh = nflog_bind_group(h, log_group);
    if (!gh)
    {
        perror(NULL);
        fprintf(stderr, ": nflog_bind_group %hhu\n", log_group);
        exit(1);
    }

    #ifdef DEBUG
    printf("setting copy_packet mode\n");
    #endif
    if (nflog_set_mode(gh, NFULNL_COPY_PACKET, 0xffff) < 0)
    {
        perror("nflog_set_mode NFULNL_COPY_PACKET");
        exit(1);
    }

    fd = nflog_fd(h);

    // Open log file
    if (!is_log_file_stdout) {
        log_file = fopen(log_file_name, "w");
        if (log_file == NULL) {
            perror("fopen log_file");
            log_file = stdout;
            is_log_file_stdout = true;
        }
    }

    #ifdef DEBUG
    printf("registering callback for group %hhu\n", log_group);
    #endif
    nflog_callback_register(gh, &callback, log_file);

    // Print CSV log header
    fprintf(log_file, "id,hash,timestamp,policy,state,verdict\n");

    #ifdef DEBUG
    printf("going into main loop\n");
    #endif
    while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0)
    {
        /* handle messages in just-received packet */
        nflog_handle_packet(h, buf, rv);
    }

    // Close log file
    if (!is_log_file_stdout) {
        fclose(log_file);
    }

    #ifdef DEBUG
    printf("unbinding from group %hhu\n", log_group);
    #endif
    nflog_unbind_group(gh);

#ifdef INSANE
    /* normally, applications SHOULD NOT issue this command,
     * since it detaches other programs/sockets from AF_INET, too ! */
    printf("unbinding from AF_INET\n");
    nflog_unbind_pf(h, AF_INET);
#endif

    #ifdef DEBUG
    printf("closing handle\n");
    #endif
    nflog_close(h);

    // Destroy packet counter mutex
    pthread_mutex_destroy(&pkt_cnt_mutex);

    return EXIT_SUCCESS;

}
