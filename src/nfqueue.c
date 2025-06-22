/**
 * @file src/nfqueue.c
 * @brief Wrapper for the netfilter_queue library
 * @date 2022-09-09
 * 
 * @copyright Copyright (c) 2022
 * 
 */

#include "nfqueue.h"


/**
 * Retrieve the packet id from a nfq_data struct,
 * or -1 in case of error.
 * 
 * @param nfa the given nfq_data struct
 * @return the packet id, or -1 in case of error
 */
int get_pkt_id(struct nfq_data *nfad) {
	struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfad);
	if (ph) {
		return ntohl(ph->packet_id);
	}
	return -1;
}

/**
 * @brief Full callback function, compliant to the nfq_callback type.
 * 
 * @param qh queue handle
 * @param nfmsg message object that contains the packet
 * @param nfad Netlink packet data handle
 * @param data data to be used by the function.
 *             In this case, a pointer to a callback_struct_t, which contains a basic_callback function and its arguments.
 * @return -1 on error, >= 0 otherwise
 */
int nfqueue_callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfad, void *data) {
	// Verdict (will be updated by the basic callback function)
	uint32_t verdict = NF_ACCEPT;

	// Get packet id
    int pkt_id = get_pkt_id(nfad);
	if (pkt_id == -1) {
		fprintf(stderr, "Could not get packet id.\n");
	}

	// Get packet payload
    uint8_t *payload;
    int length = nfq_get_payload(nfad, &payload);
    if (length == -1) {
		fprintf(stderr, "Could not get packet #%d payload.\n", pkt_id);
	}

	#ifdef LOG
	// Get packet timestamp
	struct timeval timestamp;
	if (nfq_get_timestamp(nfad, &timestamp) != 0)
	{
		fprintf(stderr, "Could not get packet #%d timestamp.\n", pkt_id);
	}

	// Compute packet SHA256 hash
	uint8_t *hash = compute_hash(payload, length);

	// Call basic callback function to set packet verdict
	verdict = (*(((callback_struct_t *)data)->func))(pkt_id, hash, timestamp, length, payload, ((callback_struct_t *)data)->arg);
	#else
	// Call basic callback function to set packet verdict
	verdict = (*(((callback_struct_t *)data)->func))(pkt_id, length, payload, ((callback_struct_t *)data)->arg);
	#endif /* LOG */

	return nfq_set_verdict(qh, pkt_id, verdict, length, payload);
}

/**
 * Bind queue to callback function,
 * and wait for packets.
 * 
 * @param queue_num the number of the queue to bind to
 * @param callback the basic callback function, called upon packet reception
 * The callback function must have the following signature:
 *     uint32_t callback(int pkt_id, uint8_t *payload, void *arg)
 * @param arg the argument to pass to the basic callback function
 */
void bind_queue(uint16_t queue_num, basic_callback *callback, void *arg)
{
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));

	#ifdef DEBUG
	printf("opening library handle\n");
	#endif
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	#ifdef DEBUG
	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	#endif
	int err = nfq_unbind_pf(h, AF_INET);
	if (err < 0) {
		perror("error during nfq_unbind_pf()");
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	#ifdef DEBUG
	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	#endif
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	#ifdef DEBUG
	printf("binding this socket to queue '%d'\n", queue_num);
	#endif
	// Create nfqueue callback function from basic callback function
	callback_struct_t callback_struct;
	callback_struct.func = callback;
	callback_struct.arg = arg;
	qh = nfq_create_queue(h, queue_num, &nfqueue_callback, &callback_struct);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	#ifdef DEBUG
	printf("setting copy_packet mode\n");
	#endif
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	#ifdef DEBUG
	printf("setting flags to request UID and GID\n");
	#endif
	if (nfq_set_queue_flags(qh, NFQA_CFG_F_UID_GID, NFQA_CFG_F_UID_GID)) {
		fprintf(stderr, "This kernel version does not allow to "
				"retrieve process UID/GID.\n");
	}

	#ifdef DEBUG
	printf("setting flags to request security context\n");
	#endif
	if (nfq_set_queue_flags(qh, NFQA_CFG_F_SECCTX, NFQA_CFG_F_SECCTX)) {
		fprintf(stderr, "This kernel version does not allow to "
				"retrieve security context.\n");
	}

	#ifdef DEBUG
	printf("Waiting for packets...\n");
	#endif

	fd = nfq_fd(h);

	while (1) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		/* if your application is too slow to digest the packets that
		 * are sent from kernel-space, the socket buffer that we use
		 * to enqueue packets may fill up returning ENOBUFS. Depending
		 * on your application, this error may be ignored. Please, see
		 * the doxygen documentation of this library on how to improve
		 * this situation.
		 */
		if (rv < 0 && errno == ENOBUFS) {
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");
		break;
	}

	#ifdef DEBUG
	printf("unbinding from queue %d\n", queue_num);
	#endif
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	#ifdef DEBUG
	printf("closing library handle\n");
	#endif
	nfq_close(h);

}

/**
 * @brief pthread wrapper for bind_queue.
 * 
 * @param arg typeless pointer to the thread argument, which is a thread_arg_t struct containing the necessary arguments for bind_queue.
 * @return NULL (should loop forever)
 */
void* nfqueue_thread(void *arg) {
	thread_arg_t *thread_arg = (thread_arg_t *) arg;
	bind_queue(thread_arg->queue_id, thread_arg->func, thread_arg->arg);
	return NULL;
}

/**
 * @brief Check if the last request is too old to be accepted
 * 
 * @param threshold time in sec before dropping the request
 * @param last_request time of the last request 
 * @return true the request is too old and must be refused
 * @return false the request is recent enought and might be accepted
 */
bool is_timedout(double threshold, time_t last_request) {
	// first request or timeout is disabled
	if (last_request == 0 || threshold == -1) {
		#ifdef DEBUG
		puts("\nFirst request or no timeout has been given") ;
		#endif
		return false ; 			// laugh in C and accept the request
	}

	if (threshold == 0) {		// If there is no timeout, use the default one
		threshold = DEFAULT_TIMEOUT ;
		#ifdef DEBUG
		printf("\nNo timeout given, defaulting to %d", DEFAULT_TIMEOUT) ;
		#endif
	} 							// default is define in nfqueue.h

	time_t now = time(NULL); 	// get the time NOW

	double diff = difftime(now, last_request) ;

	#ifdef DEBUG
		printf("\nComparing the last request %ld and the time now %ld : %f", last_request, now, diff) ;
		printf("\nthreshold (%f) < diff = %d", threshold,(threshold < diff)) ;
	#endif

	return threshold < diff ;
}

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
void parse_period(const char *period_str, int *minutes, int *hours, int *days, int *dayOfWeek, int is_duration) {
    int index = 0;
    char *token;
    char temp_str[100];
    strncpy(temp_str, period_str, sizeof(temp_str)-1);
	temp_str[sizeof(temp_str) - 1] = '\0';
    token = strtok(temp_str, " ");
    int value;
    while (token != NULL && index < 4) {
        if (strcmp(token, "*") == 0) {
            if (is_duration) {
                value = 0;
            } else {
                value = -1;
            }
        } else {
            value = atoi(token);
        }

        if (index == 0) {
            *minutes = value;
        } else if (index == 1) {
            *hours = value;
        } else if (index == 2) {
            *days = value;
        } else if (index == 3) {
            *dayOfWeek = value;
        }

        index++;
        token = strtok(NULL, " ");
    }
}

/**
 * @brief Get the Day Of Week from a time_t. 0 = Sunday, 1 = Monday, ..., 6 = Saturday
 * 
 * @param time 
 * @return int 
 */
int getDayOfWeek(time_t time) {
    struct tm *time_info = localtime(&time);
    return time_info->tm_wday;
}

/**
 * @brief Find the previous trigger time before the current time
 * 
 * @param activity_period 
 * @param current_time 
 * @return time_t 
 */
time_t previous_trigger(const ActivityPeriod *activity_period, time_t current_time) {
    struct tm *check_tm = localtime(&current_time);
	int current_day = check_tm->tm_mday;
    int current_dayOfWeek = check_tm->tm_wday;
    int current_hour = check_tm->tm_hour;
    int minutes, hours, days, dayOfWeek;
    parse_period(activity_period->start, &minutes, &hours, &days, &dayOfWeek, 0);
    // Set seconds to 0
    check_tm->tm_sec = 0;
    // Modify current date with the non "*" values
    if (minutes != -1) {
        check_tm->tm_min = minutes;
    }
    if (hours != -1) {
        check_tm->tm_hour = hours;
    }
    if (days != -1) {
        check_tm->tm_mday = days;
    }
    // loop until the previous trigger time is before the check time
    while (mktime(check_tm) > current_time || (dayOfWeek != -1 && getDayOfWeek(mktime(check_tm)) != dayOfWeek)) {
        if (days != -1) {
            check_tm->tm_mon -= 1   ;
            continue;
        }
        if (dayOfWeek != -1) {
            check_tm->tm_mday -= 1;
            continue;
        }
        if (hours != -1) {
            check_tm->tm_mday -= 1;
            continue;
        }
        if (minutes != -1) {
            check_tm->tm_hour -= 1;
            continue;
        }    
    }

    if (hours != -1 && current_hour != check_tm->tm_hour) {
        if (minutes == -1) {
            check_tm->tm_min = 59;
        }
    }
    if (days != -1 && current_day != check_tm->tm_mday) {
        if (hours == -1) {
            check_tm->tm_hour = 23;
        }
        if (minutes == -1) {
            check_tm->tm_min = 59;
        }
    }
    if (dayOfWeek != -1 && current_dayOfWeek != check_tm->tm_wday) {
        if (hours == -1) {
            check_tm->tm_hour = 23;
        }
        if (minutes == -1) {
            check_tm->tm_min = 59;
        }
    }
	
    return mktime(check_tm);
}

/**
 * @brief Check if the current time is in the activity period of the policy
 * 
 * @param activity_period the activity period of the policy
 * @param current_time the current time
 * @return true the current time is in the activity period
 * @return false the current time is not in the activity period
 */
bool is_in_activity_period(ActivityPeriod *activity_period, time_t current_time) {
	int duration_minutes, duration_hours, duration_days, duration_dayOfWeek;
    time_t start_time = previous_trigger(activity_period, current_time);
    time_t end_time;

    parse_period(activity_period->duration, &duration_minutes, &duration_hours, &duration_days, &duration_dayOfWeek, 1);

    end_time = start_time + duration_minutes * 60 + duration_hours * 3600 + duration_days * 86400;

    return (start_time <= current_time && current_time < end_time);
}