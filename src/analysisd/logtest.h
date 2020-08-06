/* Copyright (C) 2015-2020, Wazuh Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef LOGTEST_H
#define LOGTEST_H

#include "shared.h"
#include "rules.h"
#include "config.h"
#include "decoders/decoder.h"
#include "eventinfo.h"
#include "cleanevent.h"
#include "lists.h"
#include "lists_make.h"
#include "fts.h"
#include "accumulator.h"
#include "../config/logtest-config.h"
#include "../os_net/os_net.h"
#include "format/to_json.h"
#include <time.h>


/* JSON REQUEST / RESPONSE fields names */
#define W_LOGTEST_JSON_TOKEN            "token"   ///< Token field name of json input/output.
#define W_LOGTEST_JSON_EVENT            "event"   ///< Event field name of json input.
#define W_LOGTEST_JSON_LOGFORMAT   "log_format"   ///< Log format field name of json input.
#define W_LOGTEST_JSON_LOCATION      "location"   ///< Location field name of json input.
#define W_LOGTEST_JSON_ALERT            "alert"   ///< Alert field name of json output (boolean).
#define W_LOGTEST_JSON_MESSAGE        "message"   ///< Message format field name of json output.
#define W_LOGTEST_JSON_CODE           "codemsg"   ///< Code of message field name of json output (number)
#define W_LOGTEST_JSON_OUTPUT          "output"   ///< Output field name of json output.

#define W_LOGTEST_TOKEN_LENGH                 8   ///< Lenght of token
#define W_LOGTEST_ERROR_JSON_PARSE_NSTR      20   ///< Number of characters to show in parsing error

/* Return codes for responses */
#define W_LOGTEST_RCODE_ERROR_INPUT          -2   ///< Return code: Input error, malformed json, input field missing.
#define W_LOGTEST_RCODE_ERROR_PROCESS        -1   ///< Return code: Processing with error.
#define W_LOGTEST_RCODE_SUCCESS               0   ///< Return code: Successful request.
#define W_LOGTEST_RCODE_WARNING               1   ///< Return code: Successful request with warning messages.


/**
 * @brief A w_logtest_session_t instance represents a client
 */
typedef struct w_logtest_session_t {

    char *token;                            ///< Client ID
    time_t last_connection;                 ///< Timestamp of the last query

    RuleNode *rule_list;                    ///< Rule list
    OSDecoderNode *decoderlist_forpname;    ///< Decoder list to match logs which have a program name
    OSDecoderNode *decoderlist_nopname;     ///< Decoder list to match logs which haven't a program name
    ListNode *cdblistnode;                  ///< List of CDB lists
    ListRule *cdblistrule;                  ///< List to attach rules and CDB lists
    EventList *eventlist;                   ///< Previous events list
    OSHash *g_rules_hash;                   ///< Hash table of rules
    OSList *fts_list;                       ///< Save FTS previous events
    OSHash *fts_store;                      ///< Save FTS values processed
    OSHash *acm_store;                      ///< Hash to save data which have the same id
    int acm_lookups;                        ///< Counter of the number of times purged. Option accumulate
    time_t acm_purge_ts;                    ///< Counter of the time interval of last purge. Option accumulate

} w_logtest_session_t;

/**
 * @brief List of client actives
 */
OSHash *w_logtest_sessions;

/**
 * @brief An instance of w_logtest_connection allow managing the connections with the logtest socket
 */
typedef struct w_logtest_connection_t {

    pthread_mutex_t mutex;      ///< Mutex to prevent race condition in accept syscall
    int sock;                   ///< The open connection with logtest queue

} w_logtest_connection_t;


/**
 * @brief Initialize Wazuh Logtest. Initialize the listener and create threads
 * Then, call function w_logtest_main
 */
void *w_logtest_init();

/**
 * @brief Initialize logtest configuration. Then, call ReadConfig
 *
 * @return OS_SUCCESS on success, otherwise OS_INVALID
 */
int w_logtest_init_parameters();

/**
 * @brief Main function of Wazuh Logtest module
 *
 * Listen and treat connections with clients
 *
 * @param connection The listener where clients connect
 */
void *w_logtest_main(w_logtest_connection_t * connection);

/**
 * @brief Process client's request
 * @param request client input
 * @param session client session
 * @return NULL on failure, otherwise the alert generated
 */
char *w_logtest_process_log(cJSON *request,  w_logtest_session_t *session);

/**
 * @brief Create resources necessary to service client
 * @param token client identifier
 * @param msg_error contains the message to send to the client in case of invalid rules or decoder otherwise, it's null
 * @return NULL on failure, otherwise a w_logtest_session_t object which represents to the client
 */
w_logtest_session_t *w_logtest_initialize_session(char * token, OSList* log_msg);

/**
 * @brief Free resources after client closes connection
 * @param token client identifier
 */
void w_logtest_remove_session(char * token);

/**
 * @brief Check the inactive logtest sessions
 *
 * Check all the sessions. If a session has been inactive longer than session_timeout,
 * call w_logtest_remove_session to remove it.
 */
void * w_logtest_check_inactive_sessions(__attribute__((unused)) void * arg);

/**
 * @brief Initialize FTS engine for a client session
 * @param fts_list list which save fts previous events
 * @param fts_store hash table which save fts values processed previously
 * @return 1 on success, otherwise return 0
 */
int w_logtest_fts_init(OSList **fts_list, OSHash **fts_store);

#endif
