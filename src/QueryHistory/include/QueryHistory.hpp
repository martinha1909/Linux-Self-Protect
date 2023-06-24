#pragma once

#include <curl/curl.h>
#include <time.h>
#include <limits.h>
#include <vector>
#include <string>
#include "../../FanotifyEvents/include/FanotifyEvents.hpp"

#define HISTORY_JSON_DATA_MAX_LEN                   PATH_MAX * 5 /* shouldn't expect more than 20KB of data */
#define HISTORY_JSON_DATA_MAX_NUM_TOK               1024 /* shouldn't expect more than 1024 token */

#define HISTORY_DB_AUTH_POST_DATA                   "\"username\":\"self_protect_service\",\"password\":\"32b03588ddc264d8e5afaf0d5f10e30ced33701bf304605cdcf5b60dfb477e94\""
#define HISTORY_DB_INSERT_URL                       "https://self-protect-token-generator.onrender.com/create-attempt"
#define HISTORY_DB_QUERY_URL                        "https://self-protect-token-generator.onrender.com/get-attempts"
#define HISTORY_DB_DELETE_RECORDS_URL               "https://self-protect-token-generator.onrender.com/delete-attempts"
#define HISTORY_DB_POST_MSG_CONSTRUCT(fmt, ...)     ({\
                                                        char post_data[HISTORY_JSON_DATA_MAX_LEN];\
                                                        snprintf(post_data, HISTORY_JSON_DATA_MAX_LEN, fmt, ##__VA_ARGS__);\
                                                        post_data;\
                                                    })
#define HISTORY_DB_INSERT_POST_DATA_MSG_FMT         "{" HISTORY_DB_AUTH_POST_DATA ",\
                                                        \"actionType\":\"%s\",\
                                                        \"accessGranted\":%d,\
                                                        \"serviceRunning\":%d,\
                                                        \"protectedParentDirectory\":[%s],\
                                                        \"paths\":[%s],\
                                                        \"createdAt\":%ld\
                                                    }"
#define HISTORY_DB_QUERY_POST_DATA_MSG_FMT          "{" HISTORY_DB_AUTH_POST_DATA ", \
                                                        \"starting\":%ld,\
                                                        \"ending\":%ld\
                                                    }"

typedef struct query_history_record {
    char action_type[64];
    bool access_granted;
    bool service_active;
    std::vector<std::string> ppds;
    std::vector<std::string> tampering_locs;
    time_t created_at;
} query_history_record_t;

class QueryHistory {
private:
    /**
     * Prints history record to stdout. 
     * 
     * @note this function is intended to be used for attempts_history binary, so logging will not be supported. 
     *       Instead, all logging will be done via stdout
     *
     * @param record       history record to be printed
     */
    void printRecord(query_history_record_t* record);
    /**
     * Appends a path to JSON array to send via CURL
     *
     * @param list[out]          json array list to be appeneded
     * @param path[in]           path to append to json array
     */
    void jsonPathAppend(char* list, const char* path);
    /**
     * Write callback function to be called by CURL API, when the program hits this function, it indicates that the CURL transport
     * has finished
     * @note    this function will parse JSON contents receving from curl to a history record list
     *
     * @param ptr       JSON response from HTTPS when CURL makes a request
     * @param size      how many characters is presented in the response
     * @param nmemb     memory size of each character
     * @param data      json out param to be populated, must be of type query_history_record_list_t
     * 
     * @return          number of bytes processed
     */
    static size_t queryFinish(void* ptr, size_t size, size_t nmemb, void* data);
    /**
     * Write callback function to be called by CURL API, when the program hits this function, it indicates that the CURL transport
     * has finished
     *
     * @param ptr       JSON response from HTTPS when CURL makes a request
     * @param size      not used
     * @param nmemb     not used
     * @param data      not used
     */
    static void dbrecordAddFinish(void *ptr, size_t size, size_t nmemb, void* data);
    /**
     * Checks if a protected directory has already existed in a history record
     *
     * @param record             history record
     * @param protected_dir      protected dir to be checked
     * 
     * @return true if protected directory has already existed in history record, false otherwise
     */
    bool protectedParentDirAlreadyExists(query_history_record_t* record, const char* protected_dir);
public:
    QueryHistory();
    /**
     * Dynamically allocates a history record, the caller of this function must pass the returned value to free() after use
     *
     * @param access_granted    whether or not access was granted
     * @param service_active    whether service is in grace period or not
     * 
     * @return a dynamically allocated history record
     */
    query_history_record_t* allocRecord(const bool access_granted, const bool service_active);
    /**
     * Appends a protected directory to a history record
     *
     * @param record       history record to add protected dir to
     * @param dir          protected directory specified in config list
     */
    void recordProtectedParentDirAdd(query_history_record_t* record, const char* dir);
    /**
     * Appends a location of a tampering action to a history record
     *
     * @param record       history record to add protected dir to
     * @param loc          tampering action location
     */
    void recordTamperingLocAdd(query_history_record_t* record, const char* loc);
    /**
     * Gets all history events from history db based on a given interval
     * 
     * @note this function is intended to be used for attempts_history binary, so logging will not be supported. 
     *       Instead, all logging will be done via stdout
     *
     * @param start_interval       start interval to query history records from db.
     * @param end_interval         end interval to query history records from db
     * 
     * @return a list of history records ranging between the interval
     */
    std::vector<query_history_record_t*> getEventsFromDb(time_t start_interval, time_t end_interval);
    /**
     * Adds a history record to history db
     *
     * @param record            history record to add to db
     */
    void dbRecordAdd(query_history_record_t* record);
    /**
     * Deallocates a list of history records.
     * 
     * @note list of records as well as its contents must be dynamically allocated, otherwise unexpected behaviour could occur
     *
     * @param record_list       history record list to be deallocated
     */
    void deallocRecordList(std::vector<query_history_record_t*> record_list);
    /**
     * Prints a list of history records to stdout. 
     * 
     * @note this function is intended to be used for attempts_history binary, so logging will not be supported. 
     *       Instead, all logging will be done via stdout
     *
     * @param record_list       history record list to be printed
     */
    void printRecords(std::vector<query_history_record_t*> record_list);
};