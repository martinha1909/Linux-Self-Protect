#include "include/QueryHistory.hpp"
#include "../json/include/jsmn.h"

typedef struct curl_mem {
    char* response;
    size_t size;
} curl_mem_t;

QueryHistory::QueryHistory()
{

}

query_history_record_t* QueryHistory::allocRecord(const bool access_granted, const bool service_active)
{
    query_history_record_t* ret = (query_history_record_t*)calloc(sizeof(query_history_record_t), 1);
    if (ret != NULL) {
        ret->access_granted = access_granted;
        ret->service_active = service_active;
        ret->created_at = time(NULL);
    } else {
        sp_error(SP_HISTORY, "Failed to initalize history record, memory allocation failed");
    }

    return ret;
}

void QueryHistory::jsonPathAppend(char* list, const char* path)
{
    if (list[0] == '\0') {
        strcat(list, "\"");
    } else {
        strcat(list, ", \"");
    }

    strcat(list, path);
    strcat(list, "\"");
}

bool QueryHistory::protectedParentDirAlreadyExists(query_history_record_t* record, const char* protected_dir)
{
    bool ret = false;

    if (record->ppds.size() == 0) {
        goto done;
    }

    for (size_t i = 0; i < record->ppds.size(); i++) {
        if (strcmp(record->ppds[i].c_str(), protected_dir) == 0) {
            ret = true;
            goto done;
        }
    }

done:
    return ret;
}

void QueryHistory::dbrecordAddFinish(void *ptr, size_t size, size_t nmemb, void* data)
{
    (void)size;
    (void)nmemb;
    (void)data;
    sp_info(SP_HISTORY, "Attempt added to history db with message: %s", (char*)ptr);
}

size_t QueryHistory::queryFinish(void *ptr, size_t size, size_t nmemb, void* data)
{
    size_t ret = size * nmemb;
    curl_mem_t *mem = (curl_mem_t*)data;
    char *mem_ptr = (char*)realloc(mem->response, mem->size + ret + 1);

    if (mem_ptr == NULL) {
        sp_error(SP_HISTORY, "Failed to get curl response, memory allocation failed");
        ret = 0;
    } else {
        mem->response = mem_ptr;
        memcpy(&(mem->response[mem->size]), ptr, ret);
        mem->size += ret;
        mem->response[mem->size] = '\0';
    }
    
    return ret;
}

void QueryHistory::recordTamperingLocAdd(query_history_record_t* record, const char* loc)
{
    if (record != NULL && loc != NULL) {
        std::string loc_s(loc);
        record->tampering_locs.push_back(loc);
    }
}

void QueryHistory::recordProtectedParentDirAdd(query_history_record_t* record, const char* dir)
{
    if (record != NULL && dir != NULL) {
        if (!protectedParentDirAlreadyExists(record, dir)) {
            std::string dir_s(dir);
            record->ppds.push_back(dir_s);
        }
    }
}

void QueryHistory::dbRecordAdd(query_history_record_t* record)
{
    CURL *hnd;
    struct curl_slist *slist1;

    if (record != NULL && strcmp(record->action_type, "unknown") != 0) {
        size_t i = 0;
        char query_msg_paths[record->tampering_locs.size() * PATH_MAX];
        char query_protected_dir_paths[record->ppds.size() * PATH_MAX];

        query_msg_paths[0] = '\0';
        query_protected_dir_paths[0] = '\0';

        if (!record->tampering_locs.empty()) {
            jsonPathAppend(query_msg_paths, record->tampering_locs[i].c_str());
            i++;
            for (; i < record->tampering_locs.size(); i++) {
                jsonPathAppend(query_msg_paths, record->tampering_locs[i].c_str());
            }
        }

        i = 0;
        if (!record->ppds.empty()) {
            jsonPathAppend(query_protected_dir_paths, record->ppds[i].c_str());
            i++;
            for (; i < record->ppds.size(); i++) {
                jsonPathAppend(query_protected_dir_paths, record->ppds[i].c_str());
            }
        }

        slist1 = NULL;
        slist1 = curl_slist_append(slist1, "Content-Type: application/json");

        hnd = curl_easy_init();
        curl_easy_setopt(hnd, CURLOPT_URL, HISTORY_DB_INSERT_URL);
        sp_debug(SP_HISTORY, "Inserting %s to history db", HISTORY_DB_POST_MSG_CONSTRUCT(HISTORY_DB_INSERT_POST_DATA_MSG_FMT,
                                                                                         record->action_type,
                                                                                         record->access_granted,
                                                                                         record->service_active,
                                                                                         query_protected_dir_paths,
                                                                                         query_msg_paths,
                                                                                         record->created_at));

        curl_easy_setopt(hnd, CURLOPT_POSTFIELDS, HISTORY_DB_POST_MSG_CONSTRUCT(HISTORY_DB_INSERT_POST_DATA_MSG_FMT,
                                                                                record->action_type,
                                                                                record->access_granted,
                                                                                record->service_active,
                                                                                query_protected_dir_paths,
                                                                                query_msg_paths,
                                                                                record->created_at));
        curl_easy_setopt(hnd, CURLOPT_HTTPHEADER, slist1);
        curl_easy_setopt(hnd, CURLOPT_CUSTOMREQUEST, "POST");
        curl_easy_setopt(hnd, CURLOPT_WRITEFUNCTION, QueryHistory::dbrecordAddFinish);

        curl_easy_perform(hnd);

        curl_easy_cleanup(hnd);
        hnd = NULL;
        curl_slist_free_all(slist1);
        slist1 = NULL;

        free(record);
    }
}

void QueryHistory::deallocRecordList(std::vector<query_history_record_t*> records)
{
    for (size_t i = 0; i < records.size(); i++) {
        free(records[i]);
    }
}

std::vector<query_history_record_t*> QueryHistory::getEventsFromDb(time_t start_interval, time_t end_interval)
{
    int i;
    int r = -1;
    char* event_json = NULL;
    CURL *hnd;
    struct curl_slist *slist1;
    curl_mem_t chunk = {};
    std::vector<query_history_record_t*> ret;
    query_history_record_t* event = NULL;
    jsmntok_t json_tok[HISTORY_JSON_DATA_MAX_NUM_TOK];
    jsmn_parser p;

    slist1 = NULL;
    slist1 = curl_slist_append(slist1, "Content-Type: application/json");

    hnd = curl_easy_init();
    curl_easy_setopt(hnd, CURLOPT_URL, HISTORY_DB_QUERY_URL);
    curl_easy_setopt(hnd, CURLOPT_POSTFIELDS, HISTORY_DB_POST_MSG_CONSTRUCT(HISTORY_DB_QUERY_POST_DATA_MSG_FMT,
                                                                            start_interval,
                                                                            end_interval));
    curl_easy_setopt(hnd, CURLOPT_HTTPHEADER, slist1);
    curl_easy_setopt(hnd, CURLOPT_CUSTOMREQUEST, "POST");
    curl_easy_setopt(hnd, CURLOPT_WRITEFUNCTION, QueryHistory::queryFinish);
    curl_easy_setopt(hnd, CURLOPT_WRITEDATA, &chunk);

    curl_easy_perform(hnd);

    if (chunk.response == NULL) {
        printf("Unexpected error: failed to get json response\n");
        goto done;
    }
    event_json = chunk.response;

    event = (query_history_record_t*)calloc(sizeof(query_history_record_t), 1);
    if (event == NULL) {
        printf("Unexpected error: memory allocation failed\n");
        goto done;
    }

    jsmn_init(&p);

    r = jsmn_parse(&p, event_json, strlen(event_json), json_tok, HISTORY_JSON_DATA_MAX_NUM_TOK);
    if (r < 0) {
        printf("Failed to parse json\n");
        goto done;
    }

    if (r < 1 || json_tok[0].type != JSMN_OBJECT) {
        printf("Unexpected error. Json object not found\n");
        goto done;
    }

    for (i = 1; i < r; i++) {
        /* when we encounter an id node, we know it's a new attempt */
        if (jsmn_json_eq(event_json, &json_tok[i], SP_HISTORY_JSON_ATTEMPTS_ACTION_TYPE_KEY) == 0) {
            if (event != NULL) {
                strncpy(event->action_type, event_json + json_tok[i + 1].start, json_tok[i + 1].end - json_tok[i + 1].start);
            }
            i++;
        } else if (jsmn_json_eq(event_json, &json_tok[i], SP_HISTORY_JSON_ATTEMPTS_ACCESS_GRANTED_KEY) == 0) {
            char access_granted[10];
            
            strncpy(access_granted, event_json + json_tok[i + 1].start, json_tok[i + 1].end - json_tok[i + 1].start);
            /* strncpy does not null terminate string like strcpy does */
            access_granted[json_tok[i + 1].end - json_tok[i + 1].start] = '\0';

            if (event != NULL) {
                event->access_granted = (strcmp(access_granted, "true") == 0 ? true : false);
            }

            i++;
        } else if (jsmn_json_eq(event_json, &json_tok[i], SP_HISTORY_JSON_ATTEMPTS_SERVICE_RUNNING_KEY) == 0) {
            char service_running[10];
            
            strncpy(service_running, event_json + json_tok[i + 1].start, json_tok[i + 1].end - json_tok[i + 1].start);
            /* strncpy does not null terminate string like strcpy does */
            service_running[json_tok[i + 1].end - json_tok[i + 1].start] = '\0';

            if (event != NULL) {
                event->service_active = (strcmp(service_running, "true") == 0 ? true : false);
            }

            i++;
        } else if (jsmn_json_eq(event_json, &json_tok[i], SP_HISTORY_JSON_ATTEMPTS_CREATED_AT_KEY) == 0) {
            char created_at[20];
            
            strncpy(created_at, event_json + json_tok[i + 1].start, json_tok[i + 1].end - json_tok[i + 1].start);

            if (event != NULL) {
                event->created_at = strtol(created_at, NULL, 10);
                /* created_at is the last json key for an attempt, so we add to the list here and create a new one */
                ret.push_back(event);
            }

            event = (query_history_record_t*)calloc(sizeof(query_history_record_t), 1);
            i++;
        } else if (jsmn_json_eq(event_json, &json_tok[i], SP_HISTORY_JSON_ATTEMPTS_PPD_KEY) == 0) {
            int j;

            if (json_tok[i + 1].type != JSMN_ARRAY) {
                /* We expect "protectedParentDirectory" to be an array of strings */
                continue; 
            }

            for (j = 0; j < json_tok[i + 1].size; j++) {
                jsmntok_t *arr_tok = &json_tok[i + j + 2];
                char ppd[PATH_MAX];

                strncpy(ppd, event_json + arr_tok->start, arr_tok->end - arr_tok->start);
                /* strncpy does not null terminate string like strcpy does */
                ppd[arr_tok->end - arr_tok->start] = '\0';

                if (event != NULL) {
                    recordProtectedParentDirAdd(event, ppd);
                }
            }
            i += json_tok[i + 1].size + 1;
        } else if (jsmn_json_eq(event_json, &json_tok[i], SP_HISTORY_JSON_ATTEMPTS_LOCATIONS_KEY) == 0) {
            int j;

            if (json_tok[i + 1].type != JSMN_ARRAY) {
                /* We expect "paths" to be an array of strings */
                continue;
            }

            for (j = 0; j < json_tok[i + 1].size; j++) {
                jsmntok_t *arr_tok = &json_tok[i + j + 2];
                char loc[PATH_MAX];

                strncpy(loc, event_json + arr_tok->start, arr_tok->end - arr_tok->start);
                /* strncpy does not null terminate string like strcpy does */
                loc[arr_tok->end - arr_tok->start] = '\0';

                if (event != NULL) {
                    recordTamperingLocAdd(event, loc);
                }
            }
            i += json_tok[i + 1].size + 1;
        } else if (jsmn_json_eq(event_json, &json_tok[i], SP_HISTORY_JSON_ATTEMPTS_KEY) == 0) {
            if (json_tok[i + 1].type != JSMN_ARRAY) {
                /* We expect "attempts" to be an array of json objects */
                continue;
            }
            i += json_tok[i + 1].size + 1;
        }
    }

done:
    curl_easy_cleanup(hnd);
    hnd = NULL;
    curl_slist_free_all(slist1);
    slist1 = NULL;

    if (event != NULL) {
        free(event);
    }
    if (event_json != NULL) {
        free(event_json);
    }
    
    return ret;
}

void QueryHistory::printRecords(std::vector<query_history_record_t*> record_list)
{
    for (size_t i = 0; i < record_list.size(); i++) {
        printRecord(record_list[i]);
        printf("-------------------------------------------\n");
    }
}

void QueryHistory::printRecord(query_history_record_t* record)
{
    if (record != NULL) {
        struct tm epoch_time = {};
        char date_str[64];

        memcpy(&epoch_time, localtime(&record->created_at), sizeof(struct tm));
        strftime(date_str, sizeof(date_str), "%B %d, %Y %H:%M:%S", &epoch_time);
        printf("Date: %s (epoch: %ld)\n", date_str, record->created_at);

        if (record->action_type != NULL) {
            printf("Action: %s\n", record->action_type);
        }
        printf("Access status: %s\x1b[37m\n", record->access_granted == true ? "\x1b[32mGranted" : "\x1b[31mBlocked");
        printf("Grace period: %s\x1b[37m\n", record->service_active ==  true ? "\x1b[31mNo" : "\x1b[32mYes");
        printf("Protected directories:\n");
        for (size_t i = 0; i < record->ppds.size(); i++) {
            printf("-\t%s\n", record->ppds[i].c_str());
        }
        printf("Tampering locations:\n");
        for (size_t i = 0; i < record->tampering_locs.size(); i++) {
            printf("-\t%s\n", record->tampering_locs[i].c_str());
        }
    }
}