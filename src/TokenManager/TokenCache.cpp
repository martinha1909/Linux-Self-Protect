#include "include/TokenCache.hpp"
#include "../SelfProtectService/include/SpConstants.hpp"
#include "../SelfProtectService/include/SpLogger.hpp"
#include "../FileSystem/include/FileSystem.hpp"
#define JSMN_HEADER
#include "../json/include/jsmn.h"

/**
 * Callback function to be called by libcurl library.
 * Populates the correct token and updates the cache
 * 
 * @param ptr       contains the data responded by HTTP request
 * @param size      not used
 * @param nmemb     not used
 * @param param     contains the cache object to be updated
 */
static void _update_cache(void *ptr, size_t size, size_t nmemb, curl_cb_param_t *param)
{
    (void)size;
    (void)nmemb;
    int r;
    int err = -1;
    jsmn_parser parser;
    jsmntok_t tok[TOKEN_JSON_MAX_NUM];
    size_t tok_len = sizeof(tok)/sizeof(tok[0]);

    jsmn_init(&parser);
    r = jsmn_parse(&parser, (char*)ptr, strlen((char*)ptr), tok, tok_len);
    if (r < 0) {
        sp_error(SP_TOKEN_CACHE, "Failed to parse JSON: %d\n", r);
        goto done;
    }

    /* Assume the top-level element is an object */
    if (r < 1 || tok[0].type != JSMN_OBJECT) {
        sp_error(SP_TOKEN_CACHE, "json object expected");
        goto done;
    }

    for (int i = 1; i < r; i++) {
        if (jsmn_json_eq((char*)ptr, &tok[i], SELF_PROTECT_TOKEN_JSON_KEY) == 0) {
            i++;
        } else if (jsmn_json_eq((char*)ptr, &tok[i], SELF_PROTECT_TOKEN_JSON_VAL_KEY) == 0) {
            param->token_buf = strndup((char*)ptr + tok[i + 1].start, tok[i + 1].end - tok[i + 1].start);
            if (param->token_buf == NULL) {
                sp_error(SP_TOKEN_CACHE, "failed to parse token value to buffer");
            }
            i++;
        } else if (jsmn_json_eq((char*)ptr, &tok[i], SELF_PROTECT_TOKEN_JSON_CREATED_KEY) == 0) {
            char *buf;

            buf = strndup((char*)ptr + tok[i + 1].start, tok[i + 1].end - tok[i + 1].start);
            param->cache->getCache()->created_at = (time_t)strtol(buf, NULL, 10);

            free(buf);
            i++;
        } else if (jsmn_json_eq((char*)ptr, &tok[i], SELF_PROTECT_TOKEN_JSON_TTL_KEY) == 0) {
            char *buf;

            buf = strndup((char*)ptr + tok[i + 1].start, tok[i + 1].end - tok[i + 1].start);
            param->cache->getCache()->ttl = atoi(buf);

            free(buf);
            i++;
        } else {
            sp_error(SP_TOKEN_CACHE, "Unexpected key: %.*s\n", tok[i].end - tok[i].start, (char*)ptr + tok[i].start);
        }
    }

    /** 
     * if the current token is empty, that means this is the first time we request the server, 
     * no need to update the previous cache entry
     */
    if (param->cache->getCache()->cache[TOKEN_CACHE_CURRENT].empty()) {
        if (param->token_buf != NULL) {
            std::string tmp(param->token_buf);
            param->cache->getCache()->cache[TOKEN_CACHE_CURRENT] = tmp;
        }
    } else {
        if (param->token_buf != NULL) {
            /** 
             * If for some reason the token generation server isn't generating properly for an interval, 
             * we don't need to update the previous token cache index
             */
            if (strcmp(param->cache->getCache()->cache[TOKEN_CACHE_CURRENT].c_str(), param->token_buf) != 0) {
                std::string tmp(param->token_buf);

                param->cache->getCache()->cache[TOKEN_CACHE_PREV] = param->cache->getCache()->cache[TOKEN_CACHE_CURRENT];
                param->cache->getCache()->cache[TOKEN_CACHE_CURRENT] = tmp;
            }
        }
    }

    err = 0;
done:
    if (err == -1) {
        if (param->token_buf != NULL) {
            free(param->token_buf);
            param->token_buf = NULL;
        }
    }
}

TokenCache::TokenCache()
{
    free(getCorrectTokenAndUpdateCache());
    sp_debug(SP_TOKEN_CACHE, "cache created, token: %s", memory.cache[TOKEN_CACHE_CURRENT].c_str());
}

token_cache_t* TokenCache::getCache()
{
    return &memory;
}

std::string TokenCache::getPreviousToken()
{
    return memory.cache[TOKEN_CACHE_PREV];
}

token_cache_status_t TokenCache::memoryCacheCheck()
{
    token_cache_status_t ret = TOKEN_CACHE_ERR;
    time_t current_time = time(NULL);
    size_t memory_cache_size = sizeof(memory.cache)/sizeof(memory.cache[0]);

    if (memory_cache_size > TOKEN_CACHE_STORAGE) {
        sp_error(SP_TOKEN_CACHE, "Unexpected token cache storage size of %lu", memory_cache_size);
    }
    /**
     * Case where we found a record in previous cache but the current cache record is empty
     * This is usually not possible since we would only store previous cache the first time a cache expires
     */
    if (!memory.cache[TOKEN_CACHE_PREV].empty() && memory.cache[TOKEN_CACHE_CURRENT].empty()) {
        sp_error(SP_TOKEN_CACHE, "Found a record of previous token in cache but current one is empty");
    }
    /**
     * Cache first initialized, nothing in cache
     */
    if (memory.cache[TOKEN_CACHE_PREV].empty() && memory.cache[TOKEN_CACHE_CURRENT].empty()) {
        ret = TOKEN_CACHE_NOT_FOUND;
    }
    /* If we have something in cache */
    if (!memory.cache[TOKEN_CACHE_CURRENT].empty()) {
        if (memory.created_at != 0 && memory.ttl != 0) {
            if (difftime(current_time, memory.created_at) < memory.ttl) {
                ret = TOKEN_CACHE_FOUND;
            } else {
                ret = TOKEN_CACHE_EXPIRED;
            }
        } else {
            ret = TOKEN_CACHE_NOT_FOUND;
        }
    }

    return ret;
}

CURLcode TokenCache::requestTokenAndUpdateCache(curl_cb_param_t *param)
{
    CURL *curl;
    CURLcode res;
    struct curl_slist *headers = NULL;

    curl = curl_easy_init();
    if(curl) {

        headers = curl_slist_append(headers, "Accept: application/json");
        headers = curl_slist_append(headers, "Content-Type: application/json");
        headers = curl_slist_append(headers, "charset: utf-8");

        curl_easy_setopt(curl, CURLOPT_URL, RESOURCE_URL);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, TOKEN_REQUEST_POST_MSG);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)strlen(TOKEN_REQUEST_POST_MSG));
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, _update_cache);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, param);

        res = curl_easy_perform(curl);

        /* always cleanup */
        curl_easy_cleanup(curl);
    }

    return res;
}

char* TokenCache::getCorrectTokenAndUpdateCache()
{
    curl_cb_param_t param = {};
    token_cache_status_t status = TOKEN_CACHE_NOT_FOUND;

    status = memoryCacheCheck();

    if (status != TOKEN_CACHE_ERR) {
        if (status == TOKEN_CACHE_FOUND) {
            param.token_buf = (char*)malloc(sizeof(char) * memory.cache[TOKEN_CACHE_CURRENT].length());
            if (!param.token_buf) {
                sp_error(SP_TOKEN_CACHE, "Failed to allocate memory");
            } else {
                strcpy(param.token_buf, memory.cache[TOKEN_CACHE_CURRENT].c_str());
                sp_debug(SP_TOKEN_CACHE, "Found token in cache");
            }
        } else if (status == TOKEN_CACHE_NOT_FOUND || status == TOKEN_CACHE_EXPIRED) {
            param.cache = this;
            sp_debug(SP_TOKEN_CACHE, "Token not found in cache, requesting from server...");

            if (requestTokenAndUpdateCache(&param) == CURLE_OK) {
                sp_debug(SP_TOKEN_CACHE, "Request from server succeeded, token cache was updated");
            }
        }
    }
    
    return param.token_buf;
}