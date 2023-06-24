#ifndef TOKEN_CACHE_HPP
#define TOKEN_CACHE_HPP

#include <vector>
#include <string>
#include <cstring>
#include <time.h>
#include <curl/curl.h>
#include <iostream>

#define TOKEN_CACHE_STORAGE     2
#define TOKEN_JSON_MAX_NUM      128  /* jsmn.h header should expect no more than 128 tokens */

#define RESOURCE_URL            "https://self-protect-token-generator.onrender.com/get-hashed-token"
#define TOKEN_REQUEST_POST_MSG  "{\"username\":\"self_protect_service\",\"password\":\"32b03588ddc264d8e5afaf0d5f10e30ced33701bf304605cdcf5b60dfb477e94\"}"

class TokenCache;

typedef enum token_cache_index_e {
    TOKEN_CACHE_PREV = 0,
    TOKEN_CACHE_CURRENT,
    TOKEN_CACHE_SIZE
} token_cache_index_t;

typedef enum token_cache_status_e {
    TOKEN_CACHE_ERR = 0,
    TOKEN_CACHE_NOT_FOUND,
    TOKEN_CACHE_FOUND,
    TOKEN_CACHE_EXPIRED
} token_cache_status_t;

typedef struct token_cache {
    std::string cache[TOKEN_CACHE_STORAGE];
    int ttl;
    time_t created_at;
} token_cache_t;

typedef struct curl_cb_param {
    TokenCache *cache;
    char *token_buf;
} curl_cb_param_t;

class TokenCache {
private:
    token_cache_t memory;

    /**
     * Checks if token exists in cache and gives error if any
     * 
     * @return status of checking cache
     */
    token_cache_status_t memoryCacheCheck();
public:
    TokenCache();
    /**
     * Gets the current cache
     * 
     * @return current cache in memory
     */
    token_cache_t* getCache();
    /**
     * Gets the previous correct token, which has now expired
     * 
     * @return previous correct token
     */
    std::string getPreviousToken();
    /**
     * Gets the correct token by first checking if the cache has expired or not.
     * If the cache has expired, send a request to the server to get the new correct token, then update the cache
     * 
     * @return dynamically allocated c-string contains the hashed of the correct token
     */
    char* getCorrectTokenAndUpdateCache();
    /**
     * Sends a request to the web server by utilizing libcurl library
     * 
     * @param param a callback param to be filled in by curl library, which contains a buffer for the correct token
     * 
     * @return status code of the libcurl library
     */
    CURLcode requestTokenAndUpdateCache(curl_cb_param_t* param);
};

#endif