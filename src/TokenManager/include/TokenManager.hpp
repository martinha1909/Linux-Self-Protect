#ifndef TOKEN_MANAGER_HPP
#define TOKEN_MANAGER_HPP

#include <string>
#include <cstring>
#include <sstream>
#include <iomanip>
#include <iostream>
#include <openssl/evp.h>
#include "TokenCache.hpp"
#include "../../SelfProtectService/include/SpLogger.hpp"

typedef enum token_attempted_status_e {
    TOKEN_ATTEMPTED_ERROR_OCCURED,
    TOKEN_ATTEMPTED_INCORRECT,
    TOKEN_ATTEMPTED_EXPIRED,
    TOKEN_ATTEMPTED_CORRECT
} token_attempted_status_t;

class TokenManager {
private:
    std::string token_url;
    TokenCache *token_cache;

public:
    TokenManager(const char* url);
    ~TokenManager();
    /**
     * Checks if a token is valid or not by comparing the hash of the expected token and the attempted token
     *
     * @param attempt_token     attempt input token from the user
     * 
     * @return the status for user attempted token
     */
    token_attempted_status_t tokenIsValid(char *attempt_token);
    /**
     * Gets a sha256 hash string of a token
     *
     * @param token     token to be hashed
     * @param token_len length of the token string
     * 
     * @return a string containing sha256 hash of the token
     */
    std::string tokenHashStr(char* token, size_t token_len);
};

#endif