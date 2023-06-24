#include "include/TokenManager.hpp"

TokenManager::TokenManager(const char *resource_url)
{
    TokenCache *token_cache = new TokenCache();

    token_url = resource_url;
    this->token_cache = token_cache;
}

TokenManager::~TokenManager()
{
    delete token_cache;
}

std::string TokenManager::tokenHashStr(char* token, size_t token_len)
{
    std::stringstream ss;
    unsigned int diglen = EVP_MD_size(EVP_sha256());
    unsigned char hash[diglen];
    EVP_MD_CTX* ctx = EVP_MD_CTX_create();

    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, token, token_len);
    EVP_DigestFinal(ctx, hash, &diglen);
    EVP_MD_CTX_destroy(ctx);

    ss << std::hex << std::setfill('0');
    for (unsigned byte: hash) {
        ss << std::setw(2) << byte;
    }

    return ss.str();
}

token_attempted_status_t TokenManager::tokenIsValid(char *attempt_token)
{
    token_attempted_status_t ret = TOKEN_ATTEMPTED_ERROR_OCCURED;

    char *correct_token = token_cache->getCorrectTokenAndUpdateCache();

    if (correct_token != NULL) {
        sp_debug(SP_TOKEN_CACHE, "cache updated, cache current token: %s\n", token_cache->getCache()->cache[TOKEN_CACHE_CURRENT].c_str());
        sp_debug(SP_TOKEN_CACHE, "cache updated, cache prev token: %s\n", token_cache->getCache()->cache[TOKEN_CACHE_PREV].c_str());
        std::string attempt_token_hash = tokenHashStr(attempt_token, strlen(attempt_token));

        if (strcmp(attempt_token_hash.c_str(), correct_token) == 0) {
            ret = TOKEN_ATTEMPTED_CORRECT;
        } else {
            if (strcmp(attempt_token_hash.c_str(), token_cache->getPreviousToken().c_str()) == 0) {
                ret = TOKEN_ATTEMPTED_EXPIRED;
            } else {
                ret = TOKEN_ATTEMPTED_INCORRECT;
            }
        }
        free(correct_token);
    } else {
        sp_error(SP_TOKEN_MANAGER, "Error occured in verifying token");
    }

    return ret;
}