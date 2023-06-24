#pragma once

#include <curl/curl.h>
#include <pthread.h>
#include <cstdlib>
#include <string>
#include "../../SelfProtectService/include/SpLogger.hpp"

#define DROPBOX_API_AUTH_TOKEN                  "sl.Bf8wDyEgsw60lUX5w5qYVq5bYjCHquvhZsC_pSWEe1eutCS5mbS3Jy5DmEwF14V15NbaQN0DJ-ykim0V95CNgglCHjMHz04PmHKB34cgSeGoX_aDLfJCrAu37vaQgR2kvDzAKPPC"
#define DROPBOX_FILE_ATTRIB_TEMPLATE_ID         "gn_7UQCpai0AAAAAAAAAJQ"

#define FT_CU_OPT_BUF_SIZE                      102400L
#define FT_CU_OPT_MAX_DIRS                      50L
#define FT_CU_AGENT_VERSION                     "curl/7.81.0"
#define FT_CU_REQUEST_POST                      "POST"
#define FT_CU_HEADER_AUTH                       "Authorization: Bearer " DROPBOX_API_AUTH_TOKEN
#define FT_CU_HEADER_JSON                       "Content-Type: application/json"
#define FT_CU_HEADER_OCTET_STREAM               "Content-Type: application/octet-stream"
#define FT_CU_POST_FIELD_CONSTRUCT(fmt, ...)    ({\
                                                    char post_data[1024];\
                                                    snprintf(post_data, 1024, fmt, ##__VA_ARGS__);\
                                                    post_data;\
                                                })

/* remote API URLs*/
#define FT_CU_REMOTE_API_URL                    "https://api.dropboxapi.com/2/files/"
#define FT_CU_REMOTE_CONTENT_API_URL            "https://content.dropboxapi.com/2/files/"
#define FT_CU_REMOTE_API_DIR_CREATE             "create_folder_v2"
#define FT_CU_REMOTE_API_DIR_DELETE             "delete_v2"
#define FT_CU_REMOTE_API_FILE_CREATE            "upload"

/* remote directory create macros */
#define FT_CU_REMOTE_API_DIR_CREATE_DATA_FMT    "{\"autorename\":false,\"path\":\"%s\"}"
#define FT_CU_REMOTE_API_DIR_CREATE_URL         FT_CU_REMOTE_API_URL FT_CU_REMOTE_API_DIR_CREATE
#define FT_CU_REMOTE_DIR_CREATE(d)              FT_CU_POST_FIELD_CONSTRUCT(FT_CU_REMOTE_API_DIR_CREATE_DATA_FMT, d)

/* remote directory delete macros */
#define FT_CU_REMOTE_API_DIR_DELETE_DATA_FMT    "{\"path\":\"%s\"}"
#define FT_CU_REMOTE_API_DIR_DELETE_URL         FT_CU_REMOTE_API_URL FT_CU_REMOTE_API_DIR_DELETE
#define FT_CU_REMOTE_DELETE(d)                  FT_CU_POST_FIELD_CONSTRUCT(FT_CU_REMOTE_API_DIR_DELETE_DATA_FMT, d)

/* remote file create macros */
#define FT_CU_REMOTE_API_FILE_CREATE_DATA_FMT   "Dropbox-API-Arg: {\"autorename\":false,\"mode\":\"add\",\"mute\":false,\"path\":\"%s\",\"property_groups\":[{\"fields\":[{\"name\":\"Security Policy\",\"value\":\"%d\"}],\"template_id\":\"ptid:%s\"}],\"strict_conflict\":false}"
#define FT_CU_REMOTE_API_FILE_CREATE_URL        FT_CU_REMOTE_CONTENT_API_URL FT_CU_REMOTE_API_FILE_CREATE
#define FT_CU_REMOTE_FILE_CREATE(f, a)          FT_CU_POST_FIELD_CONSTRUCT(FT_CU_REMOTE_API_FILE_CREATE_DATA_FMT, f, a, DROPBOX_FILE_ATTRIB_TEMPLATE_ID)

class FileTransport;

typedef enum ft_type_e {
    FT_TYPE_REMOTE_UNKNOWN,
    FT_TYPE_REMOTE_DIR_CREATE,
    FT_TYPE_REMOTE_DIR_DELETE,
    FT_TYPE_REMOTE_FILE_CREATE,
    FT_TYPE_REMOTE_FILE_DELETE
} ft_type_t;

typedef struct ft_cu_cb_param {
    ft_type_t transport_type;
    std::string transport_data;
    FileTransport* ft;
} ft_cu_cb_param_t;

class FileTransport {
private:
    pthread_mutex_t* mutex;
    bool is_uploading;
    CURL* hnd;
    struct curl_slist* slist;

    /**
     * Sets the upload state during file/dir transportation
     *
     * @param state       whether an upload/download session is in progress
     */
    void setUploadState(bool state);
    /**
     * Write callback function to be called by CURL API, when the program hits this function, it indicates that the CURL transport
     * has finished
     *
     * @param ptr       JSON response from HTTPS when CURL makes a request
     * @param size      not used
     * @param nmemb     not used
     * @param param     contains the information done to the remote server
     */
    static void transportFinish(void *ptr, size_t size, size_t nmemb, ft_cu_cb_param_t *param);
    /**
     * Cleans up CURL library resources
     */
    void transportCleanUp();
    /**
     * Construct general options for CURL library
     *
     * @param write_func       write callback function for CURL to write back JSON data, has to match the function prototype specified by CURL API
     * @param param            parameter to be maniluated/used in curl write callback function
     */
    void transportStart(void (*write_func)(void*, size_t, size_t, ft_cu_cb_param_t*),
                        ft_cu_cb_param_t *param);
    /**
     * Adds header type to CURL header
     *
     * @param content_type     HTML content-type
     */
    void transportHeader(const char* content_type);
public:
    FileTransport();
    ~FileTransport();
    /**
     * Checks if there is a file/dir transport in progress
     *
     * @return true if a transport session is in progress, false otherwise
     */
    bool transportInProgress();
    /**
     * Creates a remote directory in the file sharing server
     *
     * @param dir        directory to be created
     */
    void createRemoteDir(std::string dir);
    /**
     * Deletes a remote directory or file in the file sharing server
     *
     * @param path       path to either file or directory to be deleted
     * @param is_file    whether the deleting action is on a directory or a file
     */
    void deleteRemoteDirOrFile(std::string path, bool is_file);
    /**
     * Creates a remote file in the file sharing server
     *
     * @param filepath       file to be created
     * @param content        file content
     * @param attrib         file attribute
     */
    void createRemoteFile(std::string filepath, 
                          const unsigned char* content, 
                          const mode_t attrib);
    /**
     * Populates a string representation of a transport action
     *
     * @param type       transport action
     * 
     * @return           a pointer to a string representation of the transport action. DO NOT pass this to free()
     */
    const char* transportTypeStr(ft_type_t type);
    /**
     * Updates a mutex
     *
     * @param mutex      mutex to be updated
     */
    void setMutex(pthread_mutex_t* mutex);
};