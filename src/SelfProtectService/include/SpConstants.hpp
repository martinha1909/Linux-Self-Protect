#ifndef SP_CONSTANTS_H
#define SP_CONSTANTS_H

#define SP_MUTEX_LOCK(m)    ({\
                                if (pthread_mutex_lock(m) == -1) {\
                                    sp_error(SP_SERVICE, "Failed to lock SelfProtectService mutex");\
                                }\
                            })

#define SP_MUTEX_UNLOCK(m)  ({\
                                if (pthread_mutex_unlock(m) == -1) {\
                                    sp_error(SP_SERVICE, "Failed to unlock SelfProtectService mutex");\
                                }\
                            })

/* configuration constants */
#define SELF_PROTECT_EXEC_NAME              "self_protect"
#define SELF_PROTECT_SYSD_MONITOR_EXEC_NAME "sysd_service_monitor"
#define SELF_PROTECT_BIN_UPLOAD_EXEC_NAME   "sp_bin_upload"
#define SELF_PROTECT_HISTORY_EXEC_NAME      "attempts_history"
#define SELF_PROTECT_EXEC_DIR               "/usr/bin/"
#define SELF_PROTECT_CONFIG_DIR             "/opt/self_protect/"
#define SELF_PROTECT_CONFIG_BIN_DIR         SELF_PROTECT_CONFIG_DIR "bin/"
#define SELF_PROTECT_QUERY_HISTORY_EXEC     SELF_PROTECT_CONFIG_BIN_DIR SELF_PROTECT_HISTORY_EXEC_NAME
#define SELF_PROTECT_CONFIG_LIST_PATH       SELF_PROTECT_CONFIG_DIR "config_list"
#define SELF_PROTECT_EXEC_PATH              SELF_PROTECT_EXEC_DIR SELF_PROTECT_EXEC_NAME
#define SELF_PROTECT_SYSD_MONITOR_EXEC      SELF_PROTECT_EXEC_DIR SELF_PROTECT_SYSD_MONITOR_EXEC_NAME
#define SELF_PROTECT_BIN_UPLOAD_PATH        SELF_PROTECT_EXEC_DIR SELF_PROTECT_BIN_UPLOAD_EXEC_NAME
#define SELF_PROTECT_SYSD_SERVICE_NAME      "selfprotect.service"

/* json constants */
/* token json constants */
#define SELF_PROTECT_TOKEN_JSON_KEY                         "hashedToken"
#define SELF_PROTECT_TOKEN_JSON_VAL_KEY                     "value"
#define SELF_PROTECT_TOKEN_JSON_CREATED_KEY                 "createdAt"
#define SELF_PROTECT_TOKEN_JSON_TTL_KEY                     "ttl"
/* history json constants */
#define SP_HISTORY_JSON_ATTEMPTS_KEY                        "attempts"
#define SP_HISTORY_JSON_ATTEMPTS_ACTION_TYPE_KEY            "actionType"
#define SP_HISTORY_JSON_ATTEMPTS_ACCESS_GRANTED_KEY         "accessGranted"
#define SP_HISTORY_JSON_ATTEMPTS_SERVICE_RUNNING_KEY        "serviceRunning"
#define SP_HISTORY_JSON_ATTEMPTS_CREATED_AT_KEY             "createdAt"
#define SP_HISTORY_JSON_ATTEMPTS_PPD_KEY                    "protectedParentDirectory"
#define SP_HISTORY_JSON_ATTEMPTS_LOCATIONS_KEY              "paths"

/* sysd service monitor constants */
#define SYSD_CLIENT_BIN_NAME                "sysd_client"
#define SYSD_CLIENT_BIN_PATH                SELF_PROTECT_EXEC_DIR SYSD_CLIENT_BIN_NAME

/* log levels */
#define SP_DEBUG                            "debug"
#define SP_WARN                             "warn"
#define SP_INFO                             "info"
#define SP_ERROR                            "error"

/* log types */
#define SP_FILEOP                            "fileop"
#define SP_FANOTIFY                          "fanotify"
#define SP_SERVICE                           "self_protect"
#define SP_FS_UTIL                           "fsutil"
#define SP_CLIENT                            "client"
#define SP_CALLBACK                          "callback"
#define SP_TOKEN_MANAGER                     "token_manager"
#define SP_TOKEN_CACHE                       "token_cache"
#define SP_SYSD                              "systemd_service"
#define SP_BACKUP                            "backup"
#define SP_TRANSPORT                         "transport"
#define SP_AUDIT                             "audit_watch"
#define SP_HISTORY                           "history"

#endif