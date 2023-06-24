#pragma once

#include "../../FileSystem/include/FileSystem.hpp"

#define AUDIT_WATCH_PERMISSIONS             "rwxa"
#define AUTIT_WATCH_DIR_ADD_CMD_FMT         "sudo auditctl -w %s -p " AUDIT_WATCH_PERMISSIONS
#define AUDIT_WATCH_DIR_REMOVE_CMD_FMT      "sudo auditctl -W %s -p " AUDIT_WATCH_PERMISSIONS
#define AUDIT_WATCH_LIST_RULES              "sudo auditctl -l"
/* an audit log entry is 5 lines long */
#define AUDIT_WATCH_SEARCH_CMD_FMT          "sudo ausearch -f %s -i | tail -n 5"
#define AUDIT_LOG_PROC_TITLE_ENTRY          "proctitle="

class Trust {
private:
    const std::vector<std::string> TRUSTED_PROCESSES;
    /**
     * Checks if a directory is already existed in auditd watch list
     *
     * @param dir  directory to check in auditd rules list
     * 
     * @return true if the directory passed is already being watched, false otherwise
     */
    bool auditctlRuleExist(const char* dir);
public:
    Trust();
    ~Trust();
    /**
     * Adds a directory to auditd watch list
     *
     * @param dir  directory to be added
     */
    void auditctlWatchDir(const char* dir);
    /**
     * Removes a directory from auditd watch list
     *
     * @param dir  directory to be removed
     */
    void auditctlUnwatchDir(const char* dir);
    /**
     * Gets the process name that is tampering a protected file or directory by searching in auditd log
     * @note a caller of this function must free the return value after use
     *
     * @param file_tampered  location of a file or directory being tampered
     * 
     * @return a dynamically allocated string containing the process name, NULL upon failure
     */
    char* getTamperingProcName(const char* file_tampered);
    /**
     * Checks if a process is trusted
     * @note proc_name must be dynamically allocated
     *
     * @param proc_name  process name to be checked
     */
    bool procIsTrusted(char* proc_name);  
};