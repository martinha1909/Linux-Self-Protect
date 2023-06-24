#include "include/Trust.hpp"
#include <limits.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>


Trust::Trust() : TRUSTED_PROCESSES  {
                                        "allow_process", 
                                        "apt-get", 
                                        "apt"
                                    }
{

}

Trust::~Trust()
{

}

bool Trust::auditctlRuleExist(const char* dir)
{
    bool ret = false;
    char buf[PATH_MAX];
    char dir_cpy[strlen(dir)];
    FILE* fp;

    strcpy(dir_cpy, dir);
    if (dir_cpy[strlen(dir_cpy) - 1] == '/') {
        dir_cpy[strlen(dir_cpy) - 1] = '\0';
    }

    fp = popen(AUDIT_WATCH_LIST_RULES, "r");
    if (fp == NULL) {
        sp_error(SP_AUDIT, "Failed to run popen command, %s", strerror(errno));
        goto done;
    }

    while(fgets(buf, sizeof(buf), fp) != NULL) {
        /* if the string being passed is a substring of a rule, that means auditwatch already has a rule for it */
        if (strstr(buf, dir_cpy) != NULL) {
            ret = true;
            break;
        }
    }

done:
    return ret;
}

void Trust::auditctlWatchDir(const char* dir)
{
    if (!auditctlRuleExist(dir)) {
        if (SYSTEM_CMD(AUTIT_WATCH_DIR_ADD_CMD_FMT, dir) == -1) {
            sp_error(SP_AUDIT, "Failed to add dir %s to audit watch list", dir);
        }
    } else {
        sp_info(SP_AUDIT, "Dir %s is already being watched by auditctl", dir);
    }
}

void Trust::auditctlUnwatchDir(const char* dir)
{
    if (auditctlRuleExist(dir)) {
        if (SYSTEM_CMD(AUDIT_WATCH_DIR_REMOVE_CMD_FMT, dir) == -1) {
            sp_error(SP_AUDIT, "Failed to remove dir %s from audit watch list", dir);
        }
    }
}

char* Trust::getTamperingProcName(const char* file_tampered)
{
    char* ret = NULL;
    char* proc_name = NULL;
    char audit_search_cmd[1024];
    char buf[2048];
    size_t i;
    FILE* fp;

    snprintf(audit_search_cmd, 1024, AUDIT_WATCH_SEARCH_CMD_FMT, file_tampered);

    fp = popen(audit_search_cmd, "r");
    if (fp == NULL) {
        sp_error(SP_AUDIT, "Failed to execute popen command");
        goto done;
    }

    while (fgets(buf, 2048, fp) != NULL) {
        proc_name = strstr(buf, AUDIT_LOG_PROC_TITLE_ENTRY);
        /* if proc_name is non-NULL, we have found the entry */
        if (proc_name != NULL) {
            break;
        }
    }

    if (proc_name == NULL) {
        sp_error(SP_AUDIT, "Unexpected error, auditd log does not contain process title entry");
        goto done;
    }

    proc_name += strlen(AUDIT_LOG_PROC_TITLE_ENTRY);
    proc_name = basename(proc_name);

    /*trim leading white space */
    while (isspace(*proc_name)) {
        proc_name++;
    }

    i = strlen(proc_name) - 1;
    /*trim trailing white space */
    while (isspace(proc_name[i])) {
        proc_name[i] = '\0';
        i--;
    }
    
    ret = strdup(proc_name);
done:
    if (fp != NULL) {
        pclose(fp);
    }
    return ret;
}

bool Trust::procIsTrusted(char *proc_name)
{
    bool ret = false;

    if (proc_name != NULL) {
        size_t i;

        for (i = 0; i < sizeof(TRUSTED_PROCESSES)/sizeof(TRUSTED_PROCESSES[0]); i++) {
            if (strcmp(proc_name, TRUSTED_PROCESSES[i].c_str()) == 0) {
                sp_info(SP_AUDIT, "Process %s is trusted, access granted", proc_name);
                ret = true;
                break;
            }
        }
        free(proc_name);
    }


    return ret;
}