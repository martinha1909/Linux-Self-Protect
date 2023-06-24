#include "../FileSystem/include/FileSystem.hpp"

static void* _spawn_client(void* vargp)
{
    if (SYSTEM_CMD(FILE_ATTR_CMD_FMT, DIR_UNBLOCK_OPT, SYSD_CLIENT_BIN_PATH) == -1) {
        sp_error(SP_SYSD, "Failed to change attribute of client binary file");
    }
    if (SYSTEM_CMD(FILE_CHMOD_CMD_FMT, ROOT_EXEC_PERM_OPT, SYSD_CLIENT_BIN_PATH) == -1) {
        sp_error(SP_SYSD, "Failed to change attribute of client binary file");
    }
    if (SYSTEM_CMD(CLIENT_SPAWN_FMT, SYSD_CLIENT_BIN_PATH) == -1) {
        sp_error(SP_SYSD, "Failed to spawn client");
    }
    /* make client binary file immutable again */
    if (SYSTEM_CMD(FILE_CHMOD_CMD_FMT, READ_ONLY_OPT, SYSD_CLIENT_BIN_PATH) == -1) {
        sp_error(SP_SYSD, "Failed to change attribute of client binary file");
    }   

    return NULL;
}

bool _service_exists(const char* service_name)
{
    bool ret = true;
    FILE* fp;
    char popen_cmd[PATH_MAX];
    char buf[PATH_MAX];

    snprintf(popen_cmd, PATH_MAX, SYSD_SERVICE_EXISTS_CMD_FMT, service_name);

    fp = popen(popen_cmd, "r");
    if (fp == NULL) {
        sp_error(SP_FS_UTIL, "Failed to run popen command");
        goto done;
    }

    if (fgets(buf, sizeof(buf), fp) == NULL) {
        /* if there is nothing to read from popen, that means the service doesn't exist */
        ret = false;
    }

done:
    pclose(fp);
    return ret;
}

sysd_service_status_t _get_sysd_service_active_status(const char* service_name)
{
    sysd_service_status_t ret = SYSD_SERVICE_ERROR;
    FILE* fp = NULL;
    char popen_cmd[PATH_MAX];
    char buf[PATH_MAX];

    if (!_service_exists(service_name)) {
        ret = SYSD_SERVICE_NOT_EXIST;
        goto done;
    }

    snprintf(popen_cmd, PATH_MAX, SYSD_SERVICE_ACTIVE_CMD_FMT, service_name);

    fp = popen(popen_cmd, "r");
    if (fp == NULL) {
        sp_error(SP_FS_UTIL, "Failed to run popen command");
        goto done;
    }

    if (fgets(buf, sizeof(buf), fp) == NULL) {
        sp_error(SP_FS_UTIL, "Failed to read from buffer");
        goto done;
    }

    if (strcmp(buf, "active\n") == 0) {
        ret = SYSD_SERVICE_ACTIVE;
    } else {
        ret = SYSD_SERVICE_INACTIVE;
    }
done:
    if (fp != NULL) {
        pclose(fp);
    }

    return ret;
}

int main(void)
{
    while (1) {
        sysd_service_status_t err = _get_sysd_service_active_status(SELF_PROTECT_SYSD_SERVICE_NAME);
        switch(err) {
            case SYSD_SERVICE_ACTIVE:
            case SYSD_SERVICE_NOT_EXIST:
                break;
            case SYSD_SERVICE_ERROR:
                sp_error(SP_SYSD, "Failed to get status for %s, restarting selfprotect", SELF_PROTECT_SYSD_SERVICE_NAME);
                if (SYSTEM_CMD(SYSD_SERVICE_START_CMD_FMT, SELF_PROTECT_SYSD_SERVICE_NAME) == -1) {
                    sp_error(SP_SYSD, "Failed to start %s", SELF_PROTECT_SYSD_SERVICE_NAME);
                }
                break;
            case SYSD_SERVICE_INACTIVE: {
                pthread_t tid;

                sp_info(SP_SYSD, "Attempt to stop %s detected", SELF_PROTECT_SYSD_SERVICE_NAME);
                if (SYSTEM_CMD(SYSD_SERVICE_START_CMD_FMT, SELF_PROTECT_SYSD_SERVICE_NAME) == -1) {
                    sp_error(SP_SYSD, "Failed to start %s", SELF_PROTECT_SYSD_SERVICE_NAME);
                } else {
                    sp_info(SP_SYSD, "Restarted service, waiting for authorization...");
                }

                pthread_create(&tid, NULL, _spawn_client, NULL);
                pthread_join(tid, NULL);
                /** 
                 * sleep here to prevent make sure that when the start command above issuing self protect service to start again it does not spawn this process again
                 */
                sleep(2);
                goto done;
            }
            default:
                sp_error(SP_SYSD, "Received unexpected code %d", err);
        }
    }

done:
    return 0;
}