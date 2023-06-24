#include <sys/select.h>
#include <wait.h>
#include "include/SelfProtectService.hpp"
#include "../CLI_Interface/include/cli_helper.h"
#include "../Trust/include/Trust.hpp"
#include "../QueryHistory/include/QueryHistory.hpp"

/**
 * glibc will automatically populate this variable with the parent's environment variables
 * These environment variables will then be inherited to the child process in posix_spawn
 * We need this to launch gnome-terminal with the child process
*/
extern char **environ;

SelfProtectService::SelfProtectService(FileManager *fileManager, 
                                       TokenManager *tokenManager,
                                       FanotifyEvents* fanotifyEvents,
                                       QueryHistory* queryHistory,
                                       Trust* trust)
{
    fm = fileManager;
    tm = tokenManager;
    fan = fanotifyEvents;
    hist = queryHistory;
    this->trust = trust;
    daemon = NULL;
    socket_fd = -1;
    client_fd = -1;
    is_monitoring = true;
    do_spawn_client = true;
    auth_in_prog = false;
    is_notif_event = false;
    is_malicious = false;
    event_in_auth = NULL;

    for (auto protected_dir : *(fm->getProtectedDirs())) {
        if (SYSTEM_CMD(DIR_ATTR_CMD_FMT, DIR_UNBLOCK_OPT, protected_dir.first.path.c_str()) == -1) {
            sp_error(SP_SERVICE, "Failed to unblock dir %s after initialization is done, events will not be reported for this dir", protected_dir.first.path.c_str());
        }
        fm->markProtectedDirAndSubDirs(protected_dir.first.path);
    }

    pthread_mutex_init(&mutex, NULL);
}

SelfProtectService::~SelfProtectService()
{
    pthread_mutex_destroy(&mutex);
    close(fan->getNotifFd());
    close(fan->getPermFd());
}

void SelfProtectService::setDaemon(struct sockaddr_un *daemon)
{
    this->daemon = daemon;
}

void SelfProtectService::setSocketFd(int socket_fd)
{
    this->socket_fd = socket_fd;
}

void SelfProtectService::setClientFd(int client_fd)
{
    this->client_fd = client_fd;
}

void SelfProtectService::monitorStateSet(bool state)
{
    SP_MUTEX_LOCK(getMutex());
    is_monitoring = state;
    SP_MUTEX_UNLOCK(getMutex());
}

void SelfProtectService::spawnClientStateSet(bool state)
{
    SP_MUTEX_LOCK(getMutex());
    do_spawn_client = state;
    SP_MUTEX_UNLOCK(getMutex());
}

void SelfProtectService::authStateSet(bool state)
{
    SP_MUTEX_LOCK(getMutex());
    auth_in_prog = state;
    SP_MUTEX_UNLOCK(getMutex());
}

void SelfProtectService::notifEventStateSet(bool state)
{
    SP_MUTEX_LOCK(getMutex());
    is_notif_event = state;
    SP_MUTEX_UNLOCK(getMutex());
}

void SelfProtectService::maliciousStateSet(bool state)
{
    SP_MUTEX_LOCK(getMutex());
    is_malicious = state;
    SP_MUTEX_UNLOCK(getMutex());
}

void SelfProtectService::eventInAuthSet(fanotify_event_response_t* event)
{
    SP_MUTEX_LOCK(getMutex());
    if (event != NULL) {
        event_in_auth = fan->eventDup(event);
    } else {
        event_in_auth = NULL;
    }
    SP_MUTEX_UNLOCK(getMutex());
}

bool SelfProtectService::isMonitoring()
{
    bool ret;

    SP_MUTEX_LOCK(getMutex());
    ret = is_monitoring;
    SP_MUTEX_UNLOCK(getMutex());

    return ret;
}

QueryHistory* SelfProtectService::getHistory()
{
    return hist;
}

FileManager* SelfProtectService::getFileManager()
{
    return fm;
}

TokenManager* SelfProtectService::getTokenManager()
{
    return tm;
}

Trust* SelfProtectService::getTrust()
{
    return trust;
}

bool SelfProtectService::isMalicious()
{
    bool ret;

    SP_MUTEX_LOCK(getMutex());
    ret = is_malicious;
    SP_MUTEX_UNLOCK(getMutex());

    return ret;
}

bool SelfProtectService::isNotifEvent()
{
    bool ret;

    SP_MUTEX_LOCK(getMutex());
    ret = is_notif_event;
    SP_MUTEX_UNLOCK(getMutex());

    return ret;
}

bool SelfProtectService::isAuthenticating()
{
    bool ret;

    SP_MUTEX_LOCK(getMutex());
    ret = auth_in_prog;
    SP_MUTEX_UNLOCK(getMutex());

    return ret;
}

bool SelfProtectService::dospawnClient()
{
    bool ret;

    SP_MUTEX_LOCK(getMutex());
    ret = do_spawn_client;
    SP_MUTEX_UNLOCK(getMutex());

    return ret;
}

int SelfProtectService::getClientFd()
{
    return client_fd;
}

FanotifyEvents* SelfProtectService::getFan()
{
    return fan;
}

pthread_mutex_t* SelfProtectService::getMutex()
{
    return &mutex;
}

fanotify_event_response_t* SelfProtectService::getEventInAuth()
{
    fanotify_event_response_t* ret = NULL;

    SP_MUTEX_LOCK(getMutex());
    ret = event_in_auth;
    SP_MUTEX_UNLOCK(getMutex());

    return ret;
}

int SelfProtectService::daemonWrite(char* buf, size_t len)
{
    return socket_write(client_fd, buf, len);
}

int SelfProtectService::daemonRead(char* buf, size_t len)
{
    return socket_read(client_fd, buf, len);
}

void SelfProtectService::spawnClient()
{
    /* needs to make it temporarily immutable first */
    if (SYSTEM_CMD(FILE_CHMOD_CMD_FMT, ROOT_EXEC_PERM_OPT, CLIENT_BIN_PATH) == -1) {
        sp_error(SP_SERVICE, "Failed to change attribute of client binary file");
    }

    /* fail safe */
    if (!fm->getFileSystem()->fileExist(CLIENT_BIN_PATH)) {
        protected_file_t client_bin = {};
        
        strcpy(client_bin.file_path, CLIENT_BIN_PATH);
        /* set attribute for root exec only */
        client_bin.attrib = S_IRUSR | S_IWUSR | S_IXUSR;
        
        fm->getBackup()->downloadRemoteELF(client_bin);
    }

    if (SYSTEM_CMD(CLIENT_SPAWN_FMT, CLIENT_BIN_PATH) == -1) {
        sp_error(SP_SERVICE, "Failed to spawn client");
    }

    /* make client binary file immutable again */
    if (SYSTEM_CMD(FILE_CHMOD_CMD_FMT, IMMUTABLE_OPT, CLIENT_BIN_PATH) == -1) {
        sp_error(SP_SERVICE, "Failed to change attribute of client binary file");
    }
}

void* SelfProtectService::spawnClientThread(void* vargp)
{
    SelfProtectService* service = (SelfProtectService*)vargp;

    service->spawnClient();
    service->spawnClientStateSet(false);

    return NULL;
}

void* SelfProtectService::spawnClientAndWait(void *vargp)
{
    char buf[1024];
    int sockfd, client_fd;
    bool err = true;
    bool client_timeout = false;
    bool new_changes_applied = false;
    struct sockaddr_un client_addr;
    struct sockaddr_un daemon;
    SelfProtectService* sp = (SelfProtectService*)vargp;
    pthread_t tid;
    unsigned int len = sizeof(client_addr);

    sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sockfd < 0) {
        sp_error(SP_SERVICE, "Daemon failed to open stream socket");
        goto done;
    }

    memset(&daemon, 0, sizeof(daemon));

    daemon.sun_family = AF_UNIX;

    /* Make sure the address we're planning to use isn't too long. */
    if (strlen(DAEMON_SUN_PATH) > sizeof(daemon.sun_path) - 1) {
        sp_error(SP_SERVICE, "Daemon socket path too long: %s", DAEMON_SUN_PATH);
        goto done;
    }

    unlink(DAEMON_SUN_PATH);
    strncpy(daemon.sun_path, DAEMON_SUN_PATH, sizeof(daemon.sun_path) - 1);
    if (bind(sockfd, (struct sockaddr*)&daemon, sizeof(struct sockaddr_un))) {
        sp_error(SP_SERVICE, "Daemon failed binding stream socket");
        goto done;
    }

    sp->setDaemon(&daemon);
    sp->setSocketFd(sockfd);

    sp_info(SP_SERVICE, "Daemon communicating on socket name %s", daemon.sun_path);
    if (listen(sockfd, 1) < 0) {
        sp_error(SP_SERVICE, "Daemon failed to listen on socket");
        goto done;
    }

    pthread_create(&tid, NULL, SelfProtectService::spawnClientThread, vargp);
    pthread_join(tid, NULL);

    client_fd = accept(sockfd, (struct sockaddr*)&client_addr, &len);
    if (client_fd < 0) {
        sp_error(SP_SERVICE, "Daemon failed to accept client");
        goto done;
    }

    sp->setClientFd(client_fd);

    while(1) {
        fd_set set;
        int count, err_select;
        struct timeval timeout;

        FD_ZERO(&set);
        FD_SET(client_fd, &set);

        timeout.tv_sec = CLIENT_TIMEOUT;
        timeout.tv_usec = CLIENT_TIMEOUT * 10000;

        err_select = select(client_fd + 1, &set, NULL, NULL, &timeout);
        if (err_select < 0) {
            sp_error(SP_SERVICE, "select failed to timeout");
            goto done;
        } else if (err_select == 0) {
            sp_info(SP_SERVICE, "Client timedout, terminating client...");
            if (sp->getFileManager()->getFileSystem()->procKill(CLIENT_BIN_NAME) == -1) {
                sp_error(SP_SERVICE, "Failed to kill client");
            }
            client_timeout = true;
            break;
        } else {
            count = sp->daemonRead(buf, sizeof(buf));
            if (count > 0) {
                if (strcmp(buf, CLIENT_FINISH) == 0) {
                    break;
                } else {
                    // token_attempted_status_t status = TOKEN_ATTEMPTED_INCORRECT;

                    // if (strcmp(buf, "12345") == 0) {
                    //     status = TOKEN_ATTEMPTED_CORRECT;
                    // }
                    token_attempted_status_t status = sp->getTokenManager()->tokenIsValid(buf);
                    if (status == TOKEN_ATTEMPTED_CORRECT) {
                        populate_new_buffer(buf, sizeof(buf), CLIENT_CORRECT_TOKEN);
                        if (sp->daemonWrite(buf, sizeof(buf)) < 0) {
                            sp_error(SP_SERVICE, "Daemon failed to write to socket");
                            goto done;
                        }

                        sp_info(SP_SERVICE, "Token is correct, permission granted. Attempting to pause monitor...");

                        sp->getFileManager()->unblockFileOp();

                        if (sp->isNotifEvent()) {
                            query_history_record_t* record = sp->getHistory()->allocRecord(true, true);
                            new_changes_applied = true;
                            sp->getFileManager()->applyNewChangesAndUpdateMemory(record);
                            sp->getHistory()->dbRecordAdd(record);
                        } else {
                            sp->addPermEventDbRecord(true, true);
                        }

                        sp->getFan()->setPermResp(FAN_ALLOW);
                        sp->monitorStateSet(false);
                        sp->authStateSet(false);

                        pthread_create(&tid, NULL, SelfProtectService::stopMonitor, sp);
                        pthread_join(tid, NULL);
                    } else if (status == TOKEN_ATTEMPTED_EXPIRED) {
                        populate_new_buffer(buf, sizeof(buf), CLIENT_ATTEMPT_TOK_EXP);
                        if (sp->daemonWrite(buf, sizeof(buf)) < 0) {
                            sp_error(SP_SERVICE, "Daemon failed to write to socket");
                            goto done;
                        }
                    } else if (status == TOKEN_ATTEMPTED_ERROR_OCCURED) {
                        populate_new_buffer(buf, sizeof(buf), CLIENT_ERROR);
                        if (sp->daemonWrite(buf, sizeof(buf)) < 0) {
                            sp_error(SP_SERVICE, "Daemon failed to write to socket");
                            goto done;
                        }
                    } else {
                        if (strcmp(buf, CLIENT_MAX_ATTEMPT_MSG) == 0) {

                            sp->getFileManager()->blockFileOp(sp);

                            if (!sp->isNotifEvent()) {

                                if (sp->getEventInAuth() != NULL) {
                                    sp->addPermEventDbRecord(false, true);
                                } else {
                                    sp_error(SP_SERVICE, "Failed to add to history db, expects non-NULL event for permission events");
                                }
                            }

                            break;
                        }
                        populate_new_buffer(buf, sizeof(buf), CLIENT_INCORRECT_TOKEN);
                        if (sp->daemonWrite(buf, sizeof(buf)) < 0) {
                            sp_error(SP_SERVICE, "Daemon failed to write to socket");
                            goto done;
                        }
                    }
                }
            } else if (count <= 0) {
                sp_error(SP_SERVICE, "Daemon failed to read from socket");
                goto done;
            }
        }
    }

    err = false;
done:
    close(sp->getClientFd());
    close(sockfd);
    unlink(DAEMON_SUN_PATH);

    if (err || client_timeout) {
        sp->getFileManager()->blockFileOp(sp);
        sp->getFan()->setPermResp(FAN_DENY);
        if (!sp->isNotifEvent()) {
            sp->addPermEventDbRecord(false, true);
        }
    }

    if (!new_changes_applied && sp->isNotifEvent()) {
        query_history_record_t* record = sp->getHistory()->allocRecord(false, true);
        sp->getFileManager()->discardNewChanges(record);
        sp->getHistory()->dbRecordAdd(record);
    }

    sp->authStateSet(false);
    if (sp->isNotifEvent()) {
        sp->notifEventStateSet(false);
    }

    return NULL;
}

void SelfProtectService::logEventInfo(fanotify_event_response_t *event)
{
    sp_info(SP_SERVICE, "Tampering detected: %s", event->event_path);
    sp_info(SP_SERVICE, "Operation: %s", event->resp);
    if (event->file_tampered[0] != '\0') {
        sp_info(SP_SERVICE, "Name: %s", event->file_tampered);
    }
    if (event->err_msg[0] != '\0') {
        sp_error(SP_SERVICE, "Error: %s", event->err_msg);
    }
}

void SelfProtectService::requestTokenAndVerify()
{
    pthread_t tid;

    if (!isAuthenticating()) {
        authStateSet(true);
    }

    fm->allDirActionLock(true);

    pthread_create(&tid, NULL, SelfProtectService::spawnClientAndWait, this);
}

void SelfProtectService::changesAllow(bool is_grace_period)
{
    query_history_record_t* record = NULL;

    record = hist->allocRecord(true, is_grace_period);
    fm->applyNewChangesAndUpdateMemory(record);
    hist->dbRecordAdd(record);
    spawnClientStateSet(true);
    authStateSet(false);
    notifEventStateSet(false);
}

void SelfProtectService::changesAuthenticate()
{
    notifEventStateSet(true);
    authStateSet(true);
    fm->revertNewChanges();
    eventInAuthSet(NULL);
    requestTokenAndVerify();
}

bool SelfProtectService::notifChangesIgnore(fanotify_event_response_t* event)
{
    if (event != NULL) {
        /* FAN_CLOSE_NOWRITE is equivalent to FAN_ACCESS_PERM, fanotify permission event will handle this */
        if (event->fileop == FAN_CLOSE_NOWRITE) {
            return true;
        }
        /* this is when our service changes attribute of client binary to prompt token, need to allow this */
        if (event->fileop == FAN_ATTRIB &&
            strcmp(event->file_tampered, CLIENT_BIN_NAME) == 0) {
            return true;
        }
        /* a text editor like VIM will generate some files, we can ignore these as they will be removed automatically */
        if (fm->fileCreatedByEditor(event->file_tampered)) {
            return true;
        }
    }

    return false;
}

void SelfProtectService::trimEventPathIfDeleted(char* event_path)
{
    /* if a protected directory is deleted, fanotify will append this keyword to the end of the path */
    std::string deleted_keyword(" (deleted)");
    std::string event_path_s(event_path);
    std::string::size_type st;

    st = event_path_s.find(deleted_keyword);
    if (st != std::string::npos) {
        event_path_s.erase(st, deleted_keyword.length());
    }

    strcpy(event_path, event_path_s.c_str());
}

void SelfProtectService::addPermEventDbRecord(bool access_granted, bool service_active)
{
    char tamper_path[PATH_MAX];
    query_history_record_t* record = hist->allocRecord(access_granted, service_active);

    if (getEventInAuth() != NULL) {
        strcpy(record->action_type, "access");
        fm->getFileSystem()->getFilepathFromEvent(tamper_path, getEventInAuth());
        hist->recordProtectedParentDirAdd(record, fm->getProtectedDirFromSubDir(getEventInAuth()->event_path).path.c_str());
        hist->recordTamperingLocAdd(record, tamper_path);
        hist->dbRecordAdd(record);
    } else {
        sp_error(SP_SERVICE, "Failed to add to history db, expects non-NULL event for permission events");
    }
}

void* SelfProtectService::permEventsListen(void *vargp)
{
    SelfProtectService* sp = (SelfProtectService*)vargp;
    fanotify_event_response_t fanotify_resp;

    while (1) {
        fanotify_resp = sp->fan->handlePermEvents();
        if (sp->isMonitoring()) {

            SP_LOG_SEPARATE_EVENT;
            sp->logEventInfo(&fanotify_resp);

            if (!sp->isAuthenticating()) {
                if (fanotify_resp.detect == FANOTIFY_EVENT_DETECTED) {
                    if (sp->fm->fileCreatedByEditor(fanotify_resp.file_tampered)) {
                        continue;
                    }
                    if (sp->isMalicious()) {
                        continue;
                    }
                    /* during a session lock made by fanotify permission event,
                    we don't want to request token again, but any changes made during
                    this time should be reverted 
                    For a modify event, our service will need to access to the file that is being modified to retrieve the content
                    for storeNewChanges, this will trigger the FAN_ACCESS_PERM so we want to ignore that */
                    if (!sp->isNotifEvent()) {
                        sp->authStateSet(true);
                        sp->notifEventStateSet(false);
                        sp->eventInAuthSet(&fanotify_resp);
                        sp->requestTokenAndVerify();
                    }
                }
            }
        } else {
            sp->addPermEventDbRecord(true, false);
        }
    }

    return NULL;
}

void SelfProtectService::notifEventsListen()
{    
    while (1) {
        fanotify_event_list_t* fanotify_events = NULL;
        int i;

        int mount_fd = fm->getFileSystem()->openDirByFd(fm->getDefaultProtectedDir()->fd, fm->getDefaultProtectedDir()->path.c_str(), O_DIRECTORY | O_RDONLY);
        if (mount_fd == -1) {
            sp_error(SP_SERVICE, "Failed to open directory fd for %s, exiting...", fm->getDefaultProtectedDir()->path.c_str());
            break;
        }

        fanotify_events = fan->handleNotifEvents(mount_fd);
        if (fanotify_events != NULL) {
            char* proc_name = NULL;

            if (fanotify_events->size <= 0) {
                fan->eventListDealloc(fanotify_events);
                continue;
            }

            /*  if we detect a tampering while a session is in progress, that means fanotify permission event has reported an event
                and now trying to spawn the client. In order to do this, it has to change the attribute of the client to be executable,
                in which case we need to allow this from happening */
            if (isAuthenticating()) {
                fan->eventListDealloc(fanotify_events);
                continue;
            }

            trimEventPathIfDeleted(fanotify_events->events[0]->event_path);

            proc_name = trust->getTamperingProcName(fanotify_events->events[0]->event_path);

            /* since file system has a tree like structure, child directories and files will be deleted first,
            we need to loop from the end of the list to revert the parent changes first before we can revert the children changes */
            for (i = (fanotify_events->size - 1); i >= 0; i--) {
                if (fanotify_events->events[i] != NULL) {
                    trimEventPathIfDeleted(fanotify_events->events[i]->event_path);

                    if (EVENT_DETECTED(fanotify_events->events[i]->detect)) {
                        if (notifChangesIgnore(fanotify_events->events[i])) {
                            continue;
                        }

                        SP_LOG_SEPARATE_EVENT;
                        logEventInfo(fanotify_events->events[i]);
                        if (TAMPERED(fanotify_events->events[i]->fileop)) {
                            notifEventStateSet(true);
                            fm->storeNewChanges(fanotify_events->events[i]);
                        }
                    }
                    else if (ERROR_DETECTED(fanotify_events->events[i]->detect)) {
                        sp_error(SP_SERVICE, "Error: %s, exiting...", fanotify_events->events[i]->err_msg);
                        exit(EXIT_FAILURE);
                    }
                }   
            }
            if (fm->getNewChangesSize() == 0) {
                authStateSet(false);
                fan->eventListDealloc(fanotify_events);
                continue;
            }

            if (isMonitoring()) {
                if (!trust->procIsTrusted(proc_name)) {
                    changesAuthenticate();
                } else {
                    changesAllow(false);
                }
            } else {
                /* need to mark this as an internal event so fanotify doesn't keep sending events over and over again during grace peiord */
                fan->setEventInternal(true);
                changesAllow(false);
            }
            fan->eventListDealloc(fanotify_events);
        }
        close(mount_fd);
    }
}

void* SelfProtectService::stopMonitor(void *vargp)
{
    SelfProtectService* service = (SelfProtectService*)vargp;
    struct timespec stop_monitor_start = {0};

    if (clock_gettime(CLOCK_MONOTONIC, &stop_monitor_start) == 0) {
        service->getFan()->setPermResp(FAN_ALLOW);
        service->maliciousStateSet(false);

        while(1) {
            struct timespec elapsed = {0};

            /* if clock_gettime above succeeds this one will likely be successful, no need to check for errors */
            clock_gettime(CLOCK_MONOTONIC, &elapsed);
            if ((int)difftime(elapsed.tv_sec, stop_monitor_start.tv_sec) >= UNBLOCK_DURATION) {
                sp_info(SP_SERVICE, "Resumed monitoring");
                service->monitorStateSet(true);
                /* deny every permission events again */
                service->getFan()->setPermResp(FAN_DENY);
                service->spawnClientStateSet(true);

                break;
            }
        }
    } else {
        sp_error(SP_SERVICE, "Failed to resume monitoring, clock_gettime error: %s", strerror(errno));
    }

    return NULL;
}

void SelfProtectService::monitor()
{
    pthread_t perm_tid;

    sp_info(SP_SERVICE, "Listening for events started");

    pthread_create(&perm_tid, NULL, SelfProtectService::permEventsListen, this);
    notifEventsListen();
    pthread_join(perm_tid, NULL);
}

void* SelfProtectService::monitorSysdService(void* vargp)
{
    (void)vargp;
    int err = -1, status;
    char* posix_spawn_path = (char*) SELF_PROTECT_SYSD_MONITOR_EXEC;
    pid_t sysd_monitor_pid;
    sigset_t sig_mask;
    posix_spawnattr_t attr;
    posix_spawnattr_t *attrp = NULL;
    posix_spawn_file_actions_t *file_actionsp = NULL;

    if (SYSTEM_CMD(PROCESS_EXISTS_CMD_FMT, SELF_PROTECT_SYSD_MONITOR_EXEC_NAME) == 0) {
        sp_info(SP_SERVICE, "systemd service monitor already running, skipping...");
        err = 0;
        goto done;
    }

    err = posix_spawnattr_init(&attr);
    if (err != 0) {
        sp_error(SP_SERVICE, "posix_spawnattr_init failed, %s", strerror(errno));
        goto done;
    }

    err = posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETSIGMASK);
    if (err != 0) {
        sp_error(SP_SERVICE, "Failed to set flags to include signals for child process, %s", strerror(errno));
        goto done;
    }

    /* make it so that the only way to kill our child service is by kill with code 9 (unblockable) */
    sigfillset(&sig_mask);
    err = posix_spawnattr_setsigmask(&attr, &sig_mask);
    if (err != 0) {
        sp_error(SP_SERVICE, "Failed to set signal mask for child process, %s", strerror(errno));
        goto done;
    }

    attrp = &attr;
    
    err = posix_spawn(&sysd_monitor_pid, 
                        posix_spawn_path, 
                        file_actionsp, 
                        attrp,
                        &posix_spawn_path, 
                        environ);
    if (err != 0) {
        sp_error(SP_SERVICE, "posix_spawn failed to spawn service monitor child process, %s", strerror(err));
        goto done;
    }
    sp_info(SP_SERVICE, "Spawned systemd service monitor process with pid %i", sysd_monitor_pid);
    
    do {
        err = waitpid(sysd_monitor_pid, &status, WUNTRACED | WCONTINUED);
        if (err == -1) {
            sp_error(SP_SERVICE, "waitpid failed");
            goto done;
        }
            
        if (WIFSIGNALED(status)) {
            sp_info(SP_SERVICE, "systemd service monitor was killed by signal %d, this could be an attack trying to stop self protect service", WTERMSIG(status));
            sp_info(SP_SERVICE, "restarting systemd service monitor...");

            err = posix_spawn(&sysd_monitor_pid, 
                                posix_spawn_path, 
                                file_actionsp, 
                                attrp,
                                &posix_spawn_path, 
                                environ);
            if (err != 0) {
                sp_error(SP_SERVICE, "failed to restart systemd service monitor, self protect service is vulnerable");
                goto done;
            } else {
                sp_info(SP_SERVICE, "systemd service monitor restarted successfully");
            }
        }
    } while (!WIFEXITED(status));

done:
    if (attrp != NULL) {
        if (posix_spawnattr_destroy(attrp) != 0) {
            sp_error(SP_SERVICE, "Failed to destroy child posix attribute, %s", strerror(errno));
        }
    }

    if (err == -1) {
        sp_error(SP_SERVICE, "Cannot spawn child process to protect self protect service from shutting down");
    }
    return NULL;
}

int main()
{
    sp_info(SP_SERVICE, "Initializing...");
    pthread_t tid;
    Trust trust;
    QueryHistory hist;
    FanotifyEvents fan(&trust);
    FileManager fm(SELF_PROTECT_CONFIG_DIR, &fan, &hist, &trust);
    TokenManager tm(RESOURCE_URL);
    SelfProtectService sp(&fm, &tm, &fan, &hist, &trust);
    
    sp_info(SP_SERVICE, "SelfProtectService started");

    pthread_create(&tid, NULL, SelfProtectService::monitorSysdService, NULL);

    sp.monitor();

    pthread_join(tid, NULL);

    return 0;
}
