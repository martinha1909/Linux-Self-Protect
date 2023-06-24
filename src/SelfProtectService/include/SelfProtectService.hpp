#ifndef SELFPROTECTSERVICE_HPP
#define SELFPROTECTSERVICE_HPP

#include <sys/socket.h>
#include <sys/un.h>
#include <spawn.h>
#include "../../FileManager/include/FileManager.hpp"
#include "../../CLI_Interface/include/CLI_Interface.hpp"
#include "../../TokenManager/include/TokenManager.hpp"
#include "../../SelfProtectService/include/SpLogger.hpp"
#include "../../CLI_Interface/include/cli_helper.h"

typedef struct fanotify_event_response fanotify_event_response_t;

class FileManager;
class TokenManager;
class FanotifyEvents;
class QueryHistory;
class Trust;
class FileSystem;

class SelfProtectService {
private:
    int socket_fd;
    int client_fd;
    bool is_monitoring;
    bool do_spawn_client;
    bool auth_in_prog;
    bool is_notif_event;
    bool is_malicious;
    FileManager *fm;
    TokenManager *tm;
    FanotifyEvents *fan;
    QueryHistory *hist;
    Trust* trust;
    struct sockaddr_un *daemon;
    fanotify_event_response_t* event_in_auth;
    pthread_mutex_t mutex;

    /**
     * Allows changes and adds a record to history db
     *
     * @param is_grace_period   whether the changes were during grace period or not
     */
    void changesAllow(bool is_grace_period);
    /**
     * Authenticates before allow or deny changes
     */
    void changesAuthenticate();
    /**
     * Determines if a notification event should be ignored or not
     *
     * @param event               event to be checked
     * 
     * @return     true if an event should be ignored, false otherwise
     */
    bool notifChangesIgnore(fanotify_event_response_t* event);
    /**
     * Trims a fanotify event path if it has been deleted
     * @note deleted paths are appended with the keyword "(deleted)", we want to remove this
     *
     * @param event_path          event path to be checked
     */
    void trimEventPathIfDeleted(char* event_path);
    /**
     * Listens for notification events reported by FAN_CLASS_NOTIF group. This function doesn't exit unless there is an error occur
     * 
     * @note this function is the communication entry point between fanotify and the service for notification events,
     *       as it gets the event and transports to other components of the service. 
     */
    void notifEventsListen();
    /**
     * Adds a permission event record to the history db
     * 
     * @param access_granted    whether authorization was successfully for a permission event
     * @param service_active    whether grace period was in effect. If this parameter is set to true, access_granted will ALWAYS be true
     */
    void addPermEventDbRecord(bool access_granted, bool service_active);
public:
    SelfProtectService(FileManager *fileManager, 
                       TokenManager* TokenManager, 
                       FanotifyEvents* fanotifyEvents,
                       QueryHistory* queryHistory,
                       Trust* trust);
    ~SelfProtectService();
    /**
     * Request a token from the user by spawning a cli interface
     */
    void requestTokenAndVerify();
    /**
     * Logs an event reported by fanotify
     *
     * @param event         fanotify detected event
     */
    void logEventInfo(fanotify_event_response_t *event);
    /**
     * Handles communication between the CLI and fanotify
     */
    void monitor();
    /**
     * Monitors systemd service status by spawning a child process. 
     * 
     * @note This function does not exit and will continuously monitors the state of the child process
     * 
     * @param vargp     not used
     */
    static void* monitorSysdService(void* vargp);
    /**
     * Spawns a client cli interface. 
     * This function will execute another program, which is then communicated with via unix domain socket
     */
    void spawnClient();
    /**
     * Spawns a cli interface
     *
     * @param vargp     pthread void argument pointer. Passed in with struct thread_spawn_client_param_t
     */
    static void* spawnClientThread(void* vargp);
    /**
     * Spawns a cli interface and waits for response. 
     * If timeout has reached and client has not input a token, we default to block. Then the client will be terminated
     * If any error occurs on the socket side, we default to block. This will need to be replaced by a backup method in the future
     *
     * @param vargp         pthread void argument pointer. Passed in with struct thread_spawn_client_param_t
     */
    static void* spawnClientAndWait(void* vargp);
    /**
     * Reads from unix domain socket
     *
     * @param buf[out]    buffer to be populated after socket is read
     * @param len[in]     buffer length
     * 
     * @return            0 on success, -1 on error
     */
    int daemonRead(char* buf, size_t len);
    /**
     * Writes to unix domain socket
     *
     * @param buf[in]     buffer to be written to socket
     * @param len[in]     buffer length
     * 
     * @return            0 on success, -1 on error
     */
    int daemonWrite(char* buf, size_t len);
    /**
     * Stops monitoring and enters grace period, any changes made during this period is allowed
     *
     * @param vargp       pthread param, not used
     * 
     * @return            NULL
     */
    static void* stopMonitor(void* vargp);
    /**
     * A multithreading function that listens for permission events reported by FAN_CLASS_CONTENT group. 
     * This function doesn't exit unless there is an error occur
     * 
     * @note the argument passed to this function MUST be a SelfProtectService object
     *
     * @param vargp          SelfProtectService object pointed argument
     */
    static void* permEventsListen(void* vargp);
    /**
     * Sets daemon socket struct
     *
     * @param daemon     socket address to set
     */
    void setDaemon(struct sockaddr_un *daemon);
    /**
     * Sets socket file descriptor that the client and daemon are created at
     *
     * @param socket_fd socket file descriptor
     */
    void setSocketFd(int socket_fd);
    /**
     * Sets client file descriptor
     *
     * @param client_fd     client socket file descriptor that daemon communicates to
     */
    void setClientFd(int client_fd);
    /**
     * Sets is_monitoring state
     *
     * @param state true if grace period is not granted, false otherwise
     */
    void monitorStateSet(bool state);
    /**
     * Sets do_spawn_client state
     *
     * @param state state to be set
     */
    void spawnClientStateSet(bool state);
    /**
     * Sets auth_in_prog state
     *
     * @param state state to be set
     */
    void authStateSet(bool state);
    /**
     * Sets is_notif_event state
     *
     * @param state state to be set
     */
    void notifEventStateSet(bool state);
    /**
     * Sets is_malicious state
     *
     * @param state state to be set
     */
    void maliciousStateSet(bool state);
    /**
     * Sets event_in_auth state
     *
     * @param event event to be set
     */
    void eventInAuthSet(fanotify_event_response_t* event);
    /**
     * is_monitoring getter
     *
     * @return is_monitoring
     */
    bool isMonitoring();
    /**
     * mutex getter
     *
     * @return mutex
     */
    pthread_mutex_t* getMutex();
    /**
     * Gets client socket file descriptor
     *
     * @return client socket file descriptor
     */
    int getClientFd();
    /**
     * do_spawn_client getter
     *
     * @return do_spawn_client
     */
    bool dospawnClient();
    /**
     * auth_in_prog getter
     *
     * @return auth_in_prog
     */
    bool isAuthenticating();
    /**
     * is_notif_event getter
     *
     * @return is_notif_event
     */
    bool isNotifEvent();
    /**
     * is_malicious getter
     *
     * @return is_malicious
     */
    bool isMalicious();
    /**
     * event_in_auth getter
     *
     * @return event_in_auth
     */
    fanotify_event_response_t* getEventInAuth();
    /**
     * fan getter
     *
     * @return fan
     */
    FanotifyEvents* getFan();
    /**
     * hist getter
     *
     * @return hist
     */
    QueryHistory* getHistory();
    /**
     * fm getter
     *
     * @return fm
     */
    FileManager* getFileManager();
    /**
     * tm getter
     *
     * @return tm
     */
    TokenManager* getTokenManager();
    /**
     * trust getter
     *
     * @return trust
     */
    Trust* getTrust();
};

#endif