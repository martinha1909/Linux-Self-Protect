#ifndef FANOTIFY_EVENTS_H
#define FANOTIFY_EVENTS_H

#include <fcntl.h>
#include <sys/fanotify.h>
#include <unistd.h>
#include <dirent.h>
#include <string.h>
#include "../../FileSystem/include/FileSystem.hpp"
#include "../../SelfProtectService/include/SpConstants.hpp"

#define GENERAL_STR_MAX_LEN 64
#define BUF_SIZE            256

/* fanotify related macros */
/**
 * When passed to fanotify_mark, this macro will mark the following events to be notifed:
 * - file creations
 * - file close unchanged
 * - file close changed
 * FAN_EVENT_ON_CHILD tells fanotify to notify all files within that directory, 
 * not just the operation on the directory itself
 */
#define FANOTIFY_EVENT_MASK                     (FAN_CREATE |\
                                                 FAN_DELETE |\
                                                 FAN_CLOSE_NOWRITE |\
                                                 FAN_CLOSE_WRITE |\
                                                 FAN_MOVED_FROM |\
                                                 FAN_MOVED_TO |\
                                                 FAN_ATTRIB |\
                                                 FAN_ONDIR |\
                                                 FAN_EVENT_ON_CHILD)

#define FANOTIFY_EVENT_PERM_MASK                (FAN_ACCESS_PERM |\
                                                 FAN_EVENT_ON_CHILD)

/**
 *  In the example, FAN_MARK_MOUNT is used, 
 *  we don't want that here since that would result in monitoring the whole fs
 */
#define FANOTIFY_DIR_EVENTS         FAN_MARK_ADD
#define FANOTIFY_DIR_IGNORE         FAN_MARK_REMOVE
#define FANOTIFY_INIT_MASK          (FAN_CLASS_NOTIF | FAN_REPORT_FID | FAN_REPORT_DFID_NAME)
#define FANOTIFY_INIT_PERM_MARK     FAN_CLASS_CONTENT

typedef __u32 __permission;
class Trust;
class FileManager;

typedef enum fanotify_event_detected_e {
    FANOTIFY_NO_EVENT = 0,
    FANOTIFY_EVENT_DETECTED,
    FANOTIFY_EVENT_ERR
} fanotify_event_detected_t;

typedef struct fanotify_event_response {
    fanotify_event_detected_t detect;
    uint64_t fileop;
    char event_path[PATH_MAX + 1];
    char file_tampered[GENERAL_STR_MAX_LEN];
    char err_msg[GENERAL_STR_MAX_LEN];
    char resp[GENERAL_STR_MAX_LEN];
} fanotify_event_response_t;

typedef struct fanotify_event_list {
    fanotify_event_response_t** events;
    int size;
} fanotify_event_list_t;

class FanotifyEvents {
private:
    int notif_fd;
    int perm_fd;
    bool event_internal;
    pthread_mutex_t perm_mutex;
    __permission perm_resp;
    Trust* trust;
    FileManager* fm;

    /**
     * Appends an event to a fanotify event list
     *
     * @param event_list   list to be appended
     * @param event        incoming event
     */
    void eventListAppend(fanotify_event_list_t* event_list, fanotify_event_response_t* event);
    int markPermEvents(const char* dir, 
                       const char** sub_dirs, 
                       const size_t num_sub_dirs, 
                       unsigned int flags);
    int markNotifEvents(const char* dir, 
                        const char** sub_dirs, 
                        const size_t num_sub_dirs, 
                        unsigned int flags);
public:
    FanotifyEvents(Trust* trust);
    /**
     * Handling notification events in directories marked by fanotify_mark and return detected events by fanotify
     *
     * @param fd       file descriptor provided by fanotify_init
     * @param mount_fd directory file descriptor to be monitored
     * 
     * @return a list of events reported by fanotify, if the field detect is set to FANOTIFY_EVENT_ERR,
     *         the program will print out err_msg and exit
     */
    fanotify_event_list_t* handleNotifEvents(int mount_fd);
    /**
     * Handling permission events in directories marked by fanotify_mark and return detected events by fanotify
     *
     * @param fd                    file descriptor provided by fanotify_init
     * 
     * @return a struct containing data of the event, if the field detect is set to FANOTIFY_EVENT_ERR,
     *         the program will print out err_msg and exit
     */
    fanotify_event_response_t handlePermEvents();
    /**
     * Marks all directories that need to be monitored by fanotify
     *
     * @param fanotify_notif_fd   notification file descriptor provided by fanotify_init.
     * @param fanotify_perm_fd    permission file descriptor provided by fanotify_init.
     * @param dir_fd              directory stream file descriptor to be marked
     * @param dir                 directory path to be marked
     * 
     * @return              0 on success, -1 on error
     */
    int mark(const char* dir, const char** sub_dirs, const size_t num_sub_dirs);
    /**
     * Unmark all directories that is monitored by fanotify
     *
     * @param fanotify_notif_fd   notification file descriptor provided by fanotify_init.
     * @param fanotify_perm_fd    permission file descriptor provided by fanotify_init.
     * @param dir_fd              directory stream file descriptor to be unmarked
     * @param dir                 directory path to be unmarked
     * 
     * @return              0 on success, -1 on error
     */
    int unmark(const char *dir, const char **sub_dirs, const size_t num_sub_dirs);
    /**
     * Duplicates a fanotify_event_response_t struct by doing dynamic memory allocation. 
     * The caller of this function must pass to free() after use
     *
     * @param event   fanotify event response to be duplicated
     * 
     * @return        duplicate version of event
     */
    fanotify_event_response_t* eventDup(fanotify_event_response_t* event);
    /**
     * Deallocates a fanotify event list
     * @note event_list must be dynamically allocated
     *
     * @param event_list   list to be deallocated
     */
    void eventListDealloc(fanotify_event_list_t* event_list);
    /**
     * Populates response string to send back to SelfProtectService class depending on the type of event
     *
     * @param resp     response string to be populated
     * @param metadata metadata containing the type of detected events
     */
    void eventMaskStr(char* resp, struct fanotify_event_metadata *metadata);
    void setNotifFd(int notif_fd);
    void setPermFd(int perm_fd);
    void setPermResp(__permission resp);
    void setFileManager(FileManager* fileManager);
    void setEventInternal(bool is_internal);
    __permission getPermResp();
    int getNotifFd();
    int getPermFd();
};

#endif