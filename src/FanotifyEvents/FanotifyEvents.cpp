#include "include/FanotifyEvents.hpp"
#include "../Trust/include/Trust.hpp"
#include <inttypes.h>

FanotifyEvents::FanotifyEvents(Trust* trust)
{
    event_internal = false;
    this->trust = trust;
    perm_resp = FAN_DENY;
    pthread_mutex_init(&perm_mutex, NULL);

    notif_fd = fanotify_init(FANOTIFY_INIT_MASK, O_RDWR);
    if (notif_fd == -1) {
        close(notif_fd);
        sp_error(SP_SERVICE, "fanotify_init failed, exiting...");
        exit(EXIT_FAILURE);
    }

    perm_fd = fanotify_init(FANOTIFY_INIT_PERM_MARK, O_RDWR);
    if (perm_fd == -1) {
        close(perm_fd);
        sp_error(SP_SERVICE, "fanotify_init failed, exiting...");
        exit(EXIT_FAILURE);
    }
}

void FanotifyEvents::setNotifFd(int notif_fd)
{
    this->notif_fd = notif_fd;
}

void FanotifyEvents::setPermFd(int perm_fd)
{
    this->perm_fd = perm_fd;
}

void FanotifyEvents::setPermResp(__permission resp)
{
    SP_MUTEX_LOCK(&perm_mutex);
    perm_resp = resp;
    SP_MUTEX_UNLOCK(&perm_mutex);
}

void FanotifyEvents::setFileManager(FileManager* fileManager)
{
    fm = fileManager;
}

void FanotifyEvents::setEventInternal(bool is_internal)
{
    event_internal = is_internal;
}

__permission FanotifyEvents::getPermResp()
{
    __permission ret;

    SP_MUTEX_LOCK(&perm_mutex);
    ret = perm_resp;
    SP_MUTEX_UNLOCK(&perm_mutex);

    return ret;
}

int FanotifyEvents::getNotifFd()
{
    return notif_fd;
}

int FanotifyEvents::getPermFd()
{
    return perm_fd;
}

void FanotifyEvents::eventMaskStr(char* resp, struct fanotify_event_metadata *metadata)
{
    int err = 0;
    switch (metadata->mask) {
        case FAN_CREATE:
            err = snprintf(resp, GENERAL_STR_MAX_LEN, "%s", "create (file)");
            break;
        case FAN_DELETE:
            err = snprintf(resp, GENERAL_STR_MAX_LEN, "%s", "delete (file)");
            break;
        case FAN_MODIFY:
            err = snprintf(resp, GENERAL_STR_MAX_LEN, "%s", "modify");
            break;
        case FAN_CLOSE_NOWRITE:
            err = snprintf(resp, GENERAL_STR_MAX_LEN, "%s", "close (untampered)");
            break;
        case FAN_CLOSE_WRITE:
            err = snprintf(resp, GENERAL_STR_MAX_LEN, "%s", "close (tampered)");
            break;
        case FAN_MOVED_TO:
            err = snprintf(resp, GENERAL_STR_MAX_LEN, "%s", "move to marked directory (file)");
            break;
        case FAN_MOVED_FROM:
            err = snprintf(resp, GENERAL_STR_MAX_LEN, "%s", "move from marked directory (file)");
            break;
        case FAN_ATTRIB:
            err = snprintf(resp, GENERAL_STR_MAX_LEN, "%s", "change attribute (file)");
            break;
        case FAN_ACCESS_PERM:
            err = snprintf(resp, GENERAL_STR_MAX_LEN, "%s", "access");
            break;
        case FAN_ONDIR | FAN_ATTRIB:
            err = snprintf(resp, GENERAL_STR_MAX_LEN, "%s", "change attribute (dir)");
            break;
        case FAN_ONDIR | FAN_CREATE:
            err = snprintf(resp, GENERAL_STR_MAX_LEN, "%s", "create (dir)");
            break;
        case FAN_ONDIR | FAN_DELETE:
            err = snprintf(resp, GENERAL_STR_MAX_LEN, "%s", "delete (dir)");
            break;
        case FAN_ONDIR | FAN_MOVED_FROM:
            err = snprintf(resp, GENERAL_STR_MAX_LEN, "%s", "move from marked directory (dir)");
            break;
        case FAN_ONDIR | FAN_MOVED_TO:
            err = snprintf(resp, GENERAL_STR_MAX_LEN, "%s", "move to marked directory (dir)");
            break;
        default:
            err = snprintf(resp, GENERAL_STR_MAX_LEN, "%s", "Unexpected mask");
    }
    
    if (err < 0) {
        sp_error(SP_SERVICE, "snprintf failed");
    }
}

int FanotifyEvents::markNotifEvents(const char* dir, 
                                    const char** sub_dirs, 
                                    const size_t num_sub_dirs, 
                                    unsigned int flags)
{
    int err = -1;

    if (!fm->getFileSystem()->dirExist(dir)) {
        sp_error(SP_FANOTIFY, "Skip marking/unmarking %s, dir doesn't exist", dir);
        err = 0;
        goto done;
    }

    err = fanotify_mark(notif_fd,
                        flags,
                        FANOTIFY_EVENT_MASK,
                        fm->getFileSystem()->getDirFd(dir),
                        dir);

    if (err == -1) {
        sp_error(SP_FANOTIFY, "fanotify_mark failed on dir %s, error: %s", dir, strerror(errno));
        goto done;
    }
    /* only mark if sub-directories exist */
    if (sub_dirs != NULL && num_sub_dirs > 0) {
        for (size_t i = 0; i < num_sub_dirs; i++) {
            if (!fm->getFileSystem()->dirExist(sub_dirs[i])) {
                sp_error(SP_FANOTIFY, "Skip marking/unmarking %s, dir doesn't exist", sub_dirs[i]);
                continue;
            }
            err = fanotify_mark(notif_fd,
                                flags,
                                FANOTIFY_EVENT_MASK,
                                fm->getFileSystem()->getDirFd(sub_dirs[i]),
                                sub_dirs[i]);
            if (err == -1) {
                sp_error(SP_FANOTIFY, "fanotify_mark failed on sub-dir %s, error: %s", sub_dirs[i], strerror(errno));
                goto done;
            }
        }
    }

    err = 0;
done:
    return err;
}

int FanotifyEvents::markPermEvents(const char* dir, 
                                   const char** sub_dirs, 
                                   const size_t num_sub_dirs, 
                                   unsigned int flags)
{
    int err = -1;
    char dir_tmp[PATH_MAX];

    if (!fm->getFileSystem()->dirExist(dir)) {
        sp_error(SP_FANOTIFY, "Skip marking/unmarking %s, dir doesn't exist", dir);
        err = 0;
        goto done;
    }

    /* may or may not contain the final '/', we want to check for both just in case */
    strcpy(dir_tmp, dir);
    strcat(dir_tmp, "/");
    /** Since this is a permission mark, 
     *  we don't want to block our config dir since our service will run binary executables like our client 
     */
    if (strcmp(dir_tmp, SELF_PROTECT_CONFIG_BIN_DIR) == 0 ||
        strcmp(dir, SELF_PROTECT_CONFIG_BIN_DIR) == 0) {
        err = 0;
        goto done;
    }

    err = fanotify_mark(perm_fd,
                        flags,
                        FANOTIFY_EVENT_PERM_MASK,
                        fm->getFileSystem()->getDirFd(dir),
                        dir);
    if (err == -1) {
        sp_error(SP_FANOTIFY, "fanotify_mark failed on dir %s, error: %s", dir, strerror(errno));
        goto done;
    }

    /* if it is our config dir, we don't want to mark the sub-dir of it since it contains the binary dir, where our client binary lies in */
    if (strcmp(dir_tmp, SELF_PROTECT_CONFIG_DIR) == 0 ||
        strcmp(dir, SELF_PROTECT_CONFIG_DIR) == 0) {
        err = 0;
        goto done;
    }
    
    /* only mark if sub-directories exist */
    if (sub_dirs != NULL && num_sub_dirs > 0) {
        for (size_t i = 0; i < num_sub_dirs; i++) {
            if (!fm->getFileSystem()->dirExist(dir)) {
                sp_error(SP_FANOTIFY, "Skip marking/unmarking %s, dir doesn't exist", sub_dirs[i]);
                continue;
            }
            err = fanotify_mark(perm_fd,
                                flags,
                                FANOTIFY_EVENT_PERM_MASK,
                                fm->getFileSystem()->getDirFd(sub_dirs[i]),
                                sub_dirs[i]);
            if (err == -1) {
                sp_error(SP_FANOTIFY, "fanotify_mark failed on sub-dir %s, error: %s", sub_dirs[i], strerror(errno));
                goto done;
            }
        }
    }

    err = 0;
done:
    return err;
}

int FanotifyEvents::unmark(const char *dir, 
                           const char **sub_dirs, 
                           const size_t num_sub_dirs)
{
    int ret = -1;

    ret = markNotifEvents(dir, sub_dirs, num_sub_dirs, FANOTIFY_DIR_IGNORE);
    if (ret == -1) {
        sp_error(SP_FANOTIFY, "Failed to unmark notification events");
        goto done;
    }

    ret = markPermEvents(dir, sub_dirs, num_sub_dirs, FANOTIFY_DIR_IGNORE);
    if (ret == -1) {
        sp_error(SP_FANOTIFY, "Failed to unmark permission events");
        goto done;
    }

    ret = 0;
done:
    return ret;
}

int FanotifyEvents::mark(const char *dir, 
                         const char **sub_dirs, 
                         const size_t num_sub_dirs)
{
    int ret = -1;

    ret = markNotifEvents(dir, sub_dirs, num_sub_dirs, FANOTIFY_DIR_EVENTS);
    if (ret == -1) {
        sp_error(SP_FANOTIFY, "Failed to mark notification events");
        goto done;
    }

    ret = markPermEvents(dir, sub_dirs, num_sub_dirs, FANOTIFY_DIR_EVENTS);
    if (ret == -1) {
        sp_error(SP_FANOTIFY, "Failed to mark permission events");
        goto done;
    }

    ret = 0;
done:
    return ret;
}

fanotify_event_list_t* FanotifyEvents::handleNotifEvents(int mount_fd)
{
    int err = -1;
    char buf[4096];
    const unsigned char *file_name;
    ssize_t buflen;
    struct file_handle *file_handle;
    struct fanotify_event_metadata *metadata;
    struct fanotify_event_info_fid *fid;
    fanotify_event_list_t* ret = (fanotify_event_list_t*)calloc(sizeof(fanotify_event_list_t), 1);

    if (ret == NULL) {
        sp_error(SP_FANOTIFY, "failed to get fanotify events list, memory allocation failed");
        goto abort;
    }

    buflen = read(notif_fd, buf, sizeof(buf));

    /* if an event is done by our own service (i.e during apply new changes), we ignore them */
    if (!event_internal) {
        for (metadata = (struct fanotify_event_metadata*)buf; FAN_EVENT_OK(metadata, buflen); metadata = FAN_EVENT_NEXT(metadata, buflen)) {
            fanotify_event_response_t response = {};

            fid = (struct fanotify_event_info_fid *) (metadata + 1);
            file_handle = (struct file_handle *) fid->handle;

            /* Ensure that the event info is of the correct type */
            if (fid->hdr.info_type == FAN_EVENT_INFO_TYPE_FID ||
                fid->hdr.info_type == FAN_EVENT_INFO_TYPE_DFID) {
                file_name = NULL;
            } else if (fid->hdr.info_type == FAN_EVENT_INFO_TYPE_DFID_NAME) {
                file_name = file_handle->f_handle +
                            file_handle->handle_bytes;
            }

            err = fm->getFileSystem()->getEventLocation(&response, mount_fd, file_handle, file_name, O_RDONLY);
            if (err == FS_UTIL_FILE_HANDLE_NOT_VALID) {
                continue;
            } else if (err == FS_UTIL_FILE_HANDLE_ERR) {
                goto abort;
            }

            eventMaskStr(response.resp, metadata);
            if (strcmp(response.resp, "Unexpected mask") == 0) {
                continue;
            }

            response.fileop = metadata->mask;
            response.detect = FANOTIFY_EVENT_DETECTED;
            response.err_msg[0] = '\0';

            /* if an action is on a directory, no need to report the filename since it will just be '.' */
            if (response.fileop == (FAN_ONDIR | FAN_ATTRIB)) {
                memset(response.file_tampered, 0, sizeof(response.file_tampered));
            }

            eventListAppend(ret, &response);

            close(metadata->fd);
        }
    } else {
        /* if an event done by our own service, we ignore it.
            After ignoring it, set to false so we can detect external event */
        event_internal = false;
    }

abort:
    return ret;
}

fanotify_event_response_t FanotifyEvents::handlePermEvents()
{
    ssize_t len;
    ssize_t path_len;
    char path[PATH_MAX];
    char procfd_path[PATH_MAX];
    const struct fanotify_event_metadata *metadata;
    struct fanotify_event_metadata buf[200];
    struct fanotify_response response;
    fanotify_event_response_t ret = {};

    len = read(perm_fd, buf, sizeof(buf));
    if (len == -1) {
        ret.detect = FANOTIFY_EVENT_ERR;
        sp_error(SP_FANOTIFY, "Failed to read from fanotify permission fd, %s", strerror(errno));
        goto abort;
    }

    /* Point to the first event in the buffer. */
    metadata = buf;

    /* Loop over all events in the buffer. */
    while (FAN_EVENT_OK(metadata, len)) {
        /* Check that run-time and compile-time structures match. */
        if (metadata->vers != FANOTIFY_METADATA_VERSION) {
            sp_error(SP_FANOTIFY, "Mismatch of fanotify metadata version");
            ret.detect = FANOTIFY_EVENT_ERR;
            goto abort;
        }

        /* metadata->fd contains either FAN_NOFD, indicating a
        queue overflow, or a file descriptor (a nonnegative
        integer). Here, we simply ignore queue overflow. */
        if (metadata->fd >= 0) {
            char path_cpy[PATH_MAX];

            /* Retrieve and print pathname of the accessed file. */
            snprintf(procfd_path, sizeof(procfd_path), "/proc/self/fd/%d", metadata->fd);
            path_len = readlink(procfd_path, path, sizeof(path) - 1);
            if (path_len == -1) {
                sp_error(SP_FANOTIFY, "readlink failed, %s", strerror(errno));
                ret.detect = FANOTIFY_EVENT_ERR;
                goto abort;
            }

            path[path_len] = '\0';
            
            strcpy(path_cpy, path);
            strcpy(ret.event_path, dirname(path_cpy));
            strcat(ret.event_path, "/");

            strcpy(path_cpy, path);
            strcpy(ret.file_tampered, basename(path_cpy));

            eventMaskStr(ret.resp, (struct fanotify_event_metadata*)metadata);

            ret.fileop = metadata->mask;

            if (metadata->mask & FAN_ACCESS_PERM) {
                char* proc_name = trust->getTamperingProcName(path);

                ret.detect = FANOTIFY_EVENT_DETECTED;
                response.fd = metadata->fd;

                if (trust->procIsTrusted(proc_name)) {
                    ret.detect = FANOTIFY_NO_EVENT;
                    response.response = FAN_ALLOW;
                } else {
                    response.response = getPermResp();
                }
                if (write(perm_fd, &response, sizeof(response)) == -1) {
                    sp_error(SP_FANOTIFY, "Failed to write fanotify permission response, %s", strerror(errno));
                    ret.detect = FANOTIFY_EVENT_ERR;
                    goto abort;
                }
            }

            /* Close the file descriptor of the event. */
            close(metadata->fd);
        }

        /* Advance to next event. */
        metadata = FAN_EVENT_NEXT(metadata, len);
    }

abort:
    return ret;
}

fanotify_event_response_t* FanotifyEvents::eventDup(fanotify_event_response_t* event)
{
    fanotify_event_response_t* ret = (fanotify_event_response_t*)calloc(sizeof(fanotify_event_response_t), 1);

    if (event != NULL) {
        if (ret != NULL) {
            ret->detect = event->detect;
            ret->fileop = event->fileop;
            strcpy(ret->event_path, event->event_path);
            strcpy(ret->file_tampered, event->file_tampered);
            strcpy(ret->err_msg, event->err_msg);
            strcpy(ret->resp, event->resp);
        } else {
            sp_error(SP_FANOTIFY, "Failed to duplicate fanotify event response, memory allocation failed");
        }
    } else {
        sp_error(SP_FANOTIFY, "Failed to duplicate fanotify event response, bad arguments");
    }

    return ret;
}

void FanotifyEvents::eventListAppend(fanotify_event_list_t* event_list, fanotify_event_response_t* event)
{
    if (event_list != NULL && event != NULL) {
        if (event_list->events == NULL) {
            event_list->size = 0;
        }
        event_list->size++;
        event_list->events = (fanotify_event_response_t**)realloc(event_list->events, sizeof(fanotify_event_response_t*) * event_list->size);
        if (event_list->events != NULL) {
            event_list->events[event_list->size - 1] = eventDup(event);
        } else {
            sp_error(SP_FANOTIFY, "Failed to append events to list, memory allocation failed");
        }
    } else {
        sp_error(SP_FANOTIFY, "Failed to append fanotify event to list, invalid arguments");
    }
}

void FanotifyEvents::eventListDealloc(fanotify_event_list_t* event_list)
{
    if (event_list != NULL) {
        int i;

        for (i = 0; i < event_list->size; i++) {
            free(event_list->events[i]);
        }
        free(event_list);
    }
}