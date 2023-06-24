#include "include/FileSystem.hpp"
#include <ctype.h>

FileSystem::FileSystem()
{
    dir_list = NULL;
    dir_list_size = 0;
}

FileSystem::~FileSystem()
{

}

int FileSystem::subDirRecursive(char* parent_dir)
{
    int ret = -1;
    DIR * d;

    d = opendir (parent_dir);
    if (d == NULL) {
        sp_error(SP_FS_UTIL, "Directory %s does not exist", parent_dir);
        goto done;
    }

    while (1) {
        struct dirent * entry;
        const char * d_name;

        /* "Readdir" gets subsequent entries from "d". */
        entry = readdir (d);
        if (! entry) {
            /* There are no more entries in this directory, so break
               out of the while loop. */
            break;
        }
        d_name = entry->d_name;

        if (entry->d_type & DT_DIR) {

            /* Check that the directory is not "d" or d's parent. */
            
            if (strcmp (d_name, "..") != 0 &&
                strcmp (d_name, ".") != 0) {
                char path[PATH_MAX];
    
                dir_list_size++;
                if (parent_dir[strlen(parent_dir) - 1] == '/') {
                    parent_dir[strlen(parent_dir) - 1] = '\0';
                }

                snprintf (path, PATH_MAX, "%s/%s", parent_dir, d_name);

                dir_list = (char**)realloc(dir_list, dir_list_size * sizeof(char*));
                if (dir_list == NULL) {
                    sp_error(SP_FS_UTIL, "Memory allocation failed");
                    goto done;
                }

                dir_list[dir_list_size - 1] = (char*)malloc(PATH_MAX * sizeof(char));
                if (dir_list[dir_list_size - 1] == NULL) {
                    sp_error(SP_FS_UTIL, "Memory allocation failed");
                    goto done;
                }

                strcpy(dir_list[dir_list_size - 1], path);
                sp_debug(SP_FS_UTIL, "Sub-dir: %s", path);
                subDirRecursive(path);
            }
	    }
    }
    closedir(d);
    ret = 0;

done:
    return ret;
}

void FileSystem::getFilepathFromEvent(char *filepath, fanotify_event_response_t *event)
{
    if (event->event_path[0] != '\0' && event->file_tampered[0] != '\0') {
        strcpy(filepath, event->event_path);
        if (filepath[strlen(filepath) - 1] != '/') {
            strcat(filepath, "/");
        }
        strcat(filepath, event->file_tampered);
    }
}

void* FileSystem::dirsActionLockWithInterval(void *vargp)
{
    thread_block_fileop_param_t *param = (thread_block_fileop_param_t*)vargp;
    struct timespec block_start = {0};

    sp_info(SP_FS_UTIL, "Block file operations started");

    param->service->spawnClientStateSet(false);

    if (clock_gettime(CLOCK_MONOTONIC, &block_start) == 0) {
        while(1) {
            struct timespec elapsed = {0};

            /* if clock_gettime above succeeds this one will likely be successful, no need to check for errors */
            clock_gettime(CLOCK_MONOTONIC, &elapsed);
            if ((int)difftime(elapsed.tv_sec, block_start.tv_sec) >= BLOCK_DURATION) {
                param->service->authStateSet(true);

                if (param->protected_dirs != NULL && param->num_dirs > 0) {
                    for (int i = 0; i < param->num_dirs; i++) {
                        if (SYSTEM_CMD(DIR_ATTR_CMD_FMT, DIR_UNBLOCK_OPT, param->protected_dirs[i]) == -1) {
                            sp_error(SP_FS_UTIL, "Failed to unblock file operations on directory %s", param->protected_dirs[i]);
                        }
                    }
                }
                param->service->authStateSet(false);
                param->service->maliciousStateSet(false);
                param->service->spawnClientStateSet(true);

                break;
            }
        }
    } else {
        /*replace with logging later*/
        sp_error(SP_FS_UTIL, "clock_gettime error, %s", strerror(errno));
        sp_error(SP_FS_UTIL, "Unable to block directories");
    }

    FileSystem::array2DFree((const void**)param->protected_dirs, param->num_dirs);
    free(param);

    sp_info(SP_FS_UTIL, "Block file operations ended");

    return NULL;
}

int FileSystem::getDirFd(const char* dir)
{
    int ret = -1;
    DIR *d = opendir(dir);
    if (!d) {
        sp_error(SP_FS_UTIL, "directory %s does not exist", dir);
    }

    ret = dirfd(d);
    if (ret == -1) {
        if (errno == ENOTSUP) {
            sp_error(SP_FS_UTIL, "Assigning file descriptor to directory is not supported, exiting...");
            exit(EXIT_FAILURE);
        } else {
            sp_error(SP_FS_UTIL, "Failed to get directory file descriptor, %s\n", strerror(errno));
        }
    }
    closedir(d);

    return ret;
}

int FileSystem::openDirByFd(const int dirfd, const char* pathname, int flags)
{
    int ret = openat(dirfd, pathname, flags);
    if (ret == -1) {
        sp_error(SP_FS_UTIL, "openat failed, %s", strerror(errno));
    }

    return ret;
}

int FileSystem::getSubDirs(char ***sub_dirs, int *size, char* parent_dir)
{
    int ret = -1;

    dir_list = (char**)malloc(dir_list_size * sizeof(char*));
    if (dir_list == NULL) {
        sp_error(SP_FS_UTIL, "Memory allocation failed");
        goto done;
    }

    ret = subDirRecursive(parent_dir);
    if (ret == -1) {
        goto done;
    }

    *sub_dirs = dir_list;
    *size = dir_list_size;

    ret = 0;
done:
    dir_list_size = 0;
    dir_list = NULL;

    return ret;
}

bool FileSystem::dirExist(const char *dir)
{
    bool ret = false;
    struct stat stats;

    stat(dir, &stats);

    if (S_ISDIR(stats.st_mode)) {
        ret = true;
    }

    return ret;
}

bool FileSystem::fileExist(const char* filepath)
{
    bool ret = false;

    if (access(filepath, F_OK) == 0) {
        ret = true;
    } else {
        sp_error(SP_FS_UTIL, "File :%s does not exist", filepath);
    }

    return ret;
}

bool FileSystem::fileIsELF(const char* filepath)
{
    bool ret = false;
    int file_fd;
    char buf[5];
    struct stat file_stat;

    if (stat(filepath, &file_stat) < 0) {
        sp_error(SP_FS_UTIL, "Failed to stat for file %s, %s", filepath, strerror(errno));
        goto done;
    }

    if (!S_ISREG(file_stat.st_mode)) {
        sp_info(SP_FS_UTIL, "%s is not a file, skip ELF test", filepath);
        goto done;
    }

    file_fd = open(filepath, O_RDONLY);
    if (file_fd < 0) {
        sp_error(SP_FS_UTIL, "Cannot open file %s, %s", filepath, strerror(errno));
        goto done;
    }

    if (read(file_fd, buf, 4) < 0) {
        sp_error(SP_FS_UTIL, "Read failed for tile %s, %s", filepath, strerror(errno));
        goto done;
    }

    /* 0x7f is the hexcode for any executable files */
    if (buf[0] == 0x7f && buf[1] == 'E' && buf[2] == 'L' && buf[3] == 'F') {
        ret = true;
    }
    
done:
    return ret;
}

bool FileSystem::fileEmpty(const char* filepath)
{
    bool ret = true;
    long size = 0;
    FILE *fp = fopen(filepath, "r");
    if (fp != NULL) {
        fseek(fp, 0, SEEK_END);
        size = ftell(fp);
        if (size > 0) {
            ret = false;
        }
        fclose(fp);
    }

    return ret;
}

int FileSystem::procKill(const char *proc_name)
{
    int ret = -1;
    FILE *fp;
    char popen_cmd[PATH_MAX];
    char buf[PATH_MAX];
    pid_t proc_id;

    snprintf(popen_cmd, PATH_MAX, PROC_GREP_PID_CMD_FMT, proc_name);
    
    fp = popen(popen_cmd, "r");
    if (fp == NULL) {
        sp_error(SP_FS_UTIL, "Failed to run popen command");
        goto done;
    }

    if (fgets(buf, sizeof(buf), fp) == NULL) {
        sp_error(SP_FS_UTIL, "Failed to read from buffer");
        goto done;
    }
    
    proc_id = strtoul(buf, NULL, 10);
    if (proc_id == 0) {
        sp_error(SP_FS_UTIL, "Failed to get process id from buf");
        goto done;
    }

    if (kill(proc_id, SIGSEGV) == -1) {
        sp_error(SP_FS_UTIL, "Failed to kill process %s, error %s", proc_name, strerror(errno));
        goto done;
    }

    ret = 0;
done:
    pclose(fp);
    return ret;
}

void FileSystem::array2DFree(const void** arr, const int size)
{
    if (arr != NULL) {
        for (int i = 0; i < size; i++) {
            free((void*)arr[i]);
        }
        free(arr);
    }
}

unsigned char* FileSystem::getFileContent(const char *path)
{
    FILE *f;
    long numbytes;
    unsigned char *content = NULL;

    f = fopen(path, "r");
    if (f != NULL) {
        fseek(f, 0L, SEEK_END);
        numbytes = ftell(f);
        fseek(f, 0L, SEEK_SET);

        content = (unsigned char*)calloc(numbytes, sizeof(char));

        fread(content, sizeof(unsigned char), numbytes, f);
    } else {
        sp_error(SP_FS_UTIL, "Failed to open file %s to store content", path);
    }
    fclose(f);

    return content;
}

mode_t FileSystem::getFileAttrib(const char* filepath)
{
    mode_t ret;
    struct stat sb;
    if (stat(filepath, &sb) == 0) {
        ret = sb.st_mode;
    } else {
        sp_error(SP_FS_UTIL, "Failed to get file attribute, stat error %s", strerror(errno));
    }

    return ret;
}

mode_t FileSystem::getDirAttrib(const std::string* path)
{
    return getFileAttrib(path->c_str());
}

unsigned char* FileSystem::getFileSHA256(const char *filepath)
{
    unsigned char* ret = NULL;
    FILE *fp;
    char popen_cmd[PATH_MAX];
    char buf[SHA256_HASH_LEN + 1];

    snprintf(popen_cmd, PATH_MAX, SHA256_HASH_FILE_CMD_FMT, filepath);

    fp = popen(popen_cmd, "r");
    if (fp == NULL) {
        sp_error(SP_FS_UTIL, "Failed to run popen command");
        goto done;
    }

    if (fgets(buf, sizeof(buf), fp) == NULL) {
        sp_error(SP_FS_UTIL, "Failed to read from buffer");
        goto done;
    }

    buf[SHA256_HASH_LEN] = '\0';

    ret = (unsigned char*)calloc(SHA256_HASH_LEN + 1, sizeof(unsigned char));
    if (ret == NULL) {
        sp_error(SP_FS_UTIL, "Failed to allocate memory");
        goto done;
    }

    strcpy((char*)ret, buf);
    ret[SHA256_HASH_LEN] = '\0';
done:
    return ret;
}

std::vector<protected_file_t*> FileSystem::getFilesByDir(const char* dir)
{
    std::vector<protected_file_t*> ret;
    DIR* d;
    struct dirent *dr;

    d = opendir(dir);
    if (d) {
        while ((dr = readdir(d)) != NULL) {
            if (dr->d_type == DT_REG) {
                char filepath[PATH_MAX];
                protected_file_t* pf = (protected_file_t*)calloc(sizeof(protected_file_t), 1);
                
                if (dir[strlen(dir) - 1] != '/') {
                    sprintf(filepath, "%s/%s", dir, dr->d_name);
                } else {
                    sprintf(filepath, "%s%s", dir, dr->d_name);
                }

                if (pf != NULL) {
                    strcpy(pf->file_path, filepath);
                    pf->attrib = getFileAttrib(filepath);
                    pf->content = getFileContent(filepath);
                    pf->sha256 = getFileSHA256(filepath);
                    pf->is_elf = fileIsELF(filepath);

                    ret.push_back(pf);
                }
            }
        }
        closedir(d);
    } else {
        sp_error(SP_FS_UTIL, "Failed to get files for directory %s, %s", dir, strerror(errno));
    }

    return ret;
}

void FileSystem::restoreFileState(const protected_file_t* file)
{
    REWRITE_FILE(file->file_path, file->content);
    if (chmod(file->file_path, file->attrib) == -1) {
        sp_error(SP_FS_UTIL, "Failed to set permissions for file %s. Error %s\n", file->file_path, strerror(errno));
    }
}

fs_util_file_handle_resp_t FileSystem::getEventLocation(fanotify_event_response_t *response, 
                                                        int mount_fd, 
                                                        struct file_handle *file_handle, 
                                                        const unsigned char *file_name, 
                                                        int flags)
{
    int event_fd;
    char path[PATH_MAX + 1];
    char fdpath[32];
    ssize_t linklen;
    struct stat sb;
    fs_util_file_handle_resp_t ret = FS_UTIL_FILE_HANDLE_ERR;

    event_fd = open_by_handle_at(mount_fd, file_handle, O_RDONLY);
    if (event_fd == -1) {
        if (errno == ESTALE) {
            /**
             *  File handle no longer available could be due to the file just got deleted, 
             *  so we would still want to send back an event
             */
            response->detect = FANOTIFY_EVENT_DETECTED;
            response->fileop = FAN_DELETE;

            snprintf(response->resp, GENERAL_STR_MAX_LEN, "%s", "File handle is no longer valid. File has been deleted");
            response->err_msg[0] = '\0';
            ret = FS_UTIL_FILE_HANDLE_NOT_VALID;
            goto done;
        } else {
            response->detect = FANOTIFY_EVENT_ERR;
            response->fileop = -1;
            snprintf(response->err_msg, GENERAL_STR_MAX_LEN, "%s", "open_by_handle_at error");
            ret = FS_UTIL_FILE_HANDLE_ERR;
            goto done;
        }
    }

    sprintf(fdpath, "/proc/self/fd/%d", event_fd);
    linklen = readlink(fdpath, path, sizeof(path) - 1);
    if (linklen == -1) {
        snprintf(response->err_msg, GENERAL_STR_MAX_LEN, "%s", "readlink error");
    }
    path[linklen] = '\0';
    /**
     *  If the event type is FAN_CREATE or FAN_DELETE, fanotify will not return the file being created or deleted, 
     *  but rather the parent directory of it. Hence, the value of path may or may not contain the file name
     */
    snprintf(response->event_path, PATH_MAX + 1, "%s", path);
    
    if (file_name) {
        (void)fstatat(event_fd, (const char*)file_name, &sb, 0);
        strcpy(response->file_tampered, (const char*)file_name);
    }

    ret = FS_UTIL_FILE_HANDLE_SUCCESS;
done:
    return ret;
}

bool FileSystem::pathIsAbsolute(const char* path, char* abs_home_path)
{
    bool ret = false;
    int i = 0;
    char path_first_char = path[i];

    /* check in case first few characters are just white space */
    while(isspace(path_first_char)) {
        i++;
        path_first_char = path[i];
    }

    strcpy(abs_home_path, path + i);
    
    if (path_first_char == '~' || path_first_char == '/') {
        if (path_first_char == '~') {
            strcpy(abs_home_path, "/home/");
            strcat(abs_home_path, getlogin());
            strcat(abs_home_path, path + 1 + i);
        }
        ret = true;
    }

    return ret;
}