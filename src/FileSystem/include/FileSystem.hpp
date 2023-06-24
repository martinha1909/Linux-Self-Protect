#ifndef FS_UTIL_H
#define FS_UTIL_H

#include <sys/stat.h>
#include <libgen.h>
#include <signal.h>
#include <pwd.h>
#include <cstdlib>
#include <cstring>
#include "../../FanotifyEvents/include/FanotifyEvents.hpp"
#include "../../SelfProtectService/include/SpLogger.hpp"
#include "../../SelfProtectService/include/SpConstants.hpp"
#include "../../FileManager/include/FileManager.hpp"
#include "../../pthread/include/pthreadUtil.hpp"

/* file system commands */
#define DIR_ATTR_CMD_FMT                "sudo chattr -R %s %s"
#define DIR_CREATE_CMD_FMT              "mkdir %s"
#define DIR_CREATE_RECURSIVE_CMD_FMT    "mkdir -p %s"
#define DIR_DELETE_CMD_FMT              "sudo rm -rf %s"
#define DIR_CHMOD_CMD_FMT               "sudo chmod -R %s %s"
#define FILE_REMOVE_CMD_FMT             "rm %s"
#define FILE_CREATE_CMD_FMT             "touch %s"
#define FILE_CHMOD_CMD_FMT              "sudo chmod %s %s"
#define FILE_ATTR_CMD_FMT               "sudo chattr %s %s"
#define PROC_GREP_PID_CMD_FMT           "pgrep %s"
#define HIDDEN_SW_FILE_REMOVE_CMD_FMT   "sudo find %s -name \"*.sw*\" -type f -delete"

/* sha256 commands */
#define SHA256_HASH_STR_CMD_FMT         "echo -n \"%s\" | sha256sum | awk '{print $1}'"
#define SHA256_HASH_FILE_CMD_FMT        "sha256sum %s | awk '{print $1}'"

/* process and service related commands */
#define SYSD_SERVICE_START_CMD_FMT      "sudo systemctl start %s"
#define SYSD_SERVICE_RESTART_CMD_FMT    "sudo systemctl restart %s"
#define SYSD_SERVICE_STOP_CMD_FMT       "sudo systemctl stop %s"
#define SYSD_SERVICE_ACTIVE_CMD_FMT     "sudo systemctl is-active %s"
#define SYSD_SERVICE_EXISTS_CMD_FMT     "sudo systemctl list-units --full -all | grep %s"
#define PROCESS_EXISTS_CMD_FMT          "pidof -x %s > /dev/null"
#define PROCESS_ID_CMD_FMT              "pidof %s"

/* shell command options */
#define DIR_UNBLOCK_OPT         "-i"
#define DIR_BLOCK_OPT           "+i"
#define IMMUTABLE_OPT           "a-rwx"
#define ROOT_EXEC_PERM_OPT      "u+x"
#define ROOT_READ_PERM_OPT      "u+r"
#define ROOT_WRITE_PERM_OPT     "u+w"
#define RW_PERM_OPT             "a+rw"
#define READ_ONLY_OPT           "a-rw"

#define BLOCK_DURATION          20 /* 10s to test, change to 1800 for 30 mins */
#define UNBLOCK_DURATION        20 /* 10s to test, change to 300 (5 mins) to mimic sudo behaviour */

#define SHA256_HASH_LEN         64

/**
 * Invoke a system command based on the formatted command passed
 * Works similar to printf(), if a formatted string is sent, 
 * its matching formatting specifier will also need to be passed
 *
 * @param fmt formatted command
 * 
 * @return 0 on success, -1 on error
 */
#define SYSTEM_CMD_VA(fmt, ...) ({\
                                    int ret = -1;\
                                    char cmd_buf[GENERAL_STR_MAX_LEN + PATH_MAX];\
                                    snprintf(cmd_buf, GENERAL_STR_MAX_LEN + PATH_MAX, fmt, ##__VA_ARGS__);\
                                    sp_debug(SP_FS_UTIL, "issuing system command: %s", cmd_buf);\
                                    ret = system(cmd_buf);\
                                    if (ret == -1) {\
                                        sp_error(SP_FS_UTIL, "Failed to issue system command: %s", cmd_buf);\
                                    }\
                                    ret;\
                                })

#define SYSTEM_CMD(fmt, ...)    SYSTEM_CMD_VA(fmt, ##__VA_ARGS__)

#define REWRITE_FILE(path, content)\
                                {\
                                    FILE *fp;\
                                    fp = fopen(path, "w");\
                                    if (fp) {\
                                        fprintf(fp, "%s", content);\
                                    } else {\
                                        sp_error(SP_FS_UTIL, "Failed to rewrite file %s", path);\
                                    }\
                                    fclose(fp);\
                                }

#define HIDDEN_CURRENT_DIR(d)   (d[0] == '.' && d[1] == '\0')
#define HIDDEN_PREV_DIR(d)      (d[0] == '.' && d[1] == '.' && d[2] == '\0')
#define DIR_IS_HIDDEN(d)        (HIDDEN_CURRENT_DIR(d) || HIDDEN_PREV_DIR(d))

typedef struct fanotify_event_response fanotify_event_response_t;
typedef struct protected_file protected_file_t;
typedef struct exec_elf_file exec_elf_file_t;

typedef enum fs_util_file_handle_resp_e {
    FS_UTIL_FILE_HANDLE_ERR,
    FS_UTIL_FILE_HANDLE_SUCCESS,
    FS_UTIL_FILE_HANDLE_NOT_VALID,
} fs_util_file_handle_resp_t;

typedef enum sysd_service_status_e {
    SYSD_SERVICE_ERROR,
    SYSD_SERVICE_NOT_EXIST,
    SYSD_SERVICE_INACTIVE,
    SYSD_SERVICE_ACTIVE
} sysd_service_status_t;

/* this class is a helper class to get filesystem information */
class FileSystem {
private:
    char** dir_list;
    int dir_list_size;

    /**
     * Gets all sub-directories of a directory recursively
     *
     * @param parent_dir directory to retrieve all sub-directories from
     * 
     * @return           0 on success, -1 on error
     */
    int subDirRecursive(char* parent_dir);
public:
    FileSystem();
    ~FileSystem();
    /**
     * concatnate event->event_path and event->file_tampered to get the full absolute filepath
     *
     * @param filepath[out] aboslute filepath to be populated
     * @param event[in]     response received from fanotify
     */
    void getFilepathFromEvent(char* filepath, fanotify_event_response_t* event);
    /**
     * Immutate marked directories and their sub-directories. This function is handled by a different thread to avoid 
     * fanotify from idling. In other words, fanotify is still able to monitor directories while this function runs
     *
     * @param vargp directory paths to be immutated
     */
    static void* dirsActionLockWithInterval(void *vargp);
    /**
     * gets file descriptor of a directory stream. Only works if the operating system supports this
     *
     * @param dir   directory to retrieve file descriptor from
     * 
     * @return      file descriptor to the directory stream
     */
    int getDirFd(const char* dir);
    /**
     * open a directory to read based on a given directory stream file descriptor
     *
     * @param dirfd      directory file descriptor to be opened
     * @param pathname   path to directory
     * @param flags      flags for read write
     * 
     * @return           file descriptor of the opened directory
     */
    int openDirByFd(int dirfd, const char* pathname, int flags);
    /**
     * Gets sub directories of a directory. 
     *
     * @param sub_dirs[out]      pointer to a dimensional array, which is dynamically allocated. 
     *                           *sub_dirs will point to the beginning of a 2-D dynamically allocated string array
     *                           *sub_dirs[0] first index of the 2-D string array
     *                           *sub_dirs[0][0] first string of the 2-D string array
     * @param size[out]          size of the 2-D dynamically allocated array
     * @param parent_dir[in]     parent directory to get sub-directories
     * 
     * @return                   0 on success, -1 on error
     */
    int getSubDirs(char ***sub_dirs, int *size, char* parent_dir);
    /**
     * Checks if a directory exists
     *
     * @param parent_dir[out]    if a directory passed by path doesn't exist, this field will be populated with the parent path
     * @param path[in]           path to check for parent directory existence 
     * 
     * @return                   true if directory exists, false otherwise
     */
    bool dirExist(const char *dir);
    /**
     * Checks if a file exists
     *
     * @param filepath      path to file for checking
     * 
     * @return              true if file exists, false otherwise
     */
    bool fileExist(const char* filepath);
    /**
     * Checks if a file is an ELF executable
     *
     * @param filepath      path to file for checking
     * 
     * @return              true if file is an ELF executable, false otherwise
     */
    bool fileIsELF(const char* filepath);
    /**
     * Checks if a file is empty
     *
     * @param filepath      path to file for checking
     * 
     * @return              true if file is empty, false otherwise
     */
    bool fileEmpty(const char* filepath);
    /**
     * Checks if a path is relative or absolute.
     * @note an absolute path starts with a '/', or in the case of a '~', the path will be expanded to the user home path. 
     *       Any other paths are relative
     *
     * @param path[in]              path to be checked
     * @param abs_home_path[out]    path to be expanded from `~` if path[0] is '~'
     * 
     * @return          true if a path is absolute, false otherwise
     */
    bool pathIsAbsolute(const char* path, char* abs_home_path);
    /**
     * Kills a process
     *
     * @param proc_name     process name to kill
     * 
     * @return              0 on success, -1 on error
     */
    int procKill(const char *proc_name);
    /**
     * free memory allocation of a 2-D array.
     *
     * @param arr      2-D array to be freed. Note that this is of type void**,
     *                 so 2-D arrays of any type can be freed, just need to type cast to (const void**) before calling
     * @param size     size of the 2-D array
     */
    static void array2DFree(const void** arr, const int size);
    /**
     * Gets content of a file and store in a buffer 
     *
     * @param path path to file
     * 
     * @return     pointer to a byte buffer
     */
    unsigned char* getFileContent(const char* path);
    /**
     * Gets attribute of a file (permission bits)
     *
     * @param filepath path to file
     * 
     * @return         permissions value, can be used to send to chmod() system call
     */
    mode_t getFileAttrib(const char* filepath);
    /**
     * Gets attribute of a directory (permission bits)
     *
     * @param path     path to directory
     * 
     * @return         permissions value, can be used to send to chmod() system call
     */
    mode_t getDirAttrib(const std::string* path);
    /**
     * Gets sha256 digest of a file
     * 
     * @note this sha256 digest is populated into a buffer and must be freed after use
     *
     * @param filepath path to file
     * 
     * @return         pointer to a buffer that contains sha256 digest on success, NULL on error
     */
    unsigned char* getFileSHA256(const char* filepath);
    /**
     * Gets all files under a given directory
     * 
     * @note the caller of this function must free all the files that are returned by this function
     * 
     * @param dir   directory to retrieve files from
     * 
     * @return  a list of file references under the given directory
    */
    std::vector<protected_file_t*> getFilesByDir(const char* dir);
    /**
     * Reverts back to the state before a file was tampered
     *
     * @param file file to be restored
     */
    void restoreFileState(const protected_file_t* file);
    /**
     * Gets event path and file being tampered reported by fanotify
     *
     * @param response      fanotify response struct to be populated with event location
     * @param mount_fd      directory stream open file descriptor
     * @param file_handle   file_handle to be passed to open_by_handle_at() system call
     * @param file_name     file name to be populated to fanotify_event_response_t
     * @param flags         flags for read write
     * 
     * @return              file descriptor of the open handle passed by file_handle
     */
    fs_util_file_handle_resp_t getEventLocation(fanotify_event_response_t *response, 
                                                int mount_fd, 
                                                struct file_handle *file_handle, 
                                                const unsigned char *file_name, 
                                                int flags);
};
#endif