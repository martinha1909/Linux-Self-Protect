#ifndef FILEMANAGER_HPP
#define FILEMANAGER_HPP

#include <string>
#include <unordered_map>
#include <vector>
#include <limits.h>
#include <fstream>
#include <algorithm>
#include "../../FanotifyEvents/include/FanotifyEvents.hpp"
#include "../../CLI_Interface/include/CLI_Interface.hpp"
#include "../../QueryHistory/include/QueryHistory.hpp"
#include "FileManagerCallbacks.hpp"
#include "FileManagerBackups.hpp"

/* dir operations */
#define DIR_ATTRIB_CHANGED(x)   (x == (FAN_ONDIR | FAN_ATTRIB))
#define SUB_DIR_MOVED_TO(x)     (x == (FAN_ONDIR | FAN_MOVED_TO))
#define SUB_DIR_MOVED_FROM(x)   (x == (FAN_ONDIR | FAN_MOVED_FROM))
#define SUB_DIR_CREATE(x)       (x == (FAN_ONDIR | FAN_CREATE)) // sub dir create only since protected dir create will be done via config list
#define SUB_DIR_DELETED(x)      (x == (FAN_ONDIR | FAN_DELETE))

/* file operations */
#define FILE_MOVED_FROM(x)      (x == FAN_MOVED_FROM)
#define FILE_MOVED_TO(x)        (x == FAN_MOVED_TO)
#define FILE_ATTRIB_CHANGED(x)  (x == FAN_ATTRIB)
#define FILE_IS_DELETED(x)      (x == FAN_DELETE || FILE_MOVED_FROM(x))
#define FILE_IS_MODIFIED(x)     (x == FAN_CLOSE_WRITE)
#define FILE_IS_CREATED(x)      (x == FAN_CREATE || FILE_MOVED_TO(x))

#define TAMPERED(x)             (FILE_IS_DELETED(x) ||\
                                 FILE_IS_MODIFIED(x) ||\
                                 FILE_IS_CREATED(x) ||\
                                 FILE_ATTRIB_CHANGED(x) ||\
                                 SUB_DIR_DELETED(x) ||\
                                 SUB_DIR_CREATE(x) ||\
                                 SUB_DIR_MOVED_FROM(x) ||\
                                 SUB_DIR_MOVED_TO(x) ||\
                                 DIR_ATTRIB_CHANGED(x))

#define EVENT_DETECTED(x)       (x == FANOTIFY_EVENT_DETECTED)
#define ERROR_DETECTED(x)       (x == FANOTIFY_EVENT_ERR)

typedef struct fanotify_event_response fanotify_event_response_t;
typedef struct query_history_record query_history_record_t;
typedef __u32 __permission;
class FileManagerCallback;
class FanotifyEvents;
class SelfProtectService;
class QueryHistory;
class Trust;
class FileSystem;

typedef enum fs_action_e {
    FS_ACTION_NONE,
    FS_PROTECTED_DIR_DELETED_ACTION,
    FS_PROTECTED_DIR_ATTRIB_CHANGED_ACTION,
    FS_SUB_DIR_DELETED_ACTION,
    FS_SUB_DIR_CREATED_ACTION,
    FS_SUB_DIR_ATTRIB_CHANGED_ACTION,
    FS_FILE_DELETED_ACTION,
    FS_FILE_CREATED_ACTION,
    FS_FILE_MODIFIED_ACTION,
    FS_FILE_ATTRIB_CHANGED_ACTION
} fs_action_t;

typedef struct new_change {
    fs_action_t action;
    void *action_param;
    void *update_mem_param;
    void (*exec_cb)(void* ctx, 
                    void* action_cb_param, 
                    void* update_mem_cb_param,
                    bool apply,
                    int action);
} new_change_t;

class FileManager {
private:
    FileManagerBackups backup;
    FileManagerCallback* fmcb;
    FanotifyEvents* fan;
    QueryHistory *hist;
    Trust* trust;
    FileSystem* fs;
    pthread_mutex_t fm_mutex;
    protected_dir_t default_protected_dir;
    std::vector<new_change_t> new_changes;
    /**
     * This data structure maps a protected directory to a list of its sub-directories
     * by default this will always have size of 1 and contain our default config dir and its sub-dirs
     */
    std::unordered_map<protected_dir_t, std::vector<protected_dir_t>> protected_dirs;

    /**
     * Loads all directories specified in the config list file that need to be watched,
     * the sub-directories of all these directories will also be stored and watched
     */
    void loadProtectedDirs();
    /**
     * Checks if a given directory is a top-level protected parent dir in the config list
     * 
     * @return true the directory given is a top-level protected dir, false otherwise
     */
    bool dirIsProtectedParentDir(const char* dir);
    /**
     * Stores the content of a directory. This could be either the protected directory or its sub-directory
     * 
     * @param path_to_dir[in]   the directory whose content should be stored to memory
     * @param files[out]        list of files under the specified directory to be populated
     */
    void storeDirContent(const char *path_to_dir, std::vector<protected_file_t*>* files);
    /**
     * Removes the stale protected directories that have been removed from config file list
     * 
     * @param new_protected_dirs   a list containing all the new protected directories input in the config file list
     */
    void removeStaleProtectedDirs(std::vector<std::string>* new_protected_dirs);
    /**
     * Creates a parameter to be passed in to update_mem_cb when a token is entered correctly
     * 
     * @note this function will allocate memory and generates a parameter based on the current action, 
     *       so the variable current_action has to be set before this function is called
     * 
     * @param action            current tampering action
     * @param protected_dir     a protected directory that is specified in the config list
     * @param sub_dir           a sub-directory of a protected directory specified in the config list
     *                          this variable is only used if the current action is FS_SUB_DIR_DELETED_ACTION, 
     *                          otherwise NULL is expected
     * @param update_mem_file   a file that contains all the new information to be updated once the token is entered correctly
     * @param old_file          old state of the file before changes
     * 
     * @return                  a pointer to the allocated block of memory on success, NULL on error
     */
    void* updateMemAlloc(fs_action_t action,
                         const char* protected_dir,
                         const char* sub_dir,
                         const protected_file_t* update_mem_file,
                         protected_file_t* old_file);
    /**
     * Adds a new change to a list of new changes
     * 
     * @param action              current tampering action
     * @param action_param        parameter to pass to action_cb
     * @param update_mem_param    parameter to pass to update_mem_cb
     * 
     * @return                      a pointer to the allocated block of memory on success, NULL on error
     */
    void addNewChangeFromAction(fs_action_t action,
                                void *action_param,
                                void *update_mem_param);
    /**
     * Looks up a protected file in memory
     * @note DO NOT pass the return value of this function to free()
     * 
     * @param pd                     parent protected directory of the file lookup
     * @param filepath               file lookup path
     * 
     * @return                      a reference to the file if found in memory, NULL otherwise
     */
    protected_file_t* protectedFileLookup(const protected_dir_t pd, const char* filepath);
    /**
     * Looks up a protected directory in memory
     * @note DO NOT pass the return value of this function to free()
     * 
     * @param pd                     parent protected directory of the file lookup
     * @param lookup_dir             file lookup path
     * 
     * @return                      a reference to the protected directory if found in memory, NULL otherwise
     */
    protected_dir_t* protectedDirLookup(const protected_dir_t pd, const char* lookup_dir);
    /**
     * Gets a list of protected files by a sub-directory
     * 
     * @param ppd       parent protected directory
     * @param sub_dir   sub-directory to lookup
     * 
     * @return          a list of protected file references
     */
    std::vector<protected_file_t*> getProtectedFilesBySubDir(const protected_dir_t ppd, char* sub_dir);
    /**
     * Stores a sub-directory deleted action
     * 
     * @param tampered_path     path to deleted sub-directory
    */
    void storeSubDirDeleteChange(const char* tampered_path);
    /**
     * Stores a sub-directory created action
     * 
     * @param tampered_path     path to created sub-directory
    */
    void storeSubDirCreateChange(const char* tampered_path);
public:
    FileManager(std::string filepath, 
                FanotifyEvents* fanotifyEvents, 
                QueryHistory* queryHistory,
                Trust* trust);
    ~FileManager();

    /**
     * Gets all protected directories
     *
     * @return list of all protected directories
     */
    std::unordered_map<protected_dir_t, std::vector<protected_dir_t>>* getProtectedDirs();
    /**
     * Gets remote backup from file sharing server
     *
     * @return FileManagerBackups object
     */
    FileManagerBackups* getBackup();
    /**
     * Gets number of new changes stored
     *
     * @return size of new_changes
     */
    size_t getNewChangesSize();
    /**
     * Gets the protected directory from a sub-directory
     * 
     * @param sub_dir     sub-directory to determine it parent protected directory
     * 
     * @return a protected directory, which should match one of the entries in config list file
     */
    protected_dir_t getProtectedDirFromSubDir(const char* sub_dir);
    /**
     * Unmarks a protected directory and all of its sub-directories
     * 
     * @param removed_protected_dir     protected directory to be unmarked by fanotify
     */
    void unmarkProtectedDirAndSubDirs(std::string removed_protected_dir);
    /**
     * Marks a protected directory and all of its sub-directories
     * 
     * @param added_protected_dir       protected directory to be marked by fanotify
     */
    void markProtectedDirAndSubDirs(std::string added_protected_dir);
    /**
     * Blocks file operation on a watched directory. Currently timeout period is defined by BLOCK_DURATION
     *
     * @param service current running service to change coonfigurations
     */
    void blockFileOp(SelfProtectService* service);
    /**
     * Unblocks file operation on a watched directory
     */
    void unblockFileOp();
    /**
     * clear new_changes
     */
    void clearStoredChanges();
    /**
     * Stores all the new changes to a list to be determined if they should be applied later
     * 
     * @note During this phase, our service will need access to the files or directories that were modified, which will 
     *       trigger the permission events in accessing these files. In order to give access, we need to change the permission
     *       before we read in the new changes, hence, a mutex lock must be called before this permission change occurs
     * 
     * @param event                     fanotify event response
     */
    void storeNewChanges(fanotify_event_response_t *event);
    /**
     * Reverts all the new changes
     * Basically, reverts all content inside a protected directory to its original state
     * 
     * @note During this phase, our service will need access to the files or directories that were modified to revert state, which will 
     *       trigger the permission events in accessing these files. In order to give access, we need to change the permission
     *       before we read in the new changes, hence, a mutex lock must be called before this permission change occurs
     */
    void revertNewChanges();
    /**
     * Apply the new changes and updates hashmap in memory. 
     * This function is to be called when token verification process is correct. 
     * 
     * @param history_record[out]    tampering locations of history record to be populated
     */
    void applyNewChangesAndUpdateMemory(query_history_record_t* history_record);
    /**
     * Removes a protected directory from memory.
     * 
     * @param removing_dir         protected dir to be removed from memory. 
     *                             Has to be one of the directories specified in config list file
     */
    void removeProtectedDirFromMem(protected_dir_t* removing_dir);
    /**
     * Updates a protected directory attribute from memory.
     * 
     * @param old_ppd         original parent protected dir in memory
     * @param new_ppd         parent protected dir whose attribute was changed
     */
    void updateProtectedDirAttribFromMem(protected_dir_t* old_ppd, protected_dir_t* new_ppd);
    /**
     * Removes a sub-directory of a protected directory from memory
     * 
     * @param deleted_sub_dir         sub-directory to be removed from mem
     * @param parent_protected_dir    matching parent protected directory specified in the config list file
     */
    void removeSubDirFromMem(protected_dir_t* deleted_sub_dir, protected_dir_t* parent_protected_dir);
    /**
     * Adds a sub-directory of a protected directory to memory
     * 
     * @param deleted_sub_dir         sub-directory to be added to mem
     * @param parent_protected_dir    matching parent protected directory specified in the config list file
     */
    void addSubDirToMem(const protected_dir_t* ppd, protected_dir_t* new_sub_dir);
    /**
     * Updates a sub directory attribute from memory.
     * 
     * @param ppd                 protected parent directory
     * @param new_sub_dir         sub-directory whose attribute was changed
     * @param old_sub_dir         original sub-directory in memory
     */
    void updateSubDirAttribFromMem(protected_dir_t* ppd, protected_dir_t* old_sub_dir, protected_dir_t* new_sub_dir);
    /**
     * Removes a protected file from memory
     * 
     * @param removing_file           file to be removed from mem
     * @param parent_protected_dir    matching parent protected directory specified in the config list file
     */
    void removeProtectedFileFromMem(const char *parent_protected_dir, protected_file_t *removing_file);
    /**
     * Adds a protected file to memory
     * 
     * @param created_file            file to be added to mem
     * @param parent_protected_dir    matching parent protected directory specified in the config list file
     */
    void addProtectedFileToMem(const char* parent_protected_dir, protected_file_t *created_file);
    /**
     * Modifies the content of a protected file from memory
     * 
     * @param modified_file           file to be modified from mem
     * @param parent_protected_dir    matching parent protected directory specified in the config list file
     */
    void modifyProtectedFileFromMem(const char *parent_protected_dir, protected_file_t *modified_file);
    /**
     * Changes the attribute of a protected file from memory
     * 
     * @param modified_file           file whose attribute will be updated in mem
     * @param parent_protected_dir    matching parent protected directory specified in the config list file
     */
    void changeProtectedFileAttribFromMem(const char *parent_protected_dir, protected_file_t *modified_file);
    /**
     * Removes all protected directory except our default config directory from memory
     */
    void removeAllProtectedDirsExceptConfig();
    /**
     * Adds or removes protected directories from memory
     * This function is used when config list file is updated
     * 
     */
    void addOrRemoveProtectedDirs();
    /**
     * Frees the allocated memory used in storedNewChanges.
     * This function is only to be called if applyNewChanges is not call, otherwise unexpected behaviour could happen
     * 
     * @param history_record[out]    tampering locations of history record to be populated
     */
    void discardNewChanges(query_history_record_t* history_record);
    /**
     * Lcoks or unlocks all file operation from directories in memory
     * 
     * @param do_lock   locks if true, unlocks if false
     */
    void allDirActionLock(bool do_lock);
    void allDirActionLockFromConfig();
    /**
     * Checks if a file is created by a text editor like vim or nano, usually has .swp or swx extensions
     * 
     * @param file   name of the file to be checked
     * 
     * @return  true if a file contains extensions .swp or .swx, false otherwise
     */
    bool fileCreatedByEditor(const char* file);
    /**
     * Duplicates a protected_file_t struct by doing dynamic memory allocation. 
     * The caller of this function must pass to free() after use
     *
     * @param dup_file   protected file to be duplicated
     * 
     * @return           duplicate version of protected file
     */
    protected_file_t* protectedFileDup(const protected_file_t* dup_file);
    /**
     * Duplicates a protected_dir_t struct by doing dynamic memory allocation. 
     * The caller of this function must pass to free() after use
     *
     * @param dup_dir    protected dir to be duplicated
     * 
     * @return           duplicate version of protected dir
     */
    protected_dir_t* protectedDirDup(const protected_dir_t* dup_dir);
    /**
     * Gets a string representation of fs_action_e enum
     * 
     * @note this string is dynamically allocated, so the caller needs to free after use
     * 
     * @param   action  current action
     *
     * @return string representation of the current action
     */
    char* fsStrAction(fs_action_t action);
    /**
     * Deallocates a dynamically allocated protected_file_t
     *
     * @param event   protected file to be deallocated
     */
    void protectedFileDealloc(protected_file_t* file);
    /**
     * Prints a protected_file_t
     * 
     * @note This function is only for debugging purposes only
     */
    void protectedFilePrint(protected_file_t* file);
    /**
     * Gets default_protected_dir
     *
     * @return default_protected_dir
     */
    protected_dir_t* getDefaultProtectedDir();
    /**
     * Prints all the content inside protected_dirs
     * 
     * @note This function is only for debugging purposes only
     */
    void printAllProtectedDirs();
    /**
     * fs getter
     *
     * @return fs
     */
    FileSystem* getFileSystem();
};

#endif
