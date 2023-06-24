#ifndef FILE_MANAGER_CALLBACKS_H
#define FILE_MANAGER_CALLBACKS_H

#include <stdlib.h>
#include <limits.h>
#include <errno.h>
#include "../../FileSystem/include/FileSystem.hpp"
#include "../../SelfProtectService/include/SpLogger.hpp"

class FileManager;
typedef struct protected_file protected_file_t;
typedef struct protected_dir protected_dir_t;

typedef struct mem_protected_file {
    protected_file_t *file;
    protected_file_t *old_file;
    char parent_protected_dir[PATH_MAX];
} mem_protected_file_t;

typedef struct mem_protected_dir {
    protected_dir_t *old_dir;
    protected_dir_t *new_dir;
    protected_dir_t *ppd;
} mem_protected_dir_t;

class FileManagerCallback {
private:
    FileManager* memory;
    /**
     * Deletes a file pointed by varpg.
     * This function is a callback function, 
     * hence when setting up the vargp param needs to point to a file_deleted_cb_param_t struct
     * 
     * @note file_deleted_cb_param_t.filepath and file_deleted_cb_param_t.filedir must be dynamically allocated
     *
     * @param vargp file_deleted_cb_param_t pointed argument
     */
    void deleteFileCb(void* vargp, bool apply_new_changes);
    /**
     * Creates a file pointed by varpg.
     * This function is a callback function, 
     * hence when setting up the vargp param needs to point to a file_created_cb_param_t struct
     * 
     * @note file_created_cb_param_t.created_file must be dynamically allocated
     *
     * @param vargp file_created_cb_param_t pointed argument
     */
    void createFileCb(void *vargp, bool apply_new_changes);
    /**
     * Modifies a file pointed by varpg.
     * This function is a callback function, 
     * hence when setting up the vargp param needs to point to a file_modified_cb_param_t struct
     * 
     * @note file_modified_cb_param_t.modified_content must be dynamically allocated
     * 
     * @param vargp file_modified_cb_param_t pointed argument
     */
    void modifyFileCb(void *vargp, bool apply_new_changes);
    /**
     * Changes attribute of a file pointed by varpg.
     * This function is a callback function, 
     * hence when setting up the vargp param needs to point to a file_attrib_cb_param_t struct
     * 
     * @note vargp must be dynamically allocated
     *
     * @param vargp file_attrib_cb_param_t pointed argument
     */
    void changeFileAttribCb(void *vargp, bool apply_new_changes);
    /**
     * Deletes a dir pointed by varpg.
     * This function is a callback function, 
     * hence when setting up the vargp param needs to point to a protected_dir_t* variable
     * 
     * @note vargp must be dynamically allocated
     *
     * @param vargp protected_dir_t* pointed argument
     */
    void deleteDirCb(void *vargp, bool apply_new_changes);
    /**
     * Creates a dir pointed by varpg.
     * This function is a callback function, 
     * hence when setting up the vargp param needs to point to a protected_dir_t variable
     * 
     * @note vargp must be dynamically allocated
     *
     * @param vargp protected_dir_t* pointed argument
     */
    void createDirCb(void *vargp, bool apply_new_changes);
    /**
     * Changes a dir attribute pointed by varpg.
     * This function is a callback function, 
     * hence when setting up the vargp param needs to point to a protected_dir_t variable
     * 
     * @note vargp must be dynamically allocated
     *
     * @param vargp protected_dir_t* pointed argument
     */
    void changeDirAttribCb(void *vargp, bool apply_new_changes);
    /**
     * Removes a protected directory from memory in FileManager
     * 
     * @note vargp must be dynamically allocated
     *
     * @param vargp mem_remove_protected_dir_param_t* pointed argument
     */
    void removeProtectedDirFromMemCb(void *vargp, bool update_mem);
    /**
     * Updates attribute of a protected directory from memory in FileManager
     * 
     * @note vargp must be dynamically allocated
     *
     * @param vargp mem_protected_dir_t* pointed argument
     */
    void updateProtectedDirAttribFromMemCb(void* vargp, bool update_mem);
    /**
     * Adds a sub-directory to memory in FileManager
     * 
     * @note vargp must be dynamically allocated
     *
     * @param vargp mem_protected_dir_t* pointed argument
     */
    void addSubDirToMemCb(void *vargp, bool update_mem);
    /**
     * Removes a protected sub-directory from memory in FileManager
     * 
     * @note vargp must be dynamically allocated
     *
     * @param vargp mem_remove_sub_dir_param_t* pointed argument
     */
    void removeSubDirFromMemCb(void *vargp, bool update_mem);
    /**
     * Updates attribute of a sub-directory from memory in FileManager
     * 
     * @note vargp must be dynamically allocated
     *
     * @param vargp mem_protected_dir_t* pointed argument
     */
    void updateSubDirAttribFromMemCb(void* vargp, bool update_mem);
    /**
     * Removes a protected file from memory in FileManager
     * 
     * @note vargp must be dynamically allocated
     *
     * @param vargp mem_remove_file_param_t* pointed argument
     */
    void removeFileFromMemCb(void *vargp, bool update_mem);
    /**
     * Adds a protected file to memory in FileManager
     * 
     * @note vargp must be dynamically allocated
     *
     * @param vargp mem_add_file_param_t* pointed argument
     */
    void addFileToMemCb(void *vargp, bool update_mem);
    /**
     * Updates the content of a protected file from memory in FileManager
     * 
     * @note vargp must be dynamically allocated
     *
     * @param vargp mem_modify_file_param_t* pointed argument
     */
    void memUpdateModifiedFileCb(void *vargp, bool update_mem);
    /**
     * Updates the attribute of a protected file from memory in FileManager
     * 
     * @note vargp must be dynamically allocated
     *
     * @param vargp mem_file_attrib_param_t* pointed argument
     */
    void memUpdateFileAttribCb(void* vargp, bool update_mem);
    /**
     * Decallocates a callback protected_file_t struct
     * 
     * @param file protected_file_t* struct to be deallocated. This originally must be dynamically allocated
     */
    void cbFileDealloc(protected_file_t* file);
    /**
     * Decallocates a callback mem_protected_dir_t struct
     * 
     * @param dir mem_protected_dir_t* struct to be deallocated. This originally must be dynamically allocated
     */
    void memProtectedDirDealloc(mem_protected_dir_t* dir);
public:
    FileManagerCallback(FileManager* fm);
    static void cbWrap(void* ctx, 
                       void* action_cb_param, 
                       void* update_mem_cb_param,
                       bool apply,
                       int action);
};

#endif