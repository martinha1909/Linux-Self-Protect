#include "include/FileManagerCallbacks.hpp"

FileManagerCallback::FileManagerCallback(FileManager* fm)
{
    memory = fm;
}

void FileManagerCallback::cbWrap(void* ctx, 
                                 void* action_cb_param, 
                                 void* update_mem_cb_param,
                                 bool apply,
                                 int action)
{
    switch (action) {
        case FS_FILE_DELETED_ACTION:
            reinterpret_cast<FileManagerCallback*>(ctx)->deleteFileCb(action_cb_param, apply);
            reinterpret_cast<FileManagerCallback*>(ctx)->removeFileFromMemCb(update_mem_cb_param, apply);
            break;
        case FS_FILE_CREATED_ACTION:
            reinterpret_cast<FileManagerCallback*>(ctx)->createFileCb(action_cb_param, apply);
            reinterpret_cast<FileManagerCallback*>(ctx)->addFileToMemCb(update_mem_cb_param, apply);
            break;
        case FS_FILE_ATTRIB_CHANGED_ACTION:
            reinterpret_cast<FileManagerCallback*>(ctx)->changeFileAttribCb(action_cb_param, apply);
            reinterpret_cast<FileManagerCallback*>(ctx)->memUpdateFileAttribCb(update_mem_cb_param, apply);
            break;
        case FS_FILE_MODIFIED_ACTION:
            reinterpret_cast<FileManagerCallback*>(ctx)->modifyFileCb(action_cb_param, apply);
            reinterpret_cast<FileManagerCallback*>(ctx)->memUpdateModifiedFileCb(update_mem_cb_param, apply);
            break;
        case FS_PROTECTED_DIR_DELETED_ACTION:
            reinterpret_cast<FileManagerCallback*>(ctx)->deleteDirCb(action_cb_param, apply);
            reinterpret_cast<FileManagerCallback*>(ctx)->removeProtectedDirFromMemCb(update_mem_cb_param, apply);
            break;
        case FS_SUB_DIR_DELETED_ACTION:
            reinterpret_cast<FileManagerCallback*>(ctx)->deleteDirCb(action_cb_param, apply);
            reinterpret_cast<FileManagerCallback*>(ctx)->removeSubDirFromMemCb(update_mem_cb_param, apply);
            break;
        case FS_SUB_DIR_ATTRIB_CHANGED_ACTION:
            reinterpret_cast<FileManagerCallback*>(ctx)->changeDirAttribCb(action_cb_param, apply);
            reinterpret_cast<FileManagerCallback*>(ctx)->updateSubDirAttribFromMemCb(update_mem_cb_param, apply);
            break;
        case FS_PROTECTED_DIR_ATTRIB_CHANGED_ACTION:
            reinterpret_cast<FileManagerCallback*>(ctx)->changeDirAttribCb(action_cb_param, apply);
            reinterpret_cast<FileManagerCallback*>(ctx)->updateProtectedDirAttribFromMemCb(update_mem_cb_param, apply);
            break;
        case FS_SUB_DIR_CREATED_ACTION:
            reinterpret_cast<FileManagerCallback*>(ctx)->createDirCb(action_cb_param, apply);
            reinterpret_cast<FileManagerCallback*>(ctx)->addSubDirToMemCb(update_mem_cb_param, apply);
            break;
        case FS_ACTION_NONE:
        default:
            sp_error(SP_CALLBACK, "received unexpected callback action");
    }
}

void FileManagerCallback::cbFileDealloc(protected_file_t *file)
{
    if (file != NULL) {
        if (file->content != NULL) {
            free(file->content);
            file->content = NULL;
        }
        if (file->sha256 != NULL) {
            free(file->sha256);
            file->sha256 = NULL;
        }
        free(file);
        file = NULL;
    }
}

void FileManagerCallback::memProtectedDirDealloc(mem_protected_dir_t* dir)
{
    if (dir != NULL) {
        if (dir->new_dir != NULL) {
            free (dir->new_dir);
            dir->new_dir = NULL;
        }
        if (dir->old_dir != NULL) {
            free(dir->old_dir);
            dir->old_dir = NULL;
        }
        if (dir->ppd != NULL) {
            free(dir->ppd);
            dir->ppd = NULL;
        }
        free(dir);
        dir = NULL;
    }
}

void FileManagerCallback::deleteFileCb(void *vargp, bool apply_new_changes)
{
    protected_file_t *deleted_file = (protected_file_t*)vargp;
    
    if (deleted_file != NULL) {
        if (apply_new_changes) {
            if (deleted_file->file_path != NULL) {
                char filepath_cpy[PATH_MAX];

                strcpy(filepath_cpy, deleted_file->file_path);
                if (memory->getFileSystem()->dirExist(dirname(filepath_cpy))) {
                    if (memory->getFileSystem()->fileExist(deleted_file->file_path)) {
                        if (SYSTEM_CMD(FILE_REMOVE_CMD_FMT, deleted_file->file_path) == -1) {
                            sp_error(SP_CALLBACK, "Failed to deleted file %s", deleted_file->file_path);
                        }
                    }
                }
            } else {
                sp_error(SP_CALLBACK, "Failed to delete file, parent path or file path not provided");
            }
        }

        cbFileDealloc(deleted_file);
    }
}

void FileManagerCallback::createFileCb(void *vargp, bool apply_new_changes)
{
    protected_file_t* created_file = (protected_file_t*)vargp;

    if (created_file != NULL) {
        if (apply_new_changes) {
            char dir_cpy[PATH_MAX];

            strcpy(dir_cpy, created_file->file_path);
            std::string file_dir(dirname(dir_cpy));

            if (!memory->getFileSystem()->dirExist(file_dir.c_str())) {
                if (SYSTEM_CMD(DIR_CREATE_RECURSIVE_CMD_FMT, file_dir.c_str()) == -1) {
                    sp_error(SP_CALLBACK, "Failed to create file dir %s", file_dir.c_str());
                }
            }

            memory->unmarkProtectedDirAndSubDirs(memory->getProtectedDirFromSubDir(file_dir.c_str()).path);
            
            if (SYSTEM_CMD(FILE_CREATE_CMD_FMT, created_file->file_path) == -1) {
                sp_error(SP_CALLBACK, "Failed to recreate file %s", created_file->file_path);
                goto free_mem;
            }
            if (chmod(created_file->file_path, created_file->attrib) == -1) {
                sp_error(SP_CALLBACK, "Failed to set attribute for file %d", created_file->attrib);
                goto free_mem;
            }
            REWRITE_FILE(created_file->file_path, created_file->content);

            memory->markProtectedDirAndSubDirs(memory->getProtectedDirFromSubDir(file_dir.c_str()).path);
        }

free_mem:
        cbFileDealloc(created_file);
    }
}

void FileManagerCallback::modifyFileCb(void *vargp, bool apply_new_changes)
{
    protected_file_t* modified_file = (protected_file_t*)vargp;

    if (modified_file != NULL) {
        if (apply_new_changes) {
            if (modified_file->content != NULL) {
                REWRITE_FILE(modified_file->file_path, modified_file->content);
            }
        }
        cbFileDealloc(modified_file);
    }
}

void FileManagerCallback::changeFileAttribCb(void *vargp, bool apply_new_changes)
{
    protected_file_t* modified_file = (protected_file_t*)vargp;

    if (modified_file != NULL) {
        if (apply_new_changes) {
            if (chmod(modified_file->file_path, modified_file->attrib) == -1) {
                sp_error(SP_CALLBACK, "Failed apply permissions for file %s", modified_file->file_path);
            }
        }
        cbFileDealloc(modified_file);
    }
}

void FileManagerCallback::deleteDirCb(void *vargp, bool apply_new_changes)
{
    protected_dir_t* dir = (protected_dir_t*)vargp;

    if (dir != NULL) {
        if (apply_new_changes) {
            if (memory->getFileSystem()->dirExist(dir->path.c_str())) {
                if (SYSTEM_CMD(DIR_DELETE_CMD_FMT, dir->path.c_str()) == -1) {
                    sp_error(SP_CALLBACK, "Failed to delete directory %s, %s", dir->path.c_str(), strerror(errno));
                }
            }
        }
        free(dir);
        dir = NULL;
    }
}

void FileManagerCallback::createDirCb(void* vargp, bool apply_new_changes)
{
    protected_dir_t* new_dir = (protected_dir_t*)vargp;

    if (new_dir != NULL) {
        if (apply_new_changes) {
            if (mkdir(new_dir->path.c_str(), new_dir->attrib) == -1) {
                sp_error(SP_CALLBACK, "Failed to create directory %s, %s\n", new_dir->path.c_str(), strerror(errno));
            }
        }
        free(new_dir);
        new_dir = NULL;
    }
}

void FileManagerCallback::changeDirAttribCb(void *vargp, bool apply_new_changes)
{
    if (vargp != NULL) {
        protected_dir_t* dir = (protected_dir_t*)vargp;

        if (apply_new_changes) {
            if (chmod(dir->path.c_str(), dir->attrib) == -1) {
                sp_error(SP_CALLBACK, "Failed to change attribute for dir %s", dir->path.c_str());
            }
        }

        free(dir);
    }
}

void FileManagerCallback::removeProtectedDirFromMemCb(void *vargp, bool update_mem)
{
    mem_protected_dir_t* removed_dir = (mem_protected_dir_t*)vargp;

    if (removed_dir != NULL) {
        if (update_mem) {
            memory->removeProtectedDirFromMem(removed_dir->ppd);
            memory->getBackup()->deleteRemoteDirOrFile(removed_dir->ppd->path.c_str(), false);
        }
        memProtectedDirDealloc(removed_dir);
    }
}

void FileManagerCallback::updateProtectedDirAttribFromMemCb(void* vargp, bool update_mem)
{
    mem_protected_dir_t* dir = (mem_protected_dir_t*)vargp;

    if (dir != NULL) {
        if (update_mem) {
            if (dir->new_dir != NULL && dir->old_dir != NULL) {
                memory->updateProtectedDirAttribFromMem(dir->old_dir, dir->new_dir);
            } else {
                sp_error(SP_CALLBACK, "Failed to update attribute for protected directory in memory, NULL arguments");
            }
        }
        memProtectedDirDealloc(dir);
    }
}

void FileManagerCallback::removeSubDirFromMemCb(void *vargp, bool update_mem)
{
    mem_protected_dir_t* removed_dir = (mem_protected_dir_t*)vargp;

    if (removed_dir != NULL) {
        if (update_mem) {
            memory->removeSubDirFromMem(removed_dir->old_dir, removed_dir->ppd);
            memory->getBackup()->deleteRemoteDirOrFile(removed_dir->old_dir->path.c_str(), false);
        }
        memProtectedDirDealloc(removed_dir);
    }
}

void FileManagerCallback::addSubDirToMemCb(void* vargp, bool update_mem)
{
    mem_protected_dir_t* new_dir = (mem_protected_dir_t*)vargp;

    if (new_dir != NULL) {
        if (update_mem) {
            if (new_dir->new_dir != NULL && new_dir->ppd != NULL) {
                memory->addSubDirToMem(new_dir->ppd, new_dir->new_dir);
                memory->getBackup()->createRemoteDirAndSubDirs(*(new_dir->new_dir), {});
            } else {
                sp_error(SP_CALLBACK, "Failed to add sub-directory to memory, NULL arguments");
            }
        }
        memProtectedDirDealloc(new_dir);
    }
}

void FileManagerCallback::updateSubDirAttribFromMemCb(void* vargp, bool update_mem)
{
    mem_protected_dir_t* dir = (mem_protected_dir_t*)vargp;

    if (dir != NULL) {
        if (update_mem) {
            if (dir->ppd != NULL && dir->new_dir != NULL && dir->old_dir != NULL) {
                memory->updateSubDirAttribFromMem(dir->ppd, dir->old_dir, dir->new_dir);
            } else {
                sp_error(SP_CALLBACK, "Failed to update attribute for sub directory in memory, NULL arguments");
            }
        }
        memProtectedDirDealloc(dir);
    }
}

void FileManagerCallback::removeFileFromMemCb(void *vargp, bool update_mem)
{
    mem_protected_file_t* param = (mem_protected_file_t*)vargp;

    if (param != NULL) {
        if (param->file != NULL) {
            if (update_mem) {
                if (param->file->file_path != NULL) {
                    /* in the case that our config list file is deleted, we remove everything in memory except our default config directory*/
                    if (strcmp(param->file->file_path, SELF_PROTECT_CONFIG_LIST_PATH) == 0) {
                        memory->removeAllProtectedDirsExceptConfig();
                    }
                    
                    memory->removeProtectedFileFromMem(param->parent_protected_dir, param->file);
                    memory->getBackup()->deleteRemoteDirOrFile(param->file->file_path, true);
                } else {
                    sp_error(SP_CALLBACK, "Failed to remove file from memory, file path not provided");
                }
            }
            free(param->file);
            param->file = NULL;
        } else {
            sp_error(SP_CALLBACK, "Failed to remove file from memory, received unexpected arguments");
        }
        free(param);
        param = NULL;
    }
}

void FileManagerCallback::addFileToMemCb(void *vargp, bool update_mem)
{
    mem_protected_file_t* param = (mem_protected_file_t*)vargp;

    if (param != NULL) {
        if (param->file != NULL) {
            if (update_mem) {
                if (param->file->file_path != NULL) {
                    memory->addProtectedFileToMem(param->parent_protected_dir, param->file);
                    memory->getBackup()->uploadNewRemoteFile(*(param->file));
                }
            }
            free(param->file);
            param->file = NULL;
        }
        free(param);
        param = NULL;
    }
}

void FileManagerCallback::memUpdateModifiedFileCb(void *vargp, bool update_mem)
{
    mem_protected_file_t* param = (mem_protected_file_t*)vargp;

    if (param != NULL) {
        if (param->file != NULL) {
            if (update_mem) {
                memory->getBackup()->updateRemoteFile(*(param->file));
                memory->modifyProtectedFileFromMem(param->parent_protected_dir, param->file);

                if (strcmp(param->file->file_path, SELF_PROTECT_CONFIG_LIST_PATH) == 0) {
                    memory->addOrRemoveProtectedDirs();
                }
            }
        } else {
            sp_error(SP_CALLBACK, "Failed to remove file from memory, received unexpected arguments");
        }
        
        cbFileDealloc(param->file);
        free(param);
        param = NULL;
    }
}

void FileManagerCallback::memUpdateFileAttribCb(void* vargp, bool update_mem)
{
    mem_protected_file_t* param = (mem_protected_file_t*)vargp;

    if (param != NULL) {
        if (param->file != NULL) {
            if (update_mem) {
                memory->changeProtectedFileAttribFromMem(param->parent_protected_dir, param->file);
            }
            free(param->file);
            param->file = NULL;
        } else {
            sp_error(SP_CALLBACK, "Failed to remove file from memory, received unexpected arguments");
        }
        free(param);
        param = NULL;
    }
}
