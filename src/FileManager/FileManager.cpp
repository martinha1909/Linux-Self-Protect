#include "include/FileManager.hpp"
#include "../Trust/include/Trust.hpp"

FileManager::FileManager(std::string filepath, 
                         FanotifyEvents* fanotifyEvents, 
                         QueryHistory* queryHistory,
                         Trust* trust) : backup()
{
    char **sub_dirs;
    int size = 0;
    std::string tmp;

    allDirActionLockFromConfig();
    fs = new FileSystem();
    fmcb = new FileManagerCallback(this);
    fan = fanotifyEvents;
    hist = queryHistory;
    this->trust = trust;
    pthread_mutex_init(&fm_mutex, NULL);
    backup.setMutex(&fm_mutex);

    fan->setFileManager(this);

    if (!fs->dirExist(filepath.c_str())) {
        protected_file_t client_bin = {};

        sp_info(SP_FILEOP, "Cannot find config directory, client binary will not be able to launch, rebuilding...");
        if (SYSTEM_CMD(DIR_CREATE_CMD_FMT, SELF_PROTECT_CONFIG_DIR) == -1) {
            sp_error(SP_FILEOP, "Failed to rebuild self protect config dir");
            goto load;
        }
        if (SYSTEM_CMD(DIR_CREATE_CMD_FMT, SELF_PROTECT_CONFIG_BIN_DIR) == -1) {
            sp_error(SP_FILEOP, "Failed to rebuild self protect config binary dir");
            goto load;
        }
        
        strcpy(client_bin.file_path, CLIENT_BIN_PATH);
        client_bin.attrib = S_IRUSR | S_IWUSR | S_IXUSR;

        backup.downloadRemoteELF(client_bin);

        if (SYSTEM_CMD(FILE_CREATE_CMD_FMT, SELF_PROTECT_CONFIG_LIST_PATH) == -1) {
            sp_error(SP_FILEOP, "Failed to create config list file to protect other directories");
            goto load;
        }
    }

    default_protected_dir.path = filepath;
    default_protected_dir.attrib = fs->getDirAttrib(&filepath);
    default_protected_dir.fd = fs->getDirFd(default_protected_dir.path.c_str());
    storeDirContent(default_protected_dir.path.c_str(), &default_protected_dir.files);
    
    trust->auditctlWatchDir(filepath.c_str());

    tmp = default_protected_dir.path;
    if (fs->getSubDirs(&sub_dirs, &size, (char*)tmp.c_str()) == -1) {
        sp_error(SP_FS_UTIL, "Failed to get sub directory of %s, skip storing to memory", default_protected_dir.path.c_str());
        protected_dirs[default_protected_dir];
    } else {
        if (sub_dirs != NULL) {
            for (int i = 0; i < size; i++) {
                protected_dir_t dir = {};

                dir.path = sub_dirs[i];
                if (dir.path.back() != '/') {
                    dir.path += '/';
                }
                dir.attrib = fs->getDirAttrib(&dir.path);
                dir.fd = fs->getDirFd(dir.path.c_str());
                storeDirContent(dir.path.c_str(), &dir.files);

                protected_dirs[default_protected_dir].push_back(dir);
            }
        }
    }

    fs->array2DFree((const void**)sub_dirs, size);

load:
    loadProtectedDirs();
}

FileManager::~FileManager()
{
    delete fmcb;
    delete fs;
    for (auto pd : protected_dirs) {
        for(size_t i = 0; i < pd.first.files.size(); i++) {
            protectedFileDealloc((protected_file_t*)pd.first.files[i]);
        }
        for (size_t i = 0; i < pd.second.size(); i++) {
            for(size_t j = 0; j < pd.second[i].files.size(); i++) {
                protectedFileDealloc((protected_file_t*)pd.second[i].files[j]);
            }
        }
    }

    pthread_mutex_destroy(&fm_mutex);
}

std::unordered_map<protected_dir_t, std::vector<protected_dir_t>>* FileManager::getProtectedDirs()
{
    return &protected_dirs;
}

FileSystem* FileManager::getFileSystem()
{
    return fs;
}

protected_dir_t* FileManager::getDefaultProtectedDir()
{
    return &default_protected_dir;
}

FileManagerBackups* FileManager::getBackup()
{
    return &backup;
}

size_t FileManager::getNewChangesSize()
{
    return new_changes.size();
}

bool FileManager::fileCreatedByEditor(const char* file)
{
    bool ret = false;
    std::string file_extension(file);
    std::string::size_type st;

    /* these 2 files extensions will be created if user tries to open by vim, no need to do anything since vim will clean these up */
    st = file_extension.find(".sw");
    if (st != std::string::npos) {
        ret = true;
    }

    return ret;
}

char* FileManager::fsStrAction(fs_action_t action)
{
    const char* ret = "unknown";

    if (ret != NULL) {
        switch (action) {
            case FS_FILE_DELETED_ACTION:
                ret = "delete (file)";
                break;
            case FS_FILE_CREATED_ACTION:
                ret = "create (file)";
                break;
            case FS_FILE_MODIFIED_ACTION:
                ret = "modify";
                break;
            case FS_FILE_ATTRIB_CHANGED_ACTION:
                ret = "change attribute (file)";
                break;
            case FS_SUB_DIR_ATTRIB_CHANGED_ACTION:
            case FS_PROTECTED_DIR_ATTRIB_CHANGED_ACTION:
                ret = "change attribute (dir)";
                break;
            case FS_PROTECTED_DIR_DELETED_ACTION:
            case FS_SUB_DIR_DELETED_ACTION:
                ret = "delete (dir)";
                break;
            case FS_SUB_DIR_CREATED_ACTION:
                ret = "create (dir)";
                break;
            case FS_ACTION_NONE:
            default:
                ret = "unknown";
        }
    }

    return (char*)ret;
}

void FileManager::protectedFileDealloc(protected_file_t* file)
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

protected_file_t* FileManager::protectedFileDup(const protected_file_t* dup_file)
{
    protected_file_t* ret = NULL;

    fan->setPermResp(FAN_ALLOW);

    if (dup_file == NULL) {
        sp_error(SP_FILEOP, "Failed to duplicate protected file, invalid arguments");
        goto done;
    }

    ret = (protected_file_t*)calloc(sizeof(protected_file_t), 1);
    if (ret == NULL) {
        sp_error(SP_FILEOP, "Failed to duplicate protected file, memory allocation failed");
        goto done;
    }

    strcpy(ret->file_path, dup_file->file_path);

    if (dup_file->content != NULL) {
        ret->content = (unsigned char*)calloc(sizeof(unsigned char), strlen((char*)dup_file->content));
        if (ret->content == NULL) {
            free(ret);
            ret = NULL;
            sp_error(SP_FILEOP, "Failed to duplicate protected file, failed to get file content");
            goto done;
        }
        memcpy(ret->content, dup_file->content, strlen((char*)dup_file->content));
    } else {
        ret->content = NULL;
    }

    if (dup_file->sha256 != NULL) {
        ret->sha256 = (unsigned char*)calloc(sizeof(unsigned char), strlen((char*)dup_file->sha256));
        if (ret->sha256 == NULL) {
            free(ret->content);
            free(ret);
            ret = NULL;
            sp_error(SP_FILEOP, "Failed to duplicate protected file, failed to get file sha256");
            goto done;
        }
        memcpy(ret->sha256, dup_file->sha256, strlen((char*)dup_file->sha256));
    } else {
        ret->sha256 = NULL;
    }

    ret->attrib = dup_file->attrib;
    ret->is_elf = dup_file->is_elf;
done:
    fan->setPermResp(FAN_DENY);
    return ret;
}

protected_dir_t* FileManager::protectedDirDup(const protected_dir_t* dup_dir)
{
    protected_dir_t* ret = NULL;

    fan->setPermResp(FAN_ALLOW);

    if (dup_dir == NULL) {
        sp_error(SP_FILEOP, "Failed to duplicate protected dir, invalid arguments");
        goto done;
    }

    ret = (protected_dir_t*)calloc(sizeof(protected_dir_t), 1);
    if (ret == NULL) {
        sp_error(SP_FILEOP, "Failed to duplicate protected file, memory allocation failed");
        goto done;
    }

    ret->path = dup_dir->path;
    ret->fd = dup_dir->fd;
    ret->attrib = dup_dir->attrib;
    ret->files = dup_dir->files;
done:
    fan->setPermResp(FAN_DENY);
    return ret;
}

void* FileManager::updateMemAlloc(fs_action_t action,
                                  const char* protected_dir,
                                  const char* sub_dir,
                                  const protected_file_t* update_file_mem,
                                  protected_file_t *old_file)
{
    void* ret = NULL;

    switch (action) {
        case FS_ACTION_NONE:
            sp_info(SP_FILEOP, "Received action none, skipping...");
            break;
        case FS_PROTECTED_DIR_DELETED_ACTION:
        case FS_PROTECTED_DIR_ATTRIB_CHANGED_ACTION:
        case FS_SUB_DIR_DELETED_ACTION:
        case FS_SUB_DIR_CREATED_ACTION:
        case FS_SUB_DIR_ATTRIB_CHANGED_ACTION:
            break;
        case FS_FILE_DELETED_ACTION:
        case FS_FILE_MODIFIED_ACTION:
        case FS_FILE_ATTRIB_CHANGED_ACTION:
        case FS_FILE_CREATED_ACTION: {
            /*not used in this action case */
            (void)sub_dir;
            mem_protected_file_t* protected_file_param = NULL;

            if (protected_dir == NULL ||
                update_file_mem == NULL) {
                sp_error(SP_FILEOP, "Invalid argument");
                goto done;
            }

            protected_file_param = (mem_protected_file_t*) calloc(sizeof(mem_protected_file_t), 1);
            if ((protected_file_param) == NULL) {
                sp_error(SP_FILEOP, "Failed to allocate memory");
                goto done;
            }

            protected_file_param->file = protectedFileDup(update_file_mem);
            if ((protected_file_param->file) == NULL) {
                free(protected_file_param);
                goto done;
            }
            strcpy(protected_file_param->parent_protected_dir, protected_dir);
            if (old_file != NULL) {
                protected_file_param->old_file = protectedFileDup(old_file);
            } else {
                protected_file_param->old_file = NULL;
            }

            ret = protected_file_param;
            break;
        }
    }

done:
    return ret;
}

void FileManager::addNewChangeFromAction(fs_action_t action,
                                         void *action_param,
                                         void *update_mem_param)
{
    new_changes.push_back((new_change_t){
        .action = action,
        .action_param = action_param,
        .update_mem_param = update_mem_param,
        .exec_cb = &FileManagerCallback::cbWrap
    });
}

protected_file_t* FileManager::protectedFileLookup(const protected_dir_t pd, const char* filepath)
{
    protected_file_t* ret = NULL;
    auto it = protected_dirs.find(pd);

    if (it != protected_dirs.end()) {
        for (size_t i = 0; i < it->first.files.size(); i++) {
            if (strcmp(it->first.files[i]->file_path, filepath) == 0) {
                ret = it->first.files[i];
                goto done;
            }
        }
    }

    for (size_t i = 0; i < protected_dirs[pd].size(); i++) {
        for (size_t j = 0; j < protected_dirs[pd][i].files.size(); j++) {
            if (strcmp(protected_dirs[pd][i].files[j]->file_path, filepath) == 0) {
                ret = protected_dirs[pd][i].files[j];
                goto done;
            }
        }
    }

done:
    return ret;
}

protected_dir_t* FileManager::protectedDirLookup(const protected_dir_t pd, const char* lookup_dir)
{
    protected_dir_t* ret = NULL;
    protected_dir_t tmp = {};

    tmp.path = lookup_dir;

    if (tmp.path.back() != '/') {
        tmp.path += '/';
    }

    auto it = protected_dirs.find(tmp);

    /* if the look up directory is a parent protected directory, just return it. 
       Otherwise it is a sub-directory of a parent protected directory */
    if (it != protected_dirs.end()) {
        ret = (protected_dir_t*)&(it->first);
    } else {
        if (!pd.path.empty()) {
            for (size_t i = 0; i <protected_dirs[pd].size(); i++) {
                if (strcmp(protected_dirs[pd][i].path.c_str(), tmp.path.c_str()) == 0) {
                    ret = &(protected_dirs[pd][i]);
                    break;
                }
            }
        } else {
            sp_error(SP_FILEOP, "Failed to look up protected directory in memory, path is empty");
        }
    }

    return ret;
}

protected_dir_t FileManager::getProtectedDirFromSubDir(const char* sub_dir)
{
    protected_dir_t ret;
    std::string sub_dir_cpy(sub_dir);

    if (sub_dir_cpy.back() != '/') {
        sub_dir_cpy += '/';
    }

    for (auto protected_dir : protected_dirs) {
        if (strcmp(sub_dir_cpy.c_str(), protected_dir.first.path.c_str()) == 0 || strstr(sub_dir_cpy.c_str(), protected_dir.first.path.c_str())) {
            ret = protected_dir.first;
            break;
        }
    }

    return ret;
}

std::vector<protected_file_t*> FileManager::getProtectedFilesBySubDir(const protected_dir_t ppd, char* sub_dir)
{
    std::vector<protected_file_t*> ret;

    if (sub_dir[strlen(sub_dir) - 1] != '/') {
        strcat(sub_dir, "/");
    }

    for (size_t i = 0; i < protected_dirs[ppd].size(); i++) {
        if (strcmp(protected_dirs[ppd][i].path.c_str(), sub_dir) == 0) {
            ret = protected_dirs[ppd][i].files;
        }
    }

    return ret;
}

bool FileManager::dirIsProtectedParentDir(const char* dir)
{
    bool ret = false;
    protected_dir_t dir_s = {};

    dir_s.path = dir;

    if (dir_s.path.back() != '/') {
        dir_s.path += "/";
    }

    if (protected_dirs.find(dir_s) != protected_dirs.end()) {
        ret = true;
    }

    return ret;
}

void FileManager::clearStoredChanges()
{
    if (new_changes.size() != 0) {
        new_changes.clear();
    }
}

void FileManager::storeSubDirDeleteChange(const char* tampered_path)
{
    protected_dir_t ppd = getProtectedDirFromSubDir(tampered_path);
    protected_dir_t* deleted_dir = protectedDirLookup(ppd, tampered_path);
    mem_protected_dir_t* update_mem_param = NULL;
        
    if (mkdir(deleted_dir->path.c_str(), deleted_dir->attrib) == -1) {
        sp_error(SP_FILEOP, "Failed to recreate deleted dir %s", deleted_dir->path.c_str());
    } else {
        if (fan->mark(deleted_dir->path.c_str(), NULL, 0) == -1) {
            sp_error(SP_FILEOP, "Failed to mark directory or sub-directories for protected dir %s", deleted_dir->path.c_str());
        }
    }

    update_mem_param = (mem_protected_dir_t*)calloc(sizeof(mem_protected_dir_t), 1);
    if (update_mem_param != NULL) {
        update_mem_param->old_dir = protectedDirDup(deleted_dir);
        update_mem_param->new_dir = NULL;
        update_mem_param->ppd = protectedDirDup(&ppd);
    }

    addNewChangeFromAction(FS_SUB_DIR_DELETED_ACTION,
                           protectedDirDup(deleted_dir),
                           update_mem_param);
}

void FileManager::storeSubDirCreateChange(const char* tampered_path)
{
    protected_dir_t new_dir = {};
    protected_dir_t ppd = getProtectedDirFromSubDir(tampered_path);
    mem_protected_dir_t* update_mem_param = NULL;

    new_dir.path = tampered_path;
    if (new_dir.path.back() != '/') {
        new_dir.path += "/";
    }
    new_dir.fd = fs->getDirFd(new_dir.path.c_str());
    new_dir.attrib = fs->getDirAttrib(&new_dir.path);
    new_dir.files = fs->getFilesByDir(new_dir.path.c_str());

    update_mem_param = (mem_protected_dir_t*)calloc(sizeof(mem_protected_dir_t), 1);
    if (update_mem_param != NULL) {
        update_mem_param->old_dir = NULL;
        update_mem_param->new_dir = protectedDirDup(&new_dir);
        update_mem_param->ppd = protectedDirDup(&ppd);
    }

    addNewChangeFromAction(FS_SUB_DIR_CREATED_ACTION,
                            protectedDirDup(&new_dir),
                            update_mem_param);
}

void FileManager::storeNewChanges(fanotify_event_response_t *event)
{
    char tampered_path[PATH_MAX];

    /* since our service needs to access files, directories, etc. that were tampered, we need to allow these actions 
       in permission events */
    fan->setPermResp(FAN_ALLOW);

    /* parent protected directory is deleted */
    if (!fs->dirExist(event->event_path) && dirIsProtectedParentDir(event->event_path)) {
        protected_dir_t* deleted_dir = protectedDirLookup({}, event->event_path);
        mem_protected_dir_t* update_mem_param = NULL;

        if (mkdir(deleted_dir->path.c_str(), deleted_dir->attrib) == -1) {
            sp_error(SP_FILEOP, "Failed to recreate deleted dir %s", deleted_dir->path.c_str());
        } else {
            if (fan->mark(deleted_dir->path.c_str(), NULL, 0) == -1) {
                sp_error(SP_FILEOP, "Failed to mark protected dir %s", deleted_dir->path.c_str());
            }
        }

        update_mem_param = (mem_protected_dir_t*)calloc(sizeof(mem_protected_dir_t), 1);
        if (update_mem_param != NULL) {
            update_mem_param->old_dir = protectedDirDup(deleted_dir);
            update_mem_param->new_dir = NULL;
            update_mem_param->ppd = protectedDirDup(deleted_dir);
        }
        addNewChangeFromAction(FS_PROTECTED_DIR_DELETED_ACTION,
                               protectedDirDup(deleted_dir),
                               update_mem_param);
    }

    fs->getFilepathFromEvent(tampered_path, event);

    /* protected parent directory deleted will not have the mask of FAN_ONDIR | FAN_DELETE*/
    if (SUB_DIR_DELETED(event->fileop) ||
        (!fs->dirExist(event->event_path) && 
         !dirIsProtectedParentDir(event->event_path))) {
        storeSubDirDeleteChange(tampered_path);
    } else if (SUB_DIR_MOVED_FROM(event->fileop)) {
        protected_dir_t ppd = getProtectedDirFromSubDir(tampered_path);
        std::vector<protected_file_t*> files_under_sub_dir = getProtectedFilesBySubDir(ppd, tampered_path);

        storeSubDirDeleteChange(tampered_path);

        for (size_t i = 0; i < files_under_sub_dir.size(); i++) {
            addNewChangeFromAction(FS_FILE_DELETED_ACTION,
                                   protectedFileDup(files_under_sub_dir[i]),
                                   updateMemAlloc(FS_FILE_DELETED_ACTION,
                                                  ppd.path.c_str(),
                                                  NULL,
                                                  files_under_sub_dir[i],
                                                  NULL));
        }
    } else if (SUB_DIR_CREATE(event->fileop)) {
        storeSubDirCreateChange(tampered_path);
    } else if (SUB_DIR_MOVED_TO(event->fileop)) {
        protected_dir_t ppd = getProtectedDirFromSubDir(event->event_path);
        std::vector<protected_file_t*> moved_files = fs->getFilesByDir(tampered_path);

        for (size_t i = 0; i < moved_files.size(); i++) {
            addNewChangeFromAction(FS_FILE_CREATED_ACTION,
                                   protectedFileDup(moved_files[i]),
                                   updateMemAlloc(FS_FILE_CREATED_ACTION,
                                                  ppd.path.c_str(),
                                                  NULL,
                                                  moved_files[i],
                                                  NULL));
            protectedFileDealloc(moved_files[i]);
        }

        /* add this after all the actions from file created action have been added so we can revert the file creations before revert dir creation */
        storeSubDirCreateChange(tampered_path);
    } else if (DIR_ATTRIB_CHANGED(event->fileop)) {
        if (dirIsProtectedParentDir(event->event_path)) {
            protected_dir_t ppd = {};

            ppd.path = event->event_path;
            if (ppd.path.back() != '/') {
                ppd.path += "/";
            }

            auto it = protected_dirs.find(ppd);
            if (it != protected_dirs.end()) {
                mem_protected_dir_t* update_mem_param = NULL;

                ppd.attrib = fs->getDirAttrib(&ppd.path);
                ppd.fd = fs->getDirFd(ppd.path.c_str());

                update_mem_param = (mem_protected_dir_t*)calloc(sizeof(mem_protected_dir_t), 1);
                if (update_mem_param != NULL) {
                    update_mem_param->old_dir = protectedDirDup(&(it->first));
                    update_mem_param->new_dir = protectedDirDup(&ppd);
                    update_mem_param->ppd = protectedDirDup(&(it->first));
                }

                addNewChangeFromAction(FS_PROTECTED_DIR_ATTRIB_CHANGED_ACTION,
                                       protectedDirDup(&ppd),
                                       update_mem_param);
            } else {
                sp_error(SP_FILEOP, "Unexpected error, unable to find %s as key", ppd.path.c_str());
            }
        } else {
            mem_protected_dir_t* update_mem_param = NULL;
            protected_dir_t dir_new = {};
            protected_dir_t* dir_old = NULL;
            protected_dir_t ppd = getProtectedDirFromSubDir(event->event_path);

            dir_new.path = event->event_path;
            if (dir_new.path.back() != '/') {
                dir_new.path += "/";
            }

            dir_new.fd = fs->getDirFd(dir_new.path.c_str());
            dir_new.attrib = fs->getDirAttrib(&dir_new.path);

            for (size_t i = 0; i < protected_dirs[ppd].size(); i++) {
                if (strcmp(dir_new.path.c_str(), protected_dirs[ppd][i].path.c_str()) == 0) {
                    dir_old = protectedDirDup(&protected_dirs[ppd][i]);
                    break;
                }
            }

            update_mem_param = (mem_protected_dir_t*)calloc(sizeof(mem_protected_dir_t), 1);
            if (update_mem_param != NULL) {
                update_mem_param->ppd = protectedDirDup(&ppd);
                update_mem_param->old_dir = dir_old;
                update_mem_param->new_dir = protectedDirDup(&dir_new);
            }

            addNewChangeFromAction(FS_SUB_DIR_ATTRIB_CHANGED_ACTION,
                                   protectedDirDup(&dir_new),
                                   update_mem_param);
        }
    } else {
        protected_dir_t protected_parent_dir = getProtectedDirFromSubDir(event->event_path);
        protected_file_t* file_look_up = protectedFileLookup(protected_parent_dir, tampered_path);

        if (file_look_up != NULL) {
            if (FILE_IS_DELETED(event->fileop)) {
                mem_protected_file_t* update_mem_param = NULL;

                update_mem_param = (mem_protected_file_t*)updateMemAlloc(FS_FILE_DELETED_ACTION,
                                                                        getProtectedDirFromSubDir(event->event_path).path.c_str(),
                                                                        NULL,
                                                                        file_look_up,
                                                                        NULL);
                if (update_mem_param == NULL) {
                    sp_error(SP_FILEOP, "Failed to allocate memory, skip storing new changes");
                }

                addNewChangeFromAction(FS_FILE_DELETED_ACTION,
                                    protectedFileDup(file_look_up),
                                    update_mem_param);
            }
            if (FILE_IS_MODIFIED(event->fileop)) {
                mem_protected_file_t* update_mem_param = NULL;
                protected_file_t update_mem_modified_file = {};

                /* create a copy for update_mem_cb */
                update_mem_modified_file = *file_look_up;
                update_mem_modified_file.content = fs->getFileContent(update_mem_modified_file.file_path);
                update_mem_modified_file.sha256 = fs->getFileSHA256(update_mem_modified_file.file_path);

                update_mem_param = (mem_protected_file_t*)updateMemAlloc(FS_FILE_MODIFIED_ACTION,
                                                                        protected_parent_dir.path.c_str(),
                                                                        NULL,
                                                                        &update_mem_modified_file,
                                                                        NULL);
                if (update_mem_param == NULL) {
                    sp_error(SP_FILEOP, "Failed to allocate memory");
                }

                if (update_mem_param != NULL) {
                    addNewChangeFromAction(FS_FILE_MODIFIED_ACTION,
                                            protectedFileDup(&update_mem_modified_file), 
                                            update_mem_param);
                }

                if (update_mem_modified_file.content != NULL) {
                    free(update_mem_modified_file.content);
                }
                if (update_mem_modified_file.sha256 != NULL) {
                    free(update_mem_modified_file.sha256);
                }
            }
            if (FILE_ATTRIB_CHANGED(event->fileop)) {
                mem_protected_file_t* update_mem_param = NULL;
                protected_file_t new_modified_file = {};

                strcpy(new_modified_file.file_path, tampered_path);
                new_modified_file.attrib = fs->getFileAttrib(new_modified_file.file_path);

                update_mem_param = (mem_protected_file_t*)updateMemAlloc(FS_FILE_ATTRIB_CHANGED_ACTION,
                                                                        protected_parent_dir.path.c_str(),
                                                                        NULL,
                                                                        &new_modified_file,
                                                                        file_look_up);
                if (update_mem_param == NULL) {
                    sp_error(SP_FILEOP, "Failed to allocate memory");
                }

                if (update_mem_param != NULL) {
                    addNewChangeFromAction(FS_FILE_ATTRIB_CHANGED_ACTION,
                                        protectedFileDup(&new_modified_file),
                                        update_mem_param);
                }
            }
        } else {
            sp_info(SP_FILEOP, "file %s not in memory, this could be a create event", tampered_path);
        }

        if (FILE_IS_CREATED(event->fileop)) {
            /* need to create a copy here since action_cb will free the content of these pointers 
                so when update_mem_cb is called these values will be garbage */
            protected_file_t created_file = {};
            mem_protected_file_t* update_mem_param = NULL;

            strcpy(created_file.file_path, tampered_path);
            created_file.content = fs->getFileContent(tampered_path);
            created_file.sha256 = fs->getFileSHA256(tampered_path);
            created_file.attrib = fs->getFileAttrib(tampered_path);
            created_file.is_elf = fs->fileIsELF(tampered_path);

            update_mem_param = (mem_protected_file_t*)updateMemAlloc(FS_FILE_CREATED_ACTION,
                                                                    protected_parent_dir.path.c_str(),
                                                                    NULL,
                                                                    &created_file,
                                                                    NULL);
            if (update_mem_param == NULL) {
                sp_error(SP_FILEOP, "Failed to allocate memory, skip storing new changes");
            }

            addNewChangeFromAction(FS_FILE_CREATED_ACTION,
                                protectedFileDup(&created_file), 
                                update_mem_param);
        }
    }

    fan->setPermResp(FAN_DENY);
}

void FileManager::revertNewChanges()
{
    fan->setPermResp(FAN_ALLOW);
    for (size_t i = 0; i < new_changes.size(); i++) {
        switch (new_changes[i].action) {
            /* dir deleted cases have been already restored in storeNewChanges */
            case FS_SUB_DIR_DELETED_ACTION:
            case FS_PROTECTED_DIR_DELETED_ACTION: 
            case FS_ACTION_NONE:
                break;
            case FS_SUB_DIR_ATTRIB_CHANGED_ACTION:
            case FS_PROTECTED_DIR_ATTRIB_CHANGED_ACTION: {
                if (new_changes[i].update_mem_param != NULL) {
                    mem_protected_dir_t* new_change_param = (mem_protected_dir_t*)new_changes[i].update_mem_param;

                    if (new_change_param->old_dir != NULL) {
                        if (chmod(new_change_param->old_dir->path.c_str(), new_change_param->old_dir->attrib) == -1) {
                            sp_error(SP_FILEOP, "Failed to revert attribute for dir %s, %s", new_change_param->old_dir->path.c_str(), strerror(errno));
                        }
                    }
                }
                break;
            }
            case FS_SUB_DIR_CREATED_ACTION: {
                protected_dir_t* new_dir = (protected_dir_t*)new_changes[i].action_param;

                if (new_dir != NULL) {
                    if (SYSTEM_CMD(DIR_DELETE_CMD_FMT ,new_dir->path.c_str()) == -1) {
                        sp_error(SP_FILEOP, "Failed to revert directory %s creation", new_dir->path.c_str());
                    }
                }
                break;
            }
            case FS_FILE_MODIFIED_ACTION: {
                if (new_changes[i].action_param != NULL) { 
                    protected_file_t* modified_file = (protected_file_t*)new_changes[i].action_param;
                    protected_dir_t protected_parent_dir = getProtectedDirFromSubDir(modified_file->file_path);
                    protected_file_t *original_file = protectedFileLookup(protected_parent_dir, modified_file->file_path);

                    if (original_file != NULL) {
                        if (original_file->is_elf) {
                            backup.downloadRemoteELF(*original_file);
                        } else {
                            fs->restoreFileState(original_file);
                        }
                        if (chmod(original_file->file_path, original_file->attrib) == -1) {
                            sp_error(SP_FILEOP, "Failed to revert attribute after rewritting file %s", original_file->file_path);
                        }
                    }
                }
                break;
            }
            case FS_FILE_DELETED_ACTION: {
                if (new_changes[i].update_mem_param != NULL) { 
                    mem_protected_file_t* new_change_param = (mem_protected_file_t*)new_changes[i].update_mem_param;

                    if (new_change_param->file->is_elf) {
                        backup.downloadRemoteELF(*(new_change_param->file));
                    } else {
                        fs->restoreFileState(new_change_param->file);
                    }

                    if (chmod(new_change_param->file->file_path, new_change_param->file->attrib) == -1) {
                        sp_error(SP_FILEOP, "Failed to revert attribute after rewritting file %s", new_change_param->file->file_path);
                    }
                }
                break;
            }
            case FS_FILE_CREATED_ACTION: {
                if (new_changes[i].action_param != NULL) { 
                    char dir_cpy[PATH_MAX];
                    char *file_dir;
                    protected_file_t* created_file = (protected_file_t*)new_changes[i].action_param;

                    strcpy(dir_cpy, created_file->file_path);
                    file_dir = dirname(dir_cpy);

                    if (fan->unmark(file_dir, NULL, 0) == -1) {
                        sp_error(SP_FILEOP, "Failed to unmark directory %s to revert file creation", file_dir);
                    }
                    if (SYSTEM_CMD(FILE_REMOVE_CMD_FMT, created_file->file_path) == -1) {
                        sp_error(SP_FILEOP, "Failed to revert file %s from being created", created_file->file_path);
                    }
                    if (fan->mark(file_dir, NULL, 0) == -1) {
                        sp_error(SP_FILEOP, "Failed to mark directory %s after preventing file creation", file_dir);
                    }
                }
                break;
            }
            case FS_FILE_ATTRIB_CHANGED_ACTION: {
                if (new_changes[i].update_mem_param != NULL) { 
                    mem_protected_file_t* new_change_param = (mem_protected_file_t*)new_changes[i].update_mem_param;

                    if (new_change_param->old_file != NULL) {
                        if (chmod(new_change_param->old_file->file_path, new_change_param->old_file->attrib) == -1) {
                            sp_error(SP_FILEOP, "Failed to revert file %s attribute, %s", new_change_param->old_file->file_path, strerror(errno));
                        }
                        protectedFileDealloc(new_change_param->old_file);
                    } else {
                        sp_error(SP_FILEOP, "Failed to revert file %s attribute, cannot file reference to old file", new_change_param->file->file_path);
                    }
                }
                break;
            }
            default: {
                sp_error(SP_FILEOP, "Received unexpected type of action");
                break;
            }
        }
    }

    fan->setPermResp(FAN_DENY);
}

void FileManager::applyNewChangesAndUpdateMemory(query_history_record_t* history_record)
{
    for (size_t i = 0; i < new_changes.size(); i++) {
        if (new_changes[i].action != FS_ACTION_NONE && history_record != NULL) {
            switch (new_changes[i].action) {
                case FS_FILE_DELETED_ACTION: 
                case FS_FILE_CREATED_ACTION:
                case FS_FILE_MODIFIED_ACTION:
                case FS_FILE_ATTRIB_CHANGED_ACTION: {
                    mem_protected_file_t* change = (mem_protected_file_t*)new_changes[i].update_mem_param;

                    if (change != NULL && change->file != NULL && change->file->file_path != NULL) {
                        strcpy(history_record->action_type, fsStrAction(new_changes[i].action));
                        hist->recordProtectedParentDirAdd(history_record, change->parent_protected_dir);
                        hist->recordTamperingLocAdd(history_record, change->file->file_path);
                    }
                    break;
                }
                case FS_PROTECTED_DIR_DELETED_ACTION:
                case FS_SUB_DIR_DELETED_ACTION: {
                    mem_protected_dir_t* removed_dir = (mem_protected_dir_t*)new_changes[i].update_mem_param;

                    if (removed_dir != NULL) {
                        strcpy(history_record->action_type, fsStrAction(new_changes[i].action));
                        hist->recordProtectedParentDirAdd(history_record, removed_dir->ppd->path.c_str());
                        hist->recordTamperingLocAdd(history_record, removed_dir->old_dir->path.c_str());
                    }
                    break;
                }
                case FS_PROTECTED_DIR_ATTRIB_CHANGED_ACTION: 
                case FS_SUB_DIR_ATTRIB_CHANGED_ACTION: {
                    mem_protected_dir_t* dir = (mem_protected_dir_t*)new_changes[i].update_mem_param;

                    if (dir != NULL) {
                        strcpy(history_record->action_type, fsStrAction(new_changes[i].action));
                        hist->recordProtectedParentDirAdd(history_record, dir->ppd->path.c_str());
                        hist->recordTamperingLocAdd(history_record, dir->new_dir->path.c_str());
                    }
                    break;
                }
                case FS_SUB_DIR_CREATED_ACTION: {
                    mem_protected_dir_t* new_dir = (mem_protected_dir_t*)new_changes[i].update_mem_param;

                    if (new_dir != NULL) {
                        strcpy(history_record->action_type, fsStrAction(new_changes[i].action));
                        hist->recordProtectedParentDirAdd(history_record, new_dir->ppd->path.c_str());
                        hist->recordTamperingLocAdd(history_record, new_dir->new_dir->path.c_str());
                    }
                    break;
                }
                case FS_ACTION_NONE:
                default:
                    break;
            }
        }
        new_changes[i].exec_cb(fmcb, 
                               new_changes[i].action_param, 
                               new_changes[i].update_mem_param, 
                               true,
                               new_changes[i].action);
    }
    
    clearStoredChanges();
    sp_debug(SP_FILEOP, "New changes applied");
}

void FileManager::removeProtectedDirFromMem(protected_dir_t* removing_dir)
{
    if (removing_dir->path.back() != '/') {
        removing_dir->path += '/';
    }

    auto it = protected_dirs.find(*removing_dir);

    /* safe check if the removing protected directory exists in memory to avoid unexpected behaviour */
    if (it != protected_dirs.end()) {
        for (size_t i = 0; i < it->first.files.size(); i++) {
            protectedFileDealloc(it->first.files[i]);
        }
        for (size_t i = 0; i < it->second.size(); i++) {
            for (size_t j = 0; j < it->second[i].files.size(); j++) {
                protectedFileDealloc(it->second[i].files[j]);
            }
            it->second[i].files.clear();
        }

        it->second.clear();
        protected_dirs.erase(it);
        
        trust->auditctlUnwatchDir(removing_dir->path.c_str());
    } else {
        sp_error(SP_FILEOP, "Failed to remove %s from memory, directory doesn't exist in memory", removing_dir->path.c_str());
    }
}

void FileManager::updateProtectedDirAttribFromMem(protected_dir_t* old_ppd, protected_dir_t* new_ppd)
{
    std::vector<protected_dir_t> sub_dirs = protected_dirs[*old_ppd];

    protected_dirs.erase(*old_ppd);
    protected_dirs[*new_ppd] = sub_dirs;
}

void FileManager::removeSubDirFromMem(protected_dir_t* deleted_sub_dir, protected_dir_t* parent_protected_dir)
{
    if (deleted_sub_dir->path.back() != '/') {
        deleted_sub_dir->path += '/';
    }

    if (parent_protected_dir->path.back() != '/') {
        parent_protected_dir->path += '/';
    }

    for (size_t i = 0; i < protected_dirs[*parent_protected_dir].size(); i++) {
        if (strcmp(protected_dirs[*parent_protected_dir][i].path.c_str(), deleted_sub_dir->path.c_str()) == 0 ||
            strstr(protected_dirs[*parent_protected_dir][i].path.c_str(), deleted_sub_dir->path.c_str()) != NULL) {
            for (size_t j = 0; j < protected_dirs[*parent_protected_dir][i].files.size(); j++) {
                protectedFileDealloc(protected_dirs[*parent_protected_dir][i].files[j]);
            }

            protected_dirs[*parent_protected_dir].erase(protected_dirs[*parent_protected_dir].begin() + i);
            i--;
        }
    }
}

void FileManager::addSubDirToMem(const protected_dir_t* ppd, protected_dir_t* new_sub_dir)
{
    protected_dirs[*ppd].push_back(*(protectedDirDup(new_sub_dir)));
}

void FileManager::updateSubDirAttribFromMem(protected_dir_t* ppd, protected_dir_t* old_sub_dir, protected_dir_t* new_sub_dir)
{
    for (size_t i = 0; i < protected_dirs[*ppd].size(); i++) {
        if (strcmp(protected_dirs[*ppd][i].path.c_str(), old_sub_dir->path.c_str()) == 0) {
            protected_dirs[*ppd][i].attrib = new_sub_dir->attrib;
        }
    }
}

void FileManager::removeProtectedFileFromMem(const char *parent_protected_dir, protected_file_t *removing_file)
{
    protected_dir_t ppd = {};
    protected_dir_t* file_dir = NULL;

    ppd.path = parent_protected_dir;

    if (ppd.path.back() != '/') {
        ppd.path += '/';
    }

    /* look up a reference to parent protected dir */
    file_dir = protectedDirLookup({}, parent_protected_dir);

    if (file_dir != NULL) {

        for (size_t i = 0; i < file_dir->files.size(); i++) {
            if (strcmp(file_dir->files[i]->file_path, removing_file->file_path) == 0) {
                protectedFileDealloc(file_dir->files[i]);
                file_dir->files.erase(file_dir->files.begin() + i);
            }
        }
    } else {
        for (size_t i = 0; i < protected_dirs[ppd].size(); i++) {
            for (size_t j = 0; j < protected_dirs[ppd][i].files.size(); j++) {
                if (strcmp(protected_dirs[ppd][i].files[j]->file_path, removing_file->file_path) == 0) {
                    protectedFileDealloc(protected_dirs[ppd][i].files[j]);
                    protected_dirs[ppd][i].files.erase(protected_dirs[ppd][i].files.begin() + j);
                }
            }
        }
    }
}

void FileManager::addProtectedFileToMem(const char* parent_protected_dir, protected_file_t *created_file)
{
    protected_dir_t ppd = {};
    char* file_dir = NULL;
    char file_path_cpy[PATH_MAX];

    ppd.path = parent_protected_dir;

    if (ppd.path.back() != '/') {
        ppd.path += '/';
    }

    strcpy(file_path_cpy, created_file->file_path);
    file_dir = dirname(file_path_cpy);

    if (file_dir[strlen(file_dir) - 1] != '/') {
        strcat(file_dir, "/");
    }

    if (strcmp(file_dir, ppd.path.c_str()) == 0) {
        auto it = protected_dirs.find(ppd);

        if (it != protected_dirs.end()) {
            std::vector<protected_dir_t> tmp = protected_dirs[ppd];

            ppd = it->first;
            ppd.files.push_back(protectedFileDup(created_file));

            protected_dirs.erase(it);
            protected_dirs[ppd] = tmp;
        } else {
            sp_error(SP_FILEOP, "Unexpected error, unable to find parent dir %s in memory", ppd.path.c_str());
        }
    } else {
        for (size_t i = 0; i < protected_dirs[ppd].size(); i++) {
            if (strcmp(protected_dirs[ppd][i].path.c_str(), file_dir) == 0) {
                protected_dirs[ppd][i].files.push_back(protectedFileDup(created_file));
                break;
            }
        }
    }
}

void FileManager::modifyProtectedFileFromMem(const char *parent_protected_dir, protected_file_t *modified_file)
{
    protected_dir_t ppd = {};
    protected_file_t* mem_file = NULL;

    ppd.path = parent_protected_dir;

    if (ppd.path.back() != '/') {
        ppd.path += '/';
    }

    mem_file = protectedFileLookup(ppd, modified_file->file_path);
    if (mem_file != NULL) {
        if (mem_file->content != NULL) {
            free(mem_file->content);
        }
        mem_file->content = (unsigned char*)strdup((char*)modified_file->content);
        if (mem_file->sha256 != NULL) {
            free(mem_file->sha256);
        }
        mem_file->sha256 = (unsigned char*)strdup((char*)modified_file->sha256);
    } else {
        sp_error(SP_FILEOP, "Failed to update file %s content in memory, file does not exist in memory", modified_file->file_path);
    }
}

void FileManager::changeProtectedFileAttribFromMem(const char *parent_protected_dir, protected_file_t *modified_file)
{
    protected_dir_t ppd = {};
    protected_file_t* mem_file = NULL;

    ppd.path = parent_protected_dir;

    if (ppd.path.back() != '/') {
        ppd.path += '/';
    }

    mem_file = protectedFileLookup(ppd, modified_file->file_path);
    if (mem_file != NULL) {
        mem_file->attrib = modified_file->attrib;
    }
}

void FileManager::removeAllProtectedDirsExceptConfig()
{
    for (auto protected_dir : protected_dirs) {
        /* skip our default config dir, since we still want to protect that */
        if (strcmp(protected_dir.first.path.c_str(), SELF_PROTECT_CONFIG_DIR) != 0) {
            for (size_t i = 0; i < protected_dir.first.files.size(); i++) {
                protectedFileDealloc(protected_dir.first.files[i]);
            }
            if (fan->unmark(protected_dir.first.path.c_str(), NULL, 0) == -1) {
                sp_error(SP_CALLBACK, "Failed to unmark protected directory %s and its sub-directories", protected_dir.first.path.c_str());
            }

            for (size_t i = 0; i < protected_dir.second.size(); i++) {
                for(size_t j = 0; j < protected_dir.second[i].files.size(); j++) {
                    protectedFileDealloc(protected_dir.second[i].files[j]);
                }
                if (fan->unmark(protected_dir.second[i].path.c_str(), NULL, 0) == -1) {
                    sp_error(SP_CALLBACK, "Failed to unmark protected directory %s and its sub-directories", protected_dir.second[i].path.c_str());
                }
            }
        }
    }
}

void FileManager::removeStaleProtectedDirs(std::vector<std::string>* new_protected_dirs)
{
    for (auto it = protected_dirs.begin(); it != protected_dirs.end(); ) {
        if (strcmp(it->first.path.c_str(), SELF_PROTECT_CONFIG_DIR) == 0) {
            it++;
            continue;
        }

        if (std::find(new_protected_dirs->begin(),
                      new_protected_dirs->end(),
                      it->first.path) == new_protected_dirs->end()) {
            for (size_t i = 0; i < it->first.files.size(); i++) {
                protectedFileDealloc(it->first.files[i]);
            }
            if (fan->unmark(it->first.path.c_str(), NULL, 0) == -1) {
                sp_error(SP_CALLBACK, "Failed to unmark protected directory %s", it->first.path.c_str());
            }

            for (size_t i = 0; i < it->second.size(); i++) {
                for (size_t j = 0; j < it->second[i].files.size(); j++) {
                    protectedFileDealloc(it->second[i].files[j]);
                }
                if (fan->unmark(it->second[i].path.c_str(), NULL, 0) == -1) {
                    sp_error(SP_CALLBACK, "Failed to unmark protected directory %s", it->second[i].path.c_str());
                }
            }
            it = protected_dirs.erase(it);
        } else {
            it++;
        }
    }
}

void FileManager::addOrRemoveProtectedDirs()
{
    /* safe check */
    if (fs->fileExist(SELF_PROTECT_CONFIG_LIST_PATH)) {
        std::ifstream config_list_file(SELF_PROTECT_CONFIG_LIST_PATH);
        std::string dir;
        std::vector<std::string> new_protected_dirs;

        fan->setPermResp(FAN_ALLOW);
        /** 
         * since the file has been updated up to this point, we can just read it again and compare it with the current memory 
         */
        while (std::getline(config_list_file, dir)) {
            if (dir.back() != '/') {
                dir += '/';
            }
            new_protected_dirs.push_back(dir);
        }
        config_list_file.close();

        removeStaleProtectedDirs(&new_protected_dirs);
        loadProtectedDirs();

        for (auto protected_dir : protected_dirs) {
            markProtectedDirAndSubDirs(protected_dir.first.path);
        }
        fan->setPermResp(FAN_DENY);
    } else {
        sp_error(SP_FILEOP, "Cannot add or remove protected dirs, config list file does not exist");
    }
}

void FileManager::discardNewChanges(query_history_record_t* history_record)
{
    for (size_t i = 0; i < new_changes.size(); i++) {
        if (new_changes[i].action != FS_ACTION_NONE && history_record != NULL) {
            switch (new_changes[i].action) {
                case FS_FILE_DELETED_ACTION: 
                case FS_FILE_CREATED_ACTION:
                case FS_FILE_MODIFIED_ACTION:
                case FS_FILE_ATTRIB_CHANGED_ACTION: {
                    mem_protected_file_t* change = (mem_protected_file_t*)new_changes[i].update_mem_param;

                    if (change != NULL && change->file != NULL && change->file->file_path != NULL) {
                        if (change->file != NULL) {
                            if (change->file->file_path != NULL) {
                                strcpy(history_record->action_type, fsStrAction(new_changes[i].action));
                                hist->recordProtectedParentDirAdd(history_record, change->parent_protected_dir);
                                hist->recordTamperingLocAdd(history_record, change->file->file_path);
                            }
                        }
                    }
                    break;
                }
                case FS_PROTECTED_DIR_DELETED_ACTION:
                case FS_SUB_DIR_DELETED_ACTION: {
                    mem_protected_dir_t* removed_dir = (mem_protected_dir_t*)new_changes[i].update_mem_param;

                    if (removed_dir != NULL) {
                        strcpy(history_record->action_type, fsStrAction(new_changes[i].action));
                        hist->recordProtectedParentDirAdd(history_record, removed_dir->ppd->path.c_str());
                        hist->recordTamperingLocAdd(history_record, removed_dir->old_dir->path.c_str());
                    }
                    break;
                }
                case FS_PROTECTED_DIR_ATTRIB_CHANGED_ACTION: 
                case FS_SUB_DIR_ATTRIB_CHANGED_ACTION: {
                    mem_protected_dir_t* dir = (mem_protected_dir_t*)new_changes[i].update_mem_param;

                    if (dir != NULL) {
                        strcpy(history_record->action_type, fsStrAction(new_changes[i].action));
                        hist->recordProtectedParentDirAdd(history_record, dir->ppd->path.c_str());
                        hist->recordTamperingLocAdd(history_record, dir->new_dir->path.c_str());
                    }
                    break;
                }
                case FS_SUB_DIR_CREATED_ACTION: {
                    mem_protected_dir_t* new_dir = (mem_protected_dir_t*)new_changes[i].update_mem_param;

                    if (new_dir != NULL) {
                        strcpy(history_record->action_type, fsStrAction(new_changes[i].action));
                        hist->recordProtectedParentDirAdd(history_record, new_dir->ppd->path.c_str());
                        hist->recordTamperingLocAdd(history_record, new_dir->new_dir->path.c_str());
                    }
                    break;
                }
                case FS_ACTION_NONE:
                default:
                    break;
            }
        }

        new_changes[i].exec_cb(fmcb,
                               new_changes[i].action_param,
                               new_changes[i].update_mem_param,
                               false,
                               new_changes[i].action);
    }

    clearStoredChanges();
    sp_debug(SP_FILEOP, "New changes memory freed");
}

void FileManager::blockFileOp(SelfProtectService* service)
{
    pthread_t tid;
    thread_block_fileop_param_t *param = (thread_block_fileop_param_t*)calloc(sizeof(thread_block_fileop_param_t), 1);

    if (param != NULL) {
        param->protected_dirs = (char**)malloc(sizeof(char*) * 0);
        param->num_dirs = 0;
        param->service = service;

        service->maliciousStateSet(true);

        for (auto protected_dir : protected_dirs) {
            if (SYSTEM_CMD(DIR_ATTR_CMD_FMT, DIR_UNBLOCK_OPT ,protected_dir.first.path.c_str()) != -1) {
                if (SYSTEM_CMD(HIDDEN_SW_FILE_REMOVE_CMD_FMT, protected_dir.first.path.c_str()) == -1) {
                    sp_error(SP_FILEOP, "Failed to remove hidden .sw files for dir %s, they could be non-existent", protected_dir.first.path.c_str());
                }
            }

            param->num_dirs++;
            param->protected_dirs = (char**)realloc(param->protected_dirs, param->num_dirs * sizeof(char*));
            if (param->protected_dirs != NULL) {
                param->protected_dirs[param->num_dirs - 1] = (char*)malloc(sizeof(char) * PATH_MAX);
                if (param->protected_dirs[param->num_dirs - 1] != NULL) {
                    strcpy(param->protected_dirs[param->num_dirs - 1], protected_dir.first.path.c_str());
                }
            } else {
                sp_error(SP_FILEOP, "Failed to allocate memory");
            }

            fan->setPermResp(FAN_ALLOW);

            if (SYSTEM_CMD(DIR_ATTR_CMD_FMT, DIR_BLOCK_OPT, protected_dir.first.path.c_str()) == -1) {
                sp_error(SP_FILEOP, "Failed to block operations on directory %s", protected_dir.first.path.c_str());
            }

            fan->setPermResp(FAN_DENY);
        }

        pthread_create(&tid, NULL, FileSystem::dirsActionLockWithInterval, (void*)param);
    } else {
        sp_error(SP_FILEOP, "failed to block file operations, memory allocation failed");
    }
}

void FileManager::allDirActionLock(bool do_lock)
{
    for (auto protected_dir : protected_dirs) {
        if (do_lock) {
            if (SYSTEM_CMD(DIR_ATTR_CMD_FMT, DIR_BLOCK_OPT, protected_dir.first.path.c_str()) == -1) {
                sp_error(SP_FILEOP, "Failed to immutate dir %s, %s", protected_dir.first.path.c_str(), strerror(errno));
            }
        } else {
            if (SYSTEM_CMD(DIR_ATTR_CMD_FMT, DIR_UNBLOCK_OPT, protected_dir.first.path.c_str()) == -1) {
                sp_error(SP_FILEOP, "Failed to unblock dir %s, %s", protected_dir.first.path.c_str(), strerror(errno));
            }
        }
    }

    /* can't immutate sp_client since we need thsi to prompt token terminal */
    if (SYSTEM_CMD(DIR_ATTR_CMD_FMT, DIR_UNBLOCK_OPT, SELF_PROTECT_CONFIG_BIN_DIR) == -1) {
        sp_error(SP_FILEOP, "Failed to unblock dir %s, %s", SELF_PROTECT_CONFIG_BIN_DIR, strerror(errno));
    }
}

void FileManager::allDirActionLockFromConfig()
{
    if (fs->fileExist(SELF_PROTECT_CONFIG_LIST_PATH)) {
        if (!fs->fileEmpty(SELF_PROTECT_CONFIG_LIST_PATH)) {
            std::ifstream config_list_file(SELF_PROTECT_CONFIG_LIST_PATH);
            std::string dir;

            while (std::getline(config_list_file, dir)) {
                struct stat d_stat;
                char absolute_home_path[PATH_MAX];

                if (!fs->pathIsAbsolute(dir.c_str(), absolute_home_path)) {
                    sp_error(SP_FILEOP, "Failed to set up block during initialization for %s, relative path not supported", dir.c_str());
                    continue;
                }

                dir.clear();
                dir.append(absolute_home_path);

                if (stat(dir.c_str(), &d_stat) == -1) {
                    sp_error(SP_FILEOP, "Unable to set up block during initialization, failed to stat %s, %s", dir.c_str(), strerror(errno));
                    continue;
                }

                if (!S_ISREG(d_stat.st_mode) && !S_ISDIR(d_stat.st_mode)) {
                    sp_error(SP_FILEOP, "%s is neither a directory nor file, skipping blocking during initialization", dir.c_str());
                    continue;
                }

                if (S_ISREG(d_stat.st_mode)) {
                    const char *dir_cpy = dir.c_str();
                    std::string parent_dir(dirname((char*)dir_cpy));
                    dir = parent_dir;
                    sp_info(SP_FILEOP, "Protected dir is a file, converted to its parent_directory");
                }

                if (dir.back() != '/') {
                    dir += '/';
                }
                
                if (SYSTEM_CMD(DIR_ATTR_CMD_FMT, DIR_BLOCK_OPT, dir.c_str()) == -1) {
                    sp_error(SP_FILEOP, "Failed to block %s during initialization", dir.c_str());
                }
            }

            config_list_file.close();
        }
    }

    if (SYSTEM_CMD(DIR_ATTR_CMD_FMT, DIR_BLOCK_OPT, SELF_PROTECT_CONFIG_DIR) == -1) {
        sp_error(SP_FILEOP, "Failed to block %s during initialization", SELF_PROTECT_CONFIG_DIR);
    }
}

void FileManager::unblockFileOp()
{
    for (auto protected_dir : protected_dirs) {
        if (fs->dirExist(protected_dir.first.path.c_str())) {
            if (SYSTEM_CMD(DIR_ATTR_CMD_FMT, DIR_UNBLOCK_OPT, protected_dir.first.path.c_str()) == 0) {
                sp_info(SP_FILEOP, "Monitoring paused successfully for dir %s", protected_dir.first.path.c_str());
            } else {
                sp_error(SP_FILEOP, "Failed to pause monitor service for dir %s", protected_dir.first.path.c_str());
            }
        }
    }

    if (SYSTEM_CMD(FILE_ATTR_CMD_FMT, DIR_BLOCK_OPT, SELF_PROTECT_EXEC_PATH) == -1) {
        sp_error(SP_FILEOP, "Failed to protect self protect service executable file");
    }
}

void FileManager::unmarkProtectedDirAndSubDirs(std::string removed_protected_dir)
{
    protected_dir_t pd = {};

    pd.path = removed_protected_dir;

    for (size_t i = 0 ; i < protected_dirs[pd].size(); i++) {
        if (fan->unmark(protected_dirs[pd][i].path.c_str(), NULL, 0) == -1) {
            sp_error(SP_FILEOP, "Failed to unmark sub-directory %s", protected_dirs[pd][i].path.c_str());
        }
    }

    if (fan->unmark(removed_protected_dir.c_str(), NULL, 0) == -1) {
        sp_error(SP_FILEOP, "Failed to unmark protected directory %s", removed_protected_dir.c_str());
    }
}

void FileManager::markProtectedDirAndSubDirs(std::string added_protected_dir)
{
    protected_dir_t pd = {};

    pd.path = added_protected_dir;
    for (size_t i = 0 ; i < protected_dirs[pd].size(); i++) {
        if (fan->mark(protected_dirs[pd][i].path.c_str(), NULL, 0) == -1) {
            sp_error(SP_FILEOP, "Failed to mark sub-directory %s", protected_dirs[pd][i].path.c_str());
        }
    }

    if (fan->mark(added_protected_dir.c_str(), NULL, 0) == -1) {
        sp_error(SP_FILEOP, "Failed to mark protected directory %s", added_protected_dir.c_str());
    }
}


void FileManager::storeDirContent(const char* path_to_dir, std::vector<protected_file_t*>* files)
{
    DIR *d;
    struct dirent *dir;

    d = opendir(path_to_dir);
    if (d) {
        while ((dir = readdir(d)) != NULL) {
            protected_file_t pf;

            if (DIR_IS_HIDDEN(dir->d_name)) {
                continue;
            }
            if (dir->d_type & DT_DIR) {
                continue;
            }
            
            if (path_to_dir[strlen(path_to_dir) - 1] != '/') {
                sprintf(pf.file_path, "%s/%s", path_to_dir, dir->d_name);
            } else {
                sprintf(pf.file_path, "%s%s", path_to_dir, dir->d_name);
            }

            pf.attrib = fs->getFileAttrib(pf.file_path);
            pf.sha256 = fs->getFileSHA256(pf.file_path);
            if (pf.sha256 == NULL) {
                sp_error(SP_FILEOP, "Failed to get sha256 digest for file %s", pf.file_path);
            }
            /* we don't want to store executables content into memory as it can cause unexpected behaviours
            *  Instead, we would want to just recompile with source file when we detect it being tampered
            */
            if (!fs->fileIsELF(pf.file_path)) {
                pf.content = fs->getFileContent(pf.file_path);
                pf.is_elf = false;
                backup.uploadNewRemoteFile(pf);
            } else {
                pf.content = NULL;
                pf.is_elf = true;
                backup.uploadNewRemoteELF(pf);
            }

            files->push_back(protectedFileDup(&pf));

            if (pf.content != NULL) {
                free(pf.content);
            }
            if (pf.sha256 != NULL) {
                free(pf.sha256);
            } 
        }
        closedir(d);
    } else {
        sp_error(SP_FILEOP, "Cannot open directory %s", path_to_dir);
    }
}

void FileManager::printAllProtectedDirs()
{
    for (auto dir : protected_dirs) {
        printf("Protected dir: %s, attrib: %3o\n", dir.first.path.c_str(), dir.first.attrib);
        printf("\tFiles:\n");
        for (size_t i = 0; i < dir.first.files.size(); i++) {
            protectedFilePrint(dir.first.files[i]);
            printf("\n");
        }
        for (size_t i = 0; i < dir.second.size(); i++) {
            printf("Sub-dir: %s, attrib: %3o\n", dir.second[i].path.c_str(), dir.second[i].attrib);
            for (size_t j = 0; j < dir.second[i].files.size(); j++) {
                protectedFilePrint(dir.second[i].files[j]);
                printf("\n");
            }
        }
        printf("\n");
    }
}

void FileManager::protectedFilePrint(protected_file_t* file)
{
    if (file != NULL) {
        printf("\t\tFile %s\n", file->file_path);
        if (file->sha256 != NULL) {
            printf("\t\tFile sha256: %s\n", file->sha256);
        }
        printf("\t\tFile attribute: %3o\n", file->attrib);
        if (file->content != NULL) {
            printf("\t\tFile content:\n%s\n", file->content);
        }
    }
}

void FileManager::loadProtectedDirs()
{
    if (fs->fileExist(SELF_PROTECT_CONFIG_LIST_PATH)) {
        /* don't need to read in the config list file if it's empty */
        if (!fs->fileEmpty(SELF_PROTECT_CONFIG_LIST_PATH)) {
            std::ifstream config_list_file(SELF_PROTECT_CONFIG_LIST_PATH);
            protected_dir_t dir = {};

            while (std::getline(config_list_file, dir.path)) {
                struct stat d_stat;
                char **sub_dirs = NULL;
                int num_sub_dirs = 0;
                bool parent_dir_entered = false;
                char absolute_home_path[PATH_MAX];

                if (!fs->pathIsAbsolute(dir.path.c_str(), absolute_home_path)) {
                    sp_error(SP_FILEOP, "Skipping %s, relative path not supported", dir.path.c_str());
                    continue;
                }

                dir.path.clear();
                dir.path.append(absolute_home_path);

                if (stat(dir.path.c_str(), &d_stat) == -1) {
                    sp_error(SP_FILEOP, "Failed to stat %s, %s", dir.path.c_str(), strerror(errno));
                    continue;
                }

                if (!S_ISREG(d_stat.st_mode) && !S_ISDIR(d_stat.st_mode)) {
                    sp_error(SP_FILEOP, "%s is neither a directory nor file, skipping", dir.path.c_str());
                    continue;
                }

                if (S_ISREG(d_stat.st_mode)) {
                    const char *dir_cpy = dir.path.c_str();
                    std::string parent_dir(dirname((char*)dir_cpy));
                    dir.path = parent_dir;
                    sp_info(SP_FILEOP, "Protected dir is a file, converted to its parent_directory");
                }

                if (dir.path.back() != '/') {
                    dir.path += '/';
                }

                if (!getProtectedDirFromSubDir(dir.path.c_str()).path.empty()) {
                    sp_info(SP_FILEOP, "Config list entry %s is a sub-directory of an existing protected directory, skipping", dir.path.c_str());
                    continue;
                }

                dir.attrib = fs->getDirAttrib(&dir.path);
                dir.fd = fs->getDirFd(dir.path.c_str());
                storeDirContent(dir.path.c_str(), &dir.files);

                for (auto protected_dir : protected_dirs) {
                    if (strstr(protected_dir.first.path.c_str(), dir.path.c_str()) != NULL) {
                        std::string dir_cpy = dir.path;

                        sp_info(SP_FILEOP, "Config list entry %s is a parent dir of an existing protected directory, swapping locations of these in memory", dir.path.c_str());
                        protected_dirs[dir].push_back(protected_dir.first);
                        for (size_t i = 0; i < protected_dirs[protected_dir.first].size(); i++) {
                            protected_dirs[dir].push_back(protected_dirs[protected_dir.first][i]);
                        }

                        trust->auditctlUnwatchDir(protected_dir.first.path.c_str());
                        trust->auditctlWatchDir(dir.path.c_str());

                        /* find out if this directory has any other sub-directories of its own */
                        if (fs->getSubDirs(&sub_dirs, &num_sub_dirs, (char*)dir_cpy.c_str()) == -1) {
                            sp_error(SP_FILEOP, "Failed to get sub directories for %s, skip storing other sub_directories", dir.path.c_str());
                        } else {
                            if (sub_dirs != NULL && num_sub_dirs > 0) {
                                for (int i = 0; i < num_sub_dirs; i++) {
                                    protected_dir_t sub_dir = {};

                                    sub_dir.path = sub_dirs[i];
                                    if (sub_dir.path.back() != '/') {
                                        sub_dir.path += '/';
                                    }
                                    sub_dir.attrib = fs->getDirAttrib(&sub_dir.path);
                                    sub_dir.fd = fs->getDirFd(sub_dir.path.c_str());
                                    storeDirContent(sub_dir.path.c_str(), &sub_dir.files);

                                    if (strcmp(protected_dir.first.path.c_str(), sub_dir.path.c_str()) != 0) {
                                        protected_dirs[dir].push_back(sub_dir);
                                    }
                                }
                            }
                        }
                        fs->array2DFree((const void**)sub_dirs, num_sub_dirs);

                        protected_dirs.erase(protected_dir.first);
                        parent_dir_entered = true;
                        break;
                    }
                }

                if (parent_dir_entered) {
                    continue;
                }

                if (fs->dirExist(dir.path.c_str())) {
                    std::string dir_cpy = dir.path;

                    if (fs->getSubDirs(&sub_dirs, &num_sub_dirs, (char*)dir_cpy.c_str()) == -1) {
                        std::vector<protected_dir_t> empty_sub_dir; 

                        sp_error(SP_FILEOP, "Failed to get sub directories for %s, skip storing sub_directories", dir.path.c_str());
                        protected_dirs[dir] = empty_sub_dir;
                    } else {
                        if (sub_dirs != NULL && num_sub_dirs > 0) {
                            for (int i = 0; i < num_sub_dirs; i++) {
                                protected_dir_t sub_dir = {};

                                sub_dir.path = sub_dirs[i];
                                if (sub_dir.path.back() != '/') {
                                    sub_dir.path += '/';
                                }
                                sub_dir.attrib = fs->getDirAttrib(&sub_dir.path);
                                sub_dir.fd = fs->getDirFd(sub_dir.path.c_str());
                                storeDirContent(sub_dir.path.c_str(), &sub_dir.files);

                                protected_dirs[dir].push_back(sub_dir);
                            }
                        } else {
                            std::vector<protected_dir_t> empty_sub_dir; 
                            protected_dirs[dir] = empty_sub_dir;
                        }
                    }

                    trust->auditctlWatchDir(dir.path.c_str());

                    fs->array2DFree((const void**)sub_dirs, num_sub_dirs);
                } else {
                    sp_error(SP_FILEOP, "Protected dir %s not found", dir.path.c_str());
                }
            }

            config_list_file.close();
        }
    } else {
        sp_error(SP_FILEOP, "config list file does not exist, unable to protect other directories");
    }
}