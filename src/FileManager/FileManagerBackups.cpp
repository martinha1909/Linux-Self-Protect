#include "include/FileManagerBackups.hpp"

FileManagerBackups::FileManagerBackups() : ft()
{
    
}

void FileManagerBackups::setMutex(pthread_mutex_t *mutex)
{
    ft.setMutex(mutex);
}

std::string FileManagerBackups::sanitizeDirStr(std::string dir)
{
    std::string ret(dir);

    /* dropbox API does not allow to create a directory ending with a '/' */
    if (ret.back() == '/') {
        ret.pop_back();
    }

    return ret;
}

std::string FileManagerBackups::sanitizeDirStr(const char* dir)
{
    std::string dir_s(dir);
    return sanitizeDirStr(dir_s);
}

void FileManagerBackups::transportWait()
{
    while (ft.transportInProgress()) {
        
    }
}

void FileManagerBackups::elfTransportWait(pid_t pid)
{
    int err = -1;
    int status;

    do {
        err = waitpid(pid, &status, WUNTRACED | WCONTINUED);
        if (err == -1) {
            sp_error(SP_BACKUP, "Failed to wait for child to transport elf file, %s", strerror(errno));
            break;
        }
    } while (!WIFEXITED(status) && !WIFSIGNALED(status));
}

void FileManagerBackups::createRemoteDirAndSubDirs(protected_dir_t protected_dir, std::vector<protected_dir_t> sub_dirs)
{
    protected_dir.path = sanitizeDirStr(protected_dir.path);

    transportWait();
    ft.createRemoteDir(protected_dir.path);

    for (size_t i = 0; i < sub_dirs.size(); i++) {
        sub_dirs[i].path = sanitizeDirStr(sub_dirs[i].path);
        transportWait();
        ft.createRemoteDir(sub_dirs[i].path);
    }
}

void FileManagerBackups::deleteRemoteDirOrFile(const char* path, bool is_file)
{
    std::string path_s = sanitizeDirStr(path);
    transportWait();
    ft.deleteRemoteDirOrFile(path_s, is_file);
}

void FileManagerBackups::uploadNewRemoteFile(const protected_file_t protected_file)
{
    transportWait();
    ft.createRemoteFile(protected_file.file_path, protected_file.content, protected_file.attrib);
}

void FileManagerBackups::updateRemoteFile(const protected_file_t protected_file)
{
    transportWait();
    ft.deleteRemoteDirOrFile(protected_file.file_path, true);
    transportWait();
    ft.createRemoteFile(protected_file.file_path, protected_file.content, protected_file.attrib);
}

void FileManagerBackups::downloadRemoteELF(const protected_file_t protected_elf)
{
    pid_t pid;

    /* fork will return pid of the child process to the parent, and return 0 to the child
       we want to execute the program in the child and wait for the child to finish execute in the parent to set the attribute */
    pid = fork();
    if (pid == -1) {
        sp_error(SP_BACKUP, "Failed to fork process, %s", strerror(errno));
    } else if (pid == 0) {
        char* path = (char*)SELF_PROTECT_BIN_UPLOAD_PATH;
        char* token = (char*)DROPBOX_API_AUTH_TOKEN;
        char* action = (char*)"download";
        char *args[] = {path, token, action, (char*)protected_elf.file_path, (char*)protected_elf.file_path, NULL};

        transportWait();
        execv(args[0], args);
    } else {
        /* pid received here will be the pid of child */
        elfTransportWait(pid);

        sp_info(SP_BACKUP, "ELF file %s downloaded successfully", protected_elf.file_path);

        if (chmod(protected_elf.file_path, protected_elf.attrib) == -1) {
            sp_error(SP_BACKUP, "Failed to restore attribute for ELF %s after downloading, %s", protected_elf.file_path, strerror(errno));
        }
    }
}

void FileManagerBackups::uploadNewRemoteELF(const protected_file_t protected_elf)
{
    pid_t pid;

    pid = fork();
    if (pid == -1) {
        sp_error(SP_BACKUP, "Failed to fork process, %s", strerror(errno));
    } else if (pid == 0) {
        /* fork will return pid of the child process to the parent, and return 0 to the child
           we want to execute the program in the child */
        char* path = (char*)SELF_PROTECT_BIN_UPLOAD_PATH;
        char* token = (char*)DROPBOX_API_AUTH_TOKEN;
        char* action = (char*)"upload";
        char *args[] = {path, token, action, (char*)protected_elf.file_path, (char*)protected_elf.file_path, NULL};

        transportWait();
        execv(args[0], args);
    } else {
        /* pid received here will be the pid of child */
        elfTransportWait(pid);

        sp_info(SP_BACKUP, "ELF file %s uploaded successfully", protected_elf.file_path);
    }
}