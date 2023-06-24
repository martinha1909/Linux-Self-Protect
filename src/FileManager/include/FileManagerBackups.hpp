#pragma once

#include <libgen.h>
#include <unistd.h>
#include <pthread.h>
#include <wait.h>
#include <sys/stat.h>
#include <string.h>     /* C strings */
#include <string>       /* C++ strings */
#include <vector>
#include "../../FileTransport/include/FileTransport.hpp"
#include "../../SelfProtectService/include/SpLogger.hpp"
#include "../../SelfProtectService/include/SpConstants.hpp"

typedef struct protected_file {
    char file_path[PATH_MAX];
    unsigned char *content;
    unsigned char *sha256;
    mode_t attrib;
    bool is_elf;
} protected_file_t;

typedef struct protected_dir {
    std::string path;
    int fd;
    mode_t attrib;
    std::vector<protected_file_t*> files;

    bool operator==(const struct protected_dir& pd) const 
    {
        return (strcmp(path.c_str(), pd.path.c_str()) == 0);
    }
} protected_dir_t;

namespace std {
    template <>
    struct hash<protected_dir_t>
    {
        std::size_t operator()(const protected_dir_t& pd) const 
        {
            return std::hash<std::string>()(pd.path);
        }
    };
}

class FileManagerBackups {
private:
    FileTransport ft;
    /**
     * Removes the ending '/' of a C-string directory
     *
     * @param dir      C-string dir to be sanitized
     * 
     * @return sanitized directory string
     */
    std::string sanitizeDirStr(const char* dir);
    /**
     * Removes the ending '/' of a C++ string directory
     *
     * @param dir      C++ string dir to be sanitized
     * 
     * @return sanitized directory string
     */
    std::string sanitizeDirStr(std::string dir);
    void transportWait();
    void elfTransportWait(pid_t pid);
public:
    FileManagerBackups();
    /**
     * Sets file transport mutex
     *
     * @param mutex      updating mutex
     */
    void setMutex(pthread_mutex_t *mutex);
    /**
     * Creates a remote directory and its sub-directory
     * 
     * @note This function will wait for the current transportation to finish before creating a new directory
     *
     * @param protected_dir      protected directory to be created in the remote file sharing server
     * @param sub_dirs           list of sub-directories to be created in the remote file sharing server
     *
     */
    void createRemoteDirAndSubDirs(protected_dir_t protected_dir, std::vector<protected_dir_t> sub_dirs);
    /**
     * Deletes a remote directory or file
     * 
     * @note This function will wait for the current transportation to finish before deleting a directory or a file
     *
     * @param path      path to a file or directory to be deleted in the remote file sharing server
     * @param is_file   whether the deleting action is on a directory or a file
     */
    void deleteRemoteDirOrFile(const char* path, bool is_file);
    /**
     * Uploads a new remote file
     * 
     * @note This function will wait for the current transportation to finish before uploading the new file
     *
     * @param protected_file      file to be uploaded to the remote server
     */
    void uploadNewRemoteFile(const protected_file_t protected_file);
    /**
     * Updates an existing remote file
     * 
     * @note This function will wait for the current transportation to finish before updating the existing remote file
     *
     * @param protected_file      remote file to be updated
     */
    void updateRemoteFile(const protected_file_t protected_file);
    /**
     * Uploads a new remote ELF executable file
     * 
     * @note This function will wait for the current transportation to finish before uploading the new file
     *       This function will use execv() to execute a bash script that can handle binary stream data
     *
     * @param protected_elf      ELF executable file to be uploaded to the remote server
     */
    void uploadNewRemoteELF(const protected_file_t protected_elf);
    /**
     * Downloads a new remote ELF executable file
     * 
     * @note This function will wait for the current transportation to finish before downloading the new file
     *       This function will use execv() to execute a bash script that can handle binary stream data
     *
     * @param protected_elf      ELF executable file to be downloaded from the remote server
     */
    void downloadRemoteELF(const protected_file_t protected_elf);
};