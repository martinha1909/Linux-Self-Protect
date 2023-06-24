#include "include/FileTransport.hpp"

FileTransport::FileTransport()
{
    is_uploading = false;
    hnd = NULL;
    slist = NULL;
}

FileTransport::~FileTransport()
{

}

void FileTransport::transportCleanUp()
{
    if (hnd != NULL) {
        curl_easy_cleanup(hnd);
        hnd = NULL;
    }
    if (slist != NULL) {
        curl_slist_free_all(slist);
        slist = NULL;
    }
}

void FileTransport::transportStart(void (*write_func)(void*, size_t, size_t, ft_cu_cb_param_t*),
                                   ft_cu_cb_param_t *param)
{
    curl_easy_setopt(hnd, CURLOPT_BUFFERSIZE, FT_CU_OPT_BUF_SIZE);
    curl_easy_setopt(hnd, CURLOPT_NOPROGRESS, 1L);
    curl_easy_setopt(hnd, CURLOPT_HTTPHEADER, slist);
    curl_easy_setopt(hnd, CURLOPT_USERAGENT, FT_CU_AGENT_VERSION);
    curl_easy_setopt(hnd, CURLOPT_MAXREDIRS, FT_CU_OPT_MAX_DIRS);
    curl_easy_setopt(hnd, CURLOPT_HTTP_VERSION, (long)CURL_HTTP_VERSION_2TLS);
    curl_easy_setopt(hnd, CURLOPT_FTP_SKIP_PASV_IP, 1L);
    curl_easy_setopt(hnd, CURLOPT_TCP_KEEPALIVE, 1L);
    curl_easy_setopt(hnd, CURLOPT_WRITEFUNCTION, write_func);
    curl_easy_setopt(hnd, CURLOPT_WRITEDATA, param);
}

void FileTransport::setUploadState(bool state)
{
    SP_MUTEX_LOCK(mutex);
    is_uploading = state;
    SP_MUTEX_UNLOCK(mutex);
}

void FileTransport::transportFinish(void *ptr, size_t size, size_t nmemb, ft_cu_cb_param_t *param)
{
    (void)size;
    (void)nmemb;

    if (param != NULL) {
        sp_info(SP_TRANSPORT, "%s %s curl response successfully", param->ft->transportTypeStr(param->transport_type), param->transport_data.c_str());
    }

    /* when curl reaches this function, that means the remote transport has completed */
    param->ft->setUploadState(false);
}

bool FileTransport::transportInProgress()
{
    bool ret = false;

    SP_MUTEX_LOCK(mutex);
    ret = is_uploading;
    SP_MUTEX_UNLOCK(mutex);

    return ret;
}

const char* FileTransport::transportTypeStr(ft_type_t type)
{
    const char* ret = NULL;

    switch (type) {
        case FT_TYPE_REMOTE_DIR_CREATE:
            ret = "Remote dir create";
            break;
        case FT_TYPE_REMOTE_DIR_DELETE:
            ret = "Remote dir delete";
            break;
        case FT_TYPE_REMOTE_FILE_CREATE:
            ret = "Remote file create";
            break;
        case FT_TYPE_REMOTE_FILE_DELETE:
            ret = "Remote file delete";
            break;
        case FT_TYPE_REMOTE_UNKNOWN:
        default:
            ret = "Unexpected transport type";
            break;
    }

    return ret;
}

void FileTransport::setMutex(pthread_mutex_t* mutex)
{
    this->mutex = mutex;
}

void FileTransport::transportHeader(const char* content_type)
{
    slist = curl_slist_append(slist, FT_CU_HEADER_AUTH);
    slist = curl_slist_append(slist, content_type);
}

void FileTransport::createRemoteDir(std::string dir)
{
    ft_cu_cb_param_t *param = (ft_cu_cb_param_t*)calloc(sizeof(ft_cu_cb_param_t), 1);
    
    if (param == NULL) {
        sp_error(SP_TRANSPORT, "Failed to allocate memory, skip creating remote dir %s", dir.c_str());
        goto done;
    }

    param->transport_data = dir;
    param->transport_type = FT_TYPE_REMOTE_DIR_CREATE;
    param->ft = this;

    setUploadState(true);
    transportCleanUp();

    transportHeader(FT_CU_HEADER_JSON);

    hnd = curl_easy_init();

    transportStart(FileTransport::transportFinish, param);
    curl_easy_setopt(hnd, CURLOPT_URL, FT_CU_REMOTE_API_DIR_CREATE_URL);
    curl_easy_setopt(hnd, CURLOPT_POSTFIELDS, FT_CU_REMOTE_DIR_CREATE(dir.c_str()));
    curl_easy_setopt(hnd, CURLOPT_CUSTOMREQUEST, FT_CU_REQUEST_POST);

    (void)curl_easy_perform(hnd);

done:
    transportCleanUp();
    if (param != NULL) {
        free(param);
    }
}

void FileTransport::deleteRemoteDirOrFile(std::string path, bool is_file)
{
    ft_cu_cb_param_t *param = (ft_cu_cb_param_t*)calloc(sizeof(ft_cu_cb_param_t), 1);

    if (param == NULL) {
        sp_error(SP_TRANSPORT, "Failed to allocate memory, skip creating remote %s", path.c_str());
        goto done;
    }

    if (is_file) {
        param->transport_type = FT_TYPE_REMOTE_FILE_DELETE;
    } else {
        param->transport_type = FT_TYPE_REMOTE_DIR_DELETE;
    }
    
    param->transport_data = path;
    param->ft = this;

    setUploadState(true);
    transportCleanUp();

    transportHeader(FT_CU_HEADER_JSON);

    hnd = curl_easy_init();

    transportStart(FileTransport::transportFinish, param);
    curl_easy_setopt(hnd, CURLOPT_URL, FT_CU_REMOTE_API_DIR_DELETE_URL);
    curl_easy_setopt(hnd, CURLOPT_POSTFIELDS, FT_CU_REMOTE_DELETE(path.c_str()));
    curl_easy_setopt(hnd, CURLOPT_CUSTOMREQUEST, FT_CU_REQUEST_POST);

    (void)curl_easy_perform(hnd);

done:
    transportCleanUp();
    if (param != NULL) {
        free(param);
    }
}

void FileTransport::createRemoteFile(std::string filepath, 
                                     const unsigned char* content, 
                                     const mode_t attrib)
{
    ft_cu_cb_param_t *param = (ft_cu_cb_param_t*)calloc(sizeof(ft_cu_cb_param_t), 1);

    if (param == NULL) {
        sp_error(SP_TRANSPORT, "Failed to allocate memory, skip creating remote file %s", filepath.c_str());
        goto done;
    }

    param->transport_data = filepath;
    param->transport_type = FT_TYPE_REMOTE_FILE_CREATE;
    param->ft = this;

    transportCleanUp();

    transportHeader(FT_CU_HEADER_OCTET_STREAM);
    slist = curl_slist_append(slist, FT_CU_REMOTE_FILE_CREATE(filepath.c_str(), attrib));

    hnd = curl_easy_init();

    transportStart(FileTransport::transportFinish, param);
    curl_easy_setopt(hnd, CURLOPT_URL, FT_CU_REMOTE_API_FILE_CREATE_URL);
    curl_easy_setopt(hnd, CURLOPT_POSTFIELDS, (char*)content);
    curl_easy_setopt(hnd, CURLOPT_CUSTOMREQUEST, FT_CU_REQUEST_POST);

    (void)curl_easy_perform(hnd);

done:
    transportCleanUp();
    if (param != NULL) {
        free(param);
    }
}