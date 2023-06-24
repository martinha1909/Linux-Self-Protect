#pragma once

#include <pthread.h>
#include "../../SelfProtectService/include/SelfProtectService.hpp"
#include "../../FileManager/include/FileManager.hpp"
#include "../../TokenManager/include/TokenManager.hpp"

typedef __u32 __permission;
typedef struct fanotify_event_response fanotify_event_response_t;
class SelfProtectService;
class FileManager;
class TokenManager;

typedef struct thread_block_fileop_param {
    char** protected_dirs;
    int num_dirs;
    SelfProtectService* service;
} thread_block_fileop_param_t;

typedef struct thread_spawn_client_param {
    SelfProtectService *service;
    fanotify_event_response_t *event;
} thread_spawn_client_param_t;