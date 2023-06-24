#ifndef CLI_HELPER_H
#define CLI_HELPER_H

#include <string.h>
#include <unistd.h>
#include <termios.h>
#include <errno.h>
#include "../../SelfProtectService/include/SpLogger.hpp"
#include "../../SelfProtectService/include/SpConstants.hpp"

#define CLIENT_BIN_NAME         "sp_client"
#define CLIENT_BIN_PATH         SELF_PROTECT_CONFIG_BIN_DIR CLIENT_BIN_NAME
#define CLIENT_COMPILE_FMT      "g++ -o %s %s %s"
#define CLIENT_OBJ_COMPILE_FMT  "g++ -c %s -o %s"
#define CLIENT_SPAWN_FMT        "gnome-terminal -- sh -c %s"

#define CLIENT_CORRECT_TOKEN    "correct"
#define CLIENT_INCORRECT_TOKEN  "incorrect"
#define CLIENT_FINISH           "finish"
#define CLIENT_ERROR            "error"
#define CLIENT_INPUT_TIMEOUT    "timeout"
#define CLIENT_MAX_ATTEMPT_MSG  "Permission denied. This window can be safely closed"
#define CLIENT_ATTEMPT_TOK_EXP  "This token has expired, please use a new token"
#define CLIENT_MAX_ATTEMPT      5
#define CLIENT_TIMEOUT          60

#define DAEMON_SUN_PATH         "sp_socket"

#define ECHOFLAGS (ECHO | ECHOE | ECHOK | ECHONL)  

#define SP_SOCKET_WRITE_ABORT_IF_FAIL(fd, buf, len, log_type)\
                                    {\
                                        if (socket_write(fd, buf, len) == -1) {\
                                            sp_error(log_type, "Failed to write to socket");\
                                            goto done;\
                                        }\
                                    }

#define SP_SOCKET_READ_ABORT_IF_FAIL(fd, buf, len, log_type)\
                                    {\
                                        if (socket_read(fd, buf, len) == -1) {\
                                            sp_error(log_type, "Failed to write to socket");\
                                            goto done;\
                                        }\
                                    }

/**
 * Populates a new buffer with a specified message
 *
 * @param buf[out]      buffer to be populated
 * @param len[in]       buffer length
 * @param new_msg[in]   new message to populate to buffer
 */
void populate_new_buffer(char *buf, size_t len, const char* new_msg);
/**
 * Writes to a socket. Buffer will be cleared after writting
 *
 * @param sock_fd     socket file descriptor to communicate to
 * @param buf         buffer to write to socket
 * @param len         buffer length
 * 
 * @return            0 on success, -1 on error
 */
int socket_write(int sock_fd, char* buf, size_t len);
/**
 * Reads from a socket. Buffer will be clears before reading
 *
 * @param sock_fd     socket file descriptor to communicate to
 * @param buf         buffer to read from socket
 * @param len         buffer length
 * 
 * @return            0 on success, -1 on error
 */
int socket_read(int sock_fd, char* buf, size_t len);
/**
 * Hides input from the terminal
 */
int cli_set_display_hidden(int fd, int option);

#endif