#ifndef CLI_INTERFACE_HPP
#define CLI_INTERFACE_HPP

#include "../../SelfProtectService/include/SpLogger.hpp"
#include "cli_helper.h"

#define CLIENT_ATTEMPT_MSG_LEN  14

class CLI_Interface {
private:
    struct sockaddr_un *daemon;
    int socket_fd;
    int client_attempts;
    
    /**
     * Writes to unix domain socket
     *
     * @param buf[in]     buffer to be written to socket
     * @param len[in]     buffer length
     * 
     * @return            0 on success, -1 on error
     */
    int clientWrite(char* buf, size_t len);
    /**
     * Reads from unix domain socket
     *
     * @param buf[out]    buffer to be populated after socket is read
     * @param len[in]     buffer length
     * 
     * @return            0 on success, -1 on error
     */
    int clientRead(char* buf, size_t len);
public:
    CLI_Interface();
    /**
     * Sets daemon socket struct
     *
     * @param daemon     socket address to set
     */
    void setDaemon(struct sockaddr_un *daemon);
    /**
     * Sets socket file descriptor that the client and daemon are created at
     *
     * @param socket_fd socket file descriptor
     */
    void setSocketFd(int sock_fd);
    /**
     * Creates socket, then asks user to enter a token and sends to SelfProtectService
     */
    void run();
};

#endif