#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include "include/CLI_Interface.hpp"

CLI_Interface::CLI_Interface()
{
    daemon = NULL;
    socket_fd = -1;
    client_attempts = 0;
}

int CLI_Interface::clientWrite(char* buf, size_t len)
{
    return socket_write(socket_fd, buf, len);
}

int CLI_Interface::clientRead(char* buf, size_t len)
{
    return socket_read(socket_fd, buf, len);
}

void CLI_Interface::run()
{
    char buf[1024], token[1024];
    bool err = true;
    bool access_granted = false;
    client_attempts = 1;

    if (connect(socket_fd, (struct sockaddr*)daemon, sizeof(struct sockaddr_un)) < 0) {
        close (socket_fd);
        sp_error(SP_CLIENT, "Error connecting to stream socket");
        goto done;
    }

    if (cli_set_display_hidden(STDIN_FILENO, 0) == -1) {
        sp_error(SP_CLIENT, "Failed to hide inputting token");
    }
    
    printf("Enter Self Protect service token to continue: ");
    scanf("%s", token);
    printf("\n");

    if (clientWrite(token, sizeof(token)) > 0) {
        if (clientRead(buf, sizeof(buf)) > 0) {
            if (strcmp(buf, CLIENT_CORRECT_TOKEN) == 0) {
                populate_new_buffer(buf, sizeof(buf), CLIENT_FINISH);
                if (clientWrite(buf, sizeof(buf)) < 0) {
                    sp_error(SP_CLIENT, "Client failed to write finish message to socket");
                    goto done;
                } else {
                    err = false;
                    access_granted = true;
                    goto done;
                }
            } else if (strcmp(buf, CLIENT_ATTEMPT_TOK_EXP) == 0) {
                printf("%s\n", CLIENT_ATTEMPT_TOK_EXP);
            } else if (strcmp(buf, CLIENT_INCORRECT_TOKEN) == 0){
                char attempt_msg[CLIENT_ATTEMPT_MSG_LEN];

                snprintf(attempt_msg, CLIENT_ATTEMPT_MSG_LEN, ", attempt %d/%d", client_attempts, CLIENT_MAX_ATTEMPT);
                strcat(buf, attempt_msg);
                printf("%s\n", buf);
            } else if (strcmp(buf, CLIENT_ERROR) == 0) {
                goto done;
            }
        } else {
            sp_error(SP_CLIENT, "Client failed to read from socket");
            goto done; 
        }
    } else {
        sp_error(SP_CLIENT, "Client failed to write to socket");
        goto done;
    }

    while(1) {
        printf("Enter token: ");
        scanf("%s", token);

        if (clientWrite(token, sizeof(token)) > 0) {
            if (clientRead(buf, sizeof(buf)) > 0) {
                if (strcmp(buf, CLIENT_CORRECT_TOKEN) == 0) {
                    populate_new_buffer(buf, sizeof(buf), CLIENT_FINISH);
                    if (clientWrite(buf, sizeof(buf)) < 0) {
                        sp_error(SP_CLIENT, "Client failed to write finish message to socket");
                        goto done;
                    }
                    access_granted = true;
                    break;
                } else if (strcmp(buf, CLIENT_ATTEMPT_TOK_EXP) == 0) {
                    printf("%s\n", CLIENT_ATTEMPT_TOK_EXP);
                } else if (strcmp(buf, CLIENT_INCORRECT_TOKEN) == 0){
                    char attempt_msg[CLIENT_ATTEMPT_MSG_LEN];

                    client_attempts++;
                    snprintf(attempt_msg, CLIENT_ATTEMPT_MSG_LEN, ", attempt %d/%d", client_attempts, CLIENT_MAX_ATTEMPT);
                    strcat(buf, attempt_msg);
                    printf("%s\n", buf);
                    
                    if (client_attempts >= CLIENT_MAX_ATTEMPT) {
                        printf("%s\n", CLIENT_MAX_ATTEMPT_MSG);
                        populate_new_buffer(buf, sizeof(buf), CLIENT_MAX_ATTEMPT_MSG);
                        if (clientWrite(buf, sizeof(buf)) < 0) {
                            sp_error(SP_CLIENT, "Client failed to write finish message to socket");
                            goto done;
                        } else {
                            err = false;
                            goto done;
                        }
                    }
                } else if (strcmp(buf, CLIENT_ERROR) == 0) {
                    goto done;
                }
            } else {
               sp_error(SP_CLIENT, "Client failed to read from socket");
                goto done; 
            }
        } else {
            sp_error(SP_CLIENT, "Client failed to write to socket");
            goto done;
        }
    }

    err = false;    
done:
    close(socket_fd);

    if (err) {
        printf("Failed to verify token, error occured\n");
    } 
    if (access_granted) {
        printf("Access granted. This window can be safely closed\n");
    }
}

void CLI_Interface::setDaemon(struct sockaddr_un *daemon)
{
    this->daemon = daemon;
}

void CLI_Interface::setSocketFd(int sock_fd)
{
    socket_fd = sock_fd;
}

int main (int argc, char *argv[])
{
    CLI_Interface client;
    int sock_fd;
    struct sockaddr_un daemon;

    sock_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock_fd < 0) {
        sp_error(SP_CLIENT, "Error opening stream socket");
        goto done;
    }

    memset(&daemon, 0, sizeof(daemon));
    daemon.sun_family = AF_UNIX;
    strcpy(daemon.sun_path, DAEMON_SUN_PATH);

    client.setDaemon(&daemon);
    client.setSocketFd(sock_fd);
    client.run();

    sleep(20);
done:
    close(sock_fd);
}
