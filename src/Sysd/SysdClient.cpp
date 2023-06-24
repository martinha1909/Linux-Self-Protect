#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/select.h>
#include <sys/time.h>
#include "../SelfProtectService/include/SpLogger.hpp"
#include "../SelfProtectService/include/SpConstants.hpp"
#include "../FileSystem/include/FileSystem.hpp"
#include "../TokenManager/include/TokenManager.hpp"

int main()
{
    printf("Initializing...\n");
    TokenManager tm(SELF_PROTECT_CONFIG_DIR);
    token_attempted_status_t status;
    bool err = true;
    bool access_granted = false;
    int err_select, fd_stdin;
    fd_set readfds;
    struct timeval tv;
    int client_attempts = 0;

    if (cli_set_display_hidden(STDIN_FILENO, 0) == -1) {
        sp_error(SP_CLIENT, "Failed to hide inputting token");
    }

    fd_stdin = fileno(stdin);

    FD_ZERO(&readfds);
    FD_SET(fileno(stdin), &readfds);

    tv.tv_sec = CLIENT_TIMEOUT;
    tv.tv_usec = CLIENT_TIMEOUT * 10000;
    printf("Enter token to stop self protect service:\n");
    fflush(stdout);
    err_select = select(fd_stdin + 1, &readfds, NULL, NULL, &tv);
    if (err_select < 0) {
        sp_error(SP_CLIENT, "Select error, %s\n", strerror(errno));
        goto done;
    }
    if (err_select == 0) {
        sp_info(SP_CLIENT, "Client timeout, aborting...");
        printf("Connection timeout\n");
        err = false;
        goto done;
    } else {
        char token[1024];
        bool done = false;

        while (!done) {
            client_attempts++;

            if (client_attempts > CLIENT_MAX_ATTEMPT) {
                printf("%s\n", CLIENT_MAX_ATTEMPT_MSG);
                done = true;
                continue;
            }

            printf("Token: ");
            scanf("%s", token);
            printf("\n");

            status = tm.tokenIsValid(token);
            if (status == TOKEN_ATTEMPTED_CORRECT) {
                printf("Correct token, stopping self protect service...\n");
                if (SYSTEM_CMD(SYSD_SERVICE_STOP_CMD_FMT, SELF_PROTECT_SYSD_SERVICE_NAME) == -1) {
                    sp_error(SP_CLIENT, "Failed to shut down self protect service");
                    goto done;
                }
                access_granted = true;
                done = true;
            } else if (status == TOKEN_ATTEMPTED_INCORRECT) {
                char attempt_msg[1028];

                snprintf(attempt_msg, 1028, "Incorrect token, attempt %d/%d", client_attempts, CLIENT_MAX_ATTEMPT);
                printf("%s\n", attempt_msg);
                continue;
            } else if (status == TOKEN_ATTEMPTED_EXPIRED) {
                printf("%s\n", CLIENT_ATTEMPT_TOK_EXP);
                client_attempts--;
                continue;
            } else if (status == TOKEN_ATTEMPTED_ERROR_OCCURED) {
                goto done;
            }
        }
    }

    err = false;
done:
    if (err) {
        printf("Failed to verify token, error occured\n");
    }
    if (access_granted) {
        printf("Access granted. This window can be safely closed\n");
    } else {
        sp_info(SP_CLIENT, "Client max attempt reached, restarting self protect service...");
        /* need to restart service to respawn sysd_service_monitor process */
        if (SYSTEM_CMD(SYSD_SERVICE_RESTART_CMD_FMT, SELF_PROTECT_SYSD_SERVICE_NAME) == -1) {
            sp_error(SP_CLIENT, "Failed to restart self protect service");
        } else {
            sp_info(SP_CLIENT, "Self protect service restarted successfully");
        }
    }

    printf("This window can be safely closed\n");

    sleep(30);
}
