#include "include/cli_helper.h"

void populate_new_buffer(char *buf, size_t len, const char* new_msg)
{
    memset(buf, '\0', len);
    strcpy(buf, new_msg);
}

int socket_write(int sock_fd, char* buf, size_t len)
{
    int ret = write(sock_fd, buf, len);
    memset(buf, '\0', len);
    return ret;
}

int socket_read(int sock_fd, char* buf, size_t len)
{
    memset(buf, '\0', len);
    return read(sock_fd, buf, len);
}

int cli_set_display_hidden(int fd, int option)
{
    int err = -1;  
    struct termios term;  

    if (tcgetattr(fd, &term)==-1) {  
        sp_error(SP_CLIENT, "Cannot get the attribution of the terminal");  
        goto done;
    }

    if (option) {
        term.c_lflag |= ECHOFLAGS;
    } else {  
        term.c_lflag &=~ECHOFLAGS;
    }

    err = tcsetattr(fd, TCSAFLUSH, &term);  
    if (err==-1 && err==EINTR) {  
        sp_error(SP_CLIENT, "Cannot set the attribution of the terminal");  
        goto done;
    } 

    err = 0;
done:
    return err;  
}