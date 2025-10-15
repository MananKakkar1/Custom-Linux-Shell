#ifndef SERVER_H
#define SERVER_H

#include <netinet/in.h>

typedef struct listen_sock{
    struct sockaddr_in *addr;
    int sock_fd;
    int client_count;
    int server_running;
    int pid;
    int client_socks[999999];
    struct client_sock *clients;
} listen_sck;

#endif
