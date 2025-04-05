#ifndef __COMMANDS_H__
#define __COMMANDS_H__

#include <unistd.h>
#include "server.h"
int execute_command(char **tokens, size_t token_count);
void execute_pipe(char **tokens, int num_pipes, size_t token_count);
int setup_server_socket(listen_sck *s, int port);
int accept_connection(int fd, struct client_sock **clients, int *client_count);
void clean_exit(listen_sck s, struct client_sock *clients, int exit_status);
int remove_client(struct client_sock **curr, struct client_sock **clients);
int write_buf_to_client(struct client_sock *c, char *buf, int len);
int read_from_client(struct client_sock *curr);
int set_username(struct client_sock *curr);
int read_from_socket(int sock_fd, char *buf, int *inbuf);
int get_message(char **dst, char *src, int *inbuf);
int write_to_socket(int sock_fd, char *buf, int len);
int find_network_newline(const char *buf, int inbuf);
#endif