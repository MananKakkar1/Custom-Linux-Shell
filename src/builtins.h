#ifndef __BUILTINS_H__
#define __BUILTINS_H__

#include <unistd.h>
#include "server.h"

struct listen_sock {
    struct sockaddr_in *addr;
    int sock_fd;
};

struct server_sock {
    int sock_fd;
    char buf[4096];
    int inbuf;
};

struct client_sock {
    int sock_fd;
    int state;
    char *username;
    char buf[4096];
    int inbuf;
    struct client_sock *next;
    int connected;
};
int contains_var(char *str);
listen_sck *get_sock_fd();
void add_bg_process_arg(pid_t pid, char *command, char *argument);
void add_bg_process_w_arg(pid_t pid, char *command);
void remove_bg_process(pid_t pid);
void clear_bg_processes();
void bg_signal_handler_setup();
void child_process_handler(int signal);
void remove_bg_process(pid_t pid);
/* Type for builtin handling functions
 * Input: Array of tokens
 * Return: >=0 on success and -1 on error
 */
typedef ssize_t (*bn_ptr)(char **);
ssize_t bn_echo(char **tokens);
ssize_t bn_ls(char **tokens);
ssize_t bn_cat(char **tokens);
ssize_t bn_cd(char **tokens);
ssize_t bn_wc(char **tokens);
ssize_t bn_ps();
ssize_t bn_kill(char **tokens);
ssize_t bn_start_client(char **tokens);
ssize_t bn_start_server(char **tokens);
ssize_t bn_send(char **tokens);
ssize_t bn_close_server(char **tokens);
ssize_t bn_gpt(char **tokens);
/* Return: index of builtin or -1 if cmd doesn't match a builtin
 */
bn_ptr check_builtin(const char *cmd);


/* BUILTINS and BUILTINS_FN are parallel arrays of length BUILTINS_COUNT
 */
static const char * const BUILTINS[] = {"kill", "ps", "ls", "cat", "cd", "wc", "echo", "gpt", "start-server", "close-server", "send", "start-client"};
static const bn_ptr BUILTINS_FN[] = {bn_kill, bn_ps, bn_ls, bn_cat, bn_cd, bn_wc, bn_echo, bn_gpt, bn_start_server, bn_close_server, bn_send, bn_start_client, NULL};    // Extra null element for 'non-builtin'
static const ssize_t BUILTINS_COUNT = sizeof(BUILTINS) / sizeof(char *);

#endif
