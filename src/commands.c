#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <signal.h>
#include <dirent.h>
#include <sys/stat.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <assert.h>

#include "variables.h"
#include "builtins.h"
#include "io_helpers.h"
void execute_pipe(char **tokens, int num_pipes, size_t token_count);
int execute_command(char **tokens, size_t token_count);
int execute_pipe_bg_process(char **tokens, int num_pipes, size_t token_count) {
	char *commands[MAX_STR_LEN] = {NULL};
	size_t command_count = 0;
	char *last_token = tokens[token_count - 1];
	size_t len = strlen(last_token);
	if (len > 0 && last_token[len - 1] == '&') {
		if (len == 1) {
			free(tokens[token_count - 1]);
			tokens[token_count - 1] = NULL;
			token_count--;
			for (size_t i = 0; i < token_count; i++) {
				commands[i] = tokens[i];
				command_count++;
			}
		} else {
			size_t i = 0;
			while (i < token_count) {
				if (tokens[i] == tokens[token_count - 1]) {
					char *sub_string = strtok(tokens[token_count - 1], "&");
					commands[i] = sub_string;
				} else {
					commands[i] = tokens[i];
				}
				command_count++;
				i++;
			}
		}
		commands[command_count] = NULL;
	}
	pid_t pid = fork();
	if (pid == 0) {
		execute_pipe(commands, num_pipes, command_count);
		exit(0);
	} else if (pid > 0) {
		if (commands[1] == NULL) {
			add_bg_process_w_arg(pid, commands[0]);
		} else {
			char temp[4096];
			for (size_t i = 0; i < command_count; i++) {
				if (i > 0 && commands[i] != NULL && strcmp(commands[i], "|") != 0 && strcmp(commands[i-1], "|") != 0) {
					strncat(temp, " ", sizeof(temp) - strlen(temp) - 1);
					strncat(temp, commands[i], sizeof(temp) - strlen(temp) - 1);
				} else if (strcmp(commands[i], "|") == 0) {
					strncat(temp, " | ", sizeof(temp) - strlen(temp) - 1);
				} else {
					strncat(temp, commands[i], sizeof(temp) - strlen(temp) - 1);
				}
			}
			add_bg_process_arg(pid, temp, "");
		}
		fflush(stdout);
	} else if (pid < 0) {
		perror("fork");
		exit(1);
	}
	return 0;
}
int execute_bg_process(char **tokens, size_t token_count) {
	char *commands[MAX_STR_LEN] = {NULL};
	size_t command_count = 0;
	char *last_token = tokens[token_count - 1];
	size_t len = strlen(last_token);
	if (len > 0 && last_token[len - 1] == '&') {
		if (len == 1) {
			free(tokens[token_count - 1]);
			tokens[token_count - 1] = NULL;
			token_count--;
			for (size_t i = 0; i < token_count; i++) {
				commands[i] = tokens[i];
				command_count++;
			}
		} else {
			size_t i = 0;
			while (i < token_count) {
				if (tokens[i] == tokens[token_count - 1]) {
					char *sub_string = strtok(tokens[token_count - 1], "&");
					commands[i] = sub_string;
				} else {
					commands[i] = tokens[i];
				}
				command_count++;
				i++;
			}
		}
		commands[command_count] = NULL;
	}
	pid_t pid = fork();
	if (pid == 0) {
		execute_command(commands, command_count);
		exit(0);
	} else if (pid > 0) {
		if (commands[1] == NULL) {
			add_bg_process_w_arg(pid, commands[0]);
		} else {
			add_bg_process_arg(pid, commands[0], commands[1]);
		}
		fflush(stdout);
	} else if (pid < 0) {
		perror("fork");
		exit(1);
	}
	return 0;
}
int execute_command(char **tokens, size_t token_count) {
	if (tokens[0] == NULL || token_count == 0) {
		return -1;
	}
	if (tokens[token_count - 1] != NULL && token_count > 0) {
		char *last_token = tokens[token_count - 1];
		if (last_token != NULL) {
			size_t len = strlen(last_token);
			if (token_count >= 1 && tokens[token_count - 1] != NULL && len > 0 && last_token[len - 1] == '&') {
				execute_bg_process(tokens, token_count);
				return 0;
			}
		}		
	}
	bn_ptr builtin_fn = check_builtin(tokens[0]);
	if (strchr(tokens[0], '=') != NULL) {
		char *key = strtok(tokens[0], "=");
		char *value = strtok(NULL, "");
		set_variable(key, value);
	} else if (token_count > 1 && tokens[1] != NULL && strchr(tokens[1], '=') != NULL && builtin_fn == NULL) {
		display_error("ERROR: Invalid Syntax", "");
	} else if (builtin_fn != NULL) {
		ssize_t err = builtin_fn(tokens);
		if (err == - 1) {
			display_error("ERROR: Builtin failed: ", tokens[0]);
		} 
	} else {
		pid_t pid = fork();
		if (pid == 0) {
			signal(SIGINT, SIG_DFL);
			execvp(tokens[0], tokens);
			char path_buf[MAX_STR_LEN];
			snprintf(path_buf, sizeof(path_buf), "/bin/%s", tokens[0]);
			execv(path_buf, tokens);
			snprintf(path_buf, sizeof(path_buf), "/usr/bin/%s", tokens[0]);
			execv(path_buf, tokens);
			display_error("ERROR: Unknown command: ", tokens[0]);
			exit(1);
		} else if (pid > 0) {
			int status;
			waitpid(pid, &status, 0);
		} else if (pid < 0) {
			perror("fork");
			exit(1);
		}
	}
	return 0;
}

void execute_pipe(char **tokens, int num_pipes, size_t token_count) {
	if (num_pipes < 1 || token_count == 0) {
		return;
	}

	int pipes[num_pipes][2];
	char *commands[num_pipes + 1][MAX_STR_LEN];
	int cmd_i = 0, arg_i = 0;
	if (tokens[token_count - 1] != NULL && token_count > 0) {
		char *last_token = tokens[token_count - 1];
		if (last_token != NULL) {
			size_t len = strlen(last_token);
			if (token_count >= 1 && tokens[token_count - 1] != NULL && len > 0 && last_token[len - 1] == '&') {
				execute_pipe_bg_process(tokens, num_pipes, token_count);
				return;
			}
		}		
	}

	for (size_t i = 0; i < token_count; i++) {
		if (strcmp(tokens[i], "|") == 0) {
			if (arg_i == 0) {
				return;
			}
			commands[cmd_i][arg_i] = NULL;
			cmd_i++;
			arg_i=0;
		} else if (tokens[i][0] == '|') {
			char *sub_token = strtok(tokens[i], "|");
			if (sub_token != NULL) {
				commands[cmd_i][arg_i] = NULL; 
				cmd_i++;
				arg_i = 0;
			}
			commands[cmd_i][arg_i++] = sub_token;
		} else {
            char *sub_token = strtok(tokens[i], "|");
            while (sub_token != NULL) {
                commands[cmd_i][arg_i++] = sub_token;
                sub_token = strtok(NULL, "|");
                if (sub_token != NULL) {
                    commands[cmd_i][arg_i] = NULL; 
                    cmd_i++;
                    arg_i = 0;
                }
            }
        }
	}
	commands[cmd_i][arg_i] = NULL;
	for (int i = 0; i < num_pipes; i++) {
		if (pipe(pipes[i]) == -1) {
			perror("pipe");
			exit(1);
		}
	}

	for (int i = 0; i <= num_pipes; i++) {
		pid_t pid = fork();
		if (pid == 0) {
			if (i > 0) {
				dup2(pipes[i-1][0], STDIN_FILENO);
			}
			if (i < num_pipes) {
                dup2(pipes[i][1], STDOUT_FILENO);
            }
			for (int j = 0; j < num_pipes; j++) {
				close(pipes[j][0]);
				close(pipes[j][1]);
			}
			if (commands[i][0] != NULL) {
				execute_command(commands[i], cmd_i);
			}
			exit(1);
		} else if (pid < 0) {
			perror("fork");
			exit(1);
		}
		if (i < num_pipes) {
            close(pipes[i][1]);
        }
	}
	for (int i = 0; i < num_pipes; i++) {
		close(pipes[i][0]);
		close(pipes[i][1]);
	}
	for (int i = 0; i <= num_pipes; i++) {
		int status;
		wait(&status);
	}
}
int setup_server_socket(struct listen_sock *s, int port) {
    if(!(s->addr = malloc(sizeof(struct sockaddr_in)))) {
        perror("malloc");
        return 1;
    }
    s->addr->sin_family = AF_INET;
    s->addr->sin_port = htons(port);
    memset(&(s->addr->sin_zero), 0, 8);
    s->addr->sin_addr.s_addr = INADDR_ANY;

    s->sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (s->sock_fd < 0) {
        perror("server socket");
        return 1;
    }

    int on = 1;
    int status = setsockopt(s->sock_fd, SOL_SOCKET, SO_REUSEADDR,
        (const char *) &on, sizeof(on));
    if (status < 0) {
        perror("setsockopt");
        return 1;
    }

    if (bind(s->sock_fd, (struct sockaddr *)s->addr, sizeof(*(s->addr))) < 0) {
        close(s->sock_fd);
		free(s->addr);
        return 1;
    }

    if (listen(s->sock_fd, 128) < 0) {
        perror("server: listen");
        close(s->sock_fd);
        return 1;
    }
	return 0;
}
int find_network_newline(const char *buf, int inbuf) {
    for (int i = 0; i < inbuf - 1; i++) {
        if (buf[i] == '\r' && buf[i + 1] == '\n') {
            return i + 2;
        }
    }
    return -1;
}

int read_from_socket(int sock_fd, char *buf, int *inbuf) {
    int bytes_read = read(sock_fd, buf + *inbuf, 4096 - *inbuf);
    if (bytes_read == -1) {
        return -1;
    } else if (bytes_read == 0) {
        if (*inbuf == 0) {
            return 1;
        } else {
            return 2;
        }
    }
    *inbuf += bytes_read;
    if (*inbuf >= 4096) {
        return -1;
    }
    int newline = find_network_newline(buf, *inbuf);
    if (newline == -1) {
        return 2;
    }   
    return 0;
}

int get_message(char **dst, char *src, int *inbuf) {
    int newline = find_network_newline(src, *inbuf);
    if (newline == -1) {
        return 1;
    }
    *dst = malloc(newline);
    if (*dst == NULL) {
        return 1;
    }
    strncpy(*dst, src, newline - 2);
    (*dst)[newline - 2] = '\0';
    *inbuf -= newline;
    memmove(src, src + newline, *inbuf);
    return 0;
}

int write_to_socket(int sock_fd, char *buf, int len) {
    int total = 0;
    while (total < len) {
        int bytes_written = write(sock_fd, buf + total, len - total);
        if (bytes_written < 0) {
            return 1;
        }
        total += bytes_written;
    }
    return 0;
}
int accept_connection(int fd, struct client_sock **clients, int *client_count) {
	(void)client_count;
    struct sockaddr_in peer;
    unsigned int peer_len = sizeof(peer);
    peer.sin_family = AF_INET;

	listen_sck *server = get_sock_fd();
    struct client_sock *curr = *clients;
    while (curr != NULL && curr->next != NULL) {
        curr = curr->next;
    }

    int client_fd = accept(fd, (struct sockaddr *)&peer, &peer_len);
    if (client_fd < 0) {
        perror("server: accept");
        close(fd);
        return 1;
    }
	server->client_count++;
    struct client_sock *newclient = malloc(sizeof(struct client_sock));
    newclient->sock_fd = client_fd;
    newclient->inbuf = newclient->state = 0;
    newclient->username = NULL;
    newclient->next = NULL;
    memset(newclient->buf, 0, 4096);
	char client_id[128];
    snprintf(client_id, sizeof(client_id), "client%d:", server->client_count);
    newclient->username = strdup(client_id);
    if (*clients == NULL) {
        *clients = newclient;
    }
    else {
        curr->next = newclient;
    }
	server->client_socks[server->client_count] = client_fd;
	server->clients = *clients;

    return client_fd;
}
void clean_exit(struct listen_sock s, struct client_sock *clients, int exit_status) {
    struct client_sock *tmp;
    while (clients) {
        tmp = clients;
        close(tmp->sock_fd);
        clients = clients->next;
        free(tmp->username);
        free(tmp);
    }
    close(s.sock_fd);
    free(s.addr);
    exit(exit_status);
}
int remove_client(struct client_sock **curr, struct client_sock **clients) {
    struct client_sock *temp = *clients;
    struct client_sock *prev = NULL;
    while (temp) {
        if (temp == *curr) {
            if (prev) {
                prev->next = temp->next;
            } else {
                *clients = (*curr)->next;
            }
            close(temp->sock_fd);
            free(temp->username);
            free(temp);
            *curr = NULL;
            return 0;
        }
        prev = temp;
        temp = temp->next; 
    }
    return 1; 
}
int write_buf_to_client(struct client_sock *c, char *buf, int len) {
    char temp_buf[4096];
    memcpy(temp_buf, buf, len);
    temp_buf[len] = '\r';
    temp_buf[len + 1] = '\n';
    return write_to_socket(c->sock_fd, temp_buf, len + 2);
}
int read_from_client(struct client_sock *curr) {
    return read_from_socket(curr->sock_fd, curr->buf, &(curr->inbuf));
}