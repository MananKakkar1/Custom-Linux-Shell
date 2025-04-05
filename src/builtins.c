#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "builtins.h"
#include "io_helpers.h"
#include "variables.h"
#include "commands.h"
#include <unistd.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <signal.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <assert.h>
#include "server.h"
char *path_error = "Invalid path";
char *input_error = "No input source provided";
char *file_not_open = "Cannot open file";
char *missing_flag = "Missing flag";
char *malloc_failure = "Malloc failed";
char *depth_error = "Incorrect depth";
char *directory_not_file = "Directory not file";

typedef struct {
	pid_t pid;
	char command[MAX_STR_LEN];
	char argument[MAX_STR_LEN];
	int process_num;
} bg_process;
static listen_sck server = {.sock_fd = -1, .addr = NULL, .client_count = 0, .server_running = 0};
int connected = 1;
bg_process bg_processes[MAX_STR_LEN];
ssize_t bg_process_count = 0;
int curr_port_in_use = 0;
int server_running = 0;
int sigint_received = 0;

void sigint_handler2(int code) {
	(void)code;
	return;
}
// ====== Command execution =====

/* Return: index of builtin or -1 if cmd doesn't match a builtin
 */
bn_ptr check_builtin(const char *cmd) {
    ssize_t cmd_num = 0;
    while (cmd_num < BUILTINS_COUNT &&
           strncmp(BUILTINS[cmd_num], cmd, MAX_STR_LEN) != 0) {
        cmd_num += 1;
    }
    return BUILTINS_FN[cmd_num];
}
int contains_var(char *str) {
	while (*str) {
		if (*str == '$') {
			return 1;
		}
	str++;
	}
	return 0;
}
listen_sck *get_sock_fd() {
	return &server;
}
ssize_t dot_count(const char *str) {
	int count = 0;
	while (*str) {
		if (*str == '.') {
			count++;
		}
		str++;
	}
	return count;
}
void view_bg_processes() {
	for (int i = 0; i < bg_process_count; i++) {
		char buffer[4096];
		snprintf(buffer, sizeof(buffer), "[%d] %d\n", i+1, bg_processes[i].pid);
		display_message(buffer);
	}
}
void add_bg_process_arg(pid_t pid, char *command, char *argument) {
	bg_processes[bg_process_count].pid = pid;
	strcpy(bg_processes[bg_process_count].command, command);
	strcpy(bg_processes[bg_process_count].argument, argument);
	bg_processes[bg_process_count].process_num = bg_process_count+1;
	char buffer[4096];
	snprintf(buffer, sizeof(buffer), "[%ld] %d\n", bg_process_count+1, bg_processes[bg_process_count].pid);
	display_message(buffer);
	fflush(stdout);
	bg_process_count++;
}
void add_bg_process_w_arg(pid_t pid, char *command) {
	bg_processes[bg_process_count].pid = pid;
	strcpy(bg_processes[bg_process_count].command, command);
	strcpy(bg_processes[bg_process_count].argument, "");
	bg_processes[bg_process_count].process_num = bg_process_count+1;
	char buffer[4096];
	snprintf(buffer, sizeof(buffer), "[%ld] %d\n", bg_process_count+1, bg_processes[bg_process_count].pid);
	display_message(buffer);
	fflush(stdout);
	bg_process_count++;
}
void remove_bg_process(pid_t pid) {
	for (int i = 0; i < bg_process_count; i++) {
		if (bg_processes[i].pid == pid) {
			char buffer[MAX_STR_LEN+MAX_STR_LEN+MAX_STR_LEN];
			snprintf(buffer, sizeof(buffer), "[%d]+  Done %s %s\n", bg_processes[i].process_num, bg_processes[i].command, bg_processes[i].argument);
			display_message(buffer);
			display_message("mysh$ ");
			for (int j = i; j < bg_process_count - 1; j++) {
				bg_processes[j] = bg_processes[j + 1];
			}
			bg_process_count--;
			break;
		}
	}
}
void clear_bg_processes() {
	bg_process_count = 0;
	int status;
	pid_t pid;
	while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
		if (WIFEXITED(status)) {
			remove_bg_process(pid);
		}
	}
}
ssize_t list_directory(const char *path, const char *filter, int recursive, int depth) {
	if (recursive != 1 && depth != -1) {
		display_error("ERROR: ", missing_flag);
		display_message("\n");
		return -1;
	}
	if (strlen(path) == 0) {
		path = ".";
	}
	DIR *dir = opendir(path);
	if (!dir) {
		display_error("ERROR: ", path_error);
		display_message("\n");
		return -1;
	}
	struct dirent *entry;
	while ((entry = readdir(dir)) != NULL) {
		if (strcmp(entry->d_name, ".") == 0 && filter == NULL) {
			display_message(".");
			display_message("\n");
		} else if (strcmp(entry->d_name, "..") == 0 && filter == NULL) {
			display_message("..");
			display_message("\n");
		} else if (filter == NULL) {
			display_message(entry->d_name);
			display_message("\n");
		} else if (strstr(entry->d_name, filter) != NULL) {
			display_message(entry->d_name);
			display_message("\n");
		}
		if (recursive == 1 && depth - 1 > 0) {
			char *new_path = malloc(strlen(path) + strlen(entry->d_name) + 2);
			if (entry->d_type == DT_DIR && strcmp(entry->d_name, "..") != 0 && strcmp(entry->d_name, ".") != 0) {
				snprintf(new_path, strlen(path) + strlen(entry->d_name) + 2, "%s/%s", path, entry->d_name);
				list_directory(new_path, filter, recursive, depth - 1);
			}
			free(new_path);
		} else if (recursive == 1 && depth == -1) {
			char *new_path = malloc(strlen(path) + strlen(entry->d_name) + 2);
			if (entry->d_type == DT_DIR && strcmp(entry->d_name, "..") != 0 && strcmp(entry->d_name, ".") != 0) {
				snprintf(new_path, strlen(path) + strlen(entry->d_name) + 2, "%s/%s", path, entry->d_name);
				list_directory(new_path, filter, recursive, depth);
			}
			free(new_path);
		}
	}
	closedir(dir);
	return 0;
}

void broadcast_message(const char *message) {
	struct client_sock *curr = server.clients;
	while (curr) {
		write_buf_to_client(curr, (char *)message, strlen(message));
		curr = curr->next;
	}
    display_message((char *)message);
}

// ===== Builtins =====

/* Prereq: tokens is a NULL terminated sequence of strings.
 * Return 0 on success and -1 on error ... but there are no errors on echo. 
 */

ssize_t bn_kill(char **tokens) {
	if (tokens[1] == NULL) {
		display_error("ERROR: Missing pid", "");
		display_message("\n");
		return -1;
	}
	pid_t pid = atoi(tokens[1]);
	if (pid <= 0) {
		display_error("ERROR: Invalid pid", "");
		display_message("\n");
		return -1;
	}
	int signal = SIGTERM;
	if (tokens[2] != NULL) {
		signal = atoi(tokens[2]);
		if (signal <= 0 || signal >= NSIG) {
			display_error("ERROR: Invalid signal specified", "");
			display_message("\n");
			return -1;
		}
	}
	if (kill(pid, signal) == -1) {
		display_error("ERROR: ", "The process does not exist");
		display_message("\n");
		return -1;
	}
	if (signal == SIGTERM) {
		remove_bg_process(pid);
	}
	return 0;
}
ssize_t bn_ps() {
	for (int i = 0; i < bg_process_count; i++) {
		char buffer[4096];
		snprintf(buffer, sizeof(buffer), "%d %s\n", bg_processes[i].pid, bg_processes[i].command);
		display_message(buffer);
	}
	return 0;
}
ssize_t bn_ls(char **tokens) {
	char *path = NULL;
	int recursive = 0;
	int depth = -1;
	char *filter = NULL;
	for (int i = 1; tokens[i] != NULL; i++) {
		if (strcmp(tokens[i], "--f") == 0 && tokens[i+1] != NULL) {
			filter = tokens[++i];
		} else if (strcmp(tokens[i], "--rec") == 0) {
			recursive = 1;
		} else if (strcmp(tokens[i], "--d") == 0 && tokens[i+1] != NULL) {
			depth = atoi(tokens[++i]);
			if (depth < 0) {
				display_error("ERROR: ", depth_error);
				display_message("\n");
				return -1;
			}
		} else {
			if (path != NULL && strcmp(path, ".") != 0) {
				display_error("ERROR: ", "Too many arguments: ls takes a single path");
				display_message("\n");
				return -1;
			}
			path = tokens[i];
		}
	}
	if (path == NULL) {
		path = ".";
	}
	ssize_t return_val = list_directory(path, filter, recursive, depth);
	if (return_val == 0) {
		return 0;
	} else {
		return -1;
	}
}
ssize_t bn_cat(char **tokens) {
	FILE *file = NULL;
	if (tokens[1] == NULL) {
		if (!isatty(STDIN_FILENO)) {
			file = stdin;
		} else {
			display_error("ERROR: ", input_error);
			return -1;
		}
	} else {
		if (tokens[2] != NULL) {
			display_error("ERROR: ", "Too many arguments: cat takes a single file");
			display_message("\n");
			return -1;
		}
		struct stat is_file;
		stat(tokens[1], &is_file);
		if (!S_ISREG(is_file.st_mode)) {
			display_error("ERROR: Cannot open file", "");
			display_message("\n");
			return -1;
		}
		file = fopen(tokens[1], "r");
		if (file == NULL) {
			display_error("ERROR: ", file_not_open);
			return -1;
		}
	}
	char buffer[4096];
	while (fgets(buffer, sizeof(buffer), file) != NULL) {
		display_message(buffer);
	}
	if (file != stdin) {
        fclose(file);
    }
	return 0;
}
ssize_t bn_cd(char **tokens) {
	if (tokens[1] == NULL) {
		display_error("ERROR: ", path_error);
		display_message("\n");
		return -1;
	}
	if (tokens[2] != NULL) {
		display_error("ERROR: ", "Too many arguments: cd takes a single path");
		display_message("\n");
		return -1;
	}
	char path[4096];
	memset(path, '\0', sizeof(path));
	if (tokens[1][0] == '/') {
        strncpy(path, tokens[1], sizeof(path) - 1);
    } else {
        char token_copy[MAX_STR_LEN];
        strncpy(token_copy, tokens[1], sizeof(token_copy));
        char *token = strtok(token_copy, "/");
        while (token != NULL) {
            ssize_t dot = dot_count(token);
            if (dot >= 2) {
                if (strcmp(token, "...") == 0) {
                    strcat(path, "../../");
                } else if (strcmp(token, "....") == 0) {
                    strcat(path, "../../../");
                } else if (strcmp(token, "..") == 0) {
                    strcat(path, "../");
                }
            } else if (strcmp(token, "..") == 0) {
                strcat(path, "../");
            } else if (strcmp(token, ".") != 0) {
                strcat(path, token);
                strcat(path, "/");
            }
            token = strtok(NULL, "/");
        }
    }
    size_t len = strlen(path);
    if (len > 1 && path[len - 1] == '/') {
        path[len - 1] = '\0';
    }

    if (chdir(path) != 0) {
        display_error("ERROR: ", path_error);
        display_message("\n");
        return -1;
    }
    return 0;
}
ssize_t bn_wc(char **tokens) {
	FILE *file = NULL;
	if (tokens[1] == NULL) {
		if (!isatty(STDIN_FILENO)) {
			file = stdin;
		} else {		
			display_error("ERROR: ", input_error);
			return -1;	
		}
	} else {
		if (tokens[2] != NULL) {
			display_error("ERROR: ", "Too many arguments: wc takes a single file");
			display_message("\n");
			return -1;
		}
		struct stat is_file;
		stat(tokens[1], &is_file);
		if (!S_ISREG(is_file.st_mode)) {
			display_error("ERROR: Cannot open file", "");
			display_message("\n");
			return -1;
		}
		file = fopen(tokens[1], "r");
		if (file == NULL) {
			display_error("ERROR: ", file_not_open);
			display_message("\n");
			return -1;
		}
	}
	int lines = 0;
	int words = 0;
	int chars = 1;
	char chr;
	char previous_char = '\0';
	if (fgetc(file) == EOF) {
		char buffer[4096];
		snprintf(buffer, sizeof(buffer), "word count %d\ncharacter count %d\nnewline count %d\n", 0, 0, 0);
		display_message(buffer);
		return 0;
	}
	while ((chr = fgetc(file)) != EOF) {
		chars++;
		if ((chr == '\n')) {
			lines++;
		}
		if ((chr == ' ' || chr == '\n' || chr == '\t' || chr == '\r') && previous_char != ' ' && 
		previous_char != '\n' && previous_char != '\t' && previous_char != '\r') {
			words++;
		}
		previous_char = chr;
	}
	if (previous_char != ' ' && previous_char != '\n' && previous_char != '\t' && previous_char != '\r') {
		words++;
	}
	char buffer[4096];
	snprintf(buffer, sizeof(buffer), "word count %d\ncharacter count %d\nnewline count %d\n", words, chars, lines);
	display_message(buffer);
	if (file != stdin) {
        fclose(file);
    }
	return 0;
}
ssize_t bn_echo(char **tokens) {
    ssize_t index = 1;
    if (tokens[index] != NULL) {
		display_message(tokens[index]);
		index += 1;
    }
    while (tokens[index] != NULL) {
		display_message(" ");
		display_message(tokens[index]);
		index += 1;
    }
    display_message("\n");
    return 0;
}


ssize_t bn_start_server(char **tokens) {
    if (tokens[1] == NULL) {
        display_error("ERROR: ", "No port provided");
        return -1;
    }
    int port = atoi(tokens[1]);
    if (port <= 0) {
        display_error("ERROR: ", "Invalid port number");
        return -1;
    }

    if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
        perror("signal");
        return -1;
    }

    struct client_sock *clients = NULL;
    listen_sck s;
    int l = setup_server_socket(&s, port);
    if (l == 1) {
        display_error("ERROR: ", "Port already in use");
        return -1;
    }
    if (s.sock_fd == -100) {
        display_error("ERROR: ", "Port already in use");
        return -1;
    }
    server.sock_fd = s.sock_fd;
    server.addr = malloc(sizeof(struct sockaddr_in));
    if (server.addr == NULL) {
        perror("malloc");
        close(s.sock_fd);
        return -1;
    }
    memcpy(server.addr, s.addr, sizeof(struct sockaddr_in));
    free(s.addr);
    server.server_running = 1;

    pid_t pid = fork();
    server.pid = pid;
    if (pid < 0) {
        perror("fork");
        free(server.addr);
        return -1;
    }
    if (pid == 0) {
        int exit_status = 0;
        int max_fd = s.sock_fd;
        fd_set all_fds, listen_fds;
        FD_ZERO(&all_fds);
        FD_SET(s.sock_fd, &all_fds);
        curr_port_in_use = port;
        do {
            listen_fds = all_fds;
            int nready = select(max_fd + 1, &listen_fds, NULL, NULL, NULL);
            if (nready == -1) {
                if (errno == EINTR) continue;
                perror("server: select");
                exit_status = 1;
                break;
            }
            if (FD_ISSET(s.sock_fd, &listen_fds)) {
                int client_fd = accept_connection(s.sock_fd, &clients, &connected);
                if (client_fd < 0) {
                    display_message("Failed to accept incoming connection.\n");
                    continue;
                }
                if (client_fd > max_fd) {
                    max_fd = client_fd;
                }
                FD_SET(client_fd, &all_fds);
            }
            struct client_sock *curr = clients;
            while (curr) {
                if (!FD_ISSET(curr->sock_fd, &listen_fds)) {
                    curr = curr->next;
                    continue;
                }
                int client_closed = read_from_client(curr);
                if (client_closed == -1) {
                    client_closed = 1;
                }
                if (client_closed == 0) {
                    char *msg;
                    while (client_closed == 0 && !get_message(&msg, curr->buf, &(curr->inbuf))) {
						char full_msg[4096];
						if (strncmp(msg, "\\connected", 10) == 0) {
							snprintf(full_msg, sizeof(full_msg), "Connected clients: %d", server.client_count);
							write_buf_to_client(curr, full_msg, strlen(full_msg));
							free(msg);
						} else {
							snprintf(full_msg, sizeof(full_msg), "%s %s\n", curr->username, msg);
							broadcast_message(full_msg);
							fflush(stdout);
							free(msg);
						}
                    }
                }
                if (client_closed == 1) {
                    FD_CLR(curr->sock_fd, &all_fds);
                    close(curr->sock_fd);
                    assert(remove_client(&curr, &clients) == 0);
                    connected--;
					server.client_count--;
                } else {
                    curr = curr->next;
                }
            }
        } while (!sigint_received);
        server.server_running = 0;
        close(s.sock_fd);
        if (kill(server.pid, SIGTERM) < 0) {
            perror("kill");
            return -1;
        }
        exit(exit_status); 
    }
    return 0;
}

ssize_t bn_close_server(char **tokens) {
	if (tokens[1] != NULL) {
		display_error("ERROR: Invalid syntax", "");
		return -1;
	}
	if (server.sock_fd == -1) {
		display_error("ERROR: No active server", "");
		return -1;
	}
	if (server.server_running == 0) {
		display_error("ERROR: Server is not running", "");
		return -1;
	}
	for (int i = 0; i < server.client_count; i++) {
        close(server.client_socks[i]);
    }
	close(server.sock_fd);
	server.sock_fd = -1;
	server.client_count = 0;
	if (server.addr != NULL) {
        free(server.addr);
        server.addr = NULL;
    }
	server.server_running = 0;
    curr_port_in_use = 0;
	if (kill(server.pid, SIGTERM) < 0) {
		perror("kill");
		return -1;
	}
	display_message("Server Closed\n");
	return 0;
}

ssize_t bn_send(char **tokens) {
	if (tokens[1] == NULL) {
        display_error("ERROR: ", "No port provided");
        return -1;
    }
    if (tokens[2] == NULL) {
        display_error("ERROR: ", "No hostname provided");
        return -1;
    }
    if (tokens[3] == NULL) {
        display_error("ERROR: ", "No message provided");
        return -1;
    }
    char *hostname = tokens[2];
    int port = atoi(tokens[1]);
	char *message = malloc(MAX_STR_LEN);
	message[0] = '\0';
	for (int i = 3; tokens[i] != NULL; i++) {
		size_t remaining_space = MAX_STR_LEN - strlen(message) - 1;
        strncat(message, tokens[i], remaining_space);
        if (tokens[i + 1] != NULL) {
            strncat(message, " ", remaining_space - strlen(message));
        }
	}
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket");
        return -1;
    }
    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(port);
    if (inet_pton(AF_INET, hostname, &dest.sin_addr) <= 0) {
        perror("inet_pton");
        close(sock);
        return -1;
    }
    if (connect(sock, (struct sockaddr*)&dest, sizeof(dest)) < 0) {
        perror("connect");
        close(sock);
        return -1;
    }
    char buf[4096];
    snprintf(buf, sizeof(buf), "%s\r\n", message);
    ssize_t bytes_sent = send(sock, buf, strlen(buf), 0);
    if (bytes_sent < 0) {
        perror("send");
        close(sock);
        return -1;
    }
	free(message);
    close(sock);
    return 0;
}

ssize_t bn_start_client(char **tokens) {
    if (tokens[1] == NULL) {
        display_error("ERROR: ", "No port provided");
        return -1;
    }
    if (tokens[2] == NULL) {
        display_error("ERROR: ", "No hostname provided");
        return -1;
    }
    char *hostname = tokens[2];
    int port = atoi(tokens[1]);
    struct server_sock s;
    s.inbuf = 0;
    int exit_status = 0;
    s.sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (s.sock_fd < 0) {
        perror("client: socket");
        return -1;
    }
    struct sockaddr_in svr;
    svr.sin_family = AF_INET;
    svr.sin_port = htons(port);
    if (inet_pton(AF_INET, hostname, &svr.sin_addr) < 1) {
        perror("client: inet_pton");
        close(s.sock_fd);
        return -1;
    }
    if (connect(s.sock_fd, (struct sockaddr *)&svr, sizeof(svr)) == -1) {
        perror("client: connect");
        close(s.sock_fd);
        return -1;
    }
    fd_set all_fds, read_fds;
    FD_ZERO(&all_fds);
    FD_SET(STDIN_FILENO, &all_fds);
    FD_SET(s.sock_fd, &all_fds);
	int max_fd = s.sock_fd;
    if (STDIN_FILENO > max_fd) {
        max_fd = STDIN_FILENO;
    }
    s.buf[0] = '\0';
    char user_input[4096];
	struct sigaction sa_sigint;
	memset(&sa_sigint, 0, sizeof(sa_sigint));
	sa_sigint.sa_handler = sigint_handler2;
	sa_sigint.sa_flags = 0;
	sigemptyset(&sa_sigint.sa_mask);
	sigaction(SIGINT, &sa_sigint, NULL);
    while (1) {
        read_fds = all_fds;
        if (select(max_fd + 1, &read_fds, NULL, NULL, NULL) == -1) {
            perror("select");
            exit_status = 1;
            break;
        }
        if (FD_ISSET(STDIN_FILENO, &read_fds)) {
            if (fgets(user_input, sizeof(user_input), stdin) == NULL) {
                break;
            }
            size_t len = strlen(user_input);
            if (len > 0 && user_input[len - 1] == '\n') {
                user_input[len - 1] = '\r';
                user_input[len] = '\n';
                user_input[len + 1] = '\0';
            }
            if (write_to_socket(s.sock_fd, user_input, strlen(user_input)) != 0) {
                display_error("Error sending message", "");
                exit_status = 1;
                break;
            }
        }
        if (FD_ISSET(s.sock_fd, &read_fds)) {
            int bytes_read = read_from_socket(s.sock_fd, s.buf, &(s.inbuf));
            if (bytes_read == -1) {
                display_error("Error reading from server", "");
                exit_status = 1;
                break;
            } else if (bytes_read == 1) {
                display_message("Server closed connection\n");
                break;
            } else {
                char *message = NULL;
                while (get_message(&message, s.buf, &(s.inbuf)) == 0) {
                    display_message(message); 
					display_message("\n");
                    fflush(stdout);
                    free(message);
                }
            }
        }
    }
    close(s.sock_fd);
	memset(s.buf, 0, sizeof(s.buf));
	s.inbuf = 0;
	if (feof(stdin)) {
		clearerr(stdin);
	}
    return exit_status;
}




