#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <signal.h>

#include "variables.h"
#include "builtins.h"
#include "io_helpers.h"
#include "commands.h"
#include "server.h"

void handler() {
	display_message("\nmysh$ ");
	fflush(stdout);
}
void child_process_handler(int signal) {
	(void) signal;
	if (signal == SIGCHLD) {
		int status;
		pid_t pid;
		while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
			if (WIFEXITED(status) || WIFSIGNALED(status)) {
				remove_bg_process(pid);
			}
		}
	}
}

// You can remove __attribute__((unused)) once argc and argv are used.
int main(__attribute__((unused)) int argc, 
         __attribute__((unused)) char* argv[]) {
    char *prompt = "mysh$ "; // TODO Step 1, Uncomment this.

    char input_buf[MAX_STR_LEN + 1];
    input_buf[MAX_STR_LEN] = '\0';
    char *token_arr[MAX_STR_LEN] = {NULL};
    size_t token_count = 0;
	signal(SIGCHLD, child_process_handler);
	signal(SIGINT, handler);
    while (1) {
		for (size_t i = 0; i < token_count; i++) {
			free(token_arr[i]);
			token_arr[i] = NULL;
		}
        // Prompt and input tokenization
        // Display the prompt via the display_message function.
		display_message(prompt);
		fflush(stdin);
        int ret = get_input(input_buf);
        token_count = tokenize_input(input_buf, token_arr);

        // Clean exit
		if ((ret != -1 && token_count == 0 && token_arr[0] != NULL) || (token_count > 0 && token_arr[0] == NULL) || ((token_arr[0] != NULL) && (strncmp("exit", token_arr[0], 5) == 0))) {
			break;
		}
		else if (ret == 0) {
			display_message("\n");
			break;
		}
		fflush(stdin);
        // Command execution
        if (token_count >= 1) {
			int num_pipes = 0;
			for (size_t i = 0; i < token_count; i++) {
				if (strcmp(token_arr[i], "|") == 0) {
					num_pipes++;
				} else if (strchr(token_arr[i], '|') != NULL) {
					for (char *p = token_arr[i]; *p != '\0'; p++) {
                        if (*p == '|') {
                            num_pipes++;
                        }
                    }
				}
			}
			if (num_pipes > 0) {
				execute_pipe(token_arr, num_pipes, token_count);
			} else {
				execute_command(token_arr, token_count);
			}
      	}
    }
    free_all_variables();
	for (size_t i = 0; i < token_count; i++) {
		free(token_arr[i]);
		token_arr[i] = NULL;
	}
	listen_sck *s = get_sock_fd();
	if (s->server_running == 1) {
		for (int i = 0; i < s->client_count; i++) {
			close(s->client_socks[i]);
		}
		close(s->sock_fd);
		s->sock_fd = -1;
		s->client_count = 0;
		if (s->addr != NULL) {
			free(s->addr);
			s->addr = NULL;
		}
		if (kill(s->pid, SIGTERM) < 0) {
			perror("kill");
		}
		s->server_running = 0;
	}
    return 0;
}
