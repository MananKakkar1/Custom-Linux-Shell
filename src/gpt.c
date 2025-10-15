#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <cjson/cJSON.h>

#include "server.h"
#include "commands.h"
#include "io_helpers.h"

#define GPT_MAX_RESPONSE 65536
#define GPT_MODEL "gpt-4o-mini"

// Long system prompt (kept exactly as specified)
#define SYSTEM_PROMPT \
"You are a Linux CLI assistant:\n" \
"- If the input is a shell question or task, return the cleanest Bash command only.\n" \
"- If the input is conversational, respond politely and briefly.\n" \
"- No markdown, no backticks.\n" \
"- Prefer short, efficient commands.\n" \
"- Only explain if the user says 'explain'.\n" \
"- Assume modern Linux shell with common tools (grep, sed, awk, jq, curl, etc).\n" \
"- Prefer POSIX utilities and pipelines.\n" \
"- If multiple answers exist, choose the cleanest and shortest.\n"

struct Memory {
    char *response;
    size_t size;
};

// Detect if prompt is “explain/show/give” style (print-only)
int is_explain_prompt(const char *prompt) {
    const char *keywords[] = {
        "give", "show", "explain", "how to", "what is", "command for", "tell me", "example"
    };
    for (size_t i = 0; i < sizeof(keywords)/sizeof(keywords[0]); i++) {
        if (strcasestr(prompt, keywords[i])) return 1;
    }
    return 0;
}

// Safety filter for GPT-executed commands
int is_command_safe(const char *cmd) {
    if (strstr(cmd, "rm -rf /")) return 0;
    if (strstr(cmd, ":(){ :|:& };:")) return 0;
    if (strstr(cmd, "mkfs")) return 0;
    if (strstr(cmd, "shutdown")) return 0;
    if (strstr(cmd, "reboot")) return 0;
    return 1;
}

// Use the shell's tokenizer and executor
static void tokenize_and_execute(const char *cmd_str) {
    if (!is_command_safe(cmd_str)) {
        fprintf(stderr, "Refused to execute unsafe command.\n");
        return;
    }

    char buffer[MAX_STR_LEN + 1];
    strncpy(buffer, cmd_str, MAX_STR_LEN);
    buffer[MAX_STR_LEN] = '\0';

    char *tokens[256] = {0};
    size_t token_count = tokenize_input(buffer, tokens);

    if (token_count > 0) {
        execute_command(tokens, token_count);
    }

    free_all_tokens(tokens);
}

// Handles incoming chunks of data from cURL
static size_t write_callback(void *data, size_t size, size_t nmemb, void *userp) {
    size_t total = size * nmemb;
    struct Memory *mem = (struct Memory *)userp;
    char *ptr = realloc(mem->response, mem->size + total + 1);
    if (ptr == NULL) {
        fprintf(stderr, "realloc() failed\n");
        return 0;
    }
    mem->response = ptr;
    memcpy(&(mem->response[mem->size]), data, total);
    mem->size += total;
    mem->response[mem->size] = '\0';
    return total;
}

// Escapes special characters to make strings valid JSON
char *escape_json(const char *input) {
    if (!input) return NULL;
    size_t len = strlen(input);
    char *escaped = malloc(len * 6 + 1);
    if (!escaped) return NULL;

    char *dst = escaped;
    for (const char *src = input; *src; src++) {
        switch (*src) {
            case '"':
            case '\\':
                *dst++ = '\\';
                *dst++ = *src;
                break;
            case '\n':
                *dst++ = '\\';
                *dst++ = 'n';
                break;
            case '\r':
                *dst++ = '\\';
                *dst++ = 'r';
                break;
            default:
                *dst++ = *src;
                break;
        }
    }
    *dst = '\0';
    return escaped;
}

// Core GPT API call
int call_gpt_api(const char *prompt) {
    CURL *curl;
    CURLcode res;

    const char *api_key = getenv("OPENAI_API_KEY");
    if (!api_key) {
        fprintf(stderr, "OPENAI_API_KEY not set.\n");
        return -1;
    }

    int debug_mode = 0;
    const char *dbg_env = getenv("GPT_DEBUG");
    if (dbg_env && strcmp(dbg_env, "1") == 0) {
        debug_mode = 1;
    }

    int explain_mode = is_explain_prompt(prompt);

    char *escaped_prompt = escape_json(prompt);
    char *escaped_system = escape_json(SYSTEM_PROMPT);
    if (!escaped_prompt || !escaped_system) {
        fprintf(stderr, "Failed to allocate memory for JSON escaping.\n");
        free(escaped_prompt);
        free(escaped_system);
        return -1;
    }

    char post_data[GPT_MAX_RESPONSE];
    snprintf(post_data, sizeof(post_data),
        "{"
        "\"model\":\"%s\","
        "\"messages\":["
            "{\"role\":\"system\",\"content\":\"%s\"},"
            "{\"role\":\"user\",\"content\":\"%s\"}"
        "],"
        "\"max_tokens\":512"
        "}",
        GPT_MODEL, escaped_system, escaped_prompt
    );

    free(escaped_prompt);
    free(escaped_system);

    struct Memory chunk;
    chunk.response = malloc(1);
    chunk.size = 0;

    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();

    if (curl) {
        struct curl_slist *headers = NULL;
        char auth_header[512];
        snprintf(auth_header, sizeof(auth_header), "Authorization: Bearer %s", api_key);

        headers = curl_slist_append(headers, "Content-Type: application/json");
        headers = curl_slist_append(headers, auth_header);

        curl_easy_setopt(curl, CURLOPT_URL, "https://api.openai.com/v1/chat/completions");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &chunk);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);

        res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        } else {
            if (debug_mode) {
                printf("\n--- RAW RESPONSE ---\n%s\n--------------------\n", chunk.response);
            }

            cJSON *root = cJSON_Parse(chunk.response);
            if (!root) {
                fprintf(stderr, "Failed to parse JSON.\n");
            } else {
                cJSON *choices = cJSON_GetObjectItem(root, "choices");
                if (choices && cJSON_IsArray(choices)) {
                    cJSON *first = cJSON_GetArrayItem(choices, 0);
                    cJSON *message = cJSON_GetObjectItem(first, "message");
                    cJSON *content = cJSON_GetObjectItem(message, "content");

                    if (content && cJSON_IsString(content)) {
                        char *out = content->valuestring;
                        while (*out == ' ' || *out == '\n' || *out == '\t') out++;
                        char *end = out + strlen(out) - 1;
                        while (end > out && (*end == ' ' || *end == '\n' || *end == '\t')) *end-- = '\0';

                        if (strlen(out) == 0) {
                            printf("[GPT]: (empty)\n");
                        } else {
                            printf("[GPT]: %s\n", out);
                            if (!explain_mode) {
        			printf("[Execute] y/n: ");
        			fflush(stdout);

        			char answer[8];
        			if (fgets(answer, sizeof(answer), stdin)) {
            				// strip newline
            				answer[strcspn(answer, "\n")] = '\0';
            				if (strcasecmp(answer, "y") == 0 || strcasecmp(answer, "yes") == 0) {
                				tokenize_and_execute(out);
            				} else {
                				printf("Command not executed.\n");
            				}
        			}
    			}
			}
                    } else {
                        fprintf(stderr, "No valid content in GPT response.\n");
                    }
                }
                cJSON_Delete(root);
            }
        }

        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
    }

    curl_global_cleanup();
    free(chunk.response);
    return 0;
}
