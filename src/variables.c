#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "variables.h"

typedef struct Variable {
    char *key;
    char *value;
    struct Variable *next;
} Variable;

static Variable *head = NULL;

void set_variable(const char *key, const char *value) {
    Variable *current = head;
    while (current != NULL) {
        if (strcmp(current->key, key) == 0) {
            free(current->value);
            current->value = strdup(value);
            return;
        }
        current = current->next;
    }
    Variable *new_var = malloc(sizeof(Variable));
    new_var->key = strdup(key);
    new_var->value = strdup(value);
    new_var->next = head;
    head = new_var;
}

const char *get_variable(const char *key) {
    Variable *current = head;

    while (current != NULL) {
        if (strcmp(current->key, key) == 0) {
            return current->value;
        }
        current = current->next;
    }

    return NULL;
}

void free_all_variables() {
	Variable *current = head;
	while (current != NULL) {
		Variable *temp = current;
		current = current->next;
		free(temp->key);
		free(temp->value);
		free(temp);
	}
	head = NULL;
}
