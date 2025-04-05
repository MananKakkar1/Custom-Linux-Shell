#ifndef VARIABLES_H
#define VARIABLES_H

void set_variable(const char *key, const char *value);
const char *get_variable(const char *key);
void free_all_variables();
#endif
