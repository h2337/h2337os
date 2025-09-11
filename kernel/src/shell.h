#ifndef SHELL_H
#define SHELL_H

#include <stdbool.h>
#include <stddef.h>

#define SHELL_BUFFER_SIZE 256
#define SHELL_MAX_ARGS 16
#define SHELL_HISTORY_SIZE 10
#define SHELL_PROMPT "h2337os> "

typedef struct {
  char *name;
  char *description;
  int (*handler)(int argc, char **argv);
} shell_command_t;

void shell_init(void);
void shell_run(void);
void shell_process_command(char *input);

#endif