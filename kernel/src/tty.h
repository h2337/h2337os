#ifndef TTY_H
#define TTY_H

#include <stdbool.h>
#include <stddef.h>

void tty_init(void);
void tty_register_device(void);
size_t tty_read(char *buffer, size_t count);
size_t tty_write(const char *buffer, size_t count);
char tty_getchar(void);
bool tty_has_input(void);
void tty_flush(void);
void tty_handle_input(char c);

#endif
