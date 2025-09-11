#ifndef CONSOLE_H
#define CONSOLE_H

#include <limine.h>

void console_init(struct limine_framebuffer *fb);
void kprint(const char *str);
void kputchar(char c);
char kgetchar(void);

#endif