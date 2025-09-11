#ifndef CONSOLE_H
#define CONSOLE_H

#include <limine.h>
#include <stdint.h>

void console_init(struct limine_framebuffer *fb);
void kprint(const char *str);
void kputchar(char c);
char kgetchar(void);
void kprint_hex(uint64_t value);
void kprint_hex8(uint8_t value);
void kprint_hex16(uint16_t value);
void kprint_dec(uint32_t value);

#endif