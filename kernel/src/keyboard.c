#include "keyboard.h"
#include "console.h"
#include "idt.h"
#include "pic.h"
#include <stdbool.h>
#include <stdint.h>

static const char scancode_to_ascii[] = {
    0,    27,   '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '-',  '=',
    '\b', '\t', 'q', 'w', 'e', 'r', 't', 'y', 'u', 'i', 'o', 'p', '[',  ']',
    '\n', 0,    'a', 's', 'd', 'f', 'g', 'h', 'j', 'k', 'l', ';', '\'', '`',
    0,    '\\', 'z', 'x', 'c', 'v', 'b', 'n', 'm', ',', '.', '/', 0,    '*',
    0,    ' ',  0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,    0,
    0,    0,    '7', '8', '9', '-', '4', '5', '6', '+', '1', '2', '3',  '0',
    '.',  0,    0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,    0,
    0,    0,    0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,    0,
    0,    0,    0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,    0,
    0,    0,    0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0};

static const char scancode_to_ascii_shift[] = {
    0,    27,   '!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '_', '+',
    '\b', '\t', 'Q', 'W', 'E', 'R', 'T', 'Y', 'U', 'I', 'O', 'P', '{', '}',
    '\n', 0,    'A', 'S', 'D', 'F', 'G', 'H', 'J', 'K', 'L', ':', '"', '~',
    0,    '|',  'Z', 'X', 'C', 'V', 'B', 'N', 'M', '<', '>', '?', 0,   '*',
    0,    ' ',  0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    0,    0,    '7', '8', '9', '-', '4', '5', '6', '+', '1', '2', '3', '0',
    '.',  0,    0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    0,    0,    0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    0,    0,    0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    0,    0,    0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0};

static keyboard_state_t kb_state = {false, false, false, false, false, false};
static char keyboard_buffer[KEYBOARD_BUFFER_SIZE];
static uint16_t buffer_start = 0;
static uint16_t buffer_end = 0;
static uint16_t buffer_count = 0;

static inline uint8_t inb(uint16_t port) {
  uint8_t ret;
  asm volatile("inb %1, %0" : "=a"(ret) : "Nd"(port));
  return ret;
}

static inline void outb(uint16_t port, uint8_t val) {
  asm volatile("outb %0, %1" : : "a"(val), "Nd"(port));
}

static void keyboard_wait_input(void) {
  while ((inb(KEYBOARD_STATUS_PORT) & 2) != 0) {
    asm volatile("pause");
  }
}

static void keyboard_wait_output(void) {
  while ((inb(KEYBOARD_STATUS_PORT) & 1) == 0) {
    asm volatile("pause");
  }
}

static void keyboard_add_to_buffer(char c) {
  if (buffer_count >= KEYBOARD_BUFFER_SIZE) {
    return;
  }

  keyboard_buffer[buffer_end] = c;
  buffer_end = (buffer_end + 1) % KEYBOARD_BUFFER_SIZE;
  buffer_count++;
}

void keyboard_handler(void) {
  uint8_t scancode = inb(KEYBOARD_DATA_PORT);

  if (scancode & KEY_RELEASED) {
    scancode &= ~KEY_RELEASED;
    switch (scancode) {
    case KEY_LEFT_SHIFT:
    case KEY_RIGHT_SHIFT:
      kb_state.shift = false;
      break;
    case KEY_LEFT_CTRL:
      kb_state.ctrl = false;
      break;
    case KEY_LEFT_ALT:
      kb_state.alt = false;
      break;
    }
  } else {
    switch (scancode) {
    case KEY_LEFT_SHIFT:
    case KEY_RIGHT_SHIFT:
      kb_state.shift = true;
      break;
    case KEY_LEFT_CTRL:
      kb_state.ctrl = true;
      break;
    case KEY_LEFT_ALT:
      kb_state.alt = true;
      break;
    case KEY_CAPSLOCK:
      kb_state.caps_lock = !kb_state.caps_lock;
      break;
    case KEY_NUMLOCK:
      kb_state.num_lock = !kb_state.num_lock;
      break;
    case KEY_SCROLLLOCK:
      kb_state.scroll_lock = !kb_state.scroll_lock;
      break;
    default:
      if (scancode < sizeof(scancode_to_ascii)) {
        char c;
        if (kb_state.shift || kb_state.caps_lock) {
          c = scancode_to_ascii_shift[scancode];
          if (kb_state.caps_lock && kb_state.shift && c >= 'A' && c <= 'Z') {
            c = c - 'A' + 'a';
          } else if (kb_state.caps_lock && !kb_state.shift && c >= 'a' &&
                     c <= 'z') {
            c = c - 'a' + 'A';
          }
        } else {
          c = scancode_to_ascii[scancode];
        }

        if (c != 0) {
          if (kb_state.ctrl && c >= 'a' && c <= 'z') {
            c = c - 'a' + 1;
          } else if (kb_state.ctrl && c >= 'A' && c <= 'Z') {
            c = c - 'A' + 1;
          }

          keyboard_add_to_buffer(c);

          if (c == '\n') {
            kprint("\n");
          } else if (c == '\b') {
            kprint("\b \b");
          } else if (c >= 32 && c <= 126) {
            kputchar(c);
          }
        }
      }
      break;
    }
  }

  pic_send_eoi(1);
}

char keyboard_getchar(void) {
  while (buffer_count == 0) {
    asm volatile("hlt");
  }

  char c = keyboard_buffer[buffer_start];
  buffer_start = (buffer_start + 1) % KEYBOARD_BUFFER_SIZE;
  buffer_count--;
  return c;
}

bool keyboard_has_input(void) { return buffer_count > 0; }

void keyboard_flush_buffer(void) {
  buffer_start = 0;
  buffer_end = 0;
  buffer_count = 0;
}

void keyboard_init(void) {
  keyboard_wait_input();
  outb(KEYBOARD_COMMAND_PORT, 0xAD);

  keyboard_wait_input();
  outb(KEYBOARD_COMMAND_PORT, 0xA7);

  inb(KEYBOARD_DATA_PORT);

  keyboard_wait_input();
  outb(KEYBOARD_COMMAND_PORT, 0x20);
  keyboard_wait_output();
  uint8_t status = inb(KEYBOARD_DATA_PORT);
  status |= 1;
  status &= ~0x10;

  keyboard_wait_input();
  outb(KEYBOARD_COMMAND_PORT, 0x60);
  keyboard_wait_input();
  outb(KEYBOARD_DATA_PORT, status);

  keyboard_wait_input();
  outb(KEYBOARD_COMMAND_PORT, 0xAA);
  keyboard_wait_output();
  if (inb(KEYBOARD_DATA_PORT) != 0x55) {
    kprint("Keyboard: Controller self-test failed\n");
  }

  keyboard_wait_input();
  outb(KEYBOARD_COMMAND_PORT, 0xAB);
  keyboard_wait_output();
  if (inb(KEYBOARD_DATA_PORT) != 0x00) {
    kprint("Keyboard: Port test failed\n");
  }

  keyboard_wait_input();
  outb(KEYBOARD_COMMAND_PORT, 0xAE);

  keyboard_wait_input();
  outb(KEYBOARD_DATA_PORT, 0xFF);
  keyboard_wait_output();
  if (inb(KEYBOARD_DATA_PORT) != 0xFA) {
    kprint("Keyboard: Reset failed\n");
  }

  keyboard_wait_input();
  outb(KEYBOARD_DATA_PORT, 0xF4);
  keyboard_wait_output();
  inb(KEYBOARD_DATA_PORT);

  keyboard_flush_buffer();

  pic_clear_mask(1);

  kprint("Keyboard initialized\n");
}