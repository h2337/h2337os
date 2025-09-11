#ifndef KEYBOARD_H
#define KEYBOARD_H

#include <stdbool.h>
#include <stdint.h>

#define KEYBOARD_DATA_PORT 0x60
#define KEYBOARD_STATUS_PORT 0x64
#define KEYBOARD_COMMAND_PORT 0x64

#define KEYBOARD_BUFFER_SIZE 256

#define KEY_RELEASED 0x80

enum SpecialKeys {
  KEY_ESCAPE = 0x01,
  KEY_BACKSPACE = 0x0E,
  KEY_TAB = 0x0F,
  KEY_ENTER = 0x1C,
  KEY_LEFT_CTRL = 0x1D,
  KEY_LEFT_SHIFT = 0x2A,
  KEY_RIGHT_SHIFT = 0x36,
  KEY_LEFT_ALT = 0x38,
  KEY_CAPSLOCK = 0x3A,
  KEY_F1 = 0x3B,
  KEY_F2 = 0x3C,
  KEY_F3 = 0x3D,
  KEY_F4 = 0x3E,
  KEY_F5 = 0x3F,
  KEY_F6 = 0x40,
  KEY_F7 = 0x41,
  KEY_F8 = 0x42,
  KEY_F9 = 0x43,
  KEY_F10 = 0x44,
  KEY_NUMLOCK = 0x45,
  KEY_SCROLLLOCK = 0x46,
  KEY_HOME = 0x47,
  KEY_UP = 0x48,
  KEY_PAGE_UP = 0x49,
  KEY_LEFT = 0x4B,
  KEY_RIGHT = 0x4D,
  KEY_END = 0x4F,
  KEY_DOWN = 0x50,
  KEY_PAGE_DOWN = 0x51,
  KEY_INSERT = 0x52,
  KEY_DELETE = 0x53,
  KEY_F11 = 0x57,
  KEY_F12 = 0x58
};

typedef struct {
  bool shift;
  bool ctrl;
  bool alt;
  bool caps_lock;
  bool num_lock;
  bool scroll_lock;
} keyboard_state_t;

void keyboard_init(void);
void keyboard_handler(void);
char keyboard_getchar(void);
bool keyboard_has_input(void);
void keyboard_flush_buffer(void);

#endif