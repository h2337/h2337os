#ifndef USERMODE_H
#define USERMODE_H

#include <stdint.h>

void enter_usermode(void *entry_point, void *user_stack);
void usermode_test(void);

#endif