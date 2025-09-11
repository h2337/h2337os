#include "shell.h"
#include "console.h"
#include "heap.h"
#include "keyboard.h"
#include "libc.h"
#include "pit.h"
#include "pmm.h"
#include "process.h"
#include "vmm.h"
#include <stdbool.h>
#include <stdint.h>

static char shell_buffer[SHELL_BUFFER_SIZE];
static size_t buffer_pos = 0;
static char *shell_history[SHELL_HISTORY_SIZE];
static int history_count = 0;
static int history_pos = 0;

static int cmd_help(int argc, char **argv);
static int cmd_clear(int argc, char **argv);
static int cmd_mem(int argc, char **argv);
static int cmd_echo(int argc, char **argv);
static int cmd_reboot(int argc, char **argv);
static int cmd_shutdown(int argc, char **argv);
static int cmd_test(int argc, char **argv);
static int cmd_about(int argc, char **argv);
static int cmd_uptime(int argc, char **argv);
static int cmd_hex(int argc, char **argv);
static int cmd_sleep(int argc, char **argv);
static int cmd_timer(int argc, char **argv);
static int cmd_ps(int argc, char **argv);
static int cmd_spawn(int argc, char **argv);
static int cmd_kill(int argc, char **argv);

static shell_command_t shell_commands[] = {
    {"help", "Display available commands", cmd_help},
    {"clear", "Clear the screen", cmd_clear},
    {"mem", "Display memory information", cmd_mem},
    {"echo", "Echo text to the screen", cmd_echo},
    {"reboot", "Reboot the system", cmd_reboot},
    {"shutdown", "Shutdown the system", cmd_shutdown},
    {"test", "Run system tests", cmd_test},
    {"about", "Display system information", cmd_about},
    {"uptime", "Display system uptime", cmd_uptime},
    {"hex", "Display hexadecimal value", cmd_hex},
    {"sleep", "Sleep for specified milliseconds", cmd_sleep},
    {"timer", "Display timer information", cmd_timer},
    {"ps", "List running processes", cmd_ps},
    {"spawn", "Spawn a test process", cmd_spawn},
    {"kill", "Kill a process by PID", cmd_kill},
    {NULL, NULL, NULL}};

static int cmd_help(int argc, char **argv) {
  (void)argc;
  (void)argv;

  kprint("Available commands:\n");
  for (int i = 0; shell_commands[i].name != NULL; i++) {
    kprint("  ");
    kprint(shell_commands[i].name);

    int name_len = strlen(shell_commands[i].name);
    for (int j = name_len; j < 12; j++) {
      kprint(" ");
    }

    kprint("- ");
    kprint(shell_commands[i].description);
    kprint("\n");
  }
  return 0;
}

static int cmd_clear(int argc, char **argv) {
  (void)argc;
  (void)argv;

  kprint("\033[2J\033[H");
  return 0;
}

static int cmd_mem(int argc, char **argv) {
  (void)argc;
  (void)argv;

  size_t total_pages = pmm_get_total_pages();
  size_t free_pages = pmm_get_free_pages();
  size_t used_pages = pmm_get_used_pages();

  kprint("Memory Information:\n");
  kprint("  Total: ");
  kprint_hex(total_pages * PAGE_SIZE);
  kprint(" bytes (");
  kprint_hex(total_pages);
  kprint(" pages)\n");

  kprint("  Free:  ");
  kprint_hex(free_pages * PAGE_SIZE);
  kprint(" bytes (");
  kprint_hex(free_pages);
  kprint(" pages)\n");

  kprint("  Used:  ");
  kprint_hex(used_pages * PAGE_SIZE);
  kprint(" bytes (");
  kprint_hex(used_pages);
  kprint(" pages)\n");

  uint64_t percent_used = (used_pages * 100) / total_pages;
  kprint("  Usage: ");
  kprint_hex(percent_used);
  kprint("%\n");

  return 0;
}

static int cmd_echo(int argc, char **argv) {
  for (int i = 1; i < argc; i++) {
    kprint(argv[i]);
    if (i < argc - 1) {
      kprint(" ");
    }
  }
  kprint("\n");
  return 0;
}

static int cmd_reboot(int argc, char **argv) {
  (void)argc;
  (void)argv;

  kprint("Rebooting system...\n");

  asm volatile("cli");

  uint8_t good = 0x02;
  while (good & 0x02) {
    asm volatile("inb $0x64, %0" : "=a"(good));
  }
  asm volatile("outb %0, $0x64" : : "a"((uint8_t)0xFE));

  for (;;) {
    asm volatile("hlt");
  }

  return 0;
}

static int cmd_shutdown(int argc, char **argv) {
  (void)argc;
  (void)argv;

  kprint("Shutting down...\n");
  kprint("System halted.\n");

  asm volatile("cli");
  for (;;) {
    asm volatile("hlt");
  }

  return 0;
}

static int cmd_test(int argc, char **argv) {
  (void)argc;
  (void)argv;

  kprint("Running system tests...\n\n");

  kprint("[TEST] Memory allocation:\n");
  void *test1 = kmalloc(128);
  if (test1) {
    kprint("  ✓ kmalloc(128) succeeded\n");
    kfree(test1);
    kprint("  ✓ kfree() succeeded\n");
  } else {
    kprint("  ✗ kmalloc(128) failed\n");
  }

  kprint("\n[TEST] String operations:\n");
  char test_str[32];
  strcpy(test_str, "Hello");
  if (strcmp(test_str, "Hello") == 0) {
    kprint("  ✓ strcpy/strcmp working\n");
  } else {
    kprint("  ✗ strcpy/strcmp failed\n");
  }

  strcat(test_str, " World");
  if (strcmp(test_str, "Hello World") == 0) {
    kprint("  ✓ strcat working\n");
  } else {
    kprint("  ✗ strcat failed\n");
  }

  kprint("\nAll tests completed.\n");
  return 0;
}

static int cmd_about(int argc, char **argv) {
  (void)argc;
  (void)argv;

  kprint("h2337os - A 64-bit Operating System\n");
  kprint("Version: 0.1.0\n");
  kprint("Architecture: x86_64\n");
  kprint("\nFeatures:\n");
  kprint("  - Physical Memory Manager (PMM)\n");
  kprint("  - Virtual Memory Manager (VMM)\n");
  kprint("  - Interrupt handling (IDT)\n");
  kprint("  - PS/2 Keyboard driver\n");
  kprint("  - Basic shell interface\n");
  kprint("  - Dynamic memory allocation\n");
  return 0;
}

static int cmd_uptime(int argc, char **argv) {
  (void)argc;
  (void)argv;

  uint64_t seconds = pit_get_seconds();
  uint64_t minutes = seconds / 60;
  uint64_t hours = minutes / 60;
  uint64_t days = hours / 24;

  kprint("System uptime: ");
  if (days > 0) {
    kprint_hex(days);
    kprint(" days, ");
  }
  if (hours > 0) {
    kprint_hex(hours % 24);
    kprint(" hours, ");
  }
  if (minutes > 0) {
    kprint_hex(minutes % 60);
    kprint(" minutes, ");
  }
  kprint_hex(seconds % 60);
  kprint(" seconds\n");

  kprint("Total ticks: ");
  kprint_hex(pit_get_ticks());
  kprint("\n");

  return 0;
}

static int cmd_hex(int argc, char **argv) {
  if (argc < 2) {
    kprint("Usage: hex <number>\n");
    return 1;
  }

  uint64_t value = 0;
  char *str = argv[1];

  while (*str) {
    if (*str >= '0' && *str <= '9') {
      value = value * 10 + (*str - '0');
    } else {
      kprint("Invalid number\n");
      return 1;
    }
    str++;
  }

  kprint("Decimal: ");
  kprint(argv[1]);
  kprint("\nHexadecimal: 0x");
  kprint_hex(value);
  kprint("\n");

  return 0;
}

static int cmd_sleep(int argc, char **argv) {
  if (argc < 2) {
    kprint("Usage: sleep <milliseconds>\n");
    return 1;
  }

  uint32_t ms = 0;
  char *str = argv[1];

  while (*str) {
    if (*str >= '0' && *str <= '9') {
      ms = ms * 10 + (*str - '0');
    } else {
      kprint("Invalid number\n");
      return 1;
    }
    str++;
  }

  kprint("Sleeping for ");
  kprint_hex(ms);
  kprint(" milliseconds...\n");

  pit_sleep(ms);

  kprint("Done!\n");
  return 0;
}

static int cmd_timer(int argc, char **argv) {
  (void)argc;
  (void)argv;

  kprint("Timer Information:\n");
  kprint("  Frequency: ");
  kprint_hex(PIT_DEFAULT_FREQUENCY);
  kprint(" Hz\n");

  kprint("  Current ticks: ");
  kprint_hex(pit_get_ticks());
  kprint("\n");

  kprint("  Milliseconds: ");
  kprint_hex(pit_get_milliseconds());
  kprint("\n");

  kprint("  Seconds: ");
  kprint_hex(pit_get_seconds());
  kprint("\n");

  return 0;
}

static void test_process_1(void) {
  int counter = 0;
  while (1) {
    kprint("[P1:");
    kprint_hex(counter++);
    kprint("] ");
    process_yield(); // Give other processes a chance
    process_sleep(1000);
    if (counter >= 10) {
      kprint("[P1 exiting]\n");
      process_exit(0);
    }
  }
}

static void test_process_2(void) {
  int counter = 0;
  while (1) {
    kprint("[P2:");
    kprint_hex(counter++);
    kprint("] ");
    process_yield(); // Give other processes a chance
    process_sleep(1500);
    if (counter >= 7) {
      kprint("[P2 exiting]\n");
      process_exit(0);
    }
  }
}

static void cpu_intensive_process(void) {
  uint64_t counter = 0;
  while (1) {
    counter++;
    if ((counter & 0xFFFFF) == 0) {
      kprint("[CPU:");
      kprint_hex(counter >> 20);
      kprint("] ");
    }
    if (counter >= 0x5000000) {
      kprint("[CPU process done]\n");
      process_exit(0);
    }
  }
}

static int cmd_ps(int argc, char **argv) {
  (void)argc;
  (void)argv;

  process_list();
  return 0;
}

static int cmd_spawn(int argc, char **argv) {
  if (argc < 2) {
    kprint("Usage: spawn <test1|test2|cpu>\n");
    kprint("  test1 - Spawn test process 1 (prints every 1s)\n");
    kprint("  test2 - Spawn test process 2 (prints every 1.5s)\n");
    kprint("  cpu   - Spawn CPU-intensive process\n");
    return 1;
  }

  if (strcmp(argv[1], "test1") == 0) {
    process_create("test1", test_process_1);
    kprint("Spawned test process 1\n");
  } else if (strcmp(argv[1], "test2") == 0) {
    process_create("test2", test_process_2);
    kprint("Spawned test process 2\n");
  } else if (strcmp(argv[1], "cpu") == 0) {
    process_create("cpu_test", cpu_intensive_process);
    kprint("Spawned CPU-intensive process\n");
  } else {
    kprint("Unknown process type: ");
    kprint(argv[1]);
    kprint("\n");
    return 1;
  }

  return 0;
}

static int cmd_kill(int argc, char **argv) {
  if (argc < 2) {
    kprint("Usage: kill <pid>\n");
    return 1;
  }

  uint32_t pid = 0;
  char *str = argv[1];

  while (*str) {
    if (*str >= '0' && *str <= '9') {
      pid = pid * 10 + (*str - '0');
    } else {
      kprint("Invalid PID\n");
      return 1;
    }
    str++;
  }

  process_t *proc = process_get_by_pid(pid);
  if (!proc) {
    kprint("Process with PID ");
    kprint_hex(pid);
    kprint(" not found\n");
    return 1;
  }

  if (pid == 0) {
    kprint("Cannot kill idle process\n");
    return 1;
  }

  kprint("Killing process '");
  kprint(proc->name);
  kprint("' (PID ");
  kprint_hex(pid);
  kprint(")\n");

  process_destroy(proc);
  return 0;
}

static char **tokenize_command(char *input, int *argc) {
  static char *args[SHELL_MAX_ARGS];
  *argc = 0;

  if (!input || *input == '\0') {
    return args;
  }

  while (*input == ' ' || *input == '\t') {
    input++;
  }

  while (*input && *argc < SHELL_MAX_ARGS - 1) {
    args[*argc] = input;
    (*argc)++;

    while (*input && *input != ' ' && *input != '\t') {
      input++;
    }

    if (*input) {
      *input = '\0';
      input++;

      while (*input == ' ' || *input == '\t') {
        input++;
      }
    }
  }

  args[*argc] = NULL;
  return args;
}

void shell_process_command(char *input) {
  int argc;
  char **argv = tokenize_command(input, &argc);

  if (argc == 0) {
    return;
  }

  for (int i = 0; shell_commands[i].name != NULL; i++) {
    if (strcmp(argv[0], shell_commands[i].name) == 0) {
      shell_commands[i].handler(argc, argv);
      return;
    }
  }

  kprint("Unknown command: ");
  kprint(argv[0]);
  kprint("\nType 'help' for available commands.\n");
}

static void add_to_history(char *command) {
  if (strlen(command) == 0) {
    return;
  }

  if (history_count < SHELL_HISTORY_SIZE) {
    shell_history[history_count] = kmalloc(strlen(command) + 1);
    if (shell_history[history_count]) {
      strcpy(shell_history[history_count], command);
      history_count++;
    }
  } else {
    kfree(shell_history[0]);
    for (int i = 0; i < SHELL_HISTORY_SIZE - 1; i++) {
      shell_history[i] = shell_history[i + 1];
    }
    shell_history[SHELL_HISTORY_SIZE - 1] = kmalloc(strlen(command) + 1);
    if (shell_history[SHELL_HISTORY_SIZE - 1]) {
      strcpy(shell_history[SHELL_HISTORY_SIZE - 1], command);
    }
  }
  history_pos = history_count;
}

void shell_init(void) {
  buffer_pos = 0;
  history_count = 0;
  history_pos = 0;
  memset(shell_buffer, 0, SHELL_BUFFER_SIZE);

  kprint("\n");
  kprint("Welcome to h2337os Shell!\n");
  kprint("Type 'help' for available commands.\n");
  kprint("\n");
}

void shell_run(void) {
  kprint(SHELL_PROMPT);

  while (1) {
    if (keyboard_has_input()) {
      char c = keyboard_getchar();

      if (c == '\n') {
        kprint("\n");
        shell_buffer[buffer_pos] = '\0';

        if (buffer_pos > 0) {
          add_to_history(shell_buffer);
          shell_process_command(shell_buffer);
        }

        buffer_pos = 0;
        memset(shell_buffer, 0, SHELL_BUFFER_SIZE);
        kprint(SHELL_PROMPT);

      } else if (c == '\b') {
        if (buffer_pos > 0) {
          buffer_pos--;
          shell_buffer[buffer_pos] = '\0';
          kprint("\b \b");
        }

      } else if (c >= 32 && c <= 126) {
        if (buffer_pos < SHELL_BUFFER_SIZE - 1) {
          shell_buffer[buffer_pos++] = c;
          kputchar(c);
        }

      } else if (c == 0x1B) {
        char next = keyboard_getchar();
        if (next == '[') {
          char arrow = keyboard_getchar();

          if (arrow == 'A' && history_pos > 0) {
            for (size_t i = 0; i < buffer_pos; i++) {
              kprint("\b \b");
            }

            history_pos--;
            strcpy(shell_buffer, shell_history[history_pos]);
            buffer_pos = strlen(shell_buffer);
            kprint(shell_buffer);

          } else if (arrow == 'B') {
            for (size_t i = 0; i < buffer_pos; i++) {
              kprint("\b \b");
            }

            if (history_pos < history_count - 1) {
              history_pos++;
              strcpy(shell_buffer, shell_history[history_pos]);
              buffer_pos = strlen(shell_buffer);
              kprint(shell_buffer);
            } else if (history_pos < history_count) {
              history_pos = history_count;
              shell_buffer[0] = '\0';
              buffer_pos = 0;
            }
          }
        }
      }
    }
    asm volatile("hlt");
  }
}