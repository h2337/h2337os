#include "shell.h"
#include "console.h"
#include "elf.h"
#include "heap.h"
#include "keyboard.h"
#include "libc.h"
#include "pci.h"
#include "pit.h"
#include "pmm.h"
#include "process.h"
#include "usermode.h"
#include "vfs.h"
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
static int cmd_ls(int argc, char **argv);
static int cmd_cat(int argc, char **argv);
static int cmd_write(int argc, char **argv);
static int cmd_mkdir(int argc, char **argv);
static int cmd_rm(int argc, char **argv);
static int cmd_touch(int argc, char **argv);
static int cmd_pwd(int argc, char **argv);
static int cmd_cd(int argc, char **argv);
static int cmd_usermode(int argc, char **argv);
static int cmd_exec(int argc, char **argv);
static int cmd_lspci(int argc, char **argv);

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
    {"ls", "List directory contents", cmd_ls},
    {"cat", "Display file contents", cmd_cat},
    {"write", "Write text to file", cmd_write},
    {"mkdir", "Create a directory", cmd_mkdir},
    {"rm", "Remove a file", cmd_rm},
    {"touch", "Create an empty file", cmd_touch},
    {"pwd", "Print working directory", cmd_pwd},
    {"cd", "Change directory", cmd_cd},
    {"usermode", "Test user mode", cmd_usermode},
    {"exec", "Execute an ELF binary", cmd_exec},
    {"lspci", "List PCI devices", cmd_lspci},
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

  // First check built-in commands
  for (int i = 0; shell_commands[i].name != NULL; i++) {
    if (strcmp(argv[0], shell_commands[i].name) == 0) {
      shell_commands[i].handler(argc, argv);
      return;
    }
  }

  // Try to execute as a binary from /bin
  char path[VFS_MAX_PATH];
  strcpy(path, "/bin/");
  strcat(path, argv[0]);

  vfs_node_t *file = vfs_open(path, VFS_READ);
  if (file) {
    if (!(file->type & VFS_DIRECTORY)) {
      // Check if it's an ELF binary
      uint8_t header[4];
      uint32_t bytes_read = vfs_read(file, 0, 4, header);
      vfs_close(file);

      if (bytes_read == 4 && *(uint32_t *)header == 0x464C457F) {
        // It's an ELF binary, execute it
        int result = elf_exec(path, argv, NULL);
        if (result < 0) {
          kprint("Failed to execute: ");
          kprint(argv[0]);
          kprint("\n");
        }
        return;
      }
    } else {
      vfs_close(file);
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

static void shell_print_prompt(void) {
  const char *cwd = process_get_cwd();
  kprint("[");
  kprint(cwd);
  kprint("] ");
  kprint(SHELL_PROMPT);
}

void shell_run(void) {
  shell_print_prompt();

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
        shell_print_prompt();

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

static int cmd_ls(int argc, char **argv) {
  vfs_node_t *dir;

  if (argc > 1) {
    // Use provided path
    dir = vfs_resolve_path(argv[1]);
    if (!dir) {
      kprint("Error: Directory not found: ");
      kprint(argv[1]);
      kprint("\n");
      return 1;
    }
  } else {
    // No argument - use current directory
    dir = vfs_resolve_path(".");
    if (!dir) {
      kprint("Error: Cannot access current directory\n");
      return 1;
    }
  }

  if (!(dir->type & VFS_DIRECTORY)) {
    kprint("Error: Not a directory\n");
    return 1;
  }

  kprint("Directory listing:\n");
  uint32_t index = 0;
  vfs_node_t *child;

  while ((child = vfs_readdir(dir, index++)) != NULL) {
    if (child->type & VFS_DIRECTORY) {
      kprint("[DIR]  ");
    } else {
      kprint("[FILE] ");
    }
    kprint(child->name);
    if (!(child->type & VFS_DIRECTORY)) {
      kprint(" (");
      kprint_hex(child->size);
      kprint(" bytes)");
    }
    kprint("\n");
    kfree(child);
  }

  return 0;
}

static int cmd_cat(int argc, char **argv) {
  if (argc < 2) {
    kprint("Usage: cat <filename>\n");
    return 1;
  }

  vfs_node_t *file = vfs_open(argv[1], VFS_READ);
  if (!file) {
    kprint("Error: File not found: ");
    kprint(argv[1]);
    kprint("\n");
    return 1;
  }

  if (file->type & VFS_DIRECTORY) {
    kprint("Error: ");
    kprint(argv[1]);
    kprint(" is a directory\n");
    vfs_close(file);
    return 1;
  }

  uint8_t *buffer = kmalloc(file->size + 1);
  if (!buffer) {
    kprint("Error: Out of memory\n");
    vfs_close(file);
    return 1;
  }

  uint32_t bytes_read = vfs_read(file, 0, file->size, buffer);
  buffer[bytes_read] = '\0';

  kprint((char *)buffer);
  if (bytes_read > 0 && buffer[bytes_read - 1] != '\n') {
    kprint("\n");
  }

  kfree(buffer);
  vfs_close(file);
  return 0;
}

static int cmd_write(int argc, char **argv) {
  if (argc < 3) {
    kprint("Usage: write <filename> <text>\n");
    return 1;
  }

  vfs_node_t *file = vfs_open(argv[1], VFS_WRITE | VFS_CREATE | VFS_TRUNCATE);
  if (!file) {
    kprint("Error: Cannot create file: ");
    kprint(argv[1]);
    kprint("\n");
    return 1;
  }

  size_t total_len = 0;
  for (int i = 2; i < argc; i++) {
    total_len += strlen(argv[i]);
    if (i < argc - 1)
      total_len++;
  }

  char *buffer = kmalloc(total_len + 1);
  if (!buffer) {
    kprint("Error: Out of memory\n");
    vfs_close(file);
    return 1;
  }

  buffer[0] = '\0';
  for (int i = 2; i < argc; i++) {
    strcat(buffer, argv[i]);
    if (i < argc - 1) {
      strcat(buffer, " ");
    }
  }

  uint32_t bytes_written =
      vfs_write(file, 0, strlen(buffer), (uint8_t *)buffer);

  kprint("Wrote ");
  kprint_hex(bytes_written);
  kprint(" bytes to ");
  kprint(argv[1]);
  kprint("\n");

  kfree(buffer);
  vfs_close(file);
  return 0;
}

static int cmd_mkdir(int argc, char **argv) {
  if (argc < 2) {
    kprint("Usage: mkdir <dirname>\n");
    return 1;
  }

  char dirpath[VFS_MAX_PATH];
  char dirname[VFS_MAX_NAME];

  strcpy(dirpath, argv[1]);
  char *last_slash = NULL;
  for (char *p = dirpath; *p; p++) {
    if (*p == '/') {
      last_slash = p;
    }
  }

  vfs_node_t *parent;
  if (last_slash) {
    strcpy(dirname, last_slash + 1);
    *last_slash = '\0';
    parent = vfs_resolve_path(dirpath);
  } else {
    // No slash means create in current directory
    strcpy(dirname, argv[1]);
    parent = vfs_resolve_path(".");
  }

  if (!parent) {
    kprint("Error: Parent directory not found\n");
    return 1;
  }

  if (vfs_create(parent, dirname, VFS_DIRECTORY) < 0) {
    kprint("Error: Cannot create directory: ");
    kprint(argv[1]);
    kprint("\n");
    return 1;
  }

  kprint("Created directory: ");
  kprint(argv[1]);
  kprint("\n");
  return 0;
}

static int cmd_rm(int argc, char **argv) {
  if (argc < 2) {
    kprint("Usage: rm <filename>\n");
    return 1;
  }

  char filepath[VFS_MAX_PATH];
  char filename[VFS_MAX_NAME];

  strcpy(filepath, argv[1]);
  char *last_slash = NULL;
  for (char *p = filepath; *p; p++) {
    if (*p == '/') {
      last_slash = p;
    }
  }

  vfs_node_t *parent;
  if (last_slash) {
    strcpy(filename, last_slash + 1);
    *last_slash = '\0';
    parent = vfs_resolve_path(filepath);
  } else {
    // No slash means remove from current directory
    strcpy(filename, argv[1]);
    parent = vfs_resolve_path(".");
  }

  if (!parent) {
    kprint("Error: Parent directory not found\n");
    return 1;
  }

  if (vfs_unlink(parent, filename) < 0) {
    kprint("Error: Cannot remove: ");
    kprint(argv[1]);
    kprint("\n");
    return 1;
  }

  kprint("Removed: ");
  kprint(argv[1]);
  kprint("\n");
  return 0;
}

static int cmd_touch(int argc, char **argv) {
  if (argc < 2) {
    kprint("Usage: touch <filename>\n");
    return 1;
  }

  vfs_node_t *file = vfs_open(argv[1], VFS_WRITE | VFS_CREATE);
  if (!file) {
    kprint("Error: Cannot create file: ");
    kprint(argv[1]);
    kprint("\n");
    return 1;
  }

  vfs_close(file);

  kprint("Created file: ");
  kprint(argv[1]);
  kprint("\n");
  return 0;
}

static int cmd_pwd(int argc, char **argv) {
  (void)argc;
  (void)argv;

  const char *cwd = process_get_cwd();
  kprint(cwd);
  kprint("\n");
  return 0;
}

static int cmd_cd(int argc, char **argv) {
  if (argc < 2) {
    // No argument means go to root
    if (process_set_cwd("/") < 0) {
      kprint("Error: Cannot change to root directory\n");
      return 1;
    }
    return 0;
  }

  if (process_set_cwd(argv[1]) < 0) {
    kprint("Error: Cannot change directory to: ");
    kprint(argv[1]);
    kprint("\n");
    return 1;
  }

  return 0;
}

static int cmd_usermode(int argc, char **argv) {
  (void)argc;
  (void)argv;

  kprint("Testing user mode transition...\n");
  usermode_test();
  return 0;
}

static int cmd_exec(int argc, char **argv) {
  if (argc < 2) {
    kprint("Usage: exec <binary>\n");
    return 1;
  }

  // Build the full path
  char path[VFS_MAX_PATH];
  if (argv[1][0] == '/' || strchr(argv[1], '/')) {
    strcpy(path, argv[1]);
  } else {
    strcpy(path, "/bin/");
    strcat(path, argv[1]);
  }

  // Check if file exists
  vfs_node_t *file = vfs_open(path, VFS_READ);
  if (!file) {
    kprint("Error: File not found: ");
    kprint(path);
    kprint("\n");
    return 1;
  }

  // Check if it's a regular file
  if (file->type & VFS_DIRECTORY) {
    kprint("Error: ");
    kprint(path);
    kprint(" is a directory\n");
    vfs_close(file);
    return 1;
  }

  // Read ELF header to verify
  uint8_t header[4];
  uint32_t bytes_read = vfs_read(file, 0, 4, header);
  vfs_close(file);

  if (bytes_read != 4 || *(uint32_t *)header != 0x464C457F) {
    kprint("Error: ");
    kprint(path);
    kprint(" is not an ELF binary\n");
    return 1;
  }

  // Create args array starting from argv[1] (the binary name)
  char **exec_argv = &argv[1];

  // Execute the ELF binary
  int result = elf_exec(path, exec_argv, NULL);

  // elf_exec returns 0 on success, negative on error
  if (result < 0) {
    kprint("Error: Failed to execute ");
    kprint(path);
    kprint(" (error code: ");
    kprint_hex(result);
    kprint(")\n");
    return 1;
  }

  // Success! The program was executed
  return 0;
}

static int cmd_lspci(int argc, char **argv) {
  (void)argc;
  (void)argv;

  kprint("Scanning PCI bus...\n");
  pci_scan_bus();
  kprint("\n");
  pci_list_devices();

  return 0;
}