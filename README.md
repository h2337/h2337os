# h2337os - A 64-bit Hobby Operating System

h2337os is a 64-bit operating system written from scratch in C for x86_64 architecture. It features a monolithic kernel with process management, filesystem implementation, and a interactive shell environment.

### Memory Management
- **Physical Memory Manager (PMM)**: Page-based allocation with bitmap tracking
- **Virtual Memory Manager (VMM)**: 4-level paging with kernel/user space separation
- **Dynamic Heap Allocator**: kmalloc/kfree/kcalloc/krealloc implementation
- **Memory-mapped I/O** support for hardware devices

### Process Management
- **Multi-process support**: Up to 256 concurrent processes
- **Preemptive round-robin scheduling** with time slicing via PIT
- **Process states**: Ready, Running, Blocked, Terminated, Zombie
- **Fork/Exec model** with full parent-child relationships
- **ELF binary loading**: Support for 64-bit ELF executables (ET_EXEC and ET_DYN)
- **User mode execution** with privilege separation (Ring 0/Ring 3)
- **Per-process resources**: File descriptors, working directory, memory space

### File System
- **Virtual File System (VFS)** layer for filesystem abstraction
- **FAT32 implementation** with:
  - Long filename (LFN) support
  - Directory operations (create, remove, navigate)
  - File operations (create, read, write, delete)
  - RAM-based storage backend
- **RAM disk** for initial root filesystem
- **Mount point management** for multiple filesystems

### System Calls (26 POSIX-like calls)

**Process Control:**
- `exit` (0) - Terminate process
- `fork` (5) - Create child process
- `execve` (6) - Execute program
- `waitpid` (7) - Wait for child
- `getpid` (8) - Get process ID
- `getppid` (9) - Get parent PID

**File Operations:**
- `write` (1) - Write to file
- `read` (2) - Read from file
- `open` (3) - Open file/directory
- `close` (4) - Close file descriptor
- `lseek` (18) - Seek in file
- `stat` (16) - Get file status
- `fstat` (17) - Get status by fd
- `unlink` (25) - Delete file

**Directory Operations:**
- `getcwd` (14) - Get current directory
- `chdir` (15) - Change directory
- `mkdir` (23) - Create directory
- `rmdir` (24) - Remove directory

**Memory Management:**
- `brk` (10) - Adjust program break
- `mmap` (11) - Map memory
- `munmap` (12) - Unmap memory

**I/O Control:**
- `ioctl` (19) - Device control
- `dup` (20) - Duplicate fd
- `dup2` (21) - Duplicate to specific fd
- `pipe` (22) - Create pipe
- `time` (13) - Get system time

### Device Drivers

**Input Devices:**
- **PS/2 Keyboard**: Full scancode set with special keys, modifiers (Shift/Ctrl/Alt), and state tracking (Caps/Num/Scroll Lock)
- **Serial Ports**: COM1-COM4 support with async I/O for debugging

**Display:**
- **Framebuffer Console**: VGA text mode via Flanterm terminal emulator
- **Text rendering** with cursor support and scrolling

**Hardware:**
- **PCI Bus Driver**: Device enumeration, configuration space access, vendor/device ID detection
- **PIT (8254)**: System timer at 100Hz for scheduling
- **PIC (8259)**: Interrupt controller management

### Interactive Shell

The built-in shell provides **25 commands**:

**System Management:**
- `help` - Show available commands
- `about` - System information
- `uptime` - System uptime
- `mem` - Memory statistics
- `timer` - Timer information
- `reboot` - Restart system
- `shutdown` - Power off

**Process Control:**
- `ps` - List processes
- `spawn` - Create test processes
- `kill` - Terminate process by PID
- `exec` - Execute ELF binary
- `usermode` - Test user mode transition

**File Operations:**
- `ls` - List directory contents
- `cat` - Display file contents
- `write` - Write text to file
- `touch` - Create empty file
- `mkdir` - Create directory
- `rm` - Remove file
- `pwd` - Print working directory
- `cd` - Change directory

**Utilities:**
- `echo` - Print text
- `clear` - Clear screen
- `hex` - Display hex value
- `sleep` - Delay execution
- `test` - Run system tests
- `lspci` - List PCI devices

## Building

### Prerequisites
- x86_64 GCC cross-compiler or Clang
- GNU Make
- NASM assembler
- xorriso (ISO creation)
- mtools (FAT32 manipulation)
- QEMU (for testing)
- curl (for OVMF download)


## Running

### QEMU Emulation
```bash
# Build root filesystem
./build-rootfs.sh

# Run with UEFI firmware
make run-uefi
```

Default QEMU configuration:
- 2GB RAM
- Serial output to stdio
- Q35 machine type

## Project Structure

```
h2337os/
├── kernel/               # Kernel source code
│   ├── src/              # Core kernel components
│   │   ├── main.c        # Kernel entry point (kmain)
│   │   ├── gdt.c/h       # Global Descriptor Table
│   │   ├── idt.c/h       # Interrupt Descriptor Table
│   │   ├── pmm.c/h       # Physical Memory Manager
│   │   ├── vmm.c/h       # Virtual Memory Manager
│   │   ├── heap.c/h      # Heap allocator
│   │   ├── process.c/h   # Process management
│   │   ├── scheduler.c/h # Process scheduler
│   │   ├── syscall.c/h   # System call handler
│   │   ├── vfs.c/h       # Virtual filesystem
│   │   ├── fat32.c/h     # FAT32 driver
│   │   ├── ramdisk.c/h   # RAM disk driver
│   │   ├── keyboard.c/h  # PS/2 keyboard driver
│   │   ├── console.c/h   # Console output
│   │   ├── serial.c/h    # Serial port driver
│   │   ├── pic.c/h       # 8259 PIC driver
│   │   ├── pit.c/h       # 8254 PIT driver
│   │   ├── pci.c/h       # PCI bus driver
│   │   ├── elf.c/h       # ELF loader
│   │   ├── usermode.c/h  # User mode support
│   │   ├── shell.c/h     # Built-in shell
│   │   ├── sync.c/h      # Synchronization (spinlocks)
│   │   ├── libc.c/h      # Kernel C library
│   │   └── limine_requests.c/h # Bootloader interface
│   ├── flanterm/          # Terminal emulator library
│   ├── freestnd-c-hdrs/   # Freestanding C headers
│   ├── cc-runtime/        # C runtime support
│   ├── limine-protocol/   # Limine protocol headers
│   ├── linker-scripts/    # Linker configuration
│   ├── GNUmakefile        # Kernel build system
│   └── get-deps           # Dependency fetcher script
├── test_programs/         # User space programs
│   ├── hello.c            # Hello world ELF binary
│   └── Makefile           # Test programs build
├── rootfs/                # Root filesystem template
│   ├── bin/               # User binaries (hello)
│   ├── dev/               # Device files
│   ├── etc/               # Configuration
│   ├── home/              # User directories
│   ├── tmp/               # Temporary files
│   ├── usr/               # User programs
│   └── var/               # Variable data
├── limine/                # Bootloader binaries
├── ovmf/                  # UEFI firmware
├── GNUmakefile            # Main build system
├── limine.conf            # Bootloader configuration
├── build-rootfs.sh        # Root filesystem builder
└── rootfs.img             # Generated FAT32 image
```

## Development

### Adding New Features

**Kernel Components:**
1. Add source files to `kernel/src/`
2. Include headers in relevant files
3. Initialize in `main.c` if needed
4. Rebuild with `make`

**System Calls:**
1. Add syscall number to `syscall.h`
2. Implement handler in `syscall.c`
3. Update syscall table
4. Test from user space

**Shell Commands:**
1. Add command to `commands[]` array in `shell.c`
2. Implement handler function
3. Follow existing command patterns

**Device Drivers:**
1. Create driver source/header files
2. Implement initialization routine
3. Register interrupt handlers if needed
4. Call init from `main.c`

### Code Style
- **Language**: C99 with GNU extensions
- **Formatting**: LLVM style (use `make format`)
- **Indentation**: Spaces (auto-formatted)
- **Naming**:
  - Functions: `snake_case`
  - Types: `snake_case_t`
  - Macros: `UPPER_CASE`
  - Global constants: `UPPER_CASE`

### Debugging

**Serial Output:**
- Kernel messages output to COM1
- View in QEMU with `-serial stdio`
- Use `kprint()` for debug messages

**QEMU Monitor:**
- Access with Ctrl+Alt+2 in QEMU window
- Commands: `info registers`, `info mem`, etc.

**GDB Debugging:**
1. Build with debug symbols (default)
2. Run: `qemu-system-x86_64 -s -S ...`
3. Connect: `gdb kernel/bin/kernel`
4. In GDB: `target remote :1234`

## System Requirements

### Minimum Hardware
- x86_64 processor with long mode
- 32 MB RAM (2 GB recommended)
- VGA-compatible display
- PS/2 keyboard

### Software Dependencies
- 64-bit host system (Linux recommended)
- GCC 8+ or Clang 10+
- GNU Make 4.0+
- NASM 2.14+
- xorriso 1.5+
- mtools 4.0+
- QEMU 6.0+ (for testing)

## Technical Specifications

- **Architecture**: x86_64 (AMD64/Intel 64)
- **Boot Protocol**: Limine v9.x
- **Executable Format**: ELF64
- **Calling Convention**: System V AMD64 ABI
- **Interrupt Model**: IDT with 256 entries
- **Memory Model**: Higher-half kernel at 0xFFFFFFFF80000000
- **Page Size**: 4 KiB
- **Timer Frequency**: 100 Hz
- **Max Processes**: 256
- **File System**: FAT32 with LFN
- **System Call Interface**: INT 0x80

## Current Limitations

- No networking support
- No SMP (multicore) support
- Limited hardware driver support
- Basic FAT32 implementation (no fragmentation handling)
- No swap/paging to disk
- Limited POSIX compliance
- No dynamic linking support
- Single console only

## Roadmap

### Short Term
- [ ] Improve FAT32 driver (fragmentation, better caching)
- [ ] Add more test programs
- [ ] Implement signals (SIGTERM, SIGKILL, etc.)
- [ ] Add basic sound support

### Medium Term
- [ ] Port newlib or musl C library
- [ ] Add ext2/ext4 filesystem support
- [ ] Implement shared memory and IPC
- [ ] Add USB driver support
- [ ] Graphics mode with framebuffer

### Long Term
- [ ] TCP/IP networking stack
- [ ] SMP support
- [ ] Virtual memory swapping
- [ ] Dynamic linking and shared libraries
- [ ] Basic window manager

## Testing

The OS includes several test mechanisms:

1. **Built-in Shell Tests**: Use `test` command
2. **Process Spawning**: Use `spawn test1/test2/cpu`
3. **ELF Execution**: Run `/bin/hello`
4. **Memory Testing**: Check with `mem` command
5. **Hardware Detection**: Use `lspci` for PCI devices

## Contributing

Contributions are welcome!

## License

MIT
