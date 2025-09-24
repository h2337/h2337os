# h2337os

A 64-bit monolithic hobby OS for x86_64, hand-rolled in C with Limine boot, FAT32 storage, multitasking, and a built-in shell.

## Core Moves
- Memory: bitmap PMM, 4-level VMM split for kernel/user, and kmalloc/kfree/kcalloc/krealloc heap, demand-paging and CoW.
- Processes: 256 slots, SMP, preemptive round-robin on PIT 100 Hz, states (Ready/Running/Blocked/Terminated/Zombie), fork/exec parenting, ELF64 (ET_EXEC/ET_DYN) loader, ring0↔ring3 hops, per-process FDs, cwd, and address space.
- Storage: VFS layer, FAT32 with LFN, create/read/write/delete for files and dirs, RAM-backed root disk, multiple mount points.

## Drivers & Devices
PS/2 keyboard (full scancodes, Shift/Ctrl/Alt, Caps/Num/Scroll lock), COM1–COM4 serial debug, Flanterm VGA text console with cursor+scroll, PCI bus scan with config access, 8254 PIT timer, 8259 PIC interrupts.

## Kernel Modules
GDT, IDT, PMM, VMM, heap, scheduler, syscalls, VFS, FAT32, RAM disk, keyboard, console, serial, PIC, PIT, PCI, ELF loader, usermode bridge, shell, spinlock sync, libc shims, Limine requests.

## Build & Boot
Need x86_64 GCC cross or Clang, GNU Make, NASM, xorriso, mtools, QEMU, curl. Then:
```bash
./build-rootfs.sh
make run-uefi
```
Default QEMU: Q35, 2 GiB RAM, serial → stdio.
