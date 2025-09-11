CC = gcc
LD = ld
CFLAGS = -ffreestanding -nostdlib -fno-pie -no-pie -m64 -mcmodel=small
LDFLAGS = -nostdlib -static -no-pie

all: hello

hello: hello.o
	$(LD) $(LDFLAGS) -o hello hello.o -Ttext=0x400000

hello.o: hello.c
	$(CC) $(CFLAGS) -c hello.c -o hello.o

install: hello
	cp hello ../rootfs/bin/

clean:
	rm -f *.o hello

.PHONY: all install clean