# file: Makefile
ARCH ?= x86
CFLAGS := -O2 -g -Wall -target bpf -D__TARGET_ARCH_$(ARCH) -I.
KERN_OBJ := xflow_kern.o

all: $(KERN_OBJ)

$(KERN_OBJ): xflow_kern.c vmlinux.h
	clang $(CFLAGS) -c $< -o $@

clean:
	rm -f $(KERN_OBJ)