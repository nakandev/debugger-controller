CC = clang
OBJDUMP = objdump
DBG = gdb
# DBG = lldb
# CC = riscv32-unknown-elf-gcc
# OBJDUMP = riscv32-unknown-elf-objdump
# DBG = riscv32-unknown-elf-gdb

all:
	$(CC) main.c -o test.elf
	$(OBJDUMP) -d test.elf > test.elf.dis

dbg:
	$(DBG) test.elf
