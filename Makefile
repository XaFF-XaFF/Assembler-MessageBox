all: compile link clean

compile:
	mkdir -p bin
	nasm -f win32 -o bin/shellcode.obj shellcode.asm

link:
	ld -m i386pe -o bin/shellcode.exe bin/shellcode.obj

clean:
	rm bin/shellcode.obj