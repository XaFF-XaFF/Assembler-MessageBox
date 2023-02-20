# Assembler MessageBox
An Assembly x86 code that shows Windows MessageBox kept as simple as possible.

## Compile
Executable:
```
git clone https://github.com/XaFF-XaFF/Assembler-MessageBox.git
cd Assembler-MessageBox
make
```

Shellcode:
```
git clone https://github.com/XaFF-XaFF/Assembler-MessageBox.git
cd Assembler-MessageBox
nasm shellcode -o shell.bin
```
Copy bytes (for example with: HxD) and paste them into your shellcode injector.

## Requirements:
I recommend compiling to executable on Linux because Windows' linker does not work correctly
- NASM
- Linker
