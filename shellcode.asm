[BITS 32]
section .text
  global _start              

_start:
    push ebp
    mov ebp, esp

    sub esp, 0x1c               ; allocate local variables and initialize them to 0
    xor eax, eax
    mov [ebp - 0x04], eax
    mov [ebp - 0x08], eax
    mov [ebp - 0x1c], eax
    mov [ebp - 0x14], eax
    mov [ebp - 0x38], eax

    push 0x41797261            
    push 0x7262694c             
    push 0x64616f4c
    mov [ebp - 0x14], esp       ; ebp - 0x14 = LoadLibraryA

    push eax                    ; Move stack

    mov eax, [fs:0x30]          ; offset to the PEB struct
    mov eax, [eax + 0x0c]       ; offset to LDR within PEB
    mov eax, [eax + 0x14]       ; offset to InMemoryOrderModuleList
    mov eax, [eax]              ; address loaded in eax (1st module)
    mov eax, [eax]              ; ntdll.dll address loaded (2nd module)
    mov eax, [eax + 0x10]       ; kernel32.dll address loaded (3rd module)
                                ; empty - 8 -> shell.exe - 8 -> ntdll.exe
                                ; ntdll.dll - 8 -> kernel32.dll + 0x18 = DllBase
                                ; -0x08 + 0x18 = 0x10

    mov ebx, eax                ; Keep kernel address
    mov [ebp - 0x70], ebx
    mov eax, [eax + 0x3c]       ; DllBase -> IMAGE_DOS_HEADER.e_lfanew
    add eax, ebx                ; Kernel32.dll base address + e_lfanew = PE structure address

    mov eax, [eax + 0x78]       ; 0x78 bytes after kernel32.dll there is export table
                                ; 0x160 (Export Dir RVA) - 0xE8 (NtHeader offset) = 0x78
    add eax, ebx                ; Address of export table

    mov ecx, [eax + 0x14]       ; Get number of exported functions
    mov [ebp - 0x04], ecx       ; Store number of exported functions in ebp - 0x04

    mov ecx, [eax + 0x1c]       ; RVA address table
                                ; 0x80D3C (Function RVA) - 0x80D20 (IMAGE_EXPORT_DIRCTORY) = 0x1c
    add ecx, ebx                ; RVA address table + kernel base address = export address table
    mov [ebp - 0x08], ecx       ; Store RVA address table in ebp - 0x08

    mov ecx, [eax + 0x20]       ; RVA Name pointer table
    add ecx, ebx                ; RVA Name pointer table address
    mov [ebp - 0x0c], ecx       ; Store RVA NPT in ebp - 0x0c

    mov ecx, [eax + 0x24]       ; RVA ordinal table 
    add ecx, ebx                ; Get RVA ordinal table address
    mov [ebp - 0x10], ecx       ; Store RVA OT in edp - 0x10

    xor eax, eax
    xor ecx, ecx

    FindLoadLibraryA:
        mov esi, [ebp - 0x14]     ; Get LoadLibraryA
        mov edi, [ebp - 0x0c]     ; Get RVA ordinary table address
        cld                       ; Process string from lowest to highest (auto-incrementing mode)
        mov edi, [edi + eax * 4]
        add edi, ebx

        mov cx, 12                ; Tell next-comparer to compare 12 bytes
        repe cmpsb                ; (repe) Keep repeating (cmpsb) compare bytes edi with esi
        jz FoundLoadLibraryA

        inc eax                   ; Increment eax (eax = 2 * 4 = 8) all of functions increases by 4
        cmp eax, [ebp - 0x04]     ; Check if we looped through all exported functions
        jne FindLoadLibraryA

    FoundLoadLibraryA:
        mov ecx, [ebp - 0x10]     ; Ordinal table
        mov edx, [ebp - 0x08]     ; Export address table

        mov ax, [ecx + eax * 2]   ; Ordinal = address + location * size(2)
        mov eax, [edx + eax * 4]  ; Get RVA of LoadLibraryA laddress + location * size(4)
        add eax, ebx
        mov [ebp - 0x34], eax     ; LoadLibraryA address
        jmp InvokeLoadLibraryA
    
    InvokeLoadLibraryA:
        xor edx, edx
        push edx

        push 0x00003233           ; 32
        push 0x72657375           ; user
        mov ecx, esp              ; Pointer to string user32

        push ecx                  ; LoadLibraryA(ecx)
        call eax

        mov [ebp - 0x38], eax     ; User32.dll base address

        push 0x00726464           ; ddr
        push 0x41636f72           ; rocA
        push 0x50746547           ; GetP
        mov [ebp - 0x20], esp     ; ebp - 0x14 = GetProcAddr

        xor eax, eax
        xor ecx, ecx
        jmp FindProc

    FindProc:
        mov esi, [ebp - 0x20]     ; Get GetProcAddress
        mov edi, [ebp - 0x0c]     ; Get RVA ordinary table address
        cld                       ; Process string from lowest to highest (auto-incrementing mode)
        mov edi, [edi + eax * 4]
        add edi, ebx

        mov cx, 8                 ; Tell next-comparer to compare 8 bytes
        repe cmpsb                ; (repe) Keep repeating (cmpsb) compare bytes edi with esi
        jz FoundProc

        inc eax                   ; Increment eax (eax = 2 * 4 = 8) all of functions increases by 4
        cmp eax, [ebp - 0x04]     ; Check if we looped through all exported functions
        jne FindProc

    FoundProc:
        mov ecx, [ebp - 0x10]     ; Ordinal table
        mov edx, [ebp - 0x08]     ; Export address table

        mov ax, [ecx + eax * 2]   ; Ordinal = address + location * size(2)
        mov eax, [edx + eax * 4]  ; Get RVA of GetProcAddress laddress + location * size(4)
        add eax, ebx              ; Get GetProcAddress address
                                  ; Add storage for GetProcAddress address
        jmp InvokeGetProc
    
    InvokeGetProc:
        push 0x0041786f           ; oxA
        push 0x42656761           ; AgeB
        push 0x7373654d           ; Mess
        mov ecx, esp              ; ecx = esp = (MessageBoxA)

        xor edx, edx
        push edx

        mov edx, [ebp - 0x38]    ; User32.dll base address
        push ecx                 ; MessageBoxA
        push edx
        call eax                 ; Call GetProcAddress, eax is overwritten with target function address

        xor edx, edx
        xor edi, edi

        push 0x21646C72          ; rld!
        push 0x6f57206f          ; o Wo
        push 0x6c6c6548          ; Hell
        mov edi, esp

        push edx                 ; HWND set to null
        push edi                 ; lpText set to Hello World!
        push edi                 ; lpCaption set to Hello World!
        push edx                 ; uType set to null
        call eax                 ; Call MessageBoxA