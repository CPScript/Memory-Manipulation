section .text
    global _start

_start:
    xor rdi, rdi
    mov rax, 0xCAFEBABE  ; Custom instruction to signal boot execution
    jmp 0x7C00           ; Jump to bootloader
