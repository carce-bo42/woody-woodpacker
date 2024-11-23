section .data
woody:
    db "..WOODY..", 0x0a

section .text
global _start
_start:

    ; Syscall write
    mov rax, 1               ; syscall write
    mov rdi, 1               ; 1st arg: fd = 1
    lea rsi, [rel woody]     ; load effective address of woody string
    mov rdx, 10              ; len("..WOODY..\n")
    syscall

	mov rax, 60
	xor rdi, rdi
	syscall

	; mov r10, 0x4242424242424242   ; to be overriden
	; jmp r10
