
global _start

#https://math.hws.edu/eck/cs220/f22/registers.html
#https://stackoverflow.com/questions/2030366/what-do-the-brackets-mean-in-nasm-syntax-for-x86-asm
_start:

    mov rax, 1               ; syscall write
    mov rdi, 1               ; 1st arg: fd = 1
    lea rsi, [rel _data]     ; load effective address of woody string
    mov rdx, 10              ; len("..WOODY..\n")
    syscall

    lea rcx, [rel _start];      ; load address of the shellcode
    mov rbx, [rel _data + 4*8]  ; vaddr of the shellcode
    sub rcx, rbx                ; offset incorporado por el loader (VLA)

    ; add the offset to the start of the encrypted .text section
    mov rbx, [rel _dat + 2*8]
    add rbx, rcx

; First decryption byte is [rbx].
_decryption_prepare:

    ; keep rbx with the value pointing towards the start
    mov rsi, rbx

    ; use rdx as the end of iteration
    mov r8, rsi
    add r8, [rel _data + 3*8]

    ; load key. We use an address here
    lea rcx, [rel _data + 4*8]
    mov rax, rcx ; save initial value to know when we need to loop the key again


_loop_step:
    cmp rsi, rdx
    je ._done

_decrypt_loop:
    xor byte [rsi], [rcx]

_data:
	db "....WOODY....", 0x0a    ; 15 bytes
    db 0x0                      ; 1 byte for alignent
    dq 0x1111111111111111       ; cipertext start address  => 2*8
    dq 0x2222222222222222       ; cipertext size           => 3*8
    dq 0x3333333333333333       ; vaddr of the shellcode   => 4*8
    times 32 db 0x44            ; key

; https://stackoverflow.com/questions/41912684/what-is-the-purpose-of-the-rbp-register-in-x86-64-assembler
; RBP es el registro que se utiliza en las funciones para que suceda que el stack se "acumule" en las llamadas
; embebidas entre funciones y se "deshaga" a medida que las funciones retornan.
