
global _start

#https://math.hws.edu/eck/cs220/f22/registers.html
#https://stackoverflow.com/questions/2030366/what-do-the-brackets-mean-in-nasm-syntax-for-x86-asm
_start:

    mov rax, 1               ; syscall write
    mov rdi, 1               ; 1st arg: fd = 1
    lea rsi, [rel woody_str] ; load effective address of woody string
    mov rdx, woody_strlen    ; len("..WOODY..\n")
    syscall

    lea rcx, [rel _start];         ; load address of the shellcode
    mov r8, [rel shellcode_vaddr]  ; vaddr of the shellcode
    sub rcx, r8                    ; offset incorporado por el loader (VLA)

    ; add the offset to the start of the encrypted .text section
    mov r8, [rel ciphertext_start]
    add r8, rcx

; First decryption byte is [r8].
_decryption_prepare:
    ; keep r8 with the value pointing towards the start
    mov rsi, r8

    ; use rdx as the end of iteration
    mov rdx, rsi
    add rdx, [rel ciphertext_size]

    ; load key. We use an address here
    lea rcx, [rel key]

    ; set rax = 0, we will use this as the counter
    xor rax, rax

; r8 : next entrypoint
; rdx : end address of ciphertext
; rsi : pointer to the next byte to be decrypted
; rcx : pointer to the start of the key
; rax : counter to keep track of current byte in key
; rdi : used to compute key+i for the xor operation

_loop_step:
    ; if rsi == rdx => decryption done
    cmp rsi, rdx
    je _done
    ; rax = rax mod 32 y evitamos una branch
    and rax, 11111b

_decrypt_loop:
    ; rdi = rcx + rax  (key + i)
    lea rdi, [rcx + rax]
    ; en x86 no se puede hacer xor byte [r1], [r2]
    mov r9b, [rdi]
    xor byte [rsi], r9b ; *rsi ^= key[index]
    inc rax
    inc rsi
    jmp _loop_step

_done:
    ; give control to initial entrypoint (start of unencrypted .text section)
    jmp r8

woody_str: db "....WOODY....", 0x0a
woody_strlen: equ $ - woody_str
ciphertext_start: dq 0x1111111111111111  ; cipertext start vaddr
ciphertext_size:  dq 0x2222222222222222  ; cipertext size
shellcode_vaddr:  dq 0x3333333333333333  ; vaddr of the shellcode
key: times 32 db 0x44                    ; key

; https://stackoverflow.com/questions/41912684/what-is-the-purpose-of-the-rbp-register-in-x86-64-assembler
; RBP es el registro que se utiliza en las funciones para que suceda que el stack se "acumule" en las llamadas
; embebidas entre funciones y se "deshaga" a medida que las funciones retornan.
