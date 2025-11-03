
global _start
_start:

    mov rax, 1               ; syscall write
    mov rdi, 1               ; 1st arg: fd = 1
    lea rsi, [rel _data]     ; load effective address of woody string
    mov rdx, 10              ; len("..WOODY..\n")
    syscall

    ; Tip: podemos usar el stack pero tendremos que devolverlo a donde estaba
    ; al acabar: ese valor es importantísimo porque apunta a argc !
    push rsp
    mov rbp, rsp

    mov rdi, [rel _data + 2*8] ; ciphertext start address
    mov rsi, [rel _data + 3*8] ; length of ciphertext
    mov rax, [rel _data + 4*8] ; key

    mov rsp, rbp
    pop rbp

_loop_qword:
    test    rsi, rsi          ; if rsi == 0 -> finished
    jz      .end_qword

    xor     qword [rdi], rax  ; XOR 8 bytes at [rdi] with rax
    add     rdi, 8            ; advance pointer by 8
    add     rax, 8
    dec     rsi               ; rsi--
    jmp     _loop_qword

.end_qword:
    ; aquí rsi == 0


_data:
	db "....WOODY....", 0x0a    ; 15 bytes
    db 0x0                      ; 1 byte for alignent
    dq 0x1111111111111111       ; cipertext start address
    dq 0x2222222222222222       ; cipertext size
    times 32 db 0x33            ; key

; https://stackoverflow.com/questions/41912684/what-is-the-purpose-of-the-rbp-register-in-x86-64-assembler
; RBP es el registro que se utiliza en las funciones para que suceda que el stack se "acumule" en las llamadas
; embebidas entre funciones y se "deshaga" a medida que las funciones retornan.
