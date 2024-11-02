section .text
global _start

_start:
    ; Allocate space for the string on the stack
    sub rsp, 8              ; Allocate 16 bytes on the stack
    mov rdi, rsp             ; rdi now points to the allocated space

    ; Store the string "WOODY" in memory (including null terminator)
    mov byte [rdi + 0], 'W'  ; 0: 'H'
    mov byte [rdi + 1], 'O'  ; 1: 'e'
    mov byte [rdi + 2], 'O'  ; 2: 'l'
    mov byte [rdi + 3], 'D'  ; 3: 'l'
    mov byte [rdi + 4], 'Y'  ; 4: 'o'
    mov byte [rdi + 5], 0x0a  ; 5: ','

    ; Now rsi can point to the string
    mov rsi, rdi             ; Load the address of the string into rsi

    ; Write the string to stdout
    mov rax, 1               ; syscall: write
    mov rdi, 1               ; file descriptor: stdout
    mov rdx, 6              ; length of the string (including the null terminator)
    syscall                  ; Invoke syscall to write

	mov rax, 60
	xor rdi, rdi
	syscall
