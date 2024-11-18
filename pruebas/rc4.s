global _start

_start:
    mov r9  0x1111111111111111   ; donde acabo de cifrar
    mov r10 0x2222222222222222   ; llave derivada
    mov r11 0x3333333333333333   ; llave derivada

rc4_init:
; RC4_initialize(key, key_length):
;     for i from 0 to 255:
;         S[i] = i
;     j = 0
;     for i from 0 to 255:
;         j = (j + S[i] + key[i % key_length]) % 256
;         swap(S[i], S[j])
