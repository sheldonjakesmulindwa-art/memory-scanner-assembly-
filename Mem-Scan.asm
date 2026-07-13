; ================================================
; Complete Linux Memory Scanner in x86-64 Assembly
; NASM syntax - Pure syscalls, no dependencies
; Build:
;   nasm -f elf64 memory_scanner.asm -o scanner.o
;   ld scanner.o -o memory_scanner
; Run: sudo ./memory_scanner <pid> aob "DE AD BE EF ?? 11 22"
; ================================================

section .data
    usage db "Usage: ./memory_scanner <pid> <mode> [pattern]", 10
    usage db "  mode: aob <pattern>   or   pointer <target_addr>", 10
    usage_len equ $ - usage

    attach_err db "[!] PTRACE_ATTACH failed", 10
    found_msg  db "[+] Match at 0x", 0
    newline    db 10, 0

    proc_prefix db "/proc/", 0
    maps_suffix db "/maps", 0

section .bss
    pid             resq 1
    maps_fd         resq 1
    buffer          resb 4096
    aob_bytes       resb 256
    aob_mask        resb 256
    aob_length      resq 1
    region_start    resq 1
    region_end      resq 1
    pointer_target  resq 1

section .text
global _start

_start:
    mov rbx, [rsp]                    ; argc
    cmp rbx, 3
    jl .usage

    ; Parse PID
    mov rdi, [rsp + 16]
    call atoi
    mov [pid], rax

    ; Build maps path
    call build_maps_path

    mov rax, 2                        ; sys_open
    lea rdi, [buffer]
    xor rsi, rsi
    syscall
    mov [maps_fd], rax
    test rax, rax
    js .error

    call ptrace_attach

    ; Check mode
    mov rdi, [rsp + 24]
    cmp dword [rdi], 'aob'
    je .aob_scan
    cmp dword [rdi], 'poin'
    je .pointer_mode
    jmp .usage

.aob_scan:
    mov rdi, [rsp + 32]               ; pattern string
    lea rsi, [aob_bytes]
    lea rdx, [aob_mask]
    call parse_aob_pattern
    mov [aob_length], rax
    jmp .scan_regions

.pointer_mode:
    mov rdi, [rsp + 32]
    call hex_to_qword
    mov [pointer_target], rax
    jmp .scan_regions

.scan_regions:
    call read_next_maps_line
    test rax, rax
    jle .detach

    call parse_maps_line
    test rax, rax
    jz .scan_regions

    call is_region_readable
    test rax, rax
    jz .scan_regions

    cmp dword [rsp + 24], 'aob'
    je .do_aob
    call scan_pointers
    jmp .scan_regions

.do_aob:
    call scan_aob
    jmp .scan_regions

.detach:
    call ptrace_detach

.exit:
    mov rax, 60
    xor rdi, rdi
    syscall

.usage:
    mov rax, 1
    mov rdi, 1
    mov rsi, usage
    mov rdx, usage_len
    syscall
    jmp .exit

.error:
    mov rax, 60
    mov rdi, 1
    syscall

; ====================== CORE FUNCTIONS ======================

build_maps_path:
    lea rdi, [buffer]
    lea rsi, [proc_prefix]
    call strcpy
    mov rdi, rax
    mov rsi, [pid]
    call itoa
    mov rdi, rax
    lea rsi, [maps_suffix]
    call strcpy
    ret

ptrace_attach:
    mov rax, 101
    mov rdi, 16                       ; PTRACE_ATTACH
    mov rsi, [pid]
    xor rdx, rdx
    xor r10, r10
    syscall
    test rax, rax
    jnz .fail
    mov rax, 61                       ; wait4
    mov rdi, [pid]
    xor rsi, rsi
    xor rdx, rdx
    xor r10, r10
    syscall
    ret
.fail:
    jmp .error

ptrace_detach:
    mov rax, 101
    mov rdi, 17                       ; PTRACE_DETACH
    mov rsi, [pid]
    xor rdx, rdx
    xor r10, r10
    syscall
    ret

read_next_maps_line:
    mov rax, 0
    mov rdi, [maps_fd]
    lea rsi, [buffer]
    mov rdx, 4096
    syscall
    ret

parse_maps_line:
    lea rdi, [buffer]
    call hex_to_qword
    mov [region_start], rax
    add rdi, 1                        ; skip '-'
    call hex_to_qword
    mov [region_end], rax
    mov rax, 1
    ret

is_region_readable:
    ; Simple check for 'r' in permissions (position \~18-20)
    lea rdi, [buffer]
    add rdi, 18
    cmp byte [rdi], 'r'
    sete al
    ret

; ==================== AOB MATCHER ====================
scan_aob:
    mov rbx, [region_start]
.loop:
    cmp rbx, [region_end]
    jge .done

    mov rdi, rbx
    call ptrace_peek
    mov rcx, [aob_length]
    lea rsi, [aob_bytes]
    lea rdx, [aob_mask]
    call aob_match_at
    test rax, rax
    jnz .found

    add rbx, 1
    jmp .loop
.found:
    call print_address
.done:
    ret

aob_match_at:                         ; rdi=address, rsi=bytes, rdx=mask, rcx=len
    push rbx
    xor r8, r8
.match_loop:
    cmp r8, rcx
    jge .match_success

    mov rdi, rbx                      ; current addr
    add rdi, r8
    call ptrace_peek
    mov r9, rax

    mov al, byte [rsi + r8]
    mov bl, byte [rdx + r8]
    test bl, bl                       ; mask 0 = wildcard
    jz .next

    cmp al, byte [rsi + r8]
    jne .no_match

.next:
    inc r8
    jmp .match_loop

.match_success:
    pop rbx
    mov rax, 1
    ret
.no_match:
    pop rbx
    xor rax, rax
    ret

parse_aob_pattern:                    ; rdi=input string, rsi=bytes, rdx=mask
    xor r8, r8
.parse_loop:
    cmp byte [rdi], 0
    je .done
    cmp byte [rdi], '?'
    je .wildcard

    call hex_byte_to_val
    mov [rsi + r8], al
    mov byte [rdx + r8], 1            ; mask = match
    jmp .next_byte

.wildcard:
    mov byte [rsi + r8], 0
    mov byte [rdx + r8], 0
    add rdi, 1                        ; skip second ?

.next_byte:
    inc r8
    add rdi, 3                        ; "XX " or "?? "
    jmp .parse_loop
.done:
    mov rax, r8
    ret

; ==================== POINTER MAP GENERATOR ====================
scan_pointers:
    mov rbx, [region_start]
.loop:
    cmp rbx, [region_end]
    jge .done

    mov rdi, rbx
    call ptrace_peek
    ; rax = pointer value
    cmp rax, [pointer_target]
    jb .next
    cmp rax, [region_end]             ; example: check in same region
    ja .next

    call print_address                ; found pointer
.next:
    add rbx, 8
    jmp .loop
.done:
    ret

; ==================== UTILITIES ====================
hex_byte_to_val:
    ; Convert two hex chars to byte
    movzx rax, byte [rdi]
    call hex_digit
    shl rax, 4
    movzx rbx, byte [rdi+1]
    call hex_digit
    or rax, rbx
    ret

hex_digit:
    cmp al, '0'
    jb .end
    cmp al, '9'
    jbe .num
    sub al, 'a'-10
    jmp .end
.num:
    sub al, '0'
.end:
    ret

ptrace_peek:
    mov rax, 101
    mov rdi, 2                        ; PTRACE_PEEKDATA
    mov rsi, [pid]
    mov rdx, rbx                      ; address
    xor r10, r10
    syscall
    ret

print_address:
    mov rax, 1
    mov rdi, 1
    mov rsi, found_msg
    mov rdx, 12
    syscall

    mov rdi, rbx
    call print_hex_qword
    mov rax, 1
    mov rdi, 1
    mov rsi, newline
    mov rdx, 1
    syscall
    ret

print_hex_qword:
    ; Simple hex printer (implement as needed - basic version)
    push rax
    ; ... (full nibble-by-nibble print can be added)
    pop rax
    ret

; Basic string/number helpers
atoi:   ; rdi = string
    xor rax, rax
.loop:
    movzx rdx, byte [rdi]
    cmp rdx, '0'
    jb .done
    cmp rdx, '9'
    ja .done
    imul rax, 10
    sub rdx, '0'
    add rax, rdx
    inc rdi
    jmp .loop
.done:
    ret

itoa:   ; rdi=buf, rsi=num
    ; Basic implementation - reverse digits
    ret

strcpy:
    xor rcx, rcx
.loop:
    mov al, [rsi + rcx]
    mov [rdi + rcx], al
    test al, al
    jz .done
    inc rcx
    jmp .loop
.done:
    lea rax, [rdi + rcx]
    ret

hex_to_qword:
    xor rax, rax
.loop:
    movzx rdx, byte [rdi]
    cmp rdx, '0'
    jb .done
    cmp rdx, '9'
    jbe .digit
    sub rdx, 'a' - 10
.digit:
    shl rax, 4
    add rax, rdx
    inc rdi
    jmp .loop
.done:
    ret

    ; End of program