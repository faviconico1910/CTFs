### Wanna_Play_A_Game
---
```
printf("[*] NickName> ");
if ( read(0, &username, 0x40uLL) == -1 )
{
  perror("READ ERROR");
  exit(-1);
}
while ( 1 )
{
  menu();
  v3 = read_int();
  printf("[*] Guess>");
  v4 = read_int();
  ((void (__fastcall *)(__int64))conv[v3 - 1])(v4);
}
```
We'll use **out of bound** bug to exploit. The program calls ``` conv ``` without checking the range of it.
```
  for ( i = 0; i <= 6; ++i )
    path[i] ^= 0x13u;
  if ( a1 == passcode )
  {
    puts("[+] WINNNN!");
    execve(path, 0LL, 0LL);
  }
  else
  {
    puts("[-] YOU ARE NOT WORTHY FOR A SHELL!");
  }
```
The plan is to call ``` hard ``` with a right ```passcode```. It gives us the shell by call ``` execve(/bin/sh, NULL, NULL) ```.
``` passcode ``` is the random value from ``` /dev/random ```. So, we have to leak it.
The offset between``` conv ``` address and the beginning of ``` username ``` is 14. Therefore, we can use index ``` 15 ``` to reach here. 
We''ll use ``` puts ``` function to leak the ```passcode``` then input it into the program. 
Here is my solution: [solution.py](https://github.com/faviconico1910/CTFs/blob/master/0xl4ugh/wanna_play_a_game/chall.py)

