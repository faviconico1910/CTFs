### Challenge Description
# It seems harmless at first glance, but could there be something hidden within? 🤔

Look at the source code, quite simple: 
```
void main()
{
    setvbuf(stdout, 0, 2, 0);
    setvbuf(stdin, 0, 2, 0);
    char buf[0x100];
    char FLAG[] = "FLAG{fake_flag}";
    printf("Enter your input: ");
    scanf("%255s", buf);
    while(1)
    {
        int i;
        printf("Enter the index of the character you want to inspect: ");
        scanf("%d", &i);
        printf("The character at index %d is '%c'.\n", i, buf[i]);
    }
}
```
![image](https://github.com/user-attachments/assets/4b25ea20-ccdf-425b-b968-89a61eee5c5d)

After a few tries, I realized that if I type in negative index, it still prints out single character, and with -2 index, I have '}', which is the end of our local flag.
This bug is called Out Of Bound.
Therefore, my plan is bruteforce every character. Here is my script:
[srcipt.py](https://github.com/faviconico1910/CTFs/blob/master/THJCC/Peekachar/solve.py)

---
# Flag: THJCC{i_ThoU9HT_i_W@S_well_HIdDen_QQ}
