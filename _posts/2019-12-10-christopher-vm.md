---
title:      "Vulnhub - Symfonos"
---

Walkthrough of Vulnhub's SP: Christopher by []()

# Nmap - Scanning the network

Scanning the network with `nmap` reveals that we have SSH and HTTP open.

```r
root@kali:~# nmap -sV -sC -A -p- -T5 192.168.0.101
Starting Nmap 7.70 ( https://nmap.org ) at 2019-12-10 07:14 EST
Nmap scan report for 192.168.0.101
Host is up (0.00075s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 14:11:d1:8b:12:0b:78:be:04:4f:74:0d:34:a5:fa:07 (RSA)
|   256 47:69:72:f9:b7:76:33:58:6f:eb:8d:1c:da:9e:b5:c6 (ECDSA)
|_  256 79:08:59:b0:df:ec:13:31:9e:d8:24:54:1d:b6:27:44 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-generator: CMS Made Simple - Copyright (C) 2004-2018. All rights reserved.
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Home - Viva La Resistance!
MAC Address: 08:00:27:DD:26:3B (Oracle VirtualBox virtual NIC)
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.9
Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE
HOP RTT     ADDRESS
1   0.75 ms 192.168.0.101

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.96 seconds
```


As of our approach, it'll be same as of the previous machines.

# HTTP Service

### Directory Traversal on HTTP Port

I'm using `uniscan` to check the different webpages and services available on the port.

```r
root@kali:~# uniscan -u 192.168.0.101 -w -q
####################################
# Uniscan project                  #
# http://uniscan.sourceforge.net/  #
####################################
V. 6.3


Scan date: 10-12-2019 7:16:42
===================================================================================================
| Domain: http://192.168.0.101/
| Server: Apache/2.4.29 (Ubuntu)
| IP: 192.168.0.101
===================================================================================================
|
| Directory check:
| [+] CODE: 200 URL: http://192.168.0.101/admin/
| [+] CODE: 200 URL: http://192.168.0.101/assets/
| [+] CODE: 200 URL: http://192.168.0.101/doc/
| [+] CODE: 200 URL: http://192.168.0.101/lib/
| [+] CODE: 200 URL: http://192.168.0.101/modules/
| [+] CODE: 200 URL: http://192.168.0.101/tmp/
| [+] CODE: 200 URL: http://192.168.0.101/uploads/
===================================================================================================
|                                                                                                   
| File check:
| [+] CODE: 200 URL: http://192.168.0.101/admin/index.php
| [+] CODE: 200 URL: http://192.168.0.101/admin/login.php
| [+] CODE: 200 URL: http://192.168.0.101/config.php
| [+] CODE: 200 URL: http://192.168.0.101/index.php
===================================================================================================
===================================================================================================
Scan end date: 10-12-2019 7:16:55



HTML report saved in: report/192.168.0.101.html
```

To our surprise, it has `/admin` and `/uploads` and other bunch of stuffs which seems of interest. Let's check them out.

### Adm