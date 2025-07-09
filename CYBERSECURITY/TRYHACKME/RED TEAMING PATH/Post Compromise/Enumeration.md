# Introduction
---

This room focuses on post-exploitation enumeration. In other words, we assume that we have successfully gained some form of access to a system. Moreover, we may have carried out privilege escalation; in other words, we might have administrator or root privileges on the target system. Some of the techniques and tools discussed in this room would still provide helpful output even with an unprivileged account, i.e., not root or administrator.

If you are interested in privilege escalation, you can check the [Windows Privilege Escalation](https://tryhackme.com/room/windowsprivesc20) room and the [Linux PrivEsc](https://tryhackme.com/room/linprivesc) room. Moreover, there are two handy scripts, [WinPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS) and [LinPEAS](https://grimbins.github.io/grimbins/linpeas/) for MS Windows and Linux privilege escalation respectively.

Our purpose is to collect more information that will aid us in gaining more access to the target network. For example, we might find the login credentials to grant access to another system. We focus on tools commonly available on standard systems to collect more information about the target. Being part of the system, such tools look innocuous and cause the least amount of "noise".

We assume you have access to a command-line interface on the target, such as`bash` on a Linux system or`cmd.exe` on an MS Windows system. Starting with one type of shell on a Linux system, it is usually easy to switch to another one. Similarly, starting from`cmd.exe`, you can switch to PowerShell if available. We just issued the command`powershell.exe` to start the PowerShell interactive command line in the terminal below.

```shell-session
user@TryHackMe$ Microsoft Windows [Version 10.0.17763.2928]
(c) 2018 Microsoft Corporation. All rights reserved.

strategos@RED-WIN-ENUM C:\Users\strategos>powershell.exe
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Users\strategos>
```

This room is organized as follows:

- Purpose of enumeration
- Linux enumeration with commonly-installed tools: System, users, networking, and running services
- MS Windows enumeration with built-in tools: System, users, networking, and running services
- Examples of additional tools: Seatbelt

Although it is not strictly necessary, we advise completing [The Lay of the Land](https://tryhackme.com/room/thelayoftheland) room before going through this one.

# Purpose
---

![Pasted image 20250514143101.png](../../../IMAGES/Pasted%20image%2020250514143101.png)

When you gain a shell on the target system, you usually have very basic knowledge of the system. If it is a server, you already know which service you have exploited; however, you don't necessarily know other details, such as usernames or network shares. Consequently, the shell will look like a dark room where you have an incomplete and vague knowledge of what's around you. In this sense, enumeration helps you build a more complete and accurate picture.

The purpose behind post-exploitation enumeration is to gather as much information about the system and its network. The exploited system might be a company desktop/laptop or a server. We aim to collect the information that would allow us to pivot to other systems on the network or to loot the current system. Some of the information we are interested in gathering include:

- Users and groups
- Hostnames
- Routing tables
- Network shares
- Network services
- Applications and banners
- Firewall configurations
- Service settings and audit configurations
- SNMP and DNS details
- Hunting for credentials (saved on web browsers or client applications)

There is no way to list everything we might stumble upon. For instance, we might find SSH keys that might grant us access to other systems. In SSH key-based authentication, we generate an SSH key pair (public and private keys); the public key is installed on a server. Consequently, the server would trust any system that can prove knowledge of the related private key.

Furthermore, we might stumble upon sensitive data saved among the user's documents or desktop directories. Think that someone might keep a`passwords.txt` or`passwords.xlsx` instead of a proper password manager. Source code might also contain keys and passwords left lurking around, especially if the source code is not intended to be made public.

# Linux Enumeration
---

![Illustration indicating enumeration types](https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/bccf63d717b423189ffff7ec926c408e.png)

This task focuses on enumerating a Linux machine after accessing a shell, such as`bash`. Although some commands provide information on more than one area, we tried to group the commands into four categories depending on the information we expect to acquire.

- System
- Users
- Networking
- Running Services

We recommend that you click "**Start AttackBox**" and "**Start Machine**" so that you can experiment and answer the questions at the end of this task.

### System

On a Linux system, we can get more information about the Linux distribution and release version by searching for files or links that end with`-release` in`/etc/`. Running`ls /etc/*-release` helps us find such files. Let's see what things look like on a CentOS Linux.

```shell-session
user@TryHackMe$ ls /etc/*-release
/etc/centos-release /etc/os-release /etc/redhat-release /etc/system-release
$ cat /etc/os-release 
NAME="CentOS Linux"
VERSION="7 (Core)"
[...]
```

Let's try on a Fedora system.

```shell-session
user@TryHackMe$ ls /etc/*-release
/etc/fedora-release@ /etc/os-release@ /etc/redhat-release@ /etc/system-release@
$ cat /etc/os-release
NAME="Fedora Linux"
VERSION="36 (Workstation Edition)"
[...]
```

We can find the system's name using the command`hostname`.

```shell-session
user@TryHackMe$ hostname
rpm-red-enum.thm
```

Various files on a system can provide plenty of useful information. In particular, consider the following`/etc/passwd`,`/etc/group`, and`/etc/shadow`. Any user can read the files`passwd` and`group`. However, the`shadow` password file requires root privileges as it contains the hashed passwords. If you manage to break the hashes, you will know the user's original password.

```shell-session
user@TryHackMe$ cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
[...]
michael:x:1001:1001::/home/michael:/bin/bash
peter:x:1002:1002::/home/peter:/bin/bash
jane:x:1003:1003::/home/jane:/bin/bash
randa:x:1004:1004::/home/randa:/bin/bash

$ cat /etc/group
root:x:0:
[...]
michael:x:1001:
peter:x:1002:
jane:x:1003:
randa:x:1004:

$ sudo cat /etc/shadow
root:$6$pZlRFi09$qqgNBS.00qtcUF9x0yHetjJbXsw0PAwQabpCilmAB47ye3OzmmJVfV6DxBYyUoWBHtTXPU0kQEVUQfPtZPO3C.:19131:0:99999:7:::
[...]
michael:$6$GADCGz6m$g.ROJGcSX/910DEipiPjU6clo6Z6/uBZ9Fvg3IaqsVnMA.UZtebTgGHpRU4NZFXTffjKPvOAgPKbtb2nQrVU70:19130:0:99999:7:::
peter:$6$RN4fdNxf$wvgzdlrIVYBJjKe3s2eqlIQhvMrtwAWBsjuxL5xMVaIw4nL9pCshJlrMu2iyj/NAryBmItFbhYAVznqRcFWIz1:19130:0:99999:7:::
jane:$6$Ees6f7QM$TL8D8yFXVXtIOY9sKjMqJ7BoHK1EHEeqM5dojTaqO52V6CPiGq2W6XjljOGx/08rSo4QXsBtLUC3PmewpeZ/Q0:19130:0:99999:7:::
randa:$6$dYsVoPyy$WR43vaETwoWooZvR03AZGPPKxjrGQ4jTb0uAHDy2GqGEOZyXvrQNH10tGlLIHac7EZGV8hSIfuXP0SnwVmnZn0:19130:0:99999:7:::
```

Similarly, various directories can reveal information about users and might contain sensitive files; one is the mail directories found at`/var/mail/`.
```shell-session
user@TryHackMe$ ls -lh /var/mail/
total 4.0K
-rw-rw----. 1 jane mail 0 May 18 14:15 jane
-rw-rw----. 1 michael mail 0 May 18 14:13 michael
-rw-rw----. 1 peter mail 0 May 18 14:14 peter
-rw-rw----. 1 randa mail 0 May 18 14:15 randa
-rw-------. 1 root mail 639 May 19 07:37 root
```

To find the installed applications you can consider listing the files in`/usr/bin/` and`/sbin/`:

- `ls -lh /usr/bin/`
- `ls -lh /sbin/`

On an RPM-based Linux system, you can get a list of all installed packages using`rpm -qa`. The`-qa` indicates that we want to _query all_ packages.

On a Debian-based Linux system, you can get the list of installed packages using`dpkg -l`. The output below is obtained from an Ubuntu server.

```shell-session
user@TryHackMe$ dpkg -l
Desired=Unknown/Install/Remove/Purge/Hold
| Status=Not/Inst/Conf-files/Unpacked/halF-conf/Half-inst/trig-aWait/Trig-pend
|/ Err?=(none)/Reinst-required (Status,Err: uppercase=bad)
||/ Name Version Architecture Description
+++-=====================================-==================================-============-===============================================================================
ii accountsservice 0.6.55-0ubuntu12~20.04.5 amd64 query and manipulate user account information
ii adduser 3.118ubuntu2 all add and remove users and groups
ii alsa-topology-conf 1.2.2-1 all ALSA topology configuration files
ii alsa-ucm-conf 1.2.2-1ubuntu0.13 all ALSA Use Case Manager configuration files
ii amd64-microcode 3.20191218.1ubuntu1 amd64 Processor microcode firmware for AMD CPUs
[... ]
ii zlib1g-dev:amd64 1:1.2.11.dfsg-2ubuntu1.3 amd64 compression library - development
```

### Users

Files such as`/etc/passwd` reveal the usernames; however, various commands can provide more information and insights about other users on the system and their whereabouts.

You can show who is logged in using`who`.

```shell-session
user@TryHackMe$ who
root tty1 2022-05-18 13:24
jane pts/0 2022-05-19 07:17 (10.20.30.105)
peter pts/1 2022-05-19 07:13 (10.20.30.113)
```

We can see that the user`root` is logged in to the system directly, while the users`jane` and`peter` are connected over the network, and we can see their IP addresses.

Note that`who` should not be confused with`whoami` which prints **your** effective user id.

```shell-session
user@TryHackMe$ whoami
jane
```

To take things to the next level, you can use`w`, which shows who is logged in and what they are doing. Based on the terminal output below,`peter` is editing`notes.txt` and`jane` is the one running`w` in this example.

```shell-session
user@TryHackMe$ w
 07:18:43 up 18:05, 3 users, load average: 0.00, 0.01, 0.05
USER TTY FROM LOGIN@ IDLE JCPU PCPU WHAT
root tty1 Wed13 17:52m 0.00s 0.00s less -s
jane pts/0 10.20.30.105 07:17 3.00s 0.01s 0.00s w
peter pts/1 10.20.30.113 07:13 5:23 0.00s 0.00s vi notes.txt
```

To print the real and effective user and group IDS, you can issue the command`id` (for ID).

```shell-session
user@TryHackMe$ id
uid=1003(jane) gid=1003(jane) groups=1003(jane) context=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```

Do you want to know who has been using the system recently?`last` displays a listing of the last logged-in users; moreover, we can see who logged out and how much they stayed connected. In the output below, the user`randa` remained logged in for almost 17 hours, while the user`michael` logged out after four minutes.


```shell-session
user@TryHackMe$ last
jane pts/0 10.20.30.105 Thu May 19 07:17 still logged in 
peter pts/1 10.20.30.113 Thu May 19 07:13 still logged in 
michael pts/0 10.20.30.1 Thu May 19 05:12 - 05:17 (00:04) 
randa pts/1 10.20.30.107 Wed May 18 14:18 - 07:08 (16:49) 
root tty1 Wed May 18 13:24 still logged in
[...]
```

Finally, it is worth mentioning that`sudo -l` lists the allowed command for the invoking user on the current system.

### Networking

The IP addresses can be shown using`ip address show` (which can be shortened to`ip a s`) or with the older command`ifconfig -a` (its package is no longer maintained.) The terminal output below shows the network interface`ens33` with the IP address`10.20.30.129` and subnet mask`255.255.255.0` as it is`24`.

```shell-session
user@TryHackMe$ ip a s
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
 link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
 inet 127.0.0.1/8 scope host lo
 valid_lft forever preferred_lft forever
 inet6 ::1/128 scope host 
 valid_lft forever preferred_lft forever
2: ens33: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
 link/ether 00:0c:29:a2:0e:7e brd ff:ff:ff:ff:ff:ff
 inet 10.20.30.129/24 brd 10.20.30.255 scope global noprefixroute dynamic ens33
 valid_lft 1580sec preferred_lft 1580sec
 inet6 fe80::761a:b360:78:26cd/64 scope link noprefixroute 
 valid_lft forever preferred_lft forever
```

The DNS servers can be found in the`/etc/resolv.conf`. Consider the following terminal output for a system that uses DHCP for its network configurations. The DNS, i.e. nameserver, is set to`10.20.30.2`.

```shell-session
user@TryHackMe$ cat /etc/resolv.conf
# Generated by NetworkManager
search localdomain thm
nameserver 10.20.30.2
```

`netstat` is a useful command for learning about network connections, routing tables, and interface statistics. We explain some of its many options in the table below.

|Option|Description|
|---|---|
|`-a`|show both listening and non-listening sockets|
|`-l`|show only listening sockets|
|`-n`|show numeric output instead of resolving the IP address and port number|
|`-t`|TCP|
|`-u`|UDP|
|`-x`|UNIX|
|`-p`|Show the PID and name of the program to which the socket belongs|

You can use any combination that suits your needs. For instance,`netstat -plt` will return _Programs Listening on TCP_ sockets. As we can see in the terminal output below,`sshd` is listening on the SSH port, while`master` is listening on the SMTP port on both IPv4 and IPv6 addresses. Note that to get all PID (process ID) and program names, you need to run`netstat` as root or use`sudo netstat`.


```shell-session
user@TryHackMe$ sudo netstat -plt
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address Foreign Address State PID/Program name 
tcp 0 0 0.0.0.0:ssh 0.0.0.0:* LISTEN 978/sshd 
tcp 0 0 localhost:smtp 0.0.0.0:* LISTEN 1141/master 
tcp6 0 0 [::]:ssh [::]:* LISTEN 978/sshd 
tcp6 0 0 localhost:smtp [::]:* LISTEN 1141/master
```

`netstat -atupn` will show _All TCP and UDP_ listening and established connections and the _program_ names with addresses and ports in _numeric_ format.


```shell-session
user@TryHackMe$ sudo netstat -atupn
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address Foreign Address State PID/Program name 
tcp 0 0 0.0.0.0:22 0.0.0.0:* LISTEN 978/sshd 
tcp 0 0 127.0.0.1:25 0.0.0.0:* LISTEN 1141/master 
tcp 0 0 10.20.30.129:22 10.20.30.113:38822 ESTABLISHED 5665/sshd: peter [p 
tcp 0 0 10.20.30.129:22 10.20.30.105:38826 ESTABLISHED 5723/sshd: jane [pr 
tcp6 0 0 :::22 :::* LISTEN 978/sshd 
tcp6 0 0 ::1:25 :::* LISTEN 1141/master 
udp 0 0 127.0.0.1:323 0.0.0.0:* 640/chronyd 
udp 0 0 0.0.0.0:68 0.0.0.0:* 5638/dhclient 
udp6 0 0 ::1:323 :::* 640/chronyd
```

One might think that using`nmap` before gaining access to the target machine would have provided a comparable result. However, this is not entirely true. Nmap needs to generate a relatively large number of packets to check for open ports, which can trigger intrusion detection and prevention systems. Furthermore, firewalls across the route can drop certain packets and hinder the scan, resulting in incomplete Nmap results.

`lsof` stands for List Open Files. If we want to display only Internet and network connections, we can use`lsof -i`. The terminal output below shows IPv4 and IPv6 listening services and ongoing connections. The user`peter` is connected to the server`rpm-red-enum.thm` on the`ssh` port. Note that to get the complete list of matching programs, you need to run`lsof` as root or use`sudo lsof`.

```shell-session
user@TryHackMe$ sudo lsof -i
COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
chronyd 640 chrony 5u IPv4 16945 0t0 UDP localhost:323 
chronyd 640 chrony 6u IPv6 16946 0t0 UDP localhost:323 
sshd 978 root 3u IPv4 20035 0t0 TCP *:ssh (LISTEN)
sshd 978 root 4u IPv6 20058 0t0 TCP *:ssh (LISTEN)
master 1141 root 13u IPv4 20665 0t0 TCP localhost:smtp (LISTEN)
master 1141 root 14u IPv6 20666 0t0 TCP localhost:smtp (LISTEN)
dhclient 5638 root 6u IPv4 47458 0t0 UDP *:bootpc 
sshd 5693 peter 3u IPv4 47594 0t0 TCP rpm-red-enum.thm:ssh->10.20.30.113:38822 (ESTABLISHED)
[...]
```

Because the list can get quite lengthy, you can further filter the output by specifying the ports you are interested in, such as SMTP port 25. By running`lsof -i :25`, we limit the output to those related to port 25, as shown in the terminal output below. The server is listening on port 25 on both IPv4 and IPv6 addresses.

```shell-session
user@TryHackMe$ sudo lsof -i :25
COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
master 1141 root 13u IPv4 20665 0t0 TCP localhost:smtp (LISTEN)
master 1141 root 14u IPv6 20666 0t0 TCP localhost:smtp (LISTEN)
```

### Running Services

Getting a snapshot of the running processes can provide many insights.`ps` lets you discover the running processes and plenty of information about them.

You can list every process on the system using`ps -e`, where`-e` selects all processes. For more information about the process, you can add`-f` for full-format and`-l` for long format. Experiment with`ps -e`,`ps -ef`, and`ps -el`.

You can get comparable output and see all the processes using BSD syntax:`ps ax` or`ps aux`. Note that`a` and`x` are necessary when using BSD syntax as they lift the only yourself and must have a tty restrictions; in other words, it becomes possible to display all processes. The`u` is for details about the user that has the process.

|Option|Description|
|---|---|
|`-e`|all processes|
|`-f`|full-format listing|
|`-j`|jobs format|
|`-l`|long format|
|`-u`|user-oriented format|

For more visual output, you can issue`ps axjf` to print a process tree. The`f` stands for forest, and it creates an ASCII art process hierarchy as shown in the terminal output below.


```shell-session
user@TryHackMe$ ps axf
 PID TTY STAT TIME COMMAND
 2 ? S 0:00 [kthreadd]
 4 ? S< 0:00 \_ [kworker/0:0H]
 5 ? S 0:01 \_ [kworker/u256:0]
[...]
 978 ? Ss 0:00 /usr/sbin/sshd -D
 5665 ? Ss 0:00 \_ sshd: peter [priv]
 5693 ? S 0:00 | \_ sshd: peter@pts/1
 5694 pts/1 Ss 0:00 | \_ -bash
 5713 pts/1 S+ 0:00 | \_ vi notes.txt
 5723 ? Ss 0:00 \_ sshd: jane [priv]
 5727 ? S 0:00 \_ sshd: jane@pts/0
 5728 pts/0 Ss 0:00 \_ -bash
 7080 pts/0 R+ 0:00 \_ ps axf
 979 ? Ssl 0:12 /usr/bin/python2 -Es /usr/sbin/tuned -l -P
 981 ? Ssl 0:07 /usr/sbin/rsyslogd -n
 1141 ? Ss 0:00 /usr/libexec/postfix/master -w
 1147 ? S 0:00 \_ qmgr -l -t unix -u
 6991 ? S 0:00 \_ pickup -l -t unix -u
 1371 ? Ss 0:00 login -- root
 1376 tty1 Ss 0:00 \_ -bash
 1411 tty1 S+ 0:00 \_ man man
 1420 tty1 S+ 0:00 \_ less -s
[...]
```

To summarize, remember to use`ps -ef` or`ps aux` to get a list of all the running processes. Consider piping the output via`grep` to display output lines with certain words. The terminal output below shows the lines with`peter` in them.

```shell-session
user@TryHackMe$ ps -ef | grep peter
root 5665 978 0 07:11 ? 00:00:00 sshd: peter [priv]
peter 5693 5665 0 07:13 ? 00:00:00 sshd: peter@pts/1
peter 5694 5693 0 07:13 pts/1 00:00:00 -bash
peter 5713 5694 0 07:13 pts/1 00:00:00 vi notes.txt
```

Start the attached Linux machine if you have not done so already, as you need it to answer the questions below. You can log in to it using SSH:`ssh user@MACHINE_IP`, where the login credentials are:

- Username:`user`
- Password:`THM6877`


## Questions
---

![Pasted image 20250514143547.png](../../../IMAGES/Pasted%20image%2020250514143547.png)

We can automate all the process using this script:

```bash
#!/bin/bash

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

# Get version information
echo -e "${GREEN}[+] Linux Distribution:${NC} ${RED}Ubuntu${NC}"
version=$(lsb_release -ds | awk '{print $2, $3, $4}' | tr -d '"')
echo -e "${GREEN}[+] Version Number:${NC} ${RED}$version${NC}"

# Get last logged-in user (excluding system users)
last_user=$(last -w | awk '!/root|reboot|wtmp|systemd|_apt|nobody/ && $1 != "'"$(whoami)"'" {print $1}' | head -1)
echo -e "${GREEN}[+] Last Logged-in User:${NC} ${RED}$last_user${NC}"

# Get highest TCP port with improved detection
highest_port=$(ss -tl4nH | awk '{gsub(/.*:/,"",$4); print $4}' | sort -nu | tail -1)
echo -e "${GREEN}[+] Highest Listening TCP Port:${NC} ${RED}$highest_port${NC}"

# Service detection with multiple fallbacks
get_service() {
 # Try ss first
 service=$(ss -tulnp 2>/dev/null | awk -v port=":$highest_port" '$5 ~ port {print $7}' | cut -d'"' -f2)
 
 # If empty, try lsof
 [ -z "$service" ] && service=$(sudo lsof -i :$highest_port 2>/dev/null | awk 'NR==2 {print $1}')
 
 # If still empty, check /proc
 if [ -z "$service" ]; then
 inode=$(awk -v port=$highest_port '$2 == port {print $10}' /proc/net/tcp | head -1)
 [ -n "$inode" ] && service=$(find /proc/*/fd/ -lname "socket:\[$inode\]" 2>/dev/null | cut -d'/' -f3 | xargs -I{} cat /proc/{}/comm 2>/dev/null)
 fi
 
 echo "${service:-Unknown}"
}

echo -e "${GREEN}[+] Service on Port $highest_port:${NC} ${RED}$(get_service)${NC}"

# THM script detection with exact match
thm_script=$(ps aux | grep '[T]HM' | awk '{for(i=11;i<=NF;i++) if ($i ~ /THM/) {print $i; exit}}' | grep -oE '/.*THM[^ ]+')
echo -e "${GREEN}[+] Running THM Script:${NC} ${RED}$thm_script${NC}"
```

If we use it, we get this:

```
user@ip-10-10-239-164:~$ ./enum.sh
[+] Linux Distribution: Ubuntu
[+] Version Number: 20.04.6 LTS
[+] Last Logged-in User: randa
[+] Highest Listening TCP Port: 6667
[+] Service on Port 6667: inspircd
[+] Running THM Script: /home/randa/THM-24765.sh
```

Those are our correct answers. 


# Windows Enumeration
---

![Pasted image 20250514144926.png](../../../IMAGES/Pasted%20image%2020250514144926.png)

In this task, we assume you have access to`cmd` on a Microsoft Windows host. You might have gained this access by exploiting a vulnerability and getting a shell or a reverse shell. You may also have installed a backdoor or set up an SSH server on a system you exploited. In all cases, the commands below require`cmd` to run.

In this task, we focus on enumerating an MS Windows host. For enumerating MS Active directory, you are encouraged to check the [Enumerating Active Directory](https://tryhackme.com/room/adenumeration) room. If you are interested in a privilege escalation on an MS Windows host, we recommend the [Windows Privesc 2.0](https://tryhackme.com/room/windowsprivesc20) room.

We recommend that you click "**Start AttackBox**" and "**Start Machine**" so that you can experiment and answer the questions at the end of this task.

### System

One command that can give us detailed information about the system, such as its build number and installed patches, would be`systeminfo`. In the example below, we can see which hotfixes have been installed.

```shell-session
C:\>systeminfo

Host Name: WIN-SERVER-CLI
OS Name: Microsoft Windows Server 2022 Standard
OS Version: 10.0.20348 N/A Build 20348
OS Manufacturer: Microsoft Corporation
[...]
Hotfix(s): 3 Hotfix(s) Installed.
 [01]: KB5013630
 [02]: KB5013944
 [03]: KB5012673
Network Card(s): 1 NIC(s) Installed.
 [01]: Intel(R) 82574L Gigabit Network Connection
[...]
```

You can check installed updates using`wmic qfe get Caption,Description`. This information will give you an idea of how quickly systems are being patched and updated.


```shell-session
C:\>wmic qfe get Caption,Description
Caption Description 
http://support.microsoft.com/?kbid=5013630 Update
https://support.microsoft.com/help/5013944 Security Update
 Update
```

You can check the installed and started Windows services using`net start`. Expect to get a long list; the output below has been snipped.

```shell-session
C:\>net start
These Windows services are started:

 Base Filtering Engine
 Certificate Propagation
 Client License Service (ClipSVC)
 COM+ Event System
 Connected User Experiences and Telemetry
 CoreMessaging
 Cryptographic Services
 DCOM Server Process Launcher
 DHCP Client
 DNS Client
[...]
 Windows Time
 Windows Update
 WinHTTP Web Proxy Auto-Discovery Service
 Workstation

The command completed successfully.
```

If you are only interested in installed apps, you can issue`wmic product get name,version,vendor`. If you run this command on the attached virtual machine, you will get something similar to the following output.


```shell-session
C:\>wmic product get name,version,vendor
Name Vendor Version
Microsoft Visual C++ 2019 X64 Minimum Runtime - 14.28.29910 Microsoft Corporation 14.28.29910
[...]
Microsoft Visual C++ 2019 X64 Additional Runtime - 14.28.29910 Microsoft Corporation 14.28.29910
```

### Users

To know who you are, you can run`whoami`; moreover, to know what you are capable of, i.e., your privileges, you can use`whoami /priv`. An example is shown in the terminal output below.


```shell-session
C:\>whoami
win-server-cli\strategos

> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name Description State
========================================= ================================================================== =======
SeIncreaseQuotaPrivilege Adjust memory quotas for a process Enabled
SeSecurityPrivilege Manage auditing and security log Enabled
SeTakeOwnershipPrivilege Take ownership of files or other objects Enabled
[...]
```

Moreover, you can use`whoami /groups` to know which groups you belong to. The terminal output below shows that this user belongs to the`NT AUTHORITY\Local account and member of Administrators group` among other groups.

```shell-session
C:\>whoami /groups

GROUP INFORMATION
-----------------

Group Name Type SID Attributes
============================================================= ================ ============ ===============================================================
Everyone Well-known group S-1-1-0 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account and member of Administrators group Well-known group S-1-5-114 Mandatory group, Enabled by default, Enabled group
BUILTIN\Administrators Alias S-1-5-32-544 Mandatory group, Enabled by default, Enabled group, Group owner
[...]
```

You can view users by running`net user`.

```shell-session
C:\>net user

User accounts for \\WIN-SERVER-CLI

-------------------------------------------------------------------------------
Administrator DefaultAccount Guest
michael peter strategos
WDAGUtilityAccount
The command completed successfully.
```

You can discover the available groups using`net group` if the system is a Windows Domain Controller or`net localgroup` otherwise, as shown in the terminal below.


```shell-session
C:\>net localgroup

Aliases for \\WIN-SERVER-CLI

-------------------------------------------------------------------------------
*Access Control Assistance Operators
*Administrators
*Backup Operators
*Certificate Service DCOM Access
*Cryptographic Operators
*Device Owners
[...]
```

You can list the users that belong to the local administrators' group using the command`net localgroup administrators`.

```shell-session
C:\>net localgroup administrators
Alias name administrators
Comment Administrators have complete and unrestricted access to the computer/domain

Members

-------------------------------------------------------------------------------
Administrator
michael
peter
strategos
The command completed successfully.
```

Use`net accounts` to see the local settings on a machine; moreover, you can use`net accounts /domain` if the machine belongs to a domain. This command helps learn about password policy, such as minimum password length, maximum password age, and lockout duration.

### Networking

You can use the`ipconfig` command to learn about your system network configuration. If you want to know all network-related settings, you can use`ipconfig /all`. The terminal output below shows the output when using`ipconfig`. For instance, we could have used`ipconfig /all` if we wanted to learn the DNS servers.


```shell-session
C:\>ipconfig

Windows IP Configuration


Ethernet adapter Ethernet0:

 Connection-specific DNS Suffix . : localdomain
 Link-local IPv6 Address . . . . . : fe80::3dc5:78ef:1274:a740%5
 IPv4 Address. . . . . . . . . . . : 10.20.30.130
 Subnet Mask . . . . . . . . . . . : 255.255.255.0
 Default Gateway . . . . . . . . . : 10.20.30.2
```

On MS Windows, we can use`netstat` to get various information, such as which ports the system is listening on, which connections are active, and who is using them. In this example, we use the options`-a` to display all listening ports and active connections. The`-b` lets us find the binary involved in the connection, while`-n` is used to avoid resolving IP addresses and port numbers. Finally,`-o` display the process ID (PID).

In the partial output shown below, we can see that`netstat -abno` showed that the server is listening on TCP ports 22, 135, 445 and 3389. The processes`sshd.exe`,`RpcSs`, and`TermService` are on ports`22`,`135`, and`3389`, respectively. Moreover, we can see two established connections to the SSH server as indicated by the state`ESTABLISHED`.

```shell-session
C:\>netstat -abno

Active Connections

 Proto Local Address Foreign Address State PID
 TCP 0.0.0.0:22 0.0.0.0:0 LISTENING 2016
 [sshd.exe]
 TCP 0.0.0.0:135 0.0.0.0:0 LISTENING 924
 RpcSs
 [svchost.exe]
 TCP 0.0.0.0:445 0.0.0.0:0 LISTENING 4
 Can not obtain ownership information
 TCP 0.0.0.0:3389 0.0.0.0:0 LISTENING 416
 TermService
 [svchost.exe]
[...]
 TCP 10.20.30.130:22 10.20.30.1:39956 ESTABLISHED 2016
 [sshd.exe]
 TCP 10.20.30.130:22 10.20.30.1:39964 ESTABLISHED 2016
 [sshd.exe]
[...]
```

You might think that you can get an identical result by port scanning the target system; however, this is inaccurate for two reasons. A firewall might be blocking the scanning host from reaching specific network ports. Moreover, port scanning a system generates a considerable amount of traffic, unlike`netstat`, which makes zero noise.

Finally, it is worth mentioning that using`arp -a` helps you discover other systems on the same LAN that recently communicated with your system. ARP stands for Address Resolution Protocol;`arp -a` shows the current ARP entries, i.e., the physical addresses of the systems on the same LAN that communicated with your system. An example output is shown below. This indicates that these IP addresses have communicated somehow with our system; the communication can be an attempt to connect or even a simple ping. Note that`10.10.255.255` does not represent a system as it is the subnet broadcast address.


```shell-session
C:\>arp -a

Interface: 10.10.204.175 --- 0x4 
 Internet Address Physical Address Type
 10.10.0.1 02-c8-85-b5-5a-aa dynamic
 10.10.16.117 02-f2-42-76-fc-ef dynamic
 10.10.122.196 02-48-58-7b-92-e5 dynamic
 10.10.146.13 02-36-c1-4d-05-f9 dynamic
 10.10.161.4 02-a8-58-98-1a-d3 dynamic
 10.10.217.222 02-68-10-dd-be-8d dynamic
 10.10.255.255 ff-ff-ff-ff-ff-ff static
```

Start the attached MS Windows Server if you have not done so already, as you need it to answer the questions below. You can connect to the MS Windows VM via SSH from the AttackBox, for example, using`ssh user@MACHINE_IP` where the login credentials are:

- Username:`user`
- Password:`THM33$$88`

### Questions
-----

![Pasted image 20250514145241.png](../../../IMAGES/Pasted%20image%2020250514145241.png)

Let's automate it again using `Powershell`:

```powershell
# Enumerate System Information
$systemInfo = systeminfo

# Fixed OS Version extraction with error handling
$osName = ($systemInfo | Select-String "OS Name:\s+(.+)").Matches.Groups[1].Value
$osVersion = ($systemInfo | Select-String "OS Version:\s+([\d\.]+)").Matches.Groups[1].Value
$hotfixCount = [regex]::Matches($systemInfo, "KB\d+").Count

# Get Network Information with proper filtering
$netstatRaw = netstat -abno | Out-String
$tcpListeners = $netstatRaw -split "`r`n" | Where-Object {
 $_ -match "TCP\s+.*LISTENING" -and ($_ -split ":")[1] -match "\d+"
}

# Find lowest valid listening port
$ports = $tcpListeners | ForEach-Object {
 [int](($_ -split ":")[1] -replace "[^0-9].*","")
} | Where-Object { $_ -gt 0 } | Sort-Object

$lowestPort = $ports[0]

# Find program for lowest port with better parsing
$program = $netstatRaw -split "`r`n" | Where-Object { 
 $_ -match ":$lowestPort\s" -or $_ -match "\[.*\]"
} | Select-Object -First 1 -Skip 1 | ForEach-Object {
 ($_ -split "\[|]")[-2].Trim()
}

# Display results with colors
Write-Host "What is the full OS Name?" -ForegroundColor Green
Write-Host $osName -ForegroundColor Red
Write-Host "`nWhat is the OS Version?" -ForegroundColor Green
Write-Host $osVersion -ForegroundColor Red
Write-Host "`nHow many hotfixes are installed on this MS Windows Server?" -ForegroundColor Green
Write-Host $hotfixCount -ForegroundColor Red
Write-Host "`nWhat is the lowest TCP port number listening on the system?" -ForegroundColor Green
Write-Host $lowestPort -ForegroundColor Red
Write-Host "`nWhat is the name of the program listening on that port?" -ForegroundColor Green
Write-Host $program -ForegroundColor Red
```

We need to use `scp` to submit it into the machine:

```
scp .\enum.ps1 user@IP:enum.ps1
```

We can now run the script and check the output:

```powershell
PS C:\Users\user> .\enum.ps1
What is the full OS Name?
Microsoft Windows Server 2019 Datacenter

What is the OS Version?
10.0.17763

How many hotfixes are installed on this MS Windows Server?
30

What is the lowest TCP port number listening on the system?
22

What is the name of the program listening on that port?
sshd.exe
```

We got our answers.


# DNS, SMB, and SNMP
---

As we cover enumeration, it is a good idea to touch on DNS, SMB, and SNMP.

### DNS

We are all familiar with Domain Name System (DNS) queries where we can look up A, AAAA, CName, and TXT records, among others. If you want to brush up on your DNS knowledge, we suggest you visit the [DNS in Detail](https://tryhackme.com/room/dnsindetail) room. If we can get a copy of all the records that a DNS server is responsible for answering, we might discover hosts we didn't know existed.

One easy way to try DNS zone transfer is via the`dig` command. If you want to learn more about`dig` and similar commands, we suggest checking the [Passive Reconnaissance](https://tryhackme.com/room/passiverecon) room. Depending on the DNS server configuration, DNS zone transfer might be restricted. If it is not restricted, it should be achievable using`dig -t AXFR DOMAIN_NAME @DNS_SERVER`. The`-t AXFR` indicates that we are requesting a zone transfer, while`@` precedes the`DNS_SERVER` that we want to query regarding the records related to the specified`DOMAIN_NAME`.

### SMB

Server Message Block (SMB) is a communication protocol that provides shared access to files and printers. We can check shared folders using`net share`. Here is an example of the output. We can see that`C:\Internal Files` is shared under the name _Internal_.

```shell-session
user@TryHackMe$ net share

Share name Resource Remark

-------------------------------------------------------------------------------
C$ C:\ Default share
IPC$ Remote IPC
ADMIN$ C:\Windows Remote Admin
Internal C:\Internal Files Internal Documents
Users C:\Users
The command completed successfully.
```

### SNMP

Simple Network Management Protocol (SNMP) was designed to help collect information about different devices on the network. It lets you know about various network events, from a server with a faulty disk to a printer out of ink. Consequently, SNMP can hold a trove of information for the attacker. One simple tool to query servers related to SNMP is`snmpcheck`. You can find it on the AttackBox at the`/opt/snmpcheck/` directory; the syntax is quite simple:`/opt/snmpcheck/snmpcheck.rb 10.10.215.161 -c COMMUNITY_STRING`.

If you would like to install`snmpcheck` on your local Linux box, consider the following commands.

```shell-session
git clone https://gitlab.com/kalilinux/packages/snmpcheck.git
cd snmpcheck/
gem install snmp
chmod +x snmpcheck-1.9.rb
```

Ensure that you are running the MS Windows Server machine from Task 4 and answer the following questions.


### Questions
---

Let's automate all with a bash script:

```bash
#!/bin/bash

# Configuration
TARGET="IP"
USER="user"
PASSWORD="THM33\$\$88" # Properly escaped password
SNMP_OID="1.3.6.1.2.1.1.6.0"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# DNS Zone Transfer
echo -e "${CYAN}[1] Performing DNS Zone Transfer...${NC}"
dns_flag=$(dig -t AXFR redteam.thm @$TARGET +short | grep -oP 'THM{.*?}')
echo -e "${GREEN}DNS Flag: ${RED}${dns_flag}${NC}"

# SMB Share Enumeration via SSH
echo -e "\n${CYAN}[2] Checking SMB Shares via SSH...${NC}"
smb_flag=$(sshpass -p "$PASSWORD" ssh -o StrictHostKeyChecking=no $USER@$TARGET "net share" 2>/dev/null | grep -oP 'THM{.*?}')
echo -e "${GREEN}SMB Flag: ${RED}${smb_flag}${NC}"

# SNMP Location Check
echo -e "\n${CYAN}[3] Checking SNMP Information...${NC}"
snmp_flag=$(snmpwalk -v 2c -c public $TARGET $SNMP_OID 2>/dev/null | grep -oP 'THM{.*?}')
echo -e "${GREEN}SNMP Flag: ${RED}${snmp_flag}${NC}"
```

We need `sshpass` and `snmpwalk` installed for the script to work.


Once we run the script, we can see this:

```python
./automate.sh

[1] Performing DNS Zone Transfer...
DNS Flag: THM{DNS_ZONE}

[2] Checking SMB Shares via SSH...
SMB Flag: THM{829738}

[3] Checking SNMP Information...
SNMP Flag: THM{SNMP_SERVICE}
```

We got our flags.


# More Tools for Windows
----

In this room, our focus has been on command-line built-in tools readily available on any modern MS Windows system. We didn't cover Graphical User Interface (GUI) tools; moreover, we didn't cover any programs requiring additional downloading and installation steps.

This task mentions three options that are not built-in command-line tools:

- Sysinternals Suite
- Process Hacker
- GhostPack Seatbelt

### Sysinternals Suite

The [Sysinternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/) is a group of command-line and GUI utilities and tools that provides information about various aspects related to the Windows system. To give you an idea, we listed a few examples in the table below.

|Utility Name|Description|
|---|---|
|Process Explorer|Shows the processes along with the open files and registry keys|
|Process Monitor|Monitor the file system, processes, and Registry|
|PsList|Provides information about processes|
|PsLoggedOn|Shows the logged-in users|

Check [Sysinternals Utilities Index](https://docs.microsoft.com/en-us/sysinternals/downloads/) for a complete list of the utilities. If you want to learn more and experiment with these different utilities, we suggest the [Sysinternals](https://tryhackme.com/room/btsysinternalssg) room.

### Process Hacker

Another efficient and reliable MS Windows GUI tool that lets you gather information about running processes is [Process Hacker](https://processhacker.sourceforge.io/). Process Hacker gives you detailed information regarding running processes and related active network connections; moreover, it gives you deep insight into system resource utilization from CPU and memory to disk and network.

### GhostPack Seatbelt

[Seatbelt](https://github.com/GhostPack/Seatbelt), part of the GhostPack collection, is a tool written in C#. It is not officially released in binary form; therefore, you are expected to compile it yourself using MS Visual Studio.


# Conclusion
---

The focus of this room was on built-in command-line tools in both Linux and MS Windows systems. Many commands exist in both systems, although the command arguments and resulting output are different. The following tables show the primary Linux and MS Windows commands that we relied on to get more information about the system.

|Linux Command|Description|
|---|---|
|`hostname`|shows the system's hostname|
|`who`|shows who is logged in|
|`whoami`|shows the effective username|
|`w`|shows who is logged in and what they are doing|
|`last`|shows a listing of the last logged-in users|
|`ip address show`|shows the network interfaces and addresses|
|`arp`|shows the ARP cache|
|`netstat`|prints network connections|
|`ps`|shows a snapshot of the current processes|

|Windows Command|Description|
|---|---|
|`systeminfo`|shows OS configuration information, including service pack levels|
|`whoami`|shows the user name and group information along with the respective security identifiers|
|`netstat`|shows protocol statistics and current TCP/IP network connections|
|`net user`|shows the user accounts on the computer|
|`net localgroup`|shows the local groups on the computer|
|`arp`|shows the IP-to-Physical address translation tables|

This room focused on post-exploitation enumeration of a Linux or MS Windows machine. For enumeration related to Active Directory, we recommend that you join the [Enumerating AD](https://tryhackme.com/room/adenumeration) room.
