---
sticker: lucide//code
---
You are given an online academy's IP address but have no further information about their website. As the first step of conducting a Penetration Test, you are expected to locate all pages and domains linked to their IP to enumerate the IP and domains properly.

Finally, you should do some fuzzing on pages you identify to see if any of them has any parameters that can be interacted with. If you do find active parameters, see if you can retrieve any data from them.

# Questions
---

![Pasted image 20250129161351.png](../../../IMAGES/Pasted%20image%2020250129161351.png)
## 1
---

Let's begin by adding the domain to `/etc/hosts`:

`sudo sh -c 'echo "94.237.54.69 academy.htb" >> /etc/hosts'`

Now, let's run an initial scan to check the size in order to filter:

`ffuf -w /opt/useful/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://academy.htb:49384/ -H 'Host: FUZZ.academy.htb'`

![Pasted image 20250129162015.png](../../../IMAGES/Pasted%20image%2020250129162015.png)

Size is `985`, let's filter by `-fs 985`:

`ffuf -w /opt/useful/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://academy.htb:34474/ -H 'Host: FUZZ.academy.htb' -fs 985 -ic -c `

```
ffuf -w /opt/useful/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://academy.htb:34474/ -H 'Host: FUZZ.academy.htb' -fs 985 -ic -c 

 /'___\ /'___\ /'___\ 
 /\ \__/ /\ \__/ __ __ /\ \__/ 
 \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\ 
 \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/ 
 \ \_\ \ \_\ \ \____/ \ \_\ 
 \/_/ \/_/ \/___/ \/_/ 

 v2.1.0-dev
________________________________________________

 :: Method : GET
 :: URL : http://academy.htb:34474/
 :: Wordlist : FUZZ: /opt/useful/seclists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Header : Host: FUZZ.academy.htb
 :: Follow redirects : false
 :: Calibration : false
 :: Timeout : 10
 :: Threads : 40
 :: Matcher : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter : Response size: 985
________________________________________________

archive [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 77ms]
test [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 3735ms]
faculty [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 78ms]
```

We got it, answer is: `archive test faculty`


Now, let's add the found vhosts to `/etc/hosts` too:

```ad-hint
1.`sudo sed -i '/academy\.htb/d' /etc/hosts` -> To erase previous line and keep it cleaner.

2.`sudo sh -c 'echo "94.237.54.69 academy.htb archive.academy.htb test.academy.htb faculty.academy.htb" >> /etc/hosts'` -> Adding all vhosts.
```

Nice, let's proceed with the next question.

## 2
---


We need to run an extensions fuzzing before the page fuzzing, since we have to iterate through each subdomain, I created a bash script with the help of AI: 


```bash
#!/bin/bash

# Configuration
PORT=34474
OUTPUT_FILE="combined_scan_results.txt"
SUBDOMAINS=("academy.htb" "archive.academy.htb" "test.academy.htb" "faculty.academy.htb")

# Clear existing output file
> "$OUTPUT_FILE"

# Loop through subdomains
for sub in "${SUBDOMAINS[@]}"; do
 # Add subdomain header to output
 echo -e "\n# ${sub}" >> "$OUTPUT_FILE"
 
 # Run ffuf and format output
 ffuf -w /usr/share/seclists/Discovery/Web-Content/web-extensions.txt:FUZZ \
 -u "http://${sub}:${PORT}/indexFUZZ" \
 -ic \
 -mc 200,301,302,403 \
 -s \
 -noninteractive 2>&1 | sed "s/^/ /" >> "$OUTPUT_FILE"
done

echo "Scan complete! Results saved to ${OUTPUT_FILE}"
```

If we run the script we can see the following output:

![Pasted image 20250129164642.png](../../../IMAGES/Pasted%20image%2020250129164642.png)

So, answer would be `.php .php7 .phps`

## 3
---

Now, let's run the page fuzzing, we need to identify the page we don't have access to, we can use the following command:

`ffuf -w /opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://faculty.academy.htb:34474/FUZZ -recursion -recursion-depth 1 -e ".php,.phps,.php7" -v -fc 403 -ic -c -t 200`

We'll be using `faculty.academy.htb` since is the only one with all the extensions, this can be a good approach at the beginning, after a while we get the following: 

```
ffuf -w /opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://faculty.academy.htb:34474/FUZZ -recursion -recursion-depth 1 -e ".php,.phps,.php7" -v -fc 403 -ic -c -t 200

 /'___\ /'___\ /'___\ 
 /\ \__/ /\ \__/ __ __ /\ \__/ 
 \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\ 
 \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/ 
 \ \_\ \ \_\ \ \____/ \ \_\ 
 \/_/ \/_/ \/___/ \/_/ 

 v2.1.0-dev
________________________________________________

 :: Method : GET
 :: URL : http://faculty.academy.htb:34474/FUZZ
 :: Wordlist : FUZZ: /opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt
 :: Extensions : .php .phps .php7 
 :: Follow redirects : false
 :: Calibration : false
 :: Timeout : 10
 :: Threads : 200
 :: Matcher : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter : Response status: 403
________________________________________________

[Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 77ms]
| URL | http://faculty.academy.htb:34474/index.php7
 * FUZZ: index.php7

[Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 77ms]
| URL | http://faculty.academy.htb:34474/index.php
 * FUZZ: index.php

[Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 78ms]
| URL | http://faculty.academy.htb:34474/
 * FUZZ: 

[Status: 301, Size: 337, Words: 20, Lines: 10, Duration: 77ms]
| URL | http://faculty.academy.htb:34474/courses
| --> | http://faculty.academy.htb:34474/courses/
 * FUZZ: courses

[INFO] Adding a new job to the queue: http://faculty.academy.htb:34474/courses/FUZZ

[Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 79ms]
| URL | http://faculty.academy.htb:34474/
 * FUZZ: 

[INFO] Starting queued job on target: http://faculty.academy.htb:34474/courses/FUZZ

[Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 82ms]
| URL | http://faculty.academy.htb:34474/courses/
 * FUZZ: 

[Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 82ms]
| URL | http://faculty.academy.htb:34474/courses/index.php7
 * FUZZ: index.php7

[Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 82ms]
| URL | http://faculty.academy.htb:34474/courses/index.php
 * FUZZ: index.php

[Status: 200, Size: 774, Words: 223, Lines: 53, Duration: 79ms]
| URL | http://faculty.academy.htb:34474/courses/linux-security.php7
 * FUZZ: linux-security.php7
```

We found the URL, answer must be in this format: `http://faculty.academy.htb:PORT/courses/linux-security.php7`


## 4
---

Now, let's perform parameters fuzzing in the page:

`ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u http://faculty.academy.htb:$PORT/courses/linux-security.php7?FUZZ=key` -> To identify the filter size needed:

![Pasted image 20250129170432.png](../../../IMAGES/Pasted%20image%2020250129170432.png)

We need to filter with `-fs 774`:

`ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u http://faculty.academy.htb:34474/courses/linux-security.php7?FUZZ=key -fs 774 -ic -c -t 200`

After a while, we get the following:

```
ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u http://faculty.academy.htb:34474/courses/linux-security.php7?FUZZ=key -fs 774 -ic -c -t 200

 /'___\ /'___\ /'___\ 
 /\ \__/ /\ \__/ __ __ /\ \__/ 
 \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\ 
 \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/ 
 \ \_\ \ \_\ \ \____/ \ \_\ 
 \/_/ \/_/ \/___/ \/_/ 

 v2.1.0-dev
________________________________________________

 :: Method : GET
 :: URL : http://faculty.academy.htb:34474/courses/linux-security.php7?FUZZ=key
 :: Wordlist : FUZZ: /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt
 :: Follow redirects : false
 :: Calibration : false
 :: Timeout : 10
 :: Threads : 200
 :: Matcher : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter : Response size: 774
________________________________________________

user [Status: 200, Size: 780, Words: 223, Lines: 53, Duration: 77ms]
```

We got one: `user`

Let's do a parameter fuzzing for POST request:

`ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u http://faculty.academy.htb:34474/courses/linux-security.php7 -X POST -d 'FUZZ=key' -H 'Content-Type: application/x-www-form-urlencoded' -fs 774 -ic -c -t 200`

After a while we get the following:

```
ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u http://faculty.academy.htb:34474/courses/linux-security.php7 -X POST -d 'FUZZ=key' -H 'Content-Type: application/x-www-form-urlencoded' -fs 774 -ic -c -t 200

 /'___\ /'___\ /'___\ 
 /\ \__/ /\ \__/ __ __ /\ \__/ 
 \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\ 
 \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/ 
 \ \_\ \ \_\ \ \____/ \ \_\ 
 \/_/ \/_/ \/___/ \/_/ 

 v2.1.0-dev
________________________________________________

 :: Method : POST
 :: URL : http://faculty.academy.htb:34474/courses/linux-security.php7
 :: Wordlist : FUZZ: /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt
 :: Header : Content-Type: application/x-www-form-urlencoded
 :: Data : FUZZ=key
 :: Follow redirects : false
 :: Calibration : false
 :: Timeout : 10
 :: Threads : 40
 :: Matcher : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter : Response size: 774
________________________________________________

user [Status: 200, Size: 780, Words: 223, Lines: 53, Duration: 77ms]
username [Status: 200, Size: 781, Words: 223, Lines: 53, Duration: 77ms]
```

So, we got both parameters: `user` `username`

## 5
---

For the final task, I'll be using the `/opt/useful/seclists/Usernames/Names/names.txt` files, since we are fuzzing for usernames, let's use the following command:

`ffuf -w /usr/share/seclists/Usernames/Names/names.txt:FUZZ -u http://faculty.academy.htb:34474/courses/linux-security.php7 -X POST -d 'username=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded'`

![Pasted image 20250129170957.png](../../../IMAGES/Pasted%20image%2020250129170957.png)

Got to filter for size 781: 

`ffuf -w /usr/share/seclists/Usernames/Names/names.txt:FUZZ -u http://faculty.academy.htb:34474/courses/linux-security.php7 -X POST -d 'username=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded' -fs 781 -ic -c -t 200`

After a while, we get the following:

```
ffuf -w /usr/share/seclists/Usernames/Names/names.txt:FUZZ -u http://faculty.academy.htb:34474/courses/linux-security.php7 -X POST -d 'username=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded' -fs 781 -ic -c -t 200

 /'___\ /'___\ /'___\ 
 /\ \__/ /\ \__/ __ __ /\ \__/ 
 \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\ 
 \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/ 
 \ \_\ \ \_\ \ \____/ \ \_\ 
 \/_/ \/_/ \/___/ \/_/ 

 v2.1.0-dev
________________________________________________

 :: Method : POST
 :: URL : http://faculty.academy.htb:34474/courses/linux-security.php7
 :: Wordlist : FUZZ: /usr/share/seclists/Usernames/Names/names.txt
 :: Header : Content-Type: application/x-www-form-urlencoded
 :: Data : username=FUZZ
 :: Follow redirects : false
 :: Calibration : false
 :: Timeout : 10
 :: Threads : 200
 :: Matcher : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter : Response size: 781
________________________________________________

harry [Status: 200, Size: 773, Words: 218, Lines: 53, Duration: 77ms]
```

![Pasted image 20250129171107.png](../../../IMAGES/Pasted%20image%2020250129171107.png)
Got the answer: `harry`, let's use curl and get the flag:

`curl http://faculty.academy.htb:34474/courses/linux-security.php7 -X POST -d 'username=harry' -H 'Content-Type: application/x-www-form-urlencoded' -s | grep HTB{`


We get the following:

![Pasted image 20250129171237.png](../../../IMAGES/Pasted%20image%2020250129171237.png)

Answer is: `HTB{w3b_fuzz1n6_m4573r}`


Just like that, module is done!


![Pasted image 20250129171314.png](../../../IMAGES/Pasted%20image%2020250129171314.png)

