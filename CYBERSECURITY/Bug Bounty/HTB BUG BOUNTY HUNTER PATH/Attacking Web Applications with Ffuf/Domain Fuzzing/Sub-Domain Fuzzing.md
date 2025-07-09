---
sticker: lucide//code
---
In this section, we will learn how to useÂ `ffuf`Â to identify sub-domains (i.e.,Â `*.website.com`) for any website.

---

## Sub-domains

A sub-domain is any website underlying another domain. For example,Â `https://photos.google.com`Â is theÂ `photos`Â sub-domain ofÂ `google.com`.

In this case, we are simply checking different websites to see if they exist by checking if they have a public DNS record that would redirect us to a working server IP. So, let's run a scan and see if we get any hits. Before we can start our scan, we need two things:

- AÂ `wordlist`
- AÂ `target`

Luckily for us, in theÂ `SecLists`Â repo, there is a specific section for sub-domain wordlists, consisting of common words usually used for sub-domains. We can find it inÂ `/opt/useful/seclists/Discovery/DNS/`. In our case, we would be using a shorter wordlist, which isÂ `subdomains-top1million-5000.txt`. If we want to extend our scan, we can pick a larger list.

As for our target, we will useÂ `inlanefreight.com`Â as our target and run our scan on it. Let us useÂ `ffuf`Â and place theÂ `FUZZ`Â keyword in the place of sub-domains, and see if we get any hits:


```shell-session
smoothment@htb[/htb]$ ffuf -w /opt/useful/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u https://FUZZ.inlanefreight.com/


        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v1.1.0-git
________________________________________________

 :: Method           : GET
 :: URL              : https://FUZZ.inlanefreight.com/
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
________________________________________________

[Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 381ms]
    * FUZZ: support

[Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 385ms]
    * FUZZ: ns3

[Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 402ms]
    * FUZZ: blog

[Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 180ms]
    * FUZZ: my

[Status: 200, Size: 22266, Words: 2903, Lines: 316, Duration: 589ms]
    * FUZZ: www

<...SNIP...>
```

We see that we do get a few hits back. Now, we can try running the same thing onÂ `academy.htb`Â and see if we get any hits back:


```shell-session
smoothment@htb[/htb]$ ffuf -w /opt/useful/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://FUZZ.academy.htb/


        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v1.1.0-git
________________________________________________

 :: Method           : GET
 :: URL              : https://FUZZ.academy.htb/
 :: Wordlist         : FUZZ: /opt/useful/seclists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403
________________________________________________

:: Progress: [4997/4997] :: Job [1/1] :: 131 req/sec :: Duration: [0:00:38] :: Errors: 4997 ::
```

We see that we do not get any hits back. Does this mean that there are no sub-domain underÂ `academy.htb`? - No.

This means that there are noÂ `public`Â sub-domains underÂ `academy.htb`, as it does not have a public DNS record, as previously mentioned. Even though we did addÂ `academy.htb`Â to ourÂ `/etc/hosts`Â file, we only added the main domain, so whenÂ `ffuf`Â is looking for other sub-domains, it will not find them inÂ `/etc/hosts`, and will ask the public DNS, which obviously will not have them.

# Question
---
![Pasted image 20250129150058.png](../../../../IMAGES/Pasted%20image%2020250129150058.png)

Let's run the following command:

`ffuf -w /opt/useful/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u https://FUZZ.inlanefreight.com/ 2>/dev/null -ic -c -t 200`

We'll get the following:

![Pasted image 20250129151218.png](../../../../IMAGES/Pasted%20image%2020250129151218.png)

Answer is `customer.inlanefreight.com`
