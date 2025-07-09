---
sticker: lucide//code
---
We now understand the basic use ofÂ `ffuf`Â through the utilization of wordlists and keywords. Next, we will learn how to locate pages.

Note: We can spawn the same target from the previous section for this section's examples as well.

---

## Extension Fuzzing

In the previous section, we found that we had access toÂ `/blog`, but the directory returned an empty page, and we cannot manually locate any links or pages. So, we will once again utilize web fuzzing to see if the directory contains any hidden pages. However, before we start, we must find out what types of pages the website uses, likeÂ `.html`,Â `.aspx`,Â `.php`, or something else.

One common way to identify that is by finding the server type through the HTTP response headers and guessing the extension. For example, if the server isÂ `apache`, then it may beÂ `.php`, or if it wasÂ `IIS`, then it could beÂ `.asp`Â orÂ `.aspx`, and so on. This method is not very practical, though. So, we will again utilizeÂ `ffuf`Â to fuzz the extension, similar to how we fuzzed for directories. Instead of placing theÂ `FUZZ`Â keyword where the directory name would be, we would place it where the extension would beÂ `.FUZZ`, and use a wordlist for common extensions. We can utilize the following wordlist inÂ `SecLists`Â for extensions:


```shell-session
smoothment@htb[/htb]$ ffuf -w /opt/useful/seclists/Discovery/Web-Content/web-extensions.txt:FUZZ <SNIP>
```

Before we start fuzzing, we must specify which file that extension would be at the end of! We can always use two wordlists and have a unique keyword for each, and then doÂ `FUZZ_1.FUZZ_2`Â to fuzz for both. However, there is one file we can always find in most websites, which isÂ `index.*`, so we will use it as our file and fuzz extensions on it.

Note: The wordlist we chose already contains a dot (.), so we will not have to add the dot after "index" in our fuzzing.

Now, we can rerun our command, carefully placing ourÂ `FUZZ`Â keyword where the extension would be afterÂ `index`:


```shell-session
smoothment@htb[/htb]$ ffuf -w /opt/useful/seclists/Discovery/Web-Content/web-extensions.txt:FUZZ -u http://SERVER_IP:PORT/blog/indexFUZZ


        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.1.0-git
________________________________________________

 :: Method           : GET
 :: URL              : http://SERVER_IP:PORT/blog/indexFUZZ
 :: Wordlist         : FUZZ: /opt/useful/seclists/Discovery/Web-Content/web-extensions.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 5
 :: Matcher          : Response status: 200,204,301,302,307,401,403
________________________________________________

.php                    [Status: 200, Size: 0, Words: 1, Lines: 1]
.phps                   [Status: 403, Size: 283, Words: 20, Lines: 10]
:: Progress: [39/39] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Errors: 0 ::
```

We do get a couple of hits, but onlyÂ `.php`Â gives us a response with codeÂ `200`. Great! We now know that this website runs onÂ `PHP`Â to start fuzzing forÂ `PHP`Â files.

---

## Page Fuzzing

We will now use the same concept of keywords we've been using withÂ `ffuf`, useÂ `.php`Â as the extension, place ourÂ `FUZZ`Â keyword where the filename should be, and use the same wordlist we used for fuzzing directories:

Â Â Page Fuzzing
```shell-session
smoothment@htb[/htb]$ ffuf -w /opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://SERVER_IP:PORT/blog/FUZZ.php


        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.1.0-git
________________________________________________

 :: Method           : GET
 :: URL              : http://SERVER_IP:PORT/blog/FUZZ.php
 :: Wordlist         : FUZZ: /opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403
________________________________________________

index                   [Status: 200, Size: 0, Words: 1, Lines: 1]
REDACTED                [Status: 200, Size: 465, Words: 42, Lines: 15]
:: Progress: [87651/87651] :: Job [1/1] :: 5843 req/sec :: Duration: [0:00:15] :: Errors: 0 ::
```

We get a couple of hits; both have an HTTP code 200, meaning we can access them. `index.php` has a size of 0, indicating that it is an empty page, while the other does not, which means that it has content. We can visit any of these pages to verify this:

Â Â Â 

![](https://academy.hackthebox.com/storage/modules/54/web_fnb_login.jpg)


# Question
---

![Pasted image 20250129143449.png](../../../../IMAGES/Pasted%20image%2020250129143449.png)

If we fuzz for the blog directory, we find the following:

![Pasted image 20250129143734.png](../../../../IMAGES/Pasted%20image%2020250129143734.png)

We found a `home.php` directory, let's check it out:

![Pasted image 20250129143814.png](../../../../IMAGES/Pasted%20image%2020250129143814.png)

Got the flag: `HTB{bru73_f0r_c0mm0n_p455w0rd5}`



