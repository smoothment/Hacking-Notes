---
sticker: lucide//code
---
If we run a recursiveÂ `ffuf`Â scan onÂ `admin.academy.htb`, we should findÂ `http://admin.academy.htb:PORT/admin/admin.php`. If we try accessing this page, we see the following:

Â Â Â 

![](https://academy.hackthebox.com/storage/modules/54/web_fnb_admin.jpg)

That indicates that there must be something that identifies users to verify whether they have access to read theÂ `flag`. We did not login, nor do we have any cookie that can be verified at the backend. So, perhaps there is a key that we can pass to the page to read theÂ `flag`. Such keys would usually be passed as aÂ `parameter`, using either aÂ `GET`Â or aÂ `POST`Â HTTP request. This section will discuss how to fuzz for such parameters until we identify a parameter that can be accepted by the page.

**Tip:**Â Fuzzing parameters may expose unpublished parameters that are publicly accessible. Such parameters tend to be less tested and less secured, so it is important to test such parameters for the web vulnerabilities we discuss in other modules.

---

## GET Request Fuzzing

Similarly to how we have been fuzzing various parts of a website, we will useÂ `ffuf`Â to enumerate parameters. Let us first start with fuzzing forÂ `GET`Â requests, which are usually passed right after the URL, with aÂ `?`Â symbol, like:

- `http://admin.academy.htb:PORT/admin/admin.php?param1=key`.

So, all we have to do is replaceÂ `param1`Â in the example above withÂ `FUZZ`Â and rerun our scan. Before we can start, however, we must pick an appropriate wordlist. Once again,Â `SecLists`Â has just that inÂ `/opt/useful/seclists/Discovery/Web-Content/burp-parameter-names.txt`. With that, we can run our scan.

Once again, we will get many results back, so we will filter out the default response size we are getting.

```shell-session
smoothment@htb[/htb]$ ffuf -w /opt/useful/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php?FUZZ=key -fs xxx


        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.1.0-git
________________________________________________

 :: Method           : GET
 :: URL              : http://admin.academy.htb:PORT/admin/admin.php?FUZZ=key
 :: Wordlist         : FUZZ: /opt/useful/seclists/Discovery/Web-Content/burp-parameter-names.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403
 :: Filter           : Response size: xxx
________________________________________________

<...SNIP...>                    [Status: xxx, Size: xxx, Words: xxx, Lines: xxx]
```

We do get a hit back. Let us try to visit the page and add thisÂ `GET`Â parameter, and see whether we can read the flag now:

Â Â Â 

![](https://academy.hackthebox.com/storage/modules/54/web_fnb_admin_param1.jpg)

As we can see, the only hit we got back has beenÂ `deprecated`Â and appears to be no longer in use.

# Question
---


![Pasted image 20250129155215.png](../../../../IMAGES/Pasted%20image%2020250129155215.png)

Let's run an initial scan to check the size:

`ffuf -w /opt/useful/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u http://admin.academy.htb:49384/admin/admin.php?FUZZ=key -fs xxx`

![Pasted image 20250129155534.png](../../../../IMAGES/Pasted%20image%2020250129155534.png)

We need to use `-fs 798`:

`ffuf -w /opt/useful/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u http://admin.academy.htb:49384/admin/admin.php?FUZZ=key -fs 798 -ic -c`

```
$ ffuf -w /opt/useful/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u http://admin.academy.htb:49384/admin/admin.php?FUZZ=key -fs 798 -ic -c

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://admin.academy.htb:49384/admin/admin.php?FUZZ=key
 :: Wordlist         : FUZZ: /opt/useful/seclists/Discovery/Web-Content/burp-parameter-names.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 798
________________________________________________

user                    [Status: 200, Size: 783, Words: 221, Lines: 54, Duration: 77ms]
```

We got the parameter: `user`

