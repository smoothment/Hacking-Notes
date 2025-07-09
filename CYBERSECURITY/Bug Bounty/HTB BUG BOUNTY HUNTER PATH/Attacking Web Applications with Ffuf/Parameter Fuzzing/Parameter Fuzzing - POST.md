---
sticker: lucide//code
---
The main difference betweenÂ `POST`Â requests andÂ `GET`Â requests is thatÂ `POST`Â requests are not passed with the URL and cannot simply be appended after aÂ `?`Â symbol.Â `POST`Â requests are passed in theÂ `data`Â field within the HTTP request. Check out theÂ [Web Requests](https://academy.hackthebox.com/module/details/35)Â module to learn more about HTTP requests.

To fuzz theÂ `data`Â field withÂ `ffuf`, we can use theÂ `-d`Â flag, as we saw previously in the output ofÂ `ffuf -h`. We also have to addÂ `-X POST`Â to sendÂ `POST`Â requests.

Tip: In PHP, "POST" data "content-type" can only accept "application/x-www-form-urlencoded". So, we can set that in "ffuf" with "`-H 'Content-Type: application/x-www-form-urlencoded'`".

So, let us repeat what we did earlier, but place ourÂ `FUZZ`Â keyword after theÂ `-d` flag:

```shell-session
smoothment@htb[/htb]$ ffuf -w /opt/useful/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php -X POST -d 'FUZZ=key' -H 'Content-Type: application/x-www-form-urlencoded' -fs xxx


        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.1.0-git
________________________________________________

 :: Method           : POST
 :: URL              : http://admin.academy.htb:PORT/admin/admin.php
 :: Wordlist         : FUZZ: /opt/useful/seclists/Discovery/Web-Content/burp-parameter-names.txt
 :: Header           : Content-Type: application/x-www-form-urlencoded
 :: Data             : FUZZ=key
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403
 :: Filter           : Response size: xxx
________________________________________________

id                      [Status: xxx, Size: xxx, Words: xxx, Lines: xxx]
<...SNIP...>
```

As we can see this time, we got a couple of hits, the same one we got when fuzzingÂ `GET`Â and another parameter, which isÂ `id`. Let's see what we get if we send aÂ `POST`Â request with theÂ `id`Â parameter. We can do that withÂ `curl`, as follows:


```shell-session
smoothment@htb[/htb]$ curl http://admin.academy.htb:PORT/admin/admin.php -X POST -d 'id=key' -H 'Content-Type: application/x-www-form-urlencoded'

<div class='center'><p>Invalid id!</p></div>
<...SNIP...>
```

As we can see, the message now saysÂ `Invalid id!`.

