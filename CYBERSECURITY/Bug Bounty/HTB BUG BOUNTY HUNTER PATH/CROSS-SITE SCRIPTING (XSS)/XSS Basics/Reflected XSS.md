---
sticker: lucide//code
---
There are two types ofÂ `Non-Persistent XSS`Â vulnerabilities:Â `Reflected XSS`, which gets processed by the back-end server, andÂ `DOM-based XSS`, which is completely processed on the client-side and never reaches the back-end server. Unlike Persistent XSS,Â `Non-Persistent XSS`Â vulnerabilities are temporary and are not persistent through page refreshes. Hence, our attacks only affect the targeted user and will not affect other users who visit the page.

`Reflected XSS`Â vulnerabilities occur when our input reaches the back-end server and gets returned to us without being filtered or sanitized. There are many cases in which our entire input might get returned to us, like error messages or confirmation messages. In these cases, we may attempt using XSS payloads to see whether they execute. However, as these are usually temporary messages, once we move from the page, they would not execute again, and hence they areÂ `Non-Persistent`.

We can start the server below to practice on a web page vulnerable to a Reflected XSS vulnerability. It is a similarÂ `To-Do List`Â app to the one we practiced with in the previous section. We can try adding anyÂ `test`Â string to see how it's handled:

Â Â Â 

![](https://academy.hackthebox.com/storage/modules/103/xss_reflected_1.jpg)

As we can see, we getÂ `Task 'test' could not be added.`, which includes our inputÂ `test`Â as part of the error message. If our input was not filtered or sanitized, the page might be vulnerable to XSS. We can try the same XSS payload we used in the previous section and clickÂ `Add`:

Â Â Â 

![](https://academy.hackthebox.com/storage/modules/103/xss_reflected_2.jpg)

Once we clickÂ `Add`, we get the alert pop-up:

Â Â Â 

![](https://academy.hackthebox.com/storage/modules/103/xss_stored_xss_alert.jpg)

In this case, we see that the error message now saysÂ `Task '' could not be added.`. Since our payload is wrapped with aÂ `<script>`Â tag, it does not get rendered by the browser, so we get empty single quotesÂ `''`Â instead. We can once again view the page source to confirm that the error message includes our XSS payload:


```html
<div></div><ul class="list-unstyled" id="todo"><div style="padding-left:25px">Task '<script>alert(window.origin)</script>' could not be added.</div></ul>
```

As we can see, the single quotes indeed contain our XSS payloadÂ `'<script>alert(window.origin)</script>'`.

If we visit theÂ `Reflected`Â page again, the error message no longer appears, and our XSS payload is not executed, which means that this XSS vulnerability is indeedÂ `Non-Persistent`.

`But if the XSS vulnerability is Non-Persistent, how would we target victims with it?`

This depends on which HTTP request is used to send our input to the server. We can check this through the FirefoxÂ `Developer Tools`Â by clicking [`CTRL+Shift+I`] and selecting theÂ `Network`Â tab. Then, we can put ourÂ `test`Â payload again and clickÂ `Add`Â to send it:

Â Â Â 

![](https://academy.hackthebox.com/storage/modules/103/xss_reflected_network.jpg)

As we can see, the first row shows that our request was aÂ `GET`Â request.Â `GET`Â request sends their parameters and data as part of the URL. So,Â `to target a user, we can send them a URL containing our payload`. To get the URL, we can copy the URL from the URL bar in Firefox after sending our XSS payload, or we can right-click on theÂ `GET`Â request in theÂ `Network`Â tab and selectÂ `Copy>Copy URL`. Once the victim visits this URL, the XSS payload would execute:

Â Â Â 

![](https://academy.hackthebox.com/storage/modules/103/xss_stored_xss_alert.jpg)


# Question
---
![Pasted image 20250130163930.png](../../../../IMAGES/Pasted%20image%2020250130163930.png)

We simply need to use:

```js
<script>alert(document.cookie)</script>
```

![Pasted image 20250130163936.png](../../../../IMAGES/Pasted%20image%2020250130163936.png)

Flag is `HTB{r3fl3c73d_b4ck_2_m3}`


