---
sticker: lucide//curly-braces
---

`HTML Injection`Â vulnerabilities can often be utilized to also performÂ [Cross-Site Scripting (XSS)](https://owasp.org/www-community/attacks/xss/)Â attacks by injectingÂ `JavaScript`Â code to be executed on the client-side. Once we can execute code on the victim's machine, we can potentially gain access to the victim's account or even their machine.Â `XSS`Â is very similar toÂ `HTML Injection`Â in practice. However,Â `XSS`Â involves the injection ofÂ `JavaScript`Â code to perform more advanced attacks on the client-side, instead of merely injecting HTML code. There are three main types ofÂ `XSS`:

|Type|Description|
|---|---|
|`Reflected XSS`|Occurs when user input is displayed on the page after processing (e.g., search result or error message).|
|`Stored XSS`|Occurs when user input is stored in the back end database and then displayed upon retrieval (e.g., posts or comments).|
|`DOM XSS`|Occurs when user input is directly shown in the browser and is written to anÂ `HTML`Â DOM object (e.g., vulnerable username or page title).|

In the example we saw forÂ `HTML Injection`, there was no input sanitization whatsoever. Therefore, it may be possible for the same page to be vulnerable toÂ `XSS`Â attacks. We can try to inject the followingÂ `DOM XSS`Â `JavaScript`Â code as a payload, which should show us the cookie value for the current user:

Code:Â javascript

```javascript
#"><img src=/ onerror=alert(document.cookie)>
```

Once we input our payload and hitÂ `ok`, we see that an alert window pops up with the cookie value in it:

![HTML Example](https://academy.hackthebox.com/storage/modules/75/web_apps_xss_2.jpg)

This payload is accessing theÂ `HTML`Â document tree and retrieving theÂ `cookie`Â object's value. When the browser processes our input, it will be considered a newÂ `DOM`, and ourÂ `JavaScript`Â will be executed, displaying the cookie value back to us in a popup.

An attacker can leverage this to steal cookie sessions and send them to themselves and attempt to use the cookie value to authenticate to the victim's account. The same attack can be used to perform various types of other attacks against a web application's users.Â `XSS`Â is a vast topic that will be covered in-depth in later modules.

# Question

![Pasted image 20250122182255.png](../../../../IMAGES/Pasted%20image%2020250122182255.png)

We can submit the following payload:

`<img src=/ onerror=alert(document.cookie)>`

![Pasted image 20250122182531.png](../../../../IMAGES/Pasted%20image%2020250122182531.png)

We got the cookie: `XSSisFun`
