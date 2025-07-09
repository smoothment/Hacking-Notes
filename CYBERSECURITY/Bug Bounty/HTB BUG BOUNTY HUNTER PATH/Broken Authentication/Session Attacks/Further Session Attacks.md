After discussing how to attack session tokens, we will now understand two attack vectors against flawed handling of session tokens in web applications.

More advanced session attacks, such as Session Puzzling, are covered in theÂ [Abusing HTTP Misconfigurations](https://academy.hackthebox.com/module/details/189)Â module.

---

## Session Fixation

[Session Fixation](https://owasp.org/www-community/attacks/Session_fixation)Â is an attack that enables an attacker to obtain a victim's valid session. A web application vulnerable to session fixation does not assign a new session token after a successful authentication. If an attacker can coerce the victim into using a session token chosen by the attacker, session fixation enables an attacker to steal the victim's session and access their account.

For instance, assume a web application vulnerable to session fixation uses a session token in the HTTP cookieÂ `session`. Furthermore, the web application sets the user's session cookie to a value provided in theÂ `sid`Â GET parameter. Under these circumstances, a session fixation attack could look like this:

1. An attacker obtains a valid session token by authenticating to the web application. For instance, let us assume the session token isÂ `a1b2c3d4e5f6`. Afterward, the attacker invalidates their session by logging out.
    
2. The attacker tricks the victim to use the known session token by sending the following link:Â `http://vulnerable.htb/?sid=a1b2c3d4e5f6`. When the victim clicks this link, the web application sets theÂ `session`Â cookie to the provided value, i.e., the response looks like this:
    


```http
HTTP/1.1 200 OK
[...]
Set-Cookie: session=a1b2c3d4e5f6
[...]
```

1. The victim authenticates to the vulnerable web application. The victim's browser already stores the attacker-provided session cookie, so it is sent along with the login request. The victim uses the attacker-provided session token since the web application does not assign a new one.
    
2. Since the attacker knows the victim's session tokenÂ `a1b2c3d4e5f6`, they can hijack the victim's session.
    

A web application must assign a new randomly generated session token after successful authentication to prevent session fixation attacks.

---

## Improper Session Timeout

Lastly, a web application must define a properÂ [Session Timeout](https://owasp.org/www-community/Session_Timeout)Â for a session token. After the time interval defined in the session timeout has passed, the session will expire, and the session token is no longer accepted. If a web application does not define a session timeout, the session token would be valid infinitely, enabling an attacker to use a hijacked session effectively forever.

For the security of a web application, the session timeout must be appropriately set. Because each web application has different business requirements, there is no universal session timeout value.Â For instance, a web application dealing with sensitive health data shouldÂ probablyÂ set a session timeout in the range of minutes.Â In contrast, a social media web application might set a session timeout of multiple hours.
