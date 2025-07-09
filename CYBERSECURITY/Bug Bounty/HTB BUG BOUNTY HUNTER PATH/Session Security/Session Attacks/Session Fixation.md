Session Fixation occurs when an attacker can fixate a (valid) session identifier. As you can imagine, the attacker will then have to trick the victim into logging into the application using the aforementioned session identifier. If the victim does so, the attacker can proceed to a Session Hijacking attack (since the session identifier is already known).

Such bugs usually occur when session identifiers (such as cookies) are being accepted fromÂ _URL Query Strings_Â orÂ _Post Data_Â (more on that in a bit).

Session Fixation attacks are usually mounted in three stages:

```ad-important
**Stage 1: Attacker manages to obtain a valid session identifier**

Authenticating to an application is not always a requirement to get a valid session identifier, and a large number of applications assign valid session identifiers to anyone who browses them. This also means that an attacker can be assigned a valid session identifier without having to authenticate.

**Note**: An attacker can also obtain a valid session identifier by creating an account on the targeted application (if this is a possibility).

**Stage 2: Attacker manages to fixate a valid session identifier**

The above is expected behavior, but it can turn into a session fixation vulnerability if:

- The assigned session identifier pre-login remains the same post-loginÂ `and`
- Session identifiers (such as cookies) are being accepted fromÂ _URL Query Strings_Â orÂ _Post Data_Â and propagated to the application

If, for example, a session-related parameter is included in the URL (and not on the cookie header) and any specified value eventually becomes a session identifier, then the attacker can fixate a session.

**Stage 3: Attacker tricks the victim into establishing a session using the abovementioned session identifier**

All the attacker has to do is craft a URL and lure the victim into visiting it. If the victim does so, the web application will then assign this session identifier to the victim.

The attacker can then proceed to a session hijacking attack since the session identifier is already known.
```

---

## Session Fixation Example

Proceed to the end of this section and click onÂ `Click here to spawn the target system!`Â or theÂ `Reset Target`Â icon. Use the provided Pwnbox or a local VM with the supplied VPN key to reach the target application and follow along. Don't forget to configure the specified vhost (`oredirect.htb.net`) to access the application.

**Part 1: Session fixation identification**

Navigate toÂ `oredirect.htb.net`. You will come across a URL of the below format:

`http://oredirect.htb.net/?redirect_uri=/complete.html&token=<RANDOM TOKEN VALUE>`

Using Web Developer Tools (Shift+Ctrl+I in the case of Firefox), notice that the application uses a session cookie namedÂ `PHPSESSID`Â and that the cookie's value is the same as theÂ `token`Â parameter's value on the URL.

![image](https://academy.hackthebox.com/storage/modules/153/18.png)

If any value or a valid session identifier specified in theÂ `token`Â parameter on the URL is propagated to theÂ `PHPSESSID`Â cookie's value, we are probably dealing with a session fixation vulnerability.

Let us see if that is the case, as follows.

**Part 2: Session fixation exploitation attempt**

Open aÂ `New Private Window`Â and navigate toÂ `http://oredirect.htb.net/?redirect_uri=/complete.html&token=IControlThisCookie`

Using Web Developer Tools (Shift+Ctrl+I in the case of Firefox), notice that theÂ `PHPSESSID`Â cookie's value isÂ `IControlThisCookie`

![image](https://academy.hackthebox.com/storage/modules/153/19.png)

We are dealing with a Session Fixation vulnerability. An attacker could send a URL similar to the above to a victim. If the victim logs into the application, the attacker could easily hijack their session since the session identifier is already known (the attacker fixated it).

**Note**: Another way of identifying this is via blindly putting the session identifier name and value in the URL and then refreshing.

For example, suppose we are looking intoÂ `http://insecure.exampleapp.com/login`Â for session fixation bugs, and the session identifier being used is a cookie namedÂ `PHPSESSID`. To test for session fixation, we could try the followingÂ `http://insecure.exampleapp.com/login?PHPSESSID=AttackerSpecifiedCookieValue`Â and see if the specified cookie value is propagated to the application (as we did in this section's lab exercise).

Below is the vulnerable code of this section's lab exercise.

```php
<?php
    if (!isset($_GET["token"])) {
        session_start();
        header("Location: /?redirect_uri=/complete.html&token=" . session_id());
    } else {
        setcookie("PHPSESSID", $_GET["token"]);
    }
?>
```

Let us break the above piece of code down.

```php
if (!isset($_GET["token"])) {
     session_start();
```

The above piece of code can be translated as follows: If theÂ _token_Â parameter hasn't been defined, start a session (generate and provide a valid session identifier).

```php
header("Location: /?redirect_uri=/complete.html&token=" . session_id());
```

The above piece of code can be translated as follows: Redirect the user toÂ `/?redirect_uri=/complete.html&token=`Â and then call theÂ _session_id()_Â function to appendÂ _session_id_Â onto the token value.

```php
 } else {
        setcookie("PHPSESSID", $_GET["token"]);
    }
```

The above piece of code can be translated as follows: If theÂ _token_Â parameter is already set (else statement), setÂ _PHPSESSID_Â to the value of theÂ _token_Â parameter. Any URL in the following formatÂ `http://oredirect.htb.net/?redirect_uri=/complete.html&token=AttackerSpecifiedCookieValue`Â will updateÂ _PHPSESSID_'s value with theÂ _token_Â parameter's value.

By now, we have covered session hijacking and session fixation. Moving forward, let us see some ways through which a bug bounty hunter or penetration tester can obtain valid session identifiers that can be then used to hijack a user's session.

# Question
---
![Pasted image 20250219122913.png](../../../../IMAGES/Pasted%20image%2020250219122913.png)

