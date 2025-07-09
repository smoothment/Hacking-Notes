User enumeration vulnerabilities arise when a web application responds differently to registered/valid and invalid inputs for authentication endpoints. User enumeration vulnerabilities frequently occur in functions based on the user's username, such as user login, user registration, and password reset.

Web developers frequently overlook user enumeration vectors, assuming that information such as usernames is not confidential. However, usernames can be considered confidential if they are the primary identifier required for authentication in web applications. Moreover, users tend to use the same username across various services other than web applications, including FTP, RDP, and SSH. Since many web applications allow us to identify usernames, we can enumerate valid usernames and use them for further attacks on authentication. This is often possible because web applications typically consider a username or user's email address as the primary identifier of users.

---

## User Enumeration Theory

Protection against username enumeration attacks can have an impact on user experience. A web application revealing whether a username exists may help a legitimate user identify that they failed to type their username correctly. Still, the same applies to an attacker trying to determine valid usernames. Even well-known and mature applications, like WordPress, allow for user enumeration by default. For instance, if we attempt to login to WordPress with an invalid username, we get the following error message:

Â Â Â 

![](https://academy.hackthebox.com/storage/modules/269/bf/01-wordpress_wrong_username.png)

On the other hand, a valid username results in a different error message:

Â Â Â 

![](https://academy.hackthebox.com/storage/modules/269/bf/02-wordpress_wrong_password.png)

As we can see, user enumeration can be a security risk that a web application deliberately accepts to provide a service. As another example, consider a chat application enabling users to chat with others. This application might provide a functionality to search for users by their username. While this functionality can be used to enumerate all users on the platform, it is also essential to the service provided by the web application. As such, user enumeration is not always a security vulnerability.Â Nevertheless, it should be avoidedÂ if possibleÂ as a defense-in-depth measure. For instance, in our example web application user enumeration can be avoided by not using the username during login but an email address instead.

---

## Enumerating Users via Differing Error Messages

To obtain a list of valid users, an attacker typically requires a wordlist of usernames to test. Usernames are often far less complicated than passwords. They rarely contain special characters when they are not email addresses. A list of common users allows an attacker to narrow the scope of a brute-force attack or carry out targeted attacks (leveraging OSINT) against support employees or users. Also, a common password could be easily sprayed against valid accounts, often leading to a successful account compromise. Further ways of harvesting usernames are crawling a web application or using public information, such as company profiles on social networks. A good starting point is the wordlist collectionÂ [SecLists](https://github.com/danielmiessler/SecLists/tree/master/Usernames).Â 

When we attempt to log in to the lab with an invalid username such asÂ `abc`, we can see the following error message:

Â Â Â 

![](https://academy.hackthebox.com/storage/modules/269/bf/userenum_1.png)

On the other hand, when we attempt to log in with a registered user such asÂ `htb-stdnt`Â and an invalid password, we can see a different error:

Â Â Â 

![](https://academy.hackthebox.com/storage/modules/269/bf/userenum_2.png)

Let us exploit this difference in error messages returned and useÂ SecLists'sÂ wordlistÂ `xato-net-10-million-usernames.txt`Â to enumerate valid users withÂ `ffuf`. We can specify the wordlist with theÂ `-w`Â parameter, the POST data with theÂ `-d`Â parameter, and the keywordÂ `FUZZ`Â in the username to fuzz valid users. Finally, we can filter out invalid users by removing responses containing the stringÂ `Unknown user`:

```shell-session
smoothment@htb[/htb]$ ffuf -w /opt/useful/seclists/Usernames/xato-net-10-million-usernames.txt -u http://172.17.0.2/index.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "username=FUZZ&password=invalid" -fr "Unknown user"

<SNIP>

[Status: 200, Size: 3271, Words: 754, Lines: 103, Duration: 310ms]
    * FUZZ: consuelo
```

We successfully identified the valid usernameÂ `consuelo`.Â We couldÂ nowÂ proceed by attempting to brute-force the user's password, as we will discuss in the following section.

---

## User Enumeration via Side-Channel Attacks

While differences in the web application's response are the simplest and most obvious way to enumerate valid usernames, weÂ mightÂ alsoÂ be able toÂ enumerate valid usernames via side channels.Â Side-channel attacks do not directly target the web application's response but rather extra information that can be obtained or inferred from the response. An example of a side channel is the response timing, i.e., the time it takes for the web application's response to reach us. Suppose a web application does database lookups only for valid usernames.Â In that case, weÂ might be able toÂ measure a difference in the response time and enumerate valid usernames this way, even if the response is the same.Â User enumeration based on response timing is covered in theÂ [Whitebox Attacks](https://academy.hackthebox.com/module/details/205)Â module.

# Question
---

![Pasted image 20250214143442.png](../../../../IMAGES/Pasted%20image%2020250214143442.png)

We need to authenticate with the following credentials:

```ad-note
`htb-stdnt`:`Academy_student!`
```

Before doing that, let's fire up burp and check what happens if we enter a nonexistent user:

![Pasted image 20250214143851.png](../../../../IMAGES/Pasted%20image%2020250214143851.png)

We get `Unknown User`, which would be the error message in this case, how about if we try to authenticate with the provided username but a wrong password:

![Pasted image 20250214143942.png](../../../../IMAGES/Pasted%20image%2020250214143942.png)

Now we are getting something different, we get `Invalid Credentials`.

We can fuzz the usernames using `ffuf`, let's do the following command:

```
ffuf -w /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt -u http://IP:PORT/index.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "username=FUZZ&password=test" -fr "Unknown user" -ic -c -t 200
```

After a while, we get the following:

```
ffuf -w /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt -u http://83.136.248.78:36443/index.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "username=FUZZ&password=test" -fr "Unknown user" -ic -c -t 200

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : POST
 :: URL              : http://83.136.248.78:36443/index.php
 :: Wordlist         : FUZZ: /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt
 :: Header           : Content-Type: application/x-www-form-urlencoded
 :: Data             : username=FUZZ&password=test
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 200
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Regexp: Unknown user
________________________________________________

cookster                [Status: 200, Size: 3271, Words: 754, Lines: 103, Duration: 1311ms]
```

User is:

```
cookster
```

