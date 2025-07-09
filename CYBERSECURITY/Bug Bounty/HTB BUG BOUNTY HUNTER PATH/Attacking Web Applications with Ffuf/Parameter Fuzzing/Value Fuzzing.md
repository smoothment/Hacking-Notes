---
sticker: lucide//code
---
After fuzzing a working parameter, we now have to fuzz the correct value that would return theÂ `flag`Â content we need. This section will discuss fuzzing for parameter values, which should be fairly similar to fuzzing for parameters, once we develop our wordlist.

---

## Custom Wordlist

When it comes to fuzzing parameter values, we may not always find a pre-made wordlist that would work for us, as each parameter would expect a certain type of value.

For some parameters, like usernames, we can find a pre-made wordlist for potential usernames, or we may create our own based on users that may potentially be using the website. For such cases, we can look for various wordlists under theÂ `seclists`Â directory and try to find one that may contain values matching the parameter we are targeting. In other cases, like custom parameters, we may have to develop our own wordlist. In this case, we can guess that theÂ `id`Â parameter can accept a number input of some sort. These ids can be in a custom format, or can be sequential, like from 1-1000 or 1-1000000, and so on. We'll start with a wordlist containing all numbers from 1-1000.

There are many ways to create this wordlist, from manually typing the IDs in a file, or scripting it using Bash or Python. The simplest way is to use the following command in Bash that writes all numbers from 1-1000 to a file:

Â Â Value Fuzzing

```shell-session
smoothment@htb[/htb]$ for i in $(seq 1 1000); do echo $i >> ids.txt; done
```

Once we run our command, we should have our wordlist ready:

Â Â Value Fuzzing

```shell-session
smoothment@htb[/htb]$ cat ids.txt

1
2
3
4
5
6
<...SNIP...>
```

Now we can move on to fuzzing for values.

---

## Value Fuzzing

Our command should be fairly similar to theÂ `POST`Â command we used to fuzz for parameters, but ourÂ `FUZZ`Â keyword should be put where the parameter value would be, and we will use theÂ `ids.txt`Â wordlist we just created, as follows:

Â Â Value Fuzzing

```shell-session
smoothment@htb[/htb]$ ffuf -w ids.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php -X POST -d 'id=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded' -fs xxx


        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v1.0.2
________________________________________________

 :: Method           : POST
 :: URL              : http://admin.academy.htb:30794/admin/admin.php
 :: Header           : Content-Type: application/x-www-form-urlencoded
 :: Data             : id=FUZZ
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403
 :: Filter           : Response size: xxx
________________________________________________

<...SNIP...>                      [Status: xxx, Size: xxx, Words: xxx, Lines: xxx]
```

We see that we get a hit right away. We can finally send anotherÂ `POST`Â request usingÂ `curl`, as we did in the previous section, use theÂ `id`Â value we just found, and collect the flag.

# Question
---
![Pasted image 20250129160543.png](../../../../IMAGES/Pasted%20image%2020250129160543.png)

So, we need to create the `ids.txt` wordlist, let's use the following command:

`for i in $(seq 1 1000); do echo $i >> ids.txt; done`

![Pasted image 20250129160645.png](../../../../IMAGES/Pasted%20image%2020250129160645.png)

We can do `wc -l ids.txt` to check that indeed it has 1000 elements. 

Let's proceed with the fuzzing:

`ffuf -w ids.txt:FUZZ -u http://admin.academy.htb:49384/admin/admin.php -X POST -d 'id=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded'`

![Pasted image 20250129160803.png](../../../../IMAGES/Pasted%20image%2020250129160803.png)

Let's filter out by size 768: `-fs 768`:

`ffuf -w ids.txt:FUZZ -u http://admin.academy.htb:49384/admin/admin.php -X POST -d 'id=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded' -fs 768 -ic `

```
ffuf -w ids.txt:FUZZ -u http://admin.academy.htb:49384/admin/admin.php -X POST -d 'id=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded' -fs 768 -ic -c 

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : POST
 :: URL              : http://admin.academy.htb:49384/admin/admin.php
 :: Wordlist         : FUZZ: /home/htb-ac-1340293/ids.txt
 :: Header           : Content-Type: application/x-www-form-urlencoded
 :: Data             : id=FUZZ
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 768
________________________________________________

73                      [Status: 200, Size: 787, Words: 218, Lines: 54, Duration: 77ms]
```

We got it, `73`, let's use curl now in order to collect the flag:

`curl http://admin.academy.htb:49384/admin/admin.php -X POST -d 'id=73' -H 'Content-Type: application/x-www-form-urlencoded' -s | grep HTB{`

```
curl http://admin.academy.htb:49384/admin/admin.php -X POST -d 'id=73' -H 'Content-Type: application/x-www-form-urlencoded' -s | grep HTB{
<div class='center'><p>HTB{p4r4m373r_fuzz1n6_15_k3y!}</p></div>
```

Flag is: `HTB{p4r4m373r_fuzz1n6_15_k3y!}`

