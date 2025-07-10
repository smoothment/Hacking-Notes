After discussing the basics of SSRF vulnerabilities, let us jump right into an example web application.

---

## Confirming SSRF

Looking at the web application, we are greeted with some generic text as well as functionality to schedule appointments:

 ![](https://academy.hackthebox.com/storage/modules/145/ssrf/ssrf_identify_1.png)

After checking the availability of a date, we can observe the following request in Burp:

![image](https://academy.hackthebox.com/storage/modules/145/ssrf/ssrf_identify_2.png)

As we can see, the request contains our chosen date and a URL in the parameter`dateserver`. This indicates that the web server fetches the availability information from a separate system determined by the URL passed in this POST parameter.

To confirm an SSRF vulnerability, let us supply a URL pointing to our system to the web application:

![image](https://academy.hackthebox.com/storage/modules/145/ssrf/ssrf_identify_3.png)

In a`netcat` listener, we can receive a connection, thus confirming SSRF:

```shell-session
smoothment@htb[/htb]$ nc -lnvp 8000

listening on [any] 8000 ...
connect to [172.17.0.1] from (UNKNOWN) [172.17.0.2] 38782
GET /ssrf HTTP/1.1
Host: 172.17.0.1:8000
Accept: */*
```

To determine whether the HTTP response reflects the SSRF response to us, let us point the web application to itself by providing the URL`http://127.0.0.1/index.php`:

![image](https://academy.hackthebox.com/storage/modules/145/ssrf/ssrf_identify_4.png)

Since the response contains the web application's HTML code, the SSRF vulnerability is not blind, i.e., the response is displayed to us.

---

## Enumerating the System

We can use the SSRF vulnerability to conduct a port scan of the system to enumerate running services. To achieve this, we need to be able to infer whether a port is open or not from the response to our SSRF payload. If we supply a port that we assume is closed (such as`81`), the response contains an error message:

![image](https://academy.hackthebox.com/storage/modules/145/ssrf/ssrf_identify_5.png)

This enables us to conduct an internal port scan of the web server through the SSRF vulnerability. We can do this using a fuzzer like`ffuf`. Let us first create a wordlist of the ports we want to scan. In this case, we'll use the first 10,000 ports:

```shell-session
smoothment@htb[/htb]$ seq 1 10000 > ports.txt
```

Afterward, we can fuzz all open ports by filtering out responses containing the error message we have identified earlier.


```shell-session
smoothment@htb[/htb]$ ffuf -w ./ports.txt -u http://172.17.0.2/index.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "dateserver=http://127.0.0.1:FUZZ/&date=2024-01-01" -fr "Failed to connect to"

<SNIP>

[Status: 200, Size: 45, Words: 7, Lines: 1, Duration: 0ms]
 * FUZZ: 3306
[Status: 200, Size: 8285, Words: 2151, Lines: 158, Duration: 338ms]
 * FUZZ: 80
```

The results show that the web server runs a service on port`3306`, typically used for a SQL database. If the web server ran other internal services, such as internal web applications, we could also identify and access them through the SSRF vulnerability.

# Question
----

![Pasted image 20250210181120.png](../../../../IMAGES/Pasted%20image%2020250210181120.png)

Let's check the website:

![Pasted image 20250210181150.png](../../../../IMAGES/Pasted%20image%2020250210181150.png)

We find this is we check the website for a while:

![Pasted image 20250210181131.png](../../../../IMAGES/Pasted%20image%2020250210181131.png)

Let's check the request in burp:

![Pasted image 20250210182951.png](../../../../IMAGES/Pasted%20image%2020250210182951.png)

We can see something weird in the request, a `dateserver` parameter that makes a call to a resource called `availabilty.php`, let's try changing that to make a call to the localhost and check if the request gets passed through us:

![Pasted image 20250211142012.png](../../../../IMAGES/Pasted%20image%2020250211142012.png)


We got a flag surprisingly, flag is: 

```
HTB{911fc5badf7d65aed95380d536c270f8}
```
