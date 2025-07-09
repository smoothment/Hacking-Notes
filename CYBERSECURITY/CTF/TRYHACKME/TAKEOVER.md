# ENUMERATION
---



## OPEN PORTS
---


| PORT | SERVICE |
| :--- | :------ |
| 22   | ssh     |
| 80   | http    |
| 443  | https   |



# RECONNAISSANCE
---

We need to perform subdomain scan in the `futurevera.thm` target, let's begin by adding it to `/etc/hosts`:

```
echo 'IP futurevera.thm' | sudo tee -a /etc/hosts
```

Let's perform a scan with ffuf


```
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u http://futurevera.thm -H "Host: FUZZ.futurevera.thm" -mc 200,301,302 -fs 0 -t 100 -ic -c

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://futurevera.thm
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Header           : Host: FUZZ.futurevera.thm
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 100
 :: Matcher          : Response status: 200,301,302
 :: Filter           : Response size: 0
________________________________________________

portal                  [Status: 200, Size: 69, Words: 9, Lines: 2, Duration: 6432ms]
payroll                 [Status: 200, Size: 70, Words: 9, Lines: 2, Duration: 167ms]
```

We found another subdomains, let's check it out:


![Pasted image 20250331143446.png](../../IMAGES/Pasted%20image%2020250331143446.png)

![Pasted image 20250331144920.png](../../IMAGES/Pasted%20image%2020250331144920.png)

Since the page is only available through the internal VPN, we can check if it's vulnerable to `subdomain takeover`:

```
dig portal.futurevera.thm CNAME +short
dig payroll.futurevera.thm CNAME +short
```

No output occurs, so, this is not the intended path to take, maybe we missed something, for example, let's check the main page:

![Pasted image 20250331144822.png](../../IMAGES/Pasted%20image%2020250331144822.png)

Nothing interesting on here too, but, remember we got a `https` site, let's fuzz by `https` instead of `http`:

```
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u https://10.10.236.142 -H "Host: FUZZ.futurevera.thm" -mc 200,301,302 -fs 4605 -t 100 -ic -c

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : https://10.10.236.142
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.futurevera.thm
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 100
 :: Matcher          : Response status: 200,301,302
 :: Filter           : Response size: 4605
________________________________________________

support                 [Status: 200, Size: 1522, Words: 367, Lines: 34, Duration: 361ms]
blog                    [Status: 200, Size: 3838, Words: 1326, Lines: 81, Duration: 515ms]
```


We can go into `support.futurevera.thm`:

![Pasted image 20250331145623.png](../../IMAGES/Pasted%20image%2020250331145623.png)


# EXPLOITATION
---

The moment we enter the `support.futurevera.thm`, it says it uses a `self-signed` certificate, let's check it out:

![Pasted image 20250331145727.png](../../IMAGES/Pasted%20image%2020250331145727.png)

We find this, another subdomain hidden, let's add it too and check it out, we need to access this through port `80`:

![Pasted image 20250331150148.png](../../IMAGES/Pasted%20image%2020250331150148.png)

We got our flag:


```
flag{beea0d6edfcee06a59b83fb50ae81b2f}
```



