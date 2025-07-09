![Pasted image 20250128151552.png](../../../IMAGES/Pasted%20image%2020250128151552.png)

# 1
---

Let's begin by adding `inlanefreight.htb` to `/etc/hosts`:

`echo '94.237.50.221 inlanefreight.htb' | sudo tee -a /etc/hosts`

Now, in order to find the IANA ID of the registrar we can use whois and grep for IANA ID:

``
`whois inlanefreight.com | grep 'IANA ID'`

![Pasted image 20250128151814.png](../../../IMAGES/Pasted%20image%2020250128151814.png)

Answer is `468`


# 2
---

We can use `curl` or `whatweb` in order to check the software name:

![Pasted image 20250128152330.png](../../../IMAGES/Pasted%20image%2020250128152330.png)

Answer is `nginx`

# 3
---

Now, the next step would be VHOST discovery, let's use this command:

`gobuster vhost -u http://inlanefreight.htb:56641 -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt --append-domain -t 100`

After scan is done, we can see the following virtual host:

![Pasted image 20250128152734.png](../../../IMAGES/Pasted%20image%2020250128152734.png)

```
gobuster vhost -u http://inlanefreight.htb:56641 -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt --append-domain -t 100
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:             http://inlanefreight.htb:56641
[+] Method:          GET
[+] Threads:         100
[+] Wordlist:        /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
[+] User Agent:      gobuster/3.6
[+] Timeout:         10s
[+] Append Domain:   true
===============================================================
Starting gobuster in VHOST enumeration mode
===============================================================
Found: web1337.inlanefreight.htb:56641 Status: 200 [Size: 104]
Progress: 114441 / 114442 (100.00%)
===============================================================
Finished
=========
```

Let's add that to `/etc/hosts` too, let's grab the banners:

![Pasted image 20250128152938.png](../../../IMAGES/Pasted%20image%2020250128152938.png)

Seems nice, since the question talks about a hidden admin directory, we can check if the entry to `robots.txt` is allowed:

![Pasted image 20250128153034.png](../../../IMAGES/Pasted%20image%2020250128153034.png)

We found it! `/admin_h1dd3n`, let's check it out:


`curl -i web1337.inlanefreight.htb:56641/admin_h1dd3n/`


![Pasted image 20250128153202.png](../../../IMAGES/Pasted%20image%2020250128153202.png)

We got the API: `e963d863ee0e82ba7080fbf558ca0d3f`

# 4
---
Following the string from the previous question, we've already found another VHOST, let's keep on enumerating them using the following:

`gobuster vhost -u http://web1337.inlanefreight.htb:56641 -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt --append-domain -t 100`:

![Pasted image 20250128153615.png](../../../IMAGES/Pasted%20image%2020250128153615.png)

We found another VHOST:

```
gobuster vhost -u http://web1337.inlanefreight.htb:56641 -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt --append-domain -t 100
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:             http://web1337.inlanefreight.htb:56641
[+] Method:          GET
[+] Threads:         100
[+] Wordlist:        /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
[+] User Agent:      gobuster/3.6
[+] Timeout:         10s
[+] Append Domain:   true
===============================================================
Starting gobuster in VHOST enumeration mode
===============================================================
Found: dev.web1337.inlanefreight.htb:56641 Status: 200 [Size: 123]
```

Let's add it to `/etc/hosts`, we can crawl using reconspider:

```ad-hint
1. `python3 ReconSpider.py http://dev.web1337.inlanefreight.htb:56641`
2. `cat results.json | grep -A 2 '"emails"' | grep -oP '"[^"]+@[^"]+"'`
```

```ad-important
#### Explanation of grep command
---

- `cat results.json` - Displays the contents of the file.
- `grep -A 2 '"emails"'` - Searches for the `"emails"` key and prints the next two lines after it (adjust `-A` as necessary if the email appears further away).
- `grep -oP '"[^"]+@[^"]+"'` - Extracts only the email address:
    - `-o` prints only the matching part.
    - `-P` enables Perl-compatible regex, which allows advanced patterns.
    - `'"[^"]+@[^"]+"'` matches an email enclosed in double quotes.

```

We get the following output:

![Pasted image 20250128154144.png](../../../IMAGES/Pasted%20image%2020250128154144.png)

Answer is: `1337testing@inlanefreight.htb`

# 5
---

We can find the API key in the same `results.json` file given by reconspider:

`cat results.json | grep API`

![Pasted image 20250128154248.png](../../../IMAGES/Pasted%20image%2020250128154248.png)

Answer is: `ba988b835be4aa97d068941dc852ff33`



Just like that, skills assessment is done.
