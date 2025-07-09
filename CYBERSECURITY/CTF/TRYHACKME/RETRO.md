# ENUMERATION
---



## OPEN PORTS
---


| PORT | SERVICE |
| :--- | :------ |
| 80 | HTTP |
| 3389 | RDP |



# RECONNAISSANCE
---


![Pasted image 20250529165619.png](../../IMAGES/Pasted%20image%2020250529165619.png)

This is a windows server website, let's fuzz to check if anything's hidden on here:


```
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u "http://retro.thm/FUZZ" -ic -c -t 200

 /'___\ /'___\ /'___\
 /\ \__/ /\ \__/ __ __ /\ \__/
 \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
 \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
 \ \_\ \ \_\ \ \____/ \ \_\
 \/_/ \/_/ \/___/ \/_/

 v2.1.0-dev
________________________________________________

 :: Method : GET
 :: URL : http://retro.thm/FUZZ
 :: Wordlist : FUZZ: /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt
 :: Follow redirects : false
 :: Calibration : false
 :: Timeout : 10
 :: Threads : 200
 :: Matcher : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

retro [Status: 301, Size: 146, Words: 9, Lines: 2, Duration: 231ms]
```

We found `/retro`, let's check it out:


![Pasted image 20250529165840.png](../../IMAGES/Pasted%20image%2020250529165840.png)


At first sight, we can notice there's an user named `wade`, if we check the page of this user we can see some posts he made and a comment too, if we check the comment, we can see this:

![Pasted image 20250529170039.png](../../IMAGES/Pasted%20image%2020250529170039.png)


We can also see a login page on here:

![Pasted image 20250529170114.png](../../IMAGES/Pasted%20image%2020250529170114.png)

This is a WordPress site, specifically a `wordpress 5.2.1` site, I got access after testing the following credentials:

```
wade:parzival
```

![Pasted image 20250529170318.png](../../IMAGES/Pasted%20image%2020250529170318.png)


Let's proceed to exploitation.


# EXPLOITATION
---


Well, enumeration took a big step since we didn't have to do anything special to get access to the admin panel, we can get a shell using the old trick of editing the `404.php` theme on `theme editor`, although, the shell truly does not work at all, we can get a `webshell` to work with that, but it's pretty uncomfortable, that's when remembering our port scan, we remember we have access to `rdp`, we can go into `rdp` with the same credentials:

```
xfreerdp /u:wade /p:parzival /v:10.10.20.116 /cert:ignore +clipboard
```

![Pasted image 20250529172124.png](../../IMAGES/Pasted%20image%2020250529172124.png)

As seen, we got our first flag on here:

```
3b99fbdc6d430bfb51c72c651a261927
```


Let's begin privilege escalation.



# PRIVILEGE ESCALATION
---


From here, we can guide ourselves on the hint provided by the room:

![Pasted image 20250529172223.png](../../IMAGES/Pasted%20image%2020250529172223.png)

## First Path (Not Recomended)

After checking stuff for some time, we can find this on google chrome's history search:


![Pasted image 20250529172314.png](../../IMAGES/Pasted%20image%2020250529172314.png)

User was searching about `CVE-2019-1388`, let's take a look at this cve:

![Pasted image 20250529172423.png](../../IMAGES/Pasted%20image%2020250529172423.png)

On the recycle bin, we can find this:

![Pasted image 20250529172748.png](../../IMAGES/Pasted%20image%2020250529172748.png)

There it is, let's restore it and do the following in order to get a root as shell:

Open the file as administrator:

![Pasted image 20250529172843.png](../../IMAGES/Pasted%20image%2020250529172843.png)

Once we get the UAC prompt, we need to go to `Show more details` and `Show more information about the publisher's certificate`:

![Pasted image 20250529172929.png](../../IMAGES/Pasted%20image%2020250529172929.png)

A new window will be open, on here we can see information about the certificate, what we need to do next is to click on the `Issued by` link:

![Pasted image 20250529173017.png](../../IMAGES/Pasted%20image%2020250529173017.png)

![Pasted image 20250529173037.png](../../IMAGES/Pasted%20image%2020250529173037.png)

If we cannot choose between IE and Chrome, we need to open both IE and CHROME and closing it before doing all this, this is why the `not recommended` part is, it is kind of bugged and even after doing all that you may not be able to get the chosing prompt, if you're able to get it, you need to do:

```
CTRL+S

Go to: C:\Windows\system32
Open cmd.exe # You will receive a cmd as administrator
```


## Second path


Now, the easiest and the path that works almost every time, we need to exploit `CVE-2017-0213`, let's go with this GitHub exploit

https://github.com/SecWiki/windows-kernel-exploits/blob/master/CVE-2017-0213/CVE-2017-0213_x64.zip


Download it and unzip it:


![Pasted image 20250529174902.png](../../IMAGES/Pasted%20image%2020250529174902.png)

As seen, we get a `.exe` file, we need to host a python server on our Linux machine and access it through chrome on our rdp session:

![Pasted image 20250529174956.png](../../IMAGES/Pasted%20image%2020250529174956.png)

Now, download the file and execute it:


![Pasted image 20250529175025.png](../../IMAGES/Pasted%20image%2020250529175025.png)

![Pasted image 20250529175035.png](../../IMAGES/Pasted%20image%2020250529175035.png)

![Pasted image 20250529175045.png](../../IMAGES/Pasted%20image%2020250529175045.png)

We got a shell as `nt authority\system` and can now read root flag;

![Pasted image 20250529175207.png](../../IMAGES/Pasted%20image%2020250529175207.png)

We got our flag:

```
7958b569565d7bd88d10c6f22d1c4063
```

![Pasted image 20250529175333.png](../../IMAGES/Pasted%20image%2020250529175333.png)

