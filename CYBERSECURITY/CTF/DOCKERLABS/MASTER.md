# ENUMERATION


## OPEN PORTS

![Pasted image 20241024150357.png](../../IMAGES/Pasted%20image%2020241024150357.png)
Seems like this lab only has port 80 open, let's start with fuzzing an website enumeration
## FUZZING

![Pasted image 20241024150423.png](../../IMAGES/Pasted%20image%2020241024150423.png)
We found two interesting directories: `/wp-content` and `/wp-admin`, let's begin by checking the main website's source code to check if there's anything useful in it:

![Pasted image 20241024150525.png](../../IMAGES/Pasted%20image%2020241024150525.png)

When I read the source code, nothing useful was in it, so, let's try to check our directories mentioned previously

### WP-ADMIN

![Pasted image 20241024150738.png](../../IMAGES/Pasted%20image%2020241024150738.png)
Login page, URL seems interesting, let's turn on burp and try to exploit either a [LFI](../../Bug%20Bounty/Vulnerabilities/SERVER%20SIDE%20VULNERABILITIES/FILE%20INCLUSION%20VULNERABILITIES/LOCAL%20FILE%20INCLUSION%20(LFI).md), [SQLI](../../Bug%20Bounty/Vulnerabilities/SERVER%20SIDE%20VULNERABILITIES/INJECTIONS/SQLI/SQL%20INJECTION%20(SQLI).md), [XSS](../../Bug%20Bounty/Vulnerabilities/SERVER%20SIDE%20VULNERABILITIES/CROSS%20SITE%20SCRIPTING/CROSS%20SITE%20SCRIPTING%20(XSS).md) or any vulnerability that may be there on the website:

After trying the previous mentioned vulnerabilities, I couldn't get anything useful, so, I went back to the main site to check if I missed something and I found this:

![Pasted image 20241024151950.png](../../IMAGES/Pasted%20image%2020241024151950.png)

`wp-automatic 3.92.0` is vulnerable to `CVE-2024-27956` which consists of:

```ad-important
CVE-2024-27956: CVE-2024-27956 is a recently disclosed critical (CVSS score 9.8) SQL injection (SQLi) vulnerability in WP-Automatic plugin prior to version 3.92.1. Successfully exploitation of this vulnerability might allow the attackers to run arbitrary SQL queries, create new admin accounts or upload malicious files onto the compromise servers. This vulnerability has been reported as being actively exploited in the wild.

Symantec protects you from this threat, identified by the following:

File-based

 PHP.Backdoor.Trojan

Network-based

 Web Attack: WP-Automatic Plugin SQL Injection Vulnerability CVE-2024-27956
```

Seems like the WordPress site was indeed vulnerable to [SQLI](../../Bug%20Bounty/Vulnerabilities/SERVER%20SIDE%20VULNERABILITIES/INJECTIONS/SQLI/SQL%20INJECTION%20(SQLI).md), so, in order to make our CTF way more simple, I used the following exploit found on GitHub:

```ad-hint
exploit: [EXPLOIT](https://github.com/diego-tella/CVE-2024-27956-RCE)
```

This is an exploit created in python which automates the task of the SQLI, burp suite can also get the job done but it can be more tricky, so, let's just use the exploit:

![Pasted image 20241024152905.png](../../IMAGES/Pasted%20image%2020241024152905.png)

Nice, now we got an admin user and can go into the wp-admin panel, let's begin with the exploitation

# EXPLOITATION

First, let's log in to our new admin account:

![Pasted image 20241024153342.png](../../IMAGES/Pasted%20image%2020241024153342.png)

![Pasted image 20241024153357.png](../../IMAGES/Pasted%20image%2020241024153357.png)

Nice, now, next step should be installing some kind of plugin that will let us get a reverse shell in some kind of way, for this CTF I installed the `Advanced File Manager` plugin and activated it:

![Pasted image 20241024153705.png](../../IMAGES/Pasted%20image%2020241024153705.png)

Next step is to upload our reverse shell and get access to the machine:

![Pasted image 20241024153745.png](../../IMAGES/Pasted%20image%2020241024153745.png)
![Pasted image 20241024153938.png](../../IMAGES/Pasted%20image%2020241024153938.png)
Nice, let's get the shell:

![Pasted image 20241024154052.png](../../IMAGES/Pasted%20image%2020241024154052.png)
![Pasted image 20241024154058.png](../../IMAGES/Pasted%20image%2020241024154058.png)
```ad-important
STABILIZE SHELL: [[CyberSecurity/Commands/Shell Tricks/STABLE SHELL.md|stable shell]]
```


![Pasted image 20241024154226.png](../../IMAGES/Pasted%20image%2020241024154226.png)

Nice, now we have an stable shell, let's begin with privilege escalation!

# PRIVILEGE ESCALATION


Let's try our [tricks](../../LINUX/LINUX%20PRIVILEGE%20ESCALATION/BASIC%20PRIVESC%20IN%20LINUX.md) for PRIVESC, after trying some, this was some useful data I could gather:

## WWW-DATA SUDO -L

![Pasted image 20241024154334.png](../../IMAGES/Pasted%20image%2020241024154334.png)

User can run `/usr/bin/php`, let's look at [GTFOBINS](https://gtfobins.github.io/) to search if anything useful can be exploited:


![Pasted image 20241024154501.png](../../IMAGES/Pasted%20image%2020241024154501.png)

So, in order to escalate our privileges, we'd need to do the following:

```ad-important
1. CMD="/bin/bash" or CMD="/bin/sh" Personally, I prefer using bash instead of sh
2. sudo php -r "system('$CMD');"
```

But, we lack of the www-data password, so, we need to do a little pivoting in order to get root, let's enumerate the machine in order to look for users:

![Pasted image 20241024154801.png](../../IMAGES/Pasted%20image%2020241024154801.png)

We have 3 usernames, let's try to switch to user `pylon` exploiting that php privilege we have:

![Pasted image 20241024154901.png](../../IMAGES/Pasted%20image%2020241024154901.png)
Nice, now we are pylon, let's pivot to `mario`:

## PYLON SUDO -L

![Pasted image 20241024154949.png](../../IMAGES/Pasted%20image%2020241024154949.png)
Something interesting happens here, we found a file called: `pingusorpresita.sh` at `/home/mario` directory, let's try to read the file:


![Pasted image 20241024155135.png](../../IMAGES/Pasted%20image%2020241024155135.png)

We are unable to read it but we don't need to read it though, let's use the same technique as before, in this case, we need to use:

```ad-hint
command: `sudo -u mario /bin/bash /home/mario/pingusorpresita.sh`
```

![Pasted image 20241024155416.png](../../IMAGES/Pasted%20image%2020241024155416.png)

When I executed the script and gave it number 1, that happened, so, if we try injecting the following:

```ad-hint
command: `a[$(/bin/bash>&2)]`
```

We get access as Mario:

![Pasted image 20241024155614.png](../../IMAGES/Pasted%20image%2020241024155614.png)


## MARIO SUDO -L


![Pasted image 20241024155834.png](../../IMAGES/Pasted%20image%2020241024155834.png)

It goes the other way around, let's try the same thing as before:

![Pasted image 20241024160001.png](../../IMAGES/Pasted%20image%2020241024160001.png)

Nice, now the CTF is done!

