# ENUMERATION
---

## OPEN PORTS
---


| PORT | SERVICE |
| :--- | :------ |
| 22 | ssh |
| 80 | http |

Let's visit the website:

![Pasted image 20250104153239.png](../../IMAGES/Pasted%20image%2020250104153239.png)

We need to add `linkvortex.htb` to `/etc/hosts`:

![Pasted image 20250104153434.png](../../IMAGES/Pasted%20image%2020250104153434.png)

Seems like a simple page, let's take a look at source code:


![Pasted image 20250104153824.png](../../IMAGES/Pasted%20image%2020250104153824.png)

Nothing useful, but, we know this machine has `robots.txt` so, let's check it:

![Pasted image 20250104162318.png](../../IMAGES/Pasted%20image%2020250104162318.png)

We found useful stuff, let's begin with fuzzing


## FUZZING
---

When we try to fuzz in the standard way, we encounter that we are unable to fuzz in this way: `http://URL/FUZZ`, so, i thought we need to fuzz for subdomains instead of directories like we always do, let's use the following ffuf command: 

```ad-hint

`ffuf -c -u http://TARGET_URL/ -H "Host: FUZZ.TARGET_URL" -w /path/to/wordlist.txt -fc 301`

#### Key points

- The -fc 301 flag filters out http 301 redirects, keeping results relevant.
- Subdomain enumeration can reveal hidden environments like `subdomain.linkvortex.htb`
```


Let's fuzz:

![Pasted image 20250104154221.png](../../IMAGES/Pasted%20image%2020250104154221.png)

We found something interesting!

`dev.linkvortex.htb`


Also, we found `linkvortex.htb/ghost/#/signin`

Let's visit the page and start with reconnaissance

# RECONNAISSANCE
---
![Pasted image 20250104154412.png](../../IMAGES/Pasted%20image%2020250104154412.png)

Let's use dirsearch on the `linkvortex.htb/ghost/#/signin` page, in order to find anything useful, we can use it in the following way:

```ad-hint

`python3 dirsearch.py -u linkvortex.htb -t 50 -i 200`


We found the same as before, we already know this website has `ghost`, if we deep in further, we find this page has `ghost 5.58`:

```


Nice, now, we can use a tool called `GitHack` to read the directories from the `dev.linkvortex.htb` subdomain, let's use it like this:

```ad-hint
`python3 GitHack.py -u http://dev.linkvortex.htb/.git/`


This will attempt to download a bunch of git files, after the process is done, we can find some interesting files such as the one located at:

`dev.linkvortex.htb/ghost/core/test/regression/api/admin`


We found an `authentication.test.js` file, let's read it: 


We found some credentials, since this is the admin api, we must think that the email is structured in the following way: `Username@linkvortex.htb`, so, our credentials would be: 

`admin@linkvortex.htb`:`OctopiFociPilfer45`
```

Let's log into the signin site we found:

![Pasted image 20250104163833.png](../../IMAGES/Pasted%20image%2020250104163833.png)
# EXPLOITATION
---


Nice, we got initial access to the CMS, now, let's search for an exploit for this version, we know this site is running `ghost 5.58`:

```ad-hint

Exploit: [CVE-2023-40028](https://github.com/0xyassine/CVE-2023-40028/blob/master/CVE-2023-40028.sh)
```

For this version, we can find the `CVE-2023-40028` which states the following:

```ad-summary
CVE-2023-40028 affects Ghost, an open source content management system, where versions prior to 5.59.1 allow authenticated users to upload files that are symlinks. This can be exploited to perform an arbitrary file read of any file on the host operating system. It is recommended that site administrators check for exploitation of this issue by looking for unknown symlinks within Ghost's content/ folder. Version 5.59.1 contains a fix for this issue, and there are no known workarounds.

- CVE ID: CVE-2023-40028
- CVSS Score: 6.5 Medium
- Affected Software: Ghost versions before 5.59.1
- Fixed in Version: Ghost 5.59.1

```

So, we need an authenticated user in order to be able to use the exploit, how lucky of us, let's download it and use it in the following way:

```ad-hint

`./CVE-2023-40028.sh -u admin@linkvortex.htb -p OctopiFociPilfer45`

(We need to change the ghost url before using the script)

Once we've used it, we get the following:


We can now read files, after i read `/etc/passwd` file, nothing useful was in it, so, after a exhausting search, I found that at `/var/lib/config.production.json` some essential info was on it, which was the following:



```

We found some ssh credentials!: `bob@linkvortex.htb`:`fibber-talented-worth`

Let's log in and read the user flag:

![Pasted image 20250104165752.png](../../IMAGES/Pasted%20image%2020250104165752.png)

![Pasted image 20250104165804.png](../../IMAGES/Pasted%20image%2020250104165804.png)

User flag is: `5048fa21aa685472d4bb3b6dbf5e59d4`

Now, let's proceed with privilege escalation.

# PRIVILEGE ESCALATION
---


### sudo -l


We can run sudo on the following:

![Pasted image 20250104165954.png](../../IMAGES/Pasted%20image%2020250104165954.png)

Let's read the file to know what we're dealing with:

![Pasted image 20250104170040.png](../../IMAGES/Pasted%20image%2020250104170040.png)

We can use the following in order to read root flag:

```ad-hint

1. `ln -s /root/root.txt hyh.txt`
2. `ln -s /home/bob/hyh.txt hyh.png`
3. `sudo CHECK_CONTENT=true /usr/bin/bash /opt/ghost/clean_symlink.sh /home/bob/hyh.png`


### PoC


We were able to read the root flag, which is: `dd348008c17143e2472558713ca807f1`
```

Just like that, machine is done!

