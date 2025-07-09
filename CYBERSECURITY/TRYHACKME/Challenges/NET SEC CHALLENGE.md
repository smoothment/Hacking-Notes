---
sticker: lucide//wifi
---


### What is the highest port number being open less than 10,000?

---
![Pasted image 20241112135121.png](../../IMAGES/Pasted%20image%2020241112135121.png)

Highest open port is `8080`

### There is an open port outside the common 1000 ports; it is above 10,000. What is it?
---


![Pasted image 20241112135224.png](../../IMAGES/Pasted%20image%2020241112135224.png)

It is port `10021`


### What is the flag hidden in the HTTP server header?
---
```ad-hint
### Used

`curl -I http://IP`

### Output



```


Flag is `THM{web_server_25352}`

### What is the flag hidden in the SSH server header?

---

```ad-hint


### Used

`nc -v IP 22`

### Output



```

Flag is `THM{946219583339}

### We have an FTP server listening on a nonstandard port. What is the version of the FTP server?
---

```ad-hint

### Used

`nc IP nonstandard-port`

### Output



```

 Version is `(vsFTPd 3.0.5)`

### We learned two usernames using social engineering:Â `eddie`Â andÂ `quinn`. What is the flag hidden in one of these two account files and accessible via FTP?
---


First, we need to perform a Hydra attack to get the password of both usernames, let's start with `eddie`

#### Eddie


```ad-hint

### Used

`hydra -l eddie -P /usr/share/wordlists/rockyou.txt ftp -s 10021`

We need to use -s flag to specify the non-standard port

### Output



```



Let's log into ftp with our credentials to check if we are able to retrieve the flag:

![Pasted image 20241112140445.png](../../IMAGES/Pasted%20image%2020241112140445.png)

Nothing useful, let's proceed with the other username

#### Quinn

```ad-hint

### Used

`hydra -l quinn -P /usr/share/wordlists/rockyou.txt ftp -s 10021`


### Output


```

Let's log into ftp and get our flag:

![Pasted image 20241112140700.png](../../IMAGES/Pasted%20image%2020241112140700.png)

Reading the flag, we get this:

![Pasted image 20241112140744.png](../../IMAGES/Pasted%20image%2020241112140744.png)

So, flag is `THM{321452667098}`


### Browsing toÂ `http://10.10.4.229:8080` displays a small challenge that will give you a flag once you solve it. What is the flag?
---

![Pasted image 20241112140846.png](../../IMAGES/Pasted%20image%2020241112140846.png)

So, using our notes from [nmap advanced port scans](../../RECONNAISSANCE/NMAP/ADVANCED%20PORT%20SCANS.md), we can perform a IDS evasion scan in the following way:



```ad-hint

### Example of a stealthy nmap scan

`sudo nmap -sS -T0 -D RND:5 -f --scan-delay 1s --max-retries 1 -p 21,22,80,443 IP`

### Explanation of the scan

Hereâ€™s a full, stealthy Nmap scan command you can try. This will:

- Use sudo as this scan needs root privileges!
- Use SYN scan (`-sS`).
- Slow down the scan using `-T0`.
- Add 5 random decoy IPs with `-D RND:5`.
- Fragment packets with `-f` to evade detection.
- Use a 1-second delay between each scan probe.


### What do we need for this room?

For this room, we just need to use a `Null Scan`, to perform this, we send the following nmap:

`sudo nmap -sN IP`

#### What is a Null Scan?

A **TCP Null scan** is a type of scan where Nmap sends a **TCP packet** with **no flags set** in the TCP header. In other words, it sends a packet with the flags field set to `0x0000` (no flags like SYN, ACK, FIN, etc., are set). The idea behind this scan is to attempt to bypass certain firewalls and packet filters that are configured to detect and block more common scan types like SYN scans.


### Output from Null Scan




```




Once we send the scan and reset the packet count, which is shown in the page, we get flag `THM{f7443f99}`



# END!

