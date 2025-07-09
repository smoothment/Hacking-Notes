# ENUMERATION
---

## OPEN PORTS
---


| PORT | SERVICE |
| :--- | :------ |
| 22 | ssh |
| 80 | http |

Seems like we only have a website located at port 80, let's try to fuzz and enumerate the website for further exploitation

## FUZZING
---

![Pasted image 20241213133810.png](../../IMAGES/Pasted%20image%2020241213133810.png)

Nothing useful when we tried to fuzz, let's have a look at the website:

![Pasted image 20241213133850.png](../../IMAGES/Pasted%20image%2020241213133850.png)

Source code doesn't have anything relevant too, since the hint said that we need to find the password for `A` we could suppose this is a ssh username. Let's use hydra and try to bruteforce:

```ad-hint

`hydra -l a -P /usr/share/wordlists/rockyou.txt 172.17.0.2 ssh`

#### Output


We were right, seems like these are some credentials for ssh:

`a`:`secret`
```




# RECONNAISSANCE
---

Once we've logged into ssh, we can see that we are indeed `a`'s user:

![Pasted image 20241213134210.png](../../IMAGES/Pasted%20image%2020241213134210.png)

Let's keep on searching since we have a ssh session:

![Pasted image 20241213134236.png](../../IMAGES/Pasted%20image%2020241213134236.png)

We're at `/home/a`, let's try to find anything useful:

![Pasted image 20241213134316.png](../../IMAGES/Pasted%20image%2020241213134316.png)

We have another user `spencer`, but the home of this user is empty too, after a while searching around the machine, I found something interesting, a `/srv/ftp` directory containing the following:

![Pasted image 20241213134505.png](../../IMAGES/Pasted%20image%2020241213134505.png)


# EXPLOITATION
---

A lot of password and keys are here, most interesting one would be the `hash_spencer.txt` one, let's read it:

![Pasted image 20241213134550.png](../../IMAGES/Pasted%20image%2020241213134550.png)

We got a `MD5` hash, let's decode it:

![Pasted image 20241213134640.png](../../IMAGES/Pasted%20image%2020241213134640.png)

I suppose this is `spencer` username password, let's switch users:

![Pasted image 20241213134714.png](../../IMAGES/Pasted%20image%2020241213134714.png)

And I was right, this was spencer's password, let's try to escalate privileges


# PRIVILEGE ESCALATION
---

## sudo -l

After using this command, we can see the following:

![Pasted image 20241213134815.png](../../IMAGES/Pasted%20image%2020241213134815.png)

We can run sudo on `/usr/bin/python3`, let's check what gtfobins have for us:


![Pasted image 20241213134855.png](../../IMAGES/Pasted%20image%2020241213134855.png)

we need to run the following command in order to get root access:

```ad-hint

`sudo /usr/bin/python3 -c 'import os; os.system("/bin/sh")'`


##### Output
---


Nice, we are root
```

This was a simple CTF, we don't need to read any flag, so, this is the end.

