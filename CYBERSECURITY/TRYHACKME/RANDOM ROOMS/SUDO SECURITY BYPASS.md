# CVE-2019-14287
---


CVE-2019-14287 is a vulnerability found in the Unix Sudo program by a researcher working for Apple: Joe Vennix. Coincidentally, he also found the vulnerability that we'll be covering in the next room of this series. This exploit has since been fixed, but may still be present in older versions of Sudo (versions < 1.8.28), so it's well worth keeping an eye out for!

For those who might be unfamiliar with it: sudo is a command in Unix that allows you to execute programs as other users. This usually defaults to the superuser (root), but it's also possible to execute programs as other users by specifying their username or UID. For example, sudo would usually be used like so:`sudo <command>`, but you could manually choose to execute it as another user like this:`sudo -u#<id> <command>`. This means that you would be pretending to be another user when you executed the chosen command, which can give you higher permissions than you might otherwise have had. As an example:

![](https://muirlandoracle.co.uk/wp-content/uploads/2020/02/sudo-demo.png) 

In this example my user account did not have permission to read the file`/root/root.txt`,so I used sudo to temporarily give myself root privileges, in order to read the file. 

Like many commands on Unix systems, sudo can be configured by editing a configuration file on your system. In this case that file is called`/etc/sudoers`. Editing this file directly is not recommended due to its importance to the OS installation, however, you can safely edit it with the command`sudo visudo`, which checks when you're saving to ensure that there are no misconfigurations. 

The vulnerability we're interested in for this task occurs in a very particular scenario. Say you have a user who you want to grant extra permissions to. You want to let this user execute a program as if they were any other user, but you _don't_ want to let them execute it as root. You might add this line to the sudoers file:

`<user> ALL=(ALL:!root) NOPASSWD: ALL`

This would let your user execute any command as another user, but would (theoretically) prevent them from executing the command as the superuser/admin/root. In other words, you can pretend to be any user, except from the admin. 

Theoretically.

In practice, with vulnerable versions of Sudo you can get around this restriction to execute the programs as root anyway, which is obviously great for privilege escalation!

With the above configuration, using`sudo -u#0 <command>` (the UID of root is always 0) would not work, as we're not allowed to execute commands as root. If we try to execute commands as user 0 we will be given an error. Enter CVE-2019-14287.

Joe Vennix found that if you specify a UID of -1 (or its unsigned equivalent: 4294967295), Sudo would incorrectly read this as being 0 (i.e. root). This means that by specifying a UID of -1 or 4294967295, you can execute a command as root, _despite being explicitly prevented from doing so_. It is worth noting that this will _only_ work if you've been granted non-root sudo permissions for the command, as in the configuration above.

Practically, the application of this is as follows:`sudo -u#-1 <command>`

![](https://muirlandoracle.co.uk/wp-content/uploads/2020/02/capture.png)

---

Now it's your turn. 

SSH into that machine you deployed earlier, **using port 2222**.

The credentials are:

```ad-note
Username: tryhackme 
Password: tryhackme
```

If you're using Linux, the command will look like this:

`ssh -p 2222 tryhackme@10.10.242.137`


## Questions
---

![Pasted image 20250106150752.png](../../IMAGES/Pasted%20image%2020250106150752.png)

Let's use sudo -l to check what command we are allowed to run:

![Pasted image 20250106150821.png](../../IMAGES/Pasted%20image%2020250106150821.png)

We are allowed to run `/bin/bash`


Now, in order to read the flag, we must perform the vulnerability in the following way:

```ad-hint
1. We can get a root session by passing in the following command: `sudo -u \#$((0xffffffff)) /bin/bash`, which can actually be: `sudo -u \#-1 /bin/bash`

#### Output


So, root flag would be: 


`THM{l33t_s3cur1ty_bypass}`
```
