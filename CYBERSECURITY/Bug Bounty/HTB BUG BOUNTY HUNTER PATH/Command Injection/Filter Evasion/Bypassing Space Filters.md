There are numerous ways to detect injection attempts, and there are multiple methods to bypass these detections. We will be demonstrating the concept of detection and how bypassing works using Linux as an example. We will learn how to utilize these bypasses and eventually be able to prevent them. Once we have a good grasp on how they work, we can go through various sources on the internet to discover other types of bypasses and learn how to mitigate them.

---

## Bypass Blacklisted Operators

We will see that most of the injection operators are indeed blacklisted. However, the new-line character is usually not blacklisted, as it may be needed in the payload itself. We know that the new-line character works in appending our commands both in Linux and on Windows, so let's try using it as our injection operator:Â 

![Filter Operator](https://academy.hackthebox.com/storage/modules/109/cmdinj_filters_operator.jpg)

As we can see, even though our payload did include a new-line character, our request was not denied, and we did get the output of the ping command,Â `which means that this character is not blacklisted, and we can use it as our injection operator`. Let us start by discussing how to bypass a commonly blacklisted character - a space character.

---

## Bypass Blacklisted Spaces

Now that we have a working injection operator, let us modify our original payload and send it again as (`127.0.0.1%0a whoami`):

![Filter Space](https://academy.hackthebox.com/storage/modules/109/cmdinj_filters_spaces_1.jpg)

As we can see, we still get anÂ `invalid input`Â error message, meaning that we still have other filters to bypass. So, as we did before, let us only add the next character (which is a space) and see if it caused the denied request:Â 

![Filter Space](https://academy.hackthebox.com/storage/modules/109/cmdinj_filters_spaces_2.jpg)

As we can see, the space character is indeed blacklisted as well. A space is a commonly blacklisted character, especially if the input should not contain any spaces, like an IP, for example. Still, there are many ways to add a space character without actually using the space character!

#### Using Tabs

Using tabs (%09) instead of spaces is a technique that may work, as both Linux and Windows accept commands with tabs between arguments, and they are executed the same. So, let us try to use a tab instead of the space character (`127.0.0.1%0a%09`) and see if our request is accepted:Â 

![Filter Space](https://academy.hackthebox.com/storage/modules/109/cmdinj_filters_spaces_3.jpg)

As we can see, we successfully bypassed the space character filter by using a tab instead. Let us see another method of replacing space characters.

#### Using $IFS

Using the ($IFS) Linux Environment Variable may also work since its default value is a space and a tab, which would work between command arguments. So, if we use ${IFS}Â where the spaces should be, the variable should be automatically replaced with a space, and our command should work.

Let us useÂ `${IFS}`Â and see if it works (`127.0.0.1%0a${IFS}`):Â 

![Filter Space](https://academy.hackthebox.com/storage/modules/109/cmdinj_filters_spaces_4.jpg)

We see that our request was not denied this time, and we bypassed the space filter again.

#### Using Brace Expansion

There are many other methods we can utilize to bypass space filters. For example, we can use theÂ `Bash Brace Expansion`Â feature, which automatically adds spaces between arguments wrapped between braces, as follows:

Â Â Bypassing Space Filters

```shell-session
smoothment@htb[/htb]$ {ls,-la}

total 0
drwxr-xr-x 1 21y4d 21y4d   0 Jul 13 07:37 .
drwxr-xr-x 1 21y4d 21y4d   0 Jul 13 13:01 ..
```

As we can see, the command was successfully executed without having spaces in it. We can utilize the same method in command injection filter bypasses, by using brace expansion on our command arguments, like (`127.0.0.1%0a{ls,-la}`). To discover more space filter bypasses, check out theÂ [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection#bypass-without-space)Â page on writing commands without spaces.

**Exercise:**Â Try to look for other methods for bypassing space filters, and use them with theÂ `Host Checker`Â web application to learn how they work.

# Question
---

![Pasted image 20250205141609.png](../../../../IMAGES/Pasted%20image%2020250205141609.png)

We can use the following:

```
127.0.0.1%0a{ls,-la}
```

We will see this:

```
PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.
64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.013 ms

--- 127.0.0.1 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.013/0.013/0.013/0.000 ms
total 16
drwxr-xr-x 1 www-data www-data 4096 Jul 16  2021 .
drwxr-xr-x 1 www-data www-data 4096 Aug 19  2020 ..
-rw-r--r-- 1 www-data www-data 1613 Jul 16  2021 index.php
-rw-r--r-- 1 www-data www-data 1256 Jul 12  2021 style.css
```

Answer is `1613`.

