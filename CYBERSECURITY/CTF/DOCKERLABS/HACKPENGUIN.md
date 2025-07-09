# ENUMERATION


## OPEN PORTS

![Pasted image 20241025170752.png](../../IMAGES/Pasted%20image%2020241025170752.png)

```ad-hint
OPEN PORTS

- 22: ssh
- 80: http
```

So, seems like a simple machine with only 2 open ports, let's enumerate our website

## FUZZING
### GOBUSTER FUZZING:

![Pasted image 20241025170908.png](../../IMAGES/Pasted%20image%2020241025170908.png)

Let's look at the page and its source code:

![Pasted image 20241025171151.png](../../IMAGES/Pasted%20image%2020241025171151.png)
Simple Apache page, source code ain't got something useful too, let's search within the directories found by gobuster:

### PENGUIN.HTML

![Pasted image 20241025171257.png](../../IMAGES/Pasted%20image%2020241025171257.png)

#### SOURCE CODE:

![Pasted image 20241025171316.png](../../IMAGES/Pasted%20image%2020241025171316.png)

Nothing interesting too, except from the `penguin.jpg` file, let's download it and try to use [steghide](https://steghide.sourceforge.net/) to get any important info out of it:

![Pasted image 20241025171924.png](../../IMAGES/Pasted%20image%2020241025171924.png)

We lack the passphrase, let's crack it using [stegseek](https://github.com/RickdeJager/stegseek):

```ad-hint
stegseek command: `stegseek penguin.jpg /usr/share/wordlists/rockyou.txt`
```


![Pasted image 20241025172143.png](../../IMAGES/Pasted%20image%2020241025172143.png)


![Pasted image 20241025172227.png](../../IMAGES/Pasted%20image%2020241025172227.png)

Seems like we got a `keepass password database 2.x` inside of the image, let's keep with the exploitation


# EXPLOITATION

To start with the exploitation, we must need to crack that file we got, for this, we will use a specific module of john the ripper called: `keepass2john`, let's look at the usage:

```ad-hint
usage for this ctf: `keepass2john penguin.kdbx > penguin.txt`
```

Now, once we have the output file, let's crack it with john:

```ad-hint
used: `john penguin.txt --wordlist=/usr/share/wordlists/rockyou.txt`

OUTPUT:


```

Seems like we were able to crack it correctly, let's go into keepass and get valuable info:

```ad-hint
command: `keepass penguin.kdbx`

OUTPUT (After passing in password):




```

So, we found user `pinguino` and its password, being the following:

```ad-note
`pinguino`:`pinguinomaravilloso123`
```

Let's go inside of ssh and begin our privilege escalation:

![Pasted image 20241025173238.png](../../IMAGES/Pasted%20image%2020241025173238.png)
Oops, we cannot log in, this is because, the password is not for user `pinguino` but user `penguin`, so, correct credentials would be the following:

```ad-note
CORRECT CREDENTIALS:

`penguin`:`pinguinomaravilloso123`
```

![Pasted image 20241025173357.png](../../IMAGES/Pasted%20image%2020241025173357.png)

And now we're in, let's proceed with PRIVESC

# PRIVILEGE ESCALATION


When we first log in, we find two files:

![Pasted image 20241025173540.png](../../IMAGES/Pasted%20image%2020241025173540.png)

`archivo.txt` and `script.sh`, first files says:

```ad-note
archivo.txt: `pinguino no hackeable`
```

So, nothing useful in it, what we are interested in, is second file, which is a bash file and we can write in it:

```ad-note 
script.sh: 

#!/bin/bash
echo 'pinguino no hackeable' > archivo.txt`
```

## GETTING OUR ROOT SHELL

If we use `ps -aux | grep root` to list for processes used for user root, we find the following:

```ad-important

# BREAKDOWN OF ps -aux | grep root

The command `ps -aux | grep root` is used to **list processes owned by the root user**. Hereâ€™s a breakdown of each part:

1. **`ps -aux`**: This part of the command displays a list of all running processes, showing details like the user, process ID (PID), CPU and memory usage, start time, and command for each process.
    
    - `a`: Shows processes for all users.
    - `u`: Displays the process list in a user-friendly format.
    - `x`: Lists processes without a controlling terminal (background processes).
2. **`| grep root`**: This **filters the output** to show only lines containing the word `root`. Essentially, this limits the displayed processes to those owned by the `root` user or processes that happen to have "root" in their command or description.
    

### Example Output

The output will look something like this:




`root       1  0.0  0.2  22572  2820 ?        Ss   Oct20   0:04 /sbin/init root     562  0.1  1.0 124428 10240 ?        Ssl  Oct20   0:50 /usr/sbin/sshd root     892  0.0  0.5  56728  5624 ?        Ss   Oct20   0:20 /usr/sbin/crond`

Each line represents a process running as the `root` user, with columns indicating:

- **User** (`root` here),
- **PID** (process ID),
- **%CPU** and **%MEM** (CPU and memory usage),
- **Command** (the command that started the process).

This command is useful for checking which `root` processes are active, especially in scenarios where you might be debugging privilege escalation attempts or investigating system services.

```

![Pasted image 20241025174633.png](../../IMAGES/Pasted%20image%2020241025174633.png)

User root, actually runs the script seen previously, so, in order to get our privileged shell, we would need to edit the `script.sh` file in the following way:

```ad-important

`chmod u+s /bin/bash`

# Explanation
The command `chmod u+s /bin/bash` sets the **SUID** (Set User ID) bit on the `/bin/bash` executable, which can have significant security implications. Hereâ€™s how it works:

1. **Sets the SUID Permission**: The **SUID** bit (symbolized by `u+s`) tells the system that whenever this program is executed, it should run with the privileges of its owner (which is `root` in this case).
    
2. **Root-Level Shell for Any User**: By applying `chmod u+s /bin/bash`, youâ€™re configuring `bash` so that any user who runs `/bin/bash` will automatically run it with **root privileges**. This allows any user to spawn a root shell just by typing `bash`.
    
3. **Permissions Result**: After setting this, youâ€™ll see the `s` permission bit added to the file when you check it with `ls -l /bin/bash`:
    
    
    `-rwsr-xr-x 1 root root 123456 Oct 25 12:34 /bin/bash`
    
    The `s` in `rws` indicates that the SUID bit is set for the user (owner).
    
4. **Security Risk**: This is a major security risk on any system, as it effectively gives **root access to anyone** with access to the system. Usually, the SUID bit is set only on specific binaries that require elevated privileges for certain tasks (like `/bin/passwd` for changing passwords).
```

Once we've added this into the file, we would only need to do `bash -p` to get our shell:

![Pasted image 20241025174906.png](../../IMAGES/Pasted%20image%2020241025174906.png)

Nice, now the CTF is done!



