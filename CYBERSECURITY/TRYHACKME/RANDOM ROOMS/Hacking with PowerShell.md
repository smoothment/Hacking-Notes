# Introduction
---

Before completing this room, you should be aware of some fundamentals. For example, the differences between CMD, PS and some syntax. This room will cover the following:

- What is Powershell
- Basic Powershell commands
- Windows enumeration skills
- Powershell scripting

You can control the machine in your browser or RDP into the instance with the following credentials:

![THM Key Credentials](https://tryhackme-images.s3.amazonaws.com/user-uploads/63588b5ef586912c7d03c4f0/room-content/be629720b11a294819516c1d4e738c92.png)

| | |
| ------------ | ------------- |
| **Username** | Administrator |
| **Password** | BHN2UVw0Q |
| **IP** | MACHINE_IP |



# What is Powershell?
---

Powershell is the Windows Scripting Language and shell environment built using the .NET framework.

This also allows Powershell to execute .NET functions directly from its shell. Most Powershell commands, called _cmdlets,_ are written in .NET. Unlike other scripting languages and shell environments, the output of these _cmdlets_ are objects - making Powershell somewhat object-oriented.

This also means that running cmdlets allows you to perform actions on the output object (which makes it convenient to pass output from one _cmdlet_ to another). The normal format of a _cmdlet_ is represented using **Verb-Noun**; for example, the _cmdlet_ to list commands is called `Get-Command`

Common verbs to use include:

- Get
- Start
- Stop - Read
- Write
- New
- Out

To get the complete list of approved verbs, visit [this](https://docs.microsoft.com/en-us/powershell/scripting/developer/cmdlet/approved-verbs-for-windows-powershell-commands?view=powershell-7) link.

![Pasted image 20250530131518.png](../../IMAGES/Pasted%20image%2020250530131518.png)


# Basic Powershell Commands
---

Now that we've understood how _cmdlets_ work - let's explore how to use them! The main thing to remember here is that `Get-Command` and `Get-Help` are your best friends! ## Using Get-Help

`Get-Help` displays information about a _cmdlet._ To get help with a particular command, run the following:

`Get-Help Command-Name`

You can also understand how exactly to use the command by passing in the `-examples` flag. This would return output like the following:

```powershell
Get-Help Get-Command -Examples

NAME
 Get-Command

SYNOPSIS
Gets all commands.

Example 1: Get cmdlets, functions, and aliases

PS C:\>Get-Command
```


## Using Get-Command

`Get-Command` gets all the _cmdlets_ installed on the current Computer. The great thing about this _cmdlet_ is that it allows for pattern matching like the following

`Get-Command Verb-*` or `Get-Command *-Noun`

Running `Get-Command New-*` to view all the _cmdlets_ for the verb new displays the following:


```powershell
Get-Command New-*

CommandType Name Version Source
----------- ---- ------- ------
Alias New-AWSCredentials 3.3.563.1 AWSPowerShell
Alias New-EC2FlowLogs 3.3.563.1 AWSPowerShell
Alias New-EC2Hosts 3.3.563.1 AWSPowerShell
Alias New-RSTags 3.3.563.1 AWSPowerShell
Alias New-SGTapes 3.3.563.1 AWSPowerShell
Function New-AutologgerConfig 1.0.0.0 EventTracingManagement
Function New-DAEntryPointTableItem 1.0.0.0 DirectAccessClientComponents
Function New-DscChecksum 1.1 PSDesiredStateConfiguration
Function New-EapConfiguration 2.0.0.0 VpnClient
Function New-EtwTraceSession 1.0.0.0 EventTracingManagement
Function New-FileShare 2.0.0.0 Storage
Function New-Fixture 3.4.0 Pester
Function New-Guid 3.1.0.0 Microsoft.PowerShell.Utility
--cropped for brevity--
```

## Object Manipulation

In the previous task, we saw how the output of every _cmdlet_ is an object. If we want to manipulate the output, we need to figure out a few things:

- passing the output to other _cmdlets_
- using specific object _cmdlets_ to extract information

The Pipeline(`|`) is used to pass output from one _cmdlet_ to another. A major difference compared to other shells is that Powershell passes an object to the next _cmdlet_ instead of passing text or string to the command after the pipe. Like every object in object-oriented frameworks, an object will contain methods and properties.

You can think of methods as functions that can be applied to output from the _cmdlet,_ and you can think of properties as variables in the output from a _cmdlet_. To view these details, pass the output of a _cmdlet_ to the `Get-Member` _cmdlet:_

`Verb-Noun | Get-Member` An example of running this to view the members for `Get-Command` is:

`Get-Command | Get-Member -MemberType Method`

```powershell
Get-Command | Get-Member -MemberType Method


 TypeName: System.Management.Automation.AliasInfo

Name MemberType Definition
---- ---------- ----------
Equals Method bool Equals(System.Object obj)
GetHashCode Method int GetHashCode()
GetType Method type GetType()
ResolveParameter Method System.Management.Automation.ParameterMetadata ResolveParameter(string name)
ToString Method string ToString()


 TypeName: System.Management.Automation.FunctionInfo

Name MemberType Definition
---- ---------- ----------
Equals Method bool Equals(System.Object obj)
GetHashCode Method int GetHashCode()
GetType Method type GetType()
ResolveParameter Method System.Management.Automation.ParameterMetadata ResolveParameter(string name)
ToString Method string ToString()


 TypeName: System.Management.Automation.CmdletInfo

Name MemberType Definition
---- ---------- ----------
Equals Method bool Equals(System.Object obj)
GetHashCode Method int GetHashCode()
GetType Method type GetType()
ResolveParameter Method System.Management.Automation.ParameterMetadata ResolveParameter(string name)
ToString Method string ToString()

```

From the above flag in the command, you can see that you can also select between methods and properties.

## Creating Objects From Previous _cmdlets_

One way of manipulating objects is pulling out the properties from the output of a _cmdlet_ and creating a new object. This is done using the `Select-Object` _cmdlet._ Here's an example of listing the directories and just selecting the mode and the name:

```powershell
Get-ChildItem | Select-Object -Property Mode, Name
Mode Name
---- ----
d-r--- Contacts
d-r--- Desktop
d-r--- Documents
d-r--- Downloads
d-r--- Favorites
d-r--- Links
d-r--- Music
d-r--- Pictures
d-r--- Saved Games
d-r--- Searches
d-r--- Videos
```

You can also use the following flags to select particular information:

- first - gets the first x object
- last - gets the last x object
- unique - shows the unique objects
- skip - skips x objects

## Filtering Objects

When retrieving output objects, you may want to select objects that match a very specific value. You can do this using the `Where-Object` to filter based on the value of properties. The general format for using this _cmdlet_ is`Verb-Noun | Where-Object -Property PropertyName -operator Value`

`Verb-Noun | Where-Object {$_.PropertyName -operator Value}`

The second version uses the `$_` operator to iterate through every object passed to the `Where-Object` _cmdlet_.

**Powershell is quite sensitive, so don't put quotes around the command!**

Where `-operator` is a list of the following operators:

- `-Contains`: if any item in the property value is an exact match for the specified value
- `-EQ`: if the property value is the same as the specified value
- `-GT`: if the property value is greater than the specified value

For a full list of operators, use [this](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/where-object?view=powershell-6) link.

Here's an example of checking the stopped processes:

```powershell
Get-Service | Where-Object -Property Status -eq Stopped

Status Name DisplayName
------ ---- -----------
Stopped AJRouter AllJoyn Router Service
Stopped ALG Application Layer Gateway Service
Stopped AppIDSvc Application Identity
Stopped AppMgmt Application Management
Stopped AppReadiness App Readiness
Stopped AppVClient Microsoft App-V Client
Stopped AppXSvc AppX Deployment Service (AppXSVC)
Stopped AudioEndpointBu... Windows Audio Endpoint Builder
Stopped Audiosrv Windows Audio
Stopped AxInstSV ActiveX Installer (AxInstSV)
Stopped BITS Background Intelligent Transfer Ser...
Stopped Browser Computer Browser
Stopped bthserv Bluetooth Support Service
-- cropped for brevity--
```

## Sort-Object

When a _cmdlet_ outputs a lot of information, you may need to sort it to extract the information more efficiently. You do this by pipe-lining the output of a _cmdlet_ to the `Sort-Object` _cmdlet_.

The format of the command would be:

`Verb-Noun | Sort-Object`

Here's an example of sorting the list of directories:

```powershell
Get-ChildItem | Sort-Object
 Directory: C:\Users\Administrator
Mode LastWriteTime Length Name
---- ------------- ------ ----
d-r--- 10/3/2019 5:11 PM Contacts
d-r--- 10/5/2019 2:38 PM Desktop
d-r--- 10/3/2019 10:55 PM Documents
d-r--- 10/3/2019 11:51 PM Downloads
d-r--- 10/3/2019 5:11 PM Favorites
d-r--- 10/3/2019 5:11 PM Links
d-r--- 10/3/2019 5:11 PM Music
d-r--- 10/3/2019 5:11 PM Pictures
d-r--- 10/3/2019 5:11 PM Saved Games
d-r--- 10/3/2019 5:11 PM Searches
d-r--- 10/3/2019 5:11 PM Videos
```

Now that you've understood how Powershell works let's try some commands to apply this knowledge!

## Practical
----

We need to answer these questions:


![Pasted image 20250530132001.png](../../IMAGES/Pasted%20image%2020250530132001.png)

Let's begin by opening up `powershell`, once it opens, we can do:

```powershell
Get-ChildItem -Path C:\ -Include *interesting-file.txt* -File -Recurse -ErrorAction SilentlyContinue
```

![Pasted image 20250530133023.png](../../IMAGES/Pasted%20image%2020250530133023.png)

```
C:\Program Files
```

Once we find the path, we can do:

```powershell
Get-Content -Path "C:\Program Files\interesting-file.txt.txt" 
```

![Pasted image 20250530133137.png](../../IMAGES/Pasted%20image%2020250530133137.png)

```
notsointerestingcontent
```

To find how many cmdlets, we can do:

```powershell
(Get-Command -CommandType Cmdlet).Count
```

We get:

![Pasted image 20250530132725.png](../../IMAGES/Pasted%20image%2020250530132725.png)

```
6638
```


To get the `MD5` hash of the file:

```powershell
Get-FileHash -Path "C:\Program Files\interesting-file.txt.txt" -Algorithm MD5 | Select-Object -ExpandProperty Hash
```

![Pasted image 20250530133226.png](../../IMAGES/Pasted%20image%2020250530133226.png)

```
49A586A2A9456226F8A1B4CEC6FAB329 
```

To get the current working directory:

```powershel
Get-Location
```

We can test the path with:

```powershell
Test-Path "C:\Users\Administrator\Documents\Passwords"
```

![Pasted image 20250530132854.png](../../IMAGES/Pasted%20image%2020250530132854.png)

```
N
```

To make a request:

```powershell
Invoke-WebRequest
```

And finally, inside of the Administrator Desktop, we can do;

```powershell
[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String((Get-Content "b64.txt" -Raw)))
```

![Pasted image 20250530133430.png](../../IMAGES/Pasted%20image%2020250530133430.png)

```
ihopeyoudidthisonwindows
```


# Enumeration
---

The first step when you have gained initial access to any machine would be to enumerate. We'll be enumerating the following:

- users
- basic networking information
- file permissions
- registry permissions
- scheduled and running tasks
- insecure files

Your task will be to answer the following questions to enumerate the machine using Powershell commands!


## Practical
---

Let's do:

```powershell
Get-LocalUser | Measure-Object | Select-Object -ExpandProperty Count
```

We get:

```
5
```

Then:

```powershell
Get-LocalUser | Where-Object SID -eq 'S-1-5-21-1394777289-3961777894-1791813945-501' | Select-Object -ExpandProperty Name
```

We get:

```
Guest
```

Then:

```powershell
(Get-LocalUser | Where-Object PasswordRequired -eq $false).Count
```


We get:

```
4
```

Then:

```powershell
(Get-LocalGroup).Count
```

We get:

```
24
```

We can use:

```
Get-NetIPAddress
```

Ports:

```powershell
(Get-NetTCPConnection | Where-Object State -eq 'Listen').Count
```

We get:

```
20
```


Remote address:

```powershell
Get-NetTCPConnection -LocalPort 445 -State Listen | Select-Object -ExpandProperty RemoteAddress
```

We get:

```
:: 
```

To check patches:

```powershell
(Get-HotFix).Count
```

We get:

```
20
```

Then:

```
Get-Hotfix -Id KB4023834
```

We get:

```
6/15/2017 12:00:00 AM
```


We can use:

```
Get-ChildItem -Path C:\ -Include *.bak* -File -Recurse -ErrorAction SilentlyContinue
```

After that:

```
Get-Content "C:\Program Files (x86)\Internet Explorer\passwords.bak.txt"
```

We get:

```
backpassflag
```

We can use:

```
Get-ChildItem C:\* -Recurse | Select-String -pattern API_KEY
```

We get:

```
fakekey123
```

We can do:

```
Get-Process
```

We can do:

```
Get-ScheduleTask -TaskName new-sched-task
```

We get:

```
/
```

We can do:

```
Get-Acl c:/
```

We get:

```
NT SERVICE\TrustedInstaller
```


For the sake of time, I will provide a powershell script to automate all the enumeration process:

```powershell
# System Enumeration Script with Timeout Protection
# Requires Run as Administrator

Write-Output "Starting system enumeration..."
Write-Output "----------------------------------------"

# 1. User Count
$userCount = (Get-LocalUser).Count
Write-Output "1. Command used: (Get-LocalUser).Count"
Write-Output " Answer: $userCount`n"

# 2. User by SID
$targetSID = "S-1-5-21-1394777289-3961777894-1791813945-501"
$userBySid = (Get-LocalUser | Where-Object SID -eq $targetSID).Name
Write-Output "2. Command used: Get-LocalUser | Where-Object SID -eq '$targetSID'"
Write-Output " Answer: $userBySid`n"

# 3. Users without password requirement
$noPassCount = (Get-LocalUser | Where-Object PasswordRequired -eq $false).Count
Write-Output "3. Command used: (Get-LocalUser | Where-Object PasswordRequired -eq `$false).Count"
Write-Output " Answer: $noPassCount`n"

# 4. Local Groups Count
$groupCount = (Get-LocalGroup).Count
Write-Output "4. Command used: (Get-LocalGroup).Count"
Write-Output " Answer: $groupCount`n"

# 5. IP Information Command
Write-Output "5. Command used: Get-NetIPAddress"
Write-Output " Answer: Get-NetIPAddress`n"

# 6. Listening Ports Count
$listenPorts = (Get-NetTCPConnection | Where-Object State -eq 'Listen').Count
Write-Output "6. Command used: (Get-NetTCPConnection | Where-Object State -eq 'Listen').Count"
Write-Output " Answer: $listenPorts`n"

# 7. Remote Address for Port 445
$port445Remote = (Get-NetTCPConnection -LocalPort 445 -State Listen).RemoteAddress
Write-Output "7. Command used: (Get-NetTCPConnection -LocalPort 445 -State Listen).RemoteAddress"
Write-Output " Answer: $port445Remote`n"

# 8. Installed Patches Count
$patchCount = (Get-HotFix).Count
Write-Output "8. Command used: (Get-HotFix).Count"
Write-Output " Answer: $patchCount`n"

# 9. KB4023834 Installation Date
try {
 $kbDate = (Get-HotFix -Id KB4023834 -ErrorAction Stop).InstalledOn
 Write-Output "9. Command used: (Get-HotFix -Id KB4023834).InstalledOn"
 Write-Output " Answer: $kbDate`n"
} catch {
 Write-Output "9. Patch KB4023834 not found or inaccessible`n"
}

# 10. Backup File Contents
try {
 $ieBackup = "C:\Program Files (x86)\Internet Explorer\passwords.bak.txt"
 if (Test-Path $ieBackup) {
 $backupContent = Get-Content -Path $ieBackup -Raw
 Write-Output "10. Command used: Get-Content -Path '$ieBackup'"
 Write-Output " Answer: $backupContent`n"
 }
 else {
 $backupFiles = Get-ChildItem -Path C:\ -Include *.bak* -File -Recurse -Force -ErrorAction SilentlyContinue | Select-Object -First 1
 if ($backupFiles) {
 $backupContent = Get-Content -Path $backupFiles.FullName -Raw
 Write-Output "10. Command used: Get-ChildItem -Path C:\ -Include *.bak* -File -Recurse | Select-Object -First 1 | Get-Content"
 Write-Output " Answer: $backupContent`n"
 } else {
 Write-Output "10. No backup files found (*.bak*)`n"
 }
 }
} catch {
 Write-Output "10. Error accessing backup files: $($_.Exception.Message)`n"
}

# 11. Files containing API_KEY with 20-second timeout
Write-Output "11. Command used: Get-ChildItem C:\* -Recurse | Select-String -Pattern API_KEY (with 20s timeout)"
try {
 $apiJob = Start-Job -ScriptBlock {
 Get-ChildItem -Path C:\* -Recurse -Force -ErrorAction SilentlyContinue | 
 Select-String -Pattern "API_KEY" -ErrorAction SilentlyContinue
 }
 
 $apiResult = $apiJob | Wait-Job -Timeout 20
 if ($apiResult.State -eq 'Completed') {
 $apiFiles = Receive-Job -Job $apiJob
 if ($apiFiles) {
 $apiFiles | ForEach-Object {
 Write-Output " Found in: $($_.Path)"
 Write-Output " Line $($_.LineNumber): $($_.Line.Trim())"
 }
 } else {
 Write-Output " No files containing API_KEY found"
 }
 } else {
 Write-Output " API_KEY search timed out after 20 seconds"
 Stop-Job -Job $apiJob
 }
 Remove-Job -Job $apiJob -Force
} catch {
 Write-Output " Error in API_KEY search: $($_.Exception.Message)"
}
Write-Output ""

# 12. Running Processes Command
Write-Output "12. Command used: Get-Process"
Write-Output " Answer: Get-Process`n"

# 13. Scheduled Task Path
try {
 $taskPath = (Get-ScheduledTask -TaskName "new-sched-task" -ErrorAction Stop).TaskPath
 Write-Output "13. Command used: (Get-ScheduledTask -TaskName 'new-sched-task').TaskPath"
 Write-Output " Answer: $taskPath`n"
} catch {
 Write-Output "13. Scheduled task 'new-sched-task' not found`n"
}

# 14. Owner of C:\
$cOwner = (Get-Acl -Path C:\ -ErrorAction SilentlyContinue).Owner
Write-Output "14. Command used: (Get-Acl -Path 'C:\').Owner"
Write-Output " Answer: $cOwner`n"

Write-Output "----------------------------------------"
Write-Output "Enumeration complete!"
```


We can run it with:

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
.\enumeration.ps1
```

Sometimes the API key command search times out, but you still got the answer on top, we can see the following output on the script:

![Pasted image 20250530141500.png](../../IMAGES/Pasted%20image%2020250530141500.png)



# Basic Scripting Challenge
---
Now that we have run Powershell commands, let's try to write and run a script to do more complex and powerful actions. 

For this ask, we'll use Powershell ISE (the Powershell Text Editor). Let's use a particular scenario to show an example of this script. Given a list of port numbers, we want to use this list to see if the local port is listening. Open the listening-ports.ps1 script on the Desktop using Powershell ISE. Powershell scripts usually have the .ps1 file extension. 

```powershell
$system_ports = Get-NetTCPConnection -State Listen

$text_port = Get-Content -Path C:\Users\Administrator\Desktop\ports.txt

foreach($port in $text_port){

 if($port -in $system_ports.LocalPort){
 echo $port
 }

}
```

On the first line, we want to get a list of all the ports on the system that are listening. We do this using the `Get-NetTCPConnection` _cmdlet_. We are then saving the output of this _cmdlet_ into a variable. The convention to create variables is used as:

```powershell
$variable_name = value
```

In the following line, we want to read a list of ports from the file. We do this using the `Get-Content` _cmdlet._ Again, we store this output in the variables. The simplest next step is to iterate through all the ports in the file to see if the ports are listening. To iterate through the ports in the file, we use the following:

```powershell
foreach($new_var in $existing_var){}
```

This particular code block is used to loop through a set of objects. Once we have each individual port, we want to check if this port occurs in the listening local ports. Instead of doing another _for_ loop, we just use an _if_ statement with the `-in` operator to check if the port exists in the `LocalPort` property of any object. A full list of _if_ statement comparison operators can be found [here](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_comparison_operators?view=powershell-6). To run the script, call the script path using Powershell or click the green button on Powershell ISE:

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5c549500924ec576f953d9fc/room-content/e72e79a91264766cbefdbf33e9763202.png) 

Now that we've seen what a basic script looks like - it's time to write one of your own. The emails folder on the Desktop contains copies of the emails John, Martha, and Mary have been sending to each other(and themselves). Answer the following questions with regard to these emails (try not to open the files and use a script to answer the questions). Scripting may be a bit difficult, but [here](https://learnxinyminutes.com/docs/powershell/) is a good resource to use:

## Practical
---

We can use the following script:

```powershell
# Path to the emails root
$path = "C:\Users\Administrator\Desktop\emails\*"
$string_pattern = "password"

# 1, 2. Simple string match across all files
Write-Output "1. Searching for files containing 'password'..."
$command = Get-ChildItem -Path $path -Recurse | Select-String -Pattern $string_pattern
Write-Output $command

# 3. Find files containing HTTPS links (unchanged)
Write-Output "`n3. Searching for files containing HTTPS links..."
$allFiles = Get-ChildItem -Path "C:\Users\Administrator\Desktop\emails" -Recurse -File
$httpsMatches = $allFiles | Select-String -Pattern 'https://' -SimpleMatch

if ($httpsMatches) {
 $httpsFiles = $httpsMatches | Select-Object -ExpandProperty Path -Unique
 Write-Output " Files with HTTPS links:"
 $httpsFiles | ForEach-Object { Write-Output " - $_" }
} else {
 Write-Output " No files containing HTTPS links found"
}

```


We get:

![Pasted image 20250530143750.png](../../IMAGES/Pasted%20image%2020250530143750.png)

Got our answers:

![Pasted image 20250530143815.png](../../IMAGES/Pasted%20image%2020250530143815.png)

# Intermediate Scripting
---

Now that you've learnt a little bit about how scripting works - let's try something a bit more interesting. Sometimes we may not have utilities like Nmap and Python available, and we are forced to write scripts to do very rudimentary tasks.

Why don't you try writing a simple port scanner using Powershell? Here's the general approach to use: - Determine IP ranges to scan(in this case it will be localhost) and you can provide the input in any way you want
- Determine the port ranges to scan
- Determine the type of scan to run(in this case it will be a simple TCP Connect Scan)

## Practical
---

Let's go with this script:

```powershell
# FastPortScanner.ps1
param(
 [string]$Target = "localhost",
 [int]$StartPort = 1,
 [int]$EndPort = 1024,
 [int]$Timeout = 200, # milliseconds
 [int]$Threads = 50 # concurrent connections
)

Write-Host "`nStarting Fast TCP Port Scan on [$Target]" -ForegroundColor Cyan
Write-Host "Scanning ports $StartPort to $EndPort (${Threads} threads, ${Timeout}ms timeout)`n" -ForegroundColor Cyan

$portRange = $StartPort..$EndPort
$totalPorts = $portRange.Count
$openPorts = [System.Collections.Concurrent.ConcurrentBag[int]]::new()
$counter = 0

# Create runspace pool
$runspacePool = [RunspaceFactory]::CreateRunspacePool(1, $Threads)
$runspacePool.Open()
$runspaces = @()

foreach ($port in $portRange) {
 $powershell = [PowerShell]::Create().AddScript({
 param($Target, $Port, $Timeout)
 
 $tcpClient = New-Object System.Net.Sockets.TcpClient
 $connection = $tcpClient.BeginConnect($Target, $Port, $null, $null)
 $success = $connection.AsyncWaitHandle.WaitOne($Timeout, $false)
 
 if ($tcpClient.Connected) {
 $tcpClient.EndConnect($connection)
 $Port
 }
 
 $tcpClient.Close()
 $tcpClient.Dispose()
 }).AddArgument($Target).AddArgument($port).AddArgument($Timeout)
 
 $powershell.RunspacePool = $runspacePool
 $runspaces += [PSCustomObject]@{
 Pipe = $powershell
 Async = $powershell.BeginInvoke()
 Port = $port
 }
}

# Monitor progress and collect results
while ($runspaces.Async -ne $null) {
 $completed = $runspaces | Where-Object { $_.Async.IsCompleted }
 
 foreach ($runspace in $completed) {
 $result = $runspace.Pipe.EndInvoke($runspace.Async)
 if ($result) {
 $openPorts.Add($result)
 Write-Host "Port $result`tOPEN" -ForegroundColor Green
 }
 
 $runspace.Pipe.Dispose()
 $runspaces = $runspaces | Where-Object { $_ -ne $runspace }
 }
 
 # Update progress
 $counter = $totalPorts - $runspaces.Count
 $progress = [math]::Round(($counter / $totalPorts) * 100)
 Write-Progress -Activity "Scanning Ports" -Status "$progress% Complete ($counter/$totalPorts ports)" -PercentComplete $progress
 
 Start-Sleep -Milliseconds 100
}

$runspacePool.Close()
$runspacePool.Dispose()
Write-Progress -Activity "Scanning Ports" -Completed

# Display results
if ($openPorts.Count -gt 0) {
 $sortedPorts = $openPorts | Sort-Object
 Write-Host "`nScan Complete! $($openPorts.Count) open ports found:" -ForegroundColor Cyan
 $sortedPorts | ForEach-Object {
 Write-Host "Port $_`tOPEN" -ForegroundColor Green
 }
}
else {
 Write-Host "`nScan Complete! No open ports found." -ForegroundColor Yellow
}

Write-Host ""
```

This will show us the open ports, the answer for the question is:

```
11
```

![Pasted image 20250530144932.png](../../IMAGES/Pasted%20image%2020250530144932.png)

