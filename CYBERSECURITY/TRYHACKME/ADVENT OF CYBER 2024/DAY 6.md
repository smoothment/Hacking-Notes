![Pasted image 20241206110950.png](../../IMAGES/Pasted%20image%2020241206110950.png)

_Mayor Malware was scheming, quite full of delight, 
To ruin SOC-mas and frighten SOC teams. 
But Glitch and McSkidy had spoiled his plan, 
By uncovering secrets that exposed the man!_

Mayor Malware slammed his hand on the table, his eyes narrowing as the report flashed on his screen. Glitch and McSkidy had uncovered his trail. He took a deep breath, calming himself. _"No matter,"_ he muttered, a sinister grin forming. _"They may have found me but haven't stopped me."_ His confidence stemmed from the malware he had craftedâ€”so devious and advanced that it would easily evade detection.

But before unleashing it to wreak havoc on SOC teams and ruin SOC-mas, there was one final step. He needed to test it in a sandbox.

This is the continuation of [day 5](DAY%205.md)
## Learning Objectives

```ad-summary
- Analyze malware behaviour using sandbox tools.
- Explore how to use YARA rules to detect malicious patterns.
- Learn about various malware evasion techniques.
- Implement an evasion technique to bypass YARA rule detection.
```


![THM credentials RDP](https://tryhackme-images.s3.amazonaws.com/user-uploads/63588b5ef586912c7d03c4f0/room-content/be629720b11a294819516c1d4e738c92.png)

| | |
|---|---|
|**Username**|administrator|
|**Password**|TryH@cKMe9#21|
|**IP**|10.10.238.227|

_He slipped his malware into a sandbox to see, 
What tricks it could play and what flaws there might be. 
For sandboxes, you see, are used by the wise, 
Defenders inspect, but attackers revise!_

## Detecting Sandboxes
---

A sandbox is an isolated environment where (malicious) code is executed without affecting anything outside the system. Often, multiple tools are installed to monitor, record, and analyze the code's behaviour.

Mayor Malware knows that before his malware executes, it needs to check if it is running on a Sandbox environment. If it is, then it should not continue with its malicious activity.

To do so, he has settled on one technique, which checks if the directory`C:\Program Files` is present by querying the Registry path`HKLM\\Software\\Microsoft\\Windows\\CurrentVersion`. The value can be confirmed by visiting the Registry path within the Registry Editor, as shown below:


![Pasted image 20241206111732.png](../../IMAGES/Pasted%20image%2020241206111732.png)

To open the`Windows Registry Editor`, navigate to the`Start Menu` on the bottom, select`Run`, enter`regedit`, and press enter.

This directory is often absent on sandboxes or other virtualized environments, which could indicate that the malware is running in a sandbox.

Here's what it looks like in the C Programming Language:

```c
void registryCheck() {
 const char *registryPath = "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion";
 const char *valueName = "ProgramFilesDir";
 
 // Prepare the command string for reg.exe
 char command[512];
 snprintf(command, sizeof(command), "reg query \"%s\" /v %s", registryPath, valueName);
 // Run the command
 int result = system(command);
 // Check for successful execution
 if (result == 0) {
 printf("Registry query executed successfully.\n");
 } else {
 fprintf(stderr, "Failed to execute registry query.\n");
 }
}
int main() {
 const char *flag = "[REDACTED]";
 registryCheck();
 return 0;

} 
```

Don't worryâ€”you don't have to understand every detail of the code. All you need to know is that this function is designed to check the system's registry for a specified directory path (ProgramFilesDir). This path's presence or absence helps the malware determine whether it's running in a typical or virtualized environment, like a sandbox.

## Can YARA Do It?
----

Mayor Malware knows that McSkidy is a big fan of YARA rules.

YARA is a tool used to identify and classify malware based on patterns in its code. By writing custom rules, analysts can define specific characteristics to look forâ€”such as particular strings, file headers, or behavioursâ€”and YARA will scan files or processes to find matches, making it invaluable for detecting malicious code.

Mayor Malware does not think such a simple tool can detect his malware. But just to be sure, he has to test it out himself.

To do this, he wrote a small script that executes a YARA detection rule every time a new event is added to the System monitor log. This particular YARA rule detects any command that tries to access the registry.

Let's have a look at the rule:

```javascript
rule SANDBOXDETECTED
{
 meta:
 description = "Detects the sandbox by querying the registry key for Program Path"
 author = "TryHackMe"
 date = "2024-10-08"
 version = "1.1"

 strings:
 
 $cmd= "Software\\Microsoft\\Windows\\CurrentVersion\" /v ProgramFilesDir" nocase

 

 condition:
 $cmd
}
```


Let's understand the contents:

```ad-note
- In the **strings** section, we have defined variables that include the value to look out for: `$cmd`
- In the **condition** section, we define when the rule will match the scanned file. In this case, if any of the specified strings are present.
```

For his testing, Mayor Malware has set up a one-function script that runs the Yara rule and logs a true positive in`C:\Tools\YaraMatches.txt`.

Open up a PowerShell window, navigate to the`C:\Tools` directory, and use the following command to start up the EDR:


```powershell
PS C:\Tools> .\JingleBells.ps1
No events found in Sysmon log.
Monitoring Sysmon events... Press Ctrl+C to exit.
```

This tool will run on the system and continuously monitor the generated Event Logs. It will alert you if it finds any activity/event that indicates the registry mentioned above key is being queried.

Now run the malware by navigating to`C:\Tools\Malware`, and double-clicking on`MerryChristmas.exe`.

If our custom script did its job, you should have witnessed a popup by our EDR with a flag included, as shown below. This will be the answer to Question 1 below. You can now exit the custom EDR by pressing`Ctrl+C`.

![PowerShell taskbar item](https://tryhackme-images.s3.amazonaws.com/user-uploads/5e8dd9a4a45e18443162feab/room-content/5e8dd9a4a45e18443162feab-1730154020793.png)

_**Note:** If the popup does not show up, hover over the PowerShell item in the taskbar. It should show the popup that was generated._

![Pasted image 20241206113220.png](../../IMAGES/Pasted%20image%2020241206113220.png)

Our first flag is: `THM{GlitchWasHere}`

## Adding More Evasion Techniques
---

Ah, it seems that Yara can detect the evasion that Mayor Malware has added. No worries. Because we can make our malware even stealthier by introducing obfuscation.

```javascript
void registryCheck() {
// Encoded PowerShell command to query the registry
 const char *encodedCommand = "RwBlAHQALQBJAHQAZQBtAFAAcgBvAHAAZQByAHQAeQAgAC0AUABhAHQAaAAgACIASABLAEwATQA6AFwAUwBvAGYAdAB3AGEAcgBlAFwATQBpAGMAcgBvAHMAbwBmAHQAXABXAGkAbgBkAG8AdwBzAFwAQwB1AHIAcgBlAG4AdABWAGUAcgBzAGkAbwBuACIAIAAtAE4AYQBtAGUAIABQAHIAbwBnAHIAYQBtAEYAaQBsAGUAcwBEAGkAcgA=";
 // Prepare the PowerShell execution command
 char command[512];
 snprintf(command, sizeof(command), "powershell -EncodedCommand %s", encodedCommand);

 // Run the command
 int result = system(command);

 // Check for successful execution
 if (result == 0) {
 printf("Registry query executed successfully.\n");
 } else {
 fprintf(stderr, "Failed to execute registry query.\n");
 } 
}
```

### **Code Explanation**
---
The above code does the same thing: query the same registry key to get the information about the Program Data. The only difference is that the query is now encoded using base64, and the code uses the PowerShell to execute the query. The encoded string can be checked by decoding it using a tool like [CyberChef](https://gchq.github.io/CyberChef/), as shown below: 

![CyberChef GUI](https://tryhackme-images.s3.amazonaws.com/user-uploads/66c44fd9733427ea1181ad58/room-content/66c44fd9733427ea1181ad58-1730911341730.png)

## Beware of Floss
----
While obfuscation is helpful, we also need to know that there are tools available that extract obfuscated strings from malware binaries. One such tool is Floss, a powerful tool developed by Mandiant that functions similarly to the Linux strings tool but is optimized for malware analysis, making it ideal for revealing any concealed details.

To try out Floss, open a PowerShell Window and enter the following command:


```powershell
PS C:\Tools\FLOSS> floss.exe C:\Tools\Malware\MerryChristmas.exe |Out-file C:\tools\malstrings.txt
```

The above command can take up to two minutes to complete. In the meantime, let's break down the command:

```ad-important
- `floss.exe C:\Tools\Malware\MerryChristmas.exe`: This command scans for strings in the binary MerryChrismas.exe. If any hardcoded variables were defined in the malware, Floss should find them.
- The`|` symbol redirects the output of the command in front of it to the input of the command behind it. 
- `Out-file C:\tools\malstrings.txt`: We save the command results in a file called`malstrings.txt`.
```


Once the command is done, open`malstrings.txt`, press`CTRL+F`, and search for the string Mayor Malware. Enter the flag as the answer to question two. The format of the string is`THM{}`.

Or, we can use powershell and type in the following command:

![Pasted image 20241206113952.png](../../IMAGES/Pasted%20image%2020241206113952.png)

```ad-note
##### Command
----

`Get-Content .\malstrings.txt | Select-String "THM"`

Flag: `THM{HiddenClue}`
```

## Using YARA Rules on Sysmon Logs

These YARA rules are becoming a pain to Mayor Malware's backside.

If he wants his malware to be undetectable, he needs to research how YARA rules can be used to stop him. For example, his research tells him that YARA rules can also be used to check Sysmon logs for any artefacts left by malware! He'll need to test this as well.

**Sysmon**, a tool from Microsoft's Sysinternals suite, continuously monitors and logs system activity across reboots. This Windows service provides detailed event data on process creation, network connections, and file changesâ€”valuable insights when tracing malware behavior.

A YARA rule will look for events with`event id 1: Process created` for this to work. There are many entries in the Sysmon log. To make it easier to find the event we are looking for, we will apply a custom filter using the`EventRecordID` that we can see in the log`YaraMatches.txt` located in`C:\Tools`.

Open a PowerShell window and enter the following command to check the contents of the EDR log file:

`get-content C:\Tools\YaraMatches.txt`

You should get a result similar to the output below:


```powershell
PS C:\Tools> get-content C:\Tools\YaraMatches.txt

Event Time: 10/11/2024 15:06:39
Event ID: 1
Event Record ID: 96517
Command Line: reg query "HKLM\Software\Microsoft\Windows\CurrentVersion" /v ProgramFilesDir
YARA Result: DetectShutdownTimeQuery C:\Users\Administrator\AppData\Local\Temp\2\tmp8D61.tmp
```

Note down the`Event Record ID value`. We will use this value to create a custom filter in the`Windows Event Viewer`.

Next, open the`Windows Event Viewer` by clicking on its logo in the taskbar and, on the left-hand side, navigate to`Applications and Services Logs -> Microsoft -> Windows -> Sysmon -> Operational`.

Continue by navigating to`Filter Current Log` on the right-hand side of the screen.

You should see a window like the one below:

![Pasted image 20241206114145.png](../../IMAGES/Pasted%20image%2020241206114145.png)

Navigate to XML and tick the checkbox`Edit query manually`. Click`Yes` to confirm. Finally, copy the following filter into the input box:

```xml
<QueryList>
 <Query Id="0" Path="Microsoft-Windows-Sysmon/Operational">
 <Select Path="Microsoft-Windows-Sysmon/Operational">
 *[System[(EventRecordID="INSERT_EVENT_record_ID_HERE")]]
 </Select>
 </Query>
</QueryList>
```


Replace the`EventRecordID` value with the one you recorded before. Apply the filter by clicking`OK`. Now you get the event related to the malware. Click on the event and then on the`Details` tab. You should get the following output:

![Pasted image 20241206114211.png](../../IMAGES/Pasted%20image%2020241206114211.png)

Let's take a look at the`EventData` that is valuable to us:

```ad-important
- The`ParentImage` key shows us which parent process spawned the cmd.exe process to execute the registry check. We can see it was our malware located at`C:\Tools\Malware\MerryChristmas.exe`.
- The`ParentProcessId` and`ProcessId` keys are valuable for follow-up research. We could also use them to check other logs for related events.
- The`User` key can help us determine which privileges were used to run the`cmd.exe` command. The malware could have created a hidden account and used that to run commands.
- The`CommandLine` key shows which command was run in detail, helping us identify the malware's actions.
- The`UtcTime` key is essential for creating a time frame for the malware's operation. This time frame can help you focus your threat hunting efforts.
```

## Never Gonna Give Up

_His malware, it seemed, wasn't quite ready for town. 
"There are watchers and scanners and rules by the ton! If I'm not careful, they'll catch all my fun!"_

Mayor Malware leaned back, tapping his fingers thoughtfully on the table. All of this research had revealed an unsettling truth: his malware, as cunning as it was, wasn't yet ready for the wild. There were too many tools and too many vigilant eyesâ€”analysts armed with YARA rules, Sysmon, and a host of detection techniques that could expose his creation before it even had a chance to spread.

![Yeti playing in a sandbox](https://tryhackme-images.s3.amazonaws.com/user-uploads/63588b5ef586912c7d03c4f0/room-content/63588b5ef586912c7d03c4f0-1730728611995.png) 

He clenched his fist, a determined glint in his eye. _"Just a little more fine-tuning,"_ he murmured. He would study, adapt, and evolve his malware until it was truly undetectable. When the time was right, he would unleash it upon the unsuspecting SOC teams, striking when they least expected it.

But for now, he would wait. Watching. Planning. And he was perfecting his craft in the shadows.

![Pasted image 20241206114316.png](../../IMAGES/Pasted%20image%2020241206114316.png)

Just like that day 6 is done!

[LinkedIn](https://www.linkedin.com/in/samuel-delgado-612163305/) 
