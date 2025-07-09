# INTRODUCTION
---

This room aims to demonstrate an active application of threat hunting with a specific focus on using YARA rules to hunt for Indicators of Compromise (IOC) related to malware. We will use a realistic scenario as the red wire throughout this room.

## Learning Objectives

```ad-summary
- Looking for actionable information that can be used to search for threats
- Installing YARA
- Creating a YARA rule
- Deploying a YARA rule
```

## Prerequisites

```ad-summary
- It is recommended to have completed the [Threat Hunting: Introduction](https://tryhackme.com/r/room/introductiontothreathunting) room. That room includes multiple concepts and terminologies used throughout our current room.
- Basic understanding of security concepts including but not limited to [Cyber Kill Chain](https://tryhackme.com/r/room/cyberkillchainzmt), TTPs, Indicator of Compromise, Hashes, and APTs.
- Basic understanding of using the Windows command line and PowerShell.
- Basic understanding of data types and encoding.
```

**Disclaimer:** We will use a real scenario as the red wire throughout this room. All the URLs and referenced files are malicious, and should not be opened outside an isolated environment.


# Scenario Description
---

Our threat hunting team is part of Belgiumâ€™s national CSIRT. We work closely with the cyber threat intelligence and incident response teams to get ahead of the numerous threats targeting our constituents. One main category of our constituents is political parties. Our cyber threat intelligence team has picked up an interesting [article](https://www.mandiant.com/resources/blog/apt29-wineloader-german-political-parties) from the Mandiant threat intelligence blog about a targeted cyber attack on a German political party. They have extracted all the relevant information and passed it to our team. We will analyze this information and look for opportunities to hunt the threat described in the article. Below is the information extracted by the cyber threat intelligence team. They have structured the information using the diamond model.

## Threat Intelligence Provided

```ad-note
**Note:** All the URLs and referenced files provided below are real and malicious. Do not open them outside of an isolated environment. 
``` 

#### **Adversary** 
APT29

#### **Victim** 
German political party

#### **Used Capabilities (TTPs)**

|**ID**|**Technique**|
|---|---|
|[**T1543.003**](https://attack.mitre.org/techniques/T1543/003)|Create or Modify System Process: Windows Service|
|[**T1012**](https://attack.mitre.org/techniques/T1012)|Query Registry|
|[**T1082**](https://attack.mitre.org/techniques/T1082)|System Information Discovery|
|[**T1134**](https://attack.mitre.org/techniques/T1134)|Access Token Manipulation|
|[**T1057**](https://attack.mitre.org/techniques/T1057)|Process Discovery|
|[**T1007**](https://attack.mitre.org/techniques/T1007)|System Service Discovery|
|[**T1027**](https://attack.mitre.org/techniques/T1027)|Obfuscated Files or Information|
|[**T1070.004**](https://attack.mitre.org/techniques/T1070/004)|Indicator Removal: File Deletion|
|[**T1055.003**](https://attack.mitre.org/techniques/T1055/003)|Process Injection: Thread Execution Hijacking|
|[**T1083**](https://attack.mitre.org/techniques/T1083)|File and Directory Discovery|

```ad-important
#**Infrastructure/IOCs** - _Invite.pdf (MD5: fb6323c19d3399ba94ecd391f7e35a9c)_ - Second CDU-themed PDF lure document - Written in LibreOffice 6.4 by default user â€œWriterâ€ - Metadata documents the PDF as en-GB language - Links to https://waterforvoiceless[.]org/invite.php - _invite.php (MD5: 7a465344a58a6c67d5a733a815ef4cb7)_ - Zip file containing ROOTSAW - Downloaded from https://waterforvoiceless[.]org/invite.php - Executes efafcd00b9157b4146506bd381326f39 - _Invite.hta (MD5: efafcd00b9157b4146506bd381326f39)_ - ROOTSAW downloader containing obfuscated code - Downloads from https://waterforvoiceless[.]org/util.php - Extracts 44ce4b785d1795b71cee9f77db6ffe1b - Executes f32c04ad97fa25752f9488781853f0ea - _invite.txt (MD5: 44ce4b785d1795b71cee9f77db6ffe1b)_ - Malicious certificate file, extracted using Windows Certutil - Executed from efafcd00b9157b4146506bd381326f39 - Downloaded from https://waterforvoiceless[.]org/util.php - _invite.zip (MD5: 5928907c41368d6e87dc3e4e4be30e42)_ - Malicious zip containing WINELOADER - Extracted from 44ce4b785d1795b71cee9f77db6ffe1b - Contains e017bfc36e387e8c3e7a338782805dde - Contains f32c04ad97fa25752f9488781853f0ea - _sqldumper.exe (MD5: f32c04ad97fa25752f9488781853f0ea)_ - Legitimate Microsoft file Sqldumper used for side-loading - _vcruntime140.dll (MD5: 8bd528d2b828c9289d9063eba2dc6aa0)_ - WINELOADER downloader - Communicates to https://siestakeying[.]com/auth.php - _Vcruntime140.dll (MD5: e017bfc36e387e8c3e7a338782805dde)_ - WINELOADER downloader - Communicates to https://siestakeying[.]com/auth.php ``
```

#### **Detections**

```javascript
rule M_APT_Dropper_Rootsaw_Obfuscated
{ 
 meta: 
 author = "Mandiant" 
 disclaimer = "This rule is meant for hunting and is not tested to run in a production environment." 
 description = "Detects obfuscated ROOTSAW payloads" 

 strings: 
 $ = "function _" 
 $ = "new XMLHttpRequest();" 
 $ = "'\\x2e\\x7a\\x69\\x70'" 
 $ = "'\\x4f\\x70\\x65\\x6e'" 
 $ = "\\x43\\x3a\\x5c\\x57" 

 condition: 
 All of them 
} 
```

 

```javascript

rule M_APT_Downloader_WINELOADER_1 
{ 
 meta: 
 author = "Mandiant" 
 disclaimer = "This rule is meant for hunting and is not tested to run in a production environment." 
 description = "Detects rc4 decryption logic in WINELOADER samples" 
 
 strings: 
 $ = {B9 00 01 00 00 99 F7 F9 8B 44 24 [50-200] 0F B6 00 3D FF 00 00 00} // Key initialization 
 $ = {0F B6 00 3D FF 00 00 00} // Key size 

 condition: 
 All of them 
} 
 
```

 

```javascript

rule M_APT_Downloader_WINELOADER_2 
{ 
 meta: 
 author = "Mandiant" 
 disclaimer = "This rule is meant for hunting and is not tested to run in a production environment." 
 description = "Detects payload invocation stub in WINELOADER" 

 strings: 
 // 48 8D 0D ?? ?? 00 00 lea rcx, module_start (Pointer to encrypted resource) 
 // 48 C7 C2 ?? ?? 00 00 mov rdx, ???? (size of encrypted source) 
 // E8 [4] call decryption 
 // 48 8D 05 [4] lea rcx, ?? 
 // 48 8D 0D [4] lea rax, module_start (decrypted resource) 
 // 48 89 05 [4] mov ptr_mod, rax 
 // 
 $ = {48 8D 0D ?? ?? 00 00 48 C7 C2 ?? ?? 00 00 E8 [4] 48 8d 0D [4] 48 8D 05 [4] 48 89 05 } 

 condition: 
 All of them 
}
```

### Question Section
---
![Pasted image 20241115125856.png](../IMAGES/Pasted%20image%2020241115125856.png)


# Opportunities for Threat Hunting
---

Based on the threat intelligence provided in Task 2, we will look for opportunities to mount a threat hunt. At first, the amount of intelligence supplied may seem daunting to process. â€œWhere do we start?â€, â€œHow do we start?â€, â€œWhat information do we need?â€, are some questions that need answering first. Before these questions can be answered for this scenario, a small overview of threat hunting styles and processes is required. ## Threat Hunting Styles
---
![Threat hunting styles](https://tryhackme-images.s3.amazonaws.com/user-uploads/66c44fd9733427ea1181ad58/room-content/66c44fd9733427ea1181ad58-1731429616800.png)

There are three styles of threat hunting: Structured hunting, unstructured hunting, and situational/entity-driven hunting.

### **Structured Hunting**
---
This hunting style uses Indicators of Attack and TTPs (Tactics, Techniques, and Procedures) to look for possible attacks from threat actors. This is also called _Hypothesis-based hunting_. The advantage of this hunting style is that an attack can be detected early on in the Kill Chain, preventing damage. One of the primary threat intelligence sources used for this style is the [MITRE ATT&CK](https://attack.mitre.org/) framework. ### **Unstructured Hunting** ---
This hunting style uses Indicators of Compromise to fuel a search in the environment. This translates into several hunting activities throughout the infrastructure: Using YARA rules for pattern matching, writing specific queries to apply to the aggregated data in the SIEM, and more. Another name for this style of hunting is _intel-based threat hunting_.

The threat intelligence sources used for this style are security blogs, the Malware Intelligence Sharing Platform ( MISP ), and threat intelligence feeds like [abuse.ch](https://abuse.ch/) or [Alienvault](https://otx.alienvault.com/). ### **Situational or Entity-Driven Hunting** ----
This style of hunting combines several elements from structured and unstructured hunting and is driven by changes in the threat landscape. For example, a new threat actor, a new report on a threat targeting your business vertical, information from the national CSIRT, a customer request, and more.

Activities include formulating a hypothesis detailing which threat actors could target your infrastructure and what high-value assets they target, hunting for IOCs, and creating or using a threat profile with the help of the [MITRE ATT&CK](https://attack.mitre.org/) framework. Hunting activities often focus on the Crown Jewels (the most critical assets). The primary sources of threat intelligence are threat reports from within the same business vertical and historical attacks. ## Threat Hunting Process
---
![Threat hunting phases](https://tryhackme-images.s3.amazonaws.com/user-uploads/66c44fd9733427ea1181ad58/room-content/66c44fd9733427ea1181ad58-1731429698717.png)

Threat hunting consists of 3 phases:```ad-summary
1. **Trigger**: This is what initiates the threat hunt. This can be an IOC, a set of TTPs, a hypothesis, a system that behaves abnormally, articles on external blogs, reports by third parties, etc.
2. **Investigation**: A specific trigger is selected and used as a starting point for hunting activities. The threat hunter can use various tools to support the hunt for anomalies, such as YARA rules, Volatility, malware scanners, packet analyzers like Wireshark, and many more. 3. **Resolution**: If the threat hunter finds evidence of a breach, the incident response team is notified, and the incident response procedure is started. Depending on the procedure, the threat hunter can support the IR team by scoping and digging deeper into the evidence found.```

## Opportunities
---
Let us now apply the above concepts to our scenario. There are multiple opportunities provided within the received threat intelligence:```ad-important
1. The received threat intelligence details specific TTPs attributed to APT29, which is known to target political entities. - This intelligence enables a _structured hunting style_ using the TTPs included in the report to build a hypothesis.
2. The received threat intel includes Indicators of Compromise and YARA rules to hunt for malware. - This intelligence enables an _unstructured hunting style_ using the IOCs provided.
3. The two opportunities above can be combined to enable a _situational or entity-driven hunting style_.
```

Throughout the rest of this room, we will focus on opportunity number 2. The provided Indicators of Compromise enable multiple threat hunting activities, e.g., ingesting them in the IDS, manually scanning with YARA or SIGMA, creating SNORT rules, and more.

We will use the provided YARA rules for this room to hunt for the WINELOADER malware.

## Question section
---

![Pasted image 20241115130918.png](../IMAGES/Pasted%20image%2020241115130918.png)


# YARA: Introduction
---

The threat intelligence received in Task 2 contained three YARA rules. These YARA rules can be used to hunt for specific malware (in this scenario, the malware is WINELOADER). Before we get hands-on with these YARA rules, it is important to understand what YARA is.

`YARA stands for Yet Another Ridiculous Acronym`. It is a tool Victor Alvarez of VirusTotal developed to assist malware researchers in detecting and describing malware families.

The main functionality of YARA is based on advanced pattern matching, explicitly tailored to malware. It can be best compared to using a supercharged grep with complex regular expressions in Linux. Just like the grep command, the YARA binary will iterate over all files in a designated path, trying to find a match with the information provided in the YARA rule.

A YARA rule describes a malware family based on a pattern using a set of strings and Boolean logic. ## Structure of a YARA Rule
---
A YARA rule uses descriptive language to define a pattern consisting of strings to match a Boolean condition specified at the end of the rule.

The main parts of a YARA rule are the rule **name**_,_ **meta**_,_ **strings**_,_ and **condition**. Below, we will discuss each part.

#### **Rule Name**
---
The **Rule name** is a descriptive name for the rule and starts with the keyword **rule**. Best practices include setting a name that clarifies what the rule is used for.

#### **Meta**
---

This part defines extra information like description, author, and more. Custom identifiers and value pairs can be freely created. The information defined in **meta** cannot be used in the **condition** part. Whether to include this part or not is entirely up to you. The rule will work completely fine without it. It is, however, recommended to include the _meta_ part with some basic information, including the author and the description of what to use the rule for.

#### **Strings**
---
In this part of the rule, matching strings are defined. Multiple types of strings can be defined, which is essential for creating functional rules. 

#### **Condition**
---
In this part of the rule, a matching condition is defined using the identifiers defined in the **strings** part.

## Example of a YARA Rule
---
Below is an example of a YARA rule we received from the CTI team. In this example, all four parts discussed in the previous paragraph are present:

```ad-summary
1. **Rule** **name**: M_APT_Dropper_Rootsaw_Obfuscated. The ruleâ€™s title is well-chosen and gives the user a good idea of what to use it for. In this case, it is to detect a dropper called Rootsaw that is obfuscated.
2. **Meta**: It is good practice to include relevant data that provides more information about the rule. This helps the user of the YARA rule know what to use the rule for, who wrote it, and where to apply it.
3. **Strings**: The strings included in this example help the user find a file containing those strings. How do malware analysts choose those strings? They analyze the malware and determine what uniquely identifies it. The strings used are _text strings._ The first two lines are straightforward.
4. **Condition**: This rule requires that all defined strings be present to have a match. This means all the strings defined in part 3 must have a match in the same file being matched against.


![Example of a YARA-rule](https://tryhackme-images.s3.amazonaws.com/user-uploads/5fbe259259ee347220b3944d/room-content/75b5a77557ffb02ad0ad7b191f689a73.png)
```

Only two parts are required for a rule to function: the rule name and the condition. All the other parts are optional. However, adding strings to a rule is recommended if you want to create complex, functional YARA rules.

More detailed information on writing YARA rules can be found in the official [YARA documentation](https://yara.readthedocs.io/en/stable/writingrules.html), or if you prefer not to write them yourself, many repositories are available with well-written YARA rules. Florian Roth is a good authority on writing quality YARA rules. Florian also created a tool called YARA FORGE that streamlines public YARA rule collection. This tool gathers, tests, organizes, and redistributes these rules more efficiently, making them more accessible and valuable for the cyber security community. You can find documentation related to this tool within the official [YARAHQ GitHub profile](https://github.com/YARAHQ/yara-forge).

# YARA: Strings and Conditions
---

In the previous task, we briefly discussed the different parts of a YARA rule and mentioned that a YARA rule requires at least the **strings** and **condition** part to function as intended. These two parts make or break a YARA rule, so it is important to go a bit deeper into them. But before that, we will talk briefly about false positives.

## False Positives
---
An essential part of threat hunting is excluding false positives. When we look at YARA, this means creating rules that uniquely identify the threat you are looking for. This is easier said than done. YARA rules can get complex very fast when tailored toward specific malware. Using well-written and tested YARA rules is a must. This leaves us with two choices: You either dive deep into the specifics of writing YARA rules or use YARA rules created by experts (like those included in the threat intelligence we received in Task 3). Of course, the combination of these two options is also viable. Even when just using pre-created YARA rules, it is crucial that you understand them.

## Strings

In this paragraph, we will investigate what strings we can use within a YARA rule. We will discuss the general types of available strings without going too deep in each category. Most modifier keywords we will encounter throughout this paragraph can be combined. It is out of scope to discuss all the possible combinations. If you want to dig deeper, you can have a look at the official [YARA documentation](https://yara.readthedocs.io/en/latest/writingrules.html#strings).

### **Text Strings**

In its simplest form, we can define an ASCII-encoded string that matches some text we seek. It is essential to mention that the specified string is case-sensitive. Let us look at an example:

```javascript
rule textString
 {
 strings: 
 $1 = "This is an ASCII-encoded string" //strings are defined between double quotes
 $2 = "This is an ascii-encoded string" //not the same as $1.
 
 condition: 
 all of them 
 } 
```

 

It is possible to define the string as case-insensitive by adding the modifier **nocase** next to it. This way, it will search for all permutations of the specified string. The example below shows the use of the **nocase** modifier:

```javascript
rule noCaseTextString
 {
 strings: 
 $1 = "This is an ASCII-encoded string" nocase
 
 condition: 
 $1
 } 
```

 

### **Wide-Character Strings**
---
Strings can be encoded in different ways. One way often found in binaries is encoding the string as two bytes per character instead of the traditional one-byte ASCII encoding. For example, the string`tryhackme` would be encoded as`t00r00y00h00a00c00k00m00e00`. It is possible to use a modifier next to the defined string so the rule matches for this wide-character string. The modifier used for this is **wide**_._ The example below shows the use of the **wide** modifier:

```javascript
rule wideTextString
 {
 strings: 
 $1 = "tryhackme" wide // will match with t\x00r\x00y\x00h\x00a\x00c\x00k\x00m\x00e\x00 
 
 condition: 
 $1
 } 
```

 

### **Hexadecimal Strings**
---
When malware analysts start analyzing malware, they often use a disassembler and debugger like IDA Pro to dismantle binaries. Often, the pieces of code they uncover are displayed in hexadecimal. We can then use the hexadecimal strings uncovered during analysis to create our own YARA rules. Sequences of hexadecimal characters are often more challenging for attackers to obfuscate and hide. So, these hexadecimal strings provide an excellent opportunity to uniquely identify a certain malicious binary. Let us look at an example of hexadecimal strings in a YARA rule.

```javascript
rule hexString
 {
 strings: 
 $1 = { E2 34 B6 C8 A3 FB } // Hexadecimal strings are defined between {}
 
 condition: 
 $1
 } 
```

 

Defining hexadecimal strings can be very flexible. YARA supports four ways to realize this: Use of wild cards, not operators, jumps, and alternatives. All of the constructions can be combined as well. Let us look at an example of its primary usage:

```javascript
rule hexStringExpanded
 {
 strings: 
 $1 = { E2 34 B6 ?? A3 FB } // The ? is a wildcard and can represent any hex value.
 $2 = { E2 34 B6 ~00 A3 FB } // The ~ is a not operator that precedes the value to exclude from the search. In this case 00.
 $3 = { E2 34 [2-4] A3 FB } // The [X-Y] construct defines a jump. This means that any value between 2 and 4 bytes can occupy this position.
 $4 = { E2 34 (C5|B5) A3 FB } // Between () alternative byte sequences can be defined separated with the boolean operator OR. The value can be B5 OR C5. 
 condition: 
 $1
 } 
```

 

### **XOR Strings**
---
Malware creators often use XOR to encrypt their code, making it harder for malware analysts to analyze. It also helps evade anti-virus signatures. The XOR string support in YARA helps us to hunt for XOR encrypted string variations with 1-byte keys. Let us look at an example:

```javascript
rule xorString
 {
 strings: 
 $1 = "http://maliciousurl.thm" xor // This line will look for all variations possible with a 1-byte XOR key
 
 condition: 
 $1
 } 
```

 

Malware authors will often use encoding to evade detection. One encoding technique that is often used is base64. YARA supports looking for base64 encoded strings. To do this, you can use the modifier _base64_ after defining the string. YARA will search for the base64 encoded string when running the YARA rule. Let us have a look at an example:

```javascript
rule base64String
 {
 strings: 
 $1 = "This is a regular string" base64 // At runtime YARA will encode the string with base64 and look for matches.
 
 condition: 
 $1
 } 
```

 

### **Regular Expressions**
---
Just like with the grep command in Linux, using regular expressions makes YARA powerful. You can define regular expressions the same way as strings, with the only difference being forward slashes instead of double quotes. A bonus is that the above modifiers can also be applied to these regular expressions. Check out our [Regular expressions](https://tryhackme.com/r/room/catregex) room for more info on creating regular expressions. It is, however, important to note that since version 2.0, YARA has used its regular expression engine, which implements most features found in PCRE. For now, let us look at an example of a YARA rule that includes a regular expression:

```javascript
rule regularExpression
 {
 strings: 
 $1 = /THM\{[a-zA-Z]
```

 

## Conditions
---
Once you have defined your strings, it is crucial to define how to combine them and match the files you are searching for. YARA offers great flexibility when making different combinations. YARA includes Boolean, relational, arithmetic, and bitwise operators. Additionally, some keywords can be used. The table below shows an overview of the operators and keywords:

|Boolean operators|Relational operators|Arithmetic operators|Bitwise operators|Keywords|
|---|---|---|---|---|
|and|>=|+|&|1 of them|
|or|<=|-|\||any of them|
|not|<|*|<<|none of them|
||>|\|>>|contains|
||==|%|~|icontains|
||!=||^|startswith|
|||||istartswith|
|||||endswith|
|||||iendswith|
|||||iequals|
|||||matches|
|||||not defined|
|||||filesize|

We could dedicate a complete room to all the operators, but for this room, we will focus only on some of the Boolean operators and keywords. Letâ€™s look at some examples:

```javascript
rule differentConditions
 {
 strings: 
 $1 = "Try" 
 $2 = "Hack" 
 $3 = "Me" 
 
 condition: 
 all of them // Matches when all defined strings are present.
 } 
```

 

```javascript
rule differentConditions
 {
 strings: 
 $1 = "Try" 
 $2 = "Hack" 
 $3 = "Me" 
 
 condition: 
 any of them // Matches when at least one of the defined strings is present.
 } 
```

 

```javascript
rule differentConditions
 {
 strings: 
 $1 = "Try" 
 $2 = "Hack" 
 $3 = "Me" 
 
 condition: 
 1 of $(*) // Identical to "any of them" condition.
 } 
```

 

```javascript
rule differentConditions
 {
 strings: 
 $1 = "Try" 
 $2 = "Hack" 
 $3 = "Me" 
 
 condition: 
 "$1 or $2" // Matches when 'Try' or 'Hack' is present.
 } 
```

 

```javascript
rule differentConditions
 {
 strings: 
 $1 = "Try" 
 $2 = "Hack" 
 $3 = "Me" 
 
 condition: 
 $1 and $2 // Matches when 'Try' and 'Hack' are present.
 } 
```

 

```javascript
rule differentConditions
 {
 strings: 
 $1 = "Try" 
 $2 = "Hack" 
 $3 = "Me" 
 
 condition: 
 $1 and ($2 or $3) // Matches when 'Try' and 'Hack' or 'Try' and 'Me' combinations are present.
 } 
```

 

```javascript
rule differentConditions
 {
 strings: 
 $1 = "Try" 
 $2 = "Hack" 
 $3 = "Me" 
 
 condition: 
 none of them // Matches only when none of the defined strings are present.
 } 
```

 

```javascript
rule differentConditions
 {
 strings: 
 $1 = "Try" 
 $2 = "Hack" 
 $3 = "Me" 
 
 condition: 
 filesize < 500KB // Matches all files smaller than 500 KiloByte. This can only be used when matching for files.
 } 
```

 

```javascript
rule differentConditions
 {
 strings: 
 $1 = "Try" 
 $2 = "Hack" 
 $3 = "Me" 
 
 condition: 
 ($1 or $2) and filesize < 200KB // Matches for 'Try' or 'Hack' in files smaller than 200KB.
 } 
```

 

Now that we have covered the two most important parts of a YARA rule, letâ€™s move on to the next task and examine how we can use YARA rules to hunt for Indicators of Compromise.

## Question Section
---

![Pasted image 20241115132332.png](../IMAGES/Pasted%20image%2020241115132332.png)

# YARA: How To Use YARA Rules To Hunt for Indicators of Compromise
---

During this task, we will learn how to use a YARA rule to hunt for Indicators of Compromise for the WINELOADER malware. It is important to note that YARA rules can be run standalone or as part of a security product like Kaspersky, VirusTotal, Trend Micro, and more.

## Basic Syntax for YARA
---
Open up a PowerShell window as administrator and enter the command yara64, where you should get the following output: 

```PS
PS C:\TMP> yara64
yara: wrong number of arguments
Usage: yara [OPTION]... [NAMESPACE:]RULES_FILE... FILE | DIR | PID
 
Try `--help` for more options
```

Enter the following command to show the help page and see the available options: `yara64 --help`. The help page is a great reference to all the different arguments available. The table below lists a few of the common flags used.

```ad-important
Short Flag	Long Flag	Description
-r	--recursive	Scan directories recursively
-n	--negate	Print only rules that weren't matched
-S	--print-stats	Print metadata related to the performance and efficiency of the rule
-s	--print-strings	Print the strings that were matched in a file
-X	--print-xor-key	Print xor key and plaintext of matched strings
-v	--version	Show the YARA version
-p	--threads=N	Use N threads to scan a directory
```


### Run a YARA Rule for the First Time

We will use a basic YARA rule we wrote for this hands-on. Letâ€™s examine the rule.

```
PS C:\TMP> get-content C:\TMP\YARARULES\myfirstrule.yar
rule myfirstrule {
 meta:
 Description = "Searches for the string tryhackme"
 Author = "TryHackMe"
 
 strings:
 $s = "tryhackme"
 
 condition:
 $s
 }
```

This rule searches for the string `tryhackme` in the `C:\TMP\` directory. Enter the following command: `yara64 C:\TMP\YARARULES\myfirstrule.yar C:\TMP\` to start searching using `myfirstrule.yar`.

The result of running this rule should be as follows:

![Pasted image 20241115132957.png](../IMAGES/Pasted%20image%2020241115132957.png)


```ad-summary
- The used command is shown on the first line.
- The second line shows a match for a file named test.txt. Open this file and verify the result.
- You can use the myfirstrule.yar as a starting point for writing your own YARA rules.
```

## Hunt for WINELOADER Malware Indicators of Compromise
---
For this walkthrough, we will use the YARA rules that the CTI team provided. A malware sample of WINELOADER is included in the `C:\TMP\` folder.

Open a PowerShell administrator window and enter the following command to hunt for WINELOADER malware:

`yara64 C:\TMP\YARARULES\WINELOADER1.yar C:\TMP\`

The following result should be displayed:

![Pasted image 20241115133114.png](../IMAGES/Pasted%20image%2020241115133114.png)

```ad-summary
- The first line is the command.
- The second line shows a match, indicating that a sample of WINELOADER has been found.
- Now do the same for the other rules `WINELOADER2.yar` and `ROOTSAW.yar`


```


## Combine Multiple Rules in One File
---
Rules can also be combined in one file. Combining the three rules in one file could be interesting in our scenario. There are no specific guidelines on when to combine rules in one file. One way could be to group rules that hunt for the same malware family:

Create a new file in `C:\TMP\YARARULES\` and name it `WINELOADERCOMBO.yar`.
Copy the content of `WINELOADER1.yar`, `WINELOADER2.yar`, and `ROOTSAW.yar` in the newly created file. Leave a space between each rule for readability. The result should look something like this:

```
PS C:\TMP> get-content C:\TMP\YARARULES\WINELOADERCOMBO.yar
rule M_APT_Downloader_WINELOADER_1
{
 meta:
 author = "Mandiant"
 disclaimer = "This rule is meant for hunting and is not tested to run in a production environment."
 description = "Detects rc4 decryption logic in WINELOADER samples"

 strings:
 $ = {B9 00 01 00 00 99 F7 F9 8B 44 24 [50-200] 0F B6 00 3D FF 00 00 00} // Key initialization
 $ = {0F B6 00 3D FF 00 00 00} // Key size

 condition:
 all of them
}

rule M_APT_Downloader_WINELOADER_2
{
 meta:
 author = "Mandiant"
 disclaimer = "This rule is meant for hunting and is not tested to run in a production environment."
 description = "Detects payload invocation stub in WINELOADER"

 strings:

 // 48 8D 0D ?? ?? 00 00 lea rcx, module_start (Pointer to encrypted resource)
 // 48 C7 C2 ?? ?? 00 00 mov rdx, ???? (size of encrypted source)
 // E8 [4] call decryption
 // 48 8D 05 [4] lea rcx, ??
 // 48 8D 0D [4] lea rax, module_start (decrypted resource)
 // 48 89 05 [4] mov ptr_mod, rax

 $ = {48 8D 0D ?? ?? 00 00 48 C7 C2 ?? ?? 00 00 E8 [4] 48 8d 0D [4] 48 8D 05 [4] 48 89 05 }

 condition:
 all of them
}

rule M_APT_Dropper_Rootsaw_Obfuscated
{
 meta:
 author = "Mandiant"
 disclaimer = "This rule is meant for hunting and is not tested to run in a production environment."
 description = "Detects obfuscated ROOTSAW payloads"

 strings:
 $ = "function _"
 $ = "new XMLHttpRequest();"
 $ = "'\\x2e\\x7a\\x69\\x70'"
 $ = "'\\x4f\\x70\\x65\\x6e'"
 $ = "\\x43\\x3a\\x5c\\x57"
 $ = "https://waterforvoiceless.org/util.php"

 condition:
 2 of them
}
```

# Indicators of Compromise Detected - Now What
---


In the previous task, we used YARA rules to hunt for the WINELOADER malware. During this hunt, we found a malicious binary. This task will focus on what happens after discovering a confirmed Indicator of Compromise.

After discovering a true positive Indicator of Compromise on a system, the first thing you should do is detailed in the incident response procedure. Any company serious about security will have an incident response policy that explains all the steps to follow before, during, and after an incident.

You will likely first have to notify the team responsible. He will follow the IR policy and get the IR team together to start all required IR activities. On the practical side, an incident response framework like DAIR (Dynamic Approach to Incident Response) is likely part of the IR policy. Based on this framework, you will likely receive follow-up tasks including but not limited to further analysis of the compromised machine, preserving evidence by calculating hashes, taking the machine offline, and more. More details involving the IR policy, team, and activities are discussed in the Intro to IR and IM room.

![Pasted image 20241115144041.png](../IMAGES/Pasted%20image%2020241115144041.png)

While doing threat hunting, it is always important to document all your findings. This information is crucial in case of an incident and can save time later in the IR process. Time is a critical factor in responding to incidents. If you look at the Cyber Kill Chain below, it could be the difference between being in the C2 phase and being in the Actions on Objectives phase.

![Pasted image 20241115144107.png](../IMAGES/Pasted%20image%2020241115144107.png)
