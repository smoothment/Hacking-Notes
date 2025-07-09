---
aliases:
  - "JOHN THE RIPPER: THE BASICS"
sticker: emoji//1f3a9
---
# INTRODUCTION

John the RipperÂ is a well-known, well-loved, and versatile hash-cracking tool. It combines a fast cracking speed with an extraordinary range of compatible hash types.

## Learning Prerequisites

For maximum benefit, we recommend you attempt this room after the first three introductory rooms about cryptography.

```ad-info

- [Cryptography Basics](https://tryhackme.com/r/room/cryptographybasics)
- [Public Key Cryptography Basics](https://tryhackme.com/r/room/publickeycrypto)
- [Hashing Basics](https://tryhackme.com/r/room/hashingbasics)
```

There are no other learning prerequisites except basic command line abilities.

## Learning Objectives

Upon the completion of this room, you learn about using John for:

```ad-info
- Cracking Windows authentication hashes
- CrackÂ `/etc/shadow`Â hashes
- Cracking password-protected Zip files
- Cracking password-protected RAR files
- CrackingÂ SSHÂ keys
```


# BASIC TERMS

## What are Hashes?

A hash is a way of taking a piece of data of any length andÂ representing it in another fixed-length form. This process masks the original value of the data. The hash value is obtained by running the original data through a hashing algorithm. Many popular hashing algorithms exist, such as MD4,Â MD5, SHA1 andÂ NTLM. Letâ€™s try and show this with an example:

If we take â€œpoloâ€, a string of four characters, and run it through anÂ MD5Â hashing algorithm, we end up with an output ofÂ `b53759f3ce692de7aff1b5779d3964da`, a standard 32-characterÂ MD5Â hash.

Likewise, if we take â€œpolomintsâ€, a string of 9 characters, and run it through the sameÂ MD5Â hashing algorithm, we end up with an output ofÂ `584b6e4f4586e136bc280f27f9c64f3b`, another standard 32-characterÂ MD5Â hash.

## What Makes Hashes Secure?

Hashing functions are designed as one-way functions. In other words, it is easy to calculate the hash value of a given input; however, it is a hard problem to find the original input given the hash value. In simple terms, a hard problem quickly becomes computationally infeasible in computer science. This computational problem has its roots in mathematics as P vs NP.

In computer science, P and NP are two classes of problems that help us understand the efficiency of algorithms:

```ad-info
- **P (Polynomial Time)**: Class P covers the problems whose solution can be found in polynomial time. Consider sorting a list in increasing order. The longer the list, the longer it would take to sort; however, the increase in time is not exponential.
- **NP (Non-deterministic Polynomial Time)**: Problems in the class NP are those for which a given solution can be checked quickly, even though finding the solution itself might be hard. In fact, we donâ€™t know if there is a fast algorithm to find the solution in the first place.
```

While this is a fascinating mathematical concept that proves fundamental to computing and cryptography, it is entirely outside the scope of this room. But abstractly, the algorithm to hash the value will be â€œPâ€ and can, therefore, be calculated reasonably. However, an â€œun-hashingâ€ algorithm would be â€œNPâ€ and intractable to solve, meaning that it cannot be computed in a reasonable time using standard computers.

## Where John Comes in

Even though the algorithm is not feasibly reversible, that doesnâ€™t mean cracking the hashes is impossible. If you have the hashed version of a password, for example, and you know the hashing algorithm, you can use that hashing algorithm to hash a large number of words, called a dictionary. You can then compare these hashes to the one youâ€™re trying to crack to see if they match. If they do, you know what word corresponds to that hash- youâ€™ve cracked it!

This process is called aÂ **dictionary attack**, andÂ John the Ripper, or John as itâ€™s commonly shortened, is a tool for conducting fast brute force attacks on various hash types.

## Learning More

For some more in-depth material on encryption and decryption, we recommend theÂ [Cryptography Basics](https://tryhackme.com/r/room/cryptographybasics)Â and theÂ [Public Key Cryptography Basics](https://tryhackme.com/r/room/publickeycrypto)Â rooms; moreover, for hashing, we recommend theÂ [Hashing Basics](https://tryhackme.com/r/room/hashingbasics)Â room.

This room will focus on the most popular extended version ofÂ John the Ripper,Â **Jumbo John**.


# SETTING UP YOUR SYSTEM

Throughout the tasks of this room, we will be using the following :

- The â€œJumbo Johnâ€ version ofÂ John the Ripper
- The RockYou password list

If you use the attached virtual machine or the AttackBox, you donâ€™t need to installÂ John the RipperÂ on your system. Consequently, feel free to skip through the installation section. If you prefer to use your system to follow along, please read along to learn how to proceed with the installation. We should note that if you use a version ofÂ John the RipperÂ other than Jumbo John, you might not have some of the required tools, such asÂ `zip2john`Â andÂ `rar2john`.

## Installation

John the Ripper is supported on many Operating Systems, not justÂ LinuxÂ Distributions. Before we go through this, there are multiple versions of John, the standard â€œcoreâ€ distribution, and multiple community editions, which extend the feature set of the original John distribution. The most popular of these distributions is the â€œ**Jumbo John**,â€ which we will use specific features of later.

**AttackBox and Kali**

Jumbo John is already installed on the attached virtual machine and on the AttackBox, so if you plan to use either one, you need not take any further action. Furthermore, offensiveÂ LinuxÂ distributions like Kali are shipped with Jumbo John installed.

You can double-check this by typingÂ `john`Â into the terminal. You should be met with a usage guide for John, with the first line reading â€œJohn the RipperÂ 1.9.0-jumbo-1â€ or something similar with a different version number.

**OtherÂ LinuxÂ Distributions**

ManyÂ LinuxÂ distributions have John the Ripper available for installation from their official repositories. For instance, on FedoraÂ Linux, you can installÂ John the RipperÂ withÂ `sudo dnf install john`, while on Ubuntu, you can install it withÂ `sudo apt install john`. Unfortunately, at the time of writing, these versions provided core functionality and missed some of the tools available through Jumbo John.

Consequently, you need to consider building from the source to access all the tools available via Jumbo John. TheÂ [official installation guide](https://github.com/openwall/john/blob/bleeding-jumbo/doc/INSTALL)Â provides detailed installation and build configuration instructions.

**Installing on Windows**

To install Jumbo John the Ripper on Windows, you need to download and install the zipped binary for either 64-bit systemsÂ [here](https://www.openwall.com/john/k/john-1.9.0-jumbo-1-win64.zip)Â or for 32-bit systemsÂ [here](https://www.openwall.com/john/k/john-1.9.0-jumbo-1-win32.zip).

## Wordlists

Now that we haveÂ `john`Â ready, we must consider another indispensable component: wordlists.

As we mentioned earlier, to use a dictionary attack against hashes, you need a list of words to hash and compare; unsurprisingly, this is called a wordlist. There are many different wordlists out there, and a good collection can be found in theÂ [SecLists](https://github.com/danielmiessler/SecLists)Â repository. There are a few places you can look for wordlists for attacking the system of choice; we will quickly run through where you can find them.

On the AttackBox and KaliÂ LinuxÂ distributions, theÂ `/usr/share/wordlists`Â directory contains a series of great wordlists.

**RockYou**

For all of the tasks in this room, we will use the infamousÂ `rockyou.txt`Â wordlist, a very large common password wordlist obtained from a data breach on a website called rockyou.com in 2009. If you are not using any of the above distributions, you can get theÂ `rockyou.txt`Â wordlist from theÂ [SecLists](https://github.com/danielmiessler/SecLists)Â repository under theÂ `/Passwords/Leaked-Databases`Â subsection. You may need to extract it from theÂ `.tar.gz`Â format usingÂ `tar xvzf rockyou.txt.tar.gz`.

Now that we have our hash cracker and wordlists all set up, letâ€™s move on to some hash cracking!


# CRACKING BASIC HASHES

There are multiple ways to useÂ John the RipperÂ to crack simple hashes. Weâ€™ll walk through a few before moving on to cracking some ourselves.

## John Basic Syntax

The basic syntax ofÂ John the RipperÂ commands is as follows. We will cover the specific options and modifiers used as we use them.

`john [options] [file path]`

- `john`: Invokes theÂ John the RipperÂ program
- `[options]`: Specifies the options you want to use
- `[file path]`: The file containing the hash youâ€™re trying to crack; if itâ€™s in the same directory, you wonâ€™t need to name a path, just the file.

## Automatic Cracking

John has built-in features to detect what type of hash itâ€™s being given and to select appropriate rules and formats to crack it for you; this isnâ€™t always the best idea as it can be unreliable, but if you canâ€™t identify what hash type youâ€™re working with and want to try cracking it, it can be a good option! To do this, we use the following syntax:

`john --wordlist=[path to wordlist] [path to file]`

- `--wordlist=`: Specifies using wordlist mode, reading from the file that you supply in the provided path
- `[path to wordlist]`: The path to the wordlist youâ€™re using, as described in the previous task

**Example Usage:**

`john --wordlist=/usr/share/wordlists/rockyou.txt hash_to_crack.txt`

## Identifying Hashes

Sometimes, John wonâ€™t play nicely with automatically recognizing and loading hashes, but thatâ€™s okay! We can use other tools to identify the hash and then set John to a specific format. There are multiple ways to do this, such as using an online hash identifier likeÂ [this site](https://hashes.com/en/tools/hash_identifier). I like to use a tool calledÂ [hash-identifier](https://gitlab.com/kalilinux/packages/hash-identifier/-/tree/kali/master), a Python tool that is super easy to use and will tell you what different types of hashes the one you enter is likely to be, giving you more options if the first one fails.

To use hash-identifier, you can useÂ `wget`Â orÂ `curl`Â to download the Python fileÂ `hash-id.py`Â from its GitLabÂ [page](https://gitlab.com/kalilinux/packages/hash-identifier/-/raw/kali/master/hash-id.py). Then, launch it withÂ `python3 hash-id.py`Â and enter the hash youâ€™re trying to identify. It will give you a list of the most probable formats. These two steps are shown in the terminal below.

```shell-session
user@TryHackMe$ wget https://gitlab.com/kalilinux/packages/hash-identifier/-/raw/kali/master/hash-id.py
$ python3 hash-id.py
   #########################################################################
   #     __  __                     __           ______    _____           #
   #    /\ \/\ \                   /\ \         /\__  _\  /\  _ `\         #
   #    \ \ \_\ \     __      ____ \ \ \___     \/_/\ \/  \ \ \/\ \        #
   #     \ \  _  \  /'__`\   / ,__\ \ \  _ `\      \ \ \   \ \ \ \ \       #
   #      \ \ \ \ \/\ \_\ \_/\__, `\ \ \ \ \ \      \_\ \__ \ \ \_\ \      #
   #       \ \_\ \_\ \___ \_\/\____/  \ \_\ \_\     /\_____\ \ \____/      #
   #        \/_/\/_/\/__/\/_/\/___/    \/_/\/_/     \/_____/  \/___/  v1.2 #
   #                                                             By Zion3R #
   #                                                    www.Blackploit.com #
   #                                                   Root@Blackploit.com #
   #########################################################################
--------------------------------------------------
 HASH: 2e728dd31fb5949bc39cac5a9f066498

Possible Hashs:
[+] MD5
[+] Domain Cached Credentials - MD4(MD4(($pass)).(strtolower($username)))
```

## Format-Specific Cracking

Once you have identified the hash that youâ€™re dealing with, you can tell John to use it while cracking the provided hash using the following syntax:

`john --format=[format] --wordlist=[path to wordlist] [path to file]`

- `--format=`: This is the flag to tell John that youâ€™re giving it a hash of a specific format and to use the following format to crack it
- `[format]`: The format that the hash is in

**Example Usage:**

`john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt hash_to_crack.txt`

**A Note on Formats:**

When you tell John to use formats, if youâ€™re dealing with a standard hash type, e.g.Â md5 as in the example above, you have to prefix it withÂ `raw-`Â to tell John youâ€™re just dealing with a standard hash type, though this doesnâ€™t always apply. To check if you need to add the prefix or not, you can list all of Johnâ€™s formats usingÂ `john --list=formats`Â and either check manually or grep for your hash type using something likeÂ `john --list=formats | grep -iF "md5"`.

## QUESTIONS

![Pasted image 20241101155712.png](../../IMAGES/Pasted%20image%2020241101155712.png)

# Cracking Windows Authentication Hashes

Now that we understand the basic syntax and usage ofÂ John the Ripper, letâ€™s move on to cracking something a little bit more complicated, something that you may even want to attempt if youâ€™re on an actual Penetration Test or Red Team engagement. Authentication hashes are the hashed versions of passwords stored by operating systems; it is sometimes possible to crack them using our brute-force methods. To get your hands on these hashes, you must often already be a privileged user, so we will explain some of the hashes we plan on cracking as we attempt them.

## NTHash /Â NTLM

NThash is the hash format modern Windows operating system machines use to store user and service passwords. Itâ€™s also commonly referred to asÂ NTLM, which references the previous version of Windows format for hashing passwords known as LM, thus NT/LM.

A bit of history: the NT designation for Windows products originally meant New Technology. It was used starting with Windows NT to denote products not built from the MS-DOSÂ Operating System. Eventually, the â€œNTâ€ line became the standard Operating System type to be released by Microsoft, and the name was dropped, but it still lives on in the names of some Microsoft technologies.

In Windows, SAM (Security Account Manager) is used to store user account information, including usernames and hashed passwords. You can acquire NTHash/NTLMÂ hashes by dumping the SAM database on a Windows machine, using a tool like Mimikatz, or using the Active Directory database:Â `NTDS.dit`. You may not have to crack the hash to continue privilege escalation, as you can often conduct a â€œpass the hashâ€ attack instead, but sometimes, hash cracking is a viable option if there is a weak password policy.
## QUESTIONS

![Pasted image 20241101155801.png](../../IMAGES/Pasted%20image%2020241101155801.png)


# Cracking /etc/shadow Hashes

## Cracking Hashes from /etc/shadow

TheÂ `/etc/shadow`Â file is the file onÂ LinuxÂ machines where password hashes are stored. It also stores other information, such as the date of last password change and password expiration information.Â It contains one entry per line for each user or user account of the system. This file is usually only accessible by the root user, so you must have sufficient privileges to access the hashes. However, if you do, there is a chance that you will be able to crack some of the hashes.

## Unshadowing

John can be very particular about the formats it needs data in to be able to work with it; for this reason, to crackÂ `/etc/shadow`Â passwords, you must combine it with theÂ `/etc/passwd`Â file for John to understand the data itâ€™s being given. To do this, we use a tool built into the John suite of tools calledÂ `unshadow`. The basic syntax ofÂ `unshadow`Â is as follows:

`unshadow [path to passwd] [path to shadow]`

- `unshadow`: Invokes the unshadow tool
- `[path to passwd]`: The file that contains the copy of theÂ `/etc/passwd`Â file youâ€™ve taken from the target machine
- `[path to shadow]`: The file that contains the copy of theÂ `/etc/shadow`Â file youâ€™ve taken from the target machine

**Example Usage:**

`unshadow local_passwd local_shadow > unshadowed.txt`

**Note on the files**

When usingÂ `unshadow`, you can either use the entireÂ `/etc/passwd`Â andÂ `/etc/shadow`Â files, assuming you have them available, or you can use the relevant line from each, for example:

**FILE 1 - local_passwd**

Contains theÂ `/etc/passwd`Â line for the root user:

`root:x:0:0::/root:/bin/bash`

**FILE 2 - local_shadow**

Contains theÂ `/etc/shadow`Â line for the root user:Â `root:$6$2nwjN454g.dv4HN/$m9Z/r2xVfweYVkrr.v5Ft8Ws3/YYksfNwq96UL1FX0OJjY1L6l.DS3KEVsZ9rOVLB/ldTeEL/OIhJZ4GMFMGA0:18576::::::`

## Cracking

We can then feed the output fromÂ `unshadow`, in our example use case calledÂ `unshadowed.txt`, directly into John. We should not need to specify a mode here as we have made the input specifically for John; however, in some cases, you will need to specify the format as we have done previously using:Â `--format=sha512crypt`

`john --wordlist=/usr/share/wordlists/rockyou.txt --format=sha512crypt unshadowed.txt`


# Single Crack Mode

So far, weâ€™ve been using Johnâ€™s wordlist mode to brute-force simple and not-so-simple hashes. But John also has another mode, called theÂ **Single Crack**Â mode. In this mode, John uses only the information provided in the username to try and work out possible passwords heuristically by slightly changing the letters and numbers contained within the username.

## Word Mangling

The best way to explain Single Crack mode and word mangling is to go through an example:

Consider the username â€œMarkusâ€.

Some possible passwords could be:

- Markus1, Markus2, Markus3 (etc.)
- MArkus, MARkus, MARKus (etc.)
- Markus!, Markus$, Markus* (etc.)

This technique is called word mangling. John is building its dictionary based on the information it has been fed and uses a set of rules called â€œmangling rules,â€ which define how it can mutate the word it started with to generate a wordlist based on relevant factors for the target youâ€™re trying to crack. This exploits how poor passwords can be based on information about the username or the service theyâ€™re logging into.

## GECOS

Johnâ€™s implementation of word mangling also features compatibility with the GECOS field of the UNIX operating system, as well as other UNIX-like operating systems such asÂ Linux. GECOS stands for General Electric Comprehensive Operating System. In the last task, we looked at the entries for bothÂ `/etc/shadow`Â andÂ `/etc/passwd`. Looking closely, you will notice that the fields are separated by a colonÂ `:`. The fifth field in the user account record is the GECOS field. It stores general information about the user, such as the userâ€™s full name, office number, and telephone number, among other things. John can take information stored in those records, such as full name and home directory name, to add to the wordlist it generates when crackingÂ `/etc/shadow`Â hashes with single crack mode.

## Using Single Crack Mode

To use single crack mode, we use roughly the same syntax that weâ€™ve used so far; for example, if we wanted to crack the password of the user named â€œMikeâ€, using the single mode, weâ€™d use:

`john --single --format=[format] [path to file]`

- `--single`: This flag lets John know you want to use the single hash-cracking mode
- `--format=[format]`: As always, it is vital to identify the proper format.

**Example Usage:**

`john --single --format=raw-sha256 hashes.txt`

**A Note on File Formats in Single Crack Mode:**

If youâ€™re cracking hashes in single crack mode, you need to change the file format that youâ€™re feeding John for it to understand what data to create a wordlist from. You do this by prepending the hash with the username that the hash belongs to, so according to the above example, we would change the fileÂ `hashes.txt`

**From**Â `1efee03cdcb96d90ad48ccc7b8666033`

**To**Â `mike:1efee03cdcb96d90ad48ccc7b8666033`

## QUESTIONS


# CUSTOM RULES


As we explored what John can do in Single Crack Mode, you may have some ideas about some good mangling patterns or what patterns your passwords often use that could be replicated with a particular mangling pattern. The good news is that you can define your rules, which John will use to create passwords dynamically. The ability to define such rules is beneficial when you know more information about the password structure of whatever your target is.

## Common Custom Rules

Many organisations will require a certain level of password complexity to try and combat dictionary attacks. In other words, when creating a new account or changing your password, if you attempt a password likeÂ `polopassword`, it will most likely not work. The reason would be the enforced password complexity. As a result, you may receive a prompt telling you that passwords have to contain at least one character from each of the following:

- Lowercase letter
- Uppercase letter
- Number
- Symbol

Password complexity is good! However, we can exploit the fact that most users will be predictable in the location of these symbols. For the above criteria, many users will use something like the following:

`Polopassword1!`

Consider the password with a capital letter first and a number followed by a symbol at the end. This familiar pattern of the password, appended and prepended by modifiers (such as capital letters or symbols), is a memorable pattern that people use and reuse when creating passwords. This pattern can let us exploit password complexity predictability.

Now, this does meet the password complexity requirements; however, as attackers, we can exploit the fact that we know the likely position of these added elements to create dynamic passwords from our wordlists.

## How to create Custom Rules

Custom rules are defined in theÂ `john.conf`Â file. This file can be found inÂ `/opt/john/john.conf`Â on the TryHackMe Attackbox. It is usually located inÂ `/etc/john/john.conf`Â if you have installed John using a package manager or built from source withÂ `make`.

Letâ€™s go over the syntax of these custom rules, using the example above as our target pattern. Note that you can define a massive level of granular control in these rules. I suggest looking at the wikiÂ [here](https://www.openwall.com/john/doc/RULES.shtml)Â to get a full view of the modifiers you can use and more examples of rule implementation.

The first line:

`[List.Rules:THMRules]`Â is used to define the name of your rule; this is what you will use to call your custom rule a John argument.

We then use a regex style pattern match to define where the word will be modified; again, we will only cover the primary and most common modifiers here:

- `Az`: Takes the word and appends it with the characters you define
- `A0`: Takes the word and prepends it with the characters you define
- `c`: Capitalises the character positionally

These can be used in combination to define where and what in the word you want to modify.

Lastly, we must define what characters should be appended, prepended or otherwise included. We do this by adding character sets in square bracketsÂ `[ ]`Â where they should be used. These follow the modifier patterns inside double quotesÂ `" "`. Here are some common examples:

- `[0-9]`: Will include numbers 0-9  
    
- `[0]`: Will include only the number 0
- `[A-z]`: Will include both upper and lowercase  
    
- `[A-Z]`: Will include only uppercase letters
- `[a-z]`: Will include only lowercase letters

Please note that:

- `[a]`: Will include onlyÂ `a`
- `[!Â£$%@]`: Will include the symbolsÂ `!`,Â `Â£`,Â `$`,Â `%`, andÂ `@`

Putting this all together, to generate a wordlist from the rules that would match the example passwordÂ `Polopassword1!`Â (assuming the wordÂ `polopassword`Â was in our wordlist), we would create a rule entry that looks like this:

`[List.Rules:PoloPassword]`

`cAz"[0-9] [!Â£$%@]"`

Utilises the following:

- `c`: Capitalises the firstÂ letter
- `Az`: Appends to the end of the word
- `[0-9]`: A number in the range 0-9
- `[!Â£$%@]`: The password is followed by one of these symbols

## Using Custom Rules

We could then call this custom rule a John argument using theÂ Â `--rule=PoloPassword`Â flag.

As a full command:Â `john --wordlist=[path to wordlist] --rule=PoloPassword [path to file]`

As a note, I find it helpful to talk out the patterns if youâ€™re writing a rule; as shown above, the same applies to writing RegEx patterns.

Jumbo John already has an extensive list of custom rules containing modifiers for use in almost all cases. If you get stuck, try looking at those rules [around line 678] if your syntax isnâ€™t working correctly.

Now, itâ€™s time for you to have a go!

## QUESTIONS

![Pasted image 20241101155941.png](../../IMAGES/Pasted%20image%2020241101155941.png)

# Cracking Password Protected Zip Files

Yes! You read that right. We can use John to crack the password on password-protected Zip files. Again, weâ€™ll use a separate part of the John suite of tools to convert the Zip file into a format that John will understand, but weâ€™ll use the syntax youâ€™re already familiar with for all intents and purposes.

## Zip2John

Similarly to theÂ `unshadow`Â tool we used previously, we will use theÂ `zip2john`Â tool to convert the Zip file into a hash format that John can understand and hopefully crack. The primary usage is like this:

`zip2john [options] [zip file] > [output file]`

- `[options]`: Allows you to pass specific checksum options toÂ `zip2john`; this shouldnâ€™t often be necessary
- `[zip file]`: The path to the Zip file you wish to get the hash of
- `>`: This redirects the output from this command to another file
- `[output file]`: This is the file that will store the output

**Example Usage**

`zip2john zipfile.zip > zip_hash.txt`

## Cracking

Weâ€™re then able to take the file we output fromÂ `zip2john`Â in our example use case,Â `zip_hash.txt`, and, as we did withÂ `unshadow`, feed it directly into John as we have made the input specifically for it.

`john --wordlist=/usr/share/wordlists/rockyou.txt zip_hash.txt`


## QUESTIONS

![Pasted image 20241101160009.png](../../IMAGES/Pasted%20image%2020241101160009.png)


# Cracking Password-Protected RAR Archives

We can use a similar process to the one we used in the last task to obtain the password for RAR archives. If you arenâ€™t familiar, RAR archives are compressed files created by the WinRAR archive manager. Like Zip files, they compress folders and files.

## Rar2John

Almost identical to theÂ `zip2john`Â tool, we will use theÂ `rar2john`Â tool to convert the RAR file into a hash format that John can understand. The basic syntax is as follows:

`rar2john [rar file] > [output file]`

- `rar2john`: Invokes theÂ `rar2john`Â tool
- `[rar file]`: The path to the RAR file you wish to get the hash of
- `>`: This redirects the output of this command to another file
- `[output file]`: This is the file that will store the output from the command  
    

**Example Usage**

`/opt/john/rar2john rarfile.rar > rar_hash.txt`

## Cracking

Once again, we can take the file we output fromÂ `rar2john`Â in our example use case,Â `rar_hash.txt`, and feed it directly into John as we did withÂ `zip2john`.

`john --wordlist=/usr/share/wordlists/rockyou.txt rar_hash.txt`

## QUESTIONS

![Pasted image 20241101160039.png](../../IMAGES/Pasted%20image%2020241101160039.png)


# Cracking SSH Keys with John

## CrackingÂ SSHÂ Key Passwords

Okay, okay, I hear you. There are no more file archives! Fine! Letâ€™s explore one more use of John that comes up semi-frequently in CTF challengesâ€”using John to crack theÂ SSHÂ private key password ofÂ `id_rsa`Â files. Unless configured otherwise, you authenticate yourÂ SSHÂ login using a password. However, you can configure key-based authentication, which lets you use your private key,Â `id_rsa`, as an authentication key to log in to a remote machine overÂ SSH. However, doing so will often require a password to access the private key; here, we will be using John to crack this password to allow authentication overÂ SSHÂ using the key.

## SSH2John

Who could have guessed it, another conversion tool? Well, thatâ€™s what working with John is all about. As the name suggests,Â `ssh2john`Â converts theÂ `id_rsa`Â private key, which is used to log in to theÂ SSHÂ session, into a hash format that John can work with. Jokes aside, itâ€™s another beautiful example of Johnâ€™s versatility. The syntax is about what youâ€™d expect. Note that if you donâ€™t haveÂ `ssh2john`Â installed, you can useÂ `ssh2john.py`, located in theÂ `/opt/john/ssh2john.py`. If youâ€™re doing this on the AttackBox, replace theÂ `ssh2john`Â command withÂ `python3 /opt/john/ssh2john.py`Â or on Kali,Â `python /usr/share/john/ssh2john.py`.

`ssh2john [id_rsa private key file] > [output file]`

- `ssh2john`: Invokes theÂ `ssh2john`Â tool
- `[id_rsa private key file]`: The path to the id_rsa file you wish to get the hash of
- `>`: This is the output director. Weâ€™re using it to redirect the output from this command to another file.
- `[output file]`: This is the file that will store the output from

**Example Usage**

`/opt/john/ssh2john.py id_rsa > id_rsa_hash.txt`

## Cracking

For the final time, weâ€™re feeding the file we output from ssh2john, which in our example use case is calledÂ `id_rsa_hash.txt`Â and, as we did withÂ `rar2john`, we can use this seamlessly with John:

`john --wordlist=/usr/share/wordlists/rockyou.txt id_rsa_hash.txt`

## QUESTIONS

