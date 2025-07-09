![5f04259cf9bf5b57aed2c476-1731561346191.svg](../../IMAGES/5f04259cf9bf5b57aed2c476-1731561346191.svg)


_As time went on by, something seemed funny:_

_Mayor Malware and the source of his money!_

_SOC-mas grew closer, so The Glitch better move it._

_Gain access to the wallet so that he could prove it!_


Glitch has been investigating how Mayor Malware funds his shady operations for quite some time. Recently, the Mayor disposed of various old electronic equipment; one was an old tablet with a cracked screen. Being an avid connoisseur of active and passive reconnaissance who does not mind â€œdumpster divingâ€ for the greater good, Glitch quickly picked it up before the garbage truck. Surprisingly, despite being in a terrible condition with a cracked and hazy screen, the tablet still turns on. Browsing through the various files, one PDF file that caught his attention was password-protected. It is time you work with Glitch to discover the password and uncover any evidence lurking there.

![nuts being cracked with a hammer, with each nut revealing characters of "password" which are then formed together](https://assets.tryhackme.com/additional/aoc2024/gifs/AoC%20day%2023%20-%20Birthday%20attack%20-%20animation%201.gif)

This is the continuation of [day 22](DAY%2022.md)


## Learning Objectives
----

By finishing todayâ€™s task, you will learn about:

```ad-summary
- Hash functions and hash values
- Saving hashed passwords
- Cracking hashes
- Finding the password of a password-protected document
```


## Hashed Passwords
---
Before we dive further, it is helpful to learn how passwords are saved in authentication systems. A long time ago, before security was a â€œthingâ€, passwords were stored in cleartext along with the associated username. When the user tries to log in, the system compares the provided password for this account with the saved one. Consequently, if a user forgets their password, someone with enough access privileges can look at the table and respond with something like, â€œThe password forÂ `joebloggs`Â isÂ `ASDF1234`.â€ This was a terrible idea, especially since a database can be stolen and its content leaked online. Unfortunately, users tend to use the same password for different services. Consequently, if an adversary discovers Joe Bloggsâ€™s password from another service, they will try it on Joeâ€™s other accounts, such as email.

To protect passwords, even in the case of a data breach, companies started to save a hashed version of the password. For that, we need to use a hash function. A hash function takes an input of any size and returns a fixed size value. For example, SHA256 (Secure Hash Algorithm 256) creates a 256-bit hash value. In other words,Â `sha256sum FILE_NAME`Â will return a 256-bit hash value regardless of whether the input file is a few bytes or several gigabytes. In the terminal below, we demonstrate this with one file being 2.3 gigabytes and another being 13 bytes.


```shell-session
user@machine:~/AOC2024/example_files$ ls -lh
total 2.3G
-rw-rw-r-- 1 user user 2.3G Oct 24 15:05 Fedora-Workstation-Live-x86_64-41-1.4.iso
-rw-rw-r-- 1 user user   13 Nov 14 14:49 hello.txt
user@machine:~/AOC2024/example_files$ sha256sum *
a2dd3caf3224b8f3a640d9e31b1016d2a4e98a6d7cb435a1e2030235976d6da2  Fedora-Workstation-Live-x86_64-41-1.4.iso
03ba204e50d126e4674c005e04d82e84c21366780af1f43bd54a37816b6ab340  hello.txt
```

Therefore, instead of saving the passwordÂ `ASDF1234`Â verbatim, its hash is saved. For instance, ifÂ MD5Â (Message Digest 5) is being used, thenÂ `ce1bccda287f1d9e6d80dbd4cb6beb60`Â would be saved. Problem solved? Not really. Firstly,Â MD5Â is now considered insecure. Secondly, in addition to choosing a secure hash function, we should add aÂ **salt**, i.e.,Â _a random string of characters_, to the password before hashing it. In other words, instead of savingÂ `hash(password)`Â in the table, we saveÂ `hash(password + salt)`Â along with the salt. Consequently, when the user tries to log in, the authentication system takes their password along with the saved salt, calculates its hash and compares it with the saved hash value; if identical, they are granted access. This makes the saved passwords more immune to a variety attacks.

Although it is recommended to use a modern secure hashing algorithm to calculate the hash value of the password concatenated with a random salt before saving it, reality is not that shiny. In many cases, there are issues in the implementation, be it due to negligence or ignorance. In a recent story, a social media platform was discovered to have saved 600 million passwords in plaintext for seven years, despite all the security guidelines warning against that. In other words, password cracking is not over yet.

## Password-Protected Files
----
On Day 14, we saw how Mayor Malware intercepted network data to eavesdrop on the village. Technically speaking, he was attacking the confidentiality and integrity ofÂ **data in transit**. Today, we will explore how to view his password-protected document. Technically speaking, we will be attacking the confidentiality of theÂ **data at rest**.

One aspect of our security requires us to protect data while it is stored on any storage device; examples include a flash memory drive, smartphone storage, laptop storage, and external drives. If an adversary gains access to any such device, we donâ€™t want them to be able to access our files. Protecting data at rest is usually achieved by encrypting the whole disk or specific files on the disk.

On the other hand, encrypted storage and files can pose an obstacle for the good guys who are investigating a criminal case. Digital forensic investigators need to find a way to access the plaintext files to prove or disprove any wrongdoing. In this case, for his private investigation to succeed, Glitch must figure out how to access the encrypted PDF file on the disposed-off tablet. Glitch needs to play an offensive security role to break the security of the protected document.

## Passwords
---
Opening a password-protected document is impossible unless we know or can find the password. The problem is that many users prefer to pick relatively easy passwords that they can remember easily and then use the same password across multiple places. Have you ever wondered which passwords are most commonly used? According to one source, the table below shows the top 15 most commonly used passwords. Interestingly, many users have opted forÂ `qwerty`, the first six consecutive letters on a QWERTY keyboard.

|Rank|Password|
|---|---|
|1|123456|
|2|password|
|3|12345678|
|4|qwerty|
|5|123456789|
|6|12345|
|7|1234|
|8|111111|
|9|1234567|
|10|dragon|
|11|123123|
|12|baseball|
|13|abc123|
|14|football|
|15|monkey|

Of course, users might get a little bit creative and might replace a character with a symbol. They might append the current year, a memorable date, or a few random characters or numbers to the original word. Knowing that Mayor Malware has a cat called Fluffy, some passwords we expect him to come up with areÂ `f1uffyc4t`Â andÂ `fluffy2024`Â unless he uses his name or title and creates a password such asÂ `m4y0r2024`.

![Pasted image 20241223134454.png](../../IMAGES/Pasted%20image%2020241223134454.png)


You can also access the virtual machine usingÂ SSHÂ at the IP addressÂ `10.10.136.127`Â using the following credentials:

- Username:Â `user`
- Password:Â `Tryhackme123!`

## Demonstration
----

Enough learning about password storage and password choices. It is time to crack some passwords. We will cover the following:

```ad-summary
- Cracking a password found in a breached database
- Finding the password of an encrypted PDF
```

**Data Breach and Hash Values**

Mayor Malware had an online account in a now-defunct forum that was breached, and all its user data was leaked. After checking online, we were able to retrieve the Mayorâ€™s password in hashed format. It is listed below.

|Username|Password Hash|
|---|---|
|`mayor@email.thm`|`d956a72c83a895cb767bb5be8dba791395021dcece002b689cf3b5bf5aaa20ac`|

We want to discover the original password. The first step in our approach is to figure out the type of the hash function. Then, we will try to hash different passwords from a password list until we find a match.

We have saved the above hash value in theÂ `/home/user/AOC2024/hash1.txt`Â file for your convenience.

- First, we will go to theÂ `AOC2024`Â directory and then display the content ofÂ `hash1.txt`.
- Copy the displayed hash. Selecting the text in the split view will copy it for you.   
- Next, we start one tool that helps identify hashes by issuing the commandÂ `python hash-id.py`.
- Paste the copied hash. Right-clicking with your mouse will paste the copied text in split view.  
- Finally, we quit the tool usingÂ `CTRL`+`C`.

The interaction is shown in the terminal output below:


```shell-session
user@machine:~$ cd AOC2024/
user@machine:~/AOC2024$ cat hash1.txt 
d956a72c83a895cb767bb5be8dba791395021dcece002b689cf3b5bf5aaa20ac
user@machine:~/AOC2024$ python hash-id.py
   #########################################################################
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
 HASH: d956a72c83a895cb767bb5be8dba791395021dcece002b689cf3b5bf5aaa20ac

Possible Hashs:
[+] SHA-256
[+] Haval-256

Least Possible Hashs:
[+] GOST R 34.11-94
[+] RipeMD-256
[+] SNEFRU-256
[+] SHA-256(HMAC)
[+] Haval-256(HMAC)
[+] RipeMD-256(HMAC)
[+] SNEFRU-256(HMAC)
[+] SHA-256(md5($pass))
[+] SHA-256(sha1($pass))
--------------------------------------------------
 HASH: ^C

  Bye!
```

Next, we will try passwords fromÂ `rockyou.txt`, a popular password wordlist from a real data breach. The command is as follows:

`john --format=raw-sha256 --wordlist=/usr/share/wordlists/rockyou.txt hash1.txt`

- `john`Â startsÂ John the Ripper; the jumbo edition is installed on the machine
- `--format=raw-sha256`Â specifies the hash format, which we have figured out earlier that it is most likely aÂ SHA-256
- `--wordlist=/usr/share/wordlists/rockyou.txt`Â sets the wordlist that we will use
- `hash1.txt`Â is the text file containing the hash value we are trying to crack

In our first attempt,Â `john`Â calculated theÂ SHA-256Â hash value for every password inÂ `rockyou.txt`Â and compared it with the hash value inÂ `hash1.txt`. Unfortunately, no password was found, as shown in the terminal output below:


```shell-session
user@machine:~/AOC2024$ john --format=raw-sha256 --wordlist=/usr/share/wordlists/rockyou.txt hash1.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-SHA256 [SHA256 256/256 AVX2 8x])
Warning: poor OpenMP scalability for this hash type, consider --fork=2
Will run 2 OpenMP threads
Note: Passwords longer than 18 [worst case UTF-8] to 55 [ASCII] rejected
Press 'q' or Ctrl-C to abort, 'h' for help, almost any other key for status
0g 0:00:00:03 DONE (2024-11-03 09:49) 0g/s 4765Kp/s 4765Kc/s 4765KC/s (4510458faruk)..*7Â¡Vamos!
Session completed.
```

There is a high chance that Mayor Malware has made some transformation to his password. For example, he might have replacedÂ `a`Â withÂ `4`Â or added a couple of digits to his password. John can start from a long password list and attempt various common derivations from each of the passwords to increase its chances of success. This behaviour can be triggered through the use ofÂ **rules**. Various rules come bundled withÂ John the Ripperâ€™s configuration files; one is suited for lengthy wordlists,Â `--rules=wordlist`.

Adding the optionÂ `--rules=worldlist`Â to yourÂ `john`Â command line generates multiple passwords from each one. For instance, it appends and prepends single digits. It does various common substitutions; for example,Â `a`Â can be replaced withÂ `@`,Â `i`Â can be replaced withÂ `!`, andÂ `s`Â can be replaced withÂ `$`. Many more mutations and transformations are part of these rules. You can check all the underlying rules by checking theÂ `[List.Rules:Wordlist]`Â section inÂ `/etc/john/john.conf`, Johnâ€™s configuration file. Unlike the first attempt, using John with this option should crack the hash for you: 

```ad-hint
`john --format=raw-sha256 --rules=wordlist --wordlist=/usr/share/wordlists/rockyou.txt hash1.txt`

##### Output
---

Password is: `fluffycat12`
```

We should note thatÂ `john`Â will not spend computing resources to crack an already-cracked password hash. Consequently, if you repeat a command that has successfully found a password earlier, you will get a message like â€œNo password hashes left to crack (see FAQ)â€. Letâ€™s say that you executed the command listed above and you recovered the password; then, the next time you want to see that password, you would useÂ `john`Â with theÂ `--show`Â option, for example,Â `john --format=raw-sha256 --show hash1.txt`.



**Data Breach and Hash Values**

Glitch has discovered Mayor Malwareâ€™s password used on the breached online forum. Although there is a high chance that this password will be used to access other online accounts created by the Mayor, Glitch does not want to go that route as it would violate the local laws and regulations. Instead of attempting anything illegal, he focused on the data he discovered in the Mayorâ€™s trash. There is one interesting-looking PDF file that happens to be password-protected. You can help Glitch break it.

The first thing you need to do is to convert the password-protected file into a format thatÂ `john`Â can attack. Luckily,Â John the RipperÂ jumbo edition comes with the necessary tools. The different tools follow the naming style â€œformat2johnâ€. The terminal below shows a few examples.

```shell-session
user@machine:~/AOC2024$ ls /opt/john/*2john*
/opt/john/1password2john.py      /opt/john/ethereum2john.py          /opt/john/openssl2john.py
/opt/john/7z2john.pl             /opt/john/filezilla2john.py         /opt/john/padlock2john.py
/opt/john/DPAPImk2john.py        /opt/john/geli2john.py              /opt/john/pcap2john.py
/opt/john/adxcsouf2john.py       /opt/john/gpg2john                  /opt/john/pdf2john.pl
/opt/john/aem2john.py            /opt/john/hccap2john                /opt/john/pdf2john.py
/opt/john/aix2john.pl            /opt/john/hccapx2john.py            /opt/john/pem2john.py
/opt/john/aix2john.py            /opt/john/htdigest2john.py          /opt/john/pfx2john.py
[...]
```

You are interested in a password-protected PDF; therefore,Â `pdf2john.pl`Â should do the job perfectly for you. In the terminal below, you can see how to create a hash challenge from a PDF file. This hash value can later be fed toÂ `john`Â to crack it.


```shell-session
user@machine:~/AOC2024$ pdf2john.pl private.pdf > pdf.hash
user@machine:~/AOC2024$ cat pdf.hash
private.pdf:$pdf$2*3*128*-1028*1*16*c1e77e30a0456552cb8a5327241559bd*32*3dc175eae491edc29b937e4fdbda766c00000000000000000000000000000000*32*6a1b5158d8d6dd9e8380f87b624da6cc936075fd41dc3c76acf2d90db62e4a27
```

The first step to consider would be trying a long wordlist such asÂ `rockyou.txt`; moreover, you might even use a rule such asÂ `--rules=wordlist`Â to test derived passwords. In this case, neither approach works; Mayor Malware has picked a password that does not exist in these public wordlists and is not derived from any word found there. Knowing Mayor Malware, we see what he holds dear, which can hint at what he would consider for his password. Therefore, you need to create your own wordlist with the following words:

```ad-summary
- Fluffy
- FluffyCat
- Mayor
- Malware
- MayorMalware
```

And save it asÂ `wordlist.txt`. We have saved the above words in theÂ `/home/user/AOC2024/wordlist.txt`Â file for your convenience. Consequently, our command would be:

```ad-hint

`john --rules=single --wordlist=wordlist.txt pdf.hash`

- `--rules=single`Â covers more modification rules and transformations on the wordlist
- `--wordlist=wordlist.txt`Â is the custom and personalized wordlist that we created
- `pdf.hash`Â is the hash generated from the password-protected document

##### Output
----


```


Now, you have gained all the necessary knowledge to tackle the questions below and uncover what Mayor Malware has been hiding in his password-protected document.


## Questions
---
![Pasted image 20241223135530.png](../../IMAGES/Pasted%20image%2020241223135530.png)

We know that the first question answer is: `fluffycat12`


Now, let's access the pdf with the previous known password we found using john:

![Pasted image 20241223135743.png](../../IMAGES/Pasted%20image%2020241223135743.png)

We found the flag, it is: `THM{do_not_GET_CAUGHT}`
