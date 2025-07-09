# SERVICE DETECTION
---


Once Nmap discovers open ports, you can probe the available port to detect the running service. Further investigation of open ports is an essential piece of information as the pentester can use it to learn if there are any known vulnerabilities of the service. JoinÂ [Vulnerabilities 101](https://tryhackme.com/room/vulnerabilities101)
to learn more about searching for vulnerable services.

AddingÂ `-sV`Â to yourÂ NmapÂ command will collect and determine service and version information for the open ports. You can control the intensity withÂ `--version-intensity LEVEL`Â where the level ranges between 0, the lightest, and 9, the most complete.Â `-sV --version-light`Â has an intensity of 2, whileÂ `-sV --version-all`Â has an intensity of 9.

It is important to note that usingÂ `-sV`Â will force Nmap to proceed with theÂ TCPÂ 3-way handshake and establish the connection. The connection establishment is necessary becauseÂ NmapÂ cannot discover the version without establishing a connection fully and communicating with the listening service. In other words, stealth SYN scanÂ `-sS`Â is not possible whenÂ `-sV`Â option is chosen.

The console output below shows a simpleÂ NmapÂ stealth SYN scan with theÂ `-sV`Â option. Adding theÂ `-sV`Â option leads to a new column in the output showing the version for each detected service. For instance, in the case ofÂ TCPÂ port 22 being open, instead ofÂ `22/tcp open ssh`, we obtainÂ `22/tcp open ssh OpenSSH 6.7p1 Debian 5+deb8u8 (protocol 2.0)`. Notice that theÂ SSHÂ protocol is guessed as the service becauseÂ TCPÂ port 22 is open;Â NmapÂ didnâ€™t need to connect to port 22 to confirm. However,Â `-sV`Â required connecting to this open port to grab the service banner and any version information it can get, such asÂ `nginx 1.6.2`. Hence, unlike theÂ _service_Â column, theÂ _version_Â column is not a guess.


```shell-session
pentester@TryHackMe$ sudo nmap -sV 10.10.137.154

Starting Nmap 7.60 ( https://nmap.org ) at 2021-09-10 05:03 BST
Nmap scan report for 10.10.137.154
Host is up (0.0040s latency).
Not shown: 995 closed ports
PORT    STATE SERVICE VERSION
22/tcp  open  ssh     OpenSSH 6.7p1 Debian 5+deb8u8 (protocol 2.0)
25/tcp  open  smtp    Postfix smtpd
80/tcp  open  http    nginx 1.6.2
110/tcp open  pop3    Dovecot pop3d
111/tcp open  rpcbind 2-4 (RPC #100000)
MAC Address: 02:A0:E7:B5:B6:C5 (Unknown)
Service Info: Host:  debra2.thm.local; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.40 seconds
```

# OS Detection and Traceroute
---

### OSÂ Detection
---

Nmap can detect the Operating System (OS) based on its behavior and any telltale signs in its responses.Â OSÂ detection can be enabled usingÂ `-O`; this is anÂ _uppercase O_Â as inÂ OS. In this example, we ranÂ `nmap -sS -O 10.10.137.154`Â on the AttackBox. Nmap detected the OS to beÂ LinuxÂ 3.X, and then it guessed further that it was running kernel 3.13.


```shell-session
pentester@TryHackMe$ sudo nmap -sS -O 10.10.137.154

Starting Nmap 7.60 ( https://nmap.org ) at 2021-09-10 05:04 BST
Nmap scan report for 10.10.137.154
Host is up (0.00099s latency).
Not shown: 994 closed ports
PORT    STATE SERVICE
22/tcp  open  ssh
25/tcp  open  smtp
80/tcp  open  http
110/tcp open  pop3
111/tcp open  rpcbind
143/tcp open  imap
MAC Address: 02:A0:E7:B5:B6:C5 (Unknown)
Device type: general purpose
Running: Linux 3.X
OS CPE: cpe:/o:linux:linux_kernel:3.13
OS details: Linux 3.13
Network Distance: 1 hop

OS detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 3.91 seconds
```

The system that we scanned and attempted to detect its OS version is running kernel version 3.16. Nmap was able to make a close guess in this case. In another case, we scanned a FedoraÂ LinuxÂ system with kernel 5.13.14; however, Nmap detected it asÂ LinuxÂ 2.6.X. The good news is that Nmap detected theÂ OSÂ correctly; the not-so-good news is that the kernel version was wrong.

TheÂ OSÂ detection is very convenient, but many factors might affect its accuracy. First and foremost, Nmap needs to find at least one open and one closed port on the target to make a reliable guess. Furthermore, the guestÂ OSÂ fingerprints might get distorted due to the rising use of virtualization and similar technologies. Therefore, always take theÂ OSÂ version with a grain of salt.

  

### Traceroute
---
If you wantÂ NmapÂ to find the routers between you and the target, just addÂ `--traceroute`. In the following example,Â NmapÂ appended a traceroute to its scan results. Note thatÂ Nmapâ€™s traceroute works slightly different than theÂ `traceroute`Â command found onÂ LinuxÂ and macOS orÂ `tracert`Â found on MS Windows. StandardÂ `traceroute`Â starts with a packet of lowÂ TTLÂ (Time to Live) and keeps increasing until it reaches the target. Nmapâ€™s traceroute starts with a packet of highÂ TTLÂ and keeps decreasing it.

In the following example, we executedÂ `nmap -sS --traceroute 10.10.137.154`Â on the AttackBox. We can see that there are no routers/hops between the two as they are connected directly.


```shell-session
pentester@TryHackMe$ sudo nmap -sS --traceroute 10.10.137.154

Starting Nmap 7.60 ( https://nmap.org ) at 2021-09-10 05:05 BST
Nmap scan report for 10.10.137.154
Host is up (0.0015s latency).
Not shown: 994 closed ports
PORT    STATE SERVICE
22/tcp  open  ssh
25/tcp  open  smtp
80/tcp  open  http
110/tcp open  pop3
111/tcp open  rpcbind
143/tcp open  imap
MAC Address: 02:A0:E7:B5:B6:C5 (Unknown)

TRACEROUTE
HOP RTT     ADDRESS
1   1.48 ms 10.10.137.154

Nmap done: 1 IP address (1 host up) scanned in 1.59 seconds
```

It is worth mentioning that many routers are configured not to send ICMP Time-to-Live exceeded, which would prevent us from discovering their IP addresses. For more information, visit theÂ [Active Reconnaissance](https://tryhackme.com/room/activerecon)Â room.


# Nmap Scripting Engine (NSE)
---

A script is a piece of code that does not need to be compiled. In other words, it remains in its original human-readable form and does not need to be converted to machine language. Many programs provide additional functionality via scripts; moreover, scripts make it possible to add custom functionality that did not exist via the built-in commands. Similarly,Â NmapÂ provides support for scripts using the Lua language. A part ofÂ Nmap,Â NmapÂ Scripting Engine (NSE) is a Lua interpreter that allowsÂ NmapÂ to executeÂ NmapÂ scripts written in Lua language. However, we donâ€™t need to learn Lua to make use ofÂ NmapÂ scripts.

YourÂ NmapÂ default installation can easily contain close to 600 scripts. Take a look at yourÂ NmapÂ installation folder. On the AttackBox, check the files atÂ `/usr/share/nmap/scripts`, and you will notice that there are hundreds of scripts conveniently named starting with the protocol they target. We listed all the scripts starting with theÂ HTTPÂ on the AttackBox in the console output below; we found around 130 scripts starting with http. With future updates, you can only expect the number of installed scripts to increase.


```shell-session
pentester@AttackBox /usr/share/nmap/scripts# ls http*
http-adobe-coldfusion-apsa1301.nse      http-passwd.nse
http-affiliate-id.nse                   http-php-version.nse
http-apache-negotiation.nse             http-phpmyadmin-dir-traversal.nse
http-apache-server-status.nse           http-phpself-xss.nse
http-aspnet-debug.nse                   http-proxy-brute.nse
http-auth-finder.nse                    http-put.nse
http-auth.nse                           http-qnap-nas-info.nse
http-avaya-ipoffice-users.nse           http-referer-checker.nse
http-awstatstotals-exec.nse             http-rfi-spider.nse
http-axis2-dir-traversal.nse            http-robots.txt.nse
http-backup-finder.nse                  http-robtex-reverse-ip.nse
http-barracuda-dir-traversal.nse        http-robtex-shared-ns.nse
http-brute.nse                          http-security-headers.nse
http-cakephp-version.nse                http-server-header.nse
http-chrono.nse                         http-shellshock.nse
http-cisco-anyconnect.nse               http-sitemap-generator.nse
http-coldfusion-subzero.nse             http-slowloris-check.nse
http-comments-displayer.nse             http-slowloris.nse
http-config-backup.nse                  http-sql-injection.nse
http-cookie-flags.nse                   http-stored-xss.nse
http-cors.nse                           http-svn-enum.nse
http-cross-domain-policy.nse            http-svn-info.nse
http-csrf.nse                           http-title.nse
http-date.nse                           http-tplink-dir-traversal.nse
http-default-accounts.nse               http-trace.nse
http-devframework.nse                   http-traceroute.nse
http-dlink-backdoor.nse                 http-unsafe-output-escaping.nse
http-dombased-xss.nse                   http-useragent-tester.nse
http-domino-enum-passwords.nse          http-userdir-enum.nse
http-drupal-enum-users.nse              http-vhosts.nse
http-drupal-enum.nse                    http-virustotal.nse
http-enum.nse                           http-vlcstreamer-ls.nse
http-errors.nse                         http-vmware-path-vuln.nse
http-exif-spider.nse                    http-vuln-cve2006-3392.nse
http-favicon.nse                        http-vuln-cve2009-3960.nse
http-feed.nse                           http-vuln-cve2010-0738.nse
http-fetch.nse                          http-vuln-cve2010-2861.nse
http-fileupload-exploiter.nse           http-vuln-cve2011-3192.nse
http-form-brute.nse                     http-vuln-cve2011-3368.nse
http-form-fuzzer.nse                    http-vuln-cve2012-1823.nse
http-frontpage-login.nse                http-vuln-cve2013-0156.nse
http-generator.nse                      http-vuln-cve2013-6786.nse
http-git.nse                            http-vuln-cve2013-7091.nse
http-gitweb-projects-enum.nse           http-vuln-cve2014-2126.nse
http-google-malware.nse                 http-vuln-cve2014-2127.nse
http-grep.nse                           http-vuln-cve2014-2128.nse
http-headers.nse                        http-vuln-cve2014-2129.nse
http-huawei-hg5xx-vuln.nse              http-vuln-cve2014-3704.nse
http-icloud-findmyiphone.nse            http-vuln-cve2014-8877.nse
http-icloud-sendmsg.nse                 http-vuln-cve2015-1427.nse
http-iis-short-name-brute.nse           http-vuln-cve2015-1635.nse
http-iis-webdav-vuln.nse                http-vuln-cve2017-1001000.nse
http-internal-ip-disclosure.nse         http-vuln-cve2017-5638.nse
http-joomla-brute.nse                   http-vuln-cve2017-5689.nse
http-litespeed-sourcecode-download.nse  http-vuln-cve2017-8917.nse
http-ls.nse                             http-vuln-misfortune-cookie.nse
http-majordomo2-dir-traversal.nse       http-vuln-wnr1000-creds.nse
http-malware-host.nse                   http-waf-detect.nse
http-mcmp.nse                           http-waf-fingerprint.nse
http-method-tamper.nse                  http-webdav-scan.nse
http-methods.nse                        http-wordpress-brute.nse
http-mobileversion-checker.nse          http-wordpress-enum.nse
http-ntlm-info.nse                      http-wordpress-users.nse
http-open-proxy.nse                     http-xssed.nse
http-open-redirect.nse
```

You can specify to use any or a group of these installed scripts; moreover, you can install other userâ€™s scripts and use them for your scans. Letâ€™s begin with the default scripts. You can choose to run the scripts in the default category usingÂ `--script=default`Â or simply addingÂ `-sC`. In addition toÂ [default](https://nmap.org/nsedoc/categories/default.html), categories include auth, broadcast, brute, default, discovery, dos, exploit, external, fuzzer, intrusive, malware, safe, version, and vuln. A brief description is shown in the following table.

|Script Category|Description|
|---|---|
|`auth`|Authentication related scripts|
|`broadcast`|Discover hosts by sending broadcast messages|
|`brute`|Performs brute-force password auditing against logins|
|`default`|Default scripts, same asÂ `-sC`|
|`discovery`|Retrieve accessible information, such as database tables andÂ DNSÂ names|
|`dos`|Detects servers vulnerable to Denial of Service (DoS)|
|`exploit`|Attempts to exploit various vulnerable services|
|`external`|Checks using a third-party service, such as Geoplugin and Virustotal|
|`fuzzer`|Launch fuzzing attacks|
|`intrusive`|Intrusive scripts such as brute-force attacks and exploitation|
|`malware`|Scans for backdoors|
|`safe`|Safe scripts that wonâ€™t crash the target|
|`version`|Retrieve service versions|
|`vuln`|Checks for vulnerabilities or exploit vulnerable services|

Some scripts belong to more than one category. Moreover, some scripts launch brute-force attacks against services, while others launchÂ DoSÂ attacks and exploit systems. Hence, it is crucial to be careful when selecting scripts to run if you donâ€™t want to crash services or exploit them.

We useÂ NmapÂ to run a SYN scan againstÂ `10.10.137.154`Â and execute the default scripts in the console shown below. The command isÂ `sudo nmap -sS -sC 10.10.137.154`, whereÂ `-sC`Â will ensure that Nmap will execute the default scripts following the SYN scan. There are new details that appear below. Take a look at theÂ SSHÂ service at port 22; Nmap recovered all four public keys related to the running server. Consider another example, theÂ HTTPÂ service at port 80;Â NmapÂ retrieved the default page title. We can see that the page has been left as default.


```shell-session
pentester@TryHackMe$ sudo nmap -sS -sC 10.10.137.154

Starting Nmap 7.60 ( https://nmap.org ) at 2021-09-10 05:08 BST
Nmap scan report for ip-10-10-161-170.eu-west-1.compute.internal (10.10.161.170)
Host is up (0.0011s latency).
Not shown: 994 closed ports
PORT    STATE SERVICE
22/tcp  open  ssh
| ssh-hostkey: 
|   1024 d5:80:97:a3:a8:3b:57:78:2f:0a:78:ae:ad:34:24:f4 (DSA)
|   2048 aa:66:7a:45:eb:d1:8c:00:e3:12:31:d8:76:8e:ed:3a (RSA)
|   256 3d:82:72:a3:07:49:2e:cb:d9:87:db:08:c6:90:56:65 (ECDSA)
|_  256 dc:f0:0c:89:70:87:65:ba:52:b1:e9:59:f7:5d:d2:6a (EdDSA)
25/tcp  open  smtp
|_smtp-commands: debra2.thm.local, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, 
| ssl-cert: Subject: commonName=debra2.thm.local
| Not valid before: 2021-08-10T12:10:58
|_Not valid after:  2031-08-08T12:10:58
|_ssl-date: TLS randomness does not represent time
80/tcp  open  http
|_http-title: Welcome to nginx on Debian!
110/tcp open  pop3
|_pop3-capabilities: RESP-CODES CAPA TOP SASL UIDL PIPELINING AUTH-RESP-CODE
111/tcp open  rpcbind
| rpcinfo: 
|   program version   port/proto  service
|   100000  2,3,4        111/tcp  rpcbind
|   100000  2,3,4        111/udp  rpcbind
|   100024  1          38099/tcp  status
|_  100024  1          54067/udp  status
143/tcp open  imap
|_imap-capabilities: LITERAL+ capabilities IMAP4rev1 OK Pre-login ENABLE have LOGINDISABLEDA0001 listed SASL-IR ID more post-login LOGIN-REFERRALS IDLE
MAC Address: 02:A0:E7:B5:B6:C5 (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 2.21 seconds
```

You can also specify the script by name usingÂ `--script "SCRIPT-NAME"`Â or a pattern such asÂ `--script "ftp*"`, which would includeÂ `ftp-brute`. If you are unsure what a script does, you can open the script file with a text reader, such asÂ `less`, or a text editor. In the case ofÂ `ftp-brute`, it states: â€œPerforms brute force password auditing againstÂ FTPÂ servers.â€ You have to be careful as some scripts are pretty intrusive. Moreover, some scripts might be for a specific server and, if chosen at random, will waste your time with no benefit. As usual, make sure that you are authorized to launch such tests on the target server.

Letâ€™s consider a benign script,Â `http-date`, which we guess would retrieve the http server date and time, and this is indeed confirmed in its description: â€œGets the date fromÂ HTTP-like services. Also, it prints how much the date differs from local timeâ€¦â€ On the AttackBox, we executeÂ `sudo nmap -sS -n --script "http-date" 10.10.137.154`Â as shown in the console below.


```shell-session
pentester@TryHackMe$ sudo nmap -sS -n --script "http-date" 10.10.137.154

Starting Nmap 7.60 ( https://nmap.org ) at 2021-09-10 08:04 BST
Nmap scan report for 10.10.137.154
Host is up (0.0011s latency).
Not shown: 994 closed ports
PORT    STATE SERVICE
22/tcp  open  ssh
25/tcp  open  smtp
80/tcp  open  http
|_http-date: Fri, 10 Sep 2021 07:04:26 GMT; 0s from local time.
110/tcp open  pop3
111/tcp open  rpcbind
143/tcp open  imap
MAC Address: 02:44:87:82:AC:83 (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 1.78 seconds
```

## QUESTIONS
---
![Pasted image 20241111150351.png](../../IMAGES/Pasted%20image%2020241111150351.png)

### POC OF LAST QUESTION
---

![Pasted image 20241111150416.png](../../IMAGES/Pasted%20image%2020241111150416.png)

# Saving the Output
---

Whenever you run aÂ NmapÂ scan, it is only reasonable to save the results in a file. Selecting and adopting a good naming convention for your filenames is also crucial. The number of files can quickly grow and hinder your ability to find a previous scan result. The three main formats are:

```ad-summary
1. Normal
2. Grepable (`grep`able)
3. XML
```

There is a fourth one that we cannot recommend:

```ad-error
- Script Kiddie
```

  

### Normal
---

As the name implies, the normal format is similar to the output you get on the screen when scanning a target. You can save your scan in normal format by usingÂ `-oN FILENAME`; N stands for normal. Here is an example of the result.



```shell-session
pentester@TryHackMe$ cat MACHINE_IP_scan.nmap 
# Nmap 7.60 scan initiated Fri Sep 10 05:14:19 2021 as: nmap -sS -sV -O -oN MACHINE_IP_scan 10.10.57.244
Nmap scan report for 10.10.57.244
Host is up (0.00086s latency).
Not shown: 994 closed ports
PORT    STATE SERVICE VERSION
22/tcp  open  ssh     OpenSSH 6.7p1 Debian 5+deb8u8 (protocol 2.0)
25/tcp  open  smtp    Postfix smtpd
80/tcp  open  http    nginx 1.6.2
110/tcp open  pop3    Dovecot pop3d
111/tcp open  rpcbind 2-4 (RPC #100000)
143/tcp open  imap    Dovecot imapd
MAC Address: 02:A0:E7:B5:B6:C5 (Unknown)
Device type: general purpose
Running: Linux 3.X
OS CPE: cpe:/o:linux:linux_kernel:3.13
OS details: Linux 3.13
Network Distance: 1 hop
Service Info: Host:  debra2.thm.local; OS: Linux; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Sep 10 05:14:28 2021 -- 1 IP address (1 host up) scanned in 9.99 seconds
```

  

### Grepable
---

The grepable format has its name from the commandÂ `grep`; grep stands for Global Regular Expression Printer. In simple terms, it makes filtering the scan output for specific keywords or terms efficient. You can save the scan result in grepable format usingÂ `-oG FILENAME`. The scan output, displayed above in normal format, is shown in the console below using grepable format. The normal output is 21 lines; however, the grepable output is only 4 lines. The main reason is thatÂ NmapÂ wants to make each line meaningful and complete when the user appliesÂ `grep`. As a result, in grepable output, the lines are so long and are not convenient to read compared to normal output.


```shell-session
pentester@TryHackMe$ cat MACHINE_IP_scan.gnmap 
# Nmap 7.60 scan initiated Fri Sep 10 05:14:19 2021 as: nmap -sS -sV -O -oG MACHINE_IP_scan 10.10.57.244
Host: 10.10.57.244	Status: Up
Host: 10.10.57.244	Ports: 22/open/tcp//ssh//OpenSSH 6.7p1 Debian 5+deb8u8 (protocol 2.0)/, 25/open/tcp//smtp//Postfix smtpd/, 80/open/tcp//http//nginx 1.6.2/, 110/open/tcp//pop3//Dovecot pop3d/, 111/open/tcp//rpcbind//2-4 (RPC #100000)/, 143/open/tcp//imap//Dovecot imapd/	Ignored State: closed (994)	OS: Linux 3.13	Seq Index: 257	IP ID Seq: All zeros
# Nmap done at Fri Sep 10 05:14:28 2021 -- 1 IP address (1 host up) scanned in 9.99 seconds
```

An example use ofÂ `grep`Â isÂ `grep KEYWORD TEXT_FILE`; this command will display all the lines containing the provided keyword. Letâ€™s compare the output of usingÂ `grep`Â on normal output and grepable output. You will notice that the former does not provide the IP address of the host. Instead, it returnedÂ `80/tcp open http nginx 1.6.2`, making it very inconvenient if you are sifting through the scan results of multiple systems. However, the latter provides enough information, such as the hostâ€™s IP address, in each line to make it complete.


```shell-session
pentester@TryHackMe$ grep http MACHINE_IP_scan.nmap 
80/tcp  open  http    nginx 1.6.2
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
```


```shell-session
pentester@TryHackMe$ grep http MACHINE_IP_scan.gnmap 
Host: 10.10.57.244	Ports: 22/open/tcp//ssh//OpenSSH 6.7p1 Debian 5+deb8u8 (protocol 2.0)/, 25/open/tcp//smtp//Postfix smtpd/, 80/open/tcp//http//nginx 1.6.2/, 110/open/tcp//pop3//Dovecot pop3d/, 111/open/tcp//rpcbind//2-4 (RPC #100000)/, 143/open/tcp//imap//Dovecot imapd/	Ignored State: closed (994)	OS: Linux 3.13	Seq Index: 257	IP ID Seq: All zeros
```

  

### XML
----

The third format isÂ XML. You can save the scan results inÂ XMLÂ format usingÂ `-oX FILENAME`. TheÂ XMLÂ format would be most convenient to process the output in other programs. Conveniently enough, you can save the scan output in all three formats usingÂ `-oA FILENAME`Â to combineÂ `-oN`,Â `-oG`, andÂ `-oX`
for normal, grepable, andÂ XML.



### Script Kiddie
----
A fourth format is script kiddie. You can see that this format is useless if you want to search the output for any interesting keywords or keep the results for future reference. However, you can use it to save the output of the scanÂ `nmap -sS 127.0.0.1 -oS FILENAME`, display the output filename, and look 31337 in front of friends who are not tech-savvy.


```shell-session
pentester@TryHackMe$ cat MACHINE_IP_scan.kiddie 

$tart!ng nMaP 7.60 ( httpz://nMap.0rG ) at 2021-09-10 05:17 B$T
Nmap scan rEp0rt f0r |p-10-10-161-170.EU-w3$t-1.C0mputE.intErnaL (10.10.161.170)
HOSt !s uP (0.00095s LatEncy).
N0T $H0wn: 994 closed pOrtS
PoRT    st4Te SeRViC3 VERS1on
22/tcp  Open  ssH     Op3n$$H 6.7p1 Deb|an 5+dEb8u8 (pr0t0COl 2.0)
25/tCp  Op3n  SmTp    P0$Tf!x Smtpd
80/tcp  0p3n  http    Ng1nx 1.6.2
110/tCP 0pen  pOP3    d0v3coT P0p3D
111/TcP op3n  RpcbInd 2-4 (RPC #100000)
143/Tcp opEn  Imap    Dovecot 1mApd
mAC 4Ddr3sz: 02:40:e7:B5:B6:c5 (Unknown)
Netw0rk d!stanc3: 1 h0p
$3rv1c3 InFO: Ho$t:  dEBra2.thM.lOcal; 0s: Linux; cPe: cP3:/0:linux:l|nux_k3rnel

0S and servIc3 D3tEcti0n pErf0rm3d. Plea$e r3p0rt any !nc0RrecT rE$ultz at hTtpz://nmap.0rg/$ubmit/ .
Nmap d0nE: 1 |P addr3SS (1 hoSt up) $CaNnEd !n 21.80 s3c0Ndz
```
