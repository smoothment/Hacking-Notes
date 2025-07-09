# Introduction
---

â€œKnow your enemy, know his sword.â€ wrote Miyamoto Musashi in his book, A Book of Five Rings: The Classic Guide to Strategy. He also wrote, â€œYou win battles by knowing the enemyâ€™s timing, and using a timing which the enemy does not expect.â€ Although this was written when swords and spears won battles, it also applies to cyberspace, where attacks are launched via keyboards and crafted packets. The more you know about your targetâ€™s infrastructure and personnel, the better you can orchestrate your attacks.

In a red team operation, you might start with no more than a company name, from which you need to start gathering information about the target. This is where reconnaissance comes into play. Reconnaissance (recon) can be defined as a preliminary survey or observation of your target (client) without alerting them to your activities. If your recon activities create too much noise, the other party would be alerted, which might decrease the likelihood of your success.

The tasks of this room cover the following topics:

- Types of reconnaissance activities
- WHOIS andÂ DNS-based reconnaissance
- Advanced searching
- Searching by image
- Google Hacking
- Specialized search engines
- Recon-ng
- Maltego

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/66c311960c9ad71cbda3709d1c9804e2.png)  

Some specific objectives we'll cover include:

- Discovering subdomains related to our target company
- Gathering publicly available information about a host and IP addresses
- Finding email addresses related to the target
- Discovering login credentials and leaked passwords
- Locating leaked documents and spreadsheets

Reconnaissance can be broken down into two parts â€” passive reconnaissance and active reconnaissance, as explained in Task 2. In this room, we will be focusing on passive reconnaissance, i.e., techniques that donâ€™t alert the target or create 'noise'. In later rooms, we will use active reconnaissance tools that tend to be noisy by nature.

# Taxonomy of Reconnaissance
---

Reconnaissance (recon) can be classified into two parts:

1. **Passive Recon**: can be carried out by watching passively
2. **Active Recon**: requires interacting with the target to provoke it in order to observe its response.

Passive recon doesn't require interacting with the target. In other words, you aren't sending any packets or requests to the target or the systems your target owns. Instead, passive recon relies on publicly available information that is collected and maintained by a third party. Open Source Intelligence (OSINT) is used to collect information about the target and can be as simple as viewing a target's publicly available social media profile. Example information that we might collect includes domain names, IP address blocks, email addresses, employee names, and job posts. In the upcoming task, we'll see how to queryÂ DNSÂ records and expand on the topics from theÂ [Passive Reconnaissance](https://tryhackme.com/room/passiverecon)Â room and introduce advanced tooling to aid in your recon.

Active recon requires interacting with the target by sending requests and packets and observing if and how it responds. The responses collected - or lack of responses - would enable us to expand on the picture we started developing using passive recon. An example of active reconnaissance is usingÂ NmapÂ to scan target subnets and live hosts. Other examples can be found in theÂ [Active Reconnaissance](https://tryhackme.com/room/activerecon)Â room. Some information that we would want to discover include live hosts, running servers, listening services, and version numbers.

Active recon can be classified as:

1. **External Recon**: Conducted outside the target's network and focuses on the externally facing assets assessable from the Internet. One example is running Nikto from outside the company network.
2. **Internal Recon**: Conducted from within the target company's network. In other words, the pentester or red teamer might be physically located inside the company building. In this scenario, they might be using an exploited host on the target's network. An example would be using Nessus to scan the internal network using one of the targetâ€™s computers.


# Built-in Tools
---

This task focuses on:

- `whois`
- `dig`,Â `nslookup`,Â `host`
- `traceroute`/`tracert`

Before we start using theÂ `whois`Â tool, let's look at WHOIS. WHOIS is a request and response protocol that follows theÂ [RFC 3912](https://www.ietf.org/rfc/rfc3912.txt)Â specification. A WHOIS server listens on TCP port 43 for incoming requests. The domain registrar is responsible for maintaining the WHOIS records for the domain names it is leasing.Â `whois`Â will query the WHOIS server to provide all saved records. In the following example, we can seeÂ `whois`Â provides us with:

- Registrar WHOIS server
- Registrar URL
- Record creation date
- Record update date
- Registrant contact info and address (unless withheld for privacy)
- Admin contact info and address (unless withheld for privacy)
- Tech contact info and address (unless withheld for privacy)


```shell-session
pentester@TryHackMe$ whois thmredteam.com
[Querying whois.verisign-grs.com]
[Redirected to whois.namecheap.com]
[Querying whois.namecheap.com]
[whois.namecheap.com]
Domain name: thmredteam.com
Registry Domain ID: 2643258257_DOMAIN_COM-VRSN
Registrar WHOIS Server: whois.namecheap.com
Registrar URL: http://www.namecheap.com
Updated Date: 0001-01-01T00:00:00.00Z
Creation Date: 2021-09-24T14:04:16.00Z
Registrar Registration Expiration Date: 2022-09-24T14:04:16.00Z
Registrar: NAMECHEAP INC
Registrar IANA ID: 1068
Registrar Abuse Contact Email: abuse@namecheap.com
Registrar Abuse Contact Phone: +1.6613102107
Reseller: NAMECHEAP INC
Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited
Registry Registrant ID: 
Registrant Name: Withheld for Privacy Purposes
Registrant Organisation: Privacy service provided by Withheld for Privacy ehf
Registrant Street: Kalkofnsvegur 2 
Registrant City: Reykjavik
Registrant State/Province: Capital Region
Registrant Postal Code: 101
Registrant Country: IS
Registrant Phone: +354.4212434
Registrant Phone Ext: 
Registrant Fax: 
Registrant Fax Ext: 
Registrant Email: 4c9d5617f14e4088a4396b2f25430925.protect@withheldforprivacy.com
Registry Admin ID: 
Admin Name: Withheld for Privacy Purposes
[...]
Tech Name: Withheld for Privacy Purposes
[...]
Name Server: kip.ns.cloudflare.comName Server: uma.ns.cloudflare.com
DNSSEC: unsigned
URL of the ICANN WHOIS Data Problem Reporting System: http://wdprs.internic.net/
>>> Last update of WHOIS database: 2021-10-13T10:42:40.11Z <<<
For more information on Whois status codes, please visit https://icann.org/epp
```

As we can see above, it is possible to gain a lot of valuable information with only a domain name. After aÂ `whois`Â lookup, we might get lucky and find names, email addresses, postal addresses, and phone numbers, in addition to other technical information. At the end of theÂ `whois`Â query, we find the authoritative name servers for the domain in question.

DNSÂ queries can be executed with many different tools found on our systems, especially Unix-like systems. One common tool found on Unix-like systems, Windows, and macOS isÂ `nslookup`. In the following query, we can see howÂ `nslookup`Â uses the defaultÂ DNSÂ server to get the A and AAAA records related to our domain.

```shell-session
pentester@TryHackMe$ nslookup cafe.thmredteam.com
Server:		127.0.0.53
Address:	127.0.0.53#53

Non-authoritative answer:
Name:	cafe.thmredteam.com
Address: 104.21.93.169
Name:	cafe.thmredteam.com
Address: 172.67.212.249
Name:	cafe.thmredteam.com
Address: 2606:4700:3034::ac43:d4f9
Name:	cafe.thmredteam.com
Address: 2606:4700:3034::6815:5da9
```

Another tool commonly found on Unix-like systems isÂ `dig`, short for Domain Information Groper (dig).Â `dig`Â provides a lot of query options and even allows you to specify a different DNS server to use. For example, we can use Cloudflare's DNS server:Â `dig @1.1.1.1 tryhackme.com`.


```shell-session
pentester@TryHackMe$ dig cafe.thmredteam.com @1.1.1.1

; <<>> DiG 9.16.21-RH <<>> cafe.thmredteam.com @1.1.1.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 16698
;; flags: qr rd ra; QUERY: 1, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4096
;; QUESTION SECTION:
;cafe.thmredteam.com.		IN	A

;; ANSWER SECTION:
cafe.thmredteam.com.	3114	IN	A	104.21.93.169
cafe.thmredteam.com.	3114	IN	A	172.67.212.249

;; Query time: 4 msec
;; SERVER: 1.1.1.1#53(1.1.1.1)
;; WHEN: Thu Oct 14 10:44:11 EEST 2021
;; MSG SIZE  rcvd: 80
```

`host`Â is another useful alternative for queryingÂ DNSÂ servers forÂ DNSÂ records. Consider the following example.


```shell-session
pentester@TryHackMe$ host cafe.thmredteam.com
cafe.thmredteam.com has address 172.67.212.249
cafe.thmredteam.com has address 104.21.93.169
cafe.thmredteam.com has IPv6 address 2606:4700:3034::ac43:d4f9
cafe.thmredteam.com has IPv6 address 2606:4700:3034::6815:5da9
```

The final tool that ships with Unix-like systems isÂ `traceroute`, or on MS Windows systems,Â `tracert`. As the name indicates, it traces the route taken by the packets from our system to the target host. The console output below shows thatÂ `traceroute`Â provided us with the routers (hops) connecting us to the target system. It's worth stressing that some routers donâ€™t respond to the packets sent byÂ `traceroute`, and as a result, we donâ€™t see their IP addresses; aÂ `*`Â is used to indicate such a case.


```shell-session
pentester@TryHackMe$ traceroute cafe.thmredteam.com
traceroute to cafe.thmredteam.com (172.67.212.249), 30 hops max, 60 byte packets
 1  _gateway (192.168.0.1)  3.535 ms  3.450 ms  3.398 ms
 2  * * *
 3  * * *
 4  * * *
 5  * * *
 6  * * *
 7  172.16.79.229 (172.16.79.229)  4.663 ms  6.417 ms  6.347 ms
 8  * * *
 9  172.16.49.1 (172.16.49.1)  6.688 ms 172.16.48.1 (172.16.48.1)  6.671 ms 172.16.49.1 (172.16.49.1)  6.651 ms
10  213.242.116.233 (213.242.116.233)  96.769 ms 81.52.187.243 (81.52.187.243)  96.634 ms  96.614 ms
11  bundle-ether302.pastr4.paris.opentransit.net (193.251.131.116)  96.592 ms  96.689 ms  96.671 ms
12  193.251.133.251 (193.251.133.251)  96.679 ms  96.660 ms  72.465 ms
13  193.251.150.10 (193.251.150.10)  72.392 ms 172.67.212.249 (172.67.212.249)  91.378 ms  91.306 ms
```

In summary, we can always rely on:

- `whois`Â to query the WHOIS database
- `nslookup`,Â `dig`, orÂ `host`Â to queryÂ DNSÂ servers

WHOIS databases andÂ DNSÂ servers hold publicly available information, and querying either does not generate any suspicious traffic.

Moreover, we can rely on Traceroute (`traceroute`Â on Linux and macOS systems andÂ `tracert`Â on MS Windows systems) to discover the hops between our system and the target host.

![Pasted image 20250512135422.png](../../../IMAGES/Pasted%20image%2020250512135422.png)

# Advanced Searching
---

Being able to use a search engine efficiently is a crucial skill. The following table shows some popular search modifiers that work with many popular search engines.  

|Symbol / Syntax|Function|
|---|---|
|`"search phrase"`|Find results with exact search phrase|
|`OSINT filetype:pdf`|Find files of typeÂ `PDF`Â related to a certain term.|
|`salary site:blog.tryhackme.com`|Limit search results to a specific site.|
|`pentest -site:example.com`|Exclude a specific site from results|
|`walkthrough intitle:TryHackMe`|Find pages with a specific term in the page title.|
|`challenge inurl:tryhackme`|Find pages with a specific term in the page URL.|

Note: In addition toÂ `pdf`, other filetypes to consider are:Â `doc`,Â `docx`,Â `ppt`,Â `pptx`,Â `xls`Â andÂ `xlsx`.

Each search engine might have a slightly varied set of rules and syntax. To learn about the specific syntax for the different search engines, you will need to visit their respective help pages. Some search engines, such as Google, provide a web interface for advanced searches:Â [Google Advanced Search](https://www.google.com/advanced_search). Other times, it is best to learn the syntax by heart, such asÂ [Google Refine Web Searches](https://support.google.com/websearch/answer/2466433),Â [DuckDuckGo Search Syntax](https://help.duckduckgo.com/duckduckgo-help-pages/results/syntax/), andÂ [Bing Advanced Search Options](https://help.bing.microsoft.com/apex/index/18/en-US/10002).

Search engines crawl the world wide web day and night to index new web pages and files. Sometimes this can lead to indexing confidential information. Examples of confidential information include:

- Documents for internal company use
- Confidential spreadsheets with usernames, email addresses, and even passwords
- Files containing usernames
- Sensitive directories
- Service version number (some of which might be vulnerable and unpatched)
- Error messages

Combining advanced Google searches with specific terms, documents containing sensitive information or vulnerable web servers can be found. Websites such asÂ [Google Hacking Database](https://www.exploit-db.com/google-hacking-database)Â (GHDB) collect such search terms and are publicly available. Let's take a look at some of the GHDB queries to see if our client has any confidential information exposed via search engines. GHDB contains queries under the following categories:

- **Footholds**  
    ConsiderÂ [GHDB-ID: 6364](https://www.exploit-db.com/ghdb/6364)Â as it uses the queryÂ `intitle:"index of" "nginx.log"`Â to discover Nginx logs and might reveal server misconfigurations that can be exploited.
- **Files Containing Usernames**  
    For example,Â [GHDB-ID: 7047](https://www.exploit-db.com/ghdb/7047)Â uses the search termÂ `intitle:"index of" "contacts.txt"`Â to discover files that leak juicy information.
- **Sensitive Directories**  
    For example, considerÂ [GHDB-ID: 6768](https://www.exploit-db.com/ghdb/6768), which uses the search termÂ `inurl:/certs/server.key`Â to find out if a privateÂ RSAÂ key is exposed.
- **Web Server Detection**  
    ConsiderÂ [GHDB-ID: 6876](https://www.exploit-db.com/ghdb/6876), which detects GlassFish Server information using the queryÂ `intitle:"GlassFish Server - Server Running"`.
- **Vulnerable Files**  
    For example, we can try to locateÂ PHPÂ files using the queryÂ `intitle:"index of" "*.php"`, as provided byÂ [GHDB-ID: 7786](https://www.exploit-db.com/ghdb/7786).
- **Vulnerable Servers**  
    For instance, to discover SolarWinds Orion web consoles,Â [GHDB-ID: 6728](https://www.exploit-db.com/ghdb/6728)Â uses the queryÂ `intext:"user name" intext:"orion core" -solarwinds.com`.
- **Error Messages**  
    Plenty of useful information can be extracted from error messages. One example isÂ [GHDB-ID: 5963](https://www.exploit-db.com/ghdb/5963), which uses the queryÂ `intitle:"index of" errors.log`Â to find log files related to errors.

You might need to adapt these Google queries to fit your needs as the queries will return results from all web servers that fit the criteria and were indexed. To avoid legal issues, it is best to refrain from accessing any files outside the scope of your legal agreement.

We recommend you join theÂ [Google Dorking](https://tryhackme.com/room/googledorking)Â room for more in-depth information.

Now we'll explore two additional sources that can provide valuable information without interacting with our target:

- Social Media
- Job ads

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/f94dadbbcf2c644230d6eb310e159ed5.png)

### Social Media

Social media websites have become very popular for not only personal use but also for corporate use. Some social media platforms can reveal tons of information about the target. This is especially true as many users tend to overshare details about themselves and their work. To name a few, it's worthwhile checking the following:

- LinkedIn
- Twitter
- Facebook
- Instagram

Social media websites make it easy to collect the names of a given company's employees; moreover, in certain instances, you might learn specific pieces of information that can reveal answers to password recovery questions or gain ideas to include in a targeted wordlist. Posts from technical staff might reveal details about a companyâ€™s systems and vendors. For example, a network engineer who was recently issued Juniper certifications may allude to Juniper networking infrastructure being used in their employerâ€™s environment.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/cf84f21108b6aae75e1fa73018bf12db.png)  

### Job Ads

Job advertisements can also tell you a lot about a company. In addition to revealing names and email addresses, job posts for technical positions could give insight into the target companyâ€™s systems and infrastructure. The popular job posts might vary from one country to another. Make sure to check job listing sites in the countries where your client would post their ads. Moreover, it is always worth checking their website for any job opening and seeing if this can leak any interesting information.

Note that theÂ [Wayback Machine](https://archive.org/web/)Â can be helpful to retrieve previous versions of a job opening page on your clientâ€™s site.

# Specialized Search Engines
---

### WHOIS andÂ DNSÂ Related

Beyond the standard WHOIS andÂ DNSÂ query tools that we covered in Task 3, there are third parties that offer paid services for historical WHOIS data. One example is WHOIS history, which provides a history of WHOIS data and can come in handy if the domain registrant didnâ€™t use WHOIS privacy when they registered the domain.

There are a handful of websites that offer advancedÂ DNSÂ services that are free to use. Some of these websites offer rich functionality and could have a complete room dedicated to exploring one domain. For now, we'll focus on keyÂ DNSÂ related aspects. We will consider the following:

- [ViewDNS.info](https://viewdns.info/)
- [Threat Intelligence Platform](https://threatintelligenceplatform.com/)

### ViewDNS.info

[ViewDNS.info](https://viewdns.info/)Â offersÂ _Reverse IP Lookup_. Initially, each web server would use one or more IP addresses; however, today, it is common to come across shared hosting servers. With shared hosting, one IP address is shared among many different web servers with different domain names. With reverse IP lookup, starting from a domain name or an IP address, you can find the other domain names using a specific IP address(es).

In the figure below, we used reverse IP lookup to find other servers sharing the same IP addresses used byÂ `cafe.thmredteam.com`. Therefore, it is important to note that knowing the IP address does not necessarily lead to a single website.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/a6a57e946b742bf9439430c1669382a5.png)

### Threat Intelligence Platform

[Threat Intelligence Platform](https://threatintelligenceplatform.com/)Â requires you to provide a domain name or an IP address, and it will launch a series of tests from malware checks to WHOIS andÂ DNSÂ queries. The WHOIS andÂ DNSÂ results are similar to the results we would get usingÂ `whois`Â andÂ `dig`, but Threat Intelligence Platform presents them in a more readable and visually appealing way. There is extra information that we get with our report. For instance, after we look upÂ `thmredteam.com`, we see that Name Server (NS) records were resolved to their respective IPv4 and IPv6 addresses, as shown in the figure below.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/8ba0fec5aad89cfb7c3d242ed92c9da4.png)

On the other hand, when we searched forÂ `cafe.thmredteam.com`, we could also get a list of other domains on the same IP address. The result we see in the figure below is similar to the results we obtained usingÂ [ViewDNS.info](https://viewdns.info/).

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/c920bcf224185c47c4ba54b300079e48.png)

### Specialized Search Engines

#### Censys

[Censys Search](https://search.censys.io/)Â can provide a lot of information about IP addresses and domains. In this example, we look up one of the IP addresses thatÂ `cafe.thmredteam.com`Â resolves to. We can easily infer that the IP address we looked up belongs to Cloudflare. We can see information related to ports 80 and 443, among others; however, it's clear that this IP address is used to server websites other thanÂ `cafe.thmredteam.com`. In other words, this IP address belongs to a company other than our client,Â [Organic Cafe](https://cafe.thmredteam.com/). It's critical to make this distinction so that we donâ€™t probe systems outside the scope of our contract.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/efc8f98cc9e721707d4bad477340e120.png)

#### Shodan

You might remember usingÂ [Shodan](https://www.shodan.io/)Â in theÂ [Passive Reconnaissance](https://tryhackme.com/room/passiverecon)Â room. In this section, we will demonstrate how to use Shodan from the command line.

To use Shodan from the command-line properly, you need to create an account withÂ [Shodan](https://www.shodan.io/), then configureÂ `shodan`Â to use your API key using the command,Â `shodan init API_KEY`.

You can use different filters depending on theÂ [type of your Shodan account](https://account.shodan.io/billing). To learn more about what you can do withÂ `shodan`, we suggest that you check outÂ [Shodan CLI](https://cli.shodan.io/). Letâ€™s demonstrate a simple example of looking up information about one of the IP addresses we got fromÂ `nslookup cafe.thmredteam.com`. UsingÂ `shodan host IP_ADDRESS`, we can get the geographical location of the IP address and the open ports, as shown below.


```shell-session
pentester@TryHackMe$ shodan host 172.67.212.249

172.67.212.249
City:                    San Francisco
Country:                 United States
Organisation:            Cloudflare, Inc.
Updated:                 2021-11-22T05:55:54.787113
Number of open ports:    5

Ports:
     80/tcp  
    443/tcp  
	|-- SSL Versions: -SSLv2, -SSLv3, -TLSv1, -TLSv1.1, TLSv1.2, TLSv1.3
   2086/tcp  
   2087/tcp  
   8080/tcp 
```

# Recon-ng
----

[Recon-ng](https://github.com/lanmaster53/recon-ng)Â is a framework that helps automate theÂ OSINTÂ work. It uses modules from various authors and provides a multitude of functionality. Some modules require keys to work; the key allows the module to query the related onlineÂ API. In this task, we will demonstrate using Recon-ng in the terminal.

From a penetration testing and red team point of view, Recon-ng can be used to find various bits and pieces of information that can aid in an operation orÂ OSINTÂ task. All the data collected is automatically saved in the database related to your workspace. For instance, you might discover host addresses to later port-scan or collect contact email addresses forÂ phishingÂ attacks.

You can start Recon-ng by running the commandÂ `recon-ng`. Starting Recon-ng will give you a prompt likeÂ `[recon-ng][default] >`. At this stage, you need to select the installed module you want to use. However, if this is the first time you're runningÂ `recon-ng`, you will need to install the module(s) you need.

In this task, we will follow the following workflow:

1. Create a workspace for your project
2. Insert the starting information into the database
3. Search the marketplace for a module and learn about it before installing
4. List the installed modules and load one
5. Run the loaded module

### Creating a Workspace

RunÂ `workspaces create WORKSPACE_NAME`Â to create a new workspace for your investigation. For example,Â `workspaces create thmredteam`Â will create a workspace namedÂ `thmredteam`.

`recon-ng -w WORKSPACE_NAME`Â starts recon-ng with the specific workspace.

### Seeding the Database

In reconnaissance, you are starting with one piece of information and transforming it into new pieces of information. For instance, you might start your research with a company name and use that to discover the domain name(s), contacts and profiles. Then you would use the new information you obtained to transform it further and learn more about your target.

Letâ€™s consider the case where we know the target's domain name,Â `thmredteam.com`, and we would like to feed it into the Recon-ng database related to the active workspace. If we want to check the names of the tables in our database, we can runÂ `db schema`.

We want to insert the domain nameÂ `thmredteam.com`Â into the domains table. We can do this using the commandÂ `db insert domains`.

Pentester Terminal

```shell-session
pentester@TryHackMe$ recon-ng -w thmredteam
[...]
[recon-ng][thmredteam] > db insert domains
domain (TEXT): thmredteam.com
notes (TEXT): 
[*] 1 rows affected.
[recon-ng][thmredteam] > marketplace search
```

### Recon-ng Marketplace

We have a domain name, so a logical next step would be to search for a module that transforms domains into other types of information. Assuming we are starting from a fresh installation of Recon-ng, we will search for suitable modules from the marketplace.

Before you install modules using the marketplace, these are some useful commands related to marketplace usage:

- `marketplace search KEYWORD`Â to search for available modules withÂ _keyword_.
- `marketplace info MODULE`Â to provide information about the module in question.
- `marketplace install MODULE`Â to install the specified module into Recon-ng.
- `marketplace remove MODULE`Â to uninstall the specified module.

The modules are grouped under multiple categories, such as discovery, import, recon and reporting. Moreover, recon is also divided into many subcategories depending on the transform type. RunÂ `marketplace search`Â to get a list of all available modules.

In the terminal below, we search for modules containingÂ `domains-`.

Pentester Terminal

```shell-session
pentester@TryHackMe$ recon-ng -w thmredteam
[...]
[recon-ng][thmredteam] > marketplace search domains-
[*] Searching module index for 'domains-'...

  +---------------------------------------------------------------------------------------------------+
  |                        Path                        | Version |     Status    |  Updated   | D | K |
  +---------------------------------------------------------------------------------------------------+
  | recon/domains-companies/censys_companies           | 2.0     | not installed | 2021-05-10 | * | * |
  | recon/domains-companies/pen                        | 1.1     | not installed | 2019-10-15 |   |   |
  | recon/domains-companies/whoxy_whois                | 1.1     | not installed | 2020-06-24 |   | * |
  | recon/domains-contacts/hunter_io                   | 1.3     | not installed | 2020-04-14 |   | * |
  | recon/domains-contacts/metacrawler                 | 1.1     | not installed | 2019-06-24 | * |   |
  | recon/domains-contacts/pen                         | 1.1     | not installed | 2019-10-15 |   |   |
  | recon/domains-contacts/pgp_search                  | 1.4     | not installed | 2019-10-16 |   |   |
  | recon/domains-contacts/whois_pocs                  | 1.0     | not installed | 2019-06-24 |   |   |
  | recon/domains-contacts/wikileaker                  | 1.0     | not installed | 2020-04-08 |   |   |
  | recon/domains-credentials/pwnedlist/account_creds  | 1.0     | not installed | 2019-06-24 | * | * |
  | recon/domains-credentials/pwnedlist/api_usage      | 1.0     | not installed | 2019-06-24 |   | * |
  | recon/domains-credentials/pwnedlist/domain_creds   | 1.0     | not installed | 2019-06-24 | * | * |
  | recon/domains-credentials/pwnedlist/domain_ispwned | 1.0     | not installed | 2019-06-24 |   | * |
  | recon/domains-credentials/pwnedlist/leak_lookup    | 1.0     | not installed | 2019-06-24 |   |   |
  | recon/domains-credentials/pwnedlist/leaks_dump     | 1.0     | not installed | 2019-06-24 |   | * |
  | recon/domains-domains/brute_suffix                 | 1.1     | not installed | 2020-05-17 |   |   |
  | recon/domains-hosts/binaryedge                     | 1.2     | not installed | 2020-06-18 |   | * |
  | recon/domains-hosts/bing_domain_api                | 1.0     | not installed | 2019-06-24 |   | * |
  | recon/domains-hosts/bing_domain_web                | 1.1     | not installed | 2019-07-04 |   |   |
  | recon/domains-hosts/brute_hosts                    | 1.0     | not installed | 2019-06-24 |   |   |
  | recon/domains-hosts/builtwith                      | 1.1     | not installed | 2021-08-24 |   | * |
  | recon/domains-hosts/censys_domain                  | 2.0     | not installed | 2021-05-10 | * | * |
  | recon/domains-hosts/certificate_transparency       | 1.2     | not installed | 2019-09-16 |   |   |
  | recon/domains-hosts/google_site_web                | 1.0     | not installed | 2019-06-24 |   |   |
  | recon/domains-hosts/hackertarget                   | 1.1     | not installed | 2020-05-17 |   |   |
  | recon/domains-hosts/mx_spf_ip                      | 1.0     | not installed | 2019-06-24 |   |   |
  | recon/domains-hosts/netcraft                       | 1.1     | not installed | 2020-02-05 |   |   |
  | recon/domains-hosts/shodan_hostname                | 1.1     | not installed | 2020-07-01 | * | * |
  | recon/domains-hosts/spyse_subdomains               | 1.1     | not installed | 2021-08-24 |   | * |
  | recon/domains-hosts/ssl_san                        | 1.0     | not installed | 2019-06-24 |   |   |
  | recon/domains-hosts/threatcrowd                    | 1.0     | not installed | 2019-06-24 |   |   |
  | recon/domains-hosts/threatminer                    | 1.0     | not installed | 2019-06-24 |   |   |
  | recon/domains-vulnerabilities/ghdb                 | 1.1     | not installed | 2019-06-26 |   |   |
  | recon/domains-vulnerabilities/xssed                | 1.1     | not installed | 2020-10-18 |   |   |
  +---------------------------------------------------------------------------------------------------+

  D = Has dependencies. See info for details.
  K = Requires keys. See info for details.

[recon-ng][thmredteam] >
```

We notice many subcategories underÂ `recon`, such asÂ `domains-companies`,Â `domains-contacts`, andÂ `domains-hosts`. This naming tells us what kind of new information we will get from that transformation. For instance,Â `domains-hosts`Â means that the module will find hosts related to the provided domain.

Some modules, likeÂ `whoxy_whois`, require a key, as we can tell from theÂ `*`Â under theÂ `K`Â column. This requirement indicates that this module is not usable unless we have a key to use the related service.

Other modules have dependencies, indicated by aÂ `*`Â under theÂ `D`Â column. Dependencies show that third-party Python libraries might be necessary to use the related module.

Letâ€™s say that you are interested inÂ `recon/domains-hosts/google_site_web`. To learn more about any particular module, you can use the commandÂ `marketplace info MODULE`; this is an essential command that explains what the module does. For example,Â `marketplace info google_site_web`Â provides the following description: â€œHarvests hosts from Google.com by using the â€˜siteâ€™ search operator. Updates the â€˜hostsâ€™ table with the results.â€ In other words, this module will use the Google search engine and the â€œsiteâ€ operator.

We can install the module we want with the commandÂ `marketplace install MODULE`, for example,Â `marketplace install google_site_web`.

### Working with Installed Modules

We can work with modules using:

- `modules search`Â to get a list of all the installed modules
- `modules load MODULE`Â to load a specific module to memory

Letâ€™s load the module that we installed earlier from the marketplace,Â `modules load viewdns_reverse_whois`. ToÂ `run`Â it, we need to set the required options.

- `options list`Â to list the options that we can set for the loaded module.
- `options set <option> <value>`Â to set the value of the option.

In a previous step, we have installed the moduleÂ `google_site_web`, so letâ€™s load it usingÂ `load google_site_web`Â and run it withÂ `run`. We have already added the domainÂ `thmredteam.com`Â to the database, so when the module is run, it will read that value from the database, get new kinds of information, and add them to the database in turn. The commands and the results are shown in the terminal output below.

Pentester Terminal

```shell-session
pentester@TryHackMe$ recon-ng -w thmredteam
[...]
[recon-ng][thmredteam] > load google_site_web
[recon-ng][thmredteam][google_site_web] > run

--------------
THMREDTEAM.COM
--------------
[*] Searching Google for: site:thmredteam.com
[*] Country: None
[*] Host: cafe.thmredteam.com
[*] Ip_Address: None
[*] Latitude: None
[*] Longitude: None
[*] Notes: None
[*] Region: None
[*] --------------------------------------------------
[*] Country: None
[*] Host: clinic.thmredteam.com
[*] Ip_Address: None
[*] Latitude: None
[*] Longitude: None
[*] Notes: None
[*] Region: None
[*] --------------------------------------------------
[...]
[*] 2 total (2 new) hosts found.
[recon-ng][thmredteam][google_site_web] >
```

This module has queried Google and discovered two hosts,Â `cafe.thmredteam.com`Â andÂ `clinic.thmredteam.com`. It is possible that by the time you run these steps, new hosts will also appear.

### Keys

Some modules cannot be used without a key for the respective serviceÂ API.Â `K`Â indicates that you need to provide the relevant service key to use the module in question.

- `keys list`Â lists the keys
- `keys add KEY_NAME KEY_VALUE`Â adds a key
- `keys remove KEY_NAME`Â removes a key

Once you have the set of modules installed, you can proceed to load and run them.

- `modules load MODULE`Â loads an installed module
- `CTRL + C`Â unloads the module.
- `info`Â to review the loaded moduleâ€™s info.
- `options list`Â lists available options for the chosen module.
- `options set NAME VALUE`
- `run`Â to execute the loaded module.

### Demo

To wrap up, use the following demonstration provided below containing all the steps we have explained earlier.

UseÂ `recon-ng`Â to repeat the steps we carried out againstÂ `thmredteam.com`, then answer the following questions.

![Pasted image 20250512142125.png](../../../IMAGES/Pasted%20image%2020250512142125.png)

# Maltego
---

[Maltego](https://www.maltego.com/)Â is an application that blends mind-mapping withÂ OSINT. In general, you would start with a domain name, company name, personâ€™s name, email address, etc. Then you can let this piece of information go through various transforms.  

The information collected in Maltego can be used for later stages. For instance, company information, contact names, and email addresses collected can be used to create very legitimate-lookingÂ phishingÂ emails.

Think of each block on a Maltego graph as an entity. An entity can have values to describe it. In Maltegoâ€™s terminology, aÂ **transform**Â is a piece of code that would query anÂ APIÂ to retrieve information related to a specific entity. The logic is shown in the figure below.Â _Information_Â related to an entity goes via aÂ _transform_Â to return zero or more entities.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/2e8ac9b5c947e1af26b7b9e24c5f8361.png)

It is crucial to mention that some of the transforms available in Maltego might actively connect to the target system. Therefore, it is better to know how the transform works before using it if you want to limit yourself to passive reconnaissance.

Every transform might lead to several new values. For instance, if we start from the â€œDNSÂ Nameâ€Â `cafe.thmredteam.com`, we expect to get new kinds of entities based on the transform we use. For instance, â€œTo IP Addressâ€ is expected to return IP addresses as shown next.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/948575bd71d1305e8505c854ac9b81e0.png)

One way to achieve this on Maltego is to right-click on the â€œDNSÂ Nameâ€Â `cafe.thmredteam.com`Â and choose:

1. Standard Transforms
2. Resolve to IP
3. To IP Address (DNS)

After executing this transform, we would get one or more IP addresses, as shown below.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/956d258d9b72d88bb6e088c2f2b4690f.png)

Then we can choose to apply another transform for one of the IP addresses. Consider the following transform:

1. DNSÂ from IP
2. ToÂ DNSÂ Name from passiveÂ DNSÂ (Robtex)

This transform will populate our graph with newÂ DNSÂ names. With a couple more clicks, you can get the location of the IP address, and so on. The result might be similar to the image below.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/3d05e45bd6021ca651892542b06f4230.png)

The above two examples should give you an idea of the workflow using Maltego. You can observe that all the work is based on transforms, and Maltego will help you keep your graph organized. You would get the same results by querying the different online websites and databases; however, Maltego helps you get all the information you need with a few clicks.

We experimented withÂ `whois`Â andÂ `nslookup`Â in a previous task. You get plenty of information, from names and email addresses to IP addresses. The results ofÂ `whois`Â andÂ `nslookup`Â are shown visually in the following Maltego graph. Interestingly, Maltego transforms were able to extract and arrange the information returned from the WHOIS database. Although the returned email addresses are not helpful due to privacy protection, it is worth seeing how Maltego can extract such information and how it's presented.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/c54a869cffca4d657f46dac618cc9135.png)

Now that we have learned how Maltegoâ€™s power stems from its transforms, the only logical thing is to make Maltego more powerful by adding new Transforms. Transforms are usually grouped into different categories based on data type, pricing, and target audience. Although many transforms can be used using Maltego Community Edition and free transforms, other transforms require a paid subscription. A screenshot is shown below to give a clearer idea.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/adc8ab512edcf6fef5414d434d7577a1.png)

Using Maltego requires activation, even if you opt for Maltego CE (Community Edition). Therefore, the following questions can be answered by visitingÂ [Maltego Transform Hub](https://www.maltego.com/transform-hub/)Â or by installing and activating Maltego CE on your own system (not on the AttackBox).

![Pasted image 20250512142318.png](../../../IMAGES/Pasted%20image%2020250512142318.png)

# Summary
---

Sun Tzu once said, â€œIf you know the enemy and know yourself, you need not fear the result of a hundred battles. If you know yourself but not the enemy, for every victory gained you will also suffer a defeat. If you know neither the enemy nor yourself, you will succumb in every battle.â€ Fast forward to the cyber warfare era; in addition to knowing our red team skillset and capabilities, we need to gain as much information about the target as possible. The terrain is constantly evolving, and new ways to collect data are becoming possible.

We have reviewed essential built-in tools such asÂ `whois`,Â `dig`, andÂ `tracert`. Moreover, we explored the power of search engines to aid in our passive reconnaissance activities. Finally, we demonstrated two tools, Recon-ng and Maltego, that allow us to collect information from various sources and present them in one place.

The purpose is to expand our knowledge about the target and collect various information that can be leveraged in the subsequent attack phases. For instance, hosts that are discovered can be scanned and probed for vulnerabilities, while contact information and email addresses can be used to launchÂ phishingÂ campaigns efficiently. In brief, the more information we gather about the target, the more we can refine our attacks and increase our chances of success.
