Have you ever wondered how your computer can dynamically configure its network settings when you turn it on or connect it to a new network? Have you ever wanted to know how many devices and countries your packets passed through before reaching their destination? Are you curious how all your home devices can access the Internet even though your ISP gives you a single IP address?

If you want to know the answers to these questions, among others, then this room is for you.

This room is the second room in a series of four rooms about computer networking:

- [Networking Concepts](https://tryhackme.com/r/room/networkingconcepts)
- Networking Essentials (this room)
- [Networking Core Protocols](https://tryhackme.com/r/room/networkingcoreprotocols)
- [Networking Secure Protocols](https://tryhackme.com/r/room/networkingsecureprotocols)

### Learning Prerequisites

To benefit from this room, we recommend that you know the following:

- ISO OSI model and layers
- TCP/IP model and layers
- Ethernet, IP, andÂ TCPÂ protocols

In other words, starting this room afterÂ [Networking Concepts](https://tryhackme.com/r/room/networkingconcepts)Â is the recommended approach.

### Learning Objectives

The objective of this room is to teach you about various standard protocols and technologies that glue things together:

```ad-summary
- Dynamic Host Configuration Protocol (DHCP)
- Address Resolution Protocol (ARP)
- Network Address Translation (NAT)
- Internet Control Message Protocol (ICMP)
    - Ping
    - Traceroute
```


# DHCP: GIVE ME MY NETWORK SETTINGS


You went to your favourite coffee shop, grabbed your favourite hot drink, and opened your laptop. Your laptop connected to the shopâ€™s WiFi and automatically configured the network, so you could now work on a new TryHackMe room. You didnâ€™t type a single IP address, yet your device is all set up. Letâ€™s see how this happened.

Whenever we want to access a network, at the very least, we need to configure the following:

- IP address along with subnet mask
- Router (or gateway)
- DNSÂ server

Whenever we connect our device to a new network, the above configurations must be set according to the new network. Manually configuring these settings is a good option, especially for servers. Servers are not expected to switch networks; you donâ€™t carry your domain controller and connect it to the coffee shop WiFi. Moreover, other devices need to connect to the servers and expect to find them at specific IP addresses.

Having an automated way to configure connected devices has many advantages. First, it would save us from manually configuring the network; this is extremely important, especially for mobile devices. Secondly, it saves us from address conflicts, i.e., when two devices are configured with the same IP address. An IP address conflict would prevent the involved hosts from using the network resources; this applies to local resources and the Internet. The solution lies in using Dynamic Host Configuration Protocol (DHCP). DHCP is an application-level protocol that relies onÂ UDP; the server listens onÂ UDPÂ port 67, and the client sends fromÂ UDPÂ port 68. Your smartphone and laptop are configured to useÂ DHCPÂ by default.

![In the DHCP protocol, DORA stands for Discover, Offer, Request, and Acknowledge.](https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/5f04259cf9bf5b57aed2c476-1719849114115.svg)  

DHCPÂ follows four steps: Discover, Offer, Request, and Acknowledge (DORA):

1. **DHCPÂ Discover**: The client broadcasts a DHCPDISCOVER message seeking the localÂ DHCPÂ server if one exists.
2. **DHCPÂ Offer**: The server responds with a DHCPOFFER message with an IP address available for the client to accept.
3. **DHCPÂ Request**: The client responds with a DHCPREQUEST message to indicate that it has accepted the offered IP.
4. **DHCPÂ Acknowledge**: The server responds with a DHCPACK message to confirm that the offered IP address is now assigned to this client.

![A laptop sends a DHCP Discover, the server responds with a DHCP Offer, the laptop responds with a DHCP Request, and finally, the server responds with a DHCP Acknowledge.](https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/5f04259cf9bf5b57aed2c476-1719849148646.svg)  

The following packet capture shows the four steps explained above. In this example, the client gets the addressÂ `192.168.66.133`.

Terminal

```shell-session
user@TryHackMe$ tshark -r DHCP-G5000.pcap -n
    1   0.000000      0.0.0.0 â†’ 255.255.255.255 DHCP 342 DHCP Discover - Transaction ID 0xfb92d53f
    2   0.013904 192.168.66.1 â†’ 192.168.66.133 DHCP 376 DHCP Offer    - Transaction ID 0xfb92d53f
    3   4.115318      0.0.0.0 â†’ 255.255.255.255 DHCP 342 DHCP Request  - Transaction ID 0xfb92d53f
    4   4.228117 192.168.66.1 â†’ 192.168.66.133 DHCP 376 DHCP ACK      - Transaction ID 0xfb92d53f
```

In theÂ DHCPÂ packet exchange, we can notice the following:

- The client starts without any IP network configuration. It only has a MAC address. In the first and third packets,Â DHCPÂ Discover andÂ DHCPÂ Request, the client searching for aÂ DHCPÂ server still has no IP network configuration and has not yet used theÂ DHCPÂ serverâ€™s offered IP address. Therefore, it sends packets from the IP addressÂ `0.0.0.0`Â to the broadcast IP addressÂ `255.255.255.255`.
- As for the link layer, in the first and third packets, the client sends to the broadcast MAC address,Â `ff:ff:ff:ff:ff:ff`Â (not shown in the output above). TheÂ DHCPÂ server offers an available IP address along with the network configuration in theÂ DHCPÂ offer. It uses the clientâ€™s destination MAC address. (It used the proposed IP address in this example system.)

At the end of theÂ DHCPÂ process, our device would have received all the configuration needed to access the network or even the Internet. In particular, we expect that theÂ DHCPÂ server has provided us with the following:

```ad-note
- The leased IP address to access network resources
- The gateway to route our packets outside the local network
- AÂ DNSÂ server to resolve domain names (more on this later)
```

## QUESTIONS

![Pasted image 20241101145235.png](../../IMAGES/Pasted%20image%2020241101145235.png)


# ARP: BRIDGING LAYER 3 ADDRESSING TO LAYER 2 ADDRESSING


We have stated in theÂ [Networking Concepts](https://tryhackme.com/r/room/networkingconcepts)Â room that as two hosts communicate over a network, an IP packet is encapsulated within a data link frame as it travels over layer 2. Remember that the two common data link layers we use are Ethernet (IEEE 802.3) and WiFi (IEEE 802.11). Whenever one host needs to communicate with another host on the same Ethernet or WiFi, it must send the IP packet within a data link layer frame. Although it knows the IP address of the target host, it needs to look up the targetâ€™s MAC address so the proper data link header can be created.

As you would remember, a MAC address is a 48-bit number typically represented in hexadecimal notation; for example,Â `7C:DF:A1:D3:8C:5C`Â andÂ `44:DF:65:D8:FE:6C`Â are two MAC addresses on my network.

However, the devices on the same Ethernet network do not need to know each otherâ€™s MAC addresses all the time; they only need to know each otherâ€™s MAC addresses while communicating. Everything revolves around IP addresses. Consider this scenario: You connect your device to a network, and if the network has a DHCP server, your device is automatically configured to use a specific gateway (router) andÂ DNSÂ server. Consequently, your device knows the IP address of theÂ DNSÂ server to resolve any domain name; moreover, it knows the IP address of the router when it needs to send packets over the Internet. In all this scenario, no MAC addresses are revealed. However, two devices on the same Ethernet cannot communicate without knowing each otherâ€™s MAC addresses.

As a reminder, in the screenshot below, we see an IP packet within an Ethernet frame. The Ethernet frame header contains:

```ad-summary
- Destination MAC address
- Source MAC address
- Type (IPv4 in this case)
```

![Wireshark showing the destination MAC address, source MAC address, and the protocol type in an Ethernet frame. The IP packet is encapsulated within this Ethernet frame.](https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/5f04259cf9bf5b57aed2c476-1719849170421.png)  

Address Resolution Protocol (ARP) makes it possible to find the MAC address of another device on the Ethernet. In the example below, a host with the IP addressÂ `192.168.66.89`Â wants to communicate with another system with the IP addressÂ `192.168.66.1`. It sends anÂ ARPÂ Request asking the host with the IP addressÂ `192.168.66.1`Â to respond. TheÂ ARPÂ Request is sent from the MAC address of the requester to the broadcast MAC address,Â `ff:ff:ff:ff:ff:ff`Â as shown in the first packet. TheÂ ARPÂ Reply arrived shortly afterwards, and the host with the IP addressÂ `192.168.66.1`Â responded with its MAC address. From this point, the two hosts can exchange data link layer frames.


```shell-session
user@TryHackMe$ tshark -r arp.pcapng -Nn
    1 0.000000000 cc:5e:f8:02:21:a7 â†’ ff:ff:ff:ff:ff:ff ARP 42 Who has 192.168.66.1? Tell 192.168.66.89
    2 0.003566632 44:df:65:d8:fe:6c â†’ cc:5e:f8:02:21:a7 ARP 42 192.168.66.1 is at 44:df:65:d8:fe:6c
```

If we useÂ `tcpdump`, the packets will be displayed differently. It uses the termsÂ ARPÂ **Request**Â andÂ ARPÂ **Reply**. For your information, the output is shown in the terminal below.


```shell-session
user@TryHackMe$ tcpdump -r arp.pcapng -n -v
17:23:44.506615 ARP, Ethernet (len 6), IPv4 (len 4), Request who-has 192.168.66.1 tell 192.168.66.89, length 28
17:23:44.510182 ARP, Ethernet (len 6), IPv4 (len 4), Reply 192.168.66.1 is-at 44:df:65:d8:fe:6c, length 28
```

AnÂ ARPÂ Request orÂ ARPÂ Reply is not encapsulated within a UDP or even IP packet; it is encapsulated directly within an Ethernet frame. The followingÂ ARPÂ Reply shows this.

![Wireshark showing an ARP Reply encapsulated directly within an Ethernet frame.](https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/5f04259cf9bf5b57aed2c476-1719849185596.png)  

ARPÂ is considered layer 2 because it deals with MAC addresses. Others would argue that it is part of layer 3 because it supports IP operations. What is essential to know is thatÂ ARPÂ allows the translation from layer 3 addressing to layer 2 addressing.


## QUESTIONS

![Pasted image 20241101145407.png](../../IMAGES/Pasted%20image%2020241101145407.png)

# ICMP: TROUBLESHOOTING NETWORKS


Internet Control Message Protocol (ICMP) is mainly used for network diagnostics and error reporting. Two popular commands rely on ICMP, and they are instrumental in network troubleshooting and network security. The commands are:

```ad-important
- `ping`: This command uses ICMP to test connectivity to a target system and measures the round-trip time (RTT). In other words, it can be used to learn that the target is alive and that its reply can reach our system.
- `traceroute`: This command is calledÂ `traceroute`Â onÂ LinuxÂ and UNIX-like systems andÂ `tracert`Â on MS Windows systems. It uses ICMP to discover the route from your host to the target.
```

### Ping

You may have never played ping-pong (table tennis) before; however, thanks to ICMP, you can now play it with the computer! TheÂ `ping`Â command sends an ICMP Echo Request (ICMP TypeÂ `8`). The screenshot below shows the ICMP message within an IP packet.

![Wireshark showing an ICMP echo request datagram encapsulated within an IP packet.](https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/5f04259cf9bf5b57aed2c476-1719849226558.png)  

The computer on the receiving end responds with an ICMP Echo Reply (ICMP TypeÂ `0`).

![Wireshark showing an ICMP echo reply datagram encapsulated within an IP packet.](https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/5f04259cf9bf5b57aed2c476-1719849246973.png)  

Many things might prevent us from getting a reply. In addition to the possibility of the target system being offline or shut down, a firewall along the path might block the necessary packets forÂ `ping`Â to work. In the example below, we usedÂ `-c 4`Â to tell theÂ `ping`Â command to stop after sending four packets.


```shell-session
user@TryHackMe$ ping 192.168.11.1 -c 4
PING 192.168.11.1 (192.168.11.1) 56(84) bytes of data.
64 bytes from 192.168.11.1: icmp_seq=1 ttl=63 time=11.2 ms
64 bytes from 192.168.11.1: icmp_seq=2 ttl=63 time=3.81 ms
64 bytes from 192.168.11.1: icmp_seq=3 ttl=63 time=3.99 ms
64 bytes from 192.168.11.1: icmp_seq=4 ttl=63 time=23.4 ms

--- 192.168.11.1 ping statistics ---
4 packets transmitted, 4 received, 0% packet loss, time 3003ms
rtt min/avg/max/mdev = 3.805/10.596/23.366/7.956 ms
```

The output shows no packet loss; moreover, it calculates the minimum, average, maximum, and standard deviation (mdev) of the round-trip time (RTT).

### Traceroute

How can we make every router between our system and a target system reveal itself?

The Internet protocol has a field called Time-to-Live (TTL) that indicates the maximum number of routers a packet can travel through before it is dropped. The router decrements the packetâ€™sÂ TTLÂ by one before it sends it across. When theÂ TTLÂ reaches zero, the router drops the packet and sends an ICMP Time Exceeded message (ICMP TypeÂ `11`). (In this context, â€œtimeâ€ is measured in the number of routers, not seconds.)

The terminal output below shows the result of runningÂ `traceroute`Â to discover the routers between our system andÂ `example.com`. Some routers donâ€™t respond; in other words, they drop the packet without sending any ICMP messages. Routers that belong to our ISP might respond, revealing their private IP address. Moreover, some routers respond and show their public IP address, and this would let us look up their domain name and discover their geographic location. Finally, there is always a possibility that an ICMP Time Exceeded message gets blocked and never reaches us.


```shell-session
user@TryHackMe$ traceroute example.com
traceroute to example.com (93.184.215.14), 30 hops max, 60 byte packets
 1  _gateway (192.168.66.1)  4.414 ms  4.342 ms  4.320 ms
 2  192.168.11.1 (192.168.11.1)  5.849 ms  5.830 ms  5.811 ms
 3  100.104.0.1 (100.104.0.1)  11.130 ms  11.111 ms  11.093 ms
 4  10.149.1.45 (10.149.1.45)  6.156 ms  6.138 ms  6.120 ms
 5  * * *
 6  * * *
 7  * * *
 8  172.16.48.1 (172.16.48.1)  5.667 ms  8.165 ms  6.861 ms
 9  ae81.edge4.Marseille1.Level3.net (212.73.201.45)  50.811 ms  52.857 ms 213.242.116.233 (213.242.116.233)  52.798 ms
10  NTT-level3-Marseille1.Level3.net (4.68.68.150)  93.351 ms  79.897 ms  79.804 ms
11  ae-9.r20.parsfr04.fr.bb.gin.ntt.net (129.250.3.38)  62.935 ms  62.908 ms  64.313 ms
12  ae-14.r21.nwrknj03.us.bb.gin.ntt.net (129.250.4.194)  141.816 ms  141.782 ms  141.757 ms
13  ae-1.a02.nycmny17.us.bb.gin.ntt.net (129.250.3.17)  145.786 ms ae-1.a03.nycmny17.us.bb.gin.ntt.net (129.250.3.128)  141.701 ms  147.586 ms
14  ce-0-3-0.a02.nycmny17.us.ce.gin.ntt.net (128.241.1.14)  148.692 ms ce-3-3-0.a03.nycmny17.us.ce.gin.ntt.net (128.241.1.90)  141.615 ms ce-0-3-0.a02.nycmny17.us.ce.gin.ntt.net (128.241.1.14)  148.168 ms
15  ae-66.core1.nyd.edgecastcdn.net (152.195.69.133)  141.100 ms ae-65.core1.nyd.edgecastcdn.net (152.195.68.133)  140.360 ms ae-66.core1.nyd.edgecastcdn.net (152.195.69.133)  140.638 ms
16  93.184.215.14 (93.184.215.14)  140.574 ms  140.543 ms  140.514 ms
17  93.184.215.14 (93.184.215.14)  140.488 ms  139.397 ms  141.854 ms
```

The traversed route might change as we rerun the command.

## QUESTIONS

![Pasted image 20241101145525.png](../../IMAGES/Pasted%20image%2020241101145525.png)

# ROUTING


Consider the network diagram shown below. It only has three networks; however, how can the Internet figure out how to deliver a packet from Network 1 to Network 2 or Network 3? Although this is an overly simplified diagram, we need some algorithm to figure out how to connect Network 1 to Network 2 and Network 3 and vice versa.

![Three networks are connected to the Internet through its own router.](https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/5f04259cf9bf5b57aed2c476-1719849271800.svg)  

Letâ€™s consider a more detailed diagram. The Internet would be millions of routers and billions of devices. The network below is a tiny subset of the Internet. The mobile user can reach the web server; however, for this to happen, each router across the path needs to send the packets via the appropriate link. Obviously, there is more than one path, i.e., route, connecting the mobile user and the web server. We need a routing algorithm for the router to figure out which link to use.

![A network with six routers provides more than one path for the hosts to communicate.](https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/5f04259cf9bf5b57aed2c476-1719849333579.svg)  

The routing algorithms are beyond the scope of this room; however, we will briefly describe a few routing protocols so that you become familiar with their names:

```ad-important
- **OSPF (Open Shortest Path First)**: OSPF is a routing protocol that allows routers to share information about the network topology and calculate the most efficient paths for data transmission. It does this by having routers exchange updates about the state of their connected links and networks. This way, each router has a complete map of the network and can determine the best routes to reach any destination.
- **EIGRP (Enhanced Interior Gateway Routing Protocol)**: EIGRP is a Cisco proprietary routing protocol that combines aspects of different routing algorithms. It allows routers to share information about the networks they can reach and the cost (like bandwidth or delay) associated with those routes. Routers then use this information to choose the most efficient paths for data transmission.
- **BGP (Border Gateway Protocol)**: BGP is the primary routing protocol used on the Internet. It allows different networks (like those of Internet Service Providers) to exchange routing information and establish paths for data to travel between these networks. BGP helps ensure data can be routed efficiently across the Internet, even when traversing multiple networks.
- **RIP (Routing Information Protocol)**: RIP is a simple routing protocol often used in small networks. Routers running RIP share information about the networks they can reach and the number of hops (routers) required to get there. As a result, each router builds a routing table based on this information, choosing the routes with the fewest hops to reach each destination.
```

## QUESTIONS

![Pasted image 20241101145818.png](../../IMAGES/Pasted%20image%2020241101145818.png)

# NAT


As discussed in theÂ [Networking Concepts](https://tryhackme.com/r/room/networkingconcepts)Â room, we calculated that IPv4 can support a maximum of four billion devices. With the increase in the number of devices connected to the Internet, from computers and smartphones to security cameras and washing machines, it was clear that the IPv4 address space would be depleted quickly. One solution to address depletion is Network Address Translation (NAT).

The idea behind NAT lies in usingÂ **one public IP address**Â to provide Internet access toÂ **many private IP addresses**. In other words, if you are connecting a company with twenty computers, you can provide Internet access to all twenty computers by using a single public IP address instead of twenty public IP addresses. (Note:Â _Technically speaking, the number of IP addresses is always expressed as a power of two. To be technically accurate, with NAT, you reserve two public IP addresses instead of thirty-two. Consequently, you would have saved thirty public IP addresses._)

Unlike routing, which is the natural way to route packets to the destination host, routers that support NAT must find a way to track ongoing connections. Consequently, NAT-supporting routers maintain a table translating network addresses between internal and external networks. Generally, the internal network would use a private IP address range, while the external network would use a public IP address.

In the diagram below, multiple devices access the Internet via a router that supports NAT. The router maintains a table that maps the internal IP address and port number with its external IP address and port number. For instance, the laptop might establish a connection with some web server. From the laptop perspective, the connection is initiated from its IP addressÂ `192.168.0.129`Â fromÂ TCPÂ source port numberÂ `15401`; however, the web server will see this same connection as being established fromÂ `212.3.4.5`Â andÂ TCPÂ port numberÂ `19273`, as shown in the translation table. The router does this address translation seamlessly.

![A private network connects to the Internet via a router that supports NAT. The router maintains a translation table for the ongoing connections.](https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/5f04259cf9bf5b57aed2c476-1719849362861.svg)

## QUESTIONS


![Pasted image 20241101145903.png](../../IMAGES/Pasted%20image%2020241101145903.png)

