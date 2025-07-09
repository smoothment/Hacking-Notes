# INTRODUCTION

Have you ever wondered why you need an IP address to access the Internet? Is it true that an IP address can uniquely identify the user? Are you curious to learn what the life of a packet looks like? If the answer is yes, letâ€™s dive in!

This room is the first room in a series of four rooms dedicated to introducing the user to vital networking concepts and the most common networking protocols:

- Networking Concepts (this room)
- [Networking Essentials](https://tryhackme.com/r/room/networkingessentials)
- [Networking Core Protocols](https://tryhackme.com/r/room/networkingcoreprotocols)
- [Networking Secure Protocols](https://tryhackme.com/r/room/networkingsecureprotocols)

### Room Prerequisites

This room expects that you know terms such as IP address and TCP port number; however, we donâ€™t expect that the reader is able to explain such terms in proper technical depth. If you are unfamiliar with these terms, please consider joining theÂ [Pre Security](https://tryhackme.com/r/path/outline/presecurity)Â path.  

### Learning Objectives

By the time you finish this room, you will have learned about the following:

- ISO OSI network model
- IP addresses, subnets, and routing
- TCP,Â UDP, and port numbers
- How to connect to an openÂ TCPÂ port from the command line

# OSI MODEL

Before we start, we should note that the OSI model might initially seem complicated. Donâ€™t worry if you encounter cryptic acronyms, as we provide examples of the OSI model layers. We assure you that by the time you finish this module, this task will feel like a piece of cake.

The OSI (Open Systems Interconnection) model is a conceptual model developed by the International Organization for Standardization (ISO) that describes how communications should occur in a computer network. In other words, the OSI model defines a framework for computer network communications. Although this model is theoretical, it is vital to learn and understand as it helps grasp networking concepts on a deeper level. The OSI model is composed of seven layers:

```ad-important
1. Physical Layer
2. Data Link Layer
3. Network Layer
4. Transport Layer
5. Session Layer
6. Presentation Layer
7. Application Layer
```

The numbering starts with the physical layer being layer 1, while the top layer, the application layer, is layer 7. To help you remember the layers from bottom to top, you can use a mnemonic such as â€œPlease Do Not Throw Spinach Pizza Away.â€ You can check the Internet for other easy-to-remember acronyms if this helps you memorize them. Remembering the OSI model layers with their layer numbers is important; otherwise, you will struggle to understand terms such as â€œlayer 3 switchâ€ or â€œlayer 7 firewall.â€

![The seven layers of the OSI ISO Model.](https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/5f04259cf9bf5b57aed2c476-1719848845717.svg)  

### Layer 1: Physical Layer

The physical layer, also referred to as layer 1, deals with the physical connection between devices; this includes the medium, such as a wire, and the definition of the binary digits 0 and 1. Data transmission can be via an electrical, optical, or wireless signal. Consequently, we need data cables or antennas, depending on our physical medium.

In addition to Ethernet cable, shown in the illustration below, and optical fiber cable, examples of the physical layer medium include the WiFi radio bands, the 2.4 GHz band, the 5 GHz band, and the 6 GHz band.

![Ethernet cable](https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/5f04259cf9bf5b57aed2c476-1719848954704.svg)  

### Layer 2: Data Link Layer

The physical layer defines a medium to transmit our signal. The data link layer, i.e., layer 2, represents the protocol that enables data transfer between nodes on the same network segment. Letâ€™s put it in simpler terms. The data link layer describes an agreement between the different systems on the same network segment on how to communicate. A network segment refers to a group of networked devices using a shared medium or channel for information transfer. For example, consider a company office with ten computers connected to a network switch; thatâ€™s a network segment.

Examples of layer 2 include Ethernet, i.e., 802.3, and WiFi, i.e., 802.11. Ethernet and WiFi addresses are six bytes. Their address is called a MAC address, where MAC stands for Media Access Control. They are usually expressed in hexadecimal format with a colon separating each two bytes. The three leftmost bytes identify the vendor.

![A MAC address is made up of six octets or bytes, where the three leftmost bytes identify the vendor who manufactured the network interface.](https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/5f04259cf9bf5b57aed2c476-1719848867222.svg)  

We expect to see two MAC addresses in each frame in real network communication over Ethernet or WiFi. The packet in the screenshot below shows:

- The destination data-link address (MAC address) highlighted in yellow
- The source data link address (MAC address) is highlighted in blue
- The remaining bits show the data being sent

![Wireshark interface displaying a packet with the source and destination MAC addresses highlighted.](https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/5f04259cf9bf5b57aed2c476-1719848893497.png)  

### Layer 3: Network Layer

The data link layer focuses on sending data between two nodes on the same network segment. The network layer, i.e., layer 3, is concerned with sending data between different networks. In more technical terms, the network layer handles logical addressing and routing, i.e., finding a path to transfer the network packets between the diverse networks.

In the data link layer, we gave an example of one company office with ten computers, where the data link layer is responsible for providing a connection between them. Letâ€™s say that this company has multiple offices distributed across various cities, countries, or even continents. The network layer is responsible for connecting the different offices together.

The network below shows that computers A and B are connected, although on different networks. You can also notice two paths connecting the two computers; the network layer will route the network packets through the path it deems better.

![A computer network diagram with two desktop computers and four routers between them. There are multiple paths that a packet can use.](https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/5f04259cf9bf5b57aed2c476-1719848912309.svg)  

Examples of the network layer include Internet Protocol (IP), Internet Control Message Protocol (ICMP), and Virtual Private Network (VPN) protocols such as IPSec and SSL/TLSÂ VPN.

### Layer 4: Transport Layer

Layer 4, the transport layer, enables end-to-end communication between running applications on different hosts. Your web browser is connected to the TryHackMe web server over the transport layer, which can support various functions like flow control, segmentation, and error correction.

Examples of layer 4 are Transmission Control Protocol (TCP) and User Datagram Protocol (UDP).

### Layer 5: Session Layer

The session layer is responsible for establishing, maintaining, and synchronizing communication between applications running on different hosts. Establishing a session means initiating communication between applications and negotiating the necessary parameters for the session. Data synchronization ensures that data is transmitted in the correct order and provides mechanisms for recovery in case of transmission failures.

Examples of the session layer are Network File System (NFS) and Remote Procedure Call (RPC).

### Layer 6: Presentation Layer

The presentation layer ensures the data is delivered in a form the application layer can understand. Layer 6 handles data encoding, compression, and encryption. An example of encoding is character encoding, such as ASCII or Unicode.

Various standards are used at the presentation layer. Consider the scenario where we want to send an image via email. First, we use JPEG, GIF, and PNG to save our images; furthermore, although hidden from the user by the email client, we useÂ MIMEÂ (Multipurpose Internet Mail Extensions) to attach the file to our email.Â MIMEÂ encodes a binary file using 7-bit ASCII characters.

### Layer 7: Application Layer

The application layer provides network services directly to end-user applications. Your web browser would use theÂ HTTPÂ protocol to request a file, submit a form, or upload a file.

The application layer is the top layer, and you might have encountered many of its protocols as you use different applications. Examples of Layer 7 protocols areÂ HTTP,Â FTP, DNS, POP3,Â SMTP, andÂ IMAP. Donâ€™t worry if you are not familiar with all of them.

### Summary

Reading about the ISO OSI model for the first time can be intimidating; however, it becomes easier as you progress in your study of networking protocols. To help with your studies, we have summarized the ISO OSI layers in the table below.

| Layer Number | Layer Name         | Main Function                                         | Example Protocols and Standards           |
| ------------ | ------------------ | ----------------------------------------------------- | ----------------------------------------- |
| Layer 7      | Application layer  | Providing services and interfaces to applications     | HTTP,Â FTP, DNS, POP3,Â SMTP,Â IMAP          |
| Layer 6      | Presentation layer | Data encoding, encryption, and compression            | Unicode,Â MIME, JPEG, PNG, MPEG            |
| Layer 5      | Session layer      | Establishing, maintaining, and synchronising sessions | NFS, RPC                                  |
| Layer 4      | Transport layer    | End-to-end communication and data segmentation        | UDP,Â TCP                                  |
| Layer 3      | Network layer      | Logical addressing and routing between networks       | IP, ICMP, IPSec                           |
| Layer 2      | Data link layer    | Reliable data transfer between adjacent nodes         | Ethernet (802.3), WiFi (802.11)           |
| Layer 1      | Physical layer     | Physical data transmission media                      | Electrical, optical, and wireless signals |
## QUESTIONS SECTION

![Pasted image 20241028151907.png](../../IMAGES/Pasted%20image%2020241028151907.png)

# TCP/IP MODEL

Now that we have covered the conceptual ISO OSI model, it is time to study an implemented model, theÂ TCP/IP model.Â TCP/IP stands for Transmission Control Protocol/Internet Protocol and was developed in the 1970s by the Department of Defense (DoD). I hear you ask why DoD would create such a model. One of the strengths of this model is that it allows a network to continue to function as parts of it are out of service, for instance, due to a military attack. This capability is possible in part due to the design of the routing protocols to adapt as the network topology changes.

In our presentation of the ISO OSI model, we went from bottom to top, from layer 1 to layer 7. In this task, letâ€™s look at things from a different perspective, from top to bottom. From top to bottom, we have:

- **Application Layer**: The OSI model application, presentation and session layers, i.e., layers 5, 6, and 7, are grouped into the application layer in theÂ TCP/IP model.
- **Transport Layer**: This is layer 4.
- **Internet Layer**: This is layer 3. The OSI modelâ€™s network layer is called the Internet layer in theÂ TCP/IP model.
- **Link Layer**: This is layer 2.

The table below shows how theÂ TCP/IP model layers map to the ISO/OSI model layers.

| Layer Number | ISO OSI Model      | TCP/IP Model (RFCÂ 1122) | Protocols                                        |
| ------------ | ------------------ | ----------------------- | ------------------------------------------------ |
| 7            | Application Layer  | Application Layer       | HTTP, HTTPS,Â FTP, POP3,Â SMTP, IMAP, Telnet,Â SSH, |
| 6            | Presentation Layer |                         |                                                  |
| 5            | Session Layer      |                         |                                                  |
| 4            | Transport Layer    | Transport Layer         | TCP,Â UDP                                         |
| 3            | Network Layer      | Internet Layer          | IP, ICMP, IPSec                                  |
| 2            | Data Link Layer    | Link Layer              | Ethernet 802.3, WiFi 802.11                      |
| 1            | Physical Layer     |                         |                                                  |

Many modern networking textbooks show the TCP/IP model as five layers instead of four. For example, in Computer Networking: A Top-Down Approach 8th Edition,Â [Kurose and Ross](http://gaia.cs.umass.edu/kurose_ross/index.php)Â describe the following five-layer Internet protocol stack by including the physical layer:

- Application
- Transport
- Network
- Link
- Physical

In the following tasks, we will cover the IP protocol from the Internet layer and theÂ UDPÂ andÂ TCPÂ protocols from the transport layer.

# IP ADDRESSES AND SUBNETS

When you hear the word IP address, you might think of an address likeÂ `192.168.0.1`Â or something less common, such asÂ `172.16.159.243`. In both cases, you are right. Both of these are IP addresses; IPv4 (IP version 4) addresses to be specific.

Every host on the network needs a unique identifier for other hosts to communicate with him. Without a unique identifier, the host cannot be found without ambiguity. When using theÂ TCP/IP protocol suite, we need to assign an IP address for each device connected to the network.

One analogy of an IP address is your home postal address. Your postal address allows you to receive letters and parcels from all over the world. Furthermore, it can identify your home without ambiguity; otherwise, you cannot shop online!

As you might already know, we have IPv4 and IPv6 (IP version 6). IPv4 is still the most common, and whenever you come across a text mentioning IP without the version, we expect them to mean IPv4.

So, what makes an IP address? An IP address comprises four octets, i.e., 32 bits. Being 8 bits, an octet allows us to represent a decimal number between 0 and 255. An IP address is shown in the image below.

![An IP address is made up of 4 octets or bytes and each octet represents a decimal number between 0 and 255.](https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/5f04259cf9bf5b57aed2c476-1719849005781.png)  

At the risk of oversimplifying things, the 0 and 255 are reserved for the network and broadcast addresses, respectively. In other words,Â `192.168.1.0`Â is the network address, whileÂ `192.168.1.255`Â is the broadcast address. Sending to the broadcast address targets all the hosts on the network. With simple math, you can conclude that we cannot have more than 4 billion unique IPv4 addresses. If you are curious about the math, it is approximatelyÂ 232Â because we have 32 bits. This number is approximate because we didnâ€™t consider network and broadcast addresses.

### Looking Up Your Network Configuration

You can look up your IP address on the MS Windows command line using the commandÂ `ipconfig`. OnÂ LinuxÂ and UNIX-based systems, you can issue the commandÂ `ifconfig`Â orÂ `ip address show`, which can be typed asÂ `ip a s`. In the terminal window below, we showÂ `ifconfig`.

Terminal

```shell-session
user@TryHackMe$ ifconfig
[...]
wlo1: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.66.89  netmask 255.255.255.0  broadcast 192.168.66.255
        inet6 fe80::73e1:ca5e:3f93:b1b3  prefixlen 64  scopeid 0x20<link>
        ether cc:5e:f8:02:21:a7  txqueuelen 1000  (Ethernet)
        RX packets 19684680  bytes 18865072842 (17.5 GiB)
        RX errors 0  dropped 364  overruns 0  frame 0
        TX packets 14439678  bytes 8773200951 (8.1 GiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

The terminal output above indicates the following:

- The host (laptop) IP address isÂ `192.168.66.89`
- The subnet mask isÂ `255.255.255.0`
- The broadcast address isÂ `192.168.66.255`

Letâ€™s useÂ `ip a s`Â to compare how the network card IP address is presented.

Terminal

```shell-session
user@TryHackMe$ ip a s
[...]
4: wlo1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
    link/ether cc:5e:f8:02:21:a7 brd ff:ff:ff:ff:ff:ff
    altname wlp3s0
    inet 192.168.66.89/24 brd 192.168.66.255 scope global dynamic noprefixroute wlo1
       valid_lft 36795sec preferred_lft 36795sec
    inet6 fe80::73e1:ca5e:3f93:b1b3/64 scope link noprefixroute 
       valid_lft forever preferred_lft forever
```

The terminal output above indicates the following:

- The host (laptop) IP address isÂ `192.168.66.89/24`
- The broadcast address isÂ `192.168.66.255`

If you are wondering, a subnet mask ofÂ `255.255.255.0`Â can also be written asÂ `/24`. TheÂ `/24`Â means that the leftmost 24 bits within the IP address do not change across the network, i.e., the subnet. In other words, the leftmost three octets are the same across the whole subnet; therefore, we can expect to find addresses that range fromÂ `192.168.66.1`Â toÂ `192.168.66.254`. Similar to what was mentioned earlier,Â `192.168.66.0`Â andÂ `192.168.66.255`Â are the network and broadcast addresses, respectively.

### Private Addresses

As we are explaining IP addresses, it is useful to mention that for most practical purposes, there are two types of IP addresses:

- Public IP addresses
- Private IP addresses

RFCÂ 1918 defines the following three ranges of private IP addresses:

- `10.0.0.0`Â -Â `10.255.255.255`Â (`10/8`)
- `172.16.0.0`Â -Â `172.31.255.255`Â (`172.16/12`)
- `192.168.0.0`Â -Â `192.168.255.255`Â (`192.168/16`)

We presented earlier an analogy stating that a public IP address is like your home postal address. A private IP address is different; the original idea is that it cannot reach or be reached from the outside world. It is like an isolated city or a compound, where all houses and apartments are numbered systematically and can easily exchange mail with each other, but not with the outside world. For a private IP address to access the Internet, the router must have a public IP address and must support Network Address Translation (NAT). At this stage, letâ€™s not worry about understanding how NAT works, as we will revisit it later in this module.

Before moving on, I recommend memorising the private IP address ranges. Otherwise, you might see an IP address such asÂ `10.1.33.7`Â orÂ `172.31.33.7`Â and try to access it from a public IP address.

### Routing

A router is like your local post office; you hand them the mail parcel, and they would know how to deliver it. If we dig deeper, you might mail something to an address in another city or country. The post office will check the address and decide where to send it next. For example, if it is to leave the country, we expect one central office to handle all shipments abroad.

In technical terms, a router forwards data packets to the proper network. Usually, a data packet passes through multiple routers before it reaches its final destination. The router functions at layer 3, inspecting the IP address and forwarding the packet to the best network (router) so the packet gets closer to its destination.

![A computer network diagram showing a web server, a mobile user with a laptop, and an office user with a desktop computer. There are six routers between the three systems and there are different paths that a packet can use to travel from one system to the other.](https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/5f04259cf9bf5b57aed2c476-1719848991082.svg)

# UDP AND TCP

The IP protocol allows us to reach a destination host on the network; the host is identified by its IP address. We need protocols that would enable processes on networked hosts to communicate with each other. There are two transport protocols to achieve that:Â UDPÂ andÂ TCP.

### UDP

UDPÂ (User Datagram Protocol) allows us to reach a specific process on this target host.Â UDPÂ is a simple connectionless protocol that operates at the transport layer, i.e., layer 4. Being connectionless means that it does not need to establish a connection.Â UDPÂ does not even provide a mechanism to know that the packet has been delivered.

An IP address identifies the host; we need a mechanism to determine the sending and receiving process. This can be achieved by using port numbers. A port number uses two octets; consequently, it ranges between 1 and 65535; port 0 is reserved. (The number 65535 is calculated by the expressionÂ 216â€…âˆ’â€…1.)

A real-life example similar toÂ UDPÂ is the standard mail service, with no delivery confirmation. In other words, there is no guarantee that theÂ UDPÂ packet has been received successfully, similar to the case of sending a parcel using standard mail with no confirmation of delivery. In the case of standard mail, it means a cheaper cost than the mail delivery options with confirmation. In the case ofÂ UDP, it means better speed than a transport protocol that provides â€œconfirmation.â€

But what if we want a transport protocol that acknowledges received packets? The answer lies in using TCP instead ofÂ UDP.

### TCP

TCP (Transmission Control Protocol) is a connection-oriented transport protocol. It uses various mechanisms to ensure reliable data delivery sent by the different processes on the networked hosts. LikeÂ UDP, it is a layer 4 protocol. Being connection-oriented, it requires the establishment of aÂ TCPÂ connection before any data can be sent.

InÂ TCP, each data octet has a sequence number; this makes it easy for the receiver to identify lost or duplicated packets. The receiver, on the other hand, acknowledges the reception of data with an acknowledgement number specifying the last received octet.

AÂ TCPÂ connection is established using whatâ€™s called a three-way handshake. Two flags are used: SYN (Synchronize) and ACK (Acknowledgment). The packets are sent as follows:

1. SYN Packet: The client initiates the connection by sending a SYN packet to the server. This packet contains the clientâ€™s randomly chosen initial sequence number.
2. SYN-ACK Packet: The server responds to the SYN packet with a SYN-ACK packet, which adds the initial sequence number randomly chosen by the server.
3. ACK Packet: The three-way handshake is completed as the client sends an ACK packet to acknowledge the reception of the SYN-ACK packet.

![The TCP three-way handshake requires the exchange of three packets.](https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/5f04259cf9bf5b57aed2c476-1719849036216.svg)  

Similar toÂ UDP,Â TCPÂ identifies the process of initiating or waiting (listening) for a connection using port numbers. As stated, a valid port number ranges between 1 and 65535 because it uses two octets and port 0 is reserved.

### QUESTIONS

![Pasted image 20241028164012.png](../../IMAGES/Pasted%20image%2020241028164012.png)

# ENCAPSULATION

Before wrapping up, it is crucial to explain another key concept:Â **encapsulation**. In this context, encapsulation refers to the process of every layer adding a header (and sometimes a trailer) to the received unit of data and sending the â€œencapsulatedâ€ unit to the layer below.

Encapsulation is an essential concept as it allows each layer to focus on its intended function. In the image below, we have the following four steps:

- **Application data**: It all starts when the user inputs the data they want to send into the application. For example, you write an email or an instant message and hit the send button. The application formats this data and starts sending it according to the application protocol used, using the layer below it, the transport layer.
- **Transport protocol segment or datagram**: The transport layer, such as TCP orÂ UDP, adds the proper header information and creates theÂ TCPÂ **segment**Â (orÂ UDPÂ **datagram**). This segment is sent to the layer below it, the network layer.
- **Network packet**: The network layer, i.e.Â the Internet layer, adds an IP header to the received TCP segment orÂ UDPÂ datagram. Then, this IPÂ **packet**Â is sent to the layer below it, the data link layer.
- **Data link frame**: The Ethernet or WiFi receives the IP packet and adds the proper header and trailer, creating aÂ **frame**.

We start with application data. At the transport layer, we add a TCP orÂ UDPÂ header to create aÂ **TCPÂ segment**Â orÂ **UDPÂ datagram**. Again, at the network layer, we add the proper IP header to get anÂ **IP packet**Â that can be routed over the Internet. Finally, we add the appropriate header and trailer to get a WiFi or Ethernet frame at the link layer.

![Application data is encapsulated within a TCP segment or UDP datagram, which in turn is encapsulated within an IP packet. The IP packet is encapsulated within a data link frame.](https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/5f04259cf9bf5b57aed2c476-1719849061418.svg)  

The process has to be reversed on the receiving end until the application data is extracted.

### The Life of a Packet

Based on what we have studied so far, we can explain aÂ _simplified version_Â of the packetâ€™s life. Letâ€™s consider the scenario where you search for a room on TryHackMe.

1. On the TryHackMe search page, you enter your search query and hit enter.
2. Your web browser, using HTTPS, prepares anÂ HTTPÂ request and pushes it to the layer below it, the transport layer.
3. The TCP layer needs to establish a connection via a three-way handshake between your browser and the TryHackMe web server. After establishing the TCP connection, it can send theÂ HTTPÂ request containing the search query. EachÂ TCPÂ segment created is sent to the layer below it, the Internet layer.
4. The IP layer adds the source IP address, i.e., your computer, and the destination IP address, i.e., the IP address of the TryHackMe web server. For this packet to reach the router, your laptop delivers it to the layer below it, the link layer.
5. Depending on the protocol, The link layer adds the proper link layer header and trailer, and the packet is sent to the router.
6. The router removes the link layer header and trailer, inspects the IP destination, among other fields, and routes the packet to the proper link. Each router repeats this process until it reaches the router of the target server.

The steps will then be reversed as the packet reaches the router of the destination network. As we cover additional protocols, we will revisit this exercise and create a more in-depth version.
### QUESTIONS

![Pasted image 20241028164606.png](../../IMAGES/Pasted%20image%2020241028164606.png)

# TELNET


The TELNET (Teletype Network) protocol is a network protocol for remote terminal connection. In simpler words,Â `telnet`, a TELNET client, allows you to connect to and communicate with a remote system and issue text commands. Although initially it was used for remote administration, we can useÂ `telnet`Â to connect to any server listening on aÂ TCPÂ port number.

On the target virtual machine, different services are running. We will experiment with three of them:

- Echo server: This server echoes everything you send it. By default, it listens on port 7.
- Daytime server: This server listens on port 13 by default and replies with the current day and time.
- Web (HTTP) server: This server listens onÂ TCPÂ port 80 by default and serves web pages.

Before continuing, we should mention that the echo and daytime servers are considered security risks and should not be run; however, we started them explicitly to demonstrate communication with the server usingÂ `telnet`. In the terminal below, we connect to the target VM at the echo serverâ€™sÂ TCPÂ port number 7. To close the connection, press theÂ `CTRL`Â +Â `]`Â keys simultaneously.

Terminal

```shell-session
user@TryHackMe$ telnet MACHINE_IP 7
telnet MACHINE_IP 7
Trying MACHINE_IP...
Connected to MACHINE_IP.
Escape character is '^]'.
Hi
Hi
How are you?
How are you?
Bye
Bye
^]

telnet> quit
Connection closed.
```

In the terminal below, we useÂ `telnet`Â to connect to the daytime server listening at port 13. We noticed that the connection closes once the current date and time are returned.

Terminal

```shell-session
user@TryHackMe$ telnet MACHINE_IP 13
Trying MACHINE_IP...
Connected to MACHINE_IP.
Escape character is '^]'.
Thu Jun 20 12:36:32 PM UTC 2024
Connection closed by foreign host.
```

Finally, letâ€™s request a web page usingÂ `telnet`. After connecting to port 80, you need to issue the commandÂ `GET /Â HTTP/1.1`Â and identify the host where anything goes, such asÂ `Host: telnet.thm`. The output below shows the exchange. (The page has been redacted.)

**Note**: You may have to pressÂ `Enter`Â after sending the information in case you donâ€™t get a response.

Terminal

```shell-session
user@TryHackMe$ telnet MACHINE_IP 80
Trying MACHINE_IP...
Connected to MACHINE_IP.
Escape character is '^]'.
GET / HTTP/1.1
Host: telnet.thm

HTTP/1.1 200 OK
Content-Type: text/html
[...]

Connection closed by foreign host.
```
