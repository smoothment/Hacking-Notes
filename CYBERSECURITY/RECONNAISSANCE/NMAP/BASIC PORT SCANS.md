# INTRODUCTION

---



This room is the second in theÂ NmapÂ series (part of the Introduction to Network Security module).

1. [NmapÂ Live Host Discovery](https://tryhackme.com/room/nmap01)
2. [NmapÂ Basic Port Scans](https://tryhackme.com/room/nmap02)
3. [NmapÂ Advanced Port Scans](https://tryhackme.com/room/nmap03)
4. [NmapÂ Post Port Scans](https://tryhackme.com/room/nmap04)

In the previous room, we focused on discovering online systems. So far, we have covered three steps of aÂ NmapÂ scan:

1. Enumerate targets
2. Discover live hosts
3. Reverse-DNSÂ lookup

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/f351cd3eaca9da85b9417ca820494ec0.png)

The next step would be checking which ports are open and listening and which ports are closed. Therefore, in this room and the next one, we focus on port scanning and the different types of port scans used byÂ `nmap`. This room explains:

1. TCPÂ connect port scan
2. TCPÂ SYN port scan
3. UDPÂ port scan

Moreover, we discuss the different options to specify the ports, the scan rate, and the number of parallel probes.

# TCP and UDP Ports

---

In the same sense that an IP address specifies a host on a network among many others, a TCP port or UDP port is used to identify a network service running on that host. A server provides the network service, and it adheres to a specific network protocol. Examples include providing time, responding toÂ DNSÂ queries, and serving web pages. A port is usually linked to a service using that specific port number. For instance, an HTTP server would bind to TCP port 80 by default; moreover, if the HTTP server supports SSL/TLS, it would listen on TCP port 443. (TCP ports 80 and 443 are the default ports for HTTP and HTTPS; however, the webserver administrator might choose other port numbers if necessary.) Furthermore, no more than one service can listen on any TCP orÂ UDPÂ port (on the same IP address).

At the risk of oversimplification, we can classify ports in two states:

```ad-note

1. Open port indicates that there is some service listening on that port.
2. Closed port indicates that there is no service listening on that port.
```

However, in practical situations, we need to consider the impact of firewalls. For instance, a port might be open, but a firewall might be blocking the packets. Therefore,Â NmapÂ considers the following six states:

```ad-note
1. **Open**: indicates that a service is listening on the specified port.
2. **Closed**: indicates that no service is listening on the specified port, although the port is accessible. By accessible, we mean that it is reachable and is not blocked by a firewall or other security appliances/programs.
3. **Filtered**: means thatÂ NmapÂ cannot determine if the port is open or closed because the port is not accessible. This state is usually due to a firewall preventingÂ NmapÂ from reaching that port.Â Nmapâ€™s packets may be blocked from reaching the port; alternatively, the responses are blocked from reachingÂ Nmapâ€™s host.
4. **Unfiltered**: means thatÂ NmapÂ cannot determine if the port is open or closed, although the port is accessible. This state is encountered when using an ACK scanÂ `-sA`.
5. **Open|Filtered**: This means thatÂ NmapÂ cannot determine whether the port is open or filtered.
6. **Closed|Filtered**: This means thatÂ NmapÂ cannot decide whether a port is closed or filtered.
```

![Pasted image 20241108165106.png](../../IMAGES/Pasted%20image%2020241108165106.png)

# TCP FLAGS

---

Nmap supports different types of TCP port scans. To understand the difference between these port scans, we need to review the TCP header. The TCP header is the first 24 bytes of a TCP segment. The following figure shows the TCP header as defined inÂ [RFCÂ 793](https://datatracker.ietf.org/doc/html/rfc793.html). This figure looks sophisticated at first; however, it is pretty simple to understand. In the first row, we have the sourceÂ TCPÂ port number and the destination port number. We can see that the port number is allocated 16 bits (2 bytes). In the second and third rows, we have the sequence number and the acknowledgement number. Each row has 32 bits (4 bytes) allocated, with six rows total, making up 24 bytes.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/79ca8e4acbd573a27cee413cde927769.png)

In particular, we need to focus on the flags that Nmap can set or unset. We have highlighted theÂ TCPÂ flags in red. Setting a flag bit means setting its value to 1. From left to right, theÂ TCPÂ header flags are:

```ad-note
1. **URG**: Urgent flag indicates that the urgent pointer filed is significant. The urgent pointer indicates that the incoming data is urgent, and that aÂ TCPÂ segment with the URG flag set is processed immediately without consideration of having to wait on previously sentÂ TCPÂ segments.
2. **ACK**: Acknowledgement flag indicates that the acknowledgement number is significant. It is used to acknowledge the receipt of aÂ TCPÂ segment.
3. **PSH**: Push flag askingÂ TCPÂ to pass the data to the application promptly.
4. **RST**: Reset flag is used to reset the connection. Another device, such as a firewall, might send it to tear aÂ TCPÂ connection. This flag is also used when data is sent to a host and there is no service on the receiving end to answer.
5. **SYN**: Synchronize flag is used to initiate aÂ TCPÂ 3-way handshake and synchronize sequence numbers with the other host. The sequence number should be set randomly duringÂ TCPÂ connection establishment.
6. **FIN**: The sender has no more data to send.
```

![Pasted image 20241108165331.png](../../IMAGES/Pasted%20image%2020241108165331.png)

# TCP Connect Scan
---

TCPÂ connect scan works by completing theÂ TCPÂ 3-way handshake. In standardÂ TCPÂ connection establishment, the client sends aÂ TCPÂ packet with SYN flag set, and the server responds with SYN/ACK if the port is open; finally, the client completes the 3-way handshake by sending an ACK.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/8390020a13d6f22f49233833f6265de6.png)

We are interested in learning whether theÂ TCPÂ port is open, not establishing aÂ TCPÂ connection. Hence the connection is torn as soon as its state is confirmed by sending a RST/ACK. You can choose to runÂ TCPÂ connect scan usingÂ `-sT`.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/514972cd54b3f58c83f951978ea9183e.png)

It is important to note that if you are not a privileged user (root or sudoer), aÂ TCPÂ connect scan is the only possible option to discover openÂ TCPÂ ports.

In the following Wireshark packet capture window, we see Nmap sendingÂ TCPÂ packets with SYN flag set to various ports, 256, 443, 143, and so on. By default, Nmap will attempt to connect to the 1000 most common ports. A closedÂ TCPÂ port responds to a SYN packet with RST/ACK to indicate that it is not open. This pattern will repeat for all the closed ports as we attempt to initiate aÂ TCPÂ 3-way handshake with them.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/a975503bd3e006bd32147ba9c9faede4.png)

We notice that port 143 is open, so it replied with a SYN/ACK, and Nmap completed the 3-way handshake by sending an ACK. The figure below shows all the packets exchanged between our Nmap host and the target systemâ€™s port 143. The first three packets are theÂ TCPÂ 3-way handshake being completed. Then, the fourth packet tears it down with an RST/ACK packet.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/19ebc8172c930867c50e214b630ef4ec.png)

To illustrate theÂ `-sT`Â (TCPÂ connect scan), the following command example returned a detailed list of the open ports.



```shell-session
pentester@TryHackMe$ nmap -sT MACHINE_IP

Starting Nmap 7.60 ( https://nmap.org ) at 2021-08-30 09:53 BST
Nmap scan report for MACHINE_IP
Host is up (0.0024s latency).
Not shown: 995 closed ports
PORT    STATE SERVICE
22/tcp  open  ssh
25/tcp  open  smtp
80/tcp  open  http
111/tcp open  rpcbind
143/tcp open  imap
MAC Address: 02:45:BF:8A:2D:6B (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 0.40 seconds
```

Note that we can useÂ `-F`Â to enable fast mode and decrease the number of scanned ports from 1000 to 100 most common ports.

It is worth mentioning that theÂ `-r`Â option can also be added to scan the ports in consecutive order instead of random order. This option is useful when testing whether ports open in a consistent manner, for instance, when a target boots up.

# TCP SYN SCAN

Unprivileged users are limited to connect scan. However, the default scan mode is SYN scan, and it requires a privileged (root or sudoer) user to run it. SYN scan does not need to complete theÂ TCPÂ 3-way handshake; instead, it tears down the connection once it receives a response from the server. Because we didnâ€™t establish aÂ TCPÂ connection, this decreases the chances of the scan being logged. We can select this scan type by using theÂ `-sS`Â option. The figure below shows how theÂ TCPÂ SYN scan works without completing theÂ TCPÂ 3-way handshake.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/48e631fd3deba4a2b759ca48405fcc08.png)

The following screenshot from Wireshark shows aÂ TCPÂ SYN scan. The behaviour in the case of closedÂ TCPÂ ports is similar to that of theÂ TCPÂ connect scan.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/ae4a89999447ab19cc829e436d1ec8fe.png)

To better see the difference between the two scans, consider the following screenshot. In the upper half of the following figure, we can see aÂ TCPÂ connect scanÂ `-sT`Â traffic. Any openÂ TCPÂ port will require Nmap to complete theÂ TCPÂ 3-way handshake before closing the connection. In the lower half of the following figure, we see how a SYN scanÂ `-sS`Â does not need to complete theÂ TCPÂ 3-way handshake; instead,Â NmapÂ sends an RST packet once a SYN/ACK packet is received.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/fe642b2fafb70cbaa2531d2c41d6cddb.png)

TCPÂ SYN scan is the default scan mode when running Nmap as a privileged user, running as root or using sudo, and it is a very reliable choice. It has successfully discovered the open ports you found earlier with theÂ TCPÂ connect scan, yet noÂ TCPÂ connection was fully established with the target.


```shell-session
pentester@TryHackMe$ sudo nmap -sS 10.10.166.223

Starting Nmap 7.60 ( https://nmap.org ) at 2021-08-30 09:53 BST
Nmap scan report for 10.10.166.223
Host is up (0.0073s latency).
Not shown: 994 closed ports
PORT    STATE SERVICE
22/tcp  open  ssh
25/tcp  open  smtp
80/tcp  open  http
110/tcp open  pop3
111/tcp open  rpcbind
143/tcp open  imap
MAC Address: 02:45:BF:8A:2D:6B (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 1.60 seconds
```

# UDP SCAN

---


UDPÂ is a connectionless protocol, and hence it does not require any handshake for connection establishment. We cannot guarantee that a service listening on aÂ UDPÂ port would respond to our packets. However, if aÂ UDPÂ packet is sent to a closed port, an ICMP port unreachable error (type 3, code 3) is returned. You can selectÂ UDPÂ scan using theÂ `-sU`Â option; moreover, you can combine it with anotherÂ TCPÂ scan.

The following figure shows that if we send aÂ UDPÂ packet to an openÂ UDPÂ port, we cannot expect any reply in return. Therefore, sending aÂ UDPÂ packet to an open port wonâ€™t tell us anything.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/085088cd1b2b122312b1ee952c4aa0f7.png)

However, as shown in the figure below, we expect to get an ICMP packet of type 3, destination unreachable, and code 3, port unreachable. In other words, theÂ UDPÂ ports that donâ€™t generate any response are the ones thatÂ NmapÂ will state as open.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/8b8b32517699b96777641a97dbf9d880.png)

In the Wireshark capture below, we can see that every closed port will generate an ICMP packet destination unreachable (port unreachable).

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/f927563f4778092ced3ef7afa67cece3.png)

Launching a UDP scan against thisÂ LinuxÂ server proved valuable, and indeed, we learned that port 111 is open. On the other hand, Nmap cannot determine whetherÂ UDPÂ port 68 is open or filtered.


```shell-session
pentester@TryHackMe$ sudo nmap -sU MACHINE_IP

Starting Nmap 7.60 ( https://nmap.org ) at 2021-08-30 09:54 BST
Nmap scan report for MACHINE_IP
Host is up (0.00061s latency).
Not shown: 998 closed ports
PORT    STATE         SERVICE
68/udp  open|filtered dhcpc
111/udp open          rpcbind
MAC Address: 02:45:BF:8A:2D:6B (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 1085.05 seconds
```

# Fine-Tuning Scope and Performance

___

You can specify the ports you want to scan instead of the default 1000 ports. Specifying the ports is intuitive by now. Letâ€™s see some examples:

```ad-note

- port list:Â `-p22,80,443`Â will scan ports 22, 80 and 443.
- port range:Â `-p1-1023`Â will scan all ports between 1 and 1023 inclusive, whileÂ `-p20-25`Â will scan ports between 20 and 25 inclusive.
```
You can request the scan of all ports by usingÂ `-p-`, which will scan all 65535 ports. If you want to scan the most common 100 ports, addÂ `-F`. UsingÂ `--top-ports 10`Â will check the ten most common ports.

You can control the scan timing usingÂ `-T<0-5>`.Â `-T0`Â is the slowest (paranoid), whileÂ `-T5`Â is the fastest. According toÂ NmapÂ manual page, there are six templates:

```ad-note
- paranoid (0)
- sneaky (1)
- polite (2)
- normal (3)
- aggressive (4)
- insane (5)
```

To avoidÂ IDSÂ alerts, you might considerÂ `-T0`Â orÂ `-T1`. For instance,Â `-T0`Â scans one port at a time and waits 5 minutes between sending each probe, so you can guess how long scanning one target would take to finish. If you donâ€™t specify any timing,Â NmapÂ uses normalÂ `-T3`. Note thatÂ `-T5`Â is the most aggressive in terms of speed; however, this can affect the accuracy of the scan results due to the increased likelihood of packet loss.Â Note thatÂ `-T4`Â is often used during CTFs and when learning to scan on practice targets, whereasÂ `-T1`Â is often used during real engagements where stealth is more important.

Alternatively, you can choose to control the packet rate usingÂ `--min-rate <number>`Â andÂ `--max-rate <number>`. For example,Â `--max-rate 10`Â orÂ `--max-rate=10`Â ensures that your scanner is not sending more than ten packets per second.

Moreover, you can control probing parallelization usingÂ `--min-parallelism <numprobes>`Â andÂ `--max-parallelism <numprobes>`.Â NmapÂ probes the targets to discover which hosts are live and which ports are open; probing parallelization specifies the number of such probes that can be run in parallel. For instance,Â `--min-parallelism=512`Â pushesÂ NmapÂ to maintain at least 512 probes in parallel; these 512 probes are related to host discovery and open ports.

![Pasted image 20241108172150.png](../../IMAGES/Pasted%20image%2020241108172150.png)


# SUMMARY

|Port Scan Type|Example Command|
|---|---|
|TCPÂ Connect Scan|`nmap -sT 10.10.175.18`|
|TCPÂ SYN Scan|`sudo nmap -sS 10.10.175.18`|
|UDPÂ Scan|`sudo nmap -sU 10.10.175.18`|

These scan types should get you started discovering running TCP andÂ UDPÂ services on a target host.

| Option                  | Purpose                                  |
| ----------------------- | ---------------------------------------- |
| `-p-`                   | all ports                                |
| `-p1-1023`              | scan ports 1 to 1023                     |
| `-F`                    | 100 most common ports                    |
| `-r`                    | scan ports in consecutive order          |
| `-T<0-5>`               | -T0 being the slowest and T5 the fastest |
| `--max-rate 50`         | rate <= 50 packets/sec                   |
| `--min-rate 15`         | rate >= 15 packets/sec                   |
| `--min-parallelism 100` | at least 100 probes in parallel          |
|                         |                                          |
