<iframe width="800" height="634" src="https://www.youtube.com/embed/vzcLrE0SfiQ" title="Packets and Frames - Networking Basics" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" referrerpolicy="strict-origin-when-cross-origin" allowfullscreen></iframe>

# What are Packets and Frames
----

Packets and frames are small pieces of data that, when forming together, make a larger piece of information or message. However, they are two different things in the OSI model. A frame is at layer 2 - the data link layer, meaning there is no such information as IP addresses. Think of this as putting an envelope within an envelope and sending it away. The first envelope will be the packet that you mail, but once it is opened, the envelope within still exists and contains data (this is a frame).

This process is called encapsulation which we discussed inÂ [room 3: the OSI model](https://tryhackme.com/room/osimodelzi). At this stage, it's safe to assume that when we are talking about anything IP addresses, we are talking about packets. When the encapsulating information is stripped away, we're talking about the frame itself.

Packets are an efficient way of communicating data across networked devices such as those explained in Task 1. Because this data is exchanged in small pieces, there is less chance of bottlenecking occurring across a network than large messages being sent at once.

For example, when loading an image from a website, this image is not sent to your computer as a whole, but rather small pieces where it is reconstructed on your computer. Take the image below as an illustration of this process. The cat's picture is divided into three packets, where it is reconstructed when it reaches the computer to form the final image.

Packets have different structures that are dependent upon the type of packet that is being sent. As we'll come on to discuss, networking is full of standards and protocols that act as a set of rules for how the packet is handled on a device. With billions of devices connected on the internet, things can quickly break down if there is no standardization

Let's continue with our example of the Internet Protocol. A packet using this protocol will have a set of headers that contain additional pieces of information to the data that is being sent across a network.

Some notable headers include:

|                     |                                                                                                                                                                         |
| ------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Header**          | **Description**                                                                                                                                                         |
| Time to Live        | This field sets an expiry timer for the packet to not clog up your network if it never manages to reach a host or escape!                                               |
| Checksum            | This field provides integrity checking for protocols such asÂ TCP/IP. If any data is changed, this value will be different from what was expected and therefore corrupt. |
| Source Address      | The IP address of the device that the packet is being sentÂ **from**Â so that data knows where toÂ **return to**.                                                          |
| Destination Address | The device's IP address the packet is being sent to so that data knows where to travel next.                                                                            |
|                     |                                                                                                                                                                         |
![Pasted image 20241120175538.png](../../IMAGES/Pasted%20image%2020241120175538.png)

# TCP/IP (The Three-Way Handshake)
---


**TCP**Â (orÂ **T**ransmissionÂ **C**ontrolÂ **P**rotocol for short) is another one of these rules used in networking.

  

This protocol is very similar to the OSI model that we have previously discussed in room three of this module so far. TheÂ TCP/IP protocol consists of four layers and is arguably just a summarized version of the OSI model. These layers are:

```ad-summary
- Application
- Transport
- Internet
- Network Interface
```


Very similar to how the OSI model works, information is added to each layer of theÂ TCPÂ model as the piece of data (or packet) traverses it. As you may recall, this process is known as encapsulation - where the reverse of this process is decapsulation.

  

One defining feature ofÂ TCPÂ is that it isÂ **connection-based**, which means thatÂ TCPÂ must establish a connection between both a client and a device acting as a serverÂ **before**Â data is sent.

  

Because of this, TCP guarantees that any data sent will be received on the other end. This process is named the Three-way handshake, which is something we'll come on to discuss shortly.Â A table comparing the advantages and disadvantages ofÂ TCPÂ is located below:

  

|   |   |
|---|---|
|**Advantages ofÂ TCP**|**Disadvantages ofÂ TCP**|
|Guarantees the integrity of data.|Requires a reliable connection between the two devices. If one small chunk of data is not received, then the entire chunk of data cannot be used and must be re-sent.|
|Capable of synchronising two devices to prevent each other from being flooded with data in the wrong order.|A slow connection can bottleneck another device as the connection will be reserved on the other device the whole time.|
|Performs a lot more processes for reliability|TCP is significantly slower thanÂ UDPÂ because more work (computing) has to be done by the devices using this protocol.|

  

TCP packets contain various sections of information known as headers that are added from encapsulation. Let's explain some of the crucial headers in the table below:

  

|   |   |
|---|---|
|Header|Description|
|Source Port|This value is the port opened by the sender to send the TCP packet from. This value is chosen randomly (out of the ports from 0-65535 that aren't already in use at the time).|
|Destination Port|This value is the port number that an application or service is running on the remote host (the one receiving data); for example, a webserver running on port 80. Unlike the source port, this value is not chosen at random.|
|Source IP|This is the IP address of the device that is sending the packet.|
|Destination IP|This is the IP address of the device that the packet is destined for.|
|Sequence Number|When a connection occurs, the first piece of data transmitted is given a random number. We'll explain this more in-depth further on.|
|Acknowledgement Number|After a piece of data has been given a sequence number, the number for the next piece of data will have the sequence number + 1. We'll also explain this more in-depth further on.|
|Checksum|This value is what givesÂ TCPÂ integrity. A mathematical calculation is made where the output is remembered. When the receiving device performs the mathematicalÂ calculation, the data must be corrupt if the output is different from what was sent.|
|Data|This header is where the data, i.e. bytes of a file that is being transmitted, is stored.|
|Flag|This header determines how the packet should be handled by either device during the handshake process. Specific flags will determine specific behaviours, which is what we'll come on to explain below.|

Next, we'll come on to discuss theÂ _Three-way handshake -_Â the term given for the process used to establish a connection between two devices.Â The Three-way handshake communicates using a few special messages - the table below highlights the main ones:

  

|   |   |   |
|---|---|---|
|**Step**|**Message**|**Description**|
|1|SYN|A SYN message is the initial packet sent by a client during the handshake. This packet is used to initiate a connection and synchronise the two devices together (we'll explain this further later on).|
|2|SYN/ACK|This packet is sent by the receiving device (server) to acknowledge the synchronisation attempt from the client.|
|3|ACK|The acknowledgement packet can be used by either the client or server to acknowledge that a series of messages/packets have been successfully received.|
|4|DATA|Once a connection has been established, data (such as bytes of a file) is sent via the "DATA" message.|
|5|FIN|This packet is used toÂ _cleanly (properly)_Â close the connection after it has been complete.|
|#|RST|This packet abruptly ends all communication. This is the last resort and indicates there was some problem during the process. For example, if the service or application is not working correctly, or the system has faults such as low resources.|

The diagram below shows a normal Three-way handshake process between Alice and Bob. In real life, this would be between two devices.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5de96d9ca744773ea7ef8c00/room-content/67dc0504ffa42cac0579cfeb64227ccb.svg)  

Any sent data is given a random number sequence and is reconstructed using this number sequence and incrementing by 1. Both computers must agree on the same number sequence for data to be sent in the correct order. This order is agreed upon during three steps:

1. SYN - Client: Here's my Initial Sequence Number(ISN) toÂ SYNchronise with (0)
2. SYN/ACK - Server: Here's my Initial Sequence NumberÂ (ISN) toÂ SYNchronise with (5,000), and IÂ ACKnowledge your initial number sequence (0)
3. ACK - Client: IÂ ACKnowledge your Initial Sequence NumberÂ (ISN) of (5,000), here is some data that is my ISN+1 (0 + 1)

|   |   |   |
|---|---|---|
|Device|**Initial Number Sequence (ISN)  <br>**|**Final Number Sequence  <br>**|
|Client (Sender)|0|0 + 1 = 1|
|Client (Sender)|1|1 + 1 = 2|
|Client (Sender)|2|2 + 1 = 3|

**TCPÂ Closing a Connection:**

Let's quickly explain the process behindÂ TCPÂ closing a connection. First,Â TCPÂ will close a connection once a device has determined that the other device has successfully received all of the data.

BecauseÂ TCPÂ reserves system resources on a device, it is best practice to closeÂ TCPÂ connections as soon as possible.

To initiate the closure of a TCP connection, the device will send a "FIN" packet to the other device. Of course, withÂ TCP, the other device will also have to acknowledge this packet.

Let's show this process using Alice and Bob as we have previously.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5de96d9ca744773ea7ef8c00/room-content/d29463eda80fa9e4cbe78b16aa5d9f87.svg)  

In the illustration, we can see that Alice has sent Bob a "**FIN**" packet. Because Bob received this, he will let Alice know that he received it and that he also wants to close the connection (using FIN). Alice has heard Bob loud and clear and will let Bob know that she acknowledges this.


![Pasted image 20241120175712.png](../../IMAGES/Pasted%20image%2020241120175712.png)

# UDP/IP
----

TheÂ **U**serÂ **D**atagramÂ **P**rotocol (**UDP**) is another protocol that is used to communicate data between devices.

  

Unlike its brother TCP,Â UDPÂ is aÂ **stateless**Â protocol that doesn't require a constant connection between the two devices for data to be sent. For example, the Three-way handshake does not occur, nor is there any synchronisation between the two devices.

  

Recall some of the comparisons made about these two protocols in Room 3: "OSI Model". Namely,Â UDPÂ is used in situations where applications can tolerate data being lost (such as video streaming or voice chat) or in scenarios where an unstable connection is not the end-all. A table comparing the advantages and disadvantages ofÂ UDPÂ is located below:

  

|   |   |
|---|---|
|**Advantages ofÂ UDP**|**Disadvantages ofÂ UDP**|
|UDPÂ is much faster thanÂ TCP.|UDP doesn't care if the data is received or not.|
|UDPÂ leaves the application (user software) to decide if there is any control over how quickly packets are sent.|It is quite flexible to software developers in this sense.|
|UDPÂ does not reserve a continuous connection on a device asÂ TCPÂ does.|This means that unstable connections result in a terrible experience for the user.|

As mentioned, no process takes place in setting up a connection between two devices. Meaning that there is no regard for whether or not data is received, and there are no safeguards such as those offered byÂ TCP, such as data integrity.

  

UDPÂ packets are much simpler thanÂ TCPÂ packets and have fewer headers. However, both protocols share some standard headers, which are what is annotated in the table below:

  

|   |   |
|---|---|
|**Header**|**Description**|
|Time to Live (TTL)|This field sets an expiry timer for the packet, so it doesn't clog up your network if it never manages to reach a host or escape!|
|Source Address|The IP address of the device that the packet is being sent from, so that data knows where to return to.|
|Destination Address|The device's IP address the packet is being sent to so that data knows where to travel next.|
|Source Port|This value is the port that is opened by the sender to send the UDP packet from. This value is randomly chosen (out of the ports from 0-65535 that aren't already in use at the time).|
|Destination Port|This value is the port number that an application or service is running on the remote host (the one receiving the data); for example, a webserver running on port 80. Unlike the source port, this value is not chosen at random.|
|Data|This header is where data, i.e. bytes of a file that is being transmitted, is stored.|

Next, we'll come on to discuss how the process of a connection viaÂ UDPÂ differs from that of something such as TCP.Â  We should recall thatÂ UDPÂ isÂ **stateless**. No acknowledgement is sent during a connection.

  

The diagram below shows a normalÂ UDPÂ connection between Alice and Bob. In real life, this would be between two devices.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5de96d9ca744773ea7ef8c00/room-content/53d459ccda57e5fdea0dafe7e64ffe7c.svg)

![Pasted image 20241120175844.png](../../IMAGES/Pasted%20image%2020241120175844.png)

# Ports 101 (Practical)
---

Perhaps aptly titled by their name, ports are an essential point in which data can be exchanged. Think of a harbour and port. Ships wishing to dock at the harbour will have to go to a port compatible with the dimensions and the facilities located on the ship. When the ship lines up, it will connect to aÂ **port**Â at the harbour. Take, for instance, that a cruise liner cannot dock at a port made for a fishing vessel and vice versa.

  

These ports enforce what can park and where â€” if it isn't compatible, it cannot park here. Networking devices also use ports to enforce strict rules when communicating with one another. When a connection has been established (recalling from the OSI model's room), any data sent or received by a device will be sent through these ports. In computing, ports are a numerical value betweenÂ **0**Â andÂ **65535**Â (65,535).

  

Because ports can range from anywhere between 0-65535, there quickly runs the risk of losing track of what application is using what port. A busy harbour is chaos! Thankfully, we associate applications, software and behaviours with a standard set of rules. For example, by enforcing that any web browser data is sent over port 80, software developers can design a web browser such as Google Chrome or Firefox to interpret the data the same way as one another.

  

This means that all web browsers now share one common rule: data is sent over port 80. How the browsers look, feel and easy to use is up to the designer or the user's decision.

  

While the standard rule for web data isÂ _port 80_, a few other protocols have been allocated a standard rule. Any port that is withinÂ **0**Â andÂ **1024**Â (1,024) is known as a common port. Let's explore some of these other protocols below:

|   |   |   |
|---|---|---|
|**Protocol**|**Port Number**|**Description**|
|**F**ileÂ **T**ransferÂ **P**rotocol (**FTP**)|21|This protocol is used by a file-sharing application built on a client-server model, meaning you can download files from a central location.|
|**S**ecureÂ **Sh**ell (**SSH**)|22|This protocol is used to securely login to systems via a text-based interface for management.|
|**H**yper**T**ext Transfer Protocol (**HTTP**)|80|This protocol powers the World Wide Web (WWW)! Your browser uses this to download text, images and videos of web pages.|
|**H**yper**T**extÂ **T**ransferÂ **P**rotocolÂ **S**ecure (**HTTPS**)|443|This protocol does the exact same as above; however, securely using encryption.|
|**S**erverÂ **M**essageÂ **B**lock (**SMB**)|445|This protocol is similar to the File Transfer Protocol (FTP); however, as well as files,Â SMBÂ allows you to share devices like printers.|
|**R**emoteÂ **D**esktopÂ **P**rotocol (**RDP**)|3389|This protocol is a secure means of logging in to a system using a visual desktop interface (as opposed to the text-based limitations of theÂ SSHÂ protocol).|

We have only briefly covered the more common protocols in cybersecurity. You canÂ [find a table of the 1024 common ports listed](http://www.vmaxx.net/techinfo/ports.htm)Â for more information.

What is worth noting here is that these protocols only follow the standards. I.e. you can administer applications that interact with these protocols on a different port other than what is the standard (running a web server on 8080 instead of the 80 standard port). Note, however, applications will presume that the standard is being followed, so you will have to provide aÂ **colon (:)**Â along with the port number.
