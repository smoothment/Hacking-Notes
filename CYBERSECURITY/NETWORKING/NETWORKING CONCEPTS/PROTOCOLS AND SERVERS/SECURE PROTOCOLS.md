---
sticker: lucide//wifi
---
# INTRODUCTION

In theÂ [Networking Core Protocols](https://tryhackme.com/r/room/networkingcoreprotocols)Â room, we learned about the protocols used to browse the web and access email, among others. These protocols work great; however, they cannot protect the confidentiality, integrity, or authenticity of the data transferred. In simpler terms, when we say that confidentiality is not protected, it means that someone watching the packets can read your password or credit card information when sent overÂ HTTP. Similarly, they can access your private documents when sent via email. As for not protecting the integrity of the data, it means that an adversary can change the contents of the transferred data; in other words, if you authorize the payment of one hundred pounds, they can easily change it to another value, such as eight hundred pounds. Authenticity means ensuring we are talking with the correct server, not a fake one. Important online transactions are risky without ensuring confidentiality, integrity, and authenticity.

Transport Layer Security (TLS) is added to existing protocols to protect communication confidentiality, integrity, and authenticity. Consequently, HTTP, POP3,Â SMTP, andÂ IMAPÂ become HTTPS, POP3S, SMTPS, and IMAPS, where the appended â€œSâ€ stands for Secure. We will examine these protocols and the benefits we reaped from TLS.

Similarly, it is deemed insecure to remotely access a system using the TELNET protocol; Secure Shell (SSH) was created to provide a secure way to access remote systems. Furthermore,Â SSHÂ is an extensible protocol that offers added security features for other protocols.

### Room Prerequisites

This room is the last in a group of four rooms about computer networking:

```ad-summary
- [Networking Concepts](https://tryhackme.com/r/room/networkingconcepts)
- [Networking Essentials](https://tryhackme.com/r/room/networkingessentials)
- [Networking Core Protocols](https://tryhackme.com/r/room/networkingcoreprotocols)
- Networking Secure Protocols (this room)
```

We recommend finishing all the previous three rooms before starting this one.

### Learning Objectives

Upon finishing this room, you will learn about:

```ad-important
- SSL/TLS
- How to secure existing plaintext protocols:
    - HTTP
    - SMTP
    - POP3
    - IMAP
- HowÂ SSHÂ replaced the plaintext TELNET
- HowÂ VPNÂ creates a secure network over an insecure one
```



# TLS

At one point, you would only need a packet-capturing tool to read all the chats, emails, and passwords of the users on your network. It was not uncommon for an attacker to set their network card in promiscuous mode, i.e., to capture all packets, including those not destined to it. They would later go through all the packet captures and obtain the login credentials of unsuspecting victims. There was nothing a user could do to prevent their login password from being sent in cleartext. Nowadays, it has become uncommon to come across a service that sends login credentials in cleartext.

In the early 1990s, Netscape Communications recognized the need for secure communication on the World Wide Web. They eventually developed SSL (Secure Sockets Layer) and released SSL 2.0 inÂ **1995**Â as the first public version. InÂ **1999**, the Internet Engineering Task Force (IETF) developed TLS (Transport Layer Security). Although very similar, TLS 1.0 was an upgrade to SSL 3.0 and offered various improved security measures. InÂ **2018**, TLS had a significant overhaul of its protocol and TLS 1.3 was released. The purpose is not to remember the exact dates but to realize the amount of work and time put into developing the current version of TLS, i.e., TLS 1.3. Over more than two decades, there have been many things to learn from and improve with every version.

Like SSL, its predecessor, TLS is a cryptographic protocol operating at the OSI modelâ€™s transport layer. It allows secure communication between a client and a server over an insecure network. By secure, we refer to confidentiality and integrity; TLS ensures that no one can read or modify the exchanged data. Please take a minute to think about what it would be like to do online shopping, online banking, or even online messaging and email without being able to guarantee the confidentiality and integrity of the network packets. Without TLS, we would be unable to use the Internet for many applications that are now part of our daily routine.

Nowadays, tens of protocols have received security upgrades with the simple addition of TLS. Examples include HTTP,Â DNS, MQTT, and SIP, which have become HTTPS, DoT (DNSÂ over TLS), MQTTS, and SIPS, where the appended â€œSâ€ stands for Secure due to the use of SSL/TLS. In the following tasks, we will visit HTTPS, SMTPS, POP3S, and IMAPS.

### Technical Background

We will not discuss the TLS handshake; however, if you are curious, you can check theÂ [Network Security Protocols](https://tryhackme.com/r/room/networksecurityprotocols)Â room. We will give a general overview of how TLS is set up and used.

The first step for every server (or client) that needs to identify itself is to get a signed TLS certificate. Generally, the server administrator creates a Certificate Signing Request (CSR) and submits it to a Certificate Authority (CA); the CA verifies the CSR and issues a digital certificate. Once the (signed) certificate is received, it can be used to identify the server (or the client) to others, who can confirm the validity of the signature. For a host to confirm the validity of a signed certificate, the certificates of the signing authorities need to be installed on the host. In the non-digital world, this is similar to recognizing the stamps of various authorities. The screenshot below shows the trusted authorities installed in a web browser.

![Certificate authorities installed by default on a web browser](https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/5f04259cf9bf5b57aed2c476-1721903285393.png)  

Generally speaking, getting a certificate signed requires paying an annual fee. However,Â [Letâ€™s Encrypt](https://letsencrypt.org/)Â allows you to get your certificate signed for free.

Finally, we should mention that some users opt to create a self-signed certificate. A self-signed certificate cannot prove the serverâ€™s authenticity as no third party has confirmed it.

## QUESTIONS

![Pasted image 20241101151405.png](../../../IMAGES/Pasted%20image%2020241101151405.png)



# HTTPS

### HTTP

As we studied in theÂ [Networking Core Protocols](https://tryhackme.com/r/room/networkingcoreprotocols)Â room, HTTP relies onÂ TCPÂ and uses port 80 by default. We also saw how allÂ HTTPÂ traffic was sent in cleartext for anyone to intercept and monitor. The screenshot below is from the previous room, and it gives a clear idea of how an adversary can easily read all the traffic exchanged between the client and the server.

![Wireshark displaying assembled plaintext HTTP request and response.](https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/5f04259cf9bf5b57aed2c476-1721903308261.png)

Letâ€™s take a minute to review the most common steps before a web browser can request a page overÂ HTTP. After resolving the domain name to an IP address, the client will carry out the following two steps:

1. Establish aÂ TCPÂ three-way handshake with the target server
2. Communicate using theÂ HTTPÂ protocol; for example, issueÂ HTTPÂ requests, such asÂ `GET /Â HTTP/1.1`

The two steps described above are shown in the window below. The three packets for theÂ TCPÂ handshake (marked with 1) precede the firstÂ HTTPÂ packet withÂ `GET`Â in it. The HTTP communication is marked with 2. The last three displayed packets are forÂ TCPÂ connection termination and are marked with 3.

![Wireshark displaying a TCP connection getting established, HTTP request sent and response received, and the TCP connection getting terminated.](https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/5f04259cf9bf5b57aed2c476-1721903373648.png)

### HTTPÂ Over TLS

HTTPS stands for Hypertext Transfer Protocol Secure. It is basicallyÂ HTTPÂ over TLS. Consequently, requesting a page over HTTPS will require the following three steps (after resolving the domain name):

1. Establish aÂ TCPÂ three-way handshake with the target server
2. Establish a TLS session
3. Communicate using theÂ HTTPÂ protocol; for example, issueÂ HTTPÂ requests, such asÂ `GET /Â HTTP/1.1`

The screenshot below shows that aÂ TCPÂ session is established in the first three packets, marked with 1. Then, several packets are exchanged to negotiate the TLS protocol, marked with 2. Finally,Â HTTPÂ application data is exchanged, marked with 3. Looking at the Wireshark screenshot, we see that it says â€œApplication Dataâ€ because there is no way to know if it is indeedÂ HTTPÂ or some other protocol sent over port 443.

![Wireshark displaying a TCP connection getting established, a TLS session getting established, and encrypted application data](https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/5f04259cf9bf5b57aed2c476-1721903449717.png)  

As expected, if one tries to follow the stream of packets and combine all their contents, they will only get gibberish, as shown in the screenshot below. The exchanged traffic is encrypted; the red is sent by the client, and the blue is sent by the server. There is no way to know the contents without acquiring the encryption key.

![Wireshark displaying assembled encrypted HTTPS traffic](https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/5f04259cf9bf5b57aed2c476-1721903354908.png)  

#### Getting the Encryption Key

Adding TLS to HTTP leads to all the packets being encrypted. We can no longer see the contents of the exchanged packets unless we get access to the private key. Although it is improbable that we will have access to the keys used for encryption in a TLS session, we repeated the above screenshots after providing the decryption key to Wireshark. TheÂ TCPÂ and TLS handshakes donâ€™t change; the main difference starts with theÂ HTTPÂ protocol marked 3. For instance, we can see when the client issues aÂ `GET`.

![Wireshark displaying a TCP connection getting established, a TLS session getting established, and HTTP request sent and response received.](https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/5f04259cf9bf5b57aed2c476-1729689224251.png)

If you want to see the data exchanged, now is your chance! It is still regularÂ HTTPÂ traffic hidden from prying eyes.

![Wireshark displaying assembled HTTPS request and response after decryption](https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/5f04259cf9bf5b57aed2c476-1721903477148.png)

The key takeaway is that TLS offered security for HTTP without requiring any changes in the lower or higher layer protocols. In other words,Â TCPÂ and IP were not modified, while HTTP was sent over TLS the way it would be sent overÂ TCP.

## QUESTIONS

![Pasted image 20241101151509.png](../../../IMAGES/Pasted%20image%2020241101151509.png)

# SMTPS, POP3S, AND IMAPS

Adding TLS toÂ SMTP, POP3, andÂ IMAPÂ is no different than adding TLS toÂ HTTP. Similar to howÂ HTTPÂ gets an appended S forÂ _Secure_Â and becomes HTTPS,Â SMTP, POP3, andÂ IMAPÂ become SMTPS, POP3S, and IMAPS, respectively. Using these protocols over TLS is no different than usingÂ HTTPÂ over TLS; therefore, almost all the points from the HTTPS discussion apply to these protocols.

The insecure versions use the defaultÂ TCPÂ port numbers shown in the table below:

|Protocol|Default Port Number|
|---|---|
|HTTP|80|
|SMTP|25|
|POP3|110|
|IMAP|143|

The secure versions, i.e., over TLS, use the followingÂ TCPÂ port numbers by default:

|Protocol|Default Port Number|
|---|---|
|HTTPS|443|
|SMTPS|465 and 587|
|POP3S|995|
|IMAPS|993|

TLS can be added to many other protocols; the reasoning and advantages would be similar.

## QUESTION

![Pasted image 20241101151544.png](../../../IMAGES/Pasted%20image%2020241101151544.png)

# SSH

We have used the TELNET protocol in theÂ [Networking Concepts](https://tryhackme.com/r/room/networkingconcepts)Â room. Although it is very convenient to log in and administer remote systems, it is risky when all the traffic is sent in cleartext. It is easy for anyone monitoring the network traffic to get hold of your login credentials once you useÂ `telnet`. This problem necessitated a solution. Tatu YlÃ¶nen developed the Secure Shell (SSH) protocol and releasedÂ SSH-1 inÂ **1995**Â as freeware. (Interestingly, it was the same year that Netscape Communications released the SSL 2.0 protocol.) A more secure version,Â SSH-2, was defined in 1996. InÂ **1999**, the OpenBSD developers released OpenSSH, an open-source implementation ofÂ SSH. Nowadays, when you use anÂ SSHÂ client, it is most likely based on OpenSSH libraries and source code.

OpenSSH offers several benefits. We will list a few key points:

```ad-summary
- **Secure authentication**: Besides password-based authentication,Â SSHÂ supports public key and two-factor authentication.
- **Confidentiality**: OpenSSH provides end-to-end encryption, protecting against eavesdropping. Furthermore, it notifies you of new server keys to protect against man-in-the-middle attacks.
- **Integrity**: In addition to protecting the confidentiality of the exchanged data, cryptography also protects the integrity of the traffic.
- **Tunneling**:Â SSHÂ can create a secure â€œtunnelâ€ to route other protocols throughÂ SSH. This setup leads to aÂ VPN-like connection.
- **X11 Forwarding**: If you connect to a Unix-like system with a graphical user interface,Â SSHÂ allows you to use the graphical application over the network.
```

You would issue the commandÂ `ssh username@hostname`Â to connect to anÂ SSHÂ server. If the username is the same as your logged-in username, you only needÂ `ssh hostname`. Then, you will be asked for a password; however, if public-key authentication is used, you will be logged in immediately.

The screenshot below shows an example of running Wireshark on a remote KaliÂ LinuxÂ system. The argumentÂ `-X`Â is required to support running graphical interfaces, for example,Â `ssh 192.168.124.148 -X`. (The local system needs to have a suitable graphical system installed.)

![After establishing an SSH connection to a remote server, we successfully started Wireshark, an application with a graphical user interface.](https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/5f04259cf9bf5b57aed2c476-1721903514417.png)

While the TELNET server listens on port 23, theÂ SSHÂ server listens on port 22.

# QUESTION

![Pasted image 20241101151635.png](../../../IMAGES/Pasted%20image%2020241101151635.png)

# SFTP AND FTPS


SFTP stands forÂ SSHÂ File Transfer Protocol and allows secure file transfer. It is part of theÂ SSHÂ protocol suite and shares the same port number, 22. If enabled in the OpenSSH server configuration, you can connect using a command such asÂ `sftp username@hostname`. Once logged in, you can issue commands such asÂ `get filename`Â andÂ `put filename`Â to download and upload files, respectively. Generally speaking, SFTP commands are Unix-like and can differ fromÂ FTPÂ commands.

SFTP should not be confused with FTPS. You are right to think that FTPS stands for File Transfer Protocol Secure. How is FTPS secured? Yes, you are correct to estimate that it is secured using TLS, just like HTTPS. WhileÂ FTPÂ uses port 21, FTPS usually uses port 990. It requires certificate setup, and it can be tricky to allow over strict firewalls as it uses separate connections for control and data transfer.

Setting up an SFTP server is as easy as enabling an option within the OpenSSH server. Like HTTPS, SMTPS, POP3S, IMAPS, and other protocols that rely on TLS for security, FTPS requires a proper TLS certificate to run securely.

# VPN

Consider a company with offices in different geographical locations. Can this company connect all its offices and sites to the main branch so that any device can access the shared resources as if physically located in the main branch? The answer is yes; furthermore, the most economical solution would be setting up a virtual private network (VPN) using the Internet infrastructure. The focus here is on the V for Virtual inÂ VPN.

When the Internet was designed, theÂ TCP/IP protocol suite focused on delivering packets. For example, if a router gets out of service, the routing protocols can adapt and pick a different route to send their packets. If a packet was not acknowledged,Â TCPÂ has built-in mechanisms to detect this situation and resend. However, no mechanisms are in place to ensure thatÂ **all data**Â leaving or entering a computer is protected from disclosure and alteration. A popular solution was the setup of aÂ VPNÂ connection. The focus here is on the P for Private inÂ VPN.

Almost all companies require â€œprivateâ€ information exchange in their virtual network. So, aÂ VPNÂ provides a very convenient and relatively inexpensive solution. The main requirements are Internet connectivity and aÂ VPNÂ server and client.

The network diagram below shows an example of a company with two remote branches connecting to the main branch. AÂ VPNÂ client in the remote branches is expected to connect to theÂ VPNÂ server in the main branch. In this case, theÂ VPNÂ client will encrypt the traffic and pass it to the main branch via the establishedÂ VPNÂ tunnel (shown in blue). TheÂ VPNÂ traffic is limited to the blue lines; the green lines would carry the decryptedÂ VPNÂ traffic.

![A network diagram showing two remote company branches connecting to the main branch over VPN.](https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/5f04259cf9bf5b57aed2c476-1721903538365.svg)

In the network diagram below, we see two remote users usingÂ VPNÂ clients to connect to theÂ VPNÂ server in the main branch. In this case, theÂ VPNÂ client connects a single device.

![A network diagram showing two remote employees with laptops connecting to the main branch over VPN](https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/5f04259cf9bf5b57aed2c476-1721903568757.svg)

Once aÂ VPNÂ tunnel is established, all our Internet traffic will usually be routed over theÂ VPNÂ connection, i.e.Â via theÂ VPNÂ tunnel. Consequently, when we try to access an Internet service or web application, they will not see our public IP address but theÂ VPNÂ serverâ€™s. This is why some Internet users connect overÂ VPNÂ to circumvent geographical restrictions. Furthermore, the local ISP will only see encrypted traffic, which limits its ability to censor Internet access.

In other words, if a user connects to aÂ VPNÂ server in Japan, they will appear to the servers they access as if located in Japan. These servers will customise their experience accordingly, such as redirecting them to the Japanese version of the service. The screenshot below shows the Google Search page after connecting to aÂ VPNÂ server in Japan.

![After we established a VPN connection to a VPN server in Japan, we visited Google Search and it was automatically displayed in Japanese language.](https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/5f04259cf9bf5b57aed2c476-1721903553939.png)

Finally, although in many scenarios, one would establish a VPN connection to route all the traffic over the VPN tunnel, some VPN connections donâ€™t do this. The VPN server may be configured to give you access to a private network but not to route your traffic. Furthermore, some VPN servers leak your actual IP address, although they are expected to route all your traffic over the VPN. Depending on why you are using a VPN connection, you might need to run a few more tests, such as aÂ DNSÂ leak test.

Finally, some countries consider using VPNs illegal and even punishable. Please check the local laws and regulations before using VPNs, especially while travelling.


