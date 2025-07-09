![Task banner for day DAY 20](https://tryhackme-images.s3.amazonaws.com/user-uploads/63588b5ef586912c7d03c4f0/room-content/63588b5ef586912c7d03c4f0-1731076103117.png)

_Glitch snuck through the shadows, swift as a breeze, 
He captured the traffic with delicate ease. 
A PCAP file from a system gone bad, 
Mayor Malware's tricks made everything mad!_

McSkidy sat at her desk, staring at the PCAP file Glitch had just sent over. It was from Marta May Ware's computer, the latest victim of Mayor Malware's long-running schemes.

She smiled, glancing at Byte. _"Looks like we'd have to use Wireshark again, eh boy?"_

Glitch's voice crackled over the comms. _"Need any help analyzing it?"_

McSkidy smiled. "_Thanks, Glitch, but I've got this._"

This is the continuation of [day 19](DAY%2019.md)

## Learning Objectives
----
```ad-summary
- Investigate network traffic using Wireshark
- Identify indicators of compromise (IOCs) in captured network traffic
- Understand how C2 servers operate and communicate with compromised systems
```


## Investigating the Depths
----
_McSkidy peered at the PCAP with care, 
"What secrets," she wondered, "are hiding in there?" 
With Wireshark, she'll dig through each Byte, 
Hoping to shed some much-needed light._

Before we dig deeper into Mayor Malware's intentions, we must learn a few essential things about C2 communication. Whenever a machine is compromised, the command and control server (C2) drops its secret agent (payload) into the target machine. This secret agent is meant to obey the instructions of the C2 server. These instructions include executing malicious commands inside the target, exfiltrating essential files from the system, and much more. Interestingly, after getting into the system, the secret agent, in addition to obeying the instructions sent by the C2, has a way to keep the C2 updated on its current status. It sends a packet to the C2 every few seconds or even minutes to let it know it is active and ready to blast anything inside the target machine that the C2 aims to. These packets are known as beacons.

![Pasted image 20241220114947.png](../../IMAGES/Pasted%20image%2020241220114947.png)

For this room, we will be using Wireshark, an open-source tool that captures and inspects network traffic saved as a PCAP file. It's a powerful tool, and you'll encounter it frequently in your journey in cyber security. It is beneficial for understanding the communications between a compromised machine and a C2 server.

If you are unfamiliar with it, here are some key capabilities youâ€™ll see in this room:

```ad-info
- Wireshark can analyze traffic and display the information in an easy-to-navigate format regardless of the protocols used (e.g., HTTP, TCP, DNS).
- Wireshark can reconstruct back-and-forth conversations in a network.
- Wireshark allows easy filtering to narrow down essential details.
- Wireshark can also export and analyze objects that are transferred over the network.
```

Of course, Wireshark has more capabilities. If you want to learn more, we suggest you visit our other Wireshark rooms:

```ad-info
- [Wireshark: The Basics](https://tryhackme.com/r/room/wiresharkthebasics) 
- [Wireshark: Packet Operations](https://tryhackme.com/r/room/wiresharkpacketoperations) 
- [Wireshark: Traffic Analysis](https://tryhackme.com/r/room/wiresharktrafficanalysis) 
```

## Diving Deeper
---

Now that we have a better idea of what C2 traffic looks like and how to use Wireshark, double-click on the file â€œ_C2_Traffic_Analysis_â€ on the Desktop. This will automatically open the PCAP file using Wireshark. 

That's traffic! Yes, and this would take us to the truth about Mayor Malware.

We already suspect that this machine is compromised. So, letâ€™s narrow down our list so that it will only show traffic coming from the IP address of Marta May Wareâ€™s machine. To do this, click inside the **Display Filter Bar** on the top, type`ip.src == 10.10.229.217`, and press **Enter**.

![Display Filter Bar](https://tryhackme-images.s3.amazonaws.com/user-uploads/63588b5ef586912c7d03c4f0/room-content/63588b5ef586912c7d03c4f0-1729246743949.png) 

Itâ€™s still a lot, but at least we can now focus our analysis on outbound traffic.

If you scroll down a bit, you will find some interesting packets, specifically those highlighted with an arrow, as shown below.

![Highlighted packets](https://tryhackme-images.s3.amazonaws.com/user-uploads/63588b5ef586912c7d03c4f0/room-content/63588b5ef586912c7d03c4f0-1729246982740.png) 

Initial? Command? Exfiltrate? That is sure to be something!

Letâ€™s dive deeper.

We can filter these packets by using: `ip.src == 10.10.229.217 && http`

## Message Received

If you click on the POST /initial packet (Frame 440), more details will be shown on the bottom panes. These panes will show more detailed information about the packet frame. It shows relevant details such as frame number (440), the destination IP (10.10.123.224), and more.

You can expand each detail if you want, but the critical area to focus on is the lower-right view, the â€œPacket Bytesâ€ pane.

Packet Bytes pane
![Pasted image 20241220115757.png](../../IMAGES/Pasted%20image%2020241220115757.png)

This pane shows the bytes used in the communication in hexadecimal and ASCII character formats. The latter format shows readable text, which can be helpful in investigations.

The screenshot above shows something interesting: â€œI am in Mayor!â€. This piece of text is likely relevant to us.

If we right-click on the POST /initial packet (Frame 440) and select Follow > HTTP Stream, a new pop-up window will appear containing the back-and-forth HTTP communication relevant to the specific session.

![Pasted image 20241220115826.png](../../IMAGES/Pasted%20image%2020241220115826.png)


This feature is useful when you need to view all requests and responses between the client and the server, as it helps you understand the complete context of the communication.

The text highlighted in red is the message sent from the source to the destination, and blue is the opposite. So, based on the screenshot above, we can see that after the message â€œI am in Mayor!â€ was sent, a response that reads â€œPerfect!" was sent back.

Perfect, indeed, Mayor. We got you now!

But letâ€™s not stop here. Other interesting HTTP packets were sent to the same destination IP. If you follow the HTTP Stream for the `GET /command` packet (Frame 457), youâ€™ll see a request to the same IP destination. Interestingly, the reply that came back was a command commonly used in Windows and Linux systems to display the current userâ€™s information. This communication suggests that the destination is attempting to gather information about the compromised system, a typical step during an early reconnaissance stage.

Usually, the reply from a C2 server contains the command, instructing the malicious program what to do next. However, the type of instruction depends on the malicious actorâ€™s configuration, intention, and capabilities. These instructions often fall into several categories:

```ad-info
1. Getting system information: The attacker may want to know more about the compromised machine to tailor their next moves. This is what we are seeing above.
2. Executing commands: If the attacker needs to perform specific actions, they can also send commands directly. However, this is less stealthy and easily attracts attention.
3. Downloading and executing payloads: The attacker can also send additional payloads to the machine containing additional functionality or tools.
4. Exfiltrating data: This is one of the most common objectives. The program may be instructed to steal valuable data such as sensitive files, credentials, or personal information.
```

Exfiltrate sounds familiar, right?

## Exfiltrating the Package
---

Picture of McSkidy

If we follow the HTTP Stream for the POST /exfiltrate packet (Frame 476) sent to the same destination IP, we will see a file exfiltrated to the C2 server. We can also find some clues inside this file. 

If you check the rest of the PCAP, youâ€™ll find that more interesting packets were captured. Letâ€™s break these down and dive deeper into what weâ€™ve uncovered.

![Pasted image 20241220120145.png](../../IMAGES/Pasted%20image%2020241220120145.png)


## Whatâ€™s in the Beacon
----

A typical C2 beacon returns regular status updates from the compromised machine to its C2 server. The beacons may be sent after regular or irregular intervals to the C2 as a heartbeat. Hereâ€™s how this exchange might look:


- **Secret agent (payload)**: â€œI am still alive. Awaiting any instructions. Over.â€
- **C2 server**: â€œGlad to hear that! Stand by for any further instructions. Over.â€

In this scenario, Mayor Malwareâ€™s agent (payload) inside Marta May Wareâ€™s computer has sent a message that is sent inside all the beacons. Since the content is highly confidential, the secret agent encrypts it inside all the beacons, leaving a clue for the Mayorâ€™s C2 to decrypt it. In the current scenario, we can identify the beacons by the multiple requests sent to the C2 from the target machine after regular intervals of time.


The exfiltrated file's content hints at how these encrypted beacons can be decrypted. Using the encryption algorithm with the provided key, we now have a potential way to unlock the beaconâ€™s message and uncover what Mayor Malware's agent is communicating to the C2 server.

But what exactly are we about to reveal?

Since the beacon is now encrypted and you have the key to decrypt it, the CyberChef tool would be our source of truth for solving this mystery. Because of its wide features, CyberChef is considered a "Swiss Army Knife". We can use this tool for encoding, decoding, encrypting, decrypting, hashing, and much more. However, considering this task's scope, we would only cover the decryption process using this tool.

This link will open the CyberChef tool in your browser. Note that you will have to open this link within your own browser, since the target VM has no internet connection.

From the tool's dashboard, you would be utilizing the following panes for decrypting your beacon:


```ad-summary
1. Operations: Search for AES Decrypt and drag it to the Recipe area, which is in the second pane.
2. Recipe: This is the area where you would select the mode of encryption, ECB, and enter the decryption key you have. Keep the other options as they are.
3. Input: Once the Recipe is done, it is time to enter our encrypted beacon into the Input area. Copy your encrypted string and paste it here.
4. Output: Once you have completed the above steps, you need to click the "Bake" button in the Recipe area. Your encrypted string will be decrypted using the AES ECB decryption with the key you provided, and the output will be displayed in the Output area.
```


If you want to learn more about CyberChef, check out our CyberChef: The Basics room from the Cyber Security 101 path.

## The End
--- 

As McSkidy opened the file with a click,
She saw all the dataâ€”this wasnâ€™t a wasn't
The storm was brewing, much bigger to come,
Mayor Malwareâ€™s agent is far from done!

â€œThis isn't just another breach,â€ McSkidy muttered to Byte, a grim realization dawning. â€œWeâ€™re going to need a bigger firewall."


## Questions
---

![Pasted image 20241220120354.png](../../IMAGES/Pasted%20image%2020241220120354.png)


Let's go step by step:


As we've checked, we are already following the stream of this http packet sent by mayor malware, let's keep on following the stream and check what it has for us:


![Pasted image 20241220120624.png](../../IMAGES/Pasted%20image%2020241220120624.png)

Second stream shows that the command `whoami` was executed in the machine, that answers our third question, let's keep following the stream:

![Pasted image 20241220120743.png](../../IMAGES/Pasted%20image%2020241220120743.png)

We got `AES ECB` data, let's use CyberChef and decrypt it, for this, we need the encrypted data, let's follow the next stream and check if its in there:

![Pasted image 20241220121133.png](../../IMAGES/Pasted%20image%2020241220121133.png)

Indeed it was, now, let's decrypt:



![Pasted image 20241220121158.png](../../IMAGES/Pasted%20image%2020241220121158.png)

We got the output: `THM_Secret_101`


Nice, now we've got all of our answers, they would be the following:


![Pasted image 20241220121351.png](../../IMAGES/Pasted%20image%2020241220121351.png)

Just like that, day 20 is done!

