![5f04259cf9bf5b57aed2c476-1731490380964 1.svg](../../IMAGES/5f04259cf9bf5b57aed2c476-1731490380964%201.svg)



_In Wareville the townspeople started to frown,_

_A problem with smart lights all over the town!_

_Was SOC-mas ruined? The chances were zero,_

_Because this they knew, the Glitch was their hero!_


 
The city of Wareville has invested in smart lights and heating, ventilation, and air conditioning (HVAC). Oh, it was so easy to control the lights and heating remotely. Following the recent incidents, McSkidy started monitoring these smart devices' communication protocols. Not long after the lights and heating were up and running, Mayor Malware figured out how these devices were controlled and sabotaged them. Luckily, McSkidy was one step ahead and picked up the malicious commands that had been sent. Can you help McSkidy figure out which commands were sent? We can then use our findings to update the devices' configuration and save the day!

This is the continuation of [day 23](DAY%2023.md) and the last day!
## Learning Objectives
---

In this task, you will learn about:

```ad-summary
- The basics of the MQTT protocol
- How to use Wireshark to analyze MQTT traffic
- Reverse engineering a simple network protocol
```


## How Smart is Smart
----
Smart devices make our lives very easy. We no longer physically need to move and turn on or off a switch to control them. With smart HVAC systems, we can maintain the temperature of our homes and ensure they are not too cold or too hot when we come home from outside. Smart vacuum cleaners can clean our house while we work on other things or go out for dinner. Many smart devices come with apps that allow us to control them using our mobile phones. Even better, since these devices can be controlled remotely through apps and interfaces connected to the Internet, we can make their designs more minimalistic and aesthetically independent, and the need for adding switches or controls on the device itself is minimized.

## Is It Smart
----
While they make our lives easier, most smart devices need a network connection to provide control to the users. Many smart devices are connected over the Internet (hence the term Internet of Things or IoT), which, from a security point of view, means that anyone can potentially take control of these devices. We can limit the exposure of these devices by adding security controls such as network isolation and authentication mechanisms. Still, if we fail to do so, the results can be catastrophic. However, the most secure system is a system that is shut down, but that does not deter us from using different systems to help us out in our daily lives, and the same should be the case with smart devices. Instead, we can ensure that we understand how our smart devices work and have adequate security set up for them.

![AoC Day 24 - Reverse engineering animation.gif](../../IMAGES/AoC%20Day%2024%20-%20Reverse%20engineering%20animation.gif)


## The Language of IoT
----
Although different IoT and smart devices use various programming languages, depending on the platform and vendor, they often need to speak the same language to be able to communicate with each other. For example, while IoT devices might use C++ or Java to talk to the compiler and the underlying hardware, they will need a language like HTTP or MQTT to talk with your system or mobile device.

## How to Speak MQTT
----
MQTT stands for Message Queuing Telemetry Transport. It is a language very commonly used in IoT devices for communication purposes. It works on a publish/subscribe model, where any client device can publish messages, and other client devices can subscribe to the messages if they are related to a topic of interest. An MQTT broker connects the different clients, publishing and subscribing to messages.

![MQTT example network](https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/5f04259cf9bf5b57aed2c476-1732161467165.png)

To further understand MQTT, let's explore some key concepts used in MQTT protocols.

**MQTT Clients:** MQTT clients are IoT devices, such as sensors and controllers, that publish or subscribe to messages using the MQTT protocol. For example, a temperature sensor can be a client that publishes temperature sensors at different places. An HVAC controller can also act as a client that subscribes to messages from the temperature sensor and turns the HVAC system on or off based on the input received.

**MQTT Broker:** An MQTT broker receives messages from publishing clients and distributes them to the subscribing clients based on their preferences.

**MQTT Topics:** Topics are used to classify the different types of messages. Clients can subscribe to messages based on their topics of interest. For example, a temperature sensor sending temperature readings can use the topic of œroom temperature, while an HVAC controller would subscribe to messages under the topic of œroom temperature. However, a light sensor can publish messages with the topic œlight readings. An HVAC controller does not need to subscribe to this topic. On the other hand, a light controller would subscribe to œlight readings but not to the topic of œroom temperature.

## Demonstration
----

Learning about a protocol theoretically can be confusing. Let's see how it works in practice. The files related to this task are in the`~/Desktop/MQTTSIM/` directory. The walkthrough and the challenge files are shown in the terminal below.

```shell-session
ubuntu@tryhackme:~/Desktop/MQTTSIM$ tree
.
â”œâ”€â”€ challenge
â”‚ â”œâ”€â”€ challenge.pcapng
â”‚ â”œâ”€â”€ challenge.sh
â”‚ â””â”€â”€ lights.py
â””â”€â”€ walkthrough
 â”œâ”€â”€ hvac.py
 â””â”€â”€ walkthrough.sh
```

As we discussed, different IoT devices communicate with each other using MQTT, a network protocol. Therefore, we must monitor network communication to see what is going on. We will use Wireshark to monitor network communication. On the left side, we can click the Wireshark logo to start Wireshark. On the home screen, we can select ˜any' for the network interface to see traffic from all the network interfaces.

![Wirshark and the available interfaces](https://tryhackme-images.s3.amazonaws.com/user-uploads/61306d87a330ed00419e22e7/room-content/61306d87a330ed00419e22e7-1729327245985.png)

The screenshot below shows the traffic from all the interfaces on the network as we have selected 'any' for the network interface.

![Wireshark capturing on the any interface](https://tryhackme-images.s3.amazonaws.com/user-uploads/61306d87a330ed00419e22e7/room-content/61306d87a330ed00419e22e7-1729327245982.png)

Since we only want to see traffic from the MQTT protocol, we can filter for this protocol only. To do that, we can type`mqtt` in the filter box and press enter.

![Wireshark filtering for MQTT traffic](https://tryhackme-images.s3.amazonaws.com/user-uploads/61306d87a330ed00419e22e7/room-content/61306d87a330ed00419e22e7-1729327245981.png)

There will be no traffic for now as no MQTT broker or client is running. Let's start the MQTT broker and client to see the traffic. For that, there is a shortcut for a directory on the Desktop named`Link to MQTT`. The directory has different scripts in it. We will start the`walkthrough.sh` script to learn how the MQTT protocol works. Let's run the`walkthrough.sh` script.


```shell-session
ubuntu@tryhackme:~$ cd Desktop/MQTTSIM/walkthrough/ 
ubuntu@tryhackme:~/Desktop/MQTTSIM/walkthrough$ ./walkthrough.sh 
Starting MQTT broker in Docker...
Starting the HVAC controller script...
All processes started.
ubuntu@tryhackme:~/MQTTSIM$
```

Once we run it, three windows will pop up. The window with the red text is the MQTT broker, the one with the blue text is the MQTT client, and the third is the application UI we might see as the end user. We can look at the logs on each of these windows if we like, but as an end user, we will only interact with the application UI.

![Heater control interface](https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/5f04259cf9bf5b57aed2c476-1731497886233.png) 

Currently, the application is in automatic mode, the heater is off, the target temperature is 22 degrees, and the current temperature is 22.3 degrees. Let's head over to Wireshark to see what kind of communication we can see. The below screenshot shows how the communication started.

![Wireshark displaying MQTT traffic](https://tryhackme-images.s3.amazonaws.com/user-uploads/61306d87a330ed00419e22e7/room-content/61306d87a330ed00419e22e7-1729328816053.png)

**Note:** If you do not see any traffic in Wireshark. Close all windows and restart your steps.

The first two events show the connection establishment, showing the`Connect Command` and`Connect Ack` text in the info. The next two events show that one of the clients wants to subscribe to the`home/temperature` topic, shown in the square brackets. This must be the HVAC controller, which needs to know the temperature to turn the heater on or off. Below, we can see the messages published by different clients, with their topics in the square brackets. The events from the`home/temperature` topic are from the temperature sensor, and the events from the`home/heater` are published by the HVAC controller. The screenshot below shows the details of the`home/temperature` topic message.

![Wireshark displaying an MQTT packet with a topic and a message being the home temperature and its value](https://tryhackme-images.s3.amazonaws.com/user-uploads/61306d87a330ed00419e22e7/room-content/61306d87a330ed00419e22e7-1729330687305.png)

In the lower pane, we can see that it is publishing a temperature of -9.6877475608946. That is very cold. Therefore, we see a message from the heater right after the temperature is broadcast. This message shows that the heater was turned on, as seen in the highlighted part in the lower pane.

![Wireshark displaying an MQTT packet with a topic and a message being the home heater and its state](https://tryhackme-images.s3.amazonaws.com/user-uploads/61306d87a330ed00419e22e7/room-content/61306d87a330ed00419e22e7-1729330687304.png)

The illustration below shows the overall communication between the heater controller and the temperature sensor, as we have deduced from Wireshark communication.

![Communication between the temperature sensor and the MQTT broker and between the MQTT broker and the heater controller](https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/5f04259cf9bf5b57aed2c476-1732161673647.png) 

Before proceeding to the challenge, quit all the HVAC controller scripts. Use **CTRL+C** for the window with the red text. It is time to use our knowledge to fix things.

## Challenge

Great! Now we understand how the MQTT publish/subscribe model works with a broker. McSkidy can use our help; the lights have gone off in all the major factories and halls. Mayor Malware has sabotaged the lighting system implemented by a contractor company. Their support will take some time to respond, as it is the holiday season. But McSkidy needs to get the lights back on now!

To see what Mayor Malware has done, we can run the script`challenge.sh` as shown below. This will open three windows, including the lights controller interface.

```shell-session
ubuntu@tryhackme:~/Desktop/MQTTSIM/walkthrough$ cd ~/Desktop/MQTTSIM/challenge/
ubuntu@tryhackme:~/Desktop/MQTTSIM/challenge$ ./challenge.sh
[...]
```

We can see the lights controller interface; however, nothing works, and there is no way to turn the lights back on.

![Lights controller interface](https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/5f04259cf9bf5b57aed2c476-1730312441669.png) 

Now that we have basic knowledge of the MQTT protocol, we must find the command to turn the lights back on. The`challenge.pcapng` file is inside the`challenge` directory. This packet capture file contains various MQTT protocol messages related to turning the lights œon and œoff. Start Wireshark then go to the **File** menu, choose **Open**, locate the`challenge.pcapng` file, and open it in Wireshark to take a closer look. 

You plan to publish a message to the MQTT broker in order to turn on the lights. As a result, all the lighting devices subscribed to this MQTT broker will turn their lights on. You can achieve this from the command line using the`mosquitto_pub` command. Consider the following example:

`mosquitto_pub -h localhost -t "some_topic" -m "message"`

We are publishing a message under a specific topic to a broker.

```ad-summary
- `mosquitto_pub` is the command-line utility to publish an MQTT message
- `-h localhost` refers to the MQTT broker, which is`localhost` in this task
- `-t "some_topic"` specifies the **topic**
- `-m "message"` sets the **message**, such as`"on"` and`"off"`
```

To determine the correct topic and message to turn on the lights, you must study the captured packets in`challenge.pcapng`. Once you figure it out, ensure you are running`challenge.sh` and use`mosquitto_pub` to publish a message to turn on the lights. Once you successfully manage to turn on the lights, a flag will appear on the lights controller interface.


## Question
---

![Pasted image 20241224125832.png](../../IMAGES/Pasted%20image%2020241224125832.png)


So, after checking the `challenge.pcapng` file, we see this is the topic:


![Pasted image 20241224132226.png](../../IMAGES/Pasted%20image%2020241224132226.png)


So, we must send the following message:

`mosquitto_pub -h localhost -t "d2FyZXZpbGxl/Y2hyaXN0bWFzbGlnaHRz" -m "on"`


This will lead to our flag:

![Pasted image 20241224132249.png](../../IMAGES/Pasted%20image%2020241224132249.png)

So, flag is: `THM{Ligh75on-day54ved}`


Just like that, day 24 and the event is done!


I truly enjoyed the event, sad that it is over, GG!


![Pasted image 20241224132417.png](../../IMAGES/Pasted%20image%2020241224132417.png)


![Pasted image 20241224143559.png](../../IMAGES/Pasted%20image%2020241224143559.png)


