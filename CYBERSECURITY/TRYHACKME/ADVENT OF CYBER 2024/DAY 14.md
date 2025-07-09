![Task banner for day 14](https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/5f04259cf9bf5b57aed2c476-1731812568781.svg)

_â€œItâ€™s the Mayorâ€ said the Glitch, he said it while sighing,_

_â€œThe people of Wareville, their browsing heâ€™s spying!â€_

_â€œThat sounds like himâ€, McSkidy then said,_

_â€œBack to work thenâ€, while scratching her head._

 

Itâ€™s a quiet morning in the town of Wareville. A wholesome town where cheer and tech come together. McSkidy is charged to protect the GiftScheduler, the service elves use to schedule all the presents to be delivered in Wareville. She assigned Glitch to the case to make sure the site is secure for G-Day (Gift Day). In the meantime, Mayor Malware works tirelessly, hoping to not only ruin Christmas by redirecting presents to the wrong addresses but also to ensure that Glitch is blamed for the attack. After all, Glitchâ€™s warnings about the same vulnerabilities Mayor Malware is exploiting make the hacker an easy scapegoat.

This is the continuation of [day 13](DAY%2013.md)
## Learning Objectives
---

In today's task you will learn about:

```ad-summary
- Self-signed certificates
- Man-in-the-middle attacks
- Using Burp Suite proxy to intercept traffic
```

## Certified to Sleigh
---

We hear a lot about certificates and their uses, but letâ€™s start dissecting what a certificate is:

```ad-info
- **Public key**: At its core, a certificate contains a public key, part of a pair of cryptographic keys: a public key and a private key. The public key is made available to anyone and is used to encrypt data.
- **Private key**: The private key remains secret and is used by the website or server to decrypt the data.
- **Metadata**: Along with the key, it includes metadata that provides additional information about the certificate holder (the website) and the certificate. You usually find information about the Certificate Authority (CA), subject (information about the website, e.g. www.meow.thm), a uniquely identifiable number, validity period, signature, and hashing algorithm.
```

## Sign Here, Trust Me
----

So what is a Certificate Authority (CA)?

A CA is a trusted entity that issues certificates; for example, GlobalSign, Letâ€™s Encrypt, and DigiCert are very common ones. The browser trusts these entities and performs a series of checks to ensure it is a trusted CA. Here is a breakdown of what happens with a certificate:

```ad-summary
- **Handshake**: Your browser requests a secure connection, and the website responds by sending a certificate, but in this case, it only requires the public key and metadata.
- **Verification:** Your browser checks the certificate for its validity by checking if it was issued by a trusted CA. If the certificate hasnâ€™t expired or been tampered with, and the CA is trusted, then the browser gives the green light. There are different types of checks you can do; check them [here](https://www.sectigo.com/resource-library/dv-ov-ev-ssl-certificates).
- **Key exchange**: The browser uses the public key to encrypt a session key, which encrypts all communications between the browser and the website.
- **Decryption**: The website (server) uses its private key to decrypt the session key, which is [symmetric](https://deviceauthority.com/symmetric-encryption-vs-asymmetric-encryption/). Now that both the browser and the website share a secret key (session key), we have established a secure and encrypted communication!
```


Ever wonder what makes HTTPS be S (secure)? Thanks to certificates, we can now have authentication, encryption, and data integrity.

**Self-Signed Certificates vs. Trusted CA Certificates**

The process of acquiring a certificate with a CA is long, you create the certificate, and send it to a CA to sign it for you. If you donâ€™t have tools and automation in place, this process can take weeks. Self-signed certificates are signed by an entity usually the same one that authenticates. For example, Wareville owns the GiftScheduler site, and if they create a certificate and sign it with Wareville as a CA, that becomes a self-signed certificate.

```ad-note
- **Browsers** generally do not trust self-signed certificates because there is no third-party verification. The browser has no way of knowing if the certificate is authentic or if itâ€™s being used for malicious purposes (like a **man-in-the-middle attack**).
- **Trusted CA certificates**, on the other hand, are verified by a CA, which acts as a trusted third party to confirm the websiteâ€™s identity.
```

CA-issued certificates sometimes take a long time; if you want to test a development environment, it can make sense to use self-signed certificates. Ideally, this is an internal, air-gapped environment with no connection to the public Internet. Otherwise, it defeats the purpose of a certificate: the entire system of secure communication relies on the fact that both parties (the browser and the server) can trust the data being exchanged and that no one in the middle can intercept or modify it without detection.

## How Mayor Malware Disrupts G-Day
----
There are less than two weeks until G-Day, and Mayor Malware has been planning its disruption ever since Glitch raised the self-signed certificate vulnerability to McSkidy during a security briefing the other day.

His plan is near perfect. He will hack into the Gift Scheduler and mess with the delivery schedule. No one will receive the gift destined for them: G-Day will be ruined! [_evil laugh_]

**Preparation**

First things first: the Glitch spoke about a self-signed certificate, but Mayor Malware canâ€™t believe that the townspeopleâ€”usually so security-savvy itâ€™s maddening to himâ€”would easily disregard such a critical vulnerability. Is it a trap set up by the Glitch and McSkidy to catch him red-handed? He definitely needs to check for himself.

Before that, though, he wants to make sure that his tracks are well covered. To prevent any DNS logs from alerting his enemies, he will resolve the Gift Schedulerâ€™s FQDN locally on his machine.

To achieve this, letâ€™s add the following line to the`/etc/hosts`
file on the AttackBox:`10.10.125.63 gift-scheduler.thm`

When we click on the`View Certificate` link marked with a 1 in the screenshot above, a new tab opens with the certificate details.

Mayor Malware canâ€™t believe his luck! This is evidence that the Glitch was speaking the truth: the Gift Scheduler web server uses a self-signed certificate.

This means that the townspeople and all the elves will be used to clicking on the`Accept the Risk and Continue` button (marked with 2 on the screenshot above) to access the website, to the point itâ€™s become a habit.

Mayor Malware does just that and inserts his credentials into the login form.

![THM Key Credentials](https://tryhackme-images.s3.amazonaws.com/user-uploads/63588b5ef586912c7d03c4f0/room-content/be629720b11a294819516c1d4e738c92.png)

| | |
| ------------ | ------------- |
| **Username** | mayor_malware |
| **Password** | G4rbag3Day |

With his credentials, he canâ€™t do anything but send a gift requestâ€”as if he were to ever do such a sickeningly sweet gesture. To carry out his evil plan, he will need to sniff some admin credentials. Maybe some of the elvesâ€™ passwords. Or evenâ€”if he gets luckyâ€”Marta May Wareâ€™s account!

![The 'Schedule your gift' form page](https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/5f04259cf9bf5b57aed2c476-1732081963676.png)

To sniff the elvesâ€™ traffic, the next step will be to start a proxy on his machine and route all of Warevilleâ€™s traffic to it. This way, the **Mayor** will be **In The Middle** between the townspeople and the Gift Scheduler. This position will allow him to sniff all requests forwarded to the sickening website.

Letâ€™s start the Burp Suite proxy by typing`burp` in the terminal. A new window will open. We can accept the default configuration by clicking on`Next`, then`Start Burp` in the next window.


Mayor Malware rubs his hands together gleefully: as we can read in the yellow box in the screenshot above, Burp Suite already comes with a self-signed certificate. The users will be prompted to accept it and continue, and Mayor Malware knows they will do it out of habit, without even thinking of verifying the certificate origin first. The G-Day disruption operation will go off without a hitch!

**Sniff From The Middle**

Now that our machine is ready to listen, we must reroute all Wareville traffic to our machine.

Mayor Malware has a wonderful idea to achieve this: he will set his own machine as a gateway for all other Warevilleâ€™s machines!

Letâ€™s add another line to the AttackBoxâ€™s`/etc/hosts` file. **Note:** The`CONNECTION_IP` address in the snippet should reflect the IP of our AttackBox, which can be found at the top of the page.


```shell-session
root@attackbox:~# echo "CONNECTION_IP wareville-gw" >> /etc/hosts
```


This will divert all of Warevilleâ€™s traffic, usually routed through the legitimate Wareville Gateway, to Mayor Malwareâ€™s machine, effectively putting him â€œIn The Middleâ€ of the requests. **Note:** In practice, the adversary can launch a similar attack if they can control the userâ€™s gateway and their attack can easily succeed against websites not using properly signed certificates. This attack requires more than adding an entry into the`/etc/hosts` file; however, this task aims to emulate parts of the attack.

As a last step, we must start a custom script to simulate the usersâ€™ requests to the Gift Scheduler. **Note:** Keep the script running so that new user requests will constantly be captured in Burp Suite.



```shell-session
root@attackbox:~# cd ~/Rooms/AoC2024/Day14
root@attackbox:~/Rooms/AoC2024/Day14# ./route-elf-traffic.sh 
Verifying archive integrity... 100% MD5 checksums are OK. All good.
Uncompressing Intercept Traffic 100% 
Intercepting user traffic in progress...
 User request intercepted successfully at 2024-12-11 16:05:56
 User request intercepted successfully at 2024-12-11 16:06:23
 User request intercepted successfully at 2024-12-11 16:06:36
[...]
```


![Pasted image 20241214142204.png](../../IMAGES/Pasted%20image%2020241214142204.png)


**Pwn the Scheduler**

At last, everything is in place. Mayor Malwareâ€™s evil plan can finally commence! [_evil laugh_]

We can return to the open Burp Suite window and click on the`HTTP History` tab.

![HTTP history with some requests, one GET open.](https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/5f04259cf9bf5b57aed2c476-1732085268640.png)

There is a triumphant gleam in Mayor Malwareâ€™s eyes while he stares intently at the web requests pouring on his screen. He can finally see them: the POST requests containing clear-text credentials for the Gift Scheduler website! Now, he only needs to wait and find the password to a privileged account.


## Questions
---

![Pasted image 20241214142258.png](../../IMAGES/Pasted%20image%2020241214142258.png)

### 1
---

![Pasted image 20241214142344.png](../../IMAGES/Pasted%20image%2020241214142344.png)

The name of the CA is `THM`


### 2
---

![Pasted image 20241214142955.png](../../IMAGES/Pasted%20image%2020241214142955.png)

Password for user `snowballelf` is `c4rrotn0s3`


### 3
---

I used the following credentials: `sugarplumelf`:`xm4sc4ndy`, when I logged in, this was the flag that showed up:

![Pasted image 20241214142926.png](../../IMAGES/Pasted%20image%2020241214142926.png)

Flag: `THM{AoC-3lf0nth3Sh3lf}`
### 4
---

![Pasted image 20241214142543.png](../../IMAGES/Pasted%20image%2020241214142543.png)

`Marta_mayware`'s password is: `H0llyJ0llySOCMAS!`


### 5
---

![Pasted image 20241214142743.png](../../IMAGES/Pasted%20image%2020241214142743.png)

After logging into `marta_mayware` account, we get that the flag is: `THM{AoC-h0wt0ru1nG1ftD4y}`



Just like that, day 14 is done!


