## Description

SSRF flaws occur whenever a web application is fetching a remote resource without validating the user-supplied URL. It allows an attacker to coerce the application to send a crafted request to an unexpected destination, even when protected by a firewall, VPN, or another type of network access control list (ACL).

As modern web applications provide end-users with convenient features, fetching a URL becomes a common scenario. As a result, the incidence of SSRF is increasing. Also, the severity of SSRF is becoming higher due to cloud services and the complexity of architectures.

## How to Prevent

Developers can prevent SSRF by implementing some or all the following defense in depth controls:

### **From Network layer**

- Segment remote resource access functionality in separate networks to reduce the impact of SSRF
 
- Enforce deny by default firewall policies or network access control rules to block all but essential intranet traffic. 
- 

 ```ad-info
Hints: 
 
 1. Establish an ownership and a lifecycle for firewall rules based on applications. 
 2. Log all accepted _and_ blocked network flows on firewalls (see [A09:2021-Security Logging and Monitoring Failures](https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/)).
```
 

### **From Application layer:**

- Sanitize and validate all client-supplied input data
 
- Enforce the URL schema, port, and destination with a positive allow list
 
- Do not send raw responses to clients
 
- Disable HTTP redirections
 
- Be aware of the URL consistency to avoid attacks such as DNS rebinding and time of check, time of use (TOCTOU) race conditions
 

Do not mitigate SSRF via the use of a deny list or regular expression. Attackers have payload lists, tools, and skills to bypass deny lists.

### **Additional Measures to consider:**

- Don't deploy other security relevant services on front systems (e.g. OpenID). Control local traffic on these systems (e.g. localhost)
 
- For frontends with dedicated and manageable user groups use network encryption (e.g. VPNs) on independent systems to consider very high protection needs
 

## Example Attack Scenarios

Attackers can use SSRF to attack systems protected behind web application firewalls, firewalls, or network ACLs, using scenarios such as:

**Scenario #1:** Port scan internal servers “ If the network architecture is unsegmented, attackers can map out internal networks and determine if ports are open or closed on internal servers from connection results or elapsed time to connect or reject SSRF payload connections.

**Scenario #2:** Sensitive data exposure “ Attackers can access local files or internal services to gain sensitive information such as`file:///etc/passwd` and`http://localhost:28017/`.

**Scenario #3:** Access metadata storage of cloud services “ Most cloud providers have metadata storage such as`http://169.254.169.254/`. An attacker can read the metadata to gain sensitive information.

**Scenario #4:** Compromise internal services “ The attacker can abuse internal services to conduct further attacks such as Remote Code Execution (RCE) or Denial of Service (DoS).

# POC

<iframe width="800" height="583" src="https://www.youtube.com/embed/Zyt7lUO3mY8" title="Server-Side Request Forgery (SSRF) Explained And Demonstrated" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" referrerpolicy="strict-origin-when-cross-origin" allowfullscreen></iframe>

# Portswigger

## What is SSRF?


Server-side request forgery is a web security vulnerability that allows an attacker to cause the server-side application to make requests to an unintended location.

In a typical SSRF attack, the attacker might cause the server to make a connection to internal-only services within the organization's infrastructure. In other cases, they may be able to force the server to connect to arbitrary external systems. This could leak sensitive data, such as authorization credentials. 

![Pasted image 20240919153000.png](../../../../IMAGES/Pasted%20image%2020240919153000.png) 

## SSRF attacks against the server

In an SSRF attack against the server, the attacker causes the application to make an HTTP request back to the server that is hosting the application, via its loopback network interface. This typically involves supplying a URL with a hostname like 127.0.0.1 (a reserved IP address that points to the loopback adapter) or localhost (a commonly used name for the same adapter).

For example, imagine a shopping application that lets the user view whether an item is in stock in a particular store. To provide the stock information, the application must query various back-end REST APIs. It does this by passing the URL to the relevant back-end API endpoint via a front-end HTTP request. When a user views the stock status for an item, their browser makes the following request:
```
POST /product/stock HTTP/1.0
Content-Type: application/x-www-form-urlencoded
Content-Length: 118

stockApi=http://stock.weliketoshop.net:8080/product/stock/check%3FproductId%3D6%26storeId%3D1
```
This causes the server to make a request to the specified URL, retrieve the stock status, and return this to the user.

In this example, an attacker can modify the request to specify a URL local to the server:
```
POST /product/stock HTTP/1.0
Content-Type: application/x-www-form-urlencoded
Content-Length: 118
stockApi=http://localhost/admin
```

The server fetches the contents of the /admin URL and returns it to the user.

An attacker can visit the /admin URL, but the administrative functionality is normally only accessible to authenticated users. This means an attacker won't see anything of interest. However, if the request to the /admin URL comes from the local machine, the normal access controls are bypassed. The application grants full access to the administrative functionality, because the request appears to originate from a trusted location.


SSRF attacks against the server - Continued

Why do applications behave in this way, and implicitly trust requests that come from the local machine? This can arise for various reasons:

*The access control check might be implemented in a different component that sits in front of the application server. When a connection is made back to the server, the check is bypassed.

*For disaster recovery purposes, the application might allow administrative access without logging in, to any user coming from the local machine. This provides a way for an administrator to recover the system if they lose their credentials. This assumes that only a fully trusted user would come directly from the server.
 
*The administrative interface might listen on a different port number to the main application, and might not be reachable directly by users.

These kind of trust relationships, where requests originating from the local machine are handled differently than ordinary requests, often make SSRF into a critical vulnerability.

### LAB
![Pasted image 20240919153543.png](../../../../IMAGES/Pasted%20image%2020240919153543.png)

For this lab, we need to go into a product, and check stock, once we've done that, we can capture the request using burp and modify the stockAPI into `/localhost/admin`

![Pasted image 20240919154556.png](../../../../IMAGES/Pasted%20image%2020240919154556.png)
Once we've done that, we can get a prior access to admin panel, if we try to delete carlos user, we'll fail, so, we need now to change the stockAPI to the url we get once we try to delete the user, being that: `/localhost/admin/delete?username=carlos`, and like that, we will finish the lab
![Pasted image 20240919154631.png](../../../../IMAGES/Pasted%20image%2020240919154631.png)
![Pasted image 20240919154917.png](../../../../IMAGES/Pasted%20image%2020240919154917.png)
![Pasted image 20240919154954.png](../../../../IMAGES/Pasted%20image%2020240919154954.png)

## SSRF attacks against other back-end systems

 In some cases, the application server is able to interact with back-end systems that are not directly reachable by users. These systems often have non-routable private IP addresses. The back-end systems are normally protected by the network topology, so they often have a weaker security posture. In many cases, internal back-end systems contain sensitive functionality that can be accessed without authentication by anyone who is able to interact with the systems.

In the previous example, imagine there is an administrative interface at the back-end URL https://192.168.0.68/admin. An attacker can submit the following request to exploit the SSRF vulnerability, and access the administrative interface:
```
POST /product/stock HTTP/1.0
Content-Type: application/x-www-form-urlencoded
Content-Length: 118

stockApi=http://192.168.0.68/admin
```

### LAB
![Pasted image 20240919155630.png](../../../../IMAGES/Pasted%20image%2020240919155630.png)

Send the request to intruder to brute force the ip:
![Pasted image 20240919155926.png](../../../../IMAGES/Pasted%20image%2020240919155926.png)
![Pasted image 20240919162207.png](../../../../IMAGES/Pasted%20image%2020240919162207.png)
So, the IP address is: 192.168.0.80, lets modify the request in burp to delete carlos username:
![Pasted image 20240919162331.png](../../../../IMAGES/Pasted%20image%2020240919162331.png)
![Pasted image 20240919162504.png](../../../../IMAGES/Pasted%20image%2020240919162504.png)

# TRYHACKME EXPLANATION


## SSRF EXAMPLES

![Pasted image 20241106093933.png](../../../../IMAGES/Pasted%20image%2020241106093933.png)

#### WITH A LITTLE BIT OF PATH TRAVERSAL

![Pasted image 20241106094005.png](../../../../IMAGES/Pasted%20image%2020241106094005.png)


#### MAKING USE OF &X=

![Pasted image 20241106094026.png](../../../../IMAGES/Pasted%20image%2020241106094026.png)

#### TAKEOVER
---
![Pasted image 20241106094119.png](../../../../IMAGES/Pasted%20image%2020241106094119.png)

### PRACTICAL EXAMPLE
---

![Pasted image 20241106094211.png](../../../../IMAGES/Pasted%20image%2020241106094211.png)

For this practical example, we need some sort of way to ignore the rest of the URL, for example, if we input this:

`server.website.thm/flag?id=9`

We get this request:

![Pasted image 20241106094312.png](../../../../IMAGES/Pasted%20image%2020241106094312.png)

So, in order to retrieve the data from the url, we need to ignore the rest of the url using our special character:

```ad-hint

##### USED

`&x=`

##### OUTPUT




```



## Finding an SSRF
---
Potential SSRF vulnerabilities can be spotted in web applications in many different ways. Here is an example of four common places to look:

**When a full URL is used in a parameter in the address bar:**

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5efe36fb68daf465530ca761/room-content/956e1914b116cbc9e564e3bb3d9ab50a.png) 

**A hidden field in a form:**

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5efe36fb68daf465530ca761/room-content/237696fc8e405d25d4fc7bbcc67919f0.png) 

**A partial URL such as just the hostname:**

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5efe36fb68daf465530ca761/room-content/f3c387849e91a4f15a7b59ff7324be75.png)

 

**Or perhaps only the path of the URL:**

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5efe36fb68daf465530ca761/room-content/3fd583950617f7a3713a107fcb4cfa49.png)

Some of these examples are easier to exploit than others, and this is where a lot of trial and error will be required to find a working payload.

If working with a blind SSRF where no output is reflected back to you, you'll need to use an external HTTP logging tool to monitor requests such as requestbin.com, your own HTTP server or Burp Suite's Collaborator client.

## Defeating Common SSRF Defenses
--- 
More security-savvy developers aware of the risks of SSRF vulnerabilities may implement checks in their applications to make sure the requested resource meets specific rules. There are usually two approaches to this, either a deny list or an allow list. 

#### **Deny List**
--- 
A Deny List is where all requests are accepted apart from resources specified in a list or matching a particular pattern. A Web Application may employ a deny list to protect sensitive endpoints, IP addresses or domains from being accessed by the public while still allowing access to other locations. A specific endpoint to restrict access is the localhost, which may contain server performance data or further sensitive information, so domain names such as localhost and 127.0.0.1 would appear on a deny list. Attackers can bypass a Deny List by using alternative localhost references such as 0, 0.0.0.0, 0000, 127.1, 127.*.*.*, 2130706433, 017700000001 or subdomains that have a DNS record which resolves to the IP Address 127.0.0.1 such as 127.0.0.1.nip.io.

 

Also, in a cloud environment, it would be beneficial to block access to the IP address 169.254.169.254, which contains metadata for the deployed cloud server, including possibly sensitive information. An attacker can bypass this by registering a subdomain on their own domain with a DNS record that points to the IP Address 169.254.169.254.

 

#### **Allow List**
--- 
An allow list is where all requests get denied unless they appear on a list or match a particular pattern, such as a rule that an URL used in a parameter must begin with **https://website.thm.** An attacker could quickly circumvent this rule by creating a subdomain on an attacker's domain name, such as https://website.thm.attackers-domain.thm. The application logic would now allow this input and let an attacker control the internal HTTP request.

 

#### **Open Redirect**
--- 
If the above bypasses do not work, there is one more trick up the attacker's sleeve, the open redirect. An open redirect is an endpoint on the server where the website visitor gets automatically redirected to another website address. Take, for example, the link https://website.thm/link?url=https://tryhackme.com. This endpoint was created to record the number of times visitors have clicked on this link for advertising/marketing purposes. But imagine there was a potential SSRF vulnerability with stringent rules which only allowed URLs beginning with https://website.thm/. An attacker could utilize the above feature to redirect the internal HTTP request to a domain of the attacker's choice.

![Pasted image 20241106095157.png](../../../../IMAGES/Pasted%20image%2020241106095157.png)


## SSRF PRACTICAL


Let's put what we've learnt about SSRF to the test in a fictional scenario. 

 

We've come across two new endpoints during a content discovery exercise against the **Acme IT Support** website. The first one is **/private**, which gives us an error message explaining that the contents cannot be viewed from our IP address. The second is a new version of the customer account page at **/customers/new-account-page** with a new feature allowing customers to choose an avatar for their account.

 

Begin by clicking the **Start Machine** button to launch the **Acme IT Support** website. Once running, visit it at the URL [https://LAB_WEB_URL.p.thmlabs.com](https://lab_web_url.p.thmlabs.com/) and then follow the below instructions to get the flag.

 

First, create a customer account and sign in. Once you've signed in, visit [https://LAB_WEB_URL.p.thmlabs.com/customers/new-account-page](https://lab_web_url.p.thmlabs.com/customers/new-account-page) to view the new avatar selection feature. By viewing the page source of the avatar form, you'll see the avatar form field value contains the path to the image. The background-image style can confirm this in the above DIV element as per the screenshot below:

 
![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5efe36fb68daf465530ca761/room-content/bd9ee9ac0b7592b5343cbc8dd9b57189.png)

 

If you choose one of the avatars and then click the **Update Avatar** button, you'll see the form change and, above it, display your currently selected avatar.

 

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5c549500924ec576f953d9fc/room-content/8685bf7a4b24616031425a7f5e8db1ae.png) 

 

Viewing the page source will show your current avatar is displayed using the data URI scheme, and the image content is base64 encoded as per the screenshot below. 

 

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5efe36fb68daf465530ca761/room-content/fff0ea113602635dcf5d1e8d0b1d8bca.png) 

 

Now let's try making the request again but changing the avatar value to **private** in hopes that the server will access the resource and get past the IP address block. To do this, firstly, right-click on one of the radio buttons on the avatar form and select **Inspect**:

 

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5efe36fb68daf465530ca761/room-content/2ef87608418e47625bedad9d0361ed08.png) 

 

**And then edit the value of the radio button to private:**

 

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5efe36fb68daf465530ca761/room-content/a1712298679cc642d792d935b14effe5.png) 

Be sure to select the avatar you edited and then click the **Update Avatar** button. Unfortunately, it looks like the web application has a deny list in place and has blocked access to the /private endpoint.

 

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5efe36fb68daf465530ca761/room-content/a59460cc19eaf5776ee8a882e25b2d64.png)

 

As you can see from the error message, the path cannot start with /private but don't worry, we've still got a trick up our sleeve to bypass this rule. We can use a directory traversal trick to reach our desired endpoint. Try setting the avatar value to **x/../private**

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5efe36fb68daf465530ca761/room-content/84b88d9c6fa6a29450520625bb42870d.png)

You'll see we have now bypassed the rule, and the user updated the avatar. This trick works because when the web server receives the request for **x/../private**, it knows that the **../** string means to move up a directory that now translates the request to just **/private**.

 

Viewing the page source of the avatar form, you'll see the currently set avatar now contains the contents from the **/private** directory in base64 encoding, decode this content and it will reveal a flag that you can enter below.


### STEP TO STEP
---

#### CREATING THE ACCOUNT

![Pasted image 20241106095947.png](../../../../IMAGES/Pasted%20image%2020241106095947.png)

#### GOING TO `/customers/new-account-page`


![Pasted image 20241106100041.png](../../../../IMAGES/Pasted%20image%2020241106100041.png)

#### CHANGING VALUE TO PRIVATE

If we change value to `private` only, we will be unable to read the contents of it, let's bypass it using 

					`x/../private`



![Pasted image 20241106100642.png](../../../../IMAGES/Pasted%20image%2020241106100642.png)

Nice, let's update the avatar and see the page source:


![Pasted image 20241106100711.png](../../../../IMAGES/Pasted%20image%2020241106100711.png)

We got a `base64` we need to decode, let's use [cyberchef](https://gchq.github.io/CyberChef/):

![Pasted image 20241106100748.png](../../../../IMAGES/Pasted%20image%2020241106100748.png)

And just like that, we exploited the SSRF vulnerability

