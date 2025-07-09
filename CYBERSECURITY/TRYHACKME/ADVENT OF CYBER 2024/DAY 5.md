![Task banner for day 5.](https://tryhackme-images.s3.amazonaws.com/user-uploads/5dbea226085ab6182a2ee0f7/room-content/5dbea226085ab6182a2ee0f7-1730807266344.png)

The days in Wareville flew by, and Software's projects were nearly complete, just in time for Christmas. One evening, after wrapping up work, Software was strolling through the town when he came across a young boy looking dejected. Curious, Software asked, "What would you like for Christmas?" The boy replied with a sigh, "I wish for a teddy bear, but I know that my family can't afford one."

This brief conversation sparked an idea in Software's mindâ€”what if there was a platform where everyone in town could share their Christmas wishes, and the Mayor's office could help make them come true? Excited by the potential, Software introduced the idea to Mayor Malware, who embraced it immediately. The Mayor encouraged the team to build the platform for the people of Wareville.

Through the developers' dedication and effort, the platform was soon ready and became an instant hit. The townspeople loved it! However, in their rush to meet the holiday deadline, the team had overlooked something criticalâ€”thorough security testing. Even Mayor Malware had chipped in to help develop a feature in the final hours. Now, it's up to you to ensure the application is secure and free of vulnerabilities. Can you guarantee the platform runs safely for the people of Wareville?

This is the continuation of [day 4](DAY%204.md)
## Learning Objectives
---


```ad-summary
- Understand the basic concepts related to XML
- Explore XML External Entity (XXE) and its components
- Learn how to exploit the vulnerability
- Understand remediation measures
```

![Pasted image 20241205130237.png](../../IMAGES/Pasted%20image%2020241205130237.png)

## Important Concepts
--- 
### **Extensible Markup Language (XML)**
---
XMLÂ is a commonly used method to transport and store data in a structured format that humans and machines can easily understand. Consider a scenario where two computers need to communicate and share data. Both devices need to agree on a common format for exchanging information. This agreement (format) is known asÂ `XML`. You can think ofÂ XMLÂ as a digital filing cabinet. Just as a filing cabinet has folders with labelled documents inside,Â XMLÂ usesÂ `tags`Â to label and organize information. These tags are like folders that define the type of data stored. This is what anÂ XMLÂ looks like, a simple piece of text information organized in a structured manner:Â 

```javascript
<people>
   <name>Glitch</name>
   <address>Wareville</address>
   <email>glitch@wareville.com</email>
   <phone>111000</phone>
</people>
```

In this case, the tagsÂ `<people>,Â <name>, <address>`, etc are like folders in a filing cabinet, but now they store data about Glitch. The content inside the tags, like "`Glitch`," "`Wareville`," and "`123-4567`" represents the actual data being stored. Like before, the key benefit ofÂ XMLÂ is that it is easily shareable and customizable, allowing you to create your own tags.

### **Document Type Definition (DTD)**
---
Now that the two computers have agreed to share data in a common format, what about the structure of the format? Here is when the DTD comes into play. A DTD is a set ofÂ **rules**Â that defines the structure of anÂ XMLÂ document. Just like a database scheme, it acts like a blueprint, telling you what elements (tags) and attributes are allowed in theÂ XMLÂ file. Think of it as a guideline that ensures theÂ XMLÂ document follows a specific structure.

For example, if we want to ensure that anÂ XMLÂ document aboutÂ `people`Â will always include aÂ `name`,Â `address`,Â `email`, andÂ `phone number`, we would define those rules through a DTD as shown below:

```xml
<!DOCTYPE people [ 
<!ELEMENT people(name, address, email, phone)> 
<!ELEMENT name (#PCDATA)> 
<!ELEMENT address (#PCDATA)> 
<!ELEMENT email (#PCDATA)> 
<!ELEMENT phone (#PCDATA)> 
]>
```

In the above DTD,Â **<!ELEMENT>**Â  defines the elements (tags) that are allowed, like name, address, email, and phone, whereasÂ `#PCDATA`Â stands for parsedÂ `people`Â data, meaning it will consist of just plain text.


### **Entities**
---

So far, both computers have agreed on the format, the structure of data, and the type of data they will share. Entities inÂ XMLÂ are placeholders that allow the insertion of large chunks of data or referencing internal or external files. They assist in making theÂ XMLÂ file easy to manage, especially when the same data is repeated multiple times. Entities can be defined internally within theÂ XMLÂ document or externally, referencing data from an outside source.Â 

For example, an external entity references data from an external file or resource. In the following code, the entityÂ `&ext;`Â could refer to an external file located at "`http://tryhackme.com/robots.txt`", which would be loaded into theÂ XML, if allowed by the system:

```xml
<!DOCTYPE people [ 
<!ENTITY ext SYSTEM "http://tryhackme.com/robots.txt"> 
]> 
<people> 
<name>Glitch</name> 
<address>&ext;</address> 
<email>glitch@wareville.com</email> 
<phone>111000</phone> 
</people>
```

We are specifically discussing external entities because it is one of the main reasons thatÂ XXEÂ is introduced if it is not properly managed.

### **XML External Entity (XXE)**
---

After understanding XML and how entities work, we can now explore theÂ XXEÂ vulnerability.Â XXEÂ is an attack that takes advantage ofÂ **how**Â **XMLÂ parsers handle external entities**.Â When a web application processes anÂ XMLÂ file that contains an external entity, the parser attempts to load or execute whatever resource the entity points to. If necessary sanitization is not in place, the attacker may point the entity to any malicious source/code causing the undesired behavior of the web app.

For example, if a vulnerableÂ XMLÂ parser processes this external entity definition:


```xml
<!DOCTYPE people[ 
<!ENTITY thmFile SYSTEM "file:///etc/passwd"> 
]> 
<people> 
<name>Glitch</name> 
<address>&thmFile;</address> 
<email>glitch@wareville.com</email> 
<phone>111000</phone> 
</people>
```

Here, the entityÂ `&thmFile;`Â refers to the sensitive fileÂ `/etc/passwd`Â on a system. When theÂ XMLÂ is processed, the parser will try to load and display the contents of that file, exposing sensitive information to the attacker.  

In the upcoming tasks, we will examine howÂ XXEÂ works and how to exploit it.

## PracticalÂ 
---

Now that you understand the basic concepts related to XML andÂ XXE, we will analyze an application that allows users to view and add products to their carts and perform the checkout activity. You can access the Wareville application hosted onÂ `http://10.10.163.220`. This application allows users to request their Christmas wishes.

### **Flow of the Application**  
---

As a penetration tester, it is important to first analyze the flow of the application. First, the user will browse through the products and add items of interest to their wishlist atÂ `http://10.10.163.220/product.php`. Click on theÂ `Add to Wishlist`Â underÂ `Wareville's Jolly Cap`, as shown below:
![Pasted image 20241205131850.png](../../IMAGES/Pasted%20image%2020241205131850.png)

After adding products to the wishlist, click theÂ `Cart`Â button or visitÂ `http://10.10.163.220/cart.php`Â to see the products added to the cart. On theÂ `Cart`Â page, click theÂ `Proceed to Checkout`Â button to buy the items as shown below:

![Pasted image 20241205131902.png](../../IMAGES/Pasted%20image%2020241205131902.png)

Enter any name of your choice and address, and click onÂ `Complete Checkout`Â to place the wish. Once you complete the wish, you will be shown the messageÂ **"WishÂ successful. Your wish has been saved as Wish #21"**, as shown below:

![Pasted image 20241205131942.png](../../IMAGES/Pasted%20image%2020241205131942.png)

**Wish #21**Â indicates the wishes placed by a user on the website.Â Once you click onÂ **Wish #21**, you will see a forbidden page because the details are only accessible toÂ `admins`. But can we try to bypass this and access other people's wishes? This is what we will try to perform in this task.

![Error page when accessing the new wish page.](https://tryhackme-images.s3.amazonaws.com/user-uploads/5dbea226085ab6182a2ee0f7/room-content/5dbea226085ab6182a2ee0f7-1730813503096.png)

### **Intercepting the Request**  
----
Before discussing exploiting XXE on the web, let's learn how to intercept the request. First, we need to configure the environment so that, as a pentester, all web traffic from our browser is routed throughÂ Burp Suite. This allows us to see and manipulate the requests as we browse.

**What is Happening in the Backend?**

Now, when you visit the URL,Â `http://10.10.163.220/product.php`, and clickÂ `Add to Wishlist`, an AJAX call is made toÂ `wishlist.php`Â with the followingÂ XMLÂ as input.Â 

```javascript
<wishlist>
  <user_id>1</user_id>
     <item>
       <product_id>1</product_id>
     </item>
</wishlist>
```

![Pasted image 20241205132120.png](../../IMAGES/Pasted%20image%2020241205132120.png)

In the aboveÂ XML,Â **<product_id>**Â tag contains the ID of the product, which isÂ **1**Â in this case. Now, let's review theÂ `Add to Wishlist`Â request logged in Burp Suite'sÂ `HTTPÂ History`Â option under the proxy tab. As discussed above, the request containsÂ XMLÂ being forwarded as aÂ `POST`Â request, as shown below:

![View of the request sent to wishlist.php using Burp.](https://tryhackme-images.s3.amazonaws.com/user-uploads/62a7685ca6e7ce005d3f3afe/room-content/62a7685ca6e7ce005d3f3afe-1729006687410.png)  

ThisÂ `wishlist.php`Â accepts the request and parses the request using the following code:

```php
<?php
..
...
libxml_disable_entity_loader(false);
$wishlist = simplexml_load_string($xml_data, "SimpleXMLElement", LIBXML_NOENT);

...
..
echo "Item added to your wishlist successfully.";
?>
```

### **Preparing the Payload**
----
When a user sends specially craftedÂ XMLÂ data to the application, the lineÂ `libxml_disable_entity_loader(false)`Â allows theÂ XMLÂ parser to load external entities. This means theÂ XMLÂ input can include external file references or requests to remote servers. When theÂ XMLÂ is processed byÂ `simplexml_load_string`Â with theÂ `LIBXML_NOENT`Â option, the web app resolves external entities, allowing attackers access to sensitive files or allowing them to make unintended requests from the server.

What if we update theÂ XMLÂ request to include references for external entities? We will use the followingÂ XMLÂ instead of the aboveÂ XML:

```xml
<!--?xml version="1.0" ?-->
<!DOCTYPE foo [<!ENTITY payload SYSTEM "/etc/hosts"> ]>
<wishlist>
  <user_id>1</user_id>
     <item>
       <product_id>&payload;</product_id>
     </item>
</wishlist>
```



![Pasted image 20241205132404.png](../../IMAGES/Pasted%20image%2020241205132404.png)

After we send the request, this was the response:

![Pasted image 20241205132451.png](../../IMAGES/Pasted%20image%2020241205132451.png)

So, we were able to get the `/etc/hosts` of this server, making it vulnerable to XXE

## Time for Some Action
---
Now that you've identified a vulnerability in the application, it's time to see it in action! McSkidy Software has tasked us with finding loopholes, and we've successfully uncovered one in theÂ `wishlist.php`Â endpoint. But our work doesn't end thereâ€”let's take it a step further and assess the potential impact this vulnerability could have on the application.

Earlier, we discovered a page accessible only by administrators, which seems like an exciting target. What if we could use the vulnerability we've found to access sensitive information, like the wishes placed by the townspeople?

Now that our objective is clear, let's leverage the vulnerability we discovered to read the contents of each wishes page and demonstrate the full extent of this flaw to help McSkidy secure the platform. To get started, let's recall the page that is only accessible by admins -Â `/wishes/wish_1.txt`. Using this path, we just need to guess the potential absolute path of the file. Typically, web applications are hosted onÂ `/var/www/html`. With that in mind, let's build our new payload to read the wishes while leveraging the vulnerabilit

**Note: Not all web applications use the path /var/www/html, but web servers typically use it.**


```xml
<!--?xml version="1.0" ?-->
<!DOCTYPE foo [<!ENTITY payload SYSTEM "/var/www/html/wishes/wish_1.txt"> ]>
<wishlist>
	<user_id>1</user_id>
	<item>
	       <product_id>&payload;</product_id>
	</item>
</wishlist>
```

![Pasted image 20241205132645.png](../../IMAGES/Pasted%20image%2020241205132645.png)

The payload worked, we got lucky, let's see if we can uncover more files, let's try with `wish_2.txt`:

![Pasted image 20241205132730.png](../../IMAGES/Pasted%20image%2020241205132730.png)

As a result, we were able to view the next wish. You may observe that we just incremented the number by one. Given this, you may continue checking the other wishes and see all the wishes stored in the application.

After iterating through the wishes, we have proved the potential impact of the vulnerability, and anyone who leverages this could read the wishes submitted by the townspeople of Wareville.

## Conclusion
---
It was confirmed that the application was vulnerable, and the developers were not at fault since they only wanted to give the townspeople something before Christmas. However, it became evident that bypassing security testing led to an application that did not securely handle incoming requests.

As soon as the vulnerability was discovered, McSkidy promptly coordinated with the developers to implement the necessary mitigations. The following proactive approach helped to address the potential risks againstÂ XXEÂ attacks:

```ad-bug
- **Disable External Entity Loading**: The primary fix is to disable external entity loading in your XML parser. InÂ PHP, for example, you can preventÂ XXEÂ by settingÂ `libxml_disable_entity_loader(true)`Â before processing theÂ XML.
- **Validate and Sanitise User Input**: Always validate and sanitise theÂ XMLÂ input received from users. This ensures that only expected data is processed, reducing the risk of malicious content being included in the request. For example, remove suspicious keywords likeÂ `/etc/host`,Â `/etc/passwd`, etc, from the request.
```

After discovering the vulnerability, McSkidy immediately remembered that a CHANGELOG file exists within the web application, stored at the following endpoint:Â [http://10.10.163.220/CHANGELOG](http://10.10.163.220/CHANGELOG). AfterÂ checking, it can be seen that someone pushed the vulnerable code within the application after Software's team.

![Pasted image 20241205132850.png](../../IMAGES/Pasted%20image%2020241205132850.png)

We got a flag: `THM{m4y0r_m4lw4r3_b4ckd00rs}`

## Question
---

![Pasted image 20241205132919.png](../../IMAGES/Pasted%20image%2020241205132919.png)

Let's keep on navigating through the wishes to find the flag, for an easier navigation, we can send the request to intruder and change the payload like this:

![Pasted image 20241205133007.png](../../IMAGES/Pasted%20image%2020241205133007.png)

Just add a simple list to 21, since we suppose we made the last request and had ticket 21, once we send the attack we have to make sure to check the responses:

![Pasted image 20241205133249.png](../../IMAGES/Pasted%20image%2020241205133249.png)



Let's send the attack:


![Pasted image 20241205133352.png](../../IMAGES/Pasted%20image%2020241205133352.png)

Wish `15` was the one with the flag: `THM{Brut3f0rc1n6_mY_w4y}`

Just like that, day 5 is done!



