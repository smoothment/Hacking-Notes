
# Introduction
---


Within this room, we will look at [OWASP's TOP 10 vulnerabilities](https://owasp.org/www-project-top-ten/) in web applications. You will find these in all types of web applications. But for today we will be looking at OWASP's own creation, Juice Shop! 

![](https://i.imgur.com/vjfcwid.png) 

The **FREE** Burpsuite rooms '[Burpsuite Basics](https://tryhackme.com/room/burpsuitebasics)' and '[Burpsuite Repeater](https://tryhackme.com/room/burpsuiterepeater)' are recommended before completing this room! 


Juice Shop is a large application so we will not be covering every topic from the top 10. 

We will, however, cover the following topics which we recommend you take a look at as you progress through this room.

<------------------------------------------------->

[Injection](https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A1-Injection)

[Broken Authentication](https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A2-Broken_Authentication)

[Sensitive Data Exposure](https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A3-Sensitive_Data_Exposure)

[Broken Access Control](https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A5-Broken_Access_Control)

[Cross-Site Scripting XSS](https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A7-Cross-Site_Scripting_(XSS))

<------------------------------------------------->

**PLEASE NOTE!** 

**[Task 3] and onwards will require a flag, which will be displayed on completion of the task.**

![](https://i.imgur.com/t4KAlh2.png)

**Troubleshooting**

The web app takes about 2-5 minutes to load, so please be patient! 

Temporarily disable burp in your proxy settings for the current browser. Refresh the page and the flag will be shown. _(This is not an issue with the application but an issue with burp stopping the flag from being shown._ ) 

If you are doing the XSS Tasks and they are not working. Clear your cookies and site data, as this can sometimes be an issue. If you are sure that you have completed the task but it's still not working. Go to **[Task 8]**, as this will allow you to check its completion.

# Let's go on an adventure!
---
 ![](https://i.imgur.com/7R1O1CF.png) 

Before we get into the actual hacking part, it's good to have a look around. In Burp, set the Intercept mode to off and then browse around the site. This allows Burp to log different requests from the server that may be helpful later. This is called **walking through** the application, which is also a form of **reconnaissance**!

Answer the questions below

### Question #1: What's the Administrator's email address?
---
![](https://i.imgur.com/hPXolAn.png)

The reviews show each user's email address. Which, by clicking on the Apple Juice product, shows us the Admin email!

![](https://i.imgur.com/YFWDP5v.png)

### **Question #2: What parameter is used for searching?** ---
![](https://i.imgur.com/pZLtWQl.png)

Click on the magnifying glass in the top right of the application will pop out a search bar.

![](https://i.imgur.com/bFgw6uS.png)

We can then input some text and by pressing **Enter** will search for the text which was just inputted.

Now pay attention to the URL which will now update with the text we just entered.

![](https://i.imgur.com/AzJ3FAM.png)

We can now see the search parameter after the **/#/search?** the letter **q**

Question #3: What show does Jim reference in his review? Jim did a review on the Green Smoothie product. We can see that he mentions a replicator. ![](https://i.imgur.com/RCFw2tB.png)

If we google "**replicator**" we will get the results indicating that it is from a TV show called Star Trek

![](https://i.imgur.com/Sp8ymGR.png)

# Inject the juice
----
![](https://i.imgur.com/uwXqDdH.png) 

This task will be focusing on injection vulnerabilities. Injection vulnerabilities are quite dangerous to a company as they can potentially cause downtime and/or loss of data. Identifying injection points within a web application is usually quite simple, as most of them will return an error. There are many types of injection attacks, some of them are:

| | |
|---|---|
|SQL Injection|SQL Injection is when an attacker enters a malicious or malformed query to either retrieve or tamper data from a database. And in some cases, log into accounts.|
|Command Injection|Command Injection is when web applications take input or user-controlled data and run them as system commands. An attacker may tamper with this data to execute their own system commands. This can be seen in applications that perform misconfigured ping tests.|
|Email Injection|Email injection is a security vulnerability that allows malicious users to send email messages without prior authorization by the email server. These occur when the attacker adds extra data to fields, which are not interpreted by the server correctly.|

 

But in our case, we will be using **SQL Injection**.

For more information: [Injection](https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A1-Injection)

Answer the questions below

### Question #1: Log into the administrator account! 
---
After we navigate to the login page, enter some data into the email and password fields.

![](https://i.imgur.com/4XHHSof.png)

 Before clicking submit, make sure Intercept mode is on.

This will allow us to see the data been sent to the server!

 

![](https://i.imgur.com/6gyZ7Vr.png) 

 

We will now change the "**a**" next to the email to: ' or 1=1-- and forward it to the server.

![](https://i.imgur.com/tPFJnmC.png)

**Why does this work?**

1. The character **'** will close the brackets in the SQL query
2. '**OR**' in a SQL statement will return true if either side of it is true. As 1=1 is always true, the whole statement is true. Thus it will tell the server that the email is valid, and log us into user id 0, which happens to be the administrator account.
3. The -- character is used in SQL to comment out data, any restrictions on the login will no longer work as they are interpreted as a comment. This is like the # and // comment in python and javascript respectively.

 


![Pasted image 20241124135522.png](../../IMAGES/Pasted%20image%2020241124135522.png)

# Who broke my lock?!
----

In this task, we will look at exploiting authentication through different flaws. When talking about flaws within authentication, we include mechanisms that are vulnerable to manipulation. These mechanisms, listed below, are what we will be exploiting. Weak passwords in high privileged accounts

Forgotten password pages

 More information: [Broken Authentication](https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A2-Broken_Authentication)


### Question #1: Bruteforce the Administrator account's password! 
----
We have used SQL Injection to log into the Administrator account but we still don't know the password. Let's try a brute-force attack! We will once again capture a login request, but instead of sending it through the proxy, we will send it to Intruder.

Go to Positions and then select the Clear § button. In the password field place two § inside the quotes. To clarify, the § § is not two sperate inputs but rather Burp's implementation of quotations e.g. "". The request should look like the image below. ![](https://i.imgur.com/I96sO28.png) 

For the payload, we will be using the best1050.txt from Seclists. 

Once the file is loaded into Burp, start the attack. You will want to filter for the request by status.

A failed request will receive a 401 Unauthorized ![](https://i.imgur.com/HcUs6eW.png)

Whereas a successful request will return a 200 OK. ![](https://i.imgur.com/q5jcfIA.png)

![Pasted image 20241125141419.png](../../IMAGES/Pasted%20image%2020241125141419.png)

So, password is `admin123`

### Question #2: Reset Jim's password!
---

Believe it or not, the reset password mechanism can also be exploited! When inputted into the email field in the Forgot Password page, Jim's security question is set to _"Your eldest siblings middle name?"_.

 

In Task 2, we found that Jim might have something to do with Star Trek. Googling "Jim Star Trek" gives us a wiki page for Jame T. Kirk from Star Trek. Looking through the wiki page we find that he has a brother.

![](https://i.imgur.com/PfHXA1h.png)

 

Looks like his brother's middle name is **Samuel**

Inputting that into the Forgot Password page allows you to successfully change his password.

You can change it to anything you want!

 

![](https://i.imgur.com/uRS3kJr.png)
# AH! Don't look!
---

 A web application should store and transmit sensitive data safely and securely. But in some cases, the developer may not correctly protect their sensitive data, making it vulnerable.

Most of the time, data protection is not applied consistently across the web application making certain pages accessible to the public. Other times information is leaked to the public without the knowledge of the developer, making the web application vulnerable to an attack. More information: [Sensitive Data Exposure](https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A3-Sensitive_Data_Exposure)

Answer the questions below

### Question #1: Access the Confidential Document! 
---
 

![](https://i.imgur.com/M1s8jfu.png)

Navigate to the About Us page, and hover over the _"Check out our terms of use"_.

 

![](https://i.imgur.com/5PsmlD4.png)

 

You will see that it links to [http://10.10.22.244](http://machine_ip/ftp/legal.md)[/ftp/legal.md](http://machine_ip/ftp/legal.md). Navigating to that **/ftp/** directory reveals that it is exposed to the public!

![](https://i.imgur.com/EY664PR.png) 

![](https://i.imgur.com/Xp2aZJW.png) 

We will download the acquisitions.md and save it. It looks like there are other files of interest here as well.

After downloading it, navigate to the **home page** to receive the flag!

### Question #2: Log into MC SafeSearch's account! 
----
 After watching the video there are certain parts of the song that stand out.

He notes that his password is "Mr. Noodles" but he has replaced some "vowels into zeros", meaning that he just replaced the o's into 0's.

We now know the password to the`mc.safesearch@juice-sh.op` account is "`Mr. N00dles`"


### Question #3: Download the Backup file! 
---
We will now go back to the [http://10.10.22.244](http://machine_ip/ftp/)[/ftp/](http://machine_ip/ftp/) folder and try to download`package.json.bak`. But it seems we are met with a 403 which says that only .md and .pdf files can be downloaded. ![](https://i.imgur.com/LDUkDBQ.png) 

To get around this, we will use a character bypass called "Poison Null Byte". A Poison Null Byte looks like this: _%00_.```ad-note
Note: as we can download it using the URL, we will need to encode this into a URL encoded format.
```

The Poison Null Byte will now look like this: _%2500._ Adding this and then a **.md** to the end will bypass the 403 error!

![](https://i.imgur.com/2qugsl5.png)

**Why does this work?** A Poison Null Byte is actually a NULL terminator. By placing a NULL character in the string at a certain byte, the string will tell the server to terminate at that point, nulling the rest of the string.

# Who's flying this thing?
---

![](https://i.imgur.com/r2qq6de.png)

Modern-day systems will allow for multiple users to have access to different pages. Administrators most commonly use an administration page to edit, add and remove different elements of a website. You might use these when you are building a website with programs such as Weebly or Wix. When Broken Access Control exploits or bugs are found, it will be categorized into one of **two types**


| | |
|---|---|
|**Horizontal** Privilege Escalation|Occurs when a user can perform an action or access data of another user with the **same** level of permissions.|
|**Vertical** Privilege Escalation|Occurs when a user can perform an action or access data of another user with a higher level of permissions.|

 

![](https://i.imgur.com/bJ9WKY4.png)


More information: [Broken Access Control](https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A5-Broken_Access_Control) 



### Question #1: Access the administration page! 
---

First, we are going to open the **Debugger** on Firefox. This can be done by navigating to it in the Web Developers menu. ![](https://i.imgur.com/rvhCm6V.png)![](https://i.imgur.com/oWJI6Yi.png) 

We are then going to refresh the page and look for a javascript file for main-es2015.js

We will then go to that page at:`http://10.10.22.244/main-es2015.js`

![](https://i.imgur.com/wF55kiO.png) 

To get this into a format we can read, click the { } button at the bottom ![](https://i.imgur.com/93xvM6I.png)

Now search for the term "admin" You will come across a couple of different words containing "admin" but the one we are looking for is "path: administration"

![](https://i.imgur.com/AS1YVjU.png) 

This hints towards a page called "**/#/administration**" as can be seen by the **about** path a couple lines below, but going there while not logged in doesn't work. As this is an Administrator page, it makes sense that we need to be in the **Admin account** in order to view it.

A good way to stop users from accessing this is to only load parts of the application that need to be used by them. This stops sensitive information such as an admin page from been leaked or viewed.

### Question #2: View another user's shopping basket! 
---
Login to the Admin account and click on `Your Basket`. Make sure Burp is running so you can capture the request!

Forward each request until you see:`GET /rest/basket/1 HTTP/1.1`

![](https://i.imgur.com/wlS88AU.png) 

Now, we are going to change the number **1** after `/basket/` to **2**

![](https://i.imgur.com/ugsRunL.png)

It will now show you the basket of UserID 2. You can do this for other `UserIDs` as well, provided that they have one!

![](https://i.imgur.com/yR4xFo3.png)

### Question #3: Remove all 5-star reviews!
---
 

Navigate to the `http://10.10.22.244/#/administration` page again and click the bin icon next to the review with 5 stars!

 

![](https://i.imgur.com/cI2sSyx.png)**

# Where did that come from?
---

XSS or Cross-site scripting is a vulnerability that allows attackers to run javascript in web applications. These are one of the most found bugs in web applications. Their complexity ranges from easy to extremely hard, as each web application parses the queries in a different way. **There are three major types of XSS attacks:**

| | |
|---|---|
|DOM (Special)|DOM XSS _(Document Object Model-based Cross-site Scripting)_ uses the HTML environment to execute malicious javascript. This type of attack commonly uses the _<script></script>_ HTML tag.|
|Persistent (Server-side)|Persistent XSS is javascript that is run when the server loads the page containing it. These can occur when the server does not sanitise the user data when it is **uploaded** to a page. These are commonly found on blog posts.|
|Reflected (Client-side)|Reflected XSS is javascript that is run on the client-side end of the web application. These are most commonly found when the server doesn't sanitise **search** data.|

More information: [Cross-Site Scripting XSS](https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A7-Cross-Site_Scripting_(XSS))

Answer the questions below

### Question #1: Perform a DOM XSS! 
---

![](https://i.imgur.com/AMz9jps.png)

We will be using the iframe element with a javascript alert tag:`<iframe src="javascript:alert('xss')">` Inputting this into the **search bar** will trigger the alert.

![](https://i.imgur.com/rKEx3aR.png)

Note that we are using **iframe** which is a common HTML element found in many web applications, there are others which also produce the same result. This type of XSS is also called XFS (Cross-Frame Scripting), is one of the most common forms of detecting XSS within web applications.

Websites that allow the user to modify the iframe or other DOM elements will most likely be vulnerable to XSS. #### **Why does this work?**
---

It is common practice that the search bar will send a request to the server in which it will then send back the related information, but this is where the flaw lies. Without correct input sanitation, we are able to perform an XSS attack against the search bar.

### Question #2: Perform a persistent XSS! 
---

First, login to the **admin** account.

We are going to navigate to the "**Last Login IP**" page for this attack. 

 ![](https://i.imgur.com/YTIzhh0.png)

 It should say the last IP Address is 0.0.0.0 or 10.x.x.x As it logs the 'last' login IP we will now logout so that it logs the 'new' IP.

![](https://i.imgur.com/4XHHSof.png)

Make sure that Burp **intercept is on**, so it will catch the logout request.

We will then head over to the Headers tab where we will add a new header:

| | |
| ---------------- | ---------------------------------------- |
| _True-Client-IP_ | `<iframe src="javascript:alert('xss')">` |
| | |

![](https://i.imgur.com/VLd2Fga.png)

Then forward the request to the server! 
When **signing back into the admin account** and navigating to the Last Login IP page again, we will see the XSS alert!

![](https://i.imgur.com/rKEx3aR.png)

#### **Why do we have to send this Header?**
---
The _True-Client-IP_ header is similar to the _X-Forwarded-For_ header, both tell the server or proxy what the IP of the client is. Due to there being no sanitation in the header we are able to perform an XSS attack.


### Question #3: Perform a reflected XSS! 
---

First, we are going to need to be on the right page to perform the reflected XSS!

**Login** into the **admin account** and navigate to the 'Order History' page. From there you will see a "Truck" icon, clicking on that will bring you to the track result page. You will also see that there is an id paired with the order. ![](https://i.imgur.com/kQdIKyL.png)

We will use the iframe XSS,`<iframe src="javascript:alert('xss')">` , in the place of the _5267-f73dcd000abcc353_

After submitting the URL, refresh the page and you will then get an alert saying XSS!


#### **Why does this work?**
---

The server will have a lookup table or database (depending on the type of server) for each tracking ID. As the 'id' parameter is not sanitised before it is sent to the server, we are able to perform an XSS attack.

# Exploration!
---

