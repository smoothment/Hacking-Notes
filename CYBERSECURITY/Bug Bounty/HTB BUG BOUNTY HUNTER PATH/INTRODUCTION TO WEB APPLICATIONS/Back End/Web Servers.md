---
sticker: lucide//curly-braces
---

AÂ [web server](https://en.wikipedia.org/wiki/Web_server)Â is an application that runs on the back end server, which handles all of the HTTP traffic from the client-side browser, routes it to the requested pages, and finally responds to the client-side browser. Web servers usually run on TCPÂ [ports](https://en.wikipedia.org/wiki/Port_(computer_networking))Â `80`Â orÂ `443`, and are responsible for connecting end-users to various parts of the web application, in addition to handling their various responses.

---

## Workflow

A typical web server accepts HTTP requests from the client-side, and responds with different HTTP responses and codes, like a codeÂ `200 OK`Â response for a successful request, a codeÂ `404 NOT FOUND`Â when requesting pages that do not exist, codeÂ `403 FORBIDDEN`Â for requesting access to restricted pages, and so on.

![web server](https://academy.hackthebox.com/storage/modules/75/web-server-requests.jpg)

The following are some of the most commonÂ [HTTP response codes](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status):

|Code|Description|
|---|---|
|**Successful responses**||
|`200 OK`|The request has succeeded|
|**Redirection messages**||
|`301 Moved Permanently`|The URL of the requested resource has been changed permanently|
|`302 Found`|The URL of the requested resource has been changed temporarily|
|**Client error responses**||
|`400 Bad Request`|The server could not understand the request due to invalid syntax|
|`401 Unauthorized`|Unauthenticated attempt to access page|
|`403 Forbidden`|The client does not have access rights to the content|
|`404 Not Found`|The server can not find the requested resource|
|`405 Method Not Allowed`|The request method is known by the server but has been disabled and cannot be used|
|`408 Request Timeout`|This response is sent on an idle connection by some servers, even without any previous request by the client|
|**Server error responses**||
|`500 Internal Server Error`|The server has encountered a situation it doesn't know how to handle|
|`502 Bad Gateway`|The server, while working as a gateway to get a response needed to handle the request, received an invalid response|
|`504 Gateway Timeout`|The server is acting as a gateway and cannot get a response in time|

Web servers also accept various types of user input within HTTP requests, including text,Â [JSON](https://www.w3schools.com/js/js_json_intro.asp), and even binary data (i.e., for file uploads). Once a web server receives a web request, it is then responsible for routing it to its destination, run any processes needed for that request, and return the response to the user on the client-side. The pages and files that the webserver processes and routes traffic to are the web application core files.

The following shows an example of requesting a page in a Linux terminal using theÂ [cURL](https://en.wikipedia.org/wiki/CURL)Â utility, and receiving the server response while using theÂ `-I`Â flag, which displays the headers:

Â Â Web Servers

```shell-session
smoothment@htb[/htb]$ curl -I https://academy.hackthebox.com

HTTP/2 200
date: Tue, 15 Dec 2020 19:54:29 GMT
content-type: text/html; charset=UTF-8
...SNIP...
```

While thisÂ `cURL`Â command example shows us the source code of the webpage:

Â Â Web Servers

```shell-session
smoothment@htb[/htb]$ curl https://academy.hackthebox.com

<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<title>Cyber Security Training : HTB Academy</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
```

Many web server types can be utilized to run web applications. Most of these can handle all types of complex HTTP requests, and they are usually free of charge. We can even develop our own basic web server using languages such asÂ `Python`,Â `JavaScript`, andÂ `PHP`. However, for each language, there's a popular web application that is optimized for handling large amounts of web traffic, which saves us time in creating our own web server.

---

## Apache

![Apache](https://academy.hackthebox.com/storage/modules/75/apache.png)

[Apache](https://www.apache.org/)Â 'orÂ `httpd`' is the most common web server on the internet, hosting more thanÂ `40%`Â of all internet websites.Â `Apache`Â usually comes pre-installed in mostÂ `Linux`Â distributions and can also be installed on Windows and macOS servers.

`Apache`Â is usually used withÂ `PHP`Â for web application development, but it also supports other languages likeÂ `.Net`,Â `Python`,Â `Perl`, and even OS languages likeÂ `Bash`Â throughÂ `CGI`. Users can install a wide variety ofÂ `Apache`Â modules to extend its functionality and support more languages. For example, to support servingÂ `PHP`Â files, users must installÂ `PHP`Â on the back end server, in addition to installing theÂ `mod_php`Â module forÂ `Apache`.

`Apache`Â is an open-source project, and community users can access its source code to fix issues and look for vulnerabilities. It is well-maintained and regularly patched against vulnerabilities to keep it safe against exploitation. Furthermore, it is very well documented, making using and configuring different parts of the webserver relatively easy.Â `Apache`Â is commonly used by startups and smaller companies, as it is straightforward to develop for. Still, some big companies utilize Apache, including:

|`Apple`|`Adobe`|`Baidu`|
|---|---|---|

---

## NGINX

![NGINX](https://academy.hackthebox.com/storage/modules/75/nginx.png)

[NGINX](https://www.nginx.com/)Â is the second most common web server on the internet, hosting roughlyÂ `30%`Â of all internet websites.Â `NGINX`Â focuses on serving many concurrent web requests with relatively low memory and CPU load by utilizing an async architecture to do so. This makesÂ `NGINX`Â a very reliable web server for popular web applications and top businesses worldwide, which is why it is the most popular web server among high traffic websites, with around 60% of the top 100,000 websites usingÂ `NGINX`.

`NGINX`Â is also free and open-source, which gives all the same benefits previously mentioned, like security and reliability. Some popular websites that utilizeÂ `NGINX`Â include:

| `Google` | `Facebook` | `Twitter` | `Cisco` | `Intel` | `Netflix` | `HackTheBox` |
| -------- | ---------- | --------- | ------- | ------- | --------- | ------------ |

---

## IIS

![iis](https://academy.hackthebox.com/storage/modules/75/iis.png)

[IIS (Internet Information Services)](https://en.wikipedia.org/wiki/Internet_Information_Services)Â is the third most common web server on the internet, hosting aroundÂ `15%`Â of all internet web sites.Â `IIS`Â is developed and maintained by Microsoft and mainly runs on Microsoft Windows Servers.Â `IIS`Â is usually used to host web applications developed for the Microsoft .NET framework, but can also be used to host web applications developed in other languages likeÂ `PHP`, or host other types of services likeÂ `FTP`. Furthermore,Â `IIS`Â is very well optimized for Active Directory integration and includes features likeÂ `Windows Auth`Â for authenticating users using Active Directory, allowing them to automatically sign in to web applications.

Though not the most popular web server, many big organizations useÂ `IIS`Â as their web server. Many of them use Windows Server on their back end or rely heavily on Active Directory within their organization. Some popular websites that utilize IIS include:

| `Microsoft` | `Office365` | `Skype` | `Stack Overflow` | `Dell` |
| ----------- | ----------- | ------- | ---------------- | ------ |

Aside from these 3 web servers, there are many other commonly used web servers, likeÂ [Apache Tomcat](https://tomcat.apache.org/)Â forÂ `Java`Â web applications, andÂ [Node.JS](https://nodejs.org/en/)Â for web applications developed usingÂ `JavaScript`Â on the back end.


![Pasted image 20250122183655.png](../../../../IMAGES/Pasted%20image%2020250122183655.png)

