---
sticker: lucide//curly-braces
---
Today, the majority of the applications we use constantly interact with the internet, both web and mobile applications. Most internet communications are made with web requests through the HTTP protocol.Â [HTTP](https://tools.ietf.org/html/rfc2616)Â is an application-level protocol used to access the World Wide Web resources. The termÂ `hypertext`Â stands for text containing links to other resources and text that the readers can easily interpret.

HTTP communication consists of a client and a server, where the client requests the server for a resource. The server processes the requests and returns the requested resource. The default port for HTTP communication is portÂ `80`, though this can be changed to any other port, depending on the web server configuration. The same requests are utilized when we use the internet to visit different websites. We enter aÂ `Fully Qualified Domain Name`Â (`FQDN`) as aÂ `Uniform Resource Locator`Â (`URL`) to reach the desired website, likeÂ [www.hackthebox.com](http://www.hackthebox.com/).

## URL

Resources over HTTP are accessed via aÂ `URL`, which offers many more specifications than simply specifying a website we want to visit. Let's look at the structure of a URL:Â ![url_structure](https://academy.hackthebox.com/storage/modules/35/url_structure.png)

Here is what each component stands for:

|**Component**|**Example**|**Description**|
|---|---|---|
|`Scheme`|`http://`Â `https://`|This is used to identify the protocol being accessed by the client, and ends with a colon and a double slash (`://`)|
|`User Info`|`admin:password@`|This is an optional component that contains the credentials (separated by a colonÂ `:`) used to authenticate to the host, and is separated from the host with an at sign (`@`)|
|`Host`|`inlanefreight.com`|The host signifies the resource location. This can be a hostname or an IP address|
|`Port`|`:80`|TheÂ `Port`Â is separated from theÂ `Host`Â by a colon (`:`). If no port is specified,Â `http`Â schemes default to portÂ `80`Â andÂ `https`Â default to portÂ `443`|
|`Path`|`/dashboard.php`|This points to the resource being accessed, which can be a file or a folder. If there is no path specified, the server returns the default index (e.g.Â `index.html`).|
|`Query String`|`?login=true`|The query string starts with a question mark (`?`), and consists of a parameter (e.g.Â `login`) and a value (e.g.Â `true`). Multiple parameters can be separated by an ampersand (`&`).|
|`Fragments`|`#status`|Fragments are processed by the browsers on the client-side to locate sections within the primary resource (e.g. a header or section on the page).|

Not all components are required to access a resource. The main mandatory fields are the scheme and the host, without which the request would have no resource to request.

## HTTP Flow

![HTTP_Flow](https://academy.hackthebox.com/storage/modules/35/HTTP_Flow.png)

The diagram above presents the anatomy of an HTTP request at a very high level. The first time a user enters the URL (`inlanefreight.com`) into the browser, it sends a request to a DNS (Domain Name Resolution) server to resolve the domain and get its IP. The DNS server looks up the IP address forÂ `inlanefreight.com`Â and returns it. All domain names need to be resolved this way, as a server can't communicate without an IP address.

**Note:**Â Our browsers usually first look up records in the local '`/etc/hosts`' file, and if the requested domain does not exist within it, then they would contact other DNS servers. We can use the '`/etc/hosts`' to manually add records to for DNS resolution, by adding the IP followed by the domain name.

Once the browser gets the IP address linked to the requested domain, it sends a GET request to the default HTTP port (e.g.Â `80`), asking for the rootÂ `/`Â path. Then, the web server receives the request and processes it. By default, servers are configured to return an index file when a request forÂ `/`Â is received.

In this case, the contents ofÂ `index.html`Â are read and returned by the web server as an HTTP response. The response also contains the status code (e.g.Â `200 OK`), which indicates that the request was successfully processed. The web browser then renders theÂ `index.html`Â contents and presents it to the user.

**Note:**Â This module is mainly focused on HTTP web requests. For more on HTML and web applications, you may refer to theÂ [Introduction to Web Applications](https://academy.hackthebox.com/module/details/75)Â module.

---

## curl

In this module, we will be sending web requests through two of the most important tools for any web penetration tester, a Web Browser, like Chrome or Firefox, and theÂ `cURL`Â command line tool.

[cURL](https://curl.haxx.se/)Â (client URL) is a command-line tool and library that primarily supports HTTP along with many other protocols. This makes it a good candidate for scripts as well as automation, making it essential for sending various types of web requests from the command line, which is necessary for many types of web penetration tests.

We can send a basic HTTP request to any URL by using it as an argument for cURL, as follows:

Â Â HyperText Transfer Protocol (HTTP)

```shell-session
rootbyte0x0@htb[/htb]$ curl inlanefreight.com

<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
...SNIP...
```

We see that curl does not render the HTML/JavaScript/CSS code, unlike a web browser, but prints it in its raw format. However, as penetration testers, we are mainly interested in the request and response context, which usually becomes much faster and more convenient than a web browser.

We may also use curl to download a page or a file and output the content into a file using theÂ `-O`Â flag. If we want to specify the output file name, we can use theÂ `-o`Â flag and specify the name. Otherwise, we can useÂ `-O`Â and cURL will use the remote file name, as follows:

Â Â HyperText Transfer Protocol (HTTP)

```shell-session
rootbyte0x0@htb[/htb]$ curl -O inlanefreight.com/index.html
rootbyte0x0@htb[/htb]$ ls
index.html
```

As we can see, the output was not printed this time but rather saved intoÂ `index.html`. We noticed that cURL still printed some status while processing the request. We can silent the status with theÂ `-s`Â flag, as follows:

Â Â HyperText Transfer Protocol (HTTP)

```shell-session
rootbyte0x0@htb[/htb]$ curl -s -O inlanefreight.com/index.html
```

This time, cURL did not print anything, as the output was saved into theÂ `index.html`Â file. Finally, we may use theÂ `-h`Â flag to see what other options we may use with cURL:

Â Â HyperText Transfer Protocol (HTTP)

```shell-session
rootbyte0x0@htb[/htb]$ curl -h
Usage: curl [options...] <url>
 -d, --data <data>   HTTP POST data
 -h, --help <category> Get help for commands
 -i, --include       Include protocol response headers in the output
 -o, --output <file> Write to file instead of stdout
 -O, --remote-name   Write output to a file named as the remote file
 -s, --silent        Silent mode
 -u, --user <user:password> Server user and password
 -A, --user-agent <name> Send User-Agent <name> to server
 -v, --verbose       Make the operation more talkative

This is not the full help, this menu is stripped into categories.
Use "--help category" to get an overview of all categories.
Use the user manual `man curl` or the "--help all" flag for all options.
```

As the above message mentions, we may useÂ `--help all`Â to print a more detailed help menu, orÂ `--help category`Â (e.g.Â `-h http`) to print the detailed help of a specific flag. If we ever need to read more detailed documentation, we can useÂ `man curl`Â to view the full cURL manual page.


# Question

![Pasted image 20250121160721.png](../../../IMAGES/Pasted%20image%2020250121160721.png)

We need to perform curl on: `83.136.253.73:44167`, if we go to the cheatsheet, we can see the following command:

![Pasted image 20250121160850.png](../../../IMAGES/Pasted%20image%2020250121160850.png)

So, we need to do: `curl -s -O 83.136.253.73:44167/download.php`

Just like that, we'll have the file:

![Pasted image 20250121160937.png](../../../IMAGES/Pasted%20image%2020250121160937.png)

Flag is: `HTB{64$!c_cURL_u$3r}`
