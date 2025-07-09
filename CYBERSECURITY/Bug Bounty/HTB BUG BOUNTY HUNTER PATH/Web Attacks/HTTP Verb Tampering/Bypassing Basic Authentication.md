Exploiting HTTP Verb Tampering vulnerabilities is usually a relatively straightforward process. We just need to try alternate HTTP methods to see how they are handled by the web server and the web application. While many automated vulnerability scanning tools can consistently identify HTTP Verb Tampering vulnerabilities caused by insecure server configurations, they usually miss identifying HTTP Tampering vulnerabilities caused by insecure coding. This is because the first type can be easily identified once we bypass an authentication page, while the other needs active testing to see whether we can bypass the security filters in place.

The first type of HTTP Verb Tampering vulnerability is mainly caused by`Insecure Web Server Configurations`, and exploiting this vulnerability can allow us to bypass the HTTP Basic Authentication prompt on certain pages.

---

## Identify

When we start the exercise at the end of this section, we see that we have a basic`File Manager` web application, in which we can add new files by typing their names and hitting`enter`:

 ![](https://academy.hackthebox.com/storage/modules/134/web_attacks_verb_tampering_add.jpg)

However, suppose we try to delete all files by clicking on the red`Reset` button. In that case, we see that this functionality seems to be restricted for authenticated users only, as we get the following`HTTP Basic Auth` prompt:

 ![](https://academy.hackthebox.com/storage/modules/134/web_attacks_verb_tampering_reset.jpg)

As we do not have any credentials, we will get a`401 Unauthorized` page:

 ![](https://academy.hackthebox.com/storage/modules/134/web_attacks_verb_tampering_unauthorized.jpg)

So, let's see whether we can bypass this with an HTTP Verb Tampering attack. To do so, we need to identify which pages are restricted by this authentication. If we examine the HTTP request after clicking the Reset button or look at the URL that the button navigates to after clicking it, we see that it is at`/admin/reset.php`. So, either the`/admin` directory is restricted to authenticated users only, or only the`/admin/reset.php` page is. We can confirm this by visiting the`/admin` directory, and we do indeed get prompted to log in again. This means that the full`/admin` directory is restricted.

---

## Exploit

To try and exploit the page, we need to identify the HTTP request method used by the web application. We can intercept the request in Burp Suite and examine it: ![unauthorized_request](https://academy.hackthebox.com/storage/modules/134/web_attacks_verb_tampering_unauthorized_request.jpg)

As the page uses a`GET` request, we can send a`POST` request and see whether the web page allows`POST` requests (i.e., whether the Authentication covers`POST` requests). To do so, we can right-click on the intercepted request in Burp and select`Change Request Method`, and it will automatically change the request into a`POST` request: ![change_request](https://academy.hackthebox.com/storage/modules/134/web_attacks_verb_tampering_change_request.jpg)

Once we do so, we can click`Forward` and examine the page in our browser. Unfortunately, we still get prompted to log in and will get a`401 Unauthorized` page if we don't provide the credentials:

 ![](https://academy.hackthebox.com/storage/modules/134/web_attacks_verb_tampering_reset.jpg)

So, it seems like the web server configurations do cover both`GET` and`POST` requests. However, as we have previously learned, we can utilize many other HTTP methods, most notably the`HEAD` method, which is identical to a`GET` request but does not return the body in the HTTP response. If this is successful, we may not receive any output, but the`reset` function should still get executed, which is our main target.

To see whether the server accepts`HEAD` requests, we can send an`OPTIONS` request to it and see what HTTP methods are accepted, as follows:

```shell-session
smoothment@htb[/htb]$ curl -i -X OPTIONS http://SERVER_IP:PORT/

HTTP/1.1 200 OK
Date: 
Server: Apache/2.4.41 (Ubuntu)
Allow: POST,OPTIONS,HEAD,GET
Content-Length: 0
Content-Type: httpd/unix-directory
```

As we can see, the response shows`Allow: POST,OPTIONS,HEAD,GET`, which means that the web server indeed accepts`HEAD` requests, which is the default configuration for many web servers. So, let's try to intercept the`reset` request again, and this time use a`HEAD` request to see how the web server handles it:

![HEAD_request](https://academy.hackthebox.com/storage/modules/134/web_attacks_verb_tampering_HEAD_request.jpg)

Once we change`POST` to`HEAD` and forward the request, we will see that we no longer get a login prompt or a`401 Unauthorized` page and get an empty output instead, as expected with a`HEAD` request. If we go back to the`File Manager` web application, we will see that all files have indeed been deleted, meaning that we successfully triggered the`Reset` functionality without having admin access or any credentials:

 ![](https://academy.hackthebox.com/storage/modules/134/web_attacks_verb_tampering_after_reset.jpg)

Try testing other HTTP methods, and see which ones can successfully bypass the authentication prompt.

# Question
---

![Pasted image 20250217141132.png](../../../../IMAGES/Pasted%20image%2020250217141132.png)

Let's check out the website:

![Pasted image 20250217141147.png](../../../../IMAGES/Pasted%20image%2020250217141147.png)

We can see it's a file manager application, we can add files and delete them, let's try adding a file:

![Pasted image 20250217141216.png](../../../../IMAGES/Pasted%20image%2020250217141216.png)

Now, if we try deleting a file, this happens:

![Pasted image 20250217141234.png](../../../../IMAGES/Pasted%20image%2020250217141234.png)

We need credentials in order to do so, this seems like a privileged action only, so, in order to bypass this, let's send the request and analyze it:

![Pasted image 20250217141331.png](../../../../IMAGES/Pasted%20image%2020250217141331.png)

First, it sends a `GET` request to `/admin/reset.php` endpoint, if we forward the request, we can see the following:

![Pasted image 20250217141414.png](../../../../IMAGES/Pasted%20image%2020250217141414.png)

If we change the request method to `PUT`, this happens:


![Pasted image 20250217141751.png](../../../../IMAGES/Pasted%20image%2020250217141751.png)

We no longer get `401` status code, let's send the request and check the behavior:

![Pasted image 20250217142846.png](../../../../IMAGES/Pasted%20image%2020250217142846.png)

Page goes blank, we are unable to retrieve any data, this means, it's not the intended way to go, let's go back to adding files and checking the request, we can use the following test payload:

```
file; cp /flag.txt ./
```

We'd see the following:

![Pasted image 20250217143156.png](../../../../IMAGES/Pasted%20image%2020250217143156.png)

It shows its a malicious request but doesn't block the access to the flag, flag is:

```
HTB{4lw4y5_c0v3r_4ll_v3rb5}
```

