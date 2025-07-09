The other and more common type of HTTP Verb Tampering vulnerability is caused byÂ `Insecure Coding`Â errors made during the development of the web application, which lead to web application not covering all HTTP methods in certain functionalities. This is commonly found in security filters that detect malicious requests. For example, if a security filter was being used to detect injection vulnerabilities and only checked for injections inÂ `POST`Â parameters (e.g.Â `$_POST['parameter']`), it may be possible to bypass it by simply changing the request method toÂ `GET`.

---

## Identify

In theÂ `File Manager`Â web application, if we try to create a new file name with special characters in its name (e.g.Â `test;`), we get the following message:

Â Â Â 

![](https://academy.hackthebox.com/storage/modules/134/web_attacks_verb_malicious_request.jpg)

This message shows that the web application uses certain filters on the back-end to identify injection attempts and then blocks any malicious requests. No matter what we try, the web application properly blocks our requests and is secured against injection attempts. However, we may try an HTTP Verb Tampering attack to see if we can bypass the security filter altogether.

---

## Exploit

To try and exploit this vulnerability, let's intercept the request in Burp Suite (Burp) and then useÂ `Change Request Method`Â to change it to another method:Â 

![unauthorized_request](https://academy.hackthebox.com/storage/modules/134/web_attacks_verb_tampering_GET_request.jpg)

This time, we did not get theÂ `Malicious Request Denied!`Â message, and our file was successfully created:


![](https://academy.hackthebox.com/storage/modules/134/web_attacks_verb_tampering_injected_request.jpg)

To confirm whether we bypassed the security filter, we need to attempt exploiting the vulnerability the filter is protecting: a Command Injection vulnerability, in this case. So, we can inject a command that creates two files and then check whether both files were created. To do so, we will use the following file name in our attack (`file1; touch file2;`):

Â Â Â 

![](https://academy.hackthebox.com/storage/modules/134/web_attacks_verb_tampering_filter_bypass.jpg)

Then, we can once again change the request method to aÂ `GET`Â request:Â 

![filter_bypass_request](https://academy.hackthebox.com/storage/modules/134/web_attacks_verb_tampering_filter_bypass_request.jpg)

Once we send our request, we see that this time bothÂ `file1`Â andÂ `file2`Â were created:


![](https://academy.hackthebox.com/storage/modules/134/web_attacks_verb_tampering_after_filter_bypass.jpg)

This shows that we successfully bypassed the filter through an HTTP Verb Tampering vulnerability and achieved command injection. Without the HTTP Verb Tampering vulnerability, the web application may have been secure against Command Injection attacks, and this vulnerability allowed us to bypass the filters in place altogether.

# Question
---

![Pasted image 20250217143523.png](../../../../IMAGES/Pasted%20image%2020250217143523.png)

Same situation as the previous module, let's check the request behavior by adding a `test;` file:

![Pasted image 20250217143548.png](../../../../IMAGES/Pasted%20image%2020250217143548.png)

We get malicious request denied error, this means the web application's got some sort of command injection security, but, it can be easily bypassed:

![Pasted image 20250217144923.png](../../../../IMAGES/Pasted%20image%2020250217144923.png)

First, let's send the payload and change the request method, once we've sent it, change it again and send it:

![Pasted image 20250217145008.png](../../../../IMAGES/Pasted%20image%2020250217145008.png)

Now we can see our `flag.txt` has been correctly added, let's take a look:

![Pasted image 20250217145033.png](../../../../IMAGES/Pasted%20image%2020250217145033.png)

There it is, let's read it:

![Pasted image 20250217145048.png](../../../../IMAGES/Pasted%20image%2020250217145048.png)

Flag is:

```
HTB{b3_v3rb_c0n51573n7}
```
