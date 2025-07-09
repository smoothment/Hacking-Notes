As we have seen in the previous section, even if developers attempt to secure the web application against injections, it may still be exploitable if it was not securely coded. Another type of injection mitigation is utilizing blacklisted characters and words on the back-end to detect injection attempts and deny the request if any request contained them. Yet another layer on top of this is utilizing Web Application Firewalls (WAFs), which may have a broader scope and various methods of injection detection and prevent various other attacks like SQL injections or XSS attacks.

This section will look at a few examples of how command injections may be detected and blocked and how we can identify what is being blocked.

---

## Filter/WAF Detection

Let us start by visiting the web application in the exercise at the end of this section. We see the sameÂ `Host Checker`Â web application we have been exploiting, but now it has a few mitigations up its sleeve. We can see that if we try the previous operators we tested, like (`;`,Â `&&`,Â `||`), we get the error messageÂ `invalid input`:Â 

![Filter](https://academy.hackthebox.com/storage/modules/109/cmdinj_filters_1.jpg)

This indicates that something we sent triggered a security mechanism in place that denied our request. This error message can be displayed in various ways. In this case, we see it in the field where the output is displayed, meaning that it was detected and prevented by theÂ `PHP`Â web application itself.Â `If the error message displayed a different page, with information like our IP and our request, this may indicate that it was denied by a WAF`.

Let us check the payload we sent:

```bash
127.0.0.1; whoami
```

Other than the IP (which we know is not blacklisted), we sent:

1. A semi-colon characterÂ `;`
2. A space character
3. AÂ `whoami`Â command

So, the web application eitherÂ `detected a blacklisted character`Â orÂ `detected a blacklisted command`, or both. So, let us see how to bypass each.

---

## Blacklisted Characters

A web application may have a list of blacklisted characters, and if the command contains them, it would deny the request. TheÂ `PHP`Â code may look something like the following:

```php
$blacklist = ['&', '|', ';', ...SNIP...];
foreach ($blacklist as $character) {
    if (strpos($_POST['ip'], $character) !== false) {
        echo "Invalid input";
    }
}
```

If any character in the string we sent matches a character in the blacklist, our request is denied. Before we start our attempts at bypassing the filter, we should try to identify which character caused the denied request.

---

## Identifying Blacklisted Character

Let us reduce our request to one character at a time and see when it gets blocked. We know that the (`127.0.0.1`) payload does work, so let us start by adding the semi-colon (`127.0.0.1;`):Â 

![Filter Character](https://academy.hackthebox.com/storage/modules/109/cmdinj_filters_2.jpg)

We still get anÂ `invalid input`, error meaning that a semi-colon is blacklisted. So, let's see if all of the injection operators we discussed previously are blacklisted.

# Question
----

![Pasted image 20250205140047.png](../../../../IMAGES/Pasted%20image%2020250205140047.png)

Answer for this question is `new-line`.
