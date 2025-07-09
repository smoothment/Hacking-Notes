In the previous section, we saw an example of a web application that only applied type validation controls on the front-end (i.e., client-side), which made it trivial to bypass these controls. This is why it is always recommended to implement all security-related controls on the back-end server, where attackers cannot directly manipulate it.

Still, if the type validation controls on the back-end server were not securely coded, an attacker can utilize multiple techniques to bypass them and reach PHP file uploads.

The exercise we find in this section is similar to the one we saw in the previous section, but it has a blacklist of disallowed extensions to prevent uploading web scripts. We will see why using a blacklist of common extensions may not be enough to prevent arbitrary file uploads and discuss several methods to bypass it.

---

## Blacklisting Extensions

Let's start by trying one of the client-side bypasses we learned in the previous section to upload a PHP script to the back-end server. We'll intercept an image upload request with Burp, replace the file content and filename with our PHP script's, and forward the request:

 ![](https://academy.hackthebox.com/storage/modules/136/file_uploads_disallowed_type.jpg)

As we can see, our attack did not succeed this time, as we got`Extension not allowed`. This indicates that the web application may have some form of file type validation on the back-end, in addition to the front-end validations.

There are generally two common forms of validating a file extension on the back-end:

1. Testing against a`blacklist` of types
2. Testing against a`whitelist` of types

Furthermore, the validation may also check the`file type` or the`file content` for type matching. The weakest form of validation amongst these is`testing the file extension against a blacklist of extension` to determine whether the upload request should be blocked. For example, the following piece of code checks if the uploaded file extension is`PHP` and drops the request if it is:


```php
$fileName = basename($_FILES["uploadFile"]["name"]);
$extension = pathinfo($fileName, PATHINFO_EXTENSION);
$blacklist = array('php', 'php7', 'phps');

if (in_array($extension, $blacklist)) {
 echo "File type not allowed";
 die();
}
```

The code is taking the file extension (`$extension`) from the uploaded file name (`$fileName`) and then comparing it against a list of blacklisted extensions (`$blacklist`). However, this validation method has a major flaw.`It is not comprehensive`, as many other extensions are not included in this list, which may still be used to execute PHP code on the back-end server if uploaded.

**Tip:** The comparison above is also case-sensitive, and is only considering lowercase extensions. In Windows Servers, file names are case insensitive, so we may try uploading a`php` with a mixed-case (e.g.`pHp`), which may bypass the blacklist as well, and should still execute as a PHP script.

So, let's try to exploit this weakness to bypass the blacklist and upload a PHP file.

---

## Fuzzing Extensions

As the web application seems to be testing the file extension, our first step is to fuzz the upload functionality with a list of potential extensions and see which of them return the previous error message. Any upload requests that do not return an error message, return a different message, or succeed in uploading the file, may indicate an allowed file extension.

There are many lists of extensions we can utilize in our fuzzing scan.`PayloadsAllTheThings` provides lists of extensions for [PHP](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Upload%20Insecure%20Files/Extension%20PHP/extensions.lst) and [.NET](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files/Extension%20ASP) web applications. We may also use`SecLists` list of common [Web Extensions](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/web-extensions.txt).

We may use any of the above lists for our fuzzing scan. As we are testing a PHP application, we will download and use the above [PHP](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Upload%20Insecure%20Files/Extension%20PHP/extensions.lst) list. Then, from`Burp History`, we can locate our last request to`/upload.php`, right-click on it, and select`Send to Intruder`. From the`Positions` tab, we can`Clear` any automatically set positions, and then select the`.php` extension in`filename="HTB.php"` and click the`Add` button to add it as a fuzzing position:

 ![](https://academy.hackthebox.com/storage/modules/136/file_uploads_burp_fuzz_extension.jpg)

We'll keep the file content for this attack, as we are only interested in fuzzing file extensions. Finally, we can`Load` the PHP extensions list from above in the`Payloads` tab under`Payload Options`. We will also un-tick the`URL Encoding` option to avoid encoding the (`.`) before the file extension. Once this is done, we can click on`Start Attack` to start fuzzing for file extensions that are not blacklisted:

 ![](https://academy.hackthebox.com/storage/modules/136/file_uploads_burp_intruder_result.jpg)

We can sort the results by`Length`, and we will see that all requests with the Content-Length (`193`) passed the extension validation, as they all responded with`File successfully uploaded`. In contrast, the rest responded with an error message saying`Extension not allowed`.

---

## Non-Blacklisted Extensions

Now, we can try uploading a file using any of the`allowed extensions` from above, and some of them may allow us to execute PHP code.`Not all extensions will work with all web server configurations`, so we may need to try several extensions to get one that successfully executes PHP code.

Let's use the`.phtml` extension, which PHP web servers often allow for code execution rights. We can right-click on its request in the Intruder results and select`Send to Repeater`. Now, all we have to do is repeat what we have done in the previous two sections by changing the file name to use the`.phtml` extension and changing the content to that of a PHP web shell:

 ![](https://academy.hackthebox.com/storage/modules/136/file_uploads_php5_web_shell.jpg)

As we can see, our file seems to have indeed been uploaded. The final step is to visit our upload file, which should be under the image upload directory (`profile_images`), as we saw in the previous section. Then, we can test executing a command, which should confirm that we successfully bypassed the blacklist and uploaded our web shell:

![](https://academy.hackthebox.com/storage/modules/136/file_uploads_php_manual_shell.jpg)


# Question
---

![Pasted image 20250206152513.png](../../../../IMAGES/Pasted%20image%2020250206152513.png)

Let's check the website:

![Pasted image 20250206152555.png](../../../../IMAGES/Pasted%20image%2020250206152555.png)

If we try to upload a simple `.php` file, we can see the following:

![Pasted image 20250206152627.png](../../../../IMAGES/Pasted%20image%2020250206152627.png)

So, let's upload an image and modify its contents using burp:

![Pasted image 20250206152734.png](../../../../IMAGES/Pasted%20image%2020250206152734.png)

If we try uploading with the `.php` extension, we get an error telling us the extension is not allowed, let's send the request to `intruder` and modify it in the following way:

![Pasted image 20250206152915.png](../../../../IMAGES/Pasted%20image%2020250206152915.png)

![Pasted image 20250206152920.png](../../../../IMAGES/Pasted%20image%2020250206152920.png)

We can use the following list of extensions:

```.php
.php3
.php4
.php5
.php7
.php8
.phtml
.phar
.phps
.pht
.pgif
.phpt
.inc
.php.jpg
.php.png
.php.gif
.php.webp
.php.inc
.php.txt
.php%00.jpg
.php.
.php...
.php.swp
.php.suspected
.php.unknown
.php.cgi
.php.asis
.php.1
.php.2
.php.test
.php~
.php.bak
.php.old
.php.new
.php_temp
.php.engine
.php.module
.php.cache
```

Let's start the attack and check the responses:

![Pasted image 20250206153151.png](../../../../IMAGES/Pasted%20image%2020250206153151.png)

A lot of them work, let's go with `.phar`:

![Pasted image 20250206153555.png](../../../../IMAGES/Pasted%20image%2020250206153555.png)

We are able to execute commands, let's read our flag:

![Pasted image 20250206153619.png](../../../../IMAGES/Pasted%20image%2020250206153619.png)

```
HTB{1_c4n_n3v3r_b3_bl4ckl1573d} 
```
