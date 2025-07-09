Now that we understand what File Inclusion vulnerabilities are and how they occur, we can start learning how we can exploit these vulnerabilities in different scenarios to be able to read the content of local files on the back-end server.

---

## Basic LFI

The exercise we have at the end of this section shows us an example of a web app that allows users to set their language to either English or Spanish:

Â Â Â 

![](https://academy.hackthebox.com/storage/modules/23/basic_lfi_lang.png)

If we select a language by clicking on it (e.g.Â `Spanish`), we see that the content text changes to spanish:

Â Â Â 

![](https://academy.hackthebox.com/storage/modules/23/basic_lfi_es.png)

We also notice that the URL includes aÂ `language`Â parameter that is now set to the language we selected (`es.php`). There are several ways the content could be changed to match the language we specified. It may be pulling the content from a different database table based on the specified parameter, or it may be loading an entirely different version of the web app. However, as previously discussed, loading part of the page using template engines is the easiest and most common method utilized.

So, if the web application is indeed pulling a file that is now being included in the page, we may be able to change the file being pulled to read the content of a different local file. Two common readable files that are available on most back-end servers areÂ `/etc/passwd`Â on Linux andÂ `C:\Windows\boot.ini`Â on Windows. So, let's change the parameter fromÂ `es`Â toÂ `/etc/passwd`:

Â Â Â 

![](https://academy.hackthebox.com/storage/modules/23/basic_lfi_lang_passwd.png)

As we can see, the page is indeed vulnerable, and we are able to read the content of theÂ `passwd`Â file and identify what users exist on the back-end server.

---

## Path Traversal

In the earlier example, we read a file by specifying itsÂ `absolute path`Â (e.g.Â `/etc/passwd`). This would work if the whole input was used within theÂ `include()`Â function without any additions, like the following example:


```php
include($_GET['language']);
```

In this case, if we try to readÂ `/etc/passwd`, then theÂ `include()`Â function would fetch that file directly. However, in many occasions, web developers may append or prepend a string to theÂ `language`Â parameter. For example, theÂ `language`Â parameter may be used for the filename, and may be added after a directory, as follows:


```php
include("./languages/" . $_GET['language']);
```

In this case, if we attempt to readÂ `/etc/passwd`, then the path passed toÂ `include()`Â would be (`./languages//etc/passwd`), and as this file does not exist, we will not be able to read anything:

Â Â Â 

![](https://academy.hackthebox.com/storage/modules/23/traversal_passwd_failed.png)

As expected, the verbose error returned shows us the string passed to theÂ `include()`Â function, stating that there is noÂ `/etc/passwd`Â in the languages directory.

**Note:**Â We are only enabling PHP errors on this web application for educational purposes, so we can properly understand how the web application is handling our input. For production web applications, such errors should never be shown. Furthermore, all of our attacks should be possible without errors, as they do not rely on them.

We can easily bypass this restriction by traversing directories usingÂ `relative paths`. To do so, we can addÂ `../`Â before our file name, which refers to the parent directory. For example, if the full path of the languages directory isÂ `/var/www/html/languages/`, then usingÂ `../index.php`Â would refer to theÂ `index.php`Â file on the parent directory (i.e.Â `/var/www/html/index.php`).

So, we can use this trick to go back several directories until we reach the root path (i.e.Â `/`), and then specify our absolute file path (e.g.Â `../../../../etc/passwd`), and the file should exist:

Â Â Â 

![](https://academy.hackthebox.com/storage/modules/23/traversal_passwd.png)

As we can see, this time we were able to read the file regardless of the directory we were in. This trick would work even if the entire parameter was used in theÂ `include()`Â function, so we can default to this technique, and it should work in both cases. Furthermore, if we were at the root path (`/`) and usedÂ `../`Â then we would still remain in the root path. So, if we were not sure of the directory the web application is in, we can addÂ `../`Â many times, and it should not break the path (even if we do it a hundred times!).

**Tip:**Â It can always be useful to be efficient and not add unnecessaryÂ `../`Â several times, especially if we were writing a report or writing an exploit. So, always try to find the minimum number ofÂ `../`Â that works and use it. You may also be able to calculate how many directories you are away from the root path and use that many. For example, withÂ `/var/www/html/`Â we areÂ `3`Â directories away from the root path, so we can useÂ `../`Â 3 times (i.e.Â `../../../`).

---

## Filename Prefix

In our previous example, we used theÂ `language`Â parameter after the directory, so we could traverse the path to read theÂ `passwd`Â file. On some occasions, our input may be appended after a different string. For example, it may be used with a prefix to get the full filename, like the following example:

```php
include("lang_" . $_GET['language']);
```

In this case, if we try to traverse the directory withÂ `../../../etc/passwd`, the final string would beÂ `lang_../../../etc/passwd`, which is invalid:

Â Â Â 

![](https://academy.hackthebox.com/storage/modules/23/lfi_another_example1.png)

As expected, the error tells us that this file does not exist. so, instead of directly using path traversal, we can prefix aÂ `/`Â before our payload, and this should consider the prefix as a directory, and then we should bypass the filename and be able to traverse directories:

Â Â Â 

![](https://academy.hackthebox.com/storage/modules/23/lfi_another_example_passwd1.png)

**Note:**Â This may not always work, as in this example a directory namedÂ `lang_/`Â may not exist, so our relative path may not be correct. Furthermore,Â `any prefix appended to our input may break some file inclusion techniques`Â we will discuss in upcoming sections, like using PHP wrappers and filters or RFI.

---

## Appended Extensions

Another very common example is when an extension is appended to theÂ `language`Â parameter, as follows:

Code:Â php

```php
include($_GET['language'] . ".php");
```

This is quite common, as in this case, we would not have to write the extension every time we need to change the language. This may also be safer as it may restrict us to only including PHP files. In this case, if we try to readÂ `/etc/passwd`, then the file included would beÂ `/etc/passwd.php`, which does not exist:

Â Â Â 

![](https://academy.hackthebox.com/storage/modules/23/lfi_extension_failed.png)

There are several techniques that we can use to bypass this, and we will discuss them in upcoming sections.

**Exercise:**Â Try to read any php file (e.g. index.php) through LFI, and see whether you would get its source code or if the file gets rendered as HTML instead.

---

## Second-Order Attacks

As we can see, LFI attacks can come in different shapes. Another common, and a little bit more advanced, LFI attack is aÂ `Second Order Attack`. This occurs because many web application functionalities may be insecurely pulling files from the back-end server based on user-controlled parameters.

For example, a web application may allow us to download our avatar through a URL like (`/profile/$username/avatar.png`). If we craft a malicious LFI username (e.g.Â `../../../etc/passwd`), then it may be possible to change the file being pulled to another local file on the server and grab it instead of our avatar.

In this case, we would be poisoning a database entry with a malicious LFI payload in our username. Then, another web application functionality would utilize this poisoned entry to perform our attack (i.e. download our avatar based on username value). This is why this attack is called aÂ `Second-Order`Â attack.

Developers often overlook these vulnerabilities, as they may protect against direct user input (e.g. from aÂ `?page`Â parameter), but they may trust values pulled from their database, like our username in this case. If we managed to poison our username during our registration, then the attack would be possible.

Exploiting LFI vulnerabilities using second-order attacks is similar to what we have discussed in this section. The only variance is that we need to spot a function that pulls a file based on a value we indirectly control and then try to control that value to exploit the vulnerability.

# Questions
---

![Pasted image 20250218141645.png](../../../../IMAGES/Pasted%20image%2020250218141645.png)

We can submit the request to burp and modify it there, let's read `/etc/passwd`:

```
../../../../etc/passwd
```

![Pasted image 20250218141916.png](../../../../IMAGES/Pasted%20image%2020250218141916.png)

We got our username:

```
barry
```

Now, let's proceed to read `/usr/share/flags/flag.txt`:

```
../../../../usr/share/flags/flag.txt
```

![Pasted image 20250218142020.png](../../../../IMAGES/Pasted%20image%2020250218142020.png)

Flag is:

```
HTB{n3v3r_tru$t_u$3r_!nput}
```

