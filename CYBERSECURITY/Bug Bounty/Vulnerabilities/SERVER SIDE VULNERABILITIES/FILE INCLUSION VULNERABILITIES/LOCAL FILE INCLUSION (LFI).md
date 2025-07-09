Local file inclusion is an attack technique in which attackers can trick a web application into either running or exposing files, this can lead to XSS(Cross site scripting) or either to RCE (Remote Code Execution)

## EXAMPLES OF LFI INCLUDING A CTF

So, to begin with the explanation, we must understand the way LFI works: Local file inclusion (also known as LFI) is the process of including files, that are already locally present on the server, through the exploiting of vulnerable inclusion procedures implemented in the application. This vulnerability occurs, for example, when a page receives, as input, the path to the file that has to be included and this input is not properly sanitized, allowing directory traversal characters (such as dot-dot-slash (../)) to be injected. Although most examples point to vulnerable PHP scripts, we should keep in mind that it is also common in other technologies such as JSP, ASP and others.

## How to Test

Since LFI occurs when paths passed to `include` statements are not properly sanitized, in a Blackbox testing approach, we should look for scripts which take filenames as parameters.

Consider the following example:

`http://vulnerablehost/preview.php?file=example.html`

This looks like a perfect place to try for LFI. If an attacker is lucky enough, and instead of selecting the appropriate page from the array by its name, the script directly includes the input parameter, it is possible to include arbitrary files on the server.

*Typical POC would be to load a passwd file:*

`http://vulnerablehost/preview.php?file=../../../etc/passwd

If the above conditions are met, an attacker would see something like the following: 

```
root:x:0:0:root:/root:/bin/bash
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
alex:x:500:500:alex:/home/alex:/bin/bash
margo:x:501:501::/home/margo:/bin/bash
```

Even when such vulnerability exists, its exploitation could be more complex in real life scenarios. Consider the following piece of code:

`<?php include($_GET['file'].".php"; ?>`

Simple substitution with a random filename would not work as the postfixÂ `.php`Â is appended to the provided input. In order to bypass it, a tester can use several techniques to get the expected exploitation.

### Null Byte Injection

TheÂ `null character`Â (also known asÂ `null terminator`Â orÂ `null byte`) is a control character with the value zero present in many character sets that is being used as a reserved character to mark the end of a string. Once used, any character after this special byte will be ignored. Commonly the way to inject this character would be with the URL encoded stringÂ `%00`Â by appending it to the requested path. In our previous sample, performing a request toÂ `http://vulnerable_host/preview.php?file=../../../../etc/passwd%00`Â would ignore theÂ `.php`Â extension being added to the input filename, returning to an attacker a list of basic users as a result of a successful exploitation.

### Path and Dot Truncation

Most PHP installations have a filename limit of 4096 bytes. If any given filename is longer than that length, PHP simply truncates it, discarding any additional characters. Abusing this behavior makes it possible to make the PHP engine ignore theÂ `.php`Â extension by moving it out of the 4096 bytes limit. When this happens, no error is triggered; the additional characters are simply dropped and PHP continues its execution normally.

This bypass would commonly be combined with other logic bypass strategies such as encoding part of the file path with Unicode encoding, the introduction of double encoding, or any other input that would still represent the valid desired filename.

### PHP Wrappers

Local File Inclusion vulnerabilities are commonly seen as read only vulnerabilities that an attacker can use to read sensitive data from the server hosting the vulnerable application. However, in some specific implementations this vulnerability can be used to upgrade the attackÂ [from LFI to Remote Code Execution](https://www.corben.io/zip-to-rce-lfi/)Â vulnerabilities that could potentially fully compromise the host.

This enhancement is common when an attacker could be able to combine theÂ [LFI vulnerability with certain PHP wrappers](https://www.netsparker.com/blog/web-security/php-stream-wrappers/).

A wrapper is a code that surrounds other code to perform some added functionality. PHP implements manyÂ [built-in wrappers](https://www.php.net/manual/en/wrappers.php)Â to be used with file system functions. Once their usage is detected during the testing process of an application, itâ€™s a good practice to try to abuse it to identify the real risk of the detected weakness(es). Below you can get a list with the most commonly used wrappers, even though you should consider that it is not exhaustive and at the same time it is possible to register custom wrappers that if employed by the target, would require a deeper ad hoc analysis.

#### PHP Filter

Used to access the local file system; this is a case insensitive wrapper that provides the capability to apply filters to a stream at the time of opening a file. This wrapper can be used to get content of a file preventing the server from executing it. For example, allowing an attacker to read the content of PHP files to get source code to identify sensitive information such as credentials or other exploitable vulnerabilities.

The wrapper can be used likeÂ `php://filter/convert.base64-encode/resource=FILE`Â whereÂ `FILE`Â is the file to retrieve. As a result of the usage of this execution, the content of the target file would be read, encoded to base64 (this is the step that prevents the execution server-side), and returned to the User-Agent.

#### PHP ZIP

On PHP 7.2.0, theÂ `zip://`Â wrapper was introduced to manipulateÂ `zip`Â compressed files. This wrapper expects the following parameter structure:Â `zip:///filename_path#internal_filename`Â whereÂ `filename_path`Â is the path to the malicious file andÂ `internal_filename`Â is the path where the malicious file is place inside the processed ZIP file. During the exploitation, itâ€™s common that theÂ `#`Â would be encoded with itâ€™s URL Encoded valueÂ `%23`.

Abuse of this wrapper could allow an attacker to design a malicious ZIP file that could be uploaded to the server, for example as an avatar image or using any file upload system available on the target website (theÂ `php:zip://`Â wrapper does not require the zip file to have any specific extension) to be executed by the LFI vulnerability.

In order to test this vulnerability, the following procedure could be followed to attack the previous code example provided.

1. Create the PHP file to be executed, for example with the contentÂ `<?php phpinfo(); ?>`Â and save it asÂ `code.php`
2. Compress it as a new ZIP file calledÂ `target.zip`
3. Rename theÂ `target.zip`Â file toÂ `target.jpg`Â to bypass the extension validation and upload it to the target website as your avatar image.
4. Supposing that theÂ `target.jpg`Â file is stored locally on the server to theÂ `../avatar/target.jpg`Â path, exploit the vulnerability with the PHP ZIP wrapper by injecting the following payload to the vulnerable URL:Â `zip://../avatar/target.jpg%23code`Â (remember thatÂ `%23`Â corresponds toÂ `#`).

Since on our sample theÂ `.php`Â extension is concatenated to our payload, the request toÂ `http://vulnerable_host/preview.php?file=zip://../avatar/target.jpg%23code`Â will result in the execution of theÂ `code.php`Â file existing in the malicious ZIP file.

#### PHP Data

Available since PHP 5.2.0, this wrapper expects the following usage:Â `data://text/plain;base64,BASE64_STR`Â whereÂ `BASE64_STR`Â is expected to be the Base64 encoded content of the file to be processed. Itâ€™s important to consider that this wrapper would only be available if the optionÂ `allow_url_include`Â would be enabled.

In order to test the LFI using this wrapper, the code to be executed should be Base64 encoded, for example, theÂ `<?php phpinfo(); ?>`Â code would be encoded as:Â `PD9waHAgcGhwaW5mbygpOyA/Pg==`Â so the payload would result as:Â `data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==`.

#### PHP Expect

This wrapper, which is not enabled by default, provides access to processesÂ `stdio`,Â `stdout`Â andÂ `stderr`. Expecting to be used asÂ `expect://command`Â the server would execute the provided command onÂ `BASH`Â and return itâ€™s result.

## Remediation

The most effective solution to eliminate file inclusion vulnerabilities is to avoid passing user-submitted input to any filesystem/framework API. If this is not possible the application can maintain an allow list of files, that may be included by the page, and then use an identifier (for example the index number) to access to the selected file. Any request containing an invalid identifier has to be rejected, in this way there is no attack surface for malicious users to manipulate the path.

Check out theÂ [File Upload Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html)Â for good security practices on this topic.


## PROOF OF CONCEPT (POC)

For this POC we are using dockerlabs machine: "buscalove": https://mega.nz/file/RG8GlDaD#haVrr92MyD-PgDUwxIJURT0q-P9Sl3kaNNBc-Ggppmg

### Enumeration

![Pasted image 20240916144543.png](../../../../IMAGES/Pasted%20image%2020240916144543.png)
![Pasted image 20240916144638.png](../../../../IMAGES/Pasted%20image%2020240916144638.png)
![Pasted image 20240916144945.png](../../../../IMAGES/Pasted%20image%2020240916144945.png)

So with this simple enumeration of the web application, we realize we've got a WordPress page, if we go into it, we can find this:

![Pasted image 20240916145226.png](../../../../IMAGES/Pasted%20image%2020240916145226.png)

#### Source code:
![Pasted image 20240916145307.png](../../../../IMAGES/Pasted%20image%2020240916145307.png)
If we keep fuzzing we will not be able to find anything useful like a `wp-admin.php` page, so, why don't we try to test for LFI if we ain't here for it haha:

Lets use the following payload:

If we keep fuzzing, using wfuzz, we can find this:

![Pasted image 20240916145504.png](../../../../IMAGES/Pasted%20image%2020240916145504.png)

We can now realize, love is the main word to begin with the LFI, so lets introduce this payload:

			index.php?love=../../../../../etc/passwd

![Pasted image 20240916145638.png](../../../../IMAGES/Pasted%20image%2020240916145638.png)

Just like that, we can find that this web application is vulnerable to LFI, we will keep testing:

Lets use this payload list from GitHub: https://raw.githubusercontent.com/emadshanab/LFI-Payload-List/master/LFI%20payloads.txt


						/etc/hosts

![Pasted image 20240916150545.png](../../../../IMAGES/Pasted%20image%2020240916150545.png)
					`/etc/ssh/ssh_config

![Pasted image 20240916150644.png](../../../../IMAGES/Pasted%20image%2020240916150644.png)

We could be testing payloads for many hours, but lets continue with the CTF, when we did /etc/passwd, we found the username `pedro` and `rosa`, now that we now that, lets brute force our way into ssh using hydra:

hydra -l rosa -P /usr/share/wordlists/rockyou.txt 172.17.0.2 ssh -t 10

![Pasted image 20240916151718.png](../../../../IMAGES/Pasted%20image%2020240916151718.png)

#### PRIVESC

![Pasted image 20240916152013.png](../../../../IMAGES/Pasted%20image%2020240916152013.png)

We have sudo privilege to use `cat` lets see what GTFOBINS have for us:
![Pasted image 20240916152141.png](../../../../IMAGES/Pasted%20image%2020240916152141.png)
If this CTF consisted in getting a flag, we could use `sudo cat /root/root.txt` and it would be over, but since we want to get root shell, we would keep enumerating until this:
![Pasted image 20240916152713.png](../../../../IMAGES/Pasted%20image%2020240916152713.png)
We could make use of Rosa's sudo permission to enumerate root folder, we found a secret.txt, we can use our cat sudo privilege to read it:
![Pasted image 20240916152812.png](../../../../IMAGES/Pasted%20image%2020240916152812.png)
Looks like hex chain, lets use CyberChef:

![Pasted image 20240916153033.png](../../../../IMAGES/Pasted%20image%2020240916153033.png)
Decrypting from hex, getting a base32 result, and decrypting it again, we get the password: `noacertarasosi`
seems like Pedro password, lets change users:
![Pasted image 20240916153150.png](../../../../IMAGES/Pasted%20image%2020240916153150.png)
And indeed it was Pedro's password, when we perform sudo -l:
![Pasted image 20240916153233.png](../../../../IMAGES/Pasted%20image%2020240916153233.png)
##### GTFOBINS
![Pasted image 20240916153308.png](../../../../IMAGES/Pasted%20image%2020240916153308.png)
![Pasted image 20240916153345.png](../../../../IMAGES/Pasted%20image%2020240916153345.png)
And just like that, we exploited a LFI vulnerability and got root access using PRIVESC.





