# WHAT IS PATH TRAVERSAL

Path traversal is also known as directory traversal. These vulnerabilities enable an attacker to read arbitrary files on the server that is running an application. This might include:

```ad-note
- Application code and data.
- Credentials for back-end systems.
- Sensitive operating system files.
```

In some cases, an attacker might be able to write to arbitrary files on the server, allowing them to modify application data or behavior, and ultimately take full control of the server.

PathÂ traversal vulnerabilities occur when the user's input is passed to a function such as file_get_contents in PHP. It's important to note that the function is not the main contributor to the vulnerability. Often poor input validation or filtering is the cause of the vulnerability.Â InÂ PHP, you can use the file_get_contents to read the content of a file. You can find more information about the functionÂ [here](https://www.php.net/manual/en/function.file-get-contents.php).

The following graph shows how a web application stores files inÂ /var/www/app. The happy path would be the user requesting the contents of userCV.pdf from a defined pathÂ /var/www/app/CVs.  

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d617515c8cd8348d0b4e68f/room-content/45d9c1baacda290c1f95858e27f740c9.png)

WeÂ can test out the URL parameter by adding payloads to see how the web application behaves. Path traversal attacks, also known as theÂ dot-dot-slashÂ attack, take advantage of moving the directory one step up using the double dotsÂ ../.Â If the attacker finds the entry point, which in this caseÂ get.php?file=, then the attacker may send something as follows,Â http://webapp.thm/get.php?file=../../../../etc/passwd  

Suppose there isn't input validation, and instead of accessing the PDF files atÂ /var/www/app/CVsÂ location, the web application retrieves files from other directories, which in this caseÂ /etc/passwd. EachÂ ..Â entry moves one directory until it reaches the root directoryÂ /. Then it changes the directory toÂ /etc, and from there, it read theÂ passwdÂ file.  

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d617515c8cd8348d0b4e68f/room-content/3037513935e3242f74bd0fe97833b5ac.png)

As a result, the web application sends back the file's content to the user.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d617515c8cd8348d0b4e68f/room-content/c12d34456ebe25bafffeb829c58f98c0.png)  

Similarly, if the web application runs on a Windows server, the attacker needs to provide Windows paths. For example, if the attacker wants to read theÂ boot.iniÂ file located inÂ c:\boot.ini, then the attacker can try the following depending on the targetÂ OSÂ version:

http://webapp.thm/get.php?file=../../../../boot.iniÂ or

http://webapp.thm/get.php?file=../../../../windows/win.ini  

The same concept applies here as with Linux operating systems, where we climb up directories until it reaches the root directory, which is usuallyÂ c:\.  

Sometimes, developers will add filters to limit access to only certain files or directories. Below are some commonÂ OSÂ files you could use when testing.Â 

  

|                             |                                                                                                                                                                   |
| --------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Location**                | **Description**                                                                                                                                                   |
| /etc/issue                  | contains a message or system identification to be printed before the login prompt.                                                                                |
| /etc/profile                | controls system-wide default variables, such asÂ Export variables, File creation mask (umask), Terminal types, Mail messages to indicate when new mail has arrived |
| /proc/version               | specifies the version of theÂ LinuxÂ kernel                                                                                                                         |
| /etc/passwd                 | has all registered user that has access to a system                                                                                                               |
| /etc/shadow                 | contains information about the system's users' passwords                                                                                                          |
| /root/.bash_history         | contains the history commands forÂ rootÂ user                                                                                                                       |
| /var/log/dmessage           | contains global system messages, including the messages that are logged during system startup                                                                     |
| /var/mail/root              | all emails forÂ rootÂ user                                                                                                                                          |
| /root/.ssh/id_rsa           | PrivateÂ SSHÂ keys for a root or any known valid user on the server                                                                                                 |
| /var/log/apache2/access.log | the accessed requests forÂ ApacheÂ Â webserver                                                                                                                       |
| C:\boot.ini                 | contains the boot options for computers withÂ BIOSÂ firmware                                                                                                        |

# Reading arbitrary files via path traversal

Imagine a shopping application that displays images of items for sale. This might load an image using the following HTML:

`<img src="/loadImage?filename=218.png">

The loadImage URL takes a filename parameter and returns the contents of the specified file. The image files are stored on disk in the location /var/www/images/. To return an image, the application appends the requested filename to this base directory and uses a filesystem API to read the contents of the file. In other words, the application reads from the following file path:
/var/www/images/218.png

This application implements no defenses against path traversal attacks. As a result, an attacker can request the following URL to retrieve the `/etc/passwd` file from the server's filesystem:

https://insecure-website.com/loadImage?filename=../../../etc/passwd

This causes the application to read from the following file path:

`/var/www/images/../../../etc/passwd`

The sequence `../` is valid within a file path, and means to step up one level in the directory structure. The three consecutive `../` sequences step up from /var/www/images/ to the filesystem root, and so the file that is actually read is:
/etc/passwd

On Unix-based operating systems, this is a standard file containing details of the users that are registered on the server, but an attacker could retrieve other arbitrary files using the same technique.

On Windows, both `../` and `..\` are valid directory traversal sequences. The following is an example of an equivalent attack against a Windows-based server:

https://insecure-website.com/loadImage?filename=..\..\..\windows\win.ini 

# PORTSWIGGER LAB:
![Pasted image 20240918135245.png](../../../../IMAGES/Pasted%20image%2020240918135245.png)
The moment we enter the website, a lot of GET requests start going through our burp, if we pick any of them, we will find something interesting, a /image?filename=file.jpg, this is the path where we'll be injecting our path traversal

### Sending to repeater

![Pasted image 20240918135455.png](../../../../IMAGES/Pasted%20image%2020240918135455.png)

If we send it to repeater, we can perform: `filename=../../../etc/passwd`

We use three `../` because the images allocate at:

`/var/www/images`

So, if we do: `../../../etc/passwd` we'd be doing this inside the server application:


`/var/www/images/../../../etc/passwd`

This way, we could retrieve the `passwd` file from `etc`



## Common obstacles to exploiting path traversal vulnerabilities

Many applications that place user input into file paths implement defenses against path traversal attacks. These can often be bypassed.

If an application strips or blocks directory traversal sequences from the user-supplied filename, it might be possible to bypass the defense using a variety of techniques.

You might be able to use an absolute path from the filesystem root, such as filename=/etc/passwd, to directly reference a file without using any traversal sequences.

### LAB

![Pasted image 20240923130540.png](../../../../IMAGES/Pasted%20image%2020240923130540.png)
Capturing the request:

![Pasted image 20240923131517.png](../../../../IMAGES/Pasted%20image%2020240923131517.png)
Sending to repeater:
![Pasted image 20240923131533.png](../../../../IMAGES/Pasted%20image%2020240923131533.png)

If we change the filename destination to `/etc/passwd` we'll be able to read the file.


![Pasted image 20240923131652.png](../../../../IMAGES/Pasted%20image%2020240923131652.png)


### Common obstacles to exploiting path traversal vulnerabilities - Continued

You might be able to use nested traversal sequences, such as ....// or ....\/. These revert to simple traversal sequences when the inner sequence is stripped.

#### LAB

![Pasted image 20240923131751.png](../../../../IMAGES/Pasted%20image%2020240923131751.png)
Request:

![Pasted image 20240923131902.png](../../../../IMAGES/Pasted%20image%2020240923131902.png)

Lets modify filename parameter, to see if we can read /etc/passwd file, if we try this: `....//....//....//etc/passwd` we will be able to read it!:

![Pasted image 20240923132302.png](../../../../IMAGES/Pasted%20image%2020240923132302.png)

Just like that, we finished the lab.

![Pasted image 20240923132340.png](../../../../IMAGES/Pasted%20image%2020240923132340.png)

#### Common obstacles to exploiting path traversal vulnerabilities - Continued

In some contexts, such as in a URL path or the filename parameter of a multipart/form-data request, web servers may strip any directory traversal sequences before passing your input to the application. You can sometimes bypass this kind of sanitization by URL encoding, or even double URL encoding, the ../ characters. This results in %2e%2e%2f and %252e%252e%252f respectively. Various non-standard encodings, such as ..%c0%af or ..%ef%bc%8f, may also work.

For Burp Suite Professional users, Burp Intruder provides the predefined payload list Fuzzing - path traversal. This contains some encoded path traversal sequences that you can try.
##### LAB
![Pasted image 20240923132530.png](../../../../IMAGES/Pasted%20image%2020240923132530.png)

Request:
![Pasted image 20240923132625.png](../../../../IMAGES/Pasted%20image%2020240923132625.png)

For this lab, when i tried standard URL encoding, i got an error, so i tried with double URL encoding and could read `/etc/passwd`. Used payload was:

`%252e%252e%252f%252e%252e%252f%252e%252e%252fetc/passwd`

![Pasted image 20240923133129.png](../../../../IMAGES/Pasted%20image%2020240923133129.png)
![Pasted image 20240923133206.png](../../../../IMAGES/Pasted%20image%2020240923133206.png)

##### Common obstacles to exploiting path traversal vulnerabilities - Continued

An application may require the user-supplied filename to start with the expected base folder, such as `/var/www/images`. In this case, it might be possible to include the required base folder followed by suitable traversal sequences. For example: 

`filename=/var/www/images/../../../etc/passwd`

###### LAB

![Pasted image 20240923133719.png](../../../../IMAGES/Pasted%20image%2020240923133719.png)

Request:
![Pasted image 20240923133959.png](../../../../IMAGES/Pasted%20image%2020240923133959.png)
Lets modify filename parameter into a path traversal:

![Pasted image 20240923133941.png](../../../../IMAGES/Pasted%20image%2020240923133941.png)
Just like that, i was able to read `/etc/passwd` file.

![Pasted image 20240923134102.png](../../../../IMAGES/Pasted%20image%2020240923134102.png)

###### Common obstacles to exploiting path traversal vulnerabilities - Continued

An application may require the user-supplied filename to end with an expected file extension, such as .png. In this case, it might be possible to use a null byte to effectively terminate the file path before the required extension. For example: 

`filename=../../../etc/passwd%00.png`


###### LAB


![Pasted image 20240923134247.png](../../../../IMAGES/Pasted%20image%2020240923134247.png)
Request:

![Pasted image 20240923134353.png](../../../../IMAGES/Pasted%20image%2020240923134353.png)

Injecting null byte:

![Pasted image 20240923134522.png](../../../../IMAGES/Pasted%20image%2020240923134522.png)

![Pasted image 20240923134600.png](../../../../IMAGES/Pasted%20image%2020240923134600.png)


## How to prevent a path traversal attack

The most effective way to prevent path traversal vulnerabilities is to avoid passing user-supplied input to filesystem APIs altogether. Many application functions that do this can be rewritten to deliver the same behavior in a safer way.

If you can't avoid passing user-supplied input to filesystem APIs, we recommend using two layers of defense to prevent attacks:

1. Validate the user input before processing it. Ideally, compare the user input with a whitelist of permitted values. If that isn't possible, verify that the input contains only permitted content, such as alphanumeric characters only.
2. After validating the supplied input, append the input to the base directory and use a platform filesystem API to canonicalize the path. Verify that the canonicalized path starts with the expected base directory.

Below is an example of some simple Java code to validate the canonical path of a file based on user input:

```java
File file = new File(BASE_DIRECTORY, userInput);
if (file.getCanonicalPath().startsWith(BASE_DIRECTORY)) {
    // process file
} 
```

![Pasted image 20240923134826.png](../../../../IMAGES/Pasted%20image%2020240923134826.png)



# TRYHACKME SECTION

In this scenario, we have the following entry point:Â 

http://webapp.thm/index.php?lang=EN. 

If we enter an invalid input, such asÂ THM, we get the following error

```php
Warning: include(languages/THM.php): failed to open stream: No such file or directory in /var/www/html/THM-4/index.php on line 12
```

  

The error message disclosesÂ significant information. By entering THM as input, an error message shows what the include function looks like:Â Â include(languages/THM.php);.Â 

If you look at the directory closely, we can tell the function includes files in the languages directory is addingÂ Â .phpÂ at the end of the entry. Thus the valid input will be something as follows:Â Â `index.php?`lang=EN,Â where the fileÂ ENÂ is located inside the givenÂ languagesÂ directory and namedÂ Â EN.php.Â 

Also, the error message disclosed another important piece of information about the full web application directory path which isÂ /var/www/html/THM-4/

To exploit this, we need to use theÂ ../Â trick, as described in the directory traversal section, to get out the current folder. Let's try the following:  

http://webapp.thm/index.php?lang=../../../../etc/passwd

Note that we used 4Â `../`Â because we know the path has four levelsÂ /var/www/html/THM-4. But we still receive the following error:  

```php
Warning: include(languages/../../../../../etc/passwd.php): failed to open stream: No such file or directory in /var/www/html/THM-4/index.php on line 12
```

It seems we could move out of the PHP directory but still, theÂ includeÂ function reads the input withÂ .phpÂ at the end! This tells us that the developer specifies the file type to pass to the include function. To bypass this scenario, we can use the NULL BYTE, which isÂ %00.  

Using null bytes is an injection technique where URL-encoded representation such asÂ %00Â orÂ 0x00Â in hex with user-supplied data to terminate strings. You could think of it as trying to trick the web app into disregarding whatever comes after the Null Byte.  

By adding the Null Byte at the end of the payload, we tell theÂ Â includeÂ function to ignore anything after the null byte which may look like:

include("languages/../../../../../etc/passwd%00").".php");Â which equivalent toÂ â†’Â include("languages/../../../../../etc/passwd");

NOTE: theÂ %00Â trick is fixed and not working withÂ PHPÂ 5.3.4Â and above.  

Now apply what we showed in Lab #3, and try to read files /etc/passwd, answer question #1 below.

  

2.Â In this section, the developer decided to filter keywords to avoid disclosing sensitive information! TheÂ /etc/passwdÂ file is being filtered. There are two possible methods to bypass the filter.Â First, by using the NullByteÂ %00Â or the current directory trick at the end of the filtered keywordÂ /..Â The exploit will be similar toÂ http://webapp.thm/index.php?lang=/etc/passwd/.Â We could also useÂ http://webapp.thm/index.php?lang=/etc/passwd%00.

To make it clearer, if we try this concept in the file system usingÂ cd ..,Â it will get you back one step; however, if you doÂ cd .,Â It stays in the current directory.Â Â Similarly, if we tryÂ Â /etc/passwd/..,Â it results to beÂ Â /etc/Â and that'sÂ because we moved one to the root.Â Â Now if we tryÂ Â /etc/passwd/.,Â the result will beÂ Â /etc/passwdÂ since dot refers to the current directory.

Now apply this technique in Lab #4 and figure out to read /etc/passwd.

**3.**Â Next, in the following scenarios, the developer starts to use input validation by filtering some keywords. Let's test out and check the error message!  

http://webapp.thm/index.php?lang=../../../../etc/passwd  

We got the following error!  

```php
Warning: include(languages/etc/passwd): failed to open stream: No such file or directory in /var/www/html/THM-5/index.php on line 15
```

  

If we check the warning message in theÂ include(languages/etc/passwd)Â section, we know that the web application replaces theÂ ../Â with the empty string. There are a couple of techniques we can use to bypass this.

First, we can send the following payload to bypass it:
`....//....//....//....//....//etc/passwd`

## Why did this work?

This works because the PHP filter only matches and replaces the first subset stringÂ ../Â it finds and doesn't do another pass, leaving what is pictured below.  

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d617515c8cd8348d0b4e68f/room-content/30d3bf0341ba99485c5f683a416a056d.png)  

Try out Lab #5 and try to read /etc/passwd and bypass the filter!

  

**4.**Â Finally, we'll discuss the case where the developer forces the include to read from a defined directory! For example, if the web application asks to supply input that has to include a directory such as:Â http://webapp.thm/index.php?lang=languages/EN.phpÂ then, to exploit this, we need to include the directory in the payload like so:Â 

`?lang=languages/../../../../../etc/passwd.`
