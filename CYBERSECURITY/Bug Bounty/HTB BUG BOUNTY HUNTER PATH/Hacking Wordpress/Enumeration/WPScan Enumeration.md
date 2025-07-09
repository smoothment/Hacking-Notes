## Enumerating a Website with WPScan

TheÂ `--enumerate`Â flag is used to enumerate various components of the WordPress application such as plugins, themes, and users. By default, WPScan enumerates vulnerable plugins, themes, users, media, and backups. However, specific arguments can be supplied to restrict enumeration to specific components. For example, all plugins can be enumerated using the argumentsÂ `--enumerate ap`. Let's run a normal enumeration scan against a WordPress website.

Note: The default number of threads used is 5, however, this value can be changed using the "-t" flag.

#### WPScan Enumeration

Â Â WPScan Enumeration

```shell-session
smoothment@htb[/htb]$ wpscan --url http://blog.inlanefreight.com --enumerate --api-token Kffr4fdJzy9qVcTk<SNIP>

[+] URL: http://blog.inlanefreight.com/                                                   

[+] Headers                                                                 
|  - Server: Apache/2.4.38 (Debian)
|  - X-Powered-By: PHP/7.3.15
| Found By: Headers (Passive Detection)

[+] XML-RPC seems to be enabled: http://blog.inlanefreight.com/xmlrpc.php
| Found By: Direct Access (Aggressive Detection)
|  - http://codex.wordpress.org/XML-RPC_Pingback_API

[+] The external WP-Cron seems to be enabled: http://blog.inlanefreight.com/wp-cron.php
| Found By: Direct Access (Aggressive Detection)
|  - https://www.iplocation.net/defend-wordpress-from-ddos

[+] WordPress version 5.3.2 identified (Latest, released on 2019-12-18).
| Found By: Rss Generator (Passive Detection)
|  - http://blog.inlanefreight.com/?feed=rss2, <generator>https://wordpress.org/?v=5.3.2</generator>

[+] WordPress theme in use: twentytwenty
| Location: http://blog.inlanefreight.com/wp-content/themes/twentytwenty/
| Readme: http://blog.inlanefreight.com/wp-content/themes/twentytwenty/readme.txt
| [!] The version is out of date, the latest version is 1.2
| Style Name: Twenty Twenty 

[+] Enumerating Vulnerable Plugins (via Passive Methods)
[i] Plugin(s) Identified:
[+] mail-masta
| Location: http://blog.inlanefreight.com/wp-content/plugins/mail-masta/                 
| Latest Version: 1.0 (up to date)
| Found By: Urls In Homepage (Passive Detection)
| [!] 2 vulnerabilities identified:
|
| [!] Title: Mail Masta 1.0 - Unauthenticated Local File Inclusion (LFI)
|      - https://www.exploit-db.com/exploits/40290/ 
| [!] Title: Mail Masta 1.0 - Multiple SQL Injection
|      - https://wpvulndb.com/vulnerabilities/8740                                                     
[+] wp-google-places-review-slider
| [!] 1 vulnerability identified:
| [!] Title: WP Google Review Slider <= 6.1 - Authenticated SQL Injection
|     Reference: https://wpvulndb.com/vulnerabilities/9933          

[i] No themes Found.  
<SNIP>
[i] No Config Backups Found.
<SNIP>
[i] No Medias Found.

[+] Enumerating Users (via Passive and Aggressive Methods)
<SNIP>
[i] User(s) Identified:
[+] admin
 | Found By: Author Posts - Display Name (Passive Detection)
 | Confirmed By:
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)

[+] david
<SNIP>
[+] roger
<SNIP>
```

WPScan uses various passive and active methods to determine versions and vulnerabilities, as shown in the scan output above.

# Question
----

![Pasted image 20250220133445.png](../../../../IMAGES/Pasted%20image%2020250220133445.png)

Let's use:

```
wpscan --url "http://IP:PORT" --enumerate ap -t 20
```

We get this:

```
[+] Headers
 | Interesting Entry: Server: nginx
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://94.237.53.112:46761/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://94.237.53.112:46761/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] Upload directory has listing enabled: http://94.237.53.112:46761/wp-content/uploads/
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://94.237.53.112:46761/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 5.1.6 identified (Insecure, released on 2020-06-10).
 | Found By: Rss Generator (Passive Detection)
 |  - http://94.237.53.112:46761/feed/, <generator>https://wordpress.org/?v=5.1.6</generator>
 |  - http://94.237.53.112:46761/comments/feed/, <generator>https://wordpress.org/?v=5.1.6</generator>

[+] WordPress theme in use: ben_theme
 | Location: http://94.237.53.112:46761/wp-content/themes/ben_theme/
 | Readme: http://94.237.53.112:46761/wp-content/themes/ben_theme/readme.txt
 | Style URL: http://94.237.53.112:46761/wp-content/themes/ben_theme/style.css?ver=5.1.6
 | Style Name: Transportex
 | Style URI: https://themeansar.com/free-themes/transportex/
 | Description: Transportex is a transport, logistics & home movers WordPress theme with focus on create online tran...
 | Author: Themeansar
 | Author URI: https://themeansar.com/
 |
 | Found By: Css Style In Homepage (Passive Detection)
 | Confirmed By: Css Style In 404 Page (Passive Detection)
 |
 | Version: 1.6.7 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://94.237.53.112:46761/wp-content/themes/ben_theme/style.css?ver=5.1.6, Match: 'Version: 1.6.7'

[+] Enumerating All Plugins (via Passive Methods)
[+] Checking Plugin Versions (via Passive and Aggressive Methods)

[i] Plugin(s) Identified:

[+] mail-masta
 | Location: http://94.237.53.112:46761/wp-content/plugins/mail-masta/
 | Latest Version: 1.0 (up to date)
 | Last Updated: 2014-09-19T07:52:00.000Z
 |
 | Found By: Urls In Homepage (Passive Detection)
 | Confirmed By: Urls In 404 Page (Passive Detection)
 |
 | Version: 1.0 (80% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://94.237.53.112:46761/wp-content/plugins/mail-masta/readme.txt

[+] photo-gallery
 | Location: http://94.237.53.112:46761/wp-content/plugins/photo-gallery/
 | Last Updated: 2025-02-06T16:46:00.000Z
 | [!] The version is out of date, the latest version is 1.8.33
 |
 | Found By: Urls In Homepage (Passive Detection)
 | Confirmed By: Urls In 404 Page (Passive Detection)
 |
 | Version: 1.5.34 (100% confidence)
 | Found By: Query Parameter (Passive Detection)
 |  - http://94.237.53.112:46761/wp-content/plugins/photo-gallery/css/jquery.mCustomScrollbar.min.css?ver=1.5.34
 |  - http://94.237.53.112:46761/wp-content/plugins/photo-gallery/css/styles.min.css?ver=1.5.34
 |  - http://94.237.53.112:46761/wp-content/plugins/photo-gallery/js/jquery.mCustomScrollbar.concat.min.js?ver=1.5.34
 |  - http://94.237.53.112:46761/wp-content/plugins/photo-gallery/js/scripts.min.js?ver=1.5.34
 | Confirmed By:
 |  Readme - Stable Tag (Aggressive Detection)
 |   - http://94.237.53.112:46761/wp-content/plugins/photo-gallery/readme.txt
 |  Readme - ChangeLog Section (Aggressive Detection)
 |   - http://94.237.53.112:46761/wp-content/plugins/photo-gallery/readme.txt

[+] wp-google-places-review-slider
 | Location: http://94.237.53.112:46761/wp-content/plugins/wp-google-places-review-slider/
 | Last Updated: 2025-02-17T16:44:00.000Z
 | [!] The version is out of date, the latest version is 15.9
 |
 | Found By: Urls In Homepage (Passive Detection)
 | Confirmed By: Urls In 404 Page (Passive Detection)
 |
 | Version: 6.1 (80% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://94.237.53.112:46761/wp-content/plugins/wp-google-places-review-slider/README.txt

```


Answer is:

```
1.5.34
```
