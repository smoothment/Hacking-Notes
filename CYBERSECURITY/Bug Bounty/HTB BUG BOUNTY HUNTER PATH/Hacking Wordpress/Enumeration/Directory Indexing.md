Active plugins should not be our only area of focus when assessing a WordPress website. Even if a plugin is deactivated, it may still be accessible, and therefore we can gain access to its associated scripts and functions. Deactivating a vulnerable plugin does not improve the WordPress site's security. It is best practice to either remove or keep up-to-date any unused plugins.

The following example shows a disabled plugin.

![image](https://academy.hackthebox.com/storage/modules/17/plugin-deactivated3.png)

If we browse to the plugins directory, we can see that we still have access to the`Mail Masta` plugin.

 ![](https://academy.hackthebox.com/storage/modules/17/plugin-mailmasta2.png)

We can also view the directory listing using cURL and convert the HTML output to a nice readable format using`html2text`.

```shell-session
smoothment@htb[/htb]$ curl -s -X GET http://blog.inlanefreight.com/wp-content/plugins/mail-masta/ | html2text

****** Index of /wp-content/plugins/mail-masta ******
[[ICO]] Name Last_modified Size Description
===========================================================================
[[PARENTDIR]] Parent_Directory - 
[[DIR]] amazon_api/ 2020-05-13 18:01 - 
[[DIR]] inc/ 2020-05-13 18:01 - 
[[DIR]] lib/ 2020-05-13 18:01 - 
[[ ]] plugin-interface.php 2020-05-13 18:01 88K 
[[TXT]] readme.txt 2020-05-13 18:01 2.2K 
===========================================================================
 Apache/2.4.29 (Ubuntu) Server at blog.inlanefreight.com Port 80
```

This type of access is called`Directory Indexing`. It allows us to navigate the folder and access files that may contain sensitive information or vulnerable code. It is best practice to disable directory indexing on web servers so a potential attacker cannot gain direct access to any files or folders other than those necessary for the website to function properly.

# Question
---

![Pasted image 20250220130304.png](../../../../IMAGES/Pasted%20image%2020250220130304.png)

Let's use `wpscan`:

```
wpscan --url http://IP:PORT/
```

This outputs the following:

```
[+] Headers
 | Interesting Entry: Server: nginx
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://94.237.53.112:46761/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 | - http://codex.wordpress.org/XML-RPC_Pingback_API
 | - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 | - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 | - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 | - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

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
 | - https://www.iplocation.net/defend-wordpress-from-ddos
 | - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 5.1.6 identified (Insecure, released on 2020-06-10).
 | Found By: Rss Generator (Passive Detection)
 | - http://94.237.53.112:46761/feed/, <generator>https://wordpress.org/?v=5.1.6</generator>
 | - http://94.237.53.112:46761/comments/feed/, <generator>https://wordpress.org/?v=5.1.6</generator>

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
 | - http://94.237.53.112:46761/wp-content/themes/ben_theme/style.css?ver=5.1.6, Match: 'Version: 1.6.7'

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
 | - http://94.237.53.112:46761/wp-content/plugins/mail-masta/readme.txt

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
 | - http://94.237.53.112:46761/wp-content/plugins/photo-gallery/css/jquery.mCustomScrollbar.min.css?ver=1.5.34
 | - http://94.237.53.112:46761/wp-content/plugins/photo-gallery/css/styles.min.css?ver=1.5.34
 | - http://94.237.53.112:46761/wp-content/plugins/photo-gallery/js/jquery.mCustomScrollbar.concat.min.js?ver=1.5.34
 | - http://94.237.53.112:46761/wp-content/plugins/photo-gallery/js/scripts.min.js?ver=1.5.34
 | Confirmed By:
 | Readme - Stable Tag (Aggressive Detection)
 | - http://94.237.53.112:46761/wp-content/plugins/photo-gallery/readme.txt
 | Readme - ChangeLog Section (Aggressive Detection)
 | - http://94.237.53.112:46761/wp-content/plugins/photo-gallery/readme.txt

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
 | - http://94.237.53.112:46761/wp-content/plugins/wp-google-places-review-slider/README.txt
```

If we navigate to:

```
http://IP:PORT/wp-content/plugins/mail-masta/inc/
```

We can see this:

```
****** Index of /wp-content/plugins/mail-masta/inc/ ******
===============================================================================
../
autoresponder/ 13-May-2020 18:54
-
campaign/ 13-May-2020 18:54
-
lists/ 13-May-2020 18:54
-
ajax_listing.php 13-May-2020 18:54
365
api_settings_ajax.php 13-May-2020 18:54
1386
campaign_delete.php 13-May-2020 18:54
353
campaign_edit.php 13-May-2020 18:54
7390
campaign_save.php 13-May-2020 18:54
9427
duplicate_campaign.php 13-May-2020 18:54
2315
flag.txt 18-May-2020 10:28
24
form_listing.php 18-May-2020 12:45
2115
mail-autoresponder-data.php 13-May-2020 18:54
80671
mail-campaign-data.php 13-May-2020 18:54
74908
mail-license-data.php 13-May-2020 18:54
4596
mail-list-data.php 13-May-2020 18:54
15353
mail-masta-autoresponders.php 13-May-2020 18:54
1853
mail-masta-campaign.php 13-May-2020 18:54
1799
mail-masta-delete.php 13-May-2020 18:54
1646
mail-masta-lists.php 13-May-2020 18:54
1964
mail-masta-settings.php 13-May-2020 18:54
797
mail-settings-data.php 13-May-2020 18:54
23607
masta_license.php 13-May-2020 18:54
1385
resp.php 13-May-2020 18:54
955
subscriber_list.php 13-May-2020 18:54
6953
view-campaign-mail.php 13-May-2020 18:54
505

```

We found our flag:

```
curl -s -X GET "http://94.237.53.112:46761/wp-content/plugins/mail-masta/inc/flag.txt" | html2text

HTB{3num3r4t10n_15_k3y}
```

Flag is:

```
HTB{3num3r4t10n_15_k3y}
```
