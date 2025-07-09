# ENUMERATION

## OPEN PORTS
To begin with this CTF writeup, we must enumerate the machine, when we run Nmap on the target, we get this output:


![Pasted image 20241023135604.png](../../IMAGES/Pasted%20image%2020241023135604.png)
So we got 3 open ports: 

```ad-note
1. 21: FTP
2. 22: SSH
3. 80: HTTP
```
## FUZZING

Nice, now let's try to enumerate our web server, for this, I used ffuf:

![Pasted image 20241023135712.png](../../IMAGES/Pasted%20image%2020241023135712.png)

And we found `/strange` directory, let's try to enumerate that directory using gobuster to check if we can find anything:

```ad-hint
gobuster command: `gobuster dir -u "http://172.17.0.2/strange" -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x gzip,7z,rar,txt,php,html`

EXPLANATION:

With this command, we are looking forward to enumerate the directory to check for any file with the extensions specified using the -x flag.
```

If we launch the gobuster command we get this:

![Pasted image 20241023135959.png](../../IMAGES/Pasted%20image%2020241023135959.png)

Seems like we have a `private.txt` file and a `secret.html` directory, let's check both, but, before that, let's try to check the page source for the website to check if we can get anything useful:

![Pasted image 20241023140149.png](../../IMAGES/Pasted%20image%2020241023140149.png)

`mwheeler` could be an username for either ftp or ssh, so, let's save it for later, now, let's check our files:

### SECRET.HTML

![Pasted image 20241023140240.png](../../IMAGES/Pasted%20image%2020241023140240.png)
## BRUTE FORCE

So, the FTP user is admin, if we use hydra to bruteforce our way in, we get this:

```ad-hint
hydra command: `hydra -l admin -P /usr/share/wordlists/rockyou.txt 172.17.0.2 ftp`

EXPLANATION

With this command, we are looking to bruteforce ftp knowing the username is admin, if FTP was located in another port, we need to specify the port using the `-s` flag
```

With the command, we get this output:

![Pasted image 20241023140748.png](../../IMAGES/Pasted%20image%2020241023140748.png)

So, our FTP admin user's password is `banana`

# EXPLOITATION

Now that we know the password, we can go into ftp and try to get any useful file:

![Pasted image 20241023140837.png](../../IMAGES/Pasted%20image%2020241023140837.png)

We found a `private_key.pem` file, let's download it using `get`
## DECRYPTION

Nice, but, seems like we are lacking something else, right, checking the `private.txt` file we downloaded earlier, if we try to read the file, it is encrypted:

![Pasted image 20241023141020.png](../../IMAGES/Pasted%20image%2020241023141020.png)

So, in order to read its contents, we would need to decrypt it, for example, let's use this command:

```ad-important
openssl: `openssl rsautl -decrypt -in private.txt -out privateOUT.txt -inkey private_key.pem`

EXPLANATION
- `rsautl`: OpenSSL command used for RSA operations.
- `-decrypt`: Specifies we are doing a decryption task.
- `-in private.txt`: Input file we are decrypting.
- `-out privateOUT.txt`: Output file we want to save the decrypted file.
- `-inkey private_key.pem`: Specifies the file which contains the private key needed for the decryption
```

If we run that command, we are now able to see the contents of our original file, if we read it, this is the output:

![Pasted image 20241023141405.png](../../IMAGES/Pasted%20image%2020241023141405.png)

Seems like the password for SSH, if we try user: `mwheeler` which we previously found on the source code of the page, we will log in to ssh:
![Pasted image 20241023141505.png](../../IMAGES/Pasted%20image%2020241023141505.png)

# PRIVILEGE ESCALATION

We got into the machine, let's escalate our privileges, for this, we can use the following commands:

```ad-important
BASIC PRIVESC LINUX COMMANDS: [[CyberSecurity/LINUX/LINUX PRIVILEGE ESCALATION/BASIC PRIVESC IN LINUX.md|Commands]]
```



After trying some commands, nothing useful came out of it, so, i checked my current directory using `pwd` and found I was in `mwheeler`home, I went back using `cd ..` and found there was 2 more homes:

![Pasted image 20241023142321.png](../../IMAGES/Pasted%20image%2020241023142321.png)
## SWITCHING USERS

Seems like we got `admin` and `ubuntu`, if server's bad configured, `admin` could be the same as FTP one, so, if we try to change user to it with the ftp password, we might get in:

![Pasted image 20241023142428.png](../../IMAGES/Pasted%20image%2020241023142428.png)


And I was right, like this, we could perform a simple PRIVESC without the need of `gtfobins` or some other website or tool, we can check we are root by checking the privileges of the user:

![Pasted image 20241023142527.png](../../IMAGES/Pasted%20image%2020241023142527.png)

Just like that, CTF is done!
