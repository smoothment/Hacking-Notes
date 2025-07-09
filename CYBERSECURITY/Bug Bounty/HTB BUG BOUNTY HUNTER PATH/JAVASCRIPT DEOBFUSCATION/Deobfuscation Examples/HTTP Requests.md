---
sticker: lucide//code-2
---
In the previous section, we found out that theÂ `secret.js`Â main function is sending an emptyÂ `POST`Â request toÂ `/serial.php`. In this section, we will attempt to do the same usingÂ `cURL`Â to send aÂ `POST`Â request toÂ `/serial.php`. To learn more aboutÂ `cURL`Â and web requests, you can check out theÂ [Web Requests](https://academy.hackthebox.com/module/details/35)Â module.

---

## cURL

`cURL`Â is a powerful command-line tool used in Linux distributions, macOS, and even the latest Windows PowerShell versions. We can request any website by simply providing its URL, and we would get it in text-format, as follows:



```shell-session
smoothment@htb[/htb]$ curl http://SERVER_IP:PORT/

</html>
<!DOCTYPE html>

<head>
    <title>Secret Serial Generator</title>
    <style>
        *,
        html {
            margin: 0;
            padding: 0;
            border: 0;
...SNIP...
        <h1>Secret Serial Generator</h1>
        <p>This page generates secret serials!</p>
    </div>
</body>

</html>
```

This is the sameÂ `HTML`Â we went through when we checked the source code in the first section.

---

## POST Request

To send aÂ `POST`Â request, we should add theÂ `-X POST`Â flag to our command, and it should send aÂ `POST`Â request:


```shell-session
smoothment@htb[/htb]$ curl -s http://SERVER_IP:PORT/ -X POST
```

Tip: We add the "-s" flag to reduce cluttering the response with unnecessary data

However,Â `POST`Â request usually containsÂ `POST`Â data. To send data, we can use the "`-d "param1=sample"`" flag and include our data for each parameter, as follows:


```shell-session
smoothment@htb[/htb]$ curl -s http://SERVER_IP:PORT/ -X POST -d "param1=sample"
```

Now that we know how to useÂ `cURL`Â to send basicÂ `POST`Â requests, in the next section, we will utilize this to replicate whatÂ `server.js`Â is doing to understand its purpose better.

# Question
---
![Pasted image 20250130134544.png](../../../../IMAGES/Pasted%20image%2020250130134544.png)

Let's perform the next curl request:

`curl -s "http://94.237.62.181:46963/serial.php" -X POST`

Since we don't need to send any data, let's just use a simple POST request:

![Pasted image 20250130134738.png](../../../../IMAGES/Pasted%20image%2020250130134738.png)

Answer is `N2gxNV8xNV9hX3MzY3IzN19tMzU1NGcz`
