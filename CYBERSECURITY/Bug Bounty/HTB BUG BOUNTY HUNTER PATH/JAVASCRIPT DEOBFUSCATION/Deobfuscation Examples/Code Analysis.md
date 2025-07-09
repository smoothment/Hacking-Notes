---
sticker: lucide//code-2
---
Now that we have deobfuscated the code, we can start going through it:


```javascript
'use strict';
function generateSerial() {
  ...SNIP...
  var xhr = new XMLHttpRequest;
  var url = "/serial.php";
  xhr.open("POST", url, true);
  xhr.send(null);
};
```

We see that theÂ `secret.js`Â file contains only one function,Â `generateSerial`.

---

## HTTP Requests

Let us look at each line of theÂ `generateSerial`Â function.

#### Code Variables

The function starts by defining a variableÂ `xhr`, which creates an object ofÂ `XMLHttpRequest`. As we may not know exactly whatÂ `XMLHttpRequest`Â does in JavaScript, let us GoogleÂ `XMLHttpRequest`Â to see what it is used for.  
After we read about it, we see that it is a JavaScript function that handles web requests.

The second variable defined is theÂ `URL`Â variable, which contains a URL toÂ `/serial.php`, which should be on the same domain, as no domain was specified.

#### Code Functions

Next, we see thatÂ `xhr.open`Â is used withÂ `"POST"`Â andÂ `URL`. We can Google this function once again, and we see that it opens the HTTP request defined '`GET`Â orÂ `POST`' to theÂ `URL`, and then the next lineÂ `xhr.send`Â would send the request.

So, allÂ `generateSerial`Â is doing is simply sending aÂ `POST`Â request toÂ `/serial.php`, without including anyÂ `POST`Â data or retrieving anything in return.

The developers may have implemented this function whenever they need to generate a serial, like when clicking on a certainÂ `Generate Serial`Â button, for example. However, since we did not see any similar HTML elements that generate serials, the developers must not have used this function yet and kept it for future use.

With the use of code deobfuscation and code analysis, we were able to uncover this function. We can now attempt to replicate its functionality to see if it is handled on the server-side when sending aÂ `POST`Â request. If the function is enabled and handled on the server-side, we may uncover an unreleased functionality, which usually tends to have bugs and vulnerabilities within them.
