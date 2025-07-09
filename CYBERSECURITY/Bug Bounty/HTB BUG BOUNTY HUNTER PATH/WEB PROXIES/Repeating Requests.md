---
aliases:
  - Repeating Requests
sticker: emoji//1f525
---
In the previous sections, we successfully bypassed the input validation to use a non-numeric input to reach command injection on the remote server. If we want to repeat the same process with a different command, we would have to intercept the request again, provide a different payload, forward it again, and finally check our browser to get the final result.

As you can imagine, if we would do this for each command, it would take us forever to enumerate a system, as each command would require 5-6 steps to get executed. However, for such repetitive tasks, we can utilize request repeating to make this process significantly easier.

Request repeating allows us to resend any web request that has previously gone through the web proxy. This allows us to make quick changes to any request before we send it, then get the response within our tools without intercepting and modifying each request.

---

## Proxy History

To start, we can view the HTTP requests history inÂ `Burp`Â at (`Proxy>HTTP History`):

![Burp history tab](https://academy.hackthebox.com/storage/modules/110/burp_history_tab.jpg)

InÂ `ZAP`Â HUD, we can find it in the bottom History pane or ZAP's main UI at the bottomÂ `History`Â tab as well:

![ZAP history tab](https://academy.hackthebox.com/storage/modules/110/zap_history_tab.jpg)

Both tools also provide filtering and sorting options for requests history, which may be helpful if we deal with a huge number of requests and want to locate a specific request.Â `Try to see how filters work on both tools.`

Note: Both tools also maintain WebSockets history, which shows all connections initiated by the web application even after being loaded, like asynchronous updates and data fetching. WebSockets can be useful when performing advanced web penetration testing, and are out of the scope of this module.

If we click on any request in the history in either tool, its details will be shown:

`Burp`:Â ![Burp request details](https://academy.hackthebox.com/storage/modules/110/burp_history_details.jpg)

`ZAP`:Â ![ZAP request details](https://academy.hackthebox.com/storage/modules/110/zap_history_details.jpg)

Tip: While ZAP only shows the final/modified request that was sent, Burp provides the ability to examine both the original request and the modified request. If a request was edited, the pane header would sayÂ `Original Request`, and we can click on it and selectÂ `Edited Request`Â to examine the final request that was sent.

---

## Repeating Requests

#### Burp

Once we locate the request we want to repeat, we can click [`CTRL+R`] in Burp to send it to theÂ `Repeater`Â tab, and then we can either navigate to theÂ `Repeater`Â tab or click [`CTRL+SHIFT+R`] to go to it directly. Once inÂ `Repeater`, we can click onÂ `Send`Â to send the request:

![Burp repeat request](https://academy.hackthebox.com/storage/modules/110/burp_repeater_request.jpg)

Tip: We can also right-click on the request and selectÂ `Change Request Method`Â to change the HTTP method between POST/GET without having to rewrite the entire request.

#### ZAP

In ZAP, once we locate our request, we can right-click on it and selectÂ `Open/Resend with Request Editor`, which would open the request editor window, and allow us to resend the request with theÂ `Send`Â button to send our request:Â ![ZAP resend request](https://academy.hackthebox.com/storage/modules/110/zap_repeater_request.jpg)

We can also see theÂ `Method`Â drop-down menu, allowing us to quickly switch the request method to any other HTTP method.

Tip: By default, the Request Editor window in ZAP has the Request/Response in different tabs. You can click on the display buttons to change how they are organized. To match the above look choose the same display options shown in the screenshot.

We can achieve the same result within the pre-configured browser withÂ `ZAP HUD`. We can locate the request in the bottom History pane, and once we click on it, theÂ `Request Editor`Â window will show, allowing us to resend it. We can selectÂ `Replay in Console`Â to get the response in the sameÂ `HUD`Â window, or selectÂ `Replay in Browser`Â to see the response rendered in the browser:

![ZAP HUD resend](https://academy.hackthebox.com/storage/modules/110/zap_hud_resend.jpg)

So, let us try to modify our request and send it. In all three options (`Burp Repeater`,Â `ZAP Request Editor`, andÂ `ZAP HUD`), we see that the requests are modifiable, and we can select the text we want to change and replace it with whatever we want, and then click theÂ `Send`Â button to send it again:

![Burp modify repeat](https://academy.hackthebox.com/storage/modules/110/burp_repeat_modify.jpg)

As we can see, we could easily modify the command and instantly get its output by using BurpÂ `Repeater`. Try doing the same inÂ `ZAP Request Editor`Â andÂ `ZAP HUD`Â to see how they work.

Finally, we can see in our previous POST request that the data is URL-encoded. This is an essential part of sending custom HTTP requests, which we will discuss in the next section.

# Question
---

![Pasted image 20250124101727.png](../../../IMAGES/Pasted%20image%2020250124101727.png)

As shown in the lesson, we can use command injection in order to retrieve data from the server, let's use `1;ls+-la;` to check the files:

![Pasted image 20250124101809.png](../../../IMAGES/Pasted%20image%2020250124101809.png)

But this is the flag from a previous exercise, we need to look around the other flag, let's follow these steps:

```ad-summary
1. `1;pwd;`
2. `1;ls+/;`
3. `1;cat+/flag.txt;`
```

If we follow these steps we can see the following:

![Pasted image 20250124102326.png](../../../IMAGES/Pasted%20image%2020250124102326.png)

As expected, we are in `/var/www/html`, other flag must be in a different directory, my next step would be verifying what does `/` contain:

![Pasted image 20250124102434.png](../../../IMAGES/Pasted%20image%2020250124102434.png)

We have the flag, let's simply read it:

![Pasted image 20250124102457.png](../../../IMAGES/Pasted%20image%2020250124102457.png)

Flag is `HTB{qu1ckly_r3p3471n6_r3qu3575}`
