Access control enforces policy such that users cannot act outside of their intended permissions. Failures typically lead to unauthorized information disclosure, modification, or destruction of all data or performing a business function outside the user's limits. Common access control vulnerabilities include:

- Violation of the principle of least privilege or deny by default, where access should only be granted for particular capabilities, roles, or users, but is available to anyone.
    
- Bypassing access control checks by modifying the URL (parameter tampering or force browsing), internal application state, or the HTML page, or by using an attack tool modifying API requests.
    
- Permitting viewing or editing someone else's account, by providing its unique identifier (insecure direct object references)
    
- Accessing API with missing access controls for POST, PUT and DELETE.
    
- Elevation of privilege. Acting as a user without being logged in or acting as an admin when logged in as a user.
    
- Metadata manipulation, such as replaying or tampering with a JSON Web Token (JWT) access control token, or a cookie or hidden field manipulated to elevate privileges or abusing JWT invalidation.
    
- CORS misconfiguration allows API access from unauthorized/untrusted origins.
    
- Force browsing to authenticated pages as an unauthenticated user or to privileged pages as a standard user.
    

## How to Prevent

Access control is only effective in trusted server-side code or server-less API, where the attacker cannot modify the access control check or metadata.

- Except for public resources, deny by default.
    
- Implement access control mechanisms once and re-use them throughout the application, including minimizing Cross-Origin Resource Sharing (CORS) usage.
    
- Model access controls should enforce record ownership rather than accepting that the user can create, read, update, or delete any record.
    
- Unique application business limit requirements should be enforced by domain models.
    
- Disable web server directory listing and ensure file metadata (e.g., .git) and backup files are not present within web roots.
    
- Log access control failures, alert admins when appropriate (e.g., repeated failures).
    
- Rate limit API and controller access to minimize the harm from automated attack tooling.
    
- Stateful session identifiers should be invalidated on the server after logout. Stateless JWT tokens should rather be short-lived so that the window of opportunity for an attacker is minimized. For longer lived JWTs it's highly recommended to follow the OAuth standards to revoke access.
    

Developers and QA staff should include functional access control unit and integration tests.

## Example Attack Scenarios

**Scenario #1:**Â The application uses unverified data in a SQL call that is accessing account information:

```
 pstmt.setString(1, request.getParameter("acct"));
 ResultSet results = pstmt.executeQuery( );
```

An attacker simply modifies the browser's 'acct' parameter to send whatever account number they want. If not correctly verified, the attacker can access any user's account.

```
 https://example.com/app/accountInfo?acct=notmyacct
```

**Scenario #2:**Â An attacker simply forces browses to target URLs. Admin rights are required for access to the admin page.

```
 https://example.com/app/getappInfo
 https://example.com/app/admin_getappInfo
```

If an unauthenticated user can access either page, it's a flaw. If a non-admin can access the admin page, this is a flaw.


# POC

<iframe width="1036" height="583" src="https://www.youtube.com/embed/2-VOSg8jDEw" title="Broken access control en aplicaciÃ³n WEB (demostraciÃ³n en vivo)" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" referrerpolicy="strict-origin-when-cross-origin" allowfullscreen></iframe>


# PORTSWIGGER LAB

PortswiggerÂ´s definition about access control says:


#### What is access control?

Access control is the application of constraints on who or what is authorized to perform actions or access resources. In the context of web applications, access control is dependent on authentication and session management:

    Authentication confirms that the user is who they say they are.
    Session management identifies which subsequent HTTP requests are being made by that same user.
    Access control determines whether the user is allowed to carry out the action that they are attempting to perform.

Broken access controls are common and often present a critical security vulnerability. Design and management of access controls is a complex and dynamic problem that applies business, organizational, and legal constraints to a technical implementation. Access control design decisions have to be made by humans so the potential for errors is high.
Access control vulnerability 

![Pasted image 20240918140537.png](../../../../IMAGES/Pasted%20image%2020240918140537.png)

#### Vertical privilege escalation


If a user can gain access to functionality that they are not permitted to access then this is vertical privilege escalation. For example, if a non-administrative user can gain access to an admin page where they can delete user accounts, then this is vertical privilege escalation.


#### Unprotected functionality

At its most basic, vertical privilege escalation arises where an application does not enforce any protection for sensitive functionality. For example, administrative functions might be linked from an administrator's welcome page but not from a user's welcome page. However, a user might be able to access the administrative functions by browsing to the relevant admin URL.

For example, a website might host sensitive functionality at the following URL:

https://insecure-website.com/admin

This might be accessible by any user, not only administrative users who have a link to the functionality in their user interface. In some cases, the administrative URL might be disclosed in other locations, such as the robots.txt file:

https://insecure-website.com/robots.txt

Even if the URL isn't disclosed anywhere, an attacker may be able to use a wordlist to brute-force the location of the sensitive functionality.

#### LAB 

##### Context:

![Pasted image 20240918140944.png](../../../../IMAGES/Pasted%20image%2020240918140944.png)

##### Burp request

![Pasted image 20240918141232.png](../../../../IMAGES/Pasted%20image%2020240918141232.png)

We can send to repeater and change the GET request, lets try `robots.txt` to see if we can read it:

##### Repeater


![Pasted image 20240918141314.png](../../../../IMAGES/Pasted%20image%2020240918141314.png)

And we are lucky, we can see it, now, we can see that there is an `/administrator-panel`, if we access it from the website, we find this:

![Pasted image 20240918141420.png](../../../../IMAGES/Pasted%20image%2020240918141420.png)

And we can delete user `Carlos`:

![Pasted image 20240918141447.png](../../../../IMAGES/Pasted%20image%2020240918141447.png)



### Unprotected functionality - Continued

In some cases, sensitive functionality is concealed by giving it a less predictable URL. This is an example of so-called "security by obscurity". However, hiding sensitive functionality does not provide effective access control because users might discover the obfuscated URL in a number of ways.

Imagine an application that hosts administrative functions at the following URL:
https://insecure-website.com/administrator-panel-yb556

This might not be directly guessable by an attacker. However, the application might still leak the URL to users. The URL might be disclosed in JavaScript that constructs the user interface based on the user's role:
<script>
	var isAdmin = false;
	if (isAdmin) {
		...
		var adminPanelTag = document.createElement('a');
		adminPanelTag.setAttribute('https://insecure-website.com/administrator-panel-yb556');
		adminPanelTag.innerText = 'Admin panel';
		...
	}
</script>

This script adds a link to the user's UI if they are an admin user. However, the script containing the URL is visible to all users regardless of their role.

#### LAB




![Pasted image 20240918143545.png](../../../../IMAGES/Pasted%20image%2020240918143545.png)

##### Source code:


![Pasted image 20240918143926.png](../../../../IMAGES/Pasted%20image%2020240918143926.png)

We found `/admin-t8859k`


##### Deleting user:

![Pasted image 20240918144012.png](../../../../IMAGES/Pasted%20image%2020240918144012.png)
![Pasted image 20240918144028.png](../../../../IMAGES/Pasted%20image%2020240918144028.png)



## Parameter-based access control methods


Some applications determine the user's access rights or role at login, and then store this information in a user-controllable location. This could be:

    A hidden field.
    A cookie.
    A preset query string parameter.

The application makes access control decisions based on the submitted value. For example:
https://insecure-website.com/login/home.jsp?admin=true
https://insecure-website.com/login/home.jsp?role=1

This approach is insecure because a user can modify the value and access functionality they're not authorized to, such as administrative functions.



### LAB

![Pasted image 20240918144413.png](../../../../IMAGES/Pasted%20image%2020240918144413.png)

###### Login

![Pasted image 20240918144608.png](../../../../IMAGES/Pasted%20image%2020240918144608.png)

When we login, we can find this in burp: 


If we pass the request to burp, we get this: 


![Pasted image 20240918163348.png](../../../../IMAGES/Pasted%20image%2020240918163348.png)

If we change: `Admin=true` we are now able to access `/admin` panel:


![Pasted image 20240918163719.png](../../../../IMAGES/Pasted%20image%2020240918163719.png)
![Pasted image 20240918163807.png](../../../../IMAGES/Pasted%20image%2020240918163807.png)
![Pasted image 20240918163942.png](../../../../IMAGES/Pasted%20image%2020240918163942.png)
There we go, we can now access the panel and delete username Carlos.


## Horizontal privilege escalation

Horizontal privilege escalation occurs if a user is able to gain access to resources belonging to another user, instead of their own resources of that type. For example, if an employee can access the records of other employees as well as their own, then this is horizontal privilege escalation.

Horizontal privilege escalation attacks may use similar types of exploit methods to vertical privilege escalation. For example, a user might access their own account page using the following URL:
https://insecure-website.com/myaccount?id=123

If an attacker modifies the id parameter value to that of another user, they might gain access to another user's account page, and the associated data and functions.
Note

This is an example of an insecure direct object reference (IDOR) vulnerability. This type of vulnerability arises where user-controller parameter values are used to access resources or functions directly.

In some applications, the exploitable parameter does not have a predictable value. For example, instead of an incrementing number, an application might use globally unique identifiers (GUIDs) to identify users. This may prevent an attacker from guessing or predicting another user's identifier. However, the GUIDs belonging to other users might be disclosed elsewhere in the application where users are referenced, such as user messages or reviews.

##### Lab

![Pasted image 20240918165253.png](../../../../IMAGES/Pasted%20image%2020240918165253.png)

When we log in, we face an unpredictable userID request system, every time you make a login request, a random userID, is assigned to you, so, if we go to home page, we can find some posts, in which, administrator's userID is leaked by using burp:

![Pasted image 20240918165829.png](../../../../IMAGES/Pasted%20image%2020240918165829.png)

![Pasted image 20240918165853.png](../../../../IMAGES/Pasted%20image%2020240918165853.png)
We can see our admin userID right there, lets change it from our account to finish the lab:

![Pasted image 20240918165954.png](../../../../IMAGES/Pasted%20image%2020240918165954.png)
But careful, if we try to submit this API key, we will get an error because we need `carlos` API not admin, so lets, repeat exercise but with a post from `carlos`:
![Pasted image 20240918170150.png](../../../../IMAGES/Pasted%20image%2020240918170150.png)
![Pasted image 20240918170220.png](../../../../IMAGES/Pasted%20image%2020240918170220.png)




## Horizontal to vertical privilege escalation

Often, a horizontal privilege escalation attack can be turned into a vertical privilege escalation, by compromising a more privileged user. For example, a horizontal escalation might allow an attacker to reset or capture the password belonging to another user. If the attacker targets an administrative user and compromises their account, then they can gain administrative access and so perform vertical privilege escalation.

An attacker might be able to gain access to another user's account page using the parameter tampering technique already described for horizontal privilege escalation:
https://insecure-website.com/myaccount?id=456

If the target user is an application administrator, then the attacker will gain access to an administrative account page. This page might disclose the administrator's password or provide a means of changing it, or might provide direct access to privileged functionality.


#### Lab
![Pasted image 20240918170422.png](../../../../IMAGES/Pasted%20image%2020240918170422.png)

When we login, we can find that we can change our account id:
![Pasted image 20240918170659.png](../../../../IMAGES/Pasted%20image%2020240918170659.png)

In the image, I've already changed it from wiener to administrator, there, we can change password, lets use burp to see the request:

![Pasted image 20240918171009.png](../../../../IMAGES/Pasted%20image%2020240918171009.png)

If we login with that password, we are inside admin account:
![Pasted image 20240918171340.png](../../../../IMAGES/Pasted%20image%2020240918171340.png)
![Pasted image 20240918171346.png](../../../../IMAGES/Pasted%20image%2020240918171346.png)
![Pasted image 20240918171355.png](../../../../IMAGES/Pasted%20image%2020240918171355.png)




# IDOR CHALLENGE


**IDOR**Â orÂ **Insecure Direct Object Reference**Â refersÂ to an access control vulnerability where you can access resources you wouldn't ordinarily be able to see. This occurs when the programmer exposes a Direct Object Reference, which is just an identifier that refers to specific objects within the server. By object, we could mean a file, a user, a bank account in a banking application, or anything really.

For example, let's say we're logging into our bank account, and after correctly authenticating ourselves, we get taken to a URL like thisÂ `https://bank.thm/account?id=111111`. On that page, we can see all our important bank details, and a user would do whatever they need to do and move along their way, thinking nothing is wrong.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/0ddb5676eebdb367bff750717268b82b.png)  

There is, however, a potentially huge problem here, anyone may be able to change theÂ `id`Â parameter to something else likeÂ `222222`, and if the site is incorrectly configured, then he would have access to someone else's bank information.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/42a83d8c119295a79dfcab36b7e4d105.png)

The application exposes a direct object reference through theÂ `id` parameter in the URL, which points to specific accounts. Since the application isn't checking if the logged-in user owns the referenced account, an attacker can get sensitive information from other users because of the IDOR vulnerability. Notice that direct object references aren't the problem, but rather that the application doesn't validate if the logged-in user should have access to the requested account.













