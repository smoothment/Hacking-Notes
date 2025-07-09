---
sticker: lucide//curly-braces
---

Another major aspect of front end security is validating and sanitizing accepted user input. In many cases, user input validation and sanitization is carried out on the back end. However, some user input would never make it to the back end in some cases and is completely processed and rendered on the front end. Therefore, it is critical to validate and sanitize user input on both the front end and the back end.

[HTML injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/03-Testing_for_HTML_Injection)Â occurs when unfiltered user input is displayed on the page. This can either be through retrieving previously submitted code, like retrieving a user comment from the back end database, or by directly displaying unfiltered user input throughÂ `JavaScript`Â on the front end.

When a user has complete control of how their input will be displayed, they can submitÂ `HTML`Â code, and the browser may display it as part of the page. This may include a maliciousÂ `HTML`Â code, like an external login form, which can be used to trick users into logging in while actually sending their login credentials to a malicious server to be collected for other attacks.

Another example ofÂ `HTML Injection`Â is web page defacing. This consists of injecting newÂ `HTML`Â code to change the web page's appearance, inserting malicious ads, or even completely changing the page. This type of attack can result in severe reputational damage to the company hosting the web application.

---

#### Example

The following example is a very basic web page with a single button "`Click to enter your name`." When we click on the button, it prompts us to input our name and then displays our name as "`Your name is ...`":

![HTML Example](https://academy.hackthebox.com/storage/modules/75/web_apps_html_injection_5.jpg)

If no input sanitization is in place, this is potentially an easy target forÂ `HTML Injection`Â andÂ `Cross-Site Scripting (XSS)`Â attacks. We take a look at the page source code and see no input sanitization in place whatsoever, as the page takes user input and directly displays it:

Code:Â html

```html
<!DOCTYPE html>
<html>

<body>
    <button onclick="inputFunction()">Click to enter your name</button>
    <p id="output"></p>

    <script>
        function inputFunction() {
            var input = prompt("Please enter your name", "");

            if (input != null) {
                document.getElementById("output").innerHTML = "Your name is " + input;
            }
        }
    </script>
</body>

</html>
```

To test forÂ `HTML Injection`, we can simply input a small snippet ofÂ `HTML`Â code as our name, and see if it is displayed as part of the page. We will test the following code, which changes the background image of the web page:

Code:Â html

```html
<style> body { background-image: url('https://academy.hackthebox.com/images/logo.svg'); } </style>
```

Once we input it, we see that the web page's background image changes instantly:

![HTML Example](https://academy.hackthebox.com/storage/modules/75/web_apps_html_injection_6.jpg)

In this example, as everything is being carried out on the front end, refreshing the web page would reset everything back to normal.

# Question

![Pasted image 20250122182012.png](../../../IMAGES/Pasted%20image%2020250122182012.png)

![Pasted image 20250122182036.png](../../../IMAGES/Pasted%20image%2020250122182036.png)

The text that appears is the following:

![Pasted image 20250122182120.png](../../../IMAGES/Pasted%20image%2020250122182120.png)

Then, answer is: `Your name is Click Me`
