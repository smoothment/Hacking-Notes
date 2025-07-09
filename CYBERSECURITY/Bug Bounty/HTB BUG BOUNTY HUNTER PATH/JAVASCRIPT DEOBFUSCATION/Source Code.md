---
sticker: lucide//code-2
---
Most websites nowadays utilize JavaScript to perform their functions. WhileÂ `HTML`Â is used to determine the website's main fields and parameters, andÂ `CSS`Â is used to determine its design,Â `JavaScript`Â is used to perform any functions necessary to run the website. This happens in the background, and we only see the pretty front-end of the website and interact with it.

Even though all of this source code is available at the client-side, it is rendered by our browsers, so we do not often pay attention to the HTML source code. However, if we wanted to understand a certain page's client-side functionalities, we usually start by taking a look at the page's source code. This section will show how we can uncover the source code that contains all of this and understand its general usage.

---

## HTML

We will start by starting the exercise below, open Firefox in our PwnBox, and visit the URL shown in the question:

Â Â Â 

![](https://academy.hackthebox.com/storage/modules/41/js_deobf_mainsite.jpg)

As we can see, the website saysÂ `Secret Serial Generator`, without having any input fields or showing any clear functionality. So, our next step is to peak at its source code. We can do that by pressingÂ `[CTRL + U]`, which should open the source view of the website:

Â Â Â 

![](https://academy.hackthebox.com/storage/modules/41/js_deobf_mainsite_source_1.jpg)

As we can see, we can view theÂ `HTML`Â source code of the website.

---

## CSS

`CSS`Â code is either definedÂ `internally`Â within the sameÂ `HTML`Â file betweenÂ `<style>`Â elements, or definedÂ `externally`Â in a separateÂ `.css`Â file and referenced within theÂ `HTML`Â code.

In this case, we see that theÂ `CSS`Â is internally defined, as seen in the code snippet below:

Code:Â html

```html
    <style>
        *,
        html {
            margin: 0;
            padding: 0;
            border: 0;
        }
        ...SNIP...
        h1 {
            font-size: 144px;
        }
        p {
            font-size: 64px;
        }
    </style>
```

If a pageÂ `CSS`Â style is externally defined, the externalÂ `.css`Â file is referred to with theÂ `<link>`Â tag within the HTML head, as follows:



```html
<head>
    <link rel="stylesheet" href="style.css">
</head>
```

---

## JavaScript

The same concept applies toÂ `JavaScript`. It can be internally written betweenÂ `<script>`Â elements or written into a separateÂ `.js`Â file and referenced within theÂ `HTML`Â code.

We can see in ourÂ `HTML`Â source that theÂ `.js`Â file is referenced externally:

```html
<script src="secret.js"></script>
```

We can check out the script by clicking onÂ `secret.js`, which should take us directly into the script. When we visit it, we see that the code is very complicated and cannot be comprehended:


```javascript
eval(function (p, a, c, k, e, d) { e = function (c) { '...SNIP... |true|function'.split('|'), 0, {}))
```

The reason behind this isÂ `code obfuscation`. What is it? How is it done? Where is it used?

# Question
---
![Pasted image 20250130132433.png](../../../IMAGES/Pasted%20image%2020250130132433.png)
![Pasted image 20250130132455.png](../../../IMAGES/Pasted%20image%2020250130132455.png)


Flag is: `HTB{4lw4y5_r34d_7h3_50urc3}`
