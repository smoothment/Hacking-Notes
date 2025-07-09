In the previous section, we saw several types of attacks that we can use for different types of LFI vulnerabilities. In many cases, we may be facing a web application that applies various protections against file inclusion, so our normal LFI payloads would not work. Still, unless the web application is properly secured against malicious LFI user input, we may be able to bypass the protections in place and reach file inclusion.

---

## Non-Recursive Path Traversal Filters

One of the most basic filters against LFI is a search and replace filter, where it simply deletes substrings of (`../`) to avoid path traversals. For example:

```php
$language = str_replace('../', '', $_GET['language']);
```

The above code is supposed to prevent path traversal, and hence renders LFI useless. If we try the LFI payloads we tried in the previous section, we get the following:


![](https://academy.hackthebox.com/storage/modules/23/lfi_blacklist.png)

We see that allÂ `../`Â substrings were removed, which resulted in a final path beingÂ `./languages/etc/passwd`. However, this filter is very insecure, as it is notÂ `recursively removing`Â theÂ `../`Â substring, as it runs a single time on the input string and does not apply the filter on the output string. For example, if we useÂ `....//`Â as our payload, then the filter would removeÂ `../`Â and the output string would beÂ `../`, which means we may still perform path traversal. Let's try applying this logic to includeÂ `/etc/passwd`Â again:

```
http://<SERVER_IP>:<PORT>/index.php?language=....//....//....//....//etc/passwd
```

![](https://academy.hackthebox.com/storage/modules/23/lfi_blacklist_passwd.png)

As we can see, the inclusion was successful this time, and we're able to readÂ `/etc/passwd`Â successfully. TheÂ `....//`Â substring is not the only bypass we can use, as we may useÂ `..././`Â orÂ `....\/`Â and several other recursive LFI payloads. Furthermore, in some cases, escaping the forward slash character may also work to avoid path traversal filters (e.g.Â `....\/`), or adding extra forward slashes (e.g.Â `....////`)

---

## Encoding

Some web filters may prevent input filters that include certain LFI-related characters, like a dotÂ `.`Â or a slashÂ `/`Â used for path traversals. However, some of these filters may be bypassed by URL encoding our input, such that it would no longer include these bad characters, but would still be decoded back to our path traversal string once it reaches the vulnerable function. Core PHP filters on versions 5.3.4 and earlier were specifically vulnerable to this bypass, but even on newer versions we may find custom filters that may be bypassed through URL encoding.

If the target web application did not allowÂ `.`Â andÂ `/`Â in our input, we can URL encodeÂ `../`Â intoÂ `%2e%2e%2f`, which may bypass the filter. To do so, we can use any online URL encoder utility or use the Burp Suite Decoder tool, as follows:Â 

![burp_url_encode](https://academy.hackthebox.com/storage/modules/23/burp_url_encode.jpg)

**Note:**Â For this to work we must URL encode all characters, including the dots. Some URL encoders may not encode dots as they are considered to be part of the URL scheme.

Let's try to use this encoded LFI payload against our earlier vulnerable web application that filtersÂ `../`Â strings:

Â Â Â 
```
<SERVER_IP>:<PORT>/index.php?language=%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%65%74%63%2f%70%61%73%73%77%64
```
![](https://academy.hackthebox.com/storage/modules/23/lfi_blacklist_passwd_filter.png)

As we can see, we were also able to successfully bypass the filter and use path traversal to readÂ `/etc/passwd`. Furthermore, we may also use Burp Decoder to encode the encoded string once again to have aÂ `double encoded`Â string, which may also bypass other types of filters.

You may refer to theÂ [Command Injections](https://academy.hackthebox.com/module/details/109)Â module for more about bypassing various blacklisted characters, as the same techniques may be used with LFI as well.

---

## Approved Paths

Some web applications may also use Regular Expressions to ensure that the file being included is under a specific path. For example, the web application we have been dealing with may only accept paths that are under theÂ `./languages`Â directory, as follows:

```php
if(preg_match('/^\.\/languages\/.+$/', $_GET['language'])) {
    include($_GET['language']);
} else {
    echo 'Illegal path specified!';
}
```

To find the approved path, we can examine the requests sent by the existing forms, and see what path they use for the normal web functionality. Furthermore, we can fuzz web directories under the same path, and try different ones until we get a match. To bypass this, we may use path traversal and start our payload with the approved path, and then useÂ `../`Â to go back to the root directory and read the file we specify, as follows:

```
<SERVER_IP>:<PORT>/index.php?language=./languages/../../../../etc/passwd
```
![](https://academy.hackthebox.com/storage/modules/23/lfi_blacklist_passwd_filter.png)

Some web applications may apply this filter along with one of the earlier filters, so we may combine both techniques by starting our payload with the approved path, and then URL encode our payload or use recursive payload.

**Note:**Â All techniques mentioned so far should work with any LFI vulnerability, regardless of the back-end development language or framework.

---

## Appended Extension

As discussed in the previous section, some web applications append an extension to our input string (e.g.Â `.php`), to ensure that the file we include is in the expected extension. With modern versions of PHP, we may not be able to bypass this and will be restricted to only reading files in that extension, which may still be useful, as we will see in the next section (e.g. for reading source code).

There are a couple of other techniques we may use, but they areÂ `obsolete with modern versions of PHP and only work with PHP versions before 5.3/5.4`. However, it may still be beneficial to mention them, as some web applications may still be running on older servers, and these techniques may be the only bypasses possible.

#### Path Truncation

In earlier versions of PHP, defined strings have a maximum length of 4096 characters, likely due to the limitation of 32-bit systems. If a longer string is passed, it will simply beÂ `truncated`, and any characters after the maximum length will be ignored. Furthermore, PHP also used to remove trailing slashes and single dots in path names, so if we call (`/etc/passwd/.`) then theÂ `/.`Â would also be truncated, and PHP would call (`/etc/passwd`). PHP, and Linux systems in general, also disregard multiple slashes in the path (e.g.Â `////etc/passwd`Â is the same asÂ `/etc/passwd`). Similarly, a current directory shortcut (`.`) in the middle of the path would also be disregarded (e.g.Â `/etc/./passwd`).

If we combine both of these PHP limitations together, we can create very long strings that evaluate to a correct path. Whenever we reach the 4096 character limitation, the appended extension (`.php`) would be truncated, and we would have a path without an appended extension. Finally, it is also important to note that we would also need toÂ `start the path with a non-existing directory`Â for this technique to work.

An example of such payload would be the following:


```url
?language=non_existing_directory/../../../etc/passwd/./././.[./ REPEATED ~2048 times]
```

Of course, we don't have to manually typeÂ `./`Â 2048 times (total of 4096 characters), but we can automate the creation of this string with the following command:


```shell-session
smoothment@htb[/htb]$ echo -n "non_existing_directory/../../../etc/passwd/" && for i in {1..2048}; do echo -n "./"; done
non_existing_directory/../../../etc/passwd/./././<SNIP>././././
```

We may also increase the count ofÂ `../`, as adding more would still land us in the root directory, as explained in the previous section. However, if we use this method, we should calculate the full length of the string to ensure onlyÂ `.php`Â gets truncated and not our requested file at the end of the string (`/etc/passwd`). This is why it would be easier to use the first method.

#### Null Bytes

PHP versions before 5.5 were vulnerable toÂ `null byte injection`, which means that adding a null byte (`%00`) at the end of the string would terminate the string and not consider anything after it. This is due to how strings are stored in low-level memory, where strings in memory must use a null byte to indicate the end of the string, as seen in Assembly, C, or C++ languages.

To exploit this vulnerability, we can end our payload with a null byte (e.g.Â `/etc/passwd%00`), such that the final path passed toÂ `include()`Â would be (`/etc/passwd%00.php`). This way, even thoughÂ `.php`Â is appended to our string, anything after the null byte would be truncated, and so the path used would actually beÂ `/etc/passwd`, leading us to bypass the appended extension.

# Question
---
![Pasted image 20250218142549.png](../../../../IMAGES/Pasted%20image%2020250218142549.png)

Let's check the request:

![Pasted image 20250218142647.png](../../../../IMAGES/Pasted%20image%2020250218142647.png)

We can see the format's changed, let's try some payloads:

```
c
```

![Pasted image 20250218143026.png](../../../../IMAGES/Pasted%20image%2020250218143026.png)

Path is right in this case, if we try moving to another path, we get the following:

![Pasted image 20250218143054.png](../../../../IMAGES/Pasted%20image%2020250218143054.png)

So, we must construct another payload based on the previous one, let's go with the following one:

```
languages//....//....///....//....//etc/passwd 
```

![Pasted image 20250218143205.png](../../../../IMAGES/Pasted%20image%2020250218143205.png)

And it worked!, we were able to read `/etc/passwd`, knowing this, we're able to read our flag:

```
languages//....//....///....//....//flag.txt
```

![Pasted image 20250218143249.png](../../../../IMAGES/Pasted%20image%2020250218143249.png)

Flag is:

```
HTB{64$!c_f!lt3r$_w0nt_$t0p_lf!}
```

