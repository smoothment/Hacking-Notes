---
aliases:
  - Burp Intruder
sticker: emoji//1f525
---
Both Burp and ZAP provide additional features other than the default web proxy, which are essential for web application penetration testing. Two of the most important extra features areÂ `web fuzzers`Â andÂ `web scanners`. The built-in web fuzzers are powerful tools that act as web fuzzing, enumeration, and brute-forcing tools. This may also act as an alternative for many of the CLI-based fuzzers we use, likeÂ `ffuf`,Â `dirbuster`,Â `gobuster`,Â `wfuzz`, among others.

Burp's web fuzzer is calledÂ `Burp Intruder`, and can be used to fuzz pages, directories, sub-domains, parameters, parameters values, and many other things. Though it is much more advanced than most CLI-based web fuzzing tools, the freeÂ `Burp Community`Â version is throttled at a speed of 1 request per second, making it extremely slow compared to CLI-based web fuzzing tools, which can usually read up to 10k requests per second. This is why we would only use the free version of Burp Intruder for short queries. TheÂ `Pro`Â version has unlimited speed, which can rival common web fuzzing tools, in addition to the very useful features of Burp Intruder. This makes it one of the best web fuzzing and brute-forcing tools.

In this section, we will demonstrate the various uses of Burp Intruder for web fuzzing and enumeration.

---

## Target

As usual, we'll start up Burp and its pre-configured browser and then visit the web application from the exercise at the end of this section. Once we do, we can go to the Proxy History, locate our request, then right-click on the request and selectÂ `Send to Intruder`, or use the shortcut [`CTRL+I`] to send it toÂ `Intruder`.

We can then go toÂ `Intruder`Â by clicking on its tab or with the shortcut [`CTRL+SHIFT+I`], which takes us right toÂ `Burp Intruder`:

![intruder_target](https://academy.hackthebox.com/storage/modules/110/burp_intruder_target.jpg)

On the first tab, '`Target`', we see the details of the target we will be fuzzing, which is fed from the request we sent toÂ `Intruder`.

---

## Positions

The second tab, '`Positions`', is where we place the payload position pointer, which is the point where words from our wordlist will be placed and iterated over. We will be demonstrating how to fuzz web directories, which is similar to what's done by tools likeÂ `ffuf`Â orÂ `gobuster`.

To check whether a web directory exists, our fuzzing should be in '`GET /DIRECTORY/`', such that existing pages would returnÂ `200 OK`, otherwise we'd getÂ `404 NOT FOUND`. So, we will need to selectÂ `DIRECTORY`Â as the payload position, by either wrapping it withÂ `Â§`Â or by selecting the wordÂ `DIRECTORY`Â and clicking on theÂ `Add Â§`Â button:

![intruder_position](https://academy.hackthebox.com/storage/modules/110/burp_intruder_position.jpg)

Tip: theÂ `DIRECTORY`Â in this case is the pointer's name, which can be anything, and can be used to refer to each pointer, in case we are using more than position with different wordlists for each.

The final thing to select in the target tab is theÂ `Attack Type`. The attack type defines how many payload pointers are used and determines which payload is assigned to which position. For simplicity, we'll stick to the first type,Â `Sniper`, which uses only one position. Try clicking on theÂ `?`Â at the top of the window to read more about attack types, or check out thisÂ [link](https://portswigger.net/burp/documentation/desktop/tools/intruder/positions#attack-type).

Note: Be sure to leave the extra two lines at the end of the request, otherwise we may get an error response from the server.

---

## Payloads

On the third tab, '`Payloads`', we get to choose and customize our payloads/wordlists. This payload/wordlist is what would be iterated over, and each element/line of it would be placed and tested one by one in the Payload Position we chose earlier. There are four main things we need to configure:

- Payload Sets
- Payload Options
- Payload Processing
- Payload Encoding

#### Payload Sets

The first thing we must configure is theÂ `Payload Set`. The payload set identifies the Payload number, depending on the attack type and number of Payloads we used in the Payload Position Pointers:

![Payload Sets](https://academy.hackthebox.com/storage/modules/110/burp_intruder_payload_set.jpg)

In this case, we only have one Payload Set, as we chose the '`Sniper`' Attack type with only one payload position. If we have chosen the '`Cluster Bomb`' attack type, for example, and added several payload positions, we would get more payload sets to choose from and choose different options for each. In our case, we'll selectÂ `1`Â for the payload set.

Next, we need to select theÂ `Payload Type`, which is the type of payloads/wordlists we will be using. Burp provides a variety of Payload Types, each of which acts in a certain way. For example:

```ad-summary
- `Simple List`: The basic and most fundamental type. We provide a wordlist, and Intruder iterates over each line in it.
    
- `Runtime file`: Similar toÂ `Simple List`, but loads line-by-line as the scan runs to avoid excessive memory usage by Burp.
    
- `Character Substitution`: Lets us specify a list of characters and their replacements, and Burp Intruder tries all potential permutations.
```
    

There are many other Payload Types, each with its own options, and many of which can build custom wordlists for each attack. Try clicking on theÂ `?`Â next toÂ `Payload Sets`, and then click onÂ `Payload Type`, to learn more about each Payload Type. In our case, we'll be going with a basicÂ `Simple List`.

#### Payload Options

Next, we must specify the Payload Options, which is different for each Payload Type we select inÂ `Payload Sets`. For aÂ `Simple List`, we have to create or load a wordlist. To do so, we can input each item manually by clickingÂ `Add`, which would build our wordlist on the fly. The other more common option is to click onÂ `Load`, and then select a file to load into Burp Intruder.

We will selectÂ `/opt/useful/seclists/Discovery/Web-Content/common.txt`Â as our wordlist. We can see that Burp Intruder loads all lines of our wordlist into the Payload Options table:

![Payload Options](https://academy.hackthebox.com/storage/modules/110/burp_intruder_payload_wordlist.jpg)

We can add another wordlist or manually add a few items, and they would be appended to the same list of items. We can use this to combine multiple wordlists or create customized wordlists. In Burp Pro, we also can select from a list of existing wordlists contained within Burp by choosing from theÂ `Add from list`Â menu option.

Tip: In case you wanted to use a very large wordlist, it's best to useÂ `Runtime file`Â as the Payload Type instead ofÂ `Simple List`, so that Burp Intruder won't have to load the entire wordlist in advance, which may throttle memory usage.

#### Payload Processing

Another option we can apply isÂ `Payload Processing`, which allows us to determine fuzzing rules over the loaded wordlist. For example, if we wanted to add an extension after our payload item, or if we wanted to filter the wordlist based on specific criteria, we can do so with payload processing.

Let's try adding a rule that skips any lines that start with aÂ `.`Â (as shown in the wordlist screenshot earlier). We can do that by clicking on theÂ `Add`Â button and then selectingÂ `Skip if matches regex`, which allows us to provide a regex pattern for items we want to skip. Then, we can provide a regex pattern that matches lines starting withÂ `.`, which is:Â `^\..*$`:

![payload processing](https://academy.hackthebox.com/storage/modules/110/burp_intruder_payload_processing_1.jpg)

We can see that our rule gets added and enabled:Â ![payload processing](https://academy.hackthebox.com/storage/modules/110/burp_intruder_payload_processing_2.jpg)

#### Payload Encoding

The fourth and final option we can apply isÂ `Payload Encoding`, enabling us to enable or disable Payload URL-encoding.

![payload encoding](https://academy.hackthebox.com/storage/modules/110/burp_intruder_payload_encoding.jpg)

We'll leave it enabled.

---

## Options

Finally, we can customize our attack options from theÂ `Options`Â tab. There are many options we can customize (or leave at default) for our attack. For example, we can set the number ofÂ `retried on failure`Â andÂ `pause before retry`Â to 0.

Another useful option is theÂ `Grep - Match`, which enables us to flag specific requests depending on their responses. As we are fuzzing web directories, we are only interested in responses with HTTP codeÂ `200 OK`. So, we'll first enable it and then clickÂ `Clear`Â to clear the current list. After that, we can typeÂ `200 OK`Â to match any requests with this string and clickÂ `Add`Â to add the new rule. Finally, we'll also disableÂ `Exclude HTTP Headers`, as what we are looking for is in the HTTP header:

![options match](https://academy.hackthebox.com/storage/modules/110/burp_intruder_options_match.jpg)

We may also utilize theÂ `Grep - Extract`Â option, which is useful if the HTTP responses are lengthy, and we're only interested in a certain part of the response. So, this helps us in only showing a specific part of the response. We are only looking for responses with HTTP CodeÂ `200 OK`, regardless of their content, so we will not opt for this option.

Try otherÂ `Intruder`Â options, and use Burp help by clicking onÂ `?`Â next to each one to learn more about each option.

Note: We may also use theÂ `Resource Pool`Â tab to specify how much network resources Intruder will use, which may be useful for very large attacks. For our example, we'll leave it at its default values.

---

## Attack

Now that everything is properly set up, we can click on theÂ `Start Attack`Â button and wait for our attack to finish. Once again, in the freeÂ `Community Version`, these attacks would be very slow and take a considerable amount of time for longer wordlists.

The first thing we will notice is that all lines starting withÂ `.`Â were skipped, and we directly started with the lines after them:

![intruder_attack_exclude](https://academy.hackthebox.com/storage/modules/110/burp_intruder_attack_exclude.jpg)

We can also see theÂ `200 OK`Â column, which shows requests that match theÂ `200 OK`Â grep value we specified in the Options tab. We can click on it to sort by it, such that we'll have matching results at the top. Otherwise, we can sort byÂ `status`Â or byÂ `Length`. Once our scan is done, we see that we get one hitÂ `/admin`:

![intruder_attack](https://academy.hackthebox.com/storage/modules/110/burp_intruder_attack.jpg)

We may now manually visit the pageÂ `<http://SERVER_IP:PORT/admin/>`, to make sure that it does exist.

Similarly, we can useÂ `Burp Intruder`Â to do any type of web fuzzing and brute-forcing, including brute forcing for passwords, or fuzzing for certain PHP parameters, and so on. We can even useÂ `Intruder`Â to perform password spraying against applications that use Active Directory (AD) authentication such as Outlook Web Access (OWA), SSL VPN portals, Remote Desktop Services (RDS), Citrix, custom web applications that use AD authentication, and more. However, as the free version ofÂ `Intruder`Â is extremely throttled, in the next section, we will see ZAP's fuzzer and its various options, which do not have a paid tier.

# Question

![Pasted image 20250124104945.png](../../../IMAGES/Pasted%20image%2020250124104945.png)

Nice, let's follow these steps:

![Pasted image 20250124115144.png](../../../IMAGES/Pasted%20image%2020250124115144.png)

Set the target, let's add the dictionary, for this, I filtered a premade dictionary using this: `cat /usr/share/seclists/Discovery/Web-Content/raft-small-files.txt | grep '\.html$' > filtered-html-files.txt`:

![Pasted image 20250124115253.png](../../../IMAGES/Pasted%20image%2020250124115253.png)

Let's send the payload:

![Pasted image 20250124115555.png](../../../IMAGES/Pasted%20image%2020250124115555.png)

After a while, we can see that `2010.html` matches `200` status code:

![Pasted image 20250124115630.png](../../../IMAGES/Pasted%20image%2020250124115630.png)

We got the flag: `HTB{burp_1n7rud3r_fuzz3r!}`
