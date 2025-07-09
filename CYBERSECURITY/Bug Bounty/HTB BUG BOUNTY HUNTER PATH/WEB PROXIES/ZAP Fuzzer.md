ZAP's Fuzzer is called (`ZAP Fuzzer`). It can be very powerful for fuzzing various web end-points, though it is missing some of the features provided by Burp Intruder. ZAP Fuzzer, however, does not throttle the fuzzing speed, which makes it much more useful than Burp's free Intruder.

In this section, we will try to replicate what we did in the previous section using ZAP Fuzzer to have an "apples to apples" comparison and decide which one we like best.

---

## Fuzz

To start our fuzzing, we will visit the URL from the exercise at the end of this section to capture a sample request. As we will be fuzzing for directories, let's visitÂ `<http://SERVER_IP:PORT/test/>`Â to place our fuzzing location onÂ `test`Â later on. Once we locate our request in the proxy history, we will right-click on it and select (`Attack>Fuzz`), which will open theÂ `Fuzzer`Â window:

![payload processing](https://academy.hackthebox.com/storage/modules/110/zap_fuzzer.jpg)

The main options we need to configure for our Fuzzer attack are:

- Fuzz Location
- Payloads
- Processors
- Options

Let's try to configure them for our web directory fuzzing attack.

---

## Locations

TheÂ `Fuzz Location`Â is very similar toÂ `Intruder Payload Position`, where our payloads will be placed. To place our location on a certain word, we can select it and click on theÂ `Add`Â button on the right pane. So, let's selectÂ `test`Â and click onÂ `Add`:

![payload processing](https://academy.hackthebox.com/storage/modules/110/zap_fuzzer_add.jpg)

As we can see, this placed aÂ `green`Â marker on our selected location and opened theÂ `Payloads`Â window for us to configure our attack payloads.

---

## Payloads

The attack payloads in ZAP's Fuzzer are similar in concept to Intruder's Payloads, though they are not as advanced as Intruder's. We can click on theÂ `Add`Â button to add our payloads and select from 8 different payload types. The following are some of them:

- `File`: This allows us to select a payload wordlist from a file.
- `File Fuzzers`: This allows us to select wordlists from built-in databases of wordlists.
- `Numberzz`: Generates sequences of numbers with custom increments.

One of the advantages of ZAP Fuzzer is having built-in wordlists we can choose from so that we do not have to provide our own wordlist. More databases can be installed from the ZAP Marketplace, as we will see in a later section. So, we can selectÂ `File Fuzzers`Â as theÂ `Type`, and then we will select the first wordlist fromÂ `dirbuster`:

![payload processing](https://academy.hackthebox.com/storage/modules/110/zap_fuzzer_add_payload.jpg)

Once we click theÂ `Add`Â button, our payload wordlist will get added, and we can examine it with theÂ `Modify`Â button.

---

## Processors

We may also want to perform some processing on each word in our payload wordlist. The following are some of the payload processors we can use:

- Base64 Decode/Encode
- MD5 Hash
- Postfix String
- Prefix String
- SHA-1/256/512 Hash
- URL Decode/Encode
- Script

As we can see, we have a variety of encoders and hashing algorithms to select from. We can also add a custom string before the payload withÂ `Prefix String`Â or a custom string withÂ `Postfix String`. Finally, theÂ `Script`Â type allows us to select a custom script that we built and run on every payload before using it in the attack.

We will select theÂ `URL Encode`Â processor for our exercise to ensure that our payload gets properly encoded and avoid server errors if our payload contains any special characters. We can click on theÂ `Generate Preview`Â button to preview how our final payload will look in the request:

![payload processing](https://academy.hackthebox.com/storage/modules/110/zap_fuzzer_add_processor.jpg)

Once that's done, we can click onÂ `Add`Â to add the processor and click onÂ `Ok`Â in the processors and payloads windows to close them.

---

## Options

Finally, we can set a few options for our fuzzers, similar to what we did with Burp Intruder. For example, we can set theÂ `Concurrent threads per scan`Â toÂ `20`, so our scan runs very quickly:

![payload processing](https://academy.hackthebox.com/storage/modules/110/zap_fuzzer_options.jpg)

The number of threads we set may be limited by how much computer processing power we want to use or how many connections the server allows us to establish.

We may also choose to run through the payloadsÂ `Depth first`, which would attempt all words from the wordlist on a single payload position before moving to the next (e.g., try all passwords for a single user before brute-forcing the following user). We could also useÂ `Breadth first`, which would run every word from the wordlist on all payload positions before moving to the next word (e.g., attempt every password for all users before moving to the following password).

---

## Start

With all of our options configured, we can finally click on theÂ `Start Fuzzer`Â button to start our attack. Once our attack is started, we can sort the results by theÂ `Response`Â code, as we are only interested in responses with codeÂ `200`:

![payload processing](https://academy.hackthebox.com/storage/modules/110/zap_fuzzer_attack.jpg)

As we can see, we got one hit with codeÂ `200`Â with theÂ `skills`Â payload, meaning that theÂ `/skills/`Â directory exists on the server and is accessible. We can click on the request in the results window to view its details:Â ![payload processing](https://academy.hackthebox.com/storage/modules/110/zap_fuzzer_dir.jpg)

We can see from the response that this page is indeed accessible by us. There are other fields that may indicate a successful hit depending on the attack scenario, likeÂ `Size Resp. Body`Â which may indicate that we got a different page if its size was different than other responses, orÂ `RTT`Â for attacks likeÂ `time-based SQL injections`, which are detected by a time delay in the server response


# Question
---
![Pasted image 20250124124608.png](../../../IMAGES/Pasted%20image%2020250124124608.png)

Let's intercept the request using zap, then go to `Attack>Fuzz`:
![Pasted image 20250124124929.png](../../../IMAGES/Pasted%20image%2020250124124929.png)

add the cookie, and the dictionary, set processors: `HASH MD5` and fuzz:

![Pasted image 20250124132718.png](../../../IMAGES/Pasted%20image%2020250124132718.png)

We can now filter for `Resp.Body` size:


![Pasted image 20250124132843.png](../../../IMAGES/Pasted%20image%2020250124132843.png)

Got the cookie: `ee11cbb19052e40b07aac0ca060c23ee`

Let's use this cookie:

![Pasted image 20250124132935.png](../../../IMAGES/Pasted%20image%2020250124132935.png)


Got the flag: `HTB{fuzz1n6_my_f1r57_c00k13}`

