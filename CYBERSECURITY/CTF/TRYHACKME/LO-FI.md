# ENUMERATION
---



## OPEN PORTS
---


| PORT | SERVICE |
| :--- | :------ |
| 22   | ssh     |
| 80   | http    |



# RECONNAISSANCE
---


This is the first thing we see once we go to the website: 

![Pasted image 20250120153845.png](../../IMAGES/Pasted%20image%2020250120153845.png)



We have a search bar, my first guess would be we need to test either for [SQLI](../../Bug%20Bounty/Vulnerabilities/SERVER%20SIDE%20VULNERABILITIES/INJECTIONS/SQLI/SQL%20INJECTION%20(SQLI).md), [XSS](../../Bug%20Bounty/Vulnerabilities/SERVER%20SIDE%20VULNERABILITIES/CROSS%20SITE%20SCRIPTING/CROSS%20SITE%20SCRIPTING%20(XSS).md) or [LFI](../../Bug%20Bounty/Vulnerabilities/SERVER%20SIDE%20VULNERABILITIES/FILE%20INCLUSION%20VULNERABILITIES/LOCAL%20FILE%20INCLUSION%20(LFI).md), let's check:

![Pasted image 20250120154118.png](../../IMAGES/Pasted%20image%2020250120154118.png)

XSS does not work, let's test SQLI:

![Pasted image 20250120154142.png](../../IMAGES/Pasted%20image%2020250120154142.png)

Seems like SQLI does not work too, if we check around the page, we find a `relax` section, if we click on it, the following URL appears:



![Pasted image 20250120154358.png](../../IMAGES/Pasted%20image%2020250120154358.png)

So, we can check it is indeed reading from a file called: `relax.php`, if we try LFI, we get the following:

![Pasted image 20250120154434.png](../../IMAGES/Pasted%20image%2020250120154434.png)

LFI is possible, let's begin exploitation.



# EXPLOITATION
---

Nice, so we already know we can use LFI to retrieve the contents of a file, since our main purpose is to read `flag.txt`, we only need to write: `../../../flag.txt` in order to read the file:



![Pasted image 20250120154645.png](../../IMAGES/Pasted%20image%2020250120154645.png)


Just like that room is done, no need to reach root.
