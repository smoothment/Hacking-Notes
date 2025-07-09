To begin with, we must understand what XPATH is, so here is a simple definition:

* *XPath, or XML Path Language, is a query language used to navigate through elements and attributes in an XML (Extensible Markup Language) document. It allows you to specify paths to select specific parts of an XML document, making it useful for extracting data, filtering content, and performing complex searches within XML.

### Key Features of XPath:

```ad-info
1. **Path Expressions:** XPath uses path expressions to select nodes or node-sets in an XML document. For example, `/bookstore/book` selects all `<book>` elements that are children of the `<bookstore>` element.
    
2. **Axes:** XPath provides various axes to traverse through nodes, such as:
    
    - `child`: Selects child nodes.
    - `parent`: Selects the parent of the current node.
    - `ancestor`: Selects all ancestors (parents, grandparents, etc.) of the current node.
    - `descendant`: Selects all descendants (children, grandchildren, etc.) of the current node.
3. **Predicates:** Predicates are used to filter nodes selected by a path expression. For example, `/bookstore/book[price>30]` selects `<book>` elements with a `<price>` child element greater than 30.
    
4. **Functions:** XPath supports various functions like `text()`, `contains()`, `starts-with()`, `last()`, and more, which can be used to refine selections.
    
5. **Operators:** XPath includes operators such as `=`, `!=`, `<`, `>`, and logical operators (`and`, `or`) to perform comparisons and logical operations within expressions.
```
    
### Common Use Cases:

```ad-note
- **Web Scraping:** Extracting data from XML-based web pages.
- **XML Data Processing:** Manipulating and querying XML documents in software applications.
- **Testing:** Identifying elements in XML responses during automated testing of web applications.
```

XPath is often used in combination with other technologies, such as XSLT (Extensible Stylesheet Language Transformations) for transforming XML documents, and with programming languages like Python (using libraries such as `lxml`), Java, or JavaScript for processing XML data programmatically.


### WHAT IS XPATH INJECTION THEN?

XPath injection is a type of security vulnerability that occurs when an application uses user-supplied input to construct XPath queries for XML data without properly validating or sanitizing the input. Just like SQL injection with databases, XPath injection allows an attacker to manipulate XPath queries to access unauthorized data, bypass authentication, or potentially execute unintended commands within the XML document.

### How XPath Injection Works

```ad-summary
1. **XPath Queries in Applications:** Applications often use XPath queries to retrieve data from XML documents, such as user authentication details. For example:
    
    

    
    
    A simple XPath query to authenticate a user might look like:
    
    
    `/users/user[username='$username' and password='$password']`
    
    where `$username` and `$password` are user inputs.
    
2. **Injection Points:** If the input fields for username and password are not properly sanitized, an attacker can inject XPath code. For instance, by submitting:
    
    - Username: `admin' or '1'='1`
    - Password: `admin' or '1'='1`
    
    The query becomes:
    
    `/users/user[username='admin' or '1'='1' and password='admin' or '1'='1']`
    
    This query always returns true (`'1'='1'`), allowing the attacker to bypass authentication.
```
    

### Common XPath Injection Techniques

```ad-summary
1. **Bypassing Authentication:** Injecting conditions that always evaluate to true (`' or '1'='1`) to gain unauthorized access.
    
2. **Extracting Data:** By modifying the XPath query to retrieve specific data:
    
    - If the query is `/users/user[username='$username']`, injecting a username like `' or '1'='1' or '1'='2` could extract all usernames.
3. **Blind XPath Injection:** Similar to blind SQL injection, this technique is used when the response doesn't directly reveal information. Attackers can infer data by injecting queries that cause different application behaviors (e.g., timing differences or error messages).
```
    

### Preventing XPath Injection

```ad-info
`1. **Input Validation and Sanitization:**
    
    - Validate input against expected formats (e.g., alphanumeric).
    - Use libraries or frameworks that automatically handle encoding and sanitization.
2. **Parameterized XPath Queries:**
    
    - Use parameterized queries or prepared statements to avoid embedding user inputs directly into XPath expressions.
3. **Use Security Libraries:**
    
    - Use libraries that offer safe methods for querying XML, such as `lxml` in Python, which can help mitigate injection risks.
4. **Least Privilege:**
    
    - Limit access to XML documents and ensure that only necessary data is exposed.
5. **Error Handling:**
    
    - Avoid exposing detailed error messages to users, as these can provide insights into the structure of XPath queries.`
```


# HACKTRICKS

```ad-important
URL: [xpath-injection](https://book.hacktricks.xyz/pentesting-web/xpath-injection)
```



# XPATH AUTHENTICATION BYPASS

<iframe width="969" height="545" src="https://www.youtube.com/embed/xHfO2bgXNJs" title="Curso Bug Bounty  |  XPATH  Authentication Bypass - Capitulo 3-2" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" referrerpolicy="strict-origin-when-cross-origin" allowfullscreen></iframe>


As seen in the video, the lab has a xpath authentication bypass, it follows this payload:

`'or true() or '`

![Pasted image 20241010143247.png](../../../../IMAGES/Pasted%20image%2020241010143247.png)
If we enter the payload, we've bypassed the login page:

![Pasted image 20241010143256.png](../../../../IMAGES/Pasted%20image%2020241010143256.png)
### FIRST WAY
But we are not admin user, we need to keep trying payloads until we get it, for example, we can enumerate the positions of the user using:

`'or position()=1 or '`

![Pasted image 20241010143417.png](../../../../IMAGES/Pasted%20image%2020241010143417.png)
If we pass in that payload, we will log in as the same user shown previously, but we can keep changing the `position()=` function until we get the user we desire:


`'or position()=2 or '`

![Pasted image 20241010143522.png](../../../../IMAGES/Pasted%20image%2020241010143522.png)

![Pasted image 20241010143532.png](../../../../IMAGES/Pasted%20image%2020241010143532.png)

`'or position()=3 or '`

![Pasted image 20241010143607.png](../../../../IMAGES/Pasted%20image%2020241010143607.png)
![Pasted image 20241010143623.png](../../../../IMAGES/Pasted%20image%2020241010143623.png)

Now we've logged in as super user (admin).

But now, imagine we are performing bug bounty on an enterprise, users would be huge, for this, we could use burp's intruder to try to brute force that `position()=` function until we get the user we desire.

### OTHER WAY

Imagine you want to log in as a specific user, using the first way would take a while and maybe, the server would cut our requests out, for this, we can use the following payload:

`'or contains(,.'user') or '`

Now, with this payload, we can actually log in as the user we want, if we know how the username, we can log in:



![Pasted image 20241010144040.png](../../../../IMAGES/Pasted%20image%2020241010144040.png)

![Pasted image 20241010144053.png](../../../../IMAGES/Pasted%20image%2020241010144053.png)

# XPATH DATA EXFILTRATION

We can access to arbitrary data using this xpath vulnerability, let's look at it:

<iframe width="800" height="600" src="https://www.youtube.com/embed/Up5h1BjFGgM" title="Curso Bug Bounty  |  XPATH  Data Exfiltration - Capitulo 3-3" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" referrerpolicy="strict-origin-when-cross-origin" allowfullscreen></iframe>
As seen in the video, we have a San Francisco street index, as it is shown, we can look up for streets, but, this search bar is vulnerable to XPATH data exfiltration.

To begin, we pass the request to our burp:

![Pasted image 20241010172508.png](../../../../IMAGES/Pasted%20image%2020241010172508.png)
For example, if we modify the `f` parameter into this:

`RAMDOM+|+//text()`

![Pasted image 20241010172638.png](../../../../IMAGES/Pasted%20image%2020241010172638.png)
We get the following response:

![Pasted image 20241010172649.png](../../../../IMAGES/Pasted%20image%2020241010172649.png)
So, seems like it works!

![Pasted image 20241010172834.png](../../../../IMAGES/Pasted%20image%2020241010172834.png)
If we look at the response, we see we are able to read the whole document information, for this exercise, we even got a password and a flag (not shown in the video).

## ADVANCED DATA EXFILTRATION

We need to modify our payload to iterate through the whole document, if we want to, we can automate the process using a programming language such as python. 

<iframe width="800" height="600" src="https://www.youtube.com/embed/d7QyaW8nSWI" title="Curso Bug Bounty  |  XPATH  Advanced Data Exfiltration - Capitulo 3-4" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" referrerpolicy="strict-origin-when-cross-origin" allowfullscreen></iframe>

To perform advanced data exfiltration, we can use the following payload, it does not apply to every website, but we can have some sort of guide with it:

`g=OMETHINGINVALID&f=fullstreetname | /*[1]`

To watch the deep of the scheme we need to take that `/*[1]` part seriously, for example, in the video, it is shown that when we add `/*[1]` or `/*[2]` in the query, different results are shown, so, in order to get reach the deepest point, we need to test these payloads, for example:

`fullstreetname | /*[1]  ---> First street
`fullstreetname | /*[1]/*[2] -------> None
`fullstreetname | /*[1]/*[2]/*[1] -----> None`

That's the structure, we need to keep testing until reaching the deepest point, we can even use `/*[3]` or `/*[4]` to test.

To know the deep of a xml file, the video provides us this code:

```python
import xml.etree.ElementTree as ET
import argparse
from colorama import init, Fore, Style

init()

def print_depth(elem, depth=1):
    if depth == 1:
        print(f'{Fore.GREEN}XML depth color identifier!{Style.RESET_ALL}')

    # Printing depth matching each color:

    color = [Fore.CYAN, Fore.YELLOW, Fore.MAGENTA, Fore.RED, Fore.BLUE, Fore.GREEN, Fore.WHITE]
    print(f'{color[(depth-1) % len(color)]}{' ' * (depth-1)*2}<{elem.tag}> - Depth {depth}{Style.RESET_ALL}')

    # looping through each child elements

    for child in elem:
        print_depth(child, depth+1)

    
def analyze_xml(file_path):
    tree = ET.parse(file_path)
    root = tree.getroot()

    # Prining root file with its depth:

    print_depth(root)


if __name__ == '__main__':
    # Setting up arguments analyzer:

    parser = argparse.ArgumentParser(prog='XML depth analyzer (with colors)',description="Analyze XML file and print node depths")
    parser.add_argument('-f', '--file', help='Use -f to specify XML file path')
    parser = parser.parse_args()
```

# XPATH BLIND EXPLOITATION

<iframe width="800" height="545" src="https://www.youtube.com/embed/a8raXmjdSAQ" title="Curso Bug Bounty  |  XPATH  Blind Exploitation - Capitulo 3-5" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" referrerpolicy="strict-origin-when-cross-origin" allowfullscreen></iframe>
Like [[CyberSecurity/Bug Bounty/Vulnerabilities/SERVER SIDE VULNERABILITIES/INJECTIONS/SQL INJECTION (SQLI).md|SQLI]], XPATH injection also have a blind exploitation, for this, we could use the following payloads:

![Pasted image 20241010180954.png](../../../../IMAGES/Pasted%20image%2020241010180954.png)
![Pasted image 20241010181012.png](../../../../IMAGES/Pasted%20image%2020241010181012.png)
