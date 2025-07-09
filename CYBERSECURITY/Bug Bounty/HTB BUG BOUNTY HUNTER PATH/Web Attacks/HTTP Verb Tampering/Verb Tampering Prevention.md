After seeing a few ways to exploit Verb Tampering vulnerabilities, let's see how we can protect ourselves against these types of attacks by preventing Verb Tampering. Insecure configurations and insecure coding are what usually introduce Verb Tampering vulnerabilities. In this section, we will look at samples of vulnerable code and configurations and discuss how we can patch them.

---

## Insecure Configuration

HTTP Verb Tampering vulnerabilities can occur in most modern web servers, includingÂ `Apache`,Â `Tomcat`, andÂ `ASP.NET`. The vulnerability usually happens when we limit a page's authorization to a particular set of HTTP verbs/methods, which leaves the other remaining methods unprotected.

The following is an example of a vulnerable configuration for an Apache web server, which is located in the site configuration file (e.g.Â `000-default.conf`), or in aÂ `.htaccess`Â web page configuration file:


```xml
<Directory "/var/www/html/admin">
    AuthType Basic
    AuthName "Admin Panel"
    AuthUserFile /etc/apache2/.htpasswd
    <Limit GET>
        Require valid-user
    </Limit>
</Directory>
```

As we can see, this configuration is setting the authorization configurations for theÂ `admin`Â web directory. However, as theÂ `<Limit GET>`Â keyword is being used, theÂ `Require valid-user`Â setting will only apply toÂ `GET`Â requests, leaving the page accessible throughÂ `POST`Â requests. Even if bothÂ `GET`Â andÂ `POST`Â were specified, this would leave the page accessible through other methods, likeÂ `HEAD`Â orÂ `OPTIONS`.

The following example shows the same vulnerability for aÂ `Tomcat`Â web server configuration, which can be found in theÂ `web.xml`Â file for a certain Java web application:

```xml
<security-constraint>
    <web-resource-collection>
        <url-pattern>/admin/*</url-pattern>
        <http-method>GET</http-method>
    </web-resource-collection>
    <auth-constraint>
        <role-name>admin</role-name>
    </auth-constraint>
</security-constraint>
```

We can see that the authorization is being limited only to theÂ `GET`Â method withÂ `http-method`, which leaves the page accessible through other HTTP methods.

Finally, the following is an example for anÂ `ASP.NET`Â configuration found in theÂ `web.config`Â file of a web application:

```xml
<system.web>
    <authorization>
        <allow verbs="GET" roles="admin">
            <deny verbs="GET" users="*">
        </deny>
        </allow>
    </authorization>
</system.web>
```

Once again, theÂ `allow`Â andÂ `deny`Â scope is limited to theÂ `GET`Â method, which leaves the web application accessible through other HTTP methods.

The above examples show that it is not secure to limit the authorization configuration to a specific HTTP verb. This is why we should always avoid restricting authorization to a particular HTTP method and always allow/deny all HTTP verbs and methods.

If we want to specify a single method, we can use safe keywords, likeÂ `LimitExcept`Â in Apache,Â `http-method-omission`Â in Tomcat, andÂ `add`/`remove`Â in ASP.NET, which cover all verbs except the specified ones.

Finally, to avoid similar attacks, we should generallyÂ `consider disabling/denying all HEAD requests`Â unless specifically required by the web application.

---

## Insecure Coding

While identifying and patching insecure web server configurations is relatively easy, doing the same for insecure code is much more challenging. This is because to identify this vulnerability in the code, we need to find inconsistencies in the use of HTTP parameters across functions, as in some instances, this may lead to unprotected functionalities and filters.

Let's consider the followingÂ `PHP`Â code from ourÂ `File Manager`Â exercise:


```php
if (isset($_REQUEST['filename'])) {
    if (!preg_match('/[^A-Za-z0-9. _-]/', $_POST['filename'])) {
        system("touch " . $_REQUEST['filename']);
    } else {
        echo "Malicious Request Denied!";
    }
}
```

If we were only considering Command Injection vulnerabilities, we would say that this is securely coded. TheÂ `preg_match`Â function properly looks for unwanted special characters and does not allow the input to go into the command if any special characters are found. However, the fatal error made in this case is not due to Command Injections but due to theÂ `inconsistent use of HTTP methods`.

We see that theÂ `preg_match`Â filter only checks for special characters inÂ `POST`Â parameters withÂ `$_POST['filename']`. However, the finalÂ `system`Â command uses theÂ `$_REQUEST['filename']`Â variable, which covers bothÂ `GET`Â andÂ `POST`Â parameters. So, in the previous section, when we were sending our malicious input through aÂ `GET`Â request, it did not get stopped by theÂ `preg_match`Â function, as theÂ `POST`Â parameters were empty and hence did not contain any special characters. Once we reach theÂ `system`Â function, however, it used any parameters found in the request, and ourÂ `GET`Â parameters were used in the command, eventually leading to Command Injection.

This basic example shows us how minor inconsistencies in the use of HTTP methods can lead to critical vulnerabilities. In a production web application, these types of vulnerabilities will not be as obvious. They would probably be spread across the web application and will not be on two consecutive lines like we have here. Instead, the web application will likely have a special function for checking for injections and a different function for creating files. This separation of code makes it difficult to catch these sorts of inconsistencies, and hence they may survive to production.

To avoid HTTP Verb Tampering vulnerabilities in our code,Â `we must be consistent with our use of HTTP methods`Â and ensure that the same method is always used for any specific functionality across the web application. It is always advised toÂ `expand the scope of testing in security filters`Â by testing all request parameters. This can be done with the following functions and variables:

|Language|Function|
|---|---|
|PHP|`$_REQUEST['param']`|
|Java|`request.getParameter('param')`|
|C#|`Request['param']`|

If our scope in security-related functions covers all methods, we should avoid such vulnerabilities or filter bypasses.
