---
sticker: lucide//book-template
---
---

Before exploiting an SSTI vulnerability, it is essential to successfully confirm that the vulnerability is present. Furthermore, we need to identify the template engine the target web application uses, as the exploitation process highly depends on the concrete template engine in use. That is because each template engine uses a slightly different syntax and supports different functions we can use for exploitation purposes.

---

## Confirming SSTI

The process of identifying an SSTI vulnerability is similar to the process of identifying any other injection vulnerability, such as SQL injection. The most effective way is to inject special characters with semantic meaning in template engines and observe the web application's behavior. As such, the following test string is commonly used to provoke an error message in a web application vulnerable to SSTI, as it consists of all special characters that have a particular semantic purpose in popular template engines:

![Pasted image 20250212130159.png](../../../../IMAGES/Pasted%20image%2020250212130159.png)


Since the above test string should almost certainly violate the template syntax, it should result in an error if the web application is vulnerable to SSTI. This behavior is similar to how injecting a single quote (`'`) into a web application vulnerable to SQL injection can break an SQL query's syntax and thus result in an SQL error.

As a practical example, let us look at our sample web application. We can insert a name, which is then reflected on the following page:

 ![](https://academy.hackthebox.com/storage/modules/145/ssti/ssti_identification_1.png)

 ![](https://academy.hackthebox.com/storage/modules/145/ssti/ssti_identification_2.png)

To test for an SSTI vulnerability, we can inject the above test string. This results in the following response from the web application:

 ![](https://academy.hackthebox.com/storage/modules/145/ssti/ssti_identification_3.png)

As we can see, the web application throws an error. While this does not confirm that the web application is vulnerable to SSTI, it should increase our suspicion that the parameter might be vulnerable.

---

## Identifying the Template Engine

To enable the successful exploitation of an SSTI vulnerability, we first need to determine the template engine used by the web application. We can utilize slight variations in the behavior of different template engines to achieve this. For instance, consider the following commonly used overview containing slight differences in popular template engines:

![image](https://academy.hackthebox.com/storage/modules/145/ssti/diagram.png)

We will start by injecting the payload`${7*7}` and follow the diagram from left to right, depending on the result of the injection. Suppose the injection resulted in a successful execution of the injected payload. In that case, we follow the green arrow; otherwise, we follow the red arrow until we arrive at a resulting template engine.

Injecting the payload`${7*7}` into our sample web application results in the following behavior:

 ![](https://academy.hackthebox.com/storage/modules/145/ssti/ssti_identification_4.png)

Since the injected payload was not executed, we follow the red arrow and now inject the payload`{{7*7}}`:

 ![](https://academy.hackthebox.com/storage/modules/145/ssti/ssti_identification_5.png)

This time, the payload was executed by the template engine. Therefore, we follow the green arrow and inject the payload`{{7*'7'}}`. The result will enable us to deduce the template engine used by the web application. In Jinja, the result will be`7777777`, while in Twig, the result will be`49`.

# Question
----

![Pasted image 20250212130935.png](../../../../IMAGES/Pasted%20image%2020250212130935.png)

We got this:

![Pasted image 20250212130951.png](../../../../IMAGES/Pasted%20image%2020250212130951.png)

We can try injecting this payload:

![Pasted image 20250212131049.png](../../../../IMAGES/Pasted%20image%2020250212131049.png)

![Pasted image 20250212131107.png](../../../../IMAGES/Pasted%20image%2020250212131107.png)

This means it worked, this site is indeed vulnerable to SSTI, let's use the following chart to test payloads:

![Pasted image 20250212131145.png](../../../../IMAGES/Pasted%20image%2020250212131145.png)

![Pasted image 20250212131203.png](../../../../IMAGES/Pasted%20image%2020250212131203.png)

Let's proceed with: `{{7*7}}`

![Pasted image 20250212131228.png](../../../../IMAGES/Pasted%20image%2020250212131228.png)

Got it, if we read the chart, we can notice the template engine being used is `twig`
