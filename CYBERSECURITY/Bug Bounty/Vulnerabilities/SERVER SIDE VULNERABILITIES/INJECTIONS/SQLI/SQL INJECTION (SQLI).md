# What is SQL injection (SQLi)?


SQL injection (SQLi) is a web security vulnerability that allows an attacker to interfere with the queries that an application makes to its database. This can allow an attacker to view data that they are not normally able to retrieve. This might include data that belongs to other users, or any other data that the application can access. In many cases, an attacker can modify or delete this data, causing persistent changes to the application's content or behavior.

In some situations, an attacker can escalate a SQL injection attack to compromise the underlying server or other back-end infrastructure. It can also enable them to perform denial-of-service attacks.

## How to detect SQL injection vulnerabilities

You can detect SQL injection manually using a systematic set of tests against every entry point in the application. To do this, you would typically submit:

1. The single quote character ' and look for errors or other anomalies.
2. Some SQL-specific syntax that evaluates to the base (original) value of the entry point, and to a different value, and look for systematic differences in the application responses.
3. Boolean conditions such as OR 1=1 and OR 1=2, and look for differences in the application's responses.
4. Payloads designed to trigger time delays when executed within a SQL query, and look for differences in the time taken to respond.
5. OAST payloads designed to trigger an out-of-band network interaction when executed within a SQL query, and monitor any resulting interactions.

Alternatively, you can find the majority of SQL injection vulnerabilities quickly and reliably using Burp Scanner.

## Retrieving hidden data

Imagine a shopping application that displays products in different categories. When the user clicks on the Gifts category, their browser requests the URL:

`https://insecure-website.com/products?category=Gifts`

This causes the application to make a SQL query to retrieve details of the relevant products from the database:
SELECT * FROM products WHERE category = 'Gifts' AND released = 1

This SQL query asks the database to return:

    all details (*)
    from the products table
    where the category is Gifts
    and released is 1.

The restriction released = 1 is being used to hide products that are not released. We could assume for unreleased products, released = 0.


### Retrieving hidden data - Continued

The application doesn't implement any defenses against SQL injection attacks. This means an attacker can construct the following attack, for example:

`https://insecure-website.com/products?category=Gifts'--`

This results in the SQL query:

`SELECT * FROM products WHERE category = 'Gifts'--' AND released = 1`

Crucially, note that -- is a comment indicator in SQL. This means that the rest of the query is interpreted as a comment, effectively removing it. In this example, this means the query no longer includes AND released = 1. As a result, all products are displayed, including those that are not yet released.

You can use a similar attack to cause the application to display all the products in any category, including categories that they don't know about:

`https://insecure-website.com/products?category=Gifts'+OR+1=1--`

This results in the SQL query:

`SELECT * FROM products WHERE category = 'Gifts' OR 1=1--' AND released = 1`

The modified query returns all items where either the category is Gifts, or 1 is equal to 1. As 1=1 is always true, the query returns all items.
```ad-warning

Take care when injecting the condition OR 1=1 into a SQL query. Even if it appears to be harmless in the context you're injecting into, it's common for applications to use data from a single request in multiple different queries. If your condition reaches an UPDATE or DELETE statement, for example, it can result in an accidental loss of data.
```

### LAB

![Pasted image 20240919180316.png](../../../../../IMAGES/Pasted%20image%2020240919180316.png)
Request:
![Pasted image 20240919180614.png](../../../../../IMAGES/Pasted%20image%2020240919180614.png)

Using `'+OR+1=1--` to perform SQLI:

![Pasted image 20240919180538.png](../../../../../IMAGES/Pasted%20image%2020240919180538.png)
![Pasted image 20240919180654.png](../../../../../IMAGES/Pasted%20image%2020240919180654.png)


## Subverting application logic

Imagine an application that lets users log in with a username and password. If a user submits the username wiener and the password bluecheese, the application checks the credentials by performing the following SQL query:

`SELECT * FROM users WHERE username = 'wiener' AND password = 'bluecheese'`


If the query returns the details of a user, then the login is successful. Otherwise, it is rejected.

In this case, an attacker can log in as any user without the need for a password. They can do this using the SQL comment sequence `--` to remove the password check from the WHERE clause of the query. For example, submitting the username `administrator'--` and a blank password results in the following query:

`SELECT * FROM users WHERE username = 'administrator'--' AND password = ''`

This query returns the user whose username is administrator and successfully logs the attacker in as that user.

### LAB

![Pasted image 20240919180913.png](../../../../../IMAGES/Pasted%20image%2020240919180913.png)

![Pasted image 20240919180954.png](../../../../../IMAGES/Pasted%20image%2020240919180954.png)
Request:

![Pasted image 20240919181021.png](../../../../../IMAGES/Pasted%20image%2020240919181021.png)
Lets perform SQLI:

![Pasted image 20240919181123.png](../../../../../IMAGES/Pasted%20image%2020240919181123.png)
Now we know this works, lets login from the panel and end the lab!:
![Pasted image 20240919181447.png](../../../../../IMAGES/Pasted%20image%2020240919181447.png)

# SQL INJECTION UNION ATTACKS

When an application is vulnerable to SQL injection, and the results of the query are returned within the application's responses, you can use the UNION keyword to retrieve data from other tables within the database. This is commonly known as a SQL injection UNION attack.

The `UNION` keyword enables you to execute one or more additional `SELECT` queries and append the results to the original query. For example:

```ad-info
`SELECT a, b FROM table1 UNION SELECT c, d FROM table2`
```

This SQL query returns a single result set with two columns, containing values from columns `a` and `b` in `table1` and columns `c` and `d` in `table2`. 

 For a `UNION` query to work, two key requirements must be met:

```ad-important
- The individual queries must return the same number of columns.
- The data types in each column must be compatible between the individual queries.
```

To carry out a SQL injection UNION attack, make sure that your attack meets these two requirements. This normally involves finding out:

 ```ad-info
- How many columns are being returned from the original query.
- Which columns returned from the original query are of a suitable data type to hold the results from the injected query.
```

## Determining the number of columns required

When you perform a SQL injection UNION attack, there are two effective methods to determine how many columns are being returned from the original query.

One method involves injecting a series of `ORDER BY` clauses and incrementing the specified column index until an error occurs. For example, if the injection point is a quoted string within the WHERE clause of the original query, you would submit:

```ad-important
`' ORDER BY 1--`
`' ORDER BY 2--`
`' ORDER BY 3--`
`etc.`
```

This series of payloads modifies the original query to order the results by different columns in the result set. The column in an ORDER BY clause can be specified by its index, so you don't need to know the names of any columns. When the specified column index exceeds the number of actual columns in the result set, the database returns an error, such as:

`The ORDER BY position number 3 is out of range of the number of items in the select list.`

The application might actually return the database error in its HTTP response, but it may also issue a generic error response. In other cases, it may simply return no results at all. Either way, as long as you can detect some difference in the response, you can infer how many columns are being returned from the query.


The second method involves submitting a series of UNION SELECT payloads specifying a different number of null values:
 
```ad-important
`' UNION SELECT NULL--`
`' UNION SELECT NULL,NULL--`
`' UNION SELECT NULL,NULL,NULL--`
`etc.`
```

If the number of nulls does not match the number of columns, the database returns an error, such as:

`All queries combined using a UNION, INTERSECT or EXCEPT operator must have an equal number of expressions in their target lists.`

We use `NULL` as the values returned from the injected `SELECT` query because the data types in each column must be compatible between the original and the injected queries. `NULL` is convertible to every common data type, so it maximizes the chance that the payload will succeed when the column count is correct.

As with the `ORDER BY` technique, the application might actually return the database error in its HTTP response, but may return a generic error or simply return no results. When the number of nulls matches the number of columns, the database returns an additional row in the result set, containing null values in each column. The effect on the HTTP response depends on the application's code. If you are lucky, you will see some additional content within the response, such as an extra row on an HTML table. Otherwise, the null values might trigger a different error, such as a NullPointerException. In the worst case, the response might look the same as a response caused by an incorrect number of nulls. This would make this method ineffective. 


LAB can be found at: [lab](LABS.md)

# DATABASE-SPECIFIC SYNTAX

On Oracle, every `SELECT` query must use the `FROM` keyword and specify a valid table. There is a built-in table on Oracle called dual which can be used for this purpose. So the injected queries on Oracle would need to look like:

`' UNION SELECT NULL FROM DUAL--`

The payloads described use the double-dash comment sequence `--` to comment out the remainder of the original query following the injection point. On MySQL, the double-dash sequence must be followed by a space. Alternatively, the hash character `#` can be used to identify a comment.

For more details of database-specific syntax, see the [SQL injection cheat sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet). 


# FINDING COLUMNS WITH A USEFUL DATA TYPE


A SQL injection `UNION` attack enables you to retrieve the results from an injected query. The interesting data that you want to retrieve is normally in string form. This means you need to find one or more columns in the original query results whose data type is, or is compatible with, string data.

After you determine the number of required columns, you can probe each column to test whether it can hold string data. You can submit a series of `UNION SELECT` payloads that place a string value into each column in turn. For example, if the query returns four columns, you would submit:

```ad-important

`' UNION SELECT 'a',NULL,NULL,NULL--`
`' UNION SELECT NULL,'a',NULL,NULL--`
`' UNION SELECT NULL,NULL,'a',NULL--`
`' UNION SELECT NULL,NULL,NULL,'a'--`
```

If the column data type is not compatible with string data, the injected query will cause a database error, such as:

`Conversion failed when converting the varchar value 'a' to data type int.`

If an error does not occur, and the application's response contains some additional content including the injected string value, then the relevant column is suitable for retrieving string data. 
