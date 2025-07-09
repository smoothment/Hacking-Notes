---
sticker: lucide//database-backup
---


# INTRODUCTION


Cyber security is a broad topic that covers a wide range of subjects, but few of those are as ubiquitous as databases. Whether youâ€™re working on securing a web application, working in a SOC and using aÂ SIEM, configuring user authentication/access control, or using malware analysis/threat detection tools (the list goes on), you will in some way be relying on databases.Â For example, on the offensive side of security, it can help us better understandÂ SQLÂ vulnerabilities, such asÂ SQLÂ injections, and create queries that help us tamper or retrieve data within a compromised service. On the other hand, on the defensive side, it can help us navigate through databases and find suspicious activity or relevant information; it can also help us better protect a service by implementing restrictions when needed.

Because databases are ubiquitous, it is important to understand them, and this room will be your first step in that direction. Weâ€™ll go through the basics of databases, covering key terms, concepts and different types before getting to grips withÂ SQL.

### Room Prerequisites

This room has been written specifically for beginners. Because of this, users with little to no IT experience will be able to follow this room without the need to complete any of our material beforehand. However, having theÂ [LinuxÂ Fundamentals](https://tryhackme.com/module/linux-fundamentals)Â down would prove helpful.  

### Learning Objectives

```ad-info
- Understand what databases are, as well as key terms and concepts
- Understand the different types of databasesÂ 
- Understand whatÂ SQLÂ is
- Understand and be able to useÂ SQLÂ CRUD Operations
- Understand and be able to useÂ SQLÂ Clauses Operations
- Understand and be able to useÂ SQLÂ Operations
- Understand and be able to useÂ SQLÂ Operators
- Understand and be able to useÂ SQLÂ Functions
``` 

# DATABASES 101

## Introducing Databases

Okay, so youâ€™ve been told just how important they are. Now, it's time to understand what they are in the first place. As mentioned in the introduction, databases are so ubiquitous that you very likely interact with systems that are using them. Databases are an organized collection of structured information or data that is easily accessible and can be manipulated or analyzed. That data can take many forms, such as user authentication data (such as usernames and passwords), which are stored and checked against when authenticating into an application or site (like TryHackMe, for example), user-generated data on social media (Like Instagram and Facebook) where data such as user posts, comments, likes etc are collected and stored, as well as information such as watch history which is stored by streaming services such as Netflix and used to generate recommendations.Â 

Iâ€™m sure you get the point: databases are used extensively and can contain many different things. Itâ€™s not just massive-scale businesses that use databases. Smaller-scale businesses, when setting up, will almost certainly have to configure a database to store their data. Speaking of kinds of databases, letâ€™s take a look now at what those are.  

  

### Different Types of Databases

Now it makes sense that something is used by so many and for (relatively) so long that there would be multiple types of implementations. There are quite a few different types of databases that can be built, but for this introductory room, we are going to focus on the two primary types:Â **relational databases**Â (akaÂ SQL) vsÂ **non-relational databases**Â (aka NoSQL).Â   

![An illustration comparing relational and non-relational databases. On the left, a relational database is shown with structured tables, rows, and columns, connected by relationships between tables. On the right, a non-relational database is depicted with flexible, unstructured data stored in formats like key-value pairs, documents, or collections, with no defined relationships between data points. The relational database emphasizes structured organization and data relationships, while the non-relational database highlights flexibility and scalability for diverse data types.](https://tryhackme-images.s3.amazonaws.com/user-uploads/66c513e4445cb5649e636a36/room-content/66c513e4445cb5649e636a36-1727686858009.png)

**Relational databases:**Â Store structured data, meaning the data inserted into this database follows a structure. For example, the data collected on a user consists of first_name, last_name, email_address, username and password. When a new user joins, an entry is made in the database following this structure. This structured data is stored in rows and columns in a table (all of which will be covered shortly); relationships can then be made between two or more tables (for example, user and order_history), hence the term relational databases.

**Non-relational databases:**Â Instead of storing data the above way, store data in a non-tabular format. For example, if documents are being scanned, which can contain varying types and quantities of data, and are stored in a database that calls for a non-tabular format. Here is an example of what that might look like:Â 

```bash
 {
    _id: ObjectId("4556712cd2b2397ce1b47661"),
    name: { first: "Thomas", last: "Anderson" },
    date_of_birth: new Date('Sep 2, 1964'),
    occupation: [ "The One"],
    steps_taken : NumberLong(4738947387743977493)
}
```

  

In terms of what database should be chosen, it always comes down to the context in which the database is going to be used.Â Relational databases are often used when the data being stored is reliably going to be received in a consistent format, where accuracy is important, such as when processing e-commerce transactions.Â Non-relational databases, on the other hand, are better used when the data being received can vary greatly in its format but need to be collected and organised in the same place, such as social media platforms collecting user-generated content.  

### Tables, Rows and Columns

Now that weâ€™ve defined the two primary types of databases, weâ€™ll focus on relational databases. Weâ€™ll start by explainingÂ **tables**,Â **rows**, andÂ **columns**. All data stored in a relational database will be stored in aÂ **table**; for example, a collection of books in stock at a bookstore might be stored in a table named â€œBooksâ€.Â   

![An illustration of a database table with rows and columns. The table has labeled columns at the top representing different data fields, such as 'ID', 'Name', and 'Published Date'. Each row below the headers contains data entries corresponding to these columns, forming individual records. The structure emphasizes how data is organized in a grid-like format, with each row representing a record and each column representing a specific attribute of the data.](https://tryhackme-images.s3.amazonaws.com/user-uploads/66c513e4445cb5649e636a36/room-content/66c513e4445cb5649e636a36-1727686918382.png)

When creating this table, you would need to define what pieces of information are needed to define a book record, for example, â€œidâ€, â€œNameâ€, and â€œPublished_dateâ€. These would then be yourÂ **columns**; when these columns are being defined, you would also define what data type this column should contain; if an attempt is made to insert a record into a database where the data type does not match, it is rejected. The data types that can be defined can vary depending on what database you are using, but the core data types used by all include Strings (a collection of words and characters), Integers (numbers), floats/decimals (numbers with a decimal point) and Times/Dates.Â 

Once a table has been created with the columns defined, the first record would be inserted into the database, for example, a book named â€œAndroid Security Internalsâ€ with an id of â€œ1â€ and a publication date of â€œ2014-10-14â€. Once inserted, this record would be represented as aÂ **row**.

### Primary and Foreign Keys

Once a table has been defined and populated, more data may need to be stored. For instance, we want to create a table named â€œAuthorsâ€ that stores the authors of the books sold in the store. Here is a very clear example of a relationship. A book (stored in the Books table) is written by an author (stored in the Authors table). If we wanted to query for a book in our story but also have the author of that book returned, our data would need to be related somehow; we do this with keys. There are two types ofÂ **keys**:

![An illustration comparing a Primary Key and a Foreign Key in database tables. On the left, a table is shown with a highlighted column labeled 'Primary Key,' which uniquely identifies each record in that table. On the right, another table is displayed with a highlighted column labeled 'Foreign Key,' which references the Primary Key from the first table. Arrows connect the Foreign Key to the Primary Key, emphasizing the relationship between the two tables, where the Foreign Key enforces referential integrity by linking related data across tables.](https://tryhackme-images.s3.amazonaws.com/user-uploads/66c513e4445cb5649e636a36/room-content/66c513e4445cb5649e636a36-1727686918373.png)

**Primary Keys**: A primary key is used to ensure that the data collected in a certain column is unique. That is, there needs to be a way to identify each record stored in a table, a value unique to that record and is not repeated by any other record in that table. Think about matriculation numbers in a university; these are numbers assigned to a student so they can be uniquely identified in records (as sometimes students can have the same name). A column has to be chosen in each table as a primary key; in our example, â€œidâ€ would make the most sense as an id has been uniquely created for each book where, as books can have the same publication date or (in rarer cases) book title. Note that there can only be one primary key column in a table.

**Foreign Keys**: A foreign key is a column (or columns) in a table that also exists in another table within the database, and therefore provides a link between the two tables. In our example, think about adding an â€œauthor_idâ€ field to our â€œBooksâ€ table; this would then act as a foreign key because the author_id in our Books table corresponds to the â€œidâ€ column in the author table. Foreign keys are what allow the relationships between different tables in relational databases. Note that there can be more than one foreign key column in a table.

## QUESTIONS


![Pasted image 20241101161706.png](../../../../../IMAGES/Pasted%20image%2020241101161706.png)


# SQL

## What isÂ SQL?

Now, all of this theoretically sounds great, but in practice, how do databases work? How would you go and make your first table and populate it with data? What would you use? Databases are usually controlled using a Database Management System (DBMS). Serving as an interface between the end user and the database, a DBMS is a software program that allows users to retrieve, update and manage the data being stored. Some examples of DBMSs include MySQL, MongoDB, Oracle Database and Maria DB.Â 

![An illustration introducing SQL with databases. The image shows a central database icon connected to multiple tables, each with rows and columns representing data.](https://tryhackme-images.s3.amazonaws.com/user-uploads/66c513e4445cb5649e636a36/room-content/66c513e4445cb5649e636a36-1727687095405.png)

The interaction between the end user and the database can be done usingÂ SQLÂ (Structured Query Language).Â SQLÂ is a programming language that can be used to query, define and manipulate the data stored in a relational database.Â 

## The Benefits ofÂ SQLÂ and Relational Databases

SQLÂ is almost as ubiquitous as databases themselves, and for good reason. Here are some of the benefits that come with learning and using to useÂ SQL:  

- **It'sÂ _fast_:**Â Relational databases (aka those thatÂ SQLÂ is used for) can return massive batches of data almost instantaneously due to how little storage space is used and high processing speeds.Â 
  
- **Easy to Learn:**Â Unlike many programming languages,Â SQLÂ is written in plain English, making it much easier to pick up. The highly readable nature of the language means users can concentrate on learning the functions and syntax.
  
- **Reliable:**Â As mentioned before, relational databases can guarantee a level of accuracy when it comes to data by defining a strict structure into which data sets must fall in order to be inserted.
  
- **Flexible:**Â SQLÂ provides all kinds of capabilities when it comes to querying a database; this allows users to perform vast data analysis tasks very efficiently.  
    

Getting Hands ON

![An illustration of a laptop displaying a terminal window used to access and interact with an SQL database.](https://tryhackme-images.s3.amazonaws.com/user-uploads/66c513e4445cb5649e636a36/room-content/66c513e4445cb5649e636a36-1727687461547.png)



Setting up MySQL

```shell-session
user@tryhackme$ mysql -u root -p
```

Once prompted for the password, enter:

Setting up MySQL

```shell-session
user@tryhackme$ tryhackme
```

The output should look as follows:

Setting up MySQL

```shell-session
user@tryhackme$ mysql -u root -p
Enter password: 
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 8
Server version: 8.0.39-0ubuntu0.20.04.1 (Ubuntu)

Copyright (c) 2000, 2024, Oracle and/or its affiliates.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql> 
```

With that covered, you are ready to start using (and learning)Â SQL!

## QUESTIONS

![Pasted image 20241101161807.png](../../../../../IMAGES/Pasted%20image%2020241101161807.png)


## SOME QUERIES
---

### **SELECT**
---

The first query type we'll learn is the SELECT query used to retrieve data from the database.Â 

Â   

`select * from users;`

  

|   |   |   |
|---|---|---|
|**id**|**username**|**password**|
|1|jon|pass123|
|2|admin|p4ssword|
|3|martin|secret123|

The first word SELECT, tells the database we want to retrieve some data; the * tells the database we want to receive back all columns from the table. For example, the table may contain three columns (id, username and password). "from users" tells the database we want to retrieve the data from the table named users. Finally, the semicolon at the end tells the database that this is the end of the query.Â Â 

  

The next query is similar to the above, but this time, instead of using the * to return all columns in the database table, we are just requesting the username and password field.

  

`select username,password from users;`

  

|   |   |
|---|---|
|**username**|**password**|
|jon|pass123|
|admin|p4ssword|
|martin|secret123|

The following query, like the first, returns all the columns by using the * selector, and then the "LIMIT 1" clause forces the database to return only one row of data. Changing the query to "LIMIT 1,1" forces the query to skip the first result, and then "LIMIT 2,1" skips the first two results, and so on. You need to remember the first number tells the database how many results you wish to skip, and the second number tells the database how many rows to return.

  

`select * from users LIMIT 1;`

  

|   |   |   |
|---|---|---|
|**id**|**username**|**password**|
|1|jon|pass123|

Lastly, we're going to utilise the where clause; this is how we can finely pick out the exact data we require by returning data that matches our specific clauses:

  

`select * from users where username='admin';`

  

|   |   |   |
|---|---|---|
|**id**|**username**|**password**|
|2|admin|p4ssword|

This will only return the rows where the username is equal to admin.

  

`select * from users where username != 'admin';`

  

|   |   |   |
|---|---|---|
|**id**|**username**|**password**|
|1|jon|pass123|
|3|martin|secret123|

This will only return the rows where the username isÂ **NOT**Â equal to admin.

  

`select * from users where username='admin' or username='jon';`

  

|   |   |   |
|---|---|---|
|**id**|**username**|**password**|
|1|jon|pass123|
|2|admin|p4ssword|

This will only return the rows where the username is either equal toÂ **admin**Â orÂ **j****on**.Â 

  

`select * from users where username='admin' and password='p4ssword';`

  

|   |   |   |
|---|---|---|
|**id**|**username**|**password**|
|2|admin|p4ssword|

This will only return the rows where the username is equal toÂ **admin**Â and the password is equal toÂ **p4ssword**.

  

Using the like clause allows you to specify data that isn't an exact match but instead either starts, contains or ends with certain characters by choosing where to place the wildcard character represented by a percentage sign %.

  

`select * from users where username like 'a%';`

  

|   |   |   |
|---|---|---|
|**id**|**username**|**password**|
|2|admin|p4ssword|

This returns any rows with a username beginning with the letter a.

  

`select * from users where username like '%n';`

  

|   |   |   |
|---|---|---|
|**id**|**username**|**password**|
|1|jon|pass123|
|2|admin|p4ssword|
|3|martin|secret123|

This returns any rows with a username ending with the letter n.

  

`select * from users where username like '%mi%';`

  

|   |   |   |
|---|---|---|
|**id**|**username**|**password**|
|2|admin|p4ssword|

This returns any rows with a username containing the charactersÂ **mi**Â within them.

  

### UNION  
---

The UNION statement combines the results of two or more SELECT statements to retrieve data from either single or multiple tables; the rules to this query are that the UNION statement must retrieve the same number of columns in each SELECT statement, the columns have to be of a similar data type, and the column order has to be the same. This might sound not very clear, so let's use the following analogy. Say a company wants to create a list of addresses for all customers and suppliers to post a new catalogue. We have one table called customers with the following contents:  

  

|   |   |   |   |   |
|---|---|---|---|---|
|**id**|**name**|**address**|**city**|**postcode**|
|1|Mr John Smith|123 Fake Street|Manchester|M2 3FJ|
|2|Mrs Jenny Palmer|99 Green Road|Birmingham|B2 4KL|
|3|Miss Sarah Lewis|15 Fore Street|London|NW12 3GH|

And another called suppliers with the following contents:

  

|   |   |   |   |   |
|---|---|---|---|---|
|**id**|**company**|**address**|**city**|**postcode**|
|1|Widgets Ltd|Unit 1a, Newby Estate|Bristol|BS19 4RT|
|2|The Tool Company|75 Industrial Road|Norwich|N22 3DR|
|3|Axe Makers Ltd|2b Makers Unit, Market Road|London|SE9 1KK|

Using the followingÂ SQLÂ Statement, we can gather the results from the two tables and put them into one result set:

  

`SELECT name,address,city,postcode from customers UNION SELECT company,address,city,postcode from suppliers;`  

  

|   |   |   |   |
|---|---|---|---|
|**name**|**address**|**city**|**postcode**|
|Mr John Smith|123 Fake Street|Manchester|M2 3FJ|
|Mrs Jenny Palmer|99 Green Road|Birmingham|B2 4KL|
|Miss Sarah Lewis|15 Fore Street|London|NW12 3GH|
|Widgets Ltd|Unit 1a, Newby Estate|Bristol|BS19 4RT|
|The Tool Company|75 Industrial Road|Norwich|N22 3DR|
|Axe Makers Ltd|2b Makers Unit, Market Road|London|SE9 1KK|

### INSERT
---

TheÂ **INSERT**Â statement tells the database we wish to insert a new row of data into the table.Â **"into users"**Â tells the database which table we wish to insert the data into,Â **"(username,password)"**Â provides the columns we are providing data for and thenÂ **"values ('bob','password');"**Â provides the data for the previously specified columns.

  

`insert into users (username,password) values ('bob','password123');`  

  

|   |   |   |
|---|---|---|
|**id**|**username**|**password**|
|1|jon|pass123|
|2|admin|p4ssword|
|3|martin|secret123|
|4|bob|password123|

### UPDATE
---
TheÂ **UPDATE**Â statement tells the database we wish to update one or more rows of data within a table. You specify the table you wish to update using "**update %tablename% SET**" and then select the field or fields you wish to update as a comma-separated list such as "**username='root',password='pass123'**" then finally, similar to the SELECT statement, you can specify exactly which rows to update using the where clause such as "**where username='admin;**".

  

`update users SET username='root',password='pass123' where username='admin';`

  

|   |   |   |
|---|---|---|
|**id**|**username**|**password**|
|1|jon|pass123|
|2|root|pass123|
|3|martin|secret123|
|4|bob|password123|

### DELETE
---

TheÂ **DELETE**Â statement tells the database we wish to delete one or more rows of data. Apart from missing the columns you wish to return, the format of this query is very similar to the SELECT. You can specify precisely which data to delete using theÂ **where**Â clause and the number of rows to be deleted using theÂ **LIMIT**Â clause.

  

`delete from users where username='martin';`

|   |   |   |
|---|---|---|
|**id**|**username**|**password**|
|1|jon|pass123|
|2|root|pass123|
|4|bob|password123|

`delete from users;`

  

Because no WHERE clause was being used in the query, all the data was deleted from the table.  

|        |              |              |
| ------ | ------------ | ------------ |
| **id** | **username** | **password** |
# Database and Table Statements


## Time to Learn

Now, the fun part! It's time to start learningÂ SQLÂ and how to use it to interact with databases. In this task, weâ€™re going to start by learning to use database and table statements. After all, itâ€™s these statements we need to initially create our databases/tables and get started.Â 

## Database Statements

### **CREATE DATABASE**

If a new database is needed, the first step you would take is to create it. This can be done inÂ SQLÂ using theÂ `CREATE DATABASE`Â statement. This would be done using the following syntax:  

Terminal

```shell-session
mysql> CREATE DATABASE database_name;
```

Run the following command to create a database namedÂ `thm_bookmarket_db`:  

Terminal

```shell-session
mysql> CREATE DATABASE thm_bookmarket_db;
```

### **SHOW DATABASES**

Now that we have created a database, we can view it using theÂ `SHOW DATABASES`Â statement. TheÂ `SHOW DATABASES`Â statement will return a list of present databases. Run the statement as follows:



```shell-session
mysql> SHOW DATABASES;
```

In the returned list, you should see the database you have just created and some databases that are included by default (mysql, information_scheme, performance_scheme and sys), which are used for various purposes that enable mysql to function. Also present are various tables needed for this lesson.

### **USE DATABASE**

Once a database is created, you may want to interact with it. Before we can interact with it, we need to tell MySQL which database we would like to interact with (so it knows which database to run subsequent queries against). To set the database we have just created as the active database, we would run theÂ `USE`Â statement as follows (make sure to run this on your machine):

 

Terminal

```shell-session
mysql> USE thm_bookmarket_db;
```

### **DROP DATABASE**

 Once a database is no longer needed (maybe it was created for test purposes, or is no longer required), it can be removed using theÂ `DROP`Â statement. To remove a database, we would use the following statement syntax (although, in our case, we want to keep our database, so no need to run this one yourself!):


Terminal

```shell-session
mysql> DROP database database_name;
```

## Table Statements

 Now that you can create, list, use, and remove databases, it's time to examine how we would populate those databases with tables and interact with those tables.Â 

### **CREATE TABLE**

 Following the logic of the database statements, creating tables also uses aÂ `CREATE`Â statement. Once a database is active (you have run theÂ `USE`Â statement on it), a table can be created within it using the following statement syntax:





```shell-session
mysql> CREATE TABLE example_table_name (
    example_column1 data_type,
    example_column2 data_type,
    example_column3 data_type
);
```

 As you can see, there is a little more involved here. In the Databases 101 task, we covered how and when a table is created; it must be decided what columns will make up a record in that table, as well as what data type is expected to be contained within that column. That is what is represented by this syntax here. In the example, there are 3 example columns, but SQL supports many (over 1000). Let's try populating ourÂ `thm_bookmarket_db`Â with a table using the following statement:





```shell-session
mysql> CREATE TABLE book_inventory (
    book_id INT AUTO_INCREMENT PRIMARY KEY,
    book_name VARCHAR(255) NOT NULL,
    publication_date DATE
);
```

This statement will create a tableÂ `book_inventory`Â with three columns:Â `book_id`,Â `book_name`Â andÂ `publication_date`.Â `book_id`Â is anÂ `INT`Â (Integer) as it should only ever be a number,Â `AUTO_INCREMENT`Â is present, meaning the first book inserted would be assigned book_id 1, the second book inserted would be assigned a book_id of 2, and so on. Finally,Â `book_id`Â is set as theÂ `PRIMARY KEY`Â as it will be the way we uniquely identify a book record in our table (and a primary must be present in a table).Â   

Book_name has the data typeÂ `VARCHAR(255)`, meaning it can variable characters (text/numbers/punctuation) and a limit of 255 characters is set andÂ `NOT NULL`, meaning it cannot be empty (so if someone tried to insert a record into this table but the book_name was empty it would be rejected. Publication_date is set as the data typeÂ `DATE`.

### **SHOW TABLES**Â 

 Just as we can list databases using a SHOW statement, we can also list the tables in our currently active database (the database on which we last used the USE statement). Run the following command, and you should see the table you have just created:



Terminal

```shell-session
mysql> SHOW TABLES;
```

### **DESCRIBE**Â   

If we want to know what columns are contained within a table (and their data type), we can describe them using theÂ `DESCRIBE`Â command (which can also be abbreviated toÂ `DESC`). Describe the table you have just created using the following command:

 

Terminal

```shell-session
mysql> DESCRIBE book_inventory;
```

### This will give you a detailed view of the table like so:

DROP Syntax

```shell-session
mysql> DESCRIBE book_inventory;
+------------------+--------------+------+-----+---------+----------------+
| Field            | Type         | Null | Key | Default | Extra          |
+------------------+--------------+------+-----+---------+----------------+
| book_id          | int          | NO   | PRI | NULL    | auto_increment |
| book_name        | varchar(255) | NO   |     | NULL    |                |
| publication_date | date         | YES  |     | NULL    |                |
+------------------+--------------+------+-----+---------+----------------+
3 rows in set (0.02 sec)
```

### **ALTER**Â   

Once you have created a table, there may come a time when your need for the dataset changes, and you need to alter the table. This can be done using theÂ `ALTER`Â statement. Letâ€™s now imagine that we have decided that we actually want to have a column in our book inventory that has the page count for each book. Add this to our table using the following statement:




```shell-session
mysql> ALTER TABLE book_inventory
ADD page_count INT;
```

TheÂ `ALTER`Â statement can be used to make changes to a table, such as renaming columns, changing the data type in a column or removing a column.Â   

### **DROP**Â   

Similar to removing a database, you can also remove tables using theÂ `DROP` statement. We donâ€™t need to do this, but the syntax you would use for this is:




```shell-session
mysql> DROP TABLE table_name;
```



# CRUD Operations

## CRUD

**CRUD**Â stands forÂ **C**reate,Â **R**ead,Â **U**pdate, andÂ **D**elete, which are considered the basic operations in any system that manages data.

Let's explore all these different operations when working withÂ **MySQL**.Â In the next two tasks, we will be using theÂ **books**Â table that is part of the databaseÂ **thm_books**. We can access it with the statementÂ `use thm_books;`.

### Create Operation (INSERT)

TheÂ **Create**Â operation will create new records in a table. In MySQL, this can be achieved by using the statementÂ `INSERT INTO`, as shown below.  

Terminal

```shell-session
mysql> INSERT INTO books (id, name, published_date, description)
    VALUES (1, "Android Security Internals", "2014-10-14", "An In-Depth Guide to Android's Security Architecture");

Query OK, 1 row affected (0.01 sec)
```

  

As we can observe, theÂ `INSERT INTO`Â statement specifies a table, in this case,Â **books**, where you can add a new record; the columnsÂ **id**,Â **name**,Â **published_date**, andÂ **description**Â are the records in the table. In this example, a new record with anÂ **id**Â ofÂ Â **1**, aÂ **name**Â ofÂ **"Android Security Internals**", aÂ **published_date**Â of "**2014-10-14**", and aÂ **description**Â stating "**Android Security Internals provides a complete understanding of the security internals of Android devices**" was added.

**Note:**Â This operation already exists in the database so there is no need to run the query.

### Read Operation (SELECT)

TheÂ **Read**Â operation, as the name suggests, is used to read or retrieve information from a table. We can fetch a column or all columns from a table with theÂ `SELECT`Â statement, as shown in the next example.  

Terminal

```shell-session
mysql> SELECT * FROM books;
+----+----------------------------+----------------+------------------------------------------------------+
| id | name                       | published_date | description                                          |
+----+----------------------------+----------------+------------------------------------------------------+
|  1 | Android Security Internals | 2014-10-14     | An In-Depth Guide to Android's Security Architecture |
+----+----------------------------+----------------+------------------------------------------------------+

1 row in set (0.00 sec)         
```

  

The above outputÂ `SELECT`Â statement is followed by anÂ `*`Â symbol indicating that all columns should be retrieved, followed by theÂ `FROM`Â clause and the table name, in this case,Â **books**.

If we want to select a specific column like theÂ **name**Â andÂ **description**, we should specify them instead of theÂ `*`Â symbol, as shown below.  

Terminal

```shell-session
mysql> SELECT name, description FROM books;
+----------------------------+------------------------------------------------------+
| name                       | description                                          |
+----------------------------+------------------------------------------------------+
| Android Security Internals | An In-Depth Guide to Android's Security Architecture |
+----------------------------+------------------------------------------------------+

1 row in set (0.00 sec)         
```

  

### Update Operation (UPDATE)

TheÂ **Update**Â operation modifies an existing record within a table, and the same statement,Â `UPDATE`, can be used for this.  

Terminal

```shell-session
mysql> UPDATE books
    SET description = "An In-Depth Guide to Android's Security Architecture."
    WHERE id = 1;

Query OK, 1 row affected (0.00 sec)
Rows matched: 1  Changed: 1  Warnings: 0     
```

  

TheÂ `UPDATE`Â statement specifies the table, in this case,Â **books**, and then we can useÂ `SET`Â followed by the column name we will update. TheÂ `WHERE`Â clause specifies which row to update when the clause is met, in this case, the one withÂ **id 1**.

### Delete Operation (DELETE)

TheÂ **delete**Â operation removes records from a table. We can achieve this with theÂ `DELETE`Â statement.

**Note:**Â There is no need to run the query. Deleting this entry will affect the rest of the examples in the upcoming tasks.

Terminal

```shell-session
mysql> DELETE FROM books WHERE id = 1;

Query OK, 1 row affected (0.00 sec)    
```

  

Above, we can observe theÂ `DELETE`Â statement followed by theÂ `FROM`Â clause, which allows us to specify the table where the record will be removed, in this case,Â **books**, followed by theÂ `WHERE`Â clause that indicates that it should be the one where theÂ **id**Â isÂ **1**.

### Summary

In summary,Â **CRUD**Â operations results are fundamental for data operations and when interacting with databases. The statements associated with them are listed below.

- **Create (INSERT statement)**Â - Adds a new record to the table.
- **Read (SELECT statement)**Â - Retrieves record from the table.
- **Update (UPDATE statement)**Â - Modifies existing data in the table.
- **Delete (DELETE statement)**Â - Removes record from the table.

These operations enable us to effectively manage and manipulate data within a database.

## QUESTIONS

![Pasted image 20241101162212.png](../../../../../IMAGES/Pasted%20image%2020241101162212.png)

# CLAUSES

A clause is a part of a statement that specifies the criteria of the data being manipulated, usually by an initial statement. Clauses can help us define the type of data and how it should be retrieved or sorted.Â 

In previous tasks, we already used some clauses, such asÂ `FROM`Â that is used to specify the table we are accessing with our statement andÂ `WHERE`, which specifies which records should be used.  

This task will focus on other clauses:Â `DISTINCT`,Â `GROUP BY`,Â `ORDER BY`, andÂ `HAVING`.  

### DISTINCT Clause

TheÂ `DISTINCT`Â clause is used to avoid duplicate records when doing a query, returning only unique values.

Let's use a queryÂ `SELECT * FROM books`Â and observe the results below.  

Terminal

```shell-session
mysql> SELECT * FROM books;
+----+----------------------------+----------------+--------------------------------------------------------+
| id | name                       | published_date | description                                            |
+----+----------------------------+----------------+--------------------------------------------------------+
|  1 | Android Security Internals | 2014-10-14     | An In-Depth Guide to Android's Security Architecture   |
|  2 | Bug Bounty Bootcamp        | 2021-11-16     | The Guide to Finding and Reporting Web Vulnerabilities |
|  3 | Car Hacker's Handbook      | 2016-02-25     | A Guide for the Penetration Tester                     |
|  4 | Designing Secure Software  | 2021-12-21     | A Guide for Developers                                 |
|  5 | Ethical Hacking            | 2021-11-02     | A Hands-on Introduction to Breaking In                 |
|  6 | Ethical Hacking            | 2021-11-02     |                                                        |
+----+----------------------------+----------------+--------------------------------------------------------+

6 rows in set (0.00 sec)
```

  

The query's output displays all the content of the tableÂ **books**, and the recordÂ **Ethical Hacking**Â is displayed twice. Let's perform the query again, but this time, using theÂ `DISTINCT`Â clause.  

Terminal

```shell-session
mysql> SELECT DISTINCT name FROM books;
+----------------------------+
| name                       |
+----------------------------+
| Android Security Internals |
| Bug Bounty Bootcamp        |
| Car Hacker's Handbook      |
| Designing Secure Software  |
| Ethical Hacking            |
+----------------------------+

5 rows in set (0.00 sec)
```

  

The output shows that only five rows are returned, and just one instance of theÂ **Ethical Hacking**Â record is displayed.

### GROUP BY Clause

TheÂ `GROUP BY`Â clause aggregates data from multiple records andÂ **groups**Â the query results in columns. This can be helpful for aggregating functions.  

Terminal

```shell-session
mysql> SELECT name, COUNT(*)
    FROM books
    GROUP BY name;
+----------------------------+----------+
| name                       | COUNT(*) |
+----------------------------+----------+
| Android Security Internals |        1 |
| Bug Bounty Bootcamp        |        1 |
| Car Hacker's Handbook      |        1 |
| Designing Secure Software  |        1 |
| Ethical Hacking            |        2 |
+----------------------------+----------+

5 rows in set (0.00 sec)
```

  

In the example above, the records on theÂ **book**Â table are regrouped by the result of theÂ `COUNT`Â function. We already know thatÂ **Ethical hacking**Â is listed twice, so the totalÂ **count**Â is 2, placed at the end since it isÂ **grouped**Â **by**Â count.

### ORDER BY Clause

TheÂ `ORDER BY`Â clause can be used to sort the records returned by a query in ascending or descending order. Using functions likeÂ `ASC`Â andÂ `DESC`Â can help us to accomplish that, as shown below in the next two examples.

**ASCENDING ORDER**

Terminal

```shell-session
mysql> SELECT *
    FROM books
    ORDER BY published_date ASC;
+----+----------------------------+----------------+--------------------------------------------------------+
| id | name                       | published_date | description                                            |
+----+----------------------------+----------------+--------------------------------------------------------+
|  1 | Android Security Internals | 2014-10-14     | An In-Depth Guide to Android's Security Architecture   |
|  3 | Car Hacker's Handbook      | 2016-02-25     | A Guide for the Penetration Tester                     |
|  5 | Ethical Hacking            | 2021-11-02     | A Hands-on Introduction to Breaking In                 |
|  6 | Ethical Hacking            | 2021-11-02     |                                                        |
|  2 | Bug Bounty Bootcamp        | 2021-11-16     | The Guide to Finding and Reporting Web Vulnerabilities |
|  4 | Designing Secure Software  | 2021-12-21     | A Guide for Developers                                 |
+----+----------------------------+----------------+--------------------------------------------------------+

6 rows in set (0.00 sec)
```

  
**DESCENDING ORDER**

Terminal

```shell-session
mysql> SELECT *
    FROM books
    ORDER BY published_date DESC;
+----+----------------------------+----------------+--------------------------------------------------------+
| id | name                       | published_date | description                                            |
+----+----------------------------+----------------+--------------------------------------------------------+
|  4 | Designing Secure Software  | 2021-12-21     | A Guide for Developers                                 |
|  2 | Bug Bounty Bootcamp        | 2021-11-16     | The Guide to Finding and Reporting Web Vulnerabilities |
|  5 | Ethical Hacking            | 2021-11-02     | A Hands-on Introduction to Breaking In                 |
|  6 | Ethical Hacking            | 2021-11-02     |                                                        |
|  3 | Car Hacker's Handbook      | 2016-02-25     | A Guide for the Penetration Tester                     |
|  1 | Android Security Internals | 2014-10-14     | An In-Depth Guide to Android's Security Architecture   |
+----+----------------------------+----------------+--------------------------------------------------------+

6 rows in set (0.00 sec)
```

  

We can observe the difference when sorting by ascending order usingÂ `ASC`Â and in descending order usingÂ `DESC`, both using theÂ **publised_date**Â as reference.  

  

### HAVING Clause

TheÂ `HAVING`Â clause is used with other clauses to filter groups or results of records based on a condition. In the case ofÂ `GROUP BY`, it evaluates the condition toÂ `TRUE`Â orÂ `FALSE`, unlike theÂ `WHERE`Â clauseÂ `HAVING`Â filters the results after the aggregation is performed.  

Terminal

```shell-session
mysql> SELECT name, COUNT(*)
    FROM books
    GROUP BY name
    HAVING name LIKE '%Hack%';
+-----------------------+----------+
| name                  | COUNT(*) |
+-----------------------+----------+
| Car Hacker's Handbook |        1 |
| Ethical Hacking       |        2 |
+-----------------------+----------+

2 rows in set (0.00 sec)
```

  

In the example above, we can observe that the query returns the books with the names that contain the wordÂ **hack**Â and the proper count, as we learned before.

## QUESTIONS

![Pasted image 20241101162318.png](../../../../../IMAGES/Pasted%20image%2020241101162318.png)

# OPERATORS

When working withÂ **SQL**Â and dealing with logic and comparisons,Â **operators**Â are our way to filter and manipulate data effectively.Â Understanding these operators will help us to create more precise and powerful queries.Â In the next two tasks, we will be using theÂ **books**Â table that is part of the databaseÂ **thm_books2**. We can access it with the statementÂ `use thm_books2;`.

## Logical Operators

These operators test the truth of a condition and return a boolean value ofÂ `TRUE`Â orÂ `FALSE`. Let's explore some of these operators next.  

### LIKE Operator

TheÂ `LIKE`Â operator is commonly used in conjunction with clauses likeÂ `WHERE`Â in order to filter for specific patterns within a column. Let's continue using our DataBase to query an example of its usage.  

Terminal

```shell-session
mysql> SELECT *
    FROM books
    WHERE description LIKE "%guide%";
+----+----------------------------+----------------+--------------------------------------------------------+--------------------+
| id | name                       | published_date | description                                            | category           |
+----+----------------------------+----------------+--------------------------------------------------------+--------------------+
|  1 | Android Security Internals | 2014-10-14     | An In-Depth Guide to Android's Security Architecture   | Defensive Security |
|  2 | Bug Bounty Bootcamp        | 2021-11-16     | The Guide to Finding and Reporting Web Vulnerabilities | Offensive Security |
|  3 | Car Hacker's Handbook      | 2016-02-25     | A Guide for the Penetration Tester                     | Offensive Security |
|  4 | Designing Secure Software  | 2021-12-21     | A Guide for Developers                                 | Defensive Security |
+----+----------------------------+----------------+--------------------------------------------------------+--------------------+

4 rows in set (0.00 sec)  
```

  

The query above returns a list of records from the books filtered, but the ones using theÂ `WHERE`Â clause that contains the word guide by using theÂ `LIKE`Â operator.  

### AND Operator

TheÂ `AND`Â operator uses multiple conditions within a query and returnsÂ `TRUE`Â if all of them are true.  

Terminal

```shell-session
mysql> SELECT *
    FROM books
    WHERE category = "Offensive Security" AND name = "Bug Bounty Bootcamp"; 
+----+---------------------+----------------+--------------------------------------------------------+--------------------+
| id | name                | published_date | description                                            | category           |
+----+---------------------+----------------+--------------------------------------------------------+--------------------+
|  2 | Bug Bounty Bootcamp | 2021-11-16     | The Guide to Finding and Reporting Web Vulnerabilities | Offensive Security |
+----+---------------------+----------------+--------------------------------------------------------+--------------------+
    
1 row in set (0.00 sec)  
```

  

The query above returns the book with the nameÂ **Bug Bounty Bootcamp**, which is under the category ofÂ **Offensive Security**.  

### OR Operator

TheÂ `OR`Â operator combines multiple conditions within queries and returnsÂ `TRUE`Â if at least one of these conditions is true.  

Terminal

```shell-session
mysql> SELECT *
    FROM books
    WHERE name LIKE "%Android%" OR name LIKE "%iOS%"; 
+----+----------------------------+----------------+------------------------------------------------------+--------------------+
| id | name                       | published_date | description                                          | category           |
+----+----------------------------+----------------+------------------------------------------------------+--------------------+
|  1 | Android Security Internals | 2014-10-14     | An In-Depth Guide to Android's Security Architecture | Defensive Security |
+----+----------------------------+----------------+------------------------------------------------------+--------------------+

1 row in set (0.00 sec)
```

  

The query above returns books whoseÂ **names**Â include eitherÂ **Android**Â orÂ **IOS**.  

### NOT Operator

TheÂ `NOT`Â operator reverses the value of a boolean operator, allowing us to exclude a specific condition.  

Terminal

```shell-session
mysql> SELECT *
    FROM books
    WHERE NOT description LIKE "%guide%";
+----+-----------------+----------------+----------------------------------------+--------------------+
| id | name            | published_date | description                            | category           |
+----+-----------------+----------------+----------------------------------------+--------------------+
|  5 | Ethical Hacking | 2021-11-02     | A Hands-on Introduction to Breaking In | Offensive Security |
+----+-----------------+----------------+----------------------------------------+--------------------+

1 row in set (0.00 sec)
```

  

The query above returns results where the description does not contain the wordÂ **guide**.  

### BETWEEN Operator

TheÂ `BETWEEN`Â operator allows us to test if a value exists within a definedÂ **range**.  

Terminal

```shell-session
mysql> SELECT *
    FROM books
    WHERE id BETWEEN 2 AND 4;
+----+---------------------------+----------------+--------------------------------------------------------+--------------------+
| id | name                      | published_date | description                                            | category           |
+----+---------------------------+----------------+--------------------------------------------------------+--------------------+
|  2 | Bug Bounty Bootcamp       | 2021-11-16     | The Guide to Finding and Reporting Web Vulnerabilities | Offensive Security |
|  3 | Car Hacker's Handbook     | 2016-02-25     | A Guide for the Penetration Tester                     | Offensive Security |
|  4 | Designing Secure Software | 2021-12-21     | A Guide for Developers                                 | Defensive Security |
+----+---------------------------+----------------+--------------------------------------------------------+--------------------+

3 rows in set (0.00 sec)
```

  

The query above returns books whoseÂ **id**Â isÂ **between 2**Â andÂ **4**.

## Comparison Operators

The comparison operators are used to compare values and check if they meet specified criteria.  

### Equal To Operator

TheÂ `=`Â (Equal) operator compares two expressions and determines if they are equal, or it can check if a value matches another one in a specific column.  

Terminal

```shell-session
mysql> SELECT *
    FROM books
    WHERE name = "Designing Secure Software";
+----+---------------------------+----------------+------------------------+--------------------+
| id | name                      | published_date | description            | category           |
+----+---------------------------+----------------+------------------------+--------------------+
|  4 | Designing Secure Software | 2021-12-21     | A Guide for Developers | Defensive Security |
+----+---------------------------+----------------+------------------------+--------------------+

1 row in set (0.10 sec)
```

  

The query above returns the book with theÂ **exact name Designing Secure Software**.

### Not Equal To Operator

TheÂ `!=`Â (not equal) operator compares expressions and tests if they are not equal; it also checks if a value differs from the one within a column.  

Terminal

```shell-session
mysql> SELECT *
    FROM books
    WHERE category != "Offensive Security";
+----+----------------------------+----------------+------------------------------------------------------+--------------------+
| id | name                       | published_date | description                                          | category           |
+----+----------------------------+----------------+------------------------------------------------------+--------------------+
|  1 | Android Security Internals | 2014-10-14     | An In-Depth Guide to Android's Security Architecture | Defensive Security |
|  4 | Designing Secure Software  | 2021-12-21     | A Guide for Developers                               | Defensive Security |
+----+----------------------------+----------------+------------------------------------------------------+--------------------+

2 rows in set (0.00 sec)
```

  

The query above returns booksÂ **except**Â those whoseÂ **category**Â isÂ **Offensive Security**.

### Less Than Operator

Less Than Operator

TheÂ `<`Â (less than) operator compares if the expression with a given value is lesser than the provided one.

Terminal

```shell-session
mysql> SELECT *
    FROM books
    WHERE published_date < "2020-01-01";
+----+----------------------------+----------------+------------------------------------------------------+--------------------+
| id | name                       | published_date | description                                          | category           |
+----+----------------------------+----------------+------------------------------------------------------+--------------------+
|  1 | Android Security Internals | 2014-10-14     | An In-Depth Guide to Android's Security Architecture | Defensive Security |
|  3 | Car Hacker's Handbook      | 2016-02-25     | A Guide for the Penetration Tester                   | Offensive Security |
+----+----------------------------+----------------+------------------------------------------------------+--------------------+

2 rows in set (0.00 sec)
```

  

The query above returns books that were publishedÂ **before January 1, 2020**.

### Greater Than Operator

TheÂ `>`Â (greater than) operator compares if the expression with a given value is greater than the provided one.  

Terminal

```shell-session
mysql> SELECT *
    FROM books
    WHERE published_date > "2020-01-01";
+----+---------------------------+----------------+--------------------------------------------------------+--------------------+
| id | name                      | published_date | description                                            | category           |
+----+---------------------------+----------------+--------------------------------------------------------+--------------------+
|  2 | Bug Bounty Bootcamp       | 2021-11-16     | The Guide to Finding and Reporting Web Vulnerabilities | Offensive Security |
|  4 | Designing Secure Software | 2021-12-21     | A Guide for Developers                                 | Defensive Security |
|  5 | Ethical Hacking           | 2021-11-02     | A Hands-on Introduction to Breaking In                 | Offensive Security |
+----+---------------------------+----------------+--------------------------------------------------------+--------------------+

3 rows in set (0.00 sec)
```

  

The query above returns books publishedÂ **after**Â **January 1, 2020**.

### Less Than or Equal To and GreaterÂ Â Than or Equal ToÂ Operators

TheÂ `<=`Â (Less than or equal) operator compares if the expression with a given value is less than or equal to the provided one. On the other hand, TheÂ `>=`Â (Greater than or Equal) operator compares if the expression with a given value is greater than or equal to the provided one. Let's observe some examples of both below.  

Terminal

```shell-session
mysql> SELECT *
    FROM books
    WHERE published_date <= "2021-11-15";
+----+----------------------------+----------------+------------------------------------------------------+--------------------+
| id | name                       | published_date | description                                          | category           |
+----+----------------------------+----------------+------------------------------------------------------+--------------------+
|  1 | Android Security Internals | 2014-10-14     | An In-Depth Guide to Android's Security Architecture | Defensive Security |
|  3 | Car Hacker's Handbook      | 2016-02-25     | A Guide for the Penetration Tester                   | Offensive Security |
|  5 | Ethical Hacking            | 2021-11-02     | A Hands-on Introduction to Breaking In               | Offensive Security |
+----+----------------------------+----------------+------------------------------------------------------+--------------------+

3 rows in set (0.00 sec)
```

  

The query above returns booksÂ **published on**Â **or before**Â **November 15, 2021**.

Terminal

```shell-session
mysql> SELECT *
    FROM books
    WHERE published_date >= "2021-11-02";
+----+---------------------------+----------------+--------------------------------------------------------+--------------------+
| id | name                      | published_date | description                                            | category           |
+----+---------------------------+----------------+--------------------------------------------------------+--------------------+
|  2 | Bug Bounty Bootcamp       | 2021-11-16     | The Guide to Finding and Reporting Web Vulnerabilities | Offensive Security |
|  4 | Designing Secure Software | 2021-12-21     | A Guide for Developers                                 | Defensive Security |
|  5 | Ethical Hacking           | 2021-11-02     | A Hands-on Introduction to Breaking In                 | Offensive Security |
+----+---------------------------+----------------+--------------------------------------------------------+--------------------+

3 rows in set (0.00 sec)
```

  

The query above returns books that wereÂ **published on or after November 2, 2021**.

## QUESTIONS

![Pasted image 20241101162405.png](../../../../../IMAGES/Pasted%20image%2020241101162405.png)

# FUNCTIONS



When working with Data, functions can help us streamline queries and operations and manipulate data. Let's explore some of these functions next.

String Functions

Strings functions perform operations on a string, returning a value associated with it.

## CONCAT() Function

This function is used to add two or more strings together. It is useful to combine text from different columns.  

Terminal

```shell-session
mysql> SELECT CONCAT(name, " is a type of ", category, " book.") AS book_info FROM books;
+------------------------------------------------------------------+
| book_info                                                         |
+------------------------------------------------------------------+
| Android Security Internals is a type of Defensive Security book. |
| Bug Bounty Bootcamp is a type of Offensive Security book.        |
| Car Hacker's Handbook is a type of Offensive Security book.      |
| Designing Secure Software is a type of Defensive Security book.  |
| Ethical Hacking is a type of Offensive Security book.            |
+------------------------------------------------------------------+

5 rows in set (0.00 sec)  
```

  

This query concatenates theÂ **name**Â andÂ **category**Â columns from theÂ **books**Â table into a single one namedÂ **book_info**.

## GROUP_CONCAT() Function

This function can help us to concatenate data from multiple rows into one field. Let's explore an example of its usage.  

Terminal

```shell-session
mysql> SELECT category, GROUP_CONCAT(name SEPARATOR ", ") AS books
    FROM books
    GROUP BY category;
+--------------------+-------------------------------------------------------------+
| category           | books                                                       |
+--------------------+-------------------------------------------------------------+
| Defensive Security | Android Security Internals, Designing Secure Software       |
| Offensive Security | Bug Bounty Bootcamp, Car Hacker's Handbook, Ethical Hacking |
+--------------------+-------------------------------------------------------------+

2 rows in set (0.01 sec)
```

  

The query above groups theÂ **books**Â byÂ **category**Â and concatenates the titles of books within each category into aÂ **single string**.

## SUBSTRING() Function

This function will retrieve a substring from a string within a query, starting at a determined position. The length of this substring can also be specified.  

Terminal

```shell-session
mysql> SELECT SUBSTRING(published_date, 1, 4) AS published_year FROM books;
+----------------+
| published_year |
+----------------+
| 2014           |
| 2021           |
| 2016           |
| 2021           |
| 2021           |
+----------------+

5 rows in set (0.00 sec)  
```

  

In the query above, we can observe how it extracts the firstÂ **four**Â characters from theÂ **published_date**Â column and stores them in theÂ **published_year**Â column.

## LENGTH() Function

This function returns the number of characters in a string. This includes spaces and punctuation. We can find an example below.  

Terminal

```shell-session
mysql> SELECT LENGTH(name) AS name_length FROM books;
+-------------+
| name_length |
+-------------+
|          26 |
|          19 |
|          21 |
|          25 |
|          15 |
+-------------+

5 rows in set (0.00 sec)  
```

  

As we can observe above, the query calculates the length of the string within theÂ **name**Â column and stores it in a column namedÂ **name_length**.

## Aggregate Functions

These functions aggregate the value of multiple rows within one specified criteria in the query; It can combine multiple values into one result.

## COUNT() Function

This function returns the number of records within an expression, as the example below shows.  

Terminal

```shell-session
mysql> SELECT COUNT(*) AS total_books FROM books;
+-------------+
| total_books |
+-------------+
|           5 |
+-------------+

1 row in set (0.01 sec)
```

  

This query above counts the total number of rows in theÂ **books**Â table. The result isÂ **5**, as there are five books in the books table, and it's stored in theÂ **total_books**Â column.

## SUM() Function

This function sums all values (not NULL) of a determined column.

**Note:**Â There is no need to execute this query. This is just for example purposes.



```shell-session
mysql> SELECT SUM(price) AS total_price FROM books;
+-------------+
| total_price |
+-------------+
|      249.95 |
+-------------+

1 row in set (0.00 sec)
```

  

The query above calculates the total sum of theÂ **price**Â column. The result provides the aggregate price of all books in the columnÂ **total_price**.

## MAX() Function

This function calculates the maximum value within a provided column in an expression.  

Terminal

```shell-session
mysql> SELECT MAX(published_date) AS latest_book FROM books;
+-------------+
| latest_book |
+-------------+
| 2021-12-21  |
+-------------+

1 row in set (0.00 sec)
```

  

The query above retrieves the latest publication (maximum value) date from theÂ **books**Â table. The resultÂ **2021-12-21**Â is stored in the columnÂ **latest_book**.

## MIN() Function

This function calculates the minimum value within a provided column in an expression.  

Terminal

```shell-session
mysql> SELECT MIN(published_date) AS earliest_book FROM books;
+---------------+
| earliest_book |
+---------------+
| 2014-10-14    |
+---------------+

1 row in set (0.00 sec)
```

  

The query above retrieves the earliest publication (minimum value) date from theÂ **books**Â table. The resultÂ **2014-10-14**Â is stored in theÂ **earliest_book**Â column.


## QUESTIONS

![Pasted image 20241101162512.png](../../../../../IMAGES/Pasted%20image%2020241101162512.png)

# IMPORTANT

FOR A DEEPER UNDERSTANDING OF THIS ROOM, VISIT THIS LINK: [LINK](https://sunnysinghverma.medium.com/sql-fundamentals-cybersecurity-101-learning-path-tryhackme-writeup-detailed-walkthrough-33063da32b2f)


