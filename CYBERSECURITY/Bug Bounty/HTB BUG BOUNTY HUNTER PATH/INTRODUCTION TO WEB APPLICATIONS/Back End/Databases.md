---
sticker: lucide//curly-braces
---

Web applications utilize back endÂ [databases](https://en.wikipedia.org/wiki/Database)Â to store various content and information related to the web application. This can be core web application assets like images and files, web application content like posts and updates, or user data like usernames and passwords. This allows web applications to easily and quickly store and retrieve data and enable dynamic content that is different for each user.

There are many different types of databases, each of which fits a certain type of use. Most developers look for certain characteristics in a database, such asÂ `speed`Â in storing and retrieving data,Â `size`Â when storing large amounts of data,Â `scalability`Â as the web application grows, andÂ `cost`.

---

## Relational (SQL)

[Relational](https://en.wikipedia.org/wiki/Relational_database)Â (SQL) databases store their data in tables, rows, and columns. Each table can have unique keys, which can link tables together and create relationships between tables.

For example, we can have aÂ `users`Â table in a relational database containing columns likeÂ `id`,Â `username`,Â `first_name`,Â `last_name`, and so on. TheÂ `id`Â can be used as the table key. Another table,Â `posts`, may contain posts made by all users, with columns likeÂ `id`,Â `user_id`,Â `date`,Â `content`, and so on.

![HTML Example](https://academy.hackthebox.com/storage/modules/75/web_apps_relational_db.jpg)

We can link theÂ `id`Â from theÂ `users`Â table to theÂ `user_id`Â in theÂ `posts`Â table to easily retrieve the user details for each post, without having to store all user details with each post.

A table can have more than one key, as another column can be used as a key to link with another table. For example, theÂ `id`Â column can be used as a key to link theÂ `posts`Â table to another table containing comments, each of which belongs to a certain post, and so on.

The relationship between tables within a database is called a Schema.

This way, by using relational databases, it becomes very quick and easy to retrieve all data about a certain element from all databases. For example, we can retrieve all details linked to a certain user from all tables with a single query. This makes relational databases very fast and reliable for big datasets that have a clear structure and design. Databases also make data management very efficient.

Some of the most common relational databases include:

|Type|Description|
|---|---|
|[MySQL](https://en.wikipedia.org/wiki/MySQL)|The most commonly used database around the internet. It is an open-source database and can be used completely free of charge|
|[MSSQL](https://en.wikipedia.org/wiki/Microsoft_SQL_Server)|Microsoft's implementation of a relational database. Widely used with Windows Servers and IIS web servers|
|[Oracle](https://en.wikipedia.org/wiki/Oracle_Database)|A very reliable database for big businesses, and is frequently updated with innovative database solutions to make it faster and more reliable. It can be costly, even for big businesses|
|[PostgreSQL](https://en.wikipedia.org/wiki/PostgreSQL)|Another free and open-source relational database. It is designed to be easily extensible, enabling adding advanced new features without needing a major change to the initial database design|

Other common SQL databases include:Â `SQLite`,Â `MariaDB`,Â `Amazon Aurora`, andÂ `Azure SQL`.

---

## Non-relational (NoSQL)

AÂ [non-relational database](https://en.wikipedia.org/wiki/NoSQL)Â does not use tables, rows, columns, primary keys, relationships, or schemas. Instead, aÂ `NoSQL`Â database stores data using various storage models, depending on the type of data stored.

Due to the lack of a defined structure for the database,Â `NoSQL`Â databases are very scalable and flexible. When dealing with datasets that are not very well defined and structured, aÂ `NoSQL`Â database would be the best choice for storing our data.

There are 4 common storage models forÂ `NoSQL`Â databases:

- Key-Value
- Document-Based
- Wide-Column
- Graph

Each of the above models has a different way of storing data. For example, theÂ `Key-Value`Â model usually stores data inÂ `JSON`Â orÂ `XML`, and has a key for each pair, storing all of its data as its value:

![HTML Example](https://academy.hackthebox.com/storage/modules/75/web_apps_non-relational_db.jpg)

The above example can be represented usingÂ `JSON`Â as follows:

Code:Â json

```json
{
  "100001": {
    "date": "01-01-2021",
    "content": "Welcome to this web application."
  },
  "100002": {
    "date": "02-01-2021",
    "content": "This is the first post on this web app."
  },
  "100003": {
    "date": "02-01-2021",
    "content": "Reminder: Tomorrow is the ..."
  }
}
```

It looks similar to a dictionary/map/key-value pair in languages likeÂ `Python`Â orÂ `PHP`Â 'i.e.Â `{'key':'value'}`', where theÂ `key`Â is usually a string, theÂ `value`Â can be a string, dictionary, or any class object.

TheÂ `Document-Based`Â model stores data in complexÂ `JSON`Â objects and each object has certain meta-data while storing the rest of the data similarly to theÂ `Key-Value`Â model.

Some of the most commonÂ `NoSQL`Â databases include:

|Type|Description|
|---|---|
|[MongoDB](https://en.wikipedia.org/wiki/MongoDB)|The most commonÂ `NoSQL`Â database. It is free and open-source, uses theÂ `Document-Based`Â model, and stores data inÂ `JSON`Â objects|
|[ElasticSearch](https://en.wikipedia.org/wiki/Elasticsearch)|Another free and open-sourceÂ `NoSQL`Â database. It is optimized for storing and analyzing huge datasets. As its name suggests, searching for data within this database is very fast and efficient|
|[Apache Cassandra](https://en.wikipedia.org/wiki/Apache_Cassandra)|Also free and open-source. It is very scalable and is optimized for gracefully handling faulty values|

Other commonÂ `NoSQL`Â databases include:Â `Redis`,Â `Neo4j`,Â `CouchDB`, andÂ `Amazon DynamoDB`.

---

## Use in Web Applications

Most modern web development languages and frameworks make it easy to integrate, store, and retrieve data from various database types. But first, the database has to be installed and set up on the back end server, and once it is up and running, the web applications can start utilizing it to store and retrieve data.

For example, within aÂ `PHP`Â web application, onceÂ `MySQL`Â is up and running, we can connect to the database server with:

Code:Â php

```php
$conn = new mysqli("localhost", "user", "pass");
```

Then, we can create a new database with:

Code:Â php

```php
$sql = "CREATE DATABASE database1";
$conn->query($sql)
```

After that, we can connect to our new database, and start using theÂ `MySQL`Â database throughÂ `MySQL`Â syntax, right withinÂ `PHP`, as follows:

Code:Â php

```php
$conn = new mysqli("localhost", "user", "pass", "database1");
$query = "select * from table_1";
$result = $conn->query($query);
```

Web applications usually use user-input when retrieving data. For example, when a user uses the search function to search for other users, their search input is passed to the web application, which uses the input to search within the database(s).

Code:Â php

```php
$searchInput =  $_POST['findUser'];
$query = "select * from users where name like '%$searchInput%'";
$result = $conn->query($query);
```

Finally, the web application sends the result back to the user:

Code:Â php

```php
while($row = $result->fetch_assoc() ){
	echo $row["name"]."<br>";
}
```

This basic example shows us how easy it is to utilize databases. However, if not securely coded, database code can lead to a variety of issues, likeÂ [SQL Injection vulnerabilities](https://owasp.org/www-community/attacks/SQL_Injection).
