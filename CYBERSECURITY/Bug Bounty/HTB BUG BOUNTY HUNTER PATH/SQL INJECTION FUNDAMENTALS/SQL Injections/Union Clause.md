---
sticker: lucide//database
---
So far, we have only been manipulating the original query to subvert the web application logic and bypass authentication, using theÂ `OR`Â operator and comments. However, another type of SQL injection is injecting entire SQL queries executed along with the original query. This section will demonstrate this by using the MySQLÂ `Union`Â clause to doÂ `SQL Union Injection`.

---

## Union

Before we start learning about Union Injection, we should first learn more about the SQL Union clause. TheÂ [Union](https://dev.mysql.com/doc/refman/8.0/en/union.html)Â clause is used to combine results from multipleÂ `SELECT`Â statements. This means that through aÂ `UNION`Â injection, we will be able toÂ `SELECT`Â and dump data from all across the DBMS, from multiple tables and databases. Let us try using theÂ `UNION`Â operator in a sample database. First, let us see the content of theÂ `ports`Â table:

```shell-session
mysql> SELECT * FROM ports;

+----------+-----------+
| code     | city      |
+----------+-----------+
| CN SHA   | Shanghai  |
| SG SIN   | Singapore |
| ZZ-21    | Shenzhen  |
+----------+-----------+
3 rows in set (0.00 sec)
```

Next, let us see the output of theÂ `ships`Â tables:


```shell-session
mysql> SELECT * FROM ships;

+----------+-----------+
| Ship     | city      |
+----------+-----------+
| Morrison | New York  |
+----------+-----------+
1 rows in set (0.00 sec)
```

Now, let us try to useÂ `UNION`Â to combine both results:


```shell-session
mysql> SELECT * FROM ports UNION SELECT * FROM ships;

+----------+-----------+
| code     | city      |
+----------+-----------+
| CN SHA   | Shanghai  |
| SG SIN   | Singapore |
| Morrison | New York  |
| ZZ-21    | Shenzhen  |
+----------+-----------+
4 rows in set (0.00 sec)
```

As we can see,Â `UNION`Â combined the output of bothÂ `SELECT`Â statements into one, so entries from theÂ `ports`Â table and theÂ `ships`Â table were combined into a single output with four rows. As we can see, some of the rows belong to theÂ `ports`Â table while others belong to theÂ `ships`Â table.

Note: The data types of the selected columns on all positions should be the same.

---

## Even Columns

AÂ `UNION`Â statement can only operate onÂ `SELECT`Â statements with an equal number of columns. For example, if we attempt toÂ `UNION`Â two queries that have results with a different number of columns, we get the following error:


```shell-session
mysql> SELECT city FROM ports UNION SELECT * FROM ships;

ERROR 1222 (21000): The used SELECT statements have a different number of columns
```

The above query results in an error, as the firstÂ `SELECT`Â returns one column and the secondÂ `SELECT`Â returns two. Once we have two queries that return the same number of columns, we can use theÂ `UNION`Â operator to extract data from other tables and databases.

For example, if the query is:

```sql
SELECT * FROM products WHERE product_id = 'user_input'
```

We can inject aÂ `UNION`Â query into the input, such that rows from another table are returned:

```sql
SELECT * from products where product_id = '1' UNION SELECT username, password from passwords-- '
```

The above query would returnÂ `username`Â andÂ `password`Â entries from theÂ `passwords`Â table, assuming theÂ `products`Â table has two columns.

---

## Un-even Columns

We will find out that the original query will usually not have the same number of columns as the SQL query we want to execute, so we will have to work around that. For example, suppose we only had one column. In that case, we want toÂ `SELECT`, we can put junk data for the remaining required columns so that the total number of columns we areÂ `UNION`ing with remains the same as the original query.

For example, we can use any string as our junk data, and the query will return the string as its output for that column. If weÂ `UNION`Â with the stringÂ `"junk"`, theÂ `SELECT`Â query would beÂ `SELECT "junk" from passwords`, which will always returnÂ `junk`. We can also use numbers. For example, the queryÂ `SELECT 1 from passwords`Â will always returnÂ `1`Â as the output.

Note: When filling other columns with junk data, we must ensure that the data type matches the columns data type, otherwise the query will return an error. For the sake of simplicity, we will use numbers as our junk data, which will also become handy for tracking our payloads positions, as we will discuss later.

Tip: For advanced SQL injection, we may want to simply use 'NULL' to fill other columns, as 'NULL' fits all data types.

TheÂ `products`Â table has two columns in the above example, so we have toÂ `UNION`Â with two columns. If we only wanted to get one column 'e.g.Â `username`', we have to doÂ `username, 2`, such that we have the same number of columns:

```sql
SELECT * from products where product_id = '1' UNION SELECT username, 2 from passwords
```

If we had more columns in the table of the original query, we have to add more numbers to create the remaining required columns. For example, if the original query usedÂ `SELECT`Â on a table with four columns, ourÂ `UNION`Â injection would be:

```sql
UNION SELECT username, 2, 3, 4 from passwords-- '
```

This query would return:

```shell-session
mysql> SELECT * from products where product_id UNION SELECT username, 2, 3, 4 from passwords-- '

+-----------+-----------+-----------+-----------+
| product_1 | product_2 | product_3 | product_4 |
+-----------+-----------+-----------+-----------+
|   admin   |    2      |    3      |    4      |
+-----------+-----------+-----------+-----------+
```

As we can see, our wanted output of the '`UNION SELECT username from passwords`' query is found at the first column of the second row, while the numbers filled the remaining columns.

# Question
---

![Pasted image 20250131165907.png](../../../../IMAGES/Pasted%20image%2020250131165907.png)

We can use the following in order to check:

```ad-hint
1. `select * from employees limit 5;`
2. `select * from departments limit 5;`
3. `select dept_no FROM departments UNION select emp_no FROM employees;`
```

Let's ask DeepSeek for a further understanding of the process:


#### **1.Â `SELECT * FROM employees LIMIT 5;`**

- **Purpose**:  
    This query retrieves theÂ **first 5 rows**Â from theÂ `employees`Â table.  
    Youâ€™re checking:
    
    - The structure of the table (e.g., columns likeÂ `emp_no`,Â `first_name`, etc.).
        
    - Sample data to confirm theÂ `emp_no`Â column exists.
        
- **Example Output**:
``
    
    +--------+------------+------------+-----------+--------+------------+
    | emp_no | first_name | last_name  | hire_date | salary | dept_no    |
    +--------+------------+------------+-----------+--------+------------+
    | 1001   | John       | Doe        | 2020-01-01| 50000  | NULL       |
    | 1002   | Jane       | Smith      | 2019-05-15| 60000  | D01        |
    | ...    | ...        | ...        | ...       | ...    | ...        |
    +--------+------------+------------+-----------+--------+------------+
    

---

#### **2.Â `SELECT * FROM departments LIMIT 5;`**

- **Purpose**:  
    This query retrieves theÂ **first 5 rows**Â from theÂ `departments`Â table.  
    Youâ€™re checking:
    
    - The structure of the table (e.g., columns likeÂ `dept_no`,Â `dept_name`).
        
    - Sample data to confirm theÂ `dept_no`Â column exists.
        
- **Example Output**:
``
    
    +---------+------------------+
    | dept_no | dept_name        |
    +---------+------------------+
    | D01     | Sales            |
    | D02     | Engineering      |
    | ...     | ...              |
    +---------+------------------+
``
    

---

#### **3.Â `SELECT dept_no FROM departments UNION SELECT emp_no FROM employees;`**

- **Purpose**:  
    This combines theÂ `dept_no`Â column fromÂ `departments`Â and theÂ `emp_no`Â column fromÂ `employees`Â usingÂ `UNION`.
    
- **Key Notes**:
    
    - `UNION`Â requires bothÂ `SELECT`Â statements to have theÂ **same number of columns**.
        
        - âœ… Here, bothÂ `dept_no`Â andÂ `emp_no`Â are single columns.
            
    - `UNION`Â removes duplicate rows. UseÂ `UNION ALL`Â to retain duplicates.
        
    - Data types must match. IfÂ `dept_no`Â is a string (e.g.,Â `D01`) andÂ `emp_no`Â is an integer (e.g.,Â `1001`), this will fail.
        
- **Example Output**:
    
```
    
    +---------+
    | dept_no |  -- Column name from the first SELECT
    +---------+
    | D01     |  -- From departments
    | D02     |
    | 1001    |  -- From employees (if emp_no is compatible)
    | 1002    |
    +---------+
```
    

---

### **What This Achieves**

1. **Step 1 & 2**: Verify the existence and structure of theÂ `employees`Â andÂ `departments`Â tables.
    
2. **Step 3**: CombineÂ `dept_no`Â andÂ `emp_no`Â into a single list, removing duplicates.
    

---


Once we do the command, we get the following amount of records:

```
| 10652   |
| 10653   |
| 10654   |
+---------+
663 rows in set (0.078 sec)
```

Answer is `663`.

