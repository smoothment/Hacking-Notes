---
sticker: lucide//database
---
Sometimes, expressions with a single condition are not enough to satisfy the user's requirement. For that, SQL supportsÂ [Logical Operators](https://dev.mysql.com/doc/refman/8.0/en/logical-operators.html)Â to use multiple conditions at once. The most common logical operators areÂ `AND`,Â `OR`, andÂ `NOT`.

---

## AND Operator

TheÂ `AND`Â operator takes in two conditions and returnsÂ `true`Â orÂ `false`Â based on their evaluation:


```sql
condition1 AND condition2
```

The result of theÂ `AND`Â operation isÂ `true`Â if and only if bothÂ `condition1`Â andÂ `condition2`Â evaluate toÂ `true`:


```shell-session
mysql> SELECT 1 = 1 AND 'test' = 'test';

+---------------------------+
| 1 = 1 AND 'test' = 'test' |
+---------------------------+
|                         1 |
+---------------------------+
1 row in set (0.00 sec)

mysql> SELECT 1 = 1 AND 'test' = 'abc';

+--------------------------+
| 1 = 1 AND 'test' = 'abc' |
+--------------------------+
|                        0 |
+--------------------------+
1 row in set (0.00 sec)
```

In MySQL terms, anyÂ `non-zero`Â value is consideredÂ `true`, and it usually returns the valueÂ `1`Â to signifyÂ `true`.Â `0`Â is consideredÂ `false`. As we can see in the example above, the first query returnedÂ `true`Â as both expressions were evaluated asÂ `true`. However, the second query returnedÂ `false`Â as the second conditionÂ `'test' = 'abc'`Â isÂ `false`.

---

## OR Operator

TheÂ `OR`Â operator takes in two expressions as well, and returnsÂ `true`Â when at least one of them evaluates toÂ `true`:


```shell-session
mysql> SELECT 1 = 1 OR 'test' = 'abc';

+-------------------------+
| 1 = 1 OR 'test' = 'abc' |
+-------------------------+
|                       1 |
+-------------------------+
1 row in set (0.00 sec)

mysql> SELECT 1 = 2 OR 'test' = 'abc';

+-------------------------+
| 1 = 2 OR 'test' = 'abc' |
+-------------------------+
|                       0 |
+-------------------------+
1 row in set (0.00 sec)
```

The queries above demonstrate how theÂ `OR`Â operator works. The first query evaluated toÂ `true`Â as the conditionÂ `1 = 1`Â isÂ `true`. The second query has twoÂ `false`Â conditions, resulting inÂ `false`Â output.

---

## NOT Operator

TheÂ `NOT`Â operator simply toggles aÂ `boolean`Â value 'i.e.Â `true`Â is converted toÂ `false`Â and vice versa':


```shell-session
mysql> SELECT NOT 1 = 1;

+-----------+
| NOT 1 = 1 |
+-----------+
|         0 |
+-----------+
1 row in set (0.00 sec)

mysql> SELECT NOT 1 = 2;

+-----------+
| NOT 1 = 2 |
+-----------+
|         1 |
+-----------+
1 row in set (0.00 sec)
```

As seen in the examples above, the first query resulted inÂ `false`Â because it is the inverse of the evaluation ofÂ `1 = 1`, which isÂ `true`, so its inverse isÂ `false`. On the other hand, the second query returnedÂ `true`, as the inverse ofÂ `1 = 2`Â 'which isÂ `false`' isÂ `true`.

---

## Symbol Operators

TheÂ `AND`,Â `OR`Â andÂ `NOT`Â operators can also be represented asÂ `&&`,Â `||`Â andÂ `!`, respectively. The below are the same previous examples, by using the symbol operators:

```shell-session
mysql> SELECT 1 = 1 && 'test' = 'abc';

+-------------------------+
| 1 = 1 && 'test' = 'abc' |
+-------------------------+
|                       0 |
+-------------------------+
1 row in set, 1 warning (0.00 sec)

mysql> SELECT 1 = 1 || 'test' = 'abc';

+-------------------------+
| 1 = 1 || 'test' = 'abc' |
+-------------------------+
|                       1 |
+-------------------------+
1 row in set, 1 warning (0.00 sec)

mysql> SELECT 1 != 1;

+--------+
| 1 != 1 |
+--------+
|      0 |
+--------+
1 row in set (0.00 sec)
```

---

## Operators in queries

Let us look at how these operators can be used in queries. The following query lists all records where theÂ `username`Â is NOTÂ `john`:


```shell-session
mysql> SELECT * FROM logins WHERE username != 'john';

+----+---------------+------------+---------------------+
| id | username      | password   | date_of_joining     |
+----+---------------+------------+---------------------+
|  1 | admin         | p@ssw0rd   | 2020-07-02 00:00:00 |
|  2 | administrator | adm1n_p@ss | 2020-07-02 11:30:50 |
|  4 | tom           | tom123!    | 2020-07-02 11:47:16 |
+----+---------------+------------+---------------------+
3 rows in set (0.00 sec)
```

The next query selects users who have theirÂ `id`Â greater thanÂ `1`Â ANDÂ `username`Â NOT equal toÂ `john`:


```shell-session
mysql> SELECT * FROM logins WHERE username != 'john' AND id > 1;

+----+---------------+------------+---------------------+
| id | username      | password   | date_of_joining     |
+----+---------------+------------+---------------------+
|  2 | administrator | adm1n_p@ss | 2020-07-02 11:30:50 |
|  4 | tom           | tom123!    | 2020-07-02 11:47:16 |
+----+---------------+------------+---------------------+
2 rows in set (0.00 sec)
```

---

## Multiple Operator Precedence

SQL supports various other operations such as addition, division as well as bitwise operations. Thus, a query could have multiple expressions with multiple operations at once. The order of these operations is decided through operator precedence.

Here is a list of common operations and their precedence, as seen in theÂ [MariaDB Documentation](https://mariadb.com/kb/en/operator-precedence/):

- Division (`/`), Multiplication (`*`), and Modulus (`%`)
- Addition (`+`) and subtraction (`-`)
- Comparison (=, `>`,Â `<`,Â `<=`,Â `>=`,Â `!=`,Â `LIKE`)
- NOT (`!`)
- AND (`&&`)
- OR (`||`)

Operations at the top are evaluated before the ones at the bottom of the list. Let us look at an example:


```sql
SELECT * FROM logins WHERE username != 'tom' AND id > 3 - 2;
```

The query has four operations:Â `!=`,Â `AND`,Â `>`, andÂ `-`. From the operator precedence, we know that subtraction comes first, so it will first evaluateÂ `3 - 2`Â toÂ `1`:


```sql
SELECT * FROM logins WHERE username != 'tom' AND id > 1;
```

Next, we have two comparison operations,Â `>`Â andÂ `!=`. Both of these are of the same precedence and will be evaluated together. So, it will return all records where username is notÂ `tom`, and all records where theÂ `id`Â is greater than 1, and then applyÂ `AND`Â to return all records with both of these conditions:

```shell-session
mysql> select * from logins where username != 'tom' AND id > 3 - 2;

+----+---------------+------------+---------------------+
| id | username      | password   | date_of_joining     |
+----+---------------+------------+---------------------+
|  2 | administrator | adm1n_p@ss | 2020-07-03 12:03:53 |
|  3 | john          | john123!   | 2020-07-03 12:03:57 |
+----+---------------+------------+---------------------+
2 rows in set (0.00 sec)
```

We will see a few other scenarios of operator precedence in the upcoming sections.

# Question
---


![Pasted image 20250131142339.png](../../../../IMAGES/Pasted%20image%2020250131142339.png)

We can use limit first to check the structure of the table:

```
MariaDB [employees]> select * from titles limit 1;
+--------+-----------------+------------+------------+
| emp_no | title           | from_date  | to_date    |
+--------+-----------------+------------+------------+
|  10001 | Senior Engineer | 1986-06-26 | 9999-01-01 |
+--------+-----------------+------------+------------+
```


Ok, since we need to filter for employee number greater than 10000 or title not containing engineer, we can use the following:

`select * from titles where emp_no > 10000 or title != 'engineer';`

If we use that, we can check the number of records at the end:

`654 rows in set`

Answer is `654`.

