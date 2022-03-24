# SQL Injection: LFI (Local File Inclusion) via load_file() function

If the database user has read permission (which most of the time it does), it is possible for an attacker to read the internal file of the server, with a small caviat that the absolute path must be known (just as a normal LFI).
In order to perform this kind of attack, the following function must be used:  

```sql
load_file(/path/to/file)
```

For example, the most basic approach is to read /etc/passwd:  
```sql
load_file('/etc/passwd')
```

A simple usage of the query:  
```
http://domain.com/index.php?id=1' Union Select 1,2,3,load_file('/etc/passwd'),5,6,7,8,9,10,11,12-- -
```

## WAF Limitation
Most of WAF detects the **../** which might be used on the absolute path. I did some research and realised that we can't really bypass WAF as it is impossible to obfuscate **../**. Unlike the normal LFI, where you can easily encode to **%2e%2e/etc/passwd%00**, in SQL injection it is not possible to implement that as well, because it will break the SQL syntax (remember that the path is inside a SQL function, so no much flexibility here).
If you come up with an idea about alternative way of using **../** inside the load_file() function, let me know :)
