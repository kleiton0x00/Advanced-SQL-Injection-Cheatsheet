# Advanced SQL Injection Cheatsheet
This repository contains a advanced methodology of all types of SQL Injection.

## General Process:
- Find injection point  
- Understand the website behaviour  
- Send queries for enumeration  
- Understanding WAF & bypass it  
- Dump the database  

## Cheat Sheet Tree
### MySQL Injection Cheatsheet
- [Error- or UNION-based SQLi](https://github.com/kleiton0x00/Advanced-SQL-Injection-Cheatsheet/blob/main/Error%20Based%20SQLi/README.md)  
  - [Routed queries (Advanced WAF Bypass)](https://github.com/kleiton0x00/Advanced-SQL-Injection-Cheatsheet/blob/main/MySQL-Routed-Queries/README.md)  
  - [Bypass Error: The used SELECT statements have a different number of columns](https://github.com/kleiton0x00/Advanced-SQL-Injection-Cheatsheet/blob/main/MySQL-Bypass-Error/README.md)
  - New attacking vectors (Bypassing WAF)
    - [The Alternative way of using And 0](https://github.com/kleiton0x00/Advanced-SQL-Injection-Cheatsheet/blob/main/The%20Alternative%20way%20of%20using%20And%200%20in%20SQL%20Injection/README.md)
    - [The Alternative WAY of using Null](https://github.com/kleiton0x00/Advanced-SQL-Injection-Cheatsheet/blob/main/The%20Alternative%20way%20of%20using%20Null%20in%20SQL%20Injection/README.md)
- [Boolean-based (content-based) Blind SQLi](https://github.com/kleiton0x00/Advanced-SQL-Injection-Cheatsheet/tree/main/MySQL%20-%20Boolean%20Based%20Blind%20SQLi)  
- [Time Based SQLi](https://github.com/kleiton0x00/Advanced-SQL-Injection-Cheatsheet/blob/main/MySQL%20-%20Time%20Based%20SQLi/README.md)

- [Stabilise & Whitespace Filter Bypass](https://github.com/kleiton0x00/Advanced-SQL-Injection-Cheatsheet/blob/main/MySQL%20-%20Stabilise%20%26%20Bypass/README.md)
- [Privilege Escalation](https://github.com/kleiton0x00/Advanced-SQL-Injection-Cheatsheet/blob/main/Privilege%20Escalation/README.md)

### PostgreSQL Injection Cheatsheet
- [Error- or UNION-based SQLi](https://github.com/kleiton0x00/Advanced-SQL-Injection-Cheatsheet/tree/main/Postgres%20-%20Error%20Based%20SQLi)

### Oracle Injection Cheatsheet
- To be added...

### MSSQL Injection Cheatsheet
- [Error- or UNION-based SQLi](https://github.com/kleiton0x00/Advanced-SQL-Injection-Cheatsheet/blob/main/MSSQL%20-%20Error%20Based%20SQLi/README.md)
- [Privilege Escalation](https://github.com/kleiton0x00/Advanced-SQL-Injection-Cheatsheet/blob/main/Privilege%20Escalation%20-%20MSSQL/README.md)
