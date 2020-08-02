# 漏洞说明
mongodb默认使用27017端口,此外mongodb可以开启web界面管理，默认端口为28017
## mongodb未授权访问漏洞
### 漏洞说明
开启MongoDB服务时不添加任何参数时,默认是没有权限验证的,登录的用户可以通过默认端口无需密码对数据库任意操作(增删改高危动作)而且可以远程访问数据库
### 涉及范围
全版本
### 验证方法
验证脚本: poc_mongodb_unauth.py
msfconsole:auxiliary/scanner/mongodb/mongodb_login
bash: 

> mongo host:port
> show databases

### 利用方法
msfconsole:exploit/linux/mongodb/mongodb_unauth_exec
pocsuite: poc_mongodb_unauth.py --attack
other: 一键利用

### 修复方式
1. 修改默认端口
  修改默认的mongoDB端口(默认为: TCP 27017)为其他端口

2. 不要开放到公网0.0.0.0

   ```bash
   vim /etc/mongodb.conf 
   bind_ip = 127.0.0.1
   ```
3. 为mongodb添加口令认证

   ```bash
   mongod --auth
   ###mongod shell
   >use admin
   >db.createUser({user:"admin",pwd:"your_password",roles:["root"]})
   >db.auth("admin","your_password")
   ```

   