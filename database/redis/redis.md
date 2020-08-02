# 漏洞说明
redis默认使用6379端口
## redis未授权访问漏洞
### 漏洞说明
redis默认配置下启动存在未授权访问漏洞，用户不需要输入口令即可远程登录redis，查看敏感信息，并通过redis写入ssh_key,webshell，达到控制服务器管理权限的目的
### 涉及范围
全版本
### 验证方法
验证脚本: poc_redis_unauth.py
msfconsole:auxiliary/scanner/redis/redis_login

### 利用方法
msfconsole:exploit/linux/redis/redis_unauth_exec
pocsuite: poc_redis_unauth.py --attack
other: 一键利用
