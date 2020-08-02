# redis
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

### 修复方式
1. 绑定127.0.0.1，redis默认是监听的127.0.0.1上，如果仅仅是本地通信，请确保监听在本地。这种方式缓解了redis的风险。在/etc/redis/redis.conf中配置如下：`bind 127.0.0.1` 
2. 设置防火墙。如果需要其他机器访问，或者设置了slave模式，需添加相应的防火墙设置。命令如下：`iptables -A INPUT -s x.x.x.x -p tcp --dport 6379 -j ACCEPT` 
3. 添加认证。redis默认没有开启密码认证，打开/etc/redis/redis.conf配置文件， （requirepass 密码）可设置认证密码，保存redis.conf，重启redis（/etc/init.d/redis-server restart）
4. 设置单独用户启用redis服务。设置一个单独的redis账户：创建一个redis账户，通过该账户启动。示例如下：`setsidsudo -u redis /usr/bin/redis-server /etc/redis/redis.conf'`

