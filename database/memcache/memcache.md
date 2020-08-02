# 漏洞说明
memcache默认使用11211端口
## memcache未授权访问漏洞
### 漏洞说明
由于memcached安全设计缺陷，客户端连接memcached服务器后无需认证就可读取、修改服务器缓存内容。
### 涉及范围及影响
除memcached中数据可被直接读取泄漏和恶意修改外，由于memcached中的数据像正常网站用户访问提交变量一样会被后端代码处理，当处理代码存在缺陷时会再次导致不同类型的安全问题。不同的是，在处理前端用户直接输入的数据时一般会接受更多的安全校验，而从memcached中读取的数据则更容易被开发者认为是可信的，或者是已经通过安全校验的，因此更容易导致安全问题。由此可见，导致的二次安全漏洞类型一般由memcached数据使用的位置（XSS通常称之为sink）的不同而不同，如：
- 缓存数据未经过滤直接输出可导致XSS；
- 缓存数据未经过滤代入拼接的SQL注入查询语句可导致SQL注入；
- 缓存数据存储敏感信息（如：用户名、密码），可以通过读取操作直接泄漏；
- 缓存数据未经过滤直接通过system()、eval()等函数处理可导致命令执行；
- 缓存数据未经过滤直接在header()函数中输出，可导致CRLF漏洞（HTTP响应拆分）。

参考漏洞攻击demo：
`http://niiconsulting.com/checkmate/2013/05/memcache-exploit/`


### 验证方法
验证脚本: poc_memcache_unauth.py
nmap: memcached-info
bash: 
>nc target ip
>stats

### 利用方法
漏洞的利用根据所造成二次漏洞的不同，可在缓存变量中构造相应的payload。
针对memcached未授权访问漏洞缓存数据的抓取，可使用go-derper工具。
注：memcached服务器基本操作及go-derper工具使用方法参见链接。


### 漏洞修复
配置memcached监听本地回环地址127.0.0.1
'''bash
vim /etc/sysconfig/memcached
OPTIONS="-l 127.0.0.1"  #设置本地为监听
/etc/init.d/memcached restart #重启服务
'''