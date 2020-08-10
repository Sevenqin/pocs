# tomcat
## 弱口令漏洞
### 漏洞说明
1. tomcat默认开启的manger 界面中，默认的用户名密码为tomcat:tomat
- manager（后台管理）
- manager-gui 拥有html页面权限
- manager-status 拥有查看status的权限
- manager-script 拥有text接口的权限，和status权限
- manager-jmx 拥有jmx权限，和status权限
2. host-manager（虚拟主机管理）
- admin-gui 拥有html页面权限
- admin-script 拥有text接口权限

### 影响范围
/
### 验证方法
poc_tomcat_weakpass.py

### 利用方法

**手工利用**:登录tomcat管理后台，上传包含恶意程序的war包，获取tomcat用户权限。
**msfconsole**:`exploit/multi/http/tomcat_mgr_upload`

### 修复方法
1、修改conf/tomcat-users.xml文件中的默认用户名和密码，设置密码为强口令。
1、在系统上以低权限运行Tomcat应用程序。创建一个专门的 Tomcat服务用户，该用户只能拥有一组最小权限（例如不允许远程登录）。

2、增加对于本地和基于证书的身份验证，部署账户锁定机制（对于集中式认证，目录服务也要做相应配置）。在CATALINA_HOME/conf/web.xml文件设置锁定机制和时间超时限制。


## tomcat命令执行漏洞 CVE-2017-12615
### 漏洞说明

### 影响范围

### 验证方法


### 利用方法

### 修复方法

## tomcat ajp协议任意文件读取漏洞 cve-2020-1938

### 漏洞说明

### 影响范围

### 验证方法


### 利用方法

### 修复方法





