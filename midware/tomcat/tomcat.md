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
在tomcat中启用put方法会导致任意文件可以上传，从而导致服务器权限被获取。
### 影响范围
Apache Tomcat 7.0.0 – 7.0.79
### 验证方法
**pocsuite**:poc_tomcat_cmdexec

### 利用方法

### 修复方法
1、配置readonly值为True或注释参数，禁止使用PUT方法并重启tomcat。
注意：如果禁用PUT方法，对于依赖PUT方法的应用，可能导致业务失效。

2、根据官方补丁升级最新版本。

## tomcat ajp协议任意文件读取漏洞 cve-2020-1938

### 漏洞说明
由于 Tomcat AJP 协议设计上存在缺陷，攻击者通过 Tomcat AJP Connector 可以读取或包含 Tomcat 上所有 webapp 目录下的任意文件，例如可以读取 webapp 配置文件或源代码。此外在目标应用有文件上传功能的情况下，配合文件包含的利用还可以达到远程代码执行的危害。
### 影响范围
**受影响版本**
- Apache Tomcat 6
- Apache Tomcat 7 < 7.0.100
- Apache Tomcat 8 < 8.5.51
- Apache Tomcat 9 < 9.0.31

**不受影响版本**
- Apache Tomcat = 7.0.100
- Apache Tomcat = 8.5.51
- Apache Tomcat = 9.0.31

### 验证方法
**pocsuite**:`poc_tomcat_ajp_read`

### 利用方法

### 修复方法

目前官方已在最新版本中修复了该漏洞，请受影响的用户尽快升级版本进行防护，官方下载链接：

| 版本号                | 下载地址                                 |
| --------------------- | ---------------------------------------- |
| Apache Tomcat 7.0.100 | http://tomcat.apache.org/download-70.cgi |
| Apache Tomcat 8.5.51  | http://tomcat.apache.org/download-80.cgi |
| Apache Tomcat 9.0.31  | http://tomcat.apache.org/download-90.cgi |



如果相关用户暂时无法进行版本升级，可根据自身情况采用下列防护措施。

一:若不需要使用Tomcat AJP协议，可直接关闭AJP Connector，或将其监听地址改为仅监听本机localhost。

具体操作：

（1）编辑 <CATALINA_BASE>/conf/server.xml，找到如下行（<CATALINA_BASE> 为 Tomcat 的工作目录）：

```
<Connector port="8009"protocol="AJP/1.3" redirectPort="8443" />
```

![img](/Users/seven/Desktop/pocs/midware/tomcat/tomcat.assets/image-4.png)

（2）将此行注释掉（也可删掉该行）：

```
<!--<Connectorport="8009" protocol="AJP/1.3"redirectPort="8443" />-->
```

（3）保存后需重新启动Tomcat，规则方可生效。

