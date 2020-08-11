# weblogic
## 控制台弱口令
### 漏洞说明
`http://your-ip:7001/console` 默认账号 weblogic:weblogic/Oracle@123
### 影响范围
/
### 验证方法
**pocsuite**:`poc_weblogic_weakpass.py`
### 利用方法
1. 登录后台
2. 上传war包，地址：`other/seven.war`,配置默认，下一步即可
3. 访问`http://127.0.0.1:7001/seven/JspSpy.jsp` 密码为`ninty`,此为大马
### 修复方式
修改weblogic登录口令为强口令