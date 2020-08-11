# supervisord
## supervisord 未授权访问及弱口令漏洞
### 漏洞说明
supervisord 默认开启的9001端口如果采用默认配置则存在未授权访问漏洞，如果仅将默认注释取消，则存在弱口令漏洞user/123

### 涉及范围
/
### 验证方法
**pocsuite**:poc_supervisord_weakpass
### 利用方法
/
### 修复方法
1. 修改supervisord.conf文件，默认在/etc/supservisor/supervisord.conf。修改port监听为本地监听，同时修改口令为强口令
```vim
[inet_http_server]         ; inet (TCP) server disabled by default
port=127.0.0.1:9001        ; (ip_address:port specifier, *:port for all iface)      
username=your-username              ; (default is no username (open server))
password=your-password
```
2. 重启supervisord生效
## supervisord 远程命令执行漏洞
### 漏洞说明

### 验证方法

### 利用方法


### 修复方式