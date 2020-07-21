# SSH
## 弱口令漏洞
### 漏洞说明


### 涉及范围
全版本
### 验证方法
poc_ssh_weakpass.py

### 利用方法
poc_ssh_weakpass.py

## 用户枚举漏洞 CVE-2018-15473
### 漏洞说明
该漏洞涉及到多个OpenSSH中的用户身份验证函数。首先我们来研究下Ubuntu下OpenSSH中的公钥认证中的这个漏洞。

通过向OpenSSH服务器发送一个错误格式的公钥认证请求，可以判断是否存在特定的用户名。如果用户名不存在，那么服务器会发给客户端一个验证失败的消息。如果用户名存在，那么将因为解析失败，不返回任何信息，直接中断通讯。
### 涉及范围
/
### 验证方法
poc_openssh_enum.py
### 利用方法

poc_openssh_enum.py

protocal/ssh/CVE-2018-15473-Exploit-master

https://github.com/Rhynorater/CVE-2018-15473-Exploit

## libssh登录绕过漏洞 CVE-2018-10933
### 漏洞说明
libssh版本0.6及更高版本在服务端代码中具有身份验证绕过漏洞。通过向服务端发送SSH2_MSG_USERAUTH_SUCCESS消息来代替服务端期望启动身份验证的SSH2_MSG_USERAUTH_REQUEST消息，攻击者可以在没有任何凭据的情况下成功进行身份验证，甚至可能登陆SSH，入侵服务器。

### 涉及范围
libssh0.6及以上的版本

### 验证方法
poc_libssh_unauthorize.py

ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p 2222 root@127.0.0.1

### 利用方法

protocal/ssh/CVE-2018-10933-master

https://github.com/blacknbunny/libSSH-Authentication-Bypass

