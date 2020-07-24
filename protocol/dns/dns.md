# dns
## dns域传送漏洞
### 漏洞说明
DNS区域传送（DNS zone transfer）指的是一台备用服务器使用来自主服务器的数据刷新自己的域（zone）数据库。这为运行中的DNS服务提供了一定的冗余度，其目的是为了防止主的域名服务器因意外故障变得不可用时影响到整个域名的解析。

一般来说，DNS区域传送操作只在网络里真的有备用域名DNS服务器时才有必要用到，但许多DNS服务器却被错误地配置成只要有client发出请求，就会向对方提供一个zone数据库的详细信息，所以说允许不受信任的因特网用户执行DNS区域传送（zone transfer）操作是后果最为严重的错误配置之一。

### 涉及范围
/
### 检测方法
**pocsuite**
poc_dns_transfer.py
**nmap**
nmap --script dns-zone-transfer --script-args dns-zone-transfer.domain=nwpu.edu.cn -p 53 -Pn dns.nwpu.edu.cn
**bash**
dig @8.8.8.8 -t axfr www.lijiejie.com
//8.8.8.8 为dns地址

### 利用方法