# FTP
## 匿名访问及弱口令漏洞
### 漏洞说明
ftp全版本中存在ftp匿名登录（anonomous/anonomous）、弱口令登录漏洞。通过该漏洞可以获取ftp服务器敏感信息，上传恶意文件到ftp服务器中。
### 涉及范围
全版本
### 验证方法
验证脚本: poc_ftp_weakpass.py

### 利用方法
无

## vsftpd后门漏洞
### 漏洞说明
vsftpd是一款Linux下的FTP服务器软件。在vsftpd 2.3.4版本中，存在一个后门漏洞。用户名中包含笑脸符号，会建立一个反向shell。漏洞编号为CVE-2011-2523。Nmap的ftp-vsftpd-backdoor脚本通过尝试执行id命令，来探测FTP服务器是否存在这个漏洞。
### 涉及范围
vsftp version 2~2.3.4
### 验证方法
#### pocsuite
poc_vsftpd_backdoor.py
#### metasploit
exploit/unix.ftp/vsftpd_234_backdoor
#### nmap 
nmap -T4 -p21 --script ftp-vsftpd-backdoor.nse @ip


### 漏洞环境
protocol/ftp
