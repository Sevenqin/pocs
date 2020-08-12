源工具链接：https://github.com/rabbitmask/WeblogicScan

# weblogicScaner

简体中文 | [English](./README_EN.md)

截至 2020 年 3 月 7 日，weblogic 漏洞扫描工具。若存在未记录且已公开 POC 的漏洞，欢迎提交 issue。

原作者已经收集得比较完整了，在这里做了部分的 bug 修复，部分脚本 POC 未生效，配置错误等问题。之前查了一下发现部分 POC 无法使用。在这个项目里面对脚本做了一些修改，提高准确率。

**注意**：部分漏洞由于稳定性原因需要多次测试才可验证

目前可检测漏洞编号有（部分非原理检测，需手动验证）：

+ weblogic administrator console
+ CVE-2014-4210
+ CVE-2016-0638
+ CVE-2016-3510
+ CVE-2017-3248
+ CVE-2017-3506
+ CVE-2017-10271
+ CVE-2018-2628
+ CVE-2018-2893
+ CVE-2018-2894
+ CVE-2018-3191
+ CVE-2018-3245
+ CVE-2018-3252
+ CVE-2019-2618
+ CVE-2019-2725
+ CVE-2019-2729
+ CVE-2019-2890
+ CVE-2020-2551

# 快速开始

### 依赖

+ python >= 3.6

进入项目目录，使用以下命令安装依赖库

```
$ pip3 install requests
```

### 使用说明

```
usage: ws.py [-h] -t TARGETS [TARGETS ...] -v VULNERABILITY
             [VULNERABILITY ...] [-o OUTPUT]

optional arguments:
  -h, --help            帮助信息
  -t TARGETS [TARGETS ...], --targets TARGETS [TARGETS ...]
                        直接填入目标或文件列表（默认使用端口7001）. 例子：
                        127.0.0.1:7001
  -v VULNERABILITY [VULNERABILITY ...], --vulnerability VULNERABILITY [VULNERABILITY ...]
                        漏洞名称或CVE编号，例子："weblogic administrator console"
  -o OUTPUT, --output OUTPUT
                        输出 json 结果的路径。默认不输出结果
```

# 结果样例

```
(venv) ~/weblogicScanner$ python ws.py -t 192.168.124.129
[*] Start to detect weblogic administrator console for 192.168.124.129:7001.
[+] Found a module with weblogic administrator console at 192.168.124.129:7001!
[*] Please verify weblogic administrator console vulnerability manually!
---------------- Heartless Split Line ----------------
[*] Start to detect CVE-2014-4210 for 192.168.124.129:7001.
[+] Found a module with CVE-2014-4210 at 192.168.124.129:7001!
[*] Please verify CVE-2014-4210 vulnerability manually!
---------------- Heartless Split Line ----------------
[*] Start to detect CVE-2016-0638 for 192.168.124.129:7001.
[+] Target 192.168.124.129:7001 has a CVE-2016-0638 vulnerability!
---------------- Heartless Split Line ----------------
[*] Start to detect CVE-2016-3510 for 192.168.124.129:7001.
[+] Target 192.168.124.129:7001 has a CVE-2016-3510 vulnerability!
---------------- Heartless Split Line ----------------
[*] Start to detect CVE-2017-3248 for 192.168.124.129:7001.
[+] Target 192.168.124.129:7001 has a CVE-2017-3248 vulnerability!
---------------- Heartless Split Line ----------------
[*] Start to detect CVE-2017-3506 for 192.168.124.129:7001.
[+] Target 192.168.124.129:7001 has a CVE-2017-3506 vulnerability!
---------------- Heartless Split Line ----------------
[*] Start to detect CVE-2017-10271 for 192.168.124.129:7001.
[+] Target 192.168.124.129:7001 has a CVE-2017-10271 vulnerability!
---------------- Heartless Split Line ----------------
[*] Start to detect CVE-2018-2628 for 192.168.124.129:7001.
[+] Target 192.168.124.129:7001 has a CVE-2018-2628 vulnerability!
---------------- Heartless Split Line ----------------
[*] Start to detect CVE-2018-2893 for 192.168.124.129:7001.
[+] Target 192.168.124.129:7001 has a CVE-2018-2893 vulnerability!
---------------- Heartless Split Line ----------------
[*] Start to detect CVE-2018-2894 for 192.168.124.129:7001.
[-] Target 192.168.124.129:7001 does not detect CVE-2018-2894!
---------------- Heartless Split Line ----------------
[*] Start to detect CVE-2018-3191 for 192.168.124.129:7001.
[+] Target 192.168.124.129:7001 has a CVE-2018-3191 vulnerability!
---------------- Heartless Split Line ----------------
[*] Start to detect CVE-2018-3245 for 192.168.124.129:7001.
[-] Target 192.168.124.129:7001 does not detect CVE-2018-3245 vulnerability!
---------------- Heartless Split Line ----------------
[*] Start to detect CVE-2018-3252 for 192.168.124.129:7001.
[+] Found a module with CVE-2018-3252 at 192.168.124.129:7001!
[*] Please verify CVE-2018-3252 vulnerability manually!
---------------- Heartless Split Line ----------------
[*] Start to detect CVE-2019-2618 for 192.168.124.129:7001.
[+] Found a module with CVE-2019-2618 at 192.168.124.129:7001!
[*] Please verify CVE-2019-2618 vulnerability manually!
---------------- Heartless Split Line ----------------
[*] Start to detect CVE-2018-2725 for 192.168.124.129:7001.
[+] Target 192.168.124.129:7001 has a CVE-2018-2725 vulnerability!
---------------- Heartless Split Line ----------------
[*] Start to detect CVE-2019-2729 for 192.168.124.129:7001.
[+] Target 192.168.124.129:7001 has a CVE-2019-2729 vulnerability!
---------------- Heartless Split Line ----------------
[*] Start to detect CVE-2019-2890 for 192.168.124.129:7001.
[-] Target 192.168.124.129:7001 does not detect CVE-2019-2890 vulnerability!
---------------- Heartless Split Line ----------------
[*] Start to detect CVE-2020-2551 for 192.168.124.129:7001.
[+] Target 192.168.124.129:7001 has a CVE-2020-2551 vulnerability!
---------------- Heartless Split Line ----------------

```