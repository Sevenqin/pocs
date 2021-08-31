# Vmware
## vmware exsi 远程代码执行漏洞CVE-2020-3992
### 漏洞说明
VMware官方发布安全通告修复了一个VMware ESXi 远程代码执行漏洞（CVE-2020-3992）。漏洞来源于ESXi中使用的OpenSLP存在“use-after-free”释放后重利用问题，当攻击者在管理网络（management network）中时，可以通过访问ESXi宿主机的427端口触发OpenSLP服务的user-after-free，从而导致远程代码执行。

### 影响范围
- ESXi = 6.5
- ESXi = 6.7
- ESXi = 7.0
- VMware Cloud Foundation (ESXi) = 3.X
- VMware Cloud Foundation (ESXi) = 4.X

**不受影响产品版本**
- ESXi650-202010401-SG
- ESXi670-202010401-SG
- ESXi_7.0.1-0.0.16850804
- VMware Cloud Foundation (ESXi) = 3.10.1.1
- VMware Cloud Foundation (ESXi) = 4.1
### 验证方法
https://github.com/HynekPetrak/CVE-2019-5544_CVE-2020-3992
CVE-2020-3992/check_slp.py

### 利用方法
暂无

### 修复方式

**1、官方升级**

目前官方已在最新版本中修复了该漏洞，请受影响的用户尽快升级版本进行防护，对应产品版本的下载链接及文档如下：

| **产品版本**                            | 下载链接                                                     | 操作文档                                                     |
| --------------------------------------- | ------------------------------------------------------------ | ------------------------------------------------------------ |
| VMware ESXi 6.5 ESXi650-202010401-SG    | https://my.vmware.com/group/vmware/patch                     | https://docs.vmware.com/en/VMware-vSphere/6.5/rn/esxi650-202010001.html |
| VMware ESXi 6.7 ESXi670-202010401-SG    | https://my.vmware.com/group/vmware/patch                     | https://docs.vmware.com/en/VMware-vSphere/6.7/rn/esxi670-202010001.html |
| VMware ESXi 7.0 ESXi_7.0.1-0.0.16850804 | https://my.vmware.com/group/vmware/patch                     | https://docs.vmware.com/en/VMware-vSphere/7.0/rn/vsphere-esxi-701-release-notes.html |
| VMware vCloud Foundation 3.10.1.1       | https://docs.vmware.com/en/VMware-Cloud-Foundation/3.10.1/rn/VMware-Cloud-Foundation-3101-Release-Notes.html#3.10.1.1 | https://docs.vmware.com/en/VMware-Cloud-Foundation/3.10.1/rn/VMware-Cloud-Foundation-3101-Release-Notes.html#3.10.1.1 |
| VMware vCloud Foundation 4.1            | https://docs.vmware.com/en/VMware-Cloud-Foundation/4.1/rn/VMware-Cloud-Foundation-41-Release-Notes.html | https://docs.vmware.com/en/VMware-Cloud-Foundation/4.1/rn/VMware-Cloud-Foundation-41-Release-Notes.html |

**2、临时防护措施**

若相关用户暂时无法进行升级操作，也可通过在VMware ESXi上禁用CIM服务器进行临时缓解，操作步骤请参考官方文档：https://kb.vmware.com/s/article/76372

```bash
/etc/init.d/slpd stop  #关闭slp
esxcli system slp stats get  # 查看slp是否在运行
esxcli network firewall ruleset set -r CIMSLP -e 0 #禁用slp
chkconfig slpd off #slp开机禁止启动
chkconfig --list | grep slpd

*output: slpd off*
```

临时处置方式恢复措施

```bash
esxcli network firewall ruleset set -r CIMSLP -e 1
chkconfig slpd on
chkconfig --list | grep slpd

*output: slpd on*

/etc/init.d/slpd start
```



