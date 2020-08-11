# zookeeper
ZooKeeper是一个分布式的，开放源码的分布式应用程序协调服务，是Google的Chubby一个开源的实现，是Hadoop和Hbase的重要组件。它是一个为分布式应用提供一致性服务的软件，提供的功能包括：配置维护、域名服务、分布式同步、组服务等。
默认使用2181端口
## 未授权访问漏洞
### 漏洞说明
ZooKeeper默认开启在`2181`端口，在未进行任何访问控制情况下，攻击者可通过执行envi命令获得系统大量的敏感信息，包括系统名称、Java环境。

### 涉及范围
all

### 验证方法
**手工验证**
`echo envi | nc host 2181`
**pocsuite**
poc_activemq_unauth.py

### 修复方式
1. 修改 ZooKeeper 默认端口，采用其他端口服务。
2. 添加访问控制，配置服务来源地址限制策略。
3. 增加 ZooKeeper 的认证配置。
