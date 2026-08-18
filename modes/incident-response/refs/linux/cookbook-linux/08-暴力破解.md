> 原文来源：Linux-INCIDENT-RESPONSE-COOKBOOK（GPL-3.0），作者 NOP Team，https://github.com/Just-Hack-For-Fun/Linux-INCIDENT-RESPONSE-COOKBOOK ；本节原文抓取自在线版 URL https://book.noptrace.com/linux/8.%E6%9A%B4%E5%8A%9B%E7%A0%B4%E8%A7%A3/

# 暴力破解


### 0x00 整体流程

<!-- 截图：暴力破解处置流程-深色（在线版图片，未随附） -->

### 0x01 梳理现场情况

#### 确认攻击信息准确性

安全设备、人、上级/行业/监管单位的通报都不见得是准确的，做二次研判是必要的，能够帮我应急响应人员确定整体排查思路

#### 询问历史被攻击情况、历史通报、历史误报

历史攻击可能会留下攻击遗产，成为未来新一轮攻击事件的发起点，询问清楚历史被攻击、被通报情况，向当事人或负责人了解清楚事件性质、处理过程、处理结果，这可能会在完全理不清攻击路径的时候帮你一把

应急响应人员大概率是没有被攻击单位运维、安全等人员熟悉他们的系统的，所以历史误报很重要，例如修改了数据库密码等问题就很容易有历史误报，建议面对暴力破解事件时打听一下历史误报情况

#### 暴力破解类型

暴力破解攻击主要针对

- ssh
- mysql
- ftp
- redis
- mongodb
- smtp

### 0x02 SSH 暴力破解

- 检查网络连接信息
  netstat -pantu
  <!-- 截图：image-20210415103922449（在线版图片，未随附） -->
  
  规则和 Local Address 规则一样
  
  这个就是进程ID和进程名字了
  - Proto 协议类型
  - Recv-Q ：表示收到的数据已经在本地接收缓冲，但是还有多少没有被进程取走，如果接收队列Recv-Q一直处于阻塞状态，可能是遭受了拒绝服务 denial-of-service 攻击。
  - Send-Q：对方没有收到的数据或者说没有Ack的,还是本地缓冲区。如果发送队列Send-Q不能很快的清零，可能是有应用向外发送数据包过快，或者是对方接收数据包不够快。
  - Local Address： 本机地址，一般有以下几种模式
  - *:80    监听IPv4或IPv6的任意IP的80端口
  - :::80    监听IPv6和IPv4的任意IP的80端口
  - 0.0.0.0:80    监听任意IPv4地址的80端口
  - 127.0.0.1:80    监听本地的80端口，只能本地访问
  - ::1:80    监听本地IPv6的回环地址，只能本地访问
  - 192.168.1.1:80  监听IP地址 192.168.1.1 的80端口
  - Foreign Address：外部地址
  - State 网络状态
  - LISTEN 侦听状态，等待对端连接
  - SYN_SENT 客户端发送建立连接的SYN请求后状态为 SYN_SENT
  - SYN_RECV 服务端发送SYN+ACK 后网络状态为 SYN_RECV
  - ESTABLISHED 已经建立起连接
  - FIN_WAIT1 主动端四次挥手主动发起的第一个包，也就是FIN包之后网络状态为 FIN_WAIT1
  - CLOSE_WAIT 被动端收到四次挥手的FIN包，发送ACK后处于CLOSE_WAIT
  - FIN_WAIT2 主动关闭端接到ACK后进入FIN_WAIT2，等待对端发下一个FIN
  - LAST_ACK 被动关闭端发送第二个FIN后进入 LAST_ACK 状态，等待最后一个ACK的到来
  - TIME_WAIT 主动端发送最后一个ACK，之后进入 TIME_WAIT状态，等待一段时间确保对端接收到了ACK
  - CLOSING 在TCP四次挥手期间，主动关闭端发送了FIN包后，没有收到对应的ACK包，却收到对方的FIN包，此时，进入CLOSING状态
  - CLOSED 被动关闭端在接受到ACK包后，就进入了closed的状态。连接结束
  - UNKNOWN 未知的Socket状态
  - PID/Program name

参考文章：https://blog.csdn.net/m0_37556444/article/details/83000553

ssh遭到暴力破解时网络连接如下：

<!-- 截图：image-20210415181422837（在线版图片，未随附） -->

存在大量的 ESTABLISHED状态的连接

- 查找特殊权限账号，默认root 
      `awk -F: '{if($3==0) print $1}' /etc/passwd`
- 查找可以登录 ssh 的账号 
      `s=$( sudo cat /etc/shadow | grep '^[^:]*:[^\*!]' | awk -F: '{print $1}');for i in $s;do cat /etc/passwd | grep -v  "/bin/false\|/nologin"| grep $i;done | sort | uniq |awk -F: '{print $1}'`
- 查看正在连接的ssh sessions
  - `who -a`
  - `w`
  - `last -p now`
  - `sudo netstat -tnpa | grep 'ESTABLISHED.*sshd'`
  - `pgrep -af sshd`
  - `echo $SSH_CONNECTION`
  - `ss | grep ssh`
- 查看ssh日志信息

https://blog.csdn.net/supertor/article/details/84334710

- Ubuntu
  `/var/log/auth.log`
- Centos
  `/var/log/secure`

这两个文件关于SSH的内容基本一致，所以此处以 Ubuntu的日志 `/var/log/auth.log` 为例，如果是Centos直接替换文件名就行

- 查找登录成功的日志 
  `cat /var/log/auth.log | grep "Accept"`
  <!-- 截图：image-20210415193905959（在线版图片，未随附） -->
- 正常退出的日志
  `cat /var/log/auth.log | grep "pam_unix(sshd:session): session closed"` 
  <!-- 截图：image-20210415194236032（在线版图片，未随附） -->
- 登录密码错误的日志
  <!-- 截图：image-20210416090138843（在线版图片，未随附） -->
- 连续输入错误密码 
  <!-- 截图：image-20210416090617691（在线版图片，未随附） -->
  <!-- 截图：image-20210416090715405（在线版图片，未随附） -->
- 暴力破解 
  <!-- 截图：image-20210416094835772（在线版图片，未随附） -->
  <!-- 截图：image-20210416094913438（在线版图片，未随附） -->
  如果短时间内存在大量的如下失败请求，可能被暴力破解攻击了
  `pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.168.197.1  user=root 
  
  Apr 16 01:44:20 helper sshd[2167]: Failed password for root from 192.168.197.1 port 58371 ssh2`
- 查看登录失败的日志
  `cat /var/log/auth.log | grep "Failed password for"  | more` 
  <!-- 截图：image-20210416100359466（在线版图片，未随附） -->
  但是，服务器跑了这么久，有一些错误登录很正常，所以需要按照事件时间和用户来进行分辨
- 统计登录失败的用户名以及次数 
  这里直接使用bypass总结的
  `grep "Failed password" /var/log/auth.log|perl -e 'while($_=<>){ /for(.*?)from/; print "$1\n";}'|sort|uniq -c|sort -nr`
  <!-- 截图：image-20210416101957872（在线版图片，未随附） -->
  可以看到，其中有一项为 invaild user www ，这样的提示说明www这个用户不存在，但是有人使用了这个用户进行了登录
- 统计暴力破解的登录者（IP）
  
  根据上面的操作，已经确定sshd，helper，root，www这几个用户可能异常，我们挨个查看一下爆破IP 
  
  **登录密码错误的用户存在的情况**
  单个用户以 root 为例 
  `cat /var/log/auth.log | grep "Failed password for" | grep "root" | grep -Po '(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|[1-9])(\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|\d)){3}' |sort|uniq -c|sort -nr`
  <!-- 截图：image-20210416105048565（在线版图片，未随附） -->
  也可以通过列来进行定位 
  `cat /var/log/auth.log | grep "Failed password for" | grep "root" | cut -d " " -f 11 |sort -nr|uniq -c`
  
  Rocky Linux 9 中 -f 11 应该改为 -f 13
  
  <!-- 截图：image-20210416105744121（在线版图片，未随附） -->
  如果你觉得上一部查出来的都是暴力破解或者说异常的，可以使用如下命令批量查询出来 
  `cat /var/log/auth.log | grep "Failed password for" | cut -d " " -f 9 | sort -nr | uniq|grep -v "invalid"| while read line;do echo [$line];cat /var/log/auth.log | grep "Failed password for" | grep $line | grep -Po '(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|[1-9])(\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|\d)){3} '|sort|uniq -c |sort -nr; done`
  <!-- 截图：image-20210416112304560（在线版图片，未随附） -->
  Rocky Linux / Centos 中应该为
  `cat /var/log/secure | grep "Failed password for" | grep -v "invalid" | cut -d " " -f 10 | sort -nr | uniq| while read line;do echo [$line];cat /var/log/secure | grep "Failed password for" | grep $line | grep -Po '(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|[1-9])(\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|\d)){3} '|sort|uniq -c |sort -nr; done`
  <!-- 截图：image-20240801002612421（在线版图片，未随附） -->
  当然了，如果你觉得某一个用户的错误次数很少，是正常的，可以在命令中使用 grep -v "user" 的方式来进行，这里假如我们认为root用户的错误登录是正常的，所以不希望在结果中看到root的显示，可以使用如下命令： 
  `cat /var/log/auth.log | grep "Failed password for" | cut -d " " -f 9 | sort -nr | uniq|grep -v "invalid\|root"| while read line;do echo [$line];cat /var/log/auth.log | grep "Failed password for" | grep $line | grep -Po '(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|[1-9])(\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|\d)){3} ' |sort|uniq -c| sort -nr; done`
  <!-- 截图：image-20210416112702958（在线版图片，未随附） -->
  这样root的结果就不显示了，如果想不显示多个用户，继续添加  `\|user` 就可以了 
  <!-- 截图：image-20210416113107247（在线版图片，未随附） -->
  **登录密码错误的用户不存在的情况**
  首先查看这些不存在的用户名以及错误登录的次数
  `cat /var/log/auth.log | grep "Failed password for"| grep "invalid" | cut -d " " -f 11 | sort | uniq -c | sort -nr`
  <!-- 截图：image-20210416131246055（在线版图片，未随附） -->
  查看这些用户的登录尝试IP以及次数 
  单用户 test来举例 
  `cat /var/log/auth.log | grep "Failed password for" | grep "test" | grep -Po '(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|[1-9])(\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|\d)){3}' |sort|uniq -c|sort -nr`
  <!-- 截图：image-20210416131949618（在线版图片，未随附） -->
  查询全部的不存在用户的登录IP以及次数 
  `cat /var/log/auth.log | grep "Failed password for" | grep "invalid"| cut -d " " -f 11 | sort -nr | uniq| while read line;do echo [$line];cat /var/log/auth.log | grep "Failed password for" | grep $line | grep -Po '(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|[1-9])(\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|\d)){3} '|sort|uniq -c |sort -nr;done`
  <!-- 截图：image-20210416133120307（在线版图片，未随附） -->
  当然，还是可以排除一个或者几个用户，这里排除 www和 test 用户 
  `cat /var/log/auth.log | grep "Failed password for" | grep "invalid" | grep -v "www\|test"| cut -d " " -f 11 | sort -nr | uniq| while read line;do echo [$line];cat /var/log/auth.log | grep "Failed password for" | grep $line | grep -Po '(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|[1-9])(\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|\d)){3} '|sort|uniq -c |sort -nr;done`
  <!-- 截图：image-20210416133031343（在线版图片，未随附） -->
- SSH加固
  - 升级SSH版本至少为 7.7版本以上，7.7及以下版本存在SSH用户名枚举
  - 加强口令复杂程度
  - 禁止root用户登录，可以通过其他用户su到root
  - 安装 fail2ban 来进行防御

### 0x03 Mysql 暴力破解

Mysql 默认安装会保留登录日志，在 Ubuntu 上默认位置为 `/var/log/mysql/error.log`

- 查看登录错误的用户名

`cat /var/log/mysql/error.log | grep "Access denied for user"  | grep "using password: YES" | awk -F "'" '{print $2}' | sort | uniq -c | sort -nr`

<!-- 截图：image-20210421120048894（在线版图片，未随附） -->

- 查看登录错误用户名的登录IP以及次数

`cat /var/log/mysql/error.log | grep "Access denied for user"  | grep "using password: YES" | awk -F "'" '{print $2}' | sort| uniq | while read line;do echo $line;cat /var/log/mysql/error.log | grep "Access denied for user" | grep "using password" | awk -F "'" '{print $4}' | sort | uniq -c | sort -nr; done`

<!-- 截图：image-20210421133337017（在线版图片，未随附） -->

### 0x04 FTP 暴力破解

> ftp服务端以 vsftpd为例，其他服务端思路类似，日志记录可能不同

[vsftpd配置过程](https://ubuntu.com/server/docs/service-ftp)

- 网络连接

<!-- 截图：image-20210416165500552（在线版图片，未随附） -->

可以看到，现在存在一条已经建立的连接，从 192.168.197.101的56806端口连接到192.168.197.129的21端口

如果存在暴力破解，网络连接情况如下：

<!-- 截图：image-20210416170129789（在线版图片，未随附） -->

有大量的ESTABLISHED状态和TIME_WAIT状态的网络连接

- 当前的ftp会话

> ftp和ssh不一样，ftp的会话一般很难捕捉到，除非此时此刻正在使用

- last -w -x 
  <!-- 截图：image-20210416171132682（在线版图片，未随附） -->
  从返回结果可以看到，有大概5次ftp连接，有一个会话依旧在线，依旧在线的连接pid为 21990
- ftpwho 
  也可以使用ftpwho来进行查看，这个工具默认没有安装在ubuntu中，需要 `apt install ftpwho`
  <!-- 截图：image-20210416171835329（在线版图片，未随附） -->
  接下来我们看看日志

> 在ubuntu上，vsftpd的日志位于 `/var/log/vsftpd.log`

- 正常登录的日志

<!-- 截图：image-20210416182252863（在线版图片，未随附） -->

- 下载文件

<!-- 截图：image-20210416182857241（在线版图片，未随附） -->

- 错误登录的日志 （不分账号是否存在）

<!-- 截图：image-20210416183352143（在线版图片，未随附） -->

- 暴力破解的日志

<!-- 截图：image-20210416183757651（在线版图片，未随附） -->

看来拒绝服务这事，服务器也是拒绝的

- 登录失败的账号地址

`cat /var/log/vsftpd.log | grep FAIL | cut -d "[" -f 3 | cut -d "]" -f 1 | sort | uniq -c | sort -nr`

<!-- 截图：image-20210416184244914（在线版图片，未随附） -->

- 查看登录失败的用户的登录IP

`cat /var/log/vsftpd.log | grep FAIL | cut -d "[" -f 3 | cut -d "]" -f 1 | sort | uniq | while read line;do echo $line;cat /var/log/vsftpd.log | grep  $line | cut -d ":" -f 7 | cut -d '"' -f 1 | sort | uniq -c | sort -nr; done`

<!-- 截图：image-20210416185123818（在线版图片，未随附） -->

- FTP服务加固
- 禁用 anonymous 和 ftp 两个账号
- 使用 SSL 加密 FTP
- 安装 fail2ban 来进行防御

### 0x05 Redis 未授权访问&暴力破解

> 未授权访问漏洞，洞如其名，因为不需要授权，所以可能会导致一顿恶意操作

没啥说的，直接连接就好

<!-- 截图：image-20210419132104196（在线版图片，未随附） -->

加固方案

- 设置密码,并且密码足够复杂
- 将redis.conf 中的 requirepass 前的注释打开，并且设置一个复杂密码 
  <!-- 截图：image-20210419133504140（在线版图片，未随附） -->
- 按照需求进行收口，如果仅仅是本机使用，可以绑定IP为 127.0.0.1

<!-- 截图：image-20210419135938427（在线版图片，未随附） -->

修改配置文件后需要重启redis生效

> redis 默认是不记录日志的，可以通过配置 logfile 来进行设置日志记录 ,默认的loglevel为notice

<!-- 截图：image-20210419143501618（在线版图片，未随附） -->

<!-- 截图：image-20210419143903356（在线版图片，未随附） -->

redis3.2版本后新增protected-mode配置，默认是yes，即开启。设置外部网络连接redis服务，设置方式如下：

1、关闭protected-mode模式，此时外部网络可以直接访问

2、开启protected-mode保护模式，需配置bind ip或者设置访问密码

> Redis 日志分析

- 未授权登录日志

loglevel = notice

主机未授权登录 --> 执行info --> 执行set hello wrold --> exit退出

<!-- 截图：image-20210419153729089（在线版图片，未随附） -->

<!-- 截图：image-20210419153657136（在线版图片，未随附） -->

loglevel = verbose

主机未授权登录 --> 执行info --> 执行set hello wrold --> exit退出

<!-- 截图：image-20210419152755915（在线版图片，未随附） -->

<!-- 截图：image-20210419154913032（在线版图片，未随附） -->

loglevel = debug

主机未授权登录 --> 执行info --> 执行set hello wrold --> exit退出

<!-- 截图：image-20210419152925766（在线版图片，未随附） -->

<!-- 截图：image-20210419155031694（在线版图片，未随附） -->

> 综上可以看出：
> 
> 只有手动设置logfile才能保存日志，默认不设置
> 默认的日志级别notice是不会记录登录、执行指令、退出的。
> loglevel设置为 verbose或者debug才会记录登录主机
> 执行的指令 info ，set 等即使 loglevel 是 debug 级别也不会记录，但是会记录我们设置了多少个key，具体key名称以及内容不会记录

如果想临时记录一下详细日志可以使用 MONITOR

使用我们的主机登录redis，之后执行 MONITOR 指令，之后就可以看到其他主机连接redis服务器后的详细操作了

<!-- 截图：image-20210419155924555（在线版图片，未随附） -->

> redis 暴力破解

<!-- 截图：image-20210419162557120（在线版图片，未随附） -->

- loglevel = notice

<!-- 截图：image-20210419162634243（在线版图片，未随附） -->

- loglevel = verbose

<!-- 截图：image-20210419162833762（在线版图片，未随附） -->

- loglevel=debug

<!-- 截图：image-20210419163007468（在线版图片，未随附） -->

> 综上来看，我们只有把 loglevel 设置为 verbose 或者 debug 的时候才可以记录到暴力破解
> 也就是说默认情况下不看网络连接根本无法观察到暴力破解，当然了，安全设备如edr可能是会监测的
> 20210419 现在的问题是 redis 对于认证成功和失败日志都是一样的，无法区分攻击和正常登录,需要后期再讨论
> 20210513 redis 目前无法通过日志来判断是否被暴力破解

<!-- 截图：image-20210419194131896（在线版图片，未随附） -->

暴力破解的

<!-- 截图：image-20210419194607697（在线版图片，未随附） -->

---

ubuntu 16.04 安装 4.0.9 版本的 redis

- 配置文件默认  `/etc/redis/redis.conf`
- 默认开启 protect mode ,绑定IP为 127.0.0.1
- 默认记录日志 `/var/log/redis/redis-server.log`

<!-- 截图：image-20210421140530386（在线版图片，未随附） -->

我们关闭protected-mode ，设置 bind 0.0.0.0 ,进行正常访问和错误登录尝试，设置 requirepass 密码

> 日志等级verbose --> 错误密码登录尝试 --> 退出 --> 正确密码登录 --> 执行 info --> 执行 set hello world --> 退出

<!-- 截图：image-20210421142352231（在线版图片，未随附） -->

> 日志等级 debug --> 错误密码登录尝试 --> 退出 --> 正确密码登录 --> 执行 info --> 执行 set hello world --> 退出

<!-- 截图：image-20210421143216002（在线版图片，未随附） -->

我擦，放弃放弃，登录成功失败一个样

### 0x06 Mongodb 暴力破解

Mongodb 曾经也出现过未授权访问漏洞，具体可以参照Freebuf 上的文章 https://www.freebuf.com/vuls/212799.html

```
3.0之前版本的MongoDB,默认监听在0.0.0.0，3.0及之后版本默认监听在127.0.0.1。 
3.0之前版本，如未添加用户管理员账号及数据库账号，使用--auth参数启动时，在本地通过127.0.0.1仍可无需账号密码登录访问数据库，远程访问则提示需认证； 
3.0及之后版本，使用--auth参数启动后，无账号则本地和远程均无任何数据库访问权限。 
```

为了分析日志，我们把监听设置为 0.0.0.0 ，使用另一台服务器来进行连接

<!-- 截图：image-20210420111110653（在线版图片，未随附） -->

在 Ubuntu 上默认无需密码验证（可以添加启动参数来设置密码验证），默认配置文件位置为 `/etc/mongodb.conf` 默认的的日志位置为 `/var/log/mongodb/mongodb.log` , 3.0 以上版本默认 band_ip 为 127.0.0.1 ，我们修改一下以便实验

<!-- 截图：image-20210420111616823（在线版图片，未随附） -->

这样 Centos 就可以连接上了

<!-- 截图：image-20210420111819092（在线版图片，未随附） -->

> 日志分析

- 正常启动，无访问

<!-- 截图：image-20210420112648038（在线版图片，未随附） -->

- 无密码正常访问 -- > 执行 show dbs --> exit 退出

<!-- 截图：image-20210420112953562（在线版图片，未随附） -->

mongodb 有一点非常好，它会记录客户端的系统 banner 信息，上图就可以清晰看到 Centos 7.8 的客户端连接了mongodb，但是遗憾的是默认并没有记录客户端的具体操作，当然了，遗憾这两个字是针对安全人员来说的，对于应用正常使用，日志存储，日志可读性，保密性等角度来说，这么做是有道理的。

当然了，mongodb 也提供了详细日志的选项，我们尝试打开

<!-- 截图：image-20210420114553703（在线版图片，未随附） -->

我们看一下开启了 verbose 之后

- 无密码正常访问 -- > 执行 show dbs --> exit 退出

<!-- 截图：image-20210420131111612（在线版图片，未随附） -->

<!-- 截图：image-20210420131231537（在线版图片，未随附） -->

<!-- 截图：image-20210420131314484（在线版图片，未随附） -->

可以看到，即使是设置 verbose 后还是不会记录具体的操作，但确实是整个过程更详细了

> 日志未设置 verbose

- 有密码正常访问 --> 执行 show dbs --> 退出

<!-- 截图：image-20210420134302533（在线版图片，未随附） -->

<!-- 截图：image-20210420135500449（在线版图片，未随附） -->

这里需要注意的是，连接到数据库后，不执行任何操作就会产生下面这条日志

```
Unauthorized: not authorized on admin to execute command { replSetGetStatus: 1.0, forShell: 1.0, $db: "admin" } 
```

也就是我标记为连接后尚未认证的这条

- 有密码 --> 使用不存在用户登录 --> 存在用户错误密码登录尝试 --> 正确用户名密码登录--> show dbs --> 退出

<!-- 截图：image-20210420142338378（在线版图片，未随附） -->

- 暴力破解

<!-- 截图：image-20210420143259853（在线版图片，未随附） -->

<!-- 截图：image-20210420143325752（在线版图片，未随附） -->

可以看到，存在大量的failed 的日志，这就好办了

> 日志设置 verbose

直接暴力破解就好

<!-- 截图：image-20210420143801623（在线版图片，未随附） -->

<!-- 截图：image-20210420143835784（在线版图片，未随附） -->

可以看到，虽然更加详细了，但是关键字 failed 还是在的，可以以此来作为筛选依据

> **日志分析**

不同系统以及安装环境日志目录可能不同，这里使用 ubuntu默认的目录 `/var/log/mongodb/mongodb.log`

- 存在的账户的登录失败情况

`cat /var/log/mongodb/mongodb.log | grep -v "UserNotFound"|grep failed | awk -F " " '{print $9}' | sort|uniq -c|sort -nr`

<!-- 截图：image-20210420150225007（在线版图片，未随附） -->

- 存在的某个账户 (以root为例) 登录失败的来源IP以及次数

`cat /var/log/mongodb/mongodb.log | grep -v "UserNotFound"|grep failed| grep root | awk -F " " '{print $14}' | cut -d ":" -f 1 | sort | uniq -c | sort -nr`

<!-- 截图：image-20210420150641540（在线版图片，未随附） -->

- 查看所有存在的账户登录失败的来源以及次数

`cat /var/log/mongodb/mongodb.log | grep -v "UserNotFound"|grep failed | awk -F " " '{print $9}' |sort | uniq | while read line;do echo $line;cat /var/log/mongodb/mongodb.log |grep -v "UserNotFound" | grep failed | grep $line | awk -F " " '{print $14}' | cut -d ":" -f 1 | sort | uniq -c | sort -nr; done`

<!-- 截图：image-20210420152915307（在线版图片，未随附） -->

- 不存在的账户的登录尝试

`cat /var/log/mongodb/mongodb.log | grep "UserNotFound"|grep failed | awk -F " " '{print $9}' | sort|uniq -c|sort -nr`

<!-- 截图：image-20210420160401931（在线版图片，未随附） -->

- 不存在账户的登录IP以及次数

`cat /var/log/mongodb/mongodb.log | grep "UserNotFound"|grep failed | awk -F " " '{print $9}' |sort | uniq | while read line;do echo $line;cat /var/log/mongodb/mongodb.log |grep "UserNotFound" | grep failed | grep $line | awk -F " " '{print $14}' | cut -d ":" -f 1 | sort | uniq -c | sort -nr; done`

<!-- 截图：image-20210420170211782（在线版图片，未随附） -->

### 0x07 smtp 暴力破解

邮件服务这块一直是企业突破口的重灾区，主要涉及三个协议 SMTP, POP3, IMAP

简单来说，SMTP负责发，POP3、IMAP负责收，POP3协议客户端收到邮件，服务器端就会将其删除，除非有特殊的配置，可能在一些方面有其用途。IMAP则弥补了这一缺陷，客户端该收收，服务端还给你保存着，同时你在客户端的各种配置操作都会在服务器上进行同步

按照其用途来说，三种协议都有身份认证的过程，对于这种出现较早的协议，设计之初都不会有双因素认证这种东西，毕竟是安全人员出现以后，网络才变得不安全了，所以出现了现在各种协议的补充，对于三种协议的具体数据包分析可以看下面的文章

https://wooyun.js.org/drops/Wireshark%E9%BB%91%E5%AE%A2%E5%8F%91%E7%8E%B0%E4%B9%8B%E6%97%85%EF%BC%884%EF%BC%89%E2%80%94%E2%80%94%E6%9A%B4%E5%8A%9B%E7%A0%B4%E8%A7%A3.html

这里直接将文章中的内容引用到这里

- POP3

```
+OK Microsoft Exchange Server 2003 POP3 .......... 6.5.6944.0 (a-ba21a05129e24.test.org) ........   //服务器准备就绪
CAPA   //用于取得此服务器的功能选项清单
+OK Capability list follows
TOP
USER
PIPELINING
EXPIRE NEVER
UIDL
.
USER jufeng001@test.org    //与 POP3 Server 送出帐户名
+OK
PASS 1qaz@WSX    //与 POP3 Server 送出密码
+OK User successfully logged on.   //认证成功
STAT
+OK 14 21568
QUIT
+OK Microsoft Exchange Server 2003 POP3 .......... 6.5.6944.0 ..........
```

- smtp

```
220 a-ba21a05129e24.test.org Microsoft ESMTP MAIL Service, Version: 6.0.3790.3959 ready at  Thu, 6 Aug 2015 11:10:17 +0800  //服务就绪
EHLO Mr.RightPC //主机名
250-a-ba21a05129e24.test.org Hello [192.1.14.228]
……
250 OK
AUTH LOGIN  //认证开始
334 VXNlcm5hbWU6  // Username:
anVmZW5nMDAxQHRlc3Qub3Jn  //输入用户名的base64编码
334 UGFzc3dvcmQ6  // Password:
MXFhekBXU1g=   //输入密码的base64编码
235 2.7.0 Authentication successful.    //认证成功
```

- IMAP

```
* OK Microsoft Exchange Server 2003 IMAP4rev1 .......... 6.5.6944.0 (a-ba21a05129e24.test.org) ........     //IMAP服务就绪
bf8p CAPABILITY
* CAPABILITY IMAP4 IMAP4rev1 IDLE LOGIN-REFERRALS MAILBOX-REFERRALS NAMESPACE LITERAL+ UIDPLUS CHILDREN
bf8p OK CAPABILITY completed.
s3yg LOGIN "jufeng002" "1qaz@WSX"        //输入用户名:jufeng002，密码:1qaz@WSX
s3yg OK LOGIN completed.     //认证成功
```

Linux 常用的邮件服务器为  Postfix , ubuntu 上默认日志位置 /var/log/mail.log

> SMTP认证失败的IP统计

`cat /var/log/mail.log | grep "authentication failed" | grep -Po '(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|[1-9])(\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|\d)){3}' |sort|uniq -c|sort -nr`

<!-- 截图：image-20210421110831573（在线版图片，未随附） -->

Postfix 日志能够提取的内容似乎不多，也就这些

### 0x08 善后阶段

> 直接查看善后阶段即可

### 0x09 常规安全检查阶段

> 直接根据常规安全检查章节进行安全检查即可，目的是找出当前系统中存在的隐藏后门等
