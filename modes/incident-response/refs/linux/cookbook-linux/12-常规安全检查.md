> 原文来源：Linux-INCIDENT-RESPONSE-COOKBOOK（GPL-3.0），作者 NOP Team，https://github.com/Just-Hack-For-Fun/Linux-INCIDENT-RESPONSE-COOKBOOK ；本节原文抓取自在线版 URL https://book.noptrace.com/linux/12.%E5%B8%B8%E8%A7%84%E5%AE%89%E5%85%A8%E6%A3%80%E6%9F%A5/

# 常规安全检查


> 善后阶段是所有事件处置都要做的步骤，放在最后一起写，主要内容包括以下几个方面

### 0x01 杀毒工具查杀

- chkrootkit
- clamav
- Unhide
- Rootkit Hunter

### 0x02 history 信息

以下四种情况history 会不完整

- 被清空或设置不记录， `history -c`  或者 `unset HISTORY HISTFILE HISTSAVE HISTZONE HISTORY HISTLOG; export HISTFILE=/dev/null; export HISTSIZE=0; export HISTFILESIZE=0`
- 如果ssh 异常中断（比如网络中断），历史命令还在缓冲区中不会写入到文件中，就会导致此连接执行的命令没有记录
- 如果命令前带一个空格，这条命令就不会被记录
- 通过 ssh 直接远程执行的命令不会记录
  - 例如 ssh ubuntu@192.168.1.1 "whoami"

history 信息默认是不显示命令执行的时间的，默认并没有记录，可以通过配置环境变量将时间显示出来，在设置后，在当前 shell 中执行的命令会同时记录时间戳

```
export HISTTIMEFORMAT='%F %T '
```

<!-- 截图：image-20250303215826466（在线版图片，未随附） -->

由于之前没有记录时间，所以此时显示的历史时间是不准的，使用上述命令设置环境变量之后，是一个临时的环境变量，也就是说仅在当前 shell 中记录，断开本次 ssh 或者关闭终端窗口后，会写入到 `~/.bash_history` 中，并且附带时间，可以在后续再次设置环境该环境变量时显示出具体时间

<!-- 截图：image-20250303220409864（在线版图片，未随附） -->

<!-- 截图：image-20250303220438186（在线版图片，未随附） -->

### 0x03 计划任务

需要检查的项

- /etc/crontab
- /etc/cron.d/*
- /var/spool/cron/xxxx
- /etc/anacrontab (Redhat/Centos)
- /var/spool/at/*
- /var/spool/cron/atspool/
- /var/spool/cron/atjobs/

**建议检查的时候使用vim打开具体的计划任务文件去看，cat命令存在一些缺陷，可以被某些字符截断，造成看的不全，具体可以参考公众号文章** [计划任务后门 | Linux 后门系列](https://mp.weixin.qq.com/s/snJ80-Aiy9-XfFvJw380vg)

【ubuntu server 16.04 64位】 默认计划任务情况

<!-- 截图：image-20210512104249066（在线版图片，未随附） -->

<!-- 截图：image-20210512104423693（在线版图片，未随附） -->

<!-- 截图：image-20210512105007780（在线版图片，未随附） -->

<!-- 截图：image-20210512105034718（在线版图片，未随附） -->

【Ubuntu Server 22.04】默认 at 和 batch 任务

<!-- 截图：image-20250227004407558（在线版图片，未随附） -->

【Centos7 64位】默认计划任务情况

<!-- 截图：image-20210512105319522（在线版图片，未随附） -->

<!-- 截图：image-20210512105349294（在线版图片，未随附） -->

<!-- 截图：image-20210512105705436（在线版图片，未随附） -->

<!-- 截图：image-20210512105609027（在线版图片，未随附） -->

【Rocky Linux 9.1】默认 at 和 batch 任务

<!-- 截图：image-20250227004608370（在线版图片，未随附） -->

更加详细信息可以参照下面这篇文章

https://mp.weixin.qq.com/s/snJ80-Aiy9-XfFvJw380vg

### 0x04 账户信息

- 新增账户
- cat /etc/passwd

<!-- 截图：image-20210421145942247（在线版图片，未随附） -->

可以与主机和业务相关人员确定是否存在未知账号，即使是 nologin 的也是可能造成风险的，比如使用 sftp 上传下载文件

【ubuntu server 16.04 64位】默认账号情况（helper是我创建的账号）

<!-- 截图：image-20210512110015314（在线版图片，未随附） -->

```
root
daemon
bin
sys
sync
games
man
lp
mail
news
uucp
proxy
www-data
backup
list
irc
gnats
nobody
systemd-timesync
systemd-network
systemd-resolve
systemd-bus-proxy
syslog
_apt
lxd
messagebus
uuidd
dnsmasq
sshd
```

【Centos 7】 默认账号情况（helper是我创建的账号）

<!-- 截图：image-20210512110118344（在线版图片，未随附） -->

```
root
bin
daemon
adm
lp
sync
shutdown
halt
mail
operator
games
ftp
nobody
systemd-network
dbus
polkitd
sssd
libstoragemgmt
colord
rpc
abrt
setroubleshoot
rtkit
chrony
ntp
gluster
unbound
tss
usbmuxd
geoclue
pulse
gdm
saned
rpcuser
nfsnobody
gnome-initial-setup
sshd
avahi
postfix
tcpdump
```

### 0x05 特权账户

`awk -F: '$3==0 {print $1}' /etc/passwd`

【ubuntu server 16.04 64位】默认情况

<!-- 截图：image-20210512110711692（在线版图片，未随附） -->

【Centos7 64位】默认情况

<!-- 截图：image-20210512110905413（在线版图片，未随附） -->

### 0x06 登录信息

- w 显示当前登录系统的用户信息
- who 显示系统中有哪些登录用户
- last -awF 显示所有登录信息
- users 当前登录的账户
- lastlog 显示所有用户最后一次的登录信息
- lslogins 查看系统账户登录信息

参考 https://www.jianshu.com/p/05926453654c

### 0x07 特殊权限文件

- SUID
- `find / -perm /4000`
- GUID
- `find / -perm /2000`
- SUID或者GUID
- `find / -perm /6000`

【ubuntu server 16.04 64位】默认情况

<!-- 截图：image-20210512111051482（在线版图片，未随附） -->

<!-- 截图：image-20210512111222476（在线版图片，未随附） -->

<!-- 截图：image-20210512111712876（在线版图片，未随附） -->

<!-- 截图：image-20210512111754432（在线版图片，未随附） -->

【Centos7 64位】默认情况

<!-- 截图：image-20210512112103389（在线版图片，未随附） -->

<!-- 截图：image-20210512112143966（在线版图片，未随附） -->

<!-- 截图：image-20210512112306529（在线版图片，未随附） -->

### 0x08 动态链接库劫持

- LD_PRELOAD
- `echo $LD_PRELOAD`
- /etc/ld.so.conf
- LD_LIBRARY_PATH
- `echo $LD_LIBRARY_PATH`
- /etc/ld.so.preload

【ubuntu server 16.04 64位】默认情况

<!-- 截图：image-20210512112828696（在线版图片，未随附） -->

<!-- 截图：image-20210819144413660（在线版图片，未随附） -->

【Centos7 64位】默认情况

<!-- 截图：image-20210512112957447（在线版图片，未随附） -->

<!-- 截图：image-20210819144443486（在线版图片，未随附） -->

具体可以参考

https://mp.weixin.qq.com/s/7mOeZ6DkSAFqzibN82qcMg

https://mp.weixin.qq.com/s/InMQaKOwns2mEIp5yF8dDw

### 0x09 BASH内置命令

> bash
> 在 bash 中输入一个命令，如果有多个同名指令，bash 需要按照一定规则去取优先级高的一个执行，bash 命令的搜索顺序为：
> 1、别名，使用alias创建的命令
> 2、关键字，如if，for
> 3、函数 
> 4、内置命令，如cd，pwd等 
> 5、外部命令，在PATH路径中寻找
> 详细可以参考 https://www.cnblogs.com/zhiminyu/p/14388997.html

根据 bash 的命令解析顺序，很多内置命令在系统中也有相关的文件，但是不出意外，这辈子不会得到执行，所以这帮文件就很适合作为后门文件，比较隐蔽

在 Centos 上很多内置命令是有同名文件的，在 /usr/bin/ 目录下边，在 Ubuntu 中没有同名文件。这些文件的内容基本就是执行 bash 内置命令

- 查看内置命令
- `compgen -b`   // 不包含使用方法，仅仅列出来命令有哪些
  <!-- 截图：image-20210909225526570（在线版图片，未随附） -->
- `help`        // 列出命令并给出使用方法
  <!-- 截图：image-20210909225556405（在线版图片，未随附） -->

ubuntu 16.04 和 Centos 7 默认内置命令是一样的，如下：

```
.
:
[
alias
bg
bind
break
builtin
caller
cd
command
compgen
complete
compopt
continue
declare
dirs
disown
echo
enable
eval
exec
exit
export
false
fc
fg
getopts
hash
help
history
jobs
kill
let
local
logout
mapfile
popd
printf
pushd
pwd
read
readarray
readonly
return
set
shift
shopt
source
suspend
test
times
trap
true
type
typeset
ulimit
umask
unalias
unset
wait
```

- 寻找内置命令同名文件

`compgen -b | grep -v -E "\.|\:" | while read line;do ls /usr/bin/$line 2>null ; done`

ubuntu 16.04 上存在的相关文件

```
/usr/bin/[
/usr/bin/printf
/usr/bin/test
```

Centos 7 上存在的相关文件

```
/usr/bin/[
/usr/bin/alias
/usr/bin/bg
/usr/bin/cd
/usr/bin/command
/usr/bin/echo
/usr/bin/false
/usr/bin/fc
/usr/bin/fg
/usr/bin/getopts
/usr/bin/jobs
/usr/bin/kill
/usr/bin/printf
/usr/bin/pwd
/usr/bin/read
/usr/bin/test
/usr/bin/true
/usr/bin/umask
/usr/bin/unalias
/usr/bin/wait
```

- 内置命令对应文件内容

以 cd 命令为例，Centos 7 中 /usr/bin/cd 内容如下：

<!-- 截图：image-20210909230632662（在线版图片，未随附） -->

> 这里存在一个问题，有一部分文件(如 /usr/bin/test 等) 不是像上面的脚本文件，而且随着系统版本的不同，bash版本的不同而不同，所以这里先讨论脚本文件，二进制文件以后我再想办法，命令如下：
> `compgen -b | grep -v -E "\.|\:" | while read line;do result=$(ls /usr/bin/$line 2>null && file /usr/bin/$line);if [[ $result =~ "script" ]]; then echo "---------------------" && echo /usr/bin/$line && cat /usr/bin/$line; fi ; done`

ubuntu 16.04 内置命令对应文件内容(脚本文件)

<!-- 截图：image-20210910002840587（在线版图片，未随附） -->

ubuntu上没有脚本类同名文件

Centos7 内置命令对应文件内容(脚本文件)

<!-- 截图：image-20210910003228772（在线版图片，未随附） -->

Centos 7 默认是存在以下几个同名的脚本文件

```
/usr/bin/alias
/usr/bin/bg
/usr/bin/cd
/usr/bin/command
/usr/bin/fc
/usr/bin/fg
/usr/bin/getopts
/usr/bin/jobs
/usr/bin/read
/usr/bin/umask
/usr/bin/unalias
/usr/bin/wait
```

为了方便大家比对，将文件内容粘贴出

```
------------------
/usr/bin/alias
#!/bin/sh
builtin alias "$@"
------------------
/usr/bin/bg
#!/bin/sh
builtin bg "$@"
------------------
/usr/bin/cd
#!/bin/sh
builtin cd "$@"
------------------
/usr/bin/command
#!/bin/sh
builtin command "$@"
------------------
/usr/bin/fc
#!/bin/sh
builtin fc "$@"
------------------
/usr/bin/fg
#!/bin/sh
builtin fg "$@"
------------------
/usr/bin/getopts
#!/bin/sh
builtin getopts "$@"
------------------
/usr/bin/jobs
#!/bin/sh
builtin jobs "$@"
------------------
/usr/bin/read
#!/bin/sh
builtin read "$@"
------------------
/usr/bin/umask
#!/bin/sh
builtin umask "$@"
------------------
/usr/bin/unalias
#!/bin/sh
builtin unalias "$@"
------------------
/usr/bin/wait
#!/bin/sh
builtin wait "$@"
```

### 0x10 BASH 函数

> bash
> 在 bash 中输入一个命令，如果有多个同名指令，bash 需要按照一定规则去取优先级高的一个执行，bash 命令的搜索顺序为：
> 1、别名，使用alias创建的命令
> 2、关键字，如if，for
> 3、函数 
> 4、内置命令，如cd，pwd等 
> 5、外部命令，在PATH路径中寻找
> 详细可以参考 https://www.cnblogs.com/zhiminyu/p/14388997.html

系统默认就设置了一些函数，可以通过 declare 命令来进行查看
- `declare -f`
    查看所有函数的具体定义内容

**内容比较长，肉眼比对比较麻烦，工具化参考小技巧篇章第7节**

可以使用 `unset -f functionName` 的方式来将恶意的函数删除

### 0x11 环境变量

- `env`
- `set`
- `export`
- `cat /proc/$PID/environ`
- `declare`

【ubuntu server 16.04 64位】默认情况

<!-- 截图：image-20210512113135041（在线版图片，未随附） -->

【Centos7 64位】默认情况

<!-- 截图：image-20210512113212254（在线版图片，未随附） -->

### 0x12 启动项&配置脚本

- `systemctl list-unit-files --type=service | grep enabled`
- 如果发现非法开机自启服务项，可以使用如下语法进行停止并使其不开机自启,以 `bluetooth` 为例
- `systemctl stop bluetooth.service`
- `systemctl disable bluetooth.service`
- /etc/rc.local
- /etc/rc.d/rc.local
- /etc/rc.d/init.d/
- chkconfig --list
- /etc/profile
- /etc/profile.d/*
- /etc/bashrc
- ~/.bashrc
- ~/.bash_profile
- ~/.profile
- ~/.bash_logout

> 由于内容较多，所以放在了知识点附录，具体 Ubutnu和Centos中默认启动项可以查看知识点附录 0x02

### 0x13 ssh key

- `/root/.ssh/authorized_keys`  保存着远程主机的公钥，远程主机可以无密码登录
- `~/.ssh/authorized_keys` 每个用户都会在自己的家目录保存一份
- `/root/.ssh/known_hosts` 每登录一台主机ssh就会把对方的公钥记录下来，下次连接进行比对，以防止网络劫持

`~/.ssh/authorized_keys`  和 `~/.ssh/authorized_keys2` 文件可以被用来配置后门，检查方法如下

> 相关后门文章可以查看
> https://mp.weixin.qq.com/s/R_CUPqa2WQUgOJu__5MFzg

本质上来说，可以通过密钥直接访问该ssh服务器的主机公钥的存储位置是由配置文件决定的，具体配置在 `/etc/ssh/sshd_config` 的 `AuthorizedKeysFile` 参数

<!-- 截图：图片（在线版图片，未随附） -->

默认情况下以下两个文件内容都有效

- `~/.ssh/authorized_keys`
- `~/.ssh/authorized_keys2`

此部分检查主要分为两个方向

- 是否存在非法添加的公钥
- 存储的公钥行中是否存在 command 参数
- 一般在行开头 `command="xxxx"`
- command 指定的命令会在对应用户登录时执行

<!-- 截图：image-20230811005940101（在线版图片，未随附） -->

### 0x14 ssh config

> ssh 客户端配置文件加载顺序 命令行参数 > ~/.ssh/config > /etc/ssh/ssh_config

`/etc/ssh/ssh_config`

这个文件默认存在

`~/.ssh/config`

默认是没有这个文件的，这个文件是给客户端用的

如果上述两个文件存在，可以检查其中的参数，以下两个参数可以被用作后门

- LocalCommand
- ProxyCommand

具体可以参照公众号文章 [SSH Config 后门 ｜ Linux 后门系列](https://mp.weixin.qq.com/s/7WDWjMOI7GdUM5e4vDVAoA)

### 0x15 alias 信息

- 直接输入 `alias` 就好

<!-- 截图：image-20210421163816107（在线版图片，未随附） -->

【Ubuntu server 16.04 64位】 默认情况

<!-- 截图：image-20210512173809616（在线版图片，未随附） -->

【Centos 7 64位】默认情况

<!-- 截图：image-20210512173850123（在线版图片，未随附） -->

具体可以参考

https://mp.weixin.qq.com/s/yXY8opNctHK5d9tXhQj35w

### 0x16 DNS配置

- `/etc/resolv.conf`

### 0x17 日志

> 日志分析就比较笼统了，基本上上面都涉及到了，基本都在 /var/log/ 下

- ssh-key 追踪
  
  Linux通过key登录。有没有什么好办法判断是哪个key登录的?
  
  可以通过登录日志来进行判断，以下面的日志为例
  <!-- 截图：2b591552b56ecc2c3e6ce76270c6af1a（在线版图片，未随附） -->
  这是两个使用 key 来登录的主机的登录日志，首先是可以看到登录ip的，但是如果想知道分别是哪个key来进行登录的，那就需要把 
  `ssh2: RSA SHA256:Ms6ouzQCIZhNUJWpMmOCBB4h7+x92xu4apHTLe8nVwQ`
  `ssh2: RSA SHA256:C5dMZnKUj8/0c5hj6CSU6D7N8EQK/qbl5CnkLC17GLc`
  这两个值与我们服务器存储的客户端的公钥进行一一对比
  其实这两个值是客户端 RSA 公钥的 SHA256 的值，所以我们可以使用下面的命令把服务器上存储的所有的公钥的SHA 256 计算出来，对比一下
  `ssh-keygen -lf ~/.ssh/authorized_keys`
  <!-- 截图：437a63856b7f3bdc062075b83c145b5b（在线版图片，未随附） -->
  这样一对比就知道是谁了
- journalctl 查看服务日志

```
journalctl -u 服务名称
```

<!-- 截图：image-20230811012036889（在线版图片，未随附） -->

可以通过以下两条命令获取到相应的服务名称

```
systemctl list-units --type=service
service --status-all
```

<!-- 截图：image-20230811012229838（在线版图片，未随附） -->

### 0x18 ptrace_scope

> 默认系统会禁止ptrace进行一些操作，比如 fork 等，可以查看 /proc/sys/kernel/yama/ptrace_scope 文件内容

【ubuntu Server 16.04 】默认

<!-- 截图：image-20210608144053515（在线版图片，未随附） -->

【centos 7】 默认

<!-- 截图：image-20210608144354520（在线版图片，未随附） -->

### 0x19 ASLR

> ASLR 是一项 Linux 系统的保护措施，将某些地址空间进行随机化，减缓一些溢出攻击

`cat /proc/sys/kernel/randomize_va_space`

此处文件内容含义如下：

- 0 - 表示关闭进程地址空间随机化。
- 1 - 表示将mmap的基址，stack和vdso页面随机化
- 2 - 表示在1的基础上增加堆（heap）的随机化

【Ubuntu Server 16.04】默认情况

<!-- 截图：image-20211123224613033（在线版图片，未随附） -->

【Centos 7】默认情况

<!-- 截图：image-20211123224655398（在线版图片，未随附） -->

`/proc/sys/kernel/randomize_va_space` 是一个在系统运行时生成的文件；一般都在 `/etc/sysctl.conf` 中配置 ASLR 的永久关闭

【Ubuntu Server 16.04】默认情况

<!-- 截图：image-20211123230303998（在线版图片，未随附） -->

【Centos 7】默认情况

<!-- 截图：image-20211123230319818（在线版图片，未随附） -->

### 0x20 capabilities

> capabilities 是一种对 Linux 权限更严格划分和管控的规范，设置得当可以有效防止过度授权造成提权操作

`getcap -r / 2>/dev/null`

【Ubuntu Server 16.04】默认情况

<!-- 截图：image-20211123212548027（在线版图片，未随附） -->

【Centos 7】默认情况

<!-- 截图：image-20211123212629003（在线版图片，未随附） -->

如果发现权限设置错误，可以使用 `setcap` 进行重新设置或者取消

### 0x21 iptables 端口复用

> 有些攻击者喜欢使用 iptables 进行端口复用

`sudo iptables -L`

【Ubuntu Server 16.04】默认情况

<!-- 截图：image-20211123214752826（在线版图片，未随附） -->

【Centos 7】默认情况

```
Chain INPUT (policy ACCEPT)
target     prot opt source               destination         
ACCEPT     all  --  anywhere             anywhere             ctstate RELATED,ESTABLISHED
ACCEPT     all  --  anywhere             anywhere            
INPUT_direct  all  --  anywhere             anywhere            
INPUT_ZONES_SOURCE  all  --  anywhere             anywhere            
INPUT_ZONES  all  --  anywhere             anywhere            
DROP       all  --  anywhere             anywhere             ctstate INVALID
REJECT     all  --  anywhere             anywhere             reject-with icmp-host-prohibited

Chain FORWARD (policy ACCEPT)
target     prot opt source               destination         
ACCEPT     all  --  anywhere             anywhere             ctstate RELATED,ESTABLISHED
ACCEPT     all  --  anywhere             anywhere            
FORWARD_direct  all  --  anywhere             anywhere            
FORWARD_IN_ZONES_SOURCE  all  --  anywhere             anywhere            
FORWARD_IN_ZONES  all  --  anywhere             anywhere            
FORWARD_OUT_ZONES_SOURCE  all  --  anywhere             anywhere            
FORWARD_OUT_ZONES  all  --  anywhere             anywhere            
DROP       all  --  anywhere             anywhere             ctstate INVALID
REJECT     all  --  anywhere             anywhere             reject-with icmp-host-prohibited

Chain OUTPUT (policy ACCEPT)
target     prot opt source               destination         
ACCEPT     all  --  anywhere             anywhere            
OUTPUT_direct  all  --  anywhere             anywhere            

Chain FORWARD_IN_ZONES (1 references)
target     prot opt source               destination         
FWDI_public  all  --  anywhere             anywhere            [goto] 
FWDI_public  all  --  anywhere             anywhere            [goto] 

Chain FORWARD_IN_ZONES_SOURCE (1 references)
target     prot opt source               destination         

Chain FORWARD_OUT_ZONES (1 references)
target     prot opt source               destination         
FWDO_public  all  --  anywhere             anywhere            [goto] 
FWDO_public  all  --  anywhere             anywhere            [goto] 

Chain FORWARD_OUT_ZONES_SOURCE (1 references)
target     prot opt source               destination         

Chain FORWARD_direct (1 references)
target     prot opt source               destination         

Chain FWDI_public (2 references)
target     prot opt source               destination         
FWDI_public_log  all  --  anywhere             anywhere            
FWDI_public_deny  all  --  anywhere             anywhere            
FWDI_public_allow  all  --  anywhere             anywhere            
ACCEPT     icmp --  anywhere             anywhere            

Chain FWDI_public_allow (1 references)
target     prot opt source               destination         

Chain FWDI_public_deny (1 references)
target     prot opt source               destination         

Chain FWDI_public_log (1 references)
target     prot opt source               destination         

Chain FWDO_public (2 references)
target     prot opt source               destination         
FWDO_public_log  all  --  anywhere             anywhere            
FWDO_public_deny  all  --  anywhere             anywhere            
FWDO_public_allow  all  --  anywhere             anywhere            

Chain FWDO_public_allow (1 references)
target     prot opt source               destination         

Chain FWDO_public_deny (1 references)
target     prot opt source               destination         

Chain FWDO_public_log (1 references)
target     prot opt source               destination         

Chain INPUT_ZONES (1 references)
target     prot opt source               destination         
IN_public  all  --  anywhere             anywhere            [goto] 
IN_public  all  --  anywhere             anywhere            [goto] 

Chain INPUT_ZONES_SOURCE (1 references)
target     prot opt source               destination         

Chain INPUT_direct (1 references)
target     prot opt source               destination         

Chain IN_public (2 references)
target     prot opt source               destination         
IN_public_log  all  --  anywhere             anywhere            
IN_public_deny  all  --  anywhere             anywhere            
IN_public_allow  all  --  anywhere             anywhere            
ACCEPT     icmp --  anywhere             anywhere            

Chain IN_public_allow (1 references)
target     prot opt source               destination         
ACCEPT     tcp  --  anywhere             anywhere             tcp dpt:ssh ctstate NEW,UNTRACKED
ACCEPT     udp  --  anywhere             224.0.0.251          udp dpt:mdns ctstate NEW,UNTRACKED

Chain IN_public_deny (1 references)
target     prot opt source               destination         

Chain IN_public_log (1 references)
target     prot opt source               destination         

Chain OUTPUT_direct (1 references)
target     prot opt source               destination    
```

### 0x22 密码填充检查

> 如果攻击者对 `/etc/passwd` 文件有写的权限，可以直接在密码字段处填写密码，之后便可以直接使用这个密码进行登录

`awk -F: '$2 != "x" { print $0 }' /etc/passwd`

【Ubuntu Server 22.04】默认情况

<!-- 截图：image-20230811022442718（在线版图片，未随附） -->

【Rocky Linux 9】默认情况

<!-- 截图：image-20230811022630525（在线版图片，未随附） -->

### 0x23 服务检查

> 系统服务相关检查

**列出正在运行的系统服务**

`sudo systemctl list-units --type=service --state=running`

【Ubuntu Server 16.04】默认情况

<!-- 截图：image-20211123222832157（在线版图片，未随附） -->

```
helper@localhost:~$ sudo systemctl list-units --type=service --state=running
UNIT                        LOAD   ACTIVE SUB     DESCRIPTION
accounts-daemon.service     loaded active running Accounts Service
acpid.service               loaded active running ACPI event daemon
atd.service                 loaded active running Deferred execution scheduler
cron.service                loaded active running Regular background program processing daemon
dbus.service                loaded active running D-Bus System Message Bus
getty@tty1.service          loaded active running Getty on tty1
irqbalance.service          loaded active running LSB: daemon to balance interrupts for SMP systems
iscsid.service              loaded active running iSCSI initiator daemon (iscsid)
lvm2-lvmetad.service        loaded active running LVM2 metadata daemon
lxcfs.service               loaded active running FUSE filesystem for LXC
mdadm.service               loaded active running LSB: MD monitoring daemon
open-vm-tools.service       loaded active running Service for virtual machines hosted on VMware
polkitd.service             loaded active running Authenticate and Authorize Users to Run Privileged Tasks
rsyslog.service             loaded active running System Logging Service
ssh.service                 loaded active running OpenBSD Secure Shell server
systemd-journald.service    loaded active running Journal Service
systemd-logind.service      loaded active running Login Service
systemd-timesyncd.service   loaded active running Network Time Synchronization
systemd-udevd.service       loaded active running udev Kernel Device Manager
unattended-upgrades.service loaded active running Unattended Upgrades Shutdown
user@1000.service           loaded active running User Manager for UID 1000
vgauth.service              loaded active running Authentication service for virtual machines hosted on VMware

LOAD   = Reflects whether the unit definition was properly loaded.
ACTIVE = The high-level unit activation state, i.e. generalization of SUB.
SUB    = The low-level unit activation state, values depend on unit type.

22 loaded units listed. Pass --all to see loaded but inactive units, too.
To show all installed unit files use 'systemctl list-unit-files'.
```

【Centos 7】默认情况

<!-- 截图：image-20211123223115999（在线版图片，未随附） -->

```
[helper@localhost ~]$ sudo systemctl list-units --type=service --state=running
UNIT                     LOAD   ACTIVE SUB     DESCRIPTION
abrt-oops.service        loaded active running ABRT kernel log watcher
abrt-xorg.service        loaded active running ABRT Xorg log watcher
abrtd.service            loaded active running ABRT Automated Bug Reporting Tool
accounts-daemon.service  loaded active running Accounts Service
alsa-state.service       loaded active running Manage Sound Card State (restore and store)
atd.service              loaded active running Job spooling tools
auditd.service           loaded active running Security Auditing Service
avahi-daemon.service     loaded active running Avahi mDNS/DNS-SD Stack
bluetooth.service        loaded active running Bluetooth service
bolt.service             loaded active running Thunderbolt system service
chronyd.service          loaded active running NTP client/server
colord.service           loaded active running Manage, Install and Generate Color Profiles
crond.service            loaded active running Command Scheduler
cups.service             loaded active running CUPS Printing Service
dbus.service             loaded active running D-Bus System Message Bus
firewalld.service        loaded active running firewalld - dynamic firewall daemon
fprintd.service          loaded active running Fingerprint Authentication Daemon
fwupd.service            loaded active running Firmware update daemon
gdm.service              loaded active running GNOME Display Manager
geoclue.service          loaded active running Location Lookup Service
gssproxy.service         loaded active running GSSAPI Proxy Daemon
libstoragemgmt.service   loaded active running libstoragemgmt plug-in server daemon
lvm2-lvmetad.service     loaded active running LVM2 metadata daemon
ModemManager.service     loaded active running Modem Manager
NetworkManager.service   loaded active running Network Manager
packagekit.service       loaded active running PackageKit Daemon
polkit.service           loaded active running Authorization Manager
postfix.service          loaded active running Postfix Mail Transport Agent
rngd.service             loaded active running Hardware RNG Entropy Gatherer Daemon
rpcbind.service          loaded active running RPC bind service
rsyslog.service          loaded active running System Logging Service
rtkit-daemon.service     loaded active running RealtimeKit Scheduling Policy Service
smartd.service           loaded active running Self Monitoring and Reporting Technology (SMART) Daemon
sshd.service             loaded active running OpenSSH server daemon
systemd-journald.service loaded active running Journal Service
systemd-logind.service   loaded active running Login Service
systemd-udevd.service    loaded active running udev Kernel Device Manager
tuned.service            loaded active running Dynamic System Tuning Daemon
udisks2.service          loaded active running Disk Manager
upower.service           loaded active running Daemon for power management
vgauthd.service          loaded active running VGAuth Service for open-vm-tools
vmtoolsd.service         loaded active running Service for virtual machines hosted on VMware
wpa_supplicant.service   loaded active running WPA Supplicant daemon

LOAD   = Reflects whether the unit definition was properly loaded.
ACTIVE = The high-level unit activation state, i.e. generalization of SUB.
SUB    = The low-level unit activation state, values depend on unit type.

43 loaded units listed. Pass --all to see loaded but inactive units, too.
To show all installed unit files use 'systemctl list-unit-files'.
[helper@localhost ~]$ 
```

**查看某个服务的进程情况**

`systemctl status xxx.service`

这里以 ssh 为例

【Ubuntu Server 16.04】默认情况

<!-- 截图：image-20211123223550842（在线版图片，未随附） -->

【Centos 7】默认情况

<!-- 截图：image-20211123223524231（在线版图片，未随附） -->

我们可以获取 pid 以及启动的文件

**获取某个服务的配置文件**

`systemctl cat xxx.service`

【Ubuntu Server 16.04】默认情况

<!-- 截图：image-20211123223728583（在线版图片，未随附） -->

【Centos 7】默认情况

<!-- 截图：image-20211123223835612（在线版图片，未随附） -->

通过服务的配置文件，我们可以找到相关的文件，之后进行判断是否为异常

> 开机自启的服务可以在启动项处进行查

### 0x24 motd 检查

> 利用motd做后门在很久以前就已经存在了，我单独进行了探究，了解详细情况可以看下面这篇文章
> https://mp.weixin.qq.com/s/AvnCXkdGqo8uBBRYH61ihA

【ubuntu server 16.04 64位】 默认 motd 情况

motd 文件默认位置 `/etc/update-motd.d/`

<!-- 截图：image-20220428155615937（在线版图片，未随附） -->

下面我把文件中 `#` 注释的行隐去，剩下的写在下面

- `00-header`
  `#!/bin/sh
  
  [ -r /etc/lsb-release ] && . /etc/lsb-release
  
  if [ -z "$DISTRIB_DESCRIPTION" ] && [ -x /usr/bin/lsb_release ]; then
      # Fall back to using the very slow lsb_release utility
      DISTRIB_DESCRIPTION=$(lsb_release -s -d)
  fi
  
  printf "Welcome to %s (%s %s %s)\n" "$DISTRIB_DESCRIPTION" "$(uname -o)" "$(uname -r)" "$(uname -m)"`
- `10-help-text`
  `#!/bin/sh
  
  printf "\n"
  printf " * Documentation:  https://help.ubuntu.com\n"
  printf " * Management:     https://landscape.canonical.com\n"
  printf " * Support:        https://ubuntu.com/advantage\n"`
- `50-motd-news`
  `#!/bin/sh
  
  # Source the local configuration
  [ -r /etc/default/motd-news ] && . /etc/default/motd-news
  
  # Exit immediately, unless we're enabled
  # This makes this script very easy to disable in /etc/default/motd-news configuration
  [ "$ENABLED" = "1" ] || exit 0
  
  # Ensure sane defaults
  [ -n "$URLS" ] || URLS="https://motd.ubuntu.com"
  [ -n "$WAIT" ] || WAIT=5
  [ -n "$CACHE" ] || CACHE="/var/cache/motd-news"
  [ "$1" = "--force" ] && FORCED=1
  
  # Ensure we print safely, maximum of the first 10 lines,
  # maximum of the first 80 chars per line, no control chars
  safe_print() {
      cat "$1" | head -n 10 | tr -d '\000-\011\013\014\016-\037' | cut -c -80
  }
  
  
  # If we're not forcing an update, and we have a cached motd-news file,
  # then just print it and exit as quickly as possible, for login performance.
  # Note that systemd should keep this cache file up to date, asynchronously
  if [ "$FORCED" != "1" ]; then
      if [ -r $CACHE ]; then
          echo
          safe_print $CACHE
      else
          : > $CACHE
      fi
      exit 0
  fi
  
  # If we've made it here, we've been given the --force argument,
  # probably from the systemd motd-news.service.  Let's update...
  
  # Abort early if wget is missing
  [ -x /usr/bin/wget ] || exit 0
  
  # Generate our temp files, clean up when done
  NEWS=$(mktemp) || exit 1
  ERR=$(mktemp) || exit 1
  CLOUD=$(mktemp) || exit 1
  trap "rm -f $NEWS $ERR $CLOUD" HUP INT QUIT ILL TRAP KILL BUS TERM
  
  # Construct a user agent, similar to Firefox/Chrome/Safari/IE to
  # ensure a proper, tailored, accurate message of the day
  
  # wget browser version, for debug purposes
  wget_ver="$(dpkg -l wget | awk '$1 == "ii" { print($3); exit(0); }')"
  
  # Distribution version, for messages releated to this Ubuntu release
  . /etc/lsb-release
  lsb=$(echo "$DISTRIB_DESCRIPTION" | sed -e "s/ /\//g")
  codename="$DISTRIB_CODENAME"
  
  # Kernel version and CPU type, for messages related to a particular revision or hardware
  platform="$(uname -o)/$(uname -r)/$(uname -m)"
  arch="$(uname -m)"
  cpu="$(grep -m1 "^model name" /proc/cpuinfo | sed -e "s/.*: //" -e "s:\s\+:/:g")"
  cloud_id="unknown"
  if [ -x /usr/bin/cloud-id ]; then
      /usr/bin/cloud-id > "$CLOUD" 2>/dev/null
      if [ $? -eq 0 ]; then
          # sanitize it a bit, just in case
          cloud_id=$(cut -c -40 "${CLOUD}" | tr -c -d '[:alnum:]')
          if [ -z "${cloud_id}" ]; then
              cloud_id="unknown"
          fi
      fi
  fi
  
  # Piece together the user agent
  USER_AGENT="wget/$wget_ver $lsb $platform $cpu cloud_id/$cloud_id"
  
  # Loop over any configured URLs
  for u in $URLS; do
      # Ensure https:// protocol, for security reasons
      case $u in
          https://*)
              true
          ;;
          https://motd.ubuntu.com)
              u="$u/$codename/$arch"
          ;;
          *)
              continue
          ;;
      esac
      # If we're forced, set the wait to much higher (1 minute)
      [ "$FORCED" = "1" ] && WAIT=60
      # Fetch and print the news motd
      result=0
      not_found_is_ok=0
      wget --timeout "$WAIT" -U "$USER_AGENT" -O- --content-on-error "$u" >"$NEWS" 2>"$ERR" || result=$?
      # from wget's manpage: 8   Server issued an error response.
      if [ $result -eq 8 ]; then
          if grep -q "ERROR 404" "$ERR"; then
              # The server's 404 document is the generic, non cloud-specific, motd-news
              # content present in the index.txt file
              not_found_is_ok=1
          fi
      fi
      if [ $result -eq 0 ] || [ $not_found_is_ok -eq 1 ]; then
          echo
          # At most, 10 lines of text, remove control characters, print at most 80 characters per line
          safe_print "$NEWS"
          # Try to update the cache
          safe_print "$NEWS" 2>/dev/null >$CACHE || true
      else
          : > "$CACHE"
      fi
  done
  rm -f "$NEWS" "$ERR" "$CLOUD"
  exit 0`
- `90-updates-available`
  `#!/bin/sh
  
  stamp="/var/lib/update-notifier/updates-available"
  
  [ ! -r "$stamp" ] || cat "$stamp"`
- `91-release-upgrade`
  `#!/bin/sh
  
  # if the current release is under development there won't be a new one
  if [ "$(lsb_release -sd | cut -d' ' -f4)" = "(development" ]; then
      exit 0
  fi
  if [ -x /usr/lib/ubuntu-release-upgrader/release-upgrade-motd ]; then
      exec /usr/lib/ubuntu-release-upgrader/release-upgrade-motd
  fi`
- `92-unattended-upgrades`
  `#!/bin/sh
  
  if [ -x /usr/share/unattended-upgrades/update-motd-unattended-upgrades ]; then
      exec /usr/share/unattended-upgrades/update-motd-unattended-upgrades
  fi`
- `97-overlayroot`
  `#!/bin/sh
  
  (egrep "overlayroot|/media/root-ro|/media/root-rw" /proc/mounts 2>/dev/null | sort -r) || true
  echo`
- `98-fsck-at-reboot`
  `#!/bin/sh
  
  if [ -x /usr/lib/update-notifier/update-motd-fsck-at-reboot ]; then
      exec /usr/lib/update-notifier/update-motd-fsck-at-reboot
  fi`
- `98-reboot-required`
  `#!/bin/sh
  
  if [ -x /usr/lib/update-notifier/update-motd-reboot-required ]; then
      exec /usr/lib/update-notifier/update-motd-reboot-required
  fi`
- `99-esm`
  `#!/bin/sh
  
  SERIES=$(lsb_release -cs)
  DESCRIPTION=$(lsb_release -ds)
  
  [ "$SERIES" = "precise" ] || exit 0
  
  [ -x /usr/bin/ubuntu-advantage ] || exit 0
  
  if ubuntu-advantage is-esm-enabled; then
      cat <<EOF
  This ${DESCRIPTION} system is configured to receive extended security updates
  from Canonical:
   * https://www.ubuntu.com/esm
  EOF
  else
      cat <<EOF
  This ${DESCRIPTION} system is past its End of Life, and is no longer
  receiving security updates.  To protect the integrity of this system, it’s
  critical that you enable Extended Security Maintenance updates:
   * https://www.ubuntu.com/esm
  EOF
  fi
  echo`

【Centos7 64位】默认 motd 情况

Centos 7 默认没有 motd 文件，与 PAM 进行了一些组合和集成

### 0x25 进程启动文件检查

> 恶意程序执行后，可能会删除本地文件，但是该文件已经被进程加载，可以通过遍历这种情况来排查恶意程序

- `sudo lsof | grep deleted`
  lsof 不仅是进程启动文件，所以内容较多，建议先参考下面这条
- `sudo ls -al /proc/*/exe 2>/dev/null | grep deleted`

【Ubuntu Server 16.04】默认情况

<!-- 截图：image-20230106210558845（在线版图片，未随附） -->

【Centos Stream】默认情况

<!-- 截图：image-20230106211117875（在线版图片，未随附） -->

<!-- 截图：image-20230106211133712（在线版图片，未随附） -->

Centos Stream 默认的情况字符如下

```
dbus-brok  811                          dbus   12u      REG                0,1   2097152       1027 /memfd:dbus-broker-log (deleted)
dbus-brok  812                          dbus   45u      REG                0,1   2097152       1041 /memfd:dbus-broker-log (deleted)
firewalld  886                          root    9u      REG                0,1      4096          7 /memfd:libffi (deleted)
firewalld  886 1055 gmain               root    9u      REG                0,1      4096          7 /memfd:libffi (deleted)
packageki 1582                          root   15u      REG              253,0      3448   69238789 /tmp/librepo-tmp-PVfssn (deleted)
packageki 1582                          root   16u      REG              253,0      3496   69238788 /tmp/librepo-tmp-ZD9IkO (deleted)
packageki 1582                          root   21r      REG              253,0     14034   34067279 /var/cache/PackageKit/9/hawkey/extras-common.solv (deleted)
packageki 1582                          root   23r      REG              253,0   3378321   34067283 /var/cache/PackageKit/9/hawkey/baseos.solv (deleted)
packageki 1582                          root   25r      REG              253,0   4513640   34067284 /var/cache/PackageKit/9/hawkey/appstream.solv (deleted)
packageki 1582 1584 gmain               root   15u      REG              253,0      3448   69238789 /tmp/librepo-tmp-PVfssn (deleted)
packageki 1582 1584 gmain               root   16u      REG              253,0      3496   69238788 /tmp/librepo-tmp-ZD9IkO (deleted)
packageki 1582 1584 gmain               root   21r      REG              253,0     14034   34067279 /var/cache/PackageKit/9/hawkey/extras-common.solv (deleted)
packageki 1582 1584 gmain               root   23r      REG              253,0   3378321   34067283 /var/cache/PackageKit/9/hawkey/baseos.solv (deleted)
packageki 1582 1584 gmain               root   25r      REG              253,0   4513640   34067284 /var/cache/PackageKit/9/hawkey/appstream.solv (deleted)
packageki 1582 1586 gdbus               root   15u      REG              253,0      3448   69238789 /tmp/librepo-tmp-PVfssn (deleted)
packageki 1582 1586 gdbus               root   16u      REG              253,0      3496   69238788 /tmp/librepo-tmp-ZD9IkO (deleted)
packageki 1582 1586 gdbus               root   21r      REG              253,0     14034   34067279 /var/cache/PackageKit/9/hawkey/extras-common.solv (deleted)
packageki 1582 1586 gdbus               root   23r      REG              253,0   3378321   34067283 /var/cache/PackageKit/9/hawkey/baseos.solv (deleted)
packageki 1582 1586 gdbus               root   25r      REG              253,0   4513640   34067284 /var/cache/PackageKit/9/hawkey/appstream.solv (deleted)
dbus-brok 1979                          join   12u      REG                0,1   2097152       1130 /memfd:dbus-broker-log (deleted)
gnome-she 2051                          join   37u      REG                0,1     28672         71 /memfd:libffi (deleted)
gnome-she 2051                          join   43u      REG                0,1  67108864       1135 /memfd:pulseaudio (deleted)
gnome-she 2051                          join   45r      REG              253,2        64   50331819 /home/join/.local/share/gvfs-metadata/root (deleted)
gnome-she 2051                          join   46r      REG              253,2     32768   50331820 /home/join/.local/share/gvfs-metadata/root-5a11136d.log (deleted)
gnome-she 2051                          join   49u      REG                0,1     67864         78 /memfd:mutter-shared (deleted)
gnome-she 2051                          join   52r      REG              253,2        64   50331816 /home/join/.local/share/gvfs-metadata/home (deleted)
gnome-she 2051                          join   56r      REG              253,2     32768   50331818 /home/join/.local/share/gvfs-metadata/home-c72c093c.log (deleted)
gnome-she 2051 2056 gmain               join   37u      REG                0,1     28672         71 /memfd:libffi (deleted)
gnome-she 2051 2056 gmain               join   43u      REG                0,1  67108864       1135 /memfd:pulseaudio (deleted)
gnome-she 2051 2056 gmain               join   45r      REG              253,2        64   50331819 /home/join/.local/share/gvfs-metadata/root (deleted)
gnome-she 2051 2056 gmain               join   46r      REG              253,2     32768   50331820 /home/join/.local/share/gvfs-metadata/root-5a11136d.log (deleted)
gnome-she 2051 2056 gmain               join   49u      REG                0,1     67864         78 /memfd:mutter-shared (deleted)
gnome-she 2051 2056 gmain               join   52r      REG              253,2        64   50331816 /home/join/.local/share/gvfs-metadata/home (deleted)
gnome-she 2051 2056 gmain               join   56r      REG              253,2     32768   50331818 /home/join/.local/share/gvfs-metadata/home-c72c093c.log (deleted)
gnome-she 2051 2058 gdbus               join   37u      REG                0,1     28672         71 /memfd:libffi (deleted)
gnome-she 2051 2058 gdbus               join   43u      REG                0,1  67108864       1135 /memfd:pulseaudio (deleted)
gnome-she 2051 2058 gdbus               join   45r      REG              253,2        64   50331819 /home/join/.local/share/gvfs-metadata/root (deleted)
gnome-she 2051 2058 gdbus               join   46r      REG              253,2     32768   50331820 /home/join/.local/share/gvfs-metadata/root-5a11136d.log (deleted)
gnome-she 2051 2058 gdbus               join   49u      REG                0,1     67864         78 /memfd:mutter-shared (deleted)
gnome-she 2051 2058 gdbus               join   52r      REG              253,2        64   50331816 /home/join/.local/share/gvfs-metadata/home (deleted)
gnome-she 2051 2058 gdbus               join   56r      REG              253,2     32768   50331818 /home/join/.local/share/gvfs-metadata/home-c72c093c.log (deleted)
gnome-she 2051 2061 dconf\x20           join   37u      REG                0,1     28672         71 /memfd:libffi (deleted)
gnome-she 2051 2061 dconf\x20           join   43u      REG                0,1  67108864       1135 /memfd:pulseaudio (deleted)
gnome-she 2051 2061 dconf\x20           join   45r      REG              253,2        64   50331819 /home/join/.local/share/gvfs-metadata/root (deleted)
gnome-she 2051 2061 dconf\x20           join   46r      REG              253,2     32768   50331820 /home/join/.local/share/gvfs-metadata/root-5a11136d.log (deleted)
gnome-she 2051 2061 dconf\x20           join   49u      REG                0,1     67864         78 /memfd:mutter-shared (deleted)
gnome-she 2051 2061 dconf\x20           join   52r      REG              253,2        64   50331816 /home/join/.local/share/gvfs-metadata/home (deleted)
gnome-she 2051 2061 dconf\x20           join   56r      REG              253,2     32768   50331818 /home/join/.local/share/gvfs-metadata/home-c72c093c.log (deleted)
gnome-she 2051 2067 gnome-s:d           join   37u      REG                0,1     28672         71 /memfd:libffi (deleted)
gnome-she 2051 2067 gnome-s:d           join   43u      REG                0,1  67108864       1135 /memfd:pulseaudio (deleted)
gnome-she 2051 2067 gnome-s:d           join   45r      REG              253,2        64   50331819 /home/join/.local/share/gvfs-metadata/root (deleted)
gnome-she 2051 2067 gnome-s:d           join   46r      REG              253,2     32768   50331820 /home/join/.local/share/gvfs-metadata/root-5a11136d.log (deleted)
gnome-she 2051 2067 gnome-s:d           join   49u      REG                0,1     67864         78 /memfd:mutter-shared (deleted)
gnome-she 2051 2067 gnome-s:d           join   52r      REG              253,2        64   50331816 /home/join/.local/share/gvfs-metadata/home (deleted)
gnome-she 2051 2067 gnome-s:d           join   56r      REG              253,2     32768   50331818 /home/join/.local/share/gvfs-metadata/home-c72c093c.log (deleted)
gnome-she 2051 2068 gnome-she           join   37u      REG                0,1     28672         71 /memfd:libffi (deleted)
gnome-she 2051 2068 gnome-she           join   43u      REG                0,1  67108864       1135 /memfd:pulseaudio (deleted)
gnome-she 2051 2068 gnome-she           join   45r      REG              253,2        64   50331819 /home/join/.local/share/gvfs-metadata/root (deleted)
gnome-she 2051 2068 gnome-she           join   46r      REG              253,2     32768   50331820 /home/join/.local/share/gvfs-metadata/root-5a11136d.log (deleted)
gnome-she 2051 2068 gnome-she           join   49u      REG                0,1     67864         78 /memfd:mutter-shared (deleted)
gnome-she 2051 2068 gnome-she           join   52r      REG              253,2        64   50331816 /home/join/.local/share/gvfs-metadata/home (deleted)
gnome-she 2051 2068 gnome-she           join   56r      REG              253,2     32768   50331818 /home/join/.local/share/gvfs-metadata/home-c72c093c.log (deleted)
gnome-she 2051 2133 JS\x20Hel           join   37u      REG                0,1     28672         71 /memfd:libffi (deleted)
gnome-she 2051 2133 JS\x20Hel           join   43u      REG                0,1  67108864       1135 /memfd:pulseaudio (deleted)
gnome-she 2051 2133 JS\x20Hel           join   45r      REG              253,2        64   50331819 /home/join/.local/share/gvfs-metadata/root (deleted)
gnome-she 2051 2133 JS\x20Hel           join   46r      REG              253,2     32768   50331820 /home/join/.local/share/gvfs-metadata/root-5a11136d.log (deleted)
gnome-she 2051 2133 JS\x20Hel           join   49u      REG                0,1     67864         78 /memfd:mutter-shared (deleted)
gnome-she 2051 2133 JS\x20Hel           join   52r      REG              253,2        64   50331816 /home/join/.local/share/gvfs-metadata/home (deleted)
gnome-she 2051 2133 JS\x20Hel           join   56r      REG              253,2     32768   50331818 /home/join/.local/share/gvfs-metadata/home-c72c093c.log (deleted)
gnome-she 2051 2134 JS\x20Hel           join   37u      REG                0,1     28672         71 /memfd:libffi (deleted)
gnome-she 2051 2134 JS\x20Hel           join   43u      REG                0,1  67108864       1135 /memfd:pulseaudio (deleted)
gnome-she 2051 2134 JS\x20Hel           join   45r      REG              253,2        64   50331819 /home/join/.local/share/gvfs-metadata/root (deleted)
gnome-she 2051 2134 JS\x20Hel           join   46r      REG              253,2     32768   50331820 /home/join/.local/share/gvfs-metadata/root-5a11136d.log (deleted)
gnome-she 2051 2134 JS\x20Hel           join   49u      REG                0,1     67864         78 /memfd:mutter-shared (deleted)
gnome-she 2051 2134 JS\x20Hel           join   52r      REG              253,2        64   50331816 /home/join/.local/share/gvfs-metadata/home (deleted)
gnome-she 2051 2134 JS\x20Hel           join   56r      REG              253,2     32768   50331818 /home/join/.local/share/gvfs-metadata/home-c72c093c.log (deleted)
gnome-she 2051 2570 pool-gnom           join   37u      REG                0,1     28672         71 /memfd:libffi (deleted)
gnome-she 2051 2570 pool-gnom           join   43u      REG                0,1  67108864       1135 /memfd:pulseaudio (deleted)
gnome-she 2051 2570 pool-gnom           join   45r      REG              253,2        64   50331819 /home/join/.local/share/gvfs-metadata/root (deleted)
gnome-she 2051 2570 pool-gnom           join   46r      REG              253,2     32768   50331820 /home/join/.local/share/gvfs-metadata/root-5a11136d.log (deleted)
gnome-she 2051 2570 pool-gnom           join   49u      REG                0,1     67864         78 /memfd:mutter-shared (deleted)
gnome-she 2051 2570 pool-gnom           join   52r      REG              253,2        64   50331816 /home/join/.local/share/gvfs-metadata/home (deleted)
gnome-she 2051 2570 pool-gnom           join   56r      REG              253,2     32768   50331818 /home/join/.local/share/gvfs-metadata/home-c72c093c.log (deleted)
gnome-she 2051 2571 pool-gnom           join   37u      REG                0,1     28672         71 /memfd:libffi (deleted)
gnome-she 2051 2571 pool-gnom           join   43u      REG                0,1  67108864       1135 /memfd:pulseaudio (deleted)
gnome-she 2051 2571 pool-gnom           join   45r      REG              253,2        64   50331819 /home/join/.local/share/gvfs-metadata/root (deleted)
gnome-she 2051 2571 pool-gnom           join   46r      REG              253,2     32768   50331820 /home/join/.local/share/gvfs-metadata/root-5a11136d.log (deleted)
gnome-she 2051 2571 pool-gnom           join   49u      REG                0,1     67864         78 /memfd:mutter-shared (deleted)
gnome-she 2051 2571 pool-gnom           join   52r      REG              253,2        64   50331816 /home/join/.local/share/gvfs-metadata/home (deleted)
gnome-she 2051 2571 pool-gnom           join   56r      REG              253,2     32768   50331818 /home/join/.local/share/gvfs-metadata/home-c72c093c.log (deleted)
dbus-brok 2124                          join   12u      REG                0,1   2097152         70 /memfd:dbus-broker-log (deleted)
ibus-exte 2149                          join   10u      REG                0,1   1177344       1141 /memfd:wayland-cursor (deleted)
ibus-exte 2149 2165 gmain               join   10u      REG                0,1   1177344       1141 /memfd:wayland-cursor (deleted)
ibus-exte 2149 2167 dconf\x20           join   10u      REG                0,1   1177344       1141 /memfd:wayland-cursor (deleted)
ibus-exte 2149 2168 gdbus               join   10u      REG                0,1   1177344       1141 /memfd:wayland-cursor (deleted)
pipewire  2183                          join   24u      REG                0,1      2312       1136 /memfd:pipewire-memfd (deleted)
pipewire  2183                          join   27u      REG                0,1      2312       1137 /memfd:pipewire-memfd (deleted)
pipewire  2183                          join   31u      REG                0,1      2312       1138 /memfd:pipewire-memfd (deleted)
pipewire  2183                          join   39u      REG                0,1      2312         76 /memfd:pipewire-memfd (deleted)
pipewire  2183                          join   41u      REG                0,1      2312         77 /memfd:pipewire-memfd (deleted)
pipewire  2183 2206 pipewire            join   24u      REG                0,1      2312       1136 /memfd:pipewire-memfd (deleted)
pipewire  2183 2206 pipewire            join   27u      REG                0,1      2312       1137 /memfd:pipewire-memfd (deleted)
pipewire  2183 2206 pipewire            join   31u      REG                0,1      2312       1138 /memfd:pipewire-memfd (deleted)
pipewire  2183 2206 pipewire            join   39u      REG                0,1      2312         76 /memfd:pipewire-memfd (deleted)
pipewire  2183 2206 pipewire            join   41u      REG                0,1      2312         77 /memfd:pipewire-memfd (deleted)
gjs       2285                          join    7u      REG                0,1      4096       1139 /memfd:libffi (deleted)
gjs       2285 2291 gmain               join    7u      REG                0,1      4096       1139 /memfd:libffi (deleted)
gjs       2285 2295 gdbus               join    7u      REG                0,1      4096       1139 /memfd:libffi (deleted)
gjs       2285 2299 JS\x20Hel           join    7u      REG                0,1      4096       1139 /memfd:libffi (deleted)
gjs       2285 2300 JS\x20Hel           join    7u      REG                0,1      4096       1139 /memfd:libffi (deleted)
gsd-color 2297                          join   10u      REG                0,1   1177344       1142 /memfd:wayland-cursor (deleted)
gsd-color 2297 2342 gmain               join   10u      REG                0,1   1177344       1142 /memfd:wayland-cursor (deleted)
gsd-color 2297 2344 dconf\x20           join   10u      REG                0,1   1177344       1142 /memfd:wayland-cursor (deleted)
gsd-color 2297 2357 gdbus               join   10u      REG                0,1   1177344       1142 /memfd:wayland-cursor (deleted)
gsd-keybo 2310                          join   10u      REG                0,1   1177344       1143 /memfd:wayland-cursor (deleted)
gsd-keybo 2310 2348 gmain               join   10u      REG                0,1   1177344       1143 /memfd:wayland-cursor (deleted)
gsd-keybo 2310 2355 dconf\x20           join   10u      REG                0,1   1177344       1143 /memfd:wayland-cursor (deleted)
gsd-keybo 2310 2358 gdbus               join   10u      REG                0,1   1177344       1143 /memfd:wayland-cursor (deleted)
gsd-media 2317                          join   10u      REG                0,1   1177344       1144 /memfd:wayland-cursor (deleted)
gsd-media 2317                          join   15u      REG                0,1  67108864       1146 /memfd:pulseaudio (deleted)
gsd-media 2317 2381 gmain               join   10u      REG                0,1   1177344       1144 /memfd:wayland-cursor (deleted)
gsd-media 2317 2381 gmain               join   15u      REG                0,1  67108864       1146 /memfd:pulseaudio (deleted)
gsd-media 2317 2383 dconf\x20           join   10u      REG                0,1   1177344       1144 /memfd:wayland-cursor (deleted)
gsd-media 2317 2383 dconf\x20           join   15u      REG                0,1  67108864       1146 /memfd:pulseaudio (deleted)
gsd-media 2317 2384 gdbus               join   10u      REG                0,1   1177344       1144 /memfd:wayland-cursor (deleted)
gsd-media 2317 2384 gdbus               join   15u      REG                0,1  67108864       1146 /memfd:pulseaudio (deleted)
gsd-power 2319                          join   10u      REG                0,1   1177344         81 /memfd:wayland-cursor (deleted)
gsd-power 2319 2361 gmain               join   10u      REG                0,1   1177344         81 /memfd:wayland-cursor (deleted)
gsd-power 2319 2372 dconf\x20           join   10u      REG                0,1   1177344         81 /memfd:wayland-cursor (deleted)
gsd-power 2319 2376 gdbus               join   10u      REG                0,1   1177344         81 /memfd:wayland-cursor (deleted)
gsd-wacom 2374                          join   10u      REG                0,1   1177344         83 /memfd:wayland-cursor (deleted)
gsd-wacom 2374 2400 gmain               join   10u      REG                0,1   1177344         83 /memfd:wayland-cursor (deleted)
gsd-wacom 2374 2403 dconf\x20           join   10u      REG                0,1   1177344         83 /memfd:wayland-cursor (deleted)
gsd-wacom 2374 2407 gdbus               join   10u      REG                0,1   1177344         83 /memfd:wayland-cursor (deleted)
evolution 2396                          join   10u      REG                0,1   1177344         82 /memfd:wayland-cursor (deleted)
evolution 2396 2500 gmain               join   10u      REG                0,1   1177344         82 /memfd:wayland-cursor (deleted)
evolution 2396 2502 dconf\x20           join   10u      REG                0,1   1177344         82 /memfd:wayland-cursor (deleted)
evolution 2396 2503 gdbus               join   10u      REG                0,1   1177344         82 /memfd:wayland-cursor (deleted)
evolution 2396 2576 evolution           join   10u      REG                0,1   1177344         82 /memfd:wayland-cursor (deleted)
evolution 2396 2596 evolution           join   10u      REG                0,1   1177344         82 /memfd:wayland-cursor (deleted)
gjs       2406                          join    7u      REG                0,1      4096       1140 /memfd:libffi (deleted)
gjs       2406 2419 gmain               join    7u      REG                0,1      4096       1140 /memfd:libffi (deleted)
gjs       2406 2422 gdbus               join    7u      REG                0,1      4096       1140 /memfd:libffi (deleted)
gjs       2406 2424 JS\x20Hel           join    7u      REG                0,1      4096       1140 /memfd:libffi (deleted)
gjs       2406 2426 JS\x20Hel           join    7u      REG                0,1      4096       1140 /memfd:libffi (deleted)
gnome-sof 2431                          join   11u      REG                0,1   1177344         84 /memfd:wayland-cursor (deleted)
gnome-sof 2431                          join   27u      REG              253,2     36864   16777371 /home/join/.cache/appstream/appcache-GTG7X1.mdb (deleted)
gnome-sof 2431                          join   28w      REG              253,2     36864   16777371 /home/join/.cache/appstream/appcache-GTG7X1.mdb (deleted)
gnome-sof 2431 2490 gmain               join   11u      REG                0,1   1177344         84 /memfd:wayland-cursor (deleted)
gnome-sof 2431 2490 gmain               join   27u      REG              253,2     36864   16777371 /home/join/.cache/appstream/appcache-GTG7X1.mdb (deleted)
gnome-sof 2431 2490 gmain               join   28w      REG              253,2     36864   16777371 /home/join/.cache/appstream/appcache-GTG7X1.mdb (deleted)
gnome-sof 2431 2492 gdbus               join   11u      REG                0,1   1177344         84 /memfd:wayland-cursor (deleted)
gnome-sof 2431 2492 gdbus               join   27u      REG              253,2     36864   16777371 /home/join/.cache/appstream/appcache-GTG7X1.mdb (deleted)
gnome-sof 2431 2492 gdbus               join   28w      REG              253,2     36864   16777371 /home/join/.cache/appstream/appcache-GTG7X1.mdb (deleted)
gnome-sof 2431 2496 dconf\x20           join   11u      REG                0,1   1177344         84 /memfd:wayland-cursor (deleted)
gnome-sof 2431 2496 dconf\x20           join   27u      REG              253,2     36864   16777371 /home/join/.cache/appstream/appcache-GTG7X1.mdb (deleted)
gnome-sof 2431 2496 dconf\x20           join   28w      REG              253,2     36864   16777371 /home/join/.cache/appstream/appcache-GTG7X1.mdb (deleted)
gnome-ter 2773                          join   10u      REG                0,1   1177344       1174 /memfd:wayland-cursor (deleted)
gnome-ter 2773 2774 gmain               join   10u      REG                0,1   1177344       1174 /memfd:wayland-cursor (deleted)
gnome-ter 2773 2776 gdbus               join   10u      REG                0,1   1177344       1174 /memfd:wayland-cursor (deleted)
gnome-ter 2773 2777 dconf\x20           join   10u      REG                0,1   1177344       1174 /memfd:wayland-cursor (deleted)
```

### 0x26 软件及其配置文件完整性检查

> 参考 小技巧 -> 系统完整性检查 章节

### 0x27 sudo 配置检查

需要注意文件权限和文件内容

- /etc/sudo.conf
- /etc/sudoers
- /etc/sudoers.d/

【Ubuntu Server 22.04】 默认情况

`/etc/sudo.conf`

<!-- 截图：image-20230426100326138（在线版图片，未随附） -->

`/etc/sudoers`

<!-- 截图：image-20230426100506866（在线版图片，未随附） -->

`/etc/sudoers.d/`

<!-- 截图：image-20230426100655218（在线版图片，未随附） -->

【Rocky Linux 9.1】 默认情况

`/etc/sudo.conf`

<!-- 截图：image-20230426100957395（在线版图片，未随附） -->

`/etc/sudoers`

<!-- 截图：image-20230426095258261（在线版图片，未随附） -->

`/etc/sudoers.d/`

<!-- 截图：image-20230426095456335（在线版图片，未随附） -->

### 0x28 第三方软件源 GPG 密钥检查

```
Ubuntu Linux
sudo apt-key list
具体存储目录为 /etc/apt/trusted.gpg.d/

Centos/Rocky Linux
gpg --quiet --show-keys /etc/pki/rpm-gpg/*
具体存储目录为 /etc/pki/rpm-gpg/
```

【Ubuntu Server 22.04】 默认情况

<!-- 截图：image-20230426201304840（在线版图片，未随附） -->

```
8439 38DF 228D 22F7 B374  2BC0 D94A A3F0 EFE2 1092
F6EC B376 2474 EDA9 D21B  7022 8719 20D1 991B C93C
```

【Rocky Linux 9.1】 默认情况

<!-- 截图：image-20230426203435112（在线版图片，未随附） -->

```
B08B659EE86AF623BC90E8DB938A80CAF21541EB
567E347AD0044ADE55BA8A5F199E2F91FD431D51
21CB256AE16FC54C6E652949702D426D350D275D
0675BD19F4FFE3AD0B2D6FEBADA2860895AE3D91
```

Centos 可能会有不同，需要拿具体服务器做对比

### 0x29 计划任务日志

计划任务是攻击者常用的权限维持手段，因此这里将其日志单独拿出来作为一个检查项，关于默认的计划任务，详情查看计划任务章节

```
journalctl -u crond
```

<!-- 截图：image-20230811012036889（在线版图片，未随附） -->

### 0x30 内核模块签名配置检查

查看系统是否配置了加载进入到内核的模块都需要有效签名

```
zgrep CONFIG_MODULE_SIG /boot/config-$(uname -r) | grep -v "^#"
```

<!-- 截图：image-20240718002729902（在线版图片，未随附） -->

- `CONFIG_MODULE_SIG_FORMAT`：是否启用模块签名格式选项
- `CONFIG_MODULE_SIG`: 如果设为 `y`，则启用模块签名功能，默认情况下，在加载没有签名或签名不正确的内核模块时，仅打印一条提示信息，然后继续加载该模块
- `CONFIG_MODULE_SIG_ALL`：是否强制所有模块都必须签名，内核在编译时会尝试对所有内核模块进行签名
- `CONFIG_MODULE_SIG_FORCE`: 如果设为 `y`，则强制所有模块必须有有效的签名才能加载。
- `CONFIG_MODULE_SIG_KEY`: 指定用于签名的私钥文件。
- `CONFIG_MODULE_SIG_HASH`: 指定用于签名的哈希算法（如 `sha256`）。

【 Ubuntu Server 22.04 】 默认情况

<!-- 截图：image-20240718003811615（在线版图片，未随附） -->

```
CONFIG_MODULE_SIG_FORMAT=y
CONFIG_MODULE_SIG=y
CONFIG_MODULE_SIG_ALL=y
CONFIG_MODULE_SIG_SHA512=y
CONFIG_MODULE_SIG_HASH="sha512"
CONFIG_MODULE_SIG_KEY="certs/signing_key.pem"
CONFIG_MODULE_SIG_KEY_TYPE_RSA=y
```

【 Rocky Linux 9.1 】

<!-- 截图：image-20240718004129497（在线版图片，未随附） -->

```
CONFIG_MODULE_SIG_FORMAT=y
CONFIG_MODULE_SIG=y
CONFIG_MODULE_SIG_ALL=y
CONFIG_MODULE_SIG_SHA512=y
CONFIG_MODULE_SIG_HASH="sha512"
CONFIG_MODULE_SIG_KEY="certs/signing_key.pem"
```

### 0x31 签名不合法的内核模块

查看内核加载的模块

```
lsmod
```

<!-- 截图：image-20240719214624820（在线版图片，未随附） -->

查看内核模块的信息

```
modinfo <module_name>
```

<!-- 截图：image-20240719214822525（在线版图片，未随附） -->

可以看到内核模块的一些信息，包括文件位置、是否签名、签名信息等

是否加载了非有效签名的模块

> 这部分内容本来是想将所有加载的内核模块的签名都校验一遍，但是查询了大量资料后，并没有找到如何从系统中找到内核模块签名校验对应的公钥文件，所以只能通过日志等方式进行辅助校验

```
sudo dmesg | grep -i "taint"
```

在部分配置情况下，未进行有效签名的内核模块也会被加载，但是会在日志中留下类似下面的记录

```
module verification failed: signature and/or required key missing - tainting kernel
```

也可以通过相关日志文件进行查看

- `/var/log/kern.log`
- `/var/log/syslog`

可以通过下面的脚本方便地进行检索

```
#!/bin/bash

# 搜索内核环缓冲区
echo "Checking dmesg for module loading issues..."
sudo dmesg | grep -i "taint"

# 搜索系统日志文件
echo "Checking /var/log/syslog for module loading issues..."
sudo grep -i "taint" /var/log/syslog

echo "Checking /var/log/kern.log for module loading issues..."
sudo grep -i -E "taint" /var/log/kern.log
```

<!-- 截图：image-20240719220321525（在线版图片，未随附） -->

### 0x32 PAM 检查

#### 针对直接修改 PAM 库的后门检查

```
debsums libpam0g -a -c
```

<!-- 截图：image-20240730150157805（在线版图片，未随附） -->

#### 针对修改 PAM 模块的后门检查

直接对 `libpam0g` 检查不能发现 PAM 模块的篡改攻击，需要对整个系统进行完整性检查

```
debsums -a -c 2>/dev/null
```

<!-- 截图：image-20240730153440145（在线版图片，未随附） -->

#### 针对修改 PAM 配置文件的后门检查

与修改 PAM 模块的后门检查方法一样

```
debsums -a -c 2>/dev/null
```

<!-- 截图：image-20240730153841997（在线版图片，未随附） -->

对于被修改的配置文件，需要详细检查其验证逻辑，同时与运维、开发人员确认是否为正常配置

此方法对于模块依赖的独立配置文件被修改情况同样有效

具体可参照我们公众号的文章

> https://mp.weixin.qq.com/s/W4RX5WRzUp-hK1_Pr3rp7w

#### 针对新增模块与配置文件的排查

直接和默认存在的配置文件进行对比即可

【 Ubuntu Server 22.04 】

模块 `/usr/lib/x86_64-linux-gnu/security/`

<!-- 截图：image-20240730160017889（在线版图片，未随附） -->

```
-rw-r--r--  1 root root  18424 Feb  2  2023 pam_access.so
-rw-r--r--  1 root root  14328 Jun  7  2023 pam_cap.so
-rw-r--r--  1 root root  14408 Feb  2  2023 pam_debug.so
-rw-r--r--  1 root root  13960 Feb  2  2023 pam_deny.so
-rw-r--r--  1 root root  14328 Feb  2  2023 pam_echo.so
-rw-r--r--  1 root root  18424 Feb  2  2023 pam_env.so
-rw-r--r--  1 root root  22600 Feb  2  2023 pam_exec.so
-rw-r--r--  1 root root  63568 Feb  2  2023 pam_extrausers.so
-rw-r--r--  1 root root  14328 Feb  2  2023 pam_faildelay.so
-rw-r--r--  1 root root  22520 Feb  2  2023 pam_faillock.so
-rw-r--r--  1 root root  18424 Feb  2  2023 pam_filter.so
-rw-r--r--  1 root root  14328 Feb  2  2023 pam_ftp.so
-rw-r--r--  1 root root  18504 Feb  2  2023 pam_group.so
-rw-r--r--  1 root root  14328 Feb  2  2023 pam_issue.so
-rw-r--r--  1 root root  14328 Feb  2  2023 pam_keyinit.so
-rw-r--r--  1 root root  18448 Feb  2  2023 pam_lastlog.so
-rw-r--r--  1 root root  26696 Feb  2  2023 pam_limits.so
-rw-r--r--  1 root root  14328 Feb  2  2023 pam_listfile.so
-rw-r--r--  1 root root  14328 Feb  2  2023 pam_localuser.so
-rw-r--r--  1 root root  14328 Feb  2  2023 pam_loginuid.so
-rw-r--r--  1 root root  18424 Feb  2  2023 pam_mail.so
-rw-r--r--  1 root root  14328 Feb  2  2023 pam_mkhomedir.so
-rw-r--r--  1 root root  18424 Feb  2  2023 pam_motd.so
-rw-r--r--  1 root root  43112 Feb  2  2023 pam_namespace.so
-rw-r--r--  1 root root  14328 Feb  2  2023 pam_nologin.so
-rw-r--r--  1 root root  14328 Feb  2  2023 pam_permit.so
-rw-r--r--  1 root root  18424 Feb  2  2023 pam_pwhistory.so
-rw-r--r--  1 root root  14328 Feb  2  2023 pam_rhosts.so
-rw-r--r--  1 root root  14328 Feb  2  2023 pam_rootok.so
-rw-r--r--  1 root root  14328 Feb  2  2023 pam_securetty.so
-rw-r--r--  1 root root  26616 Feb  2  2023 pam_selinux.so
-rw-r--r--  1 root root  18424 Feb  2  2023 pam_sepermit.so
-rw-r--r--  1 root root  18424 Feb  2  2023 pam_setquota.so
-rw-r--r--  1 root root  14328 Feb  2  2023 pam_shells.so
-rw-r--r--  1 root root  18424 Feb  2  2023 pam_stress.so
-rw-r--r--  1 root root  18424 Feb  2  2023 pam_succeed_if.so
-rw-r--r--  1 root root 472008 Mar 20  2023 pam_systemd.so
-rw-r--r--  1 root root  18504 Feb  2  2023 pam_time.so
-rw-r--r--  1 root root  22608 Feb  2  2023 pam_timestamp.so
-rw-r--r--  1 root root  14328 Feb  2  2023 pam_tty_audit.so
-rw-r--r--  1 root root  14328 Feb  2  2023 pam_umask.so
-rw-r--r--  1 root root  59464 Feb  2  2023 pam_unix.so
-rw-r--r--  1 root root  18424 Feb  2  2023 pam_userdb.so
-rw-r--r--  1 root root  14328 Feb  2  2023 pam_usertype.so
-rw-r--r--  1 root root  14328 Feb  2  2023 pam_warn.so
-rw-r--r--  1 root root  14328 Feb  2  2023 pam_wheel.so
-rw-r--r--  1 root root  26616 Feb  2  2023 pam_xauth.so
```

PAM 配置文件 `/etc/pam.d/`

<!-- 截图：image-20240730160227247（在线版图片，未随附） -->

```
-rw-r--r--  1 root root  384 Nov 11  2021 chfn
-rw-r--r--  1 root root   92 Nov 11  2021 chpasswd
-rw-r--r--  1 root root  581 Nov 11  2021 chsh
-rw-r--r--  1 root root 1208 Aug 10  2023 common-account
-rw-r--r--  1 root root 1242 Aug 10  2023 common-auth
-rw-r--r--  1 root root 1620 Aug 10  2023 common-password
-rw-r--r--  1 root root 1427 Aug 10  2023 common-session
-rw-r--r--  1 root root 1435 Aug 10  2023 common-session-noninteractive
-rw-r--r--  1 root root  606 Mar 17  2021 cron
-rw-r--r--  1 root root 4126 Mar 14  2022 login
-rw-r--r--  1 root root   92 Nov 11  2021 newusers
-rw-r--r--  1 root root  520 Aug 12  2020 other
-rw-r--r--  1 root root   92 Nov 11  2021 passwd
-rw-r--r--  1 root root  270 Feb 26  2022 polkit-1
-rw-r--r--  1 root root  143 Feb 20  2022 runuser
-rw-r--r--  1 root root  138 Feb 20  2022 runuser-l
-rw-r--r--  1 root root 2133 Jul 19  2023 sshd
-rw-r--r--  1 root root 2259 Feb 20  2022 su
-rw-r--r--  1 root root  330 Aug  3  2022 sudo
-rw-r--r--  1 root root  315 Aug  3  2022 sudo-i
-rw-r--r--  1 root root  137 Feb 20  2022 su-l
```

【 Rocky Linux  9 】

模块 `/usr/lib64/security/`

<!-- 截图：image-20240730161740184（在线版图片，未随附） -->

<!-- 截图：image-20240730161830557（在线版图片，未随附） -->

```
-rwxr-xr-x.  1 root root  19448 Apr 13  2023 pam_access.so
-rwxr-xr-x.  1 root root  15776 May 26  2022 pam_cap.so
-rwxr-xr-x.  1 root root  15176 Apr 13  2023 pam_chroot.so
-rwxr-xr-x.  1 root root  31984 Apr 13  2023 pam_console.so
-rwxr-xr-x.  1 root root  15240 Apr 13  2023 pam_debug.so
-rwxr-xr-x.  1 root root  14928 Apr 13  2023 pam_deny.so
-rwxr-xr-x.  1 root root  15264 Apr 13  2023 pam_echo.so
-rwxr-xr-x.  1 root root  19464 Apr 13  2023 pam_env.so
-rwxr-xr-x.  1 root root  23424 Apr 13  2023 pam_exec.so
-rwxr-xr-x.  1 root root  15184 Apr 13  2023 pam_faildelay.so
-rwxr-xr-x.  1 root root  23520 Apr 13  2023 pam_faillock.so
drwxr-xr-x.  2 root root     24 Aug 11  2023 pam_filter
-rwxr-xr-x.  1 root root  19360 Apr 13  2023 pam_filter.so
-rwxr-xr-x.  1 root root  15184 Apr 13  2023 pam_ftp.so
-rwxr-xr-x.  1 root root  19344 Apr 13  2023 pam_group.so
-rwxr-xr-x.  1 root root  15224 Apr 13  2023 pam_issue.so
-rwxr-xr-x.  1 root root  15352 Apr 13  2023 pam_keyinit.so
-rwxr-xr-x.  1 root root  19512 Apr 13  2023 pam_lastlog.so
-rwxr-xr-x.  1 root root  27536 Apr 13  2023 pam_limits.so
-rwxr-xr-x.  1 root root  15232 Apr 13  2023 pam_listfile.so
-rwxr-xr-x.  1 root root  15224 Apr 13  2023 pam_localuser.so
-rwxr-xr-x.  1 root root  15240 Apr 13  2023 pam_loginuid.so
-rwxr-xr-x.  1 root root  19312 Apr 13  2023 pam_mail.so
-rwxr-xr-x.  1 root root  15184 Apr 13  2023 pam_mkhomedir.so
-rwxr-xr-x.  1 root root  15264 Apr 13  2023 pam_motd.so
-rwxr-xr-x.  1 root root  44152 Apr 13  2023 pam_namespace.so
-rwxr-xr-x.  1 root root  15232 Apr 13  2023 pam_nologin.so
-rwxr-xr-x.  1 root root  15208 Apr 13  2023 pam_permit.so
-rwxr-xr-x.  1 root root  15176 Apr 13  2023 pam_postgresok.so
-rwxr-xr-x.  1 root root  27512 Apr 13  2023 pam_pwhistory.so
-rwxr-xr-x.  1 root root  15848 May 26  2022 pam_pwquality.so
-rwxr-xr-x.  1 root root  15184 Apr 13  2023 pam_rhosts.so
-rwxr-xr-x.  1 root root  15248 Apr 13  2023 pam_rootok.so
-rwxr-xr-x.  1 root root  15240 Apr 13  2023 pam_securetty.so
-rwxr-xr-x.  1 root root  27616 Apr 13  2023 pam_selinux.so
lrwxrwxrwx.  1 root root     15 Apr 13  2023 pam_selinux_permit.so -> pam_sepermit.so
-rwxr-xr-x.  1 root root  19368 Apr 13  2023 pam_sepermit.so
-rwxr-xr-x.  1 root root  19312 Apr 13  2023 pam_setquota.so
-rwxr-xr-x.  1 root root  15216 Apr 13  2023 pam_shells.so
-rwxr-xr-x.  1 root root  65200 Apr 19  2023 pam_sss.so
-rwxr-xr-x.  1 root root  36264 Apr 19  2023 pam_sss_gss.so
-rwxr-xr-x.  1 root root  19416 Apr 13  2023 pam_stress.so
-rwxr-xr-x.  1 root root  19400 Apr 13  2023 pam_succeed_if.so
-rwxr-xr-x.  1 root root 514288 May  9  2023 pam_systemd.so
-rwxr-xr-x.  1 root root  19344 Apr 13  2023 pam_time.so
-rwxr-xr-x.  1 root root  27584 Apr 13  2023 pam_timestamp.so
-rwxr-xr-x.  1 root root  15232 Apr 13  2023 pam_tty_audit.so
-rwxr-xr-x.  1 root root  15184 Apr 13  2023 pam_umask.so
-rwxr-xr-x.  1 root root  56712 Apr 13  2023 pam_unix.so
lrwxrwxrwx.  1 root root     11 Apr 13  2023 pam_unix_acct.so -> pam_unix.so
lrwxrwxrwx.  1 root root     11 Apr 13  2023 pam_unix_auth.so -> pam_unix.so
lrwxrwxrwx.  1 root root     11 Apr 13  2023 pam_unix_passwd.so -> pam_unix.so
lrwxrwxrwx.  1 root root     11 Apr 13  2023 pam_unix_session.so -> pam_unix.so
-rwxr-xr-x.  1 root root  19360 Apr 13  2023 pam_userdb.so
-rwxr-xr-x.  1 root root  15264 Apr 13  2023 pam_usertype.so
-rwxr-xr-x.  1 root root  15232 Apr 13  2023 pam_warn.so
-rwxr-xr-x.  1 root root  15232 Apr 13  2023 pam_wheel.so
-rwxr-xr-x.  1 root root  27520 Apr 13  2023 pam_xauth.so
```

配置文件 `/etc/pam.d/`

<!-- 截图：image-20240730162002060（在线版图片，未随附） -->

```
-rw-r--r--.  1 root root  232 Apr 13  2023 config-util
-rw-r--r--.  1 root root  322 Feb 15  2019 crond
-rw-r--r--.  1 root root  701 Apr 13  2023 fingerprint-auth
-rw-r--r--.  1 root root  676 May 10  2023 login
-rw-r--r--.  1 root root  154 Apr 13  2023 other
-rw-r--r--.  1 root root  168 May 15  2022 passwd
-rw-r--r--.  1 root root  760 Apr 13  2023 password-auth
-rw-r--r--.  1 root root  398 Apr 13  2023 postlogin
-rw-r--r--.  1 root root  640 May 10  2023 remote
-rw-r--r--.  1 root root  143 May 10  2023 runuser
-rw-r--r--.  1 root root  138 May 10  2023 runuser-l
-rw-r--r--.  1 root root  743 Apr 13  2023 smartcard-auth
-rw-r--r--.  1 root root  727 May 10  2023 sshd
-rw-r--r--.  1 root root  214 Dec  9  2022 sssd-shadowutils
-rw-r--r--.  1 root root  566 May 10  2023 su
-rw-r--r--.  1 root root  137 May 10  2023 su-l
-rw-r--r--.  1 root root  154 Apr 24  2023 sudo
-rw-r--r--.  1 root root  178 Apr 24  2023 sudo-i
-rw-r--r--.  1 root root  760 Apr 13  2023 system-auth
-rw-r--r--.  1 root root  295 May  9  2023 systemd-user
-rw-r--r--.  1 root root   84 May 16  2022 vlock
```

### 0x33 proc与ps进程对比

如果存在 /proc 目录中有进程文件夹，但是在 `ps -aux` 命令里没有显示的，就认为可能是异常进程

检测脚本

```
import subprocess
import os

def get_ps_aux():
    # 获取 `ps -aux` 的输出
    result = subprocess.run(['ps', '-aux'], stdout=subprocess.PIPE, text=True)
    ps_output = result.stdout.strip().split('\n')
    ps_pids = set()

    # 提取每行的PID
    for line in ps_output[1:]:  # 跳过标题行
        parts = line.split()
        if len(parts) > 1:
            ps_pids.add(parts[1])

    return ps_pids

def get_proc_pids():
    # 读取 /proc 目录中的进程ID
    proc_pids = set()
    for entry in os.listdir('/proc'):
        if entry.isdigit():
            proc_pids.add(entry)

    return proc_pids

def compare_ps_proc():
    ps_pids = get_ps_aux()
    proc_pids = get_proc_pids()

    # 找出 /proc 中有但 ps -aux 中没有的进程
    proc_not_in_ps = proc_pids - ps_pids

    return proc_not_in_ps

if __name__ == "__main__":
    proc_not_in_ps = compare_ps_proc()

    if proc_not_in_ps:
        print("在 /proc 中存在但 ps -aux 中不存在的进程:", proc_not_in_ps)
    else:
        print("未发现异常进程")
```

<!-- 截图：image-20240730194426876（在线版图片，未随附） -->

### 0x34 Trap 检查

trap 后门主要集中在与登录配置文件结合，登录配置文件检查在上面已经包含了，所以只需要检查当前 shell 环境的 trap 情况

```
trap -p 
```

<!-- 截图：image-20240731160055304（在线版图片，未随附） -->

### 0x35 家目录模板检查

系统在新建用户需要创建家目录时，会从模板处复制一份给新用户，如果攻击者在此处投毒，新创建用户可能都会受影响

新建用户的家目录模板为 `/etc/skel/`

【 Ubuntu Server 22.04 】默认情况

<!-- 截图：image-20240731190908157（在线版图片，未随附） -->

<!-- 截图：image-20240731190944941（在线版图片，未随附） -->

`/etc/skel/.bash_logout`

```
# ~/.bash_logout: executed by bash(1) when login shell exits.

# when leaving the console clear the screen to increase privacy

if [ "$SHLVL" = 1 ]; then
    [ -x /usr/bin/clear_console ] && /usr/bin/clear_console -q
fi
```

`/etc/skel/.profile`

```
# ~/.profile: executed by the command interpreter for login shells.
# This file is not read by bash(1), if ~/.bash_profile or ~/.bash_login
# exists.
# see /usr/share/doc/bash/examples/startup-files for examples.
# the files are located in the bash-doc package.

# the default umask is set in /etc/profile; for setting the umask
# for ssh logins, install and configure the libpam-umask package.
#umask 022

# if running bash
if [ -n "$BASH_VERSION" ]; then
    # include .bashrc if it exists
    if [ -f "$HOME/.bashrc" ]; then
    . "$HOME/.bashrc"
    fi
fi

# set PATH so it includes user's private bin if it exists
if [ -d "$HOME/bin" ] ; then
    PATH="$HOME/bin:$PATH"
fi

# set PATH so it includes user's private bin if it exists
if [ -d "$HOME/.local/bin" ] ; then
    PATH="$HOME/.local/bin:$PATH"
fi
```

`/etc/skel/.bashrc`

```
# ~/.bashrc: executed by bash(1) for non-login shells.
# see /usr/share/doc/bash/examples/startup-files (in the package bash-doc)
# for examples

# If not running interactively, don't do anything
case $- in
    *i*) ;;
      *) return;;
esac

# don't put duplicate lines or lines starting with space in the history.
# See bash(1) for more options
HISTCONTROL=ignoreboth

# append to the history file, don't overwrite it
shopt -s histappend

# for setting history length see HISTSIZE and HISTFILESIZE in bash(1)
HISTSIZE=1000
HISTFILESIZE=2000

# check the window size after each command and, if necessary,
# update the values of LINES and COLUMNS.
shopt -s checkwinsize

# If set, the pattern "**" used in a pathname expansion context will
# match all files and zero or more directories and subdirectories.
#shopt -s globstar

# make less more friendly for non-text input files, see lesspipe(1)
[ -x /usr/bin/lesspipe ] && eval "$(SHELL=/bin/sh lesspipe)"

# set variable identifying the chroot you work in (used in the prompt below)
if [ -z "${debian_chroot:-}" ] && [ -r /etc/debian_chroot ]; then
    debian_chroot=$(cat /etc/debian_chroot)
fi

# set a fancy prompt (non-color, unless we know we "want" color)
case "$TERM" in
    xterm-color|*-256color) color_prompt=yes;;
esac

# uncomment for a colored prompt, if the terminal has the capability; turned
# off by default to not distract the user: the focus in a terminal window
# should be on the output of commands, not on the prompt
#force_color_prompt=yes

if [ -n "$force_color_prompt" ]; then
    if [ -x /usr/bin/tput ] && tput setaf 1 >&/dev/null; then
    # We have color support; assume it's compliant with Ecma-48
    # (ISO/IEC-6429). (Lack of such support is extremely rare, and such
    # a case would tend to support setf rather than setaf.)
    color_prompt=yes
    else
    color_prompt=
    fi
fi

if [ "$color_prompt" = yes ]; then
    PS1='${debian_chroot:+($debian_chroot)}\[\033[01;32m\]\u@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ '
else
    PS1='${debian_chroot:+($debian_chroot)}\u@\h:\w\$ '
fi
unset color_prompt force_color_prompt

# If this is an xterm set the title to user@host:dir
case "$TERM" in
xterm*|rxvt*)
    PS1="\[\e]0;${debian_chroot:+($debian_chroot)}\u@\h: \w\a\]$PS1"
    ;;
*)
    ;;
esac

# enable color support of ls and also add handy aliases
if [ -x /usr/bin/dircolors ]; then
    test -r ~/.dircolors && eval "$(dircolors -b ~/.dircolors)" || eval "$(dircolors -b)"
    alias ls='ls --color=auto'
    #alias dir='dir --color=auto'
    #alias vdir='vdir --color=auto'

    alias grep='grep --color=auto'
    alias fgrep='fgrep --color=auto'
    alias egrep='egrep --color=auto'
fi

# colored GCC warnings and errors
#export GCC_COLORS='error=01;31:warning=01;35:note=01;36:caret=01;32:locus=01:quote=01'

# some more ls aliases
alias ll='ls -alF'
alias la='ls -A'
alias l='ls -CF'

# Add an "alert" alias for long running commands.  Use like so:
#   sleep 10; alert
alias alert='notify-send --urgency=low -i "$([ $? = 0 ] && echo terminal || echo error)" "$(history|tail -n1|sed -e '\''s/^\s*[0-9]\+\s*//;s/[;&|]\s*alert$//'\'')"'

# Alias definitions.
# You may want to put all your additions into a separate file like
# ~/.bash_aliases, instead of adding them here directly.
# See /usr/share/doc/bash-doc/examples in the bash-doc package.

if [ -f ~/.bash_aliases ]; then
    . ~/.bash_aliases
fi

# enable programmable completion features (you don't need to enable
# this, if it's already enabled in /etc/bash.bashrc and /etc/profile
# sources /etc/bash.bashrc).
if ! shopt -oq posix; then
  if [ -f /usr/share/bash-completion/bash_completion ]; then
    . /usr/share/bash-completion/bash_completion
  elif [ -f /etc/bash_completion ]; then
    . /etc/bash_completion
  fi
fi
```

【 Rocky Linux 9 】默认情况

<!-- 截图：image-20240731191448775（在线版图片，未随附） -->

`/etc/skel/.bash_logout`

```
# ~/.bash_logout
```

`/etc/skel/.bash_profile`

```
# .bash_profile

# Get the aliases and functions
if [ -f ~/.bashrc ]; then
    . ~/.bashrc
fi

# User specific environment and startup programs
```

`/etc/skel/.bashrc`

```
# .bashrc

# Source global definitions
if [ -f /etc/bashrc ]; then
    . /etc/bashrc
fi

# User specific environment
if ! [[ "$PATH" =~ "$HOME/.local/bin:$HOME/bin:" ]]
then
    PATH="$HOME/.local/bin:$HOME/bin:$PATH"
fi
export PATH

# Uncomment the following line if you don't like systemctl's auto-paging feature:
# export SYSTEMD_PAGER=

# User specific aliases and functions
if [ -d ~/.bashrc.d ]; then
    for rc in ~/.bashrc.d/*; do
        if [ -f "$rc" ]; then
            . "$rc"
        fi
    done
fi

unset rc
```

### 0x36 TCP Wrappers 排查

TCP Wrappers 是一种用于控制对网络服务访问的安全工具。它可以限制和记录通过 `inetd` 超级服务器启动的服务的访问。主要功能包括：

1. 访问控制：根据主机名、IP 地址或域名限制对服务的访问。
1. 日志记录：记录所有访问尝试，包括成功和失败的连接。

该工具有两个配置文件，分别控制允许和拒绝，文件地址如下:

- /etc/hosts.allow
- /etc/hosts.deny

文件内容语法如下：

```
<服务>: <客户端列表> [: <选项>]
```

第一列为服务名称，第二列为客户端列表，关键在于第三列，第三列中包含两个动作可以执行系统命令

- `spawn`：在匹配时执行命令。
- `twist`：替代服务执行某个命令。

例如

```
sshd: 192.168.1.1 : spawn (/bin/echo "Access from %h" >> /var/log/connections.log)
```

因此需要排查 `/etc/hosts.allow` 和 `/etc/hosts.deny` 文件内容是否存在 `spawn` 、`twist` 以及不合理的配置

【 Ubuntu Server 22.04 】默认情况

<!-- 截图：image-20240816142413845（在线版图片，未随附） -->

【 Rocky Linux 9 】默认情况

<!-- 截图：image-20240816142929488（在线版图片，未随附） -->

默认不安装 TCP Wrappers

### 0x37 敏感目录排查

攻击者常利用的一些目录排查，例如 `/tmp/`

| 目录地址 | 目录含义 |
| --- | --- |
| /tmp/ | 临时文件目录，所有用户都可以在这里创建文件 |
| /dev/shm | 基于内存的临时文件系统，类似于tmpfs，速度很快，但重启后数据会消失 |
| /var/tmp | 通常用于存放系统或应用在重启之间需要保留的临时文件 |
| ~/.xxxxxx | 各个用户家目录隐藏文件夹 |
| 常见Web 目录(例如 /var/www/html) | 用于存放 Web 相关脚本等 |
| 环境变量 $PATH 中包含的目录 | `$PATH` 环境变量中定义的目录是系统或用户自定义的可执行程序搜索路径 |

如果想查看目录本身的信息，可以使用 `ls -ald` 命令

<!-- 截图：image-20250224154032986（在线版图片，未随附） -->

### 0x38 udev 后门排查

> **udev** 是Linux kernel的设备管理器，主要管理`/dev`目录底下的设备节点。它同时也是用来接替 devfs 及 hotplug 的功能，这意味着它要在添加/删除硬件时处理`/dev`目录以及所有用户空间的行为，包括加载固件时。

除了 udev 程序本身以及其加载的共享库替换后门以外，udev 的规则文件经常被用来做后门，规则文件位于以下三个位置

| 目录路径 | 用途说明 | 优先级顺序 |
| --- | --- | --- |
| `/etc/udev/rules.d/` | **用户自定义规则**：由系统管理员手动添加或修改，用于覆盖或扩展默认规则。 | 高 |
| `/run/udev/rules.d/` | **临时规则**：由系统或程序在运行时动态生成，重启后失效。 | 中 |
| `/lib/udev/rules.d/` | **系统默认规则**：由发行版或软件包（如内核、驱动）提供，不可手动修改。 | 低 |

我们需要着重关注每个规则文件中以下三个关键字(赋值键)

- RUN
- PROGRAM
- IMPORT

以上三个键都是可以直接引用外部程序的，例如创建文件、写入文件、执行文件、反弹shell

```
sudo grep -riI 'RUN\|PROGRAM\|IMPORT' /etc/udev/rules.d/ /usr/lib/udev/rules.d/ /run/udev/rules.d/
```

<!-- 截图：image-20250226235344259（在线版图片，未随附） -->

输出量非常大，最好是配合文件的时间属性以及相同系统版本对照着看，也可以进一步筛选

更多关于 udev 持久化内容可以查看我们公众号的分析文章

> https://mp.weixin.qq.com/s/t9pOy5MzZ6hxH0gdgprI7g

### 0x39 Python .pth 后门排查

> 参考 
> https://dfir.ch/posts/publish_python_pth_extension/
> https://www.volexity.com/blog/2024/04/12/zero-day-exploitation-of-unauthenticated-remote-code-execution-vulnerability-in-globalprotect-cve-2024-3400/

`.pth` 后缀的文件用于扩展模块搜索路径。当此类文件位于`site-packages`或`dist-packages`等目录时，Python会在启动时自动处理文件内容

但是它有一个问题，如果文件以 import 开头，那么在执行任意 Python 代码时就会执行 `*.pth` 文件的代码

排查 `*.pth` 后门的思路就是找到所有的 `site-packages` 和 `dist-packages` 目录，之后查看其中的 `*.pth` 是否存在以 import 开头的行

还有就是关注 `PYTHONPATH` 环境变量是否被攻击者注入恶意模块路径

```
echo $PYTHONPATH
```

至于 `*.pth` 文件检查，我建议使用 locate 找到所有的 `*.pth` 文件，之后看看其中是否存在 import 开头的恶意代码

【Ubuntu Server 22.04】默认情况

<!-- 截图：image-20250227012727106（在线版图片，未随附） -->

【Rocky Linux 9.1】 默认情况

<!-- 截图：image-20250227012921064（在线版图片，未随附） -->
