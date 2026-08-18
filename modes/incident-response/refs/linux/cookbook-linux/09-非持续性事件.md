> 原文来源：Linux-INCIDENT-RESPONSE-COOKBOOK（GPL-3.0），作者 NOP Team，https://github.com/Just-Hack-For-Fun/Linux-INCIDENT-RESPONSE-COOKBOOK ；本节原文抓取自在线版 URL https://book.noptrace.com/linux/9.%E9%9D%9E%E6%8C%81%E7%BB%AD%E6%80%A7%E4%BA%8B%E4%BB%B6/

# 非持续性事件


### 0x00 简介

> 持续性的挖矿、远控后门等可以通过直接排查发现，但是在实际工作中，很多恶意行为（访问恶意域名、连接恶意IP）只集中出现了几次，无法直接通过网络连接找到恶意进程及文件或者有些恶意程序处置结束后，无法确定是否已经清理完整
> 可以通过短时间/长时间网络监控来解决

### 0x01 确定目标域名或IP

如果目标域名或者IP是某一知名组织的，可以将该组织或者种类病毒的域名和IP都收集进行监控

### 0x02 修改域名解析记录

修改恶意域名的解析记录目的主要有两个：

- 阻断控制，防止二次伤害
- 得到固定的IP解析记录，防止攻击者把域名下架或者改变解析到的IP

修改域名解析记录有两个途径：

- 在内网DNS服务器中集中修改（如果内网有DNS服务器）
- 修改 hosts 文件 (推荐)

以恶意域名 `du.testjj.com` 为例

通过修改 `/etc/hosts` 将 `du.testjj.com` 解析IP修改为 `123.123.123.123`

<!-- 截图：image-20220929170525081（在线版图片，未随附） -->

### 0x03 设置监控程序

> 很多客户不允许在服务器上安装监控程序，但是对于可审计的脚本倒是可以在审计后执行，因此这里主要以脚本为主

Linux_Audit_Nop.sh

```
#!/bin/bash


while true
do  
    sleep 0.1
    pids=$(netstat -pantu | grep 123.123.123.123 | awk -F "/" '{print $1}' | awk -F " " '{print $NF}' | sort | uniq)
    for one_pid in $pids
    do
        if [ $one_pid == "-" ]; then 
            continue
        fi

        echo "" >> $(pwd)/Audit_results.txt
        echo "[ lsof -p $one_pid ]" >> $(pwd)/Audit_results.txt
        lsof -p $one_pid >> $(pwd)/Audit_results.txt
        echo "" >> $(pwd)/Audit_results.txt
        echo "[ cat /proc/$one_pid/maps ]" >> $(pwd)/Audit_results.txt
        cat /proc/$one_pid/maps >> $(pwd)/Audit_results.txt
        echo "" >> $(pwd)/Audit_results.txt
        echo "[ ls -al /proc/$one_pid/exe ]" >> $(pwd)/Audit_results.txt
        ls -al /proc/$one_pid/exe >> $(pwd)/Audit_results.txt
    done
    if [ -f "$(pwd)/Audit_results.txt" ]; then
        echo "Found it !"
        exit
    fi    
done
```

除了上述脚本以外，再推荐两款比较优秀的程序

- sysmon for linux
- auditd

sysmon for linux 原本是微软为 Windows 开发的监控程序，21年的时候做了 Linux 开源版

https://github.com/Sysinternals/SysmonForLinux

https://github.com/OpenSecureCo/Demos/blob/main/sysmonforlinux

auditd 集成在 Ubuntu 的软件库中，可以直接安装

https://linux.die.net/man/8/auditd

### 0x04 等待恶意程序执行

<!-- 截图：image-20220929180551127（在线版图片，未随附） -->

<!-- 截图：image-20220929180611383（在线版图片，未随附） -->

### 0x05 确定程序运行时间

- 查看程序运行时间
  - `ps -w -eo pid,lstart,etime,cmd | grep <pid>`
    <!-- 截图：image-20220428140243469（在线版图片，未随附） -->
    表示 `1292` 这个进程是在 `2022`年`4`月`28`日`13:32:20` 被创建的，已经运行了`30分零2秒`，具体执行的命令行为 `/usr/sbin/sshd -D`
- 与找到的恶意文件创建时间进行对比
  - `stat xxx.sh` 
    <!-- 截图：image-20220428141007638（在线版图片，未随附） -->
  - `ls -al xxx.sh`
    <!-- 截图：image-20220428141106215（在线版图片，未随附） -->

> 这个部分更多是为了验证发现的文件是否为当前程序的恶意文件，增加这个对比，可能会发现一些之前没有发现的蛛丝马迹

### 0x06 处理异常进程

- 恶意文件样本采样
  - scp
    - `scp -P 4588 remote@www.target.com:/usr/local/aaa /home/admin`
    - -P 指定SSH端口
    - 从远程服务器将aaa下载到本地的 /home/admin
- finalshell、xshell等集成工具
  - python、php等程序起http服务
  - nc
- 病毒在线分析
  - 微步云沙箱
  - Virustotal
  - virscan
  - 哈勃
  - jotti
  - scanvir
  - 魔盾
  - HYBRID
  - 奇安信情报沙箱
  - 大圣云沙箱检测系统
  - YOMI
  - 360沙箱云
  - 安恒云沙箱
  - 绿盟威胁分析中心
- 寻找病毒分析报告
  - 深信服EDR团队安全情报分析
  - 火绒安全最新资讯
  - 安全客
  - Freebuf
  - 微步在线 X 情报社区
  - 安天
  - ...
- 进程查杀 
  
  有些进程会起子进程，可以使用如下命令查看 
  
  
  
  如果无子进程，直接使用 
  
  
  
  如果进程起子进程，需要使用如下命令        
  
  
  
  进程组ID & 会话ID 
  平时我们关注的更多是PID和PPID，对于PGID，SID接触较少，简单介绍一下 
  使用 `ps -w ajfx` 可以看到具体的PPID、PID、PGID、SID 信息
  <!-- 截图：f855634e542022-09-29-104102.png（在线版图片，未随附） -->
  程序运行起来后，会产生一个主进程，并且分配一个进程ID（pid），如果在运行期间起其他进程，那么这个其他进程就是子进程，同时分配相应的进程ID，并设置其PPID的值为父进程的pid
  此时呢，父进程和所有生成的子进程会组合成一个进程组，并且分配一个进程组ID
  那什么叫做会话ID，其实也很容易理解，我们通过ssh 链接到服务器，就会获取一个会话，分配一个会话ID，此时我们起的进程的会话ID都是一样的
  所以，如果挖矿程序有调用子进程，那么就需要以进程组为单位杀死！
  - `ps -w ajfx`
  - `systemctl status`
  - `kill -9 pid` 这样会直接杀死指定进程，但是，由这个进程产生的子进程不会被杀死
  - `kill -9 -pid` 注意，这里pid前有个减号，表示杀掉这个进程组 
    
    需要注意的是， `kill -9 -PGID` 配合 `sudo` 使用时，需要将命令修改为以下格式 
    `sudo kill -9 -- -PGID`
    也可以使用 `pkill` 来完成
    `sudo pkill -g PGID   # 进程组前没有横杠`
- 守护进程(daemon) 
  
  挖矿病毒为了保障挖矿程序的运行，通常会为挖矿程序设置守护进程，杀死守护进程与杀死普通进程并无区别，更详细的内容已经总结到 [Linux守护进程 | 应急响应](https://mp.weixin.qq.com/s/3MJUsGZeVWgOeQ9wx2KylQ) 这篇文章
- 线程查杀
  
  很多木马病毒将恶意代码执行做到了线程级别，也就是说附到了现有正常业务的进程中，做一个线程,目前查杀一个进程中的线程风险比较大，极可能会把进程搞崩掉，需要与客户确认好再进行，杀死线程的方法和杀死进程一样，因为在Linux中线程的概念就是轻量级进程
  - 根据pid查看由进程起的线程
    - `ps -w -T -p pid`
    - `ps -w -aLf pid`
      
          其中SPID就是线程ID，而CMD栏则显示了线程名称
    - `top -H -p pid` -H 选项可以显示线程
    - htop (默认未安装)，可以较为全面的展示线程
    - `pstree -agplU` 推荐，非常全面展示进程与线程间的关系
      - 可以在后面直接加 pid 的值，例如 `pstree -agplU 709` ，查看指定 pid 的进程与线程的关系
  - 查看全部的线程
    - `ps -w -eLFa`

### 0x07 删除恶意文件

> 通过进程pid以及/proc/ ,我们已经定位到了文件的具体位置，接下来就是删除恶意文件

- 查看文件占用 
      `lsof eval.sh`
      如果存在进程占用，那么占用进程也可能是恶意进程，需要按照之前的步骤进行查看
- a 和 i 属性导致文件不可删除
  - a属性 文件只能增加内容，不能修改之前的文件，不能删除文件
  - i属性 内容不能改变，文件不能删除 
        可以使用 `chattr -a` 和 `chattr -i`

具体可以参考
https://www.cnblogs.com/kzang/articles/2673790.html

- 奇怪文件名导致文件不可删除 
  
  从windows向linux传输的文件或者攻击者恶意制造的文件，很多会有文件名乱码，无法直接通过乱码的文件名进行删除，可以使用inode来确定文件名，之后删除
  
  
  
  参考文章
  https://www.cnblogs.com/starry-skys/p/12970463.html
  https://www.cnblogs.com/tssc/p/7574432.html
  - 使用 inode 进行删除
    - 查看inode 
      
      `john@john:~/temp$ ls -li evil.sh 
      12327526 -rw-r--r-- 1 john john 0 3月   7 10:21 evil.sh
      john@john:~/temp$`
      - `ls -li eval.sh`
    - 删除文件
      - `find ./* -inum 12327526 -delete`
      - `find ./ -inum 12327526 -exec rm {} \;`
      - `find ./* -inum 12327526 -exec rm -i {} \;` (会有一步确认是否删除)
      - `find ./* -inum 12327526 -exec rm -f {} \;`(不进行确认直接强制删除)
      - `find ./* -inum 12327526 |xargs rm -f`
      - `rm `find ./* -inum 12327526``
- 目录挂载导致无法删除
  
  当目录中没有文件但是依旧无法删除的时候，显示 `Device or resource busy`
  使用lsof 进行查看，又发现没有资源占用，此时要考虑可能目录存在挂载点
  
  <!-- 截图：image-20230106212758570（在线版图片，未随附） -->
  此时需要先将挂载取消，之后再删除该文件夹
  查看挂载情况
  `sudo lsblk -a`
  <!-- 截图：image-20230106212950354（在线版图片，未随附） -->
  取消挂载
  `sudo umount /dev/sdb1`
  /dev/sdb1 是演示电脑的情况，需要按照实际情况更改
  <!-- 截图：image-20230106213145676（在线版图片，未随附） -->
  这样就成功删除了

### 0x08 善后阶段

> 直接查看善后阶段即可，主要为定损以及针对性排查处理，目的是解决潜在的受害服务器

### 0x09 常规安全检查阶段

> 直接根据常规安全检查章节进行安全检查即可，目的是找出当前系统中存在的隐藏后门等
