> 原文来源：Linux-INCIDENT-RESPONSE-COOKBOOK（GPL-3.0），作者 NOP Team，https://github.com/Just-Hack-For-Fun/Linux-INCIDENT-RESPONSE-COOKBOOK ；本节原文抓取自在线版 URL https://book.noptrace.com/linux/5.%E6%8C%96%E7%9F%BF%E7%97%85%E6%AF%92/

# 挖矿病毒


### 0x00 整体流程

<!-- 截图：挖矿病毒处置流程（在线版图片，未随附） -->

### 0x01 梳理现场情况

#### 采集并确定 ioc 信息

- 从内网 dns 服务器、dns 防火墙、流量审计设备等设备获取
- 根据`ioc`信息确定挖矿程序具体家族类型
  - [Virustotal](https://www.virustotal.com/)
  - [深信服威胁情报中心](https://ti.sangfor.com/analysis-platform?lang=ZH-CN)
  - [微步在线](https://x.threatbook.cn/)
  - [venuseye](https://www.venuseye.com.cn/)
  - [安恒威胁情报中心](https://ti.dbappsecurity.com.cn/)
  - [360威胁情报中心](https://ti.360.cn/)
  - [绿盟威胁情报中心](https://ti.nsfocus.com/)
  - [AlienVault](https://otx.alienvault.com/)
  - [RedQueen安全智能服务平台](https://redqueen.tj-un.com/)
  - [IBM X-Force Exchange](https://exchange.xforce.ibmcloud.com/)
  - [ThreatMiner](https://www.threatminer.org/)
  - [腾讯威胁情报中心](https://tix.qq.com/)
  - [安天威胁情报中心](https://www.antiycloud.com/#/antiy/index)

#### 确认攻击信息准确性

安全设备、人、上级/行业/监管单位的通报都不见得是准确的，做二次研判是必要的，能够帮我应急响应人员确定整体排查思路

#### 询问历史被攻击情况、历史通报

历史攻击可能会留下攻击遗产，成为未来新一轮攻击事件的发起点，询问清楚历史被攻击、被通报情况，向当事人或负责人了解清楚事件性质、处理过程、处理结果，这可能会在完全理不清攻击路径的时候帮你一把

### 0x02 获取异常进程pid

- CPU占用
  - `top -c -o %CPU`
    - -c 参数显示进程的命令行参数
    - -p 参数指定进程的pid
  - `ps -w -eo pid,ppid,%mem,%cpu,cmd --sort=-%cpu | head -n 5`
    - 以 cpu 占用情况排序的进程信息前 5 行
- 内存占用
  - `top -c -o %MEM`
    - -c 参数显示进程的命令行参数
    - -p 参数指定进程的pid
  - `ps -w -eo pid,ppid,%mem,%cpu,cmd --sort=-%mem | head -n 5`
- 网络占用 
      > 网络占用需要安装这两个软件，之后使用root权限进行执行
      > Debian/Ubuntu 
      >
      > - `apt-get install nethogs`
      >
      > Centos/RHEL 
      > - `yum -y install epel-release`
      > - `yum -y install nethogs`
  - nethogs
  - jnettop

### 0x03 寻找恶意文件样本

经过以上步骤，我们基本上已经获取到进程pid或进程相关的命令行命令

- 根据进程名字或者部分字符串获取pid 
  `pidof "name"
  ps -w -aux | grep "name"
  ps -w -ef | grep "name" | grep -v grep | awk '{print $2}'
  pgrep -f "name"`
- 根据pid获取程序的详细信息
  `lsof -p pid 
  pwdx pid  # 获取该pid的进程启动的时候的目录,并不一定是恶意文件所在的路径，只是启动恶意文件的路径
  systemctl status pid  # 获取这个进程的 status 信息
  cat /proc/pid/maps
  ls -al /proc/pid/exe`
  
  有些时候无法通过ps，top等命令根据pid进行查询，可能是因为攻击者将/proc/pid/ 进行了隐藏，可以通过以下方式进行隐藏(ubuntu测试成功，centos测试失败) 
  - mkdir .hidden
  - mount -o bind .hidden /proc/PID
  这种情况可以使用 `cat /proc/$$/mountinfo` 来查看挂载信息
- 根据pid查看由进程起的线程
  - `ps -w H -T -p pid`
  - `ps -w -Lf pid`
    
    其中SPID就是线程ID，而CMD栏则显示了线程名称
  - `top -H -p pid` -H 选项可以显示线程
  - htop (默认未安装)，可以较为全面的展示线程
  - `pstree -agplU` 推荐，非常全面展示进程与线程间的关系
  - 可以在后面直接加 pid 的值，例如 `pstree -agplU 709` ，查看指定 pid 的进程与线程的关系

### 0x04 确定程序运行时间

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

### 0x05 处理异常进程

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
- 寻找病毒分析报告
  - 深信服EDR团队安全情报分析
  - 火绒安全最新资讯
  - 安全客
  - Freebuf
  - 微步在线 X 情报社区
  - 安天
  - ...
- 进程查杀 
      > 有些进程会起子进程，可以使用如下命令查看 
  
  
  如果无子进程，直接使用 
  - `kill -9 pid` 这样会直接杀死指定进程，但是，由这个进程产生的子进程不会被杀死
  如果进程起子进程，需要使用如下命令      
  
  - `kill -9 -pid`  这里pid前有个减号，表示杀掉这个进程组 
  
  `> 需要注意的是， `kill -9 -PGID` 配合 `sudo` 使用时，需要将命令修改为以下格式 
  >
  > ```bash
  > sudo kill -9 -- -PGID
  > ```
  >
  > 也可以使用 `pkill` 来完成
  >
  > ```bash
  > sudo pkill -g PGID   # 进程组前没有横杠
  > ````
  ​    
  
  进程组ID & 会话ID 
  平时我们关注的更多是PID和PPID，对于PGID，SID接触较少，简单介绍一下 
  使用 `ps -w ajfx` 可以看到具体的PPID、PID、PGID、SID 信息
  <!-- 截图：f01eec0cb72021-02-24-072105.png（在线版图片，未随附） -->
  程序运行起来后，会产生一个主进程，并且分配一个进程ID（pid），如果在运行期间起其他进程，那么这个其他进程就是子进程，同时分配相应的进程ID，并设置其PPID的值为父进程的pid
  此时呢，父进程和所有生成的子进程会组合成一个进程组，并且分配一个进程组ID
  那什么叫做会话ID，其实也很容易理解，我们通过ssh 链接到服务器，就会获取一个会话，分配一个会话ID，此时我们起的进程的会话ID都是一样的
  所以，如果挖矿程序有调用子进程，那么就需要以进程组为单位杀死！
  - `ps -w ajfx`
  - `systemctl status`
- 守护进程(daemon) 
  
  挖矿病毒为了保障挖矿程序的运行，通常会为挖矿程序设置守护进程，杀死守护进程与杀死普通进程并无区别，更详细的内容已经总结到 [Linux守护进程 | 应急响应](https://mp.weixin.qq.com/s/3MJUsGZeVWgOeQ9wx2KylQ) 这篇文章
- 线程查杀
      > 很多木马病毒将恶意代码执行做到了线程级别，也就是说附到了现有正常业务的进程中，做一个线程,目前查杀一个进程中的线程风险比较大，极可能会把进程搞崩掉，需要与客户确认好再进行，杀死线程的方法和杀死进程一样，因为在Linux中线程的概念就是轻量级进程
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

### 0x06 删除恶意文件

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
      > 从windows向linux传输的文件或者攻击者恶意制造的文件，很多会有文件名乱码，无法直接通过乱码的文件名进行删除，可以使用inode来确定文件名，之后删除
  - 使用 inode 进行删除
    - 查看inode
      - `ls -li eval.sh`
        `john@john:~/temp$ ls -li evil.sh 
        12327526 -rw-r--r-- 1 john john 0 3月   7 10:21 evil.sh
        john@john:~/temp$`
    - 删除文件
      - `find ./* -inum 12327526 -delete`
      - `find ./ -inum 12327526 -exec rm {} \;`
      - `find ./* -inum 12327526 -exec rm -i {} \;` (会有一步确认是否删除)
      - `find ./* -inum 12327526 -exec rm -f {} \;`(不进行确认直接强制删除)
      - `find ./* -inum 12327526 |xargs rm -f`
      - `rm `find ./* -inum 12327526``
        参考文章
        https://www.cnblogs.com/starry-skys/p/12970463.html
        https://www.cnblogs.com/tssc/p/7574432.html
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

### 0x07 善后阶段

> 直接查看善后阶段即可，主要为定损以及针对性排查处理，目的是解决潜在的受害服务器

### 0x08 常规安全检查阶段

> 直接根据常规安全检查章节进行安全检查即可，目的是找出当前系统中存在的隐藏后门等
