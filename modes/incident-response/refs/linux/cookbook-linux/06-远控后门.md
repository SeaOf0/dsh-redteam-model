> 原文来源：Linux-INCIDENT-RESPONSE-COOKBOOK（GPL-3.0），作者 NOP Team，https://github.com/Just-Hack-For-Fun/Linux-INCIDENT-RESPONSE-COOKBOOK ；本节原文抓取自在线版 URL https://book.noptrace.com/linux/6.%E8%BF%9C%E6%8E%A7%E5%90%8E%E9%97%A8/

# 远控后门


### 0x00 整体流程

<!-- 截图：木马后门处置流程-深色（在线版图片，未随附） -->

### 0x01 梳理现场情况

#### 采集并确定 ioc 信息

- 从内网 dns 服务器、dns 防火墙、流量审计设备等设备获取
- 从 EDR、态势感知等设备获取
- 根据`ioc`信息确定远控后门具体家族类型
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

#### 询问历史被攻击情况或历史通报

历史攻击可能会留下攻击遗产，成为未来新一轮攻击事件的发起点，询问清楚历史被攻击、被通报情况，向当事人或负责人了解清楚事件性质、处理过程、处理结果，这可能会在完全理不清攻击路径的时候帮你一把

### 0x02 通过EDR获取事件，直接定位到文件

已经获取到具体文件以及路径，接下来我们需要找到具体进程 
- 根据文件找pid

`lsof | grep evil.sh`
`lsof /root/evil.sh`  需要指定路径，只指定字符无法直接查出来
  `fuser /root/evil.sh` 这条命令需要在root权限下执行，不然会显示为空

### 0x03 通过态势感知获取事件，外连ip+端口

根据五元组进行查证就是比较常见的情况了
- 根据目的IP及端口查找 pid

`netstat -pantu | grep 114.114.114.114`
`netstat -pantu | grep 65533`
`lsof -i:65533`

- 根据本机IP+端口查找pid

`netstat -pantu | grep 65533`
`lsof -i:65533`

根据五元组无法找到 pid 可能是因为控制程序使用了隐藏C&C的技术，需要有针对性地进行排查，具体排查方法见 知识点附录 -> 0x05 与C&C隐藏技术的对抗 章节

### 0x04 查找进程信息

- 查找进程相关文件

`lsof -p 1234`  root权限下执行 
  `pwdx`

- 根据pid获取程序的详细信息
  - `lsof -p pid`
  - `pwdx pid` 获取该pid的进程启动的时候的目录,并不一定是恶意文件所在的路径，只是启动恶意文件的路径
  - `systemctl status pid` 获取这个进程的status信息
  - `cat /proc/pid/maps`
  - `ls -al /proc/pid/exe`
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
  如果进程起子进程，需要使用一下命令      
  
  - `kill -9 -pid` 注意，这里pid前有个减号，表示杀掉这个进程组 
  
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
  
  进程组ID & 会话ID 
  平时我们关注的更多是PID和PPID，对于PGID，SID接触较少，简单介绍一下 
  使用 `ps -w ajfx` 可以看到具体的PPID、PID、PGID、SID 信息
  <!-- 截图：f01eec0cb72021-02-24-072105.png（在线版图片，未随附） -->
  程序运行起来后，会产生一个主线程，并且分配一个进程ID（pid），如果在运行期间起其他进程，那么这个其他进程就是子进程，同时分配相应的进程ID，并设置其PPID的值为父进程的pid
  此时呢，父进程和所有生成的子进程会组合成一个进程组，并且分配一个进程组ID
  那什么叫做会话ID，其实也很容易理解，我们通过ssh 链接到服务器，就会获取一个会话，分配一个会话ID，此时我们起的进程的会话ID都是一样的
  所以，如果挖矿程序有调用子进程，那么就需要以进程组为单位杀死！
  - `ps -w ajfx`
  - `systemctl status`
- 守护进程(daemon) 
  
  挖矿病毒为了保障挖矿程序的运行，通常会为挖矿程序设置守护进程，杀死守护进程与杀死普通进程并无区别，更详细的内容已经总结到 [Linux守护进程 | 应急响应](https://mp.weixin.qq.com/s/3MJUsGZeVWgOeQ9wx2KylQ) 这篇文章
- 线程查杀
      > 很多木马病毒将恶意代码执行做到了线程级别，也就是说附到了现有正常业务的进程中，做一个线程,目前无法单独查杀一个进程中的某个线程。
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

> 通过进程pid以及/proc/ ,我们已经发现了定位到了文件的具体位置，接下来就是删除恶意文件

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
      > 在windows向linux传输的文件或者攻击者恶意制造的文件，很多会有文件名乱码，无法直接通过乱码的文件名进行删除，可以使用inode来确定文件名，之后删除
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

​

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
