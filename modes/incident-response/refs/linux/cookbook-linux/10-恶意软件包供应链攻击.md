> 原文来源：Linux-INCIDENT-RESPONSE-COOKBOOK（GPL-3.0），作者 NOP Team，https://github.com/Just-Hack-For-Fun/Linux-INCIDENT-RESPONSE-COOKBOOK ；本节原文抓取自在线版 URL https://book.noptrace.com/linux/10.%E6%81%B6%E6%84%8F%E8%BD%AF%E4%BB%B6%E5%8C%85%E4%BE%9B%E5%BA%94%E9%93%BE%E6%94%BB%E5%87%BB/

# 恶意软件包供应链攻击


### 0x00 梳理现场情况

#### 采集并确定 ioc 信息

> 恶意软件包供应链攻击的事件来源可能有很多，例如主动 `rpm -Va` 或 `debsums --all` 检查或被动流量侧、EDR侧检测到恶意程序等，因此这部分以发现恶意软件包程序 pid 为开始

#### 确认攻击信息准确性

安全设备、人、上级/行业/监管单位的通报都不见得是准确的，做二次研判是必要的，能够帮我应急响应人员确定整体排查思路

#### 询问历史被攻击情况、历史通报

历史攻击可能会留下攻击遗产，成为未来新一轮攻击事件的发起点，询问清楚历史被攻击、被通报情况，向当事人或负责人了解清楚事件性质、处理过程、处理结果，这可能会在完全理不清攻击路径的时候帮你一把

### 0x01 通过 pid 确定具体文件

- 根据pid获取程序的详细信息
  
  
  有些时候无法通过ps，top等命令根据pid进行查询，可能是因为攻击者将/proc/pid/ 进行了隐藏，可以通过以下方式进行隐藏(ubuntu测试成功，centos测试失败) 
  
  mkdir .hidden
  mount -o bind .hidden /proc/PID
      这种情况可以使用 `cat /proc/$$/mountinfo` 来查看挂载信息
  - `lsof -p pid`
  - `pwdx pid` 获取该pid的进程启动的时候的目录,并不一定是恶意文件所在的路径，只是启动恶意文件的路径
  - `systemctl status pid` 获取这个进程的status信息
  - `cat /proc/pid/maps`
  - `ls -al /proc/pid/exe`
- 根据pid查看由进程起的线程
  - `ps -w H -T -p pid`
  - `ps -w -Lf pid`
    
        其中SPID就是线程ID，而CMD栏则显示了线程名称
  - `top -H -p pid` -H 选项可以显示线程
  - htop (默认未安装)，可以较为全面的展示线程
  - `pstree -agplU` 推荐，非常全面展示进程与线程间的关系
    - 可以在后面直接加 pid 的值，例如 `pstree -agplU 709` ，查看指定 pid 的进程与线程的关系

### 0x02 确定恶意文件所属软件包

【Ubuntu】

```
dpkg -S evil.sh
```

<!-- 截图：image-20230426212721957（在线版图片，未随附） -->

【Rocky Linux】

```
yum whatprovides evil.sh
```

<!-- 截图：image-20230426212958857（在线版图片，未随附） -->

### 0x03 确定恶意软件包相关文件

【Ubuntu】

```
dpkg -L <package-name>
```

<!-- 截图：image-20230426213432980（在线版图片，未随附） -->

【Rocky Linux】

```
rpm -ql <package-name>
```

<!-- 截图：image-20230426215012662（在线版图片，未随附） -->

### 0x04 打包恶意软件所有相关文件

【Ubuntu】

```
mkdir package_details; dpkg -L <package-name> | xargs -I ford sh -c 'if [ -f ford ]; then cp ford ./package_details/ ; echo "`md5sum ford`ford" ;fi' > package_details/md5.txt; tar -cvf package_details_`date +%s`.tar ./package_details; rm -r ./package_details
```

<!-- 截图：image-20230426223806451（在线版图片，未随附） -->

会在当前目录下生成 tar 包，其中包含了该恶意软件的所有文件以及 md5

【Rocky Linux】

```
mkdir package_details; rpm -ql <package-name> | xargs -I ford sh -c 'if [ -f ford ]; then cp ford ./package_details/ ; echo "`md5sum ford`ford" ;fi' > package_details/md5.txt; tar -cvf package_details_`date +%s`.tar ./package_details; rm -rf ./package_details
```

<!-- 截图：image-20230426224232944（在线版图片，未随附） -->

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
> 例如根据事件推断软件包安装路径、需求等

### 0x06 分析恶意软件包并处理异常进程

- 病毒在线分析
  - PCHunter
  - Virustotal
  - 哈勃
  - jotti
  - scanvir
  - 魔盾
  - 微步云沙箱
  - HYBRID
  - 奇安信沙箱
- 寻找病毒分析报告
  - 深信服安全应急响应以及EDR知识赋能平台
  - 深信服EDR团队安全情报分析
  - 深信服安全中心
  - 火绒安全最新资讯
  - 安全客
  - Freebuf
  - ...
- 进程查杀 
  
  有些进程会起子进程，可以使用如下命令查看 
  
  
  
  如果无子进程，直接使用 
  
  
  
  如果进程起子进程，需要使用一下命令        
  
  
  
  进程组ID & 会话ID 
  平时我们关注的更多是PID和PPID，对于PGID，SID接触较少，简单介绍一下 
  使用 `ps -w ajfx` 可以看到具体的PPID、PID、PGID、SID 信息
  <!-- 截图：99bcffa89a2023-04-26-171718.png（在线版图片，未随附） -->
  程序运行起来后，会产生一个主线程，并且分配一个进程ID（pid），如果在运行期间起其他进程，那么这个其他进程就是子进程，同时分配相应的进程ID，并设置其PPID的值为父进程的pid
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
  
  很多木马病毒将恶意代码执行做到了线程级别，也就是说附到了现有正常业务的进程中，做一个线程,目前无法单独查杀一个进程中的某个线程。
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

### 0x07 删除恶意软件包

> 当以下方法无法清除干净的时候，可以考虑将每个文件在不影响系统和业务正常运行的情况下按需删除

【Ubuntu】

```
sudo apt purge <package-name>
或
sudo dpkg -P  <package-name>
```

**其实 apt purge和 dpkg -P 并不会删除个人用户目录(~)下的关于软件包的文件，可以选择手动删除**

【Rocky Linux】

通过 yum/dnf 安装的软件包

```
sudo dnf remove <package-name>
或
sudo rpm -e
```

默认不会清除缓存、日志、依赖等，建议对比之前查出来的相关文件进行对比补充删除

也可以通过 `dnf history` 来将某次安装恢复，以 nmap 为例

```
sudo dnf history
sudo dnf history info id
```

<!-- 截图：image-20230426233956720（在线版图片，未随附） -->

<!-- 截图：image-20230426234026944（在线版图片，未随附） -->

通过 `dnf history` 可以看到软件包历史安装情况，每次操作都有对应 id , 通过 `dns history info id` 可以查看详细情况

```
撤销当时的操作，这里以撤销安装 nmap 为例
sudo dnf history undo id -y 
```

<!-- 截图：image-20230426234253360（在线版图片，未随附） --><!-- 截图：image-20230426234317036（在线版图片，未随附） -->

### 0x08 善后阶段

> 直接查看善后阶段即可，尤其是 第三方软件源 GPG 密钥检查

### 0x09 常规安全检查阶段

> 直接根据常规安全检查章节进行安全检查即可，目的是找出当前系统中存在的隐藏后门等
