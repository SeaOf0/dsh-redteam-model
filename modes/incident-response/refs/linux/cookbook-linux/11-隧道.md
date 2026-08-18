> 原文来源：Linux-INCIDENT-RESPONSE-COOKBOOK（GPL-3.0），作者 NOP Team，https://github.com/Just-Hack-For-Fun/Linux-INCIDENT-RESPONSE-COOKBOOK ；本节原文抓取自在线版 URL https://book.noptrace.com/linux/11.%E9%9A%A7%E9%81%93/

# 隧道


> 为了隐匿流量，攻击者常常使用隧道来进行流量加密与混淆

隧道事件的事件来源一般有以下几种：

- 流量设备发现存在网络隧道
- 主机安全程序发现存在网络隧道或相关文件、进程
- 排查过程中发现存在跳板机痕迹等，进而发现隧道
- 运维相关人员发现异常端口等

其实大家可以发现，处理隧道与处理远控后门没有太大的区别，因为隧道本身就是后门大概念中的一部分，所以也是通过各种特征找到 `PID` ，进而处理

**大多数协议隧道都包含两点特征**：

1. 存在短时间、单一目标、频繁请求的该协议的数据包
1. 可能出现额外本地到本地的连接 (127.0.0.1:xx -> 127.0.0.1:xx)

大家需要明白一点，发现隧道并不是应急人员要做的，验证处理才是，现在隧道程序五花八门，尝试去记住特征并识别意义并不大，下面的部分也仅仅是介绍一些隧道技术与正常网络连接的差异，如果隧道程序想做，完全可以做到和正常网络连接没区别

> 这里给大家推荐一篇总结内网代理工具与检测方法研究的文章，下面部分内容参考该文章
> https://mp.weixin.qq.com/s?__biz=MzkzNjMxNDM0Mg==&mid=2247483876&idx=1&sn=b71f016be9f345699efcbffdc27b626f&chksm=c2a1d56df5d65c7bbee6e1052d0405eab5cb6dbb98bd549459b83b5a2ab6b530cd078ca5398e&token=229680544&lang=zh_CN#rd

### 0x00 隧道处置方法

隧道处置起来比较困难的是找到隧道对应的进程，尤其是对于 icmp 隧道来说，找到进程后，就可以按照远控后门章节的方式进行处理了

我们在接到隧道事件以后，肯定是知道隧道对端的IP地址了，无论对端IP地址是我们内网还是外网，对我们来说都是最重要的信息，我们要做的就是找到与这个 IP 地址通信的进程，eBPF 赋予了我们这样的能力，以 Ubuntu 为例

> 对于域名的情况来说，直接通过修改 /etc/hosts 文件的方式或修改内网DNS解析记录的方式将其固定为 IP 地址，所以处理过程是一样的

#### 1. 安装 bpftrace

```
sudo apt update
sudo apt install bpftrace
```

#### 2. 上传监控脚本

`request_monitor.sh`

```
#!/bin/bash

convert_ip_to_integers() {
  local ip=$1
  IFS='.' read -r a b c d <<< "$ip"

  # 计算大端序 (big-endian)
  be_ip_int=$((a << 24 | b << 16 | c << 8 | d))

  # 计算小端序 (little-endian)，需要颠倒字节顺序
  le_ip_int=$((d << 24 | c << 16 | b << 8 | a))

  echo "$be_ip_int $le_ip_int"
}

# IP地址参数
IP="$1"

# 调用函数，获取大端和小端的整数表示
read big_endian little_endian <<< $(convert_ip_to_integers "$IP")

# 假设BPFtrace脚本期望两个参数，分别对应大端和小端

echo "Start listening for the request to $IP"
echo ""
sudo ./request_monitor.bt $big_endian $little_endian
```

`request_monitor.bt`

```
#!/usr/bin/bpftrace
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/socket.h>

kprobe:__dev_queue_xmit
{
    @dev_queue_xmit[tid]=count();
    @skb[tid]=(struct sk_buff *)arg0;
}

kprobe:__dev_queue_xmit
/@skb[tid]/
{
    $skb = @skb[tid];
    $iph = (struct iphdr *)($skb->head + $skb->network_header);
    $sip = ntop(AF_INET, $iph->saddr);
    $dip = ntop(AF_INET, $iph->daddr);


    if ($iph->daddr == $1 || $iph->daddr == $2){
        printf("[+] Found the request to %s \n", $dip);
        printf("[-] pid=%d, thread_id=%d, comm=%s \n", pid,tid,comm);
    }
}
```

#### 3. 设置监听

```
sudo ./request_monitor.sh 192.168.31.83
```

这样就会监测到底是哪个进程在与 192.168.31.83 进行通信

<!-- 截图：image-20240622162621240（在线版图片，未随附） -->

这样就找到了进程的 pid，接下来的处理步骤参考远控后门章节

### 0x01 SSH隧道

**SSH隧道的详细实验过程以及分析可以查看知识点附录0x03**

> 隧道跟管子一样，两端都可以作为入口、出口，实验主机分配如下
> 攻击机就用我的物理机 10.211.55.2 
> 被控主机（做隧道的主机）Centos 10.211.55.11
> 访问受限主机 Ubuntu 10.211.55.10

#### 本地转发隧道

检测方法

我们来看一下受控主机是否存在异常

- 网络连接

<!-- 截图：image-20210427113736063（在线版图片，未随附） -->

从流量上看多了一个攻击机连接受控主机Centos 22端口的连接，同时多了一个受控主机Centos 访问 10.211.55.10 80端口的连接，在我们实验主机中可以清晰看出来，但是如果在实际情况中，很多业务在使用同一个主机的时候，是非常难以分辨出这是一个SSH隧道的，所以从网络连接上辨别SSH隧道难度较大

- 进程

<!-- 截图：image-20210428174421455（在线版图片，未随附） -->

​   从进程角度来查看多了一个ssh连接进程，这个进程很可能就是有问题的了，可以联系相关主机业务人员确认

- 日志

使用lastb 来查看异常登录日志,未发现内容

<!-- 截图：image-20210428174802359（在线版图片，未随附） -->

查看日志文件 `/var/log/secure`

<!-- 截图：image-20210428174943830（在线版图片，未随附） -->

可以看到，存在来自攻击机（物理机 10.211.55.2）的ssh认证连接

对于SSH本地转发隧道来说，执行命令是在攻击机上，所以无法通过history查到任何信息

**从上面来看，主要发现SSH隧道的手段就是查看网络连接和日志，这种连接与正常的SSH连接无异，所以较难分辨**

#### 远程转发隧道

> 受控机Centos 通过ssh远程连接我们的攻击机(物理机)，并且在我们攻击机上开放一个端口（8008），做socks隧道
> 反向的好处是在一些防火墙配置下，可能内网主机外联端口会有限制，这样我们通过配置攻击机SSH端口为 53 端口可能成功穿过防火墙
> 之所以要受控主机远程连接我们物理机，是因为ssh默认配置 -R 参数开放端口绑定的地址是 127.0.0.1 而不是 0.0.0.0 ,这就导致即使我们正向在受控主机 Centos上开了 8008 端口，我们也无法连接，所以我们采用反向的方式

检测方法：

- 网络连接

<!-- 截图：image-20210428175617913（在线版图片，未随附） -->

网络连接可以看出受控主机SSH远程连接我们的物理机，遇到这种情况就需要进行和主机、业务人员确认连接是否正常业务

- 进程

<!-- 截图：image-20210428175707707（在线版图片，未随附） -->

进程中可以看到我们执行的命令

- 日志

<!-- 截图：image-20210428175740380（在线版图片，未随附） -->

​   从history 中可以看到我们的连接操作，关于history的知识点可以查看善后工作中的history

#### 动态隧道

> 上面的两种隧道都是仅仅转发一个IP的一个端口，对于攻击者来说，需要攻击内网的不同应用，如果每攻击一个应用就要映射一次就太麻烦了，所以SSH提供了一种动态隧道，类似代理模式，流量发到入口，由SSH Server来判断具体是否什么协议，转发到那台服务器 
> 动态隧道是一种本地转发隧道,在绑定端口开一个socks4/5的代理，直接设置代理后可以访问内网主机

检测方法

我们来看一下受控主机 Centos 存在哪些异常

- 网络连接

<!-- 截图：image-20210428173036497（在线版图片，未随附） -->

​   还是一样，能看到网络连接，需要与相关人员确认

- 进程

<!-- 截图：image-20210428173224469（在线版图片，未随附） -->

​   从进程可以看出多了一个ssh，其他没啥

- 日志

异常登录日志中无异常

<!-- 截图：image-20210428175847788（在线版图片，未随附） -->

​   在 /var/log/secure 中可以看到 ssh 认证连接

<!-- 截图：image-20210428173837237（在线版图片，未随附） -->

### 0x02 DNS隧道

> dns隧道是一种相对隐蔽的一种连接方式，通过DNS的A、CNAME、TXT、MX各种记录进行流量传输，检查起来难度较大

常见的DNS隧道工具：

- dns2tcp
- dnscat2
- dnscat2 powershell版
- iodine
- Cobalt Strike
- Reverse_DNS_Shell

对于DNS隧道，检测主要分为两个方面

- DNS隧道的进程
- DNS的流量传输

> 进程角度

其实从进程角度很难去查询DNS隧道，水平一般的攻击者也会把默认的工具名称改掉，甚至改成java等和正常应用一样的名，所以这里也只是碰碰运气

- `ps -w afjx`

> 流量角度

对于重要目标的APT一般可以无限延长攻击时间，如果攻击者想，完全可以将数据包发包频率随机化，将DNS查询子域名长度限制在正常长度范围内（比如3～5个字符），在隧道DNS请求间穿插“正常”请求，比如 www.demo.com 的域名解析，甚至抓包模拟正常业务需要解析的域名的各种记录查询，诱导安全人员和设备出错

所以这里我们仅仅讨论隧道正在进行的情况，网络上有很多从AI角度来进行检测DNS隧道的文章，挑选几篇看一看就能了解怎么避免被检测到，可以参考

- DNS隧道检测特征总结 https://zhuanlan.zhihu.com/p/143220945
- 探秘-基于机器学习的DNS隐蔽隧道检测方法与实现 https://blog.riskivy.com/探秘-基于机器学习的dns隐蔽隧道检测方法与实现/

理论结束，进入实操，宗旨就是在Linux服务器上抓一段时间的包，之后拿到桌面计算机上面进行分析

tcpdump

`tcpdump -p -n -s 0 port domain -w dnstest.pcap`

这样我们收集一段时间，之后放入 wireshark 中进行分析

<!-- 截图：image-20210430162746430（在线版图片，未随附） -->

<!-- 截图：image-20210430162811301（在线版图片，未随附） -->

如果DNS流量较大，可以按照域名进行过滤，baidu，sina，ubuntu，centos，redhat 等官方域名都可以筛选掉，剩下的再进行分析

如果其中 A、TXT、CNAME、MX等记录中存在像以下这种比较特殊的请求，可能就存在DNS隧道

<!-- 截图：image-20210430164321868（在线版图片，未随附） -->

### 0x03 ICMP隧道

> ICMP 隧道与 DNS隧道类似，都是在正常的请求中加密传输我们自己的载荷

常见ICMP隧道工具

- ptunnel
- icmpsh
- icmptunnel
- icmpshell

> 进程角度

- `ps -w afjx`

<!-- 截图：image-20210507111744776（在线版图片，未随附） -->

> 网络连接角度

被攻击主机可能开放新的监听端口，以便后续进行端口转发或者在隧道内创建新的隧道，我们通过以下指令查看

`netstat -pantu`

<!-- 截图：image-20210507114013826（在线版图片，未随附） -->

> 流量角度

tcpdump 抓取ICMP流量

`tcpdump -p -n -s 0 icmp -w icmp.pcap`

放入 wireshark 进行分析，看看是否存在一些包大小不太正常的流量或者流量中存在其他协议的字符

<!-- 截图：image-20210507113147965（在线版图片，未随附） -->

### 0x04 HTTP/HTTPS 隧道

> http 隧道一般以 webshell的形式存在，检测起来基本上就是检测webshell那一套

- Proxytunnel
- httptunnel(htc/hts)
- reGeorg
- Neo-reGeorg
- Tunna
- ABPTTS

检测手段：

- 文件查杀

使用D盾等webshell查杀工具进行查杀

- D盾
- 河马查杀
- ...
- 文件名
- 参照小技巧章节中的"查找文件"
- 文件内容关键字
- 参照小技巧章节中的"查找文件内容"
- 流量特征关键字
- 例如 regeorg 的 cmd 参数等，一般需要安全设备进行辅助
- 进程
- proxytunnel 和 httptunnel 这种
- 新建文件
- 查找最近或者一段时间内新创建的文件，查找小技巧中查找文件的章节
- 主机对外行为
- 建立隧道的目的无非就是攻击内网主机，所以关注本机对外攻击情况可以有一些发现
- `netstat -pantu`

### 0x05 SSL加密隧道

> SSL隧道致力于将其他数据通过SSL加密封装，使内部安全传输

- [stunnel](https://www.stunnel.org/)
- [go-tunnel](https://github.com/opencoff/go-tunnel)

ssl隧道软件一般也都是采用客户端/服务端 + 配置文件的形式，所以可以从以下几个角度去分析

- 进程
- `ps -w afjx`
- 文件名 & 新建文件
- 参照小技巧中关于文件查找的章节
- 文件内容（配置文件）
- 参照小技巧中关于文件内容查找的章节
- 网络通信
- 至少多一个SSL的端口和网络连接
- `netstat -pantu`

### 0x06 Socks隧道

- frp
- earthworm
- shadowsocks

socks协议的代理隧道非常多，基本可以通过协议来进行区分，如果安全设备发现存在 socks 协议的通信，那么可以着重观察一下

ssh 的 -D 参数也是使用了socks代理

- 协议
- 需要安全设备自动分析，不然tcpdump 抓包后放入wireshark上分析比较麻烦，同时难度也很大
- 进程
- `ps -w afjx`
- 文件名 & 新建文件
- 参照小技巧中关于文件查找的章节
- 文件内容（配置文件）
- 参照小技巧中关于文件内容查找的章节
- 网络连接
- `netstat -pantu` 查看是否存在异常的端口连接
- 行为
- 是否存在对内网其他主机攻击行为

### 0x07 Wi-Fi or Bluetooth 隧道

- Ghost Tunnel

参考 [Ghost Tunnel：适用于隔离网络的WiFi隐蔽传输通道 - FreeBuf网络安全行业门户](https://www.freebuf.com/wireless/171108.html)

检测方法：

> 如果不是被专业团队发现，一般安全设备的人员是不会发现这种隐蔽的隧道的，所以这里假设已经有了相关猜测或者证据，我们来发现取证的角度来写

Wi-Fi

- 将无限网卡设置为监听模式
- `iwconfig  wlan0 mode monitor`  （wlan0为网卡接口名称）
  如果执行失败，可以先把网卡down掉，再进行设置，再up起来
  `ifconfig wlan0 down` 
  `iwconfig wlan0 mode monitor`
  `ifconfig wlan0 up`
- wireshark 抓 802.11的包
- 对 Wi-Fi 认证过程进行分析，是否存在异常数据包

正常的认证过程如下：

<!-- 截图：image.png（在线版图片，未随附） -->

参考 [Ghost Tunnel：适用于隔离网络的WiFi隐蔽传输通道 - FreeBuf网络安全行业门户](https://www.freebuf.com/wireless/171108.html)

Bluetooth

> 蓝牙的协议一般人了解较少，需要进行抓包后与常规协议进行对比

可以使用 WireShark 进行蓝牙数据包分析，具体可以参考

[Bluetooth · Wiki · Wireshark Foundation / wireshark · GitLab](https://gitlab.com/wireshark/wireshark/-/wikis/CaptureSetup/Bluetooth)

Wi-Fi 和 Bluetooth 的隧道对传输距离有要求，可以简单观察一下四周，不使用的时候关闭蓝牙和Wi-Fi
