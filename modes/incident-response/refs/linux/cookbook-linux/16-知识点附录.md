> 原文来源：Linux-INCIDENT-RESPONSE-COOKBOOK（GPL-3.0），作者 NOP Team，https://github.com/Just-Hack-For-Fun/Linux-INCIDENT-RESPONSE-COOKBOOK ；本节原文抓取自在线版 URL https://book.noptrace.com/linux/16.%E7%9F%A5%E8%AF%86%E7%82%B9%E9%99%84%E5%BD%95/

# 知识点附录


### 0x01 Linux 守护进程｜进程组｜session(会话)｜job(作业)

> 本来没有想单拿出来写，但是越研究越深，所以单拿出来

在Linux中：

- 打开terminal，也就是终端程序，之后可以获得一个shell
- 通过ssh连接到linux的ssh-server 服务器，也可以获得一个shell

通常我们都是通过以上两种方式来获得一个shell，之后运行程序的，此时我需要纠正一个概念，我们通常都说获得一个shell，本质上来说，我们获取了一个session（会话，以下session都是会话）

<!-- 截图：image-20210226161737381（在线版图片，未随附） -->

> 拿两种常见情况进行举例

#### 1. 案例1

我们输入

```
ping www.baidu.com
```

<!-- 截图：image-20210226162224562（在线版图片，未随附） -->

大家都知道，此时我们启动了一个程序 ping ,并且创建了一个进程，我们再开一个终端ssh连接这个服务器看一下

<!-- 截图：image-20210226162524420（在线版图片，未随附） -->

可以看到，我们起了一个PID为1779的进程，进程在不断向我们打印ping的结果，那么本质上来讲是什么样的呢？

我们使用 **ps -w ajfx** 来看一下

<!-- 截图：image-20210226163748552（在线版图片，未随附） -->

1. pid，pgid，sid均为890的 sshd 守护进程生成一个SID为1494的session，同时创建了一个pid为1494的子进程“sshd: helper [priv]” ，并且创建了一个进程组，此进程就是进程组的leader，进程组的PGID等于此进程的pid 1494，这个进程就是该session的leader
1. “sshd: helper [priv]”创建了一个PID为1518子进程 “sshd: helper@pts/2” ，其实就是开了一个虚拟终端 pts
1. 虚拟终端pts生成了一个SID为1519的session，创建了一个pid为1519的子进程 “bash”,并且创建了一个新的进程组，新进程组的PGID等于新的子进程的PID为1519，这个子进程为进程组的leader，也是这个session的leader。
1. bash创建了一个pid为1779的子进程 “ping www.baidu.com”，同时创建一个新的进程组，PGID为1779，并且这是一个前台进程

#### 2. 案例2

我们输入

```
ping www.baidu.com &
```

<!-- 截图：image-20210226165303359（在线版图片，未随附） -->

可以看到，ping百度 这个操作的“交互”已经放到后台了，但是依旧像终端输出，我们可以正常输入命令ls,pwd等，执行返回也都正常

```
ps -w ajfx
```

<!-- 截图：image-20210226165657403（在线版图片，未随附） -->

同样的过程就不重复了，不一样的地方在于

<!-- 截图：image-20210226173100663（在线版图片，未随附） -->

<!-- 截图：image-20210226172853237（在线版图片，未随附） -->

这里是 ps -w 命令的 STAT 列，具体字符含义如下

- D 不能中断的进程（通常为IO）
- R 正在运行中的进程
- S 已经中断的进程，通常情况下，系统中大部分进程都是这个状态
- T 已经停止或者暂停的进程，如果我们正在运行一个命令，比如说sleep 10，如果我们按一下ctrl -z 让他暂停，那我们用ps查看就会显示T这个状态
- W 这个好像是说，从内核2.6xx 以后，表示为没有足够的内存页分配
- X 已经死掉的进程（这个好像从来不会出现）
- Z 僵尸进程，杀不掉，打不死的垃圾进程，占系统一小点资源，不过没有关系。如果太多，就有问题了。一般不会出现。

下面一些是BSD风格的参数

- < 高优先级进程
- N 低优先级进程
- L 在内存中被锁了内存分页
- s 主进程
- l 多线程进程
- + 代表在前台运行的进程

可以看出

- 执行 ping www.baidu.com 的时候ping是前台运行的进程， bash是后台运行的进程
- 执行 ping www.baidu.com & 的时候ping是后台运行的进程， bash是前台运行的进程

---

> 如果上面涉及的所有概念你都能清晰的理解，那么下面的内容你也可以看一看，毕竟来都来了...

#### 3. 进程组

进程的概念大家都能理解的话，进程组就很好说了，其实就是一堆进程捆一起了，之后形成一个组就叫进程组了

这么做肯定是有意义的，不然Linux也不会这么搞，主要还是为了方便管理。

公司为了方便管理，给人分组，方便分配工作；社会为了方便管理，给人区分成年人，未成年人，老人；我们又因为爱好，信念等被分成了各种各样的小组...

系统把同一个job（作业）的进程分成一个组，既然有组织肯定得有组长，组的ID（PGID）就采用组长的PID

> 这里有一个问题，如果组长进程死亡了，小组还存在吗？如果存在组长归谁？

如果组长进程死亡了，小组只要还剩下进程就会存在，此时组长不会变，PGID也不会变；就像纪念一样...

实验一下：

```
#include <unistd.h>
#include <stdio.h>

int main()
{
    setbuf(stdout, NULL);
    pid_t pid;
    pid = fork();
    if(pid == 0){
        printf("child pid: %d\n", getpid());
        while(1){
            sleep(1);
            printf("child\n");
        }
    } else {
        printf("father pid %d\n", getpid());
        while(1){
            sleep(1);
            printf("father\n");
        }
    }

}
```

<!-- 截图：image-20210226222721364（在线版图片，未随附） -->

<!-- 截图：image-20210226222813661（在线版图片，未随附） -->

从ps的结果可以看到，我们的程序创建了两个进程，两个进程属于同一个进程组，PGID为29938

现在我们kill 掉进程组leader 29938

```
kill -9 29938
```

<!-- 截图：image-20210226222942077（在线版图片，未随附） -->

<!-- 截图：image-20210226222927773（在线版图片，未随附） -->

当我们kill掉进程leader之后，立马father就不打印了，但是child依旧在打印，这说明父进程被杀死，子进程还活着，接下来看看子进程活得怎么样

<!-- 截图：image-20210226223055774（在线版图片，未随附） -->

好家伙，父进程被杀死后，子进程直接把PPID设置为1，但是进程组PGID依旧没变，还是29938 ，session的id SID也没有发生变化，还是29756

此时这个子进程被称为孤儿进程

**这里我们就需要注意了，一个木马或者后门如果主进程还存在子进程，仅仅 kill -9 pid 杀死主进程可能是没用的，因为不会杀死子进程**

> 问题来了，如果我想把这些木马病毒进程都干掉，怎么操作？

我见过各种骚操作，有的是写脚本，有的是手动挨个杀，用killall、pkill等等，这种回复一看就是没遇到那种进程pid，进程名称一直变化的

其实非常简单，我们只需要把这个进程组给杀死就好了

```
kill -9 -PGID
```

没有看错，其实就是在 PGID 前面加个减号

> 需要注意的是， `kill -9 -PGID` 配合 `sudo` 使用时，需要将命令修改为以下格式 
> `sudo kill -9 -- -PGID`
> 也可以使用 `pkill` 来完成
> `sudo pkill -g PGID   # 进程组前没有横杠`

实验开始：

<!-- 截图：image-20210226225732404（在线版图片，未随附） -->

可以看到，父子进程都起来了，pid分别为29949和29950

这个时候我们杀掉这个进程组

```
kill -9 -29949
```

<!-- 截图：image-20210226225852999（在线版图片，未随附） -->

<!-- 截图：image-20210226225919158（在线版图片，未随附） -->

<!-- 截图：image-20210226225946565（在线版图片，未随附） -->

可以看到，这个进程组已经没有了，渣都不剩！

**这里一定要注意，你杀的是一个进程组，一定要注意，进程组里是否有正常业务进程，别杀错了**

#### 4. Session

> 其实文章开头我们已经简单提到过了，我们一般讨论的都是shell session，我们打开一个新的终端就会创建一个session，每个session都是由一个或者多个进程组组成的，每个进程组称为 job，这里job不是任务，而叫作业

从描述中可以看出，session管理的范围要比进程组大，打开一个终端，你执行100条命令，只要没有新的session生成（调用 setsid()函数可以生成新的session ），那么这些命令可以通过session进行统一管理，当然最常见的管理方式还是全部杀死，但是这个杀伤力太大了，所以一般不使用，主要还是了解session的概念，从web安全过来的对于session这种机制应该很容易理解

session中的第一个进程（一般是bash）的PID就是session的SID

> 现在大招来了，如何干掉整个session呢？

```
pkill -s SID
```

实验开始

<!-- 截图：image-20210226233653437（在线版图片，未随附） -->

可以看到，fk的SID为29756

```
pkill -e -s 29756
```

<!-- 截图：image-20210226233824696（在线版图片，未随附） -->

可以看到，杀掉了这个SID下的三个进程，分别为 29756, 29957, 29958

-e 参数是现实杀掉了谁,多人性化

<!-- 截图：image-20210227001524118（在线版图片，未随附） -->

可以看到，杀掉了bash进程后，ssh链接就断开了

#### 5. 守护进程(daemon)

> 守护进程这个词经常听到，名字还挺温暖，遗憾的是总是在处理linux挖矿病毒的案例中听到，简直破坏美感
> 守护进程的一个特点就是进程不受任何终端控制

不受任何终端控制这个定义似乎有些模糊，所以我试图去找到一些限定条件，大部分人是这样说的：

- 随系统启动而启动
- 父进程是init，也就是ppid为1
- 在后台运行
- 进程名字通常以字母 d 结束
- ps显示中终端名设置为问号(?)，终端前台进程组ID设置为-1
- 工作目录为 \ （根）

这其中很明显不完全准确，但是也都是基于实际情况分析出来的，所以我一直在纠结后台进程、nohup起的后台进程和守护进程是什么关系，直到遇到了[这篇文章](https://www.cnblogs.com/lvyahui/p/7389554.html)，我觉得才是说的比较透彻的

我直接摘过来：

- 没有控制终端，终端名设置为？号：也就意味着没有 stdin 0 、stdout 1、stderr 2
- 父进程不是用户创建的进程，init进程或者systemd（pid=1）以及用户人为启动的用户层进程一般以pid=1的进程为父进程，而以kthreadd内核进程创建的守护进程以kthreadd为父进程
- 守护进程一般是会话首进程、组长进程。
- 工作目录为/（根），主要是为了防止占用磁盘导致无法卸载磁盘

守护进程在后台默默提供着服务，但是不接受任何终端的管控，没有标准输入、标准输出、标准错误，比较典型的有mysqld， sshd等，当然我们也是可以创建一个守护进程的，步骤如下：

直接摘抄吧：

> `执行一个fork()，之后父进程退出，子进程继续执行。`（结果就是daemon成为了init进程的子进程。）之所以要做这一步是因为下面两个原因：
> 假设daemon是从命令行启动的，父进程的终止会被shell发现，shell在发现之后会显示出另一个shell提示符并让子进程继续在后台运行。
> 子进程被确保不会称为一个进程组组长进程，因为它从其父进程那里继承了进程组ID并且拥有了自己的唯一的进程ID，而这个进程ID与继承而来的进程组ID是不同的，这样才能够成功地执行下面一个步骤。
> `子进程调用setsid()开启一个新回话并释放它与控制终端之间的所有关联关系。`结果就是使子进程: (a)成为新会话的首进程，(b)成为一个新进程组的组长进程，(c)没有控制终端。
> 如果daemon从来没有打开过终端设备，那么就无需担心daemon会重新请求一个控制终端了。如果daemon后面可能会打开一个终端设备，那么必须要采取措施来确保这个设备不会成为控制终端。这可以通过下面两种方式实现：
> 在所有可能应用到一个终端设备上的open()调用中指定O_NOCTTY标记。
> 或者更简单地说，`在setsid()调用之后执行第二个fork()`，然后再次让父进程退出并让孙子进程继续执行。这样就确保了子进程不会称为会话组长，因此根据System V中获取终端的规则，进程永远不会重新请求一个控制终端。（多一个fork()调用不会带来任何坏处。）
> `清除进程的umask以确保当daemon创建文件和目录时拥有所需的权限。`
> `修改进程的当前工作目录，通常会改为根目录（/）。`这样做是有必要的，因为daemon通常会一直运行直至系统关闭为止。如果daemon的当前工作目录为不包含/的文件系统，那么就无法卸载该文件系统。或者daemon可以将工作目录改为完成任务时所在的目录或在配置文件中定义一个目录，只要包含这个目录的文件系统永远不会被卸载即可。
> `关闭daemon从其父进程继承而来的所有打开着的文件描述符。`（daemon可能需要保持继承而来的文件描述的打开状态，因此这一步是可选的或者可变更的。）之所以这样做的原因有很多。由于daemon失去了控制终端并且是在后台运行的，因此让daemon保持文件描述符0（标准输入）、1（标准输出）和2（标准错误）的打开状态毫无意义，因为它们指向的就是控制终端。此外，无法卸载长时间运行的daemon打开的文件所在的文件系统。因此，通常的做法是关闭所有无用的打开着的文件描述符，因为文件描述符是一种有限的资源。
> `在关闭了文件描述符0、1和2之后，daemon通常会打开/dev/null并使用dup2()（或类似的函数）使所有这些描述符指向这个设备。`之所以要这样做是因为下面两个原因：
> 它确保了当daemon调用了在这些描述符上执行I/O的库函数时不会出乎意料地失败。
> 它防止了daemon后面使用描述符1或2打开一个文件的情况，因为库函数会将这些描述符当做标准输出和标准错误来写入数据（进而破坏了原有的数据）。

说了这么多，还是那一个实际的守护进程出来看一下吧，以sshd为例

<!-- 截图：image-20210227002109868（在线版图片，未随附） -->

因为守护进程PPID为1，而且是在单独的进程组、单独的session中，所以PID=PGID=SID，同时终端处值为 ? , 终端前台进程组ID设置为-1

杀死守护进程没啥特别的，该杀杀,当然前提是权限要够

---

> 看到这里已经可以了，基本上知识点都接触到了，下面是我在关于进程相关知识学习过程中思考的一些问题，不解决不舒服那种，无聊的可以看一看

#### 6. dies und das

> ping www.baidu.com & 这种后台进程是不是守护进程

不是

<!-- 截图：image-20210227001745607（在线版图片，未随附） -->

<!-- 截图：image-20210227001724340（在线版图片，未随附） -->

存在标准输出和标准错误

> nohup ping www.baidu.com &

不是

<!-- 截图：image-20210227001957672（在线版图片，未随附） -->

<!-- 截图：image-20210227002012749（在线版图片，未随附） -->

还是存在标准输出，只不过是重定向到 nohup.out中了

> ping www.baidu.com > /dev/null 2>&1 & 更像是守护进程了吗

更像了，但还不是

<!-- 截图：image-20210227002611125（在线版图片，未随附） -->

这种形式确实是不在存在标准输出，标准输出，标准错误，但是PPID还不是1

> 不就是PPID=1吗？ 上代码

```
#include <unistd.h>
#include <stdio.h>

int main()
{
    setbuf(stdout, NULL);
    pid_t pid;
    pid = fork();
    if(pid == 0){
        system("ping www.baidu.com > /dev/null 2>&1 &");
    } else {
        exit(0);
    }
}
```

<!-- 截图：image-20210227003647300（在线版图片，未随附） -->

<!-- 截图：image-20210227003806736（在线版图片，未随附） -->

- 无标准输入、无标准输出、无标准错误
- ppid=1

现在更像是守护进程了，但是PID,PGID,SID还是不相等，终端处值不为 ? , 终端前台进程组ID也不是-1，目录也不是根目录，换句话说还是受到终端的控制。

具体创建一个守护进程的代码网上有的是，自己搜索吧，既有直接使用daemon()函数生成的，也有一步一步按照上面描述去生成的，推荐先看看后者。

> 我们ssh断开链接后session还在吗？

我使用两个终端连接同一个服务器的ssh

<!-- 截图：image-20210227005321850（在线版图片，未随附） -->

可以看到，现在有两个SID，我们使用 1682 这个session来进行执行`ping www.baidu.com`之后ctrl+c 中断，exit退出连接

<!-- 截图：image-20210227005536377（在线版图片，未随附） -->

我们使用1731的shell来查看

<!-- 截图：image-20210227005616720（在线版图片，未随附） -->

SID为1682的session不存在了，ping 的命令也被我们中断了

现在我们还是使用两个终端连接ssh

<!-- 截图：image-20210227005808055（在线版图片，未随附） -->

我们使用 1788的shell来执行 **ping www.baidu.com &** 之后exit退出ssh连接

<!-- 截图：image-20210227005924647（在线版图片，未随附） -->

<!-- 截图：image-20210227010013753（在线版图片，未随附） -->

从这里可以看到，虽然我们把ssh连接退出了，但是后台进行依旧在这个session上执行，还属于这个会话，所以如果session存在还在执行的后台进程，即使关闭终端或者断开ssh等远程连接，session还是会存在的

> nohup 命令意义难道仅仅就是将标准输出，标准错误重定向到 nohup.out 吗？

如果仅仅是输出重定向，我们可以直接使用 > ，为什么会有nohup命令呢？没有点啥重要作用也对不起这个名字呀！

其实呢，产生这个疑问的主要原因就是问题5我们仅仅从表面现象就得出了结论，而没有进行本质上的剖析，所以如果只看到问题5的哥们儿可能要被误导了...

当一个终端关闭或者ssh等远程连接退出的时候，系统会向session管理的所有进程发送一个SIGHUP信号，这个信号就是挂断的意思，效果就是进程中断，理论上问题5中 ping www.baidu.com 这个后台进程也应该能够收到，但是，在session要断开这种情况是否给属于session的后台进程发送SIGHUP信号是受系统一个配置参数控制的——**huponexit** ，**一般情况下，这个参数的缺省是off，也就是说，关闭终端不一定就会收到SIGHUP信号。**

```
shopt | grep huponexit
```

<!-- 截图：image-20210227011903069（在线版图片，未随附） -->

可以看到，在当前系统中，该参数为off，所以才会出现终端关闭或者ssh等远程连接断开的时候，后台进程能够继续以这个session运行

此时再说 nohup 应该就很清晰了，nohup其实就是忽略SIGHUP信号，这样保证我们的程序在后台平稳执行

> tmux 后台执行的效果更好，tmux的底层原理是什么呢？

还是使用两个终端来进行

<!-- 截图：image-20210227012342968（在线版图片，未随附） -->

<!-- 截图：image-20210227012534451（在线版图片，未随附） -->

```
ctrl b+d 
tmux ls
```

<!-- 截图：image-20210227012623477（在线版图片，未随附） -->

我们使用另一个终端观察一下：

<!-- 截图：image-20210227012821282（在线版图片，未随附） -->

可以看到，其实tmux创建了一个守护进程，进程PID=1348，之后通过守护进程创建 bash，之后通过bash执行ping，创建ping www.baidu.com

为了更加严谨证实这个观点，我们再创建一个tmux任务

<!-- 截图：image-20210227013334133（在线版图片，未随附） -->

<!-- 截图：image-20210227013138835（在线版图片，未随附） -->

现在是ping百度和新浪同时跑着，再观察一下

<!-- 截图：image-20210227013250696（在线版图片，未随附） -->

中间STAT为Zs的进程是因为我忘了截图，就退出了重新来的导致的，不用关注

可以看到的是，对于每一个任务，tmux都会创建一个新的session、进程组、进程，这样实现多个进程之间互不影响

至此，关于Linux的进程相关知识应该将明白了，如果想从更加底层去分析，就去学习学习C和汇编吧！

---

参考文章

https://www.cnblogs.com/lvyahui/p/7389554.html

https://wudaijun.com/2016/08/linux-job-control/

https://zhuanlan.zhihu.com/p/80439267

http://www.ruanyifeng.com/blog/2016/02/linux-daemon.html

https://blog.csdn.net/weicao1990/article/details/78639549

http://www.ruanyifeng.com/blog/2016/03/systemd-tutorial-commands.html

https://segmentfault.com/a/1190000022770900

https://segmentfault.com/q/1010000000310278

https://blog.csdn.net/hust_sheng/article/details/50766752

https://segmentfault.com/a/1190000022097240

https://ytlee.cn/2020/05/the-difference-between-daemon-and-background-process/

https://www.cnblogs.com/lvyahui/p/7389554.html

https://www.jianshu.com/p/eed75164334d

https://www.lujun9972.win/blog/2019/08/26/%E5%A6%82%E4%BD%95kill%E6%95%B4%E4%B8%80%E4%B8%AA%E8%BF%9B%E7%A8%8B%E7%BB%84%E6%88%96%E4%BC%9A%E8%AF%9D/index.html

### 0x02 Linux 启动项默认情况

【ubuntu server 16.04 64位】

```
systemctl list-unit-files --type=service | grep enabled
```

<!-- 截图：image-20210512113829200（在线版图片，未随附） -->

```
/etc/rc.local  
```

<!-- 截图：image-20210512114034756（在线版图片，未随附） -->

- /etc/rc.d/rc.local  无这个文件
- /etc/rc.d/init.d/   无这个文件
- chkconfig --list    无这个命令
- /etc/bashrc  无这个文件
- ~/.bash_profile 无这个文件

```
/etc/profile
```

<!-- 截图：image-20210512114631244（在线版图片，未随附） -->

```
~/.bashrc
```

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

```
~/.profile
```

<!-- 截图：image-20210512115351631（在线版图片，未随附） -->

```
~/.bash_logout
```

<!-- 截图：image-20210512115522315（在线版图片，未随附） -->

【Ubuntu Server 22.04 】`/etc/profile.d/*` 默认情况

<!-- 截图：image-20250227130805403（在线版图片，未随附） -->

```
/etc/profile.d/01-locale-fix.sh
```

<!-- 截图：image-20250227131004758（在线版图片，未随附） -->

```
/etc/profile.d/apps-bin-path.sh
```

```
# shellcheck shell=sh

# Expand $PATH to include the directory where snappy applications go.
snap_bin_path="/snap/bin"
if [ -n "${PATH##*${snap_bin_path}}" ] && [ -n "${PATH##*${snap_bin_path}:*}" ]; then
    export PATH="$PATH:${snap_bin_path}"
fi

# Ensure base distro defaults xdg path are set if nothing filed up some
# defaults yet.
if [ -z "$XDG_DATA_DIRS" ]; then
    export XDG_DATA_DIRS="/usr/local/share:/usr/share"
fi

# Desktop files (used by desktop environments within both X11 and Wayland) are
# looked for in XDG_DATA_DIRS; make sure it includes the relevant directory for
# snappy applications' desktop files.
snap_xdg_path="/var/lib/snapd/desktop"
if [ -n "${XDG_DATA_DIRS##*${snap_xdg_path}}" ] && [ -n "${XDG_DATA_DIRS##*${snap_xdg_path}:*}" ]; then
    export XDG_DATA_DIRS="${XDG_DATA_DIRS}:${snap_xdg_path}"
fi
```

<!-- 截图：image-20250227131111998（在线版图片，未随附） -->

```
/etc/profile.d/bash_completion.sh
```

```
# shellcheck shell=sh disable=SC1091,SC2039,SC2166
# Check for interactive bash and that we haven't already been sourced.
if [ "x${BASH_VERSION-}" != x -a "x${PS1-}" != x -a "x${BASH_COMPLETION_VERSINFO-}" = x ]; then

    # Check for recent enough version of bash.
    if [ "${BASH_VERSINFO[0]}" -gt 4 ] ||
        [ "${BASH_VERSINFO[0]}" -eq 4 -a "${BASH_VERSINFO[1]}" -ge 2 ]; then
        [ -r "${XDG_CONFIG_HOME:-$HOME/.config}/bash_completion" ] &&
            . "${XDG_CONFIG_HOME:-$HOME/.config}/bash_completion"
        if shopt -q progcomp && [ -r /usr/share/bash-completion/bash_completion ]; then
            # Source completion code.
            . /usr/share/bash-completion/bash_completion
        fi
    fi

fi
```

<!-- 截图：image-20250227131320059（在线版图片，未随附） -->

```
/etc/profile.d/gawk.csh 
```

```
alias gawkpath_default 'unsetenv AWKPATH; setenv AWKPATH `gawk -v x=AWKPATH "BEGIN {print ENVIRON[x]}"`'

alias gawkpath_prepend 'if (! $?AWKPATH) setenv AWKPATH ""; if ($AWKPATH == "") then; unsetenv AWKPATH; setenv AWKPATH `gawk -v x=AWKPATH "BEGIN {print ENVIRON[x]}"`; endif; setenv AWKPATH "\!*"":$AWKPATH"'

alias gawkpath_append 'if (! $?AWKPATH) setenv AWKPATH ""; if ($AWKPATH == "") then; unsetenv AWKPATH; setenv AWKPATH `gawk -v x=AWKPATH "BEGIN {print ENVIRON[x]}"`; endif; setenv AWKPATH "$AWKPATH"":\!*"'

alias gawklibpath_default 'unsetenv AWKLIBPATH; setenv AWKLIBPATH `gawk -v x=AWKLIBPATH "BEGIN {print ENVIRON[x]}"`'

alias gawklibpath_prepend 'if (! $?AWKLIBPATH) setenv AWKLIBPATH ""; if ($AWKLIBPATH == "") then; unsetenv AWKLIBPATH; setenv AWKLIBPATH `gawk -v x=AWKLIBPATH "BEGIN {print ENVIRON[x]}"`; endif; setenv AWKLIBPATH "\!*"":$AWKLIBPATH"'

alias gawklibpath_append 'if (! $?AWKLIBPATH) setenv AWKLIBPATH ""; if ($AWKLIBPATH == "") then; unsetenv AWKLIBPATH; setenv AWKLIBPATH `gawk -v x=AWKLIBPATH "BEGIN {print ENVIRON[x]}"`; endif; setenv AWKLIBPATH "$AWKLIBPATH"":\!*"'
```

<!-- 截图：image-20250227131355030（在线版图片，未随附） -->

```
/etc/profile.d/gawk.sh
```

```
gawkpath_default () {
    unset AWKPATH
    export AWKPATH=`gawk 'BEGIN {print ENVIRON["AWKPATH"]}'`
}

gawkpath_prepend () {
    [ -z "$AWKPATH" ] && AWKPATH=`gawk 'BEGIN {print ENVIRON["AWKPATH"]}'`
    export AWKPATH="$*:$AWKPATH"
}

gawkpath_append () {
    [ -z "$AWKPATH" ] && AWKPATH=`gawk 'BEGIN {print ENVIRON["AWKPATH"]}'`
    export AWKPATH="$AWKPATH:$*"
}

gawklibpath_default () {
    unset AWKLIBPATH
    export AWKLIBPATH=`gawk 'BEGIN {print ENVIRON["AWKLIBPATH"]}'`
}

gawklibpath_prepend () {
    [ -z "$AWKLIBPATH" ] && \
        AWKLIBPATH=`gawk 'BEGIN {print ENVIRON["AWKLIBPATH"]}'`
    export AWKLIBPATH="$*:$AWKLIBPATH"
}

gawklibpath_append () {
    [ -z "$AWKLIBPATH" ] && \
        AWKLIBPATH=`gawk 'BEGIN {print ENVIRON["AWKLIBPATH"]}'`
    export AWKLIBPATH="$AWKLIBPATH:$*"
}
```

<!-- 截图：image-20250227131531558（在线版图片，未随附） -->

```
cat /etc/profile.d/Z97-byobu.sh
```

```
#    Z97-byobu.sh - allow any user to opt into auto-launching byobu
#    Copyright (C) 2011 Canonical Ltd.
#
#    Authors: Dustin Kirkland <kirkland@byobu.org>
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, version 3 of the License.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.

# Allow any user to opt into auto-launching byobu by setting LC_BYOBU=1
# Apologies for borrowing the LC_BYOBU namespace, but:
#  a) it's reasonable to assume that no one else is using LC_BYOBU
#  b) LC_* is sent and receieved by most /etc/ssh/ssh*_config

if [ -r "/usr/bin/byobu-launch" ]; then
    if [ "$LC_BYOBU" = "0" ]; then
        true
    elif [ "$LC_BYOBU" = "1" ]; then
        . /usr/bin/byobu-launch
    elif [ -e "/etc/byobu/autolaunch" ]; then
        . /usr/bin/byobu-launch
    elif [ "$LC_TERMTYPE" = "byobu" ]; then
        . /usr/bin/byobu-launch
    elif [ "$LC_TERMTYPE" = "byobu-screen" ]; then
        export BYOBU_BACKEND="screen"
        . /usr/bin/byobu-launch
    elif [ "$LC_TERMTYPE" = "byobu-tmux" ]; then
        export BYOBU_BACKEND="tmux"
        . /usr/bin/byobu-launch
    fi
fi

# vi: syntax=sh ts=4 noexpandtab
```

<!-- 截图：image-20250227131639080（在线版图片，未随附） -->

```
/etc/profile.d/Z99-cloudinit-warnings.sh
```

```
#!/bin/sh
# This file is part of cloud-init. See LICENSE file for license information.

# Purpose: show user warnings on login.

cloud_init_warnings() {
    command -v local >/dev/null && local _local="local" ||
        typeset _local="typeset"
    $_local warning="" idir="/var/lib/cloud/instance" n=0
    $_local warndir="$idir/warnings"
    $_local ufile="$HOME/.cloud-warnings.skip" sfile="$warndir/.skip"
    [ -d "$warndir" ] || return 0
    [ ! -f "$ufile" ] || return 0
    [ ! -f "$sfile" ] || return 0

    for warning in "$warndir"/*; do
        [ -f "$warning" ] || continue
        cat "$warning"
        n=$((n+1))
    done
    [ $n -eq 0 ] && return 0
    echo ""
    echo "Disable the warnings above by:"
    echo "  touch $ufile"
    echo "or"
    echo "  touch $sfile"
}

cloud_init_warnings 1>&2
unset cloud_init_warnings
```

<!-- 截图：image-20250227131734261（在线版图片，未随附） -->

```
/etc/profile.d/Z99-cloud-locale-test.sh
```

```
#!/bin/sh
# Copyright (C) 2012, Canonical Group, Ltd.
#
# Author: Ben Howard <ben.howard@canonical.com>
# Author: Scott Moser <scott.moser@ubuntu.com>
# (c) 2012, Canonical Group, Ltd.
#
# This file is part of cloud-init. See LICENSE file for license information.

# Purpose: Detect invalid locale settings and inform the user
#  of how to fix them.

locale_warn() {
    command -v local >/dev/null && local _local="local" ||
        typeset _local="typeset"

    $_local bad_names="" bad_lcs="" key="" val="" var="" vars="" bad_kv=""
    $_local w1 w2 w3 w4 remain

    # if shell is zsh, act like sh only for this function (-L).
    # The behavior change will not permanently affect user's shell.
    [ "${ZSH_NAME+zsh}" = "zsh" ] && emulate -L sh

    # locale is expected to output either:
    # VARIABLE=
    # VARIABLE="value"
    # locale: Cannot set LC_SOMETHING to default locale
    while read -r w1 w2 w3 w4 remain; do
        case "$w1" in
            locale:) bad_names="${bad_names} ${w4}";;
            *)
                key=${w1%%=*}
                val=${w1#*=}
                val=${val#\"}
                val=${val%\"}
                vars="${vars} $key=$val";;
        esac
    done
    for bad in $bad_names; do
        for var in ${vars}; do
            [ "${bad}" = "${var%=*}" ] || continue
            val=${var#*=}
            [ "${bad_lcs#* ${val}}" = "${bad_lcs}" ] &&
                bad_lcs="${bad_lcs} ${val}"
            bad_kv="${bad_kv} $bad=$val"
            break
        done
    done
    bad_lcs=${bad_lcs# }
    bad_kv=${bad_kv# }
    [ -n "$bad_lcs" ] || return 0

    printf "_____________________________________________________________________\n"
    printf "WARNING! Your environment specifies an invalid locale.\n"
    printf " The unknown environment variables are:\n   %s\n" "$bad_kv"
    printf " This can affect your user experience significantly, including the\n"
    printf " ability to manage packages. You may install the locales by running:\n\n"

    $_local bad invalid="" to_gen="" sfile="/usr/share/i18n/SUPPORTED"
    $_local local pkgs=""
    if [ -e "$sfile" ]; then
        for bad in ${bad_lcs}; do
            grep -q -i "${bad}" "$sfile" &&
                to_gen="${to_gen} ${bad}" ||
                invalid="${invalid} ${bad}"
        done
    else
        printf "  sudo apt-get install locales\n"
        to_gen=$bad_lcs
    fi
    to_gen=${to_gen# }

    $_local pkgs=""
    for bad in ${to_gen}; do
        pkgs="${pkgs} language-pack-${bad%%_*}"
    done
    pkgs=${pkgs# }

    if [ -n "${pkgs}" ]; then
        printf "   sudo apt-get install ${pkgs# }\n"
        printf "     or\n"
        printf "   sudo locale-gen ${to_gen# }\n"
        printf "\n"
    fi
    for bad in ${invalid}; do
        printf "WARNING: '${bad}' is an invalid locale\n"
    done

    printf "To see all available language packs, run:\n"
    printf "   apt-cache search \"^language-pack-[a-z][a-z]$\"\n"
    printf "To disable this message for all users, run:\n"
    printf "   sudo touch /var/lib/cloud/instance/locale-check.skip\n"
    printf "_____________________________________________________________________\n\n"

    # only show the message once
    : > ~/.cloud-locale-test.skip 2>/dev/null || :
}

[ -f ~/.cloud-locale-test.skip -o -f /var/lib/cloud/instance/locale-check.skip ] ||
    locale 2>&1 | locale_warn

unset locale_warn
```

<!-- 截图：image-20250227131921902（在线版图片，未随附） -->

<!-- 截图：image-20250227131941701（在线版图片，未随附） -->

【Centos 7 64位】

```
systemctl list-unit-files --type=service | grep enabled
```

<!-- 截图：image-20210512144917157（在线版图片，未随附） -->

```
abrt-ccpp.service                             enabled 
abrt-oops.service                             enabled 
abrt-vmcore.service                           enabled 
abrt-xorg.service                             enabled 
abrtd.service                                 enabled 
accounts-daemon.service                       enabled 
atd.service                                   enabled 
auditd.service                                enabled 
autovt@.service                               enabled 
avahi-daemon.service                          enabled 
bluetooth.service                             enabled 
chronyd.service                               enabled 
crond.service                                 enabled 
cups.service                                  enabled 
dbus-org.bluez.service                        enabled 
dbus-org.fedoraproject.FirewallD1.service     enabled 
dbus-org.freedesktop.Avahi.service            enabled 
dbus-org.freedesktop.ModemManager1.service    enabled 
dbus-org.freedesktop.nm-dispatcher.service    enabled 
display-manager.service                       enabled 
dmraid-activation.service                     enabled 
firewalld.service                             enabled 
gdm.service                                   enabled 
getty@.service                                enabled 
initial-setup-reconfiguration.service         enabled 
irqbalance.service                            enabled 
iscsi.service                                 enabled 
kdump.service                                 enabled 
libstoragemgmt.service                        enabled 
lvm2-monitor.service                          enabled 
mdmonitor.service                             enabled 
microcode.service                             enabled 
ModemManager.service                          enabled 
multipathd.service                            enabled 
NetworkManager-dispatcher.service             enabled 
NetworkManager-wait-online.service            enabled 
NetworkManager.service                        enabled 
postfix.service                               enabled 
qemu-guest-agent.service                      enabled 
rhel-autorelabel-mark.service                 enabled 
rhel-autorelabel.service                      enabled 
rhel-configure.service                        enabled 
rhel-dmesg.service                            enabled 
rhel-domainname.service                       enabled 
rhel-import-state.service                     enabled 
rhel-loadmodules.service                      enabled 
rhel-readonly.service                         enabled 
rngd.service                                  enabled 
rpcbind.service                               enabled 
rsyslog.service                               enabled 
rtkit-daemon.service                          enabled 
smartd.service                                enabled 
sysstat.service                               enabled 
systemd-readahead-collect.service             enabled 
systemd-readahead-drop.service                enabled 
systemd-readahead-replay.service              enabled 
tuned.service                                 enabled 
udisks2.service                               enabled 
vdo.service                                   enabled 
vgauthd.service                               enabled 
vmtoolsd.service                              enabled 
```

```
/etc/rc.local 
```

<!-- 截图：6b9b962e2316208009830248.jpg（在线版图片，未随附） -->

```
/etc/rc.d/rc.local
```

<!-- 截图：ecc5c91c7a16208010073677.jpg（在线版图片，未随附） -->

```
/etc/rc.d/init.d/
```

<!-- 截图：f607b4c38916208010405441.jpg（在线版图片，未随附） -->

```
chkconfig --list
```

<!-- 截图：d6e3b5a14216208011017800.jpg（在线版图片，未随附） -->

```
/etc/profile
```

<!-- 截图：image-20210512144739901（在线版图片，未随附） -->

```
# /etc/profile

# System wide environment and startup programs, for login setup
# Functions and aliases go in /etc/bashrc

# It's NOT a good idea to change this file unless you know what you
# are doing. It's much better to create a custom.sh shell script in
# /etc/profile.d/ to make custom changes to your environment, as this
# will prevent the need for merging in future updates.

pathmunge () {
    case ":${PATH}:" in
        *:"$1":*)
            ;;
        *)
            if [ "$2" = "after" ] ; then
                PATH=$PATH:$1
            else
                PATH=$1:$PATH
            fi
    esac
}


if [ -x /usr/bin/id ]; then
    if [ -z "$EUID" ]; then
        # ksh workaround
        EUID=`/usr/bin/id -u`
        UID=`/usr/bin/id -ru`
    fi
    USER="`/usr/bin/id -un`"
    LOGNAME=$USER
    MAIL="/var/spool/mail/$USER"
fi

# Path manipulation
if [ "$EUID" = "0" ]; then
    pathmunge /usr/sbin
    pathmunge /usr/local/sbin
else
    pathmunge /usr/local/sbin after
    pathmunge /usr/sbin after
fi

HOSTNAME=`/usr/bin/hostname 2>/dev/null`
HISTSIZE=1000
if [ "$HISTCONTROL" = "ignorespace" ] ; then
    export HISTCONTROL=ignoreboth
else
    export HISTCONTROL=ignoredups
fi

export PATH USER LOGNAME MAIL HOSTNAME HISTSIZE HISTCONTROL

# By default, we want umask to get set. This sets it for login shell
# Current threshold for system reserved uid/gids is 200
# You could check uidgid reservation validity in
# /usr/share/doc/setup-*/uidgid file
if [ $UID -gt 199 ] && [ "`/usr/bin/id -gn`" = "`/usr/bin/id -un`" ]; then
    umask 002
else
    umask 022
fi

for i in /etc/profile.d/*.sh /etc/profile.d/sh.local ; do
    if [ -r "$i" ]; then
        if [ "${-#*i}" != "$-" ]; then 
            . "$i"
        else
            . "$i" >/dev/null
        fi
    fi
done

unset i
unset -f pathmunge
```

```
/etc/bashrc
```

<!-- 截图：d4e0e0c00d16208014529248.jpg（在线版图片，未随附） -->

```
~/.bashrc
```

<!-- 截图：063c00937e16208015223792.jpg（在线版图片，未随附） -->

```
~/.bash_profile
```

<!-- 截图：9325a57ee716208015420563.jpg（在线版图片，未随附） -->

- ~/.profile  无这个文件

```
~/.bash_logout
```

<!-- 截图：d4aea7e12916208015878427.jpg（在线版图片，未随附） -->

【Rocky Linux 9.1】`/etc/profile.d/*` 默认情况

<!-- 截图：image-20250227132559187（在线版图片，未随附） -->

```
/etc/profile.d/bash_completion.sh
```

```
# shellcheck shell=sh disable=SC1091,SC2039,SC2166
# Check for interactive bash and that we haven't already been sourced.
if [ "x${BASH_VERSION-}" != x -a "x${PS1-}" != x -a "x${BASH_COMPLETION_VERSINFO-}" = x ]; then

    # Check for recent enough version of bash.
    if [ "${BASH_VERSINFO[0]}" -gt 4 ] ||
        [ "${BASH_VERSINFO[0]}" -eq 4 -a "${BASH_VERSINFO[1]}" -ge 2 ]; then
        [ -r "${XDG_CONFIG_HOME:-$HOME/.config}/bash_completion" ] &&
            . "${XDG_CONFIG_HOME:-$HOME/.config}/bash_completion"
        if shopt -q progcomp && [ -r /usr/share/bash-completion/bash_completion ]; then
            # Source completion code.
            . /usr/share/bash-completion/bash_completion
        fi
    fi

fi
```

<!-- 截图：image-20250227132818677（在线版图片，未随附） -->

```
/etc/profile.d/bash_completion.sh
```

```
# shellcheck shell=sh disable=SC1091,SC2039,SC2166
# Check for interactive bash and that we haven't already been sourced.
if [ "x${BASH_VERSION-}" != x -a "x${PS1-}" != x -a "x${BASH_COMPLETION_VERSINFO-}" = x ]; then

    # Check for recent enough version of bash.
    if [ "${BASH_VERSINFO[0]}" -gt 4 ] ||
        [ "${BASH_VERSINFO[0]}" -eq 4 -a "${BASH_VERSINFO[1]}" -ge 2 ]; then
        [ -r "${XDG_CONFIG_HOME:-$HOME/.config}/bash_completion" ] &&
            . "${XDG_CONFIG_HOME:-$HOME/.config}/bash_completion"
        if shopt -q progcomp && [ -r /usr/share/bash-completion/bash_completion ]; then
            # Source completion code.
            . /usr/share/bash-completion/bash_completion
        fi
    fi

fi
[root@localhost ~]# cat /etc/profile.d/colorgrep.csh 

# color-grep initialization

/usr/libexec/grepconf.sh -c
if ( $status == 1 ) then
    exit
endif

alias grep 'grep --color=auto'
alias egrep 'egrep --color=auto'
alias fgrep 'fgrep --color=auto'
```

<!-- 截图：image-20250227132932651（在线版图片，未随附） -->

```
/etc/profile.d/colorgrep.sh
```

```
# color-grep initialization

/usr/libexec/grepconf.sh -c
if ( $status == 1 ) then
    exit
endif

alias grep 'grep --color=auto'
alias egrep 'egrep --color=auto'
alias fgrep 'fgrep --color=auto'
[root@localhost ~]# cat /etc/profile.d/colorgrep.sh 
# color-grep initialization

/usr/libexec/grepconf.sh -c || return

alias grep='grep --color=auto' 2>/dev/null
alias egrep='egrep --color=auto' 2>/dev/null
alias fgrep='fgrep --color=auto' 2>/dev/null
```

<!-- 截图：image-20250227133010674（在线版图片，未随附） -->

```
/etc/profile.d/colorls.csh
```

```
# color-grep initialization

/usr/libexec/grepconf.sh -c || return

alias grep='grep --color=auto' 2>/dev/null
alias egrep='egrep --color=auto' 2>/dev/null
alias fgrep='fgrep --color=auto' 2>/dev/null
[root@localhost ~]# cat /etc/profile.d/colorls.csh 
# skip everything for non-interactive shells
if (! $?prompt) exit

# color-ls initialization
if ( $?USER_LS_COLORS ) then
  if ( "$USER_LS_COLORS" != "" ) then
     #when USER_LS_COLORS defined do not override user
     #specified LS_COLORS and use them
     goto finish
  endif
endif

alias ll 'ls -l'
alias l. 'ls -d .*'
set COLORS=/etc/DIR_COLORS

if ($?TERM) then
  if ( -e "/etc/DIR_COLORS.$TERM" ) then
     set COLORS="/etc/DIR_COLORS.$TERM"
  endif
endif
if ( -f ~/.dircolors ) set COLORS=~/.dircolors
if ( -f ~/.dir_colors ) set COLORS=~/.dir_colors
if ($?TERM) then
  if ( -f ~/.dircolors."$TERM" ) set COLORS=~/.dircolors."$TERM"
  if ( -f ~/.dir_colors."$TERM" ) set COLORS=~/.dir_colors."$TERM"
endif
set INCLUDE="`/usr/bin/cat "$COLORS" | /usr/bin/grep '^INCLUDE' | /usr/bin/cut -d ' ' -f2-`"

if ( ! -e "$COLORS" ) exit

set _tmp="`/usr/bin/mktemp .colorlsXXX -q --tmpdir=/tmp`"
#if mktemp fails, exit when include was active, otherwise use $COLORS file
if ( "$_tmp" == '' ) then
  if ( "$INCLUDE" == '' ) then
    eval "`/usr/bin/dircolors -c $COLORS`"
  endif
  goto cleanup
endif

if ( "$INCLUDE" != '' ) /usr/bin/cat "$INCLUDE" >> $_tmp
/usr/bin/grep -v '^INCLUDE' "$COLORS" >> $_tmp

eval "`/usr/bin/dircolors -c $_tmp`"

/usr/bin/rm -f $_tmp

if ( "$LS_COLORS" == '' ) exit
cleanup:
set color_none=`/usr/bin/sed -n '/^COLOR.*none/Ip' < $COLORS`
if ( "$color_none" != '' ) then
   unset color_none
   exit
endif
unset color_none
unset _tmp
unset INCLUDE
unset COLORS

finish:
alias ll 'ls -l --color=auto'
alias l. 'ls -d .* --color=auto'
alias ls 'ls --color=auto'
```

```
/etc/profile.d/colorls.sh
```

```
# color-ls initialization

# Skip all for noninteractive shells.
[ ! -t 0 ] && return

#when USER_LS_COLORS defined do not override user LS_COLORS, but use them.
if [ -z "$USER_LS_COLORS" ]; then

  alias ll='ls -l' 2>/dev/null
  alias l.='ls -d .*' 2>/dev/null

  INCLUDE=
  COLORS=

  for colors in "$HOME/.dir_colors.$TERM" "$HOME/.dircolors.$TERM" \
      "$HOME/.dir_colors" "$HOME/.dircolors"; do
    [ -e "$colors" ] && COLORS="$colors" && \
    INCLUDE="`/usr/bin/cat "$COLORS" | /usr/bin/grep '^INCLUDE' | /usr/bin/cut -d ' ' -f2-`" && \
    break
  done

  [ -z "$COLORS" ] && [ -e "/etc/DIR_COLORS.$TERM" ] && \
  COLORS="/etc/DIR_COLORS.$TERM"

  [ -z "$COLORS" ] && [ -e "/etc/DIR_COLORS" ] && \
  COLORS="/etc/DIR_COLORS"

  # Existence of $COLORS already checked above.
  [ -n "$COLORS" ] || return

  if [ -e "$INCLUDE" ];
  then
    TMP="`/usr/bin/mktemp .colorlsXXX -q --tmpdir=/tmp`"
    [ -z "$TMP" ] && return

    /usr/bin/cat "$INCLUDE" >> $TMP
    /usr/bin/grep -v '^INCLUDE' "$COLORS" >> $TMP

    eval "`/usr/bin/dircolors --sh $TMP 2>/dev/null`"
    /usr/bin/rm -f $TMP
  else
    eval "`/usr/bin/dircolors --sh $COLORS 2>/dev/null`"
  fi

  [ -z "$LS_COLORS" ] && return
  /usr/bin/grep -qi "^COLOR.*none" $COLORS >/dev/null 2>/dev/null && return
fi

unset TMP COLORS INCLUDE

alias ll='ls -l --color=auto' 2>/dev/null
alias l.='ls -d .* --color=auto' 2>/dev/null
alias ls='ls --color=auto' 2>/dev/null
```

<!-- 截图：image-20250227133220600（在线版图片，未随附） -->

```
/etc/profile.d/colorxzgrep.csh
```

<!-- 截图：image-20250227133350313（在线版图片，未随附） -->

```
/etc/profile.d/colorxzgrep.sh
```

<!-- 截图：image-20250227133416540（在线版图片，未随附） -->

```
/etc/profile.d/colorzgrep.csh
```

<!-- 截图：image-20250227133506536（在线版图片，未随附） -->

```
/etc/profile.d/colorzgrep.sh
```

<!-- 截图：image-20250227133547793（在线版图片，未随附） -->

```
/etc/profile.d/csh.local
```

<!-- 截图：image-20250227133637727（在线版图片，未随附） -->

```
/etc/profile.d/debuginfod.csh
```

<!-- 截图：image-20250227133805237（在线版图片，未随附） -->

```
/etc/profile.d/debuginfod.sh
```

```
# $HOME/.profile* or similar files may first set $DEBUGINFOD_URLS.
# If $DEBUGINFOD_URLS is not set there, we set it from system *.url files.
# $HOME/.*rc or similar files may then amend $DEBUGINFOD_URLS.
# See also [man debuginfod-client-config] for other environment variables
# such as $DEBUGINFOD_MAXSIZE, $DEBUGINFOD_MAXTIME, $DEBUGINFOD_PROGRESS.

if [ -z "$DEBUGINFOD_URLS" ]; then
    prefix="/usr"
    DEBUGINFOD_URLS=$(cat /dev/null "/etc/debuginfod"/*.urls 2>/dev/null | tr '\n' ' ')
    [ -n "$DEBUGINFOD_URLS" ] && export DEBUGINFOD_URLS || unset DEBUGINFOD_URLS
    unset prefix
fi
```

<!-- 截图：image-20250227133841854（在线版图片，未随附） -->

```
/etc/profile.d/flatpak.sh 
```

```
if command -v flatpak > /dev/null; then
    # set XDG_DATA_DIRS to include Flatpak installations

    new_dirs=$(
        (
            unset G_MESSAGES_DEBUG
            echo "${XDG_DATA_HOME:-"$HOME/.local/share"}/flatpak"
            GIO_USE_VFS=local flatpak --installations
        ) | (
            new_dirs=
            while read -r install_path
            do
                share_path=$install_path/exports/share
                case ":$XDG_DATA_DIRS:" in
                    (*":$share_path:"*) :;;
                    (*":$share_path/:"*) :;;
                    (*) new_dirs=${new_dirs:+${new_dirs}:}$share_path;;
                esac
            done
            echo "$new_dirs"
        )
    )

    export XDG_DATA_DIRS
    XDG_DATA_DIRS="${new_dirs:+${new_dirs}:}${XDG_DATA_DIRS:-/usr/local/share:/usr/share}"
fi
```

<!-- 截图：image-20250227133954720（在线版图片，未随附） -->

```
/etc/profile.d/gawk.csh
```

<!-- 截图：image-20250227134039957（在线版图片，未随附） -->

```
/etc/profile.d/gawk.sh
```

```
gawkpath_default () {
    unset AWKPATH
    export AWKPATH=`gawk 'BEGIN {print ENVIRON["AWKPATH"]}'`
}

gawkpath_prepend () {
    [ -z "$AWKPATH" ] && AWKPATH=`gawk 'BEGIN {print ENVIRON["AWKPATH"]}'`
    export AWKPATH="$*:$AWKPATH"
}

gawkpath_append () {
    [ -z "$AWKPATH" ] && AWKPATH=`gawk 'BEGIN {print ENVIRON["AWKPATH"]}'`
    export AWKPATH="$AWKPATH:$*"
}

gawklibpath_default () {
    unset AWKLIBPATH
    export AWKLIBPATH=`gawk 'BEGIN {print ENVIRON["AWKLIBPATH"]}'`
}

gawklibpath_prepend () {
    [ -z "$AWKLIBPATH" ] && \
        AWKLIBPATH=`gawk 'BEGIN {print ENVIRON["AWKLIBPATH"]}'`
    export AWKLIBPATH="$*:$AWKLIBPATH"
}

gawklibpath_append () {
    [ -z "$AWKLIBPATH" ] && \
        AWKLIBPATH=`gawk 'BEGIN {print ENVIRON["AWKLIBPATH"]}'`
    export AWKLIBPATH="$AWKLIBPATH:$*"
}
```

<!-- 截图：image-20250227134117176（在线版图片，未随附） -->

```
/etc/profile.d/lang.csh 
```

```
# /etc/profile.d/lang.csh - exports environment variables, and provides fallback
#                          for CJK languages that can't be displayed in console.
#                          Resets the locale if unavailable.

unset LANG_backup

# If unavailable, reset to the default. Do this before reading in any
# explicit user configuration. We simply check if locale emits any
# warnings, and assume that the settings are invalid if it does.
set locale_error=`(/usr/bin/locale >/dev/null) |& cat`
if ("${locale_error}" != "") then
    if (${?LANG}) then
        setenv LANG C.UTF-8
    endif
    unsetenv LC_ALL
    setenv LC_CTYPE C.UTF-8
    setenv LC_NUMERIC C.UTF-8
    setenv LC_TIME C.UTF-8
    setenv LC_COLLATE C.UTF-8
    setenv LC_MONETARY C.UTF-8
    setenv LC_MESSAGES C.UTF-8
    setenv LC_PAPER C.UTF-8
    setenv LC_NAME C.UTF-8
    setenv LC_ADDRESS C.UTF-8
    setenv LC_TELEPHONE C.UTF-8
    setenv LC_MEASUREMENT C.UTF-8
    setenv LC_IDENTIFICATION C.UTF-8
else
    if (${?LANG}) then
        set LANG_backup=${LANG}
    endif
endif

foreach config (/etc/locale.conf "${HOME}/.i18n")
    if (-f "${config}") then
        # NOTE: We are using eval & sed here to avoid invoking of any commands & functions from those files.
        eval `/usr/bin/sed -r -e 's/^[[:blank:]]*([[:upper:]_]+)=([[:print:][:digit:]\._-]+|"[[:print:][:digit:]\._-]+")/setenv \1 \2;/;t;d' ${config}`
    endif
end

if (${?LANG_backup}) then
    setenv LANG "${LANG_backup}"
endif

unset LANG_backup config locale_error

# ----------------------------------------------

# The LC_ALL is not supposed to be set in /etc/locale.conf according to 'man 5 locale.conf'.
# If it is set, then we expect it is user's explicit override (most likely from ~/.i18n file).
# See 'man 7 locale' for more info about LC_ALL.
if (${?LC_ALL}) then
    if (${?LANG}) then
        if (${LC_ALL} != ${LANG}) then
            setenv LC_ALL
        else
            unsetenv LC_ALL
        endif
    else
        unsetenv LC_ALL
    endif
endif

# The ${LANG} manipulation is necessary only in virtual terminal (a.k.a. console - /dev/tty*):
set in_console=`/usr/bin/tty | /usr/bin/grep -vc -e '/dev/tty'`

if (${?LANG} && ${?TERM}) then
    if (${TERM} == 'linux' && $in_console == 0) then
        set utf8_used=`echo ${LANG} | /usr/bin/grep -vc -E -i -e '^.+\.utf-?8$'`

        if (${utf8_used} == 0) then
            switch (${LANG})
                case en_IN*:
                    breaksw
                case ja*:
                case ko*:
                case si*:
                case zh*:
                case ar*:
                case fa*:
                case he*:
                case *_IN*:
                    setenv LANG en_US.UTF-8
                    breaksw
            endsw
        else
            switch (${LANG})
                case en_IN*:
                    breaksw
                case ja*:
                case ko*:
                case si*:
                case zh*:
                case ar*:
                case fa*:
                case he*:
                case *_IN*:
                    setenv LANG en_US
                    breaksw
            endsw
        endif

        # NOTE: We are not exporting the ${LANG} here again on purpose.
        #       If user starts GUI session from console manually, then
        #       the previously set LANG should be okay to use.
    endif
endif

unset in_console utf8_used
```

```
/etc/profile.d/lang.sh
```

```
# /etc/profile.d/lang.sh - exports environment variables, and provides fallback
#                          for CJK languages that can't be displayed in console.
#                          Resets the locale if unavailable.

unset LANG_backup

# If unavailable, reset to the default. Do this before reading in any
# explicit user configuration. We simply check if locale emits any
# warnings, and assume that the settings are invalid if it does.
if [ -n "$(/usr/bin/locale 2>&1 1>/dev/null)" ]; then
    [ -z "$LANG" ] || LANG=C.UTF-8
    unset LC_ALL
    LC_CTYPE="C.UTF-8"
    LC_NUMERIC="C.UTF-8"
    LC_TIME="C.UTF-8"
    LC_COLLATE="C.UTF-8"
    LC_MONETARY="C.UTF-8"
    LC_MESSAGES="C.UTF-8"
    LC_PAPER="C.UTF-8"
    LC_NAME="C.UTF-8"
    LC_ADDRESS="C.UTF-8"
    LC_TELEPHONE="C.UTF-8"
    LC_MEASUREMENT="C.UTF-8"
    LC_IDENTIFICATION="C.UTF-8"
else
    LANG_backup="${LANG}"
fi

for config in /etc/locale.conf "${HOME}/.i18n"; do
    if [ -f "${config}" ]; then
        # NOTE: We are using eval & sed here to avoid invoking of any commands & functions from those files.
        if [ -x /usr/bin/sed ]; then
            eval $(/usr/bin/sed -r -e 's/^[[:blank:]]*([[:upper:]_]+)=([[:print:][:digit:]\._-]+|"[[:print:][:digit:]\._-]+")/export \1=\2/;t;d' ${config})
        else
            #but if we don't have sed, let's go old way and source it
            [ -f "${config}" ] && . "${config}"
        fi
    fi
done

if [ -n "${LANG_backup}" ]; then
    LANG="${LANG_backup}"
fi

unset LANG_backup config

# ----------------------------------------------

# The LC_ALL is not supposed to be set in /etc/locale.conf according to 'man 5 locale.conf'.
# If it is set, then we we expect it is user's explicit override (most likely from ~/.i18n file).
# See 'man 7 locale' for more info about LC_ALL.
if [ -n "${LC_ALL}" ]; then
    if [ "${LC_ALL}" != "${LANG}" -a -n "${LANG}" ]; then
        export LC_ALL
    else
        unset LC_ALL
    fi
fi

# The ${LANG} manipulation is necessary only in virtual terminal (a.k.a. console - /dev/tty*):
if [ -n "${LANG}" ] && [ "${TERM}" = 'linux' ] && /usr/bin/tty | /usr/bin/grep --quiet -e '/dev/tty'; then
    if /usr/bin/grep --quiet -E -i -e '^.+\.utf-?8$' <<< "${LANG}"; then
        case ${LANG} in
            ja*)    LANG=en_US.UTF-8 ;;
            ko*)    LANG=en_US.UTF-8 ;;
            si*)    LANG=en_US.UTF-8 ;;
            zh*)    LANG=en_US.UTF-8 ;;
            ar*)    LANG=en_US.UTF-8 ;;
            fa*)    LANG=en_US.UTF-8 ;;
            he*)    LANG=en_US.UTF-8 ;;
            en_IN*) true             ;;
            *_IN*)  LANG=en_US.UTF-8 ;;
        esac
    else
        case ${LANG} in
            ja*)    LANG=en_US ;;
            ko*)    LANG=en_US ;;
            si*)    LANG=en_US ;;
            zh*)    LANG=en_US ;;
            ar*)    LANG=en_US ;;
            fa*)    LANG=en_US ;;
            he*)    LANG=en_US ;;
            en_IN*) true       ;;
            *_IN*)  LANG=en_US ;;
        esac
    fi

    # NOTE: We are not exporting the ${LANG} here again on purpose.
    #       If user starts GUI session from console manually, then
    #       the previously set LANG should be okay to use.
fi
```

<!-- 截图：image-20250227134424091（在线版图片，未随附） -->

<!-- 截图：image-20250227134444781（在线版图片，未随附） -->

```
/etc/profile.d/less.csh
```

<!-- 截图：image-20250227134555396（在线版图片，未随附） -->

```
/etc/profile.d/less.sh
```

```
# less initialization script (csh)

# All less.*sh files should have the same semantics!

# In case you are curious, the test for non-emptiness is not as easy as in
# Bourne shell.  This "eval" construct is probably inspired by Stack
# Overflow question 13343392.
if ( $?LESSOPEN && { eval 'test ! -z "$LESSOPEN"' } ) then
    :
else
    if ( -x /usr/bin/lesspipe.sh ) then
        # The '||' here is intentional, see rhbz#1254837.
        setenv LESSOPEN "||/usr/bin/lesspipe.sh %s"
    endif
endif
[root@localhost ~]# cat /etc/profile.d/less.sh 
# less initialization script (sh)

# All less.*sh files should have the same semantics!

if [ -z "$LESSOPEN" ] && [ -x /usr/bin/lesspipe.sh ]; then
    # The '||' here is intentional, see rhbz#1254837.
    export LESSOPEN="||/usr/bin/lesspipe.sh %s"
fi
```

<!-- 截图：image-20250227134652330（在线版图片，未随附） -->

```
/etc/profile.d/PackageKit.sh
```

```
# less initialization script (sh)

# All less.*sh files should have the same semantics!

if [ -z "$LESSOPEN" ] && [ -x /usr/bin/lesspipe.sh ]; then
    # The '||' here is intentional, see rhbz#1254837.
    export LESSOPEN="||/usr/bin/lesspipe.sh %s"
fi
[root@localhost ~]# cat /etc/profile.d/PackageKit.sh 
# Copyright (C) 2008 Richard Hughes <richard@hughsie.com>
#
# Licensed under the GNU General Public License Version 2
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.

command_not_found_handle () {
    local runcnf=1
    local retval=127

    # only search for the command if we're interactive
    [[ $- == *"i"* ]] || runcnf=0

    # don't run if DBus isn't running
    [[ ! -S /run/dbus/system_bus_socket ]] && runcnf=0

    # don't run if packagekitd doesn't exist in the _system_ root
    [[ ! -x '/usr/libexec/packagekitd' ]] && runcnf=0

    # don't run if bash command completion is being run
    [[ -n ${COMP_CWORD-} ]] && runcnf=0

    # don't run if we've been uninstalled since the shell was launched
    [[ ! -x '/usr/libexec/pk-command-not-found' ]] && runcnf=0

    # run the command, or just print a warning
    if [ $runcnf -eq 1 ]; then
        '/usr/libexec/pk-command-not-found' "$@"
        retval=$?
    elif [[ -n "${BASH_VERSION-}" ]]; then
        printf >&2 'bash: %s%s\n' "${1:+$1: }" "$(gettext PackageKit 'command not found')"
    fi

    # return success or failure
    return $retval
}

if [[ -n "${ZSH_VERSION-}" ]]; then
    command_not_found_handler () {
        command_not_found_handle "$@"
    }
fi
```

<!-- 截图：image-20250227134818652（在线版图片，未随附） -->

```
/etc/profile.d/sh.local
```

<!-- 截图：image-20250227134858382（在线版图片，未随附） -->

```
/etc/profile.d/vte.csh
```

```
# Copyright © 2019 Red Hat, Inc.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
# Red Hat Author(s): Carlos Santos

# exit if non-interactive, csh, no terminal or old VTE versions
if ( ! $?prompt | ! $?tcsh | ! $?TERM | ! $?VTE_VERSION ) exit

switch($TERM)
  case xterm*:
    alias precmd 'echo -n "\e]7;file://$HOST"; /usr/libexec/vte-urlencode-cwd; echo -n "\e\\"'
endsw
```

<!-- 截图：image-20250227134954036（在线版图片，未随附） -->

```
/etc/profile.d/vte.sh
```

```
# Copyright © 2012 Christian Persch
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

# Not bash or zsh?
[ -n "${BASH_VERSION:-}" -o -n "${ZSH_VERSION:-}" ] || return 0

# Not an interactive shell?
[[ $- == *i* ]] || return 0

# Not running under vte?
[ "${VTE_VERSION:-0}" -ge 3405 ] || return 0

__vte_osc7 () {
  printf "\033]7;file://%s%s\033\\" "${HOSTNAME}" "$(/usr/libexec/vte-urlencode-cwd)"
}

__vte_prompt_command() {
  local command=$(HISTTIMEFORMAT= history 1 | sed 's/^ *[0-9]\+ *//')
  command="${command//;/ }"
  local pwd='~'
  [ "$PWD" != "$HOME" ] && pwd=${PWD/#$HOME\//\~\/}
  pwd="${pwd//[[:cntrl:]]}"
  printf '\033]777;notify;Command completed;%s\033\\\033]777;precmd\033\\\033]0;%s@%s:%s\033\\' "${command}" "${USER}" "${HOSTNAME%%.*}" "${pwd}"
  __vte_osc7
}

case "$TERM" in
  xterm*|vte*)
    [ -n "${BASH_VERSION:-}" ] && PROMPT_COMMAND="__vte_prompt_command" && PS0=$(printf "\033]777;preexec\033\\")
    [ -n "${ZSH_VERSION:-}"  ] && precmd_functions+=(__vte_osc7)
    ;;
esac

true
```

<!-- 截图：image-20250227135053499（在线版图片，未随附） -->

```
/etc/profile.d/which2.csh 
```

<!-- 截图：image-20250227135145315（在线版图片，未随附） -->

```
/etc/profile.d/which2.sh
```

```
# shellcheck shell=sh
# Initialization script for bash, sh, mksh and ksh

case "$(basename $(readlink /proc/$$/exe))" in
*ksh*)
    which_declare=""
    which_opt=""
    ;;
zsh)
    which_declare="typeset -f"
    which_opt=""
    ;;
bash|sh)
    which_declare="declare -f"
    which_opt="-f"
    ;;
*)
    which_declare=""
    which_opt=""
    ;;
esac

function which {
    (alias; eval ${which_declare}) | /usr/bin/which --tty-only --read-alias --read-functions --show-tilde --show-dot $@
}

export which_declare
export ${which_opt} which
```

<!-- 截图：image-20250227135230680（在线版图片，未随附） -->

### 0x03 SSH隧道

> 隧道跟管子一样，两端都可以作为入口、出口，实验主机分配如下
> 攻击机就用我的物理机 10.211.55.2 
> 被控主机（做隧道的主机）Centos 10.211.55.11
> 访问受限主机 Ubuntu 10.211.55.10

#### 本地转发隧道

Ubuntu 上的apache 服务默认返回页面如下

<!-- 截图：image-20210427093808955（在线版图片，未随附） -->

我们使用一下配置，这样 Ubuntu 主机不允许我们的攻击机直接进行连接

<!-- 截图：image-20210427101554861（在线版图片，未随附） -->

重启apache后，再次访问如下

<!-- 截图：image-20210427094212713（在线版图片，未随附） -->

现在我们通过被控主机 Centos 的 SSH 来做隧道，实现将访问受限的 Ubuntu 的 apache 映射出来

假设我们已经得到了 Centos 的密码（或者将我们的密钥写入进去，通过公钥进行认证）

攻击机（物理机 10.211.55.2）执行

`ssh -fCNg -L 8008:10.211.55.10:80 helper@10.211.55.11 -p 22`

- -f 后台执行
- -N 不需要TTY，即notty
- -C 使用压缩
- -g 设置监听端口为 0.0.0.0 这种形式

<!-- 截图：image-20210427113341111（在线版图片，未随附） -->

现在攻击机直接访问自己的 8008 端口就可以访问到受限主机的 apache 了

<!-- 截图：image-20210427101652876（在线版图片，未随附） -->

可以看到，我们的隧道成功了，已经成功将访问受限的 Ubuntu apache 映射到了攻击机本地

我们看一下Ubuntu上 Apache 的日志 `/var/log/apache2/access.log`

<!-- 截图：image-20210427113504004（在线版图片，未随附） -->

这里可以看到，日志记录的访问IP为受控主机Centos的IP

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

Centos 上执行 `ssh -fCNg -R 8008:10.211.55.10:80 helper@10.211.55.2 -p 22`

<!-- 截图：image-20210428164827049（在线版图片，未随附） -->

我们的攻击机就开放了一个8008端口，访问8008端口就直接访问到访问受限主机 Ubuntu 的80端口

<!-- 截图：image-20210428165147589（在线版图片，未随附） -->

现在我们看一下受控主机Centos存在哪些异常

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

攻击机（物理机）执行

`ssh -fNCg -D 8008 helper@10.211.55.11`

<!-- 截图：image-20210428172514452（在线版图片，未随附） -->

攻击机配置代理

<!-- 截图：image-20210428172704454（在线版图片，未随附） -->

挂上代理访问 Ubuntu 的 80端口

<!-- 截图：image-20210428172753987（在线版图片，未随附） -->

成功访问！

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

### 0x04 线程内存相关信息文件存储位置

我们都知道，Linux 上启动的进程都有一个专属的 `/proc/<pid>/` 这样的目录，目录中存储着相关的信息，比如内存地址，启动的文件等。在之前检查的章节中我们讲述了一些关于线程查看和检查的内容，但是没有讲过线程相关的文件都在什么位置，这里补充上

`/proc/<pid>/task`

这里我们找一些系统默认的多线程的进程

<!-- 截图：image-20211123231606061（在线版图片，未随附） -->

这里以一个 python 相关进程来说，该进程存在两个线程，线程文件夹中内容如下：

<!-- 截图：image-20211123231920775（在线版图片，未随附） -->

<!-- 截图：image-20211123231846562（在线版图片，未随附） -->

和 Linux 中进程的内容基本是一样的,我们也可以通过这些文件获取我们想要的信息

### 0x05 与C&C隐藏技术的对抗

#### 1. 简介

在攻防演练中，使用云函数来隐藏 C&C 的 ip 地址已经成为了一种“标配”

在应急处置过程中，我们经常遇到  `netstat -pantu | grep ip`  无法找到安全设备关于红队外连的告警

由于 C&C 的 ip 地址是一直变化的，所以常规的 `netstat -pantu | grep ip` 这种模式就可能行不通了

以目前国内厂商对云函数的支持来看，主要集中在 80， 443 这两个端口。所以如果要排查的服务器对外访问 80 和 443 不多的情况下还是可以一个一个分析的

但这终究是个麻烦事，所以有了今天的这篇文章

> 我们对抗云函数的方式无非就是从 DNS 解析下手
> 但是 Linux 默认的程序组合几乎无法实时获取到究竟是哪一个发起了解析了云函数的域名的 DNS 请求
> 所以，我们需要人工干预一下，将云函数的网站的解析地址换成我们自己的地址，之后通过筛连接了我们指定的地址的 80 或者 443 端口的进程，获取到 pid 后再获取进程详细信息

#### 2. 查看 DNS 缓存记录

如果是 windows ，这件事是非常简单的，在 Linux 中就变得麻烦很多，我们需要使用下面的命令来进行获取 DNS 缓存记录

```
sudo killall -USR1 systemd-resolved
sudo journalctl -u systemd-resolved > ~/dns-cache.txt
cat ~/dns-cache.txt | grep tencentcs.com
```

如果攻击者使用了云函数，那么应该会保存 DNS 的解析记录，我们只需要将常见的云函数的网站地址作为筛选条件进行筛选即可，这里以腾讯云的云函数为例

常见云函数、CDN之类的网站地址有：

```
tencentcs.com
herokuapp.com
worker.dev
*.tk
```

假设获取到的域名为 `service-123456.bj.tencentcs.com`

#### 3. 服务器配置监控程序

> 当服务器对我们的监听端口发起了连接，就将发起连接的进程相关信息记录下来
> 此处 VPS ip 以 1.1.1.1 为例

```
#!/bin/bash


while true
do  
    sleep 0.1
    pids=$(netstat -pantu | grep 1.1.1.1 | awk -F "/" '{print $1}' | awk -F " " '{print $NF}' | sort | uniq)
    for one_pid in $pids
    do
        if [ $one_pid == "-" ]; then 
            continue
        fi

        echo "" >> $(pwd)/virus_info.txt
        echo "[ lsof -p $one_pid ]" >> $(pwd)/virus_info.txt
        lsof -p $one_pid >> $(pwd)/virus_info.txt
        echo "" >> $(pwd)/virus_info.txt
        echo "[ cat /proc/$one_pid/maps -w ]" >> $(pwd)/virus_info.txt
        cat /proc/$one_pid/maps -w >> $(pwd)/virus_info.txt
        echo "" >> $(pwd)/virus_info.txt
        echo "[ ls -al /proc/$one_pid/exe ]" >> $(pwd)/virus_info.txt
        ls -al /proc/$one_pid/exe >> $(pwd)/virus_info.txt
    done
    if [ -f "$(pwd)/virus_info.txt" ]; then
        echo "Found it !"
        exit
    fi    
done
```

<!-- 截图：image-20220702225004670（在线版图片，未随附） -->

#### 4. 修改 HOSTS 文件，建立解析记录

root 用户下执行，VPS IP 以 `1.1.1.1` 为例

```
echo "1.1.1.1 service-123456.bj.tencentcs.com" >> /etc/hosts
```

<!-- 截图：image-20220702224718834（在线版图片，未随附） -->

> Linux 的 hosts 文件是不支持通配符的，也就是配置 `*.tencentcs.com` 是无效的
> 所以，如果在 0x01 步未获取到云函数的具体域名，那就需要借助 Dnsmasq 这类程序或者外部网络设备来进行辅助，原理是一样的

#### 5. VPS 上建立监听

```
mkdir listen_test
cd listen_test
python3 -m http.server 80
python3 -m http.server 443
```

#### 6. 使用 nmap 模拟对 VPS 的访问

<!-- 截图：image-20220702230406383（在线版图片，未随附） -->

`virus_info.txt` 文件内容如下

```
[ lsof -p 20657 ]
COMMAND   PID USER   FD   TYPE DEVICE SIZE/OFF    NODE NAME
nmap    20657 root  cwd    DIR    8,2     4096  524291 /home/join
nmap    20657 root  rtd    DIR    8,2     4096       2 /
nmap    20657 root  txt    REG    8,2  2961432  798351 /usr/bin/nmap
nmap    20657 root  mem    REG    8,2    47568 1581433 /lib/x86_64-linux-gnu/libnss_files-2.27.so
nmap    20657 root  mem    REG    8,2    97176 1581430 /lib/x86_64-linux-gnu/libnsl-2.27.so
nmap    20657 root  mem    REG    8,2    47576 1581435 /lib/x86_64-linux-gnu/libnss_nis-2.27.so
nmap    20657 root  mem    REG    8,2    39744 1581431 /lib/x86_64-linux-gnu/libnss_compat-2.27.so
nmap    20657 root  mem    REG    8,2   445768  798342 /usr/lib/x86_64-linux-gnu/blas/libblas.so.3.7.1
nmap    20657 root  mem    REG    8,2    14560 1581426 /lib/x86_64-linux-gnu/libdl-2.27.so
nmap    20657 root  mem    REG    8,2   144976 1581438 /lib/x86_64-linux-gnu/libpthread-2.27.so
nmap    20657 root  mem    REG    8,2  2030928 1581423 /lib/x86_64-linux-gnu/libc-2.27.so
nmap    20657 root  mem    REG    8,2    96616 1581418 /lib/x86_64-linux-gnu/libgcc_s.so.1
nmap    20657 root  mem    REG    8,2  1700792 1581427 /lib/x86_64-linux-gnu/libm-2.27.so
nmap    20657 root  mem    REG    8,2  1594864  796948 /usr/lib/x86_64-linux-gnu/libstdc++.so.6.0.25
nmap    20657 root  mem    REG    8,2    59408  798344 /usr/lib/x86_64-linux-gnu/liblinear.so.3.2.
nmap    20657 root  mem    REG    8,2   224048  798347 /usr/lib/x86_64-linux-gnu/liblua5.3.so.0.0.0
nmap    20657 root  mem    REG    8,2   116960 1573720 /lib/x86_64-linux-gnu/libz.so.1.2.11
nmap    20657 root  mem    REG    8,2  2917216  792886 /usr/lib/x86_64-linux-gnu/libcrypto.so.1.1
nmap    20657 root  mem    REG    8,2   577312  792985 /usr/lib/x86_64-linux-gnu/libssl.so.1.1
nmap    20657 root  mem    REG    8,2   265344  792967 /usr/lib/x86_64-linux-gnu/libpcap.so.1.8.1
nmap    20657 root  mem    REG    8,2   464824 1573695 /lib/x86_64-linux-gnu/libpcre.so.3.13.3
nmap    20657 root  mem    REG    8,2   179152 1581419 /lib/x86_64-linux-gnu/ld-2.27.so
nmap    20657 root    0u   CHR  136,1      0t0       4 /dev/pts/1
nmap    20657 root    1u   CHR  136,1      0t0       4 /dev/pts/1
nmap    20657 root    2u   CHR  136,1      0t0       4 /dev/pts/1
nmap    20657 root    3r   CHR    5,0      0t0      13 /dev/tty
nmap    20657 root    4u  IPv4 169623      0t0     TCP ubuntu:43930->service-123456.bj.tencentcs.com:domain (SYN_SENT)

[ cat /proc/20657/maps -w ]
55c0e5298000-55c0e53e6000 r-xp 00000000 08:02 798351                     /usr/bin/nmap
55c0e55e6000-55c0e55eb000 r--p 0014e000 08:02 798351                     /usr/bin/nmap
55c0e55eb000-55c0e576b000 rw-p 00153000 08:02 798351                     /usr/bin/nmap
55c0e576b000-55c0e5792000 rw-p 00000000 00:00 0 
55c0e66b7000-55c0e6c37000 rw-p 00000000 00:00 0                          [heap]
7fe9f2ccb000-7fe9f2cd6000 r-xp 00000000 08:02 1581433                    /lib/x86_64-linux-gnu/libnss_files-2.27.so
7fe9f2cd6000-7fe9f2ed5000 ---p 0000b000 08:02 1581433                    /lib/x86_64-linux-gnu/libnss_files-2.27.so
...
...
7fe9f5d65000-7fe9f5d66000 rw-p 0002a000 08:02 1581419                    /lib/x86_64-linux-gnu/ld-2.27.so
7fe9f5d66000-7fe9f5d67000 rw-p 00000000 00:00 0 
7ffee5382000-7ffee53a3000 rw-p 00000000 00:00 0                          [stack]
7ffee53a9000-7ffee53ac000 r--p 00000000 00:00 0                          [vvar]
7ffee53ac000-7ffee53ae000 r-xp 00000000 00:00 0                          [vdso]
ffffffffff600000-ffffffffff601000 r-xp 00000000 00:00 0                  [vsyscall]

[ ls -al /proc/20657/exe ]
lrwxrwxrwx 1 root root 0 Jul  2 15:03 /proc/20657/exe -> /usr/bin/nmap
```

我们可以获取到以下信息：

- 进程 pid 为 `20657`
- 启这个进程的二进制文件为 `/usr/bin/nmap`
- 启这个进程的时候攻击者所在的目录为 `/home/join`
- 启这个进程的用户为 `root`

### 0x06 history 无记录的可能原因

- 攻击者清空日志文件内容
- 攻击者通过设置权限或者环境变量配置为不记录日志
- 攻击者使用 `history -c` 等清空 history 缓冲区
- SSH 等远程登录过程中网络中断，导致没有将缓冲区写入到文件
- 攻击者执行命令时在前面加了一个空格
- 攻击者使用各种编程语言解析器，在编程语言代码中执行命令

<!-- 截图：bf44c67691image-20210417091202101.png（在线版图片，未随附） -->

有态度，不苟同！
