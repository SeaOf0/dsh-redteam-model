# IPC 与持久化控制面还原（Service · 计划任务 · WMI · RPC · ALPC · Named Pipe · COM LocalServer）

## 命中信号

- `ServiceMain`
- `schtasks`
- `WMI`
- `NamedPipe`
- `RPC`
- `ALPC`
- `COM LocalServer`

## 最小目标

1. 列出控制面载体
2. 建立 `launcher -> registrar -> writer -> reader -> use` 链路
3. 明确权限、会话、触发条件
4. 落盘 `artifacts/<样本哈希>/ipc-persistence-notes.md`、`artifacts/<样本哈希>/ipc-surface.md`、`artifacts/<样本哈希>/persistence-map.md`

## 静态观察

- 先看服务、计划任务、WMI、COM 注册、命名对象、互斥体和事件
- 区分"启动器""存储点""通信载体""真正执行业务的一侧"

## 动态取证

- NamedPipe/RPC/ALPC 先抓服务端创建点，再抓客户端使用点
- 服务和计划任务要同时记录注册路径、启动条件、命令行和宿主进程
- WMI / COM 先判提供者/类厂/LocalServer，不要只盯注册表

## 还原与修补

- 先复现最小控制面消息流，再决定 patch 还是旁路
- 若控制面跨多进程，先记录每个进程的角色，再做局部验证

## 常见失误

- 把单个注册表项直接等同于完整持久化链
- 只看 IPC 载体名称，不看读写双方和真实消息结构
- 忽略 Session/Integrity/Service Account 导致复现失败
