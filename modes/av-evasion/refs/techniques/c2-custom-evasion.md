---
name: c2-custom-evasion
description: C2二开免杀综合技能 - C2框架二次开发、自定义Beacon/Implant、协议规避、免杀集成
---

# C2二开免杀 (C2 Custom Development + Evasion)

C2框架二开与免杀集成的综合技能，覆盖从架构设计到implant开发的完整生命周期。

## 核心架构

```
+------------------+     +------------------+     +------------------+
|   Teamserver     |     |   Redirector     |     |   Target Host    |
|   (Operator)     |<--->|   (Relay/CDN)    |<--->|   Beacon/Implant |
+------------------+     +------------------+     +------------------+
        |                        |                        |
   - Session mgmt          - TLS termination         - Sleep cycle
   - Task queue            - Domain fronting         - Command dispatch
   - Logging               - Traffic shaping         - Plugin loading
   - Listener config       - Certificate mgmt        - Memory protection
```

## 生命周期

1. **基础设施部署** - Teamserver部署、域名注册、重定向器配置
2. **Listener配置** - 协议选择、证书配置、Profile定制
3. **Stager生成** - 载荷编码、分阶段下载、初始执行
4. **Beacon/Implant运行** - 回连、任务接收、结果返回
5. **后渗透操作** - 权限提升、横向移动、数据外泄
6. **撤离清理** - 痕迹清除、日志清理、会话关闭

## 设计原则

- **模块化** - 组件解耦，便于替换和升级
- **加密** - 全链路加密，静态和传输数据保护
- **OPSEC** - 最小化主机和网络指纹
- **弹性** - 降级机制、多通道备份、自动重连
- **隐蔽性** - 流量伪装、内存保护、行为模拟

## 技能文件索引

| 文件 | 内容 | 关键技术 |
|------|------|----------|
| [C2_ARCHITECTURE.md](./C2_ARCHITECTURE.md) | C2框架架构与改造 | 框架扩展、协议设计、Malleable C2 |
| [BEACON_DEVELOPMENT.md](./BEACON_DEVELOPMENT.md) | Beacon/Implant开发 | 内存执行、Sleep混淆、插件系统 |
| [STAGER_LOADER.md](./STAGER_LOADER.md) | Stager与Loader开发 | Shellcode执行、反射加载、格式转换 |
| [PROTOCOL_EVASION.md](./PROTOCOL_EVASION.md) | 协议层免杀 | JA3伪装、域前置、云API滥用 |
| [OPSEC_HARDENING.md](./OPSEC_HARDENING.md) | OPSEC加固 | 内存扫描规避、日志抑制、清理规程 |

## MITRE ATT&CK 技术映射

| 战术 | 技术 | ID |
|------|------|----|
| Command & Control | Application Layer Protocol: Web Protocols | T1071.001 |
| Command & Control | Application Layer Protocol: DNS | T1071.004 |
| Command & Control | Encrypted Channel: Symmetric Cryptography | T1573.001 |
| Command & Control | Proxy: Multi-hop Proxy | T1090.003 |
| Command & Control | Non-Application Layer Protocol | T1095 |
| Command & Control | Data Encoding: Standard Encoding | T1132.001 |
| Defense Evasion | Obfuscated Files or Information | T1027 |
| Defense Evasion | Process Injection | T1055 |
| Defense Evasion | Reflective Code Loading | T1620 |
| Defense Evasion | Modify System Binary | T1544 |
| Defense Evasion | Indicator Removal: Clear Logs | T1070.001 |
| Execution | Shared Modules | T1129 |
| Execution | User Execution | T1204 |

## 开发技术栈

### Beacon/Implant开发
- **C/C++** - 底层控制、系统API调用、位置无关代码
- **Rust** - 内存安全、交叉编译、小体积二进制
- **Go** - 快速开发、内置网络库、交叉编译
- **C#/.NET** - 内存加载、Assembly执行、Windows集成
- **Nim** - 跨平台、元编程、AV规避友好

### 基础设施
- **Python** - Teamserver逻辑、自动化脚本
- **Go** - 高并发Listener、重定向器
- **Nginx/Caddy** - TLS终止、流量转发、域前置

### 支持工具
- **Donut** - .NET Assembly到Shellcode转换
- **COFFLoader** - COFF/BOF加载
- **SyscallStubs** - 直接系统调用生成
- **Frida** - 动态检测和测试

## 快速参考

### 典型C2通信流

```
Operator --> Teamserver --> Listener --> Redirector --> Target
                                            |
                                     [TLS + Domain Front]
                                            |
                                     Beacon checks in
                                            |
                                     Task assigned
                                            |
                                     Beacon executes
                                            |
                                     Results returned
```

### 指纹规避检查清单

- [ ] JA3/JA3S指纹匹配正常浏览器
- [ ] HTTP头顺序和值匹配目标浏览器
- [ ] TLS证书无异常（非自签名或匹配域）
- [ ] DNS查询模式正常（无异常频率）
- [ ] Beacon间隔有随机抖动
- [ ] 数据包大小在正常范围
- [ ] 进程链看起来正常
- [ ] 内存中没有明文特征
- [ ] 磁盘无持久化文件（除非需要）
- [ ] 网络连接看起来合法
