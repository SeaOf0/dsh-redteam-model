# Beacon / Implant 开发（BEACON_DEVELOPMENT）

> 本文件为 `c2-custom-evasion.md` 技能文件索引的伴生手册（补齐断链）。
> 覆盖 Beacon/Implant 的**内存执行 → Sleep 混淆 → 插件系统 → 检测侧 → 实测判据**。
> 授权立场见 `refs/README.md`；实现细节交叉引用 `ADVANCED_EVASION.md`。

## 1. 内存执行（In-Memory Execution）

```c
// Beacon 核心：任务经加密通道下发 -> 解密 -> 内存执行 -> 结果加密回传
// 关键：任务 payload 不落盘，直接 VirtualAlloc(RW) -> 解密 -> RX -> 执行
// 执行方式按 OPSEC 等级选择：直接调用 / 回调 / 间接 syscall（见 ADVANCED_EVASION.md §1）
```

## 2. Sleep 混淆

```c
// 睡眠期加密 beacon 自身内存，规避内存扫描
// 三方案：Ekko（TimerQueue+ROP）/ Foliage（APC）/ DeathSleep（线程去注册）
// 实现见 ADVANCED_EVASION.md §2
```

**内存扫描规避要点**：睡眠期 payload 区域呈密文；唤醒前解密；加密密钥只存在于寄存器/栈（不留明文堆）。

## 3. 插件系统（Plugin System）

```text
+------------------+
| Beacon 核心      |
|  - 通信/加密/睡眠 |
+------------------+
   |  动态加载
+--+--+   +--+--+
| 模块A |  | 模块B |   <- 反射加载/BOF 执行，按需下发
+-----+   +-----+
```

- **反射加载**：插件 DLL 转 shellcode 内存加载（sRDI/donut）。
- **BOF/COFF**：编译为对象文件，beacon 内解析符号执行（更小、更隐蔽）。
- **按需下发**：只下发任务所需模块，最小化驻留面。

## 4. 检测侧

| 环节 | 检测点 | 判据 |
|---|---|---|
| 内存执行 | 私有 RX + 匿名执行 | 内存保护属性 + 栈回溯 |
| sleep 混淆 | 睡眠期加密 | 内存快照熵突变 |
| 插件 | 反射加载/BOF 特征 | 自定义 loader + 无文件模块 |

## 5. 实测判据

| 判据 | 方法 |
|---|---|
| 内存是否干净 | 睡眠期内存扫描是否出现明文 beacon 特征 |
| 插件是否隐蔽 | 反射加载后模块列表无异常、无落盘 |

*WARNING: 授权红队评估与安全研究专用。*
