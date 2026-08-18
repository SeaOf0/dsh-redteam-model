# 故障排查

本文件承接 `SKILL.md` 中完整的诊断流程，覆盖通用诊断和 Go stager 专项诊断。

---

## 诊断 0：确认使用的模式

- **`gostager` 模式不上线** → 优先检查诊断 7（Go stager 专项）
- **`createthread` 等嵌入式模式** → 按诊断 1-6 依次排查

## 诊断 1：进程是否存在

- **进程不存在** → 大概率崩溃，检查 API 调用参数数量（尤其是 NT API）
- **进程存在但不上线** → shellcode 没执行，检查内存权限和注入地址

常见崩溃原因：
- SyscallN 参数数量错误
- DLL 名/API 名 XOR 编码解码错误导致 LoadLibrary/GetProcAddress 返回 0
- VirtualAlloc 返回 0（内存分配失败，检查大小和权限参数）

## 诊断 2：检查内存权限

最常见原因：SGN 与 heapalloc 不兼容。

- **SGN 启用了但用了 heapalloc？** → SGN 解码器是自修改代码，需要 `PAGE_EXECUTE_READWRITE`，heapalloc 不保证 RWX 权限
- **SGN 启用了但 VirtualAlloc 用了 PAGE_EXECUTE_READ？** → 改为 `0x40` (PAGE_EXECUTE_READWRITE)
- **内存分配器返回 0？** → 检查 VirtualAlloc 调用参数是否正确

对照 `references/techniques.md` 确认当前注入方式的内存权限要求。

## 诊断 3：逐步关闭模块

按以下顺序去掉模块，每次重新打包测试，定位问题模块：

1. 去掉 NTDLL 脱钩 → 重新打包 → 测试
2. 去掉 Sleep 内存加密 → 重新打包 → 测试
3. 去掉 SGN 编码 → 用 raw shellcode + VirtualAlloc 测试
4. 只剩 ETW bypass + AMSI bypass + 抗沙箱 + VirtualAlloc → 此组合已验证稳定

逐步测试的目的：确认是哪个模块导致的不上线，而非一次性把所有模块都关掉。

## 诊断 4：检查抗沙箱误杀

检查用户运行环境是否满足抗沙箱检测的触发条件：

- CPU 核心数阈值是否过低？（目标环境核心数可能不满阈值）
- 物理内存阈值是否过高？（低配置虚拟机可能不满足）
- 路径检测是否误匹配了正常路径特征？

**修复方式：** 临时关闭抗沙箱模块，单独测试。确认是误杀后调整阈值或维度组合（推荐 CPU 核心数 + 物理内存，最不易误杀）。

## 诊断 5：检查 API 调用参数

嵌入式模式使用 `syscall.SyscallN` 调 Windows API，参数数量错误是常见崩溃原因。对照 `references/techniques.md` 确认每个 API 的参数数量。

## 诊断 6：检查 XOR 编码正确性

XOR 编码手算错误是导致不上线的最常见原因。

- 用 Python 验证 Go 源码中所有 XOR 编码是否能正确还原为目标合法字符串
- 手算 XOR 出错 → LoadLibrary/GetProcAddress 返回 0 → 程序静默退出
- **必须用脚本计算，禁止手算**
- 检查方式：运行编译前验证的检查项 6（见 `references/verification.md`）

---

## 诊断 7：`gostager` 模式不上线

仅适用于 CS stager（`cs-http` / `cs-https`）。

### 7A: CS stager（`cs-http` / `cs-https`）不上线

#### 7A-a. 检查 CS weblog 是否有请求记录

- **有请求记录但不上线** → 下载成功但执行失败，继续检查 7A-b ~ 7A-d
- **无请求记录** → URL/端口/网络问题，先确认 C2 可达性

#### 7A-b. 检查反射加载器偏移

- 优先重跑 `<python命令> <skill_dir>/scripts/parse_stager.py <stager.bin>` 核对 `entry_offset`
- 如 `entry_offset` 缺失或为 `0`，先确认输入是否为有效 CS stager，再继续后续排查
- 确认 `CreateThread` 执行地址是 `addr + offset`，不是 `addr`

#### 7A-c. 检查响应数据处理

- CS HTTP listener 返回 raw beacon DLL，**无 4 字节 size header**
- `fetchBeacon()` 应直接返回 `body`，不要 `body[4:]`
- 验证 `len(body) >= 0x1000`（beacon DLL 至少几十 KB）
- 下载数据过小（< 4KB）说明响应可能不是 beacon DLL

#### 7A-d. 检查 HTTP 请求是否匹配 CS profile

- User-Agent 必须和 `parse_stager.py` 输出的 `user_agent` 一致
- 优先使用 `parse_stager.py` 输出的 `headers` 对齐 CS profile（尤其是 `http-stager.client` 的自定义 header/cookie）
- `headers` 为空时，不做手工臆造，先以最小请求头验证连通性

---

---

## 诊断 8：嵌入式模式常见坑点（代码生成器相关）

以下是从实际调试中总结的、`gen_all.py` 动态生成的 Go 代码中容易出错的点。

### 8A: MEMORYSTATUSEX 结构体大小

**现象：** 所有 EXE 静默退出，进程瞬间消失。

**根因：** `GlobalMemoryStatusEx` 的 `MEMORYSTATUSEX` 结构体在 Windows x64 下固定 64 字节，但 Go struct 只定义了 40 字节（`_ [24]byte` 尾部填充不足）。API 写入 64 字节到 40 字节栈缓冲区，覆盖相邻栈变量和返回地址，导致崩溃。

**修复：** 尾部填充改为 `_ [48]byte`（总计 4 + 4 + 8 + 48 = 64 字节）。

```go
// 错误（40 字节）
type ms struct { l uint32; _ uint32; phys uint64; _ [24]byte }
// 正确（64 字节）
type ms struct { l uint32; _ uint32; phys uint64; _ [48]byte }
```

### 8B: MapViewOfFile 缺少执行权限

**现象：** `mapping` 模式进程不崩溃但不弹 calc，CreateThread 静默失败。

**根因：** `MapViewOfFile` 的 `dwDesiredAccess` 参数用了 `FILE_MAP_WRITE (0x2)`，只有写权限没有执行权限。即使 `CreateFileMappingW` 创建时指定了 `PAGE_EXECUTE_READWRITE (0x40)`，视图的访问权限仍受 `dwDesiredAccess` 限制。

**修复：** 使用 `FILE_MAP_WRITE | FILE_MAP_EXECUTE = 0x22`。

```go
// 错误
addr, _, _ := syscall.SyscallN(pMVF, hMap, 0x2, 0, 0, uintptr(size))
// 正确
addr, _, _ := syscall.SyscallN(pMVF, hMap, 0x22, 0, 0, uintptr(size))
```

### 8C: Process Hollowing — CONTEXT 结构体偏移错误

**现象：** `processhollowing` 模式进程不弹 calc。

**两个 bug：**

1. **ContextFlags 写入偏移错误** — x64 CONTEXT 结构中 `ContextFlags` 字段在偏移 `0x30`，代码错误地写到了偏移 `0x00`（覆盖了 `P1Home`）。导致 `GetThreadContext` 认为不需要填充任何寄存器。

2. **PEB 基址读取偏移错误** — 挂起进程的 x64 线程中，PEB 地址存储在 `Rdx` 寄存器（CONTEXT 偏移 `0x88`），代码错误地读取了 `Rcx`（偏移 `0x80`）。

**修复：**

```go
// 错误
ctx[0] = 0x00; ctx[1] = 0x00; ctx[2] = 0x10; ctx[3] = 0x00  // 写到 P1Home
syscall.SyscallN(pRPM, ..., uintptr(*(*uint64)(unsafe.Pointer(&ctx[0x80])))+0x10, ...)  // 读 Rcx

// 正确
*(*uint32)(unsafe.Pointer(&ctx[0x30])) = 0x10001F  // ContextFlags 正确偏移
syscall.SyscallN(pRPM, ..., uintptr(*(*uint64)(unsafe.Pointer(&ctx[0x88])))+0x10, ...)  // 读 Rdx
```

### 8D: User32 回调 API 与 GUI 子系统冲突

**现象：** `EnumWindows` / `EnumDisplayMonitors` 回调模式的 EXE 不弹 calc。

**根因：** Go 编译使用了 `-H windowsgui`（GUI 子系统），程序没有消息队列和窗口站。`EnumWindows` 和 `EnumDisplayMonitors` 依赖 user32.dll 的窗口基础设施，在没有窗口站的进程中回调永远不会被触发。

**修复：** 回调执行技术应优先使用 kernel32.dll 的枚举 API（不依赖窗口站）：
- `EnumSystemLocalesW` — 系统区域枚举
- `EnumTimeFormatsW` — 时间格式枚举
- `EnumCalendarInfoW` — 日历信息枚举

这些 API 枚举的是系统全局数据，不需要窗口基础设施，在任何子系统中都能正常工作。

---

## 模式分流建议

**体积分诊优先（避免无效 Python 调用）：**

| 体积 | 动作 |
|------|------|
| < 5KB | 运行 `parse_stager.py` → 成功则 `gostager`，失败则嵌入式 |
| 5KB ~ 100KB | 运行 `parse_stager.py` 尝试解析，失败回退嵌入式 |
| > 100KB | 跳过解析，直接嵌入式模式 |

分流优先级：
1. 先看文件体积，> 100KB 直接跳过 `parse_stager.py`（省一次调用）
2. 体积 < 100KB 时运行 `parse_stager.py`，检查 `json.type` 是否有有效输出
3. 解析成功 → 优先 `gostager`（CS HTTP 下载 + 反射加载）
4. 解析失败 → 走嵌入式模式（可选技术见 `references/techniques.md`，默认推荐 `createthread` + SGN 作为稳定基准）
5. 若体积判断与解析结果冲突，以"解析是否成功 + 实测结果"为准，不只依赖体积阈值
