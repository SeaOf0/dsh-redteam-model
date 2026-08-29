# C/C++ 审计 Sink 大表（按类型）

> 与其他语言表同形态；深度手册见 `code-audit-c-cpp.md`。C/C++ 的 sink 本质是**内存破坏
> 原语**——本表与 RCE 主线「溢出导致 RCE」类直接对应（可控性判定+缓解机制判定）。

## 1. 栈溢出原语（STACK）

**Sink**：
- `strcpy(` / `strcat(` / `sprintf(` / `vsprintf(`（无界写）
- `gets(`（无界读入栈缓冲）
- `scanf("%s"` / `sscanf(` 无宽度限定
- `alloca(`（用户长度）
- 数组局部变量 + 循环写越界（`for` 边界来自报文长度字段）

**危险模式**：长度字段/报文头进上述函数；off-by-one（`<=` 边界）。

**强制验证**：`strncpy/strlcpy/snprintf` + 显式宽度；边界 `<=` 改 `<`。

## 2. 堆溢出与整数溢出（HEAP/INT）

**Sink**：
- `malloc(n * m)`（乘法溢出→小分配大写入：`n*m` 回绕 32 位）
- `memcpy(dst, src, len)`（len 不可信/来自报文字段）
- `realloc(` 后指针未更新；`new[]`/`delete` 错配
- 显式长度运算：`uint32_t size = header.len + offset;`（回绕后绕过检查）

**危险模式**：**先检查后使用**的长度与后续使用不一致（TOCTOU 型整数检查绕过）。

**强制验证**：溢出前饱和检查（`if (len > MAX - offset)`）；memcpy 前双界校验。

## 3. 格式化字符串（FMT）

**Sink**：
- `printf(user)` / `fprintf(f, user)` / `syslog(user)` / `snprintf(buf, n, user)`
- 日志宏把报文原文当格式串（`LOG_ERR(msg)` 形态）

**危险模式**：格式串可控（`%n` 可写=任意写原语；`%x` 泄露栈/指针→绕 ASLR）。

**强制验证**：格式串字面量固定（`printf("%s", user)`）。

## 4. 命令注入（CMD）

**Sink**：
- `system(`（串拼接）
- `popen(`（同型）
- `execl/execlp/execve(`（参数拼接；`execlp` 走 PATH 搜索——路径劫持面）
- `ShellExecute(`（Win）

**强制验证**：参数数组 + 无 shell；PATH 固定。

## 5. 文件与路径（FILE）

**Sink**：
- `fopen(`（路径拼接）/ `open(`（TOCTOU：`access(` 检查后 `open(`——符号链接竞态）
- 临时文件：`tmpnam(`/`mktemp(`（可预测→symlink 劫持；用 `mkstemp`）

**强制验证**：realpath 校验；`O_NOFOLLOW`；`mkstemp`。

## 6. XXE 与 XML（XXE）

**Sink**：
- libxml2：`xmlReadFile/xmlReadMemory(`（默认解析配置核对——`XML_PARSE_NOENT` 开启时
  实体展开+外部实体=XXE；DTD 加载选项）
- `xmlParseFile(` 老接口
- expat：外部实体 handler 注册态核对

**强制验证**：禁 DTD/外部实体（libxml2 ≥2.9 默认关，配置被显式打开的必查）。

## 7. 释放后使用与双释放（UAF）

**Sink**：
- `free(ptr)` 后续读写 ptr（生命周期跨函数/回调/线程的指针）
- 双 `free(`（allocator 元数据破坏）
- C++：`delete` 后成员调用；智能指针循环引用（泄漏面，低危如实标注）

**强制验证**：free 后置 NULL；所有权明确（RAII/唯一持有）；双链追踪对象生命周期。

## 8. TOCTOU 与竞态（RACE）

**Sink**：
- `stat/access` 后 `open`（文件系统竞态）
- 全局/静态变量跨线程无锁（信号 handler 中调用非 async-signal-safe 函数）

**强制验证**：以 open 返回的 fd 为准（打开后 `fstat`）；锁覆盖共享面。

## 9. 缓解机制判定（MITIGATION）

**判定要点**（决定溢出类 finding 是「理论」还是「可利用」）：
- **NX/DEP**：栈不可执行→需 ROP；
- **Canary**：栈溢出需先泄露 canary（格式化串/infoleak 组合链）；
- **ASLR/PIE**：需信息泄露固定地址（与 FMT 节联动）；
- **RELRO**：GOT 改写可行性（Partial RELRO 下 GOT 覆盖=控制流劫持捷径）。

**产出要求**：溢出类 finding 的利用性条件全列（缓解开况组合→定级），缺条件降
「有条件 RCE」——与 RCE 主线硬要求一致。
