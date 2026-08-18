---
name: code-audit-c-cpp
description: >
  C/C++ 应用安全代码审计完整手册 — 覆盖缓冲区溢出、格式化字符串、整数溢出、UAF/
  double-free、堆溢出、栈溢出、类型混淆、竞态条件 (TOCTOU)、注入漏洞、
  不安全库函数、密码学误用等全部内存安全与逻辑漏洞类型，
  攻防合一：Part A 攻击视角漏洞模式 + ASan/UBSan/Valgrind/gdb/Checksec/pwntools，
  Part B 安全编码 + 编译器加固 (-fstack-protector, PIE, RELRO, Fortify) + 检测规则，
  内置 C/C++ 漏洞速查矩阵和 exploit 缓解措施对照表。
domain: cybersecurity
subdomain: code-audit
tags: [c, cpp, code-audit, memory-safety, buffer-overflow, format-string, exploit-mitigation]
version: 2.0.0
---

# C/C++ 应用安全代码审计 — 完整攻防手册

## 适用场景

- C/C++ 系统软件、网络服务、嵌入式固件安全审计
- 二进制漏洞挖掘与利用开发辅助
- 内存安全漏洞检测（栈/堆/格式化字符串/整数溢出）
- **不适用**：Java/C#/Python 等托管语言（见各自审计手册）

## 前置条件

- GCC 12+ / Clang 15+ / Make / CMake
- 工具：ASan / UBSan / Valgrind / Checksec / pwntools / GDB + GEF/pwndbg
- 理解 x86/x64/ARM 汇编基础

---

## Part A：攻击视角 — 漏洞模式与审计方法

### 1. 缓冲区溢出审计

**栈溢出：**

```c
// ❌ gets() — 无长度限制（经典栈溢出）
char buf[64];
gets(buf);  // CWE-120

// ❌ scanf 无宽度限制
char name[32];
scanf("%s", name);  // 无边界检查

// ❌ strcpy 无长度检查
char dst[64];
strcpy(dst, user_input);  // 溢出

// ✅ 安全替代
char buf[64];
fgets(buf, sizeof(buf), stdin);  // 限制长度

char name[32];
scanf("%31s", name);  // 宽度限制

strncpy(dst, user_input, sizeof(dst) - 1);
dst[sizeof(dst) - 1] = '\0';

// ✅ 更好：strlcpy (BSD) / snprintf
snprintf(dst, sizeof(dst), "%s", user_input);
```

**堆溢出：**

```c
// ❌ 堆上无边界写
char *buf = malloc(64);
strcpy(buf, user_input);  // 堆溢出 → 可能覆盖堆元数据

// ✅ calloc + 长度检查
size_t len = strlen(user_input);
if (len >= 64) return ERROR;
char *buf = calloc(1, 64);
memcpy(buf, user_input, len);
```

**审计 grep：**

```bash
grep -rn 'gets(\|scanf("%s"\|strcpy(\|strcat(\|sprintf(\|vsprintf(' --include='*.c' --include='*.cpp' --include='*.h' . | grep -v 'test\|_test\|#define.*strncpy'
grep -rn 'memcpy(\|memmove(\|realloc(' --include='*.c' --include='*.cpp' . | grep -v 'sizeof\|test'
```

### 2. 格式化字符串漏洞

```c
// ❌ 用户输入直接作为格式化字符串
printf(user_input);            // 任意内存读/写
fprintf(fp, user_data);
syslog(LOG_ERR, user_msg);

// ✅ 固定格式字符串
printf("%s", user_input);
fprintf(fp, "%s", user_data);
syslog(LOG_ERR, "%s", user_msg);
```

**利用方式：**
- `%x` — 栈内存泄露
- `%s` — 任意地址读（指针解引用）
- `%n` — 任意地址写（写入已打印字节数）
- `%hn` / `%hhn` — 2字节/1字节写入

**审计 grep：**

```bash
grep -rn 'printf([A-Za-z_][A-Za-z0-9_]*)\b' --include='*.c' --include='*.cpp' . | grep -v '"%s"\|"%d"\|test\|format'
grep -rn 'fprintf\|sprintf\|snprintf\|syslog\|err\|warn' --include='*.c' --include='*.cpp' . | grep -v '"%'
```

### 3. 整数溢出/下溢

```c
// ❌ 未检查乘法溢出
int size = count * element_size;  // count=2^30, element_size=4 → 溢出
buf = malloc(size);  // 分配远小于预期的内存

// ❌ 符号扩展
int len = get_length();  // 返回 -1 (0xFFFFFFFF)
memcpy(dst, src, (size_t)len);  // 变成 0xFFFFFFFFFFFFFFFF

// ❌ 无符号下溢
unsigned int remaining = total - consumed;  // consumed > total → 回绕

// ✅ 安全检查
#include <limits.h>
if (count > 0 && element_size > SIZE_MAX / count) {
    return ERROR_OVERFLOW;
}
size_t size = (size_t)count * element_size;

// ✅ 编译器内置
if (__builtin_mul_overflow(count, element_size, &size)) {
    return ERROR_OVERFLOW;
}
```

**审计 grep：**

```bash
grep -rn 'malloc(.*\*\|calloc(.*\*\|realloc(.*\+' --include='*.c' --include='*.cpp' . | grep -v 'sizeof\|test'
grep -rn 'size_t.*=\|unsigned.*-' --include='*.c' --include='*.cpp' . | grep -v 'test\|_min\|_max'
```

### 4. Use-After-Free / Double-Free

```c
// ❌ Use-After-Free
free(ptr);
// ... 其他代码 ...
*ptr = value;  // UAF — ptr 已释放

// ❌ Double-Free
free(ptr);
free(ptr);  // double-free → 堆元数据损坏

// ✅ free 后置 NULL
free(ptr);
ptr = NULL;
// 后续使用前检查
if (ptr != NULL) { *ptr = value; }

// ✅ C++ RAII（智能指针）
auto ptr = std::make_unique<Buffer>(size);
// 自动释放，无 UAF 风险
```

**审计 grep：**

```bash
# 查找 free 后未置 NULL
grep -A2 'free(' --include='*.c' --include='*.cpp' . | grep -v 'NULL\|= NULL\|test'

# 查找 delete 后使用
grep -A2 'delete ' --include='*.cpp' . | grep -v 'NULL\|= nullptr\|test'
```

### 5. 竞态条件 (TOCTOU)

```c
// ❌ Time-of-Check Time-of-Use
if (access("/tmp/safe_file", R_OK) == 0) {
    // 攻击者在此窗口替换 /tmp/safe_file 为符号链接
    FILE *f = fopen("/tmp/safe_file", "r");  // 打开了恶意文件
}

// ✅ 直接打开 + fstat 检查
int fd = open("/tmp/safe_file", O_RDONLY);
struct stat st;
if (fstat(fd, &st) != 0) { /* error */ }
if (st.st_uid != getuid()) { /* error */ }
// 继续使用 fd
```

### 6. 不安全库函数速查

| 危险函数 | 风险 | 安全替代 |
|----------|------|---------|
| `gets()` | 栈溢出（无限制） | `fgets()` |
| `strcpy()` | 栈/堆溢出 | `strncpy()` / `strlcpy()` / `snprintf()` |
| `strcat()` | 栈/堆溢出 | `strncat()` / `snprintf()` |
| `sprintf()` | 格式化溢出 | `snprintf()` |
| `vsprintf()` | 格式化溢出 | `vsnprintf()` |
| `scanf("%s")` | 栈溢出 | `scanf("%Ns")` |
| `strlen()` + `malloc()` | 整数溢出 | 检查 SIZE_MAX |
| `strtok()` | 非线程安全 | `strtok_r()` |
| `rand()` | 可预测随机数 | `arc4random()` / `getrandom()` |
| `system()` | 命令注入 | `execve()` / `posix_spawn()` |

### 7. 动态分析

**AddressSanitizer (ASan)：**

```bash
# 编译时启用
gcc -fsanitize=address -fno-omit-frame-pointer -g -O1 target.c -o target_asan
./target_asan  # 自动检测溢出/UAF/double-free

# CMake
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=address -fno-omit-frame-pointer -g")
```

**UndefinedBehaviorSanitizer (UBSan)：**

```bash
gcc -fsanitize=undefined -fno-omit-frame-pointer -g target.c -o target_ubsan
```

**Valgrind：**

```bash
valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes ./target
```

**Checksec（二进制保护检查）：**

```bash
checksec --file=target
# 输出：NX/PIE/RELRO/Canary/ Fortify 状态
```

---

## Part B：检测与防御

### 8. 编译器安全加固

```bash
# 完整安全编译选项 (GCC/Clang)
CFLAGS="-O2 \
  -fstack-protector-strong \    # 栈 Canary
  -D_FORTIFY_SOURCE=2 \         # 编译时缓冲区检查
  -Wformat \                    # 格式化字符串警告
  -Werror=format-security \     # 格式化字符串错误
  -fPIE \                       # 位置无关可执行文件
  -pie \                        # PIE
  -z,relro \                    # 只读重定位
  -z,now \                      # 完全 RELRO
  -z,noexecstack \              # 不可执行栈
  -Wall -Wextra -Wconversion \  # 警告
  -fno-strict-overflow"         # 防止优化器假设无溢出

LDFLAGS="-z,relro -z,now -z,noexecstack -pie"
```

**CMake 配置：**

```cmake
# 安全编译选项
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fstack-protector-strong -D_FORTIFY_SOURCE=2")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wformat -Werror=format-security")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIE -fno-strict-overflow")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -pie -z,relro -z,now -z,noexecstack")
```

**Makefile 模板：**

```makefile
CFLAGS += -fstack-protector-strong -D_FORTIFY_SOURCE=2 -Wformat -Werror=format-security
CFLAGS += -fPIE -fno-strict-overflow -Wall -Wextra -Wconversion
LDFLAGS += -pie -z,relro -z,now -z,noexecstack
```

### 9. 静态分析工具

```bash
# Cppcheck — C/C++ 静态分析
cppcheck --enable=all --suppress=missingInclude --error-exitcode=1 src/

# Clang Static Analyzer
scan-build make

# CodeQL
codeql database create --language=cpp ./codeql-db
codeql database analyze ./codeql-db codeql/cpp-queries

# Semgrep
semgrep --config p/c --config p/cpp src/

# Flawfinder
flawfinder -m 3 src/
```

**Cppcheck 规则速查：**

| Error ID | 漏洞类型 |
|----------|---------|
| bufferAccessOutOfBounds | 缓冲区越界 |
| uninitvar | 未初始化变量 |
| doubleFree | Double-free |
| resourceLeak | 资源泄露 |
| nullPointer | 空指针解引用 |
| leakNoVarFunctionCall | 内存泄露 |
| uninitStructMember | 未初始化结构体成员 |
| unusedAllocatedMemory | 未使用分配内存 |
| arrayIndexOutOfBounds | 数组越界 |
| unknownSignCharArrayIndex | 符号问题数组索引 |

### 10. CI/CD 安全管道

```yaml
# .github/workflows/cpp-security.yml
name: C/C++ Security
on: [push, pull_request]
jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Build with ASan
        run: |
          mkdir build && cd build
          cmake -DCMAKE_C_FLAGS="-fsanitize=address -fno-omit-frame-pointer -g" ..
          make -j$(nproc)

      - name: Cppcheck
        run: |
          sudo apt-get install -y cppcheck
          cppcheck --enable=all --suppress=missingInclude --error-exitcode=1 src/

      - name: Flawfinder
        run: |
          sudo apt-get install -y flawfinder
          flawfinder -m 3 src/

      - name: Semgrep
        uses: semgrep/semgrep-action@v1
        with:
          config: p/c

      - name: Checksec
        run: |
          sudo apt-get install -y checksec
          checksec --file=build/target
```

### 11. C++ 安全编码模式

```cpp
// ❌ 裸指针管理
class Buffer {
    char* data;
public:
    Buffer(size_t sz) : data(new char[sz]) {}
    ~Buffer() { delete[] data; }
    // 缺少拷贝构造/赋值 → double-free
};

// ✅ Rule of Zero / Rule of Five
class Buffer {
    std::unique_ptr<char[]> data;
public:
    explicit Buffer(size_t sz) : data(std::make_unique<char[]>(sz)) {}
    // 默认拷贝/移动/析构全部正确

    // 或用 std::vector
    std::vector<char> buf;
    explicit Buffer(size_t sz) : buf(sz) {}
};

// ❌ C 风格字符串操作
char buf[256];
sprintf(buf, "User: %s", username);  // 溢出

// ✅ C++ 安全字符串
std::string buf = "User: " + std::string(username);
// 或 fmtlib
fmt::memory_buffer buf;
fmt::format_to(std::back_inserter(buf), "User: {}", username);
```

---

## 速查表

### C/C++ 漏洞模式 → 审计关键词 → 修复方案矩阵

| 漏洞类型 | 审计关键词 | 危险函数 | 安全替代 |
|----------|-----------|---------|---------|
| 栈溢出 | `gets`, `strcpy`, `scanf("%s")` | 无长度限制 | `fgets`, `strncpy`, `scanf("%Ns")` |
| 堆溢出 | `malloc` + `strcpy`, `memcpy` | 无长度检查 | `calloc` + `memcpy` + 边界 |
| 格式化字符串 | `printf(var)`, `fprintf(fp, var)` | 用户可控格式 | `printf("%s", var)` |
| 整数溢出 | `malloc(count * size)`, `size_t - n` | 无溢出检查 | `__builtin_mul_overflow` |
| UAF | `free(ptr)` 后使用 | free 后未置 NULL | free + `ptr=NULL` / RAII |
| Double-Free | 连续 `free(ptr)` | 重复释放 | free + NULL + 状态跟踪 |
| TOCTOU | `access()` + `open()` | 检查与使用间窗口 | `open()` + `fstat()` |
| 命令注入 | `system()`, `popen()` | shell + 用户输入 | `execve()` / `posix_spawn()` |
| 弱随机 | `rand()`, `srand(time())` | 可预测 | `getrandom()`, `arc4random()` |
| 空指针 | `*ptr` 未检查 NULL | 未验证指针 | NULL 检查 / 断言 |

### Exploit 缓解措施对照表

| 缓解措施 | 编译选项 | 检测方法 | 绕过技术 |
|----------|---------|---------|---------|
| NX/DEP | `-z,noexecstack` | `checksec` | ROP/ret2libc |
| Stack Canary | `-fstack-protector-strong` | `checksec` | 信息泄露 + 爆破 |
| ASLR | `-fPIE -pie` | `checksec` | 信息泄露 / 偏移 |
| Full RELRO | `-z,relro -z,now` | `checksec` | 覆盖 .bss / 栈 |
| Fortify | `-D_FORTIFY_SOURCE=2` | 编译时 | 不可绕过（正确使用时） |
| CFI | `-fsanitize=cfi` | 运行时 | 目前较难 |
| SafeStack | `-fsanitize=safe-stack` | 运行时 | 覆盖 unsafe 栈 |

---

## MITRE ATT&CK 映射

| 战术 | Technique | C/C++ 相关场景 |
|------|-----------|---------------|
| Initial Access | T1190 | 网络服务缓冲区溢出 |
| Execution | T1203 — Exploitation for Client Execution | 格式化字符串 RCE |
| Privilege Escalation | T1068 | 内核模块 UAF/堆溢出提权 |
| Defense Evasion | T1055 — Process Injection | 共享库注入 |
| Credential Access | T1003 | 内存转储工具漏洞利用 |
| Impact | T1489 | DoS via 整数溢出/空指针 |

---

## Part C：2025-2026 更新

> 本部分补充 2025-2026 年 C/C++ 安全领域的关键变化：内存安全漏洞全景、模糊测试与静态分析工具演进、
> Sanitizer 深度使用、Rust 替代方案，以及 MITRE ATT&CK 扩展映射。

### 12. 内存安全漏洞全景（2025-2026）

**背景：** Google Chrome 统计 912 个高危漏洞中约 **70% 为内存安全漏洞**；美国 CISA 要求关键软件在 2026 年 1 月 1 日前制定内存安全迁移路线图。C/C++ 内存安全仍是网络安全核心议题。

#### 12.1 漏洞类型全景速查

| 漏洞类型 | CWE | 根因 | 典型触发场景 | 危害等级 |
|----------|-----|------|-------------|---------|
| **Stack Buffer Overflow** | CWE-121 | 栈缓冲区无边界检查 | `gets()`, `strcpy()`, `scanf("%s")` | Critical — RCE |
| **Heap Buffer Overflow** | CWE-122 | 堆内存越界写 | `malloc(N)` + `memcpy(src, len>N)` | Critical — RCE |
| **Heap Overflow (元数据)** | CWE-122 | 覆盖堆管理结构 | 覆盖 `malloc_chunk` 的 `fd/bk` 指针 | Critical — RCE |
| **Use-After-Free (UAF)** | CWE-416 | 访问已释放内存 | 悬空指针未置 NULL | Critical — RCE |
| **Double-Free** | CWE-415 | 同一内存重复释放 | 错误路径重复调用 `free()` | High — 堆损坏 |
| **Type Confusion** | CWE-843 | 对象类型误判 | C++ 不安全的 `static_cast`/C 风格转换 | Critical — RCE |
| **Integer Overflow** | CWE-190 | 算术运算回绕 | `malloc(count * size)` 溢出 | High — 逻辑绕过 |
| **Integer Underflow** | CWE-191 | 无符号减法回绕 | `unsigned remaining = total - consumed` | High — 逻辑绕过 |
| **Null Pointer Dereference** | CWE-476 | 解引用空指针 | 未检查 malloc 返回值 | Medium — DoS |
| **Uninitialized Memory** | CWE-908 | 使用未初始化变量 | `malloc` 后未清零即使用 | High — 信息泄露 |
| **Off-by-One** | CWE-193 | 循环/索引边界差一 | `for(i=0; i<=len; i++)` 应为 `<` | High — 溢出 |
| **Format String** | CWE-134 | 用户输入作格式串 | `printf(user_input)` | Critical — 任意读写 |
| **Race Condition (TOCTOU)** | CWE-367 | 检查与使用间窗口 | `access()` + `open()` 组合 | High — 权限绕过 |

#### 12.2 类型混淆（Type Confusion）深度分析

类型混淆是 2025 年浏览器 exploit 的**主要攻击向量**，常与 UAF 组合利用。

```cpp
// ❌ 不安全的向下转型
class Base { public: virtual void foo() {} };
class Derived : public Base { public: int secret; void foo() override { secret++; } };

Base* obj = get_object();
// 危险：如果 obj 实际不是 Derived*，则 vtable 指针错误
Derived* d = static_cast<Derived*>(obj);
d->foo();  // 如果 obj 不是 Derived → 类型混淆 → 可能控制 vtable

// ✅ 安全：dynamic_cast + RTTI 检查
Derived* d = dynamic_cast<Derived*>(obj);
if (d == nullptr) { return ERROR; }
d->foo();

// ✅ 更好：使用 visitor 模式或 std::variant (C++17)
std::variant<DerivedA, DerivedB> obj = get_object();
std::visit([](auto&& arg) { arg.foo(); }, obj);
```

**Vtable 劫持利用链：**
1. UAF/堆溢出 → 覆盖对象头部 vtable 指针
2. 构造假 vtable → 指向攻击者可控数据
3. 触发虚函数调用 → 控制流劫持
4. 绕过 CFI → 需要找到合法间接调用点

**防御：**
- 启用 LLVM CFI：`-fsanitize=cfi -flto`
- 使用 `dynamic_cast` 替代 `static_cast` 进行向下转型
- 启用 RTTI（运行时类型信息）
- 研究方向：NDSS 2025 提出 **type++** 内联类型信息系统

#### 12.3 现代堆漏洞利用技术（2025）

```
传统堆利用（已逐渐失效）          现代堆利用（2025 主流）
─────────────────────────        ──────────────────────────
unlink 攻击                      House of 系列 (House of Force/Spirit/Orange)
fastbin dup                      TCache poisoning (glibc 2.26+)
堆风水 (Heap Feng Shui)          Largebin attack / Unsorted bin attack
覆盖 __malloc_hook               IO_FILE exploit (vtable 劫持)
                                 Safe-linking 绕过 (glibc 2.32+)
                                 House of Apple / House of Emma (2023-2025)
```

**审计关键：** 检查所有涉及堆操作的自定义分配器、对象缓存池、以及 glibc 版本对应的防护机制。

### 13. 模糊测试（Fuzzing）工具详解

#### 13.1 AFL++ — 最活跃的覆盖率引导 fuzzer

```bash
# 安装
git clone https://github.com/AFLplusplus/AFLplusplus && cd AFLplusplus
make source-only=all    # 启用所有模式
sudo make install

# 编译目标
afl-clang-fast -fsanitize=address,fuzzer -o target_fuzz target.c

# 基本 fuzzing
afl-fuzz -i seeds/ -o output/ -m none -- ./target_fuzz @@

# 持久模式 (Persistent Mode) — 高性能
# target.c 中添加:
# __AFL_FUZZ_INIT();
# while (__AFL_LOOP(10000)) {
#     unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;
#     int len = __AFL_FUZZ_TESTCASE_LEN;
#     // 测试逻辑
# }

# 结合 ASan
afl-clang-fast -fsanitize=address -o target_asan target.c
AFL_USE_ASAN=1 afl-fuzz -i seeds/ -o output/ -m none -- ./target_asan @@

# QEMU 模式（无需源码）
afl-fuzz -Q -i seeds/ -o output/ -- ./binary_target @@
```

**AFL++ 2025 新特性：**
- 自定义语法器（Grammar Mutator）支持结构化输入
- CMPLOG 模式加速魔法值发现
- Intel PT 后端（Linux x86_64）提升覆盖率
- Frida 模式支持 Android/iOS 动态二进制插桩

#### 13.2 libFuzzer — LLVM 内置 in-process fuzzer

```cpp
// fuzz_target.cpp
#include <cstdint>
#include <stddef.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // 解析模糊输入并测试目标函数
    if (size < 4) return 0;
    int len = *(int*)data;
    if (len < 0 || len > 10000) return 0;  // 过滤无效输入

    // 调用被测函数
    process_data(data + 4, size - 4);
    return 0;
}
```

```bash
# 编译 + 运行
clang++ -fsanitize=fuzzer,address -g -O1 \
    fuzz_target.cpp target_lib.a -o fuzz_target

# 运行
./fuzz_target -max_len=4096 -timeout=10 corpus/ -artifact_prefix=crashes/

# 字典辅助
./fuzz_target -dict=xml.dict corpus/

# 与 ASan/MSAN/UBSAN 组合
clang++ -fsanitize=fuzzer,address,undefined fuzz_target.cpp -o fuzz_asan
clang++ -fsanitize=fuzzer,memory fuzz_target.cpp -o fuzz_msan
```

**libFuzzer 优势：** 与 LLVM sanitizer 无缝集成，适合 API 级别 fuzzing，启动快。

#### 13.3 Honggfuzz — 硬件计数器引导

```bash
# 安装
git clone https://github.com/google/honggfuzz && cd honggfuzz && make && sudo make install

# 基本使用
hfuzz_cc -fsanitize=address -o target_hf target.c
honggfuzz -i seeds/ -o output/ -- ./target_hf

# 持久模式
# 在代码中插入 HF_ITER() 循环
# 硬件性能计数器引导（如分支未预测次数）
honggfuzz -i seeds/ --linux_perf_brs_edge -- ./target @@
```

#### 13.4 Fuzzer 选择指南

| Fuzzer | 最佳场景 | 源码要求 | 性能 | 特色 |
|--------|---------|---------|------|------|
| **AFL++** | 通用二进制/文件格式 | 可选（QEMU/Frida） | 高 | 最成熟，社区最活跃 |
| **libFuzzer** | API/库函数 fuzzing | 必须（LLVM） | 最高 | in-process，零拷贝 |
| **Honggfuzz** | 硬件计数器引导 | 可选 | 高 | Intel PT，持久模式 |
| **Centipede** | 大规模集群 fuzzing | 必须（LLVM） | 极高 | Google 分布式引擎 |
| **Jackalope** | Windows 二进制 | 不需要 | 中 | WinDbg 集成 |
| **Fuzzilli** | JavaScript 引擎 | 需要 | 高 | 语法感知 |

### 14. 静态分析工具演进

#### 14.1 CodeQL — GitHub 语义代码分析

```bash
# 创建数据库
codeql database create --language=cpp --source-root=src/ ./codeql-db

# 运行安全查询套件
codeql database analyze ./codeql-db \
    codeql/cpp-queries:Security \
    --format=sarif-latest \
    --output=results.sarif

# 自定义查询 — 检测 memcpy 长度参数未检查
# memcpy_length_check.ql
"""
import cpp
from FunctionCall fc, Variable len
where
  fc.getTarget().getName() = "memcpy" and
  len = fc.getArgument(2).(VariableAccess).getTarget() and
  not exists(BoundsCheck bc | bc.getCheckedVariable() = len)
select fc, "memcpy 调用未检查长度参数 " + len.getName()
"""
```

**CodeQL 2025 安全查询套件覆盖：**
- 缓冲区溢出（栈/堆/越界读写）
- 整数溢出/符号问题
- 格式化字符串
- 命令注入/SQL 注入（C/C++ 内嵌）
- 竞态条件/TOCTOU
- 不安全加密/随机数
- 空指针解引用

#### 14.2 Semgrep — 轻量级模式匹配

```bash
# 运行 C/C++ 安全规则
semgrep --config p/c --config p/cpp --json src/ -o results.json

# 自定义规则 — 检测危险的 scanf 使用
# rules/dangerous_scanf.yaml
"""
rules:
  - id: dangerous-scanf
    patterns:
      - pattern: scanf("$FMT", ...)
      - pattern-not: scanf("%$N", ...)
    message: "scanf 使用了无宽度限制的格式说明符，可能导致栈溢出"
    severity: ERROR
    languages: [c]
"""
```

#### 14.3 其他工具对比

| 工具 | 类型 | 语言支持 | 优势 | 适用规模 |
|------|------|---------|------|---------|
| **CodeQL** | 语义分析 | C/C++/Java/Python/... | 最深语义理解，GitHub 集成 | 中大型 |
| **Semgrep** | 模式匹配 | 30+ 语言 | 快速、可自定义、CI 友好 | 所有规模 |
| **Coverity** | 商业静态分析 | C/C++/Java/C#/... | 企业级，低误报率 | 大型企业 |
| **PVS-Studio** | 商业静态分析 | C/C++/C# | 免费开源项目许可证 | 中大型 |
| **Cppcheck** | 开源 | C/C++ | 零配置、快速、CI 集成 | 所有规模 |
| **Clang-Tidy** | 编译器级 | C/C++ | 与 clang 无缝集成 | 所有规模 |
| **Flawfinder** | 模式匹配 | C/C++ | 简单快速，适合初筛 | 小型 |
| **Infer** | 抽象解释 | C/C++/Java/ObjC | Facebook 开源，增量分析 | 中大型 |

**2025 推荐组合：** Cppcheck（快速初筛）+ Semgrep（自定义规则）+ CodeQL（深度语义）+ ASan/Fuzzing（动态验证）。

### 15. Sanitizer 深度使用指南

#### 15.1 AddressSanitizer (ASan) — 内存错误检测

```bash
# 编译选项
gcc -fsanitize=address -fno-omit-frame-pointer -g -O1 -o target_asan target.c

# 运行时选项（环境变量）
ASAN_OPTIONS="detect_leaks=1:detect_stack_use_after_return=1:check_initialization_order=1:strict_init_order=1" \
    ./target_asan

# 常用 ASAN_OPTIONS
ASAN_OPTIONS="\
  detect_leaks=1 \                    # 检测内存泄露
  detect_stack_use_after_return=1 \   # 检测栈 UAF
  detect_container_overflow=1 \       # 检测容器越界
  detect_use_after_free=1 \           # 检测堆 UAF
  detect_double_free=1 \              # 检测 double-free
  quarantine_size_mb=256 \            # 延迟释放队列大小
  redzone=128 \                       # 红区大小（字节）
  halt_on_error=0 \                   # 不在首个错误时终止
  log_path=asan.log"                  # 日志路径

# CMake 集成
option(ENABLE_ASAN "Enable AddressSanitizer" OFF)
if(ENABLE_ASAN)
    add_compile_options(-fsanitize=address -fno-omit-frame-pointer -g -O1)
    add_link_options(-fsanitize=address)
endif()
```

**ASan 检测能力：**

| 漏洞类型 | 检测 | 说明 |
|----------|------|------|
| 栈缓冲区溢出 | Yes | 红区检测 |
| 堆缓冲区溢出 | Yes | 红区检测 |
| 全局缓冲区溢出 | Yes | 红区检测 |
| Use-After-Free | Yes | 延迟释放队列 |
| Double-Free | Yes | 分配跟踪 |
| 内存泄露 | Yes | LeakSanitizer 集成 |
| 栈 Use-After-Return | Yes | 需 `detect_stack_use_after_return=1` |

#### 15.2 MemorySanitizer (MSan) — 未初始化内存检测

```bash
# 必须使用 Clang（GCC 不支持 MSan）
clang -fsanitize=memory -fno-omit-frame-pointer -g -O1 -o target_msan target.c

# 注意：整个程序及所有依赖库必须用 MSan 编译
# 否则会产生大量误报

MSAN_OPTIONS="report_umrs=1:halt_on_error=0" ./target_msan
```

**典型检测场景：**

```c
int main() {
    int x;  // 未初始化
    if (x > 0) {  // MSan 报告：使用未初始化值
        printf("positive\n");
    }
}
```

#### 15.3 UndefinedBehaviorSanitizer (UBSan) — 未定义行为检测

```bash
# 全部检查
gcc -fsanitize=undefined -fno-omit-frame-pointer -g -o target_ubsan target.c

# 细粒度控制
gcc -fsanitize=\
  signed-integer-overflow \   # 有符号整数溢出
  unsigned-integer-overflow \ # 无符号整数溢出（不是 UB，但检测有益）
  shift \                     # 移位溢出
  divide-by-zero \            # 除零
  null \                      # 空指针解引用
  alignment \                 # 对齐问题
  vptr \                      # C++ 虚表指针验证
  object-size \               # 对象大小检查
  bounds \                    # 数组越界
  enum \                      # 枚举范围检查
  -fno-omit-frame-pointer -g -o target_ubsan target.c
```

#### 15.4 Sanitizer 组合使用

```bash
# ASan + UBSan（最常用组合）
gcc -fsanitize=address,undefined -fno-omit-frame-pointer -g -O1 \
    -o target_san target.c

# 注意：ASan 和 MSan 不可同时使用（互斥）
# 如果需要两者，分别编译运行

# Fuzzing 标准组合
clang -fsanitize=fuzzer,address,undefined \
    -fno-omit-frame-pointer -g -O1 \
    -o fuzz_target fuzz_target.cpp
```

#### 15.5 ThreadSanitizer (TSan) — 数据竞争检测

```bash
# 编译
gcc -fsanitize=thread -fno-omit-frame-pointer -g -O1 -o target_tsan target.c

# 运行
TSAN_OPTIONS="history_size=7:halt_on_error=0" ./target_tsan

# 注意：TSan 与 ASan 互斥，不可同时使用
```

### 16. Rust 安全替代方案

#### 16.1 为何迁移到 Rust

| 维度 | C/C++ | Rust |
|------|-------|------|
| **内存安全** | 手动管理，70% 高危漏洞源于内存安全问题 | 所有权系统编译期保证 |
| **空指针** | 运行时解引用可能崩溃 | `Option<T>` 编译期强制处理 |
| **数据竞争** | 无保护（需手动加锁） | 编译期禁止（Send/Sync trait） |
| **缓冲区溢出** | 常见（无边界检查） | 运行时边界检查 + 切片安全 |
| **UAF/Double-Free** | 常见 | 所有权系统消除 |
| **格式化字符串** | `printf` 家族 | `println!` 宏安全 |
| **性能** | 零开销 | 零开销抽象（同等性能） |

**关键数据：** Microsoft 计划 2030 年前将 Windows 核心组件迁移至 Rust；Android 13 中 Rust 代码零内存安全漏洞；RunSafe 已成功将 30,000+ 行 C++ 迁移至 Rust。

#### 16.2 C/C++ → Rust 安全模式对照

```c
// ❌ C: 缓冲区溢出
void process(const char* input) {
    char buf[64];
    strcpy(buf, input);  // 可能溢出
}
```

```rust
// ✅ Rust: 编译期保证安全
fn process(input: &str) {
    let mut buf = [0u8; 64];
    let bytes = input.as_bytes();
    let len = std::cmp::min(bytes.len(), buf.len());
    buf[..len].copy_from_slice(&bytes[..len]);  // 不会溢出
}

// ✅ 更好的 Rust 写法
fn process(input: &str) -> String {
    let buf: String = input.chars().take(64).collect();
    buf
}
```

```c
// ❌ C: UAF
char* ptr = malloc(64);
free(ptr);
ptr[0] = 'A';  // UAF — 无报错
```

```rust
// ✅ Rust: 编译期阻止
let mut v = vec![1, 2, 3];
let reference = &v[0];
v.push(4);  // 编译错误：不能在存在不可变引用时修改
// println!("{}", reference);  // 如果取消注释，借用检查器报错
```

#### 16.3 混合迁移策略（推荐）

```
方案一：FFI 边界隔离
┌──────────────────┐     ┌──────────────────┐
│  Rust 安全壳     │ ←── │  C/C++ 遗留核心  │
│  (网络输入解析)   │     │  (业务逻辑)      │
│  (验证/过滤)     │     │  (计算密集)       │
└──────────────────┘     └──────────────────┘
  通过 cxx / bindgen 安全桥接

方案二：增量重写
  1. 先用 Rust 重写网络解析/输入处理模块
  2. 用 Rust 重写内存管理密集模块
  3. 逐步替换核心逻辑

方案三：新模块用 Rust
  现有 C/C++ 代码不变，所有新增功能用 Rust 编写
```

```toml
# Cargo.toml — 使用 cxx 安全桥接
[dependencies]
cxx = "1.0"

[build-dependencies]
cxx-build = "1.0"
```

### 17. 常见危险函数速查表（2025 增强版）

#### 17.1 C 标准库危险函数

| 危险函数 | CWE | 风险 | 安全替代 | 何时禁止使用 |
|----------|-----|------|---------|------------|
| `gets()` | CWE-120 | 栈溢出（无限长） | `fgets(buf, size, stdin)` | **C11 已移除** |
| `strcpy()` | CWE-120 | 栈/堆溢出 | `strncpy()` + null / `strlcpy()` / `snprintf()` | 所有情况 |
| `strcat()` | CWE-120 | 栈/堆溢出 | `strncat()` / `snprintf()` | 所有情况 |
| `sprintf()` | CWE-120 | 格式化溢出 | `snprintf()` | 所有情况 |
| `vsprintf()` | CWE-120 | 格式化溢出 | `vsnprintf()` | 所有情况 |
| `scanf("%s")` | CWE-120 | 栈溢出 | `scanf("%63s")` / `fgets()` | 无宽度限制时 |
| `sscanf()` | CWE-120 | 栈溢出 | 指定宽度或用 `strtol()` | 无宽度限制时 |
| `strlen()` + `malloc()` | CWE-190 | 整数溢出 | `SIZE_MAX` 检查 / `calloc()` | 大量数据时 |
| `strtok()` | CWE-362 | 非线程安全 | `strtok_r()` / 自定义解析器 | 多线程环境 |
| `rand()` | CWE-335 | 可预测随机 | `arc4random()` / `getrandom()` / `RAND_bytes()` | 安全场景 |
| `srand(time(NULL))` | CWE-335 | 可预测种子 | `getrandom()` | 安全场景 |
| `system()` | CWE-78 | 命令注入 | `execve()` / `posix_spawn()` | 处理用户输入时 |
| `popen()` | CWE-78 | 命令注入 | `pipe()` + `fork()` + `execve()` | 处理用户输入时 |
| `realpath()` 无检查 | CWE-59 | 符号链接跟随 | `open()` + `fstat()` + `readlink()` | 敏感文件操作 |
| `tmpnam()` / `tempnam()` | CWE-377 | 竞态条件 | `mkstemp()` / `O_TMPFILE` | 所有情况 |
| `strcmp()` 时序泄露 | CWE-208 | 时序侧信道 | `CRYPTO_memcmp()` / `subtle::ConstantTimeEq` | 密码比较时 |
| `atoi()` / `atol()` | CWE-190 | 无溢出检测 | `strtol()` + `errno` 检查 | 所有情况 |

#### 17.2 POSIX/系统级危险函数

| 危险模式 | 风险 | 安全替代 |
|----------|------|---------|
| `access()` + `open()` | TOCTOU | `open()` + `fstat()` |
| `chown()` / `chmod()` 不检查返回值 | 权限设置失败 | 检查返回值 + 使用 `fchown()`/`fchmod()` |
| `fopen()` 用用户输入路径 | 路径遍历 | 白名单验证 + `realpath()` + `open()` |
| `dlopen()` 用用户输入路径 | 代码注入 | 白名单 + `dlopen()` 绝对路径 |
| `getenv()` 直接使用 | 环境变量注入 | 验证/过滤 + 长度检查 |
| `signal()` 注册处理器 | 异步信号安全 | `sigaction()` + 仅调用异步安全函数 |

#### 17.3 C++ 危险模式

| 危险模式 | 风险 | 安全替代 |
|----------|------|---------|
| 裸 `new`/`delete` | UAF/double-free/泄露 | `std::unique_ptr` / `std::shared_ptr` |
| 裸数组 `T arr[N]` | 越界 | `std::array<T,N>` / `std::vector<T>` |
| C 风格字符串 `char*` | 溢出/无 null 终止 | `std::string` / `std::string_view` |
| C 风格转换 `(Type*)ptr` | 类型混淆 | `dynamic_cast` / `std::variant` |
| `std::auto_ptr` (C++17 移除) | 所有权语义错误 | `std::unique_ptr` |
| `std::vector::operator[]` 越界 | 未定义行为 | `std::vector::at()` (抛异常) |
| 多线程共享 `std::shared_ptr` 循环引用 | 内存泄露 | `std::weak_ptr` 打破循环 |
| 异常构造函数中分配资源 | 资源泄露 | RAII + `std::unique_ptr` |
| 未用 `override` | 隐藏虚函数 | 始终标注 `override` |
| `reinterpret_cast` | 类型双关/对齐问题 | `std::bit_cast` (C++20) |

### 18. MITRE ATT&CK 扩展映射（2025 增强版）

#### 18.1 完整 C/C++ 相关 ATT&CK 映射

| 战术 | Technique ID | 名称 | C/C++ 相关场景 | 典型漏洞类型 |
|------|-------------|------|---------------|------------|
| **Initial Access** | T1190 | Exploit Public-Facing App | 网络服务缓冲区溢出 | Heap/Stack Overflow |
| **Initial Access** | T1133 | External Remote Services | VPN/网关漏洞利用 | 整数溢出 → RCE |
| **Execution** | T1203 | Exploitation for Client Execution | 浏览器/PDF阅读器漏洞 | UAF + Type Confusion |
| **Execution** | T1059 | Command and Scripting Interpreter | 通过 system()/popen() 执行 | 命令注入 |
| **Persistence** | T1574.002 | DLL Side-Loading | DLL 搜索顺序劫持 | 不安全库加载路径 |
| **Privilege Escalation** | T1068 | Exploitation for Privilege Escalation | 内核模块/驱动 UAF | UAF/Heap Overflow |
| **Privilege Escalation** | T1055.001 | DLL Injection | 进程注入 | 内存操作 API |
| **Defense Evasion** | T1055 | Process Injection | 共享库注入/进程空心化 | VirtualAllocEx + WriteProcessMemory |
| **Defense Evasion** | T1055.012 | Process Hollowing | 进程替换 | CreateProcess + NtUnmapViewOfSection |
| **Defense Evasion** | T1027.007 | Dynamic API Resolution | 运行时解析 API 地址 | GetProcAddress + LoadLibrary |
| **Credential Access** | T1003.001 | LSASS Memory | 内存转储 | 进程内存读取 |
| **Credential Access** | T1552.004 | Private Keys | 内存中密钥提取 | 未加密内存中的密钥 |
| **Discovery** | T1082 | System Information Discovery | 未初始化内存信息泄露 | Information Disclosure |
| **Lateral Movement** | T1210 | Exploitation of Remote Services | RPC/SMB 服务漏洞 | Buffer Overflow |
| **Exfiltration** | T1041 | Exfiltration Over C2 Channel | 利用漏洞建立 C2 通道 | RCE → C2 |
| **Impact** | T1489 | Service Stop | DoS via 整数溢出/空指针 | Null Pointer Dereference |
| **Impact** | T1486 | Data Encrypted for Impact | 勒索软件利用加密漏洞 | 弱加密实现 |

#### 18.2 ATT&CK → 防御措施映射

| ATT&CK Technique | C/C++ 防御措施 | 编译选项/工具 |
|------------------|---------------|-------------|
| T1190 (网络服务 RCE) | ASLR + Stack Canary + RELRO + NX | `-fPIE -pie -fstack-protector-strong -z,relro,-z,now -z,noexecstack` |
| T1203 (客户端漏洞) | CFI + SafeStack + Type Safety | `-fsanitize=cfi -fsanitize=safe-stack` + `dynamic_cast` |
| T1068 (内核提权) | KASLR + SMEP/SMAP + KPTI | 内核编译选项 + `CONFIG_HARDENED_USERCOPY` |
| T1055 (进程注入) | CET + Shadow Stack | `-fcf-protection=full` (Intel CET) |
| T1059 (命令注入) | 避免 `system()`/`popen()` | 用 `execve()` / `posix_spawn()` |
| T1003 (凭证转储) | 内存加密 + 安全擦除 | `explicit_bzero()` / `OPENSSL_cleanse()` |
| T1489 (DoS) | 输入验证 + 错误处理 | `-fsanitize=undefined` + 边界检查 |

#### 18.3 CVE 到 ATT&CK 映射实例

| CVE | 产品 | 漏洞类型 | ATT&CK 映射 |
|-----|------|---------|------------|
| CVE-2025-13223 | Chrome V8 | Type Confusion | T1203 (Client Execution) |
| CVE-2025-52194 | libsndfile | Buffer Overflow | T1190 (Public-Facing App) |
| CVE-2024-3094 | XZ Utils | Supply Chain Backdoor | T1195.002 (Supply Chain) |
| CVE-2023-44228 | Apache Log4j | JNDI Injection (Java) | T1190 (参考模式) |

### 19. 2025-2026 C/C++ 安全审计检查清单

#### 19.1 代码审计自动化管道

```yaml
# .github/workflows/cpp-security-2025.yml
name: C/C++ Security Pipeline (2025)
on: [push, pull_request]

jobs:
  static-analysis:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Cppcheck
        run: |
          cppcheck --enable=all --suppress=missingInclude \
            --addon=cert --addon=security \
            --error-exitcode=1 --verbose src/

      - name: Clang-Tidy
        run: |
          clang-tidy -p build src/**/*.cpp -- \
            -checks=' -*,bugprone-*,security-*,cert-*,-modernize-*'

      - name: Semgrep
        uses: semgrep/semgrep-action@v1
        with:
          config: >-
            p/c
            p/cpp
            p/security-audit

      - name: CodeQL
        uses: github/codeql-action/analyze@v3
        with:
          languages: cpp
          queries: security-extended

  dynamic-analysis:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Build with ASan + UBSan
        run: |
          mkdir build && cd build
          cmake -DCMAKE_C_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer -g -O1" \
                -DCMAKE_CXX_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer -g -O1" ..
          make -j$(nproc)

      - name: Run tests under ASan
        run: |
          cd build
          ASAN_OPTIONS="detect_leaks=1:detect_stack_use_after_return=1" \
            ctest --output-on-failure

      - name: Checksec
        run: |
          checksec --file=build/target --format=json

  fuzzing:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Build Fuzzer
        run: |
          clang++ -fsanitize=fuzzer,address,undefined \
            -fno-omit-frame-pointer -g -O1 \
            fuzz/fuzz_target.cpp src/lib.a -o fuzz_target

      - name: Run Fuzzing (5 min)
        run: |
          mkdir -p corpus crashes
          timeout 300 ./fuzz_target corpus/ \
            -max_total_time=300 \
            -artifact_prefix=crashes/ \
            -max_len=4096 || true

      - name: Check for crashes
        run: |
          if [ "$(ls crashes/ | wc -l)" -gt 0 ]; then
            echo "::error::Fuzzer found crashes!"
            ls -la crashes/
            exit 1
          fi
```

#### 19.2 审计优先级矩阵

| 优先级 | 检查项 | 工具 | 时间估计 |
|--------|--------|------|---------|
| **P0** | 不安全函数使用 (`gets`, `strcpy`, `sprintf`) | Cppcheck + Semgrep | 1-2 小时 |
| **P0** | 格式化字符串漏洞 | Semgrep + grep | 1-2 小时 |
| **P0** | 命令注入 (`system`, `popen`) | Semgrep + grep | 1 小时 |
| **P1** | 整数溢出/下溢 | CodeQL + UBSan | 2-4 小时 |
| **P1** | UAF/Double-Free | ASan + CodeQL | 4-8 小时 |
| **P1** | 堆溢出 | ASan + AFL++ | 4-8 小时 |
| **P2** | TOCTOU/竞态条件 | TSan + 代码审查 | 4-8 小时 |
| **P2** | 类型混淆 | CodeQL + CFI | 4-8 小时 |
| **P2** | 弱加密/随机数 | Semgrep 自定义规则 | 2-4 小时 |
| **P3** | 信息泄露（未初始化内存） | MSan + Valgrind | 4-8 小时 |
| **P3** | 资源泄露 | Valgrind + ASan(leak) | 2-4 小时 |
| **P3** | 编译器加固检查 | Checksec | 30 分钟 |

### 20. 参考资源

- [Google Chrome 70% 内存安全漏洞统计](https://www.easemob.com/news/4547)
- [CISA 建议：C/C++ 内存安全迁移](https://cloud.tencent.com/developer/article/2369432)
- [美国政府 2026 关键软件迁移要求](https://www.eet-china.com/mp/a358736.html)
- [AFL++ 官方文档](https://aflplus.plus/docs/fuzzing_in_depth/)
- [LLVM CFI 实践指南 (arXiv 2025)](https://arxiv.org/html/2508.15386v1)
- [Fuzzer vs 静态分析对比研究 (arXiv 2025)](https://arxiv.org/pdf/2505.22052)
- [type++ 类型混淆防护 (NDSS 2025)](https://www.ndss-symposium.org/wp-content/uploads/2025-53-paper.pdf)
- [RunSafe C++ → Rust 迁移实践](https://runsafesecurity.com/blog/convert-c-to-rust/)
- [MITRE ATT&CK T1203](https://attack.mitre.org/techniques/T1203/)
- [MITRE ATT&CK T1068](https://attack.mitre.org/techniques/T1068/)
- [MITRE ATT&CK T1055](https://attack.mitre.org/techniques/T1055/)

---

## Part D：2025-2026 精细化复核补充

> 基于 NVD/Qualys/Orca Security/Datadog/CISA 等最新威胁情报，对 C/C++ 生态系统关键 CVE、内存安全趋势、编译器加固更新进行深度补充。覆盖 OpenSSL RCE、glibc 溢出、Linux 内核 UAF、美国联邦内存安全路线图等。

---

### 21. OpenSSL CVE-2025-15467 — CMS 栈溢出预认证 RCE

| 属性 | 详情 |
|------|------|
| CVE | CVE-2025-15467 |
| 类型 | 栈缓冲区溢出 → 预认证 RCE |
| 组件 | OpenSSL CMS AuthEnvelopedData 解析 |
| 根因 | CMS AuthEnvelopedData 结构中的 IV（初始化向量）可被设为超大尺寸，OpenSSL 将其复制到固定大小的栈缓冲区，无边界检查 |
| 认证要求 | **无需认证（Pre-Auth）** |
| 影响 | 远程代码执行 (RCE) / 拒绝服务 (DoS) |
| 受影响版本 | OpenSSL 3.0.x — 3.6.x |
| 修复版本 | OpenSSL **3.3.6+** |

**21.1 漏洞原理**

```c
// OpenSSL CMS 解析中的漏洞点（简化）
// crypto/cms/cms_env.c
int cms_env_asn1_decode(CMS_ContentInfo *cms, BIO *bio) {
    // 从 CMS AuthEnvelopedData 解析 AEAD 参数
    // IV 字段: ASN.1 OCTET STRING，无长度限制
    unsigned char iv[16];  // 固定大小栈缓冲区
    // ❌ 未检查 IV 长度直接复制
    memcpy(iv, aead_params->iv, aead_params->iv_len);  // 栈溢出
}

// 攻击向量:
// 1. 构造恶意 CMS 消息，IV 长度 > 16 字节
// 2. 触发 CMS 解析（S/MIME 邮件、代码签名验证等）
// 3. 栈溢出 → 覆盖返回地址 → RCE
```

**21.2 检测与应急**

```bash
# 检查 OpenSSL 版本
openssl version
# 输出 OpenSSL 3.0.x - 3.5.x → 需升级

# 升级
# Ubuntu/Debian
apt-get update && apt-get install openssl libssl-dev

# RHEL/CentOS
yum update openssl openssl-devel

# 从源码
wget https://www.openssl.org/source/openssl-3.3.6.tar.gz
tar xzf openssl-3.3.6.tar.gz && cd openssl-3.3.6
./config && make && make install

# 检查是否使用 CMS/S/MIME 功能
grep -rn 'CMS_\|SMIME_read\|BIO_new_CMS\|CMS_decrypt\|CMS_verify' \
  --include='*.c' --include='*.cpp' . | grep -v 'node_modules'
```

**21.3 参考**

- [Orca Security: CVE-2025-15467 详细分析](https://orca.security/resources/blog/cve-2025-15467-openssl-pre-auth-rce/)
- [NVD: CVE-2025-15467](https://nvd.nist.gov/detail/cve-2025-15467)
- [Datadog: OpenSSL 2026 年 1 月安全更新](https://securitylabs.datadoghq.com/articles/openssl-january-2026-security-update-cms-and-pkcs12-buffer-overflows/)
- [JFrog: CVE-2025-15467 研究笔记](https://research.jfrog.com/post/potential-rce-vulnerabilityin-openssl-cve-2025-15467/)

---

### 22. glibc 关键 CVE — 2025-2026

| CVE | 组件 | 类型 | 影响 | 修复 |
|-----|------|------|------|------|
| CVE-2025-0395 | `assert()` | 缓冲区溢出 | assert 失败时页面对齐字符串内存分配不足 → 内存损坏/DoS | glibc 最新补丁 |
| CVE-2026-5928 | `ungetwc()` | 缓冲区溢出 | 宽字符回退缓冲区溢出 → 数据泄露/崩溃 | glibc 最新补丁 |
| CVE-2026-5358 | glibc | 缓冲区溢出 | CentOS 7 上的 glibc 缓冲区溢出 | CentOS 7 补丁 |
| CVE-2023-6246 | `__vsyslog_internal` | 堆溢出 | syslog 堆溢出（glibc 2.37 引入）→ RCE | glibc 2.39+ |

**22.1 CVE-2025-0395 assert() 溢出**

```c
// glibc assert() 实现中的漏洞
// 当 assert 失败时，glibc 构造错误消息
// 消息包含：表达式字符串 + 文件名 + 行号
// ❌ 页面对齐字符串导致分配不足

#include <assert.h>

void vulnerable() {
    // 如果表达式字符串恰好跨越页边界
    // assert 失败时的消息分配可能溢出
    assert(complex_check());  // 失败时可能触发堆溢出
}

// ✅ 修复：升级 glibc 或避免在安全敏感路径使用 assert
// 生产代码中应使用自定义错误处理而非 assert
```

**22.2 glibc 安全审计脚本**

```bash
#!/bin/bash
# glibc-security-check.sh
echo "=== glibc 版本检查 ==="
ldd --version | head -1

echo "=== 检查 glibc 已知漏洞 ==="
# 使用 govulncheck（Go 编写的工具也可扫描系统库）
# 或直接检查版本
GLIBC_VER=$(ldd --version | head -1 | grep -oP '[\d.]+$')
echo "glibc 版本: $GLIBC_VER"

echo "=== 检查 assert() 使用 ==="
grep -rn 'assert(' --include='*.c' --include='*.cpp' . | grep -v '_test\|test_' | head -20

echo "=== 检查 syslog 使用 ==="
grep -rn 'syslog(\|vsyslog(\|__vsyslog_internal' --include='*.c' . | grep -v '_test'

echo "=== 检查 ungetwc 使用 ==="
grep -rn 'ungetwc(' --include='*.c' --include='*.cpp' .
```

**22.3 参考**

- [Qualys: glibc syslog 漏洞](https://blog.qualys.com/vulnerabilities-threat-research/2024/01/30/qualys-tru-discovers-important-vulnerabilities-in-gnu-c-librarys-syslog)
- [CVE-2025-0395 — Red Hat](https://access.redhat.com/security/cve/cve-2025-0395)
- [CVE-2026-5928 — SentinelOne](https://www.sentinelone.com/vulnerability-database/cve-2026-5928/)

---

### 23. Linux 内核内存安全 CVE — 2025-2026

| CVE | 子系统 | 类型 | 影响 |
|-----|--------|------|------|
| CVE-2026-31402 | NFSv4.0 LOCK 重放缓存 | **堆溢出** | 本地提权 |
| CVE-2026-23412 | BPF netfilter link | **Use-After-Free** | 本地提权 |
| CVE-2026-23307 | BPF trampoline (cgroup shim) | **Use-After-Free** | 本地提权 |
| RHSA-2026:1445 | SMB 客户端 | **Use-After-Free** | 本地提权 |
| CVE-2024-1086 | netfilter | **Use-After-Free** | 本地提权（CISA 警告） |

**23.1 BPF 子系统 UAF 模式**

```c
// CVE-2026-23412: BPF netfilter link UAF（简化）
// 问题：BPF 程序与 netfilter hook 的生命周期不同步
// 当 netfilter hook 被移除时，BPF 程序仍持有已释放内存的引用

// ❌ 危险模式
static int nf_hook_entry(struct nf_hook_ops *ops, struct sk_buff *skb) {
    // ops 指向已被释放的内存 → UAF
    struct bpf_nf_link *link = container_of(ops, struct bpf_nf_link, ops);
    // link 可能在另一个线程被释放
    bpf_prog_run(link->prog, ctx);  // UAF
}

// ✅ 修复：使用 RCU 或 refcount 保护生命周期
static int nf_hook_entry(struct nf_hook_ops *ops, struct sk_buff *skb) {
    rcu_read_lock();
    struct bpf_nf_link *link = container_of(ops, struct bpf_nf_link, ops);
    if (!refcount_inc_not_zero(&link->refcnt)) {
        rcu_read_unlock();
        return NF_ACCEPT;
    }
    bpf_prog_run(link->prog, ctx);
    refcount_dec(&link->refcnt);
    rcu_read_unlock();
    return NF_ACCEPT;
}
```

**23.2 参考**

- [CVE-2026-31402 — SentinelOne](https://www.sentinelone.com/vulnerability-database/cve-2026-31402/)
- [CVE-2026-23412 — Mallory.ai](https://www.mallory.ai/stories/019e8425-71be-7e21-a651-c8be9d19024b)
- [RHSA-2026:1445 — Red Hat](https://access.redhat.com/errata/RHSA-2026:1445)
- [Linux Kernel Exploitation (GitHub)](https://github.com/xairy/linux-kernel-exploitation)

---

### 24. 美国联邦内存安全路线图 — C/C++ 迁移压力

**24.1 CISA/ONCD 指导**

2025-2026 年，美国联邦政府持续推动关键软件从 C/C++ 迁移到内存安全语言（Rust/Go/Java）：

| 政策 | 时间 | 内容 |
|------|------|------|
| ONSD 路线图要求 | 2026-01-01 | 关键软件供应商必须发布**内存安全路线图** |
| CISA 建议 | 2025 | 建议新项目优先选择内存安全语言 |
| 内存安全语言清单 | 2025 | Rust, Go, Java, C#, Swift, Python, Ruby |
| 现有 C/C++ 代码 | — | 需要加固：ASan/UBSan/CFI/Stack Canaries/PIE |

**24.2 C/C++ 内存安全加固清单（2025-2026 更新）**

```bash
#!/bin/bash
# c-cpp-hardening-check.sh — 检查编译器加固措施

echo "=== 编译器加固检查 ==="

# 检查二进制安全选项
if command -v checksec &> /dev/null; then
    echo "--- Checksec 结果 ---"
    checksec --file=/path/to/binary
fi

echo "--- 编译选项检查 ---"
# 搜索 Makefile/CMakeLists 中的安全编译选项
find . -name 'Makefile*' -o -name 'CMakeLists.txt' -o -name '*.cmake' | while read f; do
    echo "文件: $f"
    # 检查关键安全选项
    grep -n 'fstack-protector\|D_FORTIFY_SOURCE\|fPIE\|fPIC\|Wl,-z,relro\|Wl,-z,now\|fcf-protection' "$f" || echo "  ⚠️ 未找到安全编译选项"
done

echo "--- 安全编译选项速查 ---"
cat << 'EOF'
| 选项 | 功能 | 推荐 |
|------|------|------|
| -fstack-protector-all | 栈溢出检测 | ✅ 必须 |
| -D_FORTIFY_SOURCE=2 | 缓冲区溢出检测 | ✅ 必须 |
| -fPIE -pie | 位置无关执行 | ✅ 必须 |
| -Wl,-z,relro,-z,now | 只读重定位 (Full RELRO) | ✅ 必须 |
| -fcf-protection=full | 控制流完整性 (Intel CET) | ✅ 推荐 |
| -fsanitize=address | 地址消毒器 (ASan) | 测试时启用 |
| -fsanitize=undefined | 未定义行为检测 (UBSan) | 测试时启用 |
| -fsanitize=thread | 线程竞态检测 (TSan) | 测试时启用 |
| -fno-omit-frame-pointer | 保留栈帧指针 | ✅ 推荐 |
| -Werror=format-security | 格式化字符串安全 | ✅ 必须 |
EOF
```

**24.3 参考**

- [CISA: 内存安全路线图](https://cloud.tencent.com/developer/article/2369432)
- [美国政府 2026 关键软件迁移要求](https://www.eet-china.com/mp/a358736.html)
- [EuroLLVM 2025: 消除 C/C++ 内存安全漏洞](https://www.youtube.com/watch?v=rYOCPBUM1Hs)

---

### 25. 2025-2026 综合 CVE 速查（C/C++ 生态）

| CVE | 影响 | 类型 | 严重性 | 修复 |
|-----|------|------|--------|------|
| CVE-2025-15467 | OpenSSL CMS | 栈溢出 → Pre-Auth RCE | **Critical** | OpenSSL 3.3.6+ |
| CVE-2025-0395 | glibc `assert()` | 缓冲区溢出 | Medium-High | glibc 最新补丁 |
| CVE-2026-5928 | glibc `ungetwc()` | 缓冲区溢出 | Medium | glibc 最新补丁 |
| CVE-2026-5358 | glibc (CentOS 7) | 缓冲区溢出 | Medium | CentOS 补丁 |
| CVE-2023-6246 | glibc syslog | 堆溢出 → RCE | **Critical** | glibc 2.39+ |
| CVE-2026-31402 | Linux NFSv4.0 | 堆溢出 | High | 内核最新版 |
| CVE-2026-23412 | Linux BPF netfilter | Use-After-Free | High | 内核最新版 |
| CVE-2026-23307 | Linux BPF trampoline | Use-After-Free | High | 内核最新版 |

---

### 26. 中文社区精华参考

| 来源 | 主题 | 链接 |
|------|------|------|
| 腾讯云 | CISA建议C/C++内存安全迁移 | https://cloud.tencent.com/developer/article/2369432 |
| 电子工程专辑 | 美国2026关键软件迁移要求 | https://www.eet-china.com/mp/a358736.html |
| RunSafe Security | C++ → Rust 迁移实践 | https://runsafesecurity.com/blog/convert-c-to-rust/ |

---

### 27. 防御升级路线图（P0-P3 分级）

| 优先级 | 措施 | 具体操作 | 截止 |
|--------|------|---------|------|
| **P0** | OpenSSL 升级 | 升级到 OpenSSL 3.3.6+ | 即时 |
| **P0** | glibc 升级 | 升级到最新 glibc 补丁版本 | 即时 |
| **P0** | Linux 内核升级 | 升级到最新稳定内核 | 即时 |
| **P1** | 编译器加固检查 | checksec + 安全编译选项审计 | 1周内 |
| **P1** | ASan/UBSan CI 集成 | 测试中启用 -fsanitize | 1周内 |
| **P1** | assert() 安全审计 | 生产代码替换 assert 为错误处理 | 1周内 |
| **P2** | AFL++ 模糊测试 | 关键解析器添加 Fuzz 目标 | 1月内 |
| **P2** | CFI 启用 | -fcf-protection=full + LLVM CFI | 1月内 |
| **P2** | 内存安全路线图 | 制定 C/C++ → Rust/Go 迁移计划 | 1月内 |
| **P3** | 定期漏洞扫描 | govulncheck + Trivy + Grype | 持续 |
| **P3** | 供应链安全 | SBOM 生成 + 依赖锁定 | 持续 |
