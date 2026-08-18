# Go / Rust 二进制逆向

> 定位：`platform/go-rust-reverse/` 的参考手册。Go 深覆盖在 `methodology/reverse-engineering/references/go-reverse.md`（240 行），
> 本篇补 **Rust 侧**（识别、字符串恢复、符号 demangle、类型布局、工具链），并保留 Go 侧速查锚点。

---

## 1. Go（速查锚点）

- 特征：`runtime.` 大量函数、`go.buildid`、`GOROOT`/`GOPATH` 路径、函数 5000-50000+。
- 核心结构：pclntab（函数名/地址映射，strip 后常在）、moduledata（类型/itab）。
- 字符串：`(ptr, len)` 结构，非 null 结尾，IDA/Ghidra 默认识别会漏。
- 工具：GoReSym / redress / GoResolver（Garble 去混淆）/ GoStringUngarbler。

> 完整 Go 逆向手册：`methodology/reverse-engineering/references/go-reverse.md`。

---

## 2. Rust 逆向

### 2.1 识别

```bash
strings binary | grep -iE "rust|rustc|\.rs:|/rustc/|core::|std::|cargo"
# 特征：panic 消息带源码路径 + 行号（未 strip 时）
strings binary | grep -E "\.rs:[0-9]+"
```

识别特征：
- 含 `rustc` 版本字符串（`rustc 1.xx.x`）或 `/rustc/<hash>/` 路径。
- panic 消息：`panicked at '...', src/main.rs:42:9`（含 `.rs:行:列` 源码定位）。
- 符号（未 strip）：`std::...`、`core::...`、`<module>::<fn>::<hash>` 格式。
- 与 Go 区别：Go 有 pclntab（体积大、runtime 特征强），Rust 体积相对小、无 pclntab、有 `std::rt::lang_start` 入口。

### 2.2 符号恢复（demangle）

Rust 符号用 v0 legacy/legacy mangling，需 demangle：

```bash
# rustfilt / c++filt（检测后使用）
nm binary | rustfilt
strings binary | rustfilt
# 或 llvm-nm --demangle / rustfilt 组合
```

判据：demangle 后能读到 `<crate>::<module>::<fn>` 层次，快速定位 main/业务函数。

### 2.3 字符串恢复

Rust 字符串是 `&str`（`(ptr, len)`），非 null 结尾，与 Go 类似，IDA/Ghidra 默认字符串识别会漏：

```text
1. 用 Ghidra/IDA 的「字符串定义」手动按 (ptr, len) 定义。
2. 关注 panic 消息（含源码路径），用于定位逻辑。
3. strings -a 全量导出后 rustfilt，筛选业务相关串。
```

判据：恢复的字符串与源码路径/panic 消息互证，定位到业务逻辑。

### 2.4 类型布局与模式识别

| Rust 特性 | 逆向特征 | 识别要点 |
|---|---|---|
| `Option<T>` | 枚举（tag + payload），None 常为 0/1 判别 | 判别值 + 分支 |
| `Result<T, E>` | 双枚举（Ok/Err），Err 分支常接 panic/返回 | 判别 + 错误处理路径 |
| `enum`（多态） | 判别联合（discriminant + union） | 判别值 + 各变体布局 |
| trait object（`dyn`） | 胖指针（data ptr + vtable ptr） | 两个指针一组，vtable 内函数指针 |
| 迭代器链（`.iter().map().filter()`） | 大量内联闭包 + 惰性求值 | 闭包体紧凑、链式调用难读 |
| 所有权（move/borrow） | 无 GC，栈上 move 语义 | 变量传递后原位置「逻辑失效」 |

### 2.5 定位 main 与业务逻辑

```text
1. 未 strip：符号表找 main / <crate>::main。
2. strip 后：std::rt::lang_start（Rust 运行时入口）→ 回填 main 指针。
3. 从 panic 消息的源码路径（src/main.rs:行）反查调用链。
```

### 2.6 工具链

| 工具 | 用途 |
|---|---|
| rustfilt | 符号 demangle |
| Ghidra / IDA | 反汇编/反编译（IDA 9.x 对 Rust 有改进） |
| BinDiff / Diaphora | 与同源码编译的对照版 diff（迁移符号） |
| Frida / gdb / lldb | 动态 hook（配合去混淆） |

---

## 3. 两者通用原则

- **优先字符串驱动**（Rust 用 panic 路径 + demangle；Go 用 pclntab 恢复），避免在运行时库中迷路。
- **先识别入口**（Rust `lang_start`/Go `runtime.main`），再聚焦 `main`/业务 crate。
- **strip 后用工具恢复**（Go 用 GoReSym/redress；Rust 用 rustfilt + diff 迁移符号）。

---

## 来源与延伸

- Go 完整手册：`methodology/reverse-engineering/references/go-reverse.md`。
- 符号恢复（Rust/Go/通用）：`methodology/reverse-engineering/references/symbol-recovery.md`。
- 通用语言/编译器特征（含 MSVC/GCC/Clang）：`methodology/reverse-engineering/references/languages-compiled.md`、`kernel-driver-reverse.md`（C/C++ 模式识别）。
