# 异常与启动链分析（TLS callback · SEH/VEH · CRT · CFG/CET）

## 命中信号

- `TLS callback`
- `SEH`
- `VEH`
- `UnhandledExceptionFilter`
- `CFG`
- `CET`
- `WOW64`

## 最小目标

1. 枚举 `TLS callback -> entrypoint -> CRT -> SEH/VEH` 启动链
2. 判断异常链属于反分析、解密门还是正常业务控制流
3. 找到安全断点与 hook 点
4. 落盘 `artifacts/<样本哈希>/exception-runtime-notes.md`、`artifacts/<样本哈希>/startup-chain.md`

## 静态观察

- 先看 TLS 目录、异常处理注册、`SetUnhandledExceptionFilter`、`AddVectoredExceptionHandler`
- 判断断点为什么失效：架构不匹配、异常吞掉、TLS 先跑、CFG/CET 保护、WOW64 边界

## 动态取证

- 用最小断点记录异常前后寄存器、模块、线程与返回目标
- 把异常当成"控制流边界"，不要只把它当噪音
- 记录哪些操作会破坏启动链，比如过早 patch、错误断点或错误附加时机

## 还原与修补

- 先复现最小异常路径，再 patch 首个分叉原因
- 需要 dump 时，优先选择异常后、明文前的窗口

## 常见失误

- 只盯 `main/WinMain`，忽略 TLS callback
- 把异常吞掉逻辑误判成崩溃
- 在 WOW64 边界上用错调试器或错层 hook
