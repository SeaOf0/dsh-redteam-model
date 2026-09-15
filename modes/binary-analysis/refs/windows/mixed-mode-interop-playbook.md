# 混合托管互操作逆向（C++/CLI · IJW · P/Invoke · COM interop · CLR hosting）

## 命中信号

- `C++/CLI`
- `IJW`
- `P/Invoke`
- `COM interop`
- `CLR hosting`
- `mscoree / clr / coreclr`

## 最小目标

1. 判清托管/非托管边界与加载顺序
2. 建立至少一条跨边界调用链
3. 明确真正承载业务语义的一侧
4. 落盘 `artifacts/<样本哈希>/mixed-mode-notes.md`、`artifacts/<样本哈希>/bridge-map.md`

## 静态观察

- 看 PE 头、CLR 目录、导出、入口和 `mscoree` 相关导入
- 判断是 `native host -> CLR`、`managed -> native` 还是 `IJW thunk`
- 记录 `x86/x64/WOW64`、CLR 版本和是否伴随 COM

## 动态取证

- 优先抓 `P/Invoke`、`IJW thunk`、`CoCreateInstance`、`CLRCreateInstance`、`CorBindToRuntime*`
- 给每条桥接记录：调用方、被调方、参数/对象、线程上下文、返回值或错误码
- 如果只看得到一侧，立刻补另一侧工具链，不要把单侧视角当成闭环

## 还原与修补

- 先做最小桥接复现，再做局部 patch
- patch 只改首个分叉原因，不要跨托管/非托管两侧同时大改

## 常见失误

- 只看到 IL 就忽略 native thunk
- 只看到 native 导出就忽略 CLR host 初始化
- 把 COM 对象构造误判成普通 API 调用
