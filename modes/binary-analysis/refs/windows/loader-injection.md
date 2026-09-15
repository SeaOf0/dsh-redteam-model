# Loader 与注入链还原

适用：`CreateRemoteThread`、`NtCreateThreadEx`、`QueueUserAPC`、线程劫持、Reflective DLL、Manual Map、Process Hollowing、RunPE、早期启动注入。

## 静态观察

- 先确认宿主进程、位宽、会话、权限、是否 WOW64、是否有 PPL / CFG / CIG / ACG 限制。
- 先区分"真实注入链"与"壳 / 自解密 / 自装载"——两者会复用同一批 API，但验收点不同。
- 把远端句柄、内存保护、映像来源、触发线程分开记录。

## 动态取证

- 静态优先看：`CreateRemoteThread/NtCreateThreadEx/QueueUserAPC/VirtualAllocEx/WriteProcessMemory/MapViewOfFile/NtMapViewOfSection/SetThreadContext/ResumeThread`。
- 动态优先抓：句柄创建、远端映像写入、入口转移、加载后修补、异常恢复。
- 遇到 Manual Map 时，把 PE header 修补、reloc、IAT、TLS callback、SEH/VEH 初始化拆开。

## 还原

- 先画出最小链：宿主选择 -> 远端内存 -> 载荷写入 -> 入口触发 -> 载后修正。
- 若是 Hollowing / RunPE，单独记录原始映像、替换映像、入口切换点和线程上下文改写。
- 若是 Reflective / Manual Map，补一份 `artifacts/<样本哈希>/remote-map.md`，记录远端区段与权限变化。

## 修补与复现

- patch 只服务于稳定观察或 dump：例如跳过一次性权限检查、延后自删、保留调试输出。
- 如果要本地复现，优先重建 loader 主链，而不是把所有反分析与环境噪音一起搬过去。

## 交付最少包含

- `artifacts/<样本哈希>/loader-injection-notes.md`
- `artifacts/<样本哈希>/remote-map.md`
- `artifacts/<样本哈希>/loader-hook-template.js`
- 报告中明确宿主、装载技术、远端模块 / 区段、入口切换证据。
