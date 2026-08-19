# 05 加密载荷加载器

- 构建：`python3 payload.py <shellcode.bin> && x86_64-w64-mingw32-gcc -mwindows -o loader.exe loader.c`
- 技术侧：载荷不落明文（静态零特征）→ 运行时 RC4 解密 → RW 分配 → **RX 转换后才可执行**
  （消除 RWX 窗口）→ 执行。骨架含睡眠加密位（空闲期回密态）。
- 变体：AES-CTR 替换 RC4；分段解密（用段解段）；分配走 01 直接 syscall；执行走回调
  （EnumSystemLocales 等）替代 CreateThread。
- 检测侧配对：RX 转换后的进程私有可执行内存遥测（EDR 内存扫描主目标）；线程起始地址
  在未映射镜像区；睡眠加密检测（内存内容周期性变化=加密回置特征）。
- 判定表：| 引擎 | 结果 | 原文行 |
