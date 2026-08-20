# 05 加密载荷加载器

- 构建：`python3 payload.py <shellcode.bin> [key] && x86_64-w64-mingw32-gcc -mwindows -o loader.exe loader.c`
- 用法：`loader.exe [mode]`
  - mode 0（默认）：CreateThread 执行 + **睡眠加密循环**（已完整实现，非骨架）
  - mode 1：回调执行（EnumSystemLocalesA）替代 CreateThread
- 技术侧：载荷不落明文（静态零特征）→ 运行时 RC4 解密 → RW 分配 → **RX 转换后才可执行**
  （消除 RWX 窗口）→ 执行。
  **睡眠加密实现要点**：RC4 为对称流密码，同钥再加密=还原明文——密态回置不是
  "再加密一次"而是**回拷内嵌密文 BUF**（loader 的密文即睡眠态镜像）。循环：
  运行 2s → RX→RW 回拷密文 → RW→R 睡眠（此窗口内存扫描只见密文+不可执行页）
  → R→RW 解密 → RW→RX 继续。收尾先回密态再释放。
- 打包器自检：payload.py 生成后**解密回读比对原文**（round-trip 校验，不一致即拒产出）、
  输出 payload.h + payload.bin、打印完整 key（构建记录留档）、密文熵评估
  （<6.0 bit/byte 警告）、PE 输入误用提示。
- 变体（未落地）：AES-CTR 替换 RC4（改 payload.py 与 loader 解密段即可，接口不变）；
  分段解密（用段解段）；分配走 01 直接 syscall。
- 检测侧配对：RX 转换后的进程私有可执行内存遥测（EDR 内存扫描主目标）；线程起始地址
  在未映射镜像区；睡眠加密检测（内存内容周期性变化=加密回置特征）；保护属性频繁
  翻转（RW↔RX↔R）行为遥测。
- 判定表（本地实测后填）：| 引擎 | 结果 | 原文行 |
  运行验证待 Windows 判定环境。
