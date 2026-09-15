# 内存取证与映像重建（VAD · minidump · manual map 残留）

## 命中信号

- `VAD`
- `minidump`
- `PE-sieve`
- `HollowFind`
- `manual map residue`
- `module remap`

## 最小目标

1. 建立 `VAD / module / region` 最小地图
2. 决定 dump 粒度与时机
3. 明确重建目标：OEP、IAT、远端映像、配置明文或桥接对象
4. 落盘 `artifacts/<样本哈希>/memory-layout.md`、`artifacts/<样本哈希>/dump-plan.md`

## 静态观察

- 先看模块、内存权限、映像类型、可疑匿名区、线程起点和远端映像
- 区分"要拿哪份 dump"与"为什么现在拿"

## 动态取证

- dump 前先记录模块边界、入口、保护属性、线程与句柄线索
- 若目标是 manual map 或 hollowing，优先定位真正执行的映像而不是磁盘原件
- 记录 dump 后还需要补的步骤：IAT、重定位、头修复、字符串/配置验证

## 还原与修补

- 先验证 dump 是否可重载、可静态分析、可支持下一阶段
- 不要一次抓整进程就结束；若目标是单模块或单区段，优先做最小 dump

## 常见失误

- 把任意一份内存转储都当成最终样本
- 不记录 VAD / 模块地图，导致 dump 无法解释来源
- 未验证 dump 可读性就继续深度语义分析
