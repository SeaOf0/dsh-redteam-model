# 参考文档导航

本目录包含 packer skill 的全部参考文档，按阅读顺序排列。

## 阅读路径

### 新手路径（首次使用）
1. `layout.md` — 理解目录结构
2. `techniques.md` — 了解可用的注入技术
3. `randomization.md` — 掌握代码随机化规则
4. `gostager.md` — Go stager 分支完整流程（推荐模式）

### 日常使用
5. `encryption.md` — 加解密函数与密钥约定
6. `defense-modules.md` — 防御模块实现模式
7. `verification.md` — 编译前/编译后验证清单

### 排障
8. `troubleshooting.md` — 完整诊断流程（诊断 0-7 + 模式分流）

### 360 QVM 专项
9. `qvm-bypass.md` — 360 QVM 7 维特征对抗（UUID + Fiber + IAT欺骗 + Overlay注水 + PE元数据修复）

## 文档概览

| 文件 | 职责 | 依赖 |
|------|------|------|
| `layout.md` | 目录职责约定 | 无 |
| `techniques.md` | 13 类注入技术 API 调用链 + SyscallN 参数表（含 UUID 编码 8A/8B 两种变体） | 无 |
| `randomization.md` | 代码随机化规范 | 无 |
| `gostager.md` | Go stager 流程细节（CS HTTP 下载 + 反射加载） | `SKILL.md` |
| `encryption.md` | 加解密函数参考（AES-CBC + XOR） | 无 |
| `defense-modules.md` | 防御模块代码模式（ETW/AMSI/抗沙箱/Sleep/脱钩） | 无 |
| `verification.md` | 编译前验证 + 编译后 PE 验证 | `techniques.md` |
| `troubleshooting.md` | 诊断 0-7 + 常见问题 + 模式分流 | `verification.md` |
| `qvm-bypass.md` | 360 QVM 专项免杀（7 维对抗 + 编译后处理） | `techniques.md`, `defense-modules.md` |
