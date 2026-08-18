# 反编译引擎选择策略

## 决策树

```
目标文件类型?
│
├─ APK / DEX / JAR / AAR
│   ├─ 代码混淆程度?
│   │   ├─ 轻度 (ProGuard 重命名) ──→ jadx --deobf
│   │   ├─ 中度 (字符串加密) ──→ jadx + fernflower 交叉验证
│   │   └─ 重度 (壳/强混淆) ──→ 先脱壳, 再 jadx + fernflower both
│   │
│   ├─ 是否有 Kotlin 代码?
│   │   ├─ 是 ──→ vineflower 优先 (Kotlin 支持更好)
│   │   └─ 否 ──→ jadx 优先
│   │
│   └─ jadx 输出质量?
│       ├─ 完整可读 ──→ 使用 jadx 结果
│       ├─ 部分错误 ──→ fernflower 补充错误部分
│       └─ 大量错误 ──→ 切换到 fernflower 为主引擎
│
├─ XAPK / APKS
│   └─ 自动解压 ──→ 逐个内部 APK 按上述策略处理
│
├─ AAB
│   └─ bundletool extract-apks ──→ split APKs ──→ 按上述策略处理
│
└─ SO (Native)
    └─ jadx/fernflower 不适用 ──→ 使用 IDA Pro / Ghidra
```

## 引擎对比

| 维度 | jadx | Fernflower / Vineflower |
|---|---|---|
| **默认推荐** | 是 | 否（补充） |
| **APK 直接支持** | 是 | 否（需 dex2jar） |
| **资源解码** | 是 | 否 |
| **反混淆** | 内置 --deobf | -ren=1 |
| **速度** | 快 | 中等 |
| **准确度** | 高 | 某些场景更高 |
| **Kotlin 支持** | 好 | Vineflower 更好 |
| **错误容忍** | --show-bad-code | 跳过失败方法 |
| **GUI** | jadx-gui | 无 |
| **XAPK 处理** | 需脚本 | 需脚本 |

## 使用建议

### 标准流程

1. 先用 jadx 反编译（含 `--show-bad-code`）
2. 检查输出质量（搜索 `/* Error */` 或不完整代码）
3. 若有问题区域，用 fernflower/vineflower 补充
4. 交叉对比两个引擎输出

### 高对抗目标

1. 先评估保护等级（A0-A7）
2. A4+ 需要先脱壳/解密
3. 脱壳后同时使用两个引擎
4. 对比结果确认覆盖范围

### 资源受限环境

- 只需要代码：jadx `--no-res`
- 只需要资源：apktool decode
- 需要完整项目：jadx `--export-gradle`
