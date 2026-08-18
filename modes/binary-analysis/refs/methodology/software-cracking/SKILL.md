# 注册算法还原方法体系 + 补丁制作 + 网络验证绕过

> 定位：persona 主观念「②逆向破解——key/算法/授权逻辑还原」的**手册级支撑**（此前仅 persona 一句宣言）。
> 本文给出一条完整可执行链：验证点定位 → 算法还原 → keygen 构造 → 补丁制作 → 网络验证绕过。
> 结论交付遵守 persona 硬规则：字节级证据 + 算法模拟 + 完整 python 复现脚本（exp/<sample-id>.py，whoami 级最小影响）。
> 授权范围：只对已获授权的目标做破解/还原；删除类操作五模式严禁执行，只提示。

---

## 0. 总体心智模型

破解/还原的本质是把「授权判定」抽象成一个可逆的函数 `f(输入) → {通过, 拒绝}`，然后选一条路：

1. **还原 f**（keygen）—— 逆向出算法，生成合法输入（序列号/授权文件），不改程序。
2. **篡改 f 的出口**（补丁）—— 把「拒绝分支」改成「通过分支」，不改算法。
3. **绕开 f 的外部依赖**（网络验证绕过）—— 让「服务端验证」这条支路返回通过。

三条路可独立、可组合。选路依据：算法是否可逆（有 keygen 价值）、是否必须保留原程序（客户要求正版补丁）、验证是否依赖网络。

---

## 1. 验证点定位（找到 f 在哪）

### 1.1 字符串定位

```text
1. 搜索提示字符串（「注册失败/Invalid license/trial expired/序列号错误」）。
   x64dbg：x64dbg_search string pattern="Invalid license"
   IDA：Search → Text；Ghidra：Search → Memory。
2. 对字符串地址 xrefs_to → 找到引用它的比较指令（cmp/test 附近）。
3. 比较指令即 f 的判定点。
```

判据：xrefs 定位到「读取输入 → 与常量/计算值比较 → 条件跳转」的指令簇，即验证点。

### 1.2 API 断点定位（GUI/输入类）

输入读取 API 是「用户输入进入程序」的必经口，下断点回溯：

| 输入形态 | 断点 API |
|---|---|
| 对话框文本框 | GetDlgItemTextA/W、GetWindowTextA/W |
| 命令行/文件 | GetCommandLineA/W、ReadFile、fgets |
| 网络验证返回 | recv、InternetReadFile、WinHttpReadData |
| 授权文件读取 | CreateFileA/W、ReadFile |

```text
x64dbg：bp GetDlgItemTextA → F9 → 触发后看调用栈回溯到 f。
MCP：x64dbg_breakpoints set_software address="user32.GetDlgItemTextA"
```

判据：断点命中后调用栈（get_call_stack）往回数几帧，能看到「读输入 → 传参 → 调用校验函数」的边界，即 f 的入口。

### 1.3 消息框定位（结果出口）

```text
bp MessageBoxA/W（或 GetMessageBox），命中即「拒绝/通过」出口。
回溯调用点 → 其上的条件跳转就是判定分支。
```

判据：消息框文案（「成功/失败」）与条件跳转方向对应，确认判定点语义。

---

## 2. 算法还原（汇编 → 伪代码 → 模式识别）

### 2.1 汇编 → 伪代码

```text
1. 反汇编（objdump -d -M intel / IDA / Ghidra），定位 f 入口。
2. 反编译（Ghidra/IDA Hex-Rays/radare2 pdc）得伪代码。
3. 标注输入缓冲、常量、比较点、返回值。
```

判据：伪代码中可见「输入 → 变换 → 与常量比较 → 返回」的数据流。

### 2.2 算法模式识别（判别 f 的类型）

| 模式 | 识别特征 | 还原策略 |
|---|---|---|
| **MD5/哈希校验** | 导入 MD5Init/MD5Update（或常量 0x67452301 等 MD5 IV）、对输入哈希后与 16/32 字节常量比较 | 哈希不可逆——**放弃逆推输入，改补丁或「hash 注入」**（把目标哈希换成已知输入的哈希） |
| **序列号算法** | 对每个字符做算术/异或/查表，累加或分块，与串/常量比较 | 可逆——还原变换，逆向构造序列号（keygen） |
| **公钥/私钥（RSA/ECC）** | 导入 CryptDecrypt/BCryptVerifySignature，或内嵌大整数模数（如 "00 C4 ..."）、e=65537 | 无法逆推私钥——改「替换内嵌公钥为自己的密钥对」或补丁 |
| **黑盒查表/常量比对** | 输入直接 memcmp/strcmp 与硬编码串 | 直接读出常量串即 keygen |
| **网络服务端判定** | 校验结果来自 recv 返回值，本地无完整算法 | 走 §5 网络验证绕过 |

### 2.3 黑盒差分（无符号/难读时）

```text
1. 同长度不同输入，观察比较失败点（指令计数/断点位置）是否前移/后移。
2. 字符逐位差分：正确字符使「比较深入」一步（instruction-count side channel，见 tools-dynamic.md）。
3. 内存 dump 比对：比较前后 dump 关键缓冲，看哪个字节参与比较。
```

判据：逐位差分收敛出「每位正确字符」的 oracle，即等价于还原比较逻辑。

---

## 3. keygen 构造（还原 f 的逆）

```text
1. 用还原出的算法写等价 python（参数化，只读输入 → 输出序列号）。
2. 逆向构造：若 f = 比较(变换(input), target)，则 keygen = 变换^{-1}(target)。
3. 对哈希类：keygen 退化为「生成满足 hash==target 的输入」不可行 → 改 hash 注入或补丁。
4. 对公钥类：keygen = 用自己生成的私钥签名，但需同步替换程序内嵌公钥（与补丁配合）。
```

交付形式（persona 约定）：`exp/<sample-id>.py`，退出码 0 = 生成成功；输出合法序列号供客户手动复现。

判据：keygen 输出在**原版未改**程序上验证通过 = f 被正确还原；验证不过 = 算法还原有误，回 §2。

---

## 4. 补丁制作（篡改 f 的出口）

### 4.1 补丁策略体系

| 策略 | 手法 | 适用 | 副作用 |
|---|---|---|---|
| **jmp/je 翻转** | 条件跳转取反（je↔jne / jz↔jnz） | 单点布尔判定 | 最小侵入，首选 |
| **NOP** | 去掉检查（把「若失败则退出」的调用/跳转 NOP 掉） | 冗余的失败处理 | 可能跳过必要初始化 |
| **算法替换** | 把校验函数改成「恒返回真」（ret 后 mov eax,1; ret） | 哈希/公钥类不可逆 | 需空间足够写 jmp |
| **常量替换** | 把目标哈希/目标序列号替换为已知合法值 | MD5 校验、序列号比对 | 需重算/重签（macOS 重签名） |
| **keygen 注入** | 内嵌「合法序列号生成器」或接受任意输入的补丁 | 需要可逆但不想改原算法 | 侵入较大 |

### 4.2 补丁操作（x64dbg / IDA / 脚本）

```text
x64dbg：断在判定点 → 双击指令汇编改（空格）→ 应用补丁 → 导出补丁文件。
  MCP：x64dbg_patches apply address="0x401234" bytes="75 0E"（je→jne 翻转）
       x64dbg_dumping export_patch_file filename="patch.bin"

IDA：Edit → Patch program → Assemble / Change byte → Edit → Patch program → Apply patches to input file。

脚本兜底（python3）：按文件偏移写字节（pefile 定位 RVA→文件偏移）。
```

### 4.3 三平台补丁文件产出

| 平台 | 产出物 | 工具 |
|---|---|---|
| Windows PE | 打补丁的 .exe（或 .1337 补丁器产物） | x64dbg 导出 / pefile 写字节 |
| Linux ELF | 打补丁的 ELF | python 写字节 / radare2 `wx` |
| macOS Mach-O | 打补丁后**必须重签名**（codesign --force --deep --sign -） | codesign + lldb/hopper 定位偏移 |

判据：补丁后样本在授权环境跑通「原拒绝路径变通过」+ 记录打补丁的虚拟地址/文件偏移/原始字节/新字节（字节级证据）。

---

## 5. 网络验证绕过（绕开外部依赖）

### 5.1 识别网络验证形态

```text
1. 抓包（Wireshark/tshark/mitmproxy）看授权请求：URI、参数、响应体。
2. 静态定位：recv/InternetReadFile 后的解析逻辑，确认「响应里哪个字段=通过」。
3. 判型：
   - 纯在线校验：本地无算法，响应直接决定通过/拒绝。
   - 混合校验：本地算法 + 服务端二次确认（心跳/签名）。
   - 离线回退：网络失败时走本地缓存的授权（可断网触发回退）。
```

### 5.2 绕过路线（按侵入度递增）

| 路线 | 手法 | 适用 |
|---|---|---|
| **本地回环替换** | 把验证服务器域名/IP 指到 127.0.0.1，本地起服务返回「通过」响应 | 响应逻辑可复刻 |
| **hosts 重定向** | 改 hosts（/etc/hosts、C:\Windows\System32\drivers\etc\hosts）把域名指向可控主机 | 域名直连、无证书固定 |
| **模拟服务器应答** | 本地起 mock 服务器，按抓包到的响应格式返回合法授权（含签名/时间戳字段） | 响应可结构复刻 |
| **响应签名替换** | 若响应带服务端签名，替换本地公钥为自签密钥并自签响应（配合补丁） | 签名校验类 |
| **补丁跳检** | 直接 NOP 掉「校验响应」分支 | 响应不可复刻时的兜底 |

### 5.3 可执行链示例（hosts + 本地 mock）

```text
1. 抓包确定：请求 POST https://license.example.com/verify，响应 {"valid":true,"expire":"..."}。
2. hosts 重定向：echo "127.0.0.1 license.example.com" >> /etc/hosts（权限不足时改走补丁跳检）。
3. 本地 mock（python3 http.server 或 flask），对 /verify 返回 {"valid":true}。
4. 若程序校验证书：导入本地自签 CA 或改补丁跳检。
```

判据：程序在「服务端不可达/被替换」情况下仍进入「已授权」状态；记录抓包证据与 mock 响应字段。

---

## 6. 结论交付纪律（persona 硬规则落地）

- 还原/破解结论必须带**字节级证据**：验证点虚拟地址 + 文件偏移 + 关键反汇编片段 + 原始/补丁字节。
- 算法还原交付**可运行 python 复现脚本**（exp/<sample-id>.py：keygen 或校验模拟，只读运行，退出码 0 = 复现成功）。
- 补丁/网络绕过标注「whoami 级最小影响」：破坏性步骤默认关，只读/最小改动。
- 删除类操作严禁执行，只提示（客户自行决定）。
- 无法完整还原的算法标「疑似」，不宣称已破解。

---

## 来源与延伸

- 序列号/授权算法还原、补丁、网络绕过为本文自建方法论；CTF 侧同类技巧（memcmp/时间侧信道、LD_PRELOAD、angr 解约束）见 `methodology/reverse-engineering/references/tools-dynamic.md`。
- angr 符号执行解约束在 keygen 的实战：`methodology/reverse-engineering/references/symbolic-execution-deep.md`。
- macOS 补丁重签名链：`platform/macos-reverse/references/macho-triage.md`。
