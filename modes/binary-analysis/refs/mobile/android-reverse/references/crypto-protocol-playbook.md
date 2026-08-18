# Crypto And Protocol Playbook

目标：恢复协议、签名、密钥来源和关键参数，而不是只罗列算法名。

## 常见锚点

- `javax.crypto.Cipher`
- `MessageDigest`
- `Mac`
- `SecretKeySpec`
- `KeyStore`
- `okhttp3`
- `SSL_write / SSL_read`
- `protobuf`
- `base64`

## 必须回答

- 算法、模式、填充（如 `AES/CBC/PKCS5Padding`，不是只写 AES）
- 密钥或其来源（硬编码 / SharedPreferences / JNI 返回 / 服务端下发 / KDF 派生）
- IV / nonce / salt 来源（固定 / 随机生成 / 请求体字段）
- 参数拼接顺序（拼接后的完整明文必须记录，不能只写"a + b + c"）
- 明文、密文、摘要的对应关系（至少一组完整输入输出对）

## 密钥来源追踪

密钥来源是协议还原最关键的环节，按优先级排查：

1. **硬编码**：搜索 `SecretKeySpec` 构造参数、`byte[]` 常量、字符串 `.getBytes()`
2. **本地存储**：检查 `SharedPreferences`、`MMKV`、`SQLite`、`Android Keystore` 中的密钥条目
3. **KDF 派生**：识别 `PBKDF2`（`SecretKeyFactory`）、`HKDF`、`ECDH` 密钥协商等派生函数，记录 input 和 salt
4. **JNI/Native 返回**：密钥在 `Java_*` 或 `RegisterNatives` 映射的 native 函数中生成，需要先完成 `jni-bridge` 映射
5. **服务端下发**：密钥在登录或握手响应中返回，需要抓包 + TLS 解密后确认

## Protobuf / 二进制协议恢复

当识别到 protobuf 或自定义二进制序列化时：

1. **确认序列化类型**：搜索 `protobuf`、`parseFrom`、`toByteArray`、`writeTo` 为 protobuf；搜索 `readInt`/`readString`/`writeInt` 等为自定义二进制
2. **Protobuf schema 恢复**：在反编译源码中搜索 `.proto` 文件或 `GeneratedMessageLite` 子类的字段定义；如果 `.proto` 不存在，从 `parseFrom` / `mergeFrom` 的 `MessageLite` 子类反推字段编号和类型
3. **自定义二进制协议**：先 hook 序列化/反序列化方法抓输入输出对，再从样本反推字段顺序和类型
4. **gRPC**：搜索 `ManagedChannel`、`MethodDescriptor`、`CallOptions` 确认 gRPC 调用，path 从 `MethodDescriptor` 中提取

## 操作顺序

**抓包基线**（前置建议，非阻断）：若用户尚未提供抓包数据，建议用户先用 mitmproxy/Charles/Wireshark 抓取目标接口的 sample requests，至少包含一组完整的请求/响应对。抓包数据提供输入输出基线，后续静态分析和 hook 验证都以此为参照。若用户已提供或无法抓包（如证书锁定未绕过），直接进入步骤 1。

1. **静态定位**：从锚点类搜索，找到 Cipher/transformation 字符串和密钥构造点
2. **Hook 验证**：在 `Cipher.init`、`doFinal`、`Mac.doFinal`、`MessageDigest.digest` 处 hook，抓算法参数和输入输出
3. **密钥溯源**：从 `SecretKeySpec` 构造点向上追踪密钥字节来源
4. **拼装还原**：确认明文拼接顺序后，在 `run/protocol-notes.md` 记录完整算法链
5. **本地复现**：用 `run/fixtures.json` 中的输入输出对验证还原结果

## JNI / Native 加密

当密钥或加密逻辑在 Native 层时，不要在未完成 `jni-bridge` 映射的情况下推断算法。

必须先按 `references/jni-bridge-playbook.md` 完成 Java→Native 最小链路映射，确认加密函数的 Java 入口、Native 符号/RVA 和参数语义。然后在 SO 中搜索加密库常量（OpenSSL/BoringSSL/mbedTLS 的 S-box、SHA-256 K 等特征常量）确认是否使用标准库还是自定义实现。

## 扩展专题

以下内容是操作顺序之外的高级场景和参考材料，按需查阅。

### 白盒密码学分析

当遇到白盒实现（密钥不直接出现，通过查表实现加密）时：

### 白盒 AES

1. **识别特征**：大量 8-bit 或 32-bit 查找表，输入 128-bit 输出 128-bit
2. **DFA 差分故障攻击**：
   - 步骤 1：在 Unidbg 中加载目标 SO
   - 步骤 2：注入正确明文，记录正确密文
   - 步骤 3：在倒数第 1-2 轮注入单字节故障
   - 步骤 4：记录错误密文
   - 步骤 5：收集 128-256 组正确/错误密文对
   - 步骤 6：利用 DFA 约束恢复最后一轮密钥
   - 步骤 7：逆推完整 AES 密钥
3. **工具**：phoenixAES（DFA 自动化）、Unidbg（故障注入环境）

### 白盒 SM4

- DFA 方法类似 AES，但轮函数结构不同
- 需要调整故障注入位置和约束方程

SM4 与 AES DFA 关键差异：
- **32 轮结构**（vs AES 10/12/14 轮），需攻击最后 4 轮（29-32）恢复完整密钥
- **四字 Feistel 结构**（vs AES 4×4 字节矩阵），故障传播模式不同
- **L 变换**：`L(B) = B ⊕ rotl(B,2) ⊕ rotl(B,10) ⊕ rotl(B,18) ⊕ rotl(B,24)`，逆向为 `L'(C) = C ⊕ rotl(C,2) ⊕ rotl(C,4) ⊕ ... ⊕ rotl(C,30)`（11 项异或）

SM4 DFA 完整流程：

1. **正确密文采集**：Unidbg 加载 SO，相同明文加密，记录参考密文
2. **故障注入**（目标轮的 S-box 查找前）：

```python
diff = random.randint(1, 255)         # 非零单字节故障
offset = random.randrange(0, 25, 8)   # 字节位置: 0/8/16/24
index = random.randint(1, 3)          # 状态字索引: 1/2/3（非目标字）
ulbuf[idx + index] ^= diff << offset  # 注入故障
```

3. **差分分类**（按故障密文与参考密文的差分字节数）：

| 差分字节数 | 故障轮 | 恢复目标 |
|-----------|--------|---------|
| 5 | 第 32 轮注入 | rk32 |
| 8-9 | 第 31 轮注入 | rk31（需先用 rk32 解密一轮） |
| 12-13 | 第 30 轮注入 | rk30 |
| 16 | 第 29 轮注入 | rk29 |

4. **候选密钥恢复**（每字节独立）：

```python
delta_C = ref_word[3] ^ fault_word[3]  # 密文差分
delta_B = l_inv(delta_C)               # 逆L变换得S-box输出差分
A = ref_word[0] ^ ref_word[1] ^ ref_word[2]
A_star = fault_word[0] ^ fault_word[1] ^ fault_word[2]
alpha = extract_byte(A ^ A_star)       # S-box输入差分
beta = extract_byte(delta_B)           # S-box输出差分
candidates = IN_TABLE[alpha][beta]     # 差分查表
key_byte_candidates = extract_byte(A) ^ candidates
```

IN_TABLE 预计算：`IN[Δin][Δout] = {x : SBOX[x] ⊕ SBOX[x⊕Δin] == Δout}`

5. **主密钥恢复**（逆向密钥调度）：

```python
# 轮密钥填入（注意字节序反转：EDF3A9FA → FAA9F3ED）
rk[32:36] = [rk29, rk30, rk31, rk32][::-1]
for i in range(31, -1, -1):
    rk[i] = rk[i+4] ^ round_key(rk[i+1] ^ rk[i+2] ^ rk[i+3] ^ CK[i])
master_key = rk[:4] ^ FK
# FK = [0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC]
```

**字节序陷阱**：phoenixSM4 输出的轮密钥与 SM4 密钥调度工具的字节序相反，每个 32 位字需要逐字节反转。

工具：phoenixSM4（自动化 DFA）、Unidbg（故障注入环境）、SM4_Keyschedule（逆向密钥调度）

### 算法识别签名表

从常量和特征快速识别加密算法：

| 算法 | 特征常量 | 识别方法 |
|---|---|---|
| MD5 | `0x67452301`, `0xEFCDAB89`, `0x98BADCFE` | 初始化常量 |
| SHA-1 | `0x67452301`, `0xEFCDAB89`, `0x98BADCFE`, `0x10325476`, `0xC3D2E1F0` | 初始化常量（比 MD5 多一个） |
| SHA-256 | `0x6A09E667`, `0xBB67AE85`, `0x3C6EF372` | 前 3 个初始化常量即可确认 |
| SM3 | `0x7380166F`, `0x4914B2B9`, `0x172442D7` | 国密标准初始化常量 |
| AES | S-box `0x63, 0x7C, 0x77, 0x7B...` | 特定 S-box 表 |
| RC4 | KSA: `S[i] = i; swap(S[i], S[j])` PRGA | 特征状态初始化 |
| xxtea | `0x9E3779B9`（Delta 常量） | 单常量即可识别 |
| Base64 | 字符表 `A-Za-z0-9+/` + `=` padding | 编码字符特征 |
| CRC32 | 表 `0x00000000, 0x77073096, 0xEE0E612C...` | 查找表 |

### CRC / 完整性校验绕过

当 SO 对自身代码或关键数据做 CRC/Hash 校验时：

### 方法 1：伪造内存段

- Hook `open` / `mmap`，当读取自身 SO 时返回原始未修改的内存映射
- 适用于：校验函数通过文件读取计算 CRC

### 方法 2：伪造磁盘文件（内核级）

- 通过 KernelSU/ Magisk 模块，在读取 SO 文件时返回原始版本
- 适用于：校验函数直接读取 APK 内 SO 文件

### 方法 3：基于 Trace 的定位和绕过

1. 用 Frida Stalker trace 校验函数
2. 找到 CRC/Hash 计算的起始和结束点
3. Hook 校验结果比较指令，强制返回成功
4. 适用于：所有基于内存或文件的完整性校验

### 商业算法模式识别

常见商业应用的签名算法特征：

| 应用 | 签名参数 | 特征 |
|---|---|---|
| 抖音/TikTok | `x-gorgon` | 基于 SO 的自定义签名，4 段结构 |
| 京东 | `jdgs` / `sig3` | 多层签名，包含设备指纹 |
| 某社交 | `zzzghostsigh` | 基于 Native 的签名，包含时间戳和设备信息 |
| 美团 | `mtgsig` | 多版本签名，V2 基于纯 Java，V3+ 走 Native |

识别流程：
1. 从 HTTP 请求中定位签名参数字段名
2. 反向追踪到生成函数
3. 确认是否进入 Native 层
4. 按本 playbook 的操作顺序完整还原

### 7 阶段协议还原工作流

完整协议还原遵循以下顺序：

1. **流量拦截**：确认协议类型（HTTP/HTTPS/WebSocket/自定义 TCP/UDP）
2. **Java 层追踪**：从网络库入口追踪到签名/加密调用点
3. **Native 入口确认**：确认加密/签名是否在 JNI 层实现
4. **Unidbg 模拟**：在 PC 上模拟调用签名函数，验证可复现性
5. **算法识别**：使用常量表和特征识别具体算法
6. **密钥提取**：追踪密钥来源（硬编码/动态生成/KDF）
7. **重实现验证**：用 Python/JS 等语言重实现签名逻辑，对比结果

### 端到端示例：HTTP+JSON 签名还原

以下是一个典型的 HTTP API 签名还原完整流程，展示每阶段的具体操作和产出：

**目标**：还原 `POST /api/order` 请求中 `sign` 字段的生成逻辑

**阶段 1 — 流量拦截**：
```
# 工具：mitmproxy / Charles / Wireshark
# 抓包结果
POST /api/order
Headers: Content-Type: application/json
Body: {"product_id":"P123","timestamp":"1710000000","sign":"a1b2c3d4e5f6...","user_id":"U456"}
```
产出：至少 3 组不同参数的请求样本，确认 `sign` 值随参数变化

**阶段 2 — Java 层追踪**：
```bash
# jadx 搜索 "sign" 字段名，定位赋值点
grep -r '"sign"' sources/ -l
# 找到 RequestBuilder.java 中的 buildSign() 方法
# Frida hook 确认：
```
```javascript
Java.perform(function() {
  var RB = Java.use("com.target.network.RequestBuilder");
  RB.buildSign.implementation = function(params) {
    var result = this.buildSign(params);
    console.log("buildSign input: " + params);
    console.log("buildSign output: " + result);
    return result;
  };
});
```
产出：确认 `buildSign` 的输入是 `product_id + timestamp + user_id`，输出是 hex string

**阶段 3 — Native 入口确认**：
```bash
# jadx 搜索 System.loadLibrary / JNI 调用
grep -r 'System.loadLibrary\|native ' sources/ -B2 -A2
# 发现 buildSign 内部调用 SignUtil.nativeSign(byte[])
```
若发现 JNI 调用：Read `jni-bridge-playbook.md` 完成桥接映射。若纯 Java 实现：跳过此阶段

**阶段 4 — 算法识别**：
```javascript
// hook javax.crypto 确认算法
Java.perform(function() {
  var Cipher = Java.use("javax.crypto.Cipher");
  Cipher.getInstance.overload('java.lang.String').implementation = function(transformation) {
    console.log("Cipher algorithm: " + transformation);
    return this.getInstance(transformation);
  };
  var Mac = Java.use("javax.crypto.Mac");
  Mac.getInstance.overload('java.lang.String').implementation = function(algorithm) {
    console.log("Mac algorithm: " + algorithm);
    return this.getInstance(algorithm);
  };
});
// 输出: "Mac algorithm: HmacSHA256"
```
产出：确认使用 HMAC-SHA256

**阶段 5 — 密钥提取**：
```javascript
// hook SecretKeySpec 获取密钥
Java.perform(function() {
  var SKS = Java.use("javax.crypto.spec.SecretKeySpec");
  SKS.$init.overload('[B', 'java.lang.String').implementation = function(key, algo) {
    console.log("SecretKeySpec algo=" + algo + " key=" + Java.array('byte', key).map(function(b) {
      return ('0' + (b & 0xFF).toString(16)).slice(-2);
    }).join(''));
    return this.$init(key, algo);
  };
});
// 输出: key=68656c6c6f776f726c64313233...
```
产出：确认密钥是硬编码字符串 `helloworld123...` 的 UTF-8 bytes

**阶段 6 — 拼接顺序确认**：
```javascript
// hook buildSign 前，对比多组样本确认拼接规则
// 样本 1: product_id=P123, timestamp=T1, user_id=U456 → sign=S1
// 样本 2: product_id=P789, timestamp=T2, user_id=U456 → sign=S2
// 假设: sign = HMAC-SHA256(product_id + "|" + timestamp + "|" + user_id, key)
```
用 Python 验证假设：
```python
import hmac, hashlib
key = b'helloworld123...'
msg = 'P123|1710000000|U456'
result = hmac.new(key, msg.encode(), hashlib.sha256).hexdigest()
assert result == 'a1b2c3d4e5f6...', "签名不匹配"
```

**阶段 7 — 重实现验证**：
```python
# solver-template.py
import hmac, hashlib, time

def generate_sign(product_id, user_id, key='helloworld123...'):
    timestamp = str(int(time.time()))
    msg = f'{product_id}|{timestamp}|{user_id}'
    sign = hmac.new(key.encode(), msg.encode(), hashlib.sha256).hexdigest()
    return {'product_id': product_id, 'timestamp': timestamp, 'user_id': user_id, 'sign': sign}

# 对比 3 组样本全部通过
```
产出：可独立运行的 Python 实现，不依赖 Android 运行环境

## 常见偏差

- 只写了算法名但没写 transformation 字符串（如写 AES 但没写 CBC/PKCS5Padding）
- 密钥来源写"硬编码"但没有定位到具体类和行号
- 拼接顺序只写了字段名但没给出实际样本
- protobuf 目标只抓了序列化后字节但没恢复 schema
- Native 加密在未完成桥接映射前就下了算法结论

## 最小交付

- `run/protocol-notes.md`
- `run/fixtures.json`

## 实战补充：OLLVM 下快速判定与密钥恢复

### OLLVM 混淆下的快速判定补充

算法识别签名表见上方第 142 行。OLLVM 混淆 SO 下的组合信号判定（MD5 + malloc(0x21)、LZ4 两步签名、RC4 FLA 免疫等）和验证方法见 `references/technique-extract-2026-05.md` 第 4 节。

### DEX 格式不变量密钥恢复

当 XOR/S-box 密钥作用于 DEX 结构区域且密钥空间有限时，利用 DEX 格式不变量逐字节确定密钥：

- `map_list.size` 高 3 字节必为 0
- `map_item[0].type` 必为 `0x0000`（HEADER_ITEM）
- `map_item[1].type` 必为 `0x0001`（STRING_ID_ITEM）
- `map_item[0].unused` 必为 0

每个不变量唯一确定一个 key 字节。交叉验证：解密后检查链式 offset 连续性（`string_ids_off = header_end`、`type_ids_off = string_ids_end` 等）。

当 S-box key 只有 256 种且已知明文（如 DEX magic `dex\n`）时：暴力枚举全部 256 种 key，检查解密后已知位置是否匹配，唯一解确认。

详细案例见 `references/technique-extract-2026-05.md` 第 3-4 节。

