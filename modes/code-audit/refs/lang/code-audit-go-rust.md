---
name: code-audit-go-rust
description: >
  Go 与 Rust 应用安全代码审计完整手册 — 覆盖 Go 的 SQL 注入、命令注入、路径穿越、
  SSRF、并发竞态、反序列化 (json/xml/gob)、TLS 配置错误、unsafe 块；Rust 的 unsafe
  代码审计、内存安全越界、逻辑漏洞、依赖安全 (cargo audit)，
  攻防合一：Part A 攻击视角漏洞模式 + 静态分析工具 (gosec/cargo-audit/semgrep)，
  Part B 安全编码模式 + 检测规则，内置 Go/Rust 漏洞速查矩阵。
domain: cybersecurity
subdomain: code-audit
tags: [go, rust, code-audit, sast, concurrency, memory-safety, command-injection, sqli]
version: 2.0.0
---

# Go & Rust 应用安全代码审计 — 完整攻防手册

## 适用场景

- Go Web 服务 (net/http, Gin, Echo, Fiber, Chi) 源码安全审计
- Rust Web 服务 (Actix-web, Axum, Rocket, Warp) 源码安全审计
- Go/Rust CLI 工具与系统服务安全审查
- **不适用**：嵌入式 Rust（见硬件安全）、CGO/FFI 交互（需额外 C 审计）

## 前置条件

- Go 1.21+ / Rust 1.70+ / Cargo
- 源码访问权限
- 工具：gosec / go vet / staticcheck / cargo audit / cargo clippy / Semgrep

---

## Part A：Go 安全审计

### 1. SQL 注入审计

```go
// ❌ fmt.Sprintf 拼接 SQL
query := fmt.Sprintf("SELECT * FROM users WHERE id = %s", userID)
rows, err := db.Query(query)

// ❌ string 拼接
rows, err := db.Query("SELECT * FROM products WHERE name LIKE '%" + name + "%'")

// ✅ 参数化查询
rows, err := db.Query("SELECT * FROM users WHERE id = $1", userID)

// ✅ sqlx
var user User
err := sqlx.Get(db, &user, "SELECT * FROM users WHERE id = $1", userID)

// ✅ GORM（ORM 自动参数化）
var user User
db.Where("id = ?", userID).First(&user)
```

**审计 grep：**

```bash
grep -rn 'db\.Query\|db\.Exec\|db\.QueryRow\|sqlx\.Get\|sqlx\.Select' --include='*.go' . | grep -v '_test.go'
grep -rn 'fmt\.Sprintf.*SELECT\|fmt\.Sprintf.*INSERT\|fmt\.Sprintf.*UPDATE\|fmt\.Sprintf.*DELETE' --include='*.go' .
```

### 2. 命令注入审计

```go
// ❌ exec.Command + sh -c + 用户输入
cmd := exec.Command("sh", "-c", "ping "+userInput)

// ❌ 格式化字符串
cmd := exec.Command("sh", "-c", fmt.Sprintf("dig %s", domain))

// ✅ 参数列表（无 shell 解析）
cmd := exec.Command("ping", "-c", "1", userInput)

// ✅ 输入验证
var safeDomain = regexp.MustCompile(`^[a-zA-Z0-9.-]+$`)
if !safeDomain.MatchString(domain) {
    return errors.New("invalid domain")
}
cmd := exec.Command("dig", domain)
```

**审计 grep：**

```bash
grep -rn 'exec\.Command\|exec\.CommandContext\|os\.StartProcess' --include='*.go' . | grep -v '_test.go'
grep -rn '"sh", "-c"' --include='*.go' .
```

### 3. 路径穿越审计

```go
// ❌ 用户输入直接拼路径
filePath := filepath.Join("/uploads", req.URL.Query().Get("file"))
data, err := os.ReadFile(filePath)  // ../../etc/passwd

// ✅ 安全路径处理
func safePath(base, userPath string) (string, error) {
    absBase, _ := filepath.Abs(base)
    target := filepath.Join(absBase, userPath)
    absTarget, _ := filepath.Abs(target)
    if !strings.HasPrefix(absTarget, absBase+string(os.PathSeparator)) {
        return "", errors.New("path traversal")
    }
    return absTarget, nil
}
```

**审计 grep：**

```bash
grep -rn 'os\.Open\|os\.ReadFile\|os\.WriteFile\|filepath\.Join\|http\.ServeFile' --include='*.go' . | grep -v '_test.go'
```

### 4. SSRF 审计

```go
// ❌ 用户可控 URL
resp, err := http.Get(req.URL.Query().Get("url"))

// ❌ 自定义 Client 无限制
client := &http.Client{}
resp, err := client.Get(userURL)

// ✅ 自定义 Transport 限制
transport := &http.Transport{
    DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
        host, _, _ := net.SplitHostPort(addr)
        ip := net.ParseIP(host)
        if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {
            return nil, errors.New("private IP blocked")
        }
        return net.DialContext(ctx, network, addr)
    },
}
client := &http.Client{Transport: transport, Timeout: 10 * time.Second}
```

**审计 grep：**

```bash
grep -rn 'http\.Get\|http\.Post\|http\.Do\|client\.Get\|client\.Do\|url\.Parse' --include='*.go' . | grep -v '_test.go'
```

### 5. 并发安全审计

```go
// ❌ map 并发读写 — panic
var m = make(map[string]string)
// goroutine 1
m["key"] = "value"
// goroutine 2
_ = m["other"]  // fatal error: concurrent map read and map write

// ✅ sync.Map / mutex
var mu sync.RWMutex
var m = make(map[string]string)
mu.Lock()
m["key"] = "value"
mu.Unlock()

// ❌ goroutine 泄漏
go func() {
    for {
        doWork()  // 无 context，无法取消
    }
}()

// ✅ context 取消
ctx, cancel := context.WithCancel(context.Background())
go func() {
    for {
        select {
        case <-ctx.Done():
            return
        default:
            doWork()
        }
    }
}()
defer cancel()
```

**审计 grep：**

```bash
# 查找无 context 的 goroutine
grep -rn 'go func()' --include='*.go' . | grep -v 'context\|ctx\|_test.go'
# 查找无锁 map 操作
grep -rn 'map\[' --include='*.go' . | grep -v 'sync\.Map\|mu\.\|_test.go'
```

### 6. 反序列化审计

```go
// ❌ json.Unmarshal 用户输入到 interface{}
var data interface{}
json.Unmarshal(userInput, &data)  // 可被滥用为任意结构

// ❌ gob 解码用户输入 — RCE 风险
var buf bytes.Buffer
dec := gob.NewDecoder(&buf)
dec.Decode(&target)  // 可实例化意外类型

// ✅ 严格类型解码
var user User
if err := json.Unmarshal(input, &user); err != nil { ... }
// 验证字段
if user.Role != "user" && user.Role != "admin" { ... }
```

### 7. TLS 配置审计

```go
// ❌ 跳过证书验证
http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{
    InsecureSkipVerify: true,
}

// ❌ 弱密码套件
tls.Config{MinVersion: tls.VersionTLS10}

// ✅ 安全 TLS 配置
tls.Config{
    MinVersion: tls.VersionTLS12,
    CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256},
    CipherSuites: []uint16{
        tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
        tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
    },
}
```

**审计 grep：**

```bash
grep -rn 'InsecureSkipVerify.*true\|MinVersion.*TLS10\|TLS.*SSL' --include='*.go' .
```

---

## Part A（续）：Rust 安全审计

### 8. unsafe 代码审计

```rust
// ❌ 未检查边界的切片访问
unsafe {
    let val = *slice.get_unchecked(i);  // UB if i >= len
}

// ❌ 裸指针解引用
unsafe {
    let val = *raw_ptr;  // use-after-free / null deref
}

// ✅ 安全替代
let val = slice.get(i)?;  // Option<T>, checked

// ❌ transmute 类型混淆
unsafe {
    let float: f32 = std::mem::transmute(0x41480000u32);
}

// ✅ 安全转换
let float = f32::from_bits(0x41480000u32);
```

**审计 grep：**

```bash
grep -rn 'unsafe' --include='*.rs' . | grep -v '_test.rs\|#\[safe\]\|// SAFETY'
grep -rn 'get_unchecked\|from_raw_parts\|transmute\|as_mut_ptr\|as_ptr' --include='*.rs' .
```

### 9. 命令注入审计

```rust
// ❌ shell 形式
std::process::Command::new("sh")
    .arg("-c")
    .arg(&format!("ping {}", user_input))  // injection

// ✅ 参数列表
std::process::Command::new("ping")
    .arg("-c")
    .arg("1")
    .arg(&validated_input)
    .output()
```

### 10. 反序列化审计 (Serde)

```rust
// ❌ serde_json 反序列化到任意类型
// 如果目标结构有 #[serde(deny_unknown_fields)] 缺失，多余字段被忽略
#[derive(Deserialize)]
struct User {
    username: String,
    is_admin: bool,  // 攻击者可设置
}

// ✅ 严格验证 + deny_unknown_fields
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UserInput {
    username: String,
    email: String,
    // 不包含 is_admin
}
```

### 11. 异步并发安全审计

```rust
// ❌ 异步函数中阻塞操作
async fn handler() {
    std::thread::sleep(Duration::from_secs(5));  // 阻塞 tokio 运行时
}

// ✅ tokio::time::sleep
async fn handler() {
    tokio::time::sleep(Duration::from_secs(5)).await;
}

// ❌ Send trait 不满足导致编译错误（看似安全实为死锁）
// Arc<Mutex<RefCell<T>>> — RefCell 不是 Send

// ✅ Arc<Mutex<T>> 或 Arc<RwLock<T>> (T: Send)
```

### 12. 密码学与密钥审计

```rust
// ❌ 弱哈希
use sha1::Sha1;
use md5::Md5;

// ✅ 安全哈希
use sha2::{Sha256, Sha512};
use argon2::{Argon2, PasswordHasher};

// ❌ 硬编码密钥
const SECRET: &str = "my-secret-key";

// ✅ 环境变量
let secret = std::env::var("SECRET_KEY").expect("SECRET_KEY required");
```

---

## Part B：检测与防御

### 13. Go 静态分析工具链

**gosec：**

```bash
# 安装
go install github.com/securego/gosec/v2/cmd/gosec@latest

# 扫描项目
gosec ./...

# 指定规则
gosec -include=G101,G102,G103,G104,G201,G202,G203,G204,G301,G302,G303,G304,G305,G401,G402,G403,G404,G501,G502,G503,G504,G505,G601 ./...

# 输出 JSON
gosec -fmt=json -out=report.json ./...
```

**gosec 规则 ID 速查：**

| G-ID | 漏洞 | 严重性 |
|------|------|--------|
| G101 | 硬编码凭据 | High |
| G102 | 绑定 0.0.0.0 | Medium |
| G103 | 使用 unsafe | Low |
| G104 | 未检查错误 | Low |
| G106 | InsecureSkipVerify | High |
| G107 | SSRF (http.Get 用户 URL) | Medium |
| G108 | pprof 端点暴露 | Medium |
| G109 | 整数溢出 | Medium |
| G110 | decompression bomb | Medium |
| G201 | SQL 拼接 (Query) | High |
| G202 | SQL 拼接 (Exec) | High |
| G203 | 模板 HTML 未转义 | Medium |
| G204 | 命令注入 (exec) | High |
| G301 | 不安全文件权限 | Medium |
| G304 | 路径穿越 | Medium |
| G401 | 弱加密 (DES/RC4) | High |
| G402 | InsecureSkipVerify | High |
| G404 | 弱随机 (math/rand) | Medium |
| G501 | 黑名单导入 (crypto/md5) | Medium |
| G505 | 黑名单导入 (crypto/sha1) | Medium |
| G601 | 隐式内存别名 | Medium |

**Go CI 集成：**

```yaml
# .github/workflows/go-security.yml
name: Go Security
on: [push, pull_request]
jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: '1.22'

      - name: go vet
        run: go vet ./...

      - name: gosec
        run: |
          go install github.com/securego/gosec/v2/cmd/gosec@latest
          gosec ./...

      - name: Semgrep
        uses: semgrep/semgrep-action@v1
        with:
          config: p/go

      - name: govulncheck
        run: |
          go install golang.org/x/vuln/cmd/govulncheck@latest
          govulncheck ./...
```

### 14. Rust 静态分析工具链

**Cargo 安全工具：**

```bash
# 已知漏洞检查
cargo audit

# Lint 安全检查
cargo clippy -- -W clippy::unwrap_used -W clippy::expect_used

# 依赖树审查
cargo tree --duplicates

# 检查 unsage 块
cargo geiger  # 统计 unsafe 使用量

# Semgrep
semgrep --config p/rust src/
```

**Cargo.toml 安全配置：**

```toml
# 强制依赖审核
[dependencies]
# 明确版本，避免 ^ 语义版本陷阱
serde = { version = "1.0.198", features = ["derive"] }

[dev-dependencies]
# 测试依赖不进入生产

# deny.toml 配置 (cargo-deny)
# cargo install cargo-deny
# cargo deny check
```

**Rust CI 集成：**

```yaml
# .github/workflows/rust-security.yml
name: Rust Security
on: [push, pull_request]
jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable

      - name: cargo audit
        run: |
          cargo install cargo-audit
          cargo audit

      - name: cargo clippy
        run: cargo clippy -- -W clippy::unwrap_used -D warnings

      - name: cargo deny
        run: |
          cargo install cargo-deny
          cargo deny check

      - name: Semgrep
        uses: semgrep/semgrep-action@v1
        with:
          config: p/rust
```

### 15. 安全编码模式

**Go 安全中间件：**

```go
// 限流
func rateLimitMiddleware(next http.Handler) http.Handler {
    limiter := rate.NewLimiter(rate.Every(time.Second), 10)
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if !limiter.Allow() {
            http.Error(w, "rate limited", http.StatusTooManyRequests)
            return
        }
        next.ServeHTTP(w, r)
    })
}

// 安全头
func securityHeaders(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("X-Content-Type-Options", "nosniff")
        w.Header().Set("X-Frame-Options", "DENY")
        w.Header().Set("Content-Security-Policy", "default-src 'self'")
        w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        next.ServeHTTP(w, r)
    })
}
```

**Rust 安全中间件 (Axum)：**

```rust
use axum::{middleware, extract::Request};
use tower_http::set_header::SetResponseHeaderLayer;

// 安全头层
let app = axum::Router::new()
    .layer(SetResponseHeaderLayer::if_not_present(
        header::X_CONTENT_TYPE_OPTIONS,
        "nosniff".parse().unwrap(),
    ))
    .layer(SetResponseHeaderLayer::if_not_present(
        header::X_FRAME_OPTIONS,
        "DENY".parse().unwrap(),
    ));
```

---

## 速查表

### Go 漏洞模式 → 审计关键词 → 修复方案矩阵

| 漏洞类型 | 审计关键词 | 危险模式 | 安全替代 |
|----------|-----------|---------|---------|
| SQL 注入 | `db.Query`, `fmt.Sprintf` + SQL | 字符串拼接 | `$1` 参数化 / GORM |
| 命令注入 | `exec.Command`, `"sh", "-c"` | sh -c + 用户输入 | 参数列表 |
| 路径穿越 | `filepath.Join` + 用户输入 | 直接拼路径 | `filepath.Abs` + `HasPrefix` |
| SSRF | `http.Get(userURL)` | 用户可控 URL | 自定义 Transport + IP 检查 |
| 并发竞态 | `map[` + goroutine | 无锁 map 读写 | `sync.RWMutex` / `sync.Map` |
| TLS 弱配置 | `InsecureSkipVerify`, `TLS10` | 跳过验证 | TLS 1.2+ + 强密码套件 |
| 硬编码密钥 | `const.*=.*"secret"` | 明文密钥 | 环境变量 / Vault |
| goroutine 泄漏 | `go func()` 无 context | 不可取消 goroutine | `context.WithCancel` |

### Rust 漏洞模式 → 审计关键词 → 修复方案矩阵

| 漏洞类型 | 审计关键词 | 危险模式 | 安全替代 |
|----------|-----------|---------|---------|
| 内存越界 | `get_unchecked`, `from_raw_parts` | unsafe 指针操作 | `.get(i)?` checked 访问 |
| 类型混淆 | `transmute` | 不安全类型转换 | `from_bits`, `try_from` |
| 命令注入 | `Command::new("sh").arg("-c")` | shell + 用户输入 | 参数列表 |
| 反序列化 | `#[derive(Deserialize)]` 无 deny | 多余字段被接受 | `#[serde(deny_unknown_fields)]` |
| 阻塞运行时 | `std::thread::sleep` in async | 阻塞 tokio | `tokio::time::sleep` |
| 弱密码 | `md5`, `sha1` | 不安全哈希 | `sha2`, `argon2` |
| 依赖漏洞 | `Cargo.lock` 过时 | 已知 CVE | `cargo audit` |

---

## MITRE ATT&CK 映射

| 战术 | Technique | Go/Rust 相关场景 |
|------|-----------|----------------|
| Initial Access | T1190 | SQL注入、SSRF、路径穿越 |
| Execution | T1059 | 命令注入 (exec/Command) |
| Persistence | T1133 | 硬编码后门凭据 |
| Credential Access | T1212 | 弱 TLS 泄露凭据 |
| Defense Evasion | T1027 | unsafe 绕过安全检查 |
| Exfiltration | T1041 | SSRF 数据外泄 |
| Impact | T1489 | 并发竞态导致 DoS |

---

## Part C：2025-2026 更新

> 本节基于 2025-2026 年 Go/Rust 安全生态最新进展，补充内存安全、并发漏洞、供应链安全、
> 审计工具更新及 MITRE ATT&CK 扩展映射。

### C1. Go 内存安全进阶

#### C1.1 Slice 越界访问

Go 的 slice 操作不会在编译期阻止越界，运行时越界直接 panic 导致服务崩溃（DoS）。

```go
// ❌ 未检查长度直接索引
func getItem(data []string, idx int) string {
    return data[idx]  // panic: index out of range → DoS
}

// ✅ 边界检查
func getItem(data []string, idx int) (string, error) {
    if idx < 0 || idx >= len(data) {
        return "", fmt.Errorf("index %d out of bounds [0,%d)", idx, len(data))
    }
    return data[idx], nil
}

// ❌ Slice 截断未检查容量
sub := slice[10:20]  // 若 len(slice) < 20 → panic

// ✅ 安全截断
func safeSlice(data []byte, start, end int) ([]byte, error) {
    if start < 0 || end > len(data) || start > end {
        return nil, fmt.Errorf("invalid slice [%d:%d] for len %d", start, end, len(data))
    }
    return data[start:end], nil
}
```

**审计 grep：**

```bash
# 查找直接索引访问（非 range）
grep -rn '\[[0-9]\+\]\|\[[a-zA-Z_]*\]' --include='*.go' . | grep -v 'map\[' | grep -v '_test.go'
# 查找 slice 截断
grep -rn '\[.*:.*\]' --include='*.go' . | grep -v 'map\[' | grep -v '_test.go'
```

#### C1.2 Goroutine 泄漏进阶

2025 年 Goroutine 泄漏仍是 Go 服务内存泄漏的首要原因。

```go
// ❌ HTTP handler 中启动 goroutine 无生命周期管理
func handler(w http.ResponseWriter, r *http.Request) {
    go processAsync(r)  // 请求结束后 goroutine 仍在运行
}

// ❌ Channel 发送方阻塞导致泄漏
func producer(ch chan<- int) {
    for i := 0; i < 10000; i++ {
        ch <- i  // 若消费者停止读取 → 发送方永久阻塞
    }
}

// ✅ 使用带缓冲 channel + context + select
func safeProducer(ctx context.Context, ch chan<- int) error {
    for i := 0; i < 10000; i++ {
        select {
        case ch <- i:
        case <-ctx.Done():
            return ctx.Err()
        }
    }
    return nil
}

// ✅ goroutine 生命周期追踪 (Go 1.21+)
func trackedGoroutine(ctx context.Context) {
    ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
    defer cancel()
    go func() {
        defer func() { log.Println("goroutine exited") }()
        select {
        case <-doWork():
        case <-ctx.Done():
        }
    }()
}
```

**审计 grep：**

```bash
# 查找无 context 的 goroutine
grep -rn 'go func' --include='*.go' . | grep -v 'context\|ctx\b' | grep -v '_test.go'
# 查找无缓冲 channel
grep -rn 'make(chan' --include='*.go' . | grep -v 'make(chan.*,' | grep -v '_test.go'
```

#### C1.3 Channel 死锁

```go
// ❌ 同一 goroutine 读写无缓冲 channel
ch := make(chan int)
ch <- 42       // 阻塞，无接收方 → 死锁
val := <-ch

// ❌ select 无 default 且所有 case 阻塞
select {
case ch1 <- v1:  // 阻塞
case v2 := <-ch2:  // 阻塞
// 无 default，无超时 → 永久阻塞
}

// ✅ 带超时的 select
select {
case ch <- v:
case <-time.After(5 * time.Second):
    return errors.New("channel send timeout")
}

// ✅ 使用 context 超时
ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
defer cancel()
select {
case result := <-ch:
    return result, nil
case <-ctx.Done():
    return nil, ctx.Err()
}
```

### C2. Go 并发漏洞深入

#### C2.1 Race Condition 高级模式

Go 竞态检测器 (`-race`) 是 2025 年仍在使用的核心工具，但需注意它只能检测到运行时实际执行的代码路径。

```go
// ❌ 闭包捕获循环变量 (Go < 1.22)
for _, item := range items {
    go func() {
        process(item)  // 所有 goroutine 使用最后一个 item
    }()
}

// ✅ Go 1.22+ 循环变量语义已修复；旧版本需显式传参
for _, item := range items {
    item := item  // shadow
    go func() {
        process(item)
    }()
}

// ❌ WaitGroup 计数器竞态
var wg sync.WaitGroup
for i := 0; i < n; i++ {
    go func() {
        defer wg.Done()
        result++  // 竞态写入
    }()
    wg.Add(1)
}
wg.Wait()

// ✅ 原子操作
var result atomic.Int64
for i := 0; i < n; i++ {
    wg.Add(1)
    go func() {
        defer wg.Done()
        result.Add(1)
    }()
}
wg.Wait()
```

**竞态检测：**

```bash
# 测试时启用竞态检测
go test -race -count=1 ./...

# 构建时启用（性能有损耗，仅用于调试）
go build -race -o app-debug .

# 持续集成中运行
go test -race -timeout 10m ./...
```

#### C2.2 Deadlock 检测模式

```go
// ❌ 锁顺序不一致导致死锁
// goroutine 1
mu1.Lock()
mu2.Lock()  // 等待 mu2
// goroutine 2
mu2.Lock()
mu1.Lock()  // 等待 mu1 → 死锁

// ✅ 统一锁顺序或使用 tryLock (Go 1.18+)
if mu1.TryLock() {
    defer mu1.Unlock()
    mu2.Lock()
    defer mu2.Unlock()
    // 安全操作
}

// ❌ sync.Mutex 复制
type Server struct {
    mu sync.Mutex
    data map[string]string
}
func (s Server) Handle() {  // 值接收者 → 复制 Mutex → 无效锁
    s.mu.Lock()
    defer s.mu.Unlock()
}

// ✅ 指针接收者
func (s *Server) Handle() {
    s.mu.Lock()
    defer s.mu.Unlock()
}
```

**静态检测：**

```bash
# go vet 检测锁复制
go vet ./...

# staticcheck 检测并发问题
staticcheck -checks=SA2000,SA2001,SA2002 ./...
```

### C3. Go 供应链安全

#### C3.1 go.sum 完整性验证

```bash
# 验证依赖完整性（Go 1.16+ 内置）
go mod verify

# 检查 go.sum 中每条记录的 SHA-256
sha256sum $(go env GOMODCACHE)/cache/download/sumdb/sum.golang.org/lookup/*/*/*

# 查看直接/间接依赖
go mod graph
go mod why -m <module>
```

#### C3.2 go mod tidy 与依赖清理

```bash
# 清理未使用的依赖
go mod tidy

# 检测依赖差异（未 tidy 的标志）
git diff go.mod go.sum

# CI 中强制 tidy 检查
go mod tidy
git diff --exit-code go.mod go.sum
```

#### C3.3 govulncheck 进阶（2025 更新）

2025 年 `govulncheck` 已成为 Go 供应链安全的核心工具，支持调用图分析以减少误报。

```bash
# 安装
go install golang.org/x/vuln/cmd/govulncheck@latest

# 扫描项目（调用图分析，仅报告实际触发的漏洞）
govulncheck ./...

# 显示所有已知漏洞（包括未触发的）
govulncheck -show=all ./...

# 输出 JSON
govulncheck -json ./...

# 指定 Go 版本
govulncheck -go 1.22 ./...

# CI 集成：设置失败阈值
govulncheck -test ./... || echo "::error::Vulnerabilities found"
```

**重要 CVE 参考（2024-2025）：**

| CVE | 影响 | Go 版本 |
|-----|------|---------|
| CVE-2024-24790 | math/big 算术溢出 | < 1.21.11, < 1.22.4 |
| CVE-2025-22867 | Darwin 构建代码执行 | 1.24rc2 |
| CVE-2024-45336 | crypto/x509 链验证绕过 | < 1.22.10, < 1.23.4 |
| CVE-2024-45341 | net/http 内部重定向绕过 | < 1.22.10, < 1.23.4 |

#### C3.4 Go 供应链 CI 完整流水线

```yaml
# .github/workflows/go-supply-chain.yml
name: Go Supply Chain Security
on: [push, pull_request]
jobs:
  supply-chain:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: '1.22'

      - name: Verify modules
        run: go mod verify

      - name: Check tidy
        run: |
          go mod tidy
          git diff --exit-code go.mod go.sum

      - name: Vulnerability check
        run: |
          go install golang.org/x/vuln/cmd/govulncheck@latest
          govulncheck ./...

      - name: gosec
        run: |
          go install github.com/securego/gosec/v2/cmd/gosec@latest
          gosec -fmt=sarif -out=gosec.sarif ./...

      - name: Semgrep
        uses: semgrep/semgrep-action@v1
        with:
          config: p/go
```

### C4. Rust 安全特性深入

#### C4.1 所有权与借用检查

Rust 的所有权系统在编译期保证内存安全，无需垃圾回收。2025-2026 年的核心安全机制：

```rust
// 所有权规则：每个值有唯一所有者，离开作用域自动释放
fn ownership_basics() {
    let s1 = String::from("hello");
    let s2 = s1;         // 所有权转移，s1 不再有效
    // println!("{}", s1); // 编译错误：value borrowed after move
    println!("{}", s2);   // OK
}

// 借用规则：同一时刻可有多个不可变引用或一个可变引用
fn borrow_rules() {
    let mut data = vec![1, 2, 3];
    let r1 = &data;           // 不可变借用
    let r2 = &data;           // 再来一个不可变借用 → OK
    // let r3 = &mut data;    // 编译错误：不能同时有可变和不可变借用
    println!("{} {}", r1[0], r2[1]);

    let r3 = &mut data;       // r1, r2 生命周期结束后 → OK
    r3.push(4);
}

// 生命周期确保引用不会悬垂
fn dangling_prevention<'a>() -> &'a str {
    let s = String::from("hello");
    // &s  // 编译错误：s 在函数结束时释放，返回悬垂引用
    "static"  // OK：'static 生命周期
}
```

#### C4.2 unsafe 代码审计要点（2025 更新）

`unsafe` 块是 Rust 安全保证的"逃生舱"，所有内存安全 bug 必然存在于 unsafe 块中。

```rust
// ❌ 未检查偏移量
unsafe {
    let ptr = base.add(offset);  // offset 可能越界 → UB
    *ptr = value;
}

// ✅ 检查边界
fn safe_offset_write(slice: &mut [u8], offset: usize, value: u8) -> Option<()> {
    if offset >= slice.len() { return None; }
    // 使用安全 API
    slice[offset] = value;
    Some(())
}

// ❌ 未对齐的指针访问
unsafe {
    let ptr = misaligned_ptr as *const u32;
    let val = *ptr;  // UB: 未对齐读取
}

// ✅ 使用 read_unaligned / write_unaligned
unsafe {
    let val = std::ptr::read_unaligned(misaligned_ptr as *const u32);
}

// ❌ use-after-free
unsafe {
    let ptr = Box::into_raw(Box::new(42));
    let _box = Box::from_raw(ptr);   // 第一个所有者
    let val = *ptr;                   // use-after-free → UB
}

// ✅ 确保唯一所有权
unsafe {
    let ptr = Box::into_raw(Box::new(42));
    let val = *ptr;              // 读取原始值（OK，未创建新所有者）
    let _box = Box::from_raw(ptr); // 恢复所有权
}

// ❌ 未检查的 transmute
unsafe {
    let bytes: [u8; 4] = [0x41, 0x48, 0x00, 0x00];
    let float: f32 = std::mem::transmute(bytes); // 类型对齐可能不匹配
}

// ✅ 安全替代
let float = f32::from_ne_bytes([0x41, 0x48, 0x00, 0x00]);
```

**unsafe 审计流程：**

```bash
# 1. 统计 unsafe 使用量
cargo geiger

# 2. 查找所有 unsafe 块
grep -rn 'unsafe' --include='*.rs' . | grep -v '_test.rs\|#\[safe\]\|// SAFETY:\|// SAFETY:'

# 3. 检查 SAFETY 注释是否存在（最佳实践要求每个 unsafe 块有 SAFETY 注释）
grep -rn 'unsafe {' --include='*.rs' . | while read line; do
    file=$(echo "$line" | cut -d: -f1)
    lineno=$(echo "$line" | cut -d: -f2)
    prev=$((lineno - 1))
    if ! sed -n "${prev}p" "$file" | grep -q '// SAFETY:'; then
        echo "WARN: Missing SAFETY comment at $file:$lineno"
    fi
done
```

### C5. Rust 常见安全漏洞

#### C5.1 unsafe 块中的逻辑错误

```rust
// ❌ Send/Sync 手动实现不当
struct NotThreadSafe {
    rc: std::rc::Rc<String>,  // Rc 不是 Send
}
unsafe impl Send for NotThreadSafe {}  // 编译通过但运行时 UB

// ❌ interior mutability 误用
use std::cell::RefCell;
let data = RefCell::new(vec![1, 2, 3]);
let borrow1 = data.borrow();
let borrow2 = data.borrow_mut();  // panic: 已被不可变借用
```

#### C5.2 整数溢出与截断

```rust
// ❌ debug 模式 panic，release 模式 wrapping
let x: u8 = 255;
let y = x + 1;  // debug: panic, release: 0 (wrapping)

// ✅ 显式检查
let y = x.checked_add(1).ok_or("overflow")?;

// ❌ as 类型转换截断
let big: u64 = 0x1_0000_0001;
let small = big as u32;  // 1，高位被截断

// ✅ try_into
let small: u32 = big.try_into().map_err(|_| "overflow")?;
```

#### C5.3 unwrap/expect 滥用

```rust
// ❌ 生产代码中的 unwrap → 可能 panic
let val = map.get("key").unwrap();
let parsed = str::parse::<i32>(input).unwrap();

// ✅ 错误传播
let val = map.get("key").ok_or("key not found")?;
let parsed: i32 = str::parse(input).map_err(|e| format!("parse error: {}", e))?;

// Clippy 强制检测
// cargo clippy -- -W clippy::unwrap_used -W clippy::expect_used
```

### C6. 安全审计工具更新（2025-2026）

#### C6.1 工具对照表

| 工具 | 语言 | 用途 | 命令 |
|------|------|------|------|
| govulncheck | Go | 已知漏洞检测（调用图分析） | `govulncheck ./...` |
| gosec | Go | SAST 静态安全扫描 | `gosec ./...` |
| go vet | Go | 编译器级静态检查 | `go vet ./...` |
| staticcheck | Go | 高级静态分析 | `staticcheck ./...` |
| Semgrep (p/go) | Go | 模式匹配规则扫描 | `semgrep --config p/go` |
| cargo audit | Rust | RustSec 已知漏洞检查 | `cargo audit` |
| cargo deny | Rust | 许可证/安全/来源策略检查 | `cargo deny check` |
| cargo geiger | Rust | unsafe 使用统计 | `cargo geiger` |
| cargo clippy | Rust | Lint 检查（含安全 Lint） | `cargo clippy -- -W clippy::unwrap_used` |
| Semgrep (p/rust) | Rust | 模式匹配规则扫描 | `semgrep --config p/rust` |
| cargo outdated | Rust | 过时依赖检测 | `cargo outdated` |
| cargo crev | Rust | 依赖代码审查 | `cargo crev verify` |

#### C6.2 govulncheck 误报控制

```bash
# govulncheck 通过调用图分析减少误报
# 仅报告实际可达的漏洞路径

# 设置 Go 漏洞数据库代理（私有环境）
export GOVULNDB=https://vuln.go.dev

# 仅扫描特定包
govulncheck ./pkg/...

# 与 gosec 结合使用，互补覆盖
gosec -exclude=G104 ./...  # 排除低优先级规则
govulncheck -show=all ./...
```

#### C6.3 cargo audit 与 cargo deny 联合配置

```bash
# cargo audit：检查 RustSec 数据库
cargo audit

# 输出详细报告
cargo audit --show-tree

# cargo deny：全面策略检查
# deny.toml 配置文件
```

```toml
# deny.toml — cargo-deny 配置示例
[advisories]
db-path = "~/.cargo/advisory-db"
vulnerability = "deny"
unmaintained = "warn"

[licenses]
allow = ["MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause"]
unlicensed = "deny"

[bans]
multiple-versions = "warn"
wildcards = "deny"

[sources]
unknown-registry = "deny"
unknown-git = "deny"
allow-registry = ["https://github.com/rust-lang/crates.io"]
```

### C7. MITRE ATT&CK 映射扩展

| 战术 | Technique | Go/Rust 相关场景 | 更新说明 |
|------|-----------|-----------------|---------|
| Initial Access | T1190 | SQL注入、SSRF、路径穿越 | 新增：反序列化 RCE |
| Execution | T1059 | 命令注入 (exec/Command) | 新增：CGO/FFI 代码执行 |
| Persistence | T1133 | 硬编码后门凭据 | 新增：恶意 crate/go module |
| Privilege Escalation | T1068 | 整数溢出绕过权限检查 | 新增：unsafe 块绕过 |
| Defense Evasion | T1027 | unsafe 绕过安全检查 | 新增：混淆依赖名(typosquatting) |
| Credential Access | T1212 | 弱 TLS 泄露凭据 | 新增：硬编码 API Key |
| Discovery | T1082 | 依赖扫描收集环境信息 | 新增：信息泄露通过错误消息 |
| Lateral Movement | T1210 | SSRF 内网探测 | 新增：Channel 死锁阻断通信 |
| Exfiltration | T1041 | SSRF 数据外泄 | 新增：依赖混淆替换为恶意包 |
| Impact | T1489 | 并发竞态导致 DoS | 新增：Slice 越界 panic 导致 DoS |
| Supply Chain | T1195 | 恶意依赖/typosquatting | **新增**：go.sum篡改、Cargo.toml 投毒 |
| Resource Hijacking | T1496 | Goroutine 泄漏耗尽资源 | **新增**：内存泄漏拒绝服务 |

### C8. Go/Rust 安全审计检查清单

#### Go 项目审计清单

- [ ] `govulncheck ./...` 无高危漏洞
- [ ] `gosec ./...` 无 High 级别发现
- [ ] `go vet ./...` 无警告
- [ ] 所有 `exec.Command` 不使用 `sh -c`
- [ ] 所有 `db.Query` 使用参数化查询
- [ ] 所有 `filepath.Join` + 用户输入做路径穿越检查
- [ ] 所有 `http.Get(userURL)` 做 SSRF 防护
- [ ] 无 `InsecureSkipVerify: true`
- [ ] 无硬编码密钥/凭据
- [ ] `go mod tidy` + `go mod verify` 通过
- [ ] 所有 goroutine 有 context 取消机制
- [ ] 共享 map 使用 `sync.RWMutex` 或 `sync.Map`
- [ ] `go test -race ./...` 无竞态
- [ ] CI 中集成安全扫描流水线

#### Rust 项目审计清单

- [ ] `cargo audit` 无已知漏洞
- [ ] `cargo deny check` 策略全部通过
- [ ] `cargo clippy` 无警告（含 `unwrap_used`）
- [ ] 所有 `unsafe` 块有 `// SAFETY:` 注释
- [ ] 无未检查的 `transmute` 调用
- [ ] 所有 `Command::new` 不使用 `sh -c` + 用户输入
- [ ] Serde 反序列化结构使用 `#[serde(deny_unknown_fields)]`
- [ ] 无 `md5`/`sha1` 等弱哈希
- [ ] 无硬编码密钥/凭据
- [ ] 异步代码中无 `std::thread::sleep` 阻塞
- [ ] `Arc<Mutex<T>>` 中 `T: Send`
- [ ] 无不当 `unsafe impl Send/Sync`
- [ ] `Cargo.lock` 已提交（二进制项目）
- [ ] CI 中集成安全扫描流水线

---

## Part D：2025-2026 精细化复核补充

> 基于 Go 官方安全公告、NVD、Red Hat、Unit 42 等最新威胁情报，对 Go/Rust 生态系统关键 CVE、供应链攻击、审计工具更新进行深度补充。

---

### C9. Go 标准库关键 CVE — 2025-2026 汇总

| CVE | 组件 | 严重性 | 描述 | 修复版本 |
|-----|------|--------|------|---------|
| CVE-2025-68121 | `crypto/tls` | **Critical** | `Config.Clone` 复制自动生成的 session ticket key → 未授权 TLS 会话恢复/证书验证绕过 | Go 1.25.6 / 1.24.12 |
| CVE-2025-68119 | `cmd/go` / `crypto/tls` | **High** | toolchain 调用时意外代码执行 + TLS 握手消息在错误加密层级处理 | Go 1.25.6 / 1.24.12 |
| CVE-2026-32289 | `crypto/x509` | **High** | 排除 DNS 约束未正确应用于通配符域名 → 证书验证绕过 | Go 1.26.2 / 1.25.9 |
| CVE-2025-61726 | `net/url` | Medium | 解析包含大量条目的大型 form 时内存耗尽 → DoS | 查看 Go 安全公告 |
| CVE-2026-46598 | `crypto/tls` | — | 对不受信任证书也执行不必要的证书链验证开销 | Go 最新版 |

**C9.1 CVE-2025-68121 深度分析**

`crypto/tls` 中的 `Config.Clone()` 方法会复制自动生成的 session ticket key，攻击者可利用此漏洞恢复不应成功的 TLS 会话：

```go
// ❌ 危险模式：共享 Config 导致 session key 泄漏
config := &tls.Config{
    Certificates: []tls.Certificate{cert},
}
// Clone 会复制 session ticket key
cloned := config.Clone()  // session key 被复制
// 如果 cloned 被用于恶意服务端 → 可冒充原始服务端

// ✅ 修复：升级到 Go 1.25.6+ 或确保不共享 Config
// Go 1.25.6+ 修复了 Clone() 不再复制自动生成的 session key
```

**影响范围：** 所有使用 Go 构建的 TLS 服务，包括 Docker Engine（每个版本都受影响直到最新版）。

**C9.2 CVE-2026-32289 通配符证书绕过**

```go
// crypto/x509 中 DNS 名称约束检查的 bug
// 排除约束（excluded DNS names）未正确匹配通配符域名
// 例如：约束排除 "*.evil.com"，但 "Evil.COM" 可能通过（大小写问题）
// 影响：本应被拒绝的证书可能通过验证 → MITM 风险
```

**C9.3 审计检测脚本（增强版）**

```bash
#!/bin/bash
# go-cve-check.sh — 检查 Go 项目是否受已知 CVE 影响

echo "=== Go 版本检查 ==="
go version

echo "=== govulncheck 扫描 ==="
govulncheck ./... 2>&1 | grep -E 'Vulnerability|GO-2025|GO-2026|CVE'

echo "=== 检查 crypto/tls 使用 ==="
grep -rn 'crypto/tls\|tls\.Config\|Config\.Clone' --include='*.go' . | grep -v '_test.go'

echo "=== 检查 crypto/x509 使用 ==="
grep -rn 'crypto/x509\|x509\.CertPool\|x509\.VerifyOptions' --include='*.go' . | grep -v '_test.go'

echo "=== 检查 net/url 使用 ==="
grep -rn 'url\.Parse\|url\.ParseQuery\|url\.ParseRequestURI' --include='*.go' . | grep -v '_test.go'
```

**C9.4 参考**

- [Go 1.25.6/1.24.12 安全发布公告](https://groups.google.com/g/golang-dev/c/U8XGFyIQrv4)
- [CVE-2025-68121 — NVD](https://nvd.nist.gov/detail/cve-2025-68121)
- [CVE-2026-32289 — Go 1.26.2 发布](https://groups.google.com/g/golang-announce/c/0uYbvbPZRWU)
- [CVE-2025-61726 — SentinelOne](https://www.sentinelone.com/vulnerability-database/cve-2025-61726/)
- [Portainer: CVE-2025-68121 与 Docker](https://www.portainer.io/blog/cve-2025-68121-and-docker)
- [Go 官方漏洞数据库](https://pkg.go.dev/vuln/list)

---

### C10. Rust 供应链安全前沿 — 2025-2026

**C10.1 RustSec 生态系统现状**

| 维度 | 现状 |
|------|------|
| 漏洞数据库 | [RustSec Advisory Database](https://rustsec.org/) — Rust 生态主要漏洞追踪源 |
| 主要工具 | `cargo audit` — 扫描 Cargo.lock 中的已知漏洞 |
| 已知盲区 | 并非所有漏洞都被报告到 RustSec；`cargo audit` 存在覆盖缺口 |
| 学术进展 | 2025 arXiv 论文提出改进 crate 审计方法论 |
| 行业采用 | Ubuntu rust-coreutils、Polkadot 等大型项目积极投入 |

**C10.2 cargo audit 增强配置**

```toml
# Cargo.toml — 安全最佳实践

# 1. 明确版本（避免 ^ 语义版本陷阱）
[dependencies]
serde = { version = "=1.0.218", features = ["derive"] }
tokio = { version = "=1.44.2", features = ["full"] }

# 2. 使用 [patch] 修复已知漏洞
[patch.crates-io]
# 如果上游未及时修复，可 patch 到安全版本
# example-crate = { git = "https://github.com/fix/example", tag = "v1.2.4" }
```

```toml
# deny.toml — cargo-deny 策略配置（增强版）

[advisories]
db-path = "~/.cargo/advisory-db"
vulnerability = "deny"
unmaintained = "warn"
ignore = []  # 不要忽略已知漏洞

[licenses]
allow = ["MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "Zlib"]
unlicensed = "deny"

[bans]
multiple-versions = "warn"
wildcards = "deny"  # 禁止 "*" 版本依赖

[sources]
unknown-registry = "deny"
unknown-git = "deny"
allow-registry = ["https://github.com/rust-lang/crates.io"]

# 新增：检测已知问题 crate
[[bans.deny]]
name = "vm"       # vm2 的 Rust 等价风险
wrappers = []
```

**C10.3 Rust 容器安全 — SBOM 生成**

```bash
# Anchore 方案：Rust 容器镜像 SBOM 生成
# 安装 syft
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin

# 生成 SBOM
syft dir:. -o spdx-json > sbom.spdx.json

# 扫描 SBOM 中的漏洞
grype sbom:sbom.spdx.json

# cargo-auditable — 在编译产物中嵌入依赖信息
cargo install cargo-auditable
cargo auditable build --release
# 构建产物中包含可审计的依赖列表
```

**C10.4 参考**

- [RustSec Advisory Database](https://rustsec.org/)
- [arXiv: Auditing Rust Crates Effectively (2025)](https://arxiv.org/html/2602.06466v1)
- [Anchore: Beyond Cargo Audit](https://anchore.com/blog/beyond-cargo-audit-securing-your-rust-crates-in-container-images/)
- [Ubuntu: rust-coreutils 更新](https://discourse.ubuntu.com/t/an-update-on-rust-coreutils/80773)

---

### C11. Go 模块代理供应链防护

Go 的模块系统内置了多层供应链防护，2025-2026 年这些机制更加成熟：

```
                        Go 供应链防护层
┌─────────────────────────────────────────────────┐
│  Layer 1: Go Module Proxy (proxy.golang.org)     │
│  → 不可变缓存，防篡改                             │
│                                                   │
│  Layer 2: Go Checksum Database (sum.golang.org)  │
│  → 每个模块版本的 SHA-256 哈希，透明日志           │
│                                                   │
│  Layer 3: go mod verify                          │
│  → 本地校验下载模块的哈希                          │
│                                                   │
│  Layer 4: govulncheck                            │
│  → 调用图分析，仅报告可达漏洞                      │
│                                                   │
│  Layer 5: GONOSUMCHECK / GONOSUMDB               │
│  → 私有模块绕过公共 sumdb（需谨慎配置）            │
└─────────────────────────────────────────────────┘
```

```bash
# 验证供应链完整性
go mod verify          # 校验所有模块哈希
go mod graph           # 查看依赖图
go mod why -m <module> # 解释为什么需要某个依赖

# 检查是否使用公共代理（默认）
go env GONOSUMCHECK GOPRIVATE GONOSUMDB
# 空值 = 使用公共代理和 sumdb（推荐）

# 私有模块配置
# .gitconfig 或环境变量
git config --global url."git@github.com:".insteadOf "https://github.com/"

# GOPRIVATE 环境变量
export GOPRIVATE=github.com/your-org/*
# 私有模块绕过公共 proxy/sumdb，直接从源拉取
```

---

### C12. 2025-2026 综合 CVE 速查（Go/Rust 生态）

| CVE | 影响 | 类型 | 修复 |
|-----|------|------|------|
| CVE-2025-68121 | Go `crypto/tls` | TLS 会话恢复绕过 | Go 1.25.6+ |
| CVE-2025-68119 | Go `cmd/go` + `crypto/tls` | 代码执行 + TLS 层级错误 | Go 1.25.6+ |
| CVE-2026-32289 | Go `crypto/x509` | 通配符证书验证绕过 | Go 1.26.2+ |
| CVE-2025-61726 | Go `net/url` | 表单解析内存耗尽 DoS | Go 最新版 |
| CVE-2026-46598 | Go `crypto/tls` | 不必要证书链验证开销 | Go 最新版 |
| CVE-2024-24790 | Go `math/big` | 算术溢出 | Go 1.21.11+ / 1.22.4+ |
| CVE-2024-45336 | Go `crypto/x509` | 证书链验证绕过 | Go 1.22.10+ / 1.23.4+ |
| CVE-2024-45341 | Go `net/http` | 内部重定向绕过 | Go 1.22.10+ / 1.23.4+ |

---

### C13. 中文社区精华参考

| 来源 | 主题 | 链接 |
|------|------|------|
| Tony Bai | Go还是Rust？2025技术选型 | https://tonybai.com/2025/06/15/rust-vs-go-2025/ |
| 腾讯云 | Rust VS Go 后端开发 | https://cloud.tencent.com/developer/article/2589912 |
| 长亭百川云 | 一篇文章全面了解Rust与安全 | https://rivers.chaitin.cn/blog/cq959d90lnechd2453m0 |
| 1earn | Go代码审计备忘录 | https://github.com/ffffffff0x/1earn/blob/master/1earn/Security/RedTeam/%E8%AF%AD%E8%A8%80%E5%AE%89%E5%85%A8/Go%E5%AE%89%E5%85%A8/Go%E4%BB%A3%E7%A0%81%E5%AE%A1%E8%AE%A1.md |
| JetBrains | 2025年Go生态系统趋势 | https://blog.jetbrains.com/zh-hans/go/2025/12/06/go-language-trends-ecosystem-2025/ |

---

### C14. 防御升级路线图（P0-P3 分级）

| 优先级 | 措施 | 具体操作 | 截止 |
|--------|------|---------|------|
| **P0** | Go crypto/tls 升级 | `go get golang.org/dl/go1.25.6` 或更新 | 即时 |
| **P0** | Go crypto/x509 升级 | 升级到 Go 1.26.2+ | 即时 |
| **P0** | Rust cargo audit | `cargo audit` 修复所有高危 | 即时 |
| **P1** | govulncheck CI 集成 | GitHub Actions 添加 govulncheck 步骤 | 1周内 |
| **P1** | cargo-deny 策略 | 配置 deny.toml 完整策略 | 1周内 |
| **P1** | go mod verify CI | CI 中添加 `go mod verify` 检查 | 1周内 |
| **P2** | SBOM 生成 | Rust 项目添加 cargo-auditable | 1月内 |
| **P2** | Rust crate 审计流程 | 基于 arXiv 方法论建立审计 SOP | 1月内 |
| **P2** | GONOSUMCHECK 审计 | 检查 GOPRIVATE 配置安全性 | 1月内 |
| **P3** | 漏洞监控自动化 | Go 官方漏洞数据库 + RustSec RSS 订阅 | 持续 |
| **P3** | 容器镜像扫描 | Trivy + Syft 定期扫描 Rust/Go 镜像 | 持续 |
