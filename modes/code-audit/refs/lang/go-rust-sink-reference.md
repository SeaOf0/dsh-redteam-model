# Go / Rust 审计 Sink 大表（按类型）

> 与其他语言表同形态：greppable、按类型分节。深度手册见 `code-audit-go-rust.md`；
> 本表按语言分两部分。

# Part 1：Go

## 1. 命令注入与参数注入（CMD）

**Sink**：
- `exec.Command(` / `exec.CommandContext(`（首参=可执行路径可控=任意程序执行）
- `exec.Command("sh", "-c", 拼接串)`（shell 形态——串内拼接即命令注入）
- `os.StartProcess(`

**危险模式**：Go 的 `exec.Command` 默认**不走 shell**（无 `;|&` 串注入）——真实高危在：
① `sh -c` 显式拼接；② 工具类目标（git/ssh/kubectl）的**参数注入**（用户参数以 `-` 开头
被解析为选项）。

**强制验证**：无 shell 拼接；参数以 `--` 分隔或白名单；可执行路径服务端固定。

## 2. SQL 注入（SQL）

**Sink**：
- `database/sql`：`db.Query(` / `db.Exec(`（`fmt.Sprintf` 拼接 SQL 串）
- gorm：`Raw(` / `Exec(`（拼接）、`Order(`（列名直收）、`Where("col = " + user)`
- sqlx：`db.Queryx(` 拼接形态

**危险模式**：`fmt.Sprintf("... %s ...", user)` 进查询；排序/表名/列名内插（`?` 绑定
不覆盖标识符）。

**强制验证**：`?` 占位 + `args`；标识符白名单。

## 3. SSRF（SSRF）

**Sink**：
- `http.Get(` / `http.Post(` / `http.NewRequest(`（URL 含用户输入）
- `net.Dial(` / `net.DialTimeout(`（host 可控）
- 自定义 `http.Client` 跟随重定向进内网

**强制验证**：host 白名单；`CheckRedirect` 限制；解析后 IP 复核。

## 4. 文件与路径穿越（FILE）

**Sink**：
- `os.Open(` / `os.Create(` / `os.WriteFile(`（路径拼接）
- `filepath.Join(base, user)`（`Join` 会 Clean，但 `user` 为 `../` 序列或绝对路径时仍可
  逃出 base——**join 后必须 `strings.HasPrefix` 复核**）
- `http.ServeFile(` / `http.Dir(`（ServeFile 对包含 `..` 的请求路径有历史穿越面）
- `os.Executable(` 派生路径拼接

**强制验证**：`filepath.Clean` + 前缀校验；文件名服务端生成。

## 5. 解压穿越（ZIP）

**Sink**：
- `archive/zip`：`f.Open()` 循环写出（条目名 `../`）
- `archive/tar`：同型；链接条目
- 第三方 `mholt/archiver`（历史穿越面）

**强制验证**：`filepath.Join(dest, name)` 后前缀校验；链接条目拒绝。

## 6. 模板注入（SSTI）

**Sink**：
- `text/template`：`template.New().Parse(userInput)`（**无自动转义**——输出进 HTML=XSS，
  模板串可控=注入模板动作；text/template 无任意函数但可读字段/调用导出方法）
- `html/template`：自动转义防 XSS，但 `template.HTML(user)` 类型断言绕过转义（标记可信）

**危险模式**：用户输入作模板源；`template.HTML` 包裹用户数据。

**强制验证**：模板源服务端固定；`template.HTML` 仅白名单内容。

## 7. 反序列化（DESER）

**Sink**：
- `gob.Decode(`（不可信 gob 数据——gob 有限 gadget 面，如实评估）
- 自定义二进制协议 `binary.Read(`（解析器漏洞面，C/C++ 同型内存问题在 Go 无——越界
  panic 不是内存破坏，如实标注）
- json 反序列化到 `interface{}` 后类型断言链（逻辑缺陷面）

**强制验证**：gob 不接外部输入；协议解析输入长度与类型校验。

## 8. Goroutine 与并发（RACE）

**Sink**：
- 共享 map 并发读写（panic 面+数据竞争）
- `sync.WaitGroup` 计数错配；`Mutex` 复制（`go vet` 可检）
- time-of-check-to-time-of-use：`os.Stat` 后 `os.Open` 竞态（TOCTOU）

**强制验证**：`-race` 构建过测；检查逻辑有原子保障。

# Part 2：Rust

## 9. 命令注入与参数注入（CMD）

**Sink**：
- `std::process::Command::new(`（首参可控=任意执行；`arg(user)` 参数注入同 Go）
- `std::process::Command::new("sh").arg("-c")` 拼接形态
- `shell-words::split` 后拼装（引号逃逸面）

**强制验证**：参数以 `--` 分隔或白名单；无 shell 拼接。

## 10. SQL 注入（SQL）

**Sink**：
- sqlx：`sqlx::query(` + `format!(` 拼接（**对比 `query(...).bind(x)` 绑定形态**——grep
  `format!` 与 `query(` 同行即候选）
- diesel：`dsl::sql(`（原文片段）
- postgres/mysql crate：`query(` + format! 同型

**强制验证**：一律 bind；标识符白名单。

## 11. 文件与解压（FILE/ZIP）

**Sink**：
- `std::fs::` 系 + 用户路径拼接；`Path::join(`（`..` 段逃逸——join 后 `starts_with` 复核）
- `zip` crate：`by_index` 循环写出（条目穿越——历史 CVE 面，版本核对）
- `tar` crate：同型+链接条目

**强制验证**：canonicalize 后前缀校验；条目路径校验；链接默认拒绝。

## 12. 反序列化与 unsafe（DESER/UNSAFE）

**Sink**：
- `serde_pickle::from_reader(`（不可信 pickle=Python 同型对象还原面）
- `bincode`/`rmp` 自定义格式（长度字段进 `Vec::with_capacity` 的资源耗尽）
- `unsafe {` 块：指针算术/`transmute`/FFI 边界（`extern "C"` 接 C 库=C/C++ 表同型内存面）

**强制验证**：pickle 不接外部；unsafe 块逐处论证；FFI 输入长度契约核对。
