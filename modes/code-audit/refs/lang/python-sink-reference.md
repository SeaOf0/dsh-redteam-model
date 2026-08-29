# Python 审计 Sink 大表（按类型）

> 与 `java-sink-reference.md` / `php-sink-reference.md` 同形态：greppable、按类型分节，
> 供面映射与覆盖矩阵 sink 轴直接消费。深度手册见 `code-audit-python.md`（攻击视角逐类
> 漏洞模式）；本表只管「grep 什么、怎么判」。

## 1. SQL 注入（SQL）

**Sink**：
- 原生：`cursor.execute(` / `executemany(`（SQL 文本拼接）
- Django：`raw(` / `extra(`（where/select 拼接）
- SQLAlchemy：`text(`（f-string/% 拼接变量）、`engine.execute(` 拼接
- pandas：`read_sql(`（sql 字符串拼接）

**危险模式**：SQL 串与 f-string / `%` / `+` 拼接；表名列名排序字段直接内插。

**强制验证**：参数化（`?`/`:name`/`%(name)s`）；动态表名列名走白名单映射。

## 2. 命令注入（CMD）

**Sink**：
- `os.system(` / `os.popen(`
- `subprocess.run/call/check_output/Popen(`（`shell=True` + 命令串拼接）
- `pty.spawn(`

**危险模式**：`shell=True` 时命令串含用户输入（`;|&$()`）；`shell=False` 时首参（可执行
路径）或参数可控（参数注入——目标为 git/ssh/ffmpeg 类工具时高危）。

**强制验证**：参数列表形式 + `shell=False`；命令与参数白名单。

## 3. 反序列化（DESER）

**Sink**：
- `pickle.loads(` / `pickle.load(` / `shelve.open(`
- `yaml.load(`（未传 `Loader=SafeLoader`）
- `marshal.loads(`
- `dill.loads(`

**危险模式**：不可信字节/字符串进上述函数（pickle=yield 全局对象还原=代码执行）；
`yaml.load` 缺 SafeLoader（`= **` 构造 python/object/new 任意对象）。

**强制验证**：`yaml.safe_load`；pickle 类接口不接受任何外部输入；签名/加密信封。

## 4. SSRF（SSRF）

**Sink**：
- `requests.get/post/request(` / `httpx.` / `aiohttp.`（URL 可控）
- `urllib.request.urlopen(`
- `socket.create_connection(`（host 可控）

**危险模式**：URL 含用户输入；重定向跟随进内网；回调地址（webhook/导入功能）直接取参。

**强制验证**：协议/host 白名单（禁 file/gopher/dict）；解析后 IP 校验（防 DNS rebinding）。

## 5. 文件读写与路径穿越（FILE）

**Sink**：
- `open(`（路径拼接）、`os.remove(` / `shutil.rmtree(`
- `send_file(` / `send_from_directory(`（Flask，目录穿越）
- `os.path.join(`（`..` 绝对路径段可穿透）

**危险模式**：用户输入进路径拼接；`os.path.join(base, user)` 当 user 为绝对路径时 base 失效。

**强制验证**：resolve 后校验仍在 base 内；文件名白名单/重命名。

## 6. 解压穿越（ZIP）

**Sink**：
- `tarfile.extractall(`（条目名 `../`）
- `zipfile.extractall(`（旧版本条目穿越）
- `shutil.unpack_archive(`

**强制验证**：逐条目校验目标路径在解压目录内；条目数/总大小限额（防解压炸弹）。

## 7. 模板注入（SSTI）

**Sink**：
- `render_template_string(`（Flask，模板串含用户输入）
- `jinja2.Template(`（用户输入直接作模板）
- `str.format(` / `format_map(`（格式串可控——可越权读属性）

**强制验证**：用户数据只作模板变量不作模板；`format` 的格式串固定。

## 8. XXE（XXE）

**Sink**：
- `lxml.etree.parse/fromstring(`（默认解析外部实体，`resolve_entities` 态核对）
- `xml.sax` / `xml.dom.minidom`（配合外部 DTD 场景）
- `ElementTree`：不支持外部实体扩展（不构成 XXE，如实标注不算命中）

**强制验证**：`lxml` 显式禁实体（`XMLParser(resolve_entities=False)`）；DTD 禁用。

## 9. 输出与 XSS（XSS）

**Sink**：
- `markdown.markdown(`（输出进 HTML 且未 `bleach` 清洗）
- `render_template(`（`|safe` 过滤器作用于用户输入）
- JSON 接口被前端 `innerHTML` 消费（本表标注后端来源，前端处置看 javascript 表）

**强制验证**：输出编码；`|safe` 白名单化。

## 10. 加密与随机误用（CRYPTO）

**Sink**：
- `hashlib.md5(` / `hashlib.sha1(`（用于口令存储）
- `random.`（token/验证码生成——非密码学随机）
- 硬编码 `SECRET_KEY` / `API_KEY`（Django SECRET_KEY 泄露=会话伪造）

**强制验证**：口令走 `bcrypt/scrypt/argon2`；token 用 `secrets.`；密钥从环境注入。

## 11. 代码执行（EVAL）

**Sink**：
- `eval(` / `exec(` / `compile(`（任何含用户输入形态）
- `input()` 进 eval 的 REPL 遗留；`getattr(` 链式动态调用（`getattr(obj, user)` 白名单外）

**强制验证**：全部移除或白名单映射函数表。
