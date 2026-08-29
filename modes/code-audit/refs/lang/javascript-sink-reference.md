# JavaScript / Node.js 审计 Sink 大表（按类型）

> 与 java/php/python 表同形态：greppable、按类型分节。前端（浏览器）侧 sink 主要在
> pentest 客户端线；本表以 Node.js 服务端为主，前端 XSS 归 X 节标注。

## 1. 命令注入（CMD）

**Sink**：
- `child_process.exec(` / `execSync(`（走 shell——命令串拼接即危）
- `spawn(` / `execFile(`（`shell: true` 选项时同 exec；false 时看参数注入）
- `` exec(`${...}`) `` 模板串拼接

**危险模式**：模板串/`+` 拼接用户输入进 exec 族；`spawn(tool, [userArg])` 时 arg 以 `-`
开头（参数注入——git/ssh/ffmpeg 类工具高危）。

**强制验证**：`spawn(cmd, [args], {shell: false})` 参数数组；命令与参数白名单。

## 2. SQL 注入（SQL）

**Sink**：
- `mysql`/`mysql2`：`query(` / `execute(`（SQL 串拼接）
- `sequelize.literal(`（拼接进 SQL 的原文片段）
- `knex.raw(`（`??`/`?` 绑定之外的拼接）
- `typeorm`：`query(` 原生拼接、`orderBy(` 直接收列名

**危险模式**：模板串拼接 SQL；列名/表名/排序字段直接内插（绑定参数不覆盖标识符）。

**强制验证**：参数绑定；标识符白名单映射。

## 3. NoSQL 注入（NOSQL）

**Sink**：
- MongoDB：`collection.find(` / `findOne(` / `aggregate(`（查询对象由 `req.body` 直接
  展开——操作符注入 `$gt/$ne/$regex`）
- `$where`：值为 JS 表达式（服务端执行——**代码执行级**，等同 eval）
- Mongoose：`where(` 链式收对象字段

**危险模式**：`JSON.parse(req.body)` 整体作为 query；body-parser 解析后未做类型固化
（字符串改对象即带 `$` 键）。经典形态：`{"pass": {"$ne": ""}}`。

**强制验证**：查询字段逐项提取并类型固化；`$where` 一律禁用户输入；`mongo-sanitize` 类
键清洗（注意只清 `$` 前缀键不防点号键污染）。

## 4. 反序列化（DESER）

**Sink**：
- `node-serialize`：`unserialize(`（**已知 RCE**——`_$$ND_FUNC$$_` 键直接 eval 函数体）
- `serialize-javascript`：`deserialize` 场景（旧版 eval 面）
- `funcster` / 自研 JSON-with-function 还原

**危险验证**：该类库一律不接受不可信输入；评估升级/移除。

## 5. SSRF（SSRF）

**Sink**：
- `axios.get/post(`（URL 可控）、`node-fetch(`、`got(`、`request(`（legacy）
- `http.request(` / `https.request(`（host 拼接）
- `dns.lookup(` + 连接（重绑定窗口）

**强制验证**：协议/host 白名单；重定向策略固定；解析后 IP 复核。

## 6. 文件读写与路径穿越（FILE）

**Sink**：
- `fs.readFile/writeFile/createReadStream(`（路径拼接）
- `path.join(base, user)`（`../` 段穿透）
- `res.sendFile(`（Express，未限制 root 时穿越）
- `res.download(`

**强制验证**：`path.resolve` 后 `startsWith(base + path.sep)`；文件名服务端生成。

## 7. 解压穿越（ZIP）

**Sink**：
- `adm-zip`：`extractAllTo(`（条目名穿越）
- `yauzl` / `unzipper`：逐条目写出未校验目标路径
- `tar.extract(`（tar 条目 `../`/符号链接）

**强制验证**：逐条目路径校验在目标目录内；链接条目默认拒绝。

## 8. 原型污染（PROTO）

**Sink**（污染入口——本身低危，gadget 决定危害）：
- 递归 merge：`lodash.merge/mergeWith`（旧版）、`defaultsDeep`、`deepmerge`（非安全版）
- `Object.assign` 深拷贝自研递归（`__proto__` 键未拦）
- query-string 类解析（`?__proto__[x]=1` 数组键形式）

**危险模式**：污染→gadget 链——`child_process.spawn` 的 `options.env/shell`、EJS 模板
option 注入、`err.stack` 触发链。**污染入口+可达 gadget 才是 RCE，双链都要追**。

**强制验证**：merge 前拦 `__proto__`/`constructor`/`prototype` 键；依赖升级到修复版。

## 9. 模板注入（SSTI）

**Sink**：
- `ejs.render(`（模板串含用户输入；option 注入走 PROTO）
- `pug.render(` / `pug.compile(`（用户输入作模板=代码执行）
- `handlebars.compile(`（用户输入作模板）

**强制验证**：用户数据只作 data 不作模板源。

## 10. 代码执行（EVAL）

**Sink**：
- `eval(` / `new Function(`（任何用户输入形态）
- `vm.runInContext/runInNewContext(`（沙箱逃逸——`this.constructor.constructor` 链已知）
- `setTimeout/setInterval(` 首参为字符串（隐式 eval）

**强制验证**：全部移除；`vm` 不作为安全边界。

## 11. 输出与 XSS（XSS）

**Sink**（后端标注）：
- `res.send(` / `res.send(String(user))`（HTML 上下文反射，旧 Express 无默认类型嗅探修复时）
- JSON 接口字段被前端 `innerHTML`/`v-html`/`dangerouslySetInnerHTML` 消费——**跨表联动
  javascript 前端审计**：后端登记「用户提供+危险消费点」，前端登记消费面。

**强制验证**：按上下文编码；富文本走白名单清洗。

## 12. JWT 与会话（AUTH）

**Sink**：
- `jsonwebtoken.verify(`（缺 `algorithms` 白名单——`alg: none`/算法混淆）
- 硬编码 `jwt_SECRET`（伪造任意用户 token）
- `express-session` 默认内存 store + 未设 secret

**强制验证**：`algorithms: ['RS256'|'HS256']` 显式钉死；密钥环境注入；密钥弱熵核对
（HS256 弱密钥可离线爆破——字典与 rockyou 形态）。
