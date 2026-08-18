---
name: code-audit-javascript
description: >
  JavaScript/TypeScript 应用安全代码审计完整手册 — 覆盖 Node.js (Express/Fastify/NestJS)
  和前端 (React/Vue/Next.js) 的 XSS、原型污染、SSRF、命令注入、路径穿越、JWT、
  ReDoS、不安全反序列化、依赖混淆、CORS 配置错误等漏洞，
  攻防合一：Part A 攻击视角手工审计模式 + ESLint/Semgrep 工具链，
  Part B 安全编码 + 检测规则 + CI/CD 集成，内置 JS/TS 漏洞速查矩阵。
domain: cybersecurity
subdomain: code-audit
tags: [javascript, typescript, nodejs, express, react, code-audit, xss, prototype-pollution, sast]
version: 2.0.0
---

# JavaScript/TypeScript 应用安全代码审计 — 完整攻防手册

## 适用场景

- Node.js 后端 (Express / Fastify / NestJS / Koa) 源码安全审计
- React / Vue / Next.js / Nuxt 前端安全审计
- NPM 包 / Electron 应用安全审查
- **不适用**：纯 CSS 样式审计、React Native 移动端（见 mobile-pentest-android）

## 前置条件

- Node.js 18+ / npm / yarn / pnpm
- 源码访问权限
- 工具：ESLint (eslint-plugin-security) / Semgrep / npm audit / snyk / socket

---

## Part A：攻击视角 — 漏洞模式与审计方法

### 1. XSS 跨站脚本审计

**反射/存储型 XSS（前端）：**

```jsx
// ❌ React dangerouslySetInnerHTML
<div dangerouslySetInnerHTML={{ __html: userInput }} />

// ❌ Vue v-html
<div v-html="userInput"></div>

// ❌ 直接 DOM 操作
document.getElementById('output').innerHTML = userInput;
element.insertAdjacentHTML('beforeend', userInput);

// ✅ React 默认转义
<div>{userInput}</div>

// ✅ DOMPurify 净化
import DOMPurify from 'dompurify';
<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(userInput) }} />
```

**DOM XSS（URL 参数 → DOM）：**

```javascript
// ❌ location.hash / location.search 直接写入 DOM
document.write(location.hash.substring(1));

// ❌ eval 用户输入
eval(request.params.code);

// ✅ 安全处理
const params = new URLSearchParams(location.search);
const value = encodeURIComponent(params.get('q'));
document.getElementById('output').textContent = value;
```

**审计 grep：**

```bash
grep -rn 'dangerouslySetInnerHTML\|v-html\|innerHTML\|outerHTML\|document\.write\|insertAdjacentHTML' --include='*.js' --include='*.jsx' --include='*.ts' --include='*.tsx' --include='*.vue' . | grep -v 'node_modules\|DOMPurify\|sanitize'
grep -rn 'eval(\|new Function(' --include='*.js' --include='*.ts' . | grep -v 'node_modules\|test'
```

### 2. 原型污染审计

```javascript
// ❌ 不安全的递归合并
function merge(target, source) {
    for (const key in source) {
        if (typeof source[key] === 'object') {
            target[key] = target[key] || {};
            merge(target[key], source[key]);  // __proto__ 污染
        } else {
            target[key] = source[key];
        }
    }
}

// ❌ lodash < 4.17.12 的 merge/defaultsDeep
_.merge({}, JSON.parse(userInput));

// ❌ 用户输入控制 Object.assign 键
Object.assign(config, JSON.parse(userInput));

// ✅ 安全合并
function safeMerge(target, source) {
    const blocked = ['__proto__', 'constructor', 'prototype'];
    for (const key of Object.keys(source)) {
        if (blocked.includes(key)) continue;
        target[key] = source[key];
    }
}

// ✅ Object.create(null) — 无原型
const safe = Object.create(null);
```

**审计 grep：**

```bash
grep -rn '__proto__\|constructor\["prototype"\]\|Object\.assign.*JSON\.parse\|\.merge(.*JSON\.parse' --include='*.js' --include='*.ts' . | grep -v 'node_modules'
grep -rn 'lodash.*merge\|lodash.*set\|lodash.*zipObjectDeep' --include='*.js' --include='*.ts' .
```

### 3. 命令注入审计（Node.js）

```javascript
// ❌ exec/execSync + 字符串拼接
const { exec } = require('child_process');
exec(`ping ${userInput}`, (err, stdout) => { ... });

// ❌ eval / Function 构造器
eval(req.body.code);
new Function('return ' + req.body.expression)();

// ✅ execFile / spawn（参数数组）
const { execFile } = require('child_process');
execFile('ping', ['-c', '1', userInput], (err, stdout) => { ... });

// ✅ spawn
const { spawn } = require('child_process');
spawn('dig', [domain], { shell: false });
```

**审计 grep：**

```bash
grep -rn 'exec(\|execSync(\|spawn(.*shell:\s*true\|eval(\|new Function(' --include='*.js' --include='*.ts' . | grep -v 'node_modules\|test\|\.d\.ts'
```

### 4. SQL 注入审计（Node.js）

```javascript
// ❌ 字符串拼接 SQL
db.query(`SELECT * FROM users WHERE id = ${req.params.id}`);

// ❌ Knex raw 拼接
knex.raw(`SELECT * FROM users WHERE name = '${name}'`);

// ✅ 参数化查询
db.query('SELECT * FROM users WHERE id = ?', [req.params.id]);

// ✅ Knex 参数化
knex('users').where('id', req.params.id);

// ✅ Prisma（ORM）
await prisma.user.findUnique({ where: { id: parseInt(req.params.id) } });
```

**审计 grep：**

```bash
grep -rn 'query(`\|\.raw(`\|\.raw("' --include='*.js' --include='*.ts' . | grep -v 'node_modules\|test'
```

### 5. 路径穿越 / 文件操作审计

```javascript
// ❌ 用户输入拼路径
const fs = require('fs');
fs.readFile(`/uploads/${req.params.filename}`, (err, data) => { ... });

// ❌ path.join 不安全
const target = path.join(__dirname, 'public', req.query.file);

// ✅ 路径规范化 + 边界检查
const path = require('path');
function safePath(base, userInput) {
    const resolved = path.resolve(base, userInput);
    if (!resolved.startsWith(path.resolve(base) + path.sep)) {
        throw new Error('Path traversal');
    }
    return resolved;
}
```

**审计 grep：**

```bash
grep -rn 'fs\.readFile\|fs\.readFileSync\|fs\.createReadStream\|fs\.writeFile\|path\.join(' --include='*.js' --include='*.ts' . | grep -v 'node_modules\|test'
```

### 6. SSRF 审计

```javascript
// ❌ 用户可控 URL
const axios = require('axios');
app.get('/proxy', async (req, res) => {
    const { data } = await axios.get(req.query.url);  // SSRF
    res.send(data);
});

// ❌ fetch 用户输入
fetch(userControlledUrl);

// ✅ URL 白名单 + IP 检查
const { URL } = require('url');
const dns = require('dns').promises;

async function safeFetch(url) {
    const parsed = new URL(url);
    if (!['http:', 'https:'].includes(parsed.protocol)) throw new Error('Bad scheme');
    if (!ALLOWED_HOSTS.includes(parsed.hostname)) throw new Error('Host not allowed');
    const { address } = await dns.lookup(parsed.hostname);
    if (isPrivateIP(address)) throw new Error('Private IP');
    return fetch(url);
}
```

**审计 grep：**

```bash
grep -rn 'axios\.get\|axios\.post\|fetch(\|request(\|http\.get\|https\.get\|node-fetch' --include='*.js' --include='*.ts' . | grep -v 'node_modules\|test\|\.d\.ts'
```

### 7. 认证与 JWT 漏洞

```javascript
// ❌ JWT algorithm: none
const jwt = require('jsonwebtoken');
jwt.verify(token, secret, { algorithms: ['HS256', 'none'] });  // none attack

// ❌ 硬编码密钥
const SECRET = 'my-super-secret';

// ❌ JWT 存储在 localStorage（XSS 可窃取）
localStorage.setItem('token', token);

// ✅ 强制指定算法
jwt.verify(token, publicKey, { algorithms: ['RS256'] });

// ✅ HttpOnly cookie
res.cookie('token', token, {
    httpOnly: true,
    secure: true,
    sameSite: 'strict',
    maxAge: 3600000
});
```

**审计 grep：**

```bash
grep -rn 'jwt\.verify\|jwt\.sign\|jsonwebtoken' --include='*.js' --include='*.ts' . | grep -v 'node_modules'
grep -rn 'localStorage\|sessionStorage' --include='*.js' --include='*.jsx' --include='*.ts' --include='*.tsx' . | grep -v 'node_modules\|test'
grep -rn 'SECRET\|PRIVATE_KEY\|API_KEY' --include='*.js' --include='*.ts' --include='*.env' . | grep -v 'node_modules\|process\.env\|\.git'
```

### 8. ReDoS（正则表达式拒绝服务）

```javascript
// ❌ 回溯型正则（灾难性）
const emailRegex = /^([a-zA-Z0-9._%+-]+)@([a-zA-Z0-9.-]+)\.([a-zA-Z]{2,})$/;
// 输入 "aaaaaaa..." 可导致指数级回溯

// ❌ 嵌套量词
/(a+)+b/.test(userInput);  // ReDoS

// ✅ 安全正则
const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;

// ✅ 限制输入长度
if (input.length > 1000) throw new Error('Input too long');
regex.test(input);
```

**审计 grep：**

```bash
grep -rn 'new RegExp(\|/[^/]*[+*][^/]*[+*]/' --include='*.js' --include='*.ts' . | grep -v 'node_modules'
```

### 9. 依赖安全

```bash
# npm 内置审计
npm audit
npm audit --json

# 检查已知恶意包
npx socket scan --workspace .

# 检查包维护者变化
npx npm-check-updates

# 锁定依赖版本（package-lock.json）
npm ci  # 严格按 lockfile 安装

# 检查 typosquatting
npx socket npm verify
```

---

## Part B：检测与防御

### 10. SAST 工具链

**ESLint 安全插件：**

```javascript
// .eslintrc.js
module.exports = {
    plugins: ['security'],
    extends: ['plugin:security/recommended'],
    rules: {
        'security/detect-object-injection': 'warn',
        'security/detect-non-literal-regexp': 'warn',
        'security/detect-unsafe-regex': 'error',
        'security/detect-buffer-unsafe-allocation': 'error',
        'security/detect-child-process': 'error',
        'security/detect-disable-mustache-escape': 'error',
        'security/detect-eval-with-expression': 'error',
        'security/detect-new-buffer': 'error',
        'security/detect-no-csrf-before-method-override': 'error',
        'security/detect-non-literal-fs-filename': 'warn',
        'security/detect-non-literal-regexp': 'warn',
        'security/detect-non-literal-require': 'warn',
        'security/detect-possible-timing-attacks': 'warn',
        'security/detect-pseudoRandomBytes': 'error',
    }
};
```

**Semgrep JS/TS 规则：**

```bash
semgrep --config p/javascript --config p/typescript --config p/owasp-top-ten \
        --config p/react --config p/expressjs src/
```

**npm scripts 安全集成：**

```json
{
    "scripts": {
        "lint:security": "eslint --ext .js,.ts,.jsx,.tsx src/ -c .eslintrc.security.js",
        "audit": "npm audit --audit-level=high",
        "sast": "semgrep --config p/javascript --config p/typescript src/",
        "security": "npm run lint:security && npm run audit && npm run sast"
    }
}
```

### 11. 安全编码防御

**Express 安全中间件：**

```javascript
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');

app.use(helmet());
app.use(cors({
    origin: ['https://trusted.example.com'],
    credentials: true,
    methods: ['GET', 'POST'],
}));
app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 100 }));
app.use(express.json({ limit: '10kb' }));  // 限制 body 大小

// CSP
app.use(helmet.contentSecurityPolicy({
    directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'"],
        imgSrc: ["'self'", "data:"],
    }
}));
```

**输入验证（Joi / Zod）：**

```typescript
import { z } from 'zod';

const UserSchema = z.object({
    username: z.string().min(3).max(50).regex(/^[a-zA-Z0-9_-]+$/),
    email: z.string().email(),
    age: z.number().int().min(0).max(150),
    role: z.enum(['user', 'moderator']),  // 不允许 admin
}).strict();  // 禁止额外字段

app.post('/users', (req, res) => {
    const result = UserSchema.safeParse(req.body);
    if (!result.success) return res.status(400).json(result.error);
    // result.data 已验证
});
```

### 12. CI/CD 安全管道

```yaml
# .github/workflows/js-security.yml
name: JS/TS Security
on: [push, pull_request]
jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'

      - run: npm ci

      - name: ESLint Security
        run: npx eslint --ext .js,.ts,.jsx,.tsx src/ -c .eslintrc.security.js

      - name: Semgrep SAST
        uses: semgrep/semgrep-action@v1
        with:
          config: >-
            p/javascript
            p/typescript
            p/react
            p/expressjs
            p/owasp-top-ten

      - name: npm audit
        run: npm audit --audit-level=high

      - name: Socket Security
        run: npx socket scan --workspace .
```

---

## 速查表

### JS/TS 漏洞模式 → 审计关键词 → 修复方案矩阵

| 漏洞类型 | 审计关键词 | 危险模式 | 安全替代 |
|----------|-----------|---------|---------|
| XSS | `innerHTML`, `v-html`, `dangerouslySetInnerHTML` | 用户输入写 DOM | React 默认转义 / DOMPurify |
| 原型污染 | `__proto__`, `merge`, `Object.assign` | 递归合并用户输入 | `Object.create(null)` + 键过滤 |
| 命令注入 | `exec(`, `eval(`, `new Function(` | 用户输入拼命令 | `execFile` / `spawn` + `shell:false` |
| SQL 注入 | `query(\``, `raw(\`` | 字符串拼接 SQL | 参数化 / ORM |
| 路径穿越 | `path.join` + 用户输入, `fs.readFile` | 直接拼路径 | `path.resolve` + `startsWith` |
| SSRF | `axios.get`, `fetch(`, `http.get` | 用户可控 URL | URL 白名单 + IP 检查 |
| JWT 漏洞 | `algorithms: ['none']`, `localStorage` | None 算法 / XSS 窃取 | 强制 RS256 + HttpOnly cookie |
| ReDoS | 嵌套量词 `/(a+)+b/` | 回溯型正则 | 简化正则 + 限长 |
| 硬编码密钥 | `SECRET =`, `API_KEY =` | 明文密钥 | 环境变量 / Vault |
| CORS | `origin: '*'`, `credentials: true` | 通配符 + 凭据 | 指定域名 |
| 依赖漏洞 | `package.json` | 已知 CVE / 恶意包 | `npm audit` + `socket` |

### ESLint Security 规则 ID 速查

| Rule ID | 检测内容 | 严重性 |
|---------|---------|--------|
| detect-buffer-unsafe-allocation | Buffer 不安全分配 | Error |
| detect-child-process | child_process 使用 | Error |
| detect-disable-mustache-escape | 模板转义禁用 | Error |
| detect-eval-with-expression | eval 表达式 | Error |
| detect-new-buffer | new Buffer() | Error |
| detect-no-csrf-before-method-override | CSRF 配置错误 | Error |
| detect-non-literal-fs-filename | 非字面量文件名 | Warn |
| detect-non-literal-regexp | 非字面量正则 | Warn |
| detect-non-literal-require | 非字面量 require | Warn |
| detect-object-injection | 对象注入 | Warn |
| detect-possible-timing-attacks | 时序攻击 | Warn |
| detect-pseudoRandomBytes | 伪随机数 | Error |
| detect-unsafe-regex | 不安全正则 | Error |

---

## MITRE ATT&CK 映射

| 战术 | Technique | JS/TS 相关场景 |
|------|-----------|---------------|
| Initial Access | T1190 | XSS、SSRF、Express 路由漏洞 |
| Execution | T1059.007 — JavaScript | eval/exec、原型污染 RCE |
| Persistence | T1133 | JWT 伪造、localStorage token 窃取 |
| Credential Access | T1212 | 硬编码密钥、JWT None |
| Defense Evasion | T1140 | 原型污染绕过验证 |
| Exfiltration | T1041 | SSRF 数据外泄 |
| Impact | T1489 — Service Stop | ReDoS 拒绝服务 |

---

## Part C：2025-2026 更新

> 基于 2025 年最新威胁情报与实战经验补充，覆盖 Prototype Pollution 深度利用、ReDoS 精确分析、供应链攻击体系、Electron 安全审计、Next.js/React 服务端安全、OWASP Node.js 检查清单等。

---

### 13. Prototype Pollution 深度利用（Node.js / 浏览器）

**13.1 污染向服务端 RCE 的 Gadget Chain**

原型污染本身不直接导致 RCE，但通过污染内置对象属性可以触发已有的代码 gadget：

```javascript
// ❌ 利用场景 1: 污染 expectedJSON 属性 → EJS 模板引擎 RCE
// 攻击 payload:
JSON.parse('{"__proto__":{"outputFunctionName":"a; return process.mainModule.require(\"child_process\").execSync(\"id\").toString()//"}}')

// ❌ 利用场景 2: 污染 admin 属性 → 绕过权限检查
if (user.admin) { /* 管理员操作 */ }
// 攻击: Object.prototype.admin = true;

// ❌ 利用场景 3: 污染环境变量路径
// Object.prototype.NODE_OPTIONS = "--require /tmp/evil.js";
```

**13.2 已知 CVE 与受影响库**

| CVE | 受影响库 | 污染路径 |
|-----|---------|---------|
| CVE-2025-57353 | messageformat < 3.0.2 | Runtime 组件原型污染 |
| CVE-2022-24675 | lodash < 4.17.12 | `_.merge` / `_.defaultsDeep` |
| CVE-2020-8203 | lodash < 4.17.19 | `_.zipObjectDeep` |
| CVE-2019-10744 | lodash < 4.17.12 | `_.defaultsDeep` / `_.merge` |
| CVE-2020-36604 | node-forge | `.setPath` 原型污染 |

**13.3 深度审计 grep（含 gadget 检测）**

```bash
# 检测常见污染入口
grep -rn 'merge\|deepMerge\|extend\|defaultsDeep\|zipObjectDeep\|setWithPath' \
  --include='*.js' --include='*.ts' . | grep -v 'node_modules'

# 检测 gadget: 模板引擎 + 原型污染组合
grep -rn 'ejs\|pug\|nunjucks\|handlebars\|mustache' --include='*.js' . | grep -v 'node_modules'

# 检测 Object.prototype 直接赋值
grep -rn 'Object\.prototype\[.*\]\s*=\|Object\.prototype\.\w*\s*=' \
  --include='*.js' --include='*.ts' . | grep -v 'node_modules\|test'

# 检测 constructor 链污染
grep -rn 'constructor\["prototype"\]\|constructor\.prototype' \
  --include='*.js' --include='*.ts' . | grep -v 'node_modules'
```

**13.4 防御升级**

```javascript
// ✅ 使用 Map 替代 Object 存储用户数据
const userStore = new Map();
userStore.set(key, value);  // 无原型链

// ✅ JSON.parse 后过滤危险键
function safeParse(json) {
    const obj = JSON.parse(json);
    function clean(o) {
        if (typeof o !== 'object' || o === null) return o;
        for (const key of Object.keys(o)) {
            if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
                delete o[key];
            } else {
                o[key] = clean(o[key]);
            }
        }
        return o;
    }
    return clean(obj);
}

// ✅ 冻结关键原型
Object.freeze(Object.prototype);
// 注意：可能导致部分库兼容性问题，需测试
```

---

### 14. ReDoS 深度分析（正则表达式拒绝服务）

**14.1 灾难性回溯模式识别**

```javascript
// ❌ 经典灾难性回溯模式
/(a+)+b/           // 指数级回溯
/(a*)*b/           // 指数级回溯
/([a-zA-Z0-9._%+-]+)@/  // 嵌套量词
/(a|a)*b/          // 交替 + 量词
/(a+)+$/           // 锚定 + 量词
/(.*a){10}/        // 重复量词 + 通配符

// 测量回溯时间
const start = Date.now();
/(a+)+b/.test('a'.repeat(30));  // 可能卡死数秒
console.log(`耗时: ${Date.now() - start}ms`);
```

**14.2 安全正则编写原则**

```javascript
// ✅ 避免嵌套量词 → 使用原子组或占有量词（ES2025+）
// 使用 String.prototype.replace 预处理
function safeRegexTest(pattern, input, maxLength = 1000) {
    if (typeof input === 'string' && input.length > maxLength) {
        throw new Error(`输入超过最大长度 ${maxLength}`);
    }
    return pattern.test(input);
}

// ✅ 常见正则安全替代
// 邮箱（简单版）
/^[^\s@]+@[^\s@]+\.[^\s@]+$/;
// URL
/^https?:\/\/[a-zA-Z0-9.-]+(?:\/[^\s]*)?$/;
// IPv4
/^(\d{1,3}\.){3}\d{1,3}$/;
```

**14.3 ReDoS 审计工具**

```bash
# 使用 safe-regex 检测危险正则
npx safe-regex --include='*.js,*.ts' src/

# 使用 rexreplace 或手动检查
grep -rn 'new RegExp(' --include='*.js' --include='*.ts' . | grep -v 'node_modules'

# Node.js 20+ 内置 --max-old-space-size 限制可缓解但非根治
node --max-old-space-size=256 app.js
```

---

### 15. 供应链攻击检测体系

**15.1 多层防御流程**

```
npm install → npm audit → Socket.dev → Snyk → lockfile 校验 → 运行时监控
```

**15.2 工具链详细用法**

```bash
# 1) npm audit（内置，基础层）
npm audit --audit-level=moderate    # 中危以上
npm audit fix                       # 自动修复
npm audit fix --force               # 大版本升级修复（有风险）

# 2) Socket.dev（供应链安全平台）
npx socket scan --workspace .        # 扫描工作区
npx socket npm verify                # 验证包安全性
npx socket report view               # 查看详细报告
# 检测项: 恶意代码、typosquatting、install 脚本、混淆代码

# 3) Snyk（深度依赖扫描）
npx snyk test                       # 测试已知漏洞
npx snyk monitor                    # 持续监控
npx snyk wizard                     # 交互式修复

# 4) npm 生命周期脚本审计
npm query "[type=script]"           # 查看 install 脚本
npx ignore-scripts                  # 禁用所有 install 脚本

# 5) lockfile 完整性
npm ci                              # 严格按 lockfile 安装
# 校验 package-lock.json hash
sha256sum package-lock.json
```

**15.3 package.json 安全加固**

```jsonc
{
    // 禁用 install 脚本
    "scripts": {
        "preinstall": "npx only-allow pnpm",  // 强制使用 pnpm
        "postinstall": "npm audit --audit-level=high || exit 1"
    },
    // 限制引擎版本
    "engines": {
        "node": ">=20.0.0",
        "npm": ">=10.0.0"
    },
    // 锁定依赖范围
    "overrides": {
        "lodash": "^4.17.21"  // 强制统一安全版本
    }
}
```

**15.4 .npmrc 安全配置**

```ini
# .npmrc
audit=true                    # 安装时自动审计
ignore-scripts=true           # 禁用包脚本
package-lock=true             # 强制 lockfile
strict-ssl=true               # 强制 HTTPS
registry=https://registry.npmmirror.com  # 或企业私有 registry
```

---

### 16. Electron 安全审计

**16.1 关键安全检查项**

```javascript
// ❌ 危险: nodeIntegration 开启
new BrowserWindow({
    webPreferences: {
        nodeIntegration: true,       // 允许渲染进程访问 Node.js
        contextIsolation: false,     // 禁用上下文隔离
        sandbox: false               // 禁用沙箱
    }
});

// ❌ 危险: remote 模块
const { remote } = require('@electron/remote');
remote.getGlobal('sharedObj');

// ✅ 安全配置
new BrowserWindow({
    webPreferences: {
        nodeIntegration: false,
        contextIsolation: true,
        sandbox: true,
        preload: path.join(__dirname, 'preload.js'),
        webSecurity: true,
        allowRunningInsecureContent: false
    }
});
```

**16.2 preload 脚本安全模式**

```javascript
// preload.js — 使用 contextBridge 安全暴露 API
const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('electronAPI', {
    readFile: (path) => ipcRenderer.invoke('read-file', path),
    selectFolder: () => ipcRenderer.invoke('select-folder'),
    // ❌ 不要暴露: ipcRenderer.send, require, process
});
```

**16.3 Electron 审计 grep**

```bash
# 检测危险配置
grep -rn 'nodeIntegration.*true\|contextIsolation.*false\|sandbox.*false' \
  --include='*.js' --include='*.ts' . | grep -v 'node_modules'

# 检测 remote 模块使用
grep -rn '@electron/remote\|electron/remote\|remote\.getGlobal\|remote\.require' \
  --include='*.js' --include='*.ts' . | grep -v 'node_modules'

# 检测 shell.openExternal（可能打开恶意URL）
grep -rn 'shell\.openExternal' --include='*.js' --include='*.ts' .

# 检测 webview 标签使用
grep -rn 'webview\|<webview' --include='*.html' --include='*.js' .
```

---

### 17. Next.js / React 服务端安全

**17.1 React Server Components (RSC) 安全**

```typescript
// ❌ 危险: 在 Server Component 中直接使用用户输入
// CVE: React Server Components RCE (2025)
async function Page({ searchParams }) {
    const result = await db.query(
        `SELECT * FROM users WHERE id = ${searchParams.id}`  // SQL 注入
    );
    // ❌ 危险: 动态 require
    const mod = require(searchParams.module);  // RCE
}

// ✅ 安全: 参数化 + 输入验证
async function Page({ searchParams }: { searchParams: { id: string } }) {
    const id = z.string().uuid().parse(searchParams.id);
    const result = await db.query('SELECT * FROM users WHERE id = $1', [id]);
}
```

**17.2 Next.js API Route 安全**

```typescript
// app/api/route.ts
import { NextRequest, NextResponse } from 'next/server';
import { z } from 'zod';
import { rateLimit } from '@/lib/rate-limit';

const schema = z.object({
    name: z.string().max(100),
    email: z.string().email(),
});

export async function POST(req: NextRequest) {
    // 1. 速率限制
    const ip = req.ip ?? 'unknown';
    if (!await rateLimit(ip)) {
        return NextResponse.json({ error: 'Too many requests' }, { status: 429 });
    }

    // 2. Content-Type 校验
    const contentType = req.headers.get('content-type');
    if (!contentType?.includes('application/json')) {
        return NextResponse.json({ error: 'Invalid content type' }, { status: 400 });
    }

    // 3. Body 大小限制 (Next.js 默认限制)
    // next.config.js: api: { bodyParser: { sizeLimit: '1mb' } }

    // 4. 输入验证
    const body = await req.json();
    const result = schema.safeParse(body);
    if (!result.success) {
        return NextResponse.json({ error: result.error }, { status: 400 });
    }

    // 5. 安全响应头
    const response = NextResponse.json({ success: true });
    response.headers.set('X-Content-Type-Options', 'nosniff');
    response.headers.set('X-Frame-Options', 'DENY');
    return response;
}
```

**17.3 Next.js 安全配置**

```javascript
// next.config.js
module.exports = {
    async headers() {
        return [{
            source: '/(.*)',
            headers: [
                { key: 'X-Frame-Options', value: 'DENY' },
                { key: 'X-Content-Type-Options', value: 'nosniff' },
                { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
                { key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=()' },
                { key: 'Content-Security-Policy', value: "default-src 'self'; script-src 'self' 'unsafe-eval' 'unsafe-inline'; style-src 'self' 'unsafe-inline';" },
            ]
        }];
    },
    // 限制 API body 大小
    experimental: {
        api: { bodyParser: { sizeLimit: '1mb' } }
    }
};
```

**17.4 Next.js 审计 grep**

```bash
# 检测 Server Actions 不安全用法
grep -rn '"use server"' --include='*.ts' --include='*.tsx' . | head -20
grep -rn 'use server' --include='*.ts' --include='*.tsx' -A 10 . | \
  grep 'eval\|exec\|require(' | grep -v 'node_modules'

# 检测 dangerouslySetInnerHTML
grep -rn 'dangerouslySetInnerHTML' --include='*.tsx' --include='*.jsx' . | \
  grep -v 'DOMPurify\|sanitize\|node_modules'

# 检测 next.config.js 安全配置缺失
cat next.config.js | grep -c 'X-Frame-Options\|Content-Security-Policy\|X-Content-Type'
# 输出 0 则说明缺少安全头
```

---

### 18. 安全审计工具体系（2025 更新）

**18.1 工具矩阵**

| 工具 | 类型 | 用途 | 集成方式 |
|------|------|------|---------|
| ESLint + eslint-plugin-security | SAST | 代码模式检测 | npm scripts / CI |
| ESLint + @microsoft/eslint-plugin-sdl | SAST | Microsoft SDL 规则集 | npm scripts / CI |
| Semgrep | SAST | 多语言模式匹配 | CLI / GitHub Action |
| npm audit | SCA | 已知漏洞检测 | npm 内置 / CI |
| Socket.dev | SCA | 供应链安全分析 | CLI / GitHub Action |
| Snyk | SCA + SAST | 全栈安全平台 | CLI / GitHub Action |
| npm-audit-resolver | SCA | 审计结果持久化管理 | npm scripts |
| safe-regex | 质量检测 | ReDoS 检测 | CLI |
| npm-query | 依赖分析 | 包属性查询 | npm 内置 |
| Trivy | 容器 + 依赖 | 多层安全扫描 | CI |

**18.2 Semgrep 自定义规则示例**

```yaml
# semgrep-rules/javascript-prototype-pollution.yml
rules:
  - id: js-prototype-pollution-merge
    patterns:
      - pattern: |
          function $FUNC($TARGET, $SOURCE) {
            ...
            for (const $KEY in $SOURCE) {
              ...
              $TARGET[$KEY] = ...;
            }
          }
      - pattern-not: |
          function $FUNC($TARGET, $SOURCE) {
            ...
            if ($KEY === '__proto__') continue;
            ...
          }
    message: "不安全的递归合并可能导致原型污染"
    severity: ERROR
    languages: [javascript, typescript]

  - id: js-electron-node-integration
    pattern: |
      new BrowserWindow({
        webPreferences: {
          nodeIntegration: true,
          ...
        }
      })
    message: "Electron nodeIntegration 不应开启"
    severity: ERROR
    languages: [javascript, typescript]
```

**18.3 完整安全扫描脚本**

```bash
#!/bin/bash
# security-scan.sh — JS/TS 项目完整安全扫描
set -euo pipefail

echo "=== 1. ESLint 安全检测 ==="
npx eslint --ext .js,.ts,.jsx,.tsx src/ -c .eslintrc.security.js --format json --output-file eslint-security.json || true

echo "=== 2. Semgrep SAST ==="
semgrep --config p/javascript --config p/typescript --config p/owasp-top-ten \
        --config p/react --config p/expressjs --json -o semgrep-results.json src/ || true

echo "=== 3. npm audit ==="
npm audit --audit-level=moderate --json > npm-audit.json || true

echo "=== 4. Socket 供应链扫描 ==="
npx socket scan --workspace . --json > socket-scan.json || true

echo "=== 5. Snyk 深度扫描 ==="
npx snyk test --json > snyk-results.json || true

echo "=== 6. ReDoS 检测 ==="
npx safe-regex --include='*.js,*.ts' src/ > redos-results.txt || true

echo "=== 扫描完成 ==="
echo "结果文件: eslint-security.json / semgrep-results.json / npm-audit.json / socket-scan.json / snyk-results.json / redos-results.txt"
```

---

### 19. OWASP Node.js 安全检查清单

| # | 检查项 | 验证方法 | 优先级 |
|---|--------|---------|--------|
| 1 | Node.js 版本为最新 LTS | `node -v` 对照 nodejs.org | P0 |
| 2 | 无已知漏洞依赖 | `npm audit --audit-level=moderate` | P0 |
| 3 | 无 install-time 脚本执行 | `.npmrc: ignore-scripts=true` | P0 |
| 4 | 所有用户输入经过验证 (Zod/Joi) | grep schema/validate | P0 |
| 5 | 无硬编码密钥/凭证 | git-secrets / detect-secrets | P0 |
| 6 | Helmet 安全头已配置 | 检查 app.use(helmet()) | P1 |
| 7 | CORS 配置严格 | 非 `*` origin | P1 |
| 8 | 速率限制已启用 | express-rate-limit / custom | P1 |
| 9 | JWT 使用 RS256+ 且存 HttpOnly cookie | 检查 verify options | P1 |
| 10 | 无 eval/exec + 字符串拼接 | grep 审计 | P1 |
| 11 | SQL 使用参数化查询 | grep 模板字符串 SQL | P1 |
| 12 | 文件路径穿越防护 | path.resolve + startsWith | P1 |
| 13 | SSRF 防护 (URL 白名单 + IP 检查) | 检查 fetch/axios 调用 | P2 |
| 14 | 正则表达式安全 (无灾难性回溯) | safe-regex 工具 | P2 |
| 15 | 原型污染防护 | 键过滤 / Object.freeze | P2 |
| 16 | 依赖锁定 (package-lock.json) | npm ci 安装 | P2 |
| 17 | 错误处理不泄露堆栈 | 生产环境 NODE_ENV=production | P2 |
| 18 | 日志不包含敏感信息 | 检查 winston/bunyan 配置 | P2 |
| 19 | Content-Security-Policy 已配置 | 响应头检查 | P2 |
| 20 | CI/CD 安全扫描集成 | 检查 workflow 文件 | P3 |

---

### 20. 更新 MITRE ATT&CK 映射（2025 扩展）

| 战术 | Technique | JS/TS 相关场景 |
|------|-----------|---------------|
| Initial Access | T1190 — Exploit Public-Facing App | XSS、SSRF、Express/Next.js 路由漏洞、React Server Components RCE |
| Initial Access | T1195.002 — Compromise Software Supply Chain | npm 恶意包、typosquatting、依赖混淆、install 脚本投毒 |
| Execution | T1059.007 — JavaScript | eval/exec、原型污染 RCE、Electron nodeIntegration |
| Execution | T1203 — Exploitation for Client Execution | 浏览器 XSS → payload 执行、Electron 客户端漏洞 |
| Persistence | T1133 — External Remote Services | JWT 伪造、localStorage token 窃取 |
| Persistence | T1136 — Create Account | 原型污染添加 admin 属性 |
| Defense Evasion | T1140 — Deobfuscate/Decode Files | 原型污染绕过验证、混淆恶意 npm 包 |
| Credential Access | T1212 — Exploitation for Credential Access | 硬编码密钥、JWT None 算法、.env 泄露 |
| Credential Access | T1530 — Data from Cloud Storage | S3 bucket 配置错误（Node.js 部署场景） |
| Discovery | T1087 — Account Discovery | 原型污染 → 权限探测、API 枚举 |
| Lateral Movement | T1021 — Remote Services | SSRF 访问内部服务（CVE-2025-23167 HTTP Smuggling） |
| Exfiltration | T1041 — Exfiltration Over C2 Channel | SSRF 数据外泄、DNS 隧道（Node.js net 模块） |
| Exfiltration | T1567 — Exfiltration Over Web Service | fetch/axios 向外部服务发送数据 |
| Impact | T1489 — Service Stop | ReDoS 拒绝服务 |
| Impact | T1499 — Endpoint Denial of Service | ReDoS、大文件上传、JSON body 炸弹 |

---

### 21. 2025 关键 CVE 速查

| CVE | 影响组件 | 类型 | CVSS | 修复版本 |
|-----|---------|------|------|---------|
| CVE-2025-57353 | messageformat < 3.0.2 | Prototype Pollution | 7.5 | 3.0.2 |
| React Server Components RCE (2025) | Next.js RSC | Remote Code Execution | 9.8 | 参阅 Next.js 安全公告 |
| CVE-2025-23167 | Node.js 20.x | HTTP Request Smuggling | 5.3 | 20.19.4+ / 22.17.1+ / 24.4.1+ |
| CVE-2024-XXX | Electron | Sandbox Escape | 8.0 | 保持最新版本 |

---

## Part D：2025-2026 精细化复核补充

> 基于 CISA/Unit 42/Wiz/NVD/阿里云AVD 等最新威胁情报，对 JavaScript/TypeScript 生态系统的关键安全事件、CVE、供应链攻击进行深度补充。覆盖 React RCE、npm 蠕虫、Axios 投毒、Electron 沙箱逃逸、Node.js 运行时漏洞、Nuxt 框架漏洞等。

---

### 22. React Server Components RCE — CVE-2025-55182 "React2Shell"

**22.1 漏洞概述**

| 属性 | 详情 |
|------|------|
| CVE | CVE-2025-55182 |
| 名称 | React2Shell |
| CVSS | **10.0 (Critical)** |
| 类型 | 未认证远程代码执行 (Pre-auth RCE) |
| 影响组件 | React Server Components (RSC) Flight 协议 |
| 受影响版本 | React 19.0.0 / 19.1.0 / 19.1.1 / 19.2.0 |
| 修复版本 | React **19.2.1+** |
| 披露日期 | 2025-12-03 |
| 发现者 | Wiz 安全研究团队 |

**22.2 技术分析**

Flight 协议是 RSC 用于流式传输服务端渲染 UI 的序列化格式。漏洞在于 Flight 协议在反序列化时未对特殊元素类型做充分验证，攻击者可构造恶意 Flight 响应触发服务端任意代码执行：

```
// Flight 协议序列化格式（简化）：
// 攻击者构造恶意 Flight payload → 触发服务端 require('child_process').exec()
//
// 攻击向量：
// 1. 攻击者控制上游 SSR 响应（SSRF + Flight 注入）
// 2. 攻击者控制 RSC payload 的反序列化路径
// 3. 利用 Flight 协议中的特殊引用类型绕过沙箱
```

**22.3 影响范围**

- 所有使用 React 19.x + Server Components 的应用
- Next.js App Router（基于 RSC）全部受影响
- Remix / 其他 RSC 兼容框架受影响
- **无需认证**，攻击复杂度低

**22.4 检测与应急**

```bash
# 1. 检查 React 版本
npm list react react-dom
# 输出 react@19.x.x → 需升级

# 2. 检查 Next.js 版本（如适用）
npm list next
# Next.js 15.x 使用 React 19，受影响

# 3. 升级命令
npm install react@latest react-dom@latest
npm install next@latest  # Next.js 也需同步升级

# 4. 检查日志中的 Flight 协议利用痕迹
grep -rn 'x-middleware-subrequest\|RSC/Flight\|__rsc_payload' /var/log/nginx/ /var/log/app/
```

**22.5 Semgrep 检测规则**

```yaml
rules:
  - id: react-rsc-unvalidated-input
    patterns:
      - pattern: |
          async function $FUNC($REQ) {
            ...
            const $DATA = await $REQ.json();
            ...
          }
      - pattern-not: |
          const $SCHEMA = z.object(...);
          ...
          $SCHEMA.parse($DATA);
    message: "RSC 端点未验证输入 — CVE-2025-55182 相关风险"
    severity: WARNING
    languages: [typescript]
```

**22.6 参考**

- [Wiz Blog: React2Shell](https://www.wiz.io/blog/critical-vulnerability-in-react-cve-2025-55182)
- [Microsoft: Defending Against CVE-2025-55182](https://www.microsoft.com/en-us/security/blog/2025/12/15/defending-against-the-cve-2025-55182-react2shell-vulnerability-in-react-server-components/)
- [React 官方安全公告](https://react.dev/blog/2025/12/03/critical-security-vulnerability-in-react-server-components)
- [Unit 42: CVE-2025-55182 + CVE-2025-66478](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)

---

### 23. Next.js 中间件授权绕过 — CVE-2025-29927

| 属性 | 详情 |
|------|------|
| CVE | CVE-2025-29927 |
| CVSS | **Critical** |
| 类型 | 中间件授权绕过 |
| 影响 | 所有在 Next.js middleware 中执行认证/授权检查的应用 |
| 攻击方法 | 发送 `x-middleware-subrequest` 头绕过 middleware |

**23.1 漏洞原理**

Next.js 内部使用 `x-middleware-subrequest` 头在 middleware 层间传递状态。攻击者手动设置此头部可欺骗框架认为请求已被 middleware 处理过，从而跳过认证/授权检查：

```bash
# 攻击 POC
curl -H "x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware" \
     https://target.com/admin/dashboard
# 直接绕过 middleware 认证，访问受保护路由
```

**23.2 审计检测**

```bash
# 检查 middleware.ts/js 中是否仅依赖 middleware 做认证
grep -rn 'middleware' --include='*.ts' --include='*.js' . | grep -v 'node_modules'
# 如果认证逻辑仅在 middleware 中 → 高风险

# 检查是否有 API Route 层的二次认证
grep -rn 'getServerSession\|getToken\|verifyToken' app/api/ --include='*.ts'
# 如果 API Route 无独立认证 → 需修复
```

**23.3 修复方案**

```typescript
// ❌ 仅依赖 middleware 认证（可被绕过）
// middleware.ts
export function middleware(request: NextRequest) {
    const token = request.cookies.get('token');
    if (!token) return NextResponse.redirect('/login');
}

// ✅ 双重认证：middleware + API Route 层独立验证
// middleware.ts — 第一层（快速拒绝）
export function middleware(request: NextRequest) {
    const token = request.cookies.get('token');
    if (!token) return NextResponse.redirect('/login');
}

// app/api/admin/route.ts — 第二层（独立验证）
import { verifyToken } from '@/lib/auth';
export async function GET(req: NextRequest) {
    const user = await verifyToken(req);
    if (!user || user.role !== 'admin') {
        return NextResponse.json({ error: 'Forbidden' }, { status: 403 });
    }
    // 业务逻辑
}
```

**23.4 参考**

- [ProjectDiscovery: CVE-2025-29927](https://projectdiscovery.io/blog/nextjs-middleware-authorization-bypass)
- [Datadog Security Labs](https://securitylabs.datadoghq.com/articles/nextjs-middleware-auth-bypass/)
- [OffSec: CVE-2025-29927](https://www.offsec.com/blog/cve-2025-29927/)

---

### 24. npm 供应链攻击 — Shai-Hulud 蠕虫与 Axios 投毒

**24.1 Shai-Hulud 自复制蠕虫（2025.09）**

| 属性 | 详情 |
|------|------|
| 名称 | Shai-Hulud / Sha1-Hulud / Shai-Hulud 3.0 |
| 类型 | npm 包自复制蠕虫 |
| 第一波 | 2025-09-15，300+ 包被感染 |
| 第二波 | 2025-11，Zapier/ENS Domains 等知名包 |
| CISA 响应 | [2025-09-23 发布官方警报](https://www.cisa.gov/news-events/alerts/2025/09/23/widespread-supply-chain-compromise-impacting-npm-ecosystem) |
| 攻击向量 | 钓鱼 npm 维护者账号 → 注入 install-time 恶意脚本 |
| 能力 | 凭证窃取、密钥外泄、自传播 |

**攻击链：**

```
1. 钓鱼攻击 → 窃取 npm 维护者凭据
2. 维护者账号接管 → 修改 package.json 添加 install 脚本
3. npm install → 执行恶意 postinstall → 窃取 .env/SSH 密钥/AWS 凭证
4. 恶意脚本扫描 node_modules → 感染其他包 → 自传播
5. Shai-Hulud 3.0 → 增强混淆 → 检测规避
```

**24.2 Axios 供应链攻击（2026.03）**

| 属性 | 详情 |
|------|------|
| 日期 | 2026-03-31 |
| 受影响版本 | `axios@0.30.4` 和 `axios@1.14.1` |
| 攻击向量 | 维护者 npm 凭据被盗 → 注入恶意依赖 `plain-crypto-js@4.2.1` |
| Payload | 跨平台远程访问木马 (RAT) |
| CISA 警报 | [2026-04-20 发布](https://www.cisa.gov/news-events/alerts/2026/04/20/supply-chain-compromise-impacts-axios-node-package-manager) |
| 影响 | Axios 是 npm 最广泛使用的 HTTP 客户端之一 |

**24.3 npm 供应链防御体系升级**

```bash
# 1. 锁文件完整性验证（CI 环境）
npm ci --ignore-scripts  # 严格按 lockfile 安装，跳过脚本
npm audit signatures     # 验证包签名（npm 9+）

# 2. 检查是否安装了被投毒版本
npm list axios  # 检查 axios 版本
npm list plain-crypto-js  # 检查恶意依赖

# 3. 使用 npm provenance（可信发布）
# package.json 中验证:
npm view axios dist.integrity  # 检查完整性哈希
npm audit signatures            # 验证签名来源

# 4. 运行时依赖锁定 — .npmrc
# .npmrc
ignore-scripts=true
audit=true
package-lock=true
strict-ssl=true

# 5. CI 管道 — 阻止恶意 install 脚本
# GitHub Actions:
- run: npm ci --ignore-scripts
- run: npm audit --audit-level=high
- run: npx socket scan --workspace .

# 6. 维护者账号安全
# 启用 npm 2FA（强制）
# 使用 npm tokens（而非密码）
# 定期轮换 access tokens
```

**24.4 Semgrep 供应链检测规则**

```yaml
rules:
  - id: npm-install-script-risk
    patterns:
      - pattern: |
          "scripts": {
            "postinstall": $SCRIPT,
            ...
          }
    message: "postinstall 脚本可能被用于供应链攻击（Shai-Hulud 向量）"
    severity: WARNING
    languages: [json]

  - id: npm-suspicious-dependency
    patterns:
      - pattern: |
          "dependencies": {
            "plain-crypto-js": $VER,
            ...
          }
    message: "已知恶意依赖 plain-crypto-js（Axios 投毒事件）"
    severity: ERROR
    languages: [json]
```

**24.5 参考**

- [CISA: npm Supply Chain Alert](https://www.cisa.gov/news-events/alerts/2025/09/23/widespread-supply-chain-compromise-impacting-npm-ecosystem)
- [Unit 42: Shai-Hulud Worm](https://unit42.paloaltonetworks.com/npm-supply-chain-attack/)
- [Arctic Wolf: Axios Supply Chain Attack](https://arcticwolf.com/resources/blog/supply-chain-attack-impacts-widely-used-axios-npm-package/)
- [CISA: Axios Alert](https://www.cisa.gov/news-events/alerts/2026/04/20/supply-chain-compromise-impacts-axios-node-package-manager)
- [StepSecurity: Sha1-Hulud Second Coming](https://www.stepsecurity.io/blog/sha1-hulud-the-second-coming-zapier-ens-domains-and-other-prominent-npm-packages-compromised)
- [Microsoft: 33 Malicious npm Packages](https://www.microsoft.com/en-us/security/blog/2026/05/29/33-malicious-npm-packages-abuse-dependency-confusion-profile-developer-environments/)

---

### 25. Electron 沙箱逃逸 CVE — 2025-2026

| CVE | 类型 | 严重性 | 描述 |
|-----|------|--------|------|
| **CVE-2026-34765** | RCE / 沙箱逃逸 | Critical | `sandbox: false` 应用于子窗口时，可被利用逃逸沙箱 |
| **CVE-2026-34779** | 漏洞 | Pending | Electron 框架漏洞（NVD 收录） |
| CVE-2025-4609 | 沙箱逃逸 | Critical | 影响约 150 万开发者的沙箱逃逸 |

**25.1 CVE-2026-34765 深度分析**

```javascript
// ❌ 危险模式：主窗口安全但子窗口不安全
const mainWindow = new BrowserWindow({
    webPreferences: {
        sandbox: true,
        contextIsolation: true,
        nodeIntegration: false
    }
});

// CVE-2026-34765: 子窗口可能继承不安全的配置
const childWindow = new BrowserWindow({
    parent: mainWindow,
    webPreferences: {
        sandbox: false,  // ← 沙箱逃逸向量
    }
});

// ✅ 修复：所有窗口强制启用沙箱
const childWindow = new BrowserWindow({
    parent: mainWindow,
    webPreferences: {
        sandbox: true,
        contextIsolation: true,
        nodeIntegration: false,
        preload: path.join(__dirname, 'preload.js')
    }
});
```

**25.2 Electron 审计 grep 增强**

```bash
# 检测所有 BrowserWindow 实例的 webPreferences 配置
grep -rn 'new BrowserWindow' --include='*.js' --include='*.ts' . | grep -v 'node_modules'

# 检测 sandbox: false / nodeIntegration: true
grep -rn 'sandbox:\s*false\|nodeIntegration:\s*true\|contextIsolation:\s*false' \
  --include='*.js' --include='*.ts' . | grep -v 'node_modules'

# 检测 window.open（可能创建不安全子窗口）
grep -rn 'window\.open\|new BrowserWindow' --include='*.js' --include='*.ts' . | grep -v 'node_modules'

# 检测 webview 标签
grep -rn '<webview\|webview tag' --include='*.html' --include='*.js' .
```

**25.3 参考**

- [CVE-2026-34765 — SentinelOne](https://www.sentinelone.com/vulnerability-database/cve-2026-34765/)
- [CVE-2026-22709 — vm2 Sandbox Escape](https://www.endorlabs.com/learn/cve-2026-22709-critical-sandbox-escape-in-vm2-enables-arbitrary-code-execution)
- [CVE-2026-1470 — n8n RCE Sandbox Escape](https://orca.security/resources/blog/cve-2026-1470-n8n-rce-sandbox-escape/)

---

### 26. Node.js 运行时 CVE — 2025-2026 汇总

**26.1 关键 CVE 速查**

| CVE | 严重性 | 描述 | 修复版本 |
|-----|--------|------|---------|
| CVE-2025-55131 | **High** | Buffer 分配竞争条件 | 查看 Node.js 安全公告 |
| CVE-2025-59464 | Medium | TLS 客户端证书处理内存泄漏 → DoS | 20.19.4+ / 22.17.1+ / 24.4.1+ |
| CVE-2025-59465 | Medium | DoS 漏洞 | 同上 |
| CVE-2025-59466 | Medium | DoS 漏洞 | 同上 |
| CVE-2025-23167 | Medium | HTTP 解析器请求走私 | 20.19.4+ / 22.17.1+ / 24.4.1+ |
| CVE-2025-23084 | — | Windows 路径穿越（修复不完整） | 持续跟踪 |
| CVE-2025-57283 | Medium | 日志文件变量清理不当 → 命令注入 | 1.5.8+ |
| CVE-2026-21636 | Medium | Unix 域套接字绕过网络限制 | 2026-01 安全发布 |
| CVE-2026-21637 | Medium | DoS 漏洞 | 2026-01 安全发布 |
| CVE-2026-21711 | Medium | Node.js 绕过漏洞 | 2026-01 安全发布 |
| CVE-2026-21712 | Medium | `url` 模块畸形国际化域名处理 | 2026-01 安全发布 |
| CVE-2026-21713 | — | HMAC 验证非常量时间比较 | 2026-01 安全发布 |

**26.2 Node.js 安全审计脚本（增强版）**

```bash
#!/bin/bash
# nodejs-security-check.sh
echo "=== Node.js 运行时安全检查 ==="

# 1. 检查 Node.js 版本
NODE_VER=$(node -v)
echo "Node.js 版本: $NODE_VER"

# 2. 检查是否为 LTS 版本
echo "=== 检查 LTS 状态 ==="
node -e "
const ver = process.versions.node.split('.').map(Number);
const major = ver[0];
const lts = [20, 22, 24];
if (!lts.includes(major)) {
  console.warn('⚠️  非 LTS 版本，安全更新可能不及时');
} else {
  console.log('✅ LTS 版本');
}
"

# 3. 检查已知漏洞依赖
echo "=== npm audit ==="
npm audit --audit-level=moderate 2>/dev/null || echo "存在已知漏洞依赖"

# 4. 检查 package-lock.json 存在
if [ ! -f "package-lock.json" ]; then
  echo "⚠️  缺少 package-lock.json — 依赖未锁定"
fi

# 5. 检查 .npmrc 安全配置
if [ -f ".npmrc" ]; then
  echo "=== .npmrc 检查 ==="
  grep -q "ignore-scripts" .npmrc || echo "⚠️  未设置 ignore-scripts"
  grep -q "audit" .npmrc || echo "⚠️  未启用 audit"
else
  echo "⚠️  缺少 .npmrc 安全配置"
fi

# 6. 检查 install 脚本
echo "=== 检查 install 脚本 ==="
npm query "[type=script]" 2>/dev/null | head -10

echo "=== 检查完成 ==="
```

**26.3 参考**

- [Node.js 安全发布公告](https://nodejs.org/en/blog/vulnerability/)
- [OpenCVE Node.js 追踪](https://app.opencve.io/cve/?vendor=nodejs)
- [EndorLabs: Eight Vulnerabilities Fixed](https://www.endorlabs.com/learn/eight-for-one-multiple-vulnerabilities-fixed-in-the-node-js-runtime)
- [阿里云 AVD: CVE-2025-23167](https://avd.aliyun.com/detail?id=AVD-2025-23167)

---

### 27. Nuxt 框架安全漏洞 — 2025-2026

| CVE | 类型 | CVSS | 修复版本 |
|-----|------|------|---------|
| CVE-2025-52662 | DevTools XSS → RCE | Critical | DevTools 2.6.4 |
| CVE-2025-24360 | 服务端数据泄露 | — | Nuxt 3.15.3 |
| CVE-2025-27415 | CDN 缓存投毒 | 7.5 | Nuxt 3.16.0 |
| CVE-2025-59414 | 客户端路径穿越 | — | — |
| CVE-2025-8082 | 严重漏洞 | Critical | — |
| CVE-2026-47200 | 路由中间件绕过 | — | Nuxt 最新版 |

**27.1 CVE-2025-27415 CDN 缓存投毒**

攻击者构造特殊 HTTP 请求，使 CDN 缓存错误内容并分发给其他用户：

```bash
# 攻击示例：通过特殊头注入触发缓存投毒
curl -H "X-Forwarded-Host: evil.com" \
     -H "Accept-Language: en<script>alert(1)</script>" \
     https://nuxt-app.com/page

# 如果 CDN 缓存了包含恶意脚本的响应 → 所有用户受影响
```

**27.2 Nuxt 审计 grep**

```bash
# 检查 Nuxt 版本
cat package.json | grep '"nuxt"'

# 检查 DevTools 是否在生产环境启用
grep -rn 'devTools\|devtools' nuxt.config.ts . | grep -v 'node_modules'

# 检查 SSR 安全配置
grep -rn 'nitro\|render\|ssr' nuxt.config.ts .

# 检查 CDN 头依赖
grep -rn 'cdn\|cache\|X-Forwarded' server/ --include='*.ts'
```

**27.3 参考**

- [OpenCVE: Nuxt 漏洞列表](https://app.opencve.io/cve/?product=nuxt&vendor=nuxt)
- [zhero: Nuxt Cache Poisoning](https://zhero-web-sec.github.io/research-and-things/nuxt-show-me-your-payload)
- [HeroDevs: CVE-2025-8082](https://www.herodevs.com/vulnerability-directory/cve-2025-8082)

---

### 28. 2025-2026 综合 CVE 速查（JavaScript/TypeScript 生态）

| CVE | 影响组件 | 类型 | CVSS | 修复版本 |
|-----|---------|------|------|---------|
| CVE-2025-55182 | React 19.x RSC | Pre-auth RCE | **10.0** | React 19.2.1+ |
| CVE-2025-29927 | Next.js Middleware | 授权绕过 | **Critical** | Next.js 15.2.3+ |
| CVE-2025-66478 | Next.js RSC 协议 | Critical | **Critical** | 参阅 Next.js 公告 |
| CVE-2026-34765 | Electron | RCE/沙箱逃逸 | **Critical** | Electron 最新版 |
| CVE-2026-22709 | vm2 (Node.js) | 沙箱逃逸/RCE | **Critical** | vm2 已弃用，迁移至 isolated-vm |
| CVE-2026-1470 | n8n | RCE/沙箱逃逸 | **Critical** | n8n 最新版 |
| CVE-2025-52662 | Nuxt DevTools | XSS → RCE | **Critical** | DevTools 2.6.4 |
| CVE-2025-27415 | Nuxt | CDN 缓存投毒 | 7.5 | Nuxt 3.16.0 |
| CVE-2025-24360 | Nuxt | 数据泄露 | — | Nuxt 3.15.3 |
| CVE-2025-55131 | Node.js | Buffer 竞争条件 | **High** | 安全发布 |
| CVE-2025-59464 | Node.js | TLS 内存泄漏 DoS | Medium | 20.19.4+/22.17.1+/24.4.1+ |
| CVE-2025-23167 | Node.js | HTTP 请求走私 | Medium | 20.19.4+/22.17.1+/24.4.1+ |
| CVE-2025-57353 | messageformat | 原型污染 | 7.5 | 3.0.2 |
| CVE-2025-13223 | Chrome V8 | 类型混淆 | High | Chrome 最新版 |
| CVE-2026-21636 | Node.js | Unix 域套接字绕过 | Medium | 2026-01 发布 |

---

### 29. 中文社区精华参考

| 来源 | 主题 | 链接 |
|------|------|------|
| FreeBuf | Chrome V8 CVE-2025-13223 类型混淆 | https://m.freebuf.com/articles/459112.html |
| 腾讯云 | 2025年最危险的JavaScript漏洞 | https://cloud.tencent.com/developer/article/2452482 |
| 阿里云 AVD | Node.js CVE-2025-23167 | https://avd.aliyun.com/detail?id=AVD-2025-23167 |
| 阿里云 AVD | Node.js CVE-2025-57283 | https://avd.aliyun.com/detail?id=AVD-2025-57283 |
| 阿里云 | 2025年12月安全态势报告 | https://help.aliyun.com/zh/acsg/security-posture-report-december-2025 |
| 安全客 | JavaScript 原型链污染深入 | https://www.anquanke.com/post/id/242645 |
| 离别歌 | JS Prototype 污染攻击 | https://leavesongs.com/PENETRATION/javascript-prototype-pollution-attack.html |
| 火山引擎 | Node.js 漏洞技巧 | https://developer.volcengine.com/articles/7381504550169444378 |
| 腾讯云 | CTF中的Node.js原型链污染 | https://cloud.tencent.com/developer/article/2288287 |

---

### 30. 防御升级路线图（P0-P3 分级）

| 优先级 | 措施 | 具体操作 | 截止 |
|--------|------|---------|------|
| **P0** | React RSC 升级 | `npm install react@19.2.1+ react-dom@19.2.1+` | 即时 |
| **P0** | Next.js 中间件加固 | 升级 Next.js + API Route 层独立认证 | 即时 |
| **P0** | Electron 沙箱检查 | 所有窗口 `sandbox: true` | 即时 |
| **P0** | npm 投毒排查 | 检查 axios/plain-crypto-js 版本 | 即时 |
| **P1** | Node.js LTS 升级 | 升级到最新 LTS（含安全修复） | 1周内 |
| **P1** | Nuxt 版本升级 | 升级到 Nuxt 4.4.7+ | 1周内 |
| **P1** | install 脚本禁用 | `.npmrc` 添加 `ignore-scripts=true` | 1周内 |
| **P1** | 依赖签名验证 | CI 中添加 `npm audit signatures` | 2周内 |
| **P2** | SAST 规则更新 | Semgrep 添加 RSC/Electron 规则 | 1月内 |
| **P2** | vm2 迁移 | 移除 vm2，使用 isolated-vm | 1月内 |
| **P2** | npm 2FA 强制 | 所有 npm 维护者启用 2FA | 1月内 |
| **P3** | 运行时依赖监控 | Socket.dev 持续扫描 | 持续 |
| **P3** | 安全扫描自动化 | GitHub Actions 完整安全流水线 | 持续 |

---

### 参考资源

- [Node.js 官方安全最佳实践](https://nodejs.cn/en/learn/getting-started/security-best-practices)
- [OWASP Node.js Security Checklist](https://cheatsheetseries.owasp.org/cheatsheets/Nodejs_security_cheat_sheet.html)
- [Socket.dev 供应链安全平台](https://socket.dev/)
- [Semgrep JavaScript 规则集](https://semgrep.dev/p/javascript)
- [Electron 安全检查清单](https://www.electronjs.org/docs/latest/tutorial/security)
- [Node.js 安全发布公告](https://nodejs.org/en/blog/vulnerability/)
- [OpenCVE Node.js 追踪](https://app.opencve.io/cve/?vendor=nodejs)
- [Wiz: React2Shell (CVE-2025-55182)](https://www.wiz.io/blog/critical-vulnerability-in-react-cve-2025-55182)
- [CISA: npm Supply Chain Alert](https://www.cisa.gov/news-events/alerts/2025/09/23/widespread-supply-chain-compromise-impacting-npm-ecosystem)
- [CISA: Axios Alert](https://www.cisa.gov/news-events/alerts/2026/04/20/supply-chain-compromise-impacts-axios-node-package-manager)
