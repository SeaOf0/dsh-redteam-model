# 浏览器扩展逆向分析

> 定位：从「扩展分析要点」空壳扩为**可执行逐步路线**——manifest 权限面 → background/service worker →
> content script 注入 → 凭据/流量逻辑恢复 → 混淆扩展去混淆。
> 与 `browser-extension-reverse/SKILL.md`（工作流）互补，本篇给逐步判据。

---

## 1. 解包与 manifest 分析

```bash
# CRX 解包（检测 unzip 后使用；.crx 本质是带头的 zip）
unzip extension.crx -d ext/          # 或 7z x / 从 profile 直接取扩展目录
# Firefox .xpi 同 zip 结构
cat ext/manifest.json | jq .
```

manifest 关键字段与风险信号：

| 字段 | 风险信号 | 逆向含义 |
|---|---|---|
| `permissions` | `tabs`/`cookies`/`debugger`/`nativeMessaging`/`webRequestBlocking` | 能力面：能碰什么 |
| `host_permissions` / `matches` | `<all_urls>` / `*://*/*` | 作用域：能读写哪些站 |
| `background` | MV2 `scripts`（页面）/ MV3 `service_worker` | 常驻逻辑入口 |
| `content_scripts` | 注入 `matches` + `js` 列表 | 页面注入点 |
| `externally_connectable` | 网页可驱动扩展（`matches`） | 网页→扩展攻击面 |
| `web_accessible_resources` | 暴露给网页的资源 | 消息传递面 |

判据：列出「权限面 + 作用域 + 入口脚本 + 注入点」四件套，即完成分诊。

---

## 2. background / service_worker 逻辑恢复

```text
1. 定位入口：MV2 读 background.scripts；MV3 读 background.service_worker。
2. 读入口脚本，找：
   - chrome.runtime.onMessage / onInstalled（消息处理）
   - chrome.webRequest.onBeforeRequest（流量改写）
   - chrome.cookies / chrome.tabs（凭据/页面操作）
   - chrome.storage / IndexedDB（数据持久化）
3. 追踪消息处理链：runtime.sendMessage 与 onMessage 配对，还原「谁触发什么」。
```

判据：能还原「入口 → 消息处理 → 网络/存储/凭据操作」的调用链。

---

## 3. content script 注入点与数据流

```text
1. 读 content_scripts 的 matches + js，确认注入哪些站、跑什么。
2. 追 content script 与 background 的消息传递（runtime.sendMessage）。
3. 关注：页面 DOM 读取（表单/密码）、页面 JS 改写、页面数据外发。
```

判据：还原「页面数据 → content script → background → 外部服务器」的完整数据流。

---

## 4. 凭据 / 流量逻辑恢复

```text
1. 凭据：搜 cookies/token/password 关键字、chrome.cookies.get、IndexedDB 读取。
2. 流量：webRequest 拦截/改写、fetch/XHR 到外域、WebSocket。
3. 关联：哪些凭据被读、被发往哪个外域（IOC）。
```

判据：定位「凭据读取点 + 外发目的地」，产出数据泄露 IOC（外域/路径/字段）。

---

## 5. 混淆扩展去混淆

恶意扩展常对 JS 混淆（webpack 打包 + 字符串数组 + eval）：

```text
1. 识别：长变量名/十六进制字符串数组/`_0x` 前缀/eval/Function 构造。
2. 去混淆（与 js-reverse 工具链衔接）：
   - prettier/beautifier 格式化。
   - 还原字符串数组（定位解混淆函数 → 常量替换）。
   - AST 去混淆（js-reverse 的 ast-deobfuscation）。
3. 动态：DevTools 附加 service_worker，断点 + 运行时观察。
```

判据：去混淆后能恢复可读函数名/字符串，定位业务逻辑。

---

## 6. 动态验证

```text
1. chrome://extensions 开发者模式加载解压目录。
2. chrome://extensions 查看错误；DevTools 附加 service_worker（MV3）。
3. 观察网络请求（background 的 fetch/XHR）与消息传递。
4. 必要时浏览器 CDP / js-reverse 工具链深度 hook。
```

判据：动态观察与静态还原互证，产出「行为 + 证据」双确认。

---

## 延伸

- 深度 JS 去混淆 / 补环境：`../js-reverse/`（ast-deobfuscation、env-patching、instrumentation）。
- 恶意扩展 IOC 输出：`detection/malware-detection-yara.md`。
- 供应链扩展投毒调查：跨模式交 supply-chain（生态分工）。
