# API 提取 Grep 模式手册

本手册提供可直接执行的 Grep 搜索模式，用于从反编译源码中提取 HTTP API 调用。

## 快速启动

使用 `find-api-calls.sh` / `.ps1` 自动执行所有搜索：

```bash
bash scripts/find-api-calls.sh <source-dir> --all
```

## Retrofit 注解

| 目标 | Grep 模式 |
|---|---|
| HTTP 方法 | `@(GET\|POST\|PUT\|DELETE\|PATCH\|HEAD\|HTTP)\(` |
| 路径参数 | `@Path\(` |
| 查询参数 | `@Query\(` |
| 请求体 | `@Body\(` |
| 表单字段 | `@Field\(` |
| Header | `@Header\(` |
| 多部分 | `@Part\(` |
| URL 注入 | `@Url` |
| Base URL | `baseUrl\s*\(` |
| 构建 | `Retrofit\.Builder` |

### 输出模板

对每个 Retrofit 端点，应记录：

```markdown
### Endpoint: [METHOD] [path]
- **接口**: `com.example.ApiService.methodName()`
- **Base URL**: `https://api.example.com/`
- **完整 URL**: `https://api.example.com/path`
- **参数**: query=xxx, body=yyy
- **Header**: Authorization: Bearer xxx
- **返回类型**: `Response<Model>`
- **调用链**: Activity → ViewModel → Repository → ApiService
```

## OkHttp

| 目标 | Grep 模式 |
|---|---|
| 请求构建 | `Request\.Builder` |
| URL 构建 | `HttpUrl\.Builder` |
| 发起调用 | `newCall\(` |
| 拦截器 | `addInterceptor\|addNetworkInterceptor` |
| WebSocket | `WebSocket` |

## Volley

| 目标 | Grep 模式 |
|---|---|
| 字符串请求 | `StringRequest` |
| JSON 请求 | `JsonObjectRequest\|JsonArrayRequest` |
| 图片请求 | `ImageRequest` |
| 请求队列 | `RequestQueue\|Volley\.newRequestQueue` |

## HttpURLConnection (旧式)

| 目标 | Grep 模式 |
|---|---|
| 打开连接 | `HttpURLConnection\|openConnection` |
| 设置方法 | `setRequestMethod` |
| 写入 body | `getOutputStream` |

## WebView

| 目标 | Grep 模式 |
|---|---|
| 加载 URL | `loadUrl\(` |
| 执行 JS | `evaluateJavascript\(` |
| JS 桥接 | `@JavascriptInterface\|addJavascriptInterface` |
| 拦截请求 | `shouldInterceptRequest\|shouldOverrideUrlLoading` |

## 硬编码 URL 与密钥

| 目标 | Grep 模式 |
|---|---|
| HTTP URL | `https?://[^\s"<>]+` |
| Base URL 常量 | `(BASE_URL\|API_URL\|SERVER_URL\|HOST\|ENDPOINT)\s*=` |
| API Key | `(API_KEY\|api_key\|apikey\|APP_KEY\|APP_SECRET)\s*=` |
| Token | `(ACCESS_TOKEN\|REFRESH_TOKEN\|AUTH_TOKEN)\s*=` |
| 密钥硬编码 | `(SECRET\|PRIVATE_KEY\|ENCRYPTION_KEY)\s*=` |

## 认证模式

| 目标 | Grep 模式 |
|---|---|
| Bearer Token | `[Aa]uthorization.*[Bb]earer` |
| Basic Auth | `[Bb]asic.*auth\|Base64.*encode` |
| 签名参数 | `(sign\|signature\|sig)\s*=` |
| OAuth | `OAuth\|oauth_token\|access_token` |
| HMAC | `HmacSHA\|HMAC\|Mac\.getInstance` |
| 时间戳签名 | `timestamp.*sign\|nonce\|appKey` |

## 自动化脚本参考

脚本支持按类别过滤：

```bash
bash scripts/find-api-calls.sh <dir> --retrofit   # 仅 Retrofit
bash scripts/find-api-calls.sh <dir> --okhttp      # 仅 OkHttp
bash scripts/find-api-calls.sh <dir> --urls        # 仅硬编码 URL
bash scripts/find-api-calls.sh <dir> --auth        # 仅认证模式
```
