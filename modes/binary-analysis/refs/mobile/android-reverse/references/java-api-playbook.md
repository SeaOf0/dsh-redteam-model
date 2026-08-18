# Java API Playbook

本专项主要吸收开源安卓 skill 中关于 API 提取的高质量内容。

## 优先搜索

- Retrofit 注解：`@GET @POST @PUT @DELETE @PATCH`
- 参数注解：`@Body @Query @Path @Header`
- OkHttp：`Request.Builder`、`Interceptor`
- Volley：`StringRequest`、`JsonObjectRequest`
- `baseUrl`
- 硬编码 `http://` / `https://`

## 提取目标

- 方法
- 路径
- 基础 URL
- 认证头
- 请求体类型
- 响应类型
- 调用来源

## 作业顺序

### Step 1：识别 HTTP 客户端库

从 imports 和类引用判断网络栈：

| 特征 | 判断 |
|---|---|
| `Retrofit.Builder` / `@GET` 等 | Retrofit + OkHttp（主流） |
| `OkHttpClient` / `Request.Builder` 无 Retrofit | 纯 OkHttp |
| `StringRequest` / `JsonObjectRequest` | Volley |
| `HttpURLConnection` / `openConnection` | 原生旧式 |
| `org.chromium.net.CronetEngine` | Cronet → 见 `native-network-playbook.md` |
| `GraphQL` / `ApolloClient` | GraphQL |
| `grpc` / `ManagedChannel` | gRPC / protobuf |

混合栈常见：主业务用 Retrofit，推送/长连接走 OkHttp WebSocket 或原生。

### Step 2：提取 Base URL 与端点定义

优先级从高到低：

1. `Retrofit.Builder().baseUrl()` — 最直接
2. `BuildConfig` 字段：`BASE_URL`、`API_URL`、`SERVER_URL`、`HOST`
3. 远程配置：`FirebaseRemoteConfig`、自建 config 接口拉取
4. 硬编码字符串常量
5. Native 层返回（JNI 调用获取 URL）

对 Retrofit 端点，每个接口方法提取：HTTP 方法、路径、参数注解、返回类型。
对纯 OkHttp，从 `Request.Builder` 调用链拼接完整 URL。

### Step 3：追踪认证注入点

认证注入位置常见三种：

- **Interceptor 注入**：`addInterceptor` / `addNetworkInterceptor` 内拼接 `Authorization`、`X-Sign` 等 header
- **手动 header 注入**：`@Header` 注解或 `Request.Builder.header()` 逐请求设置
- **OkHttp Authenticator**：`Authenticator.authenticate()` 处理 token 刷新

追踪路径：
1. 找到 `OkHttpClient.Builder` 构建处，列出所有 interceptor
2. 逐个 interceptor 检查 `chain.request()` → `request.newBuilder()` 之间的 header 修改
3. 确认 token 来源：`SharedPreferences`、内存缓存、登录接口返回

### Step 4：映射请求/响应序列化

| 序列化框架 | 识别信号 |
|---|---|
| Gson | `GsonConverterFactory`、`@SerializedName` |
| Moshi | `MoshiConverterFactory` |
| Protobuf | `ProtoConverterFactory`、`.proto` 文件、`protobuf` content-type |
| Jackson | `JacksonConverterFactory` |
| 自定义 | `Converter.Factory` 子类 |

注意检查请求体是否在序列化前有额外加密/签名操作。

### Step 5：还原 API 认证流程

从登录接口开始，追踪完整 token 生命周期：

1. 登录请求 → 响应中提取 access_token / refresh_token
2. token 存储位置（SharedPreferences / 内存 / KeyStore）
3. token 注入方式（interceptor / header）
4. token 刷新机制（Authenticator / 定时器 / 401 重试）
5. 签名计算逻辑（如果有 `sign` / `signature` 参数）

## Frida Hook 锚点

### OkHttp Interceptor Chain（捕获完整请求/响应）

```javascript
Java.perform(function () {
  var OkHttpClient = Java.use("okhttp3.OkHttpClient");
  var Interceptor = Java.use("okhttp3.Interceptor");
  var Buffer = Java.use("okio.Buffer");

  // Hook RealCall.getResponseWithInterceptorChain 拿完整链路
  var RealCall = Java.use("okhttp3.internal.connection.RealCall");
  // OkHttp 3.x 路径为 okhttp3.internal.http.RealCall
  RealCall.getResponseWithInterceptorChain.implementation = function () {
    var req = this.request();
    var url = req.url().toString();
    var method = req.method();
    var headers = req.headers().toString();

    var body = "";
    if (req.body() !== null) {
      var buf = Buffer.$new();
      req.body().writeTo(buf);
      body = buf.readUtf8();
    }

    console.log("[OkHttp] " + method + " " + url);
    console.log("  Headers: " + headers);
    console.log("  Body: " + body);

    var resp = this.getResponseWithInterceptorChain();
    console.log("  Response: " + resp.code());
    return resp;
  };
});
```

### Retrofit Service Method（捕获注解 + 参数）

```javascript
Java.perform(function () {
  var ServiceMethod = Java.use("retrofit2.ServiceMethod");
  // 注意：ServiceMethod 属于 retrofit2 包，不是 okhttp3
  ServiceMethod.invoke.implementation = function (args) {
    console.log("[Retrofit] " + this);
    if (args) {
      for (var i = 0; i < args.length; i++) {
        console.log("  arg[" + i + "]: " + args[i]);
      }
    }
    return this.invoke(args);
  };
});
```

### SecretKeySpec（捕获对称密钥）

```javascript
Java.perform(function () {
  var SecretKeySpec = Java.use("javax.crypto.spec.SecretKeySpec");
  SecretKeySpec.$init.overload("[B", "java.lang.String").implementation = function (keyBytes, algorithm) {
    var key = "";
    for (var i = 0; i < keyBytes.length; i++) {
      key += ("0" + (keyBytes[i] & 0xff).toString(16)).slice(-2);
    }
    console.log("[SecretKeySpec] algorithm=" + algorithm + " key=" + key);
    console.log("  " + Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
    return this.$init(keyBytes, algorithm);
  };
});
```

## 常见模式

### 动态 Base URL

- `BuildConfig.BASE_URL` — 最常见，检查 `build.gradle` 的 `buildConfigField`
- 远程配置下发 — 搜索 `FirebaseRemoteConfig`、`remoteConfig`、自建 config 接口
- 环境切换 — 搜索 `isDebug`、`BuildConfig.DEBUG`、`ENV_TYPE` 条件分支
- WebView 内嵌 — URL 在 JS 侧拼接，需检查 `shouldInterceptRequest`

### 请求签名模式

**Interceptor 签名**（主流）：
- 自定义 `Interceptor` 内读请求体，计算 HMAC/MD5，注入 `sign` header
- 特征：类实现 `Interceptor`，`intercept()` 方法内有 `MessageDigest` / `Mac` / `SecretKeySpec` 调用

**手动 header 注入**：
- 业务代码中直接 `request.newBuilder().header("X-Sign", calcSign(params))`
- 特征：搜索 `sign`、`signature`、`X-Sign` 字符串赋值点

**Native 签名**：
- Java 调 JNI 计算签名 → 见 `jni-bridge-playbook.md`
- 特征：签名计算前有 `nativeMethod(params)` 调用，返回值直接当 sign 用

### protobuf / gRPC 检测信号

- `google.protobuf`、`LiteByteString`、`parseFrom`、`toByteArray`
- `io.grpc`、`ManagedChannel`、`MethodDescriptor`
- content-type 为 `application/x-protobuf` 或 `application/grpc`
- 请求体非 JSON/XML，呈二进制 pattern

### GraphQL 检测信号

- `ApolloClient`、`ApolloGraphQL`
- 请求体含 `"query":"mutation { ... }"` 或 `"query":"query { ... }"`
- 单一 endpoint（通常 `/graphql`），通过请求体区分操作
- `operationName` 字段

## 最小交付

- `run/api-map.md`
- 在报告中写出 `Base URL / Auth / Endpoint / Caller`
- 每个端点至少记录：HTTP 方法、完整 URL、请求参数、认证方式
- 如有签名逻辑，附签名算法摘要和关键函数定位
