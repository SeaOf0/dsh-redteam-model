# WebView Hybrid Playbook

目标：处理 Android WebView、JS bridge 和 hybrid 容器中的 JS-Native 边界。

## 关键入口

- `WebView.loadUrl`
- `WebView.evaluateJavascript`
- `addJavascriptInterface`
- `@JavascriptInterface`
- 自定义 `WebViewClient` / `WebChromeClient`

## 必须回答

- 页面从哪里加载
- JS 如何进入 Native
- Native 如何回调 JS
- 混合层是否承载登录、签名、支付或风控逻辑

## 作业顺序

### 1. 定位 WebView 使用与页面来源

- 搜索 `WebView`、`X5WebView`、`WebViewClient` 实例化点
- 区分页面来源：`file:///android_asset/` 本地资源 vs `https://` 远程 URL
- 检查是否使用第三方内核（腾讯 X5、UC SDK）
- 记录哪些 Activity / Fragment 持有 WebView 实例

### 2. 映射 JS -> Native 桥接

按优先级排查三种桥接模式：

1. **addJavascriptInterface**：搜索所有调用点，记录 interface name 和注入对象类；遍历该类中标注 `@JavascriptInterface` 的方法，记录方法名、参数、返回值
2. **shouldOverrideUrlLoading**：检查 `WebViewClient` 实现，拦截的 URL scheme（`js://`、`native://`、自定义 scheme）即为桥接通道；解析 URL path 和 query 参数格式
3. **prompt / console.log 桥接**：检查 `WebChromeClient.onJsPrompt`、`onConsoleMessage`，部分框架用 `window.prompt()` 或 `console.log` 传递结构化数据

### 3. 映射 Native -> JS 回调

- `evaluateJavascript(script, callback)`：script 参数即 Native 注入的 JS 代码
- `loadUrl("javascript:...")`：旧式回调，功能相同
- `WebView.post` + `evaluateJavascript` 组合：跨线程回调
- 记录回调时机：页面加载完成 (`onPageFinished`)、按钮点击、网络请求返回后

### 4. 识别混合框架

通过以下特征判断框架类型：

- **Cordova / Capacitor / Ionic**：`config.xml`、`cordova.js`、`capacitor.config.json`；桥接对象名通常为 `cordova.exec()` 或 `Capacitor.Plugins`
- **React Native**：`ReactRootView`、`ReactInstanceManager`；桥接走 `NativeModules` / `TurboModules`
- **Flutter WebView**：`FlutterWebView`、`webview_flutter` 插件
- **自定义桥接**：无框架特征，直接用 `addJavascriptInterface` + `evaluateJavascript`，需逐方法逆向

### 5. 评估桥接安全

- 参数是否经过校验（类型检查、长度限制、白名单）
- 远程页面时是否校验 origin / domain
- `addJavascriptInterface` 在 API < 17 时存在反射漏洞（可执行任意 Java 方法）
- 本地 HTML 是否允许被外部 Intent 加载（`file:///` 跨目录风险）

## Frida Hook 锚点

### addJavascriptInterface 捕获

```javascript
Java.perform(function () {
  var WebView = Java.use('android.webkit.WebView');
  WebView.addJavascriptInterface.overload('java.lang.Object', 'java.lang.String')
    .implementation = function (obj, name) {
      console.log('[JSI] interface=' + name + ' class=' + obj.getClass().getName());
      // 遍历 @JavascriptInterface 方法
      var methods = obj.getClass().getMethods();
      for (var i = 0; i < methods.length; i++) {
        var ann = methods[i].getAnnotation(Java.use('android.webkit.JavascriptInterface'));
        if (ann) console.log('[JSI]   method=' + methods[i].getName() + ' params=' + methods[i].getParameterTypes().length);
      }
      return this.addJavascriptInterface(obj, name);
    };
});
```

### evaluateJavascript 捕获

```javascript
Java.perform(function () {
  var WebView = Java.use('android.webkit.WebView');
  WebView.evaluateJavascript.overload("java.lang.String", "android.webkit.ValueCallback").implementation = function (script, cb) {
    console.log('[EvalJS] ' + script.substring(0, 200));
    return this.evaluateJavascript(script, cb);
  };
});
```

### @JavascriptInterface 方法调用捕获

```javascript
Java.perform(function () {
  // 替换为目标 interface 类名
  var Bridge = Java.use('com.example.app.JsBridge');
  Bridge.getUserToken.implementation = function () {
    var ret = this.getUserToken();
    console.log('[JSBridge] getUserToken => ' + ret);
    return ret;
  };
});
```

## 分析模式

### WebView 调试开关

- 搜索 `setWebContentsDebuggingEnabled`，若为 `true` 可直接 Chrome DevTools 远程调试
- 若为 `false`，Frida hook 强制开启：
  ```javascript
  Java.use('android.webkit.WebView')
    .setWebContentsDebuggingEnabled(true);
  ```

### Deep Link / Intent 与 WebView 交互

- 搜索 `Intent.ACTION_VIEW`、`<intent-filter>` 中的 scheme / host
- 检查外部 Intent 是否能向 WebView 注入 URL（`loadUrl(getIntent().getData().toString())`）
- 检查 `WebViewClient.shouldOverrideUrlLoading` 是否对 URL 做白名单校验

### JS-Native 数据序列化

- JSON 传递：最常见，检查 `JSONObject` / `Gson` 解析点
- 自定义协议：URL scheme 编码（`native://method?param1=val1&param2=val2`）
- Base64 编码：检查是否有中间编解码层

### 本地 HTML/JS 资产提取与分析

- APK 内 `assets/` 目录提取全部 `.html` / `.js` 文件
- 搜索 `window.Android`、`window.${interfaceName}`、`postMessage` 定位 JS 侧桥接调用
- 检查 JS 中是否硬编码密钥、API 端点或加密参数

## 最小交付

- `run/webview-bridge-notes.md`
- 报告中的页面入口、bridge 与边界说明
- JS-Native 调用映射表（方法名、参数、方向、业务语义）
