# Web 套壳分诊（Electron · CEF · WebView2 · Tauri · Wails）

适用于以下迹象：

- 安装目录携带大量 `js/html/css/json/map`、`asar/pak`、`locales`、`dist/assets`
- 宿主 EXE 只是壳，业务逻辑主要在前端资源、bridge API、配置或网络层
- 目标疑似 `Electron / CEF / WebView2 / NW.js / Tauri / Wails / Neutralino / Qt WebEngine / Flutter Web 资产`

## 分诊新增线路

优先新增一条 `Web 套壳 / WebView 技术路线指纹` 线路，目标不是马上理解所有 JS，而是先回答：

1. 它是不是 Web 套壳
2. 它用的是什么 wrapper/runtime
3. 前端框架 / bundler 是什么
4. 真正的入口资源和 bridge 在哪里
5. 接下来更应该进 IDA、解包资源、抓网络、还是找前端入口

## 不只看文件扫描

文件扫描只是最低成本入口，还应同时结合：

1. **目录结构**
   - `resources/app.asar` / `app.asar.unpacked` -> Electron
   - `libcef.dll` / `cef.pak` / `devtools_resources.pak` -> CEF
   - `WebView2Loader.dll` / `Microsoft.Web.WebView2.Core.dll` -> WebView2
   - `Qt5WebEngineCore.dll` / `Qt6WebEngineCore.dll` -> Qt WebEngine
   - `wails.json` / `wailsjs` -> Wails
   - `tauri.conf.json` -> Tauri
   - `neutralino.config.json` -> Neutralino
   - `flutter_assets` / `main.dart.js` -> Flutter Web 资产

2. **PE 依赖 / 字符串**
   - `CreateCoreWebView2EnvironmentWithOptions`
   - `cef_initialize`
   - `app.asar`
   - `libcef.dll`
   - `WebView2Loader.dll`
   - `QtWebEngine`

3. **前端 bundle 指纹**
   - React: `react-dom`, `createRoot(`
   - Vue: `createApp(`, `vue-router`
   - Angular: `zone.js`, `@angular/core`
   - Svelte: `svelte/internal`
   - Next: `__NEXT_DATA__`, `_next/static`
   - Nuxt: `__NUXT__`, `_nuxt/`
   - Webpack: `__webpack_require__`, `webpackChunk`
   - Vite: `/@vite/client`, `import.meta.env`
   - Parcel: `parcelRequire`
   - RequireJS: `define.amd`

4. **桥接接口**
   - Electron: `contextBridge`, `ipcRenderer`, preload
   - Tauri: `__TAURI__`, `@tauri-apps/api`, invoke
   - Wails: `window.go.*`
   - Qt WebEngine: `QWebChannel`
   - WebView2: host object / native message bridge / embedded resource loader

5. **运行时行为**
   - 窗口类名、子进程、命令行参数、模块加载
   - 本地 HTTP/WS 调试端口
   - 前端资源懒加载、chunk 请求、配置下载

## 推荐最小动作

如果安装目录可见，先按「目录结构 / PE 依赖与字符串 / 前端 bundle 指纹」三路做一次技术指纹判定，然后把结论写到：

- `artifacts/<样本哈希>/web-shell-tech.md`
- `artifacts/<样本哈希>/web-shell-notes.md`

至少记录：

- wrapper/runtime 候选
- 前端框架 / bundler 候选
- 主入口资源
- bridge / preload / host API 线索
- 下一步应进入的线路

## 技术路线判定后的下一跳

- **Electron**
  - 先找 `app.asar` / `package.json` / `main.js` / `preload.js`
  - 再找 `ipcMain/ipcRenderer/contextBridge`

- **CEF / WebView2 / Qt WebEngine**
  - 先找 HTML/JS 资源落点
  - 再找 native -> web 的 bridge 和资源装载函数

- **Tauri / Wails / Neutralino**
  - 先找前端 dist 与 bridge API
  - 再找 Rust/Go/native handler

- **纯前端 bundle 明显**
  - 先做框架与 bundler 识别
  - 再反推 API client、路由、配置和加密点

## 什么时候值得进 IDA

只有在以下场景，IDA 才是主线：

- 需要还原 native bridge、资源解密、通信封装、宿主装载逻辑
- 需要分析自定义协议、签名、配置解密或反分析逻辑在 native 侧
- 文件/前端扫描已无法继续缩窄

若尚未完成 wrapper/runtime 指纹识别，不要一上来就把大量时间投入到无上下文的宿主 EXE 反编译。
