# 调用链追踪技术手册

从入口点到 API 层的系统化执行流追踪方法。

## 1. 从 AndroidManifest.xml 开始

读取 `AndroidManifest.xml` 确定所有入口组件：

```bash
# 启动 Activity
grep -n 'android.intent.category.LAUNCHER' -A5 -B5 AndroidManifest.xml
# exported 组件
grep -n 'exported="true"' AndroidManifest.xml
# 自定义权限
grep -n 'permission' AndroidManifest.xml
# Application 类
grep -n 'android:name=' AndroidManifest.xml | head -5
```

记录：package name、launch activity、Application 类、所有 exported 组件。

## 2. Android 生命周期追踪

标准路径：

```
Application.onCreate()
  → 初始化 SDK、DI 框架、全局配置

Activity.onCreate()
  → setContentView() → 绑定 View
  → ViewModel / Presenter 初始化

ViewModel
  → Repository 调用
  → LiveData / StateFlow 状态更新

Repository
  → API Service 调用 (Retrofit/OkHttp)
  → 本地数据操作 (Room/SharedPreferences)
```

## 3. 点击事件追踪

从 UI 交互入口定位处理逻辑：

```bash
# XML onClick
grep -rn 'android:onClick=' res/layout/
# 代码 setOnClickListener
grep -rn 'setOnClickListener\|setOnItemClickListener' sources/
# Data Binding
grep -rn '@{.*\.' res/layout/ | grep -i click
```

## 4. 依赖注入追踪 (Dagger/Hilt)

当项目使用 DI 框架时，需要追踪注入链：

```bash
# Hilt @Inject
grep -rn '@Inject' sources/ | head -30
# Module 提供
grep -rn '@Provides\|@Binds' sources/
# @Singleton 作用域
grep -rn '@Singleton\|@ActivityScoped' sources/
# Component 接口
grep -rn '@Component\|@Module' sources/
```

注入链追踪步骤：
1. 找到 `@Inject` 构造函数或字段
2. 定位提供该类型的 `@Module` 中的 `@Provides` 方法
3. 沿着依赖图向上追踪到 Application Component

## 5. 从 Application 类追踪初始化

```bash
# 定位 Application 类
grep -rn 'extends Application\|extends MultiDexApplication' sources/
# 追踪 onCreate
grep -rn 'onCreate\|initSDK\|init.*SDK\|setup' <ApplicationClass>.java
```

常见初始化模式：
- 第三方 SDK：支付、推送、统计、热修复
- 网络框架：OkHttpClient 配置、证书锁定
- 安全配置：ProGuard、签名校验、反调试

## 6. 配置与常量定位

```bash
# BuildConfig
grep -rn 'BuildConfig\.' sources/ | head -20
# 资源常量
grep -rn 'R\.string\.\|R\.array\.' sources/ | head -20
# assets 配置
find assets/ -type f | head -30
```

## 7. 混淆代码导航

混淆后需要区分可读和不可读的标识符：

**通常保留的名称**（不混淆）：
- Android 框架类和接口
- 第三方库类名（通常由 ProGuard keep 规则保留）
- 资源 ID (R.xx)
- native 方法声明
- 枚举值

**通常被混淆的名称**：
- 自定义类名 → `a.b.c`
- 方法名 → `a()`, `b()`
- 字段名 → `a`, `b`
- 局部变量 → 部分混淆器保留

追踪策略：
1. 从 Android 框架回调开始（不混淆）
2. 沿着调用链深入，记录混淆映射
3. 利用字符串常量锚定功能区域
4. 利用 native 方法声明锚定 JNI 桥接

## 8. 完整调用链追踪示例

以"用户登录"为例：

```
[Manifest] LoginActivity (launcher)
  → [Activity] LoginActivity.onCreate()
    → [View] binding.loginButton.setOnClickListener
      → [ViewModel] LoginViewModel.login(email, password)
        → [Repository] AuthRepository.login(email, password)
          → [API] AuthService.login(@Body LoginRequest)
            → [Retrofit] POST /api/v1/auth/login
              → [Interceptor] AuthInterceptor.intercept()
                → 添加 Authorization header
                → 添加签名参数 (timestamp, nonce, sign)
          → [Local] TokenStorage.saveTokens(accessToken, refreshToken)
```

## 9. 工具命令汇总

| 任务 | 命令 |
|---|---|
| 查找接口方法 | `grep -rn 'interface.*Service\|interface.*Api' sources/` |
| 查找实现类 | `grep -rn 'implements.*Service\|implements.*Repository' sources/` |
| 查找调用点 | `grep -rn '\.methodName(' sources/` |
| 查找字符串引用 | `grep -rn '"api/v1/' sources/` |
| 查找回调注册 | `grep -rn 'registerCallback\|setListener\|enqueue' sources/` |
| 查找异步调用 | `grep -rn 'subscribe\|observe\|launch\|enqueue\|execute' sources/` |
