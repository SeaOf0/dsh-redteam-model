# Call Flow Playbook

目标：从 Android 入口点一路追到目标逻辑。

## 入口优先级

1. `Application.onCreate`
2. launcher `Activity.onCreate`
3. 关键 `Fragment`
4. `Service` / `BroadcastReceiver`
5. `ViewModel` / `Repository`

## 常见链路

`Activity/Fragment -> ClickListener -> ViewModel/Presenter -> Repository -> ApiService`

或

`Activity -> NativeBridge -> JNI -> SO function`

## jadx 搜索锚点

| 目标 | Grep 模式 | 说明 |
|---|---|---|
| Activity 入口 | `extends.*Activity` + `AndroidManifest.xml` launcher intent | 确认实际启动类 |
| 点击事件 | `setOnClickListener\|onClick\|onItemClick` | Java 传统事件 |
| 网络调用 | `enqueue\|execute\|sendRequest\|doRequest` | OkHttp/Retrofit 调度 |
| 异步切换 | `switchToUiThread\|postValue\|observe\|collect` | LiveData/Flow 数据回流 |
| 导航跳转 | `startActivity\|navigate\|FragmentTransaction` | 页面流转 |
| 隐式调用 | `invoke\|call\|Method\.newInstance\|Proxy` | 反射/动态代理 |

## Kotlin 协程 / Flow 详细追踪

当目标使用 Kotlin 时，同步调用链模型不再适用。编译后特征：

- `suspend fun` 编译为带 `Continuation` 参数的方法
- jadx 输出中出现 `Object invokeSuspend(Object)` 表示协程状态机入口
- `Flow` / `StateFlow` 收集器编译为 `collect(FlowCollector, Continuation)`
- `launch` / `async` / `withContext` 在反编译中变成 `BuildersKt` 调用

### 状态机还原步骤

1. **定位 `invokeSuspend`**：在 jadx 中搜索 `invokeSuspend`，找到目标类的方法。该方法就是协程的完整生命周期
2. **读取 label switch**：方法体开头的 `switch(label)` 或 `if(label == 0)` 分支对应每个挂起点。label 0 是入口，每经过一次 `suspend` 调用后 label 递增
3. **追踪数据流**：每个 label 分支内的变量赋值代表该阶段的计算结果。注意 `Continuation` 中存储的跨分支变量（通常在内部类字段中）
4. **识别挂起调用**：`BuildersKt.withContext`、`kotlinx.coroutines.Dispatchers` 等调用是挂起点——它们之后的代码在下一个 label 分支中
5. **还原 try/catch**：协程的异常处理编译为 `Label_0` / `Label_1` 跳转 + `throw`。如果看到 `try` 块后的 label 没有正常赋值，可能是异常出口

### 常见陷阱

- **不要把 `invokeSuspend` 中的每个 case 分支当成独立方法**——它们是同一个协程的不同阶段
- **`Continuation` 的 `label` 字段可能被多次赋值**——以最后一次为准
- **Lambda 内的协程**会生成额外的 `ContinuationImpl` 子类，名称类似 `ClassName$methodName$1`——追踪时要顺到内部类中
- **`Flow` 的 `collect` 是双向调用**——传入的 `FlowCollector` 的 `emit` 调用代表上游产出值，不要和下游混淆

### Grep 模式

```
invokeSuspend
ContinuationImpl
FlowCollector
BuildersKt\.(launch|async|withContext)
StateFlow\|MutableStateFlow
```

## Compose UI 详细追踪

当识别到 `@Composable` / `Composer` / `ComposableImpl` 时，UI 不走传统 View 体系：

- Composable 函数在 jadx 中以原函数名 + 后缀出现（如 `MyScreen` → `MyScreen(..., Composer, int)`）
- `remember` / `mutableStateOf` 管理的状态分散在 Composer 调用中
- 事件回调（onClick 等）是 lambda 参数，不在 `OnClickListener` 中

### Compose 状态追踪

1. **定位状态声明**：搜索 `mutableStateOf\|remember\|MutableState`，找到状态变量的创建点
2. **追踪读取**：状态变量被引用的 Composable 函数就是观察者——Compose 的重组机制会在值变化时重新调用这些函数
3. **追踪写入**：状态的 `.value =` 赋值点就是触发源——找到调用链即可还原事件流
4. **`derivedStateOf` / `produceState`**：这些是派生状态，需要追踪其计算 lambda 中的上游状态引用

### Compose 事件流还原

1. **lambda 参数即回调**：`onClick = { ... }` 编译为 `Function2` 或 `Function1` 参数，在 jadx 中表现为 `Function2<...> onClick` 或类似签名
2. **追踪 lambda 体**：lambda 体可能在同一方法内（内联），也可能在外部类（非内联 lambda，如 `remember { ... }` 中的）
3. **ViewModel 调用**：Compose 中 ViewModel 通常通过 `hiltViewModel()` 或 `viewModel()` 获取，追踪 `vm.xxx()` 调用即可

### Grep 模式

```
@Composable
Composer\.
ComposableImpl
mutableStateOf\|remember\|derivedStateOf
Function[0-9]+
```

## DI 间接层详细追踪（HILT / Dagger）

当出现 `@Inject / @Module / @Provides / MembersInjector / DaggerXxxComponent` 时：

- 实际实例化由生成的 `Factory` / `Provider` 类完成，不直接 `new`
- 追踪起点：先找 Hilt 生成类（`Hilt_XXX_Activity` / `Hilt_XXX_Fragment`），其中的 `inject()` 调用暴露了所有注入点
- 从注入点找到 `@Provides` 方法或 `@Inject` 构造函数，确定实际实现类

### Dagger 组件图追踪步骤

1. **找 Component**：搜索 `DaggerXxxComponent`（Dagger 生成的实现类），其 `builder()` 或 `factory()` 方法是依赖图的入口
2. **找 Module 绑定**：每个 `@Module` 类的 `@Provides` 方法对应一个绑定。Dagger 生成的 `XxxModule_ProvidesYyyFactory` 类包含实际创建逻辑
3. **追踪作用域**：`@Singleton` / `@ActivityScoped` 等注解决定实例生命周期。同一个 Component 中的 `@Singleton` 绑定只创建一次
4. **限定符消歧**：`@Named("xxx")` / `@Qualifier` 用于区分同一类型的多个绑定。在生成的 Factory 中会体现为不同的 Provider 字段

### 常见陷阱

- **`@Inject` 构造函数的类不生成 Factory**——Dagger 直接调用构造函数。只有 `@Provides` 方法才生成 Factory
- **多模块项目中绑定可能分散在不同 `@Module` 中**——需要搜索 `@Module(includes = [...])` 的传递链
- **`@Binds` vs `@Provides`**：`@Binds` 是抽象方法，将接口映射到实现；`@Provides` 是具体方法，有创建逻辑。两者在反编译中的形态不同

### Grep 模式

```
Hilt_\|Dagger.*Component
_Provides.*Factory\|_MembersInjector
@Inject\|@Module\|@Provides
@Singleton\|@ActivityScoped\|@FragmentScoped
```

## 观察者 / 回调链追踪

当目标使用 RxJava、LiveData 或 EventBus 等响应式框架时：

| 框架 | 订阅模式 | 追踪锚点 |
|---|---|---|
| LiveData | `observe(owner, observer)` | 找 `observer.onChanged` 实现 |
| RxJava 2 | `subscribe(observer)` / `dispose()` | 找 `Observer.onNext` / `Consumer.accept` |
| RxJava 3 | 同上 | 同上 |
| Flow | `collect { }` / `collectLatest { }` | 见 Kotlin 协程节 |
| EventBus | `@Subscribe` / `register` | 搜索 `@Subscribe` 注解方法 |
| Broadcast | `registerReceiver` / `onReceive` | 搜索 `onReceive` 实现 |

关键原则：**先找订阅点（谁接收），再找发布点（谁发送）**。发布点通常是 `postValue` / `onNext` / `emit` / `send` 调用。

## 常见错误

- 只写了 `Activity -> Repository -> ApiService` 就声称完成了调用链，缺少中间每一层的具体方法签名和参数
- 在 Kotlin 协程中把 `invokeSuspend` 的每个 label 分支当成独立调用，导致链路碎片化
- 在 Compose 中搜索 `setOnClickListener` 找不到事件处理，就声称"没有事件回调"
- 在 Dagger 项目中跳过生成的 Factory 类，直接从 `@Inject` 注解推断实现类，遗漏了 `@Provides` 中的条件分支
- 只追踪了正向调用（A→B→C），忽略了异常路径和回调路径（C→B→A 的数据回流）

## 最小交付

- `run/call-chain.md`
- 报告中至少写一条完整关键链路（含方法签名、参数、每层跳转的证据）
