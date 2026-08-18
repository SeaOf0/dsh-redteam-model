---
name: java-expr-injection-audit
description: Java 表达式注入审计专项。SpEL（StandardEvaluationContext vs SimpleEvaluationContext）、OGNL（ValueStack/addDefaultType）、MVEL（eval）、EL（ELProcessor）四引擎 sink 表与安全上下文判据、版本判据；输出可利用性分级、PoC 与修复建议（禁止省略）。
---

# Java 表达式注入审计（java-expr-injection-audit）

分析 Java 项目中用户可控数据进入表达式求值引擎（SpEL/OGNL/MVEL/EL）的路径。核心判据：
**引擎的安全上下文是否放行反射 / 类引用 / new / 静态方法调用**——放行即 RCE。

## 分级与编号
- 严重度评级见 `java-severity-rating.md`
- 漏洞编号：`{C/H/M/L}-EXPR-{序号}`

## 四引擎 Sink 表（必做）

| 引擎 | Sink | 危险上下文 | 安全上下文 | 判据 |
|------|------|------------|------------|------|
| **SpEL** | `SpelExpressionParser().parseExpression(expr).getValue(ctx)` | `StandardEvaluationContext`（可 `T(java.lang.Runtime)`、反射、new） | `SimpleEvaluationContext.forReadOnlyDataBinding()`（禁类引用/反射/new） | 是否用 `SimpleEvaluationContext` + 白名单 `TypeLocator` |
| **OGNL** | `Ognl.getValue/setValue/parseExpression`、Struts2 `ValueStack.findValue` | `ValueStack` + 默认 `OgnlContext`（静态方法/构造器可调） | 禁用静态访问 + `MemberAccess` 白名单 | 是否 `addDefaultType`/`MemberAccess` 限制；Struts2 版本 |
| **MVEL** | `MVEL.eval(expr)` / `MVEL.executeExpression` | 无沙箱，直接反射执行 | 无原生安全上下文（必须外部白名单） | 是否把用户输入传给 `MVEL.eval` |
| **EL** | `ELProcessor.eval(expr)`、`ExpressionFactory.createValueExpression` | `ELProcessor`（可 `Runtime.getRuntime().exec`） | `ELManager` 受限导入 + 无反射 | 是否直接 `eval` 用户输入 |

---

## 1. SpEL：StandardEvaluationContext vs SimpleEvaluationContext

```java
// ❌ 危险：StandardEvaluationContext 默认放行反射/类引用/new
ExpressionParser parser = new SpelExpressionParser();
StandardEvaluationContext ctx = new StandardEvaluationContext();
Object r = parser.parseExpression(userInput).getValue(ctx);
// payload: T(java.lang.Runtime).getRuntime().exec("id")
//          new javax.script.ScriptEngineManager().getEngineByName("js").eval("...")

// ✅ 安全：SimpleEvaluationContext 禁类引用/反射/new
EvaluationContext safeCtx = SimpleEvaluationContext.forReadOnlyDataBinding().build();
parser.parseExpression(safeExpr).getValue(safeCtx);

// ✅ 安全：StandardEvaluationContext + TypeLocator 白名单
StandardEvaluationContext ctx2 = new StandardEvaluationContext();
ctx2.setTypeLocator(name -> {
    if (name.startsWith("com.example.")) return Class.forName(name);
    throw new IllegalArgumentException("Type not allowed: " + name);
});
```

**SpEL 利用 payload（判据对照）：**

```
T(java.lang.Runtime).getRuntime().exec('id')                       # 静态方法 → 需 StandardEvaluationContext
new java.lang.ProcessBuilder('id').start()                          # new → 需 StandardEvaluationContext
T(javax.script.ScriptEngineManager).newInstance().getEngineByName('js').eval('...')  # 反射链
''.getClass().forName('java.lang.Runtime').getMethod('exec', ...)   # 反射链
```

**判据**：出现 `StandardEvaluationContext` 且未 `setTypeLocator` 白名单，或直接
`parser.parseExpression(userInput).getValue()`（默认 SimpleEvaluationContext 之外的能力）= 高危。

---

## 2. OGNL：ValueStack / addDefaultType

```java
// ❌ 危险：Struts2 ValueStack 直接 findValue 用户输入
ValueStack vs = ActionContext.getContext().getValueStack();
Object r = vs.findValue(userInput);   // 历史 Struts2 RCE 来源

// ❌ 危险：Ognl.getValue 默认成员访问
Ognl.getValue(userInput, context, root);

// ✅ 安全：禁用静态/构造器访问 + MemberAccess 白名单
OgnlContext ctx = (OgnlContext) Ognl.createDefaultContext(root, new DefaultMemberAccess(false));
// DefaultMemberAccess(false) 禁静态方法/构造器访问
```

**Struts2 OGNL 注入时间线（版本判据）：**

| CVE | 年份 | 注入点 |
|-----|------|--------|
| CVE-2013-2251 | 2013 | Action 名称 |
| CVE-2017-5638 | 2017 | Content-Type 头 |
| CVE-2018-11776 | 2018 | 命名空间 |
| S2-045/S2-046 | 2017 | Content-Type/Content-Disposition |

**判据**：Struts2 老版本（< 2.5.30 等）的 `Content-Type`/`namespace`/`action name` 直接进
OGNL 求值；`ValueStack.findValue` 参数可控即高危。

---

## 3. MVEL：eval

```java
// ❌ 危险：MVEL 无沙箱，eval 直接反射执行
import org.mvel2.MVEL;
Object r = MVEL.eval(userInput);              // payload: Runtime.getRuntime().exec("id")
Object r2 = MVEL.executeExpression(compiled); // 编译后执行

// ✅ 安全：MVEL 无原生沙箱，必须禁止用户输入进入 eval / 外部白名单变量
```

**判据**：`MVEL.eval`/`MVEL.executeExpression` 入参可控即高危（MVEL 不提供
`SimpleEvaluationContext` 类安全上下文，防御只能靠「不让用户输入进表达式」）。

---

## 4. EL：ELProcessor

```java
// ❌ 危险：ELProcessor.eval 用户输入
import javax.el.ELProcessor;
ELProcessor elp = new ELProcessor();
Object r = elp.eval(userInput);   // payload: ''.getClass().forName('java.lang.Runtime')...

// ❌ 危险：JSF ValueExpression 用户输入
FacesContext ctx = FacesContext.getCurrentInstance();
ValueExpression ve = ctx.getApplication().getExpressionFactory()
    .createValueExpression(elContext, userInput, Object.class);
ve.getValue(elContext);

// ✅ 安全：不把用户输入当 EL 求值；EL 3.0 默认 import 受限，但仍可反射
```

**判据**：`ELProcessor.eval` / `createValueExpression` 入参可控即高危（EL 可经
`''.getClass().forName(...)` 反射链 RCE）。

---

## 审计 grep（四引擎统一扫描）

```bash
# SpEL
grep -rn 'SpelExpressionParser\|parseExpression\|StandardEvaluationContext\|SimpleEvaluationContext\|@Value.*#{' --include='*.java' .

# OGNL
grep -rn 'Ognl.getValue\|Ognl.setValue\|Ognl.parseExpression\|findValue\|ValueStack\|addDefaultType\|MemberAccess' --include='*.java' .

# MVEL
grep -rn 'MVEL.eval\|MVEL.executeExpression\|MVEL.compileExpression' --include='*.java' .

# EL
grep -rn 'ELProcessor\|ValueExpression\|createValueExpression\|ExpressionFactory\|elContext' --include='*.java' .
```

## 漏洞条目模板（强制）
每条漏洞必须包含：数据流链（入口 → 引擎 Sink → 安全上下文判据）、可利用性分级、
PoC（`T(Runtime).getRuntime().exec('whoami')` 级最小影响）、修复建议。

## 修复建议（按引擎）

1. **SpEL**：一律 `SimpleEvaluationContext.forReadOnlyDataBinding()`；确需类型引用时
   `StandardEvaluationContext.setTypeLocator` 白名单。
2. **OGNL**：`DefaultMemberAccess(false)` 禁静态/构造器；升级 Struts2 到安全版本。
3. **MVEL**：禁止用户输入进 `eval`（无沙箱）；如需规则引擎用白名单表达式模板。
4. **EL**：不将用户输入作 EL 求值；`ELProcessor` 仅用于内部固定表达式。
