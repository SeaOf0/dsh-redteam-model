# 业务场景标签系统

本文档定义 API 级别的业务场景标签，用于在审计初期进行风险分级和资源分配，降低不必要的 LLM 调用成本。

---

## 核心理念

**不是所有 API 都需要深度审计**。

业务场景初筛的核心思想：
- 公开文章查看功能 → 不需要关心越权、并发问题
- 管理后台功能 → 重点审计权限控制
- 支付相关功能 → 重点审计金额篡改、并发竞争

**目标**：在 AI 深度审计前，通过业务场景标签快速识别高风险 API，精准分配审计资源。

---

## 业务场景分类

### 一级分类：场景类型

| 场景类型 | 代码特征 | 典型 API | 默认风险等级 |
|----------|----------|----------|-------------|
| **PUBLIC_ACCESS** | `permitAll()`, 无认证要求 | 首页、公告、公开文章 | LOW |
| **USER_OPERATION** | 需登录，操作自己的数据 | 个人资料、修改密码 | MEDIUM |
| **DATA_ACCESS** | 需登录，访问特定数据 | 订单详情、用户列表 | HIGH |
| **PRIVILEGED_OPERATION** | 需特定权限 | 用户管理、系统配置 | HIGH |
| **FINANCIAL_TRANSACTION** | 涉及资金流转 | 支付、退款、转账 | CRITICAL |
| **RESOURCE_ALLOCATION** | 有限资源分配 | 下单、抢购、预约 | HIGH |
| **STATE_TRANSITION** | 状态流转操作 | 审批、发货、退款 | HIGH |

### 二级分类：关注维度

每种场景类型有特定的安全关注维度：

| 场景类型 | 跳过检查 | 重点检查 |
|----------|----------|----------|
| PUBLIC_ACCESS | 越权、并发 | XSS、SSRF、信息泄露 |
| USER_OPERATION | 越权（操作自己数据） | 认证绕过、密码安全 |
| DATA_ACCESS | - | 水平越权、信息泄露 |
| PRIVILEGED_OPERATION | - | 垂直越权、权限绕过 |
| FINANCIAL_TRANSACTION | - | 金额篡改、并发竞争、状态机绕过 |
| RESOURCE_ALLOCATION | - | 并发竞争、库存绕过 |
| STATE_TRANSITION | - | 状态机绕过、流程跳跃 |

---

## API 标签标注方法

### 方法 1：自动识别（基于代码特征）

```bash
# 识别公开访问接口
grep -rn "permitAll\|anonymous" --include="*.java" | grep -v "//.*permitAll"

# 识别特权操作接口
grep -rn "@PreAuthorize\|@Secured\|@RolesAllowed\|hasRole" --include="*.java"

# 识别资金交易接口
grep -rn "pay\|payment\|refund\|transfer\|withdraw" --include="*.java" | grep -i "mapping"

# 识别资源分配接口
grep -rn "order\|create\|book\|reserve" --include="*.java" | grep -i "mapping"
```

### 方法 2：关键词匹配

| 关键词模式 | 场景标签 |
|------------|----------|
| `@PreAuthorize`, `hasRole('ADMIN')` | PRIVILEGED_OPERATION |
| `pay`, `payment`, `refund`, `transfer` | FINANCIAL_TRANSACTION |
| `order`, `create`, `book` | RESOURCE_ALLOCATION |
| `approve`, `reject`, `ship`, `deliver` | STATE_TRANSITION |
| `permitAll`, `anonymous()` | PUBLIC_ACCESS |
| `@GetMapping.*{id}`, `getById`, `findById` | DATA_ACCESS |

### 方法 3：URL 路径推断

| URL 模式 | 推断场景 |
|----------|----------|
| `/api/public/*`, `/open/*` | PUBLIC_ACCESS |
| `/api/user/*`, `/api/profile/*` | USER_OPERATION |
| `/api/admin/*`, `/manage/*` | PRIVILEGED_OPERATION |
| `/api/pay/*`, `/api/order/*` | FINANCIAL_TRANSACTION |
| `/api/order/create`, `/api/book/*` | RESOURCE_ALLOCATION |

---

## 标签输出格式

### 单个 API 标签

```json
{
  "api": "POST /api/pay",
  "scenario_type": "FINANCIAL_TRANSACTION",
  "risk_level": "CRITICAL",
  "skip_checks": ["XSS（非展示类）", "公开信息泄露"],
  "focus_checks": ["金额篡改", "并发竞争", "状态机绕过", "水平越权"],
  "estimated_effort": "HIGH"
}
```

### 批量标签输出

```json
{
  "project": "e-commerce-platform",
  "total_apis": 120,
  "scenario_distribution": {
    "PUBLIC_ACCESS": 15,
    "USER_OPERATION": 30,
    "DATA_ACCESS": 40,
    "PRIVILEGED_OPERATION": 10,
    "FINANCIAL_TRANSACTION": 8,
    "RESOURCE_ALLOCATION": 12,
    "STATE_TRANSITION": 5
  },
  "audit_priority": [
    {"api": "POST /api/pay", "priority": 1, "scenario": "FINANCIAL_TRANSACTION"},
    {"api": "POST /api/refund", "priority": 2, "scenario": "FINANCIAL_TRANSACTION"},
    {"api": "POST /api/order/create", "priority": 3, "scenario": "RESOURCE_ALLOCATION"},
    {"api": "DELETE /api/admin/user/{id}", "priority": 4, "scenario": "PRIVILEGED_OPERATION"}
  ]
}
```

---

## 审计资源分配策略

### 基于 EALOC 和场景标签的混合策略

```
原始 EALOC 计算：
EALOC = T1_LOC × 1.0 + T2_LOC × 0.5 + T3_LOC × 0.1

场景标签修正：
CRITICAL 场景 (FINANCIAL_TRANSACTION): × 1.5
HIGH 场景 (PRIVILEGED_OPERATION, RESOURCE_ALLOCATION, STATE_TRANSITION): × 1.2
MEDIUM 场景 (DATA_ACCESS, USER_OPERATION): × 1.0
LOW 场景 (PUBLIC_ACCESS): × 0.5

修正后 EALOC：
Adjusted_EALOC = Σ (API_EALOC × Scenario_Multiplier)
```

### Agent 分配建议

| Adjusted EALOC | Agent 数量 | 审计深度 |
|----------------|-----------|----------|
| < 10,000 | 1 | 全量深度审计 |
| 10,000 - 30,000 | 2-3 | 按场景类型分片 |
| 30,000 - 50,000 | 3-5 | 按模块 + 场景分片 |
| > 50,000 | 5+ | 考虑 CPG 工具增强 |

---

## 初筛规则

### 可跳过深度审计的场景

满足以下条件的 API 可标记为"快速模式"，仅进行 Layer 1 预扫描：

```markdown
□ 场景类型 = PUBLIC_ACCESS
□ 无用户输入参数（仅路径参数且为固定值）
□ 无敏感数据访问
□ 无状态变更操作
```

### 必须深度审计的场景

满足以下任一条件的 API 必须进行完整的 CoT 四步推理：

```markdown
□ 场景类型 = FINANCIAL_TRANSACTION
□ 场景类型 = PRIVILEGED_OPERATION 且涉及删除/修改
□ 场景类型 = RESOURCE_ALLOCATION 且有并发风险
□ 场景类型 = STATE_TRANSITION 且涉及状态跳跃
□ Layer 1 预扫描命中 P0/P1 级危险模式
```

---

## 与 Tier 分类的整合

### Tier 分类 + 场景标签矩阵

| Tier | PUBLIC_ACCESS | USER_OPERATION | DATA_ACCESS | PRIVILEGED | FINANCIAL | RESOURCE | STATE |
|------|--------------|----------------|-------------|------------|-----------|----------|-------|
| T1 (Controller) | T3 快速 | T2 标准 | T1 深度 | T1 深度 | T1 深度+CoT | T1 深度+CoT | T1 深度+CoT |
| T2 (Service) | SKIP | T3 快速 | T2 标准 | T2 标准 | T1 深度 | T2 标准 | T2 标准 |
| T3 (Entity) | SKIP | SKIP | T3 快速 | T3 快速 | T2 标准 | T3 快速 | T3 快速 |

**说明**：
- **深度**：完整 Sink-driven + Control-driven 双轨审计
- **深度+CoT**：深度审计 + 逻辑漏洞 CoT 四步推理
- **标准**：聚焦关键维度审计
- **快速**：Layer 1 预扫描 + 快速模式匹配
- **SKIP**：跳过审计

---

## 实战示例

### 示例 1：公开文章查看接口

```java
@GetMapping("/public/article/{id}")
@PermitAll
public Article getPublicArticle(@PathVariable Long id) {
    return articleService.getById(id);
}
```

**场景标签**：
```json
{
  "api": "GET /public/article/{id}",
  "scenario_type": "PUBLIC_ACCESS",
  "risk_level": "LOW",
  "skip_checks": ["越权", "并发", "状态机"],
  "focus_checks": ["SSRF（如有外部链接）", "XSS（文章内容）"],
  "audit_mode": "快速模式"
}
```

### 示例 2：支付接口

```java
@PostMapping("/api/pay")
@PreAuthorize("hasRole('USER')")
public Result pay(@RequestParam String orderId, @RequestParam BigDecimal amount) {
    return paymentService.pay(orderId, amount);
}
```

**场景标签**：
```json
{
  "api": "POST /api/pay",
  "scenario_type": "FINANCIAL_TRANSACTION",
  "risk_level": "CRITICAL",
  "skip_checks": [],
  "focus_checks": ["金额篡改", "并发竞争", "状态机绕过", "水平越权", "重放攻击"],
  "audit_mode": "深度+CoT"
}
```

### 示例 3：用户删除接口

```java
@DeleteMapping("/api/admin/user/{id}")
@PreAuthorize("hasRole('ADMIN')")
public void deleteUser(@PathVariable Long id) {
    userService.delete(id);
}
```

**场景标签**：
```json
{
  "api": "DELETE /api/admin/user/{id}",
  "scenario_type": "PRIVILEGED_OPERATION",
  "risk_level": "HIGH",
  "skip_checks": [],
  "focus_checks": ["垂直越权", "水平越权", "权限绕过"],
  "audit_mode": "深度"
}
```

---

## 使用流程

### Phase 1 项目侦察阶段

```markdown
1. 扫描所有 Controller，识别 API 端点
2. 根据关键词和代码特征标注场景类型
3. 计算场景修正后的 Adjusted EALOC
4. 生成审计优先级列表
5. 分配 Agent 资源
```

### 输出文件：`scenario-tags.json`

```json
{
  "generated_at": "2024-01-15T10:30:00Z",
  "project": "example-project",
  "apis": [
    {
      "method": "POST",
      "path": "/api/pay",
      "controller": "PaymentController.java:45",
      "scenario_type": "FINANCIAL_TRANSACTION",
      "risk_level": "CRITICAL",
      "focus_checks": ["金额篡改", "并发竞争", "状态机绕过", "水平越权"],
      "skip_checks": []
    }
  ],
  "summary": {
    "total_apis": 120,
    "critical": 8,
    "high": 27,
    "medium": 45,
    "low": 40
  }
}
```

---

## 系统特点

**本系统的设计要点**：
1. 将 EALOC 与场景标签结合
2. 明确定义每种场景的关注维度
3. 提供可跳过的检查项（真正降低成本）
4. 与 Tier 分类整合形成完整分层策略