# C2 框架架构与改造（C2_ARCHITECTURE）

> 本文件为 `c2-custom-evasion.md` 技能文件索引的伴生手册（补齐断链）。
> 覆盖 C2 框架**架构设计 → 协议设计 → Malleable C2 → 改造点 → 检测侧 → 实测判据**。
> 授权立场见 `refs/README.md`；配套见 `BEACON_DEVELOPMENT.md`、`STAGER_LOADER.md`、
> `PROTOCOL_EVASION.md`、`OPSEC_HARDENING.md`。

## 1. 架构分层

```
Teamserver（管控）→ Listener（协议入口）→ Redirector（CDN/前置）→ Beacon（目标侧）
```

| 层 | 职责 | 免杀改造点 |
|---|---|---|
| Teamserver | 会话管理、任务队列、日志 | 日志脱敏、会话加密、多租户隔离 |
| Listener | 协议监听、证书、Profile | Malleable C2、TLS 指纹、证书定制 |
| Redirector | TLS 终止、域前置、流量整形 | SNI/Host 分离、CDN 前置、云函数代理 |
| Beacon | 回连、任务执行、结果回传 | 内存执行、sleep 混淆、协议伪装 |

## 2. 协议设计原则

- **加密**：全链路对称加密（静态 + 传输），密钥随机 + 会话级派生。
- **伪装**：流量形态仿正常应用（HTTP 仿浏览器、DNS 仿正常查询）。
- **弹性**：多通道备份、自动重连、降级机制。
- **最小化**：beacon 体积最小、回连频率最低必要。

## 3. Malleable C2 Profile（配置示例）

```text
# C2 profile 关键段（骨架示例，字段名以具体 C2 框架为准）
http-get {
    uri "/api/v1/status";
    client {
        header "Host" "updates.example.com";
        header "User-Agent" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ...";
    }
    server {
        output { base64; prepend "{\"ok\":"; append "}"; }
    }
}
http-post {
    uri "/api/v1/report";
    client { header "Content-Type" "application/json"; output { base64; } }
}
sleeptime 60000; jitter 20;
```

**改造点**：URI 结构仿真实路径、UA/头顺序匹配浏览器、响应体嵌入 JSON 骨架、`sleeptime`+`jitter` 随机化。

## 4. 检测侧

| 层 | 检测点 | 判据 |
|---|---|---|
| 架构 | beacon 心跳节拍 | 固定间隔（无 jitter）外连 |
| 协议 | 响应体骨架异常 | 编码 blob + 固定 prepend/append |
| TLS | 证书/指纹 | 自签名/指纹不匹配浏览器 |

## 5. 实测判据

| 判据 | 方法 |
|---|---|
| Profile 是否生效 | 抓包比对实际流量与 profile 声明 |
| 是否被 NDR 识别 | JA3/JA4 指纹 + URI 熵 + 心跳节拍分析 |

*WARNING: 授权红队评估与安全研究专用。*
